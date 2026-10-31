//! Rebuild the authorization tree a contract hands
//! `authorize_as_current_contract` from its encoding, in the SDK's own
//! types.
//!
//! # The shape
//!
//! A contract that pre-authorizes a deeper call writes one expression:
//!
//! ```rust,ignore
//! env.authorize_as_current_contract(vec![&env, InvokerContractAuthEntry::Contract(
//!     SubContractInvocation {
//!         context: ContractContext { contract: c, fn_name: f, args },
//!         sub_invocations: vec![&env],
//!     },
//! )]);
//! ```
//!
//! None of these types is the contract's. The SDK declares them in its
//! `auth` module with `export = false`, so the contract's
//! `contractspecv0` never lists them and the struct passes, which key on
//! the spec, have nothing to name. What the binary holds is their derived
//! encodes: two `map_new_from_linear_memory` over a key table of field
//! names and frame slots, a two-element vec `[Symbol "Contract", map]` for
//! the variant, and a vec of the entries:
//!
//! ```text
//! m1 = map_new(&["args", "contract", "fn_name"], fp+72, 3)
//! m2 = map_new(&["context", "sub_invocations"], fp+56, 2)
//! e  = vec![sym "Contract", m2]
//! authorize_as_current_contract(vec![e])
//! ```
//!
//! # What this pass does
//!
//! It walks the argument top-down, typing each node by what its parent
//! declares, and rewrites the whole tree at once: each map to the struct
//! literal ([`super::udt_encode::rebuild_as`]), each variant vec to the
//! variant, each vec of entries to a typed vec. The types come from a fixed
//! table of the SDK's `auth` module ([`AUTH`]), registered in the module's
//! type registry as *imported* ([`sordec_ir::TypeRegistry::imported`]): the
//! reconstruction says `use soroban_sdk::auth::{..}` instead of declaring
//! them.
//!
//! # Why it is exact
//!
//! The types are fixed at the destination, not guessed from the shape. The
//! host function's argument is, by the protocol, a vector of
//! `InvokerContractAuthEntry`; the SDK version the contract was built with
//! (`rssdkver`, or the protocol number) fixes that type's declaration, which
//! [`AUTH`] transcribes from the SDK's source. From there each node's type
//! is its parent's declaration:
//!
//! - an element of the entries vec is an entry. The derive encodes an enum
//!   variant as a vec whose first element is the variant's name, so the
//!   constant symbol there *names* the variant, and the variant's
//!   declaration fixes its payload's type;
//! - a struct payload or field is a map the derive built from the struct's
//!   key table. The table must hold exactly the declared field names: it
//!   confirms the declaration, it never chooses one. The literal then reads
//!   every slot under [`super::udt_encode`]'s own gates;
//! - a leaf (`Address`, `Symbol`, `BytesN<32>`, `Vec<Val>`) must already be
//!   a value of that type.
//!
//! So each rewrite says what the binary built, in the type the protocol
//! declares for that position. Writing the literal regenerates the derived
//! encodes — key tables, slot stores, the map and vec constructions — the
//! same relocation argument as every marshalling elision.
//!
//! # Gates
//!
//! - **An SDK version the table covers.** `rssdkver`'s major, or the
//!   protocol's; 21 or later. It decides which variants exist (the
//!   constructor-argument variants arrived in 22).
//! - **The spec declares none of these names.** A spec built with
//!   `experimental_spec_shaking_v2` exports the SDK's types as its own, and
//!   then its declaration stands and nothing here runs.
//! - **The whole tree or nothing.** Every node must match; one that does
//!   not leaves every node as it was.
//! - **A variant** is a vec of its name's constant symbol and one element
//!   per payload, the name a variant the SDK version declares.
//! - **A struct** is a map construction whose key table is exactly the
//!   field names, every slot proven at the construction.
//! - **A leaf** is typed as the field declares it, by its binding or, for a
//!   parameter, by the spec. A `Vec<Val>` field is a vec whose elements are
//!   not all one other type (those print as a `Vec` of that type).
//! - **Each rebuilt node is read only as part of the tree:** by its parent's
//!   element list, by a store (a frame slot the derive filled, collected
//!   once unread), or through a rename. A node also used as the `Map` or
//!   `Vec` it was would be retyped under that use.

use std::collections::{HashMap, HashSet};

use sordec_common::{Provenance, ProvenanceSource, TypeId, ValueId};
use sordec_ir::{
    CompositeType, Expr, HighFunction, HighIr, ImportedType, IrType, KnownOp, KnownType, Literal, MemoryImage,
    PrimitiveType, SemanticOp, SorobanFacts, StructDef, StructField, TypeRef, TypeRegistry, UnionCase,
    UnionDef, VecOpKind,
};

use super::tuple_return::symbol_text;
use super::udt_encode;
use crate::dataflow::high_uses::{HighUseIndex, HighUseSite};
use crate::dataflow::resolve_use;
use crate::metrics_catalog::MARSHALLING_AUTH_ENTRIES as M_ENTRIES;
use crate::pass::{Pass, PassResult};
use crate::type_infer::known_of_type_ref;

/// Pass name — also the provenance `pass` field for every rewrite.
pub const PASS_NAME: &str = "marshalling-auth-entries";

/// The `soroban_sdk` module the table's types live in.
const MODULE: &str = "auth";

/// The entry type `authorize_as_current_contract` takes a vector of.
const ENTRY: &str = "InvokerContractAuthEntry";

/// The first SDK major whose `auth` module the table transcribes.
const FIRST_MAJOR: u32 = 21;

/// A field or payload type in [`AUTH`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Address,
    Symbol,
    BytesN32,
    /// `Vec<Val>`.
    ValVec,
    /// Another type of the table, by name.
    Type(&'static str),
    /// `Vec` of another type of the table.
    VecOf(&'static str),
}

/// One `#[contracttype]` of the SDK's `auth` module.
struct Decl {
    name: &'static str,
    /// The first SDK major that declares it.
    since: u32,
    shape: Shape,
}

enum Shape {
    /// Fields in declaration order.
    Struct(&'static [(&'static str, Field)]),
    /// Variants in declaration order: name, payload, first SDK major.
    Union(&'static [(&'static str, &'static [Field], u32)]),
}

/// `soroban_sdk::auth`, as `src/auth.rs` declares it in SDK 21 through 27.
/// The only change across those versions is SDK 22's constructor-argument
/// context: the struct and the `CreateContractWithCtorHostFn` variants.
const AUTH: &[Decl] = &[
    Decl {
        name: "ContractContext",
        since: FIRST_MAJOR,
        shape: Shape::Struct(&[("contract", Field::Address), ("fn_name", Field::Symbol), ("args", Field::ValVec)]),
    },
    Decl {
        name: "CreateContractHostFnContext",
        since: FIRST_MAJOR,
        shape: Shape::Struct(&[("executable", Field::Type("ContractExecutable")), ("salt", Field::BytesN32)]),
    },
    Decl {
        name: "CreateContractWithConstructorHostFnContext",
        since: 22,
        shape: Shape::Struct(&[
            ("executable", Field::Type("ContractExecutable")),
            ("salt", Field::BytesN32),
            ("constructor_args", Field::ValVec),
        ]),
    },
    Decl { name: "ContractExecutable", since: FIRST_MAJOR, shape: Shape::Union(&[("Wasm", &[Field::BytesN32], FIRST_MAJOR)]) },
    Decl {
        name: "SubContractInvocation",
        since: FIRST_MAJOR,
        shape: Shape::Struct(&[("context", Field::Type("ContractContext")), ("sub_invocations", Field::VecOf(ENTRY))]),
    },
    Decl {
        name: ENTRY,
        since: FIRST_MAJOR,
        shape: Shape::Union(&[
            ("Contract", &[Field::Type("SubContractInvocation")], FIRST_MAJOR),
            ("CreateContractHostFn", &[Field::Type("CreateContractHostFnContext")], FIRST_MAJOR),
            ("CreateContractWithCtorHostFn", &[Field::Type("CreateContractWithConstructorHostFnContext")], 22),
        ]),
    },
];

fn decl(name: &str) -> Option<&'static Decl> {
    AUTH.iter().find(|d| d.name == name)
}

/// Rebuilds `authorize_as_current_contract`'s argument in the SDK's types.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthEntryPass;

impl Pass<HighIr> for AuthEntryPass {
    fn name(&self) -> &'static str {
        PASS_NAME
    }

    fn run(&self, ir: &mut HighIr) -> PassResult {
        let mut result = PassResult::default();
        let Some(facts) = ir.soroban_facts.as_ref() else {
            return result;
        };
        if !ir.functions.iter().any(|f| !roots(f).is_empty()) {
            return result;
        }
        let Some(major) = sdk_major(facts) else {
            return result;
        };
        let Some(sdk) = SdkTypes::register(&facts.types, major) else {
            return result;
        };
        let memory = ir.memory.clone();
        let mut any = false;
        for func in &mut ir.functions {
            for root in roots(func) {
                let Some(rewrites) = plan(func, &memory, &sdk, root) else {
                    continue;
                };
                apply(func, &memory, &sdk, rewrites);
                result.metrics.increment(M_ENTRIES, 1);
                any = true;
            }
        }
        if any && let Some(facts) = ir.soroban_facts.as_mut() {
            facts.types = sdk.types;
            result.changed = true;
        }
        result
    }
}

/// The SDK major the contract was built with: `rssdkver`'s, or the
/// protocol's, which names the same major.
fn sdk_major(facts: &SorobanFacts) -> Option<u32> {
    let leading = |s: &str| s.trim().split(['.', '#']).next()?.parse::<u32>().ok();
    let major = facts
        .contract_meta
        .get("rssdkver")
        .and_then(|v| leading(v))
        .or_else(|| facts.env_meta.protocol.as_deref().and_then(leading))?;
    (major >= FIRST_MAJOR).then_some(major)
}

/// The registry with the table's types in it, and their ids.
struct SdkTypes {
    types: TypeRegistry,
    ids: HashMap<&'static str, TypeId>,
    major: u32,
}

impl SdkTypes {
    /// Register the types `major` declares, as imported from the SDK's
    /// `auth` module, into a copy of `types` — or reuse them, if an earlier
    /// run did. `None` when the contract declares a type of the same name.
    fn register(types: &TypeRegistry, major: u32) -> Option<Self> {
        let declared = AUTH.iter().filter(|d| d.since <= major);
        let imported = |id: TypeId| types.sdk_module(id) == Some(MODULE);
        let named = |name: &str| -> Vec<TypeId> {
            let structs = types.structs.iter().filter(|d| d.name == name).map(|d| d.id);
            let unions = types.unions.iter().filter(|d| d.name == name).map(|d| d.id);
            let enums = types.enums.iter().chain(&types.errors).filter(|d| d.name == name).map(|d| d.id);
            let events = types.events.iter().filter(|d| d.name == name).map(|d| d.id);
            structs.chain(unions).chain(enums).chain(events).collect()
        };
        let mut ids = HashMap::new();
        let mut fresh = Vec::new();
        for d in declared.clone() {
            match named(d.name).as_slice() {
                [] => fresh.push(d),
                [id] if imported(*id) => {
                    ids.insert(d.name, *id);
                }
                // The contract's own type of that name.
                _ => return None,
            }
        }
        let mut out = types.clone();
        let base = out.next_id();
        for (k, d) in fresh.iter().enumerate() {
            ids.insert(d.name, TypeId::new(base + u32::try_from(k).ok()?));
        }
        for d in fresh {
            let id = ids[d.name];
            match &d.shape {
                Shape::Struct(fields) => out.structs.push(StructDef {
                    id,
                    name: d.name.to_owned(),
                    fields: fields
                        .iter()
                        .map(|(name, f)| Some(StructField { name: (*name).to_owned(), ty: type_ref(*f, &ids)? }))
                        .collect::<Option<_>>()?,
                }),
                Shape::Union(cases) => out.unions.push(UnionDef {
                    id,
                    name: d.name.to_owned(),
                    cases: cases
                        .iter()
                        .filter(|(_, _, since)| *since <= major)
                        .map(|(name, payload, _)| {
                            Some(UnionCase {
                                name: (*name).to_owned(),
                                fields: payload.iter().map(|f| type_ref(*f, &ids)).collect::<Option<_>>()?,
                            })
                        })
                        .collect::<Option<_>>()?,
                    exported: false,
                }),
            }
            out.imported.push(ImportedType { id, module: MODULE.to_owned() });
        }
        Some(Self { types: out, ids, major })
    }

    fn id(&self, name: &str) -> Option<TypeId> {
        self.ids.get(name).copied()
    }
}

fn type_ref(f: Field, ids: &HashMap<&'static str, TypeId>) -> Option<TypeRef> {
    Some(match f {
        Field::Address => TypeRef::Primitive(PrimitiveType::Address),
        Field::Symbol => TypeRef::Primitive(PrimitiveType::Symbol),
        Field::BytesN32 => TypeRef::Composite(CompositeType::BytesN(32)),
        Field::ValVec => TypeRef::Composite(CompositeType::Vec(Box::new(TypeRef::Primitive(PrimitiveType::Val)))),
        Field::Type(name) => TypeRef::UserDefined(*ids.get(name)?),
        Field::VecOf(name) => TypeRef::Composite(CompositeType::Vec(Box::new(TypeRef::UserDefined(*ids.get(name)?)))),
    })
}

/// Each `authorize_as_current_contract` call's argument, with the call.
fn roots(func: &HighFunction) -> Vec<(ValueId, ValueId)> {
    func.bindings
        .iter()
        .filter_map(|(id, b)| match &b.expr {
            Expr::Semantic(SemanticOp::Known(KnownOp::AuthorizeAsCurrContract { auth_entries })) => {
                Some((id, *auth_entries))
            }
            _ => None,
        })
        .collect()
}

/// One node of the rebuilt tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rewrite {
    /// A map construction that is this struct's literal.
    Struct { at: ValueId, id: TypeId },
    /// A vec that is this variant of the enum.
    Variant { at: ValueId, id: TypeId, name: String, payload: Vec<ValueId> },
    /// A vec whose elements are all of this type.
    Vec { at: ValueId, element: TypeId },
    /// A variant's name, built only for its encode.
    Name { at: ValueId },
}

/// The rewrites rebuilding the call's argument, or `None` if any node of
/// it does not match.
fn plan(
    func: &HighFunction,
    memory: &MemoryImage,
    sdk: &SdkTypes,
    (call, entries): (ValueId, ValueId),
) -> Option<Vec<Rewrite>> {
    let mut planner = Planner {
        func,
        memory,
        sdk,
        uses: HighUseIndex::build(func),
        scheduled: func.blocks.iter().flat_map(|(_, b)| b.bindings.iter().copied()).collect(),
        rewrites: Vec::new(),
        seen: HashSet::new(),
    };
    planner.vec_of(entries, ENTRY, Some(call)).then_some(planner.rewrites)
}

struct Planner<'a> {
    func: &'a HighFunction,
    memory: &'a MemoryImage,
    sdk: &'a SdkTypes,
    uses: HighUseIndex,
    scheduled: HashSet<ValueId>,
    rewrites: Vec<Rewrite>,
    /// Nodes already placed: a value reached twice is shared, and a tree
    /// node is not.
    seen: HashSet<ValueId>,
}

impl Planner<'_> {
    /// Whether `value`, where its parent declares `want`, matches.
    fn node(&mut self, value: ValueId, want: Field) -> bool {
        match want {
            Field::Address => self.leaf(value, &KnownType::Address),
            Field::Symbol => self.leaf(value, &KnownType::Symbol),
            Field::BytesN32 => self.leaf(value, &KnownType::BytesN(32)),
            Field::ValVec => self.val_vec(value),
            Field::VecOf(name) => self.vec_of(value, name, None),
            Field::Type(name) => match decl(name).map(|d| &d.shape) {
                Some(Shape::Struct(_)) => self.structure(value, name),
                Some(Shape::Union(_)) => self.variant(value, name),
                None => false,
            },
        }
    }

    /// The type a value is known to have: its binding's, or the spec's for
    /// an entrypoint parameter.
    fn known(&self, value: ValueId) -> Option<KnownType> {
        let value = resolve_use(self.func, value);
        if let Some(index) = self.func.params.iter().position(|p| *p == value)
            && let Some(sig) = self.func.signature.as_ref()
        {
            return known_of_type_ref(&sig.inputs.get(index)?.ty);
        }
        match &self.func.bindings.get(value)?.ty {
            IrType::Known(k) => Some(k.clone()),
            _ => None,
        }
    }

    fn leaf(&self, value: ValueId, want: &KnownType) -> bool {
        self.known(value).as_ref() == Some(want)
    }

    /// A `Vec<Val>`: typed so, or a vec construction that prints as one —
    /// empty, or with an element that is (or may be) a `Val`.
    fn val_vec(&self, value: ValueId) -> bool {
        let at = resolve_use(self.func, value);
        let is_val = |t: Option<&IrType>| match t {
            Some(IrType::Known(KnownType::Val) | IrType::Inferred(KnownType::Val) | IrType::Unknown(_)) | None => {
                true
            }
            _ => false,
        };
        if let Some(KnownType::Vec(inner)) = self.known(at) {
            return is_val(Some(&inner));
        }
        match self.func.bindings.get(at).map(|b| &b.expr) {
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. }))) => {
                elements.is_empty()
                    || elements.iter().any(|e| is_val(self.func.bindings.get(resolve_use(self.func, *e)).map(|b| &b.ty)))
            }
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::New, args }))) => args.is_empty(),
            _ => false,
        }
    }

    /// A vec of `element`s: a construction whose every element matches,
    /// or a new empty vec. `root` is the call the vec is handed to.
    fn vec_of(&mut self, value: ValueId, element: &'static str, root: Option<ValueId>) -> bool {
        let at = resolve_use(self.func, value);
        let Some(id) = self.sdk.id(element) else { return false };
        if !self.seen.insert(at) || !self.read_only_as_part(at, root) {
            return false;
        }
        match self.func.bindings.get(at).map(|b| &b.expr) {
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. }))) => {
                let elements = elements.clone();
                if !elements.iter().all(|e| self.node(*e, Field::Type(element))) {
                    return false;
                }
            }
            Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::New, args }))) if args.is_empty() => {}
            _ => return false,
        }
        self.rewrites.push(Rewrite::Vec { at, element: id });
        true
    }

    /// The struct `name`'s literal: a map construction its key table and
    /// slots make that struct, each field matching its declared type.
    fn structure(&mut self, value: ValueId, name: &'static str) -> bool {
        let at = resolve_use(self.func, value);
        let (Some(id), Some(Shape::Struct(declared))) = (self.sdk.id(name), decl(name).map(|d| &d.shape)) else {
            return false;
        };
        if !self.seen.insert(at) || !self.read_only_as_part(at, None) {
            return false;
        }
        let Some(fields) = udt_encode::literal_fields(self.func, self.memory, &self.sdk.types.structs, at, id) else {
            return false;
        };
        for (field, value) in fields {
            let Some((_, want)) = declared.iter().find(|(f, _)| *f == field) else { return false };
            if !self.node(value, *want) {
                return false;
            }
        }
        self.rewrites.push(Rewrite::Struct { at, id });
        true
    }

    /// A variant of the enum `name`: a vec of the variant's name and its
    /// payload, each matching the variant's declared payload type.
    fn variant(&mut self, value: ValueId, name: &'static str) -> bool {
        let at = resolve_use(self.func, value);
        let (Some(id), Some(Shape::Union(cases))) = (self.sdk.id(name), decl(name).map(|d| &d.shape)) else {
            return false;
        };
        if !self.seen.insert(at) || !self.read_only_as_part(at, None) {
            return false;
        }
        let Some(Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. }))) =
            self.func.bindings.get(at).map(|b| &b.expr)
        else {
            return false;
        };
        let Some((tag, payload)) = elements.split_first() else { return false };
        let Some(variant) = symbol_text(self.func, *tag) else { return false };
        let major = self.sdk.major;
        let Some((_, fields, _)) = cases.iter().find(|(n, _, since)| *n == variant && *since <= major) else {
            return false;
        };
        if fields.len() != payload.len() {
            return false;
        }
        let (tag, payload) = (*tag, payload.to_vec());
        if !payload.iter().zip(fields.iter()).all(|(v, f)| self.node(*v, *f)) {
            return false;
        }
        // The symbol goes with the encode when nothing else reads it.
        let name = resolve_use(self.func, tag);
        if self.read_only_as_part(name, None) {
            self.rewrites.push(Rewrite::Name { at: name });
        }
        self.rewrites.push(Rewrite::Variant { at, id, name: variant, payload });
        true
    }

    /// Whether every reader of `at`, and of its renames, reads it as part
    /// of the tree: a vec construction listing it, a store of it, a rename
    /// of it, or `root`. A binding no block schedules and no merge stands
    /// for is residue an earlier rewrite left; it never runs.
    fn read_only_as_part(&self, at: ValueId, root: Option<ValueId>) -> bool {
        let func = self.func;
        let names: HashSet<ValueId> = std::iter::once(at).chain(renames(func, at)).collect();
        names.iter().all(|name| {
            self.uses.uses_of(*name).iter().all(|site| {
                let HighUseSite::Binding { user } = site else { return false };
                if Some(*user) == root || names.contains(user) {
                    return true;
                }
                let Some(b) = func.bindings.get(*user) else { return false };
                if !self.scheduled.contains(user) && !matches!(b.expr, Expr::Phi { .. }) {
                    return true;
                }
                match &b.expr {
                    Expr::Store { addr, value, .. } => value == name && addr != name,
                    Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { elements: Some(elements), .. })) => {
                        elements.contains(name)
                    }
                    _ => false,
                }
            })
        })
    }
}

/// The bindings that are `Use` chains ending at `at`.
fn renames(func: &HighFunction, at: ValueId) -> Vec<ValueId> {
    func.bindings
        .iter()
        .filter(|(id, b)| *id != at && matches!(b.expr, Expr::Use(_)) && resolve_use(func, *id) == at)
        .map(|(id, _)| id)
        .collect()
}

fn apply(func: &mut HighFunction, memory: &MemoryImage, sdk: &SdkTypes, rewrites: Vec<Rewrite>) {
    for rewrite in rewrites {
        let (at, ty, note) = match rewrite {
            Rewrite::Struct { at, id } => {
                udt_encode::rebuild_as(func, memory, &sdk.types.structs, at, id);
                continue;
            }
            Rewrite::Name { at } => {
                if let Some(b) = func.bindings.get_mut(at)
                    && !matches!(b.expr, Expr::Literal(Literal::Unit))
                {
                    b.expr = Expr::Literal(Literal::Unit);
                    b.ty = IrType::Known(KnownType::Unit);
                    b.add_provenance(Provenance::new(
                        PASS_NAME,
                        ProvenanceSource::SdkPattern,
                        "the variant's name, built only for its encode, regenerated by writing the variant",
                    ));
                }
                continue;
            }
            Rewrite::Variant { at, id, name, payload } => {
                if let Some(b) = func.bindings.get_mut(at) {
                    b.expr = Expr::Variant { name, payload };
                }
                (at, KnownType::UserDefined(id), "the derived enum encode, as the variant its position in the auth tree declares")
            }
            Rewrite::Vec { at, element } => (
                at,
                KnownType::Vec(Box::new(IrType::Known(KnownType::UserDefined(element)))),
                "a vec of auth entries: every element is one, as its position in the auth tree declares",
            ),
        };
        for id in std::iter::once(at).chain(renames(func, at)) {
            if let Some(b) = func.bindings.get_mut(id) {
                b.ty = IrType::Known(ty.clone());
                b.add_provenance(Provenance::new(PASS_NAME, ProvenanceSource::SdkPattern, note));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshalling::test_support::{func_with, module, store, v};
    use sordec_common::UnknownReason;
    use sordec_ir::{DataSegment, EnvCompatibility};
    use std::collections::BTreeMap;

    /// Key tables at 2000 (`first_key`, `contract`, `fn_name`) and 2100
    /// (`context`, `sub_invocations`), the names after them.
    fn memory(first_key: &[u8]) -> MemoryImage {
        let mut segments = Vec::new();
        let mut table = |at: u32, names: &[&[u8]], text_at: u32| {
            let mut bytes = Vec::new();
            let mut ptr = text_at;
            for name in names {
                bytes.extend_from_slice(&ptr.to_le_bytes());
                bytes.extend_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
                segments.push(sordec_ir::DataSegment { offset: ptr, bytes: name.to_vec() });
                ptr += 32;
            }
            segments.push(DataSegment { offset: at, bytes });
        };
        table(2000, &[first_key, b"contract", b"fn_name"], 3000);
        table(2100, &[b"context", b"sub_invocations"], 3200);
        MemoryImage::from_segments(segments)
    }

    fn known(f: &mut HighFunction, id: u32, k: KnownType) {
        f.bindings.get_mut(v(id)).unwrap().ty = IrType::Known(k);
    }

    fn vec_new(elements: Vec<ValueId>) -> Expr {
        Expr::Semantic(SemanticOp::Known(KnownOp::VecNew { vals_pos: v(0), len: v(0), elements: Some(elements) }))
    }

    /// `authorize_as_current_contract(vec![Contract(SubContractInvocation {
    /// context: ContractContext { contract: v1, fn_name: v2, args: v3 },
    /// sub_invocations: v9 })])`, as the derives encode it.
    fn call_b() -> HighFunction {
        let mut f = func_with(
            vec![
                Expr::Phi { incoming: vec![] }, // v0 the context's slots
                Expr::Phi { incoming: vec![] }, // v1 contract
                Expr::Phi { incoming: vec![] }, // v2 fn_name
                vec_new(vec![v(4)]),            // v3 args
                Expr::Phi { incoming: vec![] }, // v4 an arg
                store(v(0), v(3), 0),           // v5
                store(v(0), v(1), 8),           // v6
                store(v(0), v(2), 16),          // v7
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos: v(19), vals_pos: v(0), len: v(20) })), // v8
                Expr::Semantic(SemanticOp::Known(KnownOp::VecOp { kind: VecOpKind::New, args: vec![] })), // v9
                Expr::Phi { incoming: vec![] }, // v10 the invocation's slots
                store(v(10), v(8), 0),          // v11
                store(v(10), v(9), 8),          // v12
                Expr::Semantic(SemanticOp::Known(KnownOp::MapNew { keys_pos: v(21), vals_pos: v(10), len: v(22) })), // v13
                Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew {
                    lm_pos: v(0),
                    len: v(0),
                    resolved: Some("Contract".to_string()),
                })), // v14
                vec_new(vec![v(14), v(13)]),    // v15 the entry
                vec_new(vec![v(18)]),           // v16 the entries
                Expr::Semantic(SemanticOp::Known(KnownOp::AuthorizeAsCurrContract { auth_entries: v(16) })), // v17
                Expr::Use(v(15)),               // v18 a rename of the entry
                Expr::Literal(Literal::U32(2000)), // v19
                Expr::Literal(Literal::U32(3)),    // v20
                Expr::Literal(Literal::U32(2100)), // v21
                Expr::Literal(Literal::U32(2)),    // v22
            ],
            vec![v(0), v(1), v(2), v(4), v(10)],
            vec![19, 20, 21, 22, 3, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 18, 16, 17],
        );
        known(&mut f, 1, KnownType::Address);
        known(&mut f, 2, KnownType::Symbol);
        known(&mut f, 3, KnownType::Vec(Box::new(IrType::Unknown(UnknownReason::InsufficientEvidence))));
        known(&mut f, 14, KnownType::Symbol);
        f
    }

    fn ir(f: HighFunction, sdk: Option<&str>, memory: MemoryImage) -> HighIr {
        let mut m = module(vec![f]);
        m.memory = memory;
        m.soroban_facts = Some(SorobanFacts {
            functions: BTreeMap::new(),
            types: TypeRegistry::default(),
            contract_meta: sdk.map(|s| BTreeMap::from([("rssdkver".to_string(), s.to_string())])).unwrap_or_default(),
            env_meta: EnvCompatibility::default(),
        });
        m
    }

    fn type_named(m: &HighIr, name: &str) -> TypeId {
        let t = &m.soroban_facts.as_ref().unwrap().types;
        let structs = t.structs.iter().map(|d| (d.id, d.name.as_str()));
        let unions = t.unions.iter().map(|d| (d.id, d.name.as_str()));
        structs.chain(unions).find(|(_, n)| *n == name).map(|(id, _)| id).unwrap()
    }

    #[test]
    fn the_auth_tree_is_rebuilt_in_the_sdks_types() {
        let mut m = ir(call_b(), Some("22.0.7#abc"), memory(b"args"));
        assert!(AuthEntryPass.run(&mut m).changed);
        let (ctx, inv, entry) =
            (type_named(&m, "ContractContext"), type_named(&m, "SubContractInvocation"), type_named(&m, ENTRY));
        let types = &m.soroban_facts.as_ref().unwrap().types;
        assert!(types.imported.iter().all(|t| t.module == MODULE));
        assert_eq!(types.imported.len(), 6, "SDK 22's auth types, but for `Context`");
        let f = &m.functions[0];
        let b = |i: u32| f.bindings.get(v(i)).unwrap();
        let fields = |names: &[&str], values: &[u32]| -> Vec<(String, ValueId)> {
            names.iter().zip(values).map(|(n, i)| ((*n).to_string(), v(*i))).collect()
        };
        assert!(matches!(&b(8).expr, Expr::Struct { fields: f } if *f == fields(&["contract", "fn_name", "args"], &[1, 2, 3])));
        assert_eq!(b(8).ty, IrType::Known(KnownType::UserDefined(ctx)));
        assert!(matches!(&b(13).expr, Expr::Struct { fields: f } if *f == fields(&["context", "sub_invocations"], &[8, 9])));
        assert_eq!(b(13).ty, IrType::Known(KnownType::UserDefined(inv)));
        assert!(matches!(&b(15).expr, Expr::Variant { name, payload } if name == "Contract" && *payload == vec![v(13)]));
        assert_eq!(b(15).ty, IrType::Known(KnownType::UserDefined(entry)));
        assert_eq!(b(18).ty, IrType::Known(KnownType::UserDefined(entry)), "its rename too");
        let entries = IrType::Known(KnownType::Vec(Box::new(IrType::Known(KnownType::UserDefined(entry)))));
        assert_eq!(b(16).ty, entries);
        assert_eq!(b(9).ty, entries, "the empty sub-invocations");
        assert!(matches!(b(14).expr, Expr::Literal(Literal::Unit)), "the variant's name goes with its encode");
    }

    /// SDK 21 has no constructor-argument context: the table follows the
    /// version.
    #[test]
    fn the_table_follows_the_sdk_version() {
        let mut m = ir(call_b(), Some("21.7.7"), memory(b"args"));
        assert!(AuthEntryPass.run(&mut m).changed);
        let types = &m.soroban_facts.as_ref().unwrap().types;
        assert_eq!(types.imported.len(), 5);
        assert_eq!(types.unions.iter().find(|u| u.name == ENTRY).unwrap().cases.len(), 2);
    }

    fn unchanged(mut m: HighIr) {
        let exprs = |m: &HighIr| format!("{:?}", m.functions[0].bindings.iter().map(|(_, b)| &b.expr).collect::<Vec<_>>());
        let before = exprs(&m);
        assert!(!AuthEntryPass.run(&mut m).changed);
        assert_eq!(before, exprs(&m));
        assert!(m.soroban_facts.unwrap().types.imported.is_empty(), "nothing registered");
    }

    /// A key table the struct does not have is not its literal, and then
    /// no node of the tree is rewritten.
    #[test]
    fn a_key_table_that_does_not_fit_declines_the_whole_tree() {
        unchanged(ir(call_b(), Some("22.0.7"), memory(b"argz")));
    }

    #[test]
    fn a_leaf_of_another_type_declines() {
        let mut f = call_b();
        known(&mut f, 1, KnownType::Val);
        unchanged(ir(f, Some("22.0.7"), memory(b"args")));
    }

    /// The entry is also returned: it is read as the vec it was, too.
    #[test]
    fn a_node_read_outside_the_tree_declines() {
        let mut f = call_b();
        f.returns = vec![vec![v(18)]];
        unchanged(ir(f, Some("22.0.7"), memory(b"args")));
    }

    #[test]
    fn a_variant_the_enum_lacks_declines() {
        let mut f = call_b();
        if let Expr::Semantic(SemanticOp::Known(KnownOp::SymbolNew { resolved, .. })) =
            &mut f.bindings.get_mut(v(14)).unwrap().expr
        {
            *resolved = Some("Wasm".to_string());
        }
        unchanged(ir(f, Some("22.0.7"), memory(b"args")));
    }

    #[test]
    fn without_an_sdk_version_nothing_is_named() {
        unchanged(ir(call_b(), None, memory(b"args")));
    }

    /// A spec declaring a type of the same name has its own; the SDK's is
    /// not put beside it.
    #[test]
    fn a_contract_type_of_the_same_name_declines() {
        let mut m = ir(call_b(), Some("22.0.7"), memory(b"args"));
        m.soroban_facts.as_mut().unwrap().types.structs.push(StructDef {
            id: TypeId::new(0),
            name: "ContractContext".to_string(),
            fields: vec![],
        });
        assert!(!AuthEntryPass.run(&mut m).changed);
        let types = m.soroban_facts.unwrap().types;
        assert_eq!((types.structs.len(), types.imported.len()), (1, 0));
    }
}
