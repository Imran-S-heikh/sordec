//! `siggen` — build a signature catalogue from labelled contract builds.
//!
//! A development tool. It reads contracts rebuilt with
//! `profile.release.strip=false` (see [`sordec_sigs::oracle`]) and emits the
//! generated Rust table that ships inside the decompiler.
//!
//! ```text
//! siggen generate --out crates/sordec-sigs/src/generated.rs <labelled.wasm>...
//! siggen validate --train <wasm>... -- <wasm>...
//! ```
//!
//! `validate` is the honest-measurement mode: it builds a catalogue from the
//! training modules and reports how much of the *held-out* modules' library
//! code it recovers. Keep the two sets genuinely separate — training and
//! testing on one contract measures nothing, and testing across contracts
//! by the same author measures far less than it appears to.
//!
//! Arguments are parsed by hand rather than with `clap`: this is a two-verb
//! developer tool, and keeping the library at two dependencies is worth more
//! than the ergonomics.

// The workspace warns on `eprintln!` because library crates must report
// through the diagnostic infrastructure rather than write to a stream. This
// is a standalone developer binary whose entire output *is* that stream, so
// the rule does not apply to it.
#![allow(clippy::print_stderr)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sordec_sigs::{
    CatalogueBuilder, Fingerprint, OwnedEntry, catalogue::BuildStats, read_labelled,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("siggen: {message}");
            eprintln!("\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage:
  siggen generate --out <file.rs> <labelled.wasm>...
  siggen validate --train <labelled.wasm>... -- <held-out.wasm>...";

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("generate") => generate(&args[1..]),
        Some("validate") => validate(&args[1..]),
        Some(other) => Err(format!("unknown command `{other}`")),
        None => Err("no command given".into()),
    }
}

/// Collect `--out <path>` plus positional wasm paths.
fn parse_generate(args: &[String]) -> Result<(PathBuf, Vec<PathBuf>), String> {
    let mut out = None;
    let mut inputs = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => {
                out = Some(PathBuf::from(
                    it.next().ok_or("`--out` needs a path")?.clone(),
                ));
            }
            _ => inputs.push(PathBuf::from(a)),
        }
    }
    let out = out.ok_or("`--out <file.rs>` is required")?;
    if inputs.is_empty() {
        return Err("no input modules given".into());
    }
    Ok((out, inputs))
}

fn generate(args: &[String]) -> Result<(), String> {
    let (out, inputs) = parse_generate(args)?;
    let (entries, stats) = collect(&inputs)?;

    let rendered = render_table(&entries);
    std::fs::write(&out, rendered).map_err(|e| format!("writing {}: {e}", out.display()))?;

    eprintln!(
        "siggen: {} modules -> {} fingerprints, {} ambiguous (dropped), {} entries -> {}",
        inputs.len(),
        stats.observed,
        stats.ambiguous,
        stats.kept,
        out.display()
    );
    Ok(())
}

/// Read every module and fold its library functions into one catalogue.
fn collect(inputs: &[PathBuf]) -> Result<(Vec<OwnedEntry>, BuildStats), String> {
    let mut builder = CatalogueBuilder::new();
    for path in inputs {
        let module = load(path)?;
        for f in module.library_functions() {
            let (Some(fp), Some(origin)) = (f.fingerprint, f.origin) else {
                continue;
            };
            builder.observe(fp, &f.symbol, origin, f.insns);
        }
    }
    Ok(builder.build())
}

fn load(path: &Path) -> Result<sordec_sigs::LabelledModule, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    read_labelled(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// Split `--train A B -- C D` into training and held-out sets.
fn parse_validate(args: &[String]) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    let mut train = Vec::new();
    let mut test = Vec::new();
    let mut seen_train_flag = false;
    let mut after_separator = false;
    for a in args {
        match a.as_str() {
            "--train" => seen_train_flag = true,
            "--" => after_separator = true,
            _ if after_separator => test.push(PathBuf::from(a)),
            _ => train.push(PathBuf::from(a)),
        }
    }
    if !seen_train_flag || train.is_empty() {
        return Err("`--train <wasm>...` is required".into());
    }
    if test.is_empty() {
        return Err("no held-out modules after `--`".into());
    }
    Ok((train, test))
}

fn validate(args: &[String]) -> Result<(), String> {
    let (train, test) = parse_validate(args)?;
    let (entries, stats) = collect(&train)?;
    let table: BTreeMap<Fingerprint, &OwnedEntry> =
        entries.iter().map(|e| (e.fingerprint, e)).collect();

    eprintln!(
        "catalogue: {} entries from {} module(s) ({} ambiguous dropped)\n",
        stats.kept,
        train.len(),
        stats.ambiguous
    );
    eprintln!(
        "{:<34} {:>10} {:>10} {:>8}  {:>12}",
        "held-out module", "library fn", "identified", "rate", "false pos"
    );

    let (mut total, mut found, mut wrong) = (0_usize, 0_usize, 0_usize);
    for path in &test {
        let module = load(path)?;
        let (mut n, mut hit, mut fp) = (0_usize, 0_usize, 0_usize);
        for f in &module.functions {
            let Some(sig) = f.fingerprint else { continue };
            let matched = table.get(&sig);
            if f.origin.is_some() {
                n += 1;
                if matched.is_some() {
                    hit += 1;
                }
            } else if matched.is_some() {
                // The failure that matters: the contract author's own code
                // identified as library, which would license deleting it.
                fp += 1;
                eprintln!("  FALSE POSITIVE  {} -> {}", f.symbol, matched.map_or("?", |e| &e.path));
            }
        }
        let name = path.file_name().map_or_else(|| path.as_os_str(), |n| n);
        eprintln!(
            "{:<34} {:>10} {:>10} {:>7.1}% {:>12}",
            name.to_string_lossy(),
            n,
            hit,
            percent(hit, n),
            fp
        );
        total += n;
        found += hit;
        wrong += fp;
    }

    eprintln!(
        "\n{:<34} {:>10} {:>10} {:>7.1}% {:>12}",
        "TOTAL",
        total,
        found,
        percent(found, total),
        wrong
    );
    if wrong > 0 {
        return Err(format!(
            "{wrong} false positive(s): user code identified as library"
        ));
    }
    Ok(())
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        100.0 * part as f64 / whole as f64
    }
}

/// Render the generated table.
///
/// Deterministic by construction: entries arrive sorted by fingerprint and
/// nothing here consults a hash map's iteration order, so regenerating from
/// the same corpus produces byte-identical output.
fn render_table(entries: &[OwnedEntry]) -> String {
    let mut s = String::new();
    s.push_str(
        "//! Generated by `siggen` — do not edit.\n\
         //!\n\
         //! Rebuild with:\n\
         //!\n\
         //! ```text\n\
         //! cargo run -p sordec-sigs --bin siggen -- generate \\\n\
         //!   --out crates/sordec-sigs/src/generated.rs <labelled.wasm>...\n\
         //! ```\n\
         //!\n\
         //! Entries are sorted by fingerprint for binary search, and any\n\
         //! fingerprint claimed by two different functions has been dropped\n\
         //! rather than arbitrated. See [`crate::catalogue`].\n\n",
    );
    s.push_str("use crate::catalogue::{CrateOrigin, SigEntry};\nuse crate::fingerprint::Fingerprint;\n\n");
    s.push_str("/// The catalogue, sorted by fingerprint.\n");
    s.push_str("pub static ENTRIES: &[SigEntry] = &[\n");
    for e in entries {
        s.push_str(&format!(
            "    SigEntry {{ fingerprint: Fingerprint(0x{:032x}), path: {:?}, origin: CrateOrigin::{:?}, insns: {} }},\n",
            e.fingerprint.to_u128(),
            e.path,
            e.origin,
            e.insns
        ));
    }
    s.push_str("];\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use sordec_sigs::CrateOrigin;

    fn owned(fp: u128, path: &str) -> OwnedEntry {
        OwnedEntry {
            fingerprint: Fingerprint(fp),
            path: path.to_owned(),
            origin: CrateOrigin::Sdk,
            insns: 7,
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        let entries = vec![owned(1, "sdk::a"), owned(2, "sdk::b")];
        assert_eq!(render_table(&entries), render_table(&entries));
    }

    #[test]
    fn rendered_table_contains_each_entry() {
        let out = render_table(&[owned(0xdead_beef, "soroban_sdk::storage::get")]);
        assert!(out.contains(&format!("0x{:032x}", 0xdead_beef_u128)));
        assert!(out.contains("soroban_sdk::storage::get"));
        assert!(out.contains("CrateOrigin::Sdk"));
    }

    /// The generated file must compile: a fingerprint is a `u128` literal
    /// and paths are `{:?}`-escaped, so a stray quote or an over-wide
    /// literal would be a build error in the crate that includes it.
    #[test]
    fn rendered_literals_are_well_formed() {
        let out = render_table(&[owned(u128::MAX, "sdk::has \"quotes\" and \\ backslash")]);
        assert!(out.contains(&format!("0x{:032x}", u128::MAX)));
        assert!(out.contains(r#"\"quotes\""#));
    }

    #[test]
    fn validate_args_split_on_the_separator() {
        let args: Vec<String> = ["--train", "a.wasm", "b.wasm", "--", "c.wasm"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let (train, test) = parse_validate(&args).unwrap();
        assert_eq!(train.len(), 2);
        assert_eq!(test.len(), 1);
    }

    #[test]
    fn validate_requires_both_sets() {
        let only_train: Vec<String> = ["--train", "a.wasm"].iter().map(|s| (*s).to_owned()).collect();
        assert!(parse_validate(&only_train).is_err());
    }

    #[test]
    fn generate_requires_an_output_path() {
        let args: Vec<String> = ["a.wasm"].iter().map(|s| (*s).to_owned()).collect();
        assert!(parse_generate(&args).is_err());
    }
}
