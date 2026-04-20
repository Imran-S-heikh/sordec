//! Frontend: parse raw WASM bytes and decode Soroban metadata.
//!
//! This crate takes a `.wasm` file and produces typed IR facts — the input
//! to the rest of the pipeline. It extracts module sections, imports,
//! exports, and Soroban custom sections (contractspecv0, contractenvmetav0,
//! contractmetav0).
