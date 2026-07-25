//! Error type for the scorer.

/// Reason a scoring run failed.
///
/// `#[non_exhaustive]` so later stages (the loader's multi-file flatten,
/// the compilation harness) can add variants without breaking matchers.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ScoreError {
    /// One of the two inputs could not be read from disk.
    #[error("could not read {path}: {source}")]
    Io {
        /// The path we failed to read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// One of the two inputs was not parseable Rust. `side` names which
    /// input (`"reconstructed"` or `"original"`) so the caller can point
    /// the user at the right file.
    #[error("could not parse {side} source: {source}")]
    Parse {
        /// Which side failed (`"reconstructed"` / `"original"`).
        side: &'static str,
        /// The `syn` parse error.
        source: syn::Error,
    },

    /// A weights profile could not be parsed or was invalid. `reason`
    /// carries the flattened TOML-parse or validation message; the `toml`
    /// error type is deliberately not exposed so the public API stays stable
    /// if the config format ever changes.
    #[error("invalid weights profile {path}: {reason}")]
    Config {
        /// The profile's origin — a file path, or a marker like `"<inline>"`.
        path: String,
        /// What was wrong (a TOML-parse error or a validation failure).
        reason: String,
    },
}
