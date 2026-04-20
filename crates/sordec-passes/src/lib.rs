//! Pass-based middle-end for the sordec pipeline.
//!
//! Every transformation — lifting, normalization, data-flow analysis, type
//! inference, pattern recognition, structuring — is implemented as a
//! `Pass` that takes IR, either refines it (reducing Unknowns or raising
//! confidence) or leaves it unchanged. Passes run to fixpoint.
//!
//! Passes are monotonic: they may add information or refine existing
//! information, but must never contradict or remove valid information.
