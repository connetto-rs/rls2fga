#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
// Panic-free policy for library code: the crate ingests untrusted SQL, so a
// panic is a robustness bug. Scoped to the non-test build of this crate;
// unit tests (`cfg(test)`) and the separate integration-test crates keep the
// ergonomic `unwrap`/`expect`.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::todo,
        clippy::unimplemented
    )
)]

extern crate alloc;

/// Re-exports of `alloc` types and macros that live in the `std` prelude but
/// not the `core` prelude, so modules can `use crate::no_std_prelude::*` and
/// compile in both `std` and `no_std` builds.
#[cfg(not(feature = "std"))]
pub(crate) mod no_std_prelude {
    pub(crate) use alloc::{
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}

/// Reusable output contracts and row evaluation without parser dependencies.
///
/// ```compile_fail
/// use rls2fga::generator::records::Record;
/// ```
///
/// ```compile_fail
/// use rls2fga::generator::relations::RelationShapes;
/// ```
///
/// ```compile_fail
/// use rls2fga::generator::action_relations::ActionRelations;
/// ```
///
/// ```compile_fail
/// use rls2fga::generator::row_naming::RowNaming;
/// ```
///
/// ```compile_fail
/// use rls2fga::generator::notes::TranslationNote;
/// ```
///
/// ```compile_fail
/// use rls2fga::parser::identifiers::TableId;
/// ```
///
/// ```compile_fail
/// use rls2fga::classifier::patterns::ConfidenceLevel;
/// ```
pub use rls2fga_types as types;
pub use rls2fga_types::stable_hex_suffix;

/// RLS expression classification: pattern matching, function registry, and confidence scoring.
pub mod classifier;
/// Writing a generated model to a running `OpenFGA` server. Needs the `client` feature.
#[cfg(feature = "client")]
pub mod client;
/// The request clock a guard reads, and the thresholds a checker supplies for it.
pub mod clock;
/// `OpenFGA` model generation from classified policies (DSL, JSON, and tuple SQL).
pub mod generator;
/// File output and markdown report generation.
pub mod output;
/// SQL schema parsing and function body analysis.
pub mod parser;
/// Compiling one subscription filter, rather than a whole schema's policies.
pub mod term;
/// High-level builder/facade for classification and `OpenFGA` translation.
pub mod translator;

#[cfg(test)]
pub(crate) mod test_support;
