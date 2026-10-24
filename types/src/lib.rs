//! Parser-independent output contracts and row evaluation.
//!
//! A type or relation name cannot be built from an unresolved spelling. Object and subject
//! names are strings, encoded in one place by [`identity`].
//!
//! ```compile_fail
//! use rls2fga_types::{RelationName, TypeName};
//! let _ = TypeName::from_resolved("not valid");
//! let _ = RelationName::from_resolved("not valid");
//! ```

#![no_std]
#![warn(missing_docs)]
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

mod action_relations;
mod identifiers;
/// One place a database value becomes the name of an object.
///
/// `OpenFGA` refuses some values outright and silently reinterprets others, so every name
/// either side of the pipeline renders passes through here. A second spelling anywhere
/// reintroduces the drift this exists to close.
pub mod identity;
mod notes;
mod patterns;
mod records;
mod relations;
mod row_naming;
mod unrestricted;

pub use action_relations::{
    ActionAnswer, ActionJudgement, ActionRelations, ActionStatement, RowVersion,
};
pub use identifiers::{
    stable_hex_suffix, ColumnName, ConditionName, ConditionNameError, ConditionParameterName,
    ConditionParameterNameError, RelationName, RelationNameError, TableId, TableRef, TypeName,
    TypeNameError,
};
pub use notes::{NoteSeverity, TranslationNote};
pub use patterns::{
    AttributeLiteral, AttributeOperator, AttributePredicate, AttributeTest, ConfidenceLevel,
    ContextWitness, RolePrivilege,
};
pub use records::{
    records_from_row, BoundQuery, BoundQueryError, ColumnKind, ColumnRead, ContextRendering, Guard,
    ObjectKey, Record, RecordContext, RecordContextEntry, RecordContextValue, RecordDerivation,
    RecordDescription, RecordError, RecordTemplate, ReplayScope, RowCell, RowList, RowValues,
    SubjectKey, ValueSource,
};
pub use relations::{
    RelationShapes, RequestAtom, RequestComparison, RequestPredicate, RowDecision,
};
pub use row_naming::RowNaming;
pub use unrestricted::UnrestrictedTable;

pub(crate) mod prelude {
    pub(crate) use alloc::{
        boxed::Box,
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
}
