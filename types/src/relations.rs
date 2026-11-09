use crate::prelude::*;
use crate::{RecordDescription, RelationName, TypeName};

/// What one model relation needs and whether one row can decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationShapes {
    /// `OpenFGA` type the relation is defined on.
    pub type_name: TypeName,
    /// Relation name.
    pub relation: RelationName,
    /// True only when every leaf resolves from the object's own row, to a named user or
    /// to every user. False whenever the analysis cannot establish that, including every
    /// case it does not understand.
    pub from_one_row: bool,
    /// The shapes whose records fill this relation, one per query the loader runs
    /// for it. Empty for a relation the model computes from others, and for one
    /// nothing populates.
    pub shapes: Vec<RecordDescription>,
    /// How the subjects this relation grants compose from one row, `Some` exactly
    /// when `from_one_row` is true.
    pub decision: Option<RowDecision>,
    /// Whether the model refuses this relation for every row, so no record fills it and
    /// no round trip is needed to be told no. False for a direct relation, which grants
    /// whatever is written into it.
    pub grants_nobody: bool,
}

/// How the subjects a relation grants compose from one row's records.
///
/// The whole evaluation: [`Self::Leaf`] is the union of the subjects
/// [`crate::records_from_row`] yields over its shapes, [`Self::Everyone`] every user when
/// those shapes yield any record, [`Self::Any`] is the union of its children and
/// [`Self::All`] their intersection.
///
/// Exhaustive on purpose, so a consumer that has not learned a new shape fails to compile
/// rather than treating it as one it knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowDecision {
    /// The subjects are the records these shapes produce for this row.
    Leaf {
        /// The direct relation whose records answer. Always on the same type.
        relation: RelationName,
        /// The shapes filling it, identical to that relation's own entry. Never empty.
        shapes: Vec<RecordDescription>,
    },
    /// Every user, on a row for which at least one of the shapes yields a record.
    ///
    /// The records name the typed wildcard, so matching their subject against a caller's
    /// name refuses everybody.
    Everyone {
        /// The direct relation whose records answer. Always on the same type.
        relation: RelationName,
        /// The shapes filling it, identical to that relation's own entry. Never empty.
        shapes: Vec<RecordDescription>,
    },
    /// A subject any child grants.
    Any(Vec<RowDecision>),
    /// A subject every child grants.
    All(Vec<RowDecision>),
    /// The row settles one side of a comparison the caller's own request value
    /// completes, so a consumer holding that value decides with no round trip.
    ///
    /// Taking the subjects at face value is a wrong allow: the shapes here yield
    /// `user:*`, which grants everyone until the comparison is applied.
    RequestGated {
        /// The direct relation whose records carry the row's side. Always on the same
        /// type.
        relation: RelationName,
        /// The shapes filling it, identical to that relation's own entry. Never empty.
        shapes: Vec<RecordDescription>,
        /// Context key each record carries the row's side under.
        context_key: String,
        /// Parameter the caller supplies its own value as, in every check context.
        request_parameter: String,
        /// How the two sides are compared.
        comparison: RequestComparison,
    },
    /// Every subject of `subject_type` on a row that yields its link, while the caller's
    /// request satisfies the predicate. The predicate reads no column,
    /// so it decides every row of the type alike.
    Request {
        /// The direct relation linking the row to the object holding its request gates.
        /// Always on the same type.
        relation: RelationName,
        /// The shapes filling that link, identical to that relation's own entry. Never
        /// empty.
        shapes: Vec<RecordDescription>,
        /// The type the gate admits, as its typed wildcard. A subject of any other type,
        /// and any userset, is refused.
        subject_type: TypeName,
        /// What the caller's request has to satisfy.
        predicate: RequestPredicate,
    },
}

/// How a request-gated relation compares the row's side against the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestComparison {
    /// The caller's set has to hold the row's value.
    CallerSetHolds,
    /// The caller's single value has to equal the row's.
    CallerValueEquals,
    /// The caller's single value has to differ from the row's, which `PostgreSQL`'s
    /// `NULL` reading also fails, so an unset setting denies.
    CallerValueUnequals,
}

/// A predicate over the values the caller supplies in every check context.
///
/// In canonical form children are sorted and distinct, an [`Self::Any`] never directly
/// holds another [`Self::Any`] nor an [`Self::All`] another [`Self::All`], and either holds
/// at least two children.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestPredicate {
    /// One test of a request value against a constant the policy names.
    Holds(RequestAtom),
    /// The request acts as this `PostgreSQL` role, which a check states with the
    /// contextual tuple `(user:<subject>, usage, pg_role:<role>)`.
    ActsAs {
        /// The role's name as the deployment spells it.
        role: String,
    },
    /// Any child holds.
    Any(Vec<RequestPredicate>),
    /// Every child holds.
    All(Vec<RequestPredicate>),
}

/// One test of a request value against a constant the policy names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestAtom {
    /// Parameter the caller supplies its value as, in every check context.
    pub request_parameter: String,
    /// How the caller's value is compared against [`Self::value`]. `PostgreSQL` reads an
    /// unset setting as `NULL`, which fails the test.
    pub comparison: RequestComparison,
    /// The constant the policy names.
    pub value: String,
}
