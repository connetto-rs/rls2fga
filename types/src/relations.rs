use serde::{Deserialize, Serialize};

use crate::prelude::*;
use crate::{RecordDescription, RelationName, TypeName};

/// What one model relation needs and whether one row can decide it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// The comparison with the caller's own value gating every record of this relation,
    /// whether or not one row decides them. `None` unless one gate source fills it.
    pub caller_gate: Option<CallerGate>,
}

/// A comparison between a value each record carries and one the caller supplies in every
/// check context, which a grant needs though the record's condition may also read the
/// request clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallerGate {
    /// Context key each record carries the row's side under.
    pub context_key: String,
    /// Parameter the caller supplies its own value as, in every check context.
    pub request_parameter: String,
    /// How the two sides are compared.
    pub comparison: RequestComparison,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        /// The comparison the caller's value completes, identical to that relation's own
        /// [`RelationShapes::caller_gate`]. The records' condition reads nothing else.
        gate: CallerGate,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum RequestComparison {
    /// The caller's set has to hold the row's value.
    CallerSetHolds,
    /// The caller's single value has to equal the row's.
    CallerValueEquals,
    /// The caller's single value has to differ from the row's, which `PostgreSQL`'s
    /// `NULL` reading also fails, so an unset setting denies.
    CallerValueUnequals,
}

/// A function `PostgreSQL` applies to a request value before comparing it, whose result
/// the caller sends under a key of its own.
///
/// The result follows the database's collation, which CEL cannot read, so the caller
/// asks the database the policies run in for it rather than computing it itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestNormalization {
    /// `lower(value)`.
    Lower,
}

impl RequestNormalization {
    /// The `pg_catalog` function the policy applies, which the caller applies the same
    /// way.
    #[must_use]
    pub fn function_name(self) -> &'static str {
        match self {
            Self::Lower => "lower",
        }
    }
}

/// A predicate over the values the caller supplies in every check context.
///
/// In canonical form children are sorted and distinct, an [`Self::Any`] never directly
/// holds another [`Self::Any`] nor an [`Self::All`] another [`Self::All`], and either holds
/// at least two children.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum RequestPredicate {
    /// One test of a request value against a constant the policy names.
    Holds(RequestAtom),
    /// The request carries a value the deployment lets it leave unset, its key present in
    /// the `settings` map with a value other than `''`.
    Carries {
        /// Parameter the caller supplies the value as, in every check context.
        request_parameter: String,
    },
    /// The request leaves a value the deployment lets it leave unset absent, its key
    /// missing from the `settings` map or holding `''`, which the policy's `NULLIF` read
    /// reads as `NULL`.
    Omits {
        /// Parameter the caller would supply the value as.
        request_parameter: String,
    },
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

/// One source of a fallback read, in the order `PostgreSQL` tries them.
///
/// The caller's value falls back through the sources one by one, and the value the first
/// source hands over stands. `PostgreSQL` reads an unset setting as `NULL`, which a
/// source wrapped in `NULLIF` skips on, and a `NULLIF` without the skip would not, so a
/// source that stops the fallback on an unset setting may read more strictly than the
/// database does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FallbackStep {
    /// Setting the source reads, as the deployment spells it.
    pub setting_key: String,
    /// Parameter carrying the source's value, in every check context.
    pub parameter: String,
    /// True for a source taken from a field of a caller value, which is out of the
    /// fallback whenever the caller does not send that value at all or does not send it
    /// as `JSON`.
    pub from_json_field: bool,
    /// True when the source is wrapped in `NULLIF`, and so the empty value and the unset
    /// one both keep the fallback going.
    pub skips_empty: bool,
    /// True when the deployment can read the setting as unset, and an unset read may
    /// fall through where the model's stops.
    pub may_be_unset: bool,
}

/// One test of a request value against a constant the policy names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RequestAtom {
    /// Parameter the caller supplies its value as, in every check context.
    pub request_parameter: String,
    /// How the caller's value is compared against [`Self::value`]. `PostgreSQL` reads an
    /// unset setting as `NULL`, which fails the test.
    pub comparison: RequestComparison,
    /// The constant the policy names.
    pub value: String,
    /// When non-empty, the settings the caller's value falls back across, one per setting
    /// in the order the policy reads them. Empty for one single read.
    pub fallback: Vec<FallbackStep>,
}

/// A principal other than the caller a request acts for, such as the app installation
/// acting for a user.
///
/// A check whose `settings` map carries [`Self::request_parameter`] states the principal
/// with the contextual tuple `(<caller>, <relation>, <object>)`, the caller being the
/// check's own subject and the object [`Self::object`] of the identity the map carries. A
/// check whose map leaves it out sends no such tuple, and a grant to the principal then
/// reaches nobody, as `PostgreSQL` keeps no row comparing a column with `NULL`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestPrincipal {
    /// Setting carrying the principal's identity, as the deployment spells it.
    pub setting_key: String,
    /// Parameter the identity travels under in the check's `settings` map, in the canonical
    /// text of the type the deployment declares it in.
    pub request_parameter: String,
    /// The type the principal is an object of.
    pub principal_type: TypeName,
    /// The relation on that type holding whoever acts for the principal.
    pub relation: RelationName,
}

impl RequestPrincipal {
    /// The object naming the principal whose identity is `identity`, spelled as the tuple
    /// loader spells the grants naming it.
    #[must_use]
    pub fn object(&self, identity: &str) -> String {
        format!(
            "{}:{}",
            self.principal_type,
            crate::identity::encode_part(identity)
        )
    }
}
