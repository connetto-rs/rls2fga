use crate::prelude::*;
use crate::{ColumnName, RelationName};
use core::fmt;
use serde::{Deserialize, Serialize};

fn member_relation() -> RelationName {
    RelationName::canonicalized("member")
}

/// Which kind of membership in a role a policy asked about.
///
/// `pg_has_role` answers a different question per kind, verified against `PostgreSQL` 18.1
/// over six ways of granting one role: a member granted `NOINHERIT` holds `Member` and `SetRole`
/// but not `Usage`, a member granted `WITH SET FALSE` holds `Member` and `Usage` but not
/// `SetRole`, and only a member granted `WITH ADMIN OPTION` holds `AdminOption`. The kind
/// written before `WITH ADMIN OPTION` makes no difference to the answer, so all three of those
/// spellings are one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RolePrivilege {
    /// A member of the role, directly or through a chain of grants.
    Member,
    /// A member whose privileges apply without `SET ROLE`, so every grant in the chain
    /// inherits. This is `has_privs_of_role`, the test a `TO` clause applies.
    Usage,
    /// A member who may `SET ROLE` to it.
    SetRole,
    /// A holder of the role's admin option.
    AdminOption,
}

impl RolePrivilege {
    /// Relation on the `pg_role` type holding the facts this kind needs.
    ///
    /// One relation per kind, since the sets differ: sharing one would make the operator's
    /// facts mean whichever policy the reader happened to look at.
    #[must_use]
    pub fn relation_name(self) -> RelationName {
        match self {
            Self::Member => member_relation(),
            Self::Usage => RelationName::canonicalized("usage"),
            Self::SetRole => RelationName::canonicalized("set_role"),
            Self::AdminOption => RelationName::canonicalized("admin_option"),
        }
    }

    /// Parse the privilege argument of `pg_has_role`, or `None` when it names no kind the
    /// crate can act on. `PostgreSQL` compares case insensitively and ignores surrounding
    /// space, and answers false for a string it does not know, so refusing one falls closed
    /// the same way.
    #[must_use]
    pub fn parse(argument: &str) -> Option<Self> {
        let normalized = argument.trim().to_ascii_uppercase();
        let kind = normalized
            .strip_suffix("WITH ADMIN OPTION")
            .map(str::trim_end);
        if let Some(kind) = kind {
            return matches!(kind, "MEMBER" | "USAGE" | "SET").then_some(Self::AdminOption);
        }
        match normalized.as_str() {
            "MEMBER" => Some(Self::Member),
            "USAGE" => Some(Self::Usage),
            "SET" => Some(Self::SetRole),
            _ => None,
        }
    }
}

/// Comparison an attribute guard applies.
///
/// `#[non_exhaustive]` permits more operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttributeOperator {
    /// `=`
    Eq,
    /// `<>`
    NotEq,
    /// `>`
    Gt,
    /// `>=`
    GtEq,
    /// `<`
    Lt,
    /// `<=`
    LtEq,
}

impl AttributeOperator {
    /// SQL spelling.
    #[must_use]
    pub fn sql(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::NotEq => "<>",
            Self::Gt => ">",
            Self::GtEq => ">=",
            Self::Lt => "<",
            Self::LtEq => "<=",
        }
    }

    /// `CEL` spelling.
    #[must_use]
    pub fn cel(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::NotEq => "!=",
            Self::Gt => ">",
            Self::GtEq => ">=",
            Self::Lt => "<",
            Self::LtEq => "<=",
        }
    }

    /// Spelling for a generated name, where no operator character may appear.
    #[must_use]
    pub fn gate_token(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::NotEq => "ne",
            Self::Gt => "gt",
            Self::GtEq => "ge",
            Self::Lt => "lt",
            Self::LtEq => "le",
        }
    }

    /// Which compressed value witnesses this comparison.
    #[must_use]
    pub fn context_witness(self) -> ContextWitness {
        match self {
            Self::Eq | Self::NotEq | Self::Gt | Self::GtEq => ContextWitness::Latest,
            Self::Lt | Self::LtEq => ContextWitness::Earliest,
        }
    }

    /// Whether collapsing several rows into one witness loses no match,
    /// false for `=`/`<>`, which can miss a different row that also matches.
    #[must_use]
    pub fn is_monotone(self) -> bool {
        match self {
            Self::Gt | Self::GtEq | Self::Lt | Self::LtEq => true,
            Self::Eq | Self::NotEq => false,
        }
    }
}

/// Which value of a compressed column witnesses the comparison when several
/// rows collapse into one fact, sound either way since it is a real row's
/// value but complete only where [`AttributeOperator::is_monotone`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContextWitness {
    /// `MAX`, exact for `>`/`>=`. `=`/`<>` select it too but need a per-row witness.
    Latest,
    /// `MIN`, exact for past comparisons.
    Earliest,
}

/// A literal constant an attribute guard compares against.
///
/// A number keeps its source spelling, so the generated SQL reproduces the literal
/// the policy wrote rather than a reformatted one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttributeLiteral {
    /// A string literal.
    Text(String),
    /// A numeric literal, unparsed.
    Number(String),
    /// `TRUE` or `FALSE`.
    Boolean(bool),
}

/// What an attribute guard asks of its column, against literal constants only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttributeTest {
    /// The column compares as stated against one literal.
    Compare {
        /// Comparison applied, oriented with the column on the left.
        operator: AttributeOperator,
        /// The literal the column is compared against.
        value: AttributeLiteral,
    },
    /// The column equals one of the literals, as SQL `IN` decides it.
    In(Vec<AttributeLiteral>),
}

/// A column tested against literal constants, which the row alone decides.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttributePredicate {
    /// Column the guard reads, folded to its stored name.
    pub column: ColumnName,
    /// What the column must satisfy.
    pub test: AttributeTest,
}

/// Confidence level for a classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Lowest confidence: unrecognised or unsupported expression.
    D,
    /// Low confidence: partially recognised (e.g. ABAC crossover).
    C,
    /// Medium confidence: composite patterns where sub-parts are well-understood.
    B,
    /// Highest confidence: fully recognised, single-pattern expression.
    A,
}

impl fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfidenceLevel::A => write!(f, "A"),
            ConfidenceLevel::B => write!(f, "B"),
            ConfidenceLevel::C => write!(f, "C"),
            ConfidenceLevel::D => write!(f, "D"),
        }
    }
}

impl core::str::FromStr for ConfidenceLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(ConfidenceLevel::A),
            "B" => Ok(ConfidenceLevel::B),
            "C" => Ok(ConfidenceLevel::C),
            "D" => Ok(ConfidenceLevel::D),
            _ => Err(format!("Invalid confidence level: {s}")),
        }
    }
}
