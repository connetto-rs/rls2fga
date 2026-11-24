#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;
use core::fmt;
use serde::{Deserialize, Serialize};
use sql_traits::errors::{LookupError, PolicyClauseError};
use sql_traits::structs::{PolicyClause, PolicyExpression, PolicyTarget};
use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType, Expr};

use crate::classifier::function_registry::DeclaredSource;
use crate::clock::ClockThreshold;
use crate::parser::column_type_casts::without_column_type_casts;
use crate::parser::names::table_identity;
use crate::parser::sql_parser::{DatabaseLike, IdentifierCase, PolicyLike};
pub(crate) use crate::types::{
    AttributeLiteral, AttributeOperator, AttributePredicate, AttributeTest, ColumnName,
    ConfidenceLevel, PolicyCommand, RolePrivilege, TableId,
};
use crate::types::{FallbackStep, TypeName};

/// Policy combination mode in `PostgreSQL` RLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyMode {
    /// OR-combined policy branch.
    Permissive,
    /// AND-combined policy branch.
    Restrictive,
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyMode::Permissive => write!(f, "PERMISSIVE"),
            PolicyMode::Restrictive => write!(f, "RESTRICTIVE"),
        }
    }
}

impl From<CreatePolicyType> for PolicyMode {
    fn from(value: CreatePolicyType) -> Self {
        match value {
            CreatePolicyType::Permissive => PolicyMode::Permissive,
            CreatePolicyType::Restrictive => PolicyMode::Restrictive,
        }
    }
}

/// Comparison operator for numeric threshold checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThresholdOperator {
    /// `>= N`
    Gte,
    /// `> N`
    Gt,
}

/// Boolean operator for composite patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoolOp {
    /// Logical conjunction: all sub-conditions must hold.
    And,
    /// Logical disjunction: at least one sub-condition must hold.
    Or,
}

/// A column compared against the request clock, which no static tuple can decide. The
/// row supplies the column, the caller supplies the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeRequestPredicate {
    /// Column the guard reads, folded to its stored name.
    pub column: ColumnName,
    /// Comparison applied, oriented with the column on the left.
    pub operator: AttributeOperator,
    /// The clock reading the column is compared with, from `now()`, `current_date` or
    /// `localtimestamp`, shifted by any interval such as `now() - interval '36 hours'`.
    pub threshold: ClockThreshold,
}

/// One residual conjunct on a membership row.
///
/// The SQL is the policy's own spelling but for the names the generator has to resolve, so
/// the query it renders reads what the policy meant under any `search_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualPredicate {
    /// The conjunct as SQL, join-table qualifiers stripped and any relation it reads
    /// spelled as the catalog carries it.
    pub sql: String,
    /// The conjunct as structure, when a row image alone decides it.
    pub guard: Option<ResidualGuard>,
    /// The conjunct as a request-completed comparison, when the row settles one side
    /// and the clock the other. A temporal guard such as `expires_at > now()` is
    /// nobody's to decide from the row alone, so it becomes a condition, not a tuple.
    pub request: Option<AttributeRequestPredicate>,
    /// The relations the conjunct reads, each proven to show every row to everybody.
    ///
    /// Empty for the residual a row or a request decides, which reads none. Non-empty
    /// means the loader's one evaluation is every caller's, and the records the shape
    /// produces depend on rows the changed row does not name.
    pub relations: Vec<TableId>,
}

/// A residual conjunct a row image can evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResidualGuard {
    /// A bare boolean column, admitting only rows where it is true.
    IsTrue(ColumnName),
    /// `IS NOT NULL` on a column.
    NotNull(ColumnName),
    /// A column tested against literal constants.
    Compare(AttributePredicate),
}

/// Every residual conjunct of a membership shape, possibly none.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResidualPredicates(Vec<ResidualPredicate>);

impl ResidualPredicates {
    /// The conjuncts in policy order.
    #[must_use]
    pub fn new(conjuncts: Vec<ResidualPredicate>) -> Self {
        Self(conjuncts)
    }

    /// These conjuncts followed by `more`, all holding at once.
    #[must_use]
    pub(crate) fn and(&self, more: &[ResidualPredicate]) -> Self {
        Self(self.0.iter().chain(more).cloned().collect())
    }

    /// These conjuncts but the ones the request clock completes.
    #[must_use]
    pub(crate) fn without_requests(&self) -> Self {
        Self(
            self.0
                .iter()
                .filter(|conjunct| conjunct.request.is_none())
                .cloned()
                .collect(),
        )
    }

    /// True when the shape carries no residual at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn sql_conjuncts(
        &self,
        include_requests: bool,
    ) -> impl Iterator<Item = &str> + Clone {
        self.0
            .iter()
            .filter(move |conjunct| include_requests || conjunct.request.is_none())
            .map(|conjunct| conjunct.sql.as_str())
    }

    fn joined_sql(&self, include_requests: bool) -> Option<String> {
        let mut conjuncts = self.sql_conjuncts(include_requests);
        let first = conjuncts.next()?;
        let capacity = first.len()
            + conjuncts
                .clone()
                .map(|conjunct| 5 + conjunct.len())
                .sum::<usize>();
        let mut sql = String::with_capacity(capacity);
        sql.push_str(first);
        for conjunct in conjuncts {
            sql.push_str(" AND ");
            sql.push_str(conjunct);
        }
        Some(sql)
    }

    /// The residual as the SQL filter the policy wrote, or [`None`] when
    /// there is none.
    #[must_use]
    pub fn sql(&self) -> Option<String> {
        self.joined_sql(true)
    }

    /// One guard per conjunct, or [`None`] when any conjunct has no
    /// structure, in which case only SQL can evaluate the residual.
    #[must_use]
    pub fn guards(&self) -> Option<Vec<ResidualGuard>> {
        self.0
            .iter()
            .map(|conjunct| conjunct.guard.clone())
            .collect()
    }

    /// The request-completed conjuncts, each a comparison the clock finishes.
    #[must_use]
    pub fn requests(&self) -> Vec<AttributeRequestPredicate> {
        self.0
            .iter()
            .filter_map(|conjunct| conjunct.request.clone())
            .collect()
    }

    /// Whether a conjunct is a comparison the clock finishes.
    #[must_use]
    pub fn has_requests(&self) -> bool {
        self.0.iter().any(|conjunct| conjunct.request.is_some())
    }

    /// The row-decidable conjuncts as guards, ignoring request-completed and SQL-only
    /// ones. Total, unlike [`Self::guards`], so a caller that has already separated the
    /// requests takes the guards without a second fallible pass.
    #[must_use]
    pub fn row_guards(&self) -> Vec<ResidualGuard> {
        self.row_guard_refs().cloned().collect()
    }

    /// [`Self::row_guards`], borrowed.
    pub(crate) fn row_guard_refs(&self) -> impl Iterator<Item = &ResidualGuard> {
        self.0.iter().filter_map(|conjunct| conjunct.guard.as_ref())
    }

    /// The residual as the SQL filter with the request-completed conjuncts dropped,
    /// since those move into the condition. [`None`] when nothing is left to filter.
    #[must_use]
    pub fn sql_excluding_requests(&self) -> Option<String> {
        self.joined_sql(false)
    }

    /// Every relation the residual reads, sorted and deduplicated.
    ///
    /// Empty where the row and the request decide it all. Non-empty is what makes the
    /// records depend on rows no changed row names, so a consumer reconciling one row's
    /// slice would leave the rest standing.
    #[must_use]
    pub fn relations(&self) -> Vec<TableId> {
        let mut relations: BTreeSet<TableId> = BTreeSet::new();
        for conjunct in &self.0 {
            relations.extend(conjunct.relations.iter().cloned());
        }
        relations.into_iter().collect()
    }

    /// The residual split into row guards and request-completed comparisons, or
    /// [`None`] when a conjunct is neither: only SQL can evaluate it, so the shape
    /// stays joined.
    #[must_use]
    pub fn decidable(&self) -> Option<ResidualDecision> {
        let mut guards = Vec::new();
        let mut requests = Vec::new();
        for conjunct in &self.0 {
            match (&conjunct.guard, &conjunct.request) {
                (Some(guard), _) => guards.push(guard.clone()),
                (None, Some(request)) => requests.push(request.clone()),
                (None, None) => return None,
            }
        }
        Some(ResidualDecision { guards, requests })
    }

    /// The conjuncts the residual holds, consumed.
    #[must_use]
    pub(crate) fn into_conjuncts(self) -> Vec<ResidualPredicate> {
        self.0
    }
}

/// A residual every conjunct of which a row image or the request can evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualDecision {
    /// Conjuncts a row image alone decides, in policy order.
    pub guards: Vec<ResidualGuard>,
    /// Conjuncts the request completes, in policy order.
    pub requests: Vec<AttributeRequestPredicate>,
}

/// P1: Numeric role threshold: `role_level(user, resource) >= N`.
#[derive(Debug, Clone, PartialEq)]
pub struct NumericThreshold {
    /// Role-level function called.
    pub function_name: String,
    /// Comparison used.
    pub operator: ThresholdOperator,
    /// Level the policy requires.
    pub threshold: i32,
    /// Command the threshold applies to.
    pub command: PolicyCommand,
    /// Column whose value the call passes as the resource, absent where it passes an
    /// expression instead. The grant is a fact about that value, so a translation reading
    /// any other column grants on a comparison the database never makes.
    pub resource_column: Option<ColumnName>,
}

/// P2: Role name IN-list: `role_name(user, resource) IN ('viewer', ...)`.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleNameInList {
    /// Role-name function called.
    pub function_name: String,
    /// Roles the list admits.
    pub role_names: Vec<String>,
    /// Column whose value the call passes as the resource, as
    /// [`NumericThreshold::resource_column`].
    pub resource_column: Option<ColumnName>,
}

/// P3: Direct column equality: `owner_id = current_user_id()`.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectOwnership {
    /// Column compared against the current user.
    pub column: ColumnName,
}

/// One equality pairing a join-table column with a guarded-table column.
#[derive(Debug, Clone, PartialEq)]
pub struct MembershipJoinPair {
    /// Column of the join table identifying the parent entity.
    pub join_column: ColumnName,
    /// Column of the guarded table the policy compares against `join_column`.
    pub outer_column: ColumnName,
}

/// P4: EXISTS subquery membership: `EXISTS (SELECT 1 FROM members ...)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExistsMembership {
    /// Table scanned in the subquery.
    pub join_table: TableId,
    /// The equalities linking the scanned table to the guarded table, ordered by
    /// the key that names the parent object.
    pub pairs: Vec<MembershipJoinPair>,
    /// Column of `join_table` holding the member the row grants to.
    pub user_column: ColumnName,
    /// Residual filter such as `role = 'admin'`, structured where a row
    /// image alone decides it.
    pub extra_predicates: ResidualPredicates,
}

/// P5: Parent permission inheritance through a foreign key.
#[derive(Debug, Clone, PartialEq)]
pub struct ParentInheritance {
    /// Parent table read by the policy.
    pub parent_table: TableId,
    /// Columns of the child table naming one `parent_table` row, in the order of the key
    /// that names its objects.
    pub fk_columns: Vec<ColumnName>,
    /// The parent-side rule the policy requires.
    pub inner_pattern: Box<ClassifiedExpr>,
}

/// P31: The guarded row is named by some row of another table the caller can read, which
/// also satisfies a rule of its own.
///
/// Each referring row is its own witness. Its readability and its rule are both decided
/// on that one row, so neither pools with another row naming the same guarded row.
#[derive(Debug, Clone, PartialEq)]
pub struct ReferringRows {
    /// Table whose rows name the guarded row.
    pub referring_table: TableId,
    /// Columns of `referring_table` naming one guarded row, in the order of the guarded
    /// table's key.
    pub referring_columns: Vec<ColumnName>,
    /// The rule a referring row has to satisfy besides being readable, a constant `TRUE`
    /// where the policy states none.
    pub inner_pattern: Box<ClassifiedExpr>,
}

/// A call to a declared function, replaced by that function's body with the
/// call-site arguments substituted. The classification is the body's.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpandedFunction {
    /// The called function, as declared.
    pub function: String,
    /// The body's table reads run as an owner `PostgreSQL` lets past those
    /// tables' policies, so membership readability is not the caller's question.
    pub reads_bypass_rls: bool,
    /// Row columns that must be non-null before the body can return true.
    pub presence_columns: Vec<ColumnName>,
    /// The substituted body's classification.
    pub inner: Box<ClassifiedExpr>,
}

/// P6: Boolean flag or public access: `is_public = TRUE`.
#[derive(Debug, Clone, PartialEq)]
pub struct BooleanFlag {
    /// Column controlling visibility.
    pub column: ColumnName,
    /// Whether the `PostgreSQL` predicate also admits SQL NULL.
    pub admits_null: bool,
}

/// P7: A relationship check AND an attribute guard.
#[derive(Debug, Clone, PartialEq)]
pub struct AbacAnd {
    /// The translatable relationship half.
    pub relationship_part: Box<ClassifiedExpr>,
    /// Column the attribute guard reads.
    pub attribute_part: String,
}

/// P8: `OR` or `AND` of two or more sub-patterns.
#[derive(Debug, Clone, PartialEq)]
pub struct Composite {
    /// Operator joining `parts`.
    pub op: BoolOp,
    /// Sub-patterns being combined.
    pub parts: Vec<ClassifiedExpr>,
}

/// P9: Standalone attribute condition: `status = 'published'`.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeCondition {
    /// Column the guard reads.
    pub column: ColumnName,
    /// Human-readable form of the compared value.
    pub value_description: String,
    /// The guard as structure, when the compared value is a literal constant and
    /// so is decided by the row alone.
    pub predicate: Option<AttributePredicate>,
    /// The guard as structure, when the compared value is one only the request
    /// knows. Such a guard becomes a condition rather than a tuple, since a tuple
    /// computed once would outlive the value it was computed against.
    pub request_predicate: Option<AttributeRequestPredicate>,
}

/// P10: Constant `TRUE` or `FALSE` policy.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstantBool {
    /// The constant.
    pub value: bool,
}

/// P11: The caller is an element of an array column: `current_user = ANY (editors)`.
///
/// Exact, not a widening: `UNNEST` enumerates precisely the rows `= ANY` admits.
#[derive(Debug, Clone, PartialEq)]
pub struct ArrayMembership {
    /// Array column holding the admitted principals.
    pub column: ColumnName,
}

/// P12: The caller is named by a jsonb field: `data ->> 'owner' = current_user`.
///
/// Exact: `->>` yields NULL for a missing key, a null value and a null column, and
/// the comparison then filters, which is what dropping the NULLs reproduces.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonbFieldOwnership {
    /// Column holding the document.
    pub column: ColumnName,
    /// Key chain to the field, the last hop extracted as text.
    pub path: Vec<String>,
}

/// P26: The caller equals an immutable function of one column of the row:
/// `lower(owner) = current_setting('app.user_id', true)`.
///
/// Only the database computes the function as the policy does, collation and all, so the
/// ownership tuple is read by a query keyed on the row rather than from a row image.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerExpression {
    /// The one column of the row the expression reads.
    pub column: ColumnName,
    /// The expression as SQL over the bare row, its column quoted and every call
    /// qualified by the schema of the one function it reaches.
    pub expression: String,
}

/// A membership check naming no column of the guarded table, so it admits every
/// row at once to whoever appears in the member table.
#[derive(Debug, Clone, PartialEq)]
pub struct UncorrelatedMembership {
    /// Table whose rows list the members.
    pub member_table: TableId,
    /// Column of that table holding the member.
    pub user_column: ColumnName,
    /// Any further condition the membership row has to satisfy, structured
    /// where a row image alone decides it.
    pub extra_predicates: ResidualPredicates,
}

/// The caller's declared set holds the row's value:
/// `owner = ANY(string_to_array(current_setting('app.subjects', true), ','))`.
#[derive(Debug, Clone, PartialEq)]
pub struct RowValueInCallerSet {
    /// Column whose value the set has to hold.
    pub column: ColumnName,
    /// Separator the policy splits the setting on, since it decides which elements
    /// exist and so what the caller has to send. Absent where the source is already
    /// a list, which has no delimiter and so no such hazard.
    pub separator: Option<String>,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
}

/// The caller's declared single value equals the row's:
/// `tenant_id = current_setting('app.tenant_id')::uuid`.
#[derive(Debug, Clone, PartialEq)]
pub struct RowValueEqualsCallerScalar {
    /// Column the value has to equal.
    pub column: ColumnName,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
}

/// The caller's declared set holds a constant the policy names, so no row takes part:
/// `'admin' = ANY(string_to_array(current_setting('app.roles', true), ','))`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstantInCallerSet {
    /// The constant the set has to hold.
    pub value: String,
    /// Separator the policy splits the setting on, absent for a list source.
    pub separator: Option<String>,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
}

/// The caller's declared single value equals a constant the policy names, so no row
/// takes part: `(SELECT auth.jwt() ->> 'aal') = 'aal2'`.
#[derive(Debug, Clone, PartialEq)]
pub struct CallerScalarEqualsConstant {
    /// The constant the value has to equal.
    pub value: String,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
}

/// The caller's declared single value differs from a constant the policy names, so no row
/// takes part: `current_setting('app.mode', true) <> 'main'`.
#[derive(Debug, Clone, PartialEq)]
pub struct CallerScalarUnequalsConstant {
    /// The constant the value has to differ from.
    pub value: String,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
}

/// The caller's declared single value is, or is not, one of the constants the policy
/// names, so no row takes part: `current_setting('app.mode', true) IN ('main', 'dev')`.
#[derive(Debug, Clone, PartialEq)]
pub struct CallerScalarInConstantList {
    /// The constants the policy names, in the order written.
    pub values: Vec<String>,
    /// Whether the policy negates the list, as `NOT IN` does.
    pub negated: bool,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
}

/// The request leaves a declared single value it may leave unset absent, so no row takes
/// part: `NULLIF(current_setting('app.installation_id', true), '') IS NULL`, or carries
/// it where negated, as `IS NOT NULL` does.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestValueAbsent {
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
    /// Whether the policy tests for the value instead, as `IS NOT NULL` does.
    pub negated: bool,
}

/// The value a fallback read hands over equals a constant the policy names: Supabase's
/// `auth.role() = 'authenticated'`, whose body reads
/// `COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), NULLIF
/// (current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')`.
#[derive(Debug, Clone, PartialEq)]
pub struct FallbackScalarEqualsConstant {
    /// The constant the policy names.
    pub value: String,
    /// The first source the read tries.
    pub first: FallbackStep,
    /// The sources the read falls back through after it, in the order the policy reads
    /// them.
    pub rest: Vec<FallbackStep>,
}

/// The value a fallback read hands over differs from a constant the policy names.
///
/// `PostgreSQL` reads an unset setting as `NULL`, which also differs from the constant,
/// so the unset reading admits where the model's denies, and the note says so.
#[derive(Debug, Clone, PartialEq)]
pub struct FallbackScalarUnequalsConstant {
    /// The constant the policy names.
    pub value: String,
    /// The first source the read tries.
    pub first: FallbackStep,
    /// The sources the read falls back through after it, in the order the policy reads
    /// them.
    pub rest: Vec<FallbackStep>,
}

/// The value a fallback read hands over is one of the constants the policy names, or is
/// not.
#[derive(Debug, Clone, PartialEq)]
pub struct FallbackScalarInConstantList {
    /// The constants the policy names, in the order written.
    pub values: Vec<String>,
    /// Whether the policy negates the list, as `NOT IN` does, which also admits on the
    /// unset reading `PostgreSQL` gives a source the model stops at.
    pub negated: bool,
    /// The first source the read tries.
    pub first: FallbackStep,
    /// The sources the read falls back through after it, in the order the policy reads
    /// them.
    pub rest: Vec<FallbackStep>,
}

/// A membership row whose member column holds a value the caller's declared set has
/// to contain: `EXISTS (SELECT 1 FROM shares s WHERE s.parent_id = t.id AND
/// s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ',')))`.
///
/// The membership is the one [`ExistsMembership`] describes, compared against the
/// caller's set rather than the caller. Who completes that comparison is the
/// generator's [`CallerSetCompletion`](crate::generator::model_generator::CallerSetCompletion).
#[derive(Debug, Clone, PartialEq)]
pub struct MembershipInCallerSet {
    /// The membership row and its bridge to the guarded row, whose
    /// [`user_column`](ExistsMembership::user_column) holds the value the set must contain.
    pub membership: ExistsMembership,
    /// Separator the policy splits the setting on, absent for a list source.
    pub separator: Option<String>,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
}

/// Membership reached through a closure table sharing the far table's declared owner key.
#[derive(Debug, Clone, PartialEq)]
pub struct IndirectMembership {
    /// The link table read first, one row per guarded row and owner.
    pub link_table: TableId,
    /// Link-to-guarded equalities in the guarded key's order.
    pub pairs: Vec<MembershipJoinPair>,
    /// The owner entity the link and far columns reference.
    pub owner_table: TableId,
    /// Link columns holding the owner key in primary-key order, aligned with each membership's pairs.
    pub owner_columns: Vec<ColumnName>,
    /// Far-table memberships with owner-key pairs and a residual for each listed role.
    pub memberships: Vec<ExistsMembership>,
    /// Residual filter on the link row itself.
    pub extra_predicates: ResidualPredicates,
}

/// A column compared with the set a declared `SECURITY DEFINER` helper returns, as in
/// `project_id = ANY (ARRAY(SELECT authz.projects_with('read')))`.
///
/// The helper reads as its owner, past every policy, so what it returns is the grant
/// rows and hierarchy rows its body names, which the tuple queries load the same way.
#[derive(Debug, Clone, PartialEq)]
pub struct DeclaredHelper {
    /// Column of the rows compared the set has to hold, the table's own key or a foreign
    /// key to the rows the set names.
    pub column: ColumnName,
    /// The call and what it returns.
    pub call: HelperCall,
}

/// The request's declared single value compared with the values a declared `SECURITY
/// DEFINER` helper returns to every caller alike, as in
/// `current_setting('app.installation_id', true) IN (SELECT
/// authz.installations_allowing('docs', 'select'))`.
///
/// The helper reads as its owner, so every value it returns is a row the tuple queries
/// load the same way, and the clause holds where the request's value equals one of them.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestValueInHelperSet {
    /// The declared single value, carrying the parameter the caller supplies.
    pub source: DeclaredSource,
    /// The helper, as declared.
    pub function: String,
    /// Its arguments, each a literal as SQL spells it.
    pub arguments: Vec<String>,
    /// The sets the call returns the union of, none where it returns nothing.
    pub arms: Vec<HelperValues>,
}

/// `SELECT <value column> FROM <table> [WHERE <predicates>]`, an arm comparing no column
/// with the request.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperValues {
    /// The table the arm reads.
    pub table: TableId,
    /// Column holding the values the arm returns.
    pub value_column: ColumnName,
    /// The conditions the body puts on the row, all holding at once.
    pub predicates: Vec<AttributePredicate>,
}

/// One call of a declared helper and the rows of `level` it returns, at the labels it is
/// read at where the helper returns labels beside its keys.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperCall {
    /// The helper, as declared.
    pub function: String,
    /// Its arguments, each a literal as SQL spells it.
    pub arguments: Vec<String>,
    /// The label each column of labels the helper returns beside its keys holds, each a
    /// literal as SQL spells it, in the order the helper returns those columns. Empty
    /// where the call returns its keys whatever labels they come with.
    pub labels: Vec<String>,
    /// The table whose keys the call returns.
    pub level: TableId,
    /// The sets whose union the call returns, none where it returns nothing. An arm may
    /// return keys of another table whose key references `level`'s, an organization or a
    /// team among the grantees, each of them a key of `level` too.
    pub arms: Vec<HelperSetArm>,
    /// The grant arms a walk's final query keeps the reached rows to, `None` where it
    /// keeps every one.
    pub selection: Option<Vec<HelperGrant>>,
}

/// One `SELECT` of a helper's body.
#[derive(Debug, Clone, PartialEq)]
pub enum HelperSetArm {
    /// The rows of a grant table naming a grantee.
    Grant(Box<HelperGrant>),
    /// The rows of the level whose parent another call returns.
    Parent(HelperParent),
    /// The rows of the level next to the ones this same call returns, along its tree.
    Walk(HelperWalk),
    /// The keys of the level another call returns, at the labels the arm reads it at.
    Called(HelperCall),
}

/// `SELECT <object columns> FROM <table> WHERE <grantee> [AND <rows>] [AND <time bounds>]
/// [AND <caps>]`.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperGrant {
    /// The grant table.
    pub table: TableId,
    /// Columns naming the object each grant is on, the one naming the level's row for an
    /// arm of a call, and one per column the helper returns for an arm of a cap, naming
    /// the pair it returns.
    pub object_columns: Vec<ColumnName>,
    /// Whose rows the arm keeps.
    pub grantee: HelperGrantee,
    /// The callers the arm keeps no row for, each as the caller identity a check sends,
    /// from `current_setting(<caller>) <> <value>`.
    pub excluded: Vec<String>,
    /// The caller the deployment lets a request leave unset, whose presence the arm's gate
    /// requires, so the arm keeps its rows only for a request carrying it. `None` where
    /// the arm keeps them whether the request carries a caller or not, and where it
    /// compares a column with the caller, which `PostgreSQL` matches with no row while
    /// the caller reads `NULL`.
    pub carried_caller: Option<DeclaredSource>,
    /// The declared single values the request has to leave absent for the arm to keep any
    /// row, all of them, from `<read> IS NULL` conjuncts of the arm.
    pub absent: Vec<DeclaredSource>,
    /// Which grant rows count.
    pub rows: GrantRows,
    /// The bounds a kept row meets against the statement time, all of them, which the
    /// request completes per check.
    pub time_bounds: Vec<HelperTimeBound>,
    /// The caps a kept row meets, all of them.
    pub caps: Vec<HelperCap>,
    /// The calls whose keys the level's row the arm returns has to be among, all of them,
    /// from `<key> IN (SELECT <function>(<arguments>))` on the arm's table's own key.
    pub within: Vec<HelperCall>,
    /// The sets the level's row or the pair the arm returns has to stay outside, all of
    /// them, from `NOT (<column> = ANY (ARRAY(SELECT <function>(<arguments>))))` on a
    /// column of the arm's table, its object column, which names the level's row, any
    /// column where the arm's row is the level's row, or one of the pair's columns for an
    /// arm of a cap.
    pub outside: Vec<DeclaredHelper>,
    /// Each row of the arm's table held as its own object, with the rows of other tables
    /// it names, `None` where the level's row, or the pair an arm of a cap returns, holds
    /// the grant.
    pub held: Option<HeldRows>,
}

/// The rows of a grant arm's table, each an object keyed by the table's own key, holding
/// the grant it makes while it meets its joins and caps, as a row it joins, a row that
/// blocks it, a set a column other than the level's row names has to stay outside, or a
/// cap reading more of it than the level's row names requires.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldRows {
    /// The key of the arm's table.
    pub identity: Vec<ColumnName>,
    /// The rows named through a `JOIN`, each of which has to meet its own predicates.
    pub joined: Vec<HelperJoin>,
    /// The rows named through a correlated `NOT EXISTS`, any of which meeting its own
    /// predicates takes the row away.
    pub blocked: Vec<HelperJoin>,
    /// The sets a column of the row has to stay outside, all of them, from `NOT (<column>
    /// = ANY (ARRAY(SELECT <function>(<arguments>))))`.
    pub outside: Vec<DeclaredHelper>,
}

/// The one row of `table` a grant arm's row names by its own columns, through a foreign
/// key for a `JOIN` and through equalities covering the key for a correlated `NOT EXISTS`.
///
/// A `NULL` among the columns names no row, which a `JOIN` drops and `NOT EXISTS` keeps.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperJoin {
    /// The joined or blocking table.
    pub table: TableId,
    /// The key of `table`.
    pub identity: Vec<ColumnName>,
    /// The columns of the arm's table naming the row, in the order of `identity`.
    pub columns: Vec<ColumnName>,
    /// What the named row has to hold, all of it.
    pub predicates: Vec<AttributePredicate>,
}

impl HelperGrant {
    /// The columns keying one tuple of the arm's relations, its object, the column naming
    /// its grantee where one does and, for a relation per role, its role.
    pub(crate) fn tuple_key(&self) -> Vec<&ColumnName> {
        self.tuple_key_naming(self.grantee.compared_column())
    }

    /// The columns keying one tuple of the arm's relations naming the grantee `grantee`
    /// holds, or every caller where there is no such column, as [`Self::tuple_key`] reads
    /// them.
    pub(crate) fn tuple_key_naming<'a>(
        &'a self,
        grantee: Option<&'a ColumnName>,
    ) -> Vec<&'a ColumnName> {
        let mut key: Vec<&ColumnName> = self.object_columns.iter().chain(grantee).collect();
        if let GrantRows::Roles { column, .. } = &self.rows {
            key.push(column);
        }
        key
    }
}

/// `[<lift> IS NULL OR] (<operands>) IN (SELECT * FROM <function>(<arguments>))` in a grant
/// arm's condition, keeping a row only where the pair its operands name is one the helper
/// returns, unless the request leaves the lifting value absent.
///
/// Each row of the level, or each pair an arm of a cap returns, reaches the pair its
/// operands name.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperCap {
    /// The pairs the cap keeps rows by.
    pub pairs: HelperPairs,
    /// The rows naming the pair each row of the level, each pair an arm of a cap returns,
    /// or each held row, reaches.
    pub link: CapLink,
    /// The declared single value whose absence lifts the cap, `None` where it holds for
    /// every request.
    pub lift: Option<DeclaredSource>,
}

/// The rows one call of a declared helper returning `TABLE (...)` returns, each pair of
/// values an object of its own holding whoever the rows returning it grant it to.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperPairs {
    /// The helper returning the pairs, as declared.
    pub function: String,
    /// Its arguments, each a literal as SQL spells it.
    pub arguments: Vec<String>,
    /// The rows returning the pairs, each keyed by its columns in the order the helper
    /// returns them, none where the helper returns nothing.
    pub arms: Vec<HelperGrant>,
}

/// `(<operands>) IN (SELECT * FROM <function>(<arguments>))` in a policy clause, keeping a
/// row of the guarded table only where the pair its operands name is one a declared helper
/// returns. The subquery may list the returned columns in order instead of `*`.
///
/// Each row reaches the pair its column operands name beside its literal operands.
#[derive(Debug, Clone, PartialEq)]
pub struct RowInHelperPairs {
    /// Each column operand, a column of the guarded table, beside its position.
    pub columns: Vec<(usize, ColumnName)>,
    /// Each literal operand beside its position.
    pub literals: Vec<(usize, AttributeLiteral)>,
    /// The pairs the row is compared with.
    pub pairs: HelperPairs,
}

/// Which rows name the pair a row of the level, a pair an arm of a cap returns, or a held
/// row reaches.
#[derive(Debug, Clone, PartialEq)]
pub enum CapLink {
    /// The capped arm's own row, whose `columns` hold the pair in the order the helper
    /// returns it, and whose object columns name the level's row, or the pair for an arm
    /// of a cap.
    Row {
        /// The operands, columns of the arm's table.
        columns: Vec<ColumnName>,
    },
    /// Each pair the cap returns, whose column at `object` holds the level's row the arm
    /// returns, or the one-column pair for an arm of a cap, and whose other columns hold
    /// the literals the operands name there.
    Pair {
        /// The position of the operand naming the level's row.
        object: usize,
        /// Each literal operand beside its position.
        literals: Vec<(usize, AttributeLiteral)>,
    },
    /// The row `reader` names for each held row, whose `columns` hold the pair at their
    /// positions beside `literals` at theirs, read only where the arm's rows are held.
    Held {
        /// The row the operand columns are read from.
        reader: CapReader,
        /// Each column operand beside its position, a column of the reader's table.
        columns: Vec<(usize, ColumnName)>,
        /// Each literal operand beside its position.
        literals: Vec<(usize, AttributeLiteral)>,
    },
}

/// The row a held row's cap reads its operand columns from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapReader {
    /// The held row itself.
    Arm,
    /// The row it joins at this index of [`HeldRows::joined`].
    Joined(usize),
}

/// `<column> <operator> now() [OR <column> IS NULL]` in a grant arm's condition, on a
/// `timestamptz` column of the grant table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperTimeBound {
    /// The column compared with the request clock, at `now()` unshifted.
    pub comparison: AttributeRequestPredicate,
    /// Whether a row holding `NULL` in the column meets the bound.
    pub keeps_null: bool,
}

impl HelperGrant {
    /// Whether the arm returns the caller itself, `SELECT g.id FROM grantees g WHERE g.id =
    /// <caller>`, so a grant naming one of its rows names that user.
    pub(crate) fn returns_the_caller(&self) -> bool {
        matches!(&self.grantee, HelperGrantee::Caller { user_column }
            if matches!(self.object_columns.as_slice(), [object] if object == user_column))
    }
}

/// Whom a grant arm's rows admit.
#[derive(Debug, Clone, PartialEq)]
pub enum HelperGrantee {
    /// `<user column> = current_setting(<caller>)`, the caller each row names.
    Caller {
        /// Column holding the caller.
        user_column: ColumnName,
    },
    /// `<value column> = <value>` or `<value column> = ANY (<set>)`, each row admitting
    /// whoever presents its value as the value the request carries or in the set it
    /// carries.
    RequestValue {
        /// Column whose value the request has to present.
        value_column: ColumnName,
        /// The declared value or set, carrying the parameter the caller supplies.
        source: DeclaredSource,
    },
    /// `<principal column> = current_setting(<principal>)`, each row admitting whoever
    /// acts for the principal of the declared type it names, such as the installation a
    /// user acts through.
    Principal {
        /// Column holding the principal.
        principal_column: ColumnName,
        /// The principal's type, as the deployment declares it.
        principal_type: TypeName,
    },
    /// `<grantee column> IN (SELECT <call>)`, the rows naming one of the grantees the
    /// call returns.
    Set {
        /// Column holding the grantee.
        grantee_column: ColumnName,
        /// The call returning the grantees, keys of the table the column names.
        call: HelperCall,
    },
    /// Every row, whoever the caller is.
    Anyone,
}

impl HelperGrantee {
    /// The grant table's column compared with the caller, with another principal the
    /// request acts for, with a value or set the request carries or with the grantees a
    /// set holds, `None` for an arm naming nobody.
    #[must_use]
    pub fn compared_column(&self) -> Option<&ColumnName> {
        match self {
            Self::Caller { user_column } => Some(user_column),
            Self::Principal {
                principal_column, ..
            } => Some(principal_column),
            Self::RequestValue { value_column, .. } => Some(value_column),
            Self::Set { grantee_column, .. } => Some(grantee_column),
            Self::Anyone => None,
        }
    }
}

/// Which grant rows a grant arm keeps.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantRows {
    /// Rows holding one of `values` in `column`, the one column of the grant table both
    /// `NOT NULL` and closed by a `CHECK` to literals, and satisfying `predicates`. Every
    /// value is a relation of its own, so each grant row is one tuple whichever call
    /// reads it.
    Roles {
        /// The closed column.
        column: ColumnName,
        /// The values kept, each one the column can hold.
        values: Vec<AttributeLiteral>,
        /// The conditions the body puts on the other columns, all holding at once.
        predicates: Vec<AttributePredicate>,
    },
    /// Rows satisfying every one of `predicates`, every row where there is none, for a
    /// grant table with no such column.
    Matching {
        /// The conditions the body puts on the row, all holding at once.
        predicates: Vec<AttributePredicate>,
    },
}

/// `SELECT <child> FROM <table> WHERE <parent> IN (SELECT <call>)`.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperParent {
    /// The rows naming the parent of each row the arm returns.
    pub edges: TreeEdges,
    /// The call returning the parents.
    pub call: HelperCall,
}

/// The recursive term of a `WITH RECURSIVE` body walking a tree of the level's keys.
#[derive(Debug, Clone, PartialEq)]
pub struct HelperWalk {
    /// The rows naming the parent of each row of the tree.
    pub edges: TreeEdges,
    /// Which way the walk follows the tree.
    pub direction: sql_traits::structs::WalkDirection,
}

impl HelperWalk {
    /// The column of the edges whose values the walk adds to the set, each edge's child
    /// walking down and its parent walking up.
    #[must_use]
    pub fn returned_column(&self) -> &ColumnName {
        match self.direction {
            sql_traits::structs::WalkDirection::Down => &self.edges.child_column,
            sql_traits::structs::WalkDirection::Up => &self.edges.parent_column,
        }
    }
}

/// P29: a row of `table` its own columns flag, named by `column` of the guarded row or
/// reached from that row as an ancestor up `edges`, after climbing `steps` first.
///
/// `EXISTS (SELECT 1 FROM objects o WHERE o.id = objects.id AND o.archived)`, or the same
/// test over a `WITH RECURSIVE` walk up edge tables. Only rows decide it, never the
/// caller, and it is never `NULL`, so `NOT` of it is the subtraction of its rows.
#[derive(Debug, Clone, PartialEq)]
pub struct FlaggedRow {
    /// Column of the guarded table naming the row the test starts from.
    pub column: ColumnName,
    /// The table whose rows carry the flag.
    pub table: TableId,
    /// The one column naming each row of the flagged table.
    pub key: ColumnName,
    /// Conditions on the flagged row's own columns, all holding at once.
    pub predicates: Vec<AttributePredicate>,
    /// The edge tables the test walks up, empty where it reads the named row alone.
    pub edges: Vec<TreeEdges>,
    /// Edges climbed one each, in order, from the row `column` names to the rows the test
    /// starts from. Empty where it starts at the named row itself.
    ///
    /// `EXISTS (SELECT 1 FROM resource_parents e WHERE e.id = resources.id AND
    /// authz.is_archived(e.parent_id))` climbs `resource_parents` once, and the flag
    /// `authz.is_archived` reads starts from each parent it reaches.
    pub steps: Vec<TreeEdges>,
}

/// The rows linking a row of a tree to its parent, each naming a child and its parent by
/// their keys, the tree's own rows where each names its own parent, or an edge table's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEdges {
    /// The table holding the edges.
    pub table: TableId,
    /// Column of `table` naming each edge's child, the table's key where the table is
    /// the tree itself.
    pub child_column: ColumnName,
    /// Column of `table` naming each edge's parent.
    pub parent_column: ColumnName,
}

/// Sets subtracted from a positive grant.
#[derive(Debug, Clone, PartialEq)]
pub struct MembershipExclusion {
    /// The grant, absent only for a negative-only top-level restrictive clause.
    pub base: Option<Box<ClassifiedExpr>>,
    /// The blocked sets whose union is removed from the grant.
    pub subtract: Vec<ExcludedSet>,
}

/// One set of rows a blocklist removes.
#[derive(Debug, Clone, PartialEq)]
pub enum ExcludedSet {
    /// The rows a correlated `P4` membership names, `NOT EXISTS (SELECT 1 FROM blocks
    /// b WHERE b.doc = docs.id AND b.user_id = <caller>)`.
    Membership(ExistsMembership),
    /// The rows whose column a declared helper returns,
    /// `NOT (project_id = ANY (ARRAY(SELECT authz.blocked_projects())))`, with the
    /// column and every value the helper can return proven non-null.
    Helper(DeclaredHelper),
    /// The rows a [`FlaggedRow`] flags for every caller alike, `NOT authz.is_archived(id)`,
    /// classified as the positive test, through the calls it expanded, or the union of
    /// several where an `OR` joins them.
    Flag(Box<ClassifiedExpr>),
}

/// The flags `pattern` tests, through the function calls it expanded and the `OR`s joining
/// them, `None` where it tests anything else.
#[must_use]
pub fn flagged_rows(pattern: &PatternClass) -> Option<Vec<&FlaggedRow>> {
    let mut flags = Vec::new();
    let mut pending = vec![pattern];
    while let Some(pattern) = pending.pop() {
        match pattern {
            PatternClass::P29FlaggedRow(flagged) => flags.push(flagged),
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. }) => {
                pending.push(&inner.pattern);
            }
            PatternClass::P8Composite(Composite {
                op: BoolOp::Or,
                parts,
            }) => pending.extend(parts.iter().map(|part| &part.pattern)),
            _ => return None,
        }
    }
    Some(flags)
}

/// No known pattern matched.
#[derive(Debug, Clone, PartialEq)]
pub struct UnclassifiedExpr {
    /// The expression as written.
    pub sql_text: String,
    /// Why classification failed, surfaced to the operator.
    pub reason: String,
}

/// Classified pattern for an expression.
///
/// Variants use named payloads shared by recognizers and emitters.
///
/// `#[non_exhaustive]`: a new recognizer adds a variant, so matching this outside the
/// crate needs a wildcard arm. Two variants were added in one session already.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PatternClass {
    /// P1: Numeric role threshold: `role_level(user, resource) >= N`.
    P1NumericThreshold(NumericThreshold),
    /// P2: Role name IN-list: `role_name(user, resource) IN ('viewer', ...)`.
    P2RoleNameInList(RoleNameInList),
    /// P3: Direct column equality: `owner_id = current_user_id()`.
    P3DirectOwnership(DirectOwnership),
    /// P4: EXISTS subquery membership: `EXISTS (SELECT 1 FROM members ...)`.
    P4ExistsMembership(ExistsMembership),
    /// P5: Parent permission inheritance through a foreign key.
    P5ParentInheritance(ParentInheritance),
    /// P6: Boolean flag or public access: `is_public = TRUE`.
    P6BooleanFlag(BooleanFlag),
    /// P7: A relationship check AND an attribute guard.
    P7AbacAnd(AbacAnd),
    /// P8: `OR` or `AND` of two or more sub-patterns.
    P8Composite(Composite),
    /// P9: Standalone attribute condition: `status = 'published'`.
    P9AttributeCondition(AttributeCondition),
    /// P10: Constant `TRUE` or `FALSE` policy.
    P10ConstantBool(ConstantBool),
    /// P11: The caller is an element of an array column: `current_user = ANY (editors)`.
    ///
    /// Exact, not a widening: `UNNEST` enumerates precisely the rows `= ANY` admits.
    P11ArrayMembership(ArrayMembership),
    /// P12: The caller is named by a jsonb field: `data ->> 'owner' = current_user`.
    ///
    /// Exact: `->>` yields NULL for a missing key, a null value and a null column, and
    /// the comparison then filters, which is what dropping the NULLs reproduces.
    P12JsonbFieldOwnership(JsonbFieldOwnership),
    /// P26: The caller equals an immutable function of one column of the row:
    /// `lower(owner) = current_setting('app.user_id', true)`.
    P26OwnerExpression(OwnerExpression),
    /// A membership check naming no column of the guarded table, so it admits every
    /// row at once to whoever appears in the member table.
    P13UncorrelatedMembership(UncorrelatedMembership),
    /// The caller's declared set holds the row's value:
    /// `owner = ANY(string_to_array(current_setting('app.subjects', true), ','))`.
    P14RowValueInCallerSet(RowValueInCallerSet),
    /// The caller's declared single value equals the row's:
    /// `tenant_id = current_setting('app.tenant_id')::uuid`.
    P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar),
    /// The caller's declared set holds a constant the policy names, so no row takes part:
    /// `'admin' = ANY(string_to_array(current_setting('app.roles', true), ','))`.
    P16ConstantInCallerSet(ConstantInCallerSet),
    /// The caller's declared single value equals a constant the policy names, so no row
    /// takes part: `(SELECT auth.jwt() ->> 'aal') = 'aal2'`.
    P17CallerScalarEqualsConstant(CallerScalarEqualsConstant),
    /// The caller's declared single value differs from a constant the policy names, so no
    /// row takes part: `current_setting('app.mode', true) <> 'main'`.
    P21CallerScalarUnequalsConstant(CallerScalarUnequalsConstant),
    /// The caller's declared single value is, or is not, one of the constants the policy
    /// names, so no row takes part: `current_setting('app.mode', true) IN ('main', 'dev')`.
    P22CallerScalarInConstantList(CallerScalarInConstantList),
    /// The value a fallback read hands over equals a constant the policy names, so no row
    /// takes part: `auth.role() = 'authenticated'`, read through the body's
    /// `COALESCE` of declared settings.
    P23FallbackScalarEqualsConstant(FallbackScalarEqualsConstant),
    /// The value a fallback read hands over differs from a constant the policy names, so
    /// no row takes part. `PostgreSQL` reads an unset setting as `NULL`, which also
    /// differs, and the note carries the gap.
    P24FallbackScalarUnequalsConstant(FallbackScalarUnequalsConstant),
    /// The value a fallback read hands over is, or is not, one of the constants the
    /// policy names, so no row takes part: `auth.role() IN ('authenticated', 'anonymous')`.
    P25FallbackScalarInConstantList(FallbackScalarInConstantList),
    /// A membership row whose member column holds a value the caller's declared set has
    /// to contain: `EXISTS (SELECT 1 FROM shares s WHERE s.parent_id = t.id AND
    /// s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ',')))`.
    ///
    /// The membership row is the table's authority and the set is the request's, so the
    /// grant is a request-completed gate on the parent rather than a subject named by
    /// the row: the member value is not a person.
    P18MembershipInCallerSet(MembershipInCallerSet),
    /// Membership reached through a closure table.
    P19IndirectMembership(IndirectMembership),
    /// A column compared with the set a declared `SECURITY DEFINER` helper returns, as in
    /// `project_id = ANY (ARRAY(SELECT authz.projects_with('read')))`.
    P20DeclaredHelper(DeclaredHelper),
    /// P27: The request's declared single value is one of the values a declared
    /// `SECURITY DEFINER` helper returns to every caller alike, so no row takes part:
    /// `current_setting('app.installation_id', true) IN (SELECT
    /// authz.installations_allowing('docs', 'select'))`.
    P27RequestValueInHelperSet(RequestValueInHelperSet),
    /// P28: The request leaves a declared single value it may leave unset absent, or
    /// carries it where negated, so no row takes part:
    /// `NULLIF(current_setting('app.installation_id', true), '') IS NULL`.
    P28RequestValueAbsent(RequestValueAbsent),
    /// P29: A row its own columns flag, named by a column of the guarded row or reached
    /// from it up edge tables: `EXISTS (SELECT 1 FROM objects o WHERE o.id = objects.id
    /// AND o.archived)`, usually read through a `SECURITY DEFINER` boolean function.
    P29FlaggedRow(FlaggedRow),
    /// P30: The guarded row's columns, or one beside literals, name a pair a declared
    /// `SECURITY DEFINER` helper returning `TABLE (...)` returns:
    /// `(organization_id, kind) IN (SELECT * FROM authz.capped_kinds('reader'))`.
    P30RowInHelperPairs(RowInHelperPairs),
    /// P31: Some row of another table the caller can read names the guarded row by its
    /// key and passes a rule of its own:
    /// `id IN (SELECT i.organization_id FROM invitations i WHERE i.expires_at > now())`.
    P31ReferringRows(ReferringRows),
    /// A blocklist removed from a positive grant.
    MembershipExclusion(MembershipExclusion),
    /// A call to a declared single-expression `LANGUAGE sql` function, replaced
    /// by its body with the call-site arguments substituted.
    ExpandedFunction(ExpandedFunction),
    /// No known pattern matched.
    Unknown(UnclassifiedExpr),
}

/// A classified expression with its pattern and confidence.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifiedExpr {
    /// The matched pattern (P1 to P10 or Unknown).
    pub pattern: PatternClass,
    /// How confident the classifier is in this match.
    pub confidence: ConfidenceLevel,
}

/// Grade a pattern built out of `parts` as its lowest part.
///
/// `and` and `or` of exact relations admit what `PostgreSQL`'s `AND` and `OR` admit, since a
/// `NULL` part admits nothing as a `false` one does. That holds only while no `NOT` sits
/// above the composite, which the classifier guarantees by refusing `NOT` over anything
/// but a constant or a [`FlaggedRow`], neither of which is ever `NULL`.
#[must_use]
pub fn composite_confidence<'a, I>(parts: I) -> ConfidenceLevel
where
    I: IntoIterator<Item = &'a ClassifiedExpr>,
{
    parts
        .into_iter()
        .map(|part| part.confidence)
        .min()
        .unwrap_or(ConfidenceLevel::D)
}

/// Confidence of the positive grant, `A` for a restrictive exclusion, lowered to that of
/// any flag the exclusion subtracts.
#[must_use]
pub fn exclusion_confidence(
    base: Option<&ClassifiedExpr>,
    subtract: &[ExcludedSet],
) -> ConfidenceLevel {
    subtract
        .iter()
        .filter_map(|excluded| match excluded {
            ExcludedSet::Flag(flag) => Some(flag.confidence),
            ExcludedSet::Membership(_) | ExcludedSet::Helper(_) => None,
        })
        .fold(
            base.map_or(ConfidenceLevel::A, |base| base.confidence),
            Ord::min,
        )
}

/// The command a catalog's policy statement restricts, `ALL` when it names none.
pub(crate) fn policy_command(command: CreatePolicyCommand) -> PolicyCommand {
    match command {
        CreatePolicyCommand::All => PolicyCommand::All,
        CreatePolicyCommand::Select => PolicyCommand::Select,
        CreatePolicyCommand::Insert => PolicyCommand::Insert,
        CreatePolicyCommand::Update => PolicyCommand::Update,
        CreatePolicyCommand::Delete => PolicyCommand::Delete,
    }
}

/// A clause a policy stores, as the catalog reads it.
#[derive(Debug, Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "the readable clause is the common case, and boxing it would allocate per clause"
)]
pub(crate) enum StoredClause {
    /// The clause, each literal holding the value `PostgreSQL` stored for it.
    Read(Expr),
    /// A clause holding a literal whose stored value the input does not settle, and why.
    Unreadable(String),
}

impl StoredClause {
    /// The clause as the catalog answers it on `table`, `None` when the policy stores none.
    fn of<DB: DatabaseLike>(
        clause: Option<&PolicyExpression<'_>>,
        table: Option<&DB::Table>,
        db: &DB,
    ) -> Option<Self> {
        clause.map(|clause| match clause {
            PolicyExpression::Stored(expr) => Self::Read(match table {
                Some(table) => without_column_type_casts(expr, table, db),
                None => (*expr).clone(),
            }),
            PolicyExpression::Written { unreadable, .. } => {
                Self::Unreadable(unreadable.to_string())
            }
        })
    }

    /// The expression, when its value is known.
    pub(crate) fn expr(&self) -> Option<&Expr> {
        match self {
            Self::Read(expr) => Some(expr),
            Self::Unreadable(_) => None,
        }
    }

    /// Why the clause's value is unknown, when it is.
    fn unreadable(&self) -> Option<&str> {
        match self {
            Self::Read(_) => None,
            Self::Unreadable(reason) => Some(reason),
        }
    }
}

/// A classified policy with classifications for USING and WITH CHECK.
///
/// Holds what rls2fga reads of a policy rather than the catalog's own policy value,
/// so the pipeline runs against any [`DatabaseLike`] rather than one instantiation of it.
///
/// Every field is private, because the generator trusts a classification: a value whose
/// stored clause and whose classification of that clause disagree would build a model the
/// database does not answer for. Construction goes through
/// [`ClassifiedPolicy::from_policy`], and correction through
/// [`consult_oracle`](crate::classifier::oracle::consult_oracle).
///
/// ```compile_fail
/// # use rls2fga::classifier::patterns::{ClassifiedPolicy, PolicyMode};
/// # use rls2fga::types::PolicyCommand;
/// let policy = ClassifiedPolicy {
///     name: "p".to_string(),
///     table: "docs".to_string(),
///     command: PolicyCommand::Select,
///     mode: PolicyMode::Permissive,
///     acting_role: None,
///     using: None,
///     with_check: None,
///     using_classification: None,
///     with_check_classification: None,
///     using_filtered_at: None,
///     with_check_filtered_at: None,
/// };
/// ```
///
/// ```compile_fail
/// # use rls2fga::classifier::patterns::ClassifiedPolicy;
/// fn retarget(policy: &mut ClassifiedPolicy) {
///     policy.table = "other".to_string();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ClassifiedPolicy {
    pub(crate) name: String,
    pub(crate) table: String,
    /// The table the catalog places that spelling in, `None` when it cannot place it.
    pub(crate) resolved_table: Option<TableId>,
    pub(crate) command: PolicyCommand,
    pub(crate) mode: PolicyMode,
    /// The role a request acts as when it meets this policy, which `current_user` in its
    /// clauses names. `None` for a policy classified for no deployment.
    pub(crate) acting_role: Option<String>,
    pub(crate) using: Option<StoredClause>,
    pub(crate) with_check: Option<StoredClause>,
    pub(crate) using_classification: Option<ClassifiedExpr>,
    pub(crate) with_check_classification: Option<ClassifiedExpr>,
    /// Grade the `USING` classification held when `filter_policies_for_output` dropped it,
    /// `None` when it survived or never existed. One field rather than a flag beside a
    /// grade, so the two cannot disagree.
    pub(crate) using_filtered_at: Option<ConfidenceLevel>,
    /// Grade the `WITH CHECK` classification held when it was dropped. While this is set
    /// the USING to WITH CHECK mirror must not be applied.
    pub(crate) with_check_filtered_at: Option<ConfidenceLevel>,
    /// Targets the stored `USING` feeds, those a missing `WITH CHECK` leaves to it included.
    pub(crate) using_targets: Vec<PolicyTarget>,
    /// Targets the stored `WITH CHECK` feeds.
    pub(crate) with_check_targets: Vec<PolicyTarget>,
    /// The refusal `PostgreSQL` answers a clause this policy's command cannot store with.
    pub(crate) illegal_clause: Option<PolicyClauseError>,
}

impl ClassifiedPolicy {
    /// Read a policy out of a catalog, before anything classifies its clauses.
    ///
    /// The single place a catalog's own policy becomes one of these, so nothing
    /// downstream has to know what the catalog stores. The table is resolved here, where
    /// the catalog is in hand, so no later stage re-reads the spelling as text.
    ///
    /// # Errors
    ///
    /// Returns the catalog's [`LookupError`] when `db` does not hold `policy`.
    pub fn from_policy<P: PolicyLike>(policy: &P, db: &P::DB) -> Result<Self, LookupError> {
        let analysis = policy.clause_analysis(db)?;
        let target = policy.target_table_name();
        let table = db
            .resolve_target_table(target, IdentifierCase::AsWritten)
            .ok()
            .flatten();
        Ok(Self {
            name: policy.name().to_string(),
            table: policy.target_table_name().to_string(),
            resolved_table: table.map(table_identity),
            command: policy_command(analysis.command()),
            mode: PolicyMode::from(analysis.mode()),
            acting_role: None,
            using: StoredClause::of(analysis.clause(PolicyClause::Using), table, db),
            with_check: StoredClause::of(analysis.clause(PolicyClause::WithCheck), table, db),
            using_classification: None,
            with_check_classification: None,
            using_filtered_at: None,
            with_check_filtered_at: None,
            using_targets: analysis.targets(PolicyClause::Using).collect(),
            with_check_targets: analysis.targets(PolicyClause::WithCheck).collect(),
            illegal_clause: analysis.invalid_clause(),
        })
    }

    /// The same policy guarding a table spelling the catalog cannot place.
    ///
    /// For a caller whose catalog hands over a policy naming a table it does not resolve,
    /// which the generator answers by refusing to claim one row decides the reads of any
    /// table bearing the name. `ParserDB` refuses such a schema outright, so this is the
    /// only door to that handling.
    #[must_use]
    pub fn guarding_unresolvable_table(mut self, spelled: impl Into<String>) -> Self {
        self.table = spelled.into();
        self.resolved_table = None;
        self
    }

    /// Policy name as declared in the DDL.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Table name targeted by this policy, in the spelling the policy wrote.
    pub fn table_name(&self) -> &str {
        &self.table
    }

    /// The table the catalog places that spelling in, `None` when it cannot place it.
    pub fn resolved_table(&self) -> Option<&TableId> {
        self.resolved_table.as_ref()
    }

    /// DML command this policy restricts (ALL if unspecified).
    pub fn command(&self) -> PolicyCommand {
        self.command
    }

    /// Policy mode (`PERMISSIVE` by default when omitted).
    pub fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// The role this policy was classified for, which `current_user` in its clauses names.
    pub fn acting_role(&self) -> Option<&str> {
        self.acting_role.as_deref()
    }

    /// The `USING` expression the policy stores, if any and if its value is known.
    pub fn using(&self) -> Option<&Expr> {
        self.using.as_ref().and_then(StoredClause::expr)
    }

    /// The `WITH CHECK` expression the policy stores, if any and if its value is known.
    pub fn with_check(&self) -> Option<&Expr> {
        self.with_check.as_ref().and_then(StoredClause::expr)
    }

    /// Why the stored `USING` cannot be read, when a literal's stored value is unknown.
    pub fn using_unreadable(&self) -> Option<&str> {
        self.using.as_ref().and_then(StoredClause::unreadable)
    }

    /// Why the stored `WITH CHECK` cannot be read, when a literal's stored value is unknown.
    pub fn with_check_unreadable(&self) -> Option<&str> {
        self.with_check.as_ref().and_then(StoredClause::unreadable)
    }

    /// Classification of the `USING` expression, if present.
    pub fn using_classification(&self) -> Option<&ClassifiedExpr> {
        self.using_classification.as_ref()
    }

    /// Classification of the `WITH CHECK` expression, if present.
    pub fn with_check_classification(&self) -> Option<&ClassifiedExpr> {
        self.with_check_classification.as_ref()
    }

    /// Grade the `USING` classification held when the threshold dropped it.
    pub fn using_filtered_at(&self) -> Option<ConfidenceLevel> {
        self.using_filtered_at
    }

    /// Grade the `WITH CHECK` classification held when the threshold dropped it.
    pub fn with_check_filtered_at(&self) -> Option<ConfidenceLevel> {
        self.with_check_filtered_at
    }

    /// Iterate over all classified policy expressions (`USING` and `WITH CHECK`).
    pub fn classifications(&self) -> impl Iterator<Item = &ClassifiedExpr> {
        [
            self.using_classification.as_ref(),
            self.with_check_classification.as_ref(),
        ]
        .into_iter()
        .flatten()
    }
}

/// Keep only policy classifications at or above the requested confidence level.
///
/// A policy whose classifications all drop is still retained, in either mode, and the
/// `*_filtered_at` grades say what was lost. A RESTRICTIVE one has to be: RLS is
/// `(permissive OR ...) AND restrictive AND ...`, so removing it grants access it
/// forbids. A PERMISSIVE one has to be for the opposite reason: dropping it is pure
/// subtraction, and a union with fewer arms is indistinguishable from one that never
/// had more, so the generator could not say the model came out narrower than the
/// database. Neither contributes an expression. A policy with an unreadable clause is
/// retained for the same reason, since it carries no classification to drop. A policy
/// whose reads loop needs no such retention, since the generator reads that loop off the
/// schema rather than off the classifications.
pub fn filter_policies_for_output(
    policies: &[ClassifiedPolicy],
    min_confidence: ConfidenceLevel,
) -> Vec<ClassifiedPolicy> {
    policies
        .iter()
        .filter_map(|cp| {
            let mut filtered = cp.clone();
            let permissive = cp.mode() == PolicyMode::Permissive;

            let (using_kept, using_dropped) =
                apply_threshold(cp.using_classification.as_ref(), min_confidence, permissive);
            filtered.using_filtered_at = worst_confidence(&using_dropped);
            filtered.using_classification = using_kept;

            let (check_kept, check_dropped) = apply_threshold(
                cp.with_check_classification.as_ref(),
                min_confidence,
                permissive,
            );
            filtered.with_check_filtered_at = worst_confidence(&check_dropped);
            filtered.with_check_classification = check_kept;

            if filtered.using_classification.is_some()
                || filtered.with_check_classification.is_some()
                || filtered.using_filtered_at.is_some()
                || filtered.with_check_filtered_at.is_some()
                || filtered.mode() == PolicyMode::Restrictive
                || filtered.using_unreadable().is_some()
                || filtered.with_check_unreadable().is_some()
            {
                Some(filtered)
            } else {
                None
            }
        })
        .collect()
}

/// Grade of the worst dropped expression, `None` when nothing dropped.
fn worst_confidence(dropped: &[ClassifiedExpr]) -> Option<ConfidenceLevel> {
    dropped.iter().map(|expr| expr.confidence).min()
}

/// What survives the caller's bar, and the expressions that did not.
///
/// For a permissive clause the bar applies to each arm of an `OR` rather than to the
/// clause as a whole, so one weak arm no longer takes the strong ones with it and one
/// `OR` policy lands where two policies land. The report reads the same partition, so
/// what it calls excluded is exactly what the model excluded.
pub(crate) fn apply_threshold(
    classification: Option<&ClassifiedExpr>,
    min_confidence: ConfidenceLevel,
    permissive: bool,
) -> (Option<ClassifiedExpr>, Vec<ClassifiedExpr>) {
    let Some(classification) = classification else {
        return (None, Vec::new());
    };
    if permissive {
        return filter_or_arms(classification, min_confidence);
    }
    if classification.confidence >= min_confidence {
        (Some(classification.clone()), Vec::new())
    } else {
        (None, vec![classification.clone()])
    }
}

/// Recurse through a nested `OR`, keeping the arms at or above the bar.
///
/// An arm that is not itself an `OR` is atomic: dropping half a conjunction would grant
/// rows its other half refuses, so a conjunction below the bar goes whole, which its
/// lowest arm's grade already says.
fn filter_or_arms(
    expr: &ClassifiedExpr,
    min_confidence: ConfidenceLevel,
) -> (Option<ClassifiedExpr>, Vec<ClassifiedExpr>) {
    let PatternClass::P8Composite(Composite {
        op: BoolOp::Or,
        parts,
    }) = &expr.pattern
    else {
        return if expr.confidence >= min_confidence {
            (Some(expr.clone()), Vec::new())
        } else {
            (None, vec![expr.clone()])
        };
    };

    let mut kept: Vec<ClassifiedExpr> = Vec::new();
    let mut lost: Vec<ClassifiedExpr> = Vec::new();
    for part in parts {
        let (survivor, dropped) = filter_or_arms(part, min_confidence);
        if let Some(survivor) = survivor {
            kept.push(survivor);
        }
        lost.extend(dropped);
    }

    match kept.len() {
        0 => (None, lost),
        // One survivor is that arm, not a union of one.
        1 => (kept.pop(), lost),
        _ => {
            let confidence = composite_confidence(kept.iter());
            (
                Some(ClassifiedExpr {
                    pattern: PatternClass::P8Composite(Composite {
                        op: BoolOp::Or,
                        parts: kept,
                    }),
                    confidence,
                }),
                lost,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, DatabaseLike};
    use core::str::FromStr;
    use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType};

    fn first_classified(sql: &str) -> ClassifiedPolicy {
        let db = parse_schema(sql).expect("schema should parse");
        let policy = db.policies().next().expect("expected one policy");
        ClassifiedPolicy::from_policy(policy, &db).expect("the policy is in its database")
    }

    #[test]
    fn policy_mode_and_command_format_and_conversion() {
        assert_eq!(
            PolicyMode::from(CreatePolicyType::Permissive),
            PolicyMode::Permissive
        );
        assert_eq!(
            PolicyMode::from(CreatePolicyType::Restrictive),
            PolicyMode::Restrictive
        );
        assert_eq!(format!("{}", PolicyMode::Permissive), "PERMISSIVE");
        assert_eq!(format!("{}", PolicyMode::Restrictive), "RESTRICTIVE");

        assert_eq!(policy_command(CreatePolicyCommand::All), PolicyCommand::All);
        assert_eq!(
            policy_command(CreatePolicyCommand::Select),
            PolicyCommand::Select
        );
        assert_eq!(
            policy_command(CreatePolicyCommand::Insert),
            PolicyCommand::Insert
        );
        assert_eq!(
            policy_command(CreatePolicyCommand::Update),
            PolicyCommand::Update
        );
        assert_eq!(
            policy_command(CreatePolicyCommand::Delete),
            PolicyCommand::Delete
        );

        assert_eq!(format!("{}", PolicyCommand::Select), "SELECT");
        assert_eq!(format!("{}", PolicyCommand::Insert), "INSERT");
        assert_eq!(format!("{}", PolicyCommand::Update), "UPDATE");
        assert_eq!(format!("{}", PolicyCommand::Delete), "DELETE");
        assert_eq!(format!("{}", PolicyCommand::All), "ALL");
    }

    #[test]
    fn classified_policy_defaults_and_explicit_values() {
        let cp_default = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_default ON docs USING (TRUE);
",
        );
        assert_eq!(cp_default.name(), "p_default");
        assert_eq!(cp_default.table_name(), "docs");
        assert_eq!(cp_default.command(), PolicyCommand::All);
        assert_eq!(cp_default.mode(), PolicyMode::Permissive);

        let cp_explicit = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_explicit ON docs AS RESTRICTIVE FOR DELETE USING (FALSE);
",
        );
        assert_eq!(cp_explicit.name(), "p_explicit");
        assert_eq!(cp_explicit.table_name(), "docs");
        assert_eq!(cp_explicit.command(), PolicyCommand::Delete);
        assert_eq!(cp_explicit.mode(), PolicyMode::Restrictive);
    }

    #[test]
    fn confidence_level_parsing_is_case_insensitive() {
        assert_eq!(ConfidenceLevel::from_str("a"), Ok(ConfidenceLevel::A));
        assert_eq!(ConfidenceLevel::from_str("B"), Ok(ConfidenceLevel::B));
        assert_eq!(ConfidenceLevel::from_str("c"), Ok(ConfidenceLevel::C));
        assert_eq!(ConfidenceLevel::from_str("D"), Ok(ConfidenceLevel::D));
        assert_eq!(format!("{}", ConfidenceLevel::A), "A");
        assert_eq!(format!("{}", ConfidenceLevel::B), "B");
        assert_eq!(format!("{}", ConfidenceLevel::C), "C");
        assert_eq!(format!("{}", ConfidenceLevel::D), "D");

        let err = ConfidenceLevel::from_str("z").expect_err("invalid level should fail");
        assert!(err.contains("Invalid confidence level: z"));
    }

    /// `PostgreSQL` compares the privilege case insensitively and ignores surrounding space,
    /// and it answers false for a string it does not know rather than raising. Verified on
    /// 18.1, including that `'MEMBER WITH GRANT OPTION'` simply returns false.
    #[test]
    fn role_privilege_parses_every_spelling_postgres_accepts() {
        use RolePrivilege::{AdminOption, Member, SetRole, Usage};

        for (spelling, expected) in [
            ("MEMBER", Member),
            ("USAGE", Usage),
            ("SET", SetRole),
            ("member", Member),
            ("  usage  ", Usage),
            // The kind before the admin option makes no difference to the answer, so all
            // three spellings are one relation.
            ("MEMBER WITH ADMIN OPTION", AdminOption),
            ("USAGE WITH ADMIN OPTION", AdminOption),
            ("SET WITH ADMIN OPTION", AdminOption),
            ("member with admin option", AdminOption),
            ("MEMBER  WITH ADMIN OPTION", AdminOption),
        ] {
            assert_eq!(
                RolePrivilege::parse(spelling),
                Some(expected),
                "`{spelling}` names {expected:?} to PostgreSQL"
            );
        }

        for unknown in [
            "MEMBER WITH GRANT OPTION",
            "WITH ADMIN OPTION",
            "ADMIN",
            "nonsense",
            "",
            "MEMBERSHIP",
        ] {
            assert_eq!(
                RolePrivilege::parse(unknown),
                None,
                "`{unknown}` names no kind the crate can act on"
            );
        }

        // One relation per kind, since the sets differ.
        let names = [Member, Usage, SetRole, AdminOption].map(RolePrivilege::relation_name);
        assert_eq!(
            names.iter().collect::<BTreeSet<_>>().len(),
            names.len(),
            "two kinds sharing a relation would make the operator's facts mean both"
        );
    }
}
