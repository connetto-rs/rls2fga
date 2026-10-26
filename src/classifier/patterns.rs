#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;
use core::fmt;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{CreatePolicyCommand, CreatePolicyType, Expr, Owner};

use crate::classifier::function_registry::SessionAttribute;
use crate::parser::names::{stored_ident_name, table_identity};
use crate::parser::sql_parser::{DatabaseLike, IdentifierCase, PolicyLike};
pub(crate) use crate::types::{
    AttributeLiteral, AttributeOperator, AttributePredicate, AttributeTest, ColumnName,
    ConfidenceLevel, RolePrivilege, TableId,
};

/// The command a policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyCommand {
    /// Policy applies to SELECT queries only.
    Select,
    /// Policy applies to INSERT queries only.
    Insert,
    /// Policy applies to UPDATE queries only.
    Update,
    /// Policy applies to DELETE queries only.
    Delete,
    /// Policy applies to all DML commands.
    All,
}

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

impl fmt::Display for PolicyCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyCommand::Select => write!(f, "SELECT"),
            PolicyCommand::Insert => write!(f, "INSERT"),
            PolicyCommand::Update => write!(f, "UPDATE"),
            PolicyCommand::Delete => write!(f, "DELETE"),
            PolicyCommand::All => write!(f, "ALL"),
        }
    }
}

/// Boolean operator for composite patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoolOp {
    /// Logical conjunction: all sub-conditions must hold.
    And,
    /// Logical disjunction: at least one sub-condition must hold.
    Or,
}

/// A column compared against a value only the request knows, which no static tuple
/// can decide. The row supplies the column, the caller supplies the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeRequestPredicate {
    /// Column the guard reads, folded to its stored name.
    pub column: ColumnName,
    /// Comparison applied, oriented with the column on the left.
    pub operator: AttributeOperator,
    /// What the request supplies.
    pub request_value: RequestValue,
    /// A fixed offset applied to the request clock, from `now() - interval '30 days'`
    /// and its spellings. `None` when the guard compares against the bare clock.
    pub offset: Option<TemporalOffset>,
}

/// A value the request supplies rather than the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestValue {
    /// The moment the statement runs, from `now()` and its spellings.
    StatementTimestamp,
}

/// A fixed-length shift of the request clock, lifted from a `PostgreSQL` interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalOffset {
    /// The offset as a CEL duration, such as `720h` for `interval '30 days'`.
    pub cel_duration: String,
    /// `true` subtracts it from the clock (`now() - interval`), `false` adds it.
    pub subtract: bool,
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

    /// The row-decidable conjuncts as guards, ignoring request-completed and SQL-only
    /// ones. Total, unlike [`Self::guards`], so a caller that has already separated the
    /// requests takes the guards without a second fallible pass.
    #[must_use]
    pub fn row_guards(&self) -> Vec<ResidualGuard> {
        self.0
            .iter()
            .filter_map(|conjunct| conjunct.guard.clone())
            .collect()
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
    /// Which kind of membership in those roles the policy asked about.
    pub privilege: RolePrivilege,
    /// Column whose value the call passes as the resource, as
    /// [`NumericThreshold::resource_column`]. Absent for a plain role accessor, which
    /// takes no resource at all.
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
    /// Column of the child table linking to `parent_table`.
    pub fk_column: ColumnName,
    /// The parent-side rule the policy requires.
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
    pub source: SessionAttribute,
}

/// The caller's declared single value equals the row's:
/// `tenant_id = current_setting('app.tenant_id')::uuid`.
#[derive(Debug, Clone, PartialEq)]
pub struct RowValueEqualsCallerScalar {
    /// Column the value has to equal.
    pub column: ColumnName,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: SessionAttribute,
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
    pub source: SessionAttribute,
}

/// The caller's declared single value equals a constant the policy names, so no row
/// takes part: `(SELECT auth.jwt() ->> 'aal') = 'aal2'`.
#[derive(Debug, Clone, PartialEq)]
pub struct CallerScalarEqualsConstant {
    /// The constant the value has to equal.
    pub value: String,
    /// The declared source, carrying the parameter the caller supplies.
    pub source: SessionAttribute,
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
    pub source: SessionAttribute,
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

/// Correlated caller-identity memberships subtracted from a positive grant.
#[derive(Debug, Clone, PartialEq)]
pub struct MembershipExclusion {
    /// The grant, absent only for a negative-only top-level restrictive clause.
    pub base: Option<Box<ClassifiedExpr>>,
    /// The blocked `P4` sets whose union is removed from the grant.
    pub subtract: Vec<ExistsMembership>,
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
    /// A correlated blocklist removed from a positive grant.
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

/// Grade a pattern built out of `parts`.
///
/// The lowest part decides, capped at `B`: combining separately recognized halves is
/// never as certain as recognizing one shape whole. Both `AND` and `OR` used this rule
/// already, spelled differently, and an oracle substituting a part has to regrade the
/// same way or the composite keeps the grade its refused part dragged it to.
#[must_use]
pub fn composite_confidence<'a, I>(parts: I) -> ConfidenceLevel
where
    I: IntoIterator<Item = &'a ClassifiedExpr>,
{
    parts
        .into_iter()
        .map(|part| part.confidence)
        .min()
        .map_or(ConfidenceLevel::D, |lowest| {
            core::cmp::min(lowest, ConfidenceLevel::B)
        })
}

/// Confidence of the positive grant, or `A` for a restrictive exclusion.
#[must_use]
pub fn exclusion_confidence(base: Option<&ClassifiedExpr>) -> ConfidenceLevel {
    base.map_or(ConfidenceLevel::A, |base| base.confidence)
}

impl From<CreatePolicyCommand> for PolicyCommand {
    fn from(cmd: CreatePolicyCommand) -> Self {
        match cmd {
            CreatePolicyCommand::All => PolicyCommand::All,
            CreatePolicyCommand::Select => PolicyCommand::Select,
            CreatePolicyCommand::Insert => PolicyCommand::Insert,
            CreatePolicyCommand::Update => PolicyCommand::Update,
            CreatePolicyCommand::Delete => PolicyCommand::Delete,
        }
    }
}

/// Policy mode as declared, `PERMISSIVE` when the policy omits it.
pub fn derive_policy_mode<P: PolicyLike>(policy: &P) -> PolicyMode {
    PolicyMode::from(policy.policy_type())
}

/// Whether a policy's command covers reads.
///
/// Split out because the generator's readability walk applies this same rule to a
/// `RESTRICTIVE` barrier as well, where the rest of [`policy_grants_select`] does not
/// apply, and a command rule spelled twice can be widened in one place only.
pub(crate) fn policy_covers_reads<P: PolicyLike>(policy: &P) -> bool {
    matches!(
        PolicyCommand::from(policy.command()),
        PolicyCommand::Select | PolicyCommand::All
    )
}

/// Whether a policy can grant reads: permissive, covering `SELECT`, and storing
/// the `USING` clause a read is filtered by.
pub fn policy_grants_select<P: PolicyLike>(policy: &P, db: &P::DB) -> bool {
    derive_policy_mode(policy) == PolicyMode::Permissive
        && policy_covers_reads(policy)
        && policy.using_expression(db).is_some()
}

/// Roles in `TO (...)` that constrain policy applicability, named and resolvable.
///
/// Empty when the policy applies to every role, which `PostgreSQL` spells both as
/// `TO PUBLIC` and as no `TO` clause at all. A spelling `PostgreSQL` resolves when the
/// DDL runs is not a name and is answered by [`derive_ddl_time_scoped_roles`].
pub fn derive_scoped_roles<P: PolicyLike>(policy: &P, db: &P::DB) -> Vec<String> {
    split_scoped_roles(policy, db).0
}

/// The `TO (...)` spellings `PostgreSQL` resolves to the executing role when the
/// policy is created (`CURRENT_USER`, `CURRENT_ROLE`, `SESSION_USER`).
///
/// `pg_policy` stores the resolved role, so a dump never carries these and a schema
/// file holding one cannot say who the policy binds.
pub fn derive_ddl_time_scoped_roles<P: PolicyLike>(policy: &P, db: &P::DB) -> Vec<String> {
    split_scoped_roles(policy, db).1
}

/// One walk of the owners: `(named roles, ddl-time spellings)`.
fn split_scoped_roles<P: PolicyLike>(policy: &P, db: &P::DB) -> (Vec<String>, Vec<String>) {
    if policy.applies_to_public() {
        return (Vec::new(), Vec::new());
    }

    let mut named = Vec::new();
    let mut ddl_time = Vec::new();
    for owner in policy.roles(db) {
        if let Owner::Ident(ident) = owner {
            let stored = stored_ident_name(ident);
            if !stored.is_empty() {
                named.push(stored.into_owned());
            }
        } else {
            let spelling = owner.to_string().trim().to_string();
            if !spelling.is_empty() {
                ddl_time.push(spelling);
            }
        }
    }
    named.sort();
    named.dedup();
    ddl_time.sort();
    ddl_time.dedup();
    (named, ddl_time)
}

/// The refusal `PostgreSQL` answers a policy storing `clause` for `command`, if any.
///
/// `CREATE POLICY` refuses a `USING` on `FOR INSERT` and a `WITH CHECK` on `FOR
/// SELECT` or `FOR DELETE`, so a policy carrying one never came out of a database and
/// nothing may translate it as if it had.
#[must_use]
pub fn clause_illegal_for_command(
    command: PolicyCommand,
    has_using: bool,
    has_with_check: bool,
) -> Option<&'static str> {
    match command {
        PolicyCommand::Insert if has_using => Some("only WITH CHECK expression allowed for INSERT"),
        PolicyCommand::Select | PolicyCommand::Delete if has_with_check => {
            Some("WITH CHECK cannot be applied to SELECT or DELETE")
        }
        _ => None,
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
/// # use rls2fga::classifier::patterns::{ClassifiedPolicy, PolicyCommand, PolicyMode};
/// let policy = ClassifiedPolicy {
///     name: "p".to_string(),
///     table: "docs".to_string(),
///     command: PolicyCommand::Select,
///     mode: PolicyMode::Permissive,
///     scoped_roles: Vec::new(),
///     ddl_time_roles: Vec::new(),
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
    pub(crate) scoped_roles: Vec<String>,
    pub(crate) ddl_time_roles: Vec<String>,
    pub(crate) using: Option<Expr>,
    pub(crate) with_check: Option<Expr>,
    pub(crate) using_classification: Option<ClassifiedExpr>,
    pub(crate) with_check_classification: Option<ClassifiedExpr>,
    /// Grade the `USING` classification held when `filter_policies_for_output` dropped it,
    /// `None` when it survived or never existed. One field rather than a flag beside a
    /// grade, so the two cannot disagree.
    pub(crate) using_filtered_at: Option<ConfidenceLevel>,
    /// Grade the `WITH CHECK` classification held when it was dropped. While this is set
    /// the USING to WITH CHECK mirror must not be applied.
    pub(crate) with_check_filtered_at: Option<ConfidenceLevel>,
}

impl ClassifiedPolicy {
    /// Read a policy out of a catalog, before anything classifies its clauses.
    ///
    /// The single place a catalog's own policy becomes one of these, so nothing
    /// downstream has to know what the catalog stores. The table is resolved here, where
    /// the catalog is in hand, so no later stage re-reads the spelling as text.
    pub fn from_policy<P: PolicyLike>(policy: &P, db: &P::DB) -> Self {
        let (scoped_roles, ddl_time_roles) = split_scoped_roles(policy, db);
        let target = policy.target_table_name();
        Self {
            name: policy.name().to_string(),
            table: target.to_string(),
            resolved_table: db
                .resolve_target_table(target, IdentifierCase::AsWritten)
                .ok()
                .flatten()
                .map(table_identity),
            command: PolicyCommand::from(policy.command()),
            mode: derive_policy_mode(policy),
            scoped_roles,
            ddl_time_roles,
            using: policy.using_expression(db).cloned(),
            with_check: policy.check_expression(db).cloned(),
            using_classification: None,
            with_check_classification: None,
            using_filtered_at: None,
            with_check_filtered_at: None,
        }
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

    /// The `USING` expression the policy stores, if any.
    pub fn using(&self) -> Option<&Expr> {
        self.using.as_ref()
    }

    /// The `WITH CHECK` expression the policy stores, if any.
    pub fn with_check(&self) -> Option<&Expr> {
        self.with_check.as_ref()
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

    /// Roles in `TO (...)` that constrain policy applicability.
    pub fn scoped_roles(&self) -> &[String] {
        &self.scoped_roles
    }

    /// `TO (...)` spellings resolved only when the DDL runs.
    pub fn ddl_time_roles(&self) -> &[String] {
        &self.ddl_time_roles
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
/// database. Neither contributes an expression. A policy whose reads loop needs no
/// such retention, since the generator reads that loop off the schema rather than off
/// the classifications.
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
/// `OR` policy lands where two policies land. The clause's own grade is never compared,
/// which matters twice: it is capped at B, so an `OR` of two grade A arms would
/// otherwise die at the strictest bar with nothing weak anywhere. The report reads the
/// same partition, so what it calls excluded is exactly what the model excluded.
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
        // One survivor is that arm, not a union of one. Keeping the wrapper would cap its
        // grade at B, which is the difference between this and two separate policies.
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
        ClassifiedPolicy::from_policy(policy, &db)
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

        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::All),
            PolicyCommand::All
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Select),
            PolicyCommand::Select
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Insert),
            PolicyCommand::Insert
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Update),
            PolicyCommand::Update
        );
        assert_eq!(
            PolicyCommand::from(CreatePolicyCommand::Delete),
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

    #[test]
    fn classified_policy_scoped_roles_excludes_public_and_dedupes() {
        let scoped = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_scoped ON docs FOR SELECT TO app_user, app_user, auditors USING (TRUE);
",
        );
        assert_eq!(
            scoped.scoped_roles(),
            ["app_user".to_string(), "auditors".to_string()]
        );

        let public = first_classified(
            r"
CREATE TABLE docs(id uuid primary key);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_public ON docs FOR SELECT TO PUBLIC, app_user USING (TRUE);
",
        );
        assert_eq!(public.scoped_roles(), Vec::<String>::new());
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
