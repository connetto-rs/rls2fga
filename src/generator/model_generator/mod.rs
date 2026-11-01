#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Write;

use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::{FunctionRegistry, SessionAttribute};
use crate::classifier::patterns::*;
use crate::classifier::readability::{table_readability, ReadGate, TableReadability};
use crate::generator::caller_roles::{CallerRoles, Settlement};
use crate::generator::db_lookup::{
    column_is_nullable, column_kind, composite_primary_key_columns, resolve_row_identity,
    row_uniquely_keys, single_identity_column,
};
use crate::generator::identity::MAX_OBJECT_NAME_CHARS;
use crate::generator::ir::{GateContextColumn, MembershipGate, PrincipalInfo, TupleSource};
use crate::generator::notes::SkippedTuples;
use crate::generator::role_relations::{sorted_role_relation_names, RoleRelationName};
use crate::generator::tuple_generator::{resolve_bridge_columns, UnboundedColumns};
use crate::generator::well_known::{
    blocked_relation, can_delete_relation, can_insert_relation, can_insert_returning_relation,
    can_select_for_update_relation, can_select_relation, can_update_check_relation,
    can_update_relation, can_update_using_relation, can_update_without_reading_relation,
    can_upsert_relation, deny_relation, member_relation, owner_team_relation, owner_user_relation,
    public_relation, request_gate_link_relation, scope_roles_relation, WellKnownTypes,
    REQUEST_TIME_PARAMETER, STRING_PARAMETER_TYPE, TIMESTAMP_PARAMETER_TYPE,
};
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::{
    attribute_gate_relation_name, canonical_fga_type_name, clamp_relation_name,
    conditional_gate_relation_name, is_owner_like_column_name, lookup_table, lookup_table_id,
    membership_read_scope_relation_name, parent_type_from_fk_column, public_flag_relation_name,
    request_gate_relation_name, resolve_table_id, role_limited_relation_name, role_scope_name,
    row_presence_relation_name, stored_relation_name, table_id_has_column, table_identity,
    yielded_relation_name, MAX_RELATION_NAME_LEN, MAX_RELATION_RENAME_ATTEMPTS,
};
use crate::parser::sql_parser::{
    ColumnLike, DatabaseLike, ForeignKeyLike, IdentifierCase, PolicyLike, RoleLike, TableLike,
};
use crate::types::{
    stable_hex_suffix, ColumnKind, ColumnName, ConditionName, ConditionParameterName,
    ContextWitness, RelationName, RequestComparison, TableId, TranslationNote, TypeName,
};

/// Which relation a command reads, and how a policy's clauses reach it.
mod actions;
/// `OpenFGA` DSL text rendering from the schema plan.
mod dsl;
/// Emission for the patterns that reach through another row.
mod emit_membership;
/// Emission for the patterns one column of the row decides.
mod emit_ownership;
/// Emission for the patterns the request completes rather than the row.
mod emit_requests;
/// Emission for the patterns a role decides.
mod emit_roles;
/// Which statements `PostgreSQL` refuses to plan because the policies loop.
mod recursion;
/// A gate that reads only the request, reduced to one normal form.
mod request_formula;
/// Role-threshold resource-column inference and tuple-source population.
mod role_threshold;
/// Whole-plan passes that run once every table is translated.
mod simplify;

use actions::{
    action_relation_commands, action_relations, clauses_lost_to_the_threshold,
    commands_a_permissive_policy_covers, commands_denied_by_barriers_alone, commands_fed_by,
    compose_action, define_blanket_update_relations, define_locking_read_relations,
    define_upsert_relations, derived_action_relations, dropped_attribute_guards,
    fill_uncovered_actions_with_deny, for_each_policy_target_expr, mark_narrowed, narrowed_by,
    policies_missing_a_clause, push_action_expr, scoped_policy_expr, targets_a_policy_feeds,
    ActionTarget, ModeBuckets, INHERITED_RELATION_PREFIX,
};
use dsl::render_dsl;
use emit_membership::{
    emit_abac_and, emit_blocked_set, emit_composite, emit_exists_membership,
    emit_indirect_membership, emit_membership_exclusion, emit_parent_inheritance,
    emit_uncorrelated_membership,
};
use emit_ownership::{
    emit_attribute_condition, emit_boolean_flag, emit_constant_bool, emit_direct_ownership,
    emit_row_ownership, emit_row_presence_gate, emit_unclassified,
};
use emit_requests::{
    conditional_gate_expr, declare_temporal_condition, emit_membership_in_caller_set,
    emit_request_formula, emit_request_gate, RequestSide,
};
use emit_roles::{
    emit_numeric_threshold, emit_role_name_in_list, register_pg_role_scope, OwnerScope,
    RoleScopeSpec,
};
use recursion::PolicyReadRecursion;
pub(crate) use request_formula::GateAtom;
use request_formula::RequestFormula;
use role_threshold::{populate_role_threshold_sources, RoleThresholdTables};
pub(crate) use simplify::relation_grants_nothing;
use simplify::{
    drop_implied_insert_readback, grants_nothing, inline_synthetic_rule_aliases,
    narrow_grant_sources_to_declared, prune_unreferenced_relations, reach_userset,
    requires_read_access, simplify_redundant_select_gates,
};

/// `OpenFGA` authorization model schema version.
pub(crate) const OPENFGA_SCHEMA_VERSION: &str = "1.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectSubject {
    Type(TypeName),
    Wildcard(TypeName),
    /// A wildcard every tuple of which carries a condition, so the grant holds only
    /// while the condition evaluates true at check time.
    ConditionalWildcard {
        type_name: TypeName,
        condition: ConditionName,
    },
    /// A directly related type every tuple of which carries a condition, so a named
    /// subject grants only while the condition evaluates true at check time. The member
    /// tuple a temporal membership emits is one.
    ConditionalType {
        type_name: TypeName,
        condition: ConditionName,
    },
}

impl DirectSubject {
    /// Structural identity of one subject, stable against `Debug` formatting.
    fn identity_key(&self) -> String {
        match self {
            Self::Type(name) => format!("t:{name}"),
            Self::Wildcard(name) => format!("w:{name}"),
            Self::ConditionalWildcard {
                type_name,
                condition,
            } => format!("wc:{type_name}:{condition}"),
            Self::ConditionalType {
                type_name,
                condition,
            } => format!("tc:{type_name}:{condition}"),
        }
    }

    /// The type a tupleset walk resolves this subject to, `None` for a wildcard,
    /// which cannot be walked. A condition restricts which tuples exist, not which
    /// type they name, so a conditional subject resolves like a plain one.
    fn resolved_type_name(&self) -> Option<&TypeName> {
        match self {
            Self::Type(name)
            | Self::ConditionalType {
                type_name: name, ..
            } => Some(name),
            Self::Wildcard(_) | Self::ConditionalWildcard { .. } => None,
        }
    }

    /// The DSL spelling inside a type restriction list.
    pub(super) fn dsl_text(&self) -> String {
        match self {
            Self::Type(name) => name.to_string(),
            Self::Wildcard(name) => format!("{name}:*"),
            Self::ConditionalWildcard {
                type_name,
                condition,
            } => format!("{type_name}:* with {condition}"),
            Self::ConditionalType {
                type_name,
                condition,
            } => format!("{type_name} with {condition}"),
        }
    }
}

/// A condition the model declares and a relation reference names.
///
/// One `CEL` expression over parameters that arrive from two places: the tuple
/// carries what the row knows, the request carries what only it knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConditionSpec {
    pub expression: String,
    /// Parameter name to its `OpenFGA` type, sorted so emission is stable.
    pub parameters: BTreeMap<String, ConditionParameter>,
}

impl ConditionSpec {
    /// The name this condition is declared under, read off what it evaluates alone.
    ///
    /// `OpenFGA` refuses a model declaring more than 25 conditions, so two guards
    /// evaluating one expression over one parameter list share one name wherever they
    /// come from, and the count follows the distinct guards rather than the tables.
    pub(crate) fn name(&self) -> ConditionName {
        let mut key = self.expression.clone();
        for (parameter, kind) in &self.parameters {
            let (shape, element) = match kind {
                ConditionParameter::Scalar(element) => ("scalar", element),
                ConditionParameter::ListOf(element) => ("list", element),
            };
            for part in [parameter.as_str(), shape, element] {
                key.push('\0');
                key.push_str(part);
            }
        }
        ConditionName::canonicalized(format!(
            "when_{}_{}",
            self.expression,
            stable_hex_suffix(&key)
        ))
    }
}

/// A condition parameter's type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConditionParameter {
    /// One value, named as the API names it.
    Scalar(&'static str),
    /// A list of values of the named element type.
    ListOf(&'static str),
}

/// Structural identity of a subject list, stable against `Debug` formatting.
fn subject_key(subjects: &[DirectSubject]) -> String {
    subjects
        .iter()
        .map(DirectSubject::identity_key)
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsersetExpr {
    Computed(RelationName),
    TupleToUserset {
        tupleset: RelationName,
        computed: RelationName,
    },
    Union(Vec<UsersetExpr>),
    Intersection(Vec<UsersetExpr>),
    /// `base` minus `subtract`, the only way to negate a userset in `OpenFGA`.
    Exclusion {
        base: Box<UsersetExpr>,
        subtract: Box<UsersetExpr>,
    },
}

/// Structural identity of a userset expression, stable against `Debug` formatting.
fn userset_key(expr: &UsersetExpr) -> String {
    match expr {
        UsersetExpr::Computed(name) => format!("c:{name}"),
        UsersetExpr::TupleToUserset { tupleset, computed } => format!("t:{tupleset}:{computed}"),
        UsersetExpr::Union(children) => format!("u({})", child_keys(children)),
        UsersetExpr::Intersection(children) => format!("i({})", child_keys(children)),
        UsersetExpr::Exclusion { base, subtract } => {
            format!("x({},{})", userset_key(base), userset_key(subtract))
        }
    }
}

fn child_keys(children: &[UsersetExpr]) -> String {
    children
        .iter()
        .map(userset_key)
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Clone)]
pub(crate) struct TypePlan {
    pub type_name: TypeName,
    pub direct_relations: BTreeMap<RelationName, Vec<DirectSubject>>,
    pub computed_relations: BTreeMap<RelationName, UsersetExpr>,
    well_known: WellKnownTypes,
    /// Table-level tuple sources not tied to a specific relation (e.g. policy
    /// scope tuples).
    pub table_tuple_sources: Vec<TupleSource>,
    /// Ownership column → its relation. Sharing one would union distinct principals.
    ownership_relations: BTreeMap<String, RelationName>,
    /// Gate key → its relation. A gate's tuples satisfy only its own relation, so two
    /// keys must never share a name even on hash collision.
    gate_relations: BTreeMap<String, RelationName>,
    membership_source_relations: BTreeMap<String, RelationName>,
    /// Conditions this type's own relation references name, keyed by condition name.
    /// They live here rather than threaded through translation so a condition stays
    /// beside the relation that needs it.
    pub conditions: BTreeMap<ConditionName, ConditionSpec>,
    /// The table has `INHERITS` children, so queries minting this type's objects read
    /// `FROM ONLY`: the key does not span child rows, and a shared value would merge
    /// two rows into one object.
    pub reads_only_its_own_rows: bool,
    /// Action relations whose emitted rule came out narrower, or wider, than the
    /// database because a clause `PostgreSQL` evaluates was lost. Read where
    /// decidability is answered, so a consumer answering reads from the recipe
    /// delegates instead of guessing. An entry naming a relation this plan never
    /// defines is inert.
    pub narrowed_relations: BTreeSet<RelationName>,
    /// Table whose rows this type names, in the schema's own spelling, absent for a
    /// type nothing keys on a row (`user`, a team, a holder). Written where the type
    /// name is bound to the table, so nothing has to re-derive the association from
    /// the shapes, where two tables can key a row alike.
    pub source_table: Option<TableId>,
}

/// Subjects the generator's own structural relations hold, or `None` when the
/// name is free. These relations are referenced by name, so any other caller
/// asking for one is renamed regardless of translation order.
fn reserved_relation_subjects(
    relation: &RelationName,
    well_known: &WellKnownTypes,
) -> Option<Vec<DirectSubject>> {
    if *relation == deny_relation() {
        Some(vec![DirectSubject::Type(well_known.nobody.clone())])
    } else if *relation == member_relation()
        || *relation == owner_user_relation()
        || *relation == blocked_relation()
    {
        Some(vec![DirectSubject::Type(well_known.user.clone())])
    } else if *relation == public_relation() {
        Some(vec![DirectSubject::Wildcard(well_known.user.clone())])
    } else if *relation == owner_team_relation() {
        // The team type is per-source (one per team_membership_table), so no single
        // subject type can be declared here. An empty subject list never equals a real
        // caller's subjects, so every caller yields away from this name except
        // `TypePlan::claim_owner_team_relation`, which bypasses this check as the sole
        // legitimate owner.
        Some(Vec::new())
    } else {
        None
    }
}

/// Whether the generator defines `relation` itself once the actions are assembled,
/// so a translated name taking it would be defined twice.
fn generator_defines(relation: &RelationName) -> bool {
    action_relations()
        .chain(derived_action_relations())
        .any(|reserved| reserved == *relation)
}

impl TypePlan {
    fn new(type_name: TypeName) -> Self {
        Self::new_with_well_known(type_name, &WellKnownTypes::default())
    }

    fn new_with_well_known(type_name: TypeName, well_known: &WellKnownTypes) -> Self {
        Self {
            type_name,
            direct_relations: BTreeMap::new(),
            computed_relations: BTreeMap::new(),
            well_known: well_known.clone(),
            table_tuple_sources: Vec::new(),
            ownership_relations: BTreeMap::new(),
            gate_relations: BTreeMap::new(),
            membership_source_relations: BTreeMap::new(),
            conditions: BTreeMap::new(),
            reads_only_its_own_rows: false,
            narrowed_relations: BTreeSet::new(),
            source_table: None,
        }
    }

    /// Record which table's rows this type names, keeping the first spelling bound to
    /// it: a parent reached from a child is bound before the parent's own group is
    /// built, and both name one table.
    fn names_rows_of(&mut self, table: &TableId) {
        if self.source_table.is_none() {
            self.source_table = Some(table.clone());
        }
    }

    /// Relation carrying the subjects of an ownership source, named after
    /// `name_source` (`owner_id` → `owner`) and disambiguated on collision.
    ///
    /// `memo_key` namespaces the reuse: a jsonb path and a column spelled alike must
    /// not share a relation, or their two tuple sources union their principals.
    fn ownership_relation(&mut self, memo_key: &str, name_source: &str) -> RelationName {
        if let Some(existing) = self.ownership_relations.get(memo_key) {
            return existing.clone();
        }

        let base = parent_type_from_fk_column(name_source);
        let taken = |name: &str, plan: &Self| {
            let name = RelationName::canonicalized(name);
            reserved_relation_subjects(&name, &plan.well_known).is_some()
                || generator_defines(&name)
                || plan.direct_relations.contains_key(&name)
                || plan.computed_relations.contains_key(&name)
        };
        let name = if taken(base.as_str(), self) {
            let fallback = format!("owner_{}", canonical_fga_type_name(name_source));
            if taken(&fallback, self) {
                let hashed = format!("{fallback}_{}", stable_hex_suffix(memo_key));
                if taken(&hashed, self) {
                    let mut counter = 2u32;
                    loop {
                        let candidate = format!("{hashed}_{counter}");
                        if !taken(&candidate, self) {
                            break candidate;
                        }
                        counter += 1;
                    }
                } else {
                    hashed
                }
            } else {
                fallback
            }
        } else {
            base.to_string()
        };
        let relation = RelationName::canonicalized(clamp_relation_name(name));

        self.ownership_relations
            .insert(memo_key.to_string(), relation.clone());
        relation
    }

    /// Relation carrying one gate's `subjects`, keyed by what the gate tests.
    ///
    /// A memo hit shares the relation. A miss never adopts a name any other
    /// definition holds, whatever its subjects, or two gates' tuple sets would
    /// union under one relation.
    fn gate_relation(
        &mut self,
        memo_key: &str,
        base: impl Into<String>,
        subjects: Vec<DirectSubject>,
    ) -> RelationName {
        if let Some(existing) = self.gate_relations.get(memo_key) {
            return existing.clone();
        }
        let base = clamp_relation_name(base.into());
        let taken = |name: &RelationName, plan: &Self| {
            reserved_relation_subjects(name, &plan.well_known).is_some()
                || generator_defines(name)
                || plan.direct_relations.contains_key(name)
                || plan.computed_relations.contains_key(name)
        };
        // Unbounded on purpose: exhausting a bounded loop would adopt a taken name and
        // silently union two gates. Distinct counters give distinct names, and the
        // taken set is finite, so the loop terminates.
        let mut relation = RelationName::canonicalized(&base);
        let mut counter = 0u32;
        while taken(&relation, self) {
            counter += 1;
            let suffix = format!("_{counter}");
            let head: String = base
                .chars()
                .take(MAX_RELATION_NAME_LEN - suffix.len())
                .collect();
            relation = RelationName::canonicalized(format!("{head}{suffix}"));
        }
        self.direct_relations
            .entry(relation.clone())
            .or_insert(subjects);
        self.gate_relations
            .insert(memo_key.to_string(), relation.clone());
        relation
    }

    /// Each source's tuples satisfy only its own membership relation.
    fn membership_source_relation(
        &mut self,
        key: &str,
        base: impl Into<String>,
        subject: DirectSubject,
    ) -> RelationName {
        if let Some(relation) = self.membership_source_relations.get(key) {
            return relation.clone();
        }
        let base = clamp_relation_name(base.into());
        let mut relation = RelationName::canonicalized(&base);
        let mut counter = 0usize;
        while self.direct_relations.contains_key(&relation)
            || self.computed_relations.contains_key(&relation)
            || reserved_relation_subjects(&relation, &self.well_known).is_some()
            || generator_defines(&relation)
        {
            let suffix = if counter == 0 {
                format!("_{}", stable_hex_suffix(key))
            } else {
                format!("_{counter}")
            };
            let head: String = base
                .chars()
                .take(MAX_RELATION_NAME_LEN - suffix.len())
                .collect();
            relation = RelationName::canonicalized(format!("{head}{suffix}"));
            counter += 1;
        }
        self.direct_relations
            .insert(relation.clone(), vec![subject]);
        self.membership_source_relations
            .insert(key.to_string(), relation.clone());
        relation
    }

    /// Register a directly-assignable relation, returning the name actually used.
    fn ensure_direct(
        &mut self,
        relation: impl Into<String>,
        subjects: Vec<DirectSubject>,
    ) -> RelationName {
        let base = clamp_relation_name(relation.into());
        let key = subject_key(&subjects);
        // A name already held must yield rather than emit a second `define` or inherit
        // subjects it does not accept. The yielded name can be held too, since it is derived
        // from the value while whatever holds it may come from the schema, so keep looking:
        // the two maps are separate, and inserting blind would declare one name twice.
        let relation = yield_until_free(&base, &key, |relation| {
            self.computed_relations.contains_key(relation)
                || self
                    .direct_relations
                    .get(relation)
                    .is_some_and(|held| *held != subjects)
                || reserved_relation_subjects(relation, &self.well_known)
                    .is_some_and(|held| held != subjects)
                || generator_defines(relation)
        });
        self.direct_relations
            .entry(relation.clone())
            .or_insert(subjects);
        relation
    }

    /// Claims the literal `owner_team` relation for a role-threshold function's own
    /// owner type, the sole legitimate source for it. Unlike [`Self::ensure_direct`],
    /// this does not consult [`reserved_relation_subjects`]: that reservation exists to
    /// keep `owner_team` free from every other caller until this one claims it, not to
    /// disambiguate this call's own subjects, which vary with `team_type`.
    fn claim_owner_team_relation(&mut self, team_type: &TypeName) -> RelationName {
        let relation = owner_team_relation();
        self.direct_relations
            .entry(relation.clone())
            .or_insert_with(|| vec![DirectSubject::Type(team_type.clone())]);
        relation
    }

    fn ensure_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> RelationName {
        let base = clamp_relation_name(relation.into());
        let key = userset_key(&expr);
        // One name, one rule, or a caller deriving the name reads the wrong definition.
        let relation = yield_until_free(&base, &key, |relation| {
            self.direct_relations.contains_key(relation)
                || self
                    .computed_relations
                    .get(relation)
                    .is_some_and(|held| *held != expr)
                || generator_defines(relation)
        });
        self.computed_relations
            .entry(relation.clone())
            .or_insert(expr);
        relation
    }

    fn set_computed(&mut self, relation: impl Into<String>, expr: UsersetExpr) -> RelationName {
        let mut relation = RelationName::canonicalized(clamp_relation_name(relation.into()));
        // A name a direct relation already holds yields, exactly as `ensure_direct` and
        // `ensure_computed` do. Overwriting a computed rule is this function's whole
        // job, so only the direct case is a clash.
        if self.direct_relations.contains_key(&relation) {
            let key = userset_key(&expr);
            relation = RelationName::canonicalized(clamp_relation_name(format!(
                "{relation}_{}",
                stable_hex_suffix(key.as_str())
            )));
        }
        self.computed_relations.insert(relation.clone(), expr);
        relation
    }

    fn add_source(&mut self, source: TupleSource) {
        self.table_tuple_sources.push(source);
    }
}

/// The first name `held` does not refuse, renaming from `base` under `key` until free.
fn yield_until_free(base: &str, key: &str, held: impl Fn(&RelationName) -> bool) -> RelationName {
    let mut relation = RelationName::canonicalized(base);
    for attempt in 0..MAX_RELATION_RENAME_ATTEMPTS {
        if !held(&relation) {
            break;
        }
        relation = yielded_relation_name(base, key, attempt);
    }
    relation
}

/// Choices a deployment makes about the emitted model.
///
/// One struct rather than a growing parameter list, so the next setting costs a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorSettings {
    /// Condition parameter the caller supplies for a guard against statement time.
    pub request_time_parameter: ConditionParameterName,
    /// Type names the generator treats as its own vocabulary.
    pub well_known: WellKnownTypes,
    /// Who completes a comparison against a declared caller set.
    pub caller_set: CallerSetCompletion,
    /// The roles every caller runs as, against which each `TO` clause is settled.
    /// Without them a `TO` clause asks the consumer to load every role it names.
    pub caller_roles: Option<CallerRoles>,
}

impl Default for GeneratorSettings {
    fn default() -> Self {
        Self {
            request_time_parameter: ConditionParameterName::derived(REQUEST_TIME_PARAMETER),
            well_known: WellKnownTypes::default(),
            caller_set: CallerSetCompletion::Request,
            caller_roles: None,
        }
    }
}

/// Who completes a comparison against a set the deployment declared the caller holds
/// (`owner = ANY(string_to_array(current_setting('app.subjects', true), ','))`).
///
/// A check names one subject, so the set cannot be the subject of a tuple. What it can be
/// depends on who evaluates the model: a service completing the comparison from the
/// request, or a consumer that holds the subjects and matches a record against them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerSetCompletion {
    /// The request supplies the set as a condition parameter and the tuple carries the
    /// row's value, so the comparison runs inside the check.
    Request,
    /// The set is the subjects the caller holds, so the row's value names one of them
    /// and the record is keyed on it exactly as an identity comparison is.
    Subjects,
}

#[derive(Debug, Clone)]
pub(crate) struct SchemaPlan {
    pub types: Vec<TypePlan>,
    pub notes: Vec<TranslationNote>,
    pub confidence_summary: Vec<(String, ConfidenceLevel)>,
    /// Conditions any relation reference names, keyed by name.
    pub conditions: BTreeMap<ConditionName, ConditionSpec>,
    pub well_known: WellKnownTypes,
}

/// Why a translation cannot be planned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanningError {
    /// A table claimed a configured type name that belongs to the generator.
    #[error(
        "table '{table}' takes configured well-known type '{type_name}' from setting '{setting}'"
    )]
    ReservedTypeName {
        /// Table whose canonical name claims the configured type.
        table: String,
        /// Setting that chose that type name.
        setting: &'static str,
        /// The type name both sides tried to use.
        type_name: TypeName,
    },
    /// Two request sources were configured under one condition parameter.
    #[error("condition parameter `{parameter}` aliases request sources `{first}` and `{second}`")]
    ConditionParameterCollision {
        /// Parameter both sources tried to use.
        parameter: ConditionParameterName,
        /// Source configured first.
        first: String,
        /// Source configured second.
        second: String,
    },
    /// Two different conditions were named alike. A condition's name is read off its
    /// expression and parameters, so only a hash collision reaches this.
    #[error("two different conditions both take the name `{name}`")]
    ConditionNameCollision {
        /// The name both conditions took.
        name: ConditionName,
    },
    /// The model to be written crosses a `validate.rules` bound in `openfga/api`,
    /// which the `WriteAuthorizationModel` call would refuse.
    #[error(
        "the model crosses the OpenFGA {bound:?} bound at `{item}`: {measured} against {limit}"
    )]
    ModelBoundExceeded {
        /// The bound the model crosses.
        bound: crate::generator::model_bounds::ModelBound,
        /// The measured count or length.
        measured: usize,
        /// The limit the measurement may not cross.
        limit: usize,
        /// The item that crosses it, the name the bound applies to.
        item: String,
    },
}

struct ConditionParameterAllocator {
    request_sources: BTreeMap<ConditionParameterName, String>,
}

impl ConditionParameterAllocator {
    fn new(
        settings: &GeneratorSettings,
        registry: &FunctionRegistry,
    ) -> Result<Self, PlanningError> {
        let mut allocator = Self {
            request_sources: BTreeMap::new(),
        };
        allocator.reserve_request(
            settings.request_time_parameter.clone(),
            "request time".to_string(),
        )?;
        for attribute in registry.session_attributes() {
            let source = if attribute.path().is_empty() {
                attribute.setting_key().to_string()
            } else {
                format!("{}.{}", attribute.setting_key(), attribute.path().join("."))
            };
            allocator.reserve_request(attribute.condition_parameter().clone(), source)?;
        }
        Ok(allocator)
    }

    fn reserve_request(
        &mut self,
        parameter: ConditionParameterName,
        source: String,
    ) -> Result<(), PlanningError> {
        if let Some(first) = self.request_sources.get(&parameter) {
            return Err(PlanningError::ConditionParameterCollision {
                parameter,
                first: first.clone(),
                second: source,
            });
        }
        self.request_sources.insert(parameter, source);
        Ok(())
    }

    fn namespace<'a>(
        &self,
        request_parameters: impl IntoIterator<Item = &'a ConditionParameterName>,
    ) -> ConditionParameterNamespace {
        let used = request_parameters
            .into_iter()
            .map(|parameter| {
                debug_assert!(self.request_sources.contains_key(parameter));
                parameter.clone()
            })
            .collect();
        ConditionParameterNamespace { used }
    }
}

struct ConditionParameterNamespace {
    used: BTreeSet<ConditionParameterName>,
}

impl ConditionParameterNamespace {
    fn allocate_row(&mut self, source: &str) -> ConditionParameterName {
        let base = ConditionParameterName::derived(source);
        if self.used.insert(base.clone()) {
            return base;
        }

        let suffixed =
            ConditionParameterName::derived(&format!("{base}_{}", stable_hex_suffix(source)));
        if self.used.insert(suffixed.clone()) {
            return suffixed;
        }

        let mut sequence = 2_u64;
        loop {
            let candidate = ConditionParameterName::derived(&format!("{suffixed}_{sequence}"));
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
            sequence += 1;
        }
    }
}

/// Render the DSL text for a plan.
pub(crate) fn render_dsl_from_plan(plan: &SchemaPlan) -> String {
    render_dsl(&plan.types, &plan.conditions)
}

pub(crate) fn build_filtered_schema_plan<DB: DatabaseLike>(
    policies: &[ClassifiedPolicy],
    db: &DB,
    registry: &FunctionRegistry,
    min_confidence: ConfidenceLevel,
    settings: &GeneratorSettings,
    bounds: &UnboundedColumns,
) -> Result<SchemaPlan, PlanningError> {
    let filtered = filter_policies_for_output(policies, min_confidence);
    build_plan_typing(
        &filtered,
        db,
        registry,
        settings,
        bounds,
        PlanScope::Policies,
    )
}

#[cfg(test)]
pub(crate) fn build_schema_plan<DB: DatabaseLike>(
    policies: &[ClassifiedPolicy],
    db: &DB,
    registry: &FunctionRegistry,
    settings: &GeneratorSettings,
) -> Result<SchemaPlan, PlanningError> {
    let bounds = UnboundedColumns::resolve(db);
    build_plan_typing(
        policies,
        db,
        registry,
        settings,
        &bounds,
        PlanScope::Policies,
    )
}

/// Whether the plan describes catalog policies or one supplied read filter.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PlanScope<'a> {
    Policies,
    ReadTerm(&'a str),
}

/// Group supplied policies by resolved table and seed uncovered RLS tables for policy plans.
fn group_policies_by_table<'a, DB: DatabaseLike>(
    policies: &'a [ClassifiedPolicy],
    db: &DB,
    scope: PlanScope<'_>,
) -> BTreeMap<String, Vec<&'a ClassifiedPolicy>> {
    let mut by_table: BTreeMap<String, Vec<&ClassifiedPolicy>> = BTreeMap::new();
    for cp in policies {
        let key = cp
            .resolved_table()
            .map_or_else(|| cp.table_name().to_string(), ToString::to_string);
        by_table.entry(key).or_default().push(cp);
    }
    if matches!(scope, PlanScope::ReadTerm(_)) {
        return by_table;
    }

    // An RLS-enabled table with no policy denies every row, so seed it and let
    // the deny fill downstream cover its commands.
    let covered: BTreeSet<TableId> = by_table
        .keys()
        .filter_map(|name| lookup_table(db, name))
        .map(table_identity)
        .collect();
    for table in db.tables() {
        // A table whose RLS state cannot be read must still be deny-filled: a table
        // absent from the model reads as unconstrained.
        if table.has_row_level_security(db) == Ok(false) || covered.contains(&table_identity(table))
        {
            continue;
        }
        by_table.entry(qualified_table_name(table)).or_default();
    }
    by_table
}

/// The schema's own permissive policies, under the same key the classifications use.
///
/// The filtered set cannot say whether a policy exists at all. Splitting the two keys would
/// tell the operator RLS denies a command its own policy grants.
fn declared_permissive_policies<DB: DatabaseLike>(db: &DB) -> BTreeMap<String, Vec<&DB::Policy>> {
    let mut declared: BTreeMap<String, Vec<&DB::Policy>> = BTreeMap::new();
    for policy in db.policies() {
        if derive_policy_mode(policy) != PolicyMode::Permissive {
            continue;
        }
        let target = policy.target_table_name();
        let spelled = target.to_string();
        let key = db
            .resolve_target_table(target, IdentifierCase::AsWritten)
            .ok()
            .flatten()
            .map_or(spelled, qualified_table_name);
        declared.entry(key).or_default().push(policy);
    }
    declared
}

/// Parent identity to the spellings of its `INHERITS` children.
///
/// One pass, since `inheritors` walks every table per call. Partitions are not in this edge: a
/// partitioned root holds no rows of its own and its key spans every partition, so its plain
/// read is exact.
fn inheritance_children<DB: DatabaseLike>(db: &DB) -> BTreeMap<TableId, Vec<TableId>> {
    let mut children: BTreeMap<TableId, Vec<TableId>> = BTreeMap::new();
    for table in db.tables() {
        // A table iterated out of `db` is in `db`, so an unreadable parent list is
        // an empty one.
        for parent in table.inherits_from(db).into_iter().flatten() {
            children
                .entry(table_identity(parent))
                .or_default()
                .push(table_identity(table));
        }
    }
    children
}

/// Run `build` against one table's plan, taken out of `all_types` and put back after.
///
/// The plan has to leave the map for the duration: `translate_pattern` mints parent and holder
/// types, so it needs `&mut all_types` at the same time, and nothing can hold both that and a
/// borrow of one entry. Bracketing the pair is what stops it being half-written. Writing into
/// `all_types` for the table currently being built is discarded by the put-back, which is on the
/// trap list twice, and the closure's two arguments say which of the two to reach for.
fn with_table_plan<R>(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    type_name: &TypeName,
    well_known: &WellKnownTypes,
    build: impl FnOnce(&mut TypePlan, &mut BTreeMap<TypeName, TypePlan>) -> R,
) -> R {
    let mut plan = all_types
        .remove(type_name)
        .unwrap_or_else(|| TypePlan::new_with_well_known(type_name.clone(), well_known));
    let out = build(&mut plan, all_types);
    all_types.insert(type_name.clone(), plan);
    out
}

pub(crate) fn build_plan_typing<DB: DatabaseLike>(
    policies: &[ClassifiedPolicy],
    db: &DB,
    registry: &FunctionRegistry,
    settings: &GeneratorSettings,
    bounds: &UnboundedColumns,
    scope: PlanScope<'_>,
) -> Result<SchemaPlan, PlanningError> {
    let condition_parameters = ConditionParameterAllocator::new(settings, registry)?;
    let mut all_types: BTreeMap<TypeName, TypePlan> = BTreeMap::new();
    let mut notes = Vec::new();
    let mut confidence_summary = Vec::new();

    let catalog_policies = matches!(scope, PlanScope::Policies);
    if catalog_policies {
        for function in registry.owner_bound_accessors() {
            notes.push(TranslationNote::OwnerBoundFunction {
                function: function.to_string(),
            });
        }
        report_row_level_security_bypasses(db, &mut notes);
    }

    let by_table = group_policies_by_table(policies, db, scope);
    let declared_permissive = catalog_policies.then(|| declared_permissive_policies(db));

    let table_types = TableTypes::assign(db, scope, &settings.well_known, &mut notes)?;
    // Read terms refuse related-table RLS through classification, membership readability, and the caller-side check.
    let recursion = catalog_policies.then(|| PolicyReadRecursion::detect(db, &table_types));
    // Answered once per membership table rather than once per clause naming it.
    let mut readability: BTreeMap<TableId, TableReadability> = BTreeMap::new();
    let readability = &mut readability;

    let inheritance_children = inheritance_children(db);

    // Types a policy may have narrowed that no name resolved to. Applied after the
    // loop, since a bearer may be built after the group that named it.
    let mut unresolved_losses: BTreeMap<TypeName, BTreeSet<RelationName>> = BTreeMap::new();

    for (source_table_name, table_policies) in by_table {
        // Only RLS-enabled tables that resolve against the schema get a type. A name
        // the schema cannot resolve carries the policy nowhere, so say so.
        //
        // `parse_schema` refuses such a schema (`TableNotFoundForPolicy`), for an absent
        // name and an ambiguous unqualified one alike, so this answers a consumer's own
        // `DatabaseLike` rather than anything parsed here.
        let Some(source_table) = resolve_table_id(db, &source_table_name) else {
            let bearers = types_bearing_name(db, &source_table_name, &table_types);
            for cp in &table_policies {
                notes.push(TranslationNote::UnresolvedPolicyTable {
                    policy: cp.name().to_string(),
                    named: source_table_name.clone(),
                });
                let lost: BTreeSet<RelationName> = narrowed_by(&targets_a_policy_feeds(cp));
                for bearer in &bearers {
                    unresolved_losses
                        .entry(bearer.clone())
                        .or_default()
                        .extend(lost.iter().cloned());
                }
            }
            continue;
        };
        let Some(canonical_table_name) = table_types.get(&source_table) else {
            continue;
        };
        let canonical_table_name = canonical_table_name.clone();

        with_table_plan(
            &mut all_types,
            &canonical_table_name,
            &settings.well_known,
            |table_plan, other_types| {
                table_plan.names_rows_of(&source_table);

                // Once per table: `by_table` holds each table exactly once.
                let children = inheritance_children
                    .get(&source_table)
                    .cloned()
                    .unwrap_or_default();
                if !children.is_empty() {
                    table_plan.reads_only_its_own_rows = true;
                    let mut children = children;
                    children.sort();
                    notes.push(TranslationNote::InheritanceParentReadsOwnRowsOnly {
                        table: source_table.clone(),
                        children,
                    });
                }

                // A clause reading a table whose policies loop cannot be planned, so PostgreSQL
                // raises rather than filtering and every command that clause feeds must deny.
                let recursive_targets =
                    recursion.as_ref().map_or_else(BTreeMap::new, |recursion| {
                        recursion.blocked_targets(canonical_table_name.as_str())
                    });

                // Whether a row of this table can be named at all, which decides whether any tuple
                // source can be emitted for it. Resolved once here rather than per policy.
                let object_identifier = resolve_row_identity(&source_table, db);

                // UPDATE and DELETE name the row they change, so a denied read closes them.
                // INSERT does not name a row, and the read is the gate itself.
                let write_targets: BTreeSet<ActionTarget> = table_policies
                    .iter()
                    .filter(|cp| cp.mode() == PolicyMode::Permissive)
                    .flat_map(|cp| targets_a_policy_feeds(cp))
                    .collect();
                let row_scoped_write_commands: Vec<&'static str> = action_relation_commands()
                    .into_iter()
                    .filter(|(_, _, targets)| {
                        targets.iter().any(|target| {
                            matches!(target, ActionTarget::UpdateUsing | ActionTarget::Delete)
                                && write_targets.contains(target)
                        })
                    })
                    .map(|(_, command, _)| command)
                    .collect();

                // Every clause PostgreSQL evaluates that the model does not carry leaves the
                // relations it fed diverged from the database. Collected before anything is
                // translated, so a partial drop scars exactly like a total one rather than
                // resting on `no_access` happening to have no feeding sources. The note and
                // the scar are built from the same targets, so the two cannot disagree.
                let mut update_check_was_filtered = false;
                for cp in &table_policies {
                    for (clause, confidence, targets) in clauses_lost_to_the_threshold(cp) {
                        // A target the read loop already blocks is denied by PostgreSQL too, so
                        // the model is not narrower there and nothing may claim a divergence.
                        let targets: Vec<ActionTarget> = targets
                            .into_iter()
                            .filter(|target| !recursive_targets.contains_key(target))
                            .collect();
                        if targets.is_empty() {
                            continue;
                        }
                        if cp.mode() == PolicyMode::Permissive
                            && targets.contains(&ActionTarget::UpdateCheck)
                        {
                            update_check_was_filtered = true;
                        }
                        mark_narrowed(table_plan, &targets);
                        notes.push(TranslationNote::ClauseBelowThreshold {
                            table: source_table.clone(),
                            policy: cp.name().to_string(),
                            mode: cp.mode().to_string(),
                            clause: clause.to_string(),
                            confidence,
                            commands: commands_fed_by(&targets),
                            relations: narrowed_by(&targets).into_iter().collect(),
                        });
                    }
                }

                let mut build = TableBuild {
                    source_table: &source_table,
                    plan: table_plan,
                    other_types,
                    notes: &mut notes,
                    readability,
                    confidence_summary: &mut confidence_summary,
                    db,
                    registry,
                    settings,
                    table_types: &table_types,
                    condition_parameters: &condition_parameters,
                };
                let action_buckets = build.translate_policies(
                    table_policies,
                    &recursive_targets,
                    object_identifier.as_ref(),
                );

                // A grant whose facts cannot be written is a permission nothing can satisfy, so
                // each one above fell closed. Read the losses back off the skips they recorded,
                // rather than collecting them a second time, so the note and the loader's script
                scar_unfillable_grants(
                    build.plan,
                    build.notes,
                    &source_table,
                    &canonical_table_name,
                    bounds,
                    db,
                );
                note_request_contracts(build.plan, build.notes, settings);

                let blocked_commands = build.set_action_relations(
                    &action_buckets,
                    &recursive_targets,
                    update_check_was_filtered,
                );

                if let Some(declared_permissive) = &declared_permissive {
                    // Undefined policy actions must deny rather than leave access to the consumer.
                    let declared_here: &[&DB::Policy] = declared_permissive
                        .get(&source_table_name)
                        .map_or(&[], Vec::as_slice);
                    fill_and_report_coverage(
                        build.plan,
                        build.notes,
                        &source_table,
                        declared_here,
                        &SettledCommands {
                            blocked: &blocked_commands,
                            barrier_denied: &commands_denied_by_barriers_alone(&action_buckets),
                            row_scoped_writes: &row_scoped_write_commands,
                        },
                        db,
                    );
                }
            },
        );
    }

    // A policy whose table did not resolve may have been the one granting any table
    // bearing that name, and a dump does not record which, so each carries the loss.
    for (type_name, relations) in unresolved_losses {
        if let Some(plan) = all_types.get_mut(&type_name) {
            plan.narrowed_relations.extend(relations);
        }
    }

    all_types
        .entry(settings.well_known.user.clone())
        .or_insert_with(|| {
            TypePlan::new_with_well_known(settings.well_known.user.clone(), &settings.well_known)
        });

    simplify_redundant_select_gates(&mut all_types);
    inline_synthetic_rule_aliases(&mut all_types);
    drop_implied_insert_readback(&mut all_types);
    define_upsert_relations(&mut all_types);
    define_locking_read_relations(&mut all_types);
    define_blanket_update_relations(&mut all_types);
    prune_plain_subjects_fed_only_by_gated_sources(&mut all_types, &settings.well_known);
    prune_unreferenced_relations(&mut all_types);
    narrow_grant_sources_to_declared(&mut all_types);

    // After pruning, so a model with nothing to deny carries no such type, and only then,
    // since a denial that survives has to name a type the model declares.
    if all_types
        .values()
        .any(|plan| plan.direct_relations.contains_key(&deny_relation()))
    {
        all_types
            .entry(settings.well_known.nobody.clone())
            .or_insert_with(|| {
                TypePlan::new_with_well_known(
                    settings.well_known.nobody.clone(),
                    &settings.well_known,
                )
            });
    }

    let types = ordered_types(all_types, &settings.well_known.user);
    let conditions = surviving_conditions(&types)?;

    let plan = SchemaPlan {
        types,
        notes,
        confidence_summary,
        conditions,
        well_known: settings.well_known.clone(),
    };
    crate::generator::model_bounds::check(&crate::generator::json_model::json_model_from_plan(
        &plan,
    ))?;
    Ok(plan)
}

/// One table's build in progress.
///
/// The stages share the plan under construction, the map of the other types, the accumulators and
/// the read-only context. Threading those as arguments is what made the widest stage need fifteen
/// of them, so they live here and each stage takes only what varies.
struct TableBuild<'a, DB: DatabaseLike> {
    /// Table as the schema spells it.
    source_table: &'a TableId,
    /// The plan being built, out of the map for the duration.
    plan: &'a mut TypePlan,
    /// Every other type, which minting a parent or a holder reaches.
    other_types: &'a mut BTreeMap<TypeName, TypePlan>,
    /// Everything the translation has to say.
    notes: &'a mut Vec<TranslationNote>,
    /// Which membership tables a caller can read, answered once each.
    readability: &'a mut BTreeMap<TableId, TableReadability>,
    /// Per-clause grades, for the report.
    confidence_summary: &'a mut Vec<(String, ConfidenceLevel)>,
    /// The schema.
    db: &'a DB,
    /// Function semantics.
    registry: &'a FunctionRegistry,
    /// Caller-chosen names the emitted conditions respect.
    settings: &'a GeneratorSettings,
    condition_parameters: &'a ConditionParameterAllocator,
    /// Which table each type name belongs to.
    table_types: &'a TableTypes,
}

impl<DB: DatabaseLike> TableBuild<'_, DB> {
    /// Translate every clause of this table's policies into the buckets each action collects.
    ///
    /// The widest stage of the build, and the reason this is a value rather than a function: as
    /// free arguments it would take fifteen.
    fn translate_policies(
        &mut self,
        table_policies: Vec<&ClassifiedPolicy>,
        recursive_targets: &BTreeMap<ActionTarget, &[String]>,
        object_identifier: Option<&Vec<ColumnName>>,
    ) -> BTreeMap<ActionTarget, ModeBuckets> {
        let mut action_buckets: BTreeMap<ActionTarget, ModeBuckets> = BTreeMap::new();

        for cp in table_policies {
            self.translate_one_policy(
                cp,
                recursive_targets,
                object_identifier,
                &mut action_buckets,
            );
        }
        action_buckets
    }

    /// Translate one policy's clauses into the buckets its targets collect.
    ///
    /// One policy at a time, because a policy is the unit `PostgreSQL` combines: its mode decides
    /// whether a role scope narrows the grant or merely binds it, and its clauses are reported once
    /// per policy however many phases they cover.
    fn translate_one_policy(
        &mut self,
        cp: &ClassifiedPolicy,
        recursive_targets: &BTreeMap<ActionTarget, &[String]>,
        object_identifier: Option<&Vec<ColumnName>>,
        action_buckets: &mut BTreeMap<ActionTarget, ModeBuckets>,
    ) {
        // A policy the schema gives no clause constrains nothing, so it must not
        // mint a scope relation or ask for tuples either.
        if cp.using.is_none() && cp.with_check.is_none() {
            return;
        }
        // The threshold emptied this one, so it contributes no expression and must
        // not mint a scope relation, a note or a summary entry either. What it cost
        // is already recorded above.
        if cp.mode() == PolicyMode::Permissive
            && cp.using_classification.is_none()
            && cp.with_check_classification.is_none()
        {
            return;
        }
        // A clause PostgreSQL refuses to store never came out of a database, so
        // nothing downstream may read it as one. The INSERT spelling would
        // otherwise mint a grant through the USING-to-check mirror.
        if let Some(rule) =
            clause_illegal_for_command(cp.command(), cp.using.is_some(), cp.with_check.is_some())
        {
            self.notes.push(TranslationNote::PolicyClauseIllegal {
                policy: cp.name().to_string(),
                rule: rule.to_string(),
            });
            return;
        }
        // Nor may a policy every target of which is blocked: the loop denies each of
        // them, so a scope relation minted here would ask for tuples nothing reads.
        let mut reached = BTreeSet::new();
        for_each_policy_target_expr(cp, |target, _| {
            reached.insert(target);
        });
        if !reached.is_empty()
            && reached
                .iter()
                .all(|target| recursive_targets.contains_key(target))
        {
            return;
        }
        // PostgreSQL resolves these spellings to the DDL-running role when the
        // policy is created, so a schema file cannot know who they bind. Fall
        // closed per mode: a permissive grant is dropped, and a barrier binds
        // everyone by keeping its scope empty, named roles beside the spelling
        // included, since a barrier that also binds the DDL runner cannot be
        // narrowed to the names alone.
        let scope_unknowable = !cp.ddl_time_roles().is_empty();
        if scope_unknowable {
            self.notes.push(TranslationNote::PolicyBoundToDdlTimeRole {
                policy: cp.name().to_string(),
                spellings: cp.ddl_time_roles().to_vec(),
            });
            if cp.mode() == PolicyMode::Permissive {
                mark_narrowed(self.plan, &targets_a_policy_feeds(cp));
                return;
            }
        }
        let settled = match &self.settings.caller_roles {
            Some(callers) if !scope_unknowable && !cp.scoped_roles().is_empty() => {
                match self.settle_scope(callers, cp) {
                    Some(roles) => Some(roles),
                    None => return,
                }
            }
            _ => None,
        };
        if let Some(ref c) = cp.using_classification {
            self.confidence_summary
                .push((cp.name().to_string(), c.confidence));
        }
        if let Some(ref c) = cp.with_check_classification {
            self.confidence_summary
                .push((format!("{} (WITH CHECK)", cp.name()), c.confidence));
        }

        let scoped_roles: &[String] = if scope_unknowable {
            &[]
        } else {
            settled.as_deref().unwrap_or(cp.scoped_roles())
        };
        // A barrier is folded as `(base and rule) or (base but not member from scope)`, so
        // an unfillable scope excuses everyone from it. Binding everyone instead denies
        // more than RLS does, which is the direction a missing input has to take. The
        // permissive side needs no such case: it intersects with the scope, so an empty
        // one already falls closed.
        let barrier_cannot_bind = !scoped_roles.is_empty()
            && cp.mode() == PolicyMode::Restrictive
            && object_identifier.is_none();
        if barrier_cannot_bind {
            self.notes
                .push(TranslationNote::RestrictiveBarrierBindsEveryone {
                    policy: cp.name().to_string(),
                    roles: scoped_roles.to_vec(),
                });
        }
        let scope_relation = if scoped_roles.is_empty() || barrier_cannot_bind {
            None
        } else {
            let relation =
                role_scope_name(RolePrivilege::Usage.relation_name().as_str(), scoped_roles);
            // An unfillable scope mints nothing, and the rule it would have narrowed
            // denies for want of the same row identity, so there is no grant left to
            // narrow. Naming it anyway would ask the operator to load memberships
            // nothing reads.
            let filled = register_pg_role_scope(
                self.plan,
                &mut *self.other_types,
                self.notes,
                self.source_table,
                self.db,
                RoleScopeSpec {
                    scope_relation: &relation,
                    walked: &RolePrivilege::Usage.relation_name(),
                    role_names: scoped_roles,
                    scope_note: TranslationNote::PolicyRoleScope {
                        policy: cp.name().to_string(),
                        roles: scoped_roles.to_vec(),
                        relation: relation.clone(),
                    },
                    missing_object_what: "policy scope tuples",
                },
            );
            filled.then_some(relation)
        };

        // A policy covering several phases is translated once per phase, so the
        // same clause reports the same item repeatedly. Keep one per policy.
        let notes_before = self.notes.len();
        for_each_policy_target_expr(cp, |target, classified| {
            if recursive_targets.contains_key(&target) {
                // Nothing here can be planned, so translating it leaves dead relations.
                return;
            }
            let ctx = PatternCtx {
                policy_name: cp.name(),
                registry: self.registry,
                db: self.db,
                table_types: self.table_types,
                source_table: self.source_table,
                membership_reads_bypass_rls: false,
                settings: self.settings,
                condition_parameters: self.condition_parameters,
            };
            if let PatternClass::MembershipExclusion(MembershipExclusion {
                base: None,
                subtract,
            }) = &classified.pattern
            {
                if cp.mode() == PolicyMode::Restrictive {
                    if let Some(set) = emit_blocked_set(
                        subtract,
                        &ctx,
                        self.plan,
                        &mut *self.other_types,
                        self.notes,
                        self.readability,
                    ) {
                        let set = match &scope_relation {
                            Some(scope) => scoped_policy_expr(set, scope),
                            None => set,
                        };
                        action_buckets
                            .entry(target)
                            .or_default()
                            .subtractions
                            .push(set);
                        return;
                    }
                }
            }
            let expr = translate_pattern(
                &classified.pattern,
                &ctx,
                self.plan,
                &mut *self.other_types,
                self.notes,
                self.readability,
            );
            // A restrictive clause is a barrier, so a dropped conjunct must still deny.
            let guards = dropped_attribute_guards(&classified.pattern);
            let expr = if cp.mode() == PolicyMode::Restrictive && !guards.is_empty() {
                // The denial supersedes any runtime-enforcement note for the guard.
                for guard in guards {
                    let superseded = TranslationNote::AttributeNeedsRuntimeEnforcement {
                        policy: cp.name().to_string(),
                        attribute: guard.to_string(),
                    };
                    self.notes.retain(|note| *note != superseded);
                }
                self.notes
                    .push(TranslationNote::RestrictiveAttributeRefused {
                        policy: cp.name().to_string(),
                    });
                UsersetExpr::Intersection(vec![expr, deny_expr(self.plan)])
            } else {
                // A permissive conjunct handed to the application is enforced
                // nowhere in this model, so the rule grants rows the database
                // refuses. The one drift that widens rather than narrows.
                if !guards.is_empty() {
                    mark_narrowed(self.plan, &[target]);
                }
                expr
            };
            push_action_expr(
                action_buckets,
                target,
                cp.name(),
                cp.mode(),
                expr,
                scope_relation.as_ref(),
            );
        });
        dedup_notes_added_since(self.notes, notes_before);
    }

    /// The caller roles `cp`'s `TO` clause reaches, empty where it reaches every caller or
    /// binds every caller, and [`None`] where nothing of the policy is left to translate.
    fn settle_scope(
        &mut self,
        callers: &CallerRoles,
        cp: &ClassifiedPolicy,
    ) -> Option<Vec<String>> {
        match callers.settle(cp.scoped_roles(), self.db) {
            Settlement::Everyone => Some(Vec::new()),
            Settlement::Callers(roles) => Some(roles),
            Settlement::Nobody => {
                self.notes
                    .push(TranslationNote::PolicyAppliesToNoCallerRole {
                        policy: cp.name().to_string(),
                        roles: cp.scoped_roles().to_vec(),
                    });
                None
            }
            Settlement::Unsettled(roles) => {
                self.notes.push(TranslationNote::PolicyRoleUnsettled {
                    policy: cp.name().to_string(),
                    roles,
                });
                if cp.mode() == PolicyMode::Permissive {
                    mark_narrowed(self.plan, &targets_a_policy_feeds(cp));
                    None
                } else {
                    Some(Vec::new())
                }
            }
        }
    }

    /// Compose each action's rule from its buckets and assign the relations it answers for.
    ///
    /// The densest decision in the build. A per-row `UPDATE` or `DELETE` names the row it changes,
    /// so `PostgreSQL` applies the `SELECT` policies too and these relations intersect the read. A
    /// blanket `UPDATE` names no row and reads nothing, so it gets its own relation instead. A
    /// command whose targets a policy loop blocks is denied here rather than deny-filled, and a
    /// dropped permissive check must not come back as the `USING` it was refused beside.
    ///
    /// Returns the commands a loop denied, which the coverage report must not blame on a missing
    /// policy.
    fn set_action_relations(
        &mut self,
        action_buckets: &BTreeMap<ActionTarget, ModeBuckets>,
        recursive_targets: &BTreeMap<ActionTarget, &[String]>,
        update_check_was_filtered: bool,
    ) -> BTreeSet<&'static str> {
        let mut select_expr = compose_action(self.plan, action_buckets.get(&ActionTarget::Select));
        let mut insert_expr = compose_action(self.plan, action_buckets.get(&ActionTarget::Insert));
        let mut update_using_expr =
            compose_action(self.plan, action_buckets.get(&ActionTarget::UpdateUsing));
        // Composed only where an existing row can pass, since a WITH CHECK admits
        // the new row alone and never stands in for the missing USING.
        let mut update_check_expr = update_using_expr
            .is_some()
            .then(|| compose_action(self.plan, action_buckets.get(&ActionTarget::UpdateCheck)));
        let mut delete_expr = compose_action(self.plan, action_buckets.get(&ActionTarget::Delete));

        // Skipping the blocked targets above left their buckets empty, so the deny fill
        // below already answers for them. The UPDATE pair is the exception: a check the
        // fill never sees would fall back to mirroring the USING, which grants.
        if recursive_targets.contains_key(&ActionTarget::UpdateUsing)
            || recursive_targets.contains_key(&ActionTarget::UpdateCheck)
        {
            update_using_expr = None;
            update_check_expr = None;
        }

        // One note per loop, naming the commands it denies. A command denies as soon as
        // one of its targets is blocked, and its own coverage gap is then the loop rather
        // than a missing or dropped policy.
        let mut denied_by_loop: BTreeMap<&[String], Vec<&'static str>> = BTreeMap::new();
        for (_, command, targets) in action_relation_commands() {
            if let Some(cycle) = targets
                .iter()
                .find_map(|target| recursive_targets.get(target))
            {
                denied_by_loop.entry(cycle).or_default().push(command);
            }
        }
        let blocked_commands: BTreeSet<&'static str> =
            denied_by_loop.values().flatten().copied().collect();
        for (cycle, commands) in denied_by_loop {
            self.notes.push(TranslationNote::PolicyReadRecursion {
                table: self.source_table.clone(),
                commands: commands.into_iter().map(ToString::to_string).collect(),
                cycle: cycle.to_vec(),
            });
        }

        if let Some(expr) = select_expr.take() {
            self.plan.set_computed(can_select_relation(), expr);
        }
        if let Some(expr) = insert_expr.take() {
            self.plan.set_computed(
                can_insert_returning_relation(),
                requires_read_access(expr.clone()),
            );
            self.plan.set_computed(can_insert_relation(), expr);
        }
        // PostgreSQL applies the SELECT policies to any row a statement reads, and
        // naming the row to change reads it.
        if let Some(expr) = delete_expr.take() {
            self.plan
                .set_computed(can_delete_relation(), requires_read_access(expr));
        }

        if let Some(using_expr) = update_using_expr.take() {
            // A permissive check the threshold dropped must not come back as the USING.
            // `for_each_policy_target_expr` suppresses the mirror per policy, but this
            // fallback would resurrect exactly the clause that was refused. With no
            // surviving check arm the check half denies, while `can_update_using` keeps
            // the surviving USING so a locking read stays precise.
            let check_expr = update_check_expr.take().flatten().unwrap_or_else(|| {
                if update_check_was_filtered {
                    deny_expr(self.plan)
                } else {
                    using_expr.clone()
                }
            });
            // An update that names no row reads nothing, so `PostgreSQL` applies the
            // UPDATE policies to it and not the SELECT policies. This relation is the
            // USING half alone: it judges the row as it is, and where the clauses
            // differ [`ActionRelations`](crate::types::ActionRelations) pairs it
            // with `can_update_check` against the result. Fusing the check in would
            // answer the check against the existing row, which grants a change the
            // clause was written to refuse.
            self.plan
                .set_computed(can_update_without_reading_relation(), using_expr.clone());
            if using_expr == check_expr {
                self.plan
                    .set_computed(can_update_relation(), requires_read_access(using_expr));
            } else {
                self.plan.set_computed(
                    can_update_using_relation(),
                    requires_read_access(using_expr),
                );
                self.plan
                    .set_computed(can_update_check_relation(), check_expr);
                self.plan.set_computed(
                    can_update_relation(),
                    UsersetExpr::Intersection(vec![
                        UsersetExpr::Computed(can_update_using_relation()),
                        UsersetExpr::Computed(can_update_check_relation()),
                    ]),
                );
            }
        }
        blocked_commands
    }
}

/// What the policy loop already settled about each SQL command, so coverage reporting reads
/// its decisions rather than re-deriving them.
struct SettledCommands<'a> {
    /// Commands a read loop blocks, which `PostgreSQL` raises on rather than filtering.
    blocked: &'a BTreeSet<&'static str>,
    /// Commands a barrier with nothing permissive to narrow refuses outright.
    barrier_denied: &'a [&'static str],
    /// Commands that name the row they change, so a denied read closes them.
    row_scoped_writes: &'a [&'static str],
}

/// Fill what no surviving policy covers with a denial, and report which is which.
///
/// A command denied because every policy covering it fell below the bar gets a different line
/// from one no policy covers at all: the first says the model came out narrower than the database,
/// the second says the database denies it too. The schema is asked, since the filtered set cannot
/// tell them apart.
///
/// Coverage is read off which commands grant, not off which relations exist. A barrier with
/// nothing permissive to narrow leaves the relation defined and granting nobody, which the
/// absence reading missed.
fn fill_and_report_coverage<DB: DatabaseLike>(
    plan: &mut TypePlan,
    notes: &mut Vec<TranslationNote>,
    source_table: &TableId,
    declared_here: &[&DB::Policy],
    settled: &SettledCommands<'_>,
    db: &DB,
) {
    let filled = fill_uncovered_actions_with_deny(plan);
    let uncovered: Vec<&'static str> = action_relation_commands()
        .into_iter()
        .map(|(_, command, _)| command)
        .filter(|command| filled.contains(command) || settled.barrier_denied.contains(command))
        .filter(|command| !settled.blocked.contains(command))
        .collect();
    if !uncovered.is_empty() {
        let covered_by_schema = commands_a_permissive_policy_covers(declared_here, db);
        let (dropped, unpolicied): (Vec<&str>, Vec<&str>) = uncovered
            .into_iter()
            .partition(|command| covered_by_schema.contains(command));
        if !unpolicied.is_empty() {
            notes.push(TranslationNote::NoPermissivePolicy {
                table: source_table.clone(),
                commands: unpolicied.iter().map(|c| (*c).to_string()).collect(),
            });
        }
        if !dropped.is_empty() {
            notes.push(TranslationNote::CoveringPoliciesBelowThreshold {
                table: source_table.clone(),
                commands: dropped.iter().map(|c| (*c).to_string()).collect(),
            });
        }
    }

    for (policy_name, commands, clause) in policies_missing_a_clause(declared_here, db) {
        notes.push(TranslationNote::PolicyClauseAbsent {
            policy: policy_name,
            commands,
            clause: clause.to_string(),
        });
    }

    // Denying this silently would hide a schema mistake. Which writes it closes is the
    // per-command half of the same fact, so the note carries them rather than the reader
    // guessing from the table. Every one of them reads the row it changes through
    // `requires_read_access`, so a denied read closes all of them.
    if !settled.row_scoped_writes.is_empty()
        && relation_grants_nothing(plan, &can_select_relation())
    {
        notes.push(TranslationNote::ReadsDeniedSoWritesCannotName {
            table: source_table.clone(),
            commands: settled
                .row_scoped_writes
                .iter()
                .map(|command| (*command).to_string())
                .collect(),
        });
    }
}

/// The losses a table carries when a tuple cannot name what a grant needs.
///
/// Three readings of the same source list, kept apart because they are different losses: no row
/// identity at all, a bridge whose column the schema does not have, and a key whose rendered name
/// can reach the length cap.
fn scar_unfillable_grants<DB: DatabaseLike>(
    plan: &TypePlan,
    notes: &mut Vec<TranslationNote>,
    source_table: &TableId,
    type_name: &TypeName,
    bounds: &UnboundedColumns,
    db: &DB,
) {
    // cannot describe different losses. Nothing here is minted for a target the read
    // loop blocks: PostgreSQL raises there rather than granting, so the policy loop
    // never translated it and no skip exists to read.
    let unfillable: BTreeSet<String> = plan
        .table_tuple_sources
        .iter()
        .filter_map(|source| match source {
            TupleSource::Skipped {
                reason: SkippedTuples::NoObjectIdentifier { what, .. },
            } => Some(what.clone()),
            TupleSource::Skipped {
                reason: SkippedTuples::NoBridge { parent_type, .. },
            } => Some(format!("bridge tuples to '{parent_type}'")),
            _ => None,
        })
        .collect();
    if !unfillable.is_empty() {
        notes.push(TranslationNote::RowsCannotBeNamed {
            table: source_table.clone(),
            reason: missing_object_identifier_reason(source_table, db),
            sources: unfillable.into_iter().collect(),
        });
    }
    // The same reading, for a bridge whose column the schema does not have: the row
    // is nameable, so it is a different loss and says so.
    let unbridged: BTreeSet<(TypeName, ColumnName)> = plan
        .table_tuple_sources
        .iter()
        .filter_map(|source| match source {
            TupleSource::Skipped {
                reason:
                    SkippedTuples::BridgeColumnMissing {
                        parent_type,
                        fk_col,
                        ..
                    },
            } => Some((parent_type.clone(), fk_col.clone())),
            _ => None,
        })
        .collect();
    for (parent_type, column) in unbridged {
        notes.push(TranslationNote::BridgeColumnMissing {
            table: source_table.clone(),
            parent_type,
            column,
        });
    }

    // Where the guard is on, the operator is told the exact number. Gated the same
    // way the guard is, on whether the key's declared type can reach the cap, so a
    // `uuid` or integer key stays silent instead of putting a line on every table.
    if let Some(budget) = row_identifier_budget(source_table, type_name, bounds, db) {
        notes.push(TranslationNote::RowIdentifierBudget {
            table: source_table.clone(),
            budget,
        });
    }
}

/// Every request-scoped gate is a contract with the caller, and the model has nowhere to carry
/// it.
///
/// Read back off the sources the arms recorded, so the note and the emitted conditions cannot name
/// different parameters.
fn note_request_contracts(
    plan: &TypePlan,
    notes: &mut Vec<TranslationNote>,
    settings: &GeneratorSettings,
) {
    // Every request-scoped gate is a contract with the caller, and the model itself
    // has nowhere to carry it. Read the parameters back off the sources the arms
    // recorded, so the note and the emitted conditions cannot name different ones.
    let mut contracts: BTreeSet<(String, Option<String>, Option<String>)> = BTreeSet::new();
    for source in &plan.table_tuple_sources {
        match source {
            // A set carried against a row column and one carried against a membership row
            // state the same caller contract.
            TupleSource::SessionAttributeGate {
                request_parameter,
                setting_key,
                separator,
                ..
            } => {
                contracts.insert((
                    request_parameter.clone(),
                    Some(setting_key.clone()),
                    separator.clone(),
                ));
            }
            TupleSource::RequestGateEntry { atom, .. } => {
                contracts.insert((
                    atom.request_parameter.to_string(),
                    Some(atom.setting_key.clone()),
                    atom.separator.clone(),
                ));
            }
            TupleSource::CallerSetShareGate {
                request_parameter,
                setting_key,
                separator,
                temporal_context,
                ..
            } => {
                contracts.insert((
                    request_parameter.clone(),
                    Some(setting_key.clone()),
                    separator.clone(),
                ));
                // A clock composed into the gate is a second value the caller supplies.
                if !temporal_context.is_empty() {
                    contracts.insert((settings.request_time_parameter.to_string(), None, None));
                }
            }
            // The clock is a request value the caller supplies, whether it gates a single
            // row or rides a member tuple.
            TupleSource::ConditionalAttributeGate { .. }
            | TupleSource::ExistsMembership { gate: Some(_), .. }
            | TupleSource::HolderMembers { gate: Some(_), .. }
            | TupleSource::MembershipShareMembers { .. } => {
                contracts.insert((settings.request_time_parameter.to_string(), None, None));
            }
            _ => {}
        }
    }
    for (parameter, setting_key, separator) in contracts {
        notes.push(TranslationNote::CallerSuppliesConditionParameter {
            parameter,
            setting_key,
            separator,
        });
    }
}

/// The plans in emission order, caller type first and the rest by name.
fn ordered_types(
    mut all_types: BTreeMap<TypeName, TypePlan>,
    user_type: &TypeName,
) -> Vec<TypePlan> {
    let mut type_names: Vec<TypeName> = all_types.keys().cloned().collect();
    type_names.sort();
    if let Some(pos) = type_names.iter().position(|n| n == user_type) {
        let user = type_names.remove(pos);
        type_names.insert(0, user);
    }
    type_names
        .into_iter()
        .filter_map(|name| all_types.remove(&name))
        .collect()
}

/// Only the conditions a surviving reference still names.
///
/// A policy dropped by confidence filtering cannot leave a condition behind. Two type
/// plans declare one condition under one name, since the name is read off the content,
/// and two different conditions reaching one name is refused rather than merged.
fn surviving_conditions(
    types: &[TypePlan],
) -> Result<BTreeMap<ConditionName, ConditionSpec>, PlanningError> {
    let named: BTreeSet<&ConditionName> = types
        .iter()
        .flat_map(|plan| plan.direct_relations.values())
        .flatten()
        .filter_map(|subject| match subject {
            DirectSubject::ConditionalWildcard { condition, .. }
            | DirectSubject::ConditionalType { condition, .. } => Some(condition),
            DirectSubject::Type(_) | DirectSubject::Wildcard(_) => None,
        })
        .collect();
    let mut conditions = BTreeMap::new();
    for (name, spec) in types
        .iter()
        .flat_map(|plan| plan.conditions.iter())
        .filter(|(name, _)| named.contains(name))
    {
        match conditions.get(name) {
            Some(held) if held != spec => {
                return Err(PlanningError::ConditionNameCollision { name: name.clone() })
            }
            Some(_) => {}
            None => {
                conditions.insert(name.clone(), spec.clone());
            }
        }
    }
    Ok(conditions)
}

fn source_carries_condition(source: &TupleSource) -> bool {
    matches!(
        source,
        TupleSource::ConditionalAttributeGate { .. }
            | TupleSource::SessionAttributeGate { .. }
            | TupleSource::RequestGateEntry { .. }
            | TupleSource::CallerSetShareGate { .. }
            | TupleSource::ExistsMembership { gate: Some(_), .. }
            | TupleSource::HolderMembers { gate: Some(_), .. }
            | TupleSource::MembershipShareMembers { .. }
    )
}

fn prune_plain_subjects_fed_only_by_gated_sources(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    well_known: &WellKnownTypes,
) {
    let mut all_gated: BTreeMap<(TypeName, RelationName), bool> = BTreeMap::new();
    for plan in all_types.values() {
        for source in &plan.table_tuple_sources {
            let carries_condition = source_carries_condition(source);
            for target in source.feeds(&plan.type_name) {
                all_gated
                    .entry(target)
                    .and_modify(|known| *known &= carries_condition)
                    .or_insert(carries_condition);
            }
        }
    }

    for ((type_name, relation), gated) in all_gated {
        if !gated {
            continue;
        }
        let Some(plan) = all_types.get_mut(&type_name) else {
            continue;
        };
        let Some(subjects) = plan.direct_relations.get_mut(&relation) else {
            continue;
        };
        let has_conditional_type = subjects.iter().any(|subject| {
            matches!(
                subject,
                DirectSubject::ConditionalType { type_name, .. }
                    if type_name == &well_known.user
            )
        });
        let has_conditional_wildcard = subjects.iter().any(|subject| {
            matches!(
                subject,
                DirectSubject::ConditionalWildcard { type_name, .. }
                    if type_name == &well_known.user
            )
        });
        subjects.retain(|subject| {
            !matches!(subject, DirectSubject::Type(type_name) if has_conditional_type && type_name == &well_known.user)
                && !matches!(subject, DirectSubject::Wildcard(type_name) if has_conditional_wildcard && type_name == &well_known.user)
        });
    }
}

/// Report the principals row level security does not reach.
///
/// The model keeps describing the rules that do apply. Modelling a bypass as a
/// permission would be the largest widening available here, and it misfires the moment
/// a service account stops running as the exempt principal.
///
/// The table's owner is the third mechanism, named where the schema assigns one and
/// generic where it does not, since an unreadable answer must not invent a role.
fn report_row_level_security_bypasses<DB: DatabaseLike>(db: &DB, notes: &mut Vec<TranslationNote>) {
    for role in db.roles() {
        if role.can_bypass_rls() {
            notes.push(TranslationNote::RoleBypassesPolicies {
                role: role.name().to_string(),
            });
        }
    }
    for table in db.tables() {
        // Fail closed on an unreadable answer in the direction that reports rather than
        // hides: only a definite yes means the owner is subject to the policies.
        if table.has_row_level_security(db) == Ok(true)
            && table.has_forced_row_level_security(db) != Ok(true)
        {
            notes.push(TranslationNote::TableOwnerBypassesPolicies {
                table: table_identity(table),
                // An unreadable answer is not a name, so the note stays generic.
                owner: table.owner(db).ok().flatten().map(str::to_string),
            });
        }
        // A read naming the partition applies the partition's policies, which a partition
        // of a protected root has none of. Reported rather than folded into the
        // unrestricted tables: those show every row by every route, and these rows are
        // filtered through the root, which is the route the model answers for.
        if table.has_row_level_security(db) == Ok(false) {
            if let Some(root) = protecting_partition_root(table, db) {
                notes.push(TranslationNote::PartitionReadDirectlyIsUnfiltered {
                    table: table_identity(table),
                    root: table_identity(root),
                });
            }
        }
    }
}

/// The nearest ancestor whose policies filter a read through it, if any.
///
/// A read names one table and `PostgreSQL` applies that table's policies, so a partition
/// several levels down is filtered by nothing while the policies sit at the top. Walking
/// only one level up finds an unprotected middle table and reports nothing, which leaves
/// the leaf's direct read undisclosed.
fn protecting_partition_root<'db, DB: DatabaseLike>(
    table: &'db DB::Table,
    db: &'db DB,
) -> Option<&'db DB::Table> {
    let mut current = table.partition_root(db).ok()??;
    loop {
        if current.has_row_level_security(db) == Ok(true) {
            return Some(current);
        }
        current = current.partition_root(db).ok()??;
    }
}

/// The type standing for everyone listed in `member_table`.
fn holder_type_name(member_table: &TableId, table_types: &TableTypes) -> TypeName {
    disambiguated_kind_type_name(member_table, table_types, "holder")
}

/// The type standing for the share rows of a caller-set membership on `join_table`.
fn share_type_name(join_table: &TableId, table_types: &TableTypes) -> TypeName {
    disambiguated_kind_type_name(join_table, table_types, "share")
}

/// The type standing for the team members of a team-membership table, named with
/// `well_known.team`'s configured word, and keyed on the table so two different
/// team-membership tables never pool their members into one type.
fn team_type_name(
    team_membership_table: &TableId,
    table_types: &TableTypes,
    well_known: &WellKnownTypes,
) -> TypeName {
    disambiguated_kind_type_name(team_membership_table, table_types, well_known.team.as_str())
}

/// Builds the base kind-suffix type name and appends a hex hash if `table_types` already claims it.
fn disambiguated_kind_type_name(table: &TableId, table_types: &TableTypes, kind: &str) -> TypeName {
    let base = canonical_fga_type_name(&format!("{table}_{kind}"));
    if table_types.claims(&base) {
        // Keyed on the resolved type rather than the spelling, so a dumped
        // qualification cannot move the name.
        return canonical_fga_type_name(&format!(
            "{base}_{}",
            stable_hex_suffix(table_types.resolve(table).as_str())
        ));
    }
    base
}

/// The type standing for the owner identities `grant_table` records grants over.
///
/// One per role-threshold function, so every table using that function shares one owner
/// and two functions cannot pool their ladders. Where the schema holds more than one such
/// function, every owner type is named by its own function: nothing here can prove two
/// grant-table spellings name different tables, and a shared name would merge two ladders
/// whose levels differ.
fn owner_type_name(
    grant_table: &TableId,
    function_name: &str,
    registry: &FunctionRegistry,
    table_types: &TableTypes,
) -> TypeName {
    let base = canonical_fga_type_name(&format!("{grant_table}_owner"));
    let one_function = registry
        .functions
        .values()
        .filter(|semantic| matches!(semantic, FunctionSemantic::RoleThreshold { .. }))
        .count()
        <= 1;
    if one_function && !table_types.claims(&base) {
        return base;
    }
    canonical_fga_type_name(&format!("{base}_{}", stable_hex_suffix(function_name)))
}

/// Every `(type, relation)` a permission can consult. Anything unresolved counts as
/// reachable, since dropping a needed query would narrow the model.
pub(crate) fn grantable_relations(types: &[TypePlan]) -> BTreeSet<(TypeName, RelationName)> {
    let by_name: BTreeMap<&TypeName, &TypePlan> =
        types.iter().map(|plan| (&plan.type_name, plan)).collect();
    let mut reached: BTreeSet<(TypeName, RelationName)> = BTreeSet::new();
    for plan in types {
        for action in action_relations().chain(derived_action_relations()) {
            let Some(expr) = plan.computed_relations.get(&action) else {
                continue;
            };
            if grants_nothing(expr, plan, &mut BTreeSet::new()) {
                continue;
            }
            reach_userset(expr, plan, &by_name, &mut reached);
        }
    }
    reached
}

/// Every type whose table may be the one an unresolvable name denotes. `PostgreSQL`
/// picked one through the search path and a dump does not record it, so each of them
/// may be the table that lost the clause. A qualified name resolving to nothing bears
/// on no table at all, which is what `same_identifier` answers for it.
fn types_bearing_name<DB: DatabaseLike>(
    db: &DB,
    named: &str,
    table_types: &TableTypes,
) -> Vec<TypeName> {
    db.tables()
        .filter(|table| stored_relation_name(named) == table.stored_table_name())
        .filter_map(|table| table_types.by_identity.get(&table_identity(table)))
        .cloned()
        .collect()
}

/// Readability of one membership table, computed once per plan per table.
///
/// With caller roles declared, the roles its read policies are scoped to are settled
/// against them, so a read scope names only roles a caller runs as.
fn join_table_readability<'a, DB: DatabaseLike>(
    join_table: &TableId,
    ctx: &PatternCtx<'_, DB>,
    memo: &'a mut BTreeMap<TableId, TableReadability>,
    notes: &mut Vec<TranslationNote>,
) -> &'a TableReadability {
    memo.entry(join_table.clone()).or_insert_with(|| {
        let scope = table_readability(join_table, ctx.db, ctx.registry, &ExpansionState::new());
        let (Some(callers), TableReadability::Guarded { roles }) =
            (&ctx.settings.caller_roles, &scope)
        else {
            return scope;
        };
        if roles.is_empty() {
            return scope;
        }
        match callers.settle(roles, ctx.db) {
            Settlement::Everyone => TableReadability::Guarded { roles: Vec::new() },
            Settlement::Callers(roles) => TableReadability::Guarded { roles },
            Settlement::Nobody => TableReadability::Unreadable,
            Settlement::Unsettled(roles) => {
                notes.push(TranslationNote::PolicyRoleUnsettled {
                    policy: ctx.policy_name.to_string(),
                    roles,
                });
                TableReadability::Unreadable
            }
        }
    })
}

/// Returns the membership read constraints, or `None` when no row is visible.
fn noted_membership_read_scope<'a, DB: DatabaseLike>(
    join_table: &TableId,
    ctx: &PatternCtx<'_, DB>,
    memo: &'a mut BTreeMap<TableId, TableReadability>,
    notes: &mut Vec<TranslationNote>,
) -> Option<&'a TableReadability> {
    if ctx.membership_reads_bypass_rls {
        return Some(&TableReadability::Open);
    }
    let scope = join_table_readability(join_table, ctx, memo, notes);
    match scope {
        TableReadability::Unreadable => {
            notes.push(TranslationNote::MembershipTableGrantsNoReads {
                policy: ctx.policy_name.to_string(),
                join_table: join_table.clone(),
            });
            None
        }
        TableReadability::Guarded { .. } => {
            notes.push(TranslationNote::MembershipTableGuarded {
                policy: ctx.policy_name.to_string(),
                join_table: join_table.clone(),
            });
            Some(scope)
        }
        TableReadability::Open | TableReadability::RequestGated { .. } => Some(scope),
    }
}

/// Schema-qualified stored name, in the spelling `lookup_table` resolves.
pub(crate) fn qualified_table_name<T: TableLike>(table: &T) -> String {
    table_identity(table).to_string()
}

/// Final `OpenFGA` type name of every table that gets one, assigned in one pass so a
/// parent reference resolves to the same type as the table's own policies.
struct TypeOwner {
    identity: TableId,
}

#[derive(Default)]
struct TableTypes {
    by_identity: BTreeMap<TableId, TypeName>,
    owners: BTreeMap<TypeName, TypeOwner>,
    reserved: BTreeMap<TypeName, &'static str>,
}

impl TableTypes {
    fn new(well_known: &WellKnownTypes) -> Self {
        Self {
            reserved: well_known
                .reserved()
                .into_iter()
                .map(|(setting, type_name)| (type_name.clone(), setting))
                .collect(),
            ..Self::default()
        }
    }

    /// Whether a table or reserved generator type already holds this type name.
    fn claims(&self, type_name: &TypeName) -> bool {
        self.owners.contains_key(type_name) || self.reserved.contains_key(type_name)
    }

    /// The schema identity of the table holding this type, found by its rendered name.
    ///
    /// By name rather than by `TypeName`, because the read graph carries the names the
    /// model declares.
    fn spelling_of(&self, type_name: &str) -> String {
        self.owners
            .iter()
            .find(|(name, _)| name.as_str() == type_name)
            .map_or_else(
                || type_name.to_string(),
                |(_, owner)| owner.identity.to_string(),
            )
    }
}

impl TableTypes {
    /// One type name per table the plan constrains, collisions suffixed with a hash of
    /// the qualified name.
    ///
    /// Derived from the schema alone, never from which policies survived filtering,
    /// so names do not move with the confidence threshold. Tables carrying policies
    /// claim their canonical name first.
    fn assign<DB: DatabaseLike>(
        db: &DB,
        scope: PlanScope<'_>,
        well_known: &WellKnownTypes,
        notes: &mut Vec<TranslationNote>,
    ) -> Result<Self, PlanningError> {
        let mut types = Self::new(well_known);
        let mut policied: BTreeSet<TableId> = BTreeSet::new();
        for policy in db.policies() {
            if let Some(table) = lookup_table(db, &policy.target_table_name().to_string()) {
                policied.insert(table_identity(table));
            }
        }
        // A subscription filter guards a table that carries no policy, so its type
        // cannot wait for row-level security to be switched on.
        let forced = match scope {
            PlanScope::Policies => None,
            PlanScope::ReadTerm(table) => lookup_table(db, table).map(table_identity),
        };

        let mut names: Vec<(bool, TableId)> = db
            .tables()
            .filter(|table| {
                table.has_row_level_security(db) != Ok(false)
                    || forced.as_ref() == Some(&table_identity(table))
            })
            .map(|table| {
                let identity = table_identity(table);
                (!policied.contains(&identity), identity)
            })
            .collect();
        names.sort();

        for (_, identity) in &names {
            if types.by_identity.contains_key(identity) {
                continue;
            }

            let spelling = identity.to_string();
            let base = canonical_fga_type_name(&spelling);
            if let Some(setting) = types.reserved.get(&base) {
                return Err(PlanningError::ReservedTypeName {
                    table: spelling.clone(),
                    setting,
                    type_name: base.clone(),
                });
            }
            let assigned = match types.owners.get(&base) {
                Some(prior) => {
                    let disambiguated = canonical_fga_type_name(&format!(
                        "{base}_{}",
                        stable_hex_suffix(&spelling)
                    ));
                    if let Some(setting) = types.reserved.get(&disambiguated) {
                        return Err(PlanningError::ReservedTypeName {
                            table: spelling.clone(),
                            setting,
                            type_name: disambiguated.clone(),
                        });
                    }
                    if matches!(scope, PlanScope::Policies) || forced.as_ref() == Some(identity) {
                        notes.push(TranslationNote::TypeNameCollision {
                            spelling: identity.clone(),
                            prior: prior.identity.clone(),
                            canonical: base.to_string(),
                            renamed: disambiguated.to_string(),
                        });
                    }
                    disambiguated
                }
                None => base,
            };
            types.owners.insert(
                assigned.clone(),
                TypeOwner {
                    identity: identity.clone(),
                },
            );
            types.by_identity.insert(identity.clone(), assigned);
        }
        Ok(types)
    }

    /// Type of `table`, or `None` when it has no type (unresolvable or RLS off).
    fn get(&self, table: &TableId) -> Option<&TypeName> {
        self.by_identity.get(table)
    }

    /// Type of `table`, deriving one when it has none: a parent without RLS still
    /// needs a type for the child to point at. The derived name steps aside when
    /// another table already owns it, so the child cannot inherit that table's
    /// permissions.
    fn resolve(&self, table: &TableId) -> TypeName {
        if let Some(assigned) = self.by_identity.get(table) {
            return assigned.clone();
        }
        let spelling = table.to_string();
        let base = canonical_fga_type_name(&spelling);
        match self.owners.get(&base) {
            Some(owner) if owner.identity != *table => {
                canonical_fga_type_name(&format!("{base}_{}", stable_hex_suffix(&spelling)))
            }
            _ => base,
        }
    }
}

/// Drop notes added since `start` that repeat an earlier one. A policy covering
/// several phases is translated once per phase, so the same clause reports the same
/// note each time.
fn dedup_notes_added_since(notes: &mut Vec<TranslationNote>, start: usize) {
    let mut seen: Vec<TranslationNote> = Vec::new();
    let mut index = start;
    while index < notes.len() {
        let Some(note) = notes.get(index) else { break };
        if seen.contains(note) {
            notes.remove(index);
        } else {
            seen.push(note.clone());
            index += 1;
        }
    }
}

fn deny_expr(table_plan: &mut TypePlan) -> UsersetExpr {
    table_plan.ensure_direct(
        deny_relation(),
        vec![DirectSubject::Type(table_plan.well_known.nobody.clone())],
    );
    UsersetExpr::Computed(deny_relation())
}

fn combine_exprs(
    mut exprs: Vec<UsersetExpr>,
    wrapper: fn(Vec<UsersetExpr>) -> UsersetExpr,
) -> Option<UsersetExpr> {
    match exprs.len() {
        0 => None,
        1 => exprs.pop(),
        _ => Some(wrapper(exprs)),
    }
}

fn combine_union(exprs: Vec<UsersetExpr>) -> Option<UsersetExpr> {
    combine_exprs(exprs, UsersetExpr::Union)
}

fn combine_intersection(exprs: Vec<UsersetExpr>) -> Option<UsersetExpr> {
    combine_exprs(exprs, UsersetExpr::Intersection)
}

/// Translate a pattern against a table whose rows a tuple can name, which is what the
/// pattern arms assume. Use [`pattern_to_expr_without_row_identity`] for the other case.
#[cfg(test)]
fn pattern_to_expr(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    pattern_to_expr_against(
        "CREATE TABLE projects(id UUID PRIMARY KEY);
CREATE TABLE object_grants(grantee_id UUID, resource_id UUID, role_level INTEGER);
CREATE TABLE test_table(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));",
        pattern,
        policy_name,
        table_plan,
        all_types,
        registry,
        notes,
    )
}

/// Translate a pattern against a table no schema declares, so nothing names its rows.
#[cfg(test)]
fn pattern_to_expr_without_row_identity(
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    pattern_to_expr_against(
        "",
        pattern,
        policy_name,
        table_plan,
        all_types,
        registry,
        notes,
    )
}

#[cfg(test)]
fn pattern_to_expr_against(
    schema: &str,
    pattern: &PatternClass,
    policy_name: &str,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    registry: &FunctionRegistry,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let db = crate::parser::sql_parser::parse_schema(schema).expect("schema should parse");
    let source_table = TableId::from_stored(None, "test_table".to_string());
    let settings = GeneratorSettings::default();
    let condition_parameters =
        ConditionParameterAllocator::new(&settings, registry).expect("parameters should allocate");
    let table_types = TableTypes::default();
    translate_pattern(
        pattern,
        &PatternCtx {
            policy_name,
            registry,
            db: &db,
            table_types: &table_types,
            source_table: &source_table,
            membership_reads_bypass_rls: false,
            settings: &settings,
            condition_parameters: &condition_parameters,
        },
        table_plan,
        all_types,
        notes,
        &mut BTreeMap::new(),
    )
}

/// Everything a pattern arm reads and nobody mutates.
///
/// Passed by reference and re-targeted through [`PatternCtx::for_table`], which is what a
/// parent-rule recursion needs. A context holding the mutable state could not do that: the
/// recursion swaps the plan it writes to while keeping the map that plan came out of, so
/// those four stay explicit parameters.
struct PatternCtx<'a, DB: DatabaseLike> {
    /// Policy the clause belongs to, named in every note the arms raise.
    policy_name: &'a str,
    /// Function semantics, for the arms that resolve a call.
    registry: &'a FunctionRegistry,
    /// The schema.
    db: &'a DB,
    /// Which table each type name belongs to.
    table_types: &'a TableTypes,
    /// Table the clause guards, which a parent recursion re-targets.
    source_table: &'a TableId,
    /// Caller-chosen names the emitted conditions have to respect.
    settings: &'a GeneratorSettings,
    condition_parameters: &'a ConditionParameterAllocator,
    /// True inside a definer expansion whose table reads were proven to bypass
    /// those tables' policies, so membership readability is not asked.
    membership_reads_bypass_rls: bool,
}

impl<'a, DB: DatabaseLike> PatternCtx<'a, DB> {
    /// The same context reading a different table, which is what a parent rule is
    /// translated against.
    fn for_table(&self, source_table: &'a TableId) -> Self {
        Self {
            source_table,
            ..*self
        }
    }

    /// The same context inside a definer expansion whose reads were proven to
    /// bypass the read tables' policies.
    fn with_bypassed_reads(&self) -> Self {
        Self {
            membership_reads_bypass_rls: true,
            ..*self
        }
    }
}

/// Build the userset expression for one classified pattern.
///
/// The result does not depend on which command the policy covers: inheritance
/// always reads the parent's SELECT relation, and the caller files the expression
/// under the right action.
fn translate_pattern<DB: DatabaseLike>(
    pattern: &PatternClass,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let source_table = ctx.source_table;
    match pattern {
        PatternClass::P1NumericThreshold(numeric_threshold) => {
            emit_numeric_threshold(numeric_threshold, ctx, table_plan, all_types, notes)
        }
        PatternClass::P2RoleNameInList(role_name_in_list) => {
            emit_role_name_in_list(role_name_in_list, ctx, table_plan, all_types, notes)
        }
        PatternClass::P3DirectOwnership(DirectOwnership { column }) => {
            emit_direct_ownership(column, ctx, table_plan)
        }
        PatternClass::P11ArrayMembership(ArrayMembership { column }) => emit_row_ownership(
            column.as_str(),
            column.as_str(),
            "array membership tuples",
            ctx,
            table_plan,
            |identity_cols, relation| TupleSource::ArrayMembership {
                table: source_table.clone(),
                identity_cols,
                array_col: column.clone(),
                relation,
            },
        ),
        PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { column, path }) => {
            emit_row_ownership(
                &format!("jsonb:{column}:{}", path.join(".")),
                &path.join("_"),
                "jsonb field ownership tuples",
                ctx,
                table_plan,
                |identity_cols, relation| TupleSource::JsonbFieldOwnership {
                    table: source_table.clone(),
                    identity_cols,
                    column: column.clone(),
                    path: path.clone(),
                    relation,
                },
            )
        }
        PatternClass::P13UncorrelatedMembership(uncorrelated_membership) => {
            emit_uncorrelated_membership(
                uncorrelated_membership,
                ctx,
                table_plan,
                all_types,
                notes,
                readability,
            )
        }
        PatternClass::P18MembershipInCallerSet(MembershipInCallerSet { membership, .. })
            if ctx.settings.caller_set == CallerSetCompletion::Subjects =>
        {
            emit_exists_membership(membership, ctx, table_plan, all_types, notes, readability)
        }
        PatternClass::P18MembershipInCallerSet(membership_in_caller_set) => {
            emit_membership_in_caller_set(
                membership_in_caller_set,
                ctx,
                table_plan,
                all_types,
                notes,
                readability,
            )
        }
        PatternClass::P4ExistsMembership(exists_membership) => emit_exists_membership(
            exists_membership,
            ctx,
            table_plan,
            all_types,
            notes,
            readability,
        ),
        PatternClass::MembershipExclusion(exclusion) => {
            emit_membership_exclusion(exclusion, ctx, table_plan, all_types, notes, readability)
        }
        PatternClass::P5ParentInheritance(parent_inheritance) => emit_parent_inheritance(
            parent_inheritance,
            ctx,
            table_plan,
            all_types,
            notes,
            readability,
        ),
        PatternClass::P19IndirectMembership(indirect) => {
            emit_indirect_membership(indirect, ctx, table_plan, all_types, notes, readability)
        }
        PatternClass::ExpandedFunction(expanded) => {
            notes.push(TranslationNote::FunctionExpanded {
                policy: ctx.policy_name.to_string(),
                function: expanded.function.clone(),
            });
            let ctx = if expanded.reads_bypass_rls {
                ctx.with_bypassed_reads()
            } else {
                ctx.for_table(source_table)
            };
            let body = translate_pattern(
                &expanded.inner.pattern,
                &ctx,
                table_plan,
                all_types,
                notes,
                readability,
            );
            if expanded.presence_columns.is_empty() {
                body
            } else {
                let presence = emit_row_presence_gate(&expanded.presence_columns, &ctx, table_plan);
                combine_intersection(vec![body, presence]).unwrap_or_else(|| deny_expr(table_plan))
            }
        }
        PatternClass::P6BooleanFlag(boolean_flag) => {
            if boolean_flag.admits_null
                && column_is_nullable(ctx.source_table, boolean_flag.column.as_str(), ctx.db)
                    != Some(false)
            {
                notes.push(TranslationNote::NullableBooleanFlagNarrowed {
                    policy: ctx.policy_name.to_string(),
                    column: boolean_flag.column.clone(),
                });
            }
            emit_boolean_flag(boolean_flag, ctx, table_plan)
        }
        PatternClass::P7AbacAnd(abac_and) => {
            emit_abac_and(abac_and, ctx, table_plan, all_types, notes, readability)
        }
        PatternClass::P8Composite(composite) => {
            emit_composite(composite, ctx, table_plan, all_types, notes, readability)
        }
        PatternClass::P9AttributeCondition(attribute_condition) => {
            emit_attribute_condition(attribute_condition, ctx, table_plan, notes)
        }
        PatternClass::P10ConstantBool(constant_bool) => {
            emit_constant_bool(constant_bool, ctx, table_plan)
        }
        PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { column, .. })
            if ctx.settings.caller_set == CallerSetCompletion::Subjects =>
        {
            emit_direct_ownership(column, ctx, table_plan)
        }
        PatternClass::P14RowValueInCallerSet(RowValueInCallerSet {
            column,
            source,
            separator,
        }) => emit_request_gate(
            RequestSide {
                source,
                comparison: RequestComparison::CallerSetHolds,
                separator: separator.as_deref(),
            },
            column,
            ctx,
            table_plan,
        ),
        PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
            column,
            source,
        }) => emit_request_gate(
            RequestSide {
                source,
                comparison: RequestComparison::CallerValueEquals,
                separator: None,
            },
            column,
            ctx,
            table_plan,
        ),
        PatternClass::P16ConstantInCallerSet(test) => emit_request_formula(
            &RequestFormula::Atom(GateAtom::held_by_caller_set(test)),
            ctx,
            table_plan,
            all_types,
        ),
        PatternClass::P17CallerScalarEqualsConstant(test) => emit_request_formula(
            &RequestFormula::Atom(GateAtom::equal_to_caller_value(test)),
            ctx,
            table_plan,
            all_types,
        ),
        PatternClass::Unknown(unclassified) => {
            emit_unclassified(unclassified, ctx, table_plan, notes)
        }
    }
}

/// Characters this table's key may render before the guard leaves the row out, or
/// `None` where the key's declared type cannot reach the cap.
///
/// The budget covers the whole `type:id` string, so it shrinks as the type name
/// grows and two tables of the same schema can have different numbers.
fn row_identifier_budget<DB: DatabaseLike>(
    source_table: &TableId,
    type_name: &TypeName,
    bounds: &UnboundedColumns,
    db: &DB,
) -> Option<usize> {
    let key = resolve_row_identity(source_table, db)?;
    if !bounds.any_unbounded(source_table, &key) {
        return None;
    }
    MAX_OBJECT_NAME_CHARS.checked_sub(type_name.as_str().chars().count() + 1)
}

/// Explain why `source_table` has no usable `OpenFGA` object identifier.
fn missing_object_identifier_reason<DB: DatabaseLike>(source_table: &TableId, db: &DB) -> String {
    if let Some(columns) = composite_primary_key_columns(source_table, db) {
        return format!(
            "composite primary key ({}) leaves no single-column object identifier",
            columns.join(", ")
        );
    }
    if table_id_has_column(db, source_table, "id") {
        return "no primary key, and 'id' is nullable or not uniquely constrained, so it does \
                not identify a row"
            .to_string();
    }
    "missing object identifier column".to_string()
}

/// Record that a tuple query cannot be emitted, because no single column names a row.
///
/// The grant it would have filled falls closed at the call site, and one note per table
/// is derived from the skips recorded here so the two cannot describe different losses.
fn skip_source_without_row_identity<DB: DatabaseLike>(
    table_plan: &mut TypePlan,
    source_table: &TableId,
    what: &str,
    db: &DB,
) {
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::NoObjectIdentifier {
            table: source_table.clone(),
            what: what.to_string(),
            reason: missing_object_identifier_reason(source_table, db),
        },
    });
}

/// Whether the bridge linking a row of `source_table` to its parent can be written,
/// recording the loss when it cannot.
///
/// Asked here rather than left to the renderer, which has only a comment to carry the
/// answer: a bridge nobody writes leaves the grant above it satisfiable by no one, and
/// the caller falls closed on `false`.
fn bridge_is_buildable<DB: DatabaseLike>(
    table_plan: &mut TypePlan,
    source_table: &TableId,
    fk_cols: &[ColumnName],
    parent_type: &TypeName,
    db: &DB,
) -> bool {
    if resolve_bridge_columns(source_table, fk_cols, db).is_some() {
        return true;
    }
    let missing = fk_cols
        .iter()
        .find(|col| !table_id_has_column(db, source_table, col.as_str()));
    let reason = match missing {
        Some(fk_col) if resolve_row_identity(source_table, db).is_some() => {
            SkippedTuples::BridgeColumnMissing {
                table: source_table.clone(),
                parent_type: parent_type.clone(),
                fk_col: fk_col.clone(),
            }
        }
        _ => SkippedTuples::NoBridge {
            table: source_table.clone(),
            parent_type: parent_type.clone(),
            reason: missing_object_identifier_reason(source_table, db),
        },
    };
    table_plan.add_source(TupleSource::Skipped { reason });
    false
}

fn ensure_user_direct(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    type_name: &TypeName,
    relation: &RelationName,
    well_known: &WellKnownTypes,
) {
    all_types
        .entry(type_name.clone())
        .or_insert_with(|| TypePlan::new_with_well_known(type_name.clone(), well_known))
        .ensure_direct(
            relation.clone(),
            vec![DirectSubject::Type(well_known.user.clone())],
        );
}

fn ensure_member_type(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    type_name: &TypeName,
    well_known: &WellKnownTypes,
) {
    ensure_user_direct(all_types, type_name, &member_relation(), well_known);
}

/// Give `pg_role` a relation holding one kind of role membership, for an operator to load.
fn ensure_pg_role_relation(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    relation: &RelationName,
    well_known: &WellKnownTypes,
) {
    ensure_user_direct(all_types, &well_known.pg_role, relation, well_known);
}

/// Bind a parent type to the table whose rows it names, in the spelling the plan groups
/// tables under, so an entry the loop writes and one a parent reference writes agree.
fn bind_row_source<DB: DatabaseLike>(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    type_name: &TypeName,
    table: &TableId,
    _db: &DB,
) {
    if let Some(plan) = all_types.get_mut(type_name) {
        plan.names_rows_of(table);
    }
}

fn resolve_owner_column<DB: DatabaseLike>(table: &TableId, db: &DB) -> Option<ColumnName> {
    let table_info = lookup_table_id(db, table)?;
    for col in table_info.columns(db).into_iter().flatten() {
        let name = col.stored_column_name();
        if is_owner_like_column_name(&name) {
            return Some(ColumnName::from_stored(name));
        }
    }
    for fk in table_info.foreign_keys(db).into_iter().flatten() {
        let Ok(ref_table) = fk.referenced_table(db) else {
            continue;
        };
        let stored_ref = ref_table.stored_table_name();
        if stored_ref == "users" || stored_ref == "owners" {
            if let Some(col_name) = fk
                .host_columns(db)
                .into_iter()
                .flatten()
                .next()
                .map(|col| ColumnName::from_stored(col.stored_column_name()))
            {
                return Some(col_name);
            }
        }
    }
    None
}

/// Returns the name of the table that `fk_column` in `table` references, or
/// `None` if no matching FK constraint is found in the schema.
fn referenced_table_for_fk_col<DB: DatabaseLike>(
    db: &DB,
    table: &TableId,
    fk_column: &ColumnName,
) -> Option<TableId> {
    let table_info = lookup_table_id(db, table)?;
    for fk in table_info.foreign_keys(db).into_iter().flatten() {
        let uses_col = fk
            .host_columns(db)
            .into_iter()
            .flatten()
            .any(|c| *fk_column == c.stored_column_name().into_owned());
        if uses_col {
            return fk.referenced_table(db).ok().map(table_identity);
        }
    }
    None
}

fn resolve_principal_info<DB: DatabaseLike>(
    db: &DB,
    configured_table: Option<&str>,
    configured_pk_col: Option<&ColumnName>,
    fallback_candidates: &[&str],
) -> Option<PrincipalInfo> {
    if let Some(table) = configured_table.and_then(|table| resolve_table_id(db, table)) {
        let identity_col = if let Some(identity_col) = configured_pk_col {
            if !table_id_has_column(db, &table, identity_col.as_str()) {
                return None;
            }
            identity_col.clone()
        } else {
            single_identity_column(&table, db)?
        };
        return Some(PrincipalInfo {
            table,
            identity_col,
        });
    }

    for &candidate in fallback_candidates {
        let Some(table) = resolve_table_id(db, candidate) else {
            continue;
        };
        if let Some(identity_col) = single_identity_column(&table, db) {
            return Some(PrincipalInfo {
                table,
                identity_col,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests;
