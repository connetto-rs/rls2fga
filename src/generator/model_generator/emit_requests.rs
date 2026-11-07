//! Emission for the patterns the request completes rather than the row.
//!
//! A declared setting or token claim supplies the caller's half, so the row carries its value in
//! a condition rather than in the tuple's subject. Also the conditions an attribute guard needs
//! when the value is one only the request knows.

use super::emit_membership::{
    announce_residual, apply_membership_read_scope, link_share_rows, share_reach, MembershipParent,
    ShareRows,
};
use super::*;

/// Mint the relation, the condition and the tuple source a row column compared against a
/// declared request-scoped value needs.
///
/// The tuple carries what only the row knows, the request what only the caller knows,
/// and the condition relates them. Returns `None` when no tuple can name the row, so the
/// caller falls back to closing the policy.
pub(crate) fn session_attribute_expr<DB: DatabaseLike>(
    declared: RequestSide<'_>,
    column: &ColumnName,
    policy_name: &str,
    source_table: &TableId,
    table_plan: &mut TypePlan,
    condition_parameters: &ConditionParameterAllocator,
    db: &DB,
) -> Option<UsersetExpr> {
    let RequestSide {
        source,
        comparison,
        separator,
    } = declared;
    let identity_cols = resolve_row_identity(source_table, db)?;

    let request_parameter = source.condition_parameter();
    let mut namespace = condition_parameters.namespace([request_parameter]);
    let row_parameter = namespace.allocate_row(column.as_str());
    let spec = request_comparison_spec(&row_parameter, request_parameter, comparison);
    let condition = declare_condition(table_plan, spec);

    let memo_key = format!(
        "session:{}:{policy_name}:{condition}:{column:?}",
        policy_name.len()
    );
    let subjects = vec![DirectSubject::ConditionalWildcard {
        type_name: table_plan.well_known.user.clone(),
        condition: condition.clone(),
    }];
    let relation = table_plan.gate_relation(
        &memo_key,
        conditional_gate_relation_name(policy_name),
        subjects,
    );
    table_plan.add_source(TupleSource::SessionAttributeGate {
        table: source_table.clone(),
        identity_cols,
        relation: relation.clone(),
        condition,
        row_parameter: row_parameter.to_string(),
        column: column.clone(),
        request_parameter: request_parameter.to_string(),
        setting_key: source.setting_key().to_string(),
        separator: separator.map(str::to_string),
        comparison,
    });
    Some(UsersetExpr::Computed(relation))
}

/// The condition comparing what a tuple carries under `row_parameter` against what the
/// caller supplies under `request_parameter`.
fn request_comparison_spec(
    row_parameter: &ConditionParameterName,
    request_parameter: &ConditionParameterName,
    comparison: RequestComparison,
) -> ConditionSpec {
    let (request_type, operator) = match comparison {
        RequestComparison::CallerSetHolds => {
            (ConditionParameter::ListOf(STRING_PARAMETER_TYPE), "in")
        }
        RequestComparison::CallerValueEquals => {
            (ConditionParameter::Scalar(STRING_PARAMETER_TYPE), "==")
        }
    };
    ConditionSpec {
        expression: format!("{row_parameter} {operator} {request_parameter}"),
        parameters: [
            (
                row_parameter.to_string(),
                ConditionParameter::Scalar(STRING_PARAMETER_TYPE),
            ),
            (request_parameter.to_string(), request_type),
        ]
        .into_iter()
        .collect(),
    }
}

/// The request's half of the comparison, as the policy declared it.
#[derive(Clone, Copy)]
pub(crate) struct RequestSide<'a> {
    /// The declared source, carrying the parameter the caller supplies.
    pub(crate) source: &'a SessionAttribute,
    /// How the two sides are compared.
    pub(crate) comparison: RequestComparison,
    /// Separator the policy splits the setting on, for a set.
    pub(crate) separator: Option<&'a str>,
}

/// Gate rows on a formula only the request decides.
///
/// The formula has one truth value for every row, so it is stated once, on the object of
/// the request-gate type standing for this type. Each test is one tuple there under a
/// condition shared by every test of its kind, and the formula's `AND` and `OR` are the
/// model's own. `OpenFGA` bounds the cost of each condition evaluation, so one test per
/// evaluation keeps the longest list a caller can send at what one test allows. The row
/// carries one link to the object whatever the number of gates.
pub(crate) fn emit_request_formula<DB: DatabaseLike>(
    formula: &RequestFormula,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> UsersetExpr {
    match formula {
        RequestFormula::Const(true) => {
            return emit_constant_bool(&ConstantBool { value: true }, ctx, table_plan)
        }
        RequestFormula::Const(false) => return deny_expr(table_plan),
        RequestFormula::Atom(_) | RequestFormula::Any(_) | RequestFormula::All(_) => {}
    }
    let Some(identity_cols) = resolve_row_identity(ctx.source_table, ctx.db) else {
        skip_source_without_row_identity(
            table_plan,
            ctx.source_table,
            "request gate links",
            ctx.db,
        );
        return deny_expr(table_plan);
    };

    let well_known = &ctx.settings.well_known;
    let gate_type = well_known.request_gate.clone();
    let gate_object = table_plan.type_name.to_string();
    let mut entries = Vec::new();
    let relation = {
        let gate_plan = all_types
            .entry(gate_type.clone())
            .or_insert_with(|| TypePlan::new_with_well_known(gate_type.clone(), well_known));
        let mut gate = GateObject {
            plan: gate_plan,
            object: &gate_object,
            condition_parameters: ctx.condition_parameters,
            entries: &mut entries,
        };
        gate.relation(formula)
    };
    let Some(relation) = relation else {
        return deny_expr(table_plan);
    };
    for entry in entries {
        table_plan.add_source(entry);
    }

    let link = table_plan.ensure_direct(
        request_gate_link_relation(),
        vec![DirectSubject::Type(gate_type.clone())],
    );
    table_plan.add_source(TupleSource::PolicyScope {
        table: ctx.source_table.clone(),
        identity_cols,
        scope_relation: link.clone(),
        scope_type: gate_type,
        scope_object: gate_object,
    });
    UsersetExpr::TupleToUserset {
        tupleset: link,
        computed: relation,
    }
}

/// The request-gate object standing for one guarded type, while a formula is stated on it.
struct GateObject<'a> {
    plan: &'a mut TypePlan,
    object: &'a str,
    condition_parameters: &'a ConditionParameterAllocator,
    /// One tuple per test, written on the object.
    entries: &'a mut Vec<TupleSource>,
}

impl GateObject<'_> {
    /// The relation of the request-gate type standing for `formula`, or `None` for a
    /// constant.
    ///
    /// Named after the formula's content, so one formula is one relation wherever it
    /// gates, and two guarded types share it on their own objects.
    fn relation(&mut self, formula: &RequestFormula) -> Option<RelationName> {
        match formula {
            RequestFormula::Const(_) => None,
            RequestFormula::Atom(atom) => {
                let mut namespace = self
                    .condition_parameters
                    .namespace([&atom.request_parameter]);
                // The rule supplies it, so it is named after what it is rather than after
                // its value, which may be any text at all.
                let row_parameter = namespace.allocate_row("required_value");
                let spec = request_comparison_spec(
                    &row_parameter,
                    &atom.request_parameter,
                    atom.comparison,
                );
                let condition = declare_condition(self.plan, spec);
                let verb = match atom.comparison {
                    RequestComparison::CallerSetHolds => "holds",
                    RequestComparison::CallerValueEquals => "is",
                };
                let subjects = vec![DirectSubject::ConditionalWildcard {
                    type_name: self.plan.well_known.user.clone(),
                    condition: condition.clone(),
                }];
                let key = formula.key();
                let relation = self.plan.gate_relation(
                    &format!("request:{key}"),
                    request_gate_relation_name(
                        &format!("{}_{verb}_{}", atom.request_parameter, atom.value),
                        &key,
                    ),
                    subjects,
                );
                self.entries.push(TupleSource::RequestGateEntry {
                    gate_type: self.plan.type_name.clone(),
                    gate_object: self.object.to_string(),
                    relation: relation.clone(),
                    condition,
                    row_parameter: row_parameter.to_string(),
                    atom: atom.clone(),
                });
                Some(relation)
            }
            RequestFormula::Any(children) | RequestFormula::All(children) => {
                let members = children
                    .iter()
                    .map(|child| self.relation(child).map(UsersetExpr::Computed))
                    .collect::<Option<Vec<_>>>()?;
                let (readable, expr) = if matches!(formula, RequestFormula::Any(_)) {
                    ("any", UsersetExpr::Union(members))
                } else {
                    ("all", UsersetExpr::Intersection(members))
                };
                Some(self.plan.ensure_computed(
                    request_gate_relation_name(readable, &formula.key()).to_string(),
                    expr,
                ))
            }
        }
    }
}

/// Declare `spec` on this type plan under the name its content earns, and answer with
/// that name.
pub(crate) fn declare_condition(table_plan: &mut TypePlan, spec: ConditionSpec) -> ConditionName {
    let name = spec.name();
    table_plan.conditions.insert(name.clone(), spec);
    name
}

/// Mint the relation, the condition and the tuple source a request-time guard needs.
///
/// Returns `None` when the row cannot be identified or the column's type has no
/// condition parameter type, so the caller falls back to closing the policy.
pub(crate) fn conditional_gate_expr<DB: DatabaseLike>(
    request: &AttributeRequestPredicate,
    policy_name: &str,
    source_table: &TableId,
    table_plan: &mut TypePlan,
    condition_parameters: &ConditionParameterAllocator,
    db: &DB,
) -> Option<UsersetExpr> {
    let identity_cols = resolve_row_identity(source_table, db)?;
    let parameter_type = condition_parameter_type(source_table, request.column.as_str(), db)?;

    let clock = condition_parameters.clock_operand(request.threshold);
    let mut namespace = condition_parameters.namespace([]);
    namespace.reserve(clock.parameter.name());
    let row_parameter = namespace.allocate_row(request.column.as_str());
    let operator = request.operator.cel();

    let condition = declare_condition(
        table_plan,
        ConditionSpec {
            expression: format!("{row_parameter} {operator} {}", clock.cel),
            parameters: [
                (
                    row_parameter.to_string(),
                    ConditionParameter::Scalar(parameter_type),
                ),
                clock.declaration(),
            ]
            .into_iter()
            .collect(),
        },
    );

    let memo_key = format!(
        "clock:{}:{policy_name}:{condition}:{:?}",
        policy_name.len(),
        request.column
    );
    let subjects = vec![DirectSubject::ConditionalWildcard {
        type_name: table_plan.well_known.user.clone(),
        condition: condition.clone(),
    }];
    let relation = table_plan.gate_relation(
        &memo_key,
        conditional_gate_relation_name(policy_name),
        subjects,
    );
    table_plan.add_source(TupleSource::ConditionalAttributeGate {
        table: source_table.clone(),
        identity_cols,
        relation: relation.clone(),
        condition,
        row_parameter: row_parameter.to_string(),
        column: request.column.clone(),
    });
    Some(UsersetExpr::Computed(relation))
}

/// The condition parameter type for a column, or `None` when the schema does not say
/// or the type has no `OpenFGA` counterpart.
pub(crate) fn condition_parameter_type<DB: DatabaseLike>(
    table: &TableId,
    column: &str,
    db: &DB,
) -> Option<&'static str> {
    (column_kind(table, column, db) == ColumnKind::TimestampTz).then_some(TIMESTAMP_PARAMETER_TYPE)
}

/// One temporal comparison lifted into a condition: the parameter the row fills, the
/// column it reads, the CEL fragment comparing it against the request clock, and the
/// clock operand that fragment reads.
pub(crate) struct TemporalGate {
    pub(crate) parameter: ConditionParameterName,
    pub(crate) column: ColumnName,
    pub(crate) fragment: String,
    pub(crate) clock: ClockOperand,
    pub(crate) witness: ContextWitness,
    pub(crate) monotone: bool,
}

/// Keep the clock parameters `residual`'s temporal comparisons read from every row
/// parameter `namespace` allocates afterwards.
pub(crate) fn reserve_temporal_clocks(
    residual: &ResidualPredicates,
    condition_parameters: &ConditionParameterAllocator,
    namespace: &mut ConditionParameterNamespace,
) {
    let Some(decision) = residual.decidable() else {
        return;
    };
    for request in &decision.requests {
        namespace.reserve(
            condition_parameters
                .clock_operand(request.threshold)
                .parameter
                .name(),
        );
    }
}

/// Turn a residual's temporal comparisons (`col > now()`) into condition fragments
/// against the clock the request supplies.
///
/// [`None`] when the residual is not decidable off the row and the clock, or a temporal
/// column has no timestamp parameter type: the caller then leaves the residual in SQL and
/// the shape stays joined, exactly as it did before the clock could be a condition.
pub(crate) fn temporal_gates<DB: DatabaseLike>(
    residual: &ResidualPredicates,
    table: &TableId,
    condition_parameters: &ConditionParameterAllocator,
    namespace: &mut ConditionParameterNamespace,
    db: &DB,
) -> Option<Vec<TemporalGate>> {
    let decision = residual.decidable()?;
    reserve_temporal_clocks(residual, condition_parameters, namespace);
    let mut gates = Vec::with_capacity(decision.requests.len());
    for request in &decision.requests {
        // A zoned column has a timestamp parameter. Anything else cannot be a faithful
        // condition, so the whole residual stays in SQL.
        condition_parameter_type(table, request.column.as_str(), db)?;
        let parameter = namespace.allocate_row(request.column.as_str());
        let clock = condition_parameters.clock_operand(request.threshold);
        gates.push(TemporalGate {
            fragment: format!("{parameter} {} {}", request.operator.cel(), clock.cel),
            clock,
            column: request.column.clone(),
            witness: request.operator.context_witness(),
            monotone: request.operator.is_monotone(),
            parameter,
        });
    }
    Some(gates)
}

/// Declare a condition comparing one or more row columns against the request clock, and
/// answer with its name and the context columns a tuple must carry.
///
/// [`None`] when the residual is not decidable off the row and the clock, or carries no
/// clock at all: the caller then keeps the residual in SQL and the shape stays joined.
pub(crate) fn declare_temporal_condition<DB: DatabaseLike>(
    residual: &ResidualPredicates,
    table: &TableId,
    table_plan: &mut TypePlan,
    condition_parameters: &ConditionParameterAllocator,
    db: &DB,
) -> Option<(ConditionName, Vec<GateContextColumn>)> {
    let mut namespace = condition_parameters.namespace([]);
    let gates = temporal_gates(residual, table, condition_parameters, &mut namespace, db)?;
    if gates.is_empty() {
        return None;
    }
    let expression = gates
        .iter()
        .map(|gate| gate.fragment.as_str())
        .collect::<Vec<_>>()
        .join(" && ");
    let parameters: BTreeMap<String, ConditionParameter> = gates
        .iter()
        .flat_map(|gate| {
            [
                (
                    gate.parameter.to_string(),
                    ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
                ),
                gate.clock.declaration(),
            ]
        })
        .collect();
    let condition = declare_condition(
        table_plan,
        ConditionSpec {
            expression,
            parameters,
        },
    );
    let context = gates
        .into_iter()
        .map(|gate| GateContextColumn {
            parameter: gate.parameter.to_string(),
            column: gate.column,
            witness: gate.witness,
            monotone: gate.monotone,
        })
        .collect();
    Some((condition, context))
}

/// The gate a row column compared against a declared request-scoped value earns, for
/// P14 testing membership in the caller's set and P15 testing equality with the
/// caller's value.
pub(crate) fn emit_request_gate<DB: DatabaseLike>(
    declared: RequestSide<'_>,
    column: &ColumnName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    session_attribute_expr(
        declared,
        column,
        ctx.policy_name,
        ctx.source_table,
        table_plan,
        ctx.condition_parameters,
        ctx.db,
    )
    .unwrap_or_else(|| {
        skip_source_without_row_identity(
            table_plan,
            ctx.source_table,
            "request-scoped gate tuples",
            ctx.db,
        );
        deny_expr(table_plan)
    })
}

/// A membership row whose member value the caller's declared set has to contain,
/// completed by the request.
pub(crate) fn emit_membership_in_caller_set<DB: DatabaseLike>(
    membership_in_caller_set: &MembershipInCallerSet,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let MembershipInCallerSet {
        membership:
            ExistsMembership {
                join_table,
                pairs,
                user_column: member_column,
                extra_predicates,
            },
        separator,
        source,
    } = membership_in_caller_set;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    // The subquery reads `join_table` as the caller, so its own RLS decides which
    // membership rows count, exactly as it does for a membership naming a person.
    let Some(read_scope) = noted_membership_read_scope(join_table, ctx, readability, notes) else {
        return deny_expr(table_plan);
    };
    if let TableReadability::Guarded { roles } = read_scope {
        if !roles.is_empty() {
            notes.push(TranslationNote::ExpressionRefused {
                policy: policy_name.to_string(),
                reason: format!(
                    "only {} may read {join_table}, and a request-scoped gate cannot \
                         yet be narrowed to a role scope",
                    roles.join(", ")
                ),
            });
            return deny_expr(table_plan);
        }
    }
    let Some(parent) = MembershipParent::resolve(pairs, join_table, ctx, table_plan, notes) else {
        return deny_expr(table_plan);
    };
    // One object per share row, or two viewers of one row collide on one gate tuple.
    let Some(identity_cols) = resolve_row_identity(join_table, db) else {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!(
                "{join_table} has no primary key, so its share rows cannot be named apart \
                     and two viewers of one row would collide at load"
            ),
        });
        return deny_expr(table_plan);
    };

    let request_parameter = source.condition_parameter().clone();
    let mut namespace = ctx.condition_parameters.namespace([&request_parameter]);
    reserve_temporal_clocks(extra_predicates, ctx.condition_parameters, &mut namespace);
    let row_parameter = namespace.allocate_row(member_column.as_str());

    // The clock joins the viewer set inside the condition, since the request completes it.
    let temporal = temporal_gates(
        extra_predicates,
        join_table,
        ctx.condition_parameters,
        &mut namespace,
        db,
    )
    .unwrap_or_default();

    announce_residual(extra_predicates, !temporal.is_empty(), policy_name, notes);

    let mut expression = format!("{row_parameter} in {request_parameter}");
    let mut parameters = vec![
        (
            row_parameter.to_string(),
            ConditionParameter::Scalar(STRING_PARAMETER_TYPE),
        ),
        (
            request_parameter.to_string(),
            ConditionParameter::ListOf(STRING_PARAMETER_TYPE),
        ),
    ];
    for gate in &temporal {
        expression = format!("{expression} && {}", gate.fragment);
        parameters.push((
            gate.parameter.to_string(),
            ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
        ));
        parameters.push(gate.clock.declaration());
    }
    let spec = ConditionSpec {
        expression,
        parameters: parameters.into_iter().collect(),
    };

    let temporal_context: Vec<GateContextColumn> = temporal
        .into_iter()
        .map(|gate| GateContextColumn {
            parameter: gate.parameter.to_string(),
            column: gate.column,
            witness: gate.witness,
            monotone: gate.monotone,
        })
        .collect();
    // The gate rides the share type, keyed on the share row, so two viewers of one
    // guarded row union through the link rather than collide on one tuple.
    let share_type = share_type_name(join_table, ctx.table_types);
    let (gate_relation, condition) = {
        let share_plan = all_types.entry(share_type.clone()).or_insert_with(|| {
            TypePlan::new_with_well_known(share_type.clone(), &ctx.settings.well_known)
        });
        let condition = declare_condition(share_plan, spec);
        let key = emit_membership::membership_source_key(
            join_table,
            &identity_cols,
            member_column,
            extra_predicates,
            Some(emit_membership::MembershipSourceGate {
                condition: &condition,
                context: &temporal_context,
                aggregate: false,
                clocked: !temporal_context.is_empty(),
                inputs: &[
                    row_parameter.as_str(),
                    request_parameter.as_str(),
                    source.setting_key(),
                    if separator.is_some() { "some" } else { "none" },
                    separator.as_deref().unwrap_or_default(),
                ],
            }),
        );
        let gate_relation = share_plan.membership_source_relation(
            &key,
            conditional_gate_relation_name(policy_name),
            DirectSubject::ConditionalWildcard {
                type_name: ctx.settings.well_known.user.clone(),
                condition: condition.clone(),
            },
        );
        (gate_relation, condition)
    };

    let gate_source = TupleSource::CallerSetShareGate {
        join_table: join_table.clone(),
        identity_cols: identity_cols.clone(),
        share_type: share_type.clone(),
        relation: gate_relation.clone(),
        condition,
        row_parameter: row_parameter.to_string(),
        member_col: member_column.clone(),
        request_parameter: request_parameter.to_string(),
        setting_key: source.setting_key().to_string(),
        separator: separator.clone(),
        extra_predicates: extra_predicates.clone(),
        temporal_context,
    };
    if let Some(share_plan) = all_types.get_mut(&share_type) {
        share_plan.add_source(gate_source.clone());
    }
    table_plan.add_source(gate_source);

    let share = ShareRows {
        join_table,
        identity_cols: &identity_cols,
        fk_cols: &parent.fk_cols(),
        share_type: &share_type,
    };
    let membership = if parent.is_self(table_plan) {
        let link = link_share_rows(table_plan, &share);
        share_reach(link, gate_relation)
    } else {
        let parent_plan = parent.plan(all_types, &ctx.settings.well_known);
        let link = link_share_rows(parent_plan, &share);
        let reached = parent_plan
            .ensure_computed(gate_relation.to_string(), share_reach(link, gate_relation));
        UsersetExpr::TupleToUserset {
            tupleset: parent.bridge_from(table_plan, source_table),
            computed: reached,
        }
    };
    apply_membership_read_scope(
        membership,
        join_table,
        extra_predicates,
        read_scope,
        ctx,
        table_plan,
        all_types,
        notes,
    )
}
