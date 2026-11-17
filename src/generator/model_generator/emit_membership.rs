//! Emission for the patterns that reach through another row.
//!
//! Membership through a join table, a membership naming no column of the guarded table, a
//! parent rule through a foreign key, and the two shapes that combine other patterns.

use super::emit_requests::{
    declare_condition, request_comparison_spec, request_gate_on, reserve_temporal_clocks,
    temporal_gates,
};
use super::*;

use crate::classifier::expansion::ExpansionState;
use crate::classifier::recognizers::{owner_key_of, resolve_membership_pairing, MembershipPairing};
use crate::generator::tuple_generator::{
    quote_sql_identifier, quote_sql_string_literal, render_attribute_test,
};
use crate::generator::well_known::{actor_relation, HOLDER_OBJECT_ID};
use sql_traits::structs::WalkDirection;

pub(super) struct MembershipSourceGate<'a> {
    pub condition: &'a ConditionName,
    pub context: &'a [GateContextColumn],
    pub aggregate: bool,
    pub clocked: bool,
    pub inputs: &'a [&'a str],
}

impl<'a> From<&'a MembershipGate> for MembershipSourceGate<'a> {
    fn from(gate: &'a MembershipGate) -> Self {
        Self {
            condition: &gate.condition,
            context: &gate.context,
            aggregate: gate.aggregate,
            clocked: true,
            inputs: &[],
        }
    }
}

// Length prefixes keep separators in SQL and stored names unambiguous.
fn source_key_part(key: &mut String, part: &str) {
    let _ = write!(key, "{}:{part}", part.len());
}

fn source_key_columns(key: &mut String, columns: &[ColumnName]) {
    let _ = write!(key, "{}:", columns.len());
    for column in columns {
        source_key_part(key, column.as_str());
    }
}

fn table_source_key(kind: &str, table: &TableId) -> String {
    let mut key = String::new();
    source_key_part(&mut key, kind);
    source_key_part(&mut key, table.schema().unwrap_or("public"));
    source_key_part(&mut key, table.name());
    key
}

pub(super) fn membership_source_key(
    table: &TableId,
    object_cols: &[ColumnName],
    user_column: &ColumnName,
    residual: &ResidualPredicates,
    gate: Option<MembershipSourceGate<'_>>,
) -> String {
    let mut key = table_source_key("membership", table);
    source_key_columns(&mut key, object_cols);
    source_key_part(&mut key, user_column.as_str());
    let sql = if gate.as_ref().is_some_and(|gate| gate.clocked) {
        residual.sql_excluding_requests()
    } else {
        residual.sql()
    };
    let _ = write!(key, "{}:", sql.is_some());
    source_key_part(&mut key, sql.as_deref().unwrap_or_default());
    let Some(gate) = gate else {
        source_key_part(&mut key, "plain");
        return key;
    };
    source_key_part(&mut key, "gated");
    source_key_part(&mut key, gate.condition.as_str());
    let _ = write!(
        key,
        "{}:{}:{}:",
        gate.aggregate,
        gate.clocked,
        gate.context.len()
    );
    for column in gate.context {
        source_key_part(&mut key, &column.parameter);
        source_key_part(&mut key, column.column.as_str());
        source_key_part(
            &mut key,
            match column.witness {
                ContextWitness::Latest => "latest",
                ContextWitness::Earliest => "earliest",
            },
        );
    }
    let _ = write!(key, "{}:", gate.inputs.len());
    for input in gate.inputs {
        source_key_part(&mut key, input);
    }
    key
}

fn parent_bridge_relation(
    plan: &mut TypePlan,
    table: &TableId,
    columns: &[ColumnName],
    parent_type: &TypeName,
) -> RelationName {
    let mut key = table_source_key("parent_bridge", table);
    source_key_columns(&mut key, columns);
    source_key_part(&mut key, parent_type.as_str());
    plan.membership_source_relation(
        &key,
        parent_type.as_str(),
        vec![DirectSubject::Type(parent_type.clone())],
    )
}

/// Disclose the residual, naming the relations an exemption rests on.
///
/// `gated` drops the conjuncts the clock already took into the condition.
pub(super) fn announce_residual(
    extra_predicates: &ResidualPredicates,
    gated: bool,
    policy_name: &str,
    notes: &mut Vec<TranslationNote>,
) {
    let announced = if gated {
        extra_predicates.sql_excluding_requests()
    } else {
        extra_predicates.sql()
    };
    let Some(predicate) = announced else {
        return;
    };
    let tables = extra_predicates.relations();
    notes.push(if tables.is_empty() {
        TranslationNote::MembershipExtraPredicate {
            policy: policy_name.to_string(),
            predicate,
        }
    } else {
        TranslationNote::MembershipResidualReadsUnrestrictedTables {
            policy: policy_name.to_string(),
            predicate,
            tables,
        }
    });
}

/// A membership naming no column of the guarded table, which admits every row at once through a holder.
pub(crate) fn emit_uncorrelated_membership<DB: DatabaseLike>(
    uncorrelated_membership: &UncorrelatedMembership,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let UncorrelatedMembership {
        member_table,
        user_column,
        extra_predicates,
    } = uncorrelated_membership;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;
    // Reading the member table is still reading it as the caller, so its own
    // RLS decides which membership rows count, exactly as for P4.
    let Some(read_scope) = noted_membership_read_scope(member_table, ctx, readability, notes)
    else {
        return deny_expr(table_plan);
    };
    // Before any note or any minting: the grant hangs off a bridge from this row
    // to the holder, so with no row identity there is nothing to hang it on, a
    // holder type minted here would outlive the expression that justified it,
    // and advice about the tuple SQL names a query nothing will emit.
    let Some(source_identity_cols) = resolve_row_identity(source_table, db) else {
        skip_source_without_row_identity(table_plan, source_table, "membership holder tuples", db);
        return deny_expr(table_plan);
    };

    // Temporal comparisons on the member row move into the condition its member tuple
    // names. Declared on this plan, referenced by name from wherever the member lives.
    let gate = declare_temporal_condition(
        extra_predicates,
        member_table,
        table_plan,
        ctx.condition_parameters,
        db,
    );
    // Several member rows per user only where the user column covers no declared
    // identity, and then the clock must be evaluated per row.
    let rows_unique = row_uniquely_keys(member_table, &[user_column], db);
    let witness = match &gate {
        Some((condition, context)) if !rows_unique => {
            if let Some(identity_cols) = resolve_row_identity(member_table, db) {
                Some((condition.clone(), context.clone(), identity_cols))
            } else if context.len() == 1 {
                // A single carried value is a real row's value, so compressing the
                // rows stays sound and at worst incomplete.
                None
            } else {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason: format!(
                        "the rows of '{member_table}' have no declared identity, and \
                         several clock comparisons cannot be compressed into one \
                         fact without mixing rows"
                    ),
                });
                return deny_expr(table_plan);
            }
        }
        _ => None,
    };

    announce_residual(extra_predicates, gate.is_some(), policy_name, notes);

    // One holder per member source, never per table and never per policy: two
    // policies reading the same table may share, and two reading different
    // ones must not pool their members.
    let holder_type = holder_type_name(member_table, table_types);
    // Named after the type it points at, as the parent link is.
    let holder_relation = table_plan.ensure_direct(
        clamp_relation_name(holder_type.to_string()),
        vec![DirectSubject::Type(holder_type.clone())],
    );
    if let Some((condition, context, identity_cols)) = witness {
        let share_type = share_type_name(member_table, table_types);
        let member_rel = {
            let share_plan = all_types.entry(share_type.clone()).or_insert_with(|| {
                TypePlan::new_with_well_known(share_type.clone(), &table_plan.well_known)
            });
            let key = membership_source_key(
                member_table,
                &identity_cols,
                user_column,
                extra_predicates,
                Some(MembershipSourceGate {
                    condition: &condition,
                    context: &context,
                    aggregate: false,
                    clocked: true,
                    inputs: &[],
                }),
            );
            share_plan.membership_source_relation(
                &key,
                member_relation(),
                vec![DirectSubject::ConditionalType {
                    type_name: table_plan.well_known.user.clone(),
                    condition: condition.clone(),
                }],
            )
        };
        let share_source = TupleSource::MembershipShareMembers {
            join_table: member_table.clone(),
            identity_cols: identity_cols.clone(),
            user_col: user_column.clone(),
            share_type: share_type.clone(),
            relation: member_rel.clone(),
            condition,
            extra_predicates: extra_predicates.clone(),
            context,
        };
        table_plan.add_source(share_source.clone());
        if let Some(share_plan) = all_types.get_mut(&share_type) {
            share_plan.add_source(share_source);
        }
        let holder_plan = all_types.entry(holder_type.clone()).or_insert_with(|| {
            TypePlan::new_with_well_known(holder_type.clone(), &table_plan.well_known)
        });
        let link = holder_plan.ensure_direct(
            clamp_relation_name(share_type.to_string()),
            vec![DirectSubject::Type(share_type.clone())],
        );
        let witness_member = holder_plan.ensure_computed(
            format!("{share_type}_member"),
            UsersetExpr::TupleToUserset {
                tupleset: link.clone(),
                computed: member_rel,
            },
        );
        holder_plan.add_source(TupleSource::ScopeShares {
            scope_type: holder_type.clone(),
            scope_object: HOLDER_OBJECT_ID.to_string(),
            member_table: member_table.clone(),
            identity_cols,
            share_type,
            relation: link,
        });
        table_plan.add_source(TupleSource::HolderBridge {
            table: source_table.clone(),
            identity_cols: source_identity_cols,
            relation: holder_relation.clone(),
            holder_type,
        });
        return apply_membership_read_scope(
            UsersetExpr::TupleToUserset {
                tupleset: holder_relation,
                computed: witness_member,
            },
            member_table,
            extra_predicates,
            read_scope,
            ctx,
            table_plan,
            all_types,
            notes,
        );
    }
    let gate = gate.map(|(condition, context)| MembershipGate {
        condition,
        context,
        aggregate: !rows_unique,
    });
    let member_rel = {
        let holder_plan = all_types.entry(holder_type.clone()).or_insert_with(|| {
            TypePlan::new_with_well_known(holder_type.clone(), &table_plan.well_known)
        });
        let key = membership_source_key(
            member_table,
            &[],
            user_column,
            extra_predicates,
            gate.as_ref().map(MembershipSourceGate::from),
        );
        let subject = gate.as_ref().map_or_else(
            || DirectSubject::Type(table_plan.well_known.user.clone()),
            |gate| DirectSubject::ConditionalType {
                type_name: table_plan.well_known.user.clone(),
                condition: gate.condition.clone(),
            },
        );
        holder_plan.membership_source_relation(&key, member_relation(), vec![subject])
    };
    table_plan.add_source(TupleSource::HolderMembers {
        holder_type: holder_type.clone(),
        member_table: member_table.clone(),
        user_col: user_column.clone(),
        relation: member_rel.clone(),
        extra_predicates: extra_predicates.clone(),
        gate: gate.clone(),
    });
    if let Some(holder_plan) = all_types.get_mut(&holder_type) {
        holder_plan.add_source(TupleSource::HolderMembers {
            holder_type: holder_type.clone(),
            member_table: member_table.clone(),
            user_col: user_column.clone(),
            relation: member_rel.clone(),
            extra_predicates: extra_predicates.clone(),
            gate,
        });
    }
    table_plan.add_source(TupleSource::HolderBridge {
        table: source_table.clone(),
        identity_cols: source_identity_cols,
        relation: holder_relation.clone(),
        holder_type,
    });
    apply_membership_read_scope(
        UsersetExpr::TupleToUserset {
            tupleset: holder_relation,
            computed: member_rel,
        },
        member_table,
        extra_predicates,
        read_scope,
        ctx,
        table_plan,
        all_types,
        notes,
    )
}

/// Intersects a membership arm with its table's read constraints, and with the request
/// gates of every other table its residual reads.
///
/// The loader answers a residual once with every table in view. The classifier admits a
/// residual over a table gated by the request only where that table, read empty, makes
/// the residual false, so the grant rests on the gate exactly as the database's does.
#[expect(
    clippy::too_many_arguments,
    reason = "the plan, the types, the notes and the context are four separate borrows"
)]
pub(super) fn apply_membership_read_scope<DB: DatabaseLike>(
    membership: UsersetExpr,
    join_table: &TableId,
    residual: &ResidualPredicates,
    scope: &TableReadability,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let mut gates: Vec<ReadGate> = if ctx.membership_reads_bypass_rls {
        Vec::new()
    } else {
        residual
            .relations()
            .iter()
            .filter(|relation| *relation != join_table)
            .filter_map(|relation| {
                match table_readability(relation, ctx.db, ctx.registry, &ExpansionState::new()) {
                    TableReadability::RequestGated { gates } => Some(gates),
                    _ => None,
                }
            })
            .flatten()
            .collect()
    };
    match scope {
        TableReadability::Open | TableReadability::Guarded => {}
        TableReadability::Unreadable => return deny_expr(table_plan),
        TableReadability::RequestGated { gates: own } => gates.extend(own.iter().cloned()),
    }
    let mut expressions = Vec::with_capacity(gates.len() + 1);
    expressions.push(membership);
    // Request-only patterns never consult membership readability.
    for gate in &gates {
        expressions.push(translate_pattern(
            &gate.pattern,
            &PatternCtx {
                policy_name: &gate.policy_name,
                ..*ctx
            },
            table_plan,
            all_types,
            notes,
            &mut BTreeMap::new(),
        ));
    }
    combine_intersection(expressions).unwrap_or_else(|| deny_expr(table_plan))
}

/// The parent a membership bridges the guarded row to, decided once for every spelling
/// of the member comparison.
pub(super) struct MembershipParent {
    /// The pairs in the order that names one parent object.
    pub(super) pairs: Vec<MembershipJoinPair>,
    pub(super) parent_type: TypeName,
    /// The table whose rows the parent names, absent for the guarded row itself and for a
    /// type named after a column.
    row_source: Option<TableId>,
}

impl MembershipParent {
    /// Resolve the pairing and the bridge to the parent it names, falling closed with the
    /// reason recorded where neither can be.
    pub(super) fn resolve<DB: DatabaseLike>(
        pairs: &[MembershipJoinPair],
        join_table: &TableId,
        ctx: &PatternCtx<'_, DB>,
        table_plan: &mut TypePlan,
        notes: &mut Vec<TranslationNote>,
    ) -> Option<Self> {
        let db = ctx.db;
        let (pairs, pairing) =
            match resolve_membership_pairing(pairs.to_vec(), join_table, ctx.source_table, db) {
                Ok(resolved) => resolved,
                Err(reason) => {
                    notes.push(TranslationNote::ExpressionRefused {
                        policy: ctx.policy_name.to_string(),
                        reason,
                    });
                    return None;
                }
            };
        let (parent_type, row_source) = match (&pairing, pairs.as_slice()) {
            // A declared reference names the table, and only then are its rows the parent's.
            (MembershipPairing::Single, [pair]) => {
                match referenced_table_for_fk_col(db, join_table, &pair.join_column) {
                    Some(referenced) => (ctx.table_types.resolve(&referenced), Some(referenced)),
                    None => (parent_type_from_fk_column(pair.join_column.as_str()), None),
                }
            }
            (MembershipPairing::Single, _) => return None,
            (MembershipPairing::ForeignKey { parent_table }, _) => (
                ctx.table_types.resolve(parent_table),
                Some(parent_table.clone()),
            ),
            (MembershipPairing::SelfKeyed, _) => (table_plan.type_name.clone(), None),
        };
        let parent = Self {
            pairs,
            parent_type,
            row_source,
        };
        bridge_is_buildable(
            table_plan,
            ctx.source_table,
            &parent.outer_cols(),
            &parent.parent_type,
            db,
        )
        .then_some(parent)
    }

    pub(super) fn is_self(&self, table_plan: &TypePlan) -> bool {
        self.parent_type == table_plan.type_name
    }

    /// The join table's columns naming the parent, in the parent key's order.
    pub(super) fn fk_cols(&self) -> Vec<ColumnName> {
        self.pairs
            .iter()
            .map(|pair| pair.join_column.clone())
            .collect()
    }

    /// The guarded table's columns the bridge to the parent reads.
    pub(super) fn outer_cols(&self) -> Vec<ColumnName> {
        self.pairs
            .iter()
            .map(|pair| pair.outer_column.clone())
            .collect()
    }

    /// The parent's plan, minted and bound to the rows it names when absent.
    pub(super) fn plan<'p>(
        &self,
        all_types: &'p mut BTreeMap<TypeName, TypePlan>,
        well_known: &WellKnownTypes,
    ) -> &'p mut TypePlan {
        let plan = all_types
            .entry(self.parent_type.clone())
            .or_insert_with(|| TypePlan::new_with_well_known(self.parent_type.clone(), well_known));
        if let Some(table) = &self.row_source {
            plan.names_rows_of(table);
        }
        plan
    }

    /// The relation on the guarded plan reaching the parent, and the bridge filling it.
    pub(super) fn bridge_from(
        &self,
        table_plan: &mut TypePlan,
        source_table: &TableId,
    ) -> RelationName {
        let outer_cols = self.outer_cols();
        let relation =
            parent_bridge_relation(table_plan, source_table, &outer_cols, &self.parent_type);
        table_plan.add_source(TupleSource::ParentBridge {
            table: source_table.clone(),
            fk_cols: outer_cols,
            parent_type: self.parent_type.clone(),
            relation: relation.clone(),
        });
        relation
    }
}

/// One object per membership row, and the columns keying the guarded object each names.
pub(super) struct ShareRows<'a> {
    pub(super) join_table: &'a TableId,
    pub(super) identity_cols: &'a [ColumnName],
    pub(super) fk_cols: &'a [ColumnName],
    pub(super) share_type: &'a TypeName,
}

/// Link each object of `plan` to the share rows naming it, returning the link relation.
pub(super) fn link_share_rows(plan: &mut TypePlan, share: &ShareRows<'_>) -> RelationName {
    let mut key = table_source_key("share_bridge", share.join_table);
    source_key_columns(&mut key, share.identity_cols);
    source_key_columns(&mut key, share.fk_cols);
    source_key_part(&mut key, share.share_type.as_str());
    let link = plan.membership_source_relation(
        &key,
        share.share_type.as_str(),
        vec![DirectSubject::Type(share.share_type.clone())],
    );
    plan.add_source(TupleSource::ShareBridge {
        join_table: share.join_table.clone(),
        identity_cols: share.identity_cols.to_vec(),
        object_cols: share.fk_cols.to_vec(),
        guarded_type: plan.type_name.clone(),
        share_type: share.share_type.clone(),
        relation: link.clone(),
    });
    link
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MembershipPolarity {
    Grant,
    Block,
}

enum MembershipRoute {
    Parent(MembershipPolarity),
    Closure {
        parent: MembershipParent,
        tupleset: RelationName,
    },
}

/// Membership through a join table, bridged on the column the policy correlates.
pub(crate) fn emit_exists_membership<DB: DatabaseLike>(
    exists_membership: &ExistsMembership,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    emit_membership(
        exists_membership,
        ctx,
        table_plan,
        all_types,
        notes,
        readability,
        MembershipRoute::Parent(MembershipPolarity::Grant),
    )
}

fn emit_membership<DB: DatabaseLike>(
    exists_membership: &ExistsMembership,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
    route: MembershipRoute,
) -> UsersetExpr {
    let polarity = match &route {
        MembershipRoute::Parent(polarity) => *polarity,
        MembershipRoute::Closure { .. } => MembershipPolarity::Grant,
    };
    let ExistsMembership {
        join_table,
        pairs: _,
        user_column,
        extra_predicates,
    } = exists_membership;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;
    // The subquery reads `join_table` as the user, so its own RLS decides which
    // membership rows count.
    let open_scope = TableReadability::Open;
    let read_scope = if polarity == MembershipPolarity::Block {
        let readable = lookup_table_id(db, join_table).is_some_and(|table| {
            crate::generator::unrestricted::restricts_nothing_by_any_route(table, db)
        });
        if !readable {
            notes.push(TranslationNote::ExpressionRefused {
                policy: policy_name.to_string(),
                reason: format!(
                    "Blocklist table '{join_table}' is not provably free of row level security"
                ),
            });
            return deny_expr(table_plan);
        }
        &open_scope
    } else {
        let Some(scope) = noted_membership_read_scope(join_table, ctx, readability, notes) else {
            return deny_expr(table_plan);
        };
        scope
    };
    let (parent, tupleset) = match route {
        MembershipRoute::Parent(_) => {
            let Some(parent) = MembershipParent::resolve(
                &exists_membership.pairs,
                join_table,
                ctx,
                table_plan,
                notes,
            ) else {
                return deny_expr(table_plan);
            };
            (parent, None)
        }
        MembershipRoute::Closure { parent, tupleset } => (parent, Some(tupleset)),
    };
    let MembershipParent {
        pairs, parent_type, ..
    } = &parent;

    // A temporal comparison such as `expires_at > now()` is completed by the request, so
    // it rides the member tuple as a condition rather than filtering the query. Declared on
    // this plan and referenced by name from the member relation, wherever that lives.
    let gate = declare_temporal_condition(
        extra_predicates,
        join_table,
        table_plan,
        ctx.condition_parameters,
        db,
    );
    // Several rows can key one (parent, user) only where no declared identity of the
    // join table is covered by the correlation, and then the clock must be evaluated
    // per row: one witness object per membership row, exactly as `EXISTS` is.
    let correlation_cols: Vec<&ColumnName> = pairs
        .iter()
        .map(|pair| &pair.join_column)
        .chain([user_column])
        .collect();
    let rows_unique = row_uniquely_keys(join_table, &correlation_cols, db);
    let witness = match &gate {
        Some((condition, context)) if !rows_unique => {
            if let Some(identity_cols) = resolve_row_identity(join_table, db) {
                Some((condition.clone(), context.clone(), identity_cols))
            } else if let [column] = context.as_slice() {
                if column.monotone || polarity == MembershipPolarity::Grant {
                    None
                } else {
                    notes.push(TranslationNote::ExpressionRefused {
                        policy: policy_name.to_string(),
                        reason: format!(
                            "the rows of '{join_table}' have no declared identity, and \
                             a non-monotone clock comparison cannot be compressed into \
                             one fact without risking a missed block"
                        ),
                    });
                    return deny_expr(table_plan);
                }
            } else {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason: format!(
                        "the rows of '{join_table}' have no declared identity, and \
                         several clock comparisons cannot be compressed into one \
                         fact without mixing rows"
                    ),
                });
                return deny_expr(table_plan);
            }
        }
        _ => None,
    };

    // The clock moved into the condition, so only what remains needs announcing.
    announce_residual(extra_predicates, gate.is_some(), policy_name, notes);

    let membership = if let Some((condition, context, identity_cols)) = witness {
        let share_type = share_type_name(join_table, table_types);
        let member_rel = {
            let share_plan = all_types.entry(share_type.clone()).or_insert_with(|| {
                TypePlan::new_with_well_known(share_type.clone(), &table_plan.well_known)
            });
            let mut key = membership_source_key(
                join_table,
                &identity_cols,
                user_column,
                extra_predicates,
                Some(MembershipSourceGate {
                    condition: &condition,
                    context: &context,
                    aggregate: false,
                    clocked: true,
                    inputs: &[],
                }),
            );
            let base = if polarity == MembershipPolarity::Block {
                source_key_part(&mut key, "block");
                blocked_relation()
            } else {
                member_relation()
            };
            share_plan.membership_source_relation(
                &key,
                base,
                vec![DirectSubject::ConditionalType {
                    type_name: table_plan.well_known.user.clone(),
                    condition: condition.clone(),
                }],
            )
        };
        let reached = if tupleset.is_some() {
            format!("{share_type}_{member_rel}_{condition}")
        } else {
            format!("{share_type}_{member_rel}")
        };
        let share_source = TupleSource::MembershipShareMembers {
            join_table: join_table.clone(),
            identity_cols: identity_cols.clone(),
            user_col: user_column.clone(),
            share_type: share_type.clone(),
            relation: member_rel.clone(),
            condition,
            extra_predicates: extra_predicates.clone(),
            context,
        };
        table_plan.add_source(share_source.clone());
        if let Some(share_plan) = all_types.get_mut(&share_type) {
            share_plan.add_source(share_source);
        }
        let share = ShareRows {
            join_table,
            identity_cols: &identity_cols,
            fk_cols: &parent.fk_cols(),
            share_type: &share_type,
        };
        let witness_member = if parent.is_self(table_plan) {
            let link = link_share_rows(table_plan, &share);
            table_plan.ensure_computed(reached, share_reach(link, member_rel))
        } else {
            let parent_plan = parent.plan(all_types, &table_plan.well_known);
            let link = link_share_rows(parent_plan, &share);
            parent_plan.ensure_computed(reached, share_reach(link, member_rel))
        };
        let tupleset = tupleset.unwrap_or_else(|| parent.bridge_from(table_plan, source_table));
        UsersetExpr::TupleToUserset {
            tupleset,
            computed: witness_member,
        }
    } else {
        let gate = gate.map(|(condition, context)| MembershipGate {
            condition,
            context,
            aggregate: !rows_unique,
        });
        let fk_cols = parent.fk_cols();
        let mut key = membership_source_key(
            join_table,
            &fk_cols,
            user_column,
            extra_predicates,
            gate.as_ref().map(MembershipSourceGate::from),
        );
        let base = if polarity == MembershipPolarity::Block {
            source_key_part(&mut key, "block");
            blocked_relation()
        } else {
            member_relation()
        };
        let member_rel = {
            let parent_plan = if parent.is_self(table_plan) {
                &mut *table_plan
            } else {
                parent.plan(all_types, &table_plan.well_known)
            };
            let subject = gate.as_ref().map_or_else(
                || DirectSubject::Type(parent_plan.well_known.user.clone()),
                |gate| DirectSubject::ConditionalType {
                    type_name: parent_plan.well_known.user.clone(),
                    condition: gate.condition.clone(),
                },
            );
            parent_plan.membership_source_relation(&key, base, vec![subject])
        };
        // On the guarded plan first, which is the order the renderer emits.
        let membership_source = TupleSource::ExistsMembership {
            join_table: join_table.clone(),
            fk_cols,
            user_col: user_column.clone(),
            subject_type: table_plan.well_known.user.clone(),
            parent_type: parent_type.clone(),
            relation: member_rel.clone(),
            extra_predicates: extra_predicates.clone(),
            gate,
        };
        table_plan.add_source(membership_source.clone());
        if let Some(parent_plan) = all_types.get_mut(parent_type) {
            parent_plan.add_source(membership_source);
        }
        if polarity == MembershipPolarity::Block
            && parent.is_self(table_plan)
            && resolve_row_identity(source_table, db).is_some_and(|identity| {
                identity
                    .iter()
                    .eq(parent.pairs.iter().map(|pair| &pair.outer_column))
            })
        {
            UsersetExpr::Computed(member_rel)
        } else {
            UsersetExpr::TupleToUserset {
                tupleset: tupleset.unwrap_or_else(|| parent.bridge_from(table_plan, source_table)),
                computed: member_rel,
            }
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

/// The read scope a two-hop hop may rest on; guarded hop tables are refused.
fn indirect_read_scope<'a, DB: DatabaseLike>(
    table: &TableId,
    ctx: &PatternCtx<'_, DB>,
    memo: &'a mut BTreeMap<TableId, TableReadability>,
    notes: &mut Vec<TranslationNote>,
) -> Option<&'a TableReadability> {
    if ctx.membership_reads_bypass_rls {
        return Some(&TableReadability::Open);
    }
    let scope = join_table_readability(table, ctx.db, ctx.registry, memo);
    match scope {
        TableReadability::Open | TableReadability::RequestGated { .. } => Some(scope),
        TableReadability::Guarded => {
            notes.push(TranslationNote::MembershipTableGuarded {
                policy: ctx.policy_name.to_string(),
                join_table: table.clone(),
            });
            None
        }
        TableReadability::Unreadable => {
            notes.push(TranslationNote::MembershipTableGrantsNoReads {
                policy: ctx.policy_name.to_string(),
                join_table: table.clone(),
            });
            None
        }
    }
}

/// Emit owner membership reached through a closure table.
pub(crate) fn emit_indirect_membership<DB: DatabaseLike>(
    indirect: &IndirectMembership,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let IndirectMembership {
        link_table,
        pairs,
        owner_table,
        owner_columns,
        memberships,
        extra_predicates,
    } = indirect;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;
    if memberships.is_empty() {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!("the closure '{link_table}' carries no membership to grant"),
        });
        return deny_expr(table_plan);
    }
    if indirect_read_scope(link_table, ctx, readability, notes).is_none() {
        return deny_expr(table_plan);
    }
    let owner_type = table_types.resolve(owner_table);
    let Some((link_owner, owner_mapping)) = owner_key_of(db, link_table, owner_columns) else {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!("the closure '{link_table}' names no declared owner key"),
        });
        return deny_expr(table_plan);
    };
    if &link_owner != owner_table
        || !owner_mapping
            .iter()
            .map(|(_, host)| host.as_str())
            .eq(owner_columns.iter().map(ColumnName::as_str))
    {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!("the closure '{link_table}' does not name the key of '{owner_table}'"),
        });
        return deny_expr(table_plan);
    }
    let (link_pairs, pairing) =
        match resolve_membership_pairing(pairs.clone(), link_table, source_table, db) {
            Ok(resolved) => resolved,
            Err(reason) => {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason,
                });
                return deny_expr(table_plan);
            }
        };
    match pairing {
        MembershipPairing::SelfKeyed => {}
        MembershipPairing::ForeignKey { parent_table } => {
            if table_types.resolve(&parent_table) != table_plan.type_name {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason: format!(
                        "the closure '{link_table}' links its rows to '{parent_table}' \
                         rather than the guarded rows"
                    ),
                });
                return deny_expr(table_plan);
            }
        }
        MembershipPairing::Single => {
            notes.push(TranslationNote::ExpressionRefused {
                policy: policy_name.to_string(),
                reason: format!(
                    "the closure '{link_table}' does not name the guarded rows by a declared key"
                ),
            });
            return deny_expr(table_plan);
        }
    }
    let join_columns: Vec<ColumnName> = link_pairs
        .iter()
        .map(|pair| pair.join_column.clone())
        .collect();
    let missing = join_columns
        .iter()
        .chain(owner_columns.iter())
        .find(|column| !table_id_has_column(db, link_table, column.as_str()));
    if let Some(column) = missing {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!("the closure '{link_table}' has no column '{column}'"),
        });
        return deny_expr(table_plan);
    }
    if !extra_predicates.requests().is_empty() {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: "request-dependent closure filters are unsupported".to_string(),
        });
        return deny_expr(table_plan);
    }
    announce_residual(extra_predicates, false, policy_name, notes);
    {
        let owner_plan = all_types.entry(owner_type.clone()).or_insert_with(|| {
            TypePlan::new_with_well_known(owner_type.clone(), &table_plan.well_known)
        });
        owner_plan.names_rows_of(owner_table);
    }
    let mut key = table_source_key("indirect_closure", link_table);
    source_key_columns(&mut key, &join_columns);
    source_key_columns(&mut key, owner_columns);
    source_key_part(&mut key, owner_type.as_str());
    let residual_sql = extra_predicates.sql();
    let _ = write!(key, "{}:", residual_sql.is_some());
    source_key_part(&mut key, residual_sql.as_deref().unwrap_or_default());
    let link_relation = table_plan.membership_source_relation(
        &key,
        format!("indirect_{owner_type}"),
        vec![DirectSubject::Type(owner_type.clone())],
    );
    table_plan.add_source(TupleSource::ClosureBridge {
        link_table: link_table.clone(),
        object_cols: join_columns,
        subject_cols: owner_columns.clone(),
        guarded_type: table_plan.type_name.clone(),
        owner_type: owner_type.clone(),
        relation: link_relation.clone(),
        extra_predicates: extra_predicates.clone(),
    });
    let mut arms: Vec<UsersetExpr> = Vec::new();
    for membership in memberships {
        let Some(_scope) = indirect_read_scope(&membership.join_table, ctx, readability, notes)
        else {
            return deny_expr(table_plan);
        };
        let hosts: Vec<_> = membership
            .pairs
            .iter()
            .map(|pair| pair.join_column.clone())
            .collect();
        let valid_owner =
            owner_key_of(db, &membership.join_table, &hosts).is_some_and(|(table, mapping)| {
                &table == owner_table
                    && mapping.len() == membership.pairs.len()
                    && mapping
                        .iter()
                        .zip(&membership.pairs)
                        .all(|((key, host), pair)| {
                            key == pair.outer_column.as_str() && host == pair.join_column.as_str()
                        })
            });
        if !valid_owner {
            notes.push(TranslationNote::ExpressionRefused {
                policy: policy_name.to_string(),
                reason: format!(
                    "the membership on '{}' names a different owner key",
                    membership.join_table
                ),
            });
            return deny_expr(table_plan);
        }
        let parent = MembershipParent {
            pairs: membership.pairs.clone(),
            parent_type: owner_type.clone(),
            row_source: Some(owner_table.clone()),
        };
        arms.push(emit_membership(
            membership,
            ctx,
            table_plan,
            all_types,
            notes,
            readability,
            MembershipRoute::Closure {
                parent,
                tupleset: link_relation.clone(),
            },
        ));
    }
    let membership = if arms.len() == 1 {
        arms.pop().unwrap_or_else(|| deny_expr(table_plan))
    } else {
        combine_union(arms).unwrap_or_else(|| deny_expr(table_plan))
    };
    let link_scope = if ctx.membership_reads_bypass_rls {
        &TableReadability::Open
    } else {
        join_table_readability(link_table, db, ctx.registry, readability)
    };
    apply_membership_read_scope(
        membership,
        link_table,
        extra_predicates,
        link_scope,
        ctx,
        table_plan,
        all_types,
        notes,
    )
}

pub(super) fn emit_blocked_set<DB: DatabaseLike>(
    subtract: &[ExcludedSet],
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> Option<UsersetExpr> {
    let mut sets = Vec::with_capacity(subtract.len());
    for excluded in subtract {
        let before = notes.len();
        let set = match excluded {
            ExcludedSet::Membership(membership) => emit_membership(
                membership,
                ctx,
                table_plan,
                all_types,
                notes,
                readability,
                MembershipRoute::Parent(MembershipPolarity::Block),
            ),
            ExcludedSet::Helper(helper) => emit_declared_helper(helper, ctx, table_plan, all_types),
            ExcludedSet::Flag(flag) => translate_pattern(
                &flag.pattern,
                ctx,
                table_plan,
                all_types,
                notes,
                readability,
            ),
        };
        if grants_nothing(&set, table_plan)
            || notes
                .iter()
                .skip(before)
                .any(|note| note.severity().diverges_from_database())
        {
            return None;
        }
        sets.push(set);
    }
    combine_union(sets)
}

pub(super) fn emit_membership_exclusion<DB: DatabaseLike>(
    exclusion: &MembershipExclusion,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let Some(base) = &exclusion.base else {
        notes.push(TranslationNote::ExpressionRefused {
            policy: ctx.policy_name.to_string(),
            reason: "A blocklist exclusion requires a positive grant".to_string(),
        });
        return deny_expr(table_plan);
    };
    let base = translate_pattern(
        &base.pattern,
        ctx,
        table_plan,
        all_types,
        notes,
        readability,
    );
    let Some(subtract) = emit_blocked_set(
        &exclusion.subtract,
        ctx,
        table_plan,
        all_types,
        notes,
        readability,
    ) else {
        return deny_expr(table_plan);
    };
    UsersetExpr::Exclusion {
        base: Box::new(base),
        subtract: Box::new(subtract),
    }
}

/// Reach `relation` on the share rows through `link`.
pub(super) fn share_reach(link: RelationName, relation: RelationName) -> UsersetExpr {
    UsersetExpr::TupleToUserset {
        tupleset: link,
        computed: relation,
    }
}

/// A parent's rule reached through a foreign key, gated by the parent's own read.
pub(crate) fn emit_parent_inheritance<DB: DatabaseLike>(
    parent_inheritance: &ParentInheritance,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let ParentInheritance {
        parent_table,
        fk_column,
        inner_pattern,
    } = parent_inheritance;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let table_types = ctx.table_types;

    let parent_type = table_types.resolve(parent_table);

    let parent_relation = parent_bridge_relation(
        table_plan,
        source_table,
        core::slice::from_ref(fk_column),
        &parent_type,
    );
    // The inner rule has to land on the parent's plan. When the parent is the
    // table being built, that plan is `table_plan`, held here rather than in
    // `all_types`, so writing it there would be dropped by the re-insert at
    // the end of the table loop.
    let inherits_from_self = parent_type == table_plan.type_name.as_str();
    // A bare delegation adds nothing to the parent's own read rule, so the gate
    // below is the whole rule. Translating the constant would mint a
    // `public_viewer` relation on the parent and ask an operator for a tuple per
    // parent row that no rule reads.
    let bare_delegation = matches!(
        &inner_pattern.pattern,
        PatternClass::P10ConstantBool(ConstantBool { value: true })
    );
    let inner_expr = if bare_delegation {
        UsersetExpr::Computed(can_select_relation())
    } else if inherits_from_self {
        translate_pattern(
            &inner_pattern.pattern,
            &ctx.for_table(parent_table),
            table_plan,
            all_types,
            notes,
            readability,
        )
    } else {
        let parent_plan = all_types.entry(parent_type.clone()).or_insert_with(|| {
            TypePlan::new_with_well_known(parent_type.clone(), &table_plan.well_known)
        });
        let mut parent_plan_owned = core::mem::replace(
            parent_plan,
            TypePlan::new_with_well_known(parent_type.clone(), &table_plan.well_known),
        );
        let expr = translate_pattern(
            &inner_pattern.pattern,
            &ctx.for_table(parent_table),
            &mut parent_plan_owned,
            all_types,
            notes,
            readability,
        );
        *all_types
            .entry(parent_type.clone())
            .or_insert_with(|| TypePlan::new(parent_type.clone())) = parent_plan_owned;
        bind_row_source(all_types, &parent_type, parent_table, db);
        expr
    };

    // The policy requires this specific parent-side rule. Pointing at the
    // parent's `can_select` instead would import every other permissive
    // policy the parent has.
    let rule_is_denial =
        matches!(&inner_expr, UsersetExpr::Computed(name) if *name == deny_relation());
    // A row the parent hides cannot satisfy the rule, self references included.
    // Gating narrows the rule, so an unreadable RLS state gates.
    let gate_on_parent = !rule_is_denial
        && !bare_delegation
        && lookup_table_id(db, parent_table)
            .is_some_and(|table| table.has_row_level_security(db) != Ok(false));
    let rule_expr = if gate_on_parent {
        UsersetExpr::Intersection(vec![
            inner_expr,
            UsersetExpr::Computed(can_select_relation()),
        ])
    } else {
        inner_expr
    };
    let inherited = match rule_expr {
        UsersetExpr::Computed(name) => name,
        expr => {
            // Named after the rule, so children share it and a policy rename
            // leaves the parent alone.
            let name = clamp_relation_name(format!(
                "{INHERITED_RELATION_PREFIX}{}",
                stable_hex_suffix(userset_key(&expr).as_str())
            ));
            if inherits_from_self {
                table_plan.ensure_computed(name, expr)
            } else {
                all_types
                    .entry(parent_type.clone())
                    .or_insert_with(|| {
                        TypePlan::new_with_well_known(parent_type.clone(), &table_plan.well_known)
                    })
                    .ensure_computed(name, expr)
            }
        }
    };

    if rule_is_denial {
        notes.push(TranslationNote::ParentRuleUntranslated {
            policy: policy_name.to_string(),
            parent_table: parent_table.clone(),
        });
    }

    if !bridge_is_buildable(
        table_plan,
        source_table,
        core::slice::from_ref(fk_column),
        &parent_type,
        db,
    ) {
        return deny_expr(table_plan);
    }
    table_plan.add_source(TupleSource::ParentBridge {
        table: source_table.clone(),
        fk_cols: vec![fk_column.clone()],
        parent_type: parent_type.clone(),
        relation: parent_relation.clone(),
    });

    UsersetExpr::TupleToUserset {
        tupleset: parent_relation,
        computed: inherited,
    }
}

/// The relationship half of a hybrid clause, with the attribute half handed to the caller.
pub(crate) fn emit_abac_and<DB: DatabaseLike>(
    abac_and: &AbacAnd,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let AbacAnd {
        relationship_part,
        attribute_part,
    } = abac_and;
    let policy_name = ctx.policy_name;
    let source_table = ctx.source_table;
    notes.push(TranslationNote::AttributeNeedsRuntimeEnforcement {
        policy: policy_name.to_string(),
        attribute: attribute_part.clone(),
    });
    // Recurse first so relationship sources appear before the attribute Todo
    // in table_tuple_sources (matching old generate_tuple_queries ordering).
    let result = translate_pattern(
        &relationship_part.pattern,
        ctx,
        table_plan,
        all_types,
        notes,
        readability,
    );
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::AttributeRuntimeEnforcement {
            table: source_table.clone(),
            attribute: attribute_part.clone(),
        },
    });
    result
}

/// A union or intersection of the parts a composite clause combines.
///
/// The parts that read only the request fold into one gate in normal form, so reordered,
/// repeated or subsumed arms reach one relation. The rest translate one by one.
pub(crate) fn emit_composite<DB: DatabaseLike>(
    composite: &Composite,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> UsersetExpr {
    let Composite { op, parts } = composite;
    let mut request_only = Vec::new();
    let mut child_exprs = Vec::new();
    for part in parts {
        match RequestFormula::of(&part.pattern) {
            Some(formula) => request_only.push(formula),
            None => child_exprs.push(translate_pattern(
                &part.pattern,
                ctx,
                table_plan,
                all_types,
                notes,
                readability,
            )),
        }
    }
    if !request_only.is_empty() {
        let gate = RequestFormula::join(*op, request_only);
        child_exprs.push(emit_request_formula(&gate, ctx, table_plan, all_types));
    }
    match op {
        BoolOp::Or => combine_union(child_exprs).unwrap_or_else(|| deny_expr(table_plan)),
        BoolOp::And => combine_intersection(child_exprs).unwrap_or_else(|| deny_expr(table_plan)),
    }
}

/// A column compared with the set a declared helper returns, as the call's relation
/// reached through the column's bridge, or as that relation itself where the column is
/// the row's own key.
///
/// The helper reads as its owner, past every policy, and the tuple queries read the
/// same rows, so no membership read scope or parent read gate applies.
pub(crate) fn emit_declared_helper<DB: DatabaseLike>(
    helper: &DeclaredHelper,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> UsersetExpr {
    let DeclaredHelper { column, call } = helper;
    let Some(returned) = helper_call_relation(call, ctx, table_plan, all_types) else {
        return deny_expr(table_plan);
    };
    reach_level_relation(&call.level, column, returned, ctx, table_plan)
}

/// `relation` of the `level` row `column` names, as that relation itself where the column is
/// the guarded row's own key, or through the column's bridge.
fn reach_level_relation<DB: DatabaseLike>(
    level: &TableId,
    column: &ColumnName,
    relation: RelationName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    let source_table = ctx.source_table;
    if level == source_table
        && single_identity_column(source_table, ctx.db).as_ref() == Some(column)
    {
        return UsersetExpr::Computed(relation);
    }
    let level_type = ctx.table_types.resolve(level);
    let columns = core::slice::from_ref(column);
    if !bridge_is_buildable(table_plan, source_table, columns, &level_type, ctx.db) {
        return deny_expr(table_plan);
    }
    let tupleset = parent_bridge_relation(table_plan, source_table, columns, &level_type);
    table_plan.add_source(TupleSource::ParentBridge {
        table: source_table.clone(),
        fk_cols: columns.to_vec(),
        parent_type: level_type,
        relation: tupleset.clone(),
    });
    UsersetExpr::TupleToUserset {
        tupleset,
        computed: relation,
    }
}

/// The rows `flag` flags, a relation on the flagged table's type reached from the guarded
/// row as a declared helper's set is.
///
/// Every predicate is an attribute gate on the flagged type, and a walk makes the relation
/// name itself through one link per edge table, filled from that table's rows.
pub(crate) fn emit_flagged_row<DB: DatabaseLike>(
    flag: &FlaggedRow,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> UsersetExpr {
    let Some(flagged) = flag_relation(flag, ctx, table_plan, all_types) else {
        return deny_expr(table_plan);
    };
    reach_level_relation(&flag.table, &flag.column, flagged, ctx, table_plan)
}

/// The relation holding every row of the flagged type `flag` flags, `None` where no rule
/// names them.
fn flag_relation<DB: DatabaseLike>(
    flag: &FlaggedRow,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<RelationName> {
    let flagged_type = ctx.table_types.resolve(&flag.table);
    let mut key = format!("flag:{}:{}", flag.table.to_string().len(), flag.table);
    let plan = helper_level_plan(&flagged_type, Some(&flag.table), table_plan, all_types);
    let gates = attribute_gates(
        plan,
        &flag.table,
        core::slice::from_ref(&flag.key),
        &flag.predicates,
        &mut key,
    )?;
    let flagged = combine_intersection(gates)?;
    let named_after = flag.predicates.first()?.column.as_str();
    if flag.edges.is_empty() {
        return Some(match flagged {
            UsersetExpr::Computed(relation) => relation,
            rule => plan.ensure_computed(flag_relation_name(named_after, &key), rule),
        });
    }
    let mut links = Vec::with_capacity(flag.edges.len());
    for edge in &flag.edges {
        let TreeEdges {
            table,
            child_column,
            parent_column,
        } = edge;
        let edge_key = format!(
            "flag-edge:{}:{table}:{}:{child_column}:{}:{parent_column}",
            table.to_string().len(),
            child_column.as_str().len(),
            parent_column.as_str().len()
        );
        let _ = write!(key, ":{}:{edge_key}", edge_key.len());
        let link = plan.membership_source_relation(
            &edge_key,
            format!("{}_{parent_column}", table.name()),
            vec![DirectSubject::Type(flagged_type.clone())],
        );
        plan.add_source(TupleSource::ClosureBridge {
            link_table: table.clone(),
            object_cols: vec![child_column.clone()],
            subject_cols: vec![parent_column.clone()],
            guarded_type: flagged_type.clone(),
            owner_type: flagged_type.clone(),
            relation: link.clone(),
            extra_predicates: ResidualPredicates::default(),
        });
        links.push(link);
    }
    let relation =
        plan.ensure_walk_computed(flag_relation_name(named_after, &key), vec![flagged], links);
    plan.walk_notes
        .entry((
            relation.clone(),
            flag.table.clone(),
            ColumnName::from_stored(named_after.to_string()),
        ))
        .or_insert_with(|| TranslationNote::FlagWalkDepth {
            table: flag.table.clone(),
            relation: relation.clone(),
        });
    Some(relation)
}

/// The gates on `plan`'s type each holding every user while the row of `table` its
/// `identity` names meets one of `predicates`, each read from that row alone, with every
/// gate's key appended to `key`. `None` where a predicate has no gate.
fn attribute_gates(
    plan: &mut TypePlan,
    table: &TableId,
    identity: &[ColumnName],
    predicates: &[AttributePredicate],
    key: &mut String,
) -> Option<Vec<UsersetExpr>> {
    let mut gates = Vec::with_capacity(predicates.len());
    for predicate in predicates {
        let gate_key = attribute_gate_key(predicate)?;
        let relation = plan.gate_relation(
            &gate_key,
            attribute_gate_relation_name(predicate.column.as_str(), &gate_key),
            vec![DirectSubject::Wildcard(plan.well_known.user.clone())],
        );
        plan.add_source(TupleSource::AttributeGate {
            table: table.clone(),
            identity_cols: identity.to_vec(),
            predicate: predicate.clone(),
            relation: relation.clone(),
        });
        let _ = write!(key, ":{}:{gate_key}", gate_key.len());
        gates.push(UsersetExpr::Computed(relation));
    }
    Some(gates)
}

/// The relation holding everyone `call` returns a row for, defined on its level's type
/// with the relations and sources it reads. `None` where it returns nothing.
///
/// A walk arm makes the relation name itself through its tree's parent or child, which
/// is how `OpenFGA` spells every row below or above one the rest of the call returns. An
/// arm returning keys of a table whose key references the level's, an organization or a
/// team among the grantees, holds on the level's row sharing that key, so the walk
/// starts from every key the call returns, as the recursive term joins all of them.
fn helper_call_relation<DB: DatabaseLike>(
    call: &HelperCall,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<RelationName> {
    let level_type = ctx.table_types.resolve(&call.level);
    let mut parts = Vec::with_capacity(call.arms.len());
    let mut walked = Vec::new();
    for arm in &call.arms {
        match arm {
            HelperSetArm::Grant(grant) => parts.extend(caller_gated_grant_parts(
                grant,
                &call.level,
                &level_type,
                ctx,
                table_plan,
                all_types,
            )),
            HelperSetArm::Parent(parent) => {
                let Some(parents) = helper_call_relation(&parent.call, ctx, table_plan, all_types)
                else {
                    continue;
                };
                let parent_type = ctx.table_types.resolve(&parent.call.level);
                let plan = helper_level_plan(&level_type, Some(&call.level), table_plan, all_types);
                let tupleset =
                    helper_parent_link(plan, &parent.edges, &call.level, parent_type, ctx.db);
                parts.push(UsersetExpr::TupleToUserset {
                    tupleset,
                    computed: parents,
                });
            }
            HelperSetArm::Walk(walk) => walked.push(walk),
        }
    }
    // Next to nothing is nothing, so a walk alone returns no row.
    if parts.is_empty() {
        return None;
    }
    let plan = helper_level_plan(&level_type, Some(&call.level), table_plan, all_types);
    let name = helper_call_relation_name(&call.function, &call.arguments);
    if walked.is_empty() {
        return combine_union(parts).map(|returned| plan.ensure_computed(name, returned));
    }
    let walks = walked
        .iter()
        .map(|walk| match walk.direction {
            WalkDirection::Down => {
                helper_parent_link(plan, &walk.edges, &call.level, level_type.clone(), ctx.db)
            }
            WalkDirection::Up => helper_child_link(plan, &walk.edges, &level_type),
        })
        .collect();
    let relation = plan.ensure_walk_computed(name, parts, walks);
    for walk in walked {
        plan.walk_notes
            .entry((
                relation.clone(),
                walk.edges.table.clone(),
                walk.edges.parent_column.clone(),
            ))
            .or_insert_with(|| TranslationNote::HelperWalkDepth {
                function: call.function.clone(),
                table: walk.edges.table.clone(),
                column: walk.edges.parent_column.clone(),
                relation: relation.clone(),
            });
    }
    Some(relation)
}

/// The tupleset naming, on the level's row each edge's child names, the row of
/// `parent_type` the edge's parent names, with the source loading it.
///
/// Edges the level keeps on its own rows, each row naming its own parent, load as the
/// level's parent bridge, and any other edges from their table's rows.
fn helper_parent_link<DB: DatabaseLike>(
    plan: &mut TypePlan,
    edges: &TreeEdges,
    level: &TableId,
    parent_type: TypeName,
    db: &DB,
) -> RelationName {
    if edges.table == *level
        && single_identity_column(level, db).as_ref() == Some(&edges.child_column)
    {
        return helper_parent_bridge(plan, level, &edges.parent_column, parent_type);
    }
    let mut source_key = table_source_key("edge_bridge", &edges.table);
    source_key_part(&mut source_key, edges.child_column.as_str());
    source_key_part(&mut source_key, edges.parent_column.as_str());
    source_key_part(&mut source_key, parent_type.as_str());
    let tupleset = plan.membership_source_relation(
        &source_key,
        parent_type.as_str(),
        vec![DirectSubject::Type(parent_type.clone())],
    );
    plan.add_source(TupleSource::ClosureBridge {
        link_table: edges.table.clone(),
        object_cols: vec![edges.child_column.clone()],
        subject_cols: vec![edges.parent_column.clone()],
        guarded_type: plan.type_name.clone(),
        owner_type: parent_type,
        relation: tupleset.clone(),
        extra_predicates: ResidualPredicates::default(),
    });
    tupleset
}

/// The tupleset naming each row's parent of `parent_type` through `fk_column` of
/// `level`, with the source loading it.
///
/// The column is a single-column foreign key to the parent's primary key, so the bridge
/// is always buildable.
fn helper_parent_bridge(
    plan: &mut TypePlan,
    level: &TableId,
    fk_column: &ColumnName,
    parent_type: TypeName,
) -> RelationName {
    let columns = core::slice::from_ref(fk_column);
    let tupleset = parent_bridge_relation(plan, level, columns, &parent_type);
    plan.add_source(TupleSource::ParentBridge {
        table: level.clone(),
        fk_cols: columns.to_vec(),
        parent_type,
        relation: tupleset.clone(),
    });
    tupleset
}

/// The tupleset naming, on the level's row each edge's parent names, the row of the
/// level the edge's child names, with the source loading it.
fn helper_child_link(
    plan: &mut TypePlan,
    edges: &TreeEdges,
    level_type: &TypeName,
) -> RelationName {
    let mut source_key = table_source_key("child_bridge", &edges.table);
    source_key_part(&mut source_key, edges.parent_column.as_str());
    source_key_part(&mut source_key, edges.child_column.as_str());
    let tupleset = plan.membership_source_relation(
        &source_key,
        "child",
        vec![DirectSubject::Type(level_type.clone())],
    );
    plan.add_source(TupleSource::ClosureBridge {
        link_table: edges.table.clone(),
        object_cols: vec![edges.parent_column.clone()],
        subject_cols: vec![edges.child_column.clone()],
        guarded_type: level_type.clone(),
        owner_type: level_type.clone(),
        relation: tupleset.clone(),
        extra_predicates: ResidualPredicates::default(),
    });
    tupleset
}

/// The plan of the type a helper's level names, which is the guarded table's own plan
/// when the two coincide. A level of no table is a type of pairs a cap returns.
fn helper_level_plan<'p>(
    level_type: &TypeName,
    level: Option<&TableId>,
    table_plan: &'p mut TypePlan,
    all_types: &'p mut BTreeMap<TypeName, TypePlan>,
) -> &'p mut TypePlan {
    if table_plan.type_name == *level_type {
        return table_plan;
    }
    let plan = all_types.entry(level_type.clone()).or_insert_with(|| {
        TypePlan::new_with_well_known(level_type.clone(), &table_plan.well_known)
    });
    if let Some(level) = level {
        plan.names_rows_of(level);
    }
    plan
}

/// The call spelled as a relation name, `projects_with_read` for
/// `authz.projects_with('read')`.
fn helper_call_relation_name(function: &str, arguments: &[String]) -> String {
    let mut name = stored_relation_name(function);
    for argument in arguments {
        name.push('_');
        name.push_str(argument.trim_matches('\''));
    }
    clamp_relation_name(name)
}

/// The rows of the level a grant arm returns, one rule per group of rows it keeps, and
/// each audience or set of grantees it keeps for every caller but some as its own rule
/// less them.
fn helper_grant_parts<DB: DatabaseLike>(
    grant: &HelperGrant,
    level: Option<&TableId>,
    level_type: &TypeName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Vec<UsersetExpr> {
    // A grant row naming the caller is the one membership the generic name stands for,
    // and a grant row naming another grantee is named after its table.
    let unsplit = match grant.grantee {
        HelperGrantee::Caller { .. }
        | HelperGrantee::Principal { .. }
        | HelperGrantee::RequestValue { .. } => member_relation().to_string(),
        HelperGrantee::Set { .. } | HelperGrantee::Anyone => {
            stored_relation_name(grant.table.name())
        }
    };
    let groups = grant_row_groups(&grant.rows, &grant.time_bounds, &unsplit);
    let subjects = match &grant.grantee {
        HelperGrantee::Caller { user_column } => {
            let excluded = caller_exclusion(user_column, &grant.excluded);
            let aggregate = !row_uniquely_keys(&grant.table, &grant.tuple_key(), ctx.db);
            let plan = helper_level_plan(level_type, level, table_plan, all_types);
            let user = plan.well_known.user.clone();
            return groups
                .into_iter()
                .filter_map(|(base, extra_predicates)| {
                    caller_grant_relation(
                        grant,
                        (user_column, &user),
                        level_type,
                        plan,
                        ctx,
                        (base, extra_predicates.and(&excluded)),
                        aggregate,
                    )
                })
                .map(UsersetExpr::Computed)
                .collect();
        }
        // The rows name the principal, so the level holds it, and the caller reaches it
        // as the principal's actor, which the check states while the request acts for it.
        HelperGrantee::Principal {
            principal_column,
            principal_type,
        } => {
            let aggregate = !row_uniquely_keys(&grant.table, &grant.tuple_key(), ctx.db);
            let plan = helper_level_plan(level_type, level, table_plan, all_types);
            return groups
                .into_iter()
                .filter_map(|(base, extra_predicates)| {
                    caller_grant_relation(
                        grant,
                        (principal_column, principal_type),
                        level_type,
                        plan,
                        ctx,
                        (format!("{base}_{principal_type}"), extra_predicates),
                        aggregate,
                    )
                })
                .map(|tupleset| UsersetExpr::TupleToUserset {
                    tupleset,
                    computed: actor_relation(),
                })
                .collect();
        }
        HelperGrantee::RequestValue {
            value_column,
            source,
        } => {
            let share = RequestShares {
                table: &grant.table,
                value_column,
                source,
            };
            let Some((identity_cols, share_type, gates)) =
                share.gates(groups, ctx, table_plan, all_types)
            else {
                return Vec::new();
            };
            // Two rows naming one level row with different values would collide on one
            // tuple there, so each row is its own object, reached from the level row it
            // names, as a caller-set membership's share rows are.
            let plan = helper_level_plan(level_type, level, table_plan, all_types);
            let link = link_share_rows(
                plan,
                &ShareRows {
                    join_table: &grant.table,
                    identity_cols: &identity_cols,
                    fk_cols: &grant.object_columns,
                    share_type: &share_type,
                },
            );
            return gates
                .into_iter()
                .map(|gate| share_reach(link.clone(), gate))
                .collect();
        }
        HelperGrantee::Anyone => vec![GrantSubject {
            granted: Granted::Grantee(GranteeSubject::Everyone),
            joins: Vec::new(),
            excluded: grant.excluded.clone(),
        }],
        HelperGrantee::Set {
            grantee_column,
            call,
        } => set_subjects(
            &grant.table,
            grantee_column,
            call,
            &grant.excluded,
            ctx,
            table_plan,
            all_types,
        ),
    };
    if subjects.is_empty() {
        return Vec::new();
    }
    let grantees = match &grant.grantee {
        HelperGrantee::Set {
            grantee_column,
            call,
        } => Some((grantee_column, call)),
        _ => None,
    };
    let plan = helper_level_plan(level_type, level, table_plan, all_types);
    groups
        .into_iter()
        .flat_map(|(base, rows)| {
            grant_relation_exprs(grant, grantees, &base, &rows, &subjects, level_type, plan)
        })
        .collect()
}

/// The rows of the level a grant arm returns, as [`capped_grant_parts`] reads them, kept
/// only while the request carries the caller the arm's gate requires, which a request
/// without a caller does not, whatever subject its check names.
fn caller_gated_grant_parts<DB: DatabaseLike>(
    grant: &HelperGrant,
    level: &TableId,
    level_type: &TypeName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Vec<UsersetExpr> {
    let parts = capped_grant_parts(grant, level, level_type, ctx, table_plan, all_types);
    let Some(caller) = &grant.carried_caller else {
        return parts;
    };
    let Some(granted) = combine_union(parts) else {
        return Vec::new();
    };
    let carried = RequestFormula::Presence(PresenceAtom::new(caller, true));
    let Some(gate) = level_request_gate(&carried, level, level_type, ctx, table_plan, all_types)
    else {
        return Vec::new();
    };
    let plan = helper_level_plan(level_type, Some(level), table_plan, all_types);
    let name = format!(
        "{}_carrying_caller",
        stored_relation_name(grant.table.name())
    );
    vec![UsersetExpr::Computed(plan.ensure_computed(
        name,
        UsersetExpr::Intersection(vec![granted, gate]),
    ))]
}

/// The rows of the level a grant arm returns, as [`helper_grant_parts`] reads them, kept
/// by each cap on the arm as one relation, or as [`held_grant_expr`] reads them where the
/// arm's rows are held.
///
/// A cap read on the level's row has operands the level's row or the arm's own row where the
/// level's row keys it, so the rows keeping the pair are the ones granting the level's row.
fn capped_grant_parts<DB: DatabaseLike>(
    grant: &HelperGrant,
    level: &TableId,
    level_type: &TypeName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Vec<UsersetExpr> {
    if let Some(held) = &grant.held {
        return held_grant_expr(grant, held, level, level_type, ctx, table_plan, all_types)
            .into_iter()
            .collect();
    }
    let parts = helper_grant_parts(grant, Some(level), level_type, ctx, table_plan, all_types);
    if grant.caps.is_empty() {
        return parts;
    }
    let Some(granted) = combine_union(parts) else {
        return Vec::new();
    };
    let mut kept = vec![granted];
    let mut name = stored_relation_name(grant.table.name());
    for cap in &grant.caps {
        let reach = match &cap.link {
            CapLink::Row { columns } => CapReach::Rows {
                table: &grant.table,
                keys: &grant.object_columns,
                positions: (0..columns.len()).collect(),
                columns: columns.clone(),
                literals: &[],
            },
            CapLink::Pair { object, literals } => CapReach::Pairs {
                object: *object,
                literals,
            },
            // A cap needing more of a row than the level's row names holds its rows.
            CapLink::Held { .. } => return Vec::new(),
        };
        let Some(capped) = cap_expr(cap, reach, level, level_type, ctx, table_plan, all_types)
        else {
            return Vec::new();
        };
        name.push_str("_within_");
        name.push_str(&helper_call_relation_name(&cap.function, &cap.arguments));
        kept.push(capped);
    }
    let plan = helper_level_plan(level_type, Some(level), table_plan, all_types);
    vec![UsersetExpr::Computed(
        plan.ensure_computed(name, UsersetExpr::Intersection(kept)),
    )]
}

/// The rows of the level a grant arm returns where each row it joins meets the join, no
/// row blocking it does, and every cap on it keeps it.
///
/// Each row of the arm's table is an object of its type, holding the grant the row makes
/// while every row it joins holds a gate, no row blocking it does, and the pairs its caps
/// name hold the caller. The level's row reaches the arm's rows naming it, and every link
/// and gate is read from one row of one table, so a change to a joined or blocking row
/// moves only that row's own gate.
fn held_grant_expr<DB: DatabaseLike>(
    grant: &HelperGrant,
    held: &HeldRows,
    level: &TableId,
    level_type: &TypeName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<UsersetExpr> {
    let row_type = ctx.table_types.resolve(&grant.table);
    let row_grant = HelperGrant {
        object_columns: held.identity.clone(),
        caps: Vec::new(),
        held: None,
        ..grant.clone()
    };
    let parts = helper_grant_parts(
        &row_grant,
        Some(&grant.table),
        &row_type,
        ctx,
        table_plan,
        all_types,
    );
    let mut name = stored_relation_name(grant.table.name());
    let mut kept = vec![combine_union(parts)?];
    for joined in &held.joined {
        kept.push(joined_row_expr(
            grant, held, &row_type, joined, ctx, table_plan, all_types,
        )?);
        name.push_str("_with_");
        name.push_str(&stored_relation_name(joined.table.name()));
    }
    let mut blocking = Vec::with_capacity(held.blocked.len());
    for blocked in &held.blocked {
        blocking.push(joined_row_expr(
            grant, held, &row_type, blocked, ctx, table_plan, all_types,
        )?);
        name.push_str("_without_");
        name.push_str(&stored_relation_name(blocked.table.name()));
    }
    for cap in &grant.caps {
        kept.push(held_cap_expr(
            cap, grant, held, &row_type, ctx, table_plan, all_types,
        )?);
        name.push_str("_within_");
        name.push_str(&helper_call_relation_name(&cap.function, &cap.arguments));
    }
    let mut rule = combine_intersection(kept)?;
    if let Some(subtract) = combine_union(blocking) {
        rule = UsersetExpr::Exclusion {
            base: Box::new(rule),
            subtract: Box::new(subtract),
        };
    }
    let row_plan = helper_level_plan(&row_type, Some(&grant.table), table_plan, all_types);
    let rows_held = row_plan.ensure_computed(name, rule);

    let mut key = table_source_key("joined-grant-rows", &grant.table);
    source_key_columns(&mut key, &grant.object_columns);
    let plan = helper_level_plan(level_type, Some(level), table_plan, all_types);
    let link = plan.membership_source_relation(
        &key,
        stored_relation_name(grant.table.name()),
        vec![DirectSubject::Type(row_type.clone())],
    );
    plan.add_source(TupleSource::ClosureBridge {
        link_table: grant.table.clone(),
        object_cols: grant.object_columns.clone(),
        subject_cols: held.identity.clone(),
        guarded_type: level_type.clone(),
        owner_type: row_type,
        relation: link.clone(),
        extra_predicates: ResidualPredicates::default(),
    });
    Some(UsersetExpr::TupleToUserset {
        tupleset: link,
        computed: rows_held,
    })
}

/// Everyone a held row of the arm's table holds through the row of `joined.table` it
/// names, `None` where a predicate has no gate.
///
/// The named row holds every user while it meets every predicate, or while it exists for
/// a join with none, and each held row links to the row its columns name.
fn joined_row_expr<DB: DatabaseLike>(
    grant: &HelperGrant,
    held: &HeldRows,
    row_type: &TypeName,
    joined: &HelperJoin,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<UsersetExpr> {
    let existing;
    let predicates = if joined.predicates.is_empty() {
        existing = [AttributePredicate {
            column: joined.identity.first()?.clone(),
            test: AttributeTest::IsNotNull,
        }];
        &existing[..]
    } else {
        &joined.predicates[..]
    };
    let joined_type = ctx.table_types.resolve(&joined.table);
    let joined_plan = helper_level_plan(&joined_type, Some(&joined.table), table_plan, all_types);
    let mut gate_name = String::new();
    let gates = attribute_gates(
        joined_plan,
        &joined.table,
        &joined.identity,
        predicates,
        &mut gate_name,
    )?;
    let gate = match combine_intersection(gates)? {
        UsersetExpr::Computed(relation) => relation,
        rule => joined_plan.ensure_computed(
            flag_relation_name(predicates.first()?.column.as_str(), &gate_name),
            rule,
        ),
    };
    let row_plan = helper_level_plan(row_type, Some(&grant.table), table_plan, all_types);
    Some(UsersetExpr::TupleToUserset {
        tupleset: joined_row_link(grant, held, joined, &joined_type, row_plan),
        computed: gate,
    })
}

/// The tupleset naming, on each held row of `row_plan`'s type, the row of `joined.table`
/// its columns name, with the source loading it.
fn joined_row_link(
    grant: &HelperGrant,
    held: &HeldRows,
    joined: &HelperJoin,
    joined_type: &TypeName,
    row_plan: &mut TypePlan,
) -> RelationName {
    let mut key = table_source_key("joined-row", &grant.table);
    source_key_columns(&mut key, &joined.columns);
    source_key_part(&mut key, &joined.table.to_string());
    let link = row_plan.membership_source_relation(
        &key,
        stored_relation_name(joined.table.name()),
        vec![DirectSubject::Type(joined_type.clone())],
    );
    row_plan.add_source(TupleSource::ClosureBridge {
        link_table: grant.table.clone(),
        object_cols: held.identity.clone(),
        subject_cols: joined.columns.clone(),
        guarded_type: row_plan.type_name.clone(),
        owner_type: joined_type.clone(),
        relation: link.clone(),
        extra_predicates: ResidualPredicates::default(),
    });
    link
}

/// The held rows of the arm's table `cap` keeps, `None` where it keeps none.
///
/// A cap reading the held row's own columns is read on the held row. One reading a joined
/// row's columns is read on that joined row, which each held row reaches through the link
/// its join writes.
fn held_cap_expr<DB: DatabaseLike>(
    cap: &HelperCap,
    grant: &HelperGrant,
    held: &HeldRows,
    row_type: &TypeName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<UsersetExpr> {
    // A cap read on the level's row never reaches a held row.
    let CapLink::Held {
        reader,
        columns,
        literals,
    } = &cap.link
    else {
        return None;
    };
    let reach = |table, keys| CapReach::Rows {
        table,
        keys,
        positions: columns.iter().map(|(position, _)| *position).collect(),
        columns: columns.iter().map(|(_, column)| column.clone()).collect(),
        literals,
    };
    let CapReader::Joined(row) = reader else {
        return cap_expr(
            cap,
            reach(&grant.table, &held.identity),
            &grant.table,
            row_type,
            ctx,
            table_plan,
            all_types,
        );
    };
    let joined = held.joined.get(*row)?;
    let joined_type = ctx.table_types.resolve(&joined.table);
    let capped = cap_expr(
        cap,
        reach(&joined.table, &joined.identity),
        &joined.table,
        &joined_type,
        ctx,
        table_plan,
        all_types,
    )?;
    let joined_plan = helper_level_plan(&joined_type, Some(&joined.table), table_plan, all_types);
    let within = joined_plan.ensure_computed(
        helper_call_relation_name(&cap.function, &cap.arguments),
        capped,
    );
    let row_plan = helper_level_plan(row_type, Some(&grant.table), table_plan, all_types);
    Some(UsersetExpr::TupleToUserset {
        tupleset: joined_row_link(grant, held, joined, &joined_type, row_plan),
        computed: within,
    })
}

/// How each object of the type a cap is read on reaches the pairs its operands name.
enum CapReach<'a> {
    /// The rows of `table` naming each object by `keys`, whose `columns` hold the pair at
    /// `positions`, beside `literals` at theirs.
    Rows {
        table: &'a TableId,
        keys: &'a [ColumnName],
        positions: Vec<usize>,
        columns: Vec<ColumnName>,
        literals: &'a [(usize, AttributeLiteral)],
    },
    /// The pairs whose column at `object` holds the object itself, beside `literals` at
    /// theirs.
    Pairs {
        object: usize,
        literals: &'a [(usize, AttributeLiteral)],
    },
}

/// The objects of `level_type` `cap` keeps, `None` where it keeps none.
///
/// Each pair the cap returns is an object of its own, holding whoever the cap's arms
/// return it to, and each object of `level_type` links to the pairs its operands name as
/// `reach` reads them. Column operands beside literals name an object of their own, keyed
/// by the columns' values, which links to every pair holding those values beside those
/// literals. While the request leaves the lifting value absent, every object is kept.
fn cap_expr<DB: DatabaseLike>(
    cap: &HelperCap,
    reach: CapReach<'_>,
    level: &TableId,
    level_type: &TypeName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<UsersetExpr> {
    let call = helper_call_relation_name(&cap.function, &cap.arguments);
    let pair_type = cap_type_name(cap, "pair", ctx.table_types);
    let mut held = Vec::new();
    for arm in &cap.arms {
        held.extend(helper_grant_parts(
            arm, None, &pair_type, ctx, table_plan, all_types,
        ));
    }
    let holder = combine_union(held).map(|held| {
        helper_level_plan(&pair_type, None, table_plan, all_types)
            .ensure_computed(call.clone(), held)
    });
    let mut kept = Vec::with_capacity(2);
    if let Some(lift) = &cap.lift {
        let absent = RequestFormula::Presence(PresenceAtom::new(lift, false));
        kept.extend(level_request_gate(
            &absent, level, level_type, ctx, table_plan, all_types,
        ));
    }
    if let Some(holder) = holder {
        let reached = match reach {
            CapReach::Pairs { object, literals } => {
                let plan = helper_level_plan(level_type, Some(level), table_plan, all_types);
                UsersetExpr::TupleToUserset {
                    tupleset: cap_link(&pair_type, literal_links(cap, &[object], literals), plan),
                    computed: holder,
                }
            }
            CapReach::Rows {
                table,
                keys,
                columns,
                literals: [],
                ..
            } => {
                let plan = helper_level_plan(level_type, Some(level), table_plan, all_types);
                let rows = vec![(table, keys.to_vec(), columns, ResidualPredicates::default())];
                UsersetExpr::TupleToUserset {
                    tupleset: cap_link(&pair_type, rows, plan),
                    computed: holder,
                }
            }
            CapReach::Rows {
                table,
                keys,
                positions,
                columns,
                literals,
            } => {
                let mut suffix = String::from("key");
                for position in &positions {
                    suffix.push('_');
                    suffix.push_str(&position.to_string());
                }
                let key_type = cap_type_name(cap, &suffix, ctx.table_types);
                let key_plan = helper_level_plan(&key_type, None, table_plan, all_types);
                let pairs = cap_link(
                    &pair_type,
                    literal_links(cap, &positions, literals),
                    key_plan,
                );
                let at_key = key_plan.ensure_computed(
                    call,
                    UsersetExpr::TupleToUserset {
                        tupleset: pairs,
                        computed: holder,
                    },
                );
                let plan = helper_level_plan(level_type, Some(level), table_plan, all_types);
                let rows = vec![(table, keys.to_vec(), columns, ResidualPredicates::default())];
                UsersetExpr::TupleToUserset {
                    tupleset: cap_link(&key_type, rows, plan),
                    computed: at_key,
                }
            }
        };
        kept.push(reached);
    }
    combine_union(kept)
}

/// `formula` stated on the request gate each row of `level` links to, a rule of
/// `level_type`, the tuples it writes added to `table_plan`. `None` where no tuple names a
/// row of `level`.
fn level_request_gate<DB: DatabaseLike>(
    formula: &RequestFormula,
    level: &TableId,
    level_type: &TypeName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Option<UsersetExpr> {
    // The gate object stands for the level's type, so its plan leaves `all_types` while
    // the request-gate plan there takes the formula.
    let (gated, entries) = if table_plan.type_name == *level_type {
        request_gate_on(formula, level, ctx, table_plan, all_types)
    } else {
        let mut plan = all_types.remove(level_type).unwrap_or_else(|| {
            TypePlan::new_with_well_known(level_type.clone(), &table_plan.well_known)
        });
        plan.names_rows_of(level);
        let gated = request_gate_on(formula, level, ctx, &mut plan, all_types);
        all_types.insert(level_type.clone(), plan);
        gated
    }?;
    for entry in entries {
        table_plan.add_source(entry);
    }
    Some(gated)
}

/// The type named after the call `cap` makes and `suffix`, `capped_kinds_reader_pair` for
/// the pairs `authz.capped_kinds('reader')` returns.
fn cap_type_name(cap: &HelperCap, suffix: &str, table_types: &TableTypes) -> TypeName {
    let call = helper_call_relation_name(&cap.function, &cap.arguments);
    let base = canonical_fga_type_name(&format!("{call}_{suffix}"));
    if table_types.claims(&base) {
        let mut key = cap.function.clone();
        for argument in &cap.arguments {
            source_key_part(&mut key, argument);
        }
        return canonical_fga_type_name(&format!("{base}_{}", stable_hex_suffix(&key)));
    }
    base
}

/// One table whose rows link an object to another, each by its columns, and the filter
/// on those rows.
type CapLinkRows<'a> = (
    &'a TableId,
    Vec<ColumnName>,
    Vec<ColumnName>,
    ResidualPredicates,
);

/// The rows of `cap`'s arms linking the object their columns at `positions` name to the
/// pair they return, kept where their columns hold `literals` at those literals' positions.
fn literal_links<'a>(
    cap: &'a HelperCap,
    positions: &[usize],
    literals: &[(usize, AttributeLiteral)],
) -> Vec<CapLinkRows<'a>> {
    cap.arms
        .iter()
        .filter_map(|arm| {
            let held = literals
                .iter()
                .map(|(position, value)| {
                    Some(AttributePredicate {
                        column: arm.object_columns.get(*position)?.clone(),
                        test: AttributeTest::Compare {
                            operator: AttributeOperator::Eq,
                            value: value.clone(),
                        },
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            let keys = positions
                .iter()
                .map(|position| arm.object_columns.get(*position).cloned())
                .collect::<Option<Vec<_>>>()?;
            Some((
                &arm.table,
                keys,
                arm.object_columns.clone(),
                grant_row_conjuncts(&held, &[], 0)?,
            ))
        })
        .collect()
}

/// The tupleset naming, on each object of `plan`'s type, the objects of `owner` the rows of
/// `links` link it to, with the sources loading it.
fn cap_link(owner: &TypeName, links: Vec<CapLinkRows<'_>>, plan: &mut TypePlan) -> RelationName {
    let level_type = plan.type_name.clone();
    let mut key = format!("cap:{owner}");
    for (table, object_cols, subject_cols, predicates) in &links {
        let mut part = table_source_key("cap_link", table);
        for column in object_cols.iter().chain(subject_cols) {
            source_key_part(&mut part, column.as_str());
        }
        if let Some(sql) = predicates.sql() {
            source_key_part(&mut part, &sql);
        }
        source_key_part(&mut key, &part);
    }
    let link = plan.membership_source_relation(
        &key,
        owner.as_str(),
        vec![DirectSubject::Type(owner.clone())],
    );
    for (table, object_cols, subject_cols, extra_predicates) in links {
        plan.add_source(TupleSource::ClosureBridge {
            link_table: table.clone(),
            object_cols,
            subject_cols,
            guarded_type: level_type.clone(),
            owner_type: owner.clone(),
            relation: link.clone(),
            extra_predicates,
        });
    }
    link
}

/// Who a grant row grants.
enum Granted {
    /// The user its column names.
    User(ColumnName),
    /// Whoever the grantee it names stands for.
    Grantee(GranteeSubject),
}

/// One subject of a grant row, with the conjuncts typing its grantee, and the callers
/// an audience grants every user but.
struct GrantSubject {
    granted: Granted,
    joins: Vec<ResidualPredicate>,
    excluded: Vec<String>,
}

/// `<column> <> '<caller>'` for each of `excluded`.
fn caller_exclusion(column: &ColumnName, excluded: &[String]) -> Vec<ResidualPredicate> {
    let column_sql = quote_sql_identifier(column.as_str());
    excluded
        .iter()
        .map(|caller| ResidualPredicate {
            sql: format!("{column_sql} <> {}", quote_sql_string_literal(caller)),
            guard: Some(ResidualGuard::Compare(AttributePredicate {
                column: column.clone(),
                test: AttributeTest::Compare {
                    operator: AttributeOperator::NotEq,
                    value: AttributeLiteral::Text(caller.clone()),
                },
            })),
            request: None,
            relations: Vec::new(),
        })
        .collect()
}

impl GrantSubject {
    /// The user `column` names, unless it is one of `excluded`, which no row grants.
    fn user(
        column: ColumnName,
        mut joins: Vec<ResidualPredicate>,
        excluded: &[String],
    ) -> GrantSubject {
        joins.extend(caller_exclusion(&column, excluded));
        GrantSubject {
            granted: Granted::User(column),
            joins,
            excluded: Vec::new(),
        }
    }

    fn direct_subject(&self, well_known: &WellKnownTypes) -> DirectSubject {
        match &self.granted {
            Granted::User(_) | Granted::Grantee(GranteeSubject::Caller(_)) => {
                DirectSubject::Type(well_known.user.clone())
            }
            Granted::Grantee(GranteeSubject::Userset {
                type_name,
                relation,
                ..
            }) => DirectSubject::Userset {
                type_name: type_name.clone(),
                relation: relation.clone(),
            },
            Granted::Grantee(GranteeSubject::Everyone) => {
                DirectSubject::Wildcard(well_known.user.clone())
            }
        }
    }
}

/// The subjects a grant naming one of the grantees `call` returns grants, typed by the
/// rows `grantee_column` of `grant_table` names, none of them one of the callers
/// `excluded` names.
///
/// Where every arm is the caller itself or an audience, a grantee the arm keeps is that
/// user or every user. Otherwise it is whoever the call holds on it.
fn set_subjects<DB: DatabaseLike>(
    grant_table: &TableId,
    grantee_column: &ColumnName,
    call: &HelperCall,
    excluded: &[String],
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> Vec<GrantSubject> {
    let outer = format!(
        "{}.{}",
        grant_table.sql_name(),
        quote_sql_identifier(grantee_column.as_str())
    );
    let inline = call.arms.iter().all(|arm| {
        matches!(arm, HelperSetArm::Grant(grant)
            if grant.caps.is_empty()
                && grant.carried_caller.is_none()
                && (grant.returns_the_caller() || grant.grantee == HelperGrantee::Anyone))
    });
    if !inline {
        return helper_call_relation(call, ctx, table_plan, all_types)
            .map(|relation| GrantSubject {
                granted: Granted::Grantee(GranteeSubject::Userset {
                    type_name: ctx.table_types.resolve(&call.level),
                    relation,
                    column: grantee_column.clone(),
                }),
                joins: Vec::new(),
                excluded: excluded.to_vec(),
            })
            .into_iter()
            .collect();
    }
    let mut subjects = Vec::with_capacity(call.arms.len());
    for arm in &call.arms {
        let HelperSetArm::Grant(grant) = arm else {
            continue;
        };
        let [object] = grant.object_columns.as_slice() else {
            continue;
        };
        let Some(join) = grantee_join(&grant.table, object, &outer, &kept_rows(&grant.rows)) else {
            continue;
        };
        let mut kept_out = grant.excluded.clone();
        for caller in excluded {
            if !kept_out.contains(caller) {
                kept_out.push(caller.clone());
            }
        }
        if grant.returns_the_caller() {
            subjects.push(GrantSubject::user(
                grantee_column.clone(),
                vec![join],
                &kept_out,
            ));
        } else {
            subjects.push(GrantSubject {
                granted: Granted::Grantee(GranteeSubject::Everyone),
                joins: vec![join],
                excluded: kept_out,
            });
        }
    }
    subjects
}

/// `EXISTS` a row of `table` whose `column` holds `outer` and that satisfies
/// `predicates`. `None` where a predicate has no SQL spelling.
fn grantee_join(
    table: &TableId,
    column: &ColumnName,
    outer: &str,
    predicates: &[AttributePredicate],
) -> Option<ResidualPredicate> {
    let alias = quote_sql_identifier("grantee");
    let mut sql = format!(
        "EXISTS (SELECT 1 FROM {} AS {alias} WHERE {alias}.{} = {outer}",
        table.sql_name(),
        quote_sql_identifier(column.as_str())
    );
    for predicate in predicates {
        let _ = write!(
            sql,
            " AND {alias}.{} {}",
            quote_sql_identifier(predicate.column.as_str()),
            render_attribute_test(&predicate.test)?
        );
    }
    sql.push(')');
    Some(ResidualPredicate {
        sql,
        guard: None,
        request: None,
        relations: vec![table.clone()],
    })
}

/// The grant rows one rule reads, one group per role the arm keeps, or one for every
/// row it keeps where the grant table has no role column, each with the relation name
/// it earns, `unsplit` where no role names it.
///
/// A time bound rides the tuple as a condition comparing the row's column with the
/// request clock. A bound keeping `NULL` splits the rows by whether the column holds
/// one, since a `NULL` row meets the bound at every instant and fills no parameter, so
/// each role is the union of one group per way the row can meet the bounds.
///
/// A condition with no SQL spelling loads nothing rather than every row.
fn grant_row_groups(
    rows: &GrantRows,
    time_bounds: &[HelperTimeBound],
    unsplit: &str,
) -> Vec<(String, ResidualPredicates)> {
    let roles: Vec<(String, Vec<AttributePredicate>)> = match rows {
        GrantRows::Roles {
            column,
            values,
            predicates,
        } => values
            .iter()
            .map(|value| {
                // A role spelled as text names its relation, any other literal the
                // generic name the source key disambiguates.
                let base = match value {
                    AttributeLiteral::Text(text) => text.clone(),
                    _ => unsplit.to_string(),
                };
                let role = AttributePredicate {
                    column: column.clone(),
                    test: AttributeTest::Compare {
                        operator: AttributeOperator::Eq,
                        value: value.clone(),
                    },
                };
                let kept = core::iter::once(role).chain(predicates.iter().cloned());
                (base, kept.collect())
            })
            .collect(),
        GrantRows::Matching { predicates } => vec![(unsplit.to_string(), predicates.clone())],
    };
    let null_kept = time_bounds.iter().filter(|bound| bound.keeps_null).count();
    let mut groups = Vec::with_capacity(roles.len() << null_kept);
    for (base, kept) in roles {
        // Bit `i` set reads the rows holding `NULL` in the `i`th bound keeping it.
        for nulls in 0..1_usize << null_kept {
            groups.extend(
                grant_row_conjuncts(&kept, time_bounds, nulls)
                    .map(|conjuncts| (base.clone(), conjuncts)),
            );
        }
    }
    groups
}

/// The conjuncts a grant row meets: its role and kept values, `IS NULL` on each bound
/// keeping `NULL` whose bit `nulls` sets, and the clock comparison of every other bound.
/// `None` where a conjunct has no SQL spelling.
fn grant_row_conjuncts(
    kept: &[AttributePredicate],
    time_bounds: &[HelperTimeBound],
    nulls: usize,
) -> Option<ResidualPredicates> {
    let guard = |predicate: AttributePredicate| -> Option<ResidualPredicate> {
        Some(ResidualPredicate {
            sql: format!(
                "{} {}",
                quote_sql_identifier(predicate.column.as_str()),
                render_attribute_test(&predicate.test)?
            ),
            guard: Some(ResidualGuard::Compare(predicate)),
            request: None,
            relations: Vec::new(),
        })
    };
    let mut conjuncts = Vec::with_capacity(kept.len() + time_bounds.len());
    for predicate in kept {
        conjuncts.push(guard(predicate.clone())?);
    }
    let mut null_kept = 0;
    for bound in time_bounds {
        let column = &bound.comparison.column;
        if bound.keeps_null {
            let reads_null = nulls & (1 << null_kept) != 0;
            null_kept += 1;
            if reads_null {
                conjuncts.push(guard(AttributePredicate {
                    column: column.clone(),
                    test: AttributeTest::IsNull,
                })?);
                continue;
            }
        }
        conjuncts.push(ResidualPredicate {
            sql: format!(
                "{} {} now()",
                quote_sql_identifier(column.as_str()),
                bound.comparison.operator.sql()
            ),
            guard: None,
            request: Some(bound.comparison.clone()),
            relations: Vec::new(),
        });
    }
    Some(ResidualPredicates::new(conjuncts))
}

/// The relation holding the subject of `subject_type` that `subject_column` names in each
/// grant row the group keeps, the caller or another principal the request acts for, named
/// `base` and kept by `extra_predicates`, with the source loading it, conditioned on the
/// request clock where a conjunct compares with it, and `None` where that condition cannot
/// be declared.
fn caller_grant_relation<DB: DatabaseLike>(
    grant: &HelperGrant,
    (subject_column, subject_type): (&ColumnName, &TypeName),
    level_type: &TypeName,
    plan: &mut TypePlan,
    ctx: &PatternCtx<'_, DB>,
    (base, extra_predicates): (String, ResidualPredicates),
    aggregate: bool,
) -> Option<RelationName> {
    let gate = if extra_predicates.has_requests() {
        let (condition, context) = declare_temporal_condition(
            &extra_predicates,
            &grant.table,
            plan,
            ctx.condition_parameters,
            ctx.db,
        )?;
        Some(MembershipGate {
            condition,
            context,
            aggregate,
        })
    } else {
        None
    };
    let fk_cols = grant.object_columns.clone();
    let mut key = membership_source_key(
        &grant.table,
        &fk_cols,
        subject_column,
        &extra_predicates,
        gate.as_ref().map(MembershipSourceGate::from),
    );
    // One column names the caller in one arm and another principal in the next, and the
    // two relations hold different types.
    if *subject_type != plan.well_known.user {
        source_key_part(&mut key, subject_type.as_str());
    }
    let subject = match &gate {
        Some(gate) => DirectSubject::ConditionalType {
            type_name: subject_type.clone(),
            condition: gate.condition.clone(),
        },
        None => DirectSubject::Type(subject_type.clone()),
    };
    let relation = plan.membership_source_relation(&key, base, vec![subject]);
    plan.add_source(TupleSource::ExistsMembership {
        join_table: grant.table.clone(),
        fk_cols,
        user_col: subject_column.clone(),
        subject_type: subject_type.clone(),
        parent_type: level_type.clone(),
        relation: relation.clone(),
        extra_predicates,
        gate,
    });
    Some(relation)
}

/// The rows of a table admitting whoever presents a value the request compares with
/// each row's, the one value the source carries or one of the set's.
struct RequestShares<'a> {
    table: &'a TableId,
    value_column: &'a ColumnName,
    source: &'a DeclaredSource,
}

impl RequestShares<'_> {
    /// The relation of the table's share type admitting whoever presents a row's value,
    /// one per group of rows, with the table's row identity and its share type. `None`
    /// where the table has no row identity.
    ///
    /// Each row is an object of its own, so one condition parameter carries its value. A
    /// group kept by the statement time compares its row's bound with the request clock
    /// in the same condition, and a group whose bound has no condition admits nobody.
    fn gates<DB: DatabaseLike>(
        &self,
        groups: Vec<(String, ResidualPredicates)>,
        ctx: &PatternCtx<'_, DB>,
        table_plan: &mut TypePlan,
        all_types: &mut BTreeMap<TypeName, TypePlan>,
    ) -> Option<(Vec<ColumnName>, TypeName, Vec<RelationName>)> {
        let table = self.table;
        let Some(identity_cols) = resolve_row_identity(table, ctx.db) else {
            skip_source_without_row_identity(table_plan, table, "request value shares", ctx.db);
            return None;
        };
        let share_type = share_type_name(table, ctx.table_types);
        let request_parameter = self.source.condition_parameter();
        let comparison = if self.source.packing().is_some() {
            RequestComparison::CallerSetHolds
        } else {
            RequestComparison::CallerValueEquals
        };
        let separator = self.source.separator().map(str::to_string);
        let share_plan = all_types.entry(share_type.clone()).or_insert_with(|| {
            TypePlan::new_with_well_known(share_type.clone(), &ctx.settings.well_known)
        });
        let mut gates = Vec::with_capacity(groups.len());
        for (base, extra_predicates) in groups {
            let mut namespace = ctx.condition_parameters.namespace([request_parameter]);
            reserve_temporal_clocks(&extra_predicates, ctx.condition_parameters, &mut namespace);
            let row_parameter = namespace.allocate_row(self.value_column.as_str());
            let temporal = if extra_predicates.has_requests() {
                let Some(temporal) = temporal_gates(
                    &extra_predicates,
                    table,
                    ctx.condition_parameters,
                    &mut namespace,
                    ctx.db,
                ) else {
                    continue;
                };
                temporal
            } else {
                Vec::new()
            };
            let mut spec = request_comparison_spec(&row_parameter, request_parameter, comparison);
            for gate in &temporal {
                spec.expression = format!("{} && {}", spec.expression, gate.fragment);
                spec.parameters.extend([
                    (
                        gate.parameter.to_string(),
                        ConditionParameter::Scalar(TIMESTAMP_PARAMETER_TYPE),
                    ),
                    gate.clock.declaration(),
                ]);
            }
            let condition = declare_condition(share_plan, spec);
            let temporal_context: Vec<GateContextColumn> = temporal
                .into_iter()
                .map(|gate| GateContextColumn {
                    parameter: gate.parameter.to_string(),
                    column: gate.column,
                    witness: gate.witness,
                    monotone: gate.monotone,
                })
                .collect();
            let key = membership_source_key(
                table,
                &identity_cols,
                self.value_column,
                &extra_predicates,
                Some(MembershipSourceGate {
                    condition: &condition,
                    context: &temporal_context,
                    aggregate: false,
                    clocked: !temporal_context.is_empty(),
                    inputs: &[
                        row_parameter.as_str(),
                        request_parameter.as_str(),
                        self.source.setting_key(),
                        if separator.is_some() { "some" } else { "none" },
                        separator.as_deref().unwrap_or_default(),
                    ],
                }),
            );
            let subject = DirectSubject::ConditionalWildcard {
                type_name: share_plan.well_known.user.clone(),
                condition: condition.clone(),
            };
            let gate = share_plan.membership_source_relation(&key, base, vec![subject]);
            let gate_source = TupleSource::RequestShareGate {
                join_table: table.clone(),
                identity_cols: identity_cols.clone(),
                share_type: share_type.clone(),
                relation: gate.clone(),
                condition,
                row_parameter: row_parameter.to_string(),
                member_col: self.value_column.clone(),
                request_parameter: request_parameter.to_string(),
                setting_key: self.source.setting_key().to_string(),
                normalization: self.source.normalization(),
                separator: separator.clone(),
                comparison,
                extra_predicates,
                temporal_context,
            };
            share_plan.add_source(gate_source.clone());
            // The guarded table's own sources state what its checks ask of the caller.
            table_plan.add_source(gate_source);
            gates.push(gate);
        }
        Some((identity_cols, share_type, gates))
    }
}

/// Gate rows on the request's value being one a declared helper returns.
///
/// The helper returns the same rows to every caller, so the clause has one truth value
/// for every guarded row and is stated once, on the request-gate object standing for this
/// type, as a request formula is. Each row the helper returns is an object of its own
/// share type, admitting whoever presents its value, and every row of its table is
/// linked to the gate object, so the gate object admits whoever presents any of them.
pub(crate) fn emit_request_value_in_helper_set<DB: DatabaseLike>(
    test: &RequestValueInHelperSet,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
) -> UsersetExpr {
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
    let mut parts = Vec::with_capacity(test.arms.len());
    for arm in &test.arms {
        let share = RequestShares {
            table: &arm.table,
            value_column: &arm.value_column,
            source: &test.source,
        };
        let groups = grant_row_groups(
            &GrantRows::Matching {
                predicates: arm.predicates.clone(),
            },
            &[],
            member_relation().as_str(),
        );
        let Some((identity_cols, share_type, gates)) =
            share.gates(groups, ctx, table_plan, all_types)
        else {
            continue;
        };
        let gate_plan = request_gate_plan(all_types, well_known);
        // Every row of the table, which the share relations then keep as the arm does,
        // so one link serves every helper reading the table.
        let link = gate_plan.ensure_direct(
            clamp_relation_name(share_type.to_string()),
            vec![DirectSubject::Type(share_type.clone())],
        );
        gate_plan.add_source(TupleSource::ScopeShares {
            scope_type: gate_type.clone(),
            scope_object: gate_object.clone(),
            member_table: arm.table.clone(),
            identity_cols,
            share_type,
            relation: link.clone(),
        });
        parts.extend(
            gates
                .into_iter()
                .map(|gate| share_reach(link.clone(), gate)),
        );
    }
    let Some(held) = combine_union(parts) else {
        return deny_expr(table_plan);
    };
    let call = helper_call_relation_name(&test.function, &test.arguments);
    let relation = request_gate_plan(all_types, well_known).ensure_computed(
        clamp_relation_name(format!("{}_in_{call}", test.source.condition_parameter())),
        held,
    );
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

/// The plan of the request-gate type, declared on first use.
fn request_gate_plan<'p>(
    all_types: &'p mut BTreeMap<TypeName, TypePlan>,
    well_known: &WellKnownTypes,
) -> &'p mut TypePlan {
    all_types
        .entry(well_known.request_gate.clone())
        .or_insert_with(|| {
            TypePlan::new_with_well_known(well_known.request_gate.clone(), well_known)
        })
}

/// The conditions every row a grant arm keeps satisfies, whichever role it holds.
fn kept_rows(rows: &GrantRows) -> Vec<AttributePredicate> {
    match rows {
        GrantRows::Roles {
            column,
            values,
            predicates,
        } => core::iter::once(AttributePredicate {
            column: column.clone(),
            test: AttributeTest::In(values.clone()),
        })
        .chain(predicates.iter().cloned())
        .collect(),
        GrantRows::Matching { predicates } => predicates.clone(),
    }
}

/// The relations one set of a grant arm's rows holds on the level, each with the
/// sources loading it.
///
/// Every subject but one excluding some callers shares one relation, whose type
/// restriction lists them. Such a subject, an audience or whoever a set of grantees
/// holds, is a relation of its own, less one of the callers it excludes.
fn grant_relation_exprs(
    grant: &HelperGrant,
    grantees: Option<(&ColumnName, &HelperCall)>,
    base: &str,
    rows: &ResidualPredicates,
    subjects: &[GrantSubject],
    level_type: &TypeName,
    plan: &mut TypePlan,
) -> Vec<UsersetExpr> {
    let fk_cols = grant.object_columns.clone();
    // A grant arm returns at least one column.
    let Some(compared) = grantees.map(|(column, _)| column).or(fk_cols.first()) else {
        return Vec::new();
    };
    let mut key = membership_source_key(&grant.table, &fk_cols, compared, rows, None);
    let user_type = plan.well_known.user.clone();
    match grantees {
        Some((_, call)) => {
            source_key_part(&mut key, "grantees");
            source_key_part(
                &mut key,
                &helper_call_relation_name(&call.function, &call.arguments),
            );
        }
        None => source_key_part(&mut key, "anyone"),
    }
    for caller in &grant.excluded {
        source_key_part(&mut key, caller);
    }
    let predicates = |subject: &GrantSubject| rows.and(&subject.joins);
    let grantee_grant =
        |relation: &RelationName, subject: GranteeSubject, extra| TupleSource::GranteeGrant {
            join_table: grant.table.clone(),
            fk_cols: fk_cols.clone(),
            parent_type: level_type.clone(),
            relation: relation.clone(),
            subject,
            extra_predicates: extra,
        };
    let source = |relation: &RelationName, subject: &GrantSubject| match &subject.granted {
        Granted::User(column) => TupleSource::ExistsMembership {
            join_table: grant.table.clone(),
            fk_cols: fk_cols.clone(),
            user_col: column.clone(),
            subject_type: user_type.clone(),
            parent_type: level_type.clone(),
            relation: relation.clone(),
            extra_predicates: predicates(subject),
            gate: None,
        },
        Granted::Grantee(granted) => grantee_grant(relation, granted.clone(), predicates(subject)),
    };
    let mut exprs = Vec::new();
    let (shared, gated): (Vec<&GrantSubject>, Vec<&GrantSubject>) = subjects
        .iter()
        .partition(|subject| subject.excluded.is_empty());
    let mut direct: Vec<DirectSubject> = Vec::with_capacity(shared.len());
    for subject in &shared {
        let held = subject.direct_subject(&plan.well_known);
        if !direct.contains(&held) {
            direct.push(held);
        }
    }
    if !direct.is_empty() {
        let relation = plan.membership_source_relation(&key, base, direct);
        for subject in shared {
            plan.add_source(source(&relation, subject));
        }
        exprs.push(UsersetExpr::Computed(relation));
    }
    for (index, subject) in gated.into_iter().enumerate() {
        let mut gated_key = key.clone();
        source_key_part(&mut gated_key, &index.to_string());
        // Only an audience and whoever a set holds keep excluded callers, a user
        // subject leaving them out of its rows instead.
        let kept_name = match &subject.granted {
            Granted::Grantee(GranteeSubject::Userset { type_name, .. }) => {
                format!("{base}_{type_name}")
            }
            _ => format!("{base}_everyone"),
        };
        let kept = plan.membership_source_relation(
            &format!("{gated_key}kept"),
            kept_name,
            vec![subject.direct_subject(&plan.well_known)],
        );
        let excluded = plan.membership_source_relation(
            &format!("{gated_key}excluded"),
            format!("{base}_excluded"),
            vec![DirectSubject::Type(plan.well_known.user.clone())],
        );
        plan.add_source(source(&kept, subject));
        for caller in &subject.excluded {
            plan.add_source(grantee_grant(
                &excluded,
                GranteeSubject::Caller(caller.clone()),
                predicates(subject),
            ));
        }
        exprs.push(UsersetExpr::Exclusion {
            base: Box::new(UsersetExpr::Computed(kept)),
            subtract: Box::new(UsersetExpr::Computed(excluded)),
        });
    }
    exprs
}
