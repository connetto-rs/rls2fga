//! Emission for the patterns that reach through another row.
//!
//! Membership through a join table, a membership naming no column of the guarded table, a
//! parent rule through a foreign key, and the two shapes that combine other patterns.

use super::*;

use crate::classifier::expansion::ExpansionState;
use crate::classifier::recognizers::{owner_key_of, resolve_membership_pairing, MembershipPairing};

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
        DirectSubject::Type(parent_type.clone()),
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
        &ctx.settings.request_time_parameter,
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
                DirectSubject::ConditionalType {
                    type_name: table_plan.well_known.user.clone(),
                    condition: condition.clone(),
                },
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
        holder_plan.add_source(TupleSource::HolderShares {
            member_table: member_table.clone(),
            identity_cols,
            holder_type: holder_type.clone(),
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
        holder_plan.membership_source_relation(&key, member_relation(), subject)
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
    let roles = match scope {
        TableReadability::Open => &[][..],
        TableReadability::Unreadable => return deny_expr(table_plan),
        TableReadability::RequestGated { gates: own } => {
            gates.extend(own.iter().cloned());
            &[][..]
        }
        TableReadability::Guarded { roles } => roles.as_slice(),
    };
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
    let membership = combine_intersection(expressions).unwrap_or_else(|| deny_expr(table_plan));
    if roles.is_empty() {
        return membership;
    }
    let scope_relation =
        membership_read_scope_relation_name(ctx.table_types.resolve(join_table).as_str());
    register_pg_role_scope(
        table_plan,
        all_types,
        notes,
        ctx.source_table,
        ctx.db,
        RoleScopeSpec {
            scope_relation: &scope_relation,
            walked: &RolePrivilege::Usage.relation_name(),
            role_names: roles,
            scope_note: TranslationNote::MembershipReadScope {
                policy: ctx.policy_name.to_string(),
                join_table: join_table.clone(),
                roles: roles.to_vec(),
                relation: scope_relation.clone(),
            },
            missing_object_what: "membership read scope tuples",
        },
    );
    scoped_policy_expr(membership, &scope_relation)
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
        DirectSubject::Type(share.share_type.clone()),
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
        &ctx.settings.request_time_parameter,
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
                DirectSubject::ConditionalType {
                    type_name: table_plan.well_known.user.clone(),
                    condition: condition.clone(),
                },
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
            parent_plan.membership_source_relation(&key, base, subject)
        };
        // On the guarded plan first, which is the order the renderer emits.
        let membership_source = TupleSource::ExistsMembership {
            join_table: join_table.clone(),
            fk_cols,
            user_col: user_column.clone(),
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
    let scope = join_table_readability(table, ctx, memo, notes);
    match scope {
        TableReadability::Open | TableReadability::RequestGated { .. } => Some(scope),
        TableReadability::Guarded { .. } => {
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
        DirectSubject::Type(owner_type.clone()),
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
        join_table_readability(link_table, ctx, readability, notes)
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
    subtract: &[ExistsMembership],
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
    readability: &mut BTreeMap<TableId, TableReadability>,
) -> Option<UsersetExpr> {
    let mut sets = Vec::with_capacity(subtract.len());
    for membership in subtract {
        let before = notes.len();
        let set = emit_membership(
            membership,
            ctx,
            table_plan,
            all_types,
            notes,
            readability,
            MembershipRoute::Parent(MembershipPolarity::Block),
        );
        if grants_nothing(&set, table_plan, &mut BTreeSet::new())
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
