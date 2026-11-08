//! Emission for the patterns a role decides, and the scaffolding they need.
//!
//! A numeric threshold, a role-name list, and the grant relations a role-threshold
//! function implies.

use super::*;
use crate::generator::well_known::owner_team_relation;

/// The relation a numeric role threshold admits, or a denial when no role reaches it.
pub(crate) fn emit_numeric_threshold<DB: DatabaseLike>(
    numeric_threshold: &NumericThreshold,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let NumericThreshold {
        function_name,
        operator,
        threshold,
        resource_column,
        ..
    } = numeric_threshold;
    let Some(prepared) = prepare_role_threshold_translation(
        function_name,
        "Role-threshold",
        resource_column.as_ref(),
        ctx,
        table_plan,
        all_types,
        notes,
    ) else {
        return deny_expr(table_plan);
    };
    let Some(owner) = &prepared.owner else {
        return deny_expr(table_plan);
    };

    let min_level = match operator {
        ThresholdOperator::Gte => *threshold,
        ThresholdOperator::Gt => threshold.saturating_add(1),
    };

    if let Some(role_relation) = role_for_level(&prepared.sorted_roles, min_level) {
        UsersetExpr::TupleToUserset {
            tupleset: owner.pointer.clone(),
            computed: role_relation,
        }
    } else {
        deny_expr(table_plan)
    }
}

/// The relations a role-threshold function's role-name list admits.
pub(crate) fn emit_role_name_in_list<DB: DatabaseLike>(
    role_name_in_list: &RoleNameInList,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let RoleNameInList {
        function_name,
        role_names,
        resource_column,
    } = role_name_in_list;
    let Some(prepared) = prepare_role_threshold_translation(
        function_name,
        "Role-list",
        resource_column.as_ref(),
        ctx,
        table_plan,
        all_types,
        notes,
    ) else {
        return deny_expr(table_plan);
    };
    let Some(owner) = prepared.owner.clone() else {
        return deny_expr(table_plan);
    };

    // Matched by name, not by level, so `viewer=1` and `guest=1` stay
    // distinct. A numeric item means every role at that level.
    let mut selected_names: BTreeSet<String> = BTreeSet::new();
    for role in role_names {
        if let Ok(level) = role.parse::<i32>() {
            // Numeric string → expand to all role names at this level.
            for r in &prepared.sorted_roles {
                if r.level == level {
                    selected_names.insert(r.original_name.to_lowercase());
                }
            }
            continue;
        }
        // Role name string → insert directly (case-insensitive).
        selected_names.insert(role.to_lowercase());
    }

    if selected_names.is_empty() {
        return deny_expr(table_plan);
    }

    if let Some(relation) = ensure_exact_roles_relation(
        all_types,
        &owner.type_name,
        &prepared.sorted_roles,
        &selected_names,
        prepared.has_team_support,
        &table_plan.well_known,
    ) {
        UsersetExpr::TupleToUserset {
            tupleset: owner.pointer,
            computed: relation,
        }
    } else {
        deny_expr(table_plan)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RoleThresholdPrepared {
    sorted_roles: Vec<RoleRelationName>,
    has_team_support: bool,
    /// The owner the ladder lives on, absent where no row can point at one, which is
    /// where the whole rule falls closed.
    owner: Option<OwnerLadder>,
}

/// The owner a guarded row is judged through.
#[derive(Debug, Clone)]
pub(crate) struct OwnerLadder {
    type_name: TypeName,
    pointer: RelationName,
}

pub(crate) fn prepare_role_threshold_translation<DB: DatabaseLike>(
    function_name: &str,
    function_kind_label: &str,
    resource_column: Option<&ColumnName>,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    notes: &mut Vec<TranslationNote>,
) -> Option<RoleThresholdPrepared> {
    let policy_name = ctx.policy_name;
    let source_table = ctx.source_table;
    let registry = ctx.registry;
    let db = ctx.db;
    let Some(FunctionSemantic::RoleThreshold {
        role_levels,
        team_membership,
        grant_table,
        ..
    }) = registry.get(function_name)
    else {
        notes.push(TranslationNote::FunctionMissingMetadata {
            policy: policy_name.to_string(),
            function_kind: function_kind_label.to_string(),
            function: function_name.to_string(),
        });
        return None;
    };

    let Some(grant_table) = resolve_table_id(db, grant_table) else {
        notes.push(TranslationNote::ExpressionRefused {
            policy: policy_name.to_string(),
            reason: format!("the grant table '{grant_table}' does not resolve"),
        });
        return None;
    };
    let team_membership_table = match team_membership {
        Some(membership) => {
            let Some(table) = resolve_table_id(db, &membership.table) else {
                notes.push(TranslationNote::ExpressionRefused {
                    policy: policy_name.to_string(),
                    reason: format!(
                        "the team membership table '{}' does not resolve",
                        membership.table
                    ),
                });
                return None;
            };
            Some(table)
        }
        None => None,
    };
    let has_team_support = team_membership_table.is_some();
    let team_type = team_membership_table
        .as_ref()
        .map(|table| team_type_name(table, ctx.table_types, &table_plan.well_known));
    let owner_type = owner_type_name(&grant_table, function_name, registry, ctx.table_types);
    let refuse = |table_plan: &mut TypePlan, reason: SkippedTuples| {
        table_plan.add_source(TupleSource::Skipped { reason });
        Some(RoleThresholdPrepared {
            sorted_roles: sorted_role_relation_names(role_levels),
            has_team_support,
            owner: None,
        })
    };
    // Before any minting: without a row identity or a column to read the owner from, no row
    // can point at its owner, so the ladder is unreachable and a type minted here would
    // outlive the rule that justified it.
    if resolve_row_identity(source_table, db).is_none() {
        return refuse(
            table_plan,
            SkippedTuples::NoBridge {
                table: source_table.clone(),
                parent_type: owner_type.clone(),
                reason: missing_object_identifier_reason(source_table, db),
            },
        );
    }
    // The column the call itself passes, falling back to the schema only where the call
    // passes an expression: the ladder judges the value the function was given, so reading
    // any other column grants on a comparison the database never makes.
    let owner_column = resource_column
        .cloned()
        .or_else(|| resolve_owner_column(source_table, db));
    let Some(owner_column) = owner_column else {
        return refuse(
            table_plan,
            SkippedTuples::NoOwnerColumn {
                table: source_table.clone(),
            },
        );
    };
    let (sorted_roles, pointer) = ensure_role_threshold_scaffold(
        table_plan,
        all_types,
        &owner_type,
        &owner_column,
        role_levels,
        team_type.as_ref(),
    );
    populate_role_threshold_sources(
        function_name,
        &RoleThresholdTables {
            source: source_table,
            grant: &grant_table,
            team_membership: team_membership_table.as_ref(),
            team_type: team_type.as_ref(),
        },
        db,
        registry,
        &OwnerScope {
            type_name: &owner_type,
            pointer: &pointer,
            column: &owner_column,
        },
        table_plan,
        all_types,
    );

    Some(RoleThresholdPrepared {
        sorted_roles,
        has_team_support,
        owner: Some(OwnerLadder {
            type_name: owner_type,
            pointer,
        }),
    })
}

/// Where a role threshold's facts live: the type carrying the ladder, and the relation a
/// guarded row points at it with.
pub(crate) struct OwnerScope<'a> {
    pub(crate) type_name: &'a TypeName,
    pub(crate) pointer: &'a RelationName,
    /// Column of the guarded table whose value names the owner.
    pub(crate) column: &'a ColumnName,
}

/// Declare the role ladder on the owner type and the relation a guarded row points at it
/// with.
///
/// The ladder judges `(caller, owner value)`, which is what the function takes, so it lives
/// on the owner rather than on every row carrying that value. The pointer is named after
/// the column filling it, because one table can reach the same owner through more than one
/// column and the type name alone cannot tell those apart.
pub(crate) fn ensure_role_threshold_scaffold(
    table_plan: &mut TypePlan,
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    owner_type: &TypeName,
    owner_column: &ColumnName,
    role_levels: &BTreeMap<String, i32>,
    team_type: Option<&TypeName>,
) -> (Vec<RoleRelationName>, RelationName) {
    let sorted_roles = sorted_role_relation_names(role_levels);

    let pointer = table_plan.ensure_direct(
        clamp_relation_name(canonical_fga_type_name(owner_column.as_str()).to_string()),
        vec![DirectSubject::Type(owner_type.clone())],
    );
    let well_known = table_plan.well_known.clone();
    if let Some(team_type) = team_type {
        ensure_member_type(all_types, team_type, &well_known);
    }
    let owner_plan = all_types
        .entry(owner_type.clone())
        .or_insert_with(|| TypePlan::new_with_well_known(owner_type.clone(), &well_known));

    owner_plan.ensure_direct(
        owner_user_relation(),
        vec![DirectSubject::Type(well_known.user.clone())],
    );
    if let Some(team_type) = team_type {
        owner_plan.claim_owner_team_relation(team_type);
    }

    let grant_subjects = if let Some(team_type) = team_type {
        vec![
            DirectSubject::Type(well_known.user.clone()),
            DirectSubject::Type(team_type.clone()),
        ]
    } else {
        vec![DirectSubject::Type(well_known.user.clone())]
    };

    let has_team_support = team_type.is_some();

    for role in &sorted_roles {
        owner_plan.ensure_direct(role.grant_relation(), grant_subjects.clone());
    }

    let mut descending = sorted_roles.clone();
    descending.reverse();

    for (idx, role) in descending.iter().enumerate() {
        let mut children = Vec::new();

        if idx == 0 {
            children.push(UsersetExpr::Computed(owner_user_relation()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: owner_team_relation(),
                    computed: member_relation(),
                });
            }
        } else if let Some(prev) = descending.get(idx - 1) {
            children.push(UsersetExpr::Computed(prev.role_relation()));
        }

        let grant_name = role.grant_relation();
        children.push(UsersetExpr::Computed(grant_name.clone()));
        if has_team_support {
            children.push(UsersetExpr::TupleToUserset {
                tupleset: grant_name,
                computed: member_relation(),
            });
        }

        if let Some(expr) = combine_union(children) {
            owner_plan.ensure_computed(role.role_relation(), expr);
        }
    }

    (sorted_roles, pointer)
}

pub(crate) fn role_for_level(
    sorted_roles: &[RoleRelationName],
    min_level: i32,
) -> Option<RelationName> {
    sorted_roles
        .iter()
        .find(|role| role.level >= min_level)
        .map(RoleRelationName::role_relation)
}

/// The owner-type relation a P2 role-name-in-list policy admits, declared there because a
/// guarded row reaches the ladder through one name and an indirection cannot walk a union.
///
/// Keyed on the listed role names, so a same-level role with a different name
/// (`guest=1` beside `viewer=1`) is not admitted, and named after the names it lists, so
/// two policies listing the same set share it.
pub(crate) fn ensure_exact_roles_relation(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    owner_type: &TypeName,
    sorted_roles: &[RoleRelationName],
    selected_names: &BTreeSet<String>,
    has_team_support: bool,
    well_known: &WellKnownTypes,
) -> Option<RelationName> {
    let mut children = Vec::new();
    let mut listed = Vec::new();

    for role in sorted_roles {
        if selected_names.contains(&role.original_name.to_lowercase()) {
            listed.push(role.token.clone());
            let grant_name = role.grant_relation();
            children.push(UsersetExpr::Computed(grant_name.clone()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: grant_name,
                    computed: member_relation(),
                });
            }
        }
    }

    // Include owner_user / owner_team when the highest-level role is selected.
    let max_level = sorted_roles.iter().map(|role| role.level).max();
    if let Some(max) = max_level {
        let max_is_selected = sorted_roles
            .iter()
            .any(|r| r.level == max && selected_names.contains(&r.original_name.to_lowercase()));
        if max_is_selected {
            children.push(UsersetExpr::Computed(owner_user_relation()));
            if has_team_support {
                children.push(UsersetExpr::TupleToUserset {
                    tupleset: owner_team_relation(),
                    computed: member_relation(),
                });
            }
        }
    }

    let expr = combine_union(children)?;
    let owner_plan = all_types
        .entry(owner_type.clone())
        .or_insert_with(|| TypePlan::new_with_well_known(owner_type.clone(), well_known));
    Some(owner_plan.ensure_computed(format!("roles_{}", listed.join("_")), expr))
}
