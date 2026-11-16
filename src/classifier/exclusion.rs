//! Blocklist subtraction from positive grants, correlated memberships, declared helpers and
//! row flags alike.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::classifier::expansion::{self, ExpansionState};
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    composite_confidence, exclusion_confidence, BoolOp, ClassifiedExpr, Composite, ConfidenceLevel,
    ConstantBool, DeclaredHelper, ExcludedSet, ExistsMembership, ExpandedFunction, HelperSetArm,
    MembershipExclusion, PatternClass, PolicyCommand,
};
use crate::classifier::recognizers::{
    diagnose_p4_membership_ambiguity, is_current_user_expr, recognize_excluded_helper,
    recognize_flagged_row, recognize_p4, recognize_p4_in_subquery, recognize_parent_flag,
    renaming_casts, unparenthesize, FlagRefusal, HelperRefusal, ParentFlag,
};
use crate::classifier::role_keywords::prepare_clause;
use crate::parser::names::{lookup_table, lookup_table_id, table_identity};
use crate::parser::sql_parser::DatabaseLike;
use crate::types::{ColumnName, TableId};
use sqlparser::ast::{BinaryOperator, Expr, InTarget, UnaryOperator};

/// Why a blocklist cannot be represented exactly.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExclusionError {
    #[error("{0}")]
    UnsupportedMembership(String),
    #[error("the blocklist table '{0}' has row level security")]
    GuardedTable(TableId),
    #[error("the blocklist projection '{table}.{column}' must be provably non-null")]
    NullableProjection { table: TableId, column: ColumnName },
    #[error(
        "the column '{table}.{column}' compared with the blocklist must be provably \
         non-null, since PostgreSQL hides a row holding NULL there from exactly the callers \
         whose blocklist is not empty"
    )]
    NullableCompared { table: String, column: ColumnName },
    #[error(
        "the column '{table}.{column}' passed to a STRICT function must be provably \
         non-null, since the function returns NULL for a NULL argument, NOT keeps it NULL, \
         and PostgreSQL hides the row where no tuple flags it"
    )]
    NullableStrictArgument { table: String, column: ColumnName },
    #[error(transparent)]
    Helper(#[from] HelperRefusal),
    #[error(transparent)]
    Flag(#[from] FlagRefusal),
}

/// Split a clause into its positive grant and blocklists.
///
/// `see_through_functions` widens the `AND`/parenthesis flattening below to also
/// substitute a declared, unregistered `LANGUAGE sql` function call's body in
/// place of the call, so a blocklist spelled inside such a function classifies
/// exactly as if it had been written inline. Only the restrictive clause's own
/// top-level call sets it: every other classification site already rejects a
/// grant-less result regardless of what this function finds, so widening there
/// would only spend the shared expansion budget without changing the outcome.
#[expect(
    clippy::too_many_arguments,
    reason = "db, registry, table and state are four separate borrows the recursion threads through"
)]
pub(crate) fn try_membership_exclusion<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    command: PolicyCommand,
    depth: u32,
    state: &ExpansionState,
    see_through_functions: bool,
) -> Result<Option<ClassifiedExpr>, ExclusionError> {
    if !see_through_functions && !has_exclusion_conjunct(expr, depth) {
        return Ok(None);
    }
    let mut positives: Vec<Expr> = Vec::new();
    let mut subtract: Vec<ExcludedSet> = Vec::new();
    if !collect_conjuncts(
        expr,
        db,
        registry,
        table,
        depth,
        state,
        see_through_functions,
        &mut positives,
        &mut subtract,
    )? {
        return Ok(None);
    }
    if subtract.is_empty() {
        return Ok(None);
    }

    let base = match positives.as_slice() {
        // A flag decides every caller alike, so outside a restrictive clause, which
        // subtracts from the grants beside it, nothing but flags removes from everyone.
        [] if !see_through_functions
            && subtract
                .iter()
                .all(|excluded| matches!(excluded, ExcludedSet::Flag(_))) =>
        {
            ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
                confidence: ConfidenceLevel::A,
            }
        }
        [] => {
            return Ok(Some(ClassifiedExpr {
                confidence: exclusion_confidence(None, &subtract),
                pattern: PatternClass::MembershipExclusion(MembershipExclusion {
                    base: None,
                    subtract,
                }),
            }));
        }
        [one] => crate::classifier::policy_classifier::classify_expr_depth(
            one,
            db,
            registry,
            table,
            command,
            depth + 1,
            state,
        ),
        [first, rest @ ..] => {
            let folded = rest
                .iter()
                .fold(first.clone(), |previous, conjunct| Expr::BinaryOp {
                    left: Box::new(previous),
                    op: BinaryOperator::And,
                    right: Box::new(conjunct.clone()),
                });
            crate::classifier::policy_classifier::classify_expr_depth(
                &folded,
                db,
                registry,
                table,
                command,
                depth + 1,
                state,
            )
        }
    };
    let confidence = exclusion_confidence(Some(&base), &subtract);
    Ok(Some(ClassifiedExpr {
        pattern: PatternClass::MembershipExclusion(MembershipExclusion {
            base: Some(Box::new(base)),
            subtract,
        }),
        confidence,
    }))
}

/// Cheap pre-check for the ordinary path: whether `expr`, flattened through `AND`
/// and parentheses only, carries a conjunct shaped as a negated membership check.
/// Skipped under `see_through_functions`, where a function call may still hide
/// one and the full collection below is the only way to tell.
fn has_exclusion_conjunct(expr: &Expr, depth: u32) -> bool {
    if depth > crate::classifier::policy_classifier::MAX_CLASSIFY_DEPTH {
        return false;
    }
    match expr {
        Expr::Nested(inner) => has_exclusion_conjunct(inner, depth + 1),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => has_exclusion_conjunct(left, depth + 1) || has_exclusion_conjunct(right, depth + 1),
        Expr::Exists { negated: true, .. }
        | Expr::In {
            target: InTarget::Subquery(_),
            negated: true,
            ..
        }
        | Expr::AllOp {
            compare_op: BinaryOperator::NotEq,
            ..
        } => true,
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => matches!(
            unparenthesize(expr),
            Expr::Exists { negated: false, .. }
                | Expr::Function(_)
                | Expr::BinaryOp {
                    op: BinaryOperator::Or,
                    ..
                }
                | Expr::AnyOp {
                    compare_op: BinaryOperator::Eq,
                    ..
                }
                | Expr::In {
                    target: InTarget::Subquery(_),
                    negated: false,
                    ..
                }
        ),
        _ => false,
    }
}

/// Flatten `expr` through `AND` and parentheses, testing each resulting conjunct
/// and sorting it into `positives` or `subtract`.
///
/// Under `see_through_functions`, a conjunct that calls a declared, unregistered
/// `LANGUAGE sql` function is substituted by that call's body before testing,
/// under the same cycle cut and owner-read bookkeeping the ordinary expansion in
/// `classify_expr_inner` uses, so a membership read through a `SECURITY DEFINER`
/// helper gets the identical leniency a function-wrapped positive grant already
/// gets. An `IS TRUE` suffix unwraps the same way, since it changes nothing a
/// plain boolean conjunct would not already mean. `false` only past the
/// classifier's depth bound, where the caller treats the clause as carrying no
/// exclusion rather than guessing at a partial split.
#[expect(
    clippy::too_many_arguments,
    reason = "db, registry, table and state are four separate borrows the recursion threads through"
)]
fn collect_conjuncts<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    depth: u32,
    state: &ExpansionState,
    see_through_functions: bool,
    positives: &mut Vec<Expr>,
    subtract: &mut Vec<ExcludedSet>,
) -> Result<bool, ExclusionError> {
    if depth > crate::classifier::policy_classifier::MAX_CLASSIFY_DEPTH {
        return Ok(false);
    }
    match expr {
        Expr::Nested(inner) => collect_conjuncts(
            inner,
            db,
            registry,
            table,
            depth + 1,
            state,
            see_through_functions,
            positives,
            subtract,
        ),
        Expr::IsTrue(inner) if see_through_functions => collect_conjuncts(
            inner,
            db,
            registry,
            table,
            depth + 1,
            state,
            see_through_functions,
            positives,
            subtract,
        ),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => Ok(collect_conjuncts(
            left,
            db,
            registry,
            table,
            depth + 1,
            state,
            see_through_functions,
            positives,
            subtract,
        )? && collect_conjuncts(
            right,
            db,
            registry,
            table,
            depth + 1,
            state,
            see_through_functions,
            positives,
            subtract,
        )?),
        _ => {
            if see_through_functions {
                // A `STRICT` call over a column that can be `NULL` is `NULL` there, which no
                // split into grants and blocklists keeps, so it classifies whole instead.
                if let Some(expansion::Expansion::Body {
                    identity,
                    reads_bypass_rls,
                    expr: body,
                    ..
                }) = expansion::expand_function_call(expr, db, registry, table, state).filter(
                    |expansion| match expansion {
                        expansion::Expansion::Body {
                            presence_columns, ..
                        } => nullable_column(db, table, presence_columns).is_none(),
                        expansion::Expansion::Refused { .. } => true,
                    },
                ) {
                    state.enter(identity);
                    if reads_bypass_rls {
                        state.enter_owner_read();
                    }
                    let collected = collect_conjuncts(
                        &body,
                        db,
                        registry,
                        table,
                        depth + 1,
                        state,
                        see_through_functions,
                        positives,
                        subtract,
                    );
                    if reads_bypass_rls {
                        state.leave_owner_read();
                    }
                    state.leave();
                    return collected;
                }
            }
            match exclusion_conjunct(expr, db, registry, table, state)? {
                None => positives.push(expr.clone()),
                Some(excluded) => subtract.push(excluded),
            }
            Ok(true)
        }
    }
}

pub(crate) fn table_guarded_by_rls<DB: DatabaseLike>(db: &DB, table: &TableId) -> bool {
    use sql_traits::prelude::TableLike;
    let mut frontier = vec![table.clone()];
    let mut seen: alloc::collections::BTreeSet<TableId> = alloc::collections::BTreeSet::new();
    while let Some(current) = frontier.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        let Some(current) = lookup_table_id(db, &current) else {
            continue;
        };
        if current.has_row_level_security(db) == Ok(true) {
            return true;
        }
        for parent in current
            .inherits_from(db)
            .into_iter()
            .flatten()
            .chain(current.partition_root(db).ok().flatten())
        {
            let identity = table_identity(parent);
            if !seen.contains(&identity) {
                frontier.push(identity);
            }
        }
    }
    false
}

fn exclusion_conjunct<DB: DatabaseLike>(
    conjunct: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Result<Option<ExcludedSet>, ExclusionError> {
    let conjunct = unparenthesize(conjunct);
    if let Some(helper) = recognize_excluded_helper(conjunct, db, registry, table) {
        return excluded_helper(helper?, db, table).map(|helper| Some(ExcludedSet::Helper(helper)));
    }
    let positive = match conjunct {
        Expr::Exists {
            subquery,
            negated: true,
        } => Expr::Exists {
            subquery: subquery.clone(),
            negated: false,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => match unparenthesize(expr) {
            Expr::Exists {
                subquery,
                negated: false,
            } => Expr::Exists {
                subquery: subquery.clone(),
                negated: false,
            },
            other => return excluded_flag(other, db, registry, table, state),
        },
        Expr::In {
            expr: left,
            target: target @ InTarget::Subquery(_),
            negated: true,
            global: false,
        } => {
            if !is_current_user_expr(left, registry) {
                return Ok(None);
            }
            Expr::In {
                expr: left.clone(),
                target: target.clone(),
                negated: false,
                global: false,
            }
        }
        Expr::AllOp {
            left,
            compare_op: BinaryOperator::NotEq,
            right,
        } => match right.as_ref() {
            Expr::Subquery(subquery) if is_current_user_expr(left, registry) => Expr::In {
                expr: left.clone(),
                target: InTarget::Subquery(subquery.clone()),
                negated: false,
                global: false,
            },
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };

    if matches!(positive, Expr::Exists { .. }) {
        if let Some(flag) = excluded_flag(&positive, db, registry, table, state)? {
            return Ok(Some(flag));
        }
    }
    match membership_from_positive(&positive, db, registry, table, state) {
        None => {
            let renamings = renaming_casts(&positive, registry);
            let reason = if renamings.is_empty() {
                diagnose_p4_membership_ambiguity(&positive, db, registry, table, state)
                    .unwrap_or_else(|| {
                        "the blocklist subquery must be a plain correlated caller-identity \
                         membership"
                            .to_string()
                    })
            } else {
                renamings.join(". ")
            };
            Err(ExclusionError::UnsupportedMembership(reason))
        }
        Some(membership) => {
            if table_guarded_by_rls(db, &membership.join_table) {
                return Err(ExclusionError::GuardedTable(membership.join_table));
            }
            if requires_non_null_projection(conjunct)
                && !column_proven_not_null(
                    db,
                    &membership.join_table,
                    membership.user_column.as_str(),
                )
            {
                return Err(ExclusionError::NullableProjection {
                    table: membership.join_table,
                    column: membership.user_column,
                });
            }
            Ok(Some(ExcludedSet::Membership(membership)))
        }
    }
}

/// The rows `positive` flags as a set to subtract, `None` where it tests no flag.
///
/// Refused where a `STRICT` function on the way reads a column that can be `NULL`, since
/// the function is then `NULL`, which `NOT` keeps and the row is hidden, while no tuple
/// flags the row. Beside another flag under `OR` a `NULL` stays `NULL` wherever that flag
/// is false, so every call of a union is held to the same.
fn excluded_flag<DB: DatabaseLike>(
    positive: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Result<Option<ExcludedSet>, ExclusionError> {
    let Some(flag) = classify_flag(positive, db, registry, table, state) else {
        return Ok(None);
    };
    let flag = flag?;
    let mut pending = vec![&flag];
    while let Some(classified) = pending.pop() {
        match &classified.pattern {
            PatternClass::ExpandedFunction(ExpandedFunction {
                presence_columns,
                inner,
                ..
            }) => {
                if let Some(column) = nullable_column(db, table, presence_columns) {
                    return Err(ExclusionError::NullableStrictArgument {
                        table: table.to_string(),
                        column: column.clone(),
                    });
                }
                pending.push(inner);
            }
            PatternClass::P8Composite(Composite { parts, .. }) => pending.extend(parts),
            _ => {}
        }
    }
    Ok(Some(ExcludedSet::Flag(Box::new(flag))))
}

/// The first of `columns` of `table` not declared `NOT NULL`.
fn nullable_column<'c, DB: DatabaseLike>(
    db: &DB,
    table: &str,
    columns: &'c [ColumnName],
) -> Option<&'c ColumnName> {
    let guarded = lookup_table(db, table);
    columns.iter().find(|column| {
        !guarded.is_some_and(|guarded| declared_not_null(db, guarded, column.as_str()))
    })
}

/// The flag `positive` tests, read through the declared functions it calls, the union of
/// the flags an `OR` joins, `None` where it tests none.
fn classify_flag<DB: DatabaseLike>(
    positive: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Option<Result<ClassifiedExpr, ExclusionError>> {
    let positive = unparenthesize(positive);
    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::Or,
        right,
    } = positive
    {
        let left = classify_flag(left, db, registry, table, state)?;
        let right = classify_flag(right, db, registry, table, state)?;
        return Some(left.and_then(|left| right.map(|right| flag_union(vec![left, right]))));
    }
    if let Some(flagged) = recognize_flagged_row(positive, db, table, state) {
        return Some(
            flagged
                .map(|flagged| {
                    crate::classifier::policy_classifier::flagged_row_classified(
                        flagged, db, registry,
                    )
                })
                .map_err(ExclusionError::from),
        );
    }
    if let Some(flagged) = classify_parent_flag(positive, db, registry, table, state) {
        return Some(flagged);
    }
    let Some(expansion::Expansion::Body {
        function,
        identity,
        reads_bypass_rls,
        presence_columns,
        expr: body,
    }) = expansion::expand_function_call(positive, db, registry, table, state)
    else {
        return None;
    };
    let lowered = prepare_clause(&body, registry).ok()?;
    state.enter(identity);
    if reads_bypass_rls {
        state.enter_owner_read();
    }
    let inner = classify_flag(&lowered, db, registry, table, state);
    if reads_bypass_rls {
        state.leave_owner_read();
    }
    state.leave();
    Some(inner?.map(|inner| ClassifiedExpr {
        confidence: inner.confidence,
        pattern: PatternClass::ExpandedFunction(ExpandedFunction {
            function,
            reads_bypass_rls,
            presence_columns,
            inner: Box::new(inner),
        }),
    }))
}

/// The flag a call tests on the parent one edge row names for the guarded row, `None`
/// where `expr` tests none.
///
/// The call is classified against the edge table, as a flag on the edge row, and that flag
/// is climbed to from the guarded row one edge below.
pub(crate) fn classify_parent_flag<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Option<Result<ClassifiedExpr, ExclusionError>> {
    let parent = recognize_parent_flag(expr, db, table)?;
    let edge = parent.edge.to_string();
    let classified = match classify_flag(&parent.call, db, registry, &edge, state)? {
        Ok(classified) => classified,
        Err(refusal) => return Some(Err(refusal)),
    };
    flag_below(classified, &parent, db, registry, state)
}

/// `flag`, the flags a call tests on the edge row, each climbed to from the guarded row one
/// edge below, `None` where it tests anything else.
///
/// The calls the edge row's flags were read through drop out, since inside the `EXISTS` a
/// `NULL` they return keeps the edge row out as `false` does.
fn flag_below<DB: DatabaseLike>(
    flag: ClassifiedExpr,
    parent: &ParentFlag,
    db: &DB,
    registry: &FunctionRegistry,
    state: &ExpansionState,
) -> Option<Result<ClassifiedExpr, ExclusionError>> {
    match flag.pattern {
        PatternClass::P29FlaggedRow(flagged) => Some(
            parent
                .below(flagged, db, state)
                .map(|flagged| {
                    crate::classifier::policy_classifier::flagged_row_classified(
                        flagged, db, registry,
                    )
                })
                .map_err(ExclusionError::from),
        ),
        PatternClass::ExpandedFunction(ExpandedFunction { inner, .. }) => {
            flag_below(*inner, parent, db, registry, state)
        }
        PatternClass::P8Composite(Composite {
            op: BoolOp::Or,
            parts,
        }) => {
            let mut below = Vec::with_capacity(parts.len());
            for part in parts {
                match flag_below(part, parent, db, registry, state)? {
                    Ok(part) => below.push(part),
                    Err(refusal) => return Some(Err(refusal)),
                }
            }
            Some(Ok(flag_union(below)))
        }
        _ => None,
    }
}

/// The rows any of `flags` flags.
fn flag_union(flags: Vec<ClassifiedExpr>) -> ClassifiedExpr {
    ClassifiedExpr {
        confidence: composite_confidence(&flags),
        pattern: PatternClass::P8Composite(Composite {
            op: BoolOp::Or,
            parts: flags,
        }),
    }
}

/// `helper` as a set to subtract, refused where `PostgreSQL` would compare a `NULL`.
///
/// `NOT (x = ANY (s))` is `NULL`, which hides the row, both where `x` is `NULL` and
/// where `s` holds one while not holding `x`. A row without a value in `x` has no tuple
/// naming it, so it would stay visible to every caller, and a `NULL` the helper returns
/// has no tuple either, so it would hide nothing. So every column an arm returns has to
/// be proven `NOT NULL`, a grant arm's object column, the child column of the edges a
/// parent arm or a walk down reads, and the parent column of the edges a walk up reads.
fn excluded_helper<DB: DatabaseLike>(
    helper: DeclaredHelper,
    db: &DB,
    table: &str,
) -> Result<DeclaredHelper, ExclusionError> {
    if !lookup_table(db, table)
        .is_some_and(|guarded| declared_not_null(db, guarded, helper.column.as_str()))
    {
        return Err(ExclusionError::NullableCompared {
            table: table.to_string(),
            column: helper.column,
        });
    }
    for arm in &helper.call.arms {
        let (returned_from, returned) = match arm {
            HelperSetArm::Grant(grant) => (&grant.table, grant.object_columns.as_slice()),
            HelperSetArm::Parent(parent) => (
                &parent.edges.table,
                core::slice::from_ref(&parent.edges.child_column),
            ),
            HelperSetArm::Walk(walk) => (
                &walk.edges.table,
                core::slice::from_ref(walk.returned_column()),
            ),
        };
        for returned in returned {
            if !column_proven_not_null(db, returned_from, returned.as_str()) {
                return Err(ExclusionError::NullableProjection {
                    table: returned_from.clone(),
                    column: returned.clone(),
                });
            }
        }
    }
    Ok(helper)
}

/// Accept only `P4`, excluding caller-set and parent-inheritance patterns.
fn membership_from_positive<DB: DatabaseLike>(
    positive: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
    state: &ExpansionState,
) -> Option<ExistsMembership> {
    let classified = match positive {
        Expr::Exists { .. } => recognize_p4(positive, db, registry, table, state),
        _ => recognize_p4_in_subquery(positive, db, registry, table, PolicyCommand::Select, state),
    }?;
    match classified.pattern {
        PatternClass::P4ExistsMembership(membership) => Some(membership),
        _ => None,
    }
}

/// `NOT IN` and `<> ALL` deny every caller when a row projects `NULL`.
fn requires_non_null_projection(conjunct: &Expr) -> bool {
    matches!(
        unparenthesize(conjunct),
        Expr::In {
            target: InTarget::Subquery(_),
            negated: true,
            ..
        } | Expr::AllOp {
            compare_op: BinaryOperator::NotEq,
            ..
        }
    )
}

fn column_proven_not_null<DB: DatabaseLike>(db: &DB, table: &TableId, column: &str) -> bool {
    lookup_table_id(db, table).is_some_and(|table| declared_not_null(db, table, column))
}

fn declared_not_null<DB: DatabaseLike>(db: &DB, table: &DB::Table, column: &str) -> bool {
    use sql_traits::prelude::{ColumnLike, TableLike};
    table
        .columns(db)
        .into_iter()
        .flatten()
        .find(|declared| declared.stored_column_name() == column)
        .is_some_and(|declared| declared.is_nullable(db) == Ok(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use crate::parser::sql_parser::parse_schema;
    use crate::test_support::caller;

    const TABLES: &str = "
CREATE TABLE docs(id TEXT PRIMARY KEY, owner TEXT NOT NULL);
CREATE TABLE blocks(doc TEXT NOT NULL REFERENCES docs(id), user_id TEXT NOT NULL,
                    PRIMARY KEY(doc, user_id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

    fn registry() -> FunctionRegistry {
        crate::test_support::registry([caller("app.user_id")])
    }

    /// `GLOBAL IN` is `ClickHouse` syntax that `PostgreSqlDialect` never parses, so the only
    /// way it reaches this matcher is a hand-built AST, and the field has to be read, not
    /// wildcarded away.
    #[test]
    fn a_global_not_in_subquery_is_not_read_as_a_blocklist() {
        let db = parse_schema(TABLES).expect("schema parses");
        let registry = registry();
        let expr = parse_expr(
            "current_setting('app.user_id', true) NOT IN (
                 SELECT b.user_id FROM blocks b WHERE b.doc = docs.id
             )",
        );
        let ordinary = try_membership_exclusion(
            &expr,
            &db,
            &registry,
            "docs",
            PolicyCommand::Select,
            0,
            &ExpansionState::new(),
            true,
        )
        .expect("classification should not error");
        assert!(
            ordinary.is_some(),
            "sanity: the ordinary NOT IN subquery is read as a blocklist"
        );

        let Expr::In {
            expr: tested,
            target: target @ InTarget::Subquery(_),
            negated,
            ..
        } = &expr
        else {
            panic!("expected an IN subquery");
        };
        let global = Expr::In {
            expr: tested.clone(),
            target: target.clone(),
            negated: *negated,
            global: true,
        };
        let refused = try_membership_exclusion(
            &global,
            &db,
            &registry,
            "docs",
            PolicyCommand::Select,
            0,
            &ExpansionState::new(),
            true,
        )
        .expect("classification should not error");
        assert!(
            refused.is_none(),
            "a GLOBAL IN subquery must not be read as a blocklist exclusion"
        );
    }
}
