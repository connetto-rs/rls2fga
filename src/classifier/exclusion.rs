//! Correlated blocklist subtraction from positive grants.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::classifier::expansion::{self, ExpansionState};
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    exclusion_confidence, ClassifiedExpr, ExistsMembership, MembershipExclusion, PatternClass,
    PolicyCommand,
};
use crate::classifier::recognizers::{
    diagnose_p4_membership_ambiguity, is_current_user_expr, recognize_p4, recognize_p4_in_subquery,
    renaming_casts, unparenthesize,
};
use crate::parser::names::{lookup_table_id, table_identity};
use crate::parser::sql_parser::DatabaseLike;
use crate::types::{ColumnName, TableId};
use sqlparser::ast::{BinaryOperator, Expr, InTarget, UnaryOperator};

/// Why a correlated blocklist cannot be represented exactly.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExclusionError {
    #[error("{0}")]
    UnsupportedMembership(String),
    #[error("the blocklist table '{0}' has row level security")]
    GuardedTable(TableId),
    #[error("the blocklist projection '{table}.{column}' must be provably non-null")]
    NullableProjection { table: TableId, column: ColumnName },
}

/// Split a clause into its positive grant and correlated blocklists.
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
    let mut subtract: Vec<ExistsMembership> = Vec::new();
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
        [] => {
            return Ok(Some(ClassifiedExpr {
                pattern: PatternClass::MembershipExclusion(MembershipExclusion {
                    base: None,
                    subtract,
                }),
                confidence: exclusion_confidence(None),
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
    let confidence = exclusion_confidence(Some(&base));
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
        } => {
            matches!(unparenthesize(expr), Expr::Exists { negated: false, .. })
        }
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
    subtract: &mut Vec<ExistsMembership>,
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
                if let Some(expansion::Expansion::Body {
                    identity,
                    reads_bypass_rls,
                    expr: body,
                    ..
                }) = expansion::expand_function_call(expr, db, registry, table, state)
                {
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
                Some(membership) => subtract.push(membership),
            }
            Ok(true)
        }
    }
}

fn table_guarded_by_rls<DB: DatabaseLike>(db: &DB, table: &TableId) -> bool {
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
) -> Result<Option<ExistsMembership>, ExclusionError> {
    let positive = match unparenthesize(conjunct) {
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
            _ => return Ok(None),
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
            Ok(Some(membership))
        }
    }
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
    use sql_traits::prelude::{ColumnLike, TableLike};
    let Some(table) = lookup_table_id(db, table) else {
        return false;
    };
    let Some(column_ref) = table
        .columns(db)
        .into_iter()
        .flatten()
        .find(|declared| declared.stored_column_name() == column)
    else {
        return false;
    };
    column_ref.is_nullable(db) == Ok(false)
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
