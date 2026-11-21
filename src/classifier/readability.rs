//! How much of a table's rows a querying caller may read, from its policies alone.
//!
//! The classifier asks this to know which relations a precomputed residual may read, and the
//! generator asks it to intersect a membership with the table's read constraints. One walk,
//! one answer, so the two cannot drift apart. The answer is for the acting role the registry
//! classifies for, since which policies reach a read is decided per role. A membership check
//! then reads a guarded table through [`TableReadability::read_by`], since a row test its own
//! conditions imply hides no row it could match.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::borrow::Cow;

use sql_traits::structs::{GateTerm, PolicyExpression, RowSecurity, RowStatement};
use sqlparser::ast::Expr;

use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    AttributeCondition, AttributeOperator, AttributePredicate, AttributeTest, BoolOp, BooleanFlag,
    ColumnName, Composite, DirectOwnership, ExistsMembership, PatternClass, PolicyCommand,
    ResidualGuard, ResidualPredicates,
};
use crate::classifier::policy_classifier::classify_expr_in_state;
use crate::classifier::recognizers::{constant_bool_value, is_constantly_false};
use crate::parser::names::{lookup_table_id, table_identity};
use crate::parser::sql_parser::{DatabaseLike, PolicyLike, TableLike};
use crate::types::{AttributeLiteral, TableId};

/// One request-only gate a table's restrictive policies impose.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReadGate {
    /// The gate's spelling, named after the table and the policy that states it.
    pub policy_name: String,
    /// The pattern the gate is classified as.
    pub pattern: PatternClass,
}

/// How much of a table's rows a querying caller may read.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TableReadability {
    /// Row security is off for the role, or every read is open.
    Open,
    /// Every read is gated by request values only.
    RequestGated { gates: Vec<ReadGate> },
    /// Which rows the role reads depends on the rows themselves. A row is read when it
    /// passes every test in `rows` and the request passes every gate in `gates`.
    Guarded {
        gates: Vec<ReadGate>,
        rows: Vec<RowTest>,
    },
    /// No row is visible.
    Unreadable,
}

/// One row-dependent test a guarded table's policies impose.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RowTest {
    /// The row passes when one of these clauses holds of it.
    AnyOf(Vec<PatternClass>),
    /// A test the walk could not read, for an unset acting role or for a table whose
    /// policies read it again from inside their own walk.
    Unsettled,
}

/// What a membership check requires of every row it reads from its table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MembershipRead<'a> {
    /// The column the check compares with the caller, absent where it compares none.
    pub caller_column: Option<&'a ColumnName>,
    /// The check's further conjuncts on the row.
    pub residual: &'a ResidualPredicates,
}

impl<'a> MembershipRead<'a> {
    /// The check of `membership`, whose member column holds the caller.
    pub(crate) fn of_caller(membership: &'a ExistsMembership) -> Self {
        Self {
            caller_column: Some(&membership.user_column),
            residual: &membership.extra_predicates,
        }
    }

    /// Whether every row this check matches satisfies `pattern`, read for the caller on
    /// the same column, literal tests the check states, and `AND` or `OR` of those.
    fn implies(self, pattern: &PatternClass) -> bool {
        match pattern {
            PatternClass::P3DirectOwnership(DirectOwnership { column }) => {
                self.caller_column == Some(column)
            }
            PatternClass::P6BooleanFlag(BooleanFlag { column, .. }) => self.requires_true(column),
            PatternClass::P9AttributeCondition(AttributeCondition {
                predicate: Some(predicate),
                request_predicate: None,
                ..
            }) => self.requires(predicate),
            PatternClass::P8Composite(Composite { op, parts }) => {
                let mut implied = parts.iter().map(|part| self.implies(&part.pattern));
                match op {
                    BoolOp::And => implied.all(|holds| holds),
                    BoolOp::Or => implied.any(|holds| holds),
                }
            }
            _ => false,
        }
    }

    /// Whether one of the check's conjuncts states `predicate`.
    fn requires(self, predicate: &AttributePredicate) -> bool {
        self.residual.row_guard_refs().any(|guard| match guard {
            ResidualGuard::Compare(required) => required == predicate,
            ResidualGuard::IsTrue(column) => states_true(predicate, column),
            ResidualGuard::NotNull(column) => {
                predicate.column == *column && matches!(predicate.test, AttributeTest::IsNotNull)
            }
        })
    }

    /// Whether one of the check's conjuncts requires `column` to be true.
    fn requires_true(self, column: &ColumnName) -> bool {
        self.residual.row_guard_refs().any(|guard| match guard {
            ResidualGuard::IsTrue(required) => required == column,
            ResidualGuard::Compare(predicate) => states_true(predicate, column),
            ResidualGuard::NotNull(_) => false,
        })
    }
}

/// Whether `predicate` is `column = TRUE`, the test a bare boolean column states.
fn states_true(predicate: &AttributePredicate, column: &ColumnName) -> bool {
    predicate.column == *column
        && matches!(
            predicate.test,
            AttributeTest::Compare {
                operator: AttributeOperator::Eq,
                value: AttributeLiteral::Boolean(true),
            }
        )
}

impl RowTest {
    /// Whether every row `check` matches passes this test.
    fn implied_by(&self, check: MembershipRead<'_>) -> bool {
        match self {
            Self::AnyOf(clauses) => clauses.iter().any(|clause| check.implies(clause)),
            Self::Unsettled => false,
        }
    }
}

impl TableReadability {
    /// A guarded read whose rows the walk could not test.
    fn unsettled() -> Self {
        Self::Guarded {
            gates: Vec::new(),
            rows: vec![RowTest::Unsettled],
        }
    }

    /// The read `check` makes of the table. Every row it matches passes a row test the
    /// check implies, so a guarded table whose every row test it implies reads as its
    /// request gates alone.
    pub(crate) fn read_by(&self, check: MembershipRead<'_>) -> Cow<'_, Self> {
        match self {
            Self::Guarded { gates, rows } if rows.iter().all(|row| row.implied_by(check)) => {
                Cow::Owned(if gates.is_empty() {
                    Self::Open
                } else {
                    Self::RequestGated {
                        gates: gates.clone(),
                    }
                })
            }
            _ => Cow::Borrowed(self),
        }
    }
}

/// The read determination for `table`, for the acting role `registry` classifies.
///
/// A policy of `table` can hold a residual whose check asks for this very answer, so a walk
/// reached from inside its own walk answers [`RowTest::Unsettled`], having proven nothing
/// row independent.
pub(crate) fn table_readability<DB: DatabaseLike>(
    table: &TableId,
    db: &DB,
    registry: &FunctionRegistry,
    state: &ExpansionState,
) -> TableReadability {
    let Some(table) = lookup_table_id(db, table) else {
        return TableReadability::Open;
    };
    if table.has_row_level_security(db) == Ok(false) {
        return TableReadability::Open;
    }
    let identity = table_identity(table);
    state
        .deciding_readability(&identity, || {
            walk_policies(table, &identity, db, registry, state)
        })
        .unwrap_or_else(TableReadability::unsettled)
}

/// The read `PostgreSQL` applies to the role, unsettled where the role is unset.
///
/// A role no policy reaches reads nothing, a role row security exempts reads everything, and
/// a read that raises or that sql-traits cannot settle for the role shows nothing.
fn walk_policies<DB: DatabaseLike>(
    table: &DB::Table,
    identity: &TableId,
    db: &DB,
    registry: &FunctionRegistry,
    state: &ExpansionState,
) -> TableReadability {
    let Some(role) = registry
        .classified_acting_role()
        .and_then(|name| db.role(name))
    else {
        return TableReadability::unsettled();
    };
    let row_gates = match table.row_security(RowStatement::Select, role, db) {
        Ok(RowSecurity::Exempt(_)) => return TableReadability::Open,
        Ok(RowSecurity::Gated(gates)) => gates,
        // A read PostgreSQL raises on, or one sql-traits cannot settle, shows no row.
        Ok(RowSecurity::InfiniteRecursion { .. }) | Err(_) => return TableReadability::Unreadable,
    };
    let table_name = identity.to_string();
    let classify = |using: &Expr| {
        classify_expr_in_state(
            using,
            db,
            registry,
            &table_name,
            PolicyCommand::Select,
            state,
        )
        .pattern
    };
    let mut gates = Vec::new();
    let mut rows = Vec::new();
    for gate in &row_gates {
        // A permissive clause of unknown value grants nothing.
        let permissive: Vec<&Expr> = gate.permissive().iter().filter_map(stored_clause).collect();
        // A barrier of unknown value may admit nothing, so it hides every row.
        let Some(restrictive) = gate
            .restrictive()
            .iter()
            .map(|term| stored_clause(term).map(|using| (term, using)))
            .collect::<Option<Vec<_>>>()
        else {
            return TableReadability::Unreadable;
        };
        if permissive.iter().all(|using| is_constantly_false(using))
            || restrictive
                .iter()
                .any(|(_, using)| is_constantly_false(using))
        {
            return TableReadability::Unreadable;
        }
        if !permissive
            .iter()
            .any(|using| constant_bool_value(using) == Some(true))
        {
            rows.push(RowTest::AnyOf(
                permissive.into_iter().map(classify).collect(),
            ));
        }
        for (term, using) in restrictive {
            if constant_bool_value(using) == Some(true) {
                continue;
            }
            let pattern = classify(using);
            if is_request_only_gate(&pattern) {
                gates.push(ReadGate {
                    policy_name: format!("{identity}_{}", term.policy().name()),
                    pattern,
                });
            } else {
                rows.push(RowTest::AnyOf(vec![pattern]));
            }
        }
    }
    match (rows.is_empty(), gates.is_empty()) {
        (false, _) => TableReadability::Guarded { gates, rows },
        (true, true) => TableReadability::Open,
        (true, false) => TableReadability::RequestGated { gates },
    }
}

/// The clause of `term` with the values `PostgreSQL` stored, or `None` when one of its
/// literals cannot be read here.
fn stored_clause<'db, P>(term: &GateTerm<'db, P>) -> Option<&'db Expr> {
    match term.expression() {
        PolicyExpression::Stored(expression) => Some(expression),
        PolicyExpression::Written { .. } => None,
    }
}

/// Only these patterns can be moved without reading a membership row.
pub(crate) fn is_request_only_gate(pattern: &PatternClass) -> bool {
    match pattern {
        PatternClass::P10ConstantBool(_)
        | PatternClass::P16ConstantInCallerSet(_)
        | PatternClass::P17CallerScalarEqualsConstant(_)
        | PatternClass::P21CallerScalarUnequalsConstant(_)
        | PatternClass::P22CallerScalarInConstantList(_)
        | PatternClass::P23FallbackScalarEqualsConstant(_)
        | PatternClass::P24FallbackScalarUnequalsConstant(_)
        | PatternClass::P25FallbackScalarInConstantList(_) => true,
        PatternClass::P8Composite(composite) => composite
            .parts
            .iter()
            .all(|part| is_request_only_gate(&part.pattern)),
        PatternClass::ExpandedFunction(expanded) => {
            expanded.presence_columns.is_empty() && is_request_only_gate(&expanded.inner.pattern)
        }
        _ => false,
    }
}
