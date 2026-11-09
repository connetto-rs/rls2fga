//! How much of a table's rows a querying caller may read, from its policies alone.
//!
//! The classifier asks this to know which relations a precomputed residual may read, and the
//! generator asks it to intersect a membership with the table's read constraints. One walk,
//! one answer, so the two cannot drift apart. The answer is for the acting role the registry
//! classifies for, since which policies reach a read is decided per role.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use sql_traits::structs::{GateTerm, PolicyExpression, RowSecurity, RowStatement};
use sqlparser::ast::Expr;

use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{PatternClass, PolicyCommand};
use crate::classifier::policy_classifier::classify_expr_in_state;
use crate::classifier::recognizers::{constant_bool_value, is_constantly_false};
use crate::parser::names::{lookup_table_id, table_identity};
use crate::parser::sql_parser::{DatabaseLike, PolicyLike, TableLike};
use crate::types::TableId;

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
    /// Which rows the role reads depends on the rows themselves.
    Guarded,
    /// No row is visible.
    Unreadable,
}

/// The read determination for `table`, the shared policy walk behind both the classifier's
/// residual check and the generator's membership scope.
///
/// A policy of `table` can hold a residual whose check asks for this very answer, so a walk
/// reached from inside its own walk answers [`TableReadability::Guarded`], having proven
/// nothing row independent.
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
        .unwrap_or(TableReadability::Guarded)
}

/// The read `PostgreSQL` applies to the acting role `registry` classifies for.
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
        return TableReadability::Guarded;
    };
    let gates = match table.row_security(RowStatement::Select, role, db) {
        Ok(RowSecurity::Exempt(_)) => return TableReadability::Open,
        Ok(RowSecurity::Gated(gates)) => gates,
        // A read PostgreSQL raises on, or one sql-traits cannot settle, shows no row.
        Ok(RowSecurity::InfiniteRecursion { .. }) | Err(_) => return TableReadability::Unreadable,
    };
    let mut readability = TableReadability::Open;
    for gate in &gates {
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
            readability = TableReadability::Guarded;
            continue;
        }
        for (term, using) in restrictive {
            if constant_bool_value(using) == Some(true) {
                continue;
            }
            let pattern = classify_expr_in_state(
                using,
                db,
                registry,
                &identity.to_string(),
                PolicyCommand::Select,
                state,
            )
            .pattern;
            if !is_request_only_gate(&pattern) {
                readability = TableReadability::Guarded;
                continue;
            }
            let gate = ReadGate {
                policy_name: format!("{identity}_{}", term.policy().name()),
                pattern,
            };
            match &mut readability {
                TableReadability::Open => {
                    readability = TableReadability::RequestGated { gates: vec![gate] };
                }
                TableReadability::RequestGated { gates } => gates.push(gate),
                TableReadability::Guarded | TableReadability::Unreadable => {}
            }
        }
    }
    readability
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
        | PatternClass::P22CallerScalarInConstantList(_) => true,
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
