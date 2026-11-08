//! How much of a table's rows a querying caller may read, from its policies alone.
//!
//! The classifier asks this to know which relations a precomputed residual may read, and the
//! generator asks it to intersect a membership with the table's read constraints. One walk,
//! one answer, so the two cannot drift apart.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    derive_policy_mode, derive_scoped_roles, policy_covers_reads, PatternClass, PolicyCommand,
    PolicyMode,
};
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
    /// Row security is off, or every read is open.
    Open,
    /// Every read is gated by request values only.
    RequestGated { gates: Vec<ReadGate> },
    /// Reads depend on the caller's role.
    Guarded { roles: Vec<String> },
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
    let rls = table.has_row_level_security(db);
    if rls == Ok(false) {
        return TableReadability::Open;
    }
    let identity = table_identity(table);
    state
        .deciding_readability(&identity, || {
            walk_policies(table, &identity, rls == Ok(true), db, registry, state)
        })
        .unwrap_or(TableReadability::Guarded { roles: Vec::new() })
}

fn walk_policies<DB: DatabaseLike>(
    table: &DB::Table,
    identity: &TableId,
    rls_on: bool,
    db: &DB,
    registry: &FunctionRegistry,
    state: &ExpansionState,
) -> TableReadability {
    let mut roles = BTreeSet::new();
    let mut grants_read = false;
    let mut grants_read_unscoped = false;
    let mut row_independent = rls_on;
    let mut gates = Vec::new();
    for policy in table.policies(db).into_iter().flatten() {
        if !policy_covers_reads(policy) {
            continue;
        }
        // A clause whose literal cannot be read proves nothing either way, like an absent one.
        let Ok(Some(using)) = policy.using_expression(db) else {
            row_independent = false;
            continue;
        };
        let admits_nothing = is_constantly_false(using);

        if derive_policy_mode(policy) == PolicyMode::Restrictive {
            if admits_nothing && policy.applies_to_public() {
                return TableReadability::Unreadable;
            }
            if !policy.applies_to_public() {
                row_independent = false;
            } else if row_independent && constant_bool_value(using) != Some(true) {
                let pattern = classify_expr_in_state(
                    using,
                    db,
                    registry,
                    &identity.to_string(),
                    PolicyCommand::Select,
                    state,
                )
                .pattern;
                if is_request_only_gate(&pattern) {
                    gates.push(ReadGate {
                        policy_name: format!("{identity}_{}", policy.name()),
                        pattern,
                    });
                } else {
                    row_independent = false;
                }
            }
            continue;
        }
        row_independent &= policy.applies_to_public() && constant_bool_value(using) == Some(true);
        if admits_nothing {
            continue;
        }

        grants_read = true;
        let scoped = derive_scoped_roles(policy, db);
        if scoped.is_empty() {
            grants_read_unscoped = true;
        } else {
            roles.extend(scoped);
        }
    }

    if !grants_read {
        TableReadability::Unreadable
    } else if row_independent {
        if gates.is_empty() {
            TableReadability::Open
        } else {
            TableReadability::RequestGated { gates }
        }
    } else {
        TableReadability::Guarded {
            roles: if grants_read_unscoped {
                Vec::new()
            } else {
                roles.into_iter().collect()
            },
        }
    }
}

/// Only these patterns can be moved without reading a membership row.
pub(crate) fn is_request_only_gate(pattern: &PatternClass) -> bool {
    match pattern {
        PatternClass::P10ConstantBool(_)
        | PatternClass::P16ConstantInCallerSet(_)
        | PatternClass::P17CallerScalarEqualsConstant(_) => true,
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
