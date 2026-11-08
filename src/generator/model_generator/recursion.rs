//! Which statements `PostgreSQL` refuses to plan because the policies loop.
//!
//! Reading a table expands the `USING` clauses of its `SELECT` and `ALL` policies, and
//! every table those read expands its own, so one loop anywhere in that closure raises
//! `infinite recursion` on every read that reaches it. A clause reading such a table
//! cannot be planned either, whatever command it guards.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};

use sqlparser::ast::Expr;

use super::actions::{
    policy_uses_using_for_missing_with_check, using_targets, with_check_targets, ActionTarget,
};
use super::TableTypes;
use crate::classifier::patterns::{check_shape, policy_command, using_shape, PolicyCommand};
use crate::parser::expr::reads_relation;
use crate::parser::names::resolve_table_id;
use crate::parser::sql_parser::{DatabaseLike, PolicyLike};

/// Loops in the policy read graph, and what each one denies.
///
/// Built from the schema's declared policies rather than the classified ones, since
/// confidence filtering cannot change what the database does: a leg of the loop dropped
/// for low confidence still makes every read raise.
pub(super) struct PolicyReadRecursion {
    /// Loops, each as the tables it runs through in order. Indexed into by the maps below
    /// so a loop reached from many tables is stored once.
    loops: Vec<Vec<String>>,
    /// Table type whose reads raise, and the loop they run into.
    unreadable: BTreeMap<String, usize>,
    /// Table type, then the targets whose clauses read an unreadable table.
    blocked: BTreeMap<String, BTreeMap<ActionTarget, usize>>,
}

impl PolicyReadRecursion {
    pub(super) fn detect<DB: DatabaseLike>(db: &DB, table_types: &TableTypes) -> Self {
        // The resolution walks every table, and one table's policies repeat its name.
        let mut types: BTreeMap<String, Option<String>> = BTreeMap::new();
        let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for policy in db.policies() {
            if !matches!(
                policy_command(policy.command()),
                PolicyCommand::Select | PolicyCommand::All
            ) {
                continue;
            }
            let Some(using) = using_shape(policy, db) else {
                continue;
            };
            let source_name = policy.target_table_name().to_string();
            let Some(source) = resolve(db, table_types, &mut types, &source_name) else {
                continue;
            };
            let mut read = BTreeSet::new();
            reads_relation(using, |name| {
                if let Some(target) = resolve(db, table_types, &mut types, name) {
                    read.insert(target);
                }
                false
            });
            edges.entry(source).or_default().extend(read);
        }

        // Deduplicated while collecting, then positional so the walk below indexes it.
        let edges: BTreeMap<String, Vec<String>> = edges
            .into_iter()
            .map(|(source, read)| (source, read.into_iter().collect()))
            .collect();
        let (loops, unreadable) = loops_reachable_from(&edges, table_types);

        let mut blocked: BTreeMap<String, BTreeMap<ActionTarget, usize>> = BTreeMap::new();
        for policy in db.policies() {
            let table_name = policy.target_table_name().to_string();
            let Some(table) = resolve(db, table_types, &mut types, &table_name) else {
                continue;
            };
            for (clause, targets) in declared_clause_targets(policy, db) {
                let Some(clause) = clause else { continue };
                let mut hit = None;
                reads_relation(clause, |name| {
                    let found = resolve(db, table_types, &mut types, name)
                        .and_then(|read| unreadable.get(&read).copied());
                    hit = found;
                    found.is_some()
                });
                let Some(index) = hit else { continue };
                let entry = blocked.entry(table.clone()).or_default();
                for target in targets {
                    entry.insert(target, index);
                }
            }
        }

        Self {
            loops,
            unreadable,
            blocked,
        }
    }

    /// Targets of one table whose clauses cannot be planned, each with the loop it runs
    /// into. `Select` is present whenever the table's own reads raise, so a policy the
    /// confidence threshold dropped cannot hide the loop.
    pub(super) fn blocked_targets(&self, type_name: &str) -> BTreeMap<ActionTarget, &[String]> {
        let mut targets: BTreeMap<ActionTarget, &[String]> = BTreeMap::new();
        for (target, index) in self.blocked.get(type_name).into_iter().flatten() {
            if let Some(cycle) = self.loops.get(*index) {
                targets.insert(*target, cycle.as_slice());
            }
        }
        if let Some(cycle) = self
            .unreadable
            .get(type_name)
            .and_then(|index| self.loops.get(*index))
        {
            targets.insert(ActionTarget::Select, cycle.as_slice());
        }
        targets
    }
}

/// Each stored clause of a declared policy with the targets it feeds, which is the
/// routing `for_each_policy_target_expr` performs on the classified one. A command whose
/// `WITH CHECK` is absent is checked by the `USING` expression, so that clause reaches
/// those targets too.
pub(super) fn declared_clause_targets<'p, P: PolicyLike>(
    policy: &'p P,
    db: &'p P::DB,
) -> [(Option<&'p Expr>, Vec<ActionTarget>); 2] {
    let command = policy_command(policy.command());
    let check = check_shape(policy, db);
    let mut using = using_targets(command);
    if check.is_none() && policy_uses_using_for_missing_with_check(command) {
        using.extend(with_check_targets(command));
    }
    [
        (using_shape(policy, db), using),
        (check, with_check_targets(command)),
    ]
}

/// Type of the table a name resolves to, or `None` when the schema cannot resolve it or
/// row level security is off, in which case reading it expands nothing.
fn resolve<DB: DatabaseLike>(
    db: &DB,
    table_types: &TableTypes,
    memo: &mut BTreeMap<String, Option<String>>,
    name: &str,
) -> Option<String> {
    if let Some(known) = memo.get(name) {
        return known.clone();
    }
    let resolved = resolve_table_id(db, name)
        .and_then(|table| table_types.get(&table))
        .map(ToString::to_string);
    memo.insert(name.to_string(), resolved.clone());
    resolved
}

/// For every node from which a loop is reachable, one loop it reaches. Reachability
/// rather than membership: reading a table that reads a loop raises too.
fn loops_reachable_from(
    edges: &BTreeMap<String, Vec<String>>,
    table_types: &TableTypes,
) -> (Vec<Vec<String>>, BTreeMap<String, usize>) {
    let mut loops: Vec<Vec<String>> = Vec::new();
    let mut reached: BTreeMap<&str, Option<usize>> = BTreeMap::new();
    let mut on_path: Vec<&str> = Vec::new();

    for start in edges.keys() {
        if reached.contains_key(start.as_str()) {
            continue;
        }
        // Each frame is a node, how many of its edges are walked, and the loop found
        // below it. An explicit stack, since a chain of tables can be arbitrarily long.
        let mut stack: Vec<(&str, usize, Option<usize>)> = vec![(start.as_str(), 0, None)];
        on_path.push(start.as_str());
        while let Some(frame) = stack.last_mut() {
            let next = edges
                .get(frame.0)
                .and_then(|children| children.get(frame.1));
            if let Some(child) = next {
                frame.1 += 1;
                let child = child.as_str();
                if let Some(at) = on_path.iter().position(|node| *node == child) {
                    // An edge into the path we are on closes a loop, and the path from
                    // there to here is that loop.
                    let index = loops.len();
                    loops.push(
                        on_path
                            .get(at..)
                            .unwrap_or_default()
                            .iter()
                            .map(|node| table_types.spelling_of(node))
                            .collect(),
                    );
                    frame.2 = frame.2.or(Some(index));
                } else if let Some(below) = reached.get(child).copied().flatten() {
                    frame.2 = frame.2.or(Some(below));
                } else if !reached.contains_key(child) {
                    on_path.push(child);
                    stack.push((child, 0, None));
                }
            } else {
                let Some((node, _, found)) = stack.pop() else {
                    break;
                };
                on_path.pop();
                reached.insert(node, found);
                if let Some(parent) = stack.last_mut() {
                    parent.2 = parent.2.or(found);
                }
            }
        }
    }

    let unreadable = reached
        .into_iter()
        .filter_map(|(node, found)| found.map(|index| (node.to_string(), index)))
        .collect();
    (loops, unreadable)
}
