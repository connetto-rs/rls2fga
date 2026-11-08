//! Which tables each policy's clauses read.
//!
//! What the database reads when it evaluates the clauses, whatever the model enforces. A
//! clause the classifier left alone runs all the same, and so does every function body it
//! calls. The report feeds a refusal, so a read the schema cannot name is reported as such
//! rather than left out.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::ops::ControlFlow;

use sqlparser::ast::{Expr, Query, Visit, Visitor};

use crate::classifier::patterns::ClassifiedPolicy;
use crate::parser::names::{lookup_table_id, stored_identifier, table_identity};
use crate::parser::sql_parser::{
    DataStatementLike, DatabaseLike, FunctionLike, IdentifierCase, PolicyLike, TableLike,
};
use crate::types::{PolicyReads, TableId};

/// One entry per translated policy whose table the catalog places, ordered by table and
/// then name.
///
/// A policy the catalog does not declare, or whose table it cannot place, has no entry,
/// since nothing a consumer compares against names its table.
pub(crate) fn policy_reads<DB: DatabaseLike>(
    policies: &[ClassifiedPolicy],
    db: &DB,
) -> Vec<PolicyReads> {
    let mut declared: BTreeMap<TableId, BTreeMap<&str, &DB::Policy>> = BTreeMap::new();
    for policy in db.policies() {
        if let Ok(Some(table)) =
            db.resolve_target_table(policy.target_table_name(), IdentifierCase::AsWritten)
        {
            declared
                .entry(table_identity(table))
                .or_default()
                .insert(policy.name(), policy);
        }
    }
    let mut entries: Vec<PolicyReads> = policies
        .iter()
        .filter_map(|classified| {
            let table = classified.resolved_table()?;
            let policy = declared.get(table)?.get(classified.name())?;
            let guarded = lookup_table_id(db, table)?;
            Some(read_set(classified, guarded, *policy, db))
        })
        .collect();
    entries.sort_by(|left, right| (&left.table, &left.name).cmp(&(&right.table, &right.name)));
    entries
}

fn read_set<'db, DB: DatabaseLike>(
    classified: &ClassifiedPolicy,
    guarded: &'db DB::Table,
    policy: &'db DB::Policy,
    db: &'db DB,
) -> PolicyReads {
    let mut reads = Reads {
        db,
        tables: BTreeSet::new(),
        unresolved: Vec::new(),
    };
    reads.through(guarded);
    for clause in [policy.using_clause(db), policy.check_clause(db)] {
        match clause {
            Ok(Some(clause)) => reads.subqueries(clause.expression()),
            Ok(None) => {}
            Err(error) => reads.unresolved(error.to_string()),
        }
    }
    let mut called = Vec::new();
    match policy.using_functions(db) {
        Ok(functions) => called.extend(functions),
        Err(error) => reads.unresolved(error.to_string()),
    }
    match policy.check_functions(db) {
        Ok(functions) => called.extend(functions),
        Err(error) => reads.unresolved(error.to_string()),
    }
    reads.bodies(called);
    PolicyReads {
        name: classified.name().to_string(),
        table: table_identity(guarded),
        command: classified.command(),
        reads: reads.tables.into_iter().collect(),
        unresolved: reads.unresolved,
    }
}

struct Reads<'db, DB: DatabaseLike> {
    db: &'db DB,
    tables: BTreeSet<TableId>,
    unresolved: Vec<String>,
}

impl<'db, DB: DatabaseLike> Reads<'db, DB> {
    fn unresolved(&mut self, reason: String) {
        if !self.unresolved.contains(&reason) {
            self.unresolved.push(reason);
        }
    }

    /// `table` as a statement naming it without `ONLY` reads it, with every partition and
    /// `INHERITS` child below it and without a foreign table, which holds no rows of its own.
    fn through(&mut self, table: &'db DB::Table) {
        let mut seen: Vec<&'db DB::Table> = Vec::new();
        let mut pending = vec![table];
        while let Some(table) = pending.pop() {
            // Termination only. `PostgreSQL` allows no cycle here, and a catalog claiming
            // one must not spin.
            if seen.iter().any(|held| core::ptr::eq(*held, table)) {
                continue;
            }
            seen.push(table);
            match table.is_foreign(self.db) {
                Ok(false) => {
                    self.tables.insert(table_identity(table));
                }
                Ok(true) => {}
                Err(error) => self.unresolved(error.to_string()),
            }
            match (table.partitions(self.db), table.inheritors(self.db)) {
                (Ok(partitions), Ok(inheritors)) => pending.extend(partitions.chain(inheritors)),
                (Err(error), _) | (_, Err(error)) => self.unresolved(error.to_string()),
            }
        }
    }

    /// The tables every subquery of `clause` reads, each outermost one asked once since its
    /// answer covers the subqueries nested in it.
    fn subqueries(&mut self, clause: &Expr) {
        struct Outermost<'r, 'db, DB: DatabaseLike> {
            reads: &'r mut Reads<'db, DB>,
            depth: usize,
        }

        impl<DB: DatabaseLike> Visitor for Outermost<'_, '_, DB> {
            type Break = ();

            fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
                if self.depth == 0 {
                    match query.referenced_tables(self.reads.db) {
                        Ok(tables) => self
                            .reads
                            .tables
                            .extend(tables.into_iter().map(table_identity)),
                        Err(error) => self.reads.unresolved(error.to_string()),
                    }
                }
                self.depth += 1;
                ControlFlow::Continue(())
            }

            fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
                self.depth -= 1;
                ControlFlow::Continue(())
            }
        }

        let _ = clause.visit(&mut Outermost {
            reads: self,
            depth: 0,
        });
    }

    /// The tables the bodies of `called` read, and of every function those bodies call in
    /// turn. A server function in `pg_catalog` reads no table of the schema.
    fn bodies(&mut self, mut pending: Vec<&'db DB::Function>) {
        let mut seen: Vec<&'db DB::Function> = Vec::new();
        while let Some(function) = pending.pop() {
            if seen.iter().any(|held| core::ptr::eq(*held, function)) {
                continue;
            }
            seen.push(function);
            if is_server_function(function) {
                continue;
            }
            match function.referenced_tables(self.db) {
                Ok(tables) => self.tables.extend(tables.into_iter().map(table_identity)),
                Err(error) => self.unresolved(error.to_string()),
            }
            match function.referenced_functions(self.db) {
                Ok(functions) => pending.extend(functions),
                Err(error) => self.unresolved(error.to_string()),
            }
        }
    }
}

fn is_server_function<F: FunctionLike>(function: &F) -> bool {
    let declared_in = function.target_name();
    declared_in.schema().is_some_and(|schema| {
        stored_identifier(schema, declared_in.schema_is_quoted()) == "pg_catalog"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;

    /// A clause the catalog cannot answer for this policy is reported unresolved, never read
    /// as reading nothing beyond the guarded table.
    #[test]
    fn a_clause_the_catalog_cannot_answer_leaves_the_policy_unresolved() {
        let db = parse_schema("CREATE TABLE docs (id INT PRIMARY KEY);").expect("parses");
        let elsewhere = parse_schema(
            "CREATE TABLE docs (id INT PRIMARY KEY);
             CREATE POLICY held_elsewhere ON docs USING (id > 0);",
        )
        .expect("parses");
        let policy = elsewhere.policies().next().expect("the policy");
        let classified = ClassifiedPolicy::from_policy(policy, &elsewhere);
        let guarded = db.tables().next().expect("docs");
        let entry = read_set(&classified, guarded, policy, &db);
        assert!(
            entry
                .unresolved
                .iter()
                .any(|reason| reason.contains("held_elsewhere")),
            "{:?}",
            entry.unresolved
        );
    }
}
