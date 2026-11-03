use crate::prelude::*;
use crate::{PolicyCommand, TableId};

/// The tables one policy's clauses read, which is what a consumer refusing a table it can
/// no longer follow refuses with it.
///
/// Reports what the database reads, so a table counts whether or not the model translated
/// the clause that reads it, and the report errs toward naming more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReads {
    /// The policy name as the DDL declares it.
    pub name: String,
    /// The table the policy guards, as the schema stores it.
    pub table: TableId,
    /// The command the policy restricts.
    pub command: PolicyCommand,
    /// Every table the policy's `USING` and `WITH CHECK` clauses read, sorted and
    /// deduplicated.
    ///
    /// The guarded table is read as a statement reading through it reads it, so every
    /// partition and `INHERITS` child below it is here too. So is every table a subquery
    /// reads, views expanded to their base tables, children below a table read without
    /// `ONLY` included, and every table the body of a function the clauses call reads,
    /// following the calls those bodies make in turn. A server function in `pg_catalog`,
    /// and a function the catalog does not declare, which is server or extension code, are
    /// taken as reading no table of the schema.
    pub reads: Vec<TableId>,
    /// One reason for each read the schema cannot name, such as a function whose body is
    /// written in C or runs `EXECUTE`. Empty when [`Self::reads`] is everything the
    /// clauses read. A consumer refusing on this report treats a non-empty list as a policy
    /// reading every table.
    pub unresolved: Vec<String>,
}
