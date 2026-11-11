//! Whether the database filters none of a table's rows, by any route a read can take.
//!
//! A read naming a table with row-level security off is unfiltered, but a read reaching
//! the same rows through a guarded ancestor applies that ancestor's policies, and that
//! is the read an application makes, so the ancestor decides with the table. Only a
//! definite no counts: an unreadable answer must not become a claim that nothing is
//! enforced.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use crate::parser::names::table_identity;
use crate::parser::sql_parser::{DatabaseLike, TableLike};
use crate::types::TableId;

/// Whether row-level security is positively known to be off on this table.
///
/// Only a definite no counts: an unreadable answer must not become a claim that nothing is
/// enforced. The flag alone, which is what a query naming this table reads under; a read
/// reaching these rows through an ancestor is [`restricts_nothing_by_any_route`].
pub(crate) fn row_level_security_is_off<DB: DatabaseLike>(table: &DB::Table, db: &DB) -> bool {
    table.has_row_level_security(db) == Ok(false)
}

/// Whether the database filters none of this table's rows, by any route a reader can take.
///
/// The one predicate for the question, so the classifier deciding whether a read of the
/// table is filtered and the membership emission deciding whether a join table's rows are
/// readable ask alike and cannot disagree.
pub(crate) fn restricts_nothing_by_any_route<DB: DatabaseLike>(table: &DB::Table, db: &DB) -> bool {
    row_level_security_is_off(table, db) && !restricted_through_an_ancestor(table, db)
}

/// Whether a read that goes through an ancestor filters this table's rows.
///
/// A partition's own flag is off wherever the root carries the policies, and a read
/// through the root applies them to the partition's rows, which is the read an
/// application makes. An `INHERITS` child is the same, and the parent's tuple queries
/// read `FROM ONLY`, so nothing names those rows on the parent's type either. An
/// unreadable ancestor counts as restricting, since a claim that nothing is enforced has
/// to be positive.
fn restricted_through_an_ancestor<DB: DatabaseLike>(table: &DB::Table, db: &DB) -> bool {
    let mut seen: BTreeSet<TableId> = BTreeSet::new();
    let mut pending: Vec<&DB::Table> = Vec::new();
    let mut current = table;
    loop {
        let (Ok(root), Ok(parents)) = (current.partition_root(db), current.inherits_from(db))
        else {
            return true;
        };
        for ancestor in root.into_iter().chain(parents) {
            if !row_level_security_is_off(ancestor, db) {
                return true;
            }
            // Termination only: `PostgreSQL` allows no cycle here, and a catalog claiming
            // one must not spin.
            if seen.insert(table_identity(ancestor)) {
                pending.push(ancestor);
            }
        }
        let Some(next) = pending.pop() else {
            return false;
        };
        current = next;
    }
}
