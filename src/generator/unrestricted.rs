//! Which tables the database restricts nothing on.
//!
//! A table with row-level security off shows every row to everybody, and a table nobody
//! translated says nothing about what it shows. Reading the first as the second withholds
//! rows the database grants, reading the second as the first grants rows it may not, and a
//! consumer holding one empty report for both cannot choose.
//!
//! Reported by table rather than by type, because the emitted model defines no type for
//! such a table and canonicalizing one would reach another table's: two spellings can
//! canonicalize alike, and a consumer keying answers by type name would then read a
//! guarded table as open.
//!
//! Row filters first. Where the translation models table privileges, each entry also says
//! who holds each command, since a role lacking the privilege is refused every row.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use crate::generator::model_generator::GeneratorSettings;
use crate::generator::privileges::{read_table_privileges, TableCommand};
use crate::parser::names::table_identity;
use crate::parser::sql_parser::{DatabaseLike, TableLike};
use crate::types::{TableId, TranslationNote, UnrestrictedTable};

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
/// The one predicate both this report and
/// [`action_relations`](crate::types::ActionRelations) read, since
/// deciding openness twice lets one surface call a table open while the other does not.
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

/// One entry per table row-level security is off on, in table order, with its privileges
/// where `settings` models them, settled against its caller roles where it names them.
///
/// Read from the schema rather than from the plan, so a table the model gives a type to
/// and one it never reaches are both here.
pub(crate) fn unrestricted_tables<DB: DatabaseLike>(
    db: &DB,
    settings: &GeneratorSettings,
    notes: &mut Vec<TranslationNote>,
) -> Vec<UnrestrictedTable> {
    let mut tables: Vec<(TableId, &DB::Table)> = db
        .tables()
        .filter(|table| restricts_nothing_by_any_route(*table, db))
        .map(|table| (table_identity(table), table))
        .collect();
    tables.sort_by(|left, right| left.0.cmp(&right.0));
    tables
        .into_iter()
        .map(|(identity, table)| {
            let privileges = settings.table_privileges.then(|| {
                let read = read_table_privileges(table, db);
                // Nothing restricts a row, so every command reaches its privilege check.
                read.note_gaps(&TableCommand::ALL, notes);
                read.settled(
                    settings.caller_roles.as_ref(),
                    db,
                    &TableCommand::ALL,
                    notes,
                )
            });
            UnrestrictedTable::new(identity, privileges)
        })
        .collect()
}
