use crate::{TableId, TablePrivileges};

/// A table the database is positively known to restrict nothing on.
///
/// `#[non_exhaustive]`: a fact this learns to report adds a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnrestrictedTable {
    /// Table as the schema stores it, the spelling
    /// [`RowNaming::table`](crate::RowNaming) carries.
    pub table: TableId,
    /// Who may run each command at all, present where the translation models table
    /// privileges. Every row is open to a holder and closed to everyone else.
    pub privileges: Option<TablePrivileges>,
}
impl UnrestrictedTable {
    /// Build one unrestricted-table entry.
    #[must_use]
    pub fn new(table: TableId, privileges: Option<TablePrivileges>) -> Self {
        Self { table, privileges }
    }
}
