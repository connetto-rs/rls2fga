use crate::prelude::*;

/// Who holds one table privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegeHolders {
    /// Every caller, through a grant to `PUBLIC` or, with caller roles, one every caller role reaches.
    Everyone,
    /// The roles holding it, sorted and deduplicated, or with caller roles the caller roles
    /// reaching a holder. Empty where nobody holds it.
    Roles(Vec<String>),
}

/// The table privileges of the four commands row-level security governs.
///
/// Read from the schema's `GRANT` and `REVOKE` statements, revokes already applied, and from
/// the owner's own entry where the schema names an owner the table's rules bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TablePrivileges {
    /// Holders of `SELECT`.
    pub select: PrivilegeHolders,
    /// Holders of `INSERT`.
    pub insert: PrivilegeHolders,
    /// Holders of `UPDATE`.
    pub update: PrivilegeHolders,
    /// Holders of `DELETE`.
    pub delete: PrivilegeHolders,
}
