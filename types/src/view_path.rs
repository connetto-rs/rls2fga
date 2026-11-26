use serde::Serialize;

use crate::{TableId, TypeName};

/// A view running with its owner's rights through which a statement reaches the rows of
/// one table.
///
/// A statement naming the view is answered by the
/// [`ActionAnswer::AnyOf`](crate::ActionAnswer::AnyOf) of the table's type, whose rows are
/// named under the table's [`RowNaming`](crate::RowNaming). `PostgreSQL` checks the
/// statement's privileges on the view, which [`ActingPrivileges`](crate::ActingPrivileges)
/// list under [`type_name`](Self::type_name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ViewPath {
    /// The view a statement names.
    pub view: TableId,
    /// The table whose rows the view writes.
    pub table: TableId,
    /// The type answering the path through the view.
    pub type_name: TypeName,
}
