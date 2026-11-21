use crate::prelude::*;
use crate::{ColumnName, RelationName, TypeName};
use alloc::collections::{BTreeMap, BTreeSet};

/// Which version of the row a relation judges.
///
/// `#[non_exhaustive]`: a version this learns to report adds a variant, and a caller
/// matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RowVersion {
    /// The row as it is, which a `USING` clause reads.
    Existing,
    /// The row as it will be, which a `WITH CHECK` clause reads.
    ///
    /// No store holds that row, so a check names it with
    /// [`ResultingRow::object`](crate::ResultingRow::object) and carries
    /// [`ResultingRow::records`](crate::ResultingRow::records) as contextual tuples, and
    /// nothing else the row would state. What the clause reads through a helper or a
    /// subquery the model reads from the stored row under the same key, as `PostgreSQL`
    /// reads the statement's snapshot.
    Resulting,
}

/// One relation that must grant, the version it judges, and the type it is asked on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActionJudgement {
    /// Relation to ask, defined on [`type_name`](Self::type_name).
    pub relation: RelationName,
    /// Version to ask it about.
    pub version: RowVersion,
    /// Type the relation is asked on. The entry's own type for
    /// [`RowVersion::Existing`], and for [`RowVersion::Resulting`] the type of the
    /// table's [`ResultingRow`](crate::ResultingRow), whose object and facts the check
    /// carries.
    pub type_name: TypeName,
}
impl ActionJudgement {
    /// Build one required judgement.
    #[must_use]
    pub fn new(relation: RelationName, version: RowVersion, type_name: TypeName) -> Self {
        Self {
            relation,
            version,
            type_name,
        }
    }
}

/// How one action on one type is answered.
///
/// `#[non_exhaustive]`: an answer this learns to give adds a variant, and a caller
/// matching this outside the crate keeps a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActionAnswer {
    /// Every judgement must grant. All of them, never any of them.
    Judged(Vec<ActionJudgement>),
    /// The simplified action grants every acting role without a row or request condition.
    Unrestricted,
    /// The model refuses this statement for every row of the table, so nothing has to be
    /// named or asked.
    ///
    /// Per statement, so a table refusing writes while granting reads carries both. The
    /// model refusing is not the database refusing: a policy the classifier could not read
    /// falls closed to this and says so through a `BelowThreshold` note.
    Denied,
    /// Some acting role may run the statement on some columns only, so the columns it
    /// touches are asked beside its rows.
    ByColumn(ColumnAnswer),
}

/// A command `PostgreSQL` grants on single columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnCommand {
    /// `SELECT`, needed on every column a statement reads.
    Select,
    /// `INSERT`, needed on every column an `INSERT` assigns.
    Insert,
    /// `UPDATE`, needed on every column an `UPDATE` sets.
    Update,
}

/// The relations naming who holds one command on each column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnRelations {
    /// Command the relations hold.
    pub command: ColumnCommand,
    /// Relation per column some column grant names.
    pub columns: BTreeMap<ColumnName, RelationName>,
    /// Relation for every other column, held by the roles holding the command on the table.
    pub on_table: RelationName,
}

impl ColumnRelations {
    /// The relation to ask for `column`.
    #[must_use]
    pub fn relation(&self, column: &ColumnName) -> &RelationName {
        self.columns.get(column).unwrap_or(&self.on_table)
    }
}

/// A statement answered for its rows and for the columns it touches.
///
/// Granted only where `rows` grants and, for each command in `commands`, the relation of
/// every column the statement touches with that command grants on `gate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnAnswer {
    /// The answer for the rows, never [`ActionAnswer::Denied`] or another `ByColumn`.
    pub rows: Box<ActionAnswer>,
    /// Object the column relations are asked on, `request_gate:<table>`.
    pub gate: String,
    /// The commands of the statement some acting role holds on some columns only.
    pub commands: Vec<ColumnRelations>,
}

/// Where an acting role holds one command on a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holding {
    /// On the table, and so on every column.
    Table,
    /// On these columns only, never on the table.
    Columns(BTreeSet<ColumnName>),
    /// Nowhere.
    Absent,
}

impl Holding {
    /// Whether the command is held on every column of `columns`, which for no column
    /// means held on some column, as `PostgreSQL` checks a statement naming none.
    fn covers(&self, columns: &[ColumnName]) -> bool {
        match self {
            Self::Table => true,
            Self::Columns(held) => columns.iter().all(|column| held.contains(column)),
            Self::Absent => false,
        }
    }
}

/// The privileges one acting role holds on one table, which `PostgreSQL` checks before
/// any policy. A statement the role lacks one for fails whatever its rows, with `permission
/// denied for table <t>` (SQLSTATE 42501), where a policy refusal filters or skips rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActingPrivileges {
    /// Type of the table's rows, as [`ActionRelations`] names it.
    pub type_name: TypeName,
    /// The acting role, as the deployment names it.
    pub role: String,
    /// Where the role holds `SELECT`.
    pub select: Holding,
    /// Where the role holds `INSERT`.
    pub insert: Holding,
    /// Where the role holds `UPDATE`.
    pub update: Holding,
    /// Whether the role holds `DELETE`, which is granted on the table only.
    pub delete: bool,
}

impl ActingPrivileges {
    /// Whether the role holds every privilege `statement` needs where it touches `columns`
    /// under each column command, as [`ActionStatement::column_commands`] lists them.
    ///
    /// The statement's own command is needed on every column it touches, or on some
    /// column where it touches none. A command it only reads through, such as the
    /// `SELECT` of the columns an `UPDATE` filters on, is needed only on the columns it
    /// reads. A locking read needs `UPDATE` on some column, and a `DELETE` needs `DELETE`.
    #[must_use]
    pub fn permits(
        &self,
        statement: ActionStatement,
        columns: &BTreeMap<ColumnCommand, Vec<ColumnName>>,
    ) -> bool {
        let own = match statement {
            ActionStatement::Select | ActionStatement::SelectForUpdate => {
                Some(ColumnCommand::Select)
            }
            ActionStatement::Insert
            | ActionStatement::InsertReturning
            | ActionStatement::InsertOnConflictUpdate => Some(ColumnCommand::Insert),
            ActionStatement::Update | ActionStatement::UpdateWithoutWhere => {
                Some(ColumnCommand::Update)
            }
            ActionStatement::Delete => None,
        };
        let columns_held = statement.column_commands().iter().all(|command| {
            let touched = columns.get(command).map_or(&[][..], Vec::as_slice);
            (touched.is_empty() && own != Some(*command)) || self.holding(*command).covers(touched)
        });
        columns_held
            && match statement {
                ActionStatement::Delete => self.delete,
                ActionStatement::SelectForUpdate => self.update != Holding::Absent,
                _ => true,
            }
    }

    /// Where the role holds `command`.
    #[must_use]
    pub fn holding(&self, command: ColumnCommand) -> &Holding {
        match command {
            ColumnCommand::Select => &self.select,
            ColumnCommand::Insert => &self.insert,
            ColumnCommand::Update => &self.update,
        }
    }
}

/// A statement shape the model answers for.
///
/// `#[non_exhaustive]` permits more statement shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ActionStatement {
    /// `SELECT`.
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE` naming the rows it changes.
    Update,
    /// `DELETE`.
    Delete,
    /// A locking read, `SELECT ... FOR UPDATE` and its three siblings, which
    /// `PostgreSQL` filters by the `UPDATE` policies as well.
    SelectForUpdate,
    /// `INSERT ... ON CONFLICT ... DO UPDATE`, which changes the conflicting row.
    InsertOnConflictUpdate,
    /// `INSERT ... RETURNING`, which reads the row it wrote.
    InsertReturning,
    /// `UPDATE` with no `WHERE`, which reads nothing to choose rows, so the `SELECT`
    /// policies do not apply.
    UpdateWithoutWhere,
}

impl ActionStatement {
    /// The SQL command this answers for.
    ///
    /// Not a key into the notes: `SelectForUpdate` is a `SELECT` that the `UPDATE` policies
    /// filter as well, so a note naming the commands it refuses can leave it out while the
    /// model still refuses it. [`ActionAnswer::Denied`] is the answer to that question.
    #[must_use]
    pub fn command(&self) -> &'static str {
        match self {
            Self::Select | Self::SelectForUpdate => "SELECT",
            Self::Insert | Self::InsertOnConflictUpdate | Self::InsertReturning => "INSERT",
            Self::Update | Self::UpdateWithoutWhere => "UPDATE",
            Self::Delete => "DELETE",
        }
    }

    /// The commands whose column privileges this statement needs, as `PostgreSQL` checks
    /// them. `DELETE` and the column a locking read updates are table-wide.
    #[must_use]
    pub fn column_commands(&self) -> &'static [ColumnCommand] {
        match self {
            Self::Select | Self::SelectForUpdate | Self::Delete => &[ColumnCommand::Select],
            Self::Insert => &[ColumnCommand::Insert],
            Self::InsertReturning => &[ColumnCommand::Insert, ColumnCommand::Select],
            Self::Update | Self::UpdateWithoutWhere => {
                &[ColumnCommand::Update, ColumnCommand::Select]
            }
            Self::InsertOnConflictUpdate => &[
                ColumnCommand::Insert,
                ColumnCommand::Update,
                ColumnCommand::Select,
            ],
        }
    }
}

/// How one statement on one type is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActionRelations {
    /// Type the action is asked on, as [`RelationShapes`](crate::RelationShapes) spells it.
    pub type_name: TypeName,
    /// Statement it answers for.
    pub statement: ActionStatement,
    /// What has to grant.
    pub answer: ActionAnswer,
}
impl ActionRelations {
    /// Build one statement answer.
    #[must_use]
    pub fn new(type_name: TypeName, statement: ActionStatement, answer: ActionAnswer) -> Self {
        Self {
            type_name,
            statement,
            answer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn columns(names: &[&str]) -> Vec<ColumnName> {
        names
            .iter()
            .map(|name| ColumnName::from_stored(*name))
            .collect()
    }

    fn held(names: &[&str]) -> Holding {
        Holding::Columns(columns(names).into_iter().collect())
    }

    fn privileges(
        select: Holding,
        insert: Holding,
        update: Holding,
        delete: bool,
    ) -> ActingPrivileges {
        ActingPrivileges {
            type_name: TypeName::canonicalized("docs"),
            role: "app_reader".into(),
            select,
            insert,
            update,
            delete,
        }
    }

    fn touching(touched: &[(ColumnCommand, &[&str])]) -> BTreeMap<ColumnCommand, Vec<ColumnName>> {
        touched
            .iter()
            .map(|(command, names)| (*command, columns(names)))
            .collect()
    }

    /// `GRANT INSERT` alone refuses every read, and `GRANT SELECT (id, owner)` refuses a
    /// read projecting `body` while admitting one projecting `id` alone.
    #[test]
    fn a_read_needs_select_on_every_column_it_names() {
        let insert_only = privileges(Holding::Absent, Holding::Table, Holding::Absent, false);
        let id = touching(&[(ColumnCommand::Select, &["id"])]);
        assert!(!insert_only.permits(ActionStatement::Select, &id));
        assert!(insert_only.permits(
            ActionStatement::Insert,
            &touching(&[
                (ColumnCommand::Select, &[]),
                (ColumnCommand::Insert, &["id", "owner"])
            ]),
        ));

        let column_grant = privileges(
            held(&["id", "owner"]),
            Holding::Absent,
            Holding::Absent,
            false,
        );
        assert!(column_grant.permits(ActionStatement::Select, &id));
        assert!(!column_grant.permits(
            ActionStatement::Select,
            &touching(&[(ColumnCommand::Select, &["id", "body"])]),
        ));
    }

    /// A statement naming no column still needs its own command on some column, while a
    /// command it reads nothing through is not needed at all.
    #[test]
    fn a_statement_naming_no_column_needs_its_own_command_somewhere() {
        let none = touching(&[]);
        assert!(
            !privileges(Holding::Absent, Holding::Absent, Holding::Absent, false)
                .permits(ActionStatement::Select, &none)
        );
        assert!(
            privileges(held(&["id"]), Holding::Absent, Holding::Absent, false)
                .permits(ActionStatement::Select, &none)
        );
        let blind = privileges(Holding::Absent, Holding::Absent, Holding::Table, false);
        assert!(blind.permits(
            ActionStatement::UpdateWithoutWhere,
            &touching(&[
                (ColumnCommand::Select, &[]),
                (ColumnCommand::Update, &["body"])
            ]),
        ));
        assert!(!blind.permits(
            ActionStatement::Update,
            &touching(&[
                (ColumnCommand::Select, &["id"]),
                (ColumnCommand::Update, &["body"])
            ]),
        ));
    }

    /// `DELETE` is granted on the table only, and a locking read needs `UPDATE` beside
    /// the `SELECT` of what it reads.
    #[test]
    fn delete_and_locking_reads_need_their_table_wide_privileges() {
        let key = touching(&[(ColumnCommand::Select, &["id"])]);
        let reader = privileges(Holding::Table, Holding::Absent, Holding::Absent, false);
        assert!(!reader.permits(ActionStatement::Delete, &key));
        assert!(!reader.permits(ActionStatement::SelectForUpdate, &key));
        let editor = privileges(Holding::Table, Holding::Absent, held(&["body"]), true);
        assert!(editor.permits(ActionStatement::Delete, &key));
        assert!(editor.permits(ActionStatement::SelectForUpdate, &key));
    }
}
