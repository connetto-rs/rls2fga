use crate::prelude::*;
use crate::{ColumnName, RelationName, TypeName};
use alloc::collections::BTreeMap;

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
    Resulting,
}

/// One relation that must grant, and the version it judges.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActionJudgement {
    /// Relation to ask, always defined on the entry's type.
    pub relation: RelationName,
    /// Version to ask it about.
    pub version: RowVersion,
}
impl ActionJudgement {
    /// Build one required judgement.
    #[must_use]
    pub fn new(relation: RelationName, version: RowVersion) -> Self {
        Self { relation, version }
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
