//! The row a write would produce, as a check about it names it and states its facts.

use crate::prelude::*;
use crate::{
    records_from_row, ObjectKey, Record, RecordDescription, RecordError, RowValues, TableId,
    TypeName,
};

/// How a check judging the row a write would produce names that row and which facts it
/// carries.
///
/// The model judges such a row on a type of its own, so the new row's facts never mix
/// with the stored row's under the same key. Nothing loads that type. Each check carries
/// [`records`](Self::records) as contextual tuples, and the model reads everything
/// `PostgreSQL` answers through a helper or subquery from the stored row under the same
/// key, which is what the statement's snapshot holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResultingRow {
    /// Table whose writes this judges.
    pub table: TableId,
    /// Type every [`RowVersion::Resulting`](crate::RowVersion::Resulting) judgement on
    /// the table is asked on.
    pub type_name: TypeName,
    /// How a row names its object, under either type.
    key: ObjectKey,
    /// The new row's own records, each keyed on the row itself, and the record linking it
    /// to the stored row under the same key.
    shapes: Vec<RecordDescription>,
}

impl ResultingRow {
    /// How rows of `table` written under `type_name` are named by `key` and which records
    /// in `shapes` a check about one carries.
    #[must_use]
    pub fn new(
        table: TableId,
        type_name: TypeName,
        key: ObjectKey,
        shapes: Vec<RecordDescription>,
    ) -> Self {
        Self {
            table,
            type_name,
            key,
            shapes,
        }
    }

    /// The object a resulting judgement asks about, `None` where the row does not say.
    ///
    /// # Errors
    ///
    /// [`RecordError::RowCannotBeNamed`] when the name is longer than the target accepts.
    pub fn object<R: RowValues + ?Sized>(&self, row: &R) -> Result<Option<String>, RecordError> {
        self.key.render(&self.type_name, row)
    }

    /// The contextual tuples a resulting judgement about `row` carries.
    ///
    /// # Errors
    ///
    /// The first [`RecordError`] one of the shapes raises reading `row`.
    pub fn records<R: RowValues + ?Sized>(&self, row: &R) -> Result<Vec<Record>, RecordError> {
        let mut records = Vec::new();
        for shape in &self.shapes {
            records.extend(records_from_row(shape, row)?);
        }
        Ok(records)
    }
}
