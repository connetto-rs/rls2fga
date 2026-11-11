use crate::prelude::*;
use crate::{ObjectKey, RecordError, RowValues, TableId, TypeName};

/// How rows of one table are named as objects of the emitted model.
///
/// `#[non_exhaustive]`: a naming this learns to report adds a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RowNaming {
    /// Table whose query route this object naming describes.
    pub table: TableId,
    /// The type the model assigned it, after any collision suffix.
    pub type_name: TypeName,
    /// Row identity, or a constant key for row-independent permissions.
    pub key: ObjectKey,
}
impl RowNaming {
    /// Build one table naming contract.
    #[must_use]
    pub fn new(table: TableId, type_name: TypeName, key: ObjectKey) -> Self {
        Self {
            table,
            type_name,
            key,
        }
    }
}

impl RowNaming {
    /// Render this row under the type the translation assigned it.
    pub fn render<R: RowValues + ?Sized>(&self, row: &R) -> Result<Option<String>, RecordError> {
        self.key.render(&self.type_name, row)
    }
}
