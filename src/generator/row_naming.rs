//! What the emitted model calls a row of a table.
//!
//! A consumer asking an authorization service about one changed row has to name that row,
//! and the name is not the table's: the model assigns a type, appending a suffix when two
//! tables canonicalise alike, and builds the object from the row's key.
//!
//! Reading the naming off the shapes instead is ambiguous, which is why this exists: a
//! table whose whole primary key is a foreign key is keyed identically by its own shape
//! and by a shape describing its parent from its rows, so `doc_acl` rows are named both
//! `doc_acl:4` and `docs:4` and nothing in a shape says which is the row's own.
//!
//! A covered partition uses its direct query route, while an uncovered partition can use a planned root whose tuple queries include its rows.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeMap;

use crate::generator::db_lookup::{column_kind, resolve_row_identity};
use crate::generator::ir::{TupleSource, SINGLETON_OBJECT_KEY};
use crate::generator::model_generator::{SchemaPlan, TypePlan};
use crate::parser::names::table_identity;
use crate::parser::sql_parser::{DatabaseLike, TableLike};
use crate::types::{ColumnName, ColumnRead, ObjectKey, RowNaming, TableId, ValueSource};

/// The columns that key the rows of the table `type_plan` names.
fn key_columns<DB: DatabaseLike>(type_plan: &TypePlan, db: &DB) -> Option<Vec<ColumnName>> {
    resolve_row_identity(type_plan.source_table.as_ref()?, db)
}

/// Name the shared object only when the plan emits its constant scope link.
fn singleton_key(type_plan: &TypePlan) -> Option<ObjectKey> {
    type_plan
        .table_tuple_sources
        .iter()
        .any(|source| matches!(source, TupleSource::SingletonScope { .. }))
        .then(|| ObjectKey::new(vec![ValueSource::Literal(SINGLETON_OBJECT_KEY.to_string())]))
}

/// The plan whose objects a partition's rows are named as, walking up until one is
/// planned.
///
/// A partitioned root's own tuple queries read every partition and its key spans them,
/// so a partition's rows already carry the root's objects. An `INHERITS` child is not
/// reached from here: those queries read `FROM ONLY`, and `PostgreSQL` refuses both to
/// inherit from a partitioned table and to inherit from a partition, so this walk cannot
/// arrive at one.
fn planned_partition_root<'plan, DB: DatabaseLike>(
    table: &DB::Table,
    planned: &BTreeMap<TableId, &'plan TypePlan>,
    db: &DB,
) -> Option<&'plan TypePlan> {
    let mut current = table.partition_root(db).ok()??;
    loop {
        if let Some(found) = planned.get(&table_identity(current)) {
            return Some(found);
        }
        current = current.partition_root(db).ok()??;
    }
}

/// How a row of the table `type_plan` names is keyed as an object of it, `None` for a type
/// naming no table's rows.
pub(crate) fn row_key<DB: DatabaseLike>(type_plan: &TypePlan, db: &DB) -> Option<ObjectKey> {
    let table = type_plan.source_table.as_ref()?;
    key_columns(type_plan, db)
        .map(|columns| object_key(table, columns, db))
        .or_else(|| singleton_key(type_plan))
}

/// Name covered rows by their key or the plan's row-independent singleton, omitting unnamed tables.
pub(crate) fn row_naming<DB: DatabaseLike>(plan: &SchemaPlan, db: &DB) -> Vec<RowNaming> {
    let mut entries: Vec<RowNaming> = plan
        .types
        .iter()
        .filter_map(|type_plan| {
            let table = type_plan.source_table.as_ref()?;
            let key = row_key(type_plan, db)?;
            Some(RowNaming::new(
                table.clone(),
                type_plan.type_name.clone(),
                key,
            ))
        })
        .collect();
    let planned: BTreeMap<TableId, &TypePlan> = plan
        .types
        .iter()
        .filter_map(|type_plan| Some((type_plan.source_table.clone()?, type_plan)))
        .collect();
    entries.extend(db.tables().filter_map(|table| {
        let root = planned_partition_root(table, &planned, db)?;
        let named = table_identity(table);
        // A partition carrying its own policy already has a type, and one table takes one
        // name: a consumer keying on the table drops whichever entry came second, and
        // which one that is would be arbitrary.
        if planned.contains_key(&named) {
            return None;
        }
        let key = object_key(&named, key_columns(root, db)?, db);
        Some(RowNaming::new(named, root.type_name.clone(), key))
    }));
    entries.sort_by(|left, right| left.table.cmp(&right.table));
    entries
}

fn object_key<DB: DatabaseLike>(table: &TableId, columns: Vec<ColumnName>, db: &DB) -> ObjectKey {
    ObjectKey::new(
        columns
            .into_iter()
            .map(|column| {
                let kind = column_kind(table, column.as_str(), db);
                ValueSource::Column(ColumnRead::new(column, kind))
            })
            .collect(),
    )
}
