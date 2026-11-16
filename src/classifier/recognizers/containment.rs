//! Keys of the row contained in a set built from a subquery.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use sqlparser::ast::{Array, BinaryOperator, Expr};

use crate::classifier::recognizers::helper::compared_column;
use crate::classifier::recognizers::{takes_a_subquery, unparenthesize};
use crate::parser::names::lookup_table;
use crate::parser::sql_parser::{ColumnLike, DataTypeLike, DatabaseLike, TableLike};

/// `ARRAY[k1, ..., kn] <@ ARRAY(SELECT ...)`, or `ARRAY(SELECT ...) @> ARRAY[k1, ..., kn]`,
/// rewritten as `k1 = ANY (ARRAY(SELECT ...)) AND ... AND kn = ANY (ARRAY(SELECT ...))`.
///
/// Each key is a column of `table` holding no array, since the operator flattens an
/// array element into its elements while `= ANY` compares it whole. A key repeated is
/// contained once, so it is compared once. Neither array is ever `NULL`, so the two
/// differ only where a key or an element of the set is `NULL`, which makes the
/// containment `false` and the membership `NULL`. A clause denies on both, and the
/// classifier reads no containment under `NOT`, which it refuses.
///
/// `None` for any other expression, so today's refusal stands.
pub(crate) fn contained_keys_as_memberships<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    table: &str,
) -> Option<Expr> {
    let (keys, set) = match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::ArrowAt,
            right,
        } => (left, right),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::AtArrow,
            right,
        } => (right, left),
        _ => return None,
    };
    let Expr::Array(Array { elem: keys, .. }) = unparenthesize(keys) else {
        return None;
    };
    let set = unparenthesize(set);
    let Expr::Function(constructor) = set else {
        return None;
    };
    if keys.is_empty() || !takes_a_subquery(constructor) {
        return None;
    }
    let guarded = lookup_table(db, table)?;
    let mut columns = Vec::with_capacity(keys.len());
    let mut memberships = Vec::with_capacity(keys.len());
    for key in keys {
        let column = compared_column(key, table)?;
        let mut stored = guarded
            .columns(db)
            .ok()?
            .find(|candidate| candidate.stored_column_name() == column.as_str())?
            .data_type(db);
        while let Some(base) = stored.base_type(db) {
            stored = base;
        }
        if stored.array_dimensions(db).is_some() {
            return None;
        }
        if columns.contains(&column) {
            continue;
        }
        columns.push(column);
        memberships.push(Expr::AnyOp {
            left: Box::new(key.clone()),
            compare_op: BinaryOperator::Eq,
            right: Box::new(set.clone()),
            is_some: false,
        });
    }
    memberships
        .into_iter()
        .reduce(|conjunction, membership| Expr::BinaryOp {
            left: Box::new(conjunction),
            op: BinaryOperator::And,
            right: Box::new(membership),
        })
}
