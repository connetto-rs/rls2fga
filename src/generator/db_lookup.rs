#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::parser::names::lookup_table_id;
use crate::parser::sql_parser::{ColumnLike, DataTypeLike, DatabaseLike, IndexLike, TableLike};
use crate::types::ColumnKind;
use crate::types::{ColumnName, TableId};
use core::num::NonZeroU32;
use sql_traits::utils::scalar_family::ScalarFamily;

/// SQL tables a user principal conventionally lives in, most specific first.
pub(crate) const USER_PRINCIPAL_TABLES: &[&str] = &["users", "user"];

/// SQL tables a team principal conventionally lives in, most specific first.
pub(crate) const TEAM_PRINCIPAL_TABLES: &[&str] = &["teams", "team"];

/// Every column naming a row of `table`, in declared order.
///
/// A declared primary key answers whatever its arity, and a table with none
/// falls back to its narrowest all-`NOT NULL` unique key. `None` means nothing
/// positively identifies a row, which includes a schema that cannot answer,
/// since a guessed identifier merges distinct rows into one `OpenFGA` object.
pub(crate) fn resolve_row_identity<DB: DatabaseLike>(
    table: &TableId,
    db: &DB,
) -> Option<Vec<ColumnName>> {
    let table_info = lookup_table_id(db, table)?;
    // Every arm below refuses unless it positively knows: an identifier the schema
    // does not confirm merges distinct rows into one object.
    let Ok(declared) = table_info.primary_key_columns(db) else {
        return None;
    };
    let declared: Vec<ColumnName> = declared
        .map(|c| ColumnName::from_stored(c.stored_column_name()))
        .collect();
    if !declared.is_empty() {
        return Some(declared);
    }
    let mut best: Option<Vec<ColumnName>> = None;
    for key in not_null_unique_keys(table_info, db) {
        // Strictly narrower only, so the first declared key wins a tie.
        if best.as_ref().is_none_or(|held| key.len() < held.len()) {
            best = Some(key);
        }
    }
    best
}

/// Each unique key whose shape is a plain column list and whose every column is
/// `NOT NULL`, in declaration order.
///
/// A nullable column admits duplicate rows under a unique index, and an
/// expression can produce `NULL` from `NOT NULL` columns, so neither names a row.
fn not_null_unique_keys<'db, DB: DatabaseLike>(
    table_info: &'db DB::Table,
    db: &'db DB,
) -> impl Iterator<Item = Vec<ColumnName>> + 'db {
    table_info
        .unique_indices(db)
        .into_iter()
        .flatten()
        .filter_map(|index| {
            if !index.expression(db).is_ok_and(is_plain_column_key) {
                return None;
            }
            let mut columns = Vec::new();
            for column in index.columns(db).into_iter().flatten() {
                if column.is_nullable(db) != Ok(false) {
                    return None;
                }
                columns.push(ColumnName::from_stored(column.stored_column_name()));
            }
            (!columns.is_empty()).then_some(columns)
        })
}

/// Whether the index expression is a bare column or a tuple of bare columns,
/// through any parenthesisation.
fn is_plain_column_key(expr: &sqlparser::ast::Expr) -> bool {
    use sqlparser::ast::Expr;
    fn unwrap_nested(expr: &Expr) -> &Expr {
        match expr {
            Expr::Nested(inner) => unwrap_nested(inner),
            other => other,
        }
    }
    fn is_column(expr: &Expr) -> bool {
        matches!(
            unwrap_nested(expr),
            Expr::Identifier(_) | Expr::CompoundIdentifier(_)
        )
    }
    match unwrap_nested(expr) {
        Expr::Tuple(elements) => elements.iter().all(is_column),
        other => is_column(other),
    }
}

/// The one column naming a row, `None` when several do or none does.
///
/// Derived from [`resolve_row_identity`] rather than resolving again, so a caller
/// that cannot work with a compound key refuses explicitly instead of by
/// accident.
pub(crate) fn single_identity_column<DB: DatabaseLike>(
    table: &TableId,
    db: &DB,
) -> Option<ColumnName> {
    let mut columns = resolve_row_identity(table, db)?.into_iter();
    let only = columns.next()?;
    columns.next().is_none().then_some(only)
}

/// True when `key_cols` uniquely keys a row of `table`: its primary key or an
/// all-`NOT NULL` unique key is a subset, so no two rows share those columns.
/// False when unknown, since then two rows may key the same tuple and a per-row
/// conditional tuple would collide.
pub(crate) fn row_uniquely_keys<DB: DatabaseLike>(
    table: &TableId,
    key_cols: &[&ColumnName],
    db: &DB,
) -> bool {
    let covered = |identity: &[ColumnName]| {
        !identity.is_empty() && identity.iter().all(|column| key_cols.contains(&column))
    };
    if resolve_row_identity(table, db).is_some_and(|pk| covered(&pk)) {
        return true;
    }
    let Some(table_info) = lookup_table_id(db, table) else {
        return false;
    };
    not_null_unique_keys(table_info, db).any(|key| covered(&key))
}

fn declared_column<'db, DB: DatabaseLike>(
    table: &TableId,
    column: &str,
    db: &'db DB,
) -> Option<&'db DB::Column> {
    lookup_table_id(db, table)?
        .columns(db)
        .into_iter()
        .flatten()
        .find(|candidate| candidate.stored_column_name() == column)
}

pub(crate) fn column_is_nullable<DB: DatabaseLike>(
    table: &TableId,
    column: &str,
    db: &DB,
) -> Option<bool> {
    declared_column(table, column, db).and_then(|column| column.is_nullable(db).ok())
}

const fn column_kind_from_scalar_family(family: Option<ScalarFamily>) -> ColumnKind {
    match family {
        Some(ScalarFamily::Bool) => ColumnKind::Bool,
        Some(ScalarFamily::Int) => ColumnKind::Integer,
        Some(ScalarFamily::Decimal) => ColumnKind::Decimal,
        Some(ScalarFamily::String) => ColumnKind::Text,
        Some(ScalarFamily::Bytes) => ColumnKind::Bytea,
        Some(ScalarFamily::Uuid) => ColumnKind::Uuid,
        Some(ScalarFamily::Date) => ColumnKind::Date,
        Some(ScalarFamily::Time) => ColumnKind::Time,
        Some(ScalarFamily::Timestamp) => ColumnKind::Timestamp,
        Some(ScalarFamily::TimestampTz) => ColumnKind::TimestampTz,
        Some(ScalarFamily::Json | ScalarFamily::Jsonb) => ColumnKind::Json,
        Some(ScalarFamily::Float | ScalarFamily::Interval) | None => ColumnKind::Unsupported,
    }
}

/// The modelled kind of one stored scalar column.
pub(crate) fn column_kind<DB: DatabaseLike>(table: &TableId, column: &str, db: &DB) -> ColumnKind {
    column_kind_from_scalar_family(
        declared_column(table, column, db)
            .and_then(|column| column.data_type(db).scalar_family(db)),
    )
}

/// The modelled element kind of one stored list column, `Unsupported` for an array of arrays.
pub(crate) fn list_element_kind<DB: DatabaseLike>(
    table: &TableId,
    column: &str,
    db: &DB,
) -> ColumnKind {
    let family = declared_column(table, column, db).and_then(|column| {
        let declared = column.data_type(db);
        if declared.array_dimensions(db).map(NonZeroU32::get) != Some(1) {
            return None;
        }
        declared.array_element(db)?.scalar_family(db)
    });
    column_kind_from_scalar_family(family)
}

/// Column names of `table`'s primary key when it spans more than one column.
///
/// `None` also covers a key the schema cannot resolve, so a caller deciding whether to
/// refuse must ask `has_composite_primary_key` rather than read `None` as "single".
pub(crate) fn composite_primary_key_columns<DB: DatabaseLike>(
    table: &TableId,
    db: &DB,
) -> Option<Vec<ColumnName>> {
    let table_info = lookup_table_id(db, table)?;
    let columns: Vec<ColumnName> = table_info
        .primary_key_columns(db)
        .into_iter()
        .flatten()
        .map(|c| ColumnName::from_stored(c.stored_column_name()))
        .collect();
    (columns.len() > 1).then_some(columns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;

    const SCHEMA: &str = "
        CREATE TABLE docs (id uuid PRIMARY KEY, owner text);
        CREATE TABLE paper_shares (
            paper_id uuid,
            viewer text,
            PRIMARY KEY (paper_id, viewer)
        );
        CREATE TABLE loose (id uuid NOT NULL UNIQUE, owner text);
        CREATE TABLE nameless (a text, b text);
        CREATE TABLE keyed (code text NOT NULL UNIQUE, val text);
        CREATE TABLE pair (a text NOT NULL, b text NOT NULL, val text, UNIQUE (a, b));
        CREATE TABLE nully (code text UNIQUE, val text);
        CREATE TABLE ranked (a text NOT NULL, b text NOT NULL, c text NOT NULL, UNIQUE (a, b), UNIQUE (c));
        CREATE TABLE grants (id uuid PRIMARY KEY, doc_id uuid NOT NULL, user_id text NOT NULL, UNIQUE (doc_id, user_id));
    ";

    fn table(name: &str) -> TableId {
        TableId::from_stored(None, name.to_string())
    }

    #[test]
    fn a_compound_key_resolves_every_column_in_declared_order() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_row_identity(&table("paper_shares"), &db),
            Some(vec![
                ColumnName::from_stored("paper_id"),
                ColumnName::from_stored("viewer")
            ]),
            "a key spanning two columns names a row through both"
        );
    }

    #[test]
    fn a_single_column_key_resolves_as_a_list_of_one() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_row_identity(&table("docs"), &db),
            Some(vec![ColumnName::from_stored("id")])
        );
        assert_eq!(
            resolve_row_identity(&table("loose"), &db),
            Some(vec![ColumnName::from_stored("id")]),
            "the id fallback still answers where no key is declared"
        );
    }

    #[test]
    fn a_table_nothing_identifies_still_refuses() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(resolve_row_identity(&table("nameless"), &db), None);
        assert_eq!(resolve_row_identity(&table("absent"), &db), None);
    }

    #[test]
    fn a_named_not_null_unique_key_identifies_rows() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_row_identity(&table("keyed"), &db),
            Some(vec![ColumnName::from_stored("code")]),
            "any NOT NULL unique key names a row, whatever the column is called"
        );
    }

    #[test]
    fn a_composite_not_null_unique_key_identifies_rows() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_row_identity(&table("pair"), &db),
            Some(vec![
                ColumnName::from_stored("a"),
                ColumnName::from_stored("b")
            ]),
            "a composite NOT NULL unique key names a row through both columns"
        );
    }

    #[test]
    fn a_nullable_unique_key_still_refuses() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_row_identity(&table("nully"), &db),
            None,
            "NULLs duplicate under a unique index, so a nullable key names nothing"
        );
    }

    #[test]
    fn a_unique_index_statement_is_not_an_identity() {
        // Only declared constraints reach `unique_indices` at the pinned catalog:
        // a `CREATE UNIQUE INDEX` statement may be partial or over expressions, and
        // the trait exposes no predicate, so it must never become a row identity.
        let mut parsed = 0usize;
        for spelling in [
            "CREATE TABLE stated (code text NOT NULL); CREATE UNIQUE INDEX ON stated (code);",
            "CREATE TABLE stated (code text NOT NULL, active boolean); \
             CREATE UNIQUE INDEX ON stated (code) WHERE active;",
            "CREATE TABLE stated (code text NOT NULL); CREATE UNIQUE INDEX ON stated (lower(code));",
        ] {
            let Ok(db) = parse_schema(spelling) else {
                continue;
            };
            parsed += 1;
            assert_eq!(
                resolve_row_identity(&table("stated"), &db),
                None,
                "`{spelling}`: an index statement must not become a row identity"
            );
        }
        assert_eq!(parsed, 3, "every spelling parses, or the claim must narrow");
    }

    #[test]
    fn the_smallest_identity_wins() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            resolve_row_identity(&table("ranked"), &db),
            Some(vec![ColumnName::from_stored("c")]),
            "the narrowest declared identity keys the object"
        );
    }

    #[test]
    fn an_expression_unique_key_names_nothing() {
        // PostgreSQL only spells expression uniqueness through CREATE UNIQUE INDEX,
        // which the catalog keeps out of `unique_indices`, but the generic parser
        // may accept constraint spellings carrying expressions. An expression can
        // produce NULL from NOT NULL columns, and NULLs duplicate, so only a plain
        // column list is an identity.
        for spelling in [
            "CREATE TABLE exprd (code text NOT NULL, UNIQUE (lower(code)))",
            "CREATE TABLE exprd (a text NOT NULL, b text NOT NULL, UNIQUE (a, lower(b)))",
        ] {
            let Ok(db) = parse_schema(spelling) else {
                // The spelling does not parse, so the hazard is unreachable from SQL.
                continue;
            };
            assert_eq!(
                resolve_row_identity(&table("exprd"), &db),
                None,
                "`{spelling}`: an expression key must not become a row identity"
            );
        }
    }

    #[test]
    fn a_unique_pair_beside_a_surrogate_key_uniquely_keys_the_row() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        let doc_id = ColumnName::from_stored("doc_id");
        let user_id = ColumnName::from_stored("user_id");
        assert!(
            row_uniquely_keys(&table("grants"), &[&doc_id, &user_id], &db),
            "the declared unique pair keys a row even though the primary key is the surrogate"
        );
        let doc_only = [&doc_id];
        assert!(
            !row_uniquely_keys(&table("grants"), &doc_only, &db),
            "half the pair keys nothing"
        );
    }

    #[test]
    fn the_single_column_answer_refuses_a_compound_key() {
        let db = parse_schema(SCHEMA).expect("schema parses");
        assert_eq!(
            single_identity_column(&table("docs"), &db),
            Some(ColumnName::from_stored("id"))
        );
        assert_eq!(
            single_identity_column(&table("paper_shares"), &db),
            None,
            "a caller that can only join one column must refuse rather than take the first"
        );
    }
    #[test]
    fn sql_traits_normalizes_timestamp_declarations_before_kind_mapping() {
        let db = parse_schema(
            r"
CREATE TABLE temporal (
    zoned TIMESTAMP(3) WITH TIME ZONE,
    compact TIMESTAMPTZ(3),
    plain TIMESTAMP(3),
    explicit TIMESTAMP(3) WITHOUT TIME ZONE,
    zoned_list TIMESTAMPTZ(3)[]
);
",
        )
        .expect("schema parses");
        let temporal = table("temporal");

        assert_eq!(
            column_kind(&temporal, "zoned", &db),
            ColumnKind::TimestampTz
        );
        assert_eq!(
            column_kind(&temporal, "compact", &db),
            ColumnKind::TimestampTz
        );
        assert_eq!(column_kind(&temporal, "plain", &db), ColumnKind::Timestamp);
        assert_eq!(
            column_kind(&temporal, "explicit", &db),
            ColumnKind::Timestamp
        );
        assert_eq!(
            list_element_kind(&temporal, "zoned_list", &db),
            ColumnKind::TimestampTz
        );
    }

    #[test]
    fn sql_traits_scalar_families_decide_column_kinds() {
        let db = parse_schema(
            r"
CREATE TABLE family_columns (
    label CHAR(8),
    balance MONEY,
    clock TIMETZ,
    labels CHAR(8)[]
);
",
        )
        .expect("schema parses");
        let columns = table("family_columns");

        assert_eq!(column_kind(&columns, "label", &db), ColumnKind::Text);
        assert_eq!(column_kind(&columns, "balance", &db), ColumnKind::Decimal);
        assert_eq!(column_kind(&columns, "clock", &db), ColumnKind::Time);
        assert_eq!(list_element_kind(&columns, "labels", &db), ColumnKind::Text);
    }

    #[test]
    fn only_a_one_dimensional_array_or_a_known_family_has_a_kind() {
        let db = parse_schema(
            r"
CREATE TABLE shaped_columns (
    span INTERVAL,
    counts INT[],
    grid INT[][]
);
",
        )
        .expect("schema parses");
        let columns = table("shaped_columns");

        assert_eq!(column_kind(&columns, "span", &db), ColumnKind::Unsupported);
        assert_eq!(
            list_element_kind(&columns, "counts", &db),
            ColumnKind::Integer
        );
        assert_eq!(
            list_element_kind(&columns, "grid", &db),
            ColumnKind::Unsupported
        );
    }
}
