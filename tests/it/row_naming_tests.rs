//! What the emitted model calls a row of a table.
//!
//! The assertions come from the request recorded in `plans/row-naming.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::parser::sql_parser::ParserDB;
use rls2fga::translator::Translation;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RowNaming;
use rls2fga::types::{records_from_row, ColumnKind, RecordDerivation, RecordError, ValueSource};

use crate::support;
use crate::support::row;

const CALLER: &str = "current_setting('app.user_id', true)";

fn translate(db: &ParserDB) -> Translation {
    support::deployment::translator_builder()
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(db)
        .expect("translation should plan")
}

fn naming(sql: &str) -> Vec<RowNaming> {
    let db: ParserDB = support::deployment::db(sql);
    let mut entries = translate(&db).row_naming().to_vec();
    entries.sort_by_key(|entry| entry.table.clone());
    entries
}

fn entry<'a>(entries: &'a [RowNaming], table: &str) -> &'a RowNaming {
    entries
        .iter()
        .find(|entry| entry.table.to_string() == table)
        .unwrap_or_else(|| {
            panic!(
                "no entry for {table}, got {:?}",
                entries
                    .iter()
                    .map(|entry| entry.table.to_string())
                    .collect::<Vec<_>>()
            )
        })
}

/// Assertion 1: one entry per named table, and the type it reports is the type its own
/// relations are defined on.
#[test]
fn a_named_table_reports_the_type_its_relations_live_on() {
    let sql = "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db: ParserDB = support::deployment::db(sql);
    let planned = translate(&db);
    let entries = planned.row_naming();
    assert_eq!(
        entries.len(),
        1,
        "one entry per named table, got {entries:?}"
    );

    let docs = &entries[0];
    assert_eq!(docs.table.to_string(), "docs");
    assert_eq!(docs.key.parts(), [ValueSource::column("id")].as_slice());
    assert!(
        planned
            .relations()
            .iter()
            .any(|entry| entry.type_name.as_str() == docs.type_name
                && entry.relation == "can_select"),
        "the type it reports is the one carrying that table's actions"
    );
}

/// Assertion 2: the name the key renders is the name the tuple SQL writes, which is what
/// makes the entry answerable against the loaded store.
#[test]
fn the_rendered_name_is_the_one_the_records_carry() {
    let sql = "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db: ParserDB = support::deployment::db(sql);
    let planned = translate(&db);
    let entries = planned.row_naming();
    let docs = entry(entries, "docs");
    let subject = row(&[("id", "a|b"), ("owner", "alice")]);

    let rendered = docs
        .render(&subject)
        .expect("the row is nameable")
        .expect("the name fits");

    let shape = planned
        .relations()
        .iter()
        .flat_map(|entry| entry.shapes.iter())
        .find(|shape| {
            matches!(
                &shape.derivation,
                RecordDerivation::FromRow { table, template, .. }
                    if table.to_string() == "docs" && template.object_type == docs.type_name
            )
        })
        .expect("the ownership shape names a docs object from a docs row");
    let records = records_from_row(shape, &subject).expect("the row names itself");
    assert!(
        records.iter().any(|record| record.object == rendered),
        "the entry renders the object the records carry, got {rendered} against {records:?}"
    );
}

#[test]
fn an_array_key_is_not_treated_as_element_text() {
    let sql = "CREATE TABLE docs(id TEXT[] PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db: ParserDB = support::deployment::db(sql);
    let planned = translate(&db);
    let entries = planned.row_naming();
    let docs = entry(entries, "docs");
    let subject = row(&[("id", "{a,b}"), ("owner", "alice")]);

    assert_eq!(
        docs.render(&subject),
        Err(RecordError::ColumnTypeUnsupported {
            column: "id".to_string(),
            kind: ColumnKind::Unsupported,
        })
    );
}

/// Assertion 3: two tables whose names canonicalise alike are told apart, and each entry
/// names its own.
#[test]
fn two_tables_that_canonicalise_alike_report_different_types() {
    let entries = naming(
        "CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE a.users(id INTEGER PRIMARY KEY, owner TEXT);
CREATE TABLE b.users(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE a.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE b.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON a.users FOR SELECT USING (owner = current_setting('app.user_id', true));
CREATE POLICY q ON b.users FOR SELECT USING (owner = current_setting('app.user_id', true));
",
    );
    let first = entry(&entries, "a.users");
    let second = entry(&entries, "b.users");
    assert_ne!(
        first.type_name, second.type_name,
        "one type name for two tables names the wrong rows"
    );
    assert_eq!(first.type_name, "users");
    assert_eq!(second.type_name, "users_ba5dba17");
}

/// Assertion 4: a table whose whole key is a foreign key is named by its own type, not by
/// the parent a shape describes from its rows.
#[test]
fn a_table_keyed_by_its_foreign_key_names_itself() {
    let entries = naming(
        "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
CREATE TABLE doc_acl(doc_id INTEGER PRIMARY KEY REFERENCES docs(id), grantee TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_acl ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  owner = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM doc_acl a WHERE a.doc_id = docs.id
             AND a.grantee = current_setting('app.user_id', true)));
CREATE POLICY q ON doc_acl FOR SELECT USING (grantee = current_setting('app.user_id', true));
",
    );
    assert_eq!(entry(&entries, "doc_acl").type_name, "doc_acl");
    assert_eq!(entry(&entries, "docs").type_name, "docs");
}

/// Assertion 5: a table the model grants nobody still has to be nameable, since naming
/// the row is how a consumer is told no.
#[test]
fn a_table_that_grants_nobody_is_still_named() {
    let entries = naming(
        "CREATE TABLE docs(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner LIKE '%x%');
",
    );
    assert_eq!(entry(&entries, "docs").type_name, "docs");
}

/// Assertion 6: a row the model cannot name has no entry rather than an empty one. The
/// loss is not silent: the translation already reports it as unhandled.
#[test]
fn a_table_whose_rows_cannot_be_named_has_no_entry() {
    let sql = "CREATE TABLE docs(id INTEGER, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db: ParserDB = support::deployment::db(sql);
    let planned = translate(&db);
    assert!(
        planned.row_naming().is_empty(),
        "a table with no key names no row, got {:?}",
        planned.row_naming()
    );
    assert!(
        planned.unhandled().count() > 0,
        "and the translation says so rather than leaving the absence to be noticed"
    );
}

/// A table reached only as a parent is named too: a consumer watching its rows has to
/// name them, and the model already carries a type for it.
#[test]
fn a_table_reached_only_as_a_parent_is_named() {
    let entries = naming(&format!(
        "CREATE TABLE projects(id INTEGER PRIMARY KEY, owner TEXT);
CREATE TABLE docs(id INTEGER PRIMARY KEY, project_id INTEGER REFERENCES projects(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = docs.project_id AND p.owner = {CALLER}));
"
    ));
    assert_eq!(entry(&entries, "projects").type_name, "projects");
    assert_eq!(entry(&entries, "docs").type_name, "docs");
}

/// A parent reached through a membership table is named after the table the foreign key
/// references, not after the membership table the rows were read from.
#[test]
fn a_parent_reached_through_a_membership_table_names_the_parent() {
    let entries = naming(&format!(
        "CREATE TABLE projects(id TEXT PRIMARY KEY);
CREATE TABLE docs(id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));
CREATE TABLE project_members(id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  project_id IN (SELECT project_id FROM project_members WHERE user_id = {CALLER}));
"
    ));
    assert_eq!(entry(&entries, "projects").type_name, "projects");
    assert!(
        entries
            .iter()
            .all(|entry| entry.table.to_string() != "project_members"),
        "the membership table carries no type of its own here, got {entries:?}"
    );
}

/// A parent reached through an undeclared foreign key is a type derived from a column's
/// name, and no table's rows are named by it. The child is still named.
#[test]
fn a_parent_named_from_a_column_rather_than_a_table_has_no_entry() {
    let entries = naming(&format!(
        "CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(id TEXT PRIMARY KEY, doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = {CALLER}));
"
    ));
    assert_eq!(entry(&entries, "docs").type_name, "docs");
    assert!(
        entries
            .iter()
            .all(|entry| entry.table.to_string() != "doc_members"
                && entry.type_name.as_str() != "doc"),
        "a type named after a column names no table's rows, got {entries:?}"
    );
}

/// A partition holds the root's rows, and the query minting the root's objects reads
/// every partition, so a row of a partition is named after the root and keyed by the
/// root's key. `PostgreSQL` requires that key to span the partitioning columns, which is
/// why it is composite here.
#[test]
fn a_partition_is_named_after_its_root() {
    let entries = naming(&format!(
        "CREATE TABLE events(id TEXT, tenant TEXT, at DATE, PRIMARY KEY (id, at))
  PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON events FOR SELECT USING (tenant = {CALLER});
"
    ));
    let partition = entry(&entries, "events_2026");
    assert_eq!(partition.type_name, "events");
    assert_eq!(
        partition.key.parts(),
        entry(&entries, "events").key.parts(),
        "the partition is keyed exactly as the root is"
    );
    assert_eq!(
        partition.render(&row(&[("id", "e-1"), ("at", "2026-05-01")])),
        Ok(Some("events:e-1|2026-05-01".to_string())),
        "the rendered name is the root's object"
    );
}

/// Two levels down, with nothing guarding the middle one.
#[test]
fn a_subpartition_is_named_after_the_root_that_carries_the_policy() {
    let entries = naming(&format!(
        "CREATE TABLE events(id TEXT, tenant TEXT, at DATE, PRIMARY KEY (id, at))
  PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')
  PARTITION BY RANGE (at);
CREATE TABLE events_2026_h1 PARTITION OF events_2026
  FOR VALUES FROM ('2026-01-01') TO ('2026-07-01');
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON events FOR SELECT USING (tenant = {CALLER});
"
    ));
    assert_eq!(entry(&entries, "events_2026_h1").type_name, "events");
}

/// A partition carrying its own policy already has a type, and its rows are named once.
///
/// `PostgreSQL` answers a direct read of it from its own policies and a read through the
/// root from the root's, so both types judge those rows and neither is the answer to the
/// other's question. One table, one name: a second entry would be silently dropped by any
/// consumer keying on the table, and which of the two survived would be arbitrary.
#[test]
fn a_partition_carrying_its_own_policy_is_named_once() {
    let entries = naming(&format!(
        "CREATE TABLE events(id TEXT, tenant TEXT, region TEXT, PRIMARY KEY (id, region))
  PARTITION BY LIST (region);
CREATE TABLE events_eu PARTITION OF events FOR VALUES IN ('eu');
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events_eu ENABLE ROW LEVEL SECURITY;
CREATE POLICY r ON events FOR SELECT USING (tenant = {CALLER});
CREATE POLICY p ON events_eu FOR SELECT USING (tenant = {CALLER});
"
    ));
    let named: Vec<&str> = entries
        .iter()
        .filter(|entry| entry.table.to_string() == "events_eu")
        .map(|entry| entry.type_name.as_str())
        .collect();
    assert_eq!(named, ["events_eu"], "one entry, its own");
}

/// An `INHERITS` child is not named after its parent: those queries read `FROM ONLY`, so
/// no tuple names a child row, and naming one would point at an object nothing grants.
#[test]
fn an_inheritance_child_is_not_named_after_its_parent() {
    let entries = naming(&format!(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner TEXT);
CREATE TABLE secret_docs(extra TEXT) INHERITS (docs);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner = {CALLER});
"
    ));
    assert_eq!(entry(&entries, "docs").type_name, "docs");
    assert!(
        entries
            .iter()
            .all(|entry| entry.table.to_string() != "secret_docs"),
        "a child of an inheritance parent carries no name, got {entries:?}"
    );
}
