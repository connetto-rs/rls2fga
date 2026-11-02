//! Which tables the database restricts nothing on.
//!
//! The assertions come from the finding recorded in `plans/unrestricted-table-report.md`:
//! a table with row-level security off has to be told apart from a table nothing
//! covered, and the only safe reading of the second is to refuse.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{ActionAnswer, ActionStatement};

/// The finding's own reproduction, which is also the `wasm-smoke` fixture downstream.
const NO_ROW_LEVEL_SECURITY: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, quantity BIGINT NOT NULL);";

/// The state that must not collapse into the one above: row-level security on with no
/// policy grants nobody, where off grants everybody.
const ENABLED_WITHOUT_POLICY: &str = "
CREATE TABLE orders (id INT PRIMARY KEY, quantity BIGINT NOT NULL);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
";

/// One guarded table beside one the database leaves open.
const GUARDED_AND_OPEN: &str = "
CREATE TABLE orders (id INT PRIMARY KEY, quantity BIGINT NOT NULL);
CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (owner = current_user);
";

/// A parent and a membership table the model reaches from a guarded table, both of
/// which the database itself restricts not at all.
const UNRESTRICTED_PARENT: &str = "
CREATE TABLE projects(id INTEGER PRIMARY KEY);
CREATE TABLE docs(id INTEGER PRIMARY KEY, project_id INTEGER REFERENCES projects(id));
CREATE TABLE project_members(project_id INTEGER REFERENCES projects(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (project_id IN (
  SELECT project_id FROM project_members WHERE user_id = current_setting('app.user_id', true)));
";

/// Two tables canonicalizing to one type name, only one of them guarded.
const COLLIDING_SPELLINGS: &str = "
CREATE SCHEMA app;
CREATE TABLE app.orders (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE public.orders (id INT PRIMARY KEY, quantity BIGINT);
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY o ON app.orders USING (owner = current_user);
";

/// A partitioned root carrying the policy, its partitions carrying none, which is what
/// `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` on a root leaves behind: the flag does not
/// reach the partitions, and a read through the root filters their rows all the same.
const GUARDED_PARTITION_ROOT: &str = "
CREATE TABLE events(id INT, tenant TEXT, at DATE, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events USING (tenant = current_user);
";

/// The same shape with the policy on the partition instead. A read through the open root
/// applies nothing, which `PostgreSQL` 18 confirms, so the root really is open.
const OPEN_PARTITION_ROOT: &str = "
CREATE TABLE events(id INT, tenant TEXT, at DATE, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE events_2026 ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events_2026 USING (tenant = current_user);
";

/// An `INHERITS` child of a guarded parent. A read through the parent applies the
/// parent's policy to the child's rows, and the parent's own tuple queries read
/// `FROM ONLY`, so no tuple names the child's rows at all.
const GUARDED_INHERITANCE_PARENT: &str = "
CREATE TABLE docs(id INT PRIMARY KEY, owner TEXT);
CREATE TABLE secret_docs(extra TEXT) INHERITS (docs);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (owner = current_user);
";

/// A partition of a guarded root that the plan gives a type to anyway, because a declared
/// foreign key names it, which `PostgreSQL` allows onto a partition's own primary key.
/// Its own row-level-security flag is off and a read through the root still filters it.
const TYPED_PARTITION_OF_A_GUARDED_ROOT: &str = "
CREATE TABLE events(id TEXT, tenant TEXT, region TEXT, PRIMARY KEY (id, region))
  PARTITION BY LIST (region);
CREATE TABLE events_eu PARTITION OF events FOR VALUES IN ('eu');
CREATE TABLE event_members(event_id TEXT, region TEXT, user_id TEXT,
  FOREIGN KEY (event_id, region) REFERENCES events_eu(id, region));
CREATE TABLE docs(id TEXT PRIMARY KEY, event_id TEXT, region TEXT,
  FOREIGN KEY (event_id, region) REFERENCES events_eu(id, region));
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events USING (tenant = current_user);
CREATE POLICY d ON docs USING (
  event_id IN (SELECT event_id FROM event_members WHERE user_id = current_user));
";

fn translate(db: &ParserDB) -> Translation {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(db)
        .expect("translation should plan")
}

/// Every table the report names, in the order it names them.
fn unrestricted(sql: &str) -> Vec<String> {
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    translate(&db)
        .unrestricted_tables()
        .iter()
        .map(|entry| entry.table.to_string())
        .collect()
}

#[test]
fn a_table_without_row_level_security_is_reported_unrestricted() {
    assert_eq!(unrestricted(NO_ROW_LEVEL_SECURITY), vec!["orders"]);
}

#[test]
fn row_level_security_with_no_policy_is_not_unrestricted() {
    assert!(
        unrestricted(ENABLED_WITHOUT_POLICY).is_empty(),
        "a table with row-level security on grants nobody, so nothing is unrestricted"
    );
}

/// The two states are told apart in both directions: the open table is named by the
/// list and answered nowhere else, the closed one is answered and named nowhere here.
#[test]
fn the_open_table_and_the_closed_one_are_answered_by_different_surfaces() {
    let db: ParserDB = parse_schema(ENABLED_WITHOUT_POLICY).expect("schema should parse");
    let translation = translate(&db);
    let reads: Vec<ActionAnswer> = translation
        .action_relations()
        .iter()
        .filter(|entry| entry.statement == ActionStatement::Select)
        .map(|entry| entry.answer.clone())
        .collect();
    assert_eq!(
        reads.as_slice(),
        [ActionAnswer::Denied],
        "row-level security on with no policy refuses reads, it does not leave them open"
    );
}

#[test]
fn only_the_open_table_of_a_mixed_schema_is_reported() {
    assert_eq!(unrestricted(GUARDED_AND_OPEN), vec!["orders"]);
}

/// A table the model gives a type to is still reported, so a consumer has one place to
/// look rather than two.
#[test]
fn a_table_the_model_types_but_the_database_leaves_open_is_reported_too() {
    assert_eq!(
        unrestricted(UNRESTRICTED_PARENT),
        vec!["project_members", "projects"]
    );
}

/// Whatever answers unrestricted through the action report is in this list as well,
/// joined on the type name through the naming report.
#[test]
fn every_type_answered_unrestricted_names_a_table_the_list_carries() {
    let mut checked = 0;
    for (label, sql) in [
        ("unrestricted parent", UNRESTRICTED_PARENT),
        ("guarded and open", GUARDED_AND_OPEN),
        ("typed partition", TYPED_PARTITION_OF_A_GUARDED_ROOT),
    ] {
        let db: ParserDB = parse_schema(sql).expect("schema should parse");
        let translation = translate(&db);
        let listed: Vec<String> = translation
            .unrestricted_tables()
            .iter()
            .map(|entry| entry.table.to_string())
            .collect();
        let naming = translation.row_naming();
        for entry in translation.action_relations() {
            if entry.answer != ActionAnswer::Unrestricted {
                continue;
            }
            let named = naming
                .iter()
                .find(|row| row.type_name == entry.type_name.as_str())
                .expect("an answered type names its rows");
            assert!(
                listed.contains(&named.table.to_string()),
                "{label}: {} answers unrestricted and is not listed: {listed:?}",
                named.table
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 8,
        "the membership parent is the one open type, and it answers all eight statements"
    );
}

/// The list carries the schema's own spelling, so the guarded table and the open one
/// stay apart even where their type names would not.
#[test]
fn two_tables_canonicalizing_alike_are_reported_by_their_own_spelling() {
    assert_eq!(unrestricted(COLLIDING_SPELLINGS), vec!["public.orders"]);
}

/// Nothing can name a row of a keyless table, and the database still shows every one of
/// them to everybody.
#[test]
fn a_table_no_key_names_rows_of_is_reported_unrestricted() {
    let sql = "CREATE TABLE audit (message TEXT);";
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    let translation = translate(&db);
    assert!(
        translation.row_naming().is_empty(),
        "nothing names a row of a keyless table"
    );
    assert_eq!(
        translation
            .unrestricted_tables()
            .iter()
            .map(|entry| entry.table.to_string())
            .collect::<Vec<String>>(),
        vec!["audit"]
    );
}

/// A partition carries the root's policies for every read that goes through the root,
/// which is how an application reads it, while its own row-level-security flag is off.
/// Verified on `PostgreSQL` 18: the root read returns one row of two, the direct read of
/// the partition returns both.
#[test]
fn a_partition_of_a_guarded_root_is_not_reported_unrestricted() {
    assert_eq!(unrestricted(GUARDED_PARTITION_ROOT), Vec::<String>::new());
}

/// The other direction stays reported. Verified on `PostgreSQL` 18: a read through an
/// open root applies the partition's policy to nothing and returns both rows.
#[test]
fn an_open_root_over_a_guarded_partition_is_still_reported() {
    assert_eq!(unrestricted(OPEN_PARTITION_ROOT), vec!["events"]);
}

/// Verified on `PostgreSQL` 18: reading the guarded parent applies its policy to the
/// child's rows too, so the child is not a table the database restricts nothing on.
#[test]
fn an_inheritance_child_of_a_guarded_parent_is_not_reported_unrestricted() {
    assert_eq!(
        unrestricted(GUARDED_INHERITANCE_PARENT),
        Vec::<String>::new()
    );
}

/// Two levels down, with the middle one open, so one step up is not enough.
#[test]
fn a_subpartition_of_a_guarded_root_is_not_reported_unrestricted() {
    let sql = "
CREATE TABLE events(id INT, tenant TEXT, at DATE, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')
  PARTITION BY RANGE (at);
CREATE TABLE events_2026_h1 PARTITION OF events_2026 FOR VALUES FROM ('2026-01-01') TO ('2026-07-01');
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events USING (tenant = current_user);
";
    assert_eq!(unrestricted(sql), Vec::<String>::new());
}
