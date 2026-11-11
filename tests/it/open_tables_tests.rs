//! Tables the database restricts nothing on enter the role-gated model beside the guarded
//! ones, and the action report tells the ways apart it answers them.
//!
//! A table no policy filters answers every statement with the local grant, a statement the
//! policies refuse is answered with the refusal, and a guarded route stays judged.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::parser::sql_parser::ParserDB;
use rls2fga::translator::Translation;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{ActionAnswer, ActionStatement, TranslationNote};

use crate::support;

/// Every statement the report answers for, in enum order. Pinned against the enum
/// declaration by the action relations suite, the way its own copy is.
const EVERY_STATEMENT: [ActionStatement; 8] = [
    ActionStatement::Select,
    ActionStatement::Insert,
    ActionStatement::Update,
    ActionStatement::Delete,
    ActionStatement::SelectForUpdate,
    ActionStatement::InsertOnConflictUpdate,
    ActionStatement::InsertReturning,
    ActionStatement::UpdateWithoutWhere,
];

/// A table the database filters nothing on.
const NO_ROW_LEVEL_SECURITY: &str = "
CREATE TABLE orders (id INT PRIMARY KEY, quantity BIGINT NOT NULL);
";

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
CREATE POLICY d ON docs USING (owner = current_setting('app.user_id', true));
";

/// A parent the model reaches through a membership table, and which the database itself
/// restricts not at all.
const OPEN_PARENT: &str = "
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
CREATE POLICY o ON app.orders USING (owner = current_setting('app.user_id', true));
";

/// A partitioned root carrying the policy, its partitions carrying none, which is what
/// `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` on a root leaves behind: the flag does not
/// reach the partitions, and a read through the root filters their rows all the same.
const GUARDED_PARTITION_ROOT: &str = "
CREATE TABLE events(id INT, tenant TEXT, at DATE, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events USING (tenant = current_setting('app.user_id', true));
";

/// The same shape with the policy on the partition instead. A read through the open root
/// applies nothing, which `PostgreSQL` 18 confirms, so the root really is open.
const OPEN_PARTITION_ROOT: &str = "
CREATE TABLE events(id INT, tenant TEXT, at DATE, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
ALTER TABLE events_2026 ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events_2026 USING (tenant = current_setting('app.user_id', true));
";

/// An `INHERITS` child of a guarded parent. A read through the parent applies the
/// parent's policy to the child's rows, and the parent's own tuple queries read
/// `FROM ONLY`, so nothing names those rows on the parent's type either.
const GUARDED_INHERITANCE_PARENT: &str = "
CREATE TABLE docs(id INT PRIMARY KEY, owner TEXT);
CREATE TABLE secret_docs(extra TEXT) INHERITS (docs);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (owner = current_setting('app.user_id', true));
";

fn translate(db: &ParserDB) -> Translation {
    support::deployment::translator_builder()
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(db)
        .expect("translation should plan")
}

/// The answer a type gives one statement, `None` where the model never answers it.
fn answer<'a>(
    planned: &'a Translation,
    type_name: &str,
    statement: ActionStatement,
) -> Option<&'a ActionAnswer> {
    planned
        .action_relations()
        .iter()
        .find(|entry| entry.type_name.as_str() == type_name && entry.statement == statement)
        .map(|entry| &entry.answer)
}

/// Whether every statement on the type is the local grant.
fn unrestricted_everywhere(planned: &Translation, type_name: &str) -> bool {
    EVERY_STATEMENT.iter().all(|statement| {
        answer(planned, type_name, *statement) == Some(&ActionAnswer::Unrestricted)
    })
}

/// Whether every statement on the type is a relation a request has to satisfy.
fn judged_everywhere(planned: &Translation, type_name: &str) -> bool {
    EVERY_STATEMENT.iter().all(|statement| {
        matches!(
            answer(planned, type_name, *statement),
            Some(ActionAnswer::Judged(judgements)) if !judgements.is_empty()
        )
    })
}

#[test]
fn an_open_table_answers_every_statement_locally() {
    let db: ParserDB = support::deployment::db(NO_ROW_LEVEL_SECURITY);
    let planned = translate(&db);
    assert!(
        unrestricted_everywhere(&planned, "orders"),
        "no policy filters the table, so no statement is asked: {:?}",
        planned.action_relations()
    );
}

#[test]
fn row_level_security_with_no_policy_denies_every_statement() {
    let db: ParserDB = support::deployment::db(ENABLED_WITHOUT_POLICY);
    let planned = translate(&db);
    for statement in EVERY_STATEMENT {
        assert_eq!(
            answer(&planned, "orders", statement),
            Some(&ActionAnswer::Denied),
            "row-level security on with no policy refuses {statement:?}, it does not leave it open"
        );
    }
}

/// The two states are told apart in both directions: the open table is the local grant,
/// the guarded one beside it stays judged.
#[test]
fn the_open_table_and_the_guarded_one_are_answered_apart() {
    let db: ParserDB = support::deployment::db(GUARDED_AND_OPEN);
    let planned = translate(&db);
    assert!(
        unrestricted_everywhere(&planned, "orders"),
        "the open table is the local grant: {:?}",
        planned.action_relations()
    );
    assert!(
        judged_everywhere(&planned, "docs"),
        "and the guarded table beside it is still judged: {:?}",
        planned.action_relations()
    );
}

/// A table the model reaches through another table's policy is answered by its own route.
#[test]
fn an_open_parent_is_answered_by_its_own_route() {
    let db: ParserDB = support::deployment::db(OPEN_PARENT);
    let planned = translate(&db);
    assert!(
        unrestricted_everywhere(&planned, "projects"),
        "the open parent is the local grant: {:?}",
        planned.action_relations()
    );
    assert!(
        judged_everywhere(&planned, "docs"),
        "and the guarded child beside it is still judged: {:?}",
        planned.action_relations()
    );
}

/// The consumer has a route from each table's own spelling to its answer, where the type
/// names would not tell the two apart.
#[test]
fn two_tables_canonicalizing_alike_are_answered_apart() {
    let db: ParserDB = support::deployment::db(COLLIDING_SPELLINGS);
    let planned = translate(&db);
    let type_of = |table: &str| {
        planned
            .row_naming()
            .iter()
            .find(|row| row.table.to_string() == table)
            .map_or_else(
                || panic!("{table} is named by the model: {:?}", planned.row_naming()),
                |row| row.type_name.as_str(),
            )
    };
    assert!(
        judged_everywhere(&planned, type_of("app.orders")),
        "the guarded spelling is judged: {:?}",
        planned.action_relations()
    );
    assert!(
        unrestricted_everywhere(&planned, type_of("public.orders")),
        "the open spelling is the local grant: {:?}",
        planned.action_relations()
    );
}

/// A keyless table's rows share the one object, and the database shows every one of them
/// to everybody.
#[test]
fn a_table_no_key_names_rows_of_answers_every_statement_locally() {
    let db: ParserDB = support::deployment::db("CREATE TABLE audit (message TEXT);");
    let planned = translate(&db);
    assert!(
        unrestricted_everywhere(&planned, "audit"),
        "the keyless open table is the local grant: {:?}",
        planned.action_relations()
    );
}

/// A partition carries the root's policies for every read that goes through the root,
/// which is how an application reads it, while its own row-level-security flag is off.
/// Verified on `PostgreSQL` 18: the root read returns one row of two, the direct read of
/// the partition returns both.
#[test]
fn a_partition_of_a_guarded_root_is_answered_through_the_root_route() {
    let db: ParserDB = support::deployment::db(GUARDED_PARTITION_ROOT);
    let planned = translate(&db);
    assert!(
        judged_everywhere(&planned, "events"),
        "the root's route is the guarded one: {:?}",
        planned.action_relations()
    );
    assert!(
        unrestricted_everywhere(&planned, "events_2026"),
        "a direct read of the partition applies no policy: {:?}",
        planned.action_relations()
    );
    assert!(
        planned.notes().iter().any(|note| matches!(
            note,
            TranslationNote::PartitionReadDirectlyIsUnfiltered { table, .. }
                if table.name() == "events_2026"
        )),
        "the direct read of the partition is disclosed: {:?}",
        planned.notes()
    );
}

/// The other direction. Verified on `PostgreSQL` 18: a read through an open root applies
/// the partition's policy to nothing and returns both rows.
#[test]
fn an_open_root_over_a_guarded_partition_answers_its_route_locally() {
    let db: ParserDB = support::deployment::db(OPEN_PARTITION_ROOT);
    let planned = translate(&db);
    assert!(
        unrestricted_everywhere(&planned, "events"),
        "the open root's route is unfiltered: {:?}",
        planned.action_relations()
    );
    assert!(
        judged_everywhere(&planned, "events_2026"),
        "the guarded partition's own route stays judged: {:?}",
        planned.action_relations()
    );
    assert!(
        !planned.notes().iter().any(|note| matches!(
            note,
            TranslationNote::PartitionReadDirectlyIsUnfiltered { .. }
        )),
        "no route skips a policy that would filter it: {:?}",
        planned.notes()
    );
}

/// Verified on `PostgreSQL` 18: reading the guarded parent applies its policy to the
/// child's rows too, so the parent's type answers that route, and a read naming the child
/// applies nothing.
#[test]
fn an_inheritance_child_of_a_guarded_parent_is_answered_by_its_own_route() {
    let db: ParserDB = support::deployment::db(GUARDED_INHERITANCE_PARENT);
    let planned = translate(&db);
    assert!(
        judged_everywhere(&planned, "docs"),
        "the parent's route is the guarded one: {:?}",
        planned.action_relations()
    );
    assert!(
        unrestricted_everywhere(&planned, "secret_docs"),
        "a read naming the child applies no policy: {:?}",
        planned.action_relations()
    );
}

/// Two levels down, with the middle one open, so one step up is not enough.
#[test]
fn a_subpartition_of_a_guarded_root_is_answered_through_the_root_route() {
    let sql = "
CREATE TABLE events(id INT, tenant TEXT, at DATE, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')
  PARTITION BY RANGE (at);
CREATE TABLE events_2026_h1 PARTITION OF events_2026 FOR VALUES FROM ('2026-01-01') TO ('2026-07-01');
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events USING (tenant = current_setting('app.user_id', true));
";
    let db: ParserDB = support::deployment::db(sql);
    let planned = translate(&db);
    assert!(
        judged_everywhere(&planned, "events"),
        "the guarded root is the route the model judges: {:?}",
        planned.action_relations()
    );
    assert!(
        unrestricted_everywhere(&planned, "events_2026_h1"),
        "a direct read of the leaf applies no policy: {:?}",
        planned.action_relations()
    );
}
