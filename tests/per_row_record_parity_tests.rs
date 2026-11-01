//! Differential test for the per-row record descriptions.
//!
//! The whole-table SQL is the reference implementation. For every row of every
//! table a description reads, evaluating the description must yield exactly the
//! records the description's own query yields for that row. No expected output is
//! written by hand, so a description that disagrees with its own SQL fails here.

#![cfg(not(target_os = "windows"))]

use std::collections::{BTreeMap, BTreeSet};

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::{Jsonb, Text};
use testcontainers::GenericImage;

use openfga_client::client::OpenFgaClient;
use openfga_client::tonic::transport::Channel;
use rls2fga::generator::json_model::AuthorizationModel;
use rls2fga::generator::tuple_generator::{TupleCondition, TupleQuery, TupleRow};
use rls2fga::translator::Outputs;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RowDecision;
use rls2fga::types::{
    records_from_row, BoundQuery, ColumnKind, Record, RecordDerivation, RecordDescription,
    ReplayScope, RowCell, RowList, RowValues, ValueSource,
};
use rls2fga::types::{ActionAnswer, ActionStatement};
use rls2fga::types::{ColumnName, TableId};

mod support;

use support::containers::{PG_DB, PG_PASSWORD, PG_USER};

use support::{scalar_text, JsonRowValues};

/// One `(object, relation, subject)` triple as the generated SQL returns it.
///
/// The query under test is generated text, so it cannot go through the typed
/// query DSL. The row type still binds every column to its declared SQL type.
#[derive(QueryableByName, Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct SqlRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
}

/// The same, for a query whose tuples carry a condition context. A conditional record
/// grants nobody until the request completes the comparison, so the condition it names
/// and the context are part of what the two sides have to agree on.
#[derive(QueryableByName, Debug, Clone)]
struct ConditionalSqlRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
    #[diesel(sql_type = Text)]
    condition: String,
    #[diesel(sql_type = Jsonb)]
    context: serde_json::Value,
}

/// A whole row as JSON, which is how a test reads columns it only learns about
/// from the description at runtime.
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    row: serde_json::Value,
}

/// One key value a bound query is replayed for.
#[derive(QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = Text)]
    value: String,
}

async fn start_postgres() -> (testcontainers::ContainerAsync<GenericImage>, PgConnection) {
    let container = support::containers::start_postgres().await;
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{port}/{PG_DB}");
    let conn = support::containers::connect_postgres_with_retry(&url);
    (container, conn)
}

/// What a fixture needs in place before `PostgreSQL` will accept its schema, for the few
/// that name something outside their own file. A fixture absent from here needs nothing.
const FIXTURE_PREREQUISITES: [(&str, &str); 5] = [
    ("role_scope_inherit", "CREATE ROLE editors"),
    ("role_scoped_membership", "CREATE ROLE auditor"),
    ("role_scoped_restrictive", "CREATE ROLE contractor"),
    // Both declare their own `auth.uid()`, but not the schema holding it.
    ("supabase_auth", "CREATE SCHEMA auth"),
    ("supabase_mfa_restrictive", "CREATE SCHEMA auth"),
];

/// Every role the cluster holds. Raw SQL because `pg_roles` is a catalog view no `table!`
/// here describes, and nothing else in this file needs one.
fn role_names(conn: &mut PgConnection) -> BTreeSet<String> {
    #[derive(QueryableByName)]
    struct RoleName {
        #[diesel(sql_type = Text)]
        rolname: String,
    }
    diesel::sql_query("SELECT rolname FROM pg_roles")
        .load::<RoleName>(conn)
        .expect("failed to read the cluster's roles")
        .into_iter()
        .map(|row| row.rolname)
        .collect()
}

/// Every fixture schema is one `PostgreSQL` accepts.
///
/// A fixture the database refuses pins a translation of a policy nobody can create, so every
/// assertion resting on it is about a rule that cannot exist. This caught three: a policy
/// comparing a `uuid` column against `current_user`, which is of type `name`, has no operator
/// and was rejected at creation while the corpus asserted its translation.
///
/// A fresh database per fixture, since a leftover policy or role from the previous one would
/// make the next pass for the wrong reason.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn every_fixture_schema_is_one_postgres_accepts() {
    let (container, mut admin) = start_postgres().await;
    let port = container.get_host_port_ipv4(5432).await.unwrap();

    let mut fixtures: Vec<String> = std::fs::read_dir("tests/fixtures")
        .expect("the fixtures directory")
        .map(|entry| entry.expect("a fixture entry").path())
        .filter(|path| path.is_dir())
        .filter_map(|path| path.file_name()?.to_str().map(ToString::to_string))
        .collect();
    fixtures.sort();
    assert!(fixtures.len() > 20, "the corpus is read, not guessed");

    // A role is cluster-wide, not per database, so one fixture's role outlives its schema and
    // collides with the next fixture that declares the same name. Everything minted beyond
    // the baseline goes, once the database owning it is gone.
    let baseline = role_names(&mut admin);
    let mut refused = Vec::new();
    for fixture in &fixtures {
        let database = format!("fixture_{fixture}");
        admin
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .expect("failed to create the fixture's own database");
        {
            let mut conn = support::containers::connect_postgres_with_retry(&format!(
                "postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{port}/{database}"
            ));
            if let Some((_, prerequisite)) = FIXTURE_PREREQUISITES
                .iter()
                .find(|(named, _)| named == fixture)
            {
                conn.batch_execute(prerequisite)
                    .expect("failed to apply the fixture's prerequisite");
            }
            if let Err(error) = conn.batch_execute(&support::read_fixture_sql(fixture)) {
                refused.push(format!("{fixture}: {error}"));
            }
        }
        admin
            .batch_execute(&format!("DROP DATABASE {database}"))
            .expect("failed to drop the fixture's database");
        for role in role_names(&mut admin) {
            if !baseline.contains(&role) {
                admin
                    .batch_execute(&format!("DROP ROLE IF EXISTS \"{role}\""))
                    .expect("failed to drop a role the fixture minted");
            }
        }
    }

    assert!(
        refused.is_empty(),
        "PostgreSQL refuses to create these fixtures, so nothing resting on them is about a \
         policy that can exist:\n{}",
        refused.join("\n")
    );
}

/// Records the generated query returns, read back through the crate's own reader.
///
/// Building the fact here by hand would compare the description against a second
/// spelling of the mapping rather than against the one a consumer uses.
fn records_from_sql(
    outputs: &Outputs,
    conn: &mut PgConnection,
    query: &TupleQuery,
) -> BTreeSet<Record> {
    records_of_sql(outputs, conn, &query.sql, query.condition.is_some(), || {
        query.comment.clone()
    })
}

/// Every row of `sql`, as the records it spells.
fn records_of_sql(
    outputs: &Outputs,
    conn: &mut PgConnection,
    sql: &str,
    conditional: bool,
    label: impl Fn() -> String,
) -> BTreeSet<Record> {
    let failed = |error: diesel::result::Error| -> ! {
        panic!(
            "the generated query failed on PostgreSQL 18: {}\n{sql}\nError: {error}",
            label()
        )
    };
    let read = |row: TupleRow<'_>| {
        outputs.record_from_tuple_row(row).unwrap_or_else(|error| {
            panic!("the query returned a row it cannot mean:\n{sql}\n{error}")
        })
    };
    if conditional {
        let rows: Vec<ConditionalSqlRow> = diesel::sql_query(sql)
            .load(conn)
            .unwrap_or_else(|error| failed(error));
        return rows
            .iter()
            .map(|row| {
                let context = row.context.to_string();
                read(TupleRow {
                    object: &row.object,
                    relation: &row.relation,
                    subject: &row.subject,
                    condition: Some(TupleCondition {
                        name: &row.condition,
                        context: &context,
                    }),
                })
            })
            .collect();
    }
    let rows: Vec<SqlRow> = diesel::sql_query(sql)
        .load(conn)
        .unwrap_or_else(|error| failed(error));
    rows.iter()
        .map(|row| {
            read(TupleRow {
                object: &row.object,
                relation: &row.relation,
                subject: &row.subject,
                condition: None,
            })
        })
        .collect()
}

/// Every row of `table`, as JSON.
fn rows_of(conn: &mut PgConnection, table: &TableId) -> Vec<serde_json::Value> {
    // The table is discovered from the description at runtime, so the typed DSL
    // cannot name it. `to_jsonb` keeps every column without a per-table struct.
    let sql = format!("SELECT to_jsonb(t) AS row FROM {} t", table.sql_name());
    let rows: Vec<JsonRow> = diesel::sql_query(&sql)
        .load(conn)
        .unwrap_or_else(|error| panic!("failed to read rows of {table}: {error}"));
    rows.into_iter().map(|row| row.row).collect()
}

/// Records the description yields over every row of its table.
fn records_from_descriptions(
    conn: &mut PgConnection,
    description: &RecordDescription,
) -> BTreeSet<Record> {
    let table = description
        .row_table()
        .expect("only a pure description reaches here");
    rows_of(conn, table)
        .iter()
        .flat_map(|row| {
            records_from_row(description, &JsonRowValues(row))
                .expect("a pure description evaluates without a database")
        })
        .collect()
}

/// Distinct values of `columns` in `table`, one entry per key tuple, as text.
///
/// Raw SQL rather than the typed DSL, and it stays raw: the table and every column name
/// are discovered from the description at runtime, so no `table!` can name them. The
/// values come back as a JSON array of the same `::text` renderings a single-column read
/// produced, so a compound key is one row here rather than a cross product.
fn distinct_keys(
    conn: &mut PgConnection,
    table: &TableId,
    columns: &[ColumnName],
) -> Vec<Vec<String>> {
    let rendered: Vec<String> = columns
        .iter()
        .map(|column| format!("\"{}\"::text", column.as_str()))
        .collect();
    let not_null: Vec<String> = columns
        .iter()
        .map(|column| format!("\"{}\" IS NOT NULL", column.as_str()))
        .collect();
    let sql = format!(
        "SELECT DISTINCT json_build_array({})::text AS value FROM {} \
         WHERE {} ORDER BY value",
        rendered.join(", "),
        table.sql_name(),
        not_null.join(" AND ")
    );
    let rows: Vec<KeyRow> = diesel::sql_query(&sql)
        .load(conn)
        .unwrap_or_else(|error| panic!("failed to read keys of {table}: {error}"));
    rows.into_iter()
        .map(|row| {
            serde_json::from_str::<Vec<String>>(&row.value)
                .unwrap_or_else(|error| panic!("key tuple {} is not an array: {error}", row.value))
        })
        .collect()
}

/// Run a bound query for one key tuple.
///
/// Each value is substituted as a literal rather than bound as a parameter, because
/// a literal carries `unknown` type and coerces to whatever the column is, while
/// a text-typed parameter against a `uuid` column raises `operator does not
/// exist`. What is under test is the SQL the description carries, not the wire
/// form of the placeholder.
fn records_from_bound_query(
    outputs: &Outputs,
    conn: &mut PgConnection,
    bound: &BoundQuery,
    key: &[String],
) -> BTreeSet<Record> {
    let literals: Vec<String> = key
        .iter()
        .map(|value| format!("'{}'", value.replace('\'', "''")))
        .collect();
    // Highest placeholder first, so `$1` cannot eat the head of `$10`.
    let mut sql = bound.sql().to_string();
    for (index, literal) in literals.iter().enumerate().rev() {
        sql = sql.replace(&format!("${}", index + 1), literal);
    }
    // The whole-table query and its bound replay have to agree on the context too, or a
    // consumer replaying a change would answer differently from the loader. The shape of
    // the result is read from the bound query alone, which is all a consumer holds.
    records_of_sql(outputs, conn, &sql, bound.condition().is_some(), || {
        format!(
            "bound replay of {} {:?} = {}",
            bound.table(),
            bound.key_columns(),
            literals.join(", ")
        )
    })
}

/// A joining shape answers a change by querying, so every bound query has to run, return
/// only records the whole-table query returns, stay inside the slice it declares, and
/// together account for all of them. Replaying every changed row is how the consumer stays
/// complete.
///
/// The slice check is what a consumer cannot do for itself: it reconciles by reading the
/// slice the key names and deleting whatever the replay stopped returning, so a record
/// outside that name means the declaration promises a guarantee the query does not keep, and
/// the reconciliation either refuses or deletes another slice's facts. Spelled here rather
/// than asked of the crate, so both sides are not the same sentence twice.
///
/// Completeness is asked per table rather than per query, because a change arrives on a
/// table and every query bound to it is replayed together: one grant table replay per
/// principal kind each answers for its own subjects, and only their union is the table.
fn assert_bound_queries_account_for_every_record(
    outputs: &Outputs,
    conn: &mut PgConnection,
    query: &TupleQuery,
    bound_queries: &[BoundQuery],
    label: &str,
) {
    let whole = records_from_sql(outputs, conn, query);
    assert!(
        !whole.is_empty(),
        "{label}: nothing to compare, the seed produces no records for {}",
        query.comment
    );

    let mut by_table: BTreeMap<String, BTreeSet<Record>> = BTreeMap::new();
    for bound in bound_queries {
        assert_eq!(
            bound.condition(),
            query.condition.as_ref(),
            "{label}: the replay of {} claims a different projection from the load it \
             extends, so the two loaders decode the same rows differently:\n{}",
            bound.table(),
            bound.sql()
        );
        let keys = distinct_keys(conn, bound.table(), bound.key_columns());
        assert!(
            !keys.is_empty(),
            "{label}: no key values in {} {:?}, so the bound query is untested for {}",
            bound.table(),
            bound.key_columns(),
            query.comment
        );

        let mut narrowed = false;
        for key in &keys {
            let bound_records = records_from_bound_query(outputs, conn, bound, key);
            let invented: Vec<_> = bound_records.difference(&whole).collect();
            assert!(
                invented.is_empty(),
                "{label}: the bound query on {} {:?} = {key:?} returned records the \
                 whole-table query does not: {invented:?}\n{}",
                bound.table(),
                bound.key_columns(),
                bound.sql()
            );
            assert_records_lie_in_the_declared_slice(bound, key, &bound_records, label);
            narrowed |= bound_records.len() < whole.len();
            by_table
                .entry(bound.table().to_string())
                .or_default()
                .extend(bound_records);
        }

        // A query ignoring its key would pass both checks above, so require that
        // at least one key answered with less than everything.
        assert!(
            narrowed || keys.len() == 1,
            "{label}: the bound query on {} {:?} returned every record for every one of \
             its {} keys, so it does not bind:\n{}",
            bound.table(),
            bound.key_columns(),
            keys.len(),
            bound.sql()
        );
    }

    for (table, union) in by_table {
        assert_eq!(
            union,
            whole,
            "{label}: replaying every key of every query bound to {table} must reproduce the \
             whole table for {}\nmissing: {:?}",
            query.comment,
            whole.difference(&union).collect::<Vec<_>>(),
        );
    }
}

/// Every record a replay returned lies inside the slice its own declaration names.
fn assert_records_lie_in_the_declared_slice(
    bound: &BoundQuery,
    key: &[String],
    records: &BTreeSet<Record>,
    label: &str,
) {
    let values: Vec<&str> = key.iter().map(String::as_str).collect();
    let slice = bound.scope().rendered_key(&values).unwrap_or_else(|error| {
        panic!(
            "{label}: the replay of {} {:?} = {key:?} declares a slice its own key cannot \
             name: {error}",
            bound.table(),
            bound.key_columns()
        )
    });
    for record in records {
        let inside = match bound.scope() {
            ReplayScope::Object { relations, .. } => {
                record.object == slice && relations.contains(&record.relation)
            }
            ReplayScope::Subject {
                object_type,
                relation,
                ..
            } => {
                record.subject == slice
                    && &record.relation == relation
                    && record.object.starts_with(&format!("{object_type}:"))
            }
        };
        assert!(
            inside,
            "{label}: the replay of {} {:?} = {key:?} returned ({}, {}, {}) which lies outside \
             the slice {slice} its scope {:?} names:\n{}",
            bound.table(),
            bound.key_columns(),
            record.subject,
            record.relation,
            record.object,
            bound.scope(),
            bound.sql()
        );
    }
}

/// Compare both sides for every query the schema emits, and report what was covered.
fn assert_descriptions_match_their_sql(
    outputs: &Outputs,
    conn: &mut PgConnection,
    queries: &[TupleQuery],
    label: &str,
) -> (usize, usize, usize) {
    let (mut pure, mut joined, mut records) = (0, 0, 0);

    for query in queries {
        let Some(description) = &query.description else {
            // Only the TODO placeholder produces no records, and it emits no query.
            assert!(
                query.skipped.is_some(),
                "{label}: a real query must carry a description:\n{}\n{}",
                query.comment,
                query.sql
            );
            continue;
        };

        match &description.derivation {
            RecordDerivation::Joined { queries: bound, .. } => {
                joined += 1;
                assert!(
                    !bound.is_empty(),
                    "{label}: a joining description must carry a bound query per side it reads: {}",
                    query.comment
                );
                // Requirement 7: the consumer refuses to start by name, so every
                // table a bound query reads has to appear in the list.
                for query_side in bound {
                    assert!(
                        description.tables.contains(query_side.table()),
                        "{label}: {} is bound but absent from the table list {:?}: {}",
                        query_side.table(),
                        description.tables,
                        query.comment
                    );
                }
                assert_bound_queries_account_for_every_record(outputs, conn, query, bound, label);
                continue;
            }
            RecordDerivation::FromRow { table, .. } => {
                assert!(
                    description.tables.contains(table),
                    "{label}: the table list must name the row's own table: {}",
                    query.comment
                );
            }
            // A constant is compared whole rather than per row: the query yields exactly
            // the fact the description carries, whatever any table holds, so there is no
            // row to evaluate against and nothing may claim there is.
            RecordDerivation::Constant { record } => {
                assert!(
                    description.tables.is_empty(),
                    "{label}: a constant reads no table, got {:?}: {}",
                    description.tables,
                    query.comment
                );
                let expected = records_from_sql(outputs, conn, query);
                let carried: BTreeSet<Record> = [record.clone()].into_iter().collect();
                assert_eq!(
                    carried, expected,
                    "{label}: the constant disagrees with its own SQL for {}\n{}",
                    query.comment, query.sql
                );
                records += expected.len();
                continue;
            }
            // No key narrows this one, so the carried query has to be the whole one and
            // the table list has to name what it reads.
            RecordDerivation::WholeShape {
                query: whole,
                condition,
                ..
            } => {
                joined += 1;
                assert_eq!(
                    whole, &query.sql,
                    "{label}: an unnarrowed replay is the whole query: {}",
                    query.comment
                );
                assert_eq!(
                    condition, &query.condition,
                    "{label}: the rows carry the query's own condition: {}",
                    query.comment
                );
                assert!(
                    !description.tables.is_empty(),
                    "{label}: a query reading nothing cannot need a whole replay: {}",
                    query.comment
                );
                for table in &description.tables {
                    assert!(
                        whole.contains(&table.sql_name()),
                        "{label}: {} is listed but the query never reads it:\n{}",
                        table,
                        query.sql
                    );
                }
                let expected = records_from_sql(outputs, conn, query);
                assert!(
                    !expected.is_empty(),
                    "{label}: the unnarrowed replay yields nothing, so it proves nothing: {}",
                    query.comment
                );
                records += expected.len();
                continue;
            }
            // `RecordDerivation` is non_exhaustive, so a variant added later has
            // to be judged here rather than passing as one of the three above.
            other => panic!("{label}: unhandled derivation {other:?}"),
        }

        pure += 1;
        let expected = records_from_sql(outputs, conn, query);
        let actual = records_from_descriptions(conn, description);
        records += expected.len();

        assert_eq!(
            actual,
            expected,
            "{label}: the description disagrees with its own SQL for {}\n{}\n\
             only the description produced: {:?}\nonly the SQL produced: {:?}",
            query.comment,
            query.sql,
            actual.difference(&expected).collect::<Vec<_>>(),
            expected.difference(&actual).collect::<Vec<_>>(),
        );
    }

    (pure, joined, records)
}

/// Schema covering every shape whose records follow from one row, with rows
/// chosen for the cases that decide the answer: a null owner, a null list, an
/// empty list, a list holding only null, a null beside a real element, a missing
/// JSON key, and a false flag.
const ROW_SHAPES_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    folder_id TEXT REFERENCES folders(id),
    owner_id TEXT,
    editors TEXT[],
    meta JSONB,
    status TEXT,
    priority INT,
    is_public BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE note_members (note_id TEXT REFERENCES notes(id), user_id TEXT);
CREATE TABLE note_reviewers (note_id TEXT REFERENCES notes(id), user_id TEXT, role TEXT);
CREATE TABLE announcements (id TEXT PRIMARY KEY, body TEXT);
CREATE TABLE audits (id TEXT PRIMARY KEY, body TEXT);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE announcements ENABLE ROW LEVEL SECURITY;
ALTER TABLE audits ENABLE ROW LEVEL SECURITY;

-- P3 direct ownership.
CREATE POLICY folders_owner ON folders FOR SELECT
    USING (owner_id = auth_current_user_id());
-- P3 again, plus P11 list membership, P12 JSON field, P6 public flag,
-- and P4 membership, which also mints the note to folder bridge.
CREATE POLICY notes_owner ON notes FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY notes_editors ON notes FOR SELECT
    USING (auth_current_user_id() = ANY (editors));
CREATE POLICY notes_meta ON notes FOR SELECT
    USING (meta ->> 'owner_id' = auth_current_user_id());
CREATE POLICY notes_public ON notes FOR SELECT
    USING (is_public = TRUE);
CREATE POLICY notes_members ON notes FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM note_members
        WHERE note_members.note_id = notes.id
          AND note_members.user_id = auth_current_user_id()));
-- The same membership with a residual the row image evaluates, so the shape
-- still settles and the residual travels as a guard.
CREATE POLICY notes_reviewers ON notes FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM note_reviewers
        WHERE note_reviewers.note_id = notes.id
          AND note_reviewers.user_id = auth_current_user_id()
          AND note_reviewers.role = 'editor'));
-- A literal list residual, which the row image decides as it does one literal.
CREATE POLICY notes_triagers ON notes FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM note_reviewers
        WHERE note_reviewers.note_id = notes.id
          AND note_reviewers.user_id = auth_current_user_id()
          AND note_reviewers.role IN ('viewer', 'owner')));
-- P9 attribute guards over literal constants, which the row decides just as the
-- boolean flag does.
CREATE POLICY notes_published ON notes FOR SELECT USING (status = 'published');
CREATE POLICY notes_priority ON notes FOR SELECT USING (priority >= 3);
CREATE POLICY notes_listed ON notes FOR SELECT USING (status IN ('draft', 'archived'));
-- P10 constant TRUE.
CREATE POLICY announcements_all ON announcements FOR SELECT USING (TRUE);
-- A role-scoped policy, which mints the pg_role scope.
CREATE POLICY audits_auditor ON audits FOR SELECT TO auditor USING (TRUE);
";

const ROW_SHAPES_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob'), ('carol');

INSERT INTO folders (id, owner_id) VALUES
    ('f1', 'alice'),
    ('f2', NULL);

-- `status` and `priority` cover what an attribute guard turns on: the value it
-- admits, one it refuses, NULL (which fails every comparison including `<>`), and
-- both sides of a numeric boundary.
INSERT INTO notes (id, folder_id, owner_id, editors, meta, status, priority, is_public) VALUES
    ('n-owned',        'f1',  'alice', NULL,                    NULL,                          'published', 5,    FALSE),
    ('n-null-owner',   'f1',  NULL,    NULL,                    NULL,                          'draft',     1,    FALSE),
    ('n-null-list',    'f2',  'bob',   NULL,                    NULL,                          NULL,        NULL, FALSE),
    ('n-empty-list',   NULL,  'bob',   '{}',                    NULL,                          'draft',     3,    FALSE),
    ('n-only-null',    NULL,  'bob',   '{NULL}',                NULL,                          'published', 2,    FALSE),
    ('n-null-beside',  NULL,  'bob',   '{NULL,carol}',          NULL,                          NULL,        4,    FALSE),
    ('n-two-editors',  'f1',  'bob',   '{alice,carol}',         NULL,                          'archived',  10,   FALSE),
    ('n-meta-owner',   NULL,  'bob',   NULL,                    '{\"owner_id\": \"carol\"}',   'published', NULL, FALSE),
    ('n-meta-absent',  NULL,  'bob',   NULL,                    '{\"other\": \"carol\"}',      'draft',     0,    FALSE),
    ('n-meta-null',    NULL,  'bob',   NULL,                    '{\"owner_id\": null}',        NULL,        3,    FALSE),
    ('n-public',       NULL,  'bob',   NULL,                    NULL,                          'archived',  -1,   TRUE);

INSERT INTO note_members (note_id, user_id) VALUES
    ('n-owned', 'bob'),
    ('n-owned', NULL),
    ('n-public', 'carol');

-- Rows the residual predicate keeps and rows it drops, over more than one note so
-- the bound query has something to narrow.
INSERT INTO note_reviewers (note_id, user_id, role) VALUES
    ('n-owned',      'alice', 'editor'),
    ('n-owned',      'bob',   'viewer'),
    ('n-public',     'carol', 'editor'),
    ('n-null-list',  'alice', 'editor'),
    ('n-null-list',  NULL,    'editor');

INSERT INTO announcements (id, body) VALUES ('a1', 'hello'), ('a2', 'world');
INSERT INTO audits (id, body) VALUES ('au1', 'secret');
";

/// The accessor these inline schemas declare.
const ACCESSOR: &str =
    r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#;

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn every_row_shape_description_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute("CREATE ROLE auditor;")
        .expect("failed to create the scoped role");
    conn.batch_execute(ROW_SHAPES_SCHEMA)
        .expect("failed to apply the row-shapes schema");
    conn.batch_execute(ROW_SHAPES_SEED)
        .expect("failed to seed the row-shapes schema");

    // Without the accessor the ownership, list, field and membership policies fall
    // below the threshold and the schema exercises only three shapes.
    let (classified, db, registry) = support::classify_sql(ROW_SHAPES_SCHEMA, Some(ACCESSOR));
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "row shapes");

    // Non-vacuous: the schema really does exercise the fast path, and the rows
    // really do produce records on both sides.
    assert!(
        pure >= 11,
        "the schema must exercise every row-decidable shape, saw {pure}"
    );
    let listed = queries
        .iter()
        .find(|query| query.sql.contains("\"status\" IN ("))
        .expect("the literal list gate is loaded");
    assert!(
        listed
            .description
            .as_ref()
            .is_some_and(|description| matches!(
                description.derivation,
                RecordDerivation::FromRow { .. }
            )),
        "the row alone decides the list, so it is evaluated rather than joined:\n{}",
        listed.sql
    );
    assert_eq!(
        joined, 0,
        "every residual here is decided by the row image, saw {joined}"
    );
    assert!(
        records > 20,
        "the seed must produce records to compare, saw {records}"
    );
}

/// Weights straddling their own average, so the residual admits some and refuses others.
const CROSS_ROW_SEED: &str = "
INSERT INTO papers (id, owner) VALUES (1, 'owner'), (2, 'owner'), (3, 'owner');
INSERT INTO paper_shares (paper_id, viewer, weight) VALUES
    (1, 'alice', 50),
    (2, 'bob',   30),
    (3, 'alice', 1);
";

/// The shape no key narrows, which nothing else in this file produces.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_cross_row_residual_description_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(&support::read_fixture_sql("cross_row_residual"))
        .expect("failed to apply the cross-row residual schema");
    conn.batch_execute(CROSS_ROW_SEED)
        .expect("failed to seed the cross-row residual schema");

    let (classified, db, registry) = support::try_load_fixture_classified("cross_row_residual");
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let unnarrowed = queries
        .iter()
        .filter(|query| {
            query.description.as_ref().is_some_and(|description| {
                matches!(description.derivation, RecordDerivation::WholeShape { .. })
            })
        })
        .count();
    assert_eq!(
        unnarrowed, 1,
        "the membership is the one shape no key narrows, saw {unnarrowed}"
    );

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "cross-row residual");
    assert_eq!(
        pure, 1,
        "each paper names itself from its own row, and nothing else is row-decided, saw {pure}"
    );
    assert_eq!(
        joined, 1,
        "the membership is read by querying, since no row decides an average, saw {joined}"
    );
    assert_eq!(
        records, 5,
        "three papers name themselves and the two shares above the average grant, saw {records}"
    );
}

/// Rows chosen for what decides the answer: two teams that differ, a repeat so the
/// record set cannot pass by being a bijection with the rows, and a NULL that must yield
/// no record at all, since a comparison against NULL is NULL and `PostgreSQL` hides the
/// row.
const REQUEST_GATE_SEED: &str = "
INSERT INTO documents (id, team_id) VALUES (1, 'team-a'), (2, 'team-b'), (3, 'team-a'), (4, NULL);
INSERT INTO reports (id, team_id) VALUES (1, 'team-a'), (2, 'team-b'), (3, 'team-a'), (4, NULL);
";

/// The request-gated shape, which nothing else in this file produces.
///
/// Every other schema here reaches the caller through an accessor rather than through a
/// declared set, so no conditional tuple from a request gate ever reached this
/// comparison and the context a description carries went unchecked against the context
/// its own SQL emits. Both fixtures are run because they differ in what the caller has
/// to send, a list against a split, while the record each row yields must be identical.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_request_gated_description_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    for fixture in ["token_claim_set", "function_carried_set"] {
        conn.batch_execute(
            "DROP TABLE IF EXISTS documents, reports CASCADE; \
             DROP FUNCTION IF EXISTS user_teams();",
        )
        .expect("failed to clear the previous fixture");
        conn.batch_execute(&support::read_fixture_sql(fixture))
            .unwrap_or_else(|error| panic!("failed to apply the {fixture} schema: {error}"));
        conn.batch_execute(REQUEST_GATE_SEED)
            .unwrap_or_else(|error| panic!("failed to seed {fixture}: {error}"));

        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        let queries = outputs.tuple_queries();

        // Non-vacuous: without this the comparison below could pass by comparing two
        // empty sets, which is exactly how this shape went uncovered until now.
        let conditional = queries
            .iter()
            .filter(|query| query.condition.is_some())
            .count();
        assert_eq!(
            conditional, 2,
            "{fixture}: both spellings emit a conditional query, got {conditional}"
        );

        let (pure, joined, records) =
            assert_descriptions_match_their_sql(&outputs, &mut conn, queries, fixture);
        assert_eq!(
            joined, 0,
            "{fixture}: a request gate is decided by the row alone"
        );
        assert_eq!(
            pure, 2,
            "{fixture}: one description per spelling, got {pure}"
        );
        assert_eq!(
            records, 6,
            "{fixture}: three named teams per table and none for the NULL, got {records}"
        );
    }
}

/// A clock guard is settled at check time, and which record exists is settled by the
/// row alone, so the record carries the condition and the row's own timestamp in its
/// context. Keyed on a whole compound key, since a clock column names every row
/// sharing a timestamp.
const CLOCK_GATE_SCHEMA: &str = "
CREATE TABLE readings (
    tenant_id INT,
    reading_id INT,
    starts_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, reading_id)
);
ALTER TABLE readings ENABLE ROW LEVEL SECURITY;
CREATE POLICY readings_visible ON readings FOR SELECT TO PUBLIC USING (starts_at <= now());
";

/// Two rows per tenant, so a replay bound to one key has something to leave out and a
/// prefix of the key would answer for a row it does not name, plus a NULL the comparison
/// hides, which both sides have to drop.
const CLOCK_GATE_SEED: &str = "
INSERT INTO readings (tenant_id, reading_id, starts_at) VALUES
  (7, 9, '2026-01-01 00:00:00+00'),
  (7, 10, '2026-02-01 00:00:00+00'),
  (8, 9, '2026-03-01 00:00:00+00'),
  (8, 10, NULL);
";

/// A conditional shape the row decides, over a compound key: every record here has to
/// carry the condition and the context its own five-column SQL emits, spelled from the
/// row alone.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_clock_gated_record_is_decoded_from_its_own_row() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(CLOCK_GATE_SCHEMA)
        .expect("failed to apply the clock-gate schema");
    conn.batch_execute(CLOCK_GATE_SEED)
        .expect("failed to seed the clock-gate schema");

    let (classified, db, registry) = support::classify_sql(CLOCK_GATE_SCHEMA, None);
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let gated: Vec<&TupleQuery> = queries
        .iter()
        .filter(|query| query.condition.is_some())
        .collect();
    let [gate] = gated.as_slice() else {
        panic!("one conditional query, got {}", gated.len());
    };

    let (pure, joined, _) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "clock gate");
    assert_eq!(pure, 1, "the clock guard settles from the row");
    assert_eq!(joined, 0, "nothing here is left to replay, got {joined}");

    // Non-vacuous: the comparison above passes on two empty sets when the seed produces
    // nothing, and every record here reached `record_from_tuple_row` as five columns.
    let loaded = records_from_sql(&outputs, &mut conn, gate);
    assert_eq!(
        loaded.len(),
        3,
        "one record per row the comparison can judge and none for the NULL, got {loaded:?}"
    );
    for record in &loaded {
        let context = record
            .context
            .as_ref()
            .expect("a conditional record carries the value the request completes");
        assert_eq!(
            Some(&context.condition),
            gate.condition.as_ref(),
            "the record names the condition its query declares"
        );
    }
}

/// Two papers carry a live share, one an expired share and one none, so a replay has
/// something to leave out in both directions and the union over every key still has to
/// reproduce the whole table.
const EXPIRING_SHARE_SEED: &str = "
INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob'), (4, 'bob');
INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES
  (2, 'team-a', '2099-01-01 00:00:00+00'),
  (3, 'team-z', '2000-01-01 00:00:00+00'),
  (4, 'team-a', '2099-01-01 00:00:00+00');
";

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn an_expiring_share_settles_and_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(support::EXPIRING_SHARE_SCHEMA)
        .expect("failed to apply the expiring share schema");
    conn.batch_execute(EXPIRING_SHARE_SEED)
        .expect("failed to seed the expiring shares");

    let (classified, db, registry) = support::classify_sql_with_session_attributes(
        support::EXPIRING_SHARE_SCHEMA,
        r#"[
      { "key": "app.user_id", "kind": "caller_id" },
      { "key": "app.subjects", "kind": "set_attribute" }
    ]"#,
    );
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    // Non-vacuous: the clock now rides the share arm's condition and the row still decides
    // the record, so a conditional shape that settles from its row has to be present.
    let conditional_from_row = queries
        .iter()
        .filter(|query| {
            query.condition.is_some()
                && query
                    .description
                    .as_ref()
                    .is_some_and(RecordDescription::is_pure)
        })
        .count();
    assert_eq!(
        conditional_from_row, 1,
        "the expiring share arm carries a condition and settles from its own row"
    );

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "expiring share");
    assert_eq!(
        joined, 0,
        "the clock in the condition lets every arm settle from its own row"
    );
    assert!(
        pure > 0,
        "the owner arm and the conditioned share arm both settle from the row, saw {pure}"
    );
    assert!(
        records > 0,
        "the seed must produce records to compare, saw {records}"
    );
}

/// The unexpiring sibling settles from the share row, so its context-carrying records,
/// keyed on a foreign column, run through the pure comparison: each has to spell the
/// object, the condition and the viewer exactly as its own five-column SQL does.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_settled_share_arm_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(&support::read_fixture_sql("connetto_capability"))
        .expect("failed to apply the connetto capability schema");
    conn.batch_execute(
        "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
         INSERT INTO paper_shares (paper_id, viewer) VALUES (2, 'team-a'), (3, 'team-z');",
    )
    .expect("failed to seed the papers and shares");

    let (classified, db, registry) = support::try_load_fixture_classified("connetto_capability");
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "settled share arm");
    assert_eq!(joined, 0, "the share row decides its record, saw {joined}");
    assert!(
        pure >= 3,
        "the share arm runs beside the owner arm and the sharing table's own rows, saw {pure}"
    );
    assert!(
        records > 0,
        "the seed must produce records to compare, saw {records}"
    );
}

/// The grant rule over a table two columns identify together, run rather than inspected.
///
/// Two columns naming a row is where a shape most easily answers for a row it was not
/// given, so the pointer at the owner has to carry both, and the grant replay, which is
/// keyed on the owner rather than on any row, has to run and narrow.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_compound_key_grant_shape_runs_and_narrows_on_its_whole_key() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(&support::read_fixture_sql("role_threshold_compound_key"))
        .expect("failed to apply the compound-key grant schema");
    // Two rows sharing a tenant, so a query bound to the tenant alone answers for both and
    // the narrowing check below fails rather than passing on a union that happens to match.
    // One row is user owned and one team owned, so both principal arms produce a record.
    conn.batch_execute(
        "
INSERT INTO users (id) VALUES
    ('00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000a2');
INSERT INTO teams (id) VALUES ('00000000-0000-0000-0000-0000000000b1');
INSERT INTO team_members (team_id, user_id) VALUES
    ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000a1');
INSERT INTO ownables (tenant_id, ownable_id, owner_id) VALUES
    ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000d1',
     '00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000d2',
     '00000000-0000-0000-0000-0000000000b1');
INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
    ('00000000-0000-0000-0000-0000000000a2', '00000000-0000-0000-0000-0000000000a1', 3);
",
    )
    .expect("failed to seed the compound-key grant schema");

    let (classified, db, registry) =
        support::load_fixture_classified("role_threshold_compound_key");
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    // Non-vacuous: the pointer and both identity facts follow from one row and are
    // evaluated against their own SQL, and the grant replay runs for every owner.
    let (pure, joined, _) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "compound key grants");
    assert_eq!(
        joined, 1,
        "only the grant table is answered by querying, saw {joined}"
    );
    assert!(
        pure >= 4,
        "the pointer, both owner identities and the membership follow from one row, saw {pure}"
    );

    let pointer = queries
        .iter()
        .filter_map(|query| match &query.description.as_ref()?.derivation {
            RecordDerivation::FromRow {
                table, template, ..
            } if table.name() == "ownables" => Some(template),
            _ => None,
        })
        .find(|template| template.subject_type == "owner_grants_owner")
        .expect("the guarded rows point at their owner");
    assert_eq!(
        pointer
            .object_key
            .parts()
            .iter()
            .filter_map(|part| match part {
                ValueSource::Column(column) => Some(column.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        ["tenant_id", "ownable_id"],
        "a pointer named by the tenant alone merges every row it holds into one object"
    );
}

/// Only the grant table needs a query here, and the row owned by nobody the schema records
/// is what separates the shapes: an identity fact exists for every principal, so a row
/// pointing at an owner nobody is grants nobody without the pointer having to know.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn only_the_grant_table_is_answered_by_querying() {
    let (_container, mut conn) = start_postgres().await;

    let schema_sql = support::read_fixture_sql("earth_metabolome");
    conn.batch_execute(&schema_sql)
        .expect("failed to apply the earth_metabolome schema");
    conn.batch_execute(
        "
INSERT INTO users (id) VALUES
    ('00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000a2'),
    ('00000000-0000-0000-0000-0000000000a3');
INSERT INTO teams (id) VALUES
    ('00000000-0000-0000-0000-0000000000b1'),
    ('00000000-0000-0000-0000-0000000000b2');
INSERT INTO team_members (team_id, user_id) VALUES
    ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-0000000000a2');
INSERT INTO ownables (id, owner_id) VALUES
    ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000d2', '00000000-0000-0000-0000-0000000000a2'),
    -- Team owned, which is the only way the team-ownership shape produces a record.
    ('00000000-0000-0000-0000-0000000000d3', '00000000-0000-0000-0000-0000000000b1'),
    ('00000000-0000-0000-0000-0000000000d4', '00000000-0000-0000-0000-0000000000b2'),
    -- Owned by nobody the schema records. `owner_id` carries no foreign key, so
    -- this row is legal, and it is what separates a row-derived record from the
    -- principal-table filter the query applies. Marking the shape row-derived
    -- claims a record here that the query refuses.
    ('00000000-0000-0000-0000-0000000000d9', '00000000-0000-0000-0000-0000000000ff');
INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
    ('00000000-0000-0000-0000-0000000000a3', '00000000-0000-0000-0000-0000000000a1', 3),
    ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000a2', 2),
    ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-0000000000b1', 4);
",
    )
    .expect("failed to seed the earth_metabolome schema");

    let (classified, db, registry) = support::load_fixture_classified("earth_metabolome");
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, _) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "earth_metabolome");

    // The pointer, both owner identities and the membership all follow from one row, and
    // only the grant table, whose grantee kind the row does not carry, needs a query.
    assert!(
        pure >= 4,
        "ownership stopped reading a second table, saw {pure} pure"
    );
    assert_eq!(
        joined, 1,
        "only the grant expansion reads a table the row does not carry, saw {joined} joining"
    );
}

/// An uncorrelated membership grants the whole table at once, so the generator mints
/// a holder object standing for the member list. Three of them: one plain, one whose
/// residual the row image decides, and one gated by the clock, which only SQL can
/// read.
const HOLDER_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE staff (user_id TEXT);
CREATE TABLE reviewers (user_id TEXT, active BOOLEAN);
CREATE TABLE vetted (user_id TEXT, expires_at TIMESTAMPTZ);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE memos (id TEXT PRIMARY KEY);
CREATE TABLE drafts (id TEXT PRIMARY KEY);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
ALTER TABLE drafts ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_staff ON docs FOR SELECT
    USING (EXISTS (SELECT 1 FROM staff WHERE staff.user_id = auth_current_user_id()));
CREATE POLICY memos_reviewers ON memos FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM reviewers
        WHERE reviewers.user_id = auth_current_user_id()
          AND reviewers.active));
CREATE POLICY drafts_vetted ON drafts FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM vetted
        WHERE vetted.user_id = auth_current_user_id()
          AND vetted.expires_at > now()));
";

/// A duplicated member and a null one, which is what separates a set of records from
/// a row count, members on both sides of each residual so a guard and a bound query
/// both have something to refuse.
const HOLDER_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob'), ('carol');

INSERT INTO staff (user_id) VALUES ('alice'), ('alice'), ('bob'), (NULL);

INSERT INTO reviewers (user_id, active) VALUES
    ('alice', TRUE),
    ('alice', TRUE),
    ('bob',   TRUE),
    ('carol', FALSE),
    (NULL,    TRUE);

INSERT INTO vetted (user_id, expires_at) VALUES
    ('alice', '2099-01-01 00:00:00+00'),
    ('bob',   '2000-01-01 00:00:00+00'),
    (NULL,    '2099-01-01 00:00:00+00');

INSERT INTO docs (id, owner_id) VALUES ('d1', 'alice'), ('d2', NULL);
INSERT INTO memos (id) VALUES ('m1'), ('m2');
INSERT INTO drafts (id) VALUES ('dr1'), ('dr2');
";

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn holder_shapes_match_their_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(HOLDER_SCHEMA)
        .expect("failed to apply the holder schema");
    conn.batch_execute(HOLDER_SEED)
        .expect("failed to seed the holder schema");

    let (classified, db, registry) = support::classify_sql(HOLDER_SCHEMA, Some(ACCESSOR));
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "holder shapes");

    // Three bridges and the two member lists the row decides, with the residual
    // travelling as a guard, and the clock-gated list left to its query.
    assert_eq!(
        pure, 5,
        "the bridges and the row-decided member lists follow from one row, saw {pure}"
    );
    assert_eq!(
        joined, 1,
        "only the clock-gated member list reads more than the row, saw {joined}"
    );
    assert!(
        records >= 6,
        "the seed must produce records to compare, saw {records}"
    );
}

/// A correlated membership whose residual only SQL can evaluate, which is the one joining
/// shape outside the grant family, run rather than inspected.
///
/// Its replay is keyed on the column naming the parent, and the object it returns is built
/// from that same column, so this is where that slice is checked against rows instead of
/// against the structure alone.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_membership_with_a_sql_residual_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(&support::read_fixture_sql(
        "membership_wrapped_function_safe",
    ))
    .expect("failed to apply the wrapped-membership schema");
    // Two members of one doc, so a replay bound to that doc has something to leave out, and
    // roles on both sides of the residual, so the query has something to refuse. The mixed
    // case is the point of the fixture: only SQL can lower it.
    conn.batch_execute(
        "
INSERT INTO docs (id, owner_id) VALUES
    ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000a1'),
    ('00000000-0000-0000-0000-0000000000d2', '00000000-0000-0000-0000-0000000000a1');
INSERT INTO doc_members (doc_id, user_id, member_id, role) VALUES
    ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000a1',
     '00000000-0000-0000-0000-0000000000c1', 'Admin'),
    ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000a2',
     '00000000-0000-0000-0000-0000000000c2', 'admin'),
    ('00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-0000000000a3',
     '00000000-0000-0000-0000-0000000000c3', 'viewer'),
    ('00000000-0000-0000-0000-0000000000d2', '00000000-0000-0000-0000-0000000000a3',
     '00000000-0000-0000-0000-0000000000c4', 'ADMIN');
",
    )
    .expect("failed to seed the wrapped-membership schema");

    let (classified, db, registry) =
        support::try_load_fixture_classified("membership_wrapped_function_safe");
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "wrapped membership");
    assert_eq!(
        joined, 1,
        "the residual only SQL can evaluate keeps the member list on its query, saw {joined}"
    );
    assert!(
        pure >= 1,
        "the row still points at the parent on its own, saw {pure} pure"
    );
    // The joining side's records are compared inside the bound-query check, which refuses an
    // empty result and a replay that answers the same for every key. What is left to count
    // here is the pointer each guarded row writes on its own.
    assert_eq!(
        records, 2,
        "one pointer per seeded doc row reaches the evaluator, saw {records}"
    );
}

/// Both composite-key membership routes: a share keyed by the guarded table's whole
/// key (self route) and a membership carrying a declared composite foreign key onto a
/// parent's whole key (FK route). One `paper_id` and one `project_id` repeat across
/// tenants, so an object keyed on either column alone merges two rows.
const COMPOSITE_KEY_MEMBERSHIP_SCHEMA: &str = "
CREATE TABLE tenant_papers (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE tenant_shares (
    tenant_id TEXT NOT NULL,
    paper_id TEXT NOT NULL,
    viewer TEXT NOT NULL,
    PRIMARY KEY (tenant_id, paper_id, viewer)
);
CREATE TABLE projects (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE grouped_docs (
    doc_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE TABLE project_members (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, project_id, user_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE tenant_papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_visible ON tenant_papers FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM tenant_shares s
        WHERE s.tenant_id = tenant_papers.tenant_id
          AND s.paper_id = tenant_papers.id
          AND s.viewer = auth_current_user_id()));
ALTER TABLE grouped_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_visible ON grouped_docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM project_members m
        WHERE m.tenant_id = grouped_docs.tenant_id
          AND m.project_id = grouped_docs.project_id
          AND m.user_id = auth_current_user_id()));
";

/// One shared id per key family across tenants, plus an unshared row on each side.
const COMPOSITE_KEY_MEMBERSHIP_SEED: &str = "
INSERT INTO tenant_papers (tenant_id, id) VALUES
    ('t1', 'p-shared'), ('t2', 'p-shared'), ('t1', 'p-solo');
INSERT INTO tenant_shares (tenant_id, paper_id, viewer) VALUES
    ('t1', 'p-shared', 'alice'), ('t2', 'p-shared', 'bob');
INSERT INTO projects (tenant_id, id) VALUES
    ('t1', 'proj'), ('t2', 'proj'), ('t1', 'proj-empty');
INSERT INTO grouped_docs (doc_id, tenant_id, project_id) VALUES
    ('doc-t1', 't1', 'proj'), ('doc-t2', 't2', 'proj'), ('doc-empty', 't1', 'proj-empty');
INSERT INTO project_members (tenant_id, project_id, user_id) VALUES
    ('t1', 'proj', 'alice'), ('t2', 'proj', 'bob');
";

/// Every record a composite-key membership row yields must match the tuple its own
/// SQL writes, multi-part object and all, on both routes.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_composite_key_membership_matches_its_own_sql() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(COMPOSITE_KEY_MEMBERSHIP_SCHEMA)
        .expect("failed to apply the composite-key membership schema");
    conn.batch_execute(COMPOSITE_KEY_MEMBERSHIP_SEED)
        .expect("failed to seed the composite-key membership schema");

    let (classified, db, registry) =
        support::classify_sql(COMPOSITE_KEY_MEMBERSHIP_SCHEMA, Some(ACCESSOR));
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, records) = assert_descriptions_match_their_sql(
        &outputs,
        &mut conn,
        queries,
        "composite-key membership",
    );

    assert_eq!(
        joined, 0,
        "both routes resolve from single rows, saw {joined} joined"
    );
    assert!(
        pure >= 4,
        "two memberships and two bridges resolve from rows, saw {pure} pure"
    );
    // Two share rows, three self-bridge rows, two member rows, three doc bridges.
    assert!(
        records >= 10,
        "the seed must produce records on both sides, saw {records}"
    );
}

/// A scope naming two roles over three rows stores five facts, not eight.
///
/// The roles a policy admits are a fact about the policy, so they belong on the scope object.
/// Storing them per row multiplies the whole table by the roles the clause names, which is
/// the shape this counts: three pointers and one fact per role, whatever the table holds.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_role_scope_stores_its_roles_once_not_once_per_row() {
    let (_container, mut conn) = start_postgres().await;

    let schema = "
CREATE TABLE docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT TO auditor, support USING (TRUE);
";
    conn.batch_execute("CREATE ROLE auditor; CREATE ROLE support;")
        .expect("failed to create the roles the clause names");
    conn.batch_execute(schema)
        .expect("failed to apply the role-scoped schema");
    conn.batch_execute(
        "
INSERT INTO docs (id, title) VALUES
    ('00000000-0000-0000-0000-0000000000d1', 'one'),
    ('00000000-0000-0000-0000-0000000000d2', 'two'),
    ('00000000-0000-0000-0000-0000000000d3', 'three');
",
    )
    .expect("failed to seed the rows the scope judges");

    let (classified, db, registry) = support::classify_sql(schema, None);
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

    let mut pointers = 0usize;
    let mut role_facts = 0usize;
    for query in outputs.tuple_queries() {
        if query.skipped.is_some() {
            continue;
        }
        let rows = rows_returned(&mut conn, &query.sql);
        if query.comment.contains("admits PostgreSQL role") {
            assert_eq!(
                rows, 1,
                "a role the scope admits is one fact however many rows it judges: {}",
                query.sql
            );
            role_facts += 1;
        } else if query.comment.contains("judged by the scope") {
            pointers += rows;
        }
    }
    assert_eq!(role_facts, 2, "both roles the clause names reach the scope");
    assert_eq!(pointers, 3, "every row points at the scope that judges it");
}

/// How many rows the generated query returns.
///
/// Raw SQL because the argument is generated text this counts around, which no typed query
/// can describe.
fn rows_returned(conn: &mut PgConnection, sql: &str) -> usize {
    #[derive(QueryableByName)]
    struct Counted {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        rows: i64,
    }
    let counted: Counted = diesel::sql_query(format!(
        "SELECT count(*) AS rows FROM ({}) AS emitted",
        sql.trim().trim_end_matches(';')
    ))
    .get_result(conn)
    .expect("failed to count the rows the generated query returns");
    usize::try_from(counted.rows).expect("a row count fits")
}

/// A table keyed on two columns, carrying its own read policy, seeded with values the
/// target cannot spell verbatim.
///
/// This is the case the encoding exists for. The whole batch is refused if one value
/// renders wrong, and a compound name the evaluator spells differently from the SQL is
/// drift no DSL assertion can see, so the two are compared row by row here.
const COMPOUND_IDENTITY_SCHEMA: &str = "
CREATE TABLE paper_shares (
    paper_id TEXT,
    viewer TEXT,
    PRIMARY KEY (paper_id, viewer)
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON paper_shares FOR SELECT
    USING (viewer = auth_current_user_id());
";

/// Every member of the refused family, on both sides of the key and in the subject.
/// `alice smith` is the ordinary one: a space in a name breaks the load today.
const COMPOUND_IDENTITY_SEED: &str = "
INSERT INTO paper_shares (paper_id, viewer) VALUES
  ('p1', 'alice'),
  ('p1', 'alice smith'),
  ('p|2', 'bob'),
  ('p2', 'a|b'),
  ('p3', ''),
  ('p4', '*'),
  ('p5', 'carol#member'),
  ('p6', 'ali\u{00e7}e'),
  ('p:7', 'dave'),
  ('', 'erin');
";

const TIMESTAMPTZ_IDENTITY_SCHEMA: &str = "
CREATE TABLE readings (
    observed_at TIMESTAMPTZ PRIMARY KEY,
    owner_id TEXT
);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE readings ENABLE ROW LEVEL SECURITY;
CREATE POLICY readings_read ON readings FOR SELECT
    USING (owner_id = auth_current_user_id());
";

const TIMESTAMPTZ_IDENTITY_SEED: &str = "
INSERT INTO readings (observed_at, owner_id) VALUES
  ('2026-01-01 00:00:00.1234+00', 'alice'),
  ('2026-02-03 04:05:06.789+00', 'bob');
";

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_compound_identity_matches_between_the_sql_and_the_evaluator() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(COMPOUND_IDENTITY_SCHEMA)
        .expect("failed to apply the compound identity schema");
    conn.batch_execute(COMPOUND_IDENTITY_SEED)
        .expect("failed to seed the compound identity schema");

    let (classified, db, registry) =
        support::classify_sql(COMPOUND_IDENTITY_SCHEMA, Some(ACCESSOR));
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "compound identity");

    assert_eq!(
        pure, 1,
        "the ownership shape follows from one row of the share table, saw {pure}"
    );
    assert_eq!(joined, 0, "nothing here reads a second table, saw {joined}");
    assert_eq!(
        records, 10,
        "every seeded row must be named, including the ones the target refuses \
         verbatim, saw {records}"
    );
}

#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_timestamptz_identity_matches_between_the_sql_and_the_evaluator() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(TIMESTAMPTZ_IDENTITY_SCHEMA)
        .expect("failed to apply the timestamp identity schema");
    conn.batch_execute(TIMESTAMPTZ_IDENTITY_SEED)
        .expect("failed to seed the timestamp identity schema");

    let (classified, db, registry) =
        support::classify_sql(TIMESTAMPTZ_IDENTITY_SCHEMA, Some(ACCESSOR));
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let (pure, joined, records) =
        assert_descriptions_match_their_sql(&outputs, &mut conn, queries, "timestamp identity");

    assert_eq!(pure, 1, "the ownership shape follows from one row");
    assert_eq!(joined, 0, "nothing here reads a second table");
    assert_eq!(records, 2, "both seeded rows must be named");
}

/// A schema whose reads compose all three ways a recipe can: one relation's records
/// alone, a union of two, and an intersection a barrier makes. `can_delete` nests the
/// union inside the intersection, since a per-row `DELETE` reads the table.
const RECIPE_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT, reviewer_id TEXT);
CREATE TABLE memos (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);

CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_read ON docs FOR SELECT
    USING (owner_id = auth_current_user_id() OR editor_id = auth_current_user_id());
CREATE POLICY docs_purge ON docs FOR DELETE
    USING (reviewer_id = auth_current_user_id());
CREATE POLICY memos_owner ON memos FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY memos_barrier ON memos AS RESTRICTIVE FOR SELECT
    USING (editor_id = auth_current_user_id());
";

/// Rows for both sides of every composition. `m-disagree` and `d-reviewer-out` are the
/// ones that matter: each names a subject one side of an intersection grants and the
/// other refuses, so a recipe flattened into a single list would read them wrong.
const RECIPE_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob'), ('carol');

INSERT INTO docs (id, owner_id, editor_id, reviewer_id) VALUES
    ('d-owner',        'alice', NULL,    NULL),
    ('d-editor',       NULL,    'bob',   NULL),
    ('d-both',         'alice', 'bob',   NULL),
    ('d-neither',      NULL,    NULL,    NULL),
    ('d-reviewer',     'alice', NULL,    'alice'),
    ('d-reviewer-out', 'alice', NULL,    'carol'),
    ('d-all-three',    'alice', 'alice', 'alice');

INSERT INTO memos (id, owner_id, editor_id) VALUES
    ('m-agree',    'alice', 'alice'),
    ('m-disagree', 'alice', 'bob'),
    ('m-owner',    'alice', NULL),
    ('m-editor',   NULL,    'bob'),
    ('m-neither',  NULL,    NULL);
";

/// Which composition a recipe is, for the coverage count.
fn recipe_kind(decision: &RowDecision) -> &'static str {
    match decision {
        RowDecision::Leaf { .. } => "leaf",
        RowDecision::Any(_) => "any",
        RowDecision::All(_) => "all",
        RowDecision::RequestGated { .. } => "request-gated",
        other => panic!("a recipe shape this test cannot read: {other:?}"),
    }
}

/// The first shape a recipe reaches, which names the table and object type every other
/// leaf of the same recipe has to agree on.
fn first_shape(decision: &RowDecision) -> &RecordDescription {
    match decision {
        RowDecision::Leaf { relation, shapes }
        | RowDecision::RequestGated {
            relation, shapes, ..
        } => shapes
            .first()
            .unwrap_or_else(|| panic!("leaf {relation} carries no shape, so it decides nothing")),
        RowDecision::Any(children) | RowDecision::All(children) => children
            .first()
            .map(first_shape)
            .expect("a recipe reaches at least one leaf"),
        other => panic!("a recipe shape this test cannot read: {other:?}"),
    }
}

/// The object one row of a recipe's table names, `None` when the row has no identity.
fn recipe_object(decision: &RowDecision, row: &serde_json::Value) -> Option<String> {
    let RecordDerivation::FromRow { template, .. } = &first_shape(decision).derivation else {
        panic!("a leaf resolves from the row");
    };
    let [ValueSource::Column(column)] = template.object_key.parts() else {
        panic!("a leaf keys its object on a column");
    };
    let key = scalar_text(row.get(column.as_str())?)?;
    Some(format!("{}:{key}", template.object_type))
}

/// Evaluate a recipe: a leaf is the union of the subjects its shapes produce for this
/// row, [`RowDecision::Any`] the union of its children and [`RowDecision::All`] their
/// intersection. Nothing else, which is the whole contract a consumer implements.
fn recipe_subjects(
    decision: &RowDecision,
    row: &serde_json::Value,
    object: &str,
) -> BTreeSet<String> {
    match decision {
        RowDecision::Leaf { relation, shapes } => shapes
            .iter()
            .flat_map(|shape| {
                records_from_row(shape, &JsonRowValues(row))
                    .expect("a leaf shape resolves without a database")
            })
            .map(|record| {
                assert_eq!(
                    record.object, object,
                    "leaf {relation} produced a record for another object"
                );
                assert_eq!(&record.relation, relation, "leaf {relation} misattributed");
                record.subject
            })
            .collect(),
        RowDecision::Any(children) => children
            .iter()
            .flat_map(|child| recipe_subjects(child, row, object))
            .collect(),
        RowDecision::All(children) => children
            .iter()
            .map(|child| recipe_subjects(child, row, object))
            .reduce(|left, right| left.intersection(&right).cloned().collect())
            .expect("a recipe reaches at least one leaf"),
        other => panic!("a recipe shape this test cannot evaluate: {other:?}"),
    }
}

/// Subjects a recipe would grant if its composition were thrown away and every leaf
/// unioned into one list, which is the shape the intersection has to differ from.
fn flattened_subjects(
    decision: &RowDecision,
    row: &serde_json::Value,
    object: &str,
) -> BTreeSet<String> {
    match decision {
        RowDecision::Leaf { .. } => recipe_subjects(decision, row, object),
        RowDecision::Any(children) | RowDecision::All(children) => children
            .iter()
            .flat_map(|child| flattened_subjects(child, row, object))
            .collect(),
        other => panic!("a recipe shape this test cannot evaluate: {other:?}"),
    }
}

async fn start_openfga(
    model: &AuthorizationModel,
    tuples: &BTreeSet<Record>,
) -> (
    testcontainers::ContainerAsync<GenericImage>,
    OpenFgaClient<Channel>,
) {
    let container = support::containers::start_openfga().await;
    let grpc_port = container.get_host_port_ipv4(8081).await.unwrap();

    let mut service = support::openfga::connect(grpc_port).await;
    let store_id = support::openfga::create_store(&mut service, "recipe-parity").await;
    let model_id =
        support::openfga::write_authorization_model(&mut service, &store_id, model).await;
    let client = service.into_client(&store_id, &model_id);
    support::openfga::write_tuples(
        &client,
        tuples
            .iter()
            .map(|record| {
                support::openfga::make_tuple(
                    &record.object,
                    record.relation.as_str(),
                    &record.subject,
                )
            })
            .collect(),
    )
    .await;
    (container, client)
}

/// The recipe is the whole answer, so the subjects it yields for a row have to be the
/// subjects the emitted model grants once the whole-table SQL has loaded it. Neither
/// side is written by hand: the tuples come from the generated queries and the answers
/// come from real `OpenFGA` resolving the model it was handed.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn every_recipe_grants_the_subjects_the_model_grants() {
    let (_postgres, mut conn) = start_postgres().await;
    conn.batch_execute(RECIPE_SCHEMA)
        .expect("failed to apply the recipe schema");
    conn.batch_execute(RECIPE_SEED)
        .expect("failed to seed the recipe schema");

    let (classified, db, registry) = support::classify_sql(RECIPE_SCHEMA, Some(ACCESSOR));
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let reported = planned.translation().relations();

    let mut tuples: BTreeSet<Record> = BTreeSet::new();
    for query in planned.tuple_queries() {
        tuples.extend(records_from_sql(&planned, &mut conn, query));
    }
    assert!(
        !tuples.is_empty(),
        "the loader must produce tuples, otherwise every check answers no"
    );

    let (_openfga, client) = start_openfga(&planned.json_model(), &tuples).await;

    // Every user any tuple names, which bounds the comparison: a subject outside it
    // could only reach the relation through a tuple, and every tuple is in here.
    let universe: BTreeSet<String> = tuples
        .iter()
        .filter(|record| record.subject.starts_with("user:"))
        .map(|record| record.subject.clone())
        .collect();

    let mut kinds: BTreeSet<&str> = BTreeSet::new();
    let mut compared = 0usize;
    let mut granting_rows = 0usize;
    let mut refusals = 0usize;
    let mut narrowed_by_composition = 0usize;
    let mut failures = Vec::new();

    for entry in reported {
        let Some(decision) = entry.decision.as_ref() else {
            continue;
        };
        kinds.insert(recipe_kind(decision));
        let table = first_shape(decision)
            .row_table()
            .expect("a leaf resolves from a row of one table");

        for row in rows_of(&mut conn, table) {
            let Some(object) = recipe_object(decision, &row) else {
                continue;
            };
            let expected = recipe_subjects(decision, &row, &object);
            if !expected.is_empty() {
                granting_rows += 1;
            }
            if flattened_subjects(decision, &row, &object) != expected {
                narrowed_by_composition += 1;
            }

            let mut allowed = BTreeSet::new();
            for candidate in universe.union(&expected) {
                compared += 1;
                if support::openfga::check_allowed(
                    &client,
                    candidate,
                    entry.relation.as_str(),
                    &object,
                )
                .await
                {
                    allowed.insert(candidate.clone());
                } else {
                    refusals += 1;
                }
            }
            if allowed != expected {
                failures.push(format!(
                    "{object}#{}: the recipe grants {expected:?}, the model grants {allowed:?}",
                    entry.relation
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "the recipe and the model disagree:\n{}",
        failures.join("\n")
    );

    // Non-vacuous on every axis the comparison could be blind on.
    assert_eq!(
        kinds,
        BTreeSet::from(["all", "any", "leaf"]),
        "the schema has to exercise every composition, saw {kinds:?}"
    );
    assert!(
        granting_rows > 0,
        "no row grants anybody, so nothing is compared against a grant"
    );
    assert!(
        refusals > 0,
        "nothing is refused, so granting everybody would pass"
    );
    assert!(
        narrowed_by_composition > 0,
        "no row is narrowed by an intersection, so a recipe flattened into one list \
         would pass this comparison"
    );
    assert!(
        compared > 50,
        "too few checks to be meaningful, saw {compared}"
    );
}

/// The other half of the compound identity case: the names the two renderers agree on
/// have to be names the service actually takes, and they have to answer for the right
/// caller.
///
/// The load is all or nothing, so one value the target cannot spell fails the write and
/// the whole seed with it. That is the failure this encoding exists to remove, and the
/// seed carries every member of the refused family.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_compound_identity_loads_and_answers_against_the_service() {
    let (_postgres, mut conn) = start_postgres().await;
    conn.batch_execute(COMPOUND_IDENTITY_SCHEMA)
        .expect("failed to apply the compound identity schema");
    conn.batch_execute(COMPOUND_IDENTITY_SEED)
        .expect("failed to seed the compound identity schema");

    let (classified, db, registry) =
        support::classify_sql(COMPOUND_IDENTITY_SCHEMA, Some(ACCESSOR));
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

    let mut tuples: BTreeSet<Record> = BTreeSet::new();
    for query in outputs.tuple_queries() {
        tuples.extend(records_from_sql(&outputs, &mut conn, query));
    }
    assert_eq!(
        tuples.len(),
        10,
        "every seeded share must produce a fact, or the encoding lost a row: {tuples:#?}"
    );

    // The write is where an unspellable name fails, and it fails the whole batch.
    let (_openfga, client) = start_openfga(&outputs.json_model(), &tuples).await;

    let mut allowed = 0usize;
    let mut denied = 0usize;
    for record in &tuples {
        assert!(
            support::openfga::check_allowed(
                &client,
                &record.subject,
                record.relation.as_str(),
                &record.object
            )
            .await,
            "the viewer a share names must reach it: {record:?}"
        );
        allowed += 1;

        // A stranger must not, or the encoding has collapsed two names into one. The
        // wildcard spelling is the one that would: an owner of `*` renders `user:*`
        // verbatim and grants everybody.
        assert!(
            !support::openfga::check_allowed(
                &client,
                "user:stranger",
                record.relation.as_str(),
                &record.object
            )
            .await,
            "nobody else may reach it: {record:?}"
        );
        denied += 1;
    }

    assert!(allowed > 0 && denied > 0, "the case has to cut both ways");
}

/// A schema whose naming is not the obvious one: two tables canonicalise alike, so one
/// takes a suffix, and a third is keyed by two columns.
const NAMING_SCHEMA: &str = "
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE a.notes (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE b.notes (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE parts (order_id TEXT, line_no INT, owner_id TEXT, PRIMARY KEY (order_id, line_no));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE a.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE b.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE parts ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON a.notes FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY q ON b.notes FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY r ON parts FOR SELECT USING (owner_id = auth_current_user_id());
";

/// Keys chosen for what the encoder has to survive: a separator inside a value, a space,
/// and a non-ASCII character, each of which the object name escapes rather than passes on.
const NAMING_SEED: &str = "
INSERT INTO a.notes (id, owner_id) VALUES ('n1', 'alice'), ('a|b', 'bob');
INSERT INTO b.notes (id, owner_id) VALUES ('n1', 'carol'), ('two words', 'dave');
INSERT INTO parts (order_id, line_no, owner_id) VALUES ('o|1', 2, 'alice'), ('\u{00e9}', 3, 'bob');
";

/// The name a row-naming entry renders is the name the table's own SQL writes.
///
/// A consumer asking the authorization service about one changed row spells the name from
/// the entry, and the store holds the names the generated SQL loaded. Derived apart, the
/// two can disagree on the collision suffix, on the key, or on the encoding, and every
/// question about that row would then be asked about nothing.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_row_naming_entry_spells_the_object_its_own_sql_writes() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(NAMING_SCHEMA)
        .expect("failed to apply the naming schema");
    conn.batch_execute(NAMING_SEED)
        .expect("failed to seed the naming schema");

    let (classified, db, registry) = support::classify_sql(NAMING_SCHEMA, Some(ACCESSOR));
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let naming = planned.translation().row_naming().to_vec();
    assert_eq!(
        naming.len(),
        3,
        "every guarded table is named, got {naming:?}"
    );
    // The case is only worth running while the naming is not the obvious one.
    assert!(
        naming
            .iter()
            .any(|entry| entry.type_name.as_str() != entry.table.name()
                && entry.type_name.as_str().contains('_')),
        "one table has to take a collision suffix: {naming:?}"
    );
    assert!(
        naming.iter().any(|entry| entry.key.parts().len() > 1),
        "one table has to be keyed by two columns: {naming:?}"
    );

    let queries = planned.tuple_queries();
    let written: BTreeSet<String> = queries
        .iter()
        .filter(|query| query.skipped.is_none())
        .flat_map(|query| records_from_sql(&planned, &mut conn, query))
        .map(|record| record.object)
        .collect();

    let mut compared = 0usize;
    for entry in naming {
        let rendered: BTreeSet<String> = rows_of(&mut conn, &entry.table)
            .iter()
            .filter_map(|row| {
                entry.render(&JsonRowValues(row)).unwrap_or_else(|error| {
                    panic!("a row of {} cannot be named: {error:?}", entry.table)
                })
            })
            .collect();
        let prefix = format!("{}:", entry.type_name);
        let mine: Vec<&String> = written
            .iter()
            .filter(|object| object.starts_with(&prefix))
            .collect();
        assert!(
            !mine.is_empty(),
            "the SQL wrote no object for {}, so the comparison is vacuous",
            entry.table
        );
        for object in mine {
            assert!(
                rendered.contains(object),
                "the SQL wrote {object} for {}, which the entry's key never renders: {rendered:?}",
                entry.table
            );
            compared += 1;
        }
    }

    // A naming that rendered nothing, or a seed that loaded nothing, would pass silently.
    assert_eq!(
        compared, 6,
        "every seeded row is named on both sides, compared {compared}"
    );
}

/// A partitioned root carrying the policy, with two partitions holding the rows.
///
/// The key spans the partitioning column because `PostgreSQL` refuses a primary key on a
/// partitioned table that does not.
const PARTITION_SCHEMA: &str = "
CREATE TABLE events (id TEXT, tenant TEXT, at DATE, PRIMARY KEY (id, at))
    PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE events_2027 PARTITION OF events FOR VALUES FROM ('2027-01-01') TO ('2028-01-01');
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON events FOR SELECT USING (tenant = auth_current_user_id());
";

/// One row per partition, so a naming that covered only the first would fail.
const PARTITION_SEED: &str = "
INSERT INTO events (id, tenant, at) VALUES
  ('e-1', 'alice', '2026-05-01'),
  ('e-2', 'bob', '2027-05-01');
";

/// A partition's rows are named after the root, and the root's own SQL writes exactly
/// those objects.
///
/// A change stream delivers the row at the partition while the policy and the tuples live
/// on the root, so the entry claims a partition's row is named `events:<key>`. If the
/// query minting the root's objects did not read the partitions, or keyed them
/// differently, every question about such a row would be asked about nothing.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_partition_is_named_by_the_object_its_root_s_sql_writes() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(PARTITION_SCHEMA)
        .expect("failed to apply the partitioned schema");
    conn.batch_execute(PARTITION_SEED)
        .expect("failed to seed the partitions");

    let (classified, db, registry) = support::classify_sql(PARTITION_SCHEMA, Some(ACCESSOR));
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let naming = planned.translation().row_naming().to_vec();

    let queries = planned.tuple_queries();
    let written: BTreeSet<String> = queries
        .iter()
        .filter(|query| query.skipped.is_none())
        .flat_map(|query| records_from_sql(&planned, &mut conn, query))
        .map(|record| record.object)
        .collect();

    let mut compared = 0usize;
    for partition in ["events_2026", "events_2027"] {
        let entry = naming
            .iter()
            .find(|entry| entry.table.name() == partition)
            .unwrap_or_else(|| panic!("no entry for {partition}, got {naming:?}"));
        assert_eq!(
            entry.type_name, "events",
            "a partition's rows are objects of its root"
        );
        let rows = rows_of(&mut conn, &entry.table);
        assert_eq!(rows.len(), 1, "each partition holds one seeded row");
        for row in &rows {
            let object = entry
                .render(&JsonRowValues(row))
                .expect("a partition row renders")
                .expect("every key column is filled");
            assert!(
                written.contains(&object),
                "the entry names {object} for {partition}, which the root's SQL never wrote: {written:?}"
            );
            compared += 1;
        }
    }

    // A naming that rendered nothing, or a seed that loaded nothing, would pass silently.
    assert_eq!(compared, 2, "both partitions are compared, not {compared}");
}

/// Two clauses spelled apart, which is the shape whose `UPDATE` the model answers with
/// two relations instead of one.
const REPLACEMENT_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    writer_user_id TEXT NOT NULL REFERENCES users(id),
    reviewer_user_id TEXT NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (writer_user_id = auth_current_user_id());
CREATE POLICY notes_write ON notes FOR UPDATE
    USING (writer_user_id = auth_current_user_id())
    WITH CHECK (reviewer_user_id = auth_current_user_id());
";

/// One row per way the two clauses can disagree, so a comparison that ignored one of
/// them still has a row to be wrong about.
const REPLACEMENT_SEED: &str = "
INSERT INTO users (id) VALUES ('alice'), ('bob');
INSERT INTO notes (id, writer_user_id, reviewer_user_id, body) VALUES
    ('both', 'alice', 'alice', 'x'),
    ('write-only', 'alice', 'bob', 'x'),
    ('review-only', 'bob', 'alice', 'x'),
    ('neither', 'bob', 'bob', 'x');
";

/// Asking every judgement the report names, and requiring all of them, has to answer as
/// the model's own relation does where the two row versions are the same row. That is
/// what says the report and the emitted model have not drifted apart.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn every_judgement_together_answers_as_the_action_relation_does() {
    let (_postgres, mut conn) = start_postgres().await;
    conn.batch_execute(REPLACEMENT_SCHEMA)
        .expect("failed to apply the replacement schema");
    conn.batch_execute(REPLACEMENT_SEED)
        .expect("failed to seed the replacement schema");

    let (classified, db, registry) = support::classify_sql(REPLACEMENT_SCHEMA, Some(ACCESSOR));
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let reported = planned.translation().action_relations();

    let mut tuples: BTreeSet<Record> = BTreeSet::new();
    for query in planned.tuple_queries() {
        tuples.extend(records_from_sql(&planned, &mut conn, query));
    }
    let (_openfga, client) = start_openfga(&planned.json_model(), &tuples).await;

    let update = reported
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "notes" && entry.statement == ActionStatement::Update
        })
        .expect("the guarded table answers for an UPDATE");
    let ActionAnswer::Judged(judges) = &update.answer else {
        panic!("a replacement is judged, got {:?}", update.answer);
    };
    let named: BTreeSet<&str> = judges.iter().map(|judge| judge.relation.as_str()).collect();
    assert_eq!(
        named,
        BTreeSet::from(["can_update_using", "can_update_check"]),
        "the case only tests anything while the two clauses are answered apart"
    );

    let mut agreed = 0usize;
    let mut granted = 0usize;
    let mut split_by_a_half = 0usize;
    let mut failures = Vec::new();
    for id in ["both", "write-only", "review-only", "neither"] {
        let object = format!("notes:{id}");
        for user in ["user:alice", "user:bob"] {
            let mut halves = Vec::new();
            for judge in judges {
                halves.push(
                    support::openfga::check_allowed(
                        &client,
                        user,
                        judge.relation.as_str(),
                        &object,
                    )
                    .await,
                );
            }
            let together = halves.iter().all(|granted| *granted);
            let whole = support::openfga::check_allowed(&client, user, "can_update", &object).await;
            if together != whole {
                failures.push(format!(
                    "{object} for {user}: the judgements answer {together}, can_update answers \
                     {whole}"
                ));
            }
            agreed += 1;
            granted += usize::from(whole);
            split_by_a_half += usize::from(halves.iter().any(|granted| *granted) && !together);
        }
    }

    assert!(
        failures.is_empty(),
        "the report and the model disagree:\n{}",
        failures.join("\n")
    );
    assert_eq!(agreed, 8, "every seeded row is asked about by both callers");
    assert!(
        granted > 0,
        "nothing is granted, so a report naming a denial for everything would pass"
    );
    assert!(
        split_by_a_half > 0,
        "no row is admitted by one half alone, so requiring either half would pass"
    );
}

/// Deleting a row does not withdraw the roles its scope admits.
///
/// The roles a policy admits are decided by the policy, so the fact survives the table
/// emptying. Described as following from a row instead, every row implied the same fact and
/// a consumer withdrawing what a deleted row implied removed the one thing every surviving
/// row still needs, which denies the whole table. That is invisible to a union oracle: the
/// union over the rows equals the query's result either way, and only the withdrawal
/// direction tells them apart.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_role_scope_keeps_its_roles_when_a_row_is_deleted() {
    let (_container, mut conn) = start_postgres().await;

    let schema = "
CREATE TABLE docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT TO auditor USING (TRUE);
";
    conn.batch_execute("CREATE ROLE auditor;")
        .expect("failed to create the role the clause names");
    conn.batch_execute(schema)
        .expect("failed to apply the role-scoped schema");
    conn.batch_execute(
        "
INSERT INTO docs (id, title) VALUES
    ('00000000-0000-0000-0000-0000000000d1', 'one'),
    ('00000000-0000-0000-0000-0000000000d2', 'two');
",
    )
    .expect("failed to seed the rows the scope judges");

    let (classified, db, registry) = support::classify_sql(schema, None);
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = outputs.tuple_queries();

    let role_fact = queries
        .iter()
        .find(|query| query.comment.contains("admits PostgreSQL role"))
        .expect("the scope admits a role, so a query carries it");
    let pointer = queries
        .iter()
        .find(|query| query.comment.contains("judged by the scope"))
        .expect("every row points at the scope that judges it");

    // The description says the fact is nobody's row, so no consumer can attribute it to
    // one: it names no table to arrive on, and asking for a row's records refuses.
    let description = role_fact
        .description
        .as_ref()
        .expect("the role fact is described");
    assert!(
        description.tables.is_empty(),
        "a constant reads no table, got {:?}",
        description.tables
    );
    assert!(
        matches!(&description.derivation, RecordDerivation::Constant { .. }),
        "the roles a policy admits follow from the policy, got {:?}",
        description.derivation
    );
    assert!(
        records_from_row(description, &EmptyRow).is_err(),
        "a row must not be able to claim the fact as its own"
    );

    assert_eq!(rows_returned(&mut conn, &role_fact.sql), 1);
    assert_eq!(rows_returned(&mut conn, &pointer.sql), 2);

    conn.batch_execute("DELETE FROM docs WHERE title = 'one';")
        .expect("failed to delete one of the judged rows");
    assert_eq!(
        rows_returned(&mut conn, &role_fact.sql),
        1,
        "the surviving row still needs the roles its scope admits"
    );
    assert_eq!(rows_returned(&mut conn, &pointer.sql), 1);

    conn.batch_execute("DELETE FROM docs;")
        .expect("failed to empty the guarded table");
    assert_eq!(
        rows_returned(&mut conn, &role_fact.sql),
        1,
        "the policy still admits the role with no row to judge, and the next insert needs \
         the fact already there"
    );
    assert_eq!(rows_returned(&mut conn, &pointer.sql), 0);
}

/// A row that answers nothing, for asking whether a description reads one at all.
struct EmptyRow;

impl RowValues for EmptyRow {
    fn cell(&self, _column: &str, _kind: ColumnKind) -> RowCell<'_> {
        RowCell::Absent
    }

    fn list(&self, _column: &str, _kind: ColumnKind) -> RowList<'_> {
        RowList::Absent
    }

    fn json_text(&self, _column: &str, _path: &[String]) -> RowCell<'_> {
        RowCell::Absent
    }
}

/// Row security filters a read by the policies of the relation the query names alone,
/// which is why the residual exemption asks only that relation's flag.
#[tokio::test]
#[ignore = "requires Docker: starts a PostgreSQL 18 container"]
async fn a_partition_is_filtered_by_the_relation_the_query_names() {
    let (_container, mut conn) = start_postgres().await;

    conn.batch_execute(
        "CREATE TABLE parted(id int, region text) PARTITION BY LIST (region); \
         CREATE TABLE parted_eu PARTITION OF parted FOR VALUES IN ('eu'); \
         CREATE TABLE inh_parent(id int, tag text); \
         CREATE TABLE inh_child(extra text) INHERITS (inh_parent); \
         INSERT INTO parted VALUES (1,'eu'),(2,'eu'); \
         INSERT INTO inh_parent VALUES (1,'a'); \
         INSERT INTO inh_child VALUES (2,'b','x'); \
         CREATE ROLE probe; \
         GRANT SELECT ON parted, parted_eu, inh_parent, inh_child TO probe;",
    )
    .expect("failed to build the inheritance shapes");

    let counted = |conn: &mut PgConnection, relation: &str| -> usize {
        let mut rows = 0;
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            conn.batch_execute("SET LOCAL ROLE probe")?;
            rows = rows_returned(conn, &format!("SELECT 1 FROM {relation}"));
            Err::<(), _>(diesel::result::Error::RollbackTransaction)
        })
        .ok();
        rows
    };

    // Guarding the ancestor. A query naming the descendant is unaffected by it.
    conn.batch_execute(
        "ALTER TABLE parted ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE inh_parent ENABLE ROW LEVEL SECURITY; \
         CREATE POLICY p_parted ON parted FOR SELECT USING (false); \
         CREATE POLICY p_inh ON inh_parent FOR SELECT USING (false);",
    )
    .expect("failed to guard the ancestors");
    assert_eq!(
        counted(&mut conn, "parted"),
        0,
        "the root's own policy filters a read naming the root"
    );
    assert_eq!(
        counted(&mut conn, "parted_eu"),
        2,
        "a read naming the partition is not filtered by the root's policy"
    );
    assert_eq!(
        counted(&mut conn, "inh_parent"),
        0,
        "the parent's own policy filters a read naming the parent"
    );
    assert_eq!(
        counted(&mut conn, "inh_child"),
        1,
        "a read naming the inheriting child is not filtered by the parent's policy"
    );

    // The mirror: guarding the descendant leaves a read naming the ancestor unfiltered,
    // so a relation whose own flag is off is open however its descendants are guarded.
    conn.batch_execute(
        "DROP POLICY p_parted ON parted; \
         DROP POLICY p_inh ON inh_parent; \
         ALTER TABLE parted DISABLE ROW LEVEL SECURITY; \
         ALTER TABLE inh_parent DISABLE ROW LEVEL SECURITY; \
         ALTER TABLE parted_eu ENABLE ROW LEVEL SECURITY; \
         ALTER TABLE inh_child ENABLE ROW LEVEL SECURITY; \
         CREATE POLICY p_eu ON parted_eu FOR SELECT USING (false); \
         CREATE POLICY p_child ON inh_child FOR SELECT USING (false);",
    )
    .expect("failed to guard the descendants");
    assert_eq!(
        counted(&mut conn, "parted"),
        2,
        "a read naming the root is not filtered by the partition's policy"
    );
    assert_eq!(
        counted(&mut conn, "inh_parent"),
        2,
        "a read naming the parent is not filtered by the child's policy"
    );
}
