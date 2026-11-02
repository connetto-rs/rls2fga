#![cfg(not(target_os = "windows"))]
//! `pg_dump` preserves model and tuple semantics under consistent source-relation renaming.

use serde_json::Value;
use std::collections::BTreeSet;

use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::sql_types::Text;
use testcontainers::core::{CmdWaitFor, ExecCommand};
use testcontainers::{ContainerAsync, GenericImage};

use rls2fga::generator::tuple_generator::TupleQuery;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

use crate::support;

use crate::support::model_equivalence;

use crate::support::containers::{connect_postgres_with_retry, PG_DB, PG_PASSWORD, PG_USER};

/// Fixtures whose dump cannot parse yet, each waiting on a named sqlparser
/// gap. An entry whose dump starts parsing fails the run, which is the signal
/// to promote it into the round trip.
const DUMP_BLOCKED_ON_SQLPARSER: [(&str, &str); 2] = [
    (
        "current_user_equality",
        "a SERIAL key dumps as CREATE SEQUENCE options in an order sqlparser #2414 \
         refuses, and as ALTER SEQUENCE, which is not an ALTER target upstream at all",
    ),
    (
        "schema_objects",
        "the declared type dumps as ALTER TYPE ... OWNER TO, and OWNER TO is gated to \
         the table target upstream, the unfiled owner-to-uneven finding",
    ),
];
/// Roles fixture policies name in `TO` clauses, which must exist before
/// `CREATE POLICY` runs.
const FIXTURE_ROLES: [&str; 4] = ["auditor", "contractor", "editors", "app"];

/// Roles a fixture creates itself, which must be absent when it applies.
const CREATES_ROLES: [(&str, &str); 1] = [("schema_objects", "auditor")];

/// The model and tuple queries planned with the fixture's registry.
fn artifacts(db: &ParserDB, fixture: &str) -> (Value, Vec<TupleQuery>) {
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry(support::try_load_fixture_registry(fixture))
        .build()
        .translate(db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries().to_vec();
    (
        serde_json::to_value(outputs.json_model()).expect("the model should serialize"),
        tuples,
    )
}

#[derive(QueryableByName, PartialEq, Eq, PartialOrd, Ord)]
struct TupleRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
}

/// Every `(object, relation, subject)` the queries return against the live
/// schema. Two spellings of one schema must return one set.
fn executed_rows(
    conn: &mut PgConnection,
    queries: &[TupleQuery],
) -> BTreeSet<(String, String, String)> {
    let mut keys = BTreeSet::new();
    for query in queries {
        // The generated SQL is the artifact under test, so it runs verbatim.
        let rows: Vec<TupleRow> =
            diesel::sql_query(&query.sql)
                .load(conn)
                .unwrap_or_else(|error| {
                    panic!("tuple SQL failed on PostgreSQL 18: {error}\n{}", query.sql)
                });
        keys.extend(
            rows.into_iter()
                .map(|row| (row.object, row.relation, row.subject)),
        );
    }
    keys
}

/// `pg_dump -s` of one database, run inside the server's own container so the
/// client version always matches the server's.
async fn dump_schema(container: &ContainerAsync<GenericImage>, database: &str) -> String {
    let mut result = container
        .exec(
            ExecCommand::new(["pg_dump", "--schema-only", "-U", PG_USER, database])
                .with_cmd_ready_condition(CmdWaitFor::exit()),
        )
        .await
        .expect("pg_dump should run inside the container");
    let stdout = result
        .stdout_to_vec()
        .await
        .expect("pg_dump output should be readable");
    String::from_utf8(stdout).expect("pg_dump emits UTF-8")
}

/// Drop the psql meta-commands a dump carries (`\restrict`, `\unrestrict`,
/// `\connect`), which are commands to psql rather than SQL.
fn strip_meta_commands(dump: &str) -> String {
    dump.lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
#[ignore = "requires Docker and the postgres:18 container"]
async fn every_fixture_round_trips_through_pg_dump() {
    let postgres = support::containers::start_postgres().await;
    let pg_port = postgres.get_host_port_ipv4(5432).await.unwrap();
    let admin_url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{PG_DB}");
    let mut admin = connect_postgres_with_retry(&admin_url);

    let mut failures = Vec::new();
    for fixture in support::fixture_names() {
        let fixture = fixture.as_str();
        // A fixture that creates a role itself must find it absent, and every
        // other fixture must find the shared roles present. Databases are
        // dropped after use, so the drop below never has dependents.
        for role in FIXTURE_ROLES {
            let owned_by_fixture = CREATES_ROLES
                .iter()
                .any(|(name, owned)| *name == fixture && *owned == role);
            let statement = if owned_by_fixture {
                format!("DROP ROLE IF EXISTS {role}")
            } else {
                format!(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = \
                     '{role}') THEN CREATE ROLE {role}; END IF; END $$"
                )
            };
            admin
                .batch_execute(&statement)
                .expect("Failed to prepare a fixture role");
        }
        let database = format!("rt_{fixture}");
        admin
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .expect("Failed to create a fixture database");
        let fixture_url =
            format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{pg_port}/{database}");
        let mut conn = connect_postgres_with_retry(&fixture_url);
        // The Supabase fixtures declare functions under `auth` without creating it,
        // exactly as their deployments find it already present.
        conn.batch_execute("CREATE SCHEMA IF NOT EXISTS auth")
            .expect("Failed to create the auth schema");

        if let Err(error) = conn.batch_execute(&support::read_fixture_sql(fixture)) {
            failures.push(format!(
                "{fixture}: failed to apply on PostgreSQL 18: {error}"
            ));
            continue;
        }

        let dump = format!(
            "CREATE ROLE {PG_USER};\n{}",
            strip_meta_commands(&dump_schema(&postgres, &database).await)
        );
        let parsed = parse_schema(&dump);
        let verdict = if let Some((_, reason)) = DUMP_BLOCKED_ON_SQLPARSER
            .iter()
            .find(|(name, _)| *name == fixture)
        {
            match parsed {
                Err(_) => None,
                Ok(_) => Some(format!(
                    "{fixture}: its dump now parses, so promote it into the round \
                     trip (was blocked: {reason})"
                )),
            }
        } else {
            match parsed {
                Err(error) => Some(format!("{fixture}: its dump does not parse: {error}")),
                Ok(dumped_db) => {
                    let fixture_db = support::parse_fixture_db(fixture);
                    let (fixture_model, fixture_tuples) = artifacts(&fixture_db, fixture);
                    let (dump_model, dump_tuples) = artifacts(&dumped_db, fixture);
                    let fixture_rows = executed_rows(&mut conn, &fixture_tuples);
                    let dump_rows = executed_rows(&mut conn, &dump_tuples);
                    if model_equivalence::equivalent(
                        &fixture_model,
                        &fixture_rows,
                        &dump_model,
                        &dump_rows,
                    ) {
                        None
                    } else {
                        Some(format!("{fixture}: the dumped model or tuple rows diverge"))
                    }
                }
            }
        };
        failures.extend(verdict);
        drop(conn);
        admin
            .batch_execute(&format!("DROP DATABASE {database}"))
            .expect("Failed to drop a fixture database");
    }

    assert!(
        failures.is_empty(),
        "pg_dump round trip divergences:\n{}",
        failures.join("\n")
    );
}
