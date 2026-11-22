//! Recipes under request-only gates, answered locally and compared against `PostgreSQL`
//! and `OpenFGA` for one set of callers.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;

use crate::support;

use crate::support::deployment;
use crate::support::parity::{
    assert_agrees, assert_postgres, ClauseKind, Cluster, ParityCase, Principal, Side,
};

/// The four gates connetto puts on every synced table, one per command.
fn gates(table: &str) -> String {
    let list = "string_to_array(current_setting('app.bot_list', true), ',')";
    let clause = |verb: &str| format!("'{table}:{verb}' = ANY({list}) OR '*' = ANY({list})");
    format!(
        "CREATE POLICY {table}_cap_read ON {table} AS RESTRICTIVE FOR SELECT USING ({read});
CREATE POLICY {table}_cap_insert ON {table} AS RESTRICTIVE FOR INSERT WITH CHECK ({insert});
CREATE POLICY {table}_cap_update ON {table} AS RESTRICTIVE FOR UPDATE
    USING ({update}) WITH CHECK ({update});
CREATE POLICY {table}_cap_delete ON {table} AS RESTRICTIVE FOR DELETE USING ({delete});
",
        read = clause("read"),
        insert = clause("insert"),
        update = clause("update"),
        delete = clause("delete"),
    )
}

/// `orders` is open to everybody, `capped` has the gates and nothing else, `notes` is
/// owned by a column and `flagged` is public where its flag holds.
fn schema() -> String {
    format!(
        "
CREATE TABLE orders (id INT PRIMARY KEY, quantity BIGINT NOT NULL);
CREATE TABLE capped (id INT PRIMARY KEY);
CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE flagged (id INT PRIMARY KEY, is_public BOOLEAN NOT NULL);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE capped ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE flagged ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_open ON orders FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY notes_own ON notes FOR ALL USING (owner = current_setting('app.user_id', true));
CREATE POLICY flagged_public ON flagged FOR SELECT USING (is_public);
{}{}{}{}",
        gates("orders"),
        gates("capped"),
        gates("notes"),
        gates("flagged"),
    )
}

const SEED: &str = "
INSERT INTO orders VALUES (1, 10), (2, 20);
INSERT INTO capped VALUES (1), (2);
INSERT INTO flagged VALUES (1, true), (2, false);
INSERT INTO notes VALUES (1, 'entry'), (2, 'wild'), (3, 'neither'), (4, 'unset'), (5, NULL), (6, 'reader');
";

fn callers() -> Vec<Principal> {
    let entries = [
        "orders:read",
        "orders:delete",
        "capped:read",
        "capped:delete",
        "notes:read",
        "notes:delete",
        "flagged:read",
        "flagged:delete",
    ];
    vec![
        Principal::with_bot_list("entry", Some(&entries)),
        Principal::with_bot_list("wild", Some(&["*"])),
        Principal::with_bot_list("neither", Some(&["orders:insert", "notes:update"])),
        Principal::with_bot_list("unset", None),
        Principal::with_bot_list(
            "reader",
            Some(&["orders:read", "capped:read", "notes:read", "flagged:read"]),
        ),
    ]
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_request_gated_table_is_answered_locally_as_the_database_answers() {
    let schema = schema();
    let mut case = ParityCase::reading(
        "request-gate-recipes",
        &schema,
        &[
            SEED,
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT, INSERT, UPDATE, DELETE ON orders, capped, notes, flagged TO app_reader",
        ],
        callers(),
    )
    .with_settings([deployment::delimited_set("app.bot_list", ",")])
    .updating("orders", "quantity = quantity")
    .updating("notes", "owner = owner");
    for table in ["capped", "flagged"] {
        for (command, clause) in [
            ("read", ClauseKind::Using),
            ("insert", ClauseKind::Check),
            ("update", ClauseKind::Using),
            ("update", ClauseKind::Check),
            ("delete", ClauseKind::Using),
        ] {
            if table == "flagged" && command == "read" {
                continue;
            }
            for side in [Side::Grants, Side::Denies] {
                case = case.unobservable(
                    table,
                    &format!("{table}_cap_{command}"),
                    clause,
                    side,
                    "No permissive policy admits this command, regardless of the restrictive gate.",
                );
            }
        }
    }
    for table in ["orders", "notes"] {
        case = case.unobservable(
            table,
            &format!("{table}_cap_update"),
            ClauseKind::Check,
            Side::Denies,
            "The identical request-only `USING` gate rejects every row before `WITH CHECK`.",
        );
    }

    let cluster = Cluster::start().await;
    for from_rows in [false, true] {
        case.loading_from_rows = from_rows;
        if from_rows {
            case.name.push_str("-rows");
        }
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(120)).await;
        assert_agrees(&case, &run);
        for (subject, object, allowed) in [
            ("entry", "orders:1", true),
            ("wild", "orders:1", true),
            ("neither", "orders:1", false),
            ("unset", "orders:1", false),
            ("wild", "capped:1", false),
            ("entry", "notes:1", true),
            ("wild", "notes:2", true),
            ("wild", "notes:1", false),
            ("neither", "notes:3", false),
            ("unset", "notes:4", false),
            ("wild", "flagged:1", true),
            ("wild", "flagged:2", false),
            ("neither", "flagged:1", false),
        ] {
            assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                allowed,
            );
        }

        let mut compared = 0usize;
        let mut failures = Vec::new();
        for observation in &run.observations {
            let local = observation
                .local
                .unwrap_or_else(|| panic!("{observation} is not answered locally"));
            compared += 1;
            if local != observation.postgres {
                failures.push(format!("{observation}: the recipe answers {local}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{}: the recipe and the database disagree:\n{}",
            case.name,
            failures.join("\n")
        );
        assert!(
            compared >= 60,
            "{}: too few local answers compared, saw {compared}",
            case.name
        );
    }
}
