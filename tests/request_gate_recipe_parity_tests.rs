//! Recipes under request-only gates, answered locally and compared against `PostgreSQL`
//! and `OpenFGA` for one set of callers.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;
use std::collections::BTreeMap;

use rls2fga::types::{
    records_from_row, ActionAnswer, ActionStatement, ConfidenceLevel, RelationShapes,
    RequestComparison, RowDecision,
};

mod support;

use support::parity::{
    assert_agrees, assert_postgres, request_predicate_holds, Cluster, ParityCase, Principal,
};
use support::JsonRowValues;

const ATTRIBUTES: &str = r#"[
    { "key": "app.user_id", "kind": "caller_id" },
    { "key": "app.bot_list", "kind": "set_attribute" }
]"#;

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

/// Every row of the seed, keyed by the object the model names it as.
fn rows() -> BTreeMap<String, serde_json::Value> {
    let mut rows = BTreeMap::new();
    for id in [1, 2] {
        rows.insert(
            format!("orders:{id}"),
            serde_json::json!({ "id": id, "quantity": id * 10 }),
        );
        rows.insert(format!("capped:{id}"), serde_json::json!({ "id": id }));
        rows.insert(
            format!("flagged:{id}"),
            serde_json::json!({ "id": id, "is_public": id == 1 }),
        );
    }
    for (id, owner) in [
        (1, Some("entry")),
        (2, Some("wild")),
        (3, Some("neither")),
        (4, Some("unset")),
        (5, None),
    ] {
        rows.insert(
            format!("notes:{id}"),
            serde_json::json!({ "id": id, "owner": owner }),
        );
    }
    rows
}

const SEED: &str = "
INSERT INTO orders VALUES (1, 10), (2, 20);
INSERT INTO capped VALUES (1), (2);
INSERT INTO flagged VALUES (1, true), (2, false);
INSERT INTO notes VALUES (1, 'entry'), (2, 'wild'), (3, 'neither'), (4, 'unset'), (5, NULL);
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
    ]
}

/// Whether `decision` grants `subject` on `row`, completing request gates from `context`.
///
/// The consumer's whole evaluation, written from the contract alone.
fn grants(
    decision: &RowDecision,
    row: &serde_json::Value,
    subject: &str,
    context: &serde_json::Value,
) -> bool {
    let records = |shapes: &[rls2fga::types::RecordDescription]| -> Vec<rls2fga::types::Record> {
        shapes
            .iter()
            .flat_map(|shape| {
                records_from_row(shape, &JsonRowValues(row)).expect("every seeded row is named")
            })
            .collect()
    };
    match decision {
        RowDecision::Leaf { shapes, .. } => records(shapes)
            .iter()
            .any(|record| record.subject == format!("user:{subject}")),
        RowDecision::Everyone { shapes, .. } => !records(shapes).is_empty(),
        RowDecision::RequestGated {
            shapes,
            context_key,
            request_parameter,
            comparison,
            ..
        } => records(shapes).iter().any(|record| {
            let row_side = &record
                .context
                .as_ref()
                .expect("a gated record carries its context")
                .values[context_key];
            let caller_side = &context[request_parameter.as_str()];
            match comparison {
                RequestComparison::CallerSetHolds => caller_side
                    .as_array()
                    .is_some_and(|held| held.iter().any(|value| value == row_side.as_str())),
                RequestComparison::CallerValueEquals => caller_side == row_side.as_str(),
            }
        }),
        RowDecision::Request {
            shapes,
            subject_type,
            predicate,
            ..
        } => {
            subject_type.as_str() == "user"
                && !records(shapes).is_empty()
                && request_predicate_holds(predicate, context)
        }
        RowDecision::Any(children) => children
            .iter()
            .any(|child| grants(child, row, subject, context)),
        RowDecision::All(children) => children
            .iter()
            .all(|child| grants(child, row, subject, context)),
    }
}

fn recipe<'a>(relations: &'a [RelationShapes], type_name: &str, relation: &str) -> &'a RowDecision {
    relations
        .iter()
        .find(|entry| entry.type_name.as_str() == type_name && entry.relation == relation)
        .and_then(|entry| entry.decision.as_ref())
        .unwrap_or_else(|| panic!("{type_name}#{relation} has no recipe, so it costs a round trip"))
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
             GRANT SELECT, DELETE ON orders, capped, notes, flagged TO app_reader",
        ],
        callers(),
    )
    .with_attributes(ATTRIBUTES);

    let (classified, db, registry) =
        support::classify_sql_with_session_attributes(&schema, ATTRIBUTES);
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let translation = planned.translation();
    let rows = rows();
    let contexts: BTreeMap<String, serde_json::Value> = callers()
        .into_iter()
        .map(|principal| (principal.subject, principal.context))
        .collect();

    let cluster = Cluster::start().await;
    for from_rows in [false, true] {
        case.loading_from_rows = from_rows;
        if from_rows {
            case.name.push_str("-rows");
        }
        let run = tokio::time::timeout(
            Duration::from_secs(120),
            support::parity::run(&cluster, &case),
        )
        .await
        .unwrap_or_else(|_| panic!("{} exceeded its parity deadline", case.name));
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
            let Some(row) = rows.get(&observation.object) else {
                continue;
            };
            let (type_name, _) = observation
                .object
                .split_once(':')
                .expect("an object is type:key");
            let answer = translation
                .action_relations()
                .iter()
                .find(|entry| {
                    entry.type_name.as_str() == type_name
                        && entry.statement == observation.statement
                })
                .map(|entry| &entry.answer);
            let local = match answer {
                Some(ActionAnswer::Judged(judges)) if !judges.is_empty() => {
                    judges.iter().all(|judge| {
                        grants(
                            recipe(translation.relations(), type_name, judge.relation.as_str()),
                            row,
                            &observation.subject,
                            &contexts[&observation.subject],
                        )
                    })
                }
                Some(ActionAnswer::Denied) => false,
                other => panic!(
                    "{} {:?} is not answered locally: {other:?}",
                    observation.object, observation.statement
                ),
            };
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
