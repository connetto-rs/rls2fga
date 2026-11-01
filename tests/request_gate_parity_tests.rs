//! Gates that read only the request, compared against `PostgreSQL` with both tuple
//! loaders, on a model carrying thirty gated tables, and the local recipe compared with
//! both.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::fmt::Write;
use core::time::Duration;

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::{records_from_row, ActionStatement, ConfidenceLevel, RowDecision};

mod support;

use support::footgun::{db_of, gated_tables, OPEN_PLUS_CAP_BOT_LIST_GATES};
use support::parity::{
    assert_agrees, assert_postgres, request_predicate_holds, Cluster, Mutations, ParityCase,
    Principal,
};
use support::JsonRowValues;

const ATTRIBUTES: &str = r#"[
    { "key": "app.user_id", "kind": "caller_id" },
    { "key": "app.bot_list", "kind": "set_attribute" }
]"#;

/// Gated tables in the model. Over the 25 conditions `OpenFGA` accepts, had each gate
/// declared its own.
const TABLES: usize = 30;

/// A caller owning one row of every table, holding `entries` in its list or no list at
/// all.
fn caller(subject: &str, entries: Option<&[&str]>) -> Principal {
    let mut principal = Principal::with_setting(subject, "app_rw", "app.user_id", subject)
        .with_context(serde_json::json!({ "app_bot_list": entries.unwrap_or_default() }));
    if let Some(entries) = entries {
        principal
            .session
            .push(("app.bot_list".into(), entries.join(",")));
    }
    principal
}

fn callers() -> Vec<Principal> {
    vec![
        caller(
            "entry",
            Some(&["t0:read", "t0:insert", "t0:update", "t0:delete"]),
        ),
        caller("star", Some(&["*"])),
        caller("neither", Some(&["t1:read", "t0:reads"])),
        caller("unset", None),
    ]
}

fn case(name: &str) -> ParityCase {
    let tables: Vec<String> = (0..TABLES).map(|index| format!("t{index}")).collect();
    let rows = tables.iter().fold(String::new(), |mut rows, table| {
        let _ = writeln!(
            rows,
            "INSERT INTO {table} VALUES ('entry', 'entry'), ('star', 'star'), \
             ('neither', 'neither'), ('unset', 'unset');"
        );
        rows
    });
    let mut case = ParityCase::reading(
        name,
        &gated_tables(TABLES),
        &[
            &rows,
            &format!(
                "CREATE ROLE app_rw LOGIN;
                 GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO app_rw",
                tables.join(", ")
            ),
        ],
        callers(),
    )
    .with_attributes(ATTRIBUTES);
    for table in ["t0", "t1"] {
        case = case.writing(
            table,
            Mutations {
                update_set: Some("owner = owner".to_string()),
                check_neutral: true,
            },
        );
    }
    case
}

/// Whether the recipe grants `subject` on `row` for a check carrying `context`.
fn recipe_allows(
    decision: &RowDecision,
    row: &serde_json::Value,
    subject: &str,
    context: &serde_json::Value,
) -> bool {
    match decision {
        RowDecision::Leaf { shapes, .. } => shapes.iter().any(|shape| {
            records_from_row(shape, &JsonRowValues(row))
                .expect("a leaf resolves from the row")
                .iter()
                .any(|record| record.subject == format!("user:{subject}"))
        }),
        RowDecision::Any(children) => children
            .iter()
            .any(|child| recipe_allows(child, row, subject, context)),
        RowDecision::All(children) => children
            .iter()
            .all(|child| recipe_allows(child, row, subject, context)),
        RowDecision::Request {
            shapes,
            subject_type,
            predicate,
            ..
        } => {
            subject_type.as_str() == "user"
                && shapes.iter().any(|shape| {
                    !records_from_row(shape, &JsonRowValues(row))
                        .expect("the link resolves from the row")
                        .is_empty()
                })
                && request_predicate_holds(predicate, context)
        }
        other => panic!("a recipe shape this gate does not produce: {other:?}"),
    }
}

/// The recipe `t0#can_select` reports, read without a round trip.
fn select_recipe() -> RowDecision {
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.bot_list", SessionAttributeKind::SetAttribute),
        ])
        .build()
        .translate(&db_of(&gated_tables(TABLES)))
        .expect("translation should plan")
        .outputs()
        .expect("every clause translates");
    outputs
        .translation()
        .relations()
        .iter()
        .find(|entry| entry.type_name.as_str() == "t0" && entry.relation.as_str() == "can_select")
        .and_then(|entry| entry.decision.clone())
        .expect("the row and the request decide t0#can_select")
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn request_gate_parity() {
    let cluster = Cluster::start().await;
    for from_rows in [false, true] {
        let mut case = case(if from_rows { "gates-rows" } else { "gates" });
        case.loading_from_rows = from_rows;
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(300)).await;
        for (subject, object, allowed) in [
            ("entry", "t0:entry", true),
            ("entry", "t1:entry", false),
            ("star", "t0:star", true),
            ("star", "t29:star", true),
            ("neither", "t0:neither", false),
            ("unset", "t0:unset", false),
            ("star", "t0:entry", false),
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
        // `assert_agrees` holds `OpenFGA` to `PostgreSQL`, so a recipe answering as
        // `PostgreSQL` does answers as `OpenFGA` too.
        let recipe = select_recipe();
        for principal in callers() {
            for owner in ["entry", "star", "neither", "unset"] {
                let row = serde_json::json!({ "id": owner, "owner": owner });
                assert_postgres(
                    &case,
                    &run,
                    &principal.subject,
                    &format!("t0:{owner}"),
                    ActionStatement::Select,
                    recipe_allows(&recipe, &row, &principal.subject, &principal.context),
                );
            }
        }
        assert_agrees(&case, &run);
    }
}

/// A grant whose residual compares against aggregates over two tables the request gates,
/// the share table the membership reads and a second table only the residual reads.
fn gated_aggregate_schema() -> String {
    format!(
        "
CREATE TABLE papers (id TEXT PRIMARY KEY);
CREATE TABLE paper_shares (paper_id TEXT REFERENCES papers(id), viewer TEXT, weight NUMERIC,
                           PRIMARY KEY (paper_id, viewer));
CREATE TABLE tiers (id TEXT PRIMARY KEY, cutoff NUMERIC);

ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY paper_read ON papers FOR SELECT USING (
    EXISTS (SELECT 1 FROM paper_shares s
            WHERE s.paper_id = papers.id
              AND s.viewer = current_setting('app.user_id', true)
              AND s.weight > (SELECT avg(weight) FROM paper_shares)
              AND s.weight > (SELECT max(cutoff) FROM tiers)));
{OPEN_PLUS_CAP_BOT_LIST_GATES}"
    )
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn gated_aggregate_parity() {
    let cluster = Cluster::start().await;
    let viewers: [(&str, Option<&[&str]>); 5] = [
        ("both", Some(&["paper_shares:read", "tiers:read"])),
        ("shares", Some(&["paper_shares:read"])),
        ("tiers", Some(&["tiers:read"])),
        ("star", Some(&["*"])),
        ("unset", None),
    ];
    // Each viewer holds one share above both the average (5.5) and the cutoff (5), and one
    // below them.
    let rows = viewers.iter().fold(String::new(), |mut rows, (viewer, _)| {
        let _ = writeln!(
            rows,
            "INSERT INTO papers VALUES ('{viewer}-hi'), ('{viewer}-lo');
             INSERT INTO paper_shares VALUES ('{viewer}-hi', '{viewer}', 10),
                                             ('{viewer}-lo', '{viewer}', 1);"
        );
        rows
    });
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            if from_rows {
                "aggregates-rows"
            } else {
                "aggregates"
            },
            &gated_aggregate_schema(),
            &[
                &format!("{rows}INSERT INTO tiers VALUES ('gold', 5);"),
                "CREATE ROLE app_rw LOGIN;
                 GRANT SELECT ON papers, paper_shares, tiers TO app_rw",
            ],
            viewers
                .iter()
                .map(|(viewer, entries)| caller(viewer, *entries))
                .collect(),
        )
        .with_attributes(ATTRIBUTES);
        case.loading_from_rows = from_rows;
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(300)).await;
        for (subject, object, allowed) in [
            ("both", "papers:both-hi", true),
            ("both", "papers:both-lo", false),
            ("star", "papers:star-hi", true),
            // `tiers` reads empty, so `max(cutoff)` is `NULL` and no share passes.
            ("shares", "papers:shares-hi", false),
            // `paper_shares` reads empty, so no membership exists.
            ("tiers", "papers:tiers-hi", false),
            ("unset", "papers:unset-hi", false),
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
        assert_agrees(&case, &run);
    }
}
