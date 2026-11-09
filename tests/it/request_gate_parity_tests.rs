//! Gates that read only the request, compared against `PostgreSQL` with both tuple
//! loaders, on a model carrying thirty gated tables, and the local recipe compared with
//! both.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::fmt::Write;
use core::time::Duration;

use rls2fga::classifier::function_registry::DeclaredSources;
use rls2fga::parser::sql_parser::SettingValue;
use rls2fga::types::{records_from_row, ActionStatement, ConfidenceLevel, RowDecision};
use sqlparser::ast::DataType;

use crate::support;

use crate::support::deployment;
use crate::support::footgun::{gated_tables, OPEN_PLUS_CAP_BOT_LIST_GATES};
use crate::support::parity::{
    assert_agrees, assert_postgres, request_predicate_holds, settings_map, Cluster, Mutations,
    ParityCase, Principal,
};
use crate::support::JsonRowValues;

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
    .with_settings([deployment::delimited_set("app.bot_list", ",")]);
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

/// Whether the recipe grants `subject` on `row` for a check carrying `context` and
/// acting as `acting_role`, the role the check's kind names.
fn recipe_allows(
    decision: &RowDecision,
    row: &serde_json::Value,
    subject: &str,
    context: &serde_json::Value,
    acting_role: &str,
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
            .any(|child| recipe_allows(child, row, subject, context, acting_role)),
        RowDecision::All(children) => children
            .iter()
            .all(|child| recipe_allows(child, row, subject, context, acting_role)),
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
                && request_predicate_holds(predicate, context, acting_role)
        }
        other => panic!("a recipe shape this gate does not produce: {other:?}"),
    }
}

/// The deployment the harness checks the gates with, acting as the caller's login role.
fn gate_deployment() -> rls2fga::parser::sql_parser::Deployment {
    deployment::caller_deployment_acting_as(
        &["app_rw"],
        [deployment::delimited_set("app.bot_list", ",")],
    )
}

/// A snapshot of the caller's check context with the harness' `settings` map merged in,
/// the value the local recipe reads the gates from.
fn with_settings_map(sources: &DeclaredSources, principal: &Principal) -> serde_json::Value {
    let mut context = principal.context.clone();
    if let Some(entries) = context.as_object_mut() {
        entries.insert("settings".to_string(), settings_map(sources, principal));
    }
    context
}

/// The recipe `t0#can_select` reports, read without a round trip, for the deployment the
/// harness checks with: acting as the caller's login role.
fn select_recipe() -> RowDecision {
    let deployment = gate_deployment();
    // The role the harness creates in its seed, so the deployment resolves against it.
    let sql = format!("CREATE ROLE app_rw LOGIN;\n{}", gated_tables(TABLES));
    let (classified, db, registry) = support::classify_with(&sql, None, &deployment);
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    planned
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
        let sources = DeclaredSources::of(&gate_deployment());
        for principal in callers() {
            let context = with_settings_map(&sources, &principal);
            for owner in ["entry", "star", "neither", "unset"] {
                let row = serde_json::json!({ "id": owner, "owner": owner });
                assert_postgres(
                    &case,
                    &run,
                    &principal.subject,
                    &format!("t0:{owner}"),
                    ActionStatement::Select,
                    recipe_allows(
                        &recipe,
                        &row,
                        &principal.subject,
                        &context,
                        &principal.login_role,
                    ),
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
        .with_settings([deployment::delimited_set("app.bot_list", ",")]);
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

/// A caller holding `tier` and `mode` in its session, either one left out where the
/// request leaves the setting unset.
fn scalar_caller(subject: &str, tier: Option<&str>, mode: Option<&str>) -> Principal {
    let mut principal = Principal::as_role(subject, "app_reader");
    if let Some(tier) = tier {
        principal.session.push(("app.tier".into(), tier.into()));
    }
    if let Some(mode) = mode {
        principal.session.push(("app.mode".into(), mode.into()));
    }
    principal
}

/// A row value and a formula each read one declared value the request may leave unset,
/// the formula among them comparing the value with the empty reading, which only a
/// setting sent as `''` makes true. `PostgreSQL` 18 and `OpenFGA` agree in all three
/// states, the value set, set to `''` and unset.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn scalar_setting_parity() {
    let cluster = Cluster::start().await;
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            if from_rows {
                "scalar-setting-rows"
            } else {
                "scalar-setting"
            },
            "CREATE TABLE tiered_docs(id TEXT PRIMARY KEY, tier TEXT);
             ALTER TABLE tiered_docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY tiered_read ON tiered_docs FOR SELECT USING (
                 tier = current_setting('app.tier', true));
             CREATE TABLE modes(id TEXT PRIMARY KEY);
             ALTER TABLE modes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY empty_mode ON modes FOR SELECT USING (
                 current_setting('app.mode', true) = '');
             CREATE POLICY main_mode ON modes FOR SELECT USING (
                 current_setting('app.mode', true) = 'main');",
            &[
                "INSERT INTO tiered_docs VALUES ('gold-row', 'gold'), ('empty-row', '');",
                "INSERT INTO modes VALUES ('m1');",
                "CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON tiered_docs, modes TO app_reader",
            ],
            vec![
                scalar_caller("gold", Some("gold"), Some("main")),
                scalar_caller("empty", Some(""), Some("")),
                scalar_caller("unset", None, None),
                scalar_caller("other", Some("bronze"), Some("other")),
            ],
        )
        .with_settings([
            deployment::scalar("app.tier"),
            deployment::scalar("app.mode"),
        ]);
        case.loading_from_rows = from_rows;
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(120)).await;
        for (subject, object, allowed) in [
            // The value set admits its own reading.
            ("gold", "tiered_docs:gold-row", true),
            ("gold", "tiered_docs:empty-row", false),
            ("gold", "modes:m1", true),
            // The value set to `''` admits the `''` reading and no other.
            ("empty", "tiered_docs:empty-row", true),
            ("empty", "tiered_docs:gold-row", false),
            ("empty", "modes:m1", true),
            // The setting unset is an absent key, which admits nothing.
            ("unset", "tiered_docs:gold-row", false),
            ("unset", "tiered_docs:empty-row", false),
            ("unset", "modes:m1", false),
            // A value neither arm reads admits nothing.
            ("other", "tiered_docs:gold-row", false),
            ("other", "modes:m1", false),
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

/// A caller holding `value` in both the bare setting and the JSON field, or neither where
/// the request leaves the setting unset.
fn mode_caller(subject: &str, value: Option<&str>) -> Principal {
    let mut principal = Principal::as_role(subject, "app_reader");
    if let Some(value) = value {
        principal.session.push(("app.mode".into(), value.into()));
        principal.session.push((
            "request.jwt.claims".into(),
            format!(r#"{{"mode":"{value}"}}"#),
        ));
    }
    principal
}

/// Eight gates read one declared scalar value the request may leave unset, the bare
/// `app.mode` and the `request.jwt.claims` field `mode` each four ways, by `<>`, `IN`,
/// `= ANY` and `NOT IN` against literals. `PostgreSQL` 18 and `OpenFGA` agree in all four
/// states, the value set to a listed value, to another value, to `''`, and unset, and the
/// local recipe agrees with both.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn setting_operator_parity() {
    const INSERTS: &str = "INSERT INTO m_neq VALUES ('r1');
        INSERT INTO m_in VALUES ('r1');
        INSERT INTO m_any VALUES ('r1');
        INSERT INTO m_notin VALUES ('r1');
        INSERT INTO j_neq VALUES ('r1');
        INSERT INTO j_in VALUES ('r1');
        INSERT INTO j_any VALUES ('r1');
        INSERT INTO j_notin VALUES ('r1');";
    let cluster = Cluster::start().await;
    // Each table is one operator over one source, the bare setting and the JSON field.
    let operators = [
        ("neq", "<> 'main'"),
        ("in", "IN ('main', 'dev')"),
        ("any", "= ANY (ARRAY['main', 'dev'])"),
        ("notin", "NOT IN ('main', 'dev')"),
    ];
    let mut schema = String::new();
    let mut grants = String::new();
    for (prefix, source) in [
        ("m", "current_setting('app.mode', true)"),
        (
            "j",
            "current_setting('request.jwt.claims', true)::jsonb ->> 'mode'",
        ),
    ] {
        for (suffix, operator) in operators {
            let table = format!("{prefix}_{suffix}");
            let _ = writeln!(
                schema,
                "CREATE TABLE {table}(id TEXT PRIMARY KEY);
                 ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY {table}_read ON {table} FOR SELECT USING ({source} {operator});"
            );
            let _ = write!(grants, "{table}, ");
        }
    }
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            if from_rows {
                "setting-operator-rows"
            } else {
                "setting-operator"
            },
            &schema,
            &[
                INSERTS,
                &format!(
                    "CREATE ROLE app_reader LOGIN;
                     GRANT SELECT ON {} TO app_reader",
                    grants.trim_end().trim_end_matches(',')
                ),
            ],
            vec![
                mode_caller("listed", Some("main")),
                mode_caller("other", Some("other")),
                mode_caller("empty", Some("")),
                mode_caller("unset", None),
            ],
        )
        .with_settings([
            deployment::scalar("app.mode"),
            deployment::json_setting(
                "request.jwt.claims",
                [(&["mode"], SettingValue::Scalar(DataType::Text))],
            ),
        ]);
        case.loading_from_rows = from_rows;
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(300)).await;
        // `neq` and `notin` admit the other and `''` readings and deny the listed and
        // unset ones; `in` and `any` admit only the listed value.
        for (subject, membership, negation) in [
            ("listed", true, false),
            ("other", false, true),
            ("empty", false, true),
            ("unset", false, false),
        ] {
            for (suffix, expected) in [
                ("neq", negation),
                ("in", membership),
                ("any", membership),
                ("notin", negation),
            ] {
                for prefix in ["m", "j"] {
                    assert_postgres(
                        &case,
                        &run,
                        subject,
                        &format!("{prefix}_{suffix}:r1"),
                        ActionStatement::Select,
                        expected,
                    );
                }
            }
        }
        assert_agrees(&case, &run);
    }
}

/// The fallback the cases below spell inline.
const FALLBACK: &str = "coalesce(nullif(current_setting('request.jwt.claim.role', true), ''), (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'))::text";

/// A caller holding `a` in the bare setting and the `role` field of `c`, `None` for a
/// setting the request leaves unset and a document that is not `JSON` for one that raises
/// when the fallback reaches it.
fn fallback_caller(subject: &str, a: Option<&str>, c: Option<&str>) -> Principal {
    let mut principal = Principal::as_role(subject, "app_reader");
    if let Some(a) = a {
        principal
            .session
            .push(("request.jwt.claim.role".into(), a.into()));
    }
    if let Some(c) = c {
        principal
            .session
            .push(("request.jwt.claims".into(), c.into()));
    }
    principal
}

/// The value the fallback hands over, the four operators over it, over the readers the
/// plan's table states: the first source holding the literal admits, the first source
/// holding anything else denies, an unset first source hands over the second source's
/// `role`, and a second source that is not a `JSON` document raises where the fallback
/// reaches it.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn fallback_parity() {
    const INSERTS: &str = "INSERT INTO i_eq VALUES ('r1');
        INSERT INTO i_neq VALUES ('r1');
        INSERT INTO i_in VALUES ('r1');
        INSERT INTO i_notin VALUES ('r1');";
    const X: &str = "authenticated";
    let cluster = Cluster::start().await;
    let operators = [
        ("eq", "= 'authenticated'"),
        ("neq", "<> 'authenticated'"),
        ("in", "= ANY (ARRAY['authenticated', 'anon'])"),
        ("notin", "NOT IN ('authenticated', 'anon')"),
    ];
    let mut schema = String::new();
    let mut grants = String::new();
    for (suffix, operator) in operators {
        let table = format!("i_{suffix}");
        let _ = writeln!(
            schema,
            "CREATE TABLE {table}(id TEXT PRIMARY KEY);
             ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
             CREATE POLICY {table}_read ON {table} FOR SELECT USING ({FALLBACK} {operator});"
        );
        let _ = write!(grants, "{table}, ");
    }
    for from_rows in [false, true] {
        let mut case = ParityCase::reading(
            if from_rows {
                "fallback-rows"
            } else {
                "fallback"
            },
            &schema,
            &[
                INSERTS,
                &format!(
                    "CREATE ROLE app_reader LOGIN;
                     GRANT SELECT ON {} TO app_reader",
                    grants.trim_end().trim_end_matches(',')
                ),
            ],
            vec![
                fallback_caller("listed_a", Some(X), None),
                fallback_caller("listed_c", None, Some(r#"{"role":"authenticated"}"#)),
                fallback_caller("both", Some(X), Some(r#"{"role":"authenticated"}"#)),
                fallback_caller("neither", None, None),
                fallback_caller("no_field", None, Some("{}")),
                fallback_caller("other_a", Some("other"), None),
                fallback_caller("other_c", None, Some(r#"{"role":"other"}"#)),
                fallback_caller("bad_c", None, Some("not a document"))
                    .reading_a_non_json_document(),
            ],
        )
        .with_settings([
            deployment::typed_scalar("request.jwt.claim.role", DataType::Text).may_be_unset(),
            deployment::json_setting(
                "request.jwt.claims",
                [(&["role"], SettingValue::Scalar(DataType::Text))],
            ),
        ]);
        case.loading_from_rows = from_rows;
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(300)).await;
        // The value holding the literal admits only `eq` and `in`, the value holding
        // anything else only `neq` and `notin`, and an unset value, a missing field and
        // a document that raises admit nothing.
        let expected = |subject: &str, suffix: &str| {
            matches!(
                (subject, suffix),
                ("listed_a" | "listed_c" | "both", "eq" | "in")
                    | ("other_a" | "other_c", "neq" | "notin")
            )
        };
        for subject in [
            "listed_a", "listed_c", "both", "neither", "no_field", "other_a", "other_c", "bad_c",
        ] {
            for (suffix, _) in operators {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    &format!("i_{suffix}:r1"),
                    ActionStatement::Select,
                    expected(subject, suffix),
                );
            }
        }
        assert_agrees(&case, &run);
    }
}
