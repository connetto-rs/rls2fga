//! The caller compared with an immutable function of one column of the row, the spelling an
//! expression index on that function serves.

use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{ConfidenceLevel, RecordDerivation, RecordDescription, ReplayScope};

use crate::support;

const SCHEMA: &str = "
CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT NOT NULL);
CREATE INDEX notes_owner ON notes (lower(owner));
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
";

const CALLER: &str = "(SELECT current_setting('app.user_id', true))";

fn outputs(sql: &str) -> Outputs {
    let db = support::deployment::db(&format!("{SCHEMA} {sql}"));
    TranslatorBuilder::new(support::deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db)
        .unwrap()
        .outputs_accepting_gaps()
}

/// Whether some note says the model answers otherwise than the database, which is what a
/// deployment refuses to boot on.
fn diverges(outputs: &Outputs) -> bool {
    outputs
        .notes()
        .iter()
        .any(|note| note.severity().diverges_from_database())
}

/// The descriptions of the queries loading `notes` whose records a changed row cannot
/// settle without querying.
fn requeried(outputs: &Outputs) -> Vec<&RecordDescription> {
    outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| query.description.as_ref())
        .filter(|description| {
            description
                .tables
                .iter()
                .any(|table| table.name() == "notes")
                && matches!(description.derivation, RecordDerivation::Joined { .. })
        })
        .collect()
}

#[test]
fn an_immutable_function_of_the_owner_is_replayed_by_the_rows_key() {
    for row_side in [
        "lower(owner)",
        "LOWER(notes.owner)",
        "upper(btrim(owner))",
        "pg_catalog.lower(owner)",
        "split_part(owner, '@', 1)",
    ] {
        let outputs = outputs(&format!(
            "CREATE POLICY own ON notes FOR SELECT USING ({row_side} = {CALLER});"
        ));
        assert!(!diverges(&outputs), "{row_side}\n{}", outputs.report());
        let [description] = requeried(&outputs)[..] else {
            panic!("{row_side}: {:?}", requeried(&outputs));
        };
        let RecordDerivation::Joined { queries, .. } = &description.derivation else {
            panic!("{row_side}: {description:?}");
        };
        let [query] = &queries[..] else {
            panic!("{row_side}: {queries:?}");
        };
        assert_eq!(query.table().name(), "notes");
        assert_eq!(
            query
                .key_columns()
                .iter()
                .map(rls2fga::types::ColumnName::as_str)
                .collect::<Vec<_>>(),
            ["id"],
            "{row_side}"
        );
        assert!(query.sql().contains("\"pg_catalog\"."), "{}", query.sql());
    }
}

#[test]
fn a_declared_immutable_function_translates() {
    let outputs = outputs(&format!(
        "CREATE FUNCTION app_norm(value TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE
            AS 'SELECT lower(value)';
         CREATE POLICY own ON notes FOR SELECT USING (app_norm(owner) = {CALLER});"
    ));
    assert!(!diverges(&outputs), "{}", outputs.report());
}

#[test]
fn a_function_that_may_answer_otherwise_in_the_callers_session_stays_refused() {
    for declaration in [
        "CREATE FUNCTION app_norm(value TEXT) RETURNS TEXT LANGUAGE sql STABLE
            AS 'SELECT lower(value)';",
        "CREATE FUNCTION app_norm(value TEXT) RETURNS TEXT LANGUAGE sql
            AS 'SELECT lower(value)';",
    ] {
        let outputs = outputs(&format!(
            "{declaration}
             CREATE POLICY own ON notes FOR SELECT USING (app_norm(owner) = {CALLER});"
        ));
        assert!(diverges(&outputs), "{declaration}\n{}", outputs.report());
    }
}

/// A schema function named like a builtin leaves the choice to the search path and the
/// argument types, which the translation does not make.
#[test]
fn a_call_reaching_functions_of_two_schemas_stays_refused() {
    let outputs = outputs(&format!(
        "CREATE FUNCTION lower(value TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE
            AS 'SELECT upper(value)';
         CREATE POLICY own ON notes FOR SELECT USING (lower(owner) = {CALLER});"
    ));
    assert!(diverges(&outputs), "{}", outputs.report());
}

#[test]
fn an_expression_over_two_columns_stays_refused() {
    let db = support::deployment::db(&format!(
        "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT NOT NULL, domain TEXT NOT NULL);
         ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY own ON notes FOR SELECT USING (concat(owner, domain) = {CALLER});"
    ));
    let outputs = TranslatorBuilder::new(support::deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db)
        .unwrap()
        .outputs_accepting_gaps();
    assert!(diverges(&outputs), "{}", outputs.report());
}

/// The bare column decides its tuple from the row image and the expression only by a query,
/// so the two arms fill separate relations and neither replay withdraws the other's facts.
#[test]
fn the_bare_column_and_the_expression_fill_separate_relations() {
    let outputs = outputs(&format!(
        "CREATE POLICY own ON notes FOR SELECT USING (
            owner = {CALLER} OR lower(owner) = {CALLER});"
    ));
    assert!(!diverges(&outputs), "{}", outputs.report());
    let row_decided: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| match &query.description.as_ref()?.derivation {
            RecordDerivation::FromRow { template, .. } => Some(template.relation.as_str()),
            _ => None,
        })
        .collect();
    assert!(row_decided.contains(&"owner"), "{row_decided:?}");
    let [description] = requeried(&outputs)[..] else {
        panic!("{:?}", requeried(&outputs));
    };
    let RecordDerivation::Joined { queries, .. } = &description.derivation else {
        unreachable!();
    };
    for query in queries {
        let ReplayScope::Object { relations, .. } = query.scope() else {
            panic!("{:?}", query.scope());
        };
        assert!(
            relations
                .iter()
                .all(|relation| !row_decided.contains(&relation.as_str())),
            "{relations:?} against {row_decided:?}"
        );
    }
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn owner_expression_live_parity() {
    use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};
    use rls2fga::types::ActionStatement;

    const EMILE: &str = "~c3a96d696c65";
    let cluster = Cluster::start().await;
    for (label, predicate) in [
        ("lower", format!("lower(owner) = {CALLER}")),
        (
            "both",
            format!("owner = {CALLER} OR lower(owner) = {CALLER}"),
        ),
    ] {
        for from_rows in [false, true] {
            let mut case = ParityCase::reading(
                &format!("owner-expression-{label}-{from_rows}"),
                &format!("{SCHEMA} CREATE POLICY own ON notes FOR SELECT USING ({predicate});"),
                &[
                    "INSERT INTO notes VALUES (1, 'Alice'), (2, 'bob'), (3, 'ÉMILE'), (4, 'Carol');
                     CREATE ROLE app_reader LOGIN;
                     GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;",
                ],
                // `émile` holds a character an id is never spelled with verbatim, so the
                // model knows that caller by the escaped id the tuple query writes.
                [
                    ("alice", "alice"),
                    ("bob", "bob"),
                    (EMILE, "émile"),
                    ("Carol", "Carol"),
                ]
                .iter()
                .map(|(subject, setting)| {
                    Principal::with_setting(subject, "app_reader", "app.user_id", setting)
                })
                .collect(),
            );
            case.loading_from_rows = from_rows;
            let run =
                support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                    .await;
            for (subject, object, allowed) in [
                ("alice", "notes:1", true),
                ("bob", "notes:2", true),
                (EMILE, "notes:3", true),
                ("alice", "notes:2", false),
                ("Carol", "notes:4", label == "both"),
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
}
