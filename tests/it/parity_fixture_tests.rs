//! `sql-traits`' recorded row-level security cases, replayed on the model.

use std::fmt::Write as _;

use rls2fga::parity::{replay, Database, Probe, Replay};
use sql_traits::parity::{fixtures, Answer, Case, Engine, Fixture};

use crate::support::containers::{connect_postgres_with_retry, PG_DB};
use crate::support::parity::Cluster;

/// Load `case` into a fresh database on `cluster`, replay `probes` on its own deployment,
/// and drop the database and its roles.
async fn replayed(cluster: &Cluster, case: &Case, probes: Vec<Probe>) -> Replay {
    let deployment = case
        .config
        .deployment()
        .unwrap_or_else(|error| panic!("{}: deployment {error}", case.name));
    let mut database = Database::create(&cluster.url(PG_DB), case)
        .unwrap_or_else(|error| panic!("{}: database {error:?}", case.name));
    let replay = replay(
        case,
        &deployment,
        probes,
        &mut database,
        &cluster.openfga_url(),
    )
    .await
    .unwrap_or_else(|error| panic!("{}: replay {error:?}", case.name));
    database
        .cleanup()
        .unwrap_or_else(|error| panic!("{}: cleanup {error}", case.name));
    replay
}

/// A cluster whose PostgreSQL already accepts connections.
async fn cluster() -> Cluster {
    let cluster = Cluster::start().await;
    connect_postgres_with_retry(&cluster.url(PG_DB));
    cluster
}

/// Every embedded case answers each recorded probe as PostgreSQL does, or as its
/// `known.toml` lists for `OpenFGA`, and refuses the schema exactly when a refusal is
/// listed.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn every_fixture_agrees_with_postgres() {
    let cluster = cluster().await;
    let mut report = String::new();
    let mut cases = 0;
    for fixture in fixtures() {
        let fixture = fixture.expect("an embedded fixture reads");
        let probes = fixture.recorded.answer.iter().map(Probe::from).collect();
        let Replay { refusal, answers } = replayed(&cluster, &fixture.case, probes).await;
        for discrepancy in fixture.judge(Engine::Openfga, refusal.as_deref(), &answers) {
            writeln!(report, "{discrepancy}").expect("writing to a string");
        }
        cases += 1;
    }
    assert_eq!(cases, 26, "every embedded case is replayed");
    assert!(
        report.is_empty(),
        "discrepancies from the fixtures:\n{report}"
    );
}

/// The case column grants and key edits are measured on.
fn grant_without_update() -> Fixture {
    fixtures()
        .map(|fixture| fixture.expect("an embedded fixture reads"))
        .find(|fixture| fixture.case.name == "grant_without_update")
        .expect("the fixture is embedded")
}

fn probe(caller: &str, row: &str, statement: &str) -> Probe {
    Probe {
        caller: caller.into(),
        row: row.into(),
        statement: statement.into(),
    }
}

fn error_text(answer: &Answer) -> &str {
    match answer {
        Answer::Error(message) => message,
        other => panic!("expected an error answer, got {other:?}"),
    }
}

/// A column grant hides the rows of a read projecting an ungranted column, a probe naming
/// nothing the case runs is an error, a schema the parser rejects is refused for every
/// probe, and a table without a row key cannot name the row a check asks about.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn probes_outside_the_case() {
    let cluster = cluster().await;
    let mut case = grant_without_update().case;
    case.schema = case
        .schema
        .replace("GRANT SELECT, INSERT", "GRANT SELECT (id), INSERT");
    case.config.tables[0].columns.push("body".into());
    let id = r#"SELECT "id" FROM "docs""#;
    let id_and_body = r#"SELECT "id", "body" FROM "docs""#;
    let projecting_body = replayed(
        &cluster,
        &case,
        vec![
            probe("alice", "docs:1", id_and_body),
            probe("bob", "docs:2", id_and_body),
            probe("carol", "docs:1", id_and_body),
            probe("alice", "docs:1", "SELECT 1"),
            probe("alice", "docs:9", id_and_body),
        ],
    )
    .await;
    assert_eq!(projecting_body.refusal, None);
    let answers: Vec<&Answer> = projecting_body
        .answers
        .iter()
        .map(|answer| &answer.answer)
        .collect();
    assert_eq!(answers[..2], [&Answer::Hidden, &Answer::Hidden]);
    assert!(error_text(answers[2]).contains("no caller carol"));
    assert!(error_text(answers[3]).contains("`SELECT 1`"));
    assert!(error_text(answers[4]).contains("no row docs:9"));

    case.config.tables[0].columns.pop();
    let projecting_id = replayed(
        &cluster,
        &case,
        vec![
            probe("alice", "docs:1", id),
            probe("alice", "docs:2", id),
            probe("bob", "docs:1", id),
        ],
    )
    .await;
    let answers: Vec<&Answer> = projecting_id
        .answers
        .iter()
        .map(|answer| &answer.answer)
        .collect();
    assert_eq!(
        answers,
        [&Answer::Visible, &Answer::Hidden, &Answer::Hidden]
    );

    let deployment = case.config.deployment().expect("the deployment is valid");
    let mut database =
        Database::create(&cluster.url(PG_DB), &case).expect("the case's database loads");
    let mut unparsable = case.clone();
    unparsable.schema = "INVALID SQL".into();
    let refused = replay(
        &unparsable,
        &deployment,
        vec![probe("alice", "docs:1", id), probe("bob", "docs:2", id)],
        &mut database,
        &cluster.openfga_url(),
    )
    .await
    .expect("a refused schema is a replay");
    database.cleanup().expect("the case's database drops");
    let reason = refused.refusal.expect("an unparsable schema is refused");
    for answer in &refused.answers {
        assert_eq!(answer.answer, Answer::Refused(reason.clone()));
    }

    case.schema = case.schema.replace("PRIMARY KEY", "");
    let keyless = replayed(&cluster, &case, vec![probe("alice", "docs:1", id)]).await;
    assert!(error_text(&keyless.answers[0].answer).contains("row naming"));
}
