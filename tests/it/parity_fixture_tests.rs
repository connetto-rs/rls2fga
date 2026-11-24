//! `sql-traits`' recorded row-level security cases, replayed on the model.

use std::fmt::Write as _;

use rls2fga::parity::{replay, Database, ParityError, Probe, Replay};
use sql_traits::parity::{fixtures, Answer, Case, Engine};

use crate::support::containers::{connect_postgres_with_retry, PG_DB};
use crate::support::parity::Cluster;

/// Load `case` into a fresh database on `cluster`, replay `probes` on its own deployment,
/// and drop the database and its roles whether or not the replay succeeds.
async fn replay_of(
    cluster: &Cluster,
    case: &Case,
    probes: Vec<Probe>,
) -> Result<Replay, ParityError> {
    let deployment = case
        .config
        .deployment()
        .unwrap_or_else(|error| panic!("{}: deployment {error}", case.name));
    let mut database = Database::create(&cluster.url(PG_DB), case)
        .unwrap_or_else(|error| panic!("{}: database {error:?}", case.name));
    let replayed = replay(
        case,
        &deployment,
        probes,
        &mut database,
        &cluster.openfga_url(),
    )
    .await;
    database
        .cleanup()
        .unwrap_or_else(|error| panic!("{}: cleanup {error}", case.name));
    replayed
}

/// [`replay_of`] for a case that replays.
async fn replayed(cluster: &Cluster, case: &Case, probes: Vec<Probe>) -> Replay {
    replay_of(cluster, case, probes)
        .await
        .unwrap_or_else(|error| panic!("{}: replay {error:?}", case.name))
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

/// The embedded case named `name`.
fn case_named(name: &str) -> Case {
    fixtures()
        .map(|fixture| fixture.expect("an embedded fixture reads"))
        .find(|fixture| fixture.case.name == name)
        .expect("the fixture is embedded")
        .case
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

/// A read projecting a column the caller's role holds no `SELECT` on fails as `PostgreSQL`
/// fails it, while one projecting only granted columns answers its rows, a probe naming
/// nothing the case runs is an error, a schema the parser rejects is refused for every
/// probe, a caller acting as a role the deployment does not list is an error, and a table
/// without a row key cannot name the row a check asks about.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn probes_outside_the_case() {
    let cluster = cluster().await;
    let mut case = case_named("grant_without_update");
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
    assert_eq!(
        answers[..2],
        [
            &Answer::Error("permission denied for table docs".into()),
            &Answer::Error("permission denied for table docs".into()),
        ]
    );
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

    let mut admin_only = case.clone();
    admin_only
        .config
        .callers
        .retain(|caller| caller.name == "alice");
    admin_only.config.callers[0].role = "app_admin".into();
    let admin = admin_only
        .config
        .deployment()
        .expect("the deployment is valid");
    let mut database =
        Database::create(&cluster.url(PG_DB), &case).expect("the case's database loads");
    let unlisted = replay(
        &case,
        &admin,
        vec![probe("alice", "docs:1", id)],
        &mut database,
        &cluster.openfga_url(),
    )
    .await
    .expect("a caller outside the deployment is a probe error");
    database.cleanup().expect("the case's database drops");
    assert!(error_text(&unlisted.answers[0].answer).contains("acting role app_reader"));

    case.schema = case.schema.replace("PRIMARY KEY", "");
    let keyless = replayed(&cluster, &case, vec![probe("alice", "docs:1", id)]).await;
    assert!(error_text(&keyless.answers[0].answer).contains("row naming"));
}

/// A case naming what its database does not hold is no replay, and a caller missing the
/// identity setting answers an error rather than a verdict.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_case_its_database_contradicts_is_not_replayed() {
    let cluster = cluster().await;
    let case = case_named("grant_without_update");
    let url = cluster.url(PG_DB);
    let id = r#"SELECT "id" FROM "docs""#;

    let mut first = Database::create(&url, &case).expect("the case's database loads");
    let occupied = Database::create(&url, &case)
        .err()
        .expect("the roles are taken");
    first.cleanup().expect("the case's database drops");
    assert!(matches!(occupied, ParityError::RolesExist), "{occupied:?}");

    let mut undeclared = case.clone();
    undeclared.config.writes[0].table = "ghost".into();
    let refused = replay_of(&cluster, &undeclared, Vec::new()).await.err();
    assert!(
        matches!(&refused, Some(ParityError::UndeclaredTable(table)) if table == "ghost"),
        "{refused:?}"
    );

    let mut failing = case.clone();
    failing.config.writes[0].set = [("ghost".into(), "edited".into())].into();
    let refused = replay_of(&cluster, &failing, Vec::new()).await.err();
    assert!(
        matches!(&refused, Some(ParityError::Resulting { statement, .. }) if statement.contains("ghost")),
        "{refused:?}"
    );

    let mut unseeded = case.clone();
    unseeded.seed = "TRUNCATE docs".into();
    let refused = replay_of(&cluster, &unseeded, Vec::new()).await.err();
    assert!(
        matches!(&refused, Some(ParityError::NoSeededRows(table)) if table == "docs"),
        "{refused:?}"
    );

    let mut unkeyed = case.clone();
    unkeyed.config.tables[0].key = vec!["ghost".into()];
    let refused = replay_of(&cluster, &unkeyed, Vec::new()).await.err();
    assert!(
        matches!(&refused, Some(ParityError::MissingKeyColumn(_))),
        "{refused:?}"
    );

    let mut anonymous = case;
    anonymous.config.callers[0].settings.remove("app.user_id");
    let answered = replayed(&cluster, &anonymous, vec![probe("alice", "docs:1", id)]).await;
    assert!(error_text(&answered.answers[0].answer).contains("does not set app.user_id"));
}
