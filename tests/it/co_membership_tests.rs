//! A row readable by whoever shares a group with the subject it names, read through one
//! membership table joined to itself on the group column.

use rls2fga::json_row::JsonRow;
use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{records_from_row, ConfidenceLevel, Record, RecordDerivation};

use crate::support;

/// `users` and the `team_members` roster naming each team's members, the team a declared
/// entity the roster references. A member is any identity, signed in or not, so the
/// roster carries no foreign key onto `users`.
const SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY, login_name TEXT NOT NULL);
CREATE TABLE teams (id TEXT PRIMARY KEY);
CREATE TABLE team_members (
    team_id TEXT NOT NULL REFERENCES teams(id),
    member_id TEXT NOT NULL,
    PRIMARY KEY (team_id, member_id));
CREATE INDEX team_members_member ON team_members (member_id);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
";

/// [`SCHEMA`] with the team named by free text, so no entity stands for it.
const UNDECLARED_TEAM_SCHEMA: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY, login_name TEXT NOT NULL);
CREATE TABLE team_members (
    team_id TEXT NOT NULL,
    member_id TEXT NOT NULL,
    PRIMARY KEY (team_id, member_id));
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
";

const CALLER: &str = "(SELECT current_setting('app.user_id', true))";

/// Every spelling of "the row's subject shares a team with the caller".
fn spellings() -> [(&'static str, String); 5] {
    [
        (
            "nested in",
            format!(
                "id IN (SELECT member_id FROM team_members WHERE team_id IN (
                    SELECT team_id FROM team_members WHERE member_id = {CALLER}))"
            ),
        ),
        (
            "nested in, qualified by table",
            format!(
                "users.id IN (SELECT team_members.member_id FROM team_members
                    WHERE team_members.team_id IN (
                        SELECT team_members.team_id FROM team_members
                        WHERE team_members.member_id = {CALLER}))"
            ),
        ),
        (
            "nested exists",
            format!(
                "EXISTS (SELECT 1 FROM team_members theirs WHERE theirs.member_id = users.id
                    AND EXISTS (SELECT 1 FROM team_members mine
                        WHERE mine.team_id = theirs.team_id AND mine.member_id = {CALLER}))"
            ),
        ),
        (
            "joined exists",
            format!(
                "EXISTS (SELECT 1 FROM team_members theirs
                    JOIN team_members mine ON mine.team_id = theirs.team_id
                    WHERE theirs.member_id = users.id AND mine.member_id = {CALLER})"
            ),
        ),
        (
            "aliased link, nested in",
            format!(
                "EXISTS (SELECT 1 FROM team_members theirs WHERE theirs.member_id = users.id
                    AND theirs.team_id IN (
                        SELECT team_id FROM team_members WHERE member_id = {CALLER}))"
            ),
        ),
    ]
}

fn outputs(schema: &str, predicate: &str) -> Outputs {
    let db = support::deployment::db(&format!(
        "{schema} CREATE POLICY users_read ON users FOR SELECT USING (
            id = {CALLER} OR {predicate});"
    ));
    TranslatorBuilder::new(support::deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db)
        .unwrap()
        .outputs_accepting_gaps()
}

/// The records one row of `table_name` derives, whatever type they name.
fn row_records(outputs: &Outputs, table_name: &str, row: &serde_json::Value) -> Vec<Record> {
    let mut records: Vec<Record> = outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| query.description.as_ref())
        .filter(|description| {
            matches!(&description.derivation,
                RecordDerivation::FromRow { table, .. } if table.name() == table_name)
        })
        .flat_map(|description| records_from_row(description, &JsonRow(row)).unwrap())
        .collect();
    records.sort_by(|left, right| left.object.cmp(&right.object));
    records
}

/// Whether some note says the model answers otherwise than the database, which is what a
/// deployment refuses to boot on.
fn diverges(outputs: &Outputs) -> bool {
    outputs
        .notes()
        .iter()
        .any(|note| note.severity().diverges_from_database())
}

#[test]
fn every_spelling_translates_through_the_declared_team() {
    for (spelling, predicate) in spellings() {
        let outputs = outputs(SCHEMA, &predicate);
        assert!(!diverges(&outputs), "{spelling}\n{}", outputs.report());
        let roster = row_records(
            &outputs,
            "team_members",
            &serde_json::json!({"team_id":"t1","member_id":"alice"}),
        );
        let pairs: Vec<(&str, &str)> = roster
            .iter()
            .map(|record| (record.object.as_str(), record.subject.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [("teams:t1", "user:alice"), ("users:alice", "teams:t1")],
            "{spelling}\n{}",
            outputs.model()
        );
        let own = row_records(
            &outputs,
            "users",
            &serde_json::json!({"id":"alice","login_name":"Alice"}),
        );
        assert!(
            own.iter()
                .any(|record| record.object == "users:alice" && record.subject == "user:alice"),
            "{spelling}: {own:?}"
        );
    }
}

#[test]
fn an_undeclared_team_stays_refused() {
    for (spelling, predicate) in spellings() {
        let outputs = outputs(UNDECLARED_TEAM_SCHEMA, &predicate);
        assert!(diverges(&outputs), "{spelling}\n{}", outputs.report());
    }
}

/// A far-side reference the inner `FROM` shadows names the inner row, so a subquery
/// whose only link to the outer roster is such a reference correlates nothing with it.
#[test]
fn a_shadowed_reference_is_not_read_as_the_link() {
    let outputs = outputs(
        SCHEMA,
        &format!(
            "EXISTS (SELECT 1 FROM team_members WHERE team_members.member_id = users.id
                AND EXISTS (SELECT 1 FROM team_members
                    WHERE team_members.team_id = team_members.team_id
                    AND team_members.member_id = {CALLER}))"
        ),
    );
    assert!(diverges(&outputs), "{}", outputs.report());
}

/// An unqualified name the roster lacks reaches past both hops to the guarded row, so the
/// inner hop's filter depends on the row being read and no membership tuple holds it.
#[test]
fn a_far_filter_reading_the_guarded_row_stays_refused() {
    let outputs = outputs(
        SCHEMA,
        &format!(
            "id IN (SELECT member_id FROM team_members WHERE team_id IN (
                SELECT team_id FROM team_members
                WHERE member_id = {CALLER} AND login_name <> ''))"
        ),
    );
    assert!(diverges(&outputs), "{}", outputs.report());
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn co_membership_live_parity() {
    use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};
    use rls2fga::types::ActionStatement;

    let cluster = Cluster::start().await;
    for (spelling, predicate) in spellings() {
        for from_rows in [false, true] {
            let mut case = ParityCase::reading(
                &format!(
                    "co-membership-{}-{from_rows}",
                    spelling.replace([' ', ','], "-")
                ),
                &format!(
                    "{SCHEMA}
                    CREATE POLICY users_read ON users FOR SELECT USING (
                        id = {CALLER} OR {predicate});"
                ),
                &["INSERT INTO users VALUES ('alice','Alice'), ('bob','Bob'),
                        ('carol','Carol'), ('dave','Dave');
                     INSERT INTO teams VALUES ('t1'), ('t2');
                     INSERT INTO team_members VALUES ('t1','alice'), ('t1','bob'),
                        ('t2','bob'), ('t2','carol');
                     CREATE ROLE app_reader LOGIN;
                     GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader;"],
                ["alice", "bob", "carol", "dave"]
                    .iter()
                    .map(|subject| {
                        Principal::with_setting(subject, "app_reader", "app.user_id", subject)
                    })
                    .collect(),
            );
            case.loading_from_rows = from_rows;
            let run =
                support::parity::run_before(&cluster, &case, core::time::Duration::from_secs(300))
                    .await;
            for (subject, object, allowed) in [
                ("alice", "users:bob", true),
                ("alice", "users:carol", false),
                ("bob", "users:carol", true),
                ("carol", "users:alice", false),
                ("dave", "users:dave", true),
                ("dave", "users:alice", false),
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
