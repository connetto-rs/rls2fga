//! Declared definer helpers compared against `PostgreSQL` 17 and 18, with both tuple
//! loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;

use crate::declared_helper_tests::{INSTALLATIONS, LEVELS, ORDERS, OWNER_READS};
use crate::support;
use crate::support::parity::{
    assert_agrees, assert_postgres, Cluster, Mutations, ParityCase, Principal,
};

const HELPERS: &str = r#"{
    "authz.projects_with": { "kind": "declared_helper" },
    "authz.teams_with": { "kind": "declared_helper" },
    "authz.installations_administered": { "kind": "declared_helper" }
}"#;

/// Each level reads its own rows through its helper too.
const LEVEL_READS: &str = "
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_read ON projects FOR SELECT USING (
  id = ANY (ARRAY(SELECT authz.projects_with('read'))));
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
CREATE POLICY teams_read ON teams FOR SELECT USING (
  id IN (SELECT authz.teams_with('read')));
";

fn caller(subject: &str) -> Principal {
    Principal::with_setting(subject, "app_reader", "app.user_id", subject)
}

fn levels_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helpers-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!("{LEVELS}{OWNER_READS}{ORDERS}{LEVEL_READS}{INSTALLATIONS}"),
        &[
            "INSERT INTO teams VALUES ('T1'), ('T2');
             INSERT INTO projects VALUES ('P1', 'T1'), ('P2', 'T1'), ('P3', 'T2');
             INSERT INTO orders VALUES ('o1', 'P1', NULL), ('o2', 'P2', NULL), ('o3', 'P3', NULL);
             INSERT INTO team_grants VALUES
               ('T1', 'bob', 'write'), ('T2', 'dave', 'read'), ('T1', 'hank', 'admin');
             INSERT INTO project_grants VALUES ('P2', 'carol', 'read'), ('P3', 'frank', 'admin');
             INSERT INTO installations VALUES ('i1', 'T1'), ('i2', 'P3'), ('i3', 'elsewhere');
             INSERT INTO installation_tables VALUES ('t1', 'i1', 'a'), ('t2', 'i2', 'b'), ('t3', 'i3', 'c')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON orders, projects, teams, installations, installation_tables TO app_reader;
             GRANT UPDATE ON orders TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller("bob"),
            caller("carol"),
            caller("dave"),
            caller("frank"),
            caller("hank"),
            caller("erin"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(HELPERS)
    .writing(
        "orders",
        Mutations {
            update_set: Some("title = 'changed'".into()),
            check_neutral: true,
        },
    );
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn declared_helpers_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = levels_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, statement, allowed| {
                assert_postgres(&case, &run, subject, object, statement, allowed);
            };
            // A team writer reads and changes every order under the team.
            expect("bob", "orders:o1", ActionStatement::Select, true);
            expect("bob", "orders:o2", ActionStatement::Update, true);
            expect("bob", "orders:o3", ActionStatement::Select, false);
            expect("bob", "teams:T1", ActionStatement::Select, true);
            // A project reader reads that project's orders and changes none.
            expect("carol", "orders:o2", ActionStatement::Select, true);
            expect("carol", "orders:o2", ActionStatement::Update, false);
            expect("carol", "orders:o1", ActionStatement::Select, false);
            expect("carol", "projects:P2", ActionStatement::Select, true);
            expect("carol", "teams:T1", ActionStatement::Select, false);
            // A reader of another team sees only that team's orders.
            expect("dave", "orders:o3", ActionStatement::Select, true);
            expect("dave", "orders:o1", ActionStatement::Select, false);
            // A project admin writes.
            expect("frank", "orders:o3", ActionStatement::Update, true);
            // An installation is read by an admin of the level its owner names.
            expect("frank", "installations:i2", ActionStatement::Select, true);
            expect("frank", "installations:i1", ActionStatement::Select, false);
            expect("hank", "installations:i1", ActionStatement::Select, true);
            expect("hank", "installations:i2", ActionStatement::Select, false);
            expect("bob", "installations:i1", ActionStatement::Select, false);
            expect(
                "hank",
                "installation_tables:t1",
                ActionStatement::Select,
                true,
            );
            expect(
                "frank",
                "installation_tables:t2",
                ActionStatement::Select,
                true,
            );
            expect(
                "frank",
                "installation_tables:t1",
                ActionStatement::Select,
                false,
            );
            // No grant, and no caller at all, read nothing.
            expect("erin", "orders:o1", ActionStatement::Select, false);
            expect("anonymous", "orders:o1", ActionStatement::Select, false);
            expect(
                "anonymous",
                "installations:i3",
                ActionStatement::Select,
                false,
            );
            assert_agrees(&case, &run);
        }
    }
}
