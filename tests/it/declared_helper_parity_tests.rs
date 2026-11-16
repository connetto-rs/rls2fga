//! Declared definer helpers compared against `PostgreSQL` 17 and 18, with both tuple
//! loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::fmt::Write as _;
use core::time::Duration;

use rls2fga::types::ActionStatement;
use sqlparser::ast::DataType;

use crate::declared_helper_blocklist_tests::{BLOCKS, DOCS_UNBLOCKED, PROJECTS_UNBLOCKED};
use crate::declared_helper_containment_tests::FOLDERS;
use crate::declared_helper_tests::{
    caller_and_audiences_only, ABSENT_INSTALLATION, AUDIENCES, EDGE_FOLDERS, EXPIRING, GRANTEES,
    GROUPS, INSTALLATIONS, INVITATIONS, LEVELS, MEMBERSHIP_STATES, ORDERS, OWNER_READS,
    REQUEST_VALUES, RESOURCES,
};
use crate::request_principal_tests::{principal_blocks, CALLER_OR_INSTALLATION};
use crate::row_cap_tests::INSTALLATION_CAPS;
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

const GROUP_HELPERS: &str = r#"{
    "authz.groups_with": { "kind": "declared_helper" }
}"#;

/// The groups read their own rows through the walk too.
const GROUP_READS: &str = "
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY groups_read ON groups FOR SELECT USING (
  id = ANY (ARRAY(SELECT authz.groups_with('read'))));
";

/// `org` holds `team` and `side`, `team` holds `squad`, `other` is a tree of its own, and
/// `loop_a` and `loop_b` are each other's parent.
fn groups_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-walk-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!("{LEVELS}{OWNER_READS}{GROUPS}{GROUP_READS}"),
        &[
            "INSERT INTO groups (id, parent_id) VALUES
               ('org', NULL), ('team', 'org'), ('side', 'org'), ('squad', 'team'),
               ('other', NULL), ('loop_a', NULL), ('loop_b', 'loop_a');
             UPDATE groups SET parent_id = 'loop_b' WHERE id = 'loop_a';
             INSERT INTO docs VALUES ('d_org', 'org', NULL), ('d_team', 'team', NULL),
               ('d_side', 'side', NULL), ('d_squad', 'squad', NULL), ('d_other', 'other', NULL),
               ('d_loop_a', 'loop_a', NULL), ('d_loop_b', 'loop_b', NULL);
             INSERT INTO group_grants VALUES
               ('team', 'alice', 'read'), ('org', 'bob', 'write'), ('loop_a', 'dave', 'read')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs, groups TO app_reader;
             GRANT UPDATE ON docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller("alice"),
            caller("bob"),
            caller("dave"),
            caller("erin"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(GROUP_HELPERS)
    .writing(
        "docs",
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
async fn a_walk_down_the_group_tree_agrees_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = groups_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, statement, allowed| {
                assert_postgres(&case, &run, subject, object, statement, allowed);
            };
            // A grant in the middle reaches the subtree, not the parent or a sibling.
            expect("alice", "docs:d_team", ActionStatement::Select, true);
            expect("alice", "docs:d_squad", ActionStatement::Select, true);
            expect("alice", "docs:d_org", ActionStatement::Select, false);
            expect("alice", "docs:d_side", ActionStatement::Select, false);
            expect("alice", "docs:d_other", ActionStatement::Select, false);
            expect("alice", "docs:d_squad", ActionStatement::Update, false);
            expect("alice", "groups:squad", ActionStatement::Select, true);
            expect("alice", "groups:org", ActionStatement::Select, false);
            // A write grant at the root reads and changes the whole tree, and no other.
            expect("bob", "docs:d_org", ActionStatement::Select, true);
            expect("bob", "docs:d_squad", ActionStatement::Update, true);
            expect("bob", "docs:d_side", ActionStatement::Update, true);
            expect("bob", "docs:d_other", ActionStatement::Select, false);
            // A grant on a cycle reaches every group on it, and a walk never reaching a
            // grant ends.
            expect("dave", "docs:d_loop_a", ActionStatement::Select, true);
            expect("dave", "docs:d_loop_b", ActionStatement::Select, true);
            expect("alice", "docs:d_loop_a", ActionStatement::Select, false);
            // No grant, and no caller at all, read nothing.
            expect("erin", "docs:d_squad", ActionStatement::Select, false);
            expect("anonymous", "docs:d_org", ActionStatement::Select, false);
            assert_agrees(&case, &run);
        }
    }
}

const EDGE_FOLDER_HELPERS: &str = r#"{
    "authz.folders_reached": { "kind": "declared_helper" },
    "authz.projects_reached": { "kind": "declared_helper" }
}"#;

/// `root` holds `mid`, which holds `leaf`, and `other` stands alone, each edge a row of
/// `folder_parents`. `p_leaf`, `p_mid` and `p_other` sit in the folder they name, and
/// `p_loose` in none.
fn edge_folders_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-edges-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        EDGE_FOLDERS,
        &[
            "INSERT INTO folders VALUES ('root'), ('mid'), ('leaf'), ('other');
             INSERT INTO folder_parents VALUES ('mid', 'root'), ('leaf', 'mid');
             INSERT INTO projects VALUES ('p_leaf'), ('p_mid'), ('p_other'), ('p_loose');
             INSERT INTO project_folders VALUES
               ('pf1', 'p_leaf', 'leaf'), ('pf2', 'p_mid', 'mid'), ('pf3', 'p_other', 'other');
             INSERT INTO folder_grants VALUES ('root', 'alice'), ('mid', 'bob'), ('other', 'carol')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON folders, projects TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller("alice"),
            caller("bob"),
            caller("carol"),
            caller("erin"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(EDGE_FOLDER_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn a_walk_and_a_parent_arm_through_edge_tables_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = edge_folders_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, allowed| {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    object,
                    ActionStatement::Select,
                    allowed,
                );
            };
            // A grant on the root reaches the whole chain and the projects in it, and a
            // project in no folder inherits nothing.
            expect("alice", "folders:root", true);
            expect("alice", "folders:leaf", true);
            expect("alice", "folders:other", false);
            expect("alice", "projects:p_leaf", true);
            expect("alice", "projects:p_mid", true);
            expect("alice", "projects:p_loose", false);
            // A grant in the middle reaches below it, not above.
            expect("bob", "folders:root", false);
            expect("bob", "folders:leaf", true);
            expect("bob", "projects:p_leaf", true);
            expect("bob", "projects:p_other", false);
            // A folder with no edge is a tree of its own.
            expect("carol", "projects:p_other", true);
            expect("carol", "projects:p_leaf", false);
            // No grant, and no caller at all, read nothing.
            expect("erin", "folders:root", false);
            expect("anonymous", "projects:p_leaf", false);
            assert_agrees(&case, &run);
        }
    }
}

const RESOURCE_HELPERS: &str = r#"{
    "authz.resources_above": { "kind": "declared_helper" },
    "authz.resources_below": { "kind": "declared_helper" }
}"#;

/// The folder `f_team` under `f_root`, the project `p1` under `f_team`, the project
/// `p_other` under no folder, and the ownables `o1` in `p1` and `o2` in `p_other`, read
/// through the walk down both edge tables and changed through the walk up them.
fn resources_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-lateral-edges-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        RESOURCES,
        &[
            "INSERT INTO resources (id, kind) VALUES ('f_root', 'folder'), ('f_team', 'folder'),
               ('p1', 'project'), ('p_other', 'project'), ('o1', 'ownable'), ('o2', 'ownable');
             INSERT INTO resource_parents (id, kind, parent_id) VALUES
               ('f_team', 'folder', 'f_root'), ('p1', 'project', 'f_team');
             INSERT INTO ownables (id, project_id) VALUES ('o1', 'p1'), ('o2', 'p_other');
             INSERT INTO resource_grants VALUES
               ('f_team', 'alice'), ('f_root', 'bob'), ('p_other', 'carol'), ('o1', 'dave')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT, UPDATE ON resources TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller("alice"),
            caller("bob"),
            caller("carol"),
            caller("dave"),
            caller("erin"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(RESOURCE_HELPERS)
    .writing(
        "resources",
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
async fn lateral_walks_over_composite_key_edge_tables_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = resources_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, statement, allowed| {
                assert_postgres(&case, &run, subject, object, statement, allowed);
            };
            // Walking down both edge tables, a folder's grant reaches its projects and
            // their ownables, and a project's grant only its own ownables.
            expect("alice", "resources:f_team", ActionStatement::Select, true);
            expect("alice", "resources:o1", ActionStatement::Select, true);
            expect("alice", "resources:f_root", ActionStatement::Select, false);
            expect("bob", "resources:o1", ActionStatement::Select, true);
            expect("carol", "resources:o2", ActionStatement::Select, true);
            expect("carol", "resources:o1", ActionStatement::Select, false);
            expect("dave", "resources:p1", ActionStatement::Select, false);
            // Walking up both, a grant reaches every row above it, which a change needs
            // beside reading the row.
            expect("dave", "resources:o1", ActionStatement::Update, true);
            expect("alice", "resources:f_team", ActionStatement::Update, true);
            expect("alice", "resources:p1", ActionStatement::Update, false);
            expect("bob", "resources:f_root", ActionStatement::Update, true);
            expect("bob", "resources:f_team", ActionStatement::Update, false);
            // No grant, and no caller at all, read nothing.
            expect("erin", "resources:f_root", ActionStatement::Select, false);
            expect("anonymous", "resources:o1", ActionStatement::Select, false);
            assert_agrees(&case, &run);
        }
    }
}

const BLOCK_HELPERS: &str = r#"{
    "authz.blocked_projects": { "kind": "declared_helper" },
    "authz.blocking_organizations": { "kind": "declared_helper" }
}"#;

/// `O1` blocks `alice` and `O2` blocks `carol`, who own projects or write documents in
/// both organizations.
fn blocks_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-blocklist-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!("{BLOCKS}{PROJECTS_UNBLOCKED}{DOCS_UNBLOCKED}"),
        &[
            "INSERT INTO organizations VALUES ('O1'), ('O2');
             INSERT INTO projects VALUES ('P1', 'O1', 'alice', NULL), ('P2', 'O2', 'alice', NULL),
               ('P3', 'O1', 'bob', NULL), ('P4', 'O2', 'bob', NULL);
             INSERT INTO docs VALUES ('d1', 'P1', 'alice', NULL), ('d2', 'P2', 'alice', NULL),
               ('d3', 'P3', 'bob', NULL), ('d4', 'P4', 'carol', NULL), ('d5', 'P1', 'carol', NULL);
             INSERT INTO organization_blocks VALUES ('O1', 'alice'), ('O2', 'carol')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON projects, docs TO app_reader;
             GRANT UPDATE ON projects TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller("alice"),
            caller("bob"),
            caller("carol"),
            caller("erin"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(BLOCK_HELPERS)
    .writing(
        "projects",
        Mutations {
            update_set: Some("label = 'changed'".into()),
            check_neutral: true,
        },
    );
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn a_blocklist_through_a_declared_helper_agrees_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = blocks_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, statement, allowed| {
                assert_postgres(&case, &run, subject, object, statement, allowed);
            };
            // A block hides the organization's projects from their owner, for every
            // command, and their documents through the project.
            expect("alice", "projects:P1", ActionStatement::Select, false);
            expect("alice", "projects:P1", ActionStatement::Update, false);
            expect("alice", "projects:P2", ActionStatement::Select, true);
            expect("alice", "projects:P2", ActionStatement::Update, true);
            expect("alice", "docs:d1", ActionStatement::Select, false);
            expect("alice", "docs:d2", ActionStatement::Select, true);
            // A block on someone else changes nothing for an unblocked owner.
            expect("bob", "projects:P3", ActionStatement::Select, true);
            expect("bob", "projects:P4", ActionStatement::Update, true);
            expect("bob", "docs:d3", ActionStatement::Select, true);
            // A block reaches only its own organization's projects.
            expect("carol", "docs:d4", ActionStatement::Select, false);
            expect("carol", "docs:d5", ActionStatement::Select, true);
            // No grant, and no caller at all, read nothing.
            expect("erin", "projects:P2", ActionStatement::Select, false);
            expect("anonymous", "projects:P2", ActionStatement::Select, false);
            assert_agrees(&case, &run);
        }
    }
}

/// A request acting as `subject`, through `installation` where it names one, the empty
/// string standing for a pooled connection that once carried one.
fn acting(subject: &str, caller: Option<&str>, installation: Option<&str>) -> Principal {
    let mut principal = Principal::as_role(subject, "app_reader").with_clock();
    for (setting, value) in [
        ("app.user_id", caller),
        ("app.installation_id", installation),
    ] {
        if let Some(value) = value {
            principal.session.push((setting.into(), value.into()));
        }
    }
    principal
}

/// `O1` blocks the caller `alice` and the installation `i1`, `O2` blocked `i2` until
/// yesterday, blocks `i3` until tomorrow and blocks `i4` for good.
fn principal_blocks_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-principal-blocks-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &principal_blocks(&format!(
            "{CALLER_OR_INSTALLATION} AND (b.expires_at IS NULL OR b.expires_at > now())"
        )),
        &[
            "INSERT INTO organizations VALUES ('O1'), ('O2');
             INSERT INTO projects VALUES ('P1', 'O1'), ('P2', 'O2');
             INSERT INTO organization_blocks VALUES
               ('O1', 'alice', NULL), ('O1', 'i1', NULL),
               ('O2', 'i2', now() - interval '1 day'), ('O2', 'i3', now() + interval '1 day'),
               ('O2', 'i4', NULL)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON projects TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            acting("alice", Some("alice"), None),
            acting("bob", Some("bob"), Some("i1")),
            acting("carol", Some("carol"), Some("i2")),
            acting("dave", Some("dave"), Some("i3")),
            acting("erin", Some("erin"), Some("")),
            acting("i4", Some("i4"), None),
            acting("anonymous", None, Some("i1")),
        ],
    )
    .with_settings([
        support::deployment::caller("app.user_id").may_be_unset(),
        support::deployment::principal("app.installation_id", "installation", DataType::Text)
            .may_be_unset(),
    ])
    .with_registry(PRINCIPAL_BLOCK_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

const PRINCIPAL_BLOCK_HELPERS: &str = r#"{
    "authz.blocking_organizations": { "kind": "declared_helper" }
}"#;

/// A block on the installation a request acts through hides the organization's projects
/// as a block on the caller does, for a user acting through it, for no user at all, and
/// for an installation acting as the caller itself.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn blocks_on_the_acting_installation_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = principal_blocks_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            for (subject, p1, p2) in [
                ("alice", false, true),
                ("bob", false, true),
                ("carol", true, true),
                ("dave", true, false),
                ("erin", true, true),
                ("i4", true, false),
                ("anonymous", false, true),
            ] {
                for (object, allowed) in [("projects:P1", p1), ("projects:P2", p2)] {
                    assert_postgres(
                        &case,
                        &run,
                        subject,
                        object,
                        ActionStatement::Select,
                        allowed,
                    );
                }
            }
            assert_agrees(&case, &run);
        }
    }
}

const REQUEST_HELPERS: &str = r#"{
    "authz.presented_links": { "kind": "declared_helper" },
    "authz.installations_allowing": { "kind": "declared_helper" }
}"#;

/// A caller presenting `links` through `installation`, `None` leaving it unset.
fn presenting(subject: &str, links: &[&str], installation: Option<&str>) -> Principal {
    let mut principal =
        Principal::with_setting(subject, "app_reader", "app.link_ids", &links.join(","))
            .with_context(serde_json::json!({ "app_link_ids": links }));
    if let Some(installation) = installation {
        principal
            .session
            .push(("app.installation_id".into(), installation.into()));
    }
    principal
}

/// `l2` is revoked, `i1` may read the docs and `i2` may only update them.
fn request_values_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-request-values-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!("{LEVELS}{OWNER_READS}{REQUEST_VALUES}"),
        &[
            "INSERT INTO share_links VALUES ('l1', FALSE), ('l2', TRUE), ('l3', FALSE);
             INSERT INTO docs VALUES ('d1', 'l1'), ('d2', 'l2'), ('d3', 'l3');
             INSERT INTO installation_permissions VALUES
               ('i1', 'docs', 'select'), ('i2', 'docs', 'update')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            presenting("direct", &["l1", "l2"], Some("")),
            presenting("via_i1", &["l1", "l3"], Some("i1")),
            presenting("via_i2", &["l1", "l3"], Some("i2")),
            presenting("no_links", &[], Some("")),
            presenting("unset_installation", &["l1"], None),
        ],
    )
    .with_settings([
        support::deployment::caller("app.user_id"),
        support::deployment::scalar("app.installation_id"),
        support::deployment::delimited_set("app.link_ids", ","),
    ])
    .with_registry(REQUEST_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn request_values_behind_helpers_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = request_values_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, allowed| {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    object,
                    ActionStatement::Select,
                    allowed,
                );
            };
            // A presented link reads its docs, a revoked one does not.
            expect("direct", "docs:d1", true);
            expect("direct", "docs:d2", false);
            expect("direct", "docs:d3", false);
            // An installation approved for reading passes the cap, another does not.
            expect("via_i1", "docs:d1", true);
            expect("via_i1", "docs:d3", true);
            expect("via_i2", "docs:d1", false);
            // No link, and an installation never set, read nothing.
            expect("no_links", "docs:d1", false);
            expect("unset_installation", "docs:d1", false);
            assert_agrees(&case, &run);
        }
    }
}

const INSTALLATION_HELPERS: &str = r#"{
    "authz.installations_allowing": { "kind": "declared_helper" }
}"#;

/// The installation `docs` may be read through, and one that may only update them.
const READING_INSTALLATION: &str = "11111111-1111-1111-1111-111111111111";
const UPDATING_INSTALLATION: &str = "22222222-2222-2222-2222-222222222222";

/// A caller presenting `installation`, `None` leaving it unset.
fn installed(subject: &str, installation: Option<&str>) -> Principal {
    let mut principal = Principal::with_setting(subject, "app_reader", "app.user_id", subject);
    if let Some(installation) = installation {
        principal
            .session
            .push(("app.installation_id".into(), installation.into()));
    }
    principal
}

/// [`ABSENT_INSTALLATION`] with one document, which [`READING_INSTALLATION`] may read and
/// [`UPDATING_INSTALLATION`] may only update.
fn absent_installation_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-absent-installation-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        ABSENT_INSTALLATION,
        &[
            &format!(
                "INSERT INTO docs VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
                 INSERT INTO installation_permissions VALUES
                   ('{READING_INSTALLATION}', 'docs', 'select'),
                   ('{UPDATING_INSTALLATION}', 'docs', 'update')"
            ),
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            installed("via_i1", Some(READING_INSTALLATION)),
            installed("via_i2", Some(UPDATING_INSTALLATION)),
            installed("via_other", Some("33333333-3333-3333-3333-333333333333")),
            installed("unset_installation", None),
            installed("empty_installation", Some("")),
        ],
    )
    .with_settings([
        support::deployment::caller("app.user_id"),
        support::deployment::typed_scalar("app.installation_id", DataType::Uuid).may_be_unset(),
    ])
    .with_registry(INSTALLATION_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

/// A request leaving the installation unset passes the cap, as does one whose pooled
/// connection reads it as `''`, which `NULLIF` reads as `NULL`, and one presenting an
/// installation passes where the helper allows that installation to read.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn an_absent_installation_agrees_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = absent_installation_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            for (subject, allowed) in [
                ("via_i1", true),
                ("via_i2", false),
                ("via_other", false),
                ("unset_installation", true),
                ("empty_installation", true),
            ] {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    "docs:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    ActionStatement::Select,
                    allowed,
                );
            }
            assert_agrees(&case, &run);
        }
    }
}

const AUDIENCE_HELPERS: &str = r#"{
    "authz.projects_visible": { "kind": "declared_helper" }
}"#;

/// `p_public` is everyone's, `p_signed` every caller's but `anonymous`, and `p_private`
/// its members', `alice` and `anonymous`, whom the arm's gate excludes.
fn audiences_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-audiences-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        AUDIENCES,
        &[
            "INSERT INTO projects VALUES ('p_public', 'public'), ('p_signed', 'signed_in'),
               ('p_private', 'private');
             INSERT INTO project_members VALUES ('p_private', 'alice'), ('p_private', 'anonymous');
             INSERT INTO docs VALUES ('d_public', 'p_public', NULL), ('d_signed', 'p_signed', NULL),
               ('d_private', 'p_private', NULL)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        ["alice", "bob", "anonymous"]
            .into_iter()
            .map(caller)
            .collect(),
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(AUDIENCE_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn audiences_and_caller_gates_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = audiences_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, allowed| {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    object,
                    ActionStatement::Select,
                    allowed,
                );
            };
            // Everyone includes the caller the other arms' gates exclude.
            expect("anonymous", "docs:d_public", true);
            expect("bob", "docs:d_signed", true);
            expect("anonymous", "docs:d_signed", false);
            // A member is admitted unless the gate excludes it.
            expect("alice", "docs:d_private", true);
            expect("bob", "docs:d_private", false);
            expect("anonymous", "docs:d_private", false);
            assert_agrees(&case, &run);
        }
    }
}

const GRANTEE_HELPERS: &str = r#"{
    "authz.caller_grantees": { "kind": "declared_helper" },
    "authz.projects_granted": { "kind": "declared_helper" }
}"#;

/// The caller arm as the request writes it, and narrowed to user grantees.
const CALLER_ARM: &str = "WHERE g.id = current_setting('app.user_id', true)";
const USER_CALLER_ARM: &str =
    "WHERE g.id = current_setting('app.user_id', true) AND g.kind = 'user'";

/// The grant arm with a gate keeping no row for `anonymous`.
const GATED_GRANT_ARM: &str = "IN (SELECT authz.caller_grantees()) \
     AND current_setting('app.user_id', true) <> 'anonymous'";

/// `org1` has `bob` active and `carol` deactivated, `team_leaf` sits under `team_root`
/// with `dave` in the leaf and `erin` in the root, and a request without a caller sends
/// `anonymous`, which the signed-in audience excludes, and the grant arm too where
/// `gated`. Where `inline`, the set holds only the caller and the audiences.
fn grantees_case(
    major: &str,
    caller_arm: &str,
    gated: bool,
    inline: bool,
    loading_from_rows: bool,
) -> ParityCase {
    let narrowed = if caller_arm == CALLER_ARM {
        ""
    } else {
        "-users"
    };
    let mut schema = GRANTEES
        .replace(CALLER_ARM, caller_arm)
        .replace("<> ''", "<> 'anonymous'");
    if gated {
        schema = schema.replace("IN (SELECT authz.caller_grantees())", GATED_GRANT_ARM);
    }
    if inline {
        schema = caller_and_audiences_only(&schema);
    }
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-grantees-pg{major}{narrowed}{}{}{}",
            if gated { "-gated" } else { "" },
            if inline { "-inline" } else { "" },
            if loading_from_rows { "-rows" } else { "" }
        ),
        &schema,
        &[
            "INSERT INTO grantees VALUES
               ('alice', 'user'), ('bob', 'user'), ('carol', 'user'), ('dave', 'user'),
               ('erin', 'user'), ('anonymous', 'user'), ('org1', 'organization'),
               ('team_root', 'team'), ('team_leaf', 'team'), ('everyone', 'everyone'),
               ('signed_in', 'signed_in');
             INSERT INTO organizations VALUES ('org1');
             INSERT INTO memberships VALUES ('org1', 'bob', 'active'), ('org1', 'carol', 'deactivated');
             INSERT INTO teams VALUES ('team_root', NULL), ('team_leaf', 'team_root');
             INSERT INTO team_members VALUES ('team_leaf', 'dave'), ('team_root', 'erin');
             INSERT INTO projects VALUES ('p_user', 'org1'), ('p_org', 'org1'), ('p_root', 'org1'),
               ('p_leaf', 'org1'), ('p_everyone', 'org1'), ('p_signed', 'org1'),
               ('p_anonymous', 'org1');
             INSERT INTO project_grants VALUES ('p_user', 'alice'), ('p_org', 'org1'),
               ('p_root', 'team_root'), ('p_leaf', 'team_leaf'), ('p_everyone', 'everyone'),
               ('p_signed', 'signed_in'), ('p_anonymous', 'anonymous');
             INSERT INTO docs VALUES ('d_user', 'p_user', NULL), ('d_org', 'p_org', NULL),
               ('d_root', 'p_root', NULL), ('d_leaf', 'p_leaf', NULL),
               ('d_everyone', 'p_everyone', NULL), ('d_signed', 'p_signed', NULL),
               ('d_anonymous', 'p_anonymous', NULL)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        [
            "alice",
            "bob",
            "carol",
            "dave",
            "erin",
            "anonymous",
            "org1",
            "team_leaf",
        ]
            .into_iter()
            .map(caller)
            .collect(),
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(GRANTEE_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn grants_naming_typed_grantees_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for (caller_arm, gated, inline) in [
            (CALLER_ARM, false, false),
            (USER_CALLER_ARM, false, false),
            (CALLER_ARM, true, false),
            (CALLER_ARM, true, true),
        ] {
            for loading_from_rows in [false, true] {
                let case = grantees_case(major, caller_arm, gated, inline, loading_from_rows);
                let run =
                    support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
                let expect = |subject: &str, object: &str, allowed| {
                    assert_postgres(
                        &case,
                        &run,
                        subject,
                        object,
                        ActionStatement::Select,
                        allowed,
                    );
                };
                // A user grant reaches that user alone.
                expect("alice", "docs:d_user", true);
                expect("bob", "docs:d_user", false);
                // An organization grant reaches its active members, unless the set holds
                // only the caller and the audiences.
                expect("bob", "docs:d_org", !inline);
                expect("carol", "docs:d_org", false);
                // A team grant reaches the team's members and those of every team below.
                expect("dave", "docs:d_leaf", !inline);
                expect("dave", "docs:d_root", !inline);
                expect("erin", "docs:d_root", !inline);
                expect("erin", "docs:d_leaf", false);
                // Everyone includes a request without a caller unless the grant arm's
                // gate excludes it, and signed-in always excludes it.
                expect("anonymous", "docs:d_everyone", !gated);
                expect("anonymous", "docs:d_signed", false);
                expect("carol", "docs:d_signed", true);
                // A caller spelling a grantee's id is that grantee only where the arm
                // reads every kind, and climbs the teams above it like a member would.
                expect("org1", "docs:d_org", caller_arm == CALLER_ARM);
                expect(
                    "team_leaf",
                    "docs:d_root",
                    caller_arm == CALLER_ARM && !inline,
                );
                // A grant naming the caller the grant arm's gate excludes holds it nowhere.
                expect("anonymous", "docs:d_anonymous", !gated);
                assert_agrees(&case, &run);
            }
        }
    }
}

const EXPIRING_HELPERS: &str = r#"{
    "authz.projects_granted": { "kind": "declared_helper" }
}"#;

/// `alice` holds an open grant, `bob` one ending tomorrow, `carol` one that ended
/// yesterday, `dave` one starting next month, and `erin` one ending in two years.
fn expiring_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-expiry-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        EXPIRING,
        &[
            "INSERT INTO projects VALUES ('P1'), ('P2');
             INSERT INTO docs VALUES ('d1', 'P1', NULL), ('d2', 'P2', NULL);
             INSERT INTO project_grants VALUES
               ('P1', 'alice', now() - interval '1 day', NULL),
               ('P1', 'bob', now() - interval '1 day', now() + interval '1 day'),
               ('P1', 'carol', now() - interval '2 days', now() - interval '1 day'),
               ('P1', 'dave', now() + interval '1 month', NULL),
               ('P2', 'erin', now() - interval '1 day', now() + interval '2 years')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        ["alice", "bob", "carol", "dave", "erin"]
            .into_iter()
            .map(|subject| caller(subject).with_clock())
            .collect(),
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(EXPIRING_HELPERS)
    .also_at(
        "1 year",
        "SELECT g.grantee_id AS subject, 'docs:' || d.id AS object
         FROM docs d JOIN project_grants g ON g.project_id = d.project_id
         WHERE g.starts_at <= $1::timestamptz
           AND (g.expires_at IS NULL OR g.expires_at > $1::timestamptz)",
    );
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn expiring_grants_agree_with_postgres_17_and_18_now_and_a_year_on() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = expiring_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            for (subject, allowed) in [
                ("alice", true),
                ("bob", true),
                ("carol", false),
                ("dave", false),
            ] {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    "docs:d1",
                    ActionStatement::Select,
                    allowed,
                );
            }
            assert_postgres(
                &case,
                &run,
                "erin",
                "docs:d2",
                ActionStatement::Select,
                true,
            );
            assert_agrees(&case, &run);
        }
    }
}

const INVITATION_HELPERS: &str = r#"{
    "authz.pending_invitations": { "kind": "declared_helper" },
    "authz.claimable": { "kind": "declared_helper" },
    "authz.addressed": { "kind": "declared_helper" },
    "authz.live_links": { "kind": "declared_helper" }
}"#;

/// The callers of [`invitations_case`], each with the address it presents, `None`
/// leaving it unset, and the links it presents.
const INVITEES: [(&str, Option<&str>, &str); 5] = [
    ("ann", Some("Ann@Example.com"), "l1"),
    ("emile", Some("ÉMILE@EXAMPLE.COM"), "l2"),
    ("bob", Some("bob@example.com"), "l3"),
    ("carol", Some("carol@example.com"), ""),
    ("unset", None, "l1,l2"),
];

/// `ann`'s invitation ends tomorrow and `emile`'s in two years, `bob` accepted his,
/// and `carol`'s ended yesterday. `l1` ends tomorrow, `l2` in two years and `l3`
/// ended yesterday.
fn invitations_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let principals = INVITEES
        .iter()
        .map(|(subject, email, links)| {
            let mut principal = Principal::as_role(subject, "app_reader")
                .with_context(serde_json::json!({
                    "app_link_ids": links.split(',').filter(|link| !link.is_empty()).collect::<Vec<_>>()
                }))
                .with_clock();
            if let Some(email) = email {
                principal
                    .session
                    .push(("app.verified_email".into(), (*email).into()));
            }
            principal
                .session
                .push(("app.link_ids".into(), (*links).into()));
            principal
        })
        .collect();
    let callers = INVITEES
        .iter()
        .map(|(subject, email, links)| {
            format!(
                "('{subject}', {}, '{links}')",
                email.map_or_else(|| "NULL::text".to_string(), |email| format!("'{email}'"))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-invitations-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        INVITATIONS,
        &[
            "INSERT INTO invitations VALUES
               ('i1', 'ann@example.com', NULL, now() + interval '1 day'),
               ('i2', 'émile@example.com', NULL, now() + interval '2 years'),
               ('i3', 'bob@example.com', 'bob', now() + interval '1 day'),
               ('i4', 'carol@example.com', NULL, now() - interval '1 day');
             INSERT INTO share_links VALUES
               ('l1', now() + interval '1 day'),
               ('l2', now() + interval '2 years'),
               ('l3', now() - interval '1 day');
             INSERT INTO memberships VALUES
               ('m1', 'i1'), ('m2', 'i2'), ('m3', 'i3'), ('m4', 'i4'), ('m5', NULL);
             INSERT INTO claims VALUES ('c1', 'i1'), ('c2', 'i2'), ('c3', 'i3'), ('c4', 'i4');
             INSERT INTO notices VALUES ('n1', 'i1'), ('n3', 'i3'), ('n4', 'i4');
             INSERT INTO docs VALUES ('d1', 'l1'), ('d2', 'l2'), ('d3', 'l3')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON memberships, claims, notices, docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        principals,
    )
    .with_settings([
        support::deployment::scalar("app.verified_email").may_be_unset(),
        support::deployment::delimited_set("app.link_ids", ","),
    ])
    .with_registry(INVITATION_HELPERS)
    .also_at(
        "1 year",
        &format!(
            "WITH callers (subject, email, links) AS (VALUES {callers}),
                  presented AS (
                    SELECT c.subject, i.id, i.accepted_by, i.expires_at, i.email = lower(c.email) AS lowered,
                           i.email = c.email AS exact
                    FROM callers c JOIN invitations i ON i.email IN (lower(c.email), c.email))
             SELECT p.subject, 'memberships:' || m.id AS object
             FROM presented p JOIN memberships m ON m.invitation_id = p.id
             WHERE p.lowered AND p.accepted_by IS NULL AND p.expires_at > $1::timestamptz
             UNION ALL
             SELECT p.subject, 'claims:' || c.id FROM presented p JOIN claims c ON c.invitation_id = p.id
             WHERE p.lowered
             UNION ALL
             SELECT p.subject, 'notices:' || n.id FROM presented p JOIN notices n ON n.invitation_id = p.id
             WHERE p.exact
             UNION ALL
             SELECT c.subject, 'docs:' || d.id
             FROM callers c JOIN share_links l ON l.id = ANY (string_to_array(c.links, ','))
               JOIN docs d ON d.link_id = l.id
             WHERE l.expires_at > $1::timestamptz"
        ),
    );
    case.loading_from_rows = loading_from_rows;
    case
}

/// A grant arm comparing its column with the lowered request address, through the
/// accessor and inline, or with the address as sent, and a set kept while its rows last,
/// agree with `PostgreSQL` now and a year on.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn request_values_behind_helpers_agree_with_postgres_17_and_18_now_and_a_year_on() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = invitations_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            for (subject, object, allowed) in [
                ("ann", "memberships:m1", true),
                ("ann", "claims:c1", true),
                ("ann", "notices:n1", false),
                ("ann", "docs:d1", true),
                ("emile", "memberships:m2", true),
                ("emile", "claims:c2", true),
                ("emile", "docs:d2", true),
                ("bob", "memberships:m3", false),
                ("bob", "claims:c3", true),
                ("bob", "notices:n3", true),
                ("bob", "docs:d3", false),
                ("carol", "memberships:m4", false),
                ("carol", "claims:c4", true),
                ("carol", "notices:n4", true),
                ("unset", "memberships:m1", false),
                ("unset", "claims:c1", false),
                ("unset", "docs:d1", true),
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

/// One bound over grant rows that can repeat: `bob` holds one grant that ended and one
/// ending tomorrow, `frank` one that ended and one with no end.
fn repeated_expiry_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let schema = EXPIRING
        .replace(",\n  PRIMARY KEY (project_id, grantee_id)", "")
        .replace("    AND now() >= pg.starts_at\n", "");
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-repeated-expiry-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &schema,
        &[
            "INSERT INTO projects VALUES ('P1');
             INSERT INTO docs VALUES ('d1', 'P1', NULL);
             INSERT INTO project_grants VALUES
               ('P1', 'bob', now(), now() - interval '1 day'),
               ('P1', 'bob', now(), now() + interval '1 day'),
               ('P1', 'frank', now(), now() - interval '1 day'),
               ('P1', 'frank', now(), NULL)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        ["bob", "frank", "erin"]
            .into_iter()
            .map(|subject| caller(subject).with_clock())
            .collect(),
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(EXPIRING_HELPERS)
    .also_at(
        "1 year",
        "SELECT DISTINCT g.grantee_id AS subject, 'docs:' || d.id AS object
         FROM docs d JOIN project_grants g ON g.project_id = d.project_id
         WHERE g.expires_at IS NULL OR g.expires_at > $1::timestamptz",
    );
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn repeated_expiring_grants_agree_with_postgres_now_and_a_year_on() {
    let cluster = Cluster::start().await;
    for loading_from_rows in [false, true] {
        let case = repeated_expiry_case("18", loading_from_rows);
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
        for (subject, allowed) in [("bob", true), ("frank", true), ("erin", false)] {
            assert_postgres(
                &case,
                &run,
                subject,
                "docs:d1",
                ActionStatement::Select,
                allowed,
            );
        }
        assert_agrees(&case, &run);
    }
}

const CONTAINMENT_HELPERS: &str = r#"{
    "authz.owned_folders": { "kind": "declared_helper" }
}"#;

/// A folder is read by the owner of both it and its parent.
const CONTAINED_KEYS: &str = "
CREATE POLICY folders_read ON folders FOR SELECT USING (
  ARRAY[id, parent_id] <@ ARRAY(SELECT authz.owned_folders()));
";

/// `alice` owns the root `f1`, `f2` under it and `f4` under `bob`'s `f3`.
fn containment_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-containment-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!("{FOLDERS}{CONTAINED_KEYS}"),
        &[
            "INSERT INTO folders VALUES ('f1', NULL, 'alice', NULL), ('f2', 'f1', 'alice', NULL),
               ('f3', 'f1', 'bob', NULL), ('f4', 'f3', 'alice', NULL)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON folders TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller("alice"),
            caller("bob"),
            caller("erin"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(CONTAINMENT_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn contained_row_keys_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = containment_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, statement, allowed| {
                assert_postgres(&case, &run, subject, object, statement, allowed);
            };
            expect("alice", "folders:f2", ActionStatement::Select, true);
            // A root's `NULL` parent makes the containment false.
            expect("alice", "folders:f1", ActionStatement::Select, false);
            // Each key must be in the set, a parent owned by someone else failing it.
            expect("alice", "folders:f4", ActionStatement::Select, false);
            expect("bob", "folders:f3", ActionStatement::Select, false);
            expect("erin", "folders:f2", ActionStatement::Select, false);
            expect("anonymous", "folders:f2", ActionStatement::Select, false);
            assert_agrees(&case, &run);
        }
    }
}

const CAP_HELPERS: &str = r#"{
    "authz.capped_kinds": { "kind": "declared_helper" },
    "authz.member_organizations": { "kind": "declared_helper" },
    "authz.owned_resources": { "kind": "declared_helper" }
}"#;

/// The two organizations, `…a1` and `…a2`.
const ORGANIZATIONS: [&str; 2] = [
    "0a000000-0000-4000-8000-0000000000a1",
    "0a000000-0000-4000-8000-0000000000a2",
];

/// Installations `…f1` and `…f2` in the first organization and `…f3` in the second.
const INSTALLATIONS_ACTING: [&str; 3] = [
    "0f000000-0000-4000-8000-0000000000f1",
    "0f000000-0000-4000-8000-0000000000f2",
    "0f000000-0000-4000-8000-0000000000f3",
];

/// The member reading with `installation` set, `None` leaving it unset and `""` standing
/// for a pooled connection that once carried one.
const CAPPED_MEMBERS: [(&str, Option<&str>); 5] = [
    ("0b000000-0000-4000-8000-000000000001", None),
    ("0b000000-0000-4000-8000-000000000002", Some("")),
    (
        "0b000000-0000-4000-8000-000000000003",
        Some(INSTALLATIONS_ACTING[0]),
    ),
    (
        "0b000000-0000-4000-8000-000000000004",
        Some(INSTALLATIONS_ACTING[1]),
    ),
    (
        "0b000000-0000-4000-8000-000000000005",
        Some(INSTALLATIONS_ACTING[2]),
    ),
];

/// The resource member `member` owns in `organization` of `kind`, numbered as the three
/// [`row_caps_case`] seeds.
fn owned_resource(member: usize, resource: usize) -> String {
    format!("0c000000-0000-4000-8000-0000000000{member}{resource}")
}

/// Every member belongs to both organizations, each holding a note and three resources.
/// `…f1` holds `organization` as reader and `project` as writer, `…f2` holds
/// `organization` as admin and `project` as reader, both in the first organization, and
/// `…f3` holds `project` as admin in the second.
fn row_caps_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let [a1, a2] = ORGANIZATIONS;
    let [f1, f2, f3] = INSTALLATIONS_ACTING;
    let mut seed = format!(
        "INSERT INTO organizations VALUES ('{a1}'), ('{a2}');
         INSERT INTO organization_notes VALUES
           ('0d000000-0000-4000-8000-0000000000a1', '{a1}'),
           ('0d000000-0000-4000-8000-0000000000a2', '{a2}');
         INSERT INTO app_installations VALUES ('{f1}', '{a1}'), ('{f2}', '{a1}'), ('{f3}', '{a2}');
         INSERT INTO installation_permissions (installation_id, organization_id, kind, max_role)
         VALUES
           ('{f1}', '{a1}', 'organization', 'reader'), ('{f1}', '{a1}', 'project', 'writer'),
           ('{f2}', '{a1}', 'organization', 'admin'), ('{f2}', '{a1}', 'project', 'reader'),
           ('{f3}', '{a2}', 'project', 'admin');"
    );
    for (index, (member, _)) in CAPPED_MEMBERS.iter().enumerate() {
        let number = index + 1;
        let _ = write!(
            seed,
            "INSERT INTO memberships VALUES ('{a1}', '{member}'), ('{a2}', '{member}');
             INSERT INTO resources VALUES
               ('{}', '{a1}', 'project', '{member}'),
               ('{}', '{a1}', 'organization', '{member}'),
               ('{}', '{a2}', 'project', '{member}');",
            owned_resource(number, 1),
            owned_resource(number, 2),
            owned_resource(number, 3),
        );
    }
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-row-caps-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        INSTALLATION_CAPS,
        &[
            &seed,
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON organizations, organization_notes, resources TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        CAPPED_MEMBERS
            .iter()
            .map(|(member, installation)| acting(member, Some(member), *installation))
            .collect(),
    )
    .with_settings([
        support::deployment::typed_caller("app.user_id", DataType::Uuid).may_be_unset(),
        support::deployment::principal("app.installation_id", "installation", DataType::Uuid)
            .may_be_unset(),
    ])
    .with_registry(CAP_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

/// A request leaving the installation unset or empty reads every organization, note and
/// resource of its member. One acting through an installation reads an organization and
/// its notes where the installation holds `organization` there at reader or above, and a
/// resource where it holds the resource's kind in the resource's organization at writer or
/// above.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn row_caps_agree_with_postgres_17_and_18() {
    let [a1, a2] = ORGANIZATIONS;
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = row_caps_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            for (index, (member, organizations, resources)) in [
                (CAPPED_MEMBERS[0].0, [true, true], [true, true, true]),
                (CAPPED_MEMBERS[1].0, [true, true], [true, true, true]),
                (CAPPED_MEMBERS[2].0, [true, false], [true, false, false]),
                (CAPPED_MEMBERS[3].0, [true, false], [false, true, false]),
                (CAPPED_MEMBERS[4].0, [false, false], [false, false, true]),
            ]
            .into_iter()
            .enumerate()
            {
                let expect = |object: String, allowed| {
                    assert_postgres(
                        &case,
                        &run,
                        member,
                        &object,
                        ActionStatement::Select,
                        allowed,
                    );
                };
                for ((organization, note), allowed) in
                    [(a1, "a1"), (a2, "a2")].into_iter().zip(organizations)
                {
                    expect(format!("organizations:{organization}"), allowed);
                    expect(
                        format!("organization_notes:0d000000-0000-4000-8000-0000000000{note}"),
                        allowed,
                    );
                }
                for (resource, allowed) in (1..=3).zip(resources) {
                    expect(
                        format!("resources:{}", owned_resource(index + 1, resource)),
                        allowed,
                    );
                }
            }
            assert_agrees(&case, &run);
        }
    }
}

/// Teams `…e1` in the first organization and `…e2` in the second.
const CAPPED_TEAMS: [&str; 2] = [
    "0e000000-0000-4000-8000-0000000000e1",
    "0e000000-0000-4000-8000-0000000000e2",
];

/// Each request of [`joined_caps_case`], its own user acting as one of four profiles,
/// through the installation acting for it, `None` leaving the installation unset and `""`
/// standing for a pooled connection that once carried one.
fn joined_cap_requests() -> [(String, usize, Option<&'static str>); 8] {
    let [f1, f2, f3] = INSTALLATIONS_ACTING;
    let mut index = 0;
    [
        (0, None),
        (0, Some("")),
        (0, Some(f1)),
        (0, Some(f2)),
        (1, Some(f1)),
        (1, Some(f3)),
        (2, None),
        (3, Some(f1)),
    ]
    .map(|(profile, installation)| {
        index += 1;
        (
            format!("0b000000-0000-4000-8000-0000000001{index:02}"),
            profile,
            installation,
        )
    })
}

/// The user of each request of [`joined_cap_requests`] holds the rows of its profile. The
/// first administers `…e1` and is a member of `…e2`, the second administers `…e2`, the
/// third administers `…e1` through a deactivated membership, and the fourth is a member of
/// `…e1`. Memberships scope `organization` for the first and third in the first
/// organization and `project` otherwise. `…f1` holds `organization` as admin and `project`
/// as reader and `…f2` holds `organization` as writer, both in the first organization, and
/// `…f3` holds `organization` as admin in the second. Teams are read through `helper`.
fn joined_caps_case(major: &str, helper: &str, loading_from_rows: bool) -> ParityCase {
    let [a1, a2] = ORGANIZATIONS;
    let [f1, f2, f3] = INSTALLATIONS_ACTING;
    let [e1, e2] = CAPPED_TEAMS;
    let mut seed = format!(
        "INSERT INTO organizations VALUES ('{a1}'), ('{a2}');
         INSERT INTO app_installations VALUES ('{f1}', '{a1}'), ('{f2}', '{a1}'), ('{f3}', '{a2}');
         INSERT INTO installation_permissions (installation_id, organization_id, kind, max_role)
         VALUES
           ('{f1}', '{a1}', 'organization', 'admin'), ('{f1}', '{a1}', 'project', 'reader'),
           ('{f2}', '{a1}', 'organization', 'writer'),
           ('{f3}', '{a2}', 'organization', 'admin');
         INSERT INTO teams VALUES ('{e1}', '{a1}'), ('{e2}', '{a2}');"
    );
    for (user, profile, _) in joined_cap_requests() {
        let (memberships, members) = match profile {
            0 => (
                format!("('{a1}', '{user}', 'active', 'organization'), ('{a2}', '{user}', 'active', 'project')"),
                format!("('{e1}', '{a1}', '{user}', 'admin'), ('{e2}', '{a2}', '{user}', 'member')"),
            ),
            1 => (
                format!("('{a2}', '{user}', 'active', 'project')"),
                format!("('{e2}', '{a2}', '{user}', 'admin')"),
            ),
            2 => (
                format!("('{a1}', '{user}', 'deactivated', 'organization')"),
                format!("('{e1}', '{a1}', '{user}', 'admin')"),
            ),
            _ => (
                format!("('{a1}', '{user}', 'active', 'project')"),
                format!("('{e1}', '{a1}', '{user}', 'member')"),
            ),
        };
        let _ = write!(
            seed,
            "INSERT INTO memberships VALUES {memberships};
             INSERT INTO team_members VALUES {members};"
        );
    }
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-{}-pg{major}{}",
            helper.replace('_', "-"),
            if loading_from_rows { "-rows" } else { "" }
        ),
        &crate::row_cap_tests::joined_caps_reading(helper),
        &[
            &seed,
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON teams, team_members TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        joined_cap_requests()
            .into_iter()
            .map(|(user, _, installation)| acting(&user, Some(&user), installation))
            .collect(),
    )
    .with_settings([
        support::deployment::typed_caller("app.user_id", DataType::Uuid).may_be_unset(),
        support::deployment::principal("app.installation_id", "installation", DataType::Uuid)
            .may_be_unset(),
    ])
    .with_registry(
        r#"{
            "authz.capped_kinds": { "kind": "declared_helper" },
            "authz.administered_teams": { "kind": "declared_helper" },
            "authz.capped_teams": { "kind": "declared_helper" },
            "authz.scoped_teams": { "kind": "declared_helper" }
        }"#,
    );
    case.loading_from_rows = loading_from_rows;
    case
}

/// A request leaving the installation unset or empty reads the teams of every member row
/// its helper keeps. One acting through an installation reads a team where the
/// installation holds the kind the cap names in the organization it names:
/// `administered_teams` the membership's organization as `organization` at admin,
/// `capped_teams` the member row's organization as `organization` at writer, and
/// `scoped_teams` the membership's organization as the membership's scope at reader.
/// Member rows are read through `administered_teams` in every case.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn caps_over_joined_rows_agree_with_postgres_17_and_18() {
    let [e1, e2] = CAPPED_TEAMS;
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for (helper, teams) in [
            (
                "administered_teams",
                [
                    [true, false],
                    [true, false],
                    [true, false],
                    [false, false],
                    [false, false],
                    [false, true],
                    [false, false],
                    [false, false],
                ],
            ),
            (
                "capped_teams",
                [
                    [true, true],
                    [true, true],
                    [true, false],
                    [true, false],
                    [false, false],
                    [false, true],
                    [true, false],
                    [true, false],
                ],
            ),
            (
                "scoped_teams",
                [
                    [true, true],
                    [true, true],
                    [true, false],
                    [true, false],
                    [false, false],
                    [false, false],
                    [true, false],
                    [true, false],
                ],
            ),
        ] {
            for loading_from_rows in [false, true] {
                let case = joined_caps_case(major, helper, loading_from_rows);
                let run =
                    support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
                for ((subject, _, _), allowed) in joined_cap_requests().into_iter().zip(teams) {
                    for (team, allowed) in [e1, e2].into_iter().zip(allowed) {
                        assert_postgres(
                            &case,
                            &run,
                            &subject,
                            &format!("teams:{team}"),
                            ActionStatement::Select,
                            allowed,
                        );
                    }
                }
                assert_agrees(&case, &run);
            }
        }
    }
}

/// `t1` holds `bob`, `carol`, whose deactivated membership has expired, and `dave`, whose
/// active membership expires, `t2` holds `alice` and `bob`, and `bob`'s membership is
/// deactivated where `deactivated`. Teams are read through `helper`.
fn membership_states_case(
    major: &str,
    helper: &str,
    deactivated: bool,
    loading_from_rows: bool,
) -> ParityCase {
    let bob = if deactivated { "deactivated" } else { "active" };
    let mut case = ParityCase::reading(
        &format!(
            "declared-helper-{}-pg{major}{}{}",
            helper.replace('_', "-"),
            if deactivated { "-deactivated" } else { "" },
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!(
            "{MEMBERSHIP_STATES}CREATE POLICY teams_read ON teams FOR SELECT \
             USING (id IN (SELECT authz.{helper}()));"
        ),
        &[
            &format!(
                "INSERT INTO memberships VALUES ('org1', 'alice', 'active', NULL),
                   ('org1', 'bob', '{bob}', NULL),
                   ('org1', 'carol', 'deactivated', '2000-01-01'),
                   ('org1', 'dave', 'active', '2099-01-01');
                 INSERT INTO teams VALUES ('t1', 'org1'), ('t2', 'org1');
                 INSERT INTO team_members VALUES ('t1', 'org1', 'bob'), ('t1', 'org1', 'carol'),
                   ('t1', 'org1', 'dave'), ('t2', 'org1', 'alice'), ('t2', 'org1', 'bob')"
            ),
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON teams TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        ["alice", "bob", "carol", "dave", "anonymous"]
            .into_iter()
            .map(caller)
            .collect(),
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(&format!(
        r#"{{ "authz.{helper}": {{ "kind": "declared_helper" }} }}"#
    ));
    case.loading_from_rows = loading_from_rows;
    case
}

/// A member reads the teams whose membership row the helper keeps. A bare join keeps every
/// member, a join on the state or an anti-join on deactivation keeps active ones, a join on
/// both keeps active ones never expiring, and an anti-join on the expiry keeps those never
/// expiring. Deactivating `bob` moves only the helpers reading the state.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn grant_arms_kept_by_membership_state_agree_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for (helper, by_state, carol, dave) in [
            ("joined_teams", true, false, true),
            ("unblocked_teams", true, false, true),
            ("member_teams", false, true, true),
            ("current_teams", true, false, false),
            ("unexpiring_teams", false, false, false),
        ] {
            for deactivated in [false, true] {
                for loading_from_rows in [false, true] {
                    let case =
                        membership_states_case(major, helper, deactivated, loading_from_rows);
                    let run =
                        support::parity::run_before(&cluster, &case, Duration::from_secs(180))
                            .await;
                    let expect = |subject: &str, team: &str, allowed| {
                        assert_postgres(
                            &case,
                            &run,
                            subject,
                            &format!("teams:{team}"),
                            ActionStatement::Select,
                            allowed,
                        );
                    };
                    expect("alice", "t1", false);
                    expect("alice", "t2", true);
                    expect("bob", "t1", !(by_state && deactivated));
                    expect("bob", "t2", !(by_state && deactivated));
                    expect("carol", "t1", carol);
                    expect("dave", "t1", dave);
                    expect("anonymous", "t2", false);
                    assert_agrees(&case, &run);
                }
            }
        }
    }
}
