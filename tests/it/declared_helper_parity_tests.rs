//! Declared definer helpers compared against `PostgreSQL` 17 and 18, with both tuple
//! loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;

use crate::declared_helper_blocklist_tests::{BLOCKS, DOCS_UNBLOCKED, PROJECTS_UNBLOCKED};
use crate::declared_helper_tests::{
    caller_and_audiences_only, AUDIENCES, GRANTEES, GROUPS, INSTALLATIONS, LEVELS, ORDERS,
    OWNER_READS, REQUEST_VALUES,
};
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
