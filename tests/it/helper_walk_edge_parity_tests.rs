//! Declared helpers walking the edges their term keeps, compared against `PostgreSQL` 18,
//! with both tuple loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;

use crate::helper_walk_edge_tests::{CONTAINERS_SELECT, EDGE_CONDITIONS, TEMPLATES_SELECT};
use crate::support;
use crate::support::parity::{assert_agrees, assert_postgres, ParityCase, Principal};

const EDGE_HELPERS: &str = r#"{
    "authz.blocking_organizations": { "kind": "declared_helper" },
    "authz.readable_templates": { "kind": "declared_helper" },
    "authz.watched_templates": { "kind": "declared_helper" },
    "authz.enclosing_assets": { "kind": "declared_helper" },
    "authz.folders_below": { "kind": "declared_helper" },
    "authz.folders_above": { "kind": "declared_helper" }
}"#;

const ORGANIZATIONS: &str = "INSERT INTO organizations VALUES ('O1'), ('O2');
     INSERT INTO organization_blocks VALUES ('O1', 'alice'), ('O2', 'carol'), ('O2', 'dave')";

fn caller(subject: &str) -> Principal {
    Principal::with_setting(subject, "app_reader", "app.user_id", subject)
}

fn reader(tables: &str) -> String {
    format!(
        "CREATE ROLE app_reader LOGIN;
         GRANT SELECT ON {tables} TO app_reader;
         GRANT USAGE ON SCHEMA authz TO app_reader;
         REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader"
    )
}

/// `O1` blocks `alice` and `O2` blocks `carol`, all three holding `t_root`. `t_shared`
/// runs under `t_mid` through an `O1` step and under `t_root` through an `O2` one, `t_draft`
/// is no run, `t_expired`'s step ended yesterday and `t_open`'s ends tomorrow.
fn templates_case(loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "helper-walk-edge-templates{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!("{EDGE_CONDITIONS}{TEMPLATES_SELECT}"),
        &[
            &format!(
                "{ORGANIZATIONS};
                 INSERT INTO templates VALUES ('t_root'), ('t_mid'), ('t_leaf'), ('t_shared'),
                   ('t_deep'), ('t_draft'), ('t_expired'), ('t_open');
                 INSERT INTO template_grants VALUES
                   ('t_root', 'alice'), ('t_root', 'bob'), ('t_root', 'carol');
                 INSERT INTO template_steps VALUES
                   ('s1', 't_root', 't_mid', 'O2', 'run', NULL),
                   ('s2', 't_mid', 't_leaf', 'O1', 'run', NULL),
                   ('s3', 't_mid', 't_shared', 'O1', 'run', NULL),
                   ('s4', 't_root', 't_shared', 'O2', 'run', NULL),
                   ('s5', 't_root', 't_draft', 'O2', 'draft', NULL),
                   ('s6', 't_root', 't_expired', 'O2', 'run', now() - interval '1 day'),
                   ('s7', 't_root', 't_open', 'O2', 'run', now() + interval '1 day'),
                   ('s8', 't_leaf', 't_deep', 'O2', 'run', NULL);
                 INSERT INTO template_watchers VALUES ('t_root', 'dave')"
            ),
            &reader("templates"),
        ],
        ["alice", "bob", "carol", "dave", "erin"]
            .into_iter()
            .map(|subject| caller(subject).with_clock())
            .collect(),
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(EDGE_HELPERS)
    .also_at(
        "1 year",
        "WITH RECURSIVE readable (subject, id) AS (
           SELECT g.user_id, g.template_id FROM template_grants g
           UNION
           SELECT readable.subject, step.child_template_id FROM template_steps step
           JOIN readable ON readable.id = step.parent_template_id
           WHERE step.kind = 'run' AND (step.ends_at IS NULL OR step.ends_at > $1::timestamptz)
             AND NOT EXISTS (SELECT 1 FROM organization_blocks b
               WHERE b.organization_id = step.organization_id
                 AND b.principal_id = readable.subject)
         ), watched (subject, id) AS (
           SELECT w.user_id, w.template_id FROM template_watchers w
           UNION
           SELECT watched.subject, step.child_template_id FROM template_steps step
           JOIN watched ON watched.id = step.parent_template_id
           WHERE step.kind = 'run'
         )
         SELECT subject, 'templates:' || id AS object FROM readable
         UNION SELECT subject, 'templates:' || id FROM watched",
    );
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_walk_over_blocked_and_bounded_steps_agrees_with_postgres_now_and_a_year_on() {
    let cluster = support::parity::Cluster::start().await;
    for loading_from_rows in [false, true] {
        let case = templates_case(loading_from_rows);
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
        // Every run step reaches its template while it lasts.
        for template in ["t_root", "t_mid", "t_leaf", "t_shared", "t_deep", "t_open"] {
            expect("bob", &format!("templates:{template}"), true);
        }
        expect("bob", "templates:t_draft", false);
        expect("bob", "templates:t_expired", false);
        // A block stops the walk at the blocked steps alone, so a template under another
        // step stays reached.
        expect("alice", "templates:t_mid", true);
        expect("alice", "templates:t_leaf", false);
        expect("alice", "templates:t_deep", false);
        expect("alice", "templates:t_shared", true);
        expect("carol", "templates:t_root", true);
        expect("carol", "templates:t_mid", false);
        expect("carol", "templates:t_shared", false);
        // Watching keeps the steps of its kind whatever blocks or bounds them.
        for template in ["t_mid", "t_deep", "t_expired"] {
            expect("dave", &format!("templates:{template}"), true);
        }
        expect("dave", "templates:t_draft", false);
        expect("erin", "templates:t_root", false);
        assert_agrees(&case, &run);
    }
}

/// `O1` blocks `alice`, `O2` blocks `carol` and `dave`. `a_vial` sits in `a_box` through
/// an `O1` placement and on `a_shelf` through an `O2` one, and both sit in `a_room`, the
/// box through `O2` and the shelf through `O1`. The vial's placement on `a_cart` has not
/// completed and its move into `a_bin` is no placement into it. The folders `f_a`, shared,
/// and `f_b`, private, sit under `f_root`, and the shared `f_c` under `f_a`.
fn containers_case(loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "helper-walk-edge-containers{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        &format!("{EDGE_CONDITIONS}{CONTAINERS_SELECT}"),
        &[
            &format!(
                "{ORGANIZATIONS};
                 INSERT INTO assets VALUES ('a_vial'), ('a_box'), ('a_shelf'), ('a_room'),
                   ('a_cart'), ('a_bin');
                 INSERT INTO asset_grants VALUES
                   ('a_vial', 'alice'), ('a_vial', 'bob'), ('a_vial', 'carol');
                 INSERT INTO placements VALUES
                   ('a_vial', 'a_box', 'into', 'completed', 'O1'),
                   ('a_vial', 'a_shelf', 'into', 'completed', 'O2'),
                   ('a_box', 'a_room', 'into', 'completed', 'O2'),
                   ('a_shelf', 'a_room', 'into', 'completed', 'O1'),
                   ('a_vial', 'a_cart', 'into', 'started', 'O2'),
                   ('a_vial', 'a_bin', 'out', 'completed', 'O2');
                 INSERT INTO folders VALUES ('f_root', NULL, 'shared', 'O1'),
                   ('f_a', 'f_root', 'shared', 'O2'), ('f_b', 'f_root', 'private', 'O2'),
                   ('f_c', 'f_a', 'shared', 'O1');
                 INSERT INTO folder_grants VALUES
                   ('f_root', 'alice'), ('f_root', 'bob'), ('f_root', 'carol'), ('f_c', 'dave')"
            ),
            &reader("assets, folders"),
        ],
        vec![
            caller("alice"),
            caller("bob"),
            caller("carol"),
            caller("dave"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .with_registry(EDGE_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn walks_over_blocked_placements_and_folders_agree_with_postgres() {
    let cluster = support::parity::Cluster::start().await;
    for loading_from_rows in [false, true] {
        let case = containers_case(loading_from_rows);
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
        // Completed placements into a container reach it, whichever path leads there.
        for asset in ["a_vial", "a_box", "a_shelf", "a_room"] {
            expect("bob", &format!("assets:{asset}"), true);
        }
        expect("bob", "assets:a_cart", false);
        expect("bob", "assets:a_bin", false);
        // A block stops each path at its blocked placement.
        expect("alice", "assets:a_shelf", true);
        expect("alice", "assets:a_box", false);
        expect("alice", "assets:a_room", false);
        expect("carol", "assets:a_box", true);
        expect("carol", "assets:a_shelf", false);
        expect("carol", "assets:a_room", false);
        // Down a tree of its own rows, the child's kind and organization decide.
        expect("bob", "folders:f_c", true);
        expect("bob", "folders:f_b", false);
        expect("alice", "folders:f_a", true);
        expect("alice", "folders:f_c", false);
        expect("carol", "folders:f_a", false);
        // Up the tree, the organization of the folder left behind decides.
        expect("dave", "folders:f_a", true);
        expect("dave", "folders:f_root", false);
        expect("anonymous", "folders:f_root", false);
        assert_agrees(&case, &run);
    }
}
