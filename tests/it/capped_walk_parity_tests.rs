//! Declared helpers capping their walks and parent arms, compared against `PostgreSQL` 18,
//! with both tuple loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::fmt::Write as _;
use core::time::Duration;

use rls2fga::types::ActionStatement;
use sqlparser::ast::DataType;

use crate::capped_walk_tests::CAPPED_WALKS;
use crate::support;
use crate::support::parity::{assert_agrees, assert_postgres, ParityCase, Principal};

const CAPPED_WALK_HELPERS: &str = r#"{
    "authz.capped_kinds": { "kind": "declared_helper" },
    "authz.blocking_organizations": { "kind": "declared_helper" },
    "authz.reached_resources": { "kind": "declared_helper" },
    "authz.capped_children": { "kind": "declared_helper" },
    "authz.open_projects": { "kind": "declared_helper" },
    "authz.shortcut_targets": { "kind": "declared_helper" }
}"#;

const ORGANIZATIONS: [&str; 2] = [
    "0a000000-0000-4000-8000-0000000000a1",
    "0a000000-0000-4000-8000-0000000000a2",
];

const INSTALLATIONS: [&str; 2] = [
    "0f000000-0000-4000-8000-0000000000f1",
    "0f000000-0000-4000-8000-0000000000f2",
];

const RESOURCES: [&str; 6] = ["11", "12", "13", "14", "21", "22"];

/// A member reading through `installation`, `None` leaving it unset and `""` standing for
/// a pooled connection that once carried one.
struct Member {
    id: &'static str,
    installation: Option<&'static str>,
    /// Whether it reads each resource, each note, each task and each file, in the order of
    /// [`RESOURCES`].
    reads: [[bool; 6]; 4],
}

const MEMBERS: [Member; 5] = [
    Member {
        id: "0b000000-0000-4000-8000-000000000001",
        installation: None,
        reads: [
            [true, true, true, true, true, true],
            [false, true, true, true, false, true],
            [false, false, true, false, false, true],
            [false, true, true, true, false, true],
        ],
    },
    Member {
        id: "0b000000-0000-4000-8000-000000000002",
        installation: Some(INSTALLATIONS[0]),
        reads: [
            [true, true, false, false, false, false],
            [false, true, false, false, false, false],
            [false, false, true, false, false, false],
            [false, true, false, true, false, false],
        ],
    },
    Member {
        id: "0b000000-0000-4000-8000-000000000003",
        installation: Some(INSTALLATIONS[1]),
        reads: [
            [true, false, false, true, false, false],
            [false, false, false, true, false, false],
            [false; 6],
            [false, true, true, false, false, false],
        ],
    },
    Member {
        id: "0b000000-0000-4000-8000-000000000004",
        installation: Some(INSTALLATIONS[1]),
        reads: [
            [false, true, true, false, false, false],
            [false, false, true, false, false, false],
            [false, false, true, false, false, false],
            [false; 6],
        ],
    },
    Member {
        id: "0b000000-0000-4000-8000-000000000005",
        installation: Some(""),
        reads: [
            [true, true, true, true, false, false],
            [false, true, true, true, false, false],
            [false; 6],
            [false, true, true, true, false, false],
        ],
    },
];

fn resource(prefix: &str, suffix: &str) -> String {
    format!("{prefix}000000-0000-4000-8000-0000000000{suffix}")
}

fn acting(member: &str, installation: Option<&str>) -> Principal {
    let mut principal = Principal::as_role(member, "app_reader").with_clock();
    principal
        .session
        .push(("app.user_id".into(), member.into()));
    if let Some(installation) = installation {
        principal
            .session
            .push(("app.installation_id".into(), installation.into()));
    }
    principal
}

fn capped_walks_case(loading_from_rows: bool) -> ParityCase {
    let [a1, a2] = ORGANIZATIONS;
    let [f1, f2] = INSTALLATIONS;
    let id = |suffix| resource("0c", suffix);
    let [m1, m2, m3, m4, m5] = MEMBERS.map(|member| member.id);
    let mut seed = format!(
        "INSERT INTO organizations VALUES ('{a1}'), ('{a2}');
         INSERT INTO app_installations VALUES ('{f1}', '{a1}'), ('{f2}', '{a1}');
         INSERT INTO installation_permissions VALUES
           ('{f1}', '{a1}', 'organization', 'writer'), ('{f1}', '{a1}', 'folder', 'writer'),
           ('{f2}', '{a1}', 'organization', 'writer'), ('{f2}', '{a1}', 'project', 'writer');
         INSERT INTO resources VALUES
           ('{r11}', '{a1}', 'organization', NULL, NULL),
           ('{r12}', '{a1}', 'folder', '{r11}', NULL),
           ('{r13}', '{a1}', 'project', '{r12}', NULL),
           ('{r14}', '{a1}', 'project', '{r11}', now() - interval '1 day'),
           ('{r21}', '{a2}', 'organization', NULL, NULL),
           ('{r22}', '{a2}', 'project', '{r21}', now() + interval '1 day');
         INSERT INTO resource_grants VALUES
           ('{r11}', '{m1}'), ('{r21}', '{m1}'), ('{r11}', '{m2}'), ('{r11}', '{m3}'),
           ('{r12}', '{m4}'), ('{r11}', '{m5}');
         INSERT INTO organization_blocks VALUES ('{a1}', '{m5}');
         INSERT INTO resource_shortcuts VALUES
           ('{s1}', '{r11}', '{r13}', '{a1}', 'project'),
           ('{s2}', '{r12}', '{r14}', '{a1}', 'folder'),
           ('{s3}', '{r21}', '{r22}', '{a2}', 'project'),
           ('{s4}', '{r11}', '{r12}', '{a1}', 'organization');",
        r11 = id("11"),
        r12 = id("12"),
        r13 = id("13"),
        r14 = id("14"),
        r21 = id("21"),
        r22 = id("22"),
        s1 = resource("1b", "01"),
        s2 = resource("1b", "02"),
        s3 = resource("1b", "03"),
        s4 = resource("1b", "04"),
    );
    for suffix in RESOURCES {
        let _ = write!(
            seed,
            "INSERT INTO notes VALUES ('{}', '{}');
             INSERT INTO tasks VALUES ('{}', '{}');
             INSERT INTO files VALUES ('{}', '{}');",
            resource("0d", suffix),
            id(suffix),
            resource("0e", suffix),
            id(suffix),
            resource("1a", suffix),
            id(suffix),
        );
    }
    let mut case = ParityCase::reading(
        &format!(
            "capped-walks{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        CAPPED_WALKS,
        &[
            &seed,
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON resources, notes, tasks, files TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        MEMBERS
            .iter()
            .map(|member| acting(member.id, member.installation))
            .collect(),
    )
    .with_settings([
        support::deployment::typed_caller("app.user_id", DataType::Uuid).may_be_unset(),
        support::deployment::principal("app.installation_id", "installation", DataType::Uuid)
            .may_be_unset(),
    ])
    .with_registry(CAPPED_WALK_HELPERS);
    case.loading_from_rows = loading_from_rows;
    case
}

/// A walk adds a child only where the acting installation holds its kind in its
/// organization, so a folder it lacks hides every row below it while a row granted
/// outright stays read. A parent arm returns a child under the same cap, one keeping
/// open projects outside blocked organizations returns only those, and one over shortcut
/// rows returns a shortcut's target only while the cap keeps the shortcut.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn capped_walks_and_parent_arms_agree_with_postgres() {
    let cluster = support::parity::Cluster::start().await;
    for loading_from_rows in [false, true] {
        let case = capped_walks_case(loading_from_rows);
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
        for member in MEMBERS {
            for ((table, prefix), visible) in [
                ("resources", "0c"),
                ("notes", "0d"),
                ("tasks", "0e"),
                ("files", "1a"),
            ]
            .into_iter()
            .zip(member.reads)
            {
                for (suffix, allowed) in RESOURCES.into_iter().zip(visible) {
                    assert_postgres(
                        &case,
                        &run,
                        member.id,
                        &format!("{table}:{}", resource(prefix, suffix)),
                        ActionStatement::Select,
                        allowed,
                    );
                }
            }
        }
        assert_agrees(&case, &run);
    }
}
