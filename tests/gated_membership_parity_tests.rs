//! Membership read gates compared against `PostgreSQL` with both tuple loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::fmt::Write;
use core::time::Duration;

use rls2fga::types::ActionStatement;

mod support;

use support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

const ATTRIBUTES: &str = r#"[
    { "key": "app.user_id", "kind": "caller_id" },
    { "key": "app.bot_list", "kind": "set_attribute" },
    { "key": "app.mode", "kind": "scalar_attribute" },
    { "key": "app.members", "kind": "set_attribute" }
]"#;

const DOCS: &str = "
CREATE TABLE teams(id INT PRIMARY KEY);
CREATE TABLE team_members(team INT REFERENCES teams(id), user_id TEXT,
                          PRIMARY KEY (team, user_id));
CREATE TABLE docs(id INT PRIMARY KEY, team INT REFERENCES teams(id), owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM team_members m
            WHERE m.team = docs.team
              AND m.user_id = current_setting('app.user_id', true)));
";

const OPEN: &str = "
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_all ON team_members FOR SELECT USING (true);
";

const GATE: &str = "
CREATE POLICY team_members_cap_read ON team_members AS RESTRICTIVE FOR SELECT USING (
    'team_members:read' = ANY(string_to_array(current_setting('app.bot_list', true), ','))
    OR '*' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
";

fn docs_case(name: &str, policies: &str, principals: Vec<Principal>) -> ParityCase {
    ParityCase::reading(
        name,
        &format!("{DOCS}{policies}"),
        &[
            "INSERT INTO teams VALUES (1), (2);
             INSERT INTO team_members VALUES (1, 'wild'), (1, 'token'), (1, 'missing'), (1, 'unset');
             INSERT INTO docs VALUES (1, 1, NULL), (2, 2, 'missing')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs, teams, team_members TO app_reader",
        ],
        principals,
    )
    .with_attributes(ATTRIBUTES)
}

async fn assert_exact(cluster: &Cluster, mut case: ParityCase, pairs: &[(&str, &str, bool)]) {
    for from_rows in [false, true] {
        case.loading_from_rows = from_rows;
        if from_rows {
            case.name.push_str("-rows");
        }
        let run = tokio::time::timeout(
            Duration::from_secs(120),
            support::parity::run(cluster, &case),
        )
        .await
        .unwrap_or_else(|_| panic!("{} exceeded its parity deadline", case.name));
        for (subject, object, allowed) in pairs {
            assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                *allowed,
            );
        }
        assert_agrees(&case, &run);
    }
}

#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn gated_membership_parity() {
    let cluster = Cluster::start().await;
    let matrix = || {
        vec![
            Principal::with_bot_list("wild", Some(&["*"])),
            Principal::with_bot_list("token", Some(&["docs:read", "team_members:read"])),
            Principal::with_bot_list("missing", Some(&["docs:read"])),
            Principal::with_bot_list("unset", None),
            Principal::with_bot_list("nonmember", Some(&["*"])),
        ]
    };

    assert_exact(
        &cluster,
        docs_case("membership-open", OPEN, matrix()),
        &[
            ("wild", "docs:1", true),
            ("missing", "docs:1", true),
            ("unset", "docs:1", true),
            ("nonmember", "docs:1", false),
        ],
    )
    .await;
    assert_exact(
        &cluster,
        docs_case("membership-gate", &format!("{OPEN}{GATE}"), matrix()),
        &[
            ("wild", "docs:1", true),
            ("token", "docs:1", true),
            ("missing", "docs:1", false),
            ("unset", "docs:1", false),
            ("nonmember", "docs:1", false),
        ],
    )
    .await;

    let mode_reader = |subject, keys: &[&str], mode: &str| {
        let mut principal = Principal::with_bot_list(subject, Some(keys));
        principal.session.push(("app.mode".into(), mode.into()));
        principal.context["app_mode"] = serde_json::json!(mode);
        principal
    };
    assert_exact(
        &cluster,
        docs_case(
            "membership-multiple-gates",
            &format!(
                "{OPEN}{GATE}
                CREATE POLICY cap_mode ON team_members AS RESTRICTIVE FOR ALL
                    USING (current_setting('app.mode', true) = 'enabled');"
            ),
            vec![
                mode_reader("wild", &["*"], "enabled"),
                mode_reader("token", &["team_members:read"], "disabled"),
                mode_reader("missing", &["docs:read"], "enabled"),
                mode_reader("nonmember", &["*"], "enabled"),
            ],
        ),
        &[
            ("wild", "docs:1", true),
            ("token", "docs:1", false),
            ("missing", "docs:1", false),
            ("nonmember", "docs:1", false),
        ],
    )
    .await;

    assert_exact(
        &cluster,
        docs_case(
            "membership-write-gates",
            &format!("{OPEN}
                CREATE POLICY cap_write ON team_members AS RESTRICTIVE FOR INSERT
                    WITH CHECK ('write' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
                CREATE POLICY cap_delete ON team_members AS RESTRICTIVE FOR DELETE USING (false);
                CREATE POLICY cap_update ON team_members AS RESTRICTIVE FOR UPDATE USING (false);"),
            matrix(),
        ),
        &[("unset", "docs:1", true), ("nonmember", "docs:1", false)],
    ).await;

    assert_exact(
        &cluster,
        docs_case(
            "membership-owner-arm",
            &format!(
                "{OPEN}{GATE}
                CREATE POLICY docs_owner ON docs FOR SELECT
                    USING (owner_id = current_setting('app.user_id', true));"
            ),
            matrix(),
        ),
        &[
            ("missing", "docs:2", true),
            ("missing", "docs:1", false),
            ("wild", "docs:1", true),
            ("nonmember", "docs:2", false),
        ],
    )
    .await;

    let set_reader = |subject, members: &[&str], keys: &[&str]| {
        let mut principal = Principal::with_bot_list(subject, Some(keys));
        principal
            .session
            .push(("app.members".into(), members.join(",")));
        principal.context["app_members"] = serde_json::json!(members);
        principal
    };
    assert_exact(
        &cluster,
        docs_case(
            "membership-caller-set",
            &format!("{OPEN}{GATE}
                DROP POLICY docs_read ON docs;
                CREATE POLICY docs_read ON docs FOR SELECT USING (
                    EXISTS (SELECT 1 FROM team_members m WHERE m.team = docs.team
                        AND m.user_id = ANY(string_to_array(current_setting('app.members', true), ','))));"),
            vec![
                set_reader("has_key", &["wild"], &["team_members:read"]),
                set_reader("missing_gate", &["wild"], &["docs:read"]),
                set_reader("missing_key", &[], &["team_members:read"]),
            ],
        ),
        &[
            ("has_key", "docs:1", true),
            ("missing_gate", "docs:1", false),
            ("missing_key", "docs:1", false),
        ],
    ).await;

    for clocked in [false, true] {
        let time_filter = if clocked {
            "AND s.expires_at > now()"
        } else {
            ""
        };
        let case = ParityCase::reading(
            if clocked { "membership-holder-witness" } else { "membership-holder" },
            &format!("
                CREATE TABLE memos(id INT PRIMARY KEY);
                CREATE TABLE staff(id INT PRIMARY KEY, user_id TEXT, expires_at TIMESTAMPTZ);
                ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
                CREATE POLICY memos_staff ON memos FOR SELECT USING (
                    EXISTS (SELECT 1 FROM staff s
                        WHERE s.user_id = current_setting('app.user_id', true) {time_filter}));
                ALTER TABLE staff ENABLE ROW LEVEL SECURITY;
                CREATE POLICY staff_all ON staff FOR SELECT USING (true);
                CREATE POLICY staff_cap ON staff AS RESTRICTIVE FOR SELECT USING (
                    'staff:read' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));"),
            &[
                "INSERT INTO memos VALUES (1), (2);
                 INSERT INTO staff VALUES
                    (1, 'token', now() + interval '1 day'),
                    (2, 'missing', now() + interval '1 day'),
                    (3, 'expired', now() - interval '1 day')",
                "CREATE ROLE app_reader LOGIN; GRANT SELECT ON memos, staff TO app_reader",
            ],
            vec![
                Principal::with_bot_list("token", Some(&["staff:read"])).with_clock(),
                Principal::with_bot_list("missing", Some(&["docs:read"])).with_clock(),
                Principal::with_bot_list("expired", Some(&["staff:read"])).with_clock(),
                Principal::with_bot_list("nonmember", Some(&["staff:read"])).with_clock(),
            ],
        ).with_attributes(ATTRIBUTES);
        assert_exact(
            &cluster,
            case,
            &[
                ("token", "memos:1", true),
                ("missing", "memos:1", false),
                ("expired", "memos:1", !clocked),
                ("nonmember", "memos:1", false),
            ],
        )
        .await;
    }

    let mut names_case = docs_case(
            "membership-gate-policy-names",
            &format!("{OPEN}
                CREATE POLICY cap_read ON team_members AS RESTRICTIVE FOR SELECT USING (
                    'team_members:read' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
                CREATE TABLE other_members(team INT REFERENCES teams(id), user_id TEXT,
                    PRIMARY KEY (team, user_id));
                ALTER TABLE other_members ENABLE ROW LEVEL SECURITY;
                CREATE POLICY members_all ON other_members FOR SELECT USING (true);
                CREATE POLICY cap_read ON other_members AS RESTRICTIVE FOR SELECT USING (
                    'other_members:read' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
                CREATE POLICY docs_other ON docs FOR SELECT USING (
                    EXISTS (SELECT 1 FROM other_members m WHERE m.team = docs.team
                        AND m.user_id = current_setting('app.user_id', true)));"),
            vec![
                Principal::with_bot_list("token", Some(&["team_members:read"])),
                Principal::with_bot_list("missing", Some(&["other_members:read"])),
                Principal::with_bot_list("other", Some(&["other_members:read"])),
                Principal::with_bot_list("wrong", Some(&["team_members:read"])),
            ],
        );
    names_case.seed.push(
        "INSERT INTO other_members VALUES (2, 'other'), (2, 'wrong');
         GRANT SELECT ON other_members TO app_reader"
            .into(),
    );
    assert_exact(
        &cluster,
        names_case,
        &[
            ("token", "docs:1", true),
            ("token", "docs:2", false),
            ("missing", "docs:1", false),
            ("other", "docs:2", true),
            ("other", "docs:1", false),
            ("wrong", "docs:2", false),
        ],
    )
    .await;

    for correlated in [true, false] {
        let mut schema = String::from("
            CREATE TABLE teams(id INT PRIMARY KEY);
            CREATE TABLE members(id INT PRIMARY KEY, team INT REFERENCES teams(id),
                user_id TEXT, delegate_id TEXT, approved BOOLEAN);
            ALTER TABLE members ENABLE ROW LEVEL SECURITY;
            CREATE POLICY members_all ON members FOR SELECT USING (true);
            CREATE POLICY members_cap ON members AS RESTRICTIVE FOR SELECT USING (
                'members:read' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));");
        for (table, user_column, residual) in [
            ("plain_docs", "user_id", ""),
            ("restricted_docs", "user_id", "AND m.approved"),
            ("delegated_docs", "delegate_id", ""),
        ] {
            let correlation = if correlated {
                format!("m.team = {table}.team AND")
            } else {
                String::new()
            };
            let _ = write!(
                schema,
                "
                CREATE TABLE {table}(id INT PRIMARY KEY, team INT REFERENCES teams(id));
                ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
                CREATE POLICY docs_read ON {table} FOR SELECT USING (
                    EXISTS (SELECT 1 FROM members m WHERE {correlation}
                        m.{user_column} = current_setting('app.user_id', true) {residual}));"
            );
        }
        let case = ParityCase::reading(
            if correlated {
                "membership-source-columns"
            } else {
                "holder-source-columns"
            },
            &schema,
            &[
                "INSERT INTO teams VALUES (1);
                 INSERT INTO members VALUES
                    (1, 1, 'alice', 'bob', false), (2, 1, 'carol', 'dave', true);
                 INSERT INTO plain_docs VALUES (1, 1);
                 INSERT INTO restricted_docs VALUES (1, 1);
                 INSERT INTO delegated_docs VALUES (1, 1)",
                "CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON teams, members, plain_docs, restricted_docs, delegated_docs
                    TO app_reader",
            ],
            ["alice", "bob", "carol", "dave"]
                .into_iter()
                .map(|user| Principal::with_bot_list(user, Some(&["members:read"])))
                .collect(),
        )
        .with_attributes(ATTRIBUTES);
        assert_exact(
            &cluster,
            case,
            &[
                ("alice", "plain_docs:1", true),
                ("alice", "restricted_docs:1", false),
                ("alice", "delegated_docs:1", false),
                ("bob", "plain_docs:1", false),
                ("bob", "delegated_docs:1", true),
                ("carol", "restricted_docs:1", true),
                ("dave", "delegated_docs:1", true),
            ],
        )
        .await;
    }

    for (outer_columns, clocked) in [(true, false), (true, true), (false, true)] {
        let other_pair = if outer_columns {
            "m.team = docs.other_team"
        } else {
            "m.other_team = docs.team"
        };
        let clock = if clocked {
            "AND m.expires_at > now()"
        } else {
            ""
        };
        let principals = ["alice", "carol"]
            .into_iter()
            .map(|user| {
                let mut principal = Principal::with_bot_list(user, Some(&["members:read"]))
                    .with_clock()
                    .with_context(serde_json::json!({
                        "app_bot_list": ["members:read"], "app_mode": "other"
                    }));
                principal.session.push(("app.mode".into(), "other".into()));
                principal
            })
            .collect();
        let case = ParityCase::reading(
            &format!("membership-correlation-{outer_columns}-{clocked}"),
            &format!("
                CREATE TABLE teams(id INT PRIMARY KEY);
                CREATE TABLE members(id INT PRIMARY KEY, team INT REFERENCES teams(id),
                    other_team INT REFERENCES teams(id), user_id TEXT, expires_at TIMESTAMPTZ);
                CREATE TABLE docs(id INT PRIMARY KEY, team INT REFERENCES teams(id),
                    other_team INT REFERENCES teams(id));
                ALTER TABLE members ENABLE ROW LEVEL SECURITY;
                CREATE POLICY members_all ON members FOR SELECT USING (true);
                CREATE POLICY members_cap ON members AS RESTRICTIVE FOR SELECT USING (
                    'members:read' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
                ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
                CREATE POLICY docs_read ON docs FOR SELECT USING (
                    (EXISTS (SELECT 1 FROM members m WHERE m.team = docs.team
                        AND m.user_id = current_setting('app.user_id', true) {clock})
                        AND current_setting('app.mode', true) = 'main')
                    OR (EXISTS (SELECT 1 FROM members m WHERE {other_pair}
                        AND m.user_id = current_setting('app.user_id', true) {clock})
                        AND current_setting('app.mode', true) = 'other'));"),
            &[
                "INSERT INTO teams VALUES (1), (2);
                 INSERT INTO members VALUES
                    (1, 1, 2, 'alice', now() + interval '1 day'),
                    (2, 2, 1, 'carol', now() + interval '1 day');
                 INSERT INTO docs VALUES (1, 1, 2), (2, 2, 1)",
                "CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON teams, members, docs TO app_reader",
            ],
            principals,
        ).with_attributes(ATTRIBUTES);
        assert_exact(
            &cluster,
            case,
            &[
                ("alice", "docs:1", false),
                ("alice", "docs:2", true),
                ("carol", "docs:1", true),
                ("carol", "docs:2", false),
            ],
        )
        .await;
    }

    for (name, correlated, caller_set) in [
        ("membership-witness-branches", true, false),
        ("holder-witness-branches", false, false),
        ("caller-set-witness-branches", true, true),
    ] {
        let correlation = if correlated {
            "m.team = docs.team AND"
        } else {
            ""
        };
        let caller = if caller_set {
            "m.user_id = ANY(string_to_array(current_setting('app.members', true), ','))"
        } else {
            "m.user_id = current_setting('app.user_id', true) AND m.expires_at > now()"
        };
        let principals = ["alice", "carol"]
            .into_iter()
            .map(|user| {
                let mut principal = Principal::with_bot_list(user, Some(&["members:read"]))
                    .with_clock()
                    .with_context(serde_json::json!({
                        "app_bot_list": ["members:read"],
                        "app_mode": "approved",
                        "app_members": [user]
                    }));
                principal.session.extend([
                    ("app.mode".into(), "approved".into()),
                    ("app.members".into(), user.into()),
                ]);
                principal
            })
            .collect();
        let case = ParityCase::reading(
            name,
            &format!("
                CREATE TABLE teams(id INT PRIMARY KEY);
                CREATE TABLE members(id INT PRIMARY KEY, team INT REFERENCES teams(id),
                    user_id TEXT, approved BOOLEAN, expires_at TIMESTAMPTZ);
                CREATE TABLE docs(id INT PRIMARY KEY, team INT REFERENCES teams(id));
                ALTER TABLE members ENABLE ROW LEVEL SECURITY;
                CREATE POLICY members_all ON members FOR SELECT USING (true);
                CREATE POLICY members_cap ON members AS RESTRICTIVE FOR SELECT USING (
                    'members:read' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
                ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
                CREATE POLICY docs_read ON docs FOR SELECT USING (
                    (EXISTS (SELECT 1 FROM members m WHERE {correlation} {caller} AND m.approved)
                        AND current_setting('app.mode', true) = 'approved')
                    OR (EXISTS (SELECT 1 FROM members m WHERE {correlation} {caller} AND m.approved = false)
                        AND current_setting('app.mode', true) = 'pending'));"),
            &[
                "INSERT INTO teams VALUES (1), (2);
                 INSERT INTO members VALUES
                    (1, 1, 'alice', false, now() + interval '1 day'),
                    (2, 2, 'carol', true, now() + interval '1 day');
                 INSERT INTO docs VALUES (1, 1), (2, 2)",
                "CREATE ROLE app_reader LOGIN;
                 GRANT SELECT ON teams, members, docs TO app_reader",
            ],
            principals,
        ).with_attributes(ATTRIBUTES);
        assert_exact(
            &cluster,
            case,
            &[("alice", "docs:1", false), ("carol", "docs:2", true)],
        )
        .await;
    }
}
