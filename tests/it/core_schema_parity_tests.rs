//! The core schema of connetto-schema, compared against `PostgreSQL` 17 and 18 over every
//! table, every command and a principal for each way the core grants or refuses access.
//!
//! `tests/fixtures/core_schema/input.sql` is the schema at a pinned connetto-schema commit,
//! so refreshing it is copying the files the fixture's header names and rerunning.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use crate::support::parity::{
    assert_agrees, assert_two_sided, run_variants_before, ClauseKind, Cluster, ParityCase,
    Principal, Side,
};

const FIXTURE: &str = "core_schema";

/// A case loads twenty tables and compares every principal against every row of them.
const DEADLINE: Duration = Duration::from_mins(30);

/// The access attributes connetto-schema's lint registry confirms.
const ATTRIBUTE_COLUMNS: [(&str, &str); 9] = [
    ("grants", "role"),
    ("grants", "grantee_kind"),
    ("grants", "organization_id"),
    ("grants", "resource_id"),
    ("memberships", "invitation_id"),
    ("memberships", "state"),
    ("resources", "kind"),
    ("resources", "archived_at"),
    ("share_links", "revoked_at"),
];

/// Organization admin and the creator of `O1`.
const ALICE: &str = "00000000-0000-0000-0000-000000000101";
/// Organization writer, sharing `P1` as its writers may, and reader of the archived `P3`.
const BOB: &str = "00000000-0000-0000-0000-000000000102";
/// Organization reader, admin of the parent team `T2` and of the folder `F1`.
const CAROL: &str = "00000000-0000-0000-0000-000000000103";
/// Member of `T1`, which reaches `P1` through its parent team `T2`.
const DAVE: &str = "00000000-0000-0000-0000-000000000104";
/// Reader of the folder `F1`, reaching `P2` below it, admin of `W2` alone, and a member by
/// invitation.
const ERIN: &str = "00000000-0000-0000-0000-000000000105";
/// Invited to `O1` by verified email, and no member yet.
const GRACE: &str = "00000000-0000-0000-0000-000000000106";
/// Organization admin acting through the installation `IN1`, capped below admin.
const IVAN: &str = "00000000-0000-0000-0000-000000000107";
/// Organization writer the organization blocked.
const JUDY: &str = "00000000-0000-0000-0000-000000000108";
/// Organization admin acting through the blocked installation `IN2`.
const KATE: &str = "00000000-0000-0000-0000-000000000109";
/// Member whose writer grant on `P1` expired, and whose block expired too.
const LEO: &str = "00000000-0000-0000-0000-00000000010a";
/// Platform operator, with no organization.
const MIA: &str = "00000000-0000-0000-0000-00000000010b";
/// Deactivated member holding a writer grant on `P2`.
const NINA: &str = "00000000-0000-0000-0000-00000000010c";
/// Admin of the other organization `O2`.
const OSCAR: &str = "00000000-0000-0000-0000-00000000010d";
/// Signed in, and a member of nothing.
const PAUL: &str = "00000000-0000-0000-0000-00000000010e";
/// Creator of `O3`, which has no admin yet.
const HENRY: &str = "00000000-0000-0000-0000-00000000010f";
/// Organization admin the organization blocked, acting directly.
const QUINN: &str = "00000000-0000-0000-0000-000000000110";

const O1: &str = "00000000-0000-0000-0000-000000000201";
/// Archived.
const O2: &str = "00000000-0000-0000-0000-000000000202";
const O3: &str = "00000000-0000-0000-0000-000000000203";
const O4: &str = "00000000-0000-0000-0000-000000000204";

const F1: &str = "00000000-0000-0000-0000-000000000301";
const P1: &str = "00000000-0000-0000-0000-000000000302";
const P2: &str = "00000000-0000-0000-0000-000000000303";
/// An archived folder.
const F2: &str = "00000000-0000-0000-0000-000000000304";
/// A project below the archived folder.
const P3: &str = "00000000-0000-0000-0000-000000000305";
const P4: &str = "00000000-0000-0000-0000-000000000306";

const W1: &str = "00000000-0000-0000-0000-000000000401";
const W2: &str = "00000000-0000-0000-0000-000000000402";
const W3: &str = "00000000-0000-0000-0000-000000000403";
const W4: &str = "00000000-0000-0000-0000-000000000404";
/// Created by `QUINN`.
const W5: &str = "00000000-0000-0000-0000-000000000405";

const T2: &str = "00000000-0000-0000-0000-000000000501";
const T1: &str = "00000000-0000-0000-0000-000000000502";

const I1: &str = "00000000-0000-0000-0000-000000000601";
const I2: &str = "00000000-0000-0000-0000-000000000602";
const I3: &str = "00000000-0000-0000-0000-000000000603";
/// Invited by `QUINN`.
const I4: &str = "00000000-0000-0000-0000-000000000604";

const L1: &str = "00000000-0000-0000-0000-000000000701";
/// A revoked link.
const L2: &str = "00000000-0000-0000-0000-000000000702";
/// Created by `QUINN`.
const L3: &str = "00000000-0000-0000-0000-000000000703";

const A1: &str = "00000000-0000-0000-0000-000000000801";
const IN1: &str = "00000000-0000-0000-0000-000000000901";
/// An installation the organization blocked.
const IN2: &str = "00000000-0000-0000-0000-000000000902";

/// The committed state: two founded organizations and every way into and out of them.
///
/// One transaction, as the schema's deferred checks require. They run at commit as an
/// admin of `O1`, because a team's edge check reads the caller.
fn committed_seed() -> String {
    format!(
        "DO $$
BEGIN
  PERFORM set_config('app.user_id', '{ALICE}', true);
  INSERT INTO users (id) VALUES
    ('{ALICE}'), ('{BOB}'), ('{CAROL}'), ('{DAVE}'), ('{ERIN}'), ('{GRACE}'), ('{IVAN}'),
    ('{JUDY}'), ('{KATE}'), ('{LEO}'), ('{MIA}'), ('{NINA}'), ('{OSCAR}'), ('{PAUL}'),
    ('{QUINN}');
  INSERT INTO organizations (id, created_by_id) VALUES ('{O1}', '{ALICE}'), ('{O2}', '{OSCAR}');
  INSERT INTO resources (id, kind, organization_id, archived_at, writers_can_share) VALUES
    ('{O1}', 'organization', '{O1}', NULL, FALSE),
    ('{O2}', 'organization', '{O2}', now(), FALSE),
    ('{F1}', 'folder', '{O1}', NULL, FALSE),
    ('{P1}', 'project', '{O1}', NULL, TRUE),
    ('{P2}', 'project', '{O1}', NULL, FALSE),
    ('{F2}', 'folder', '{O1}', now(), FALSE),
    ('{P3}', 'project', '{O1}', NULL, FALSE),
    ('{P4}', 'project', '{O2}', NULL, FALSE),
    ('{W1}', 'ownable', '{O1}', NULL, FALSE),
    ('{W2}', 'ownable', '{O1}', NULL, FALSE),
    ('{W3}', 'ownable', '{O1}', NULL, FALSE),
    ('{W4}', 'ownable', '{O2}', NULL, FALSE),
    ('{W5}', 'ownable', '{O1}', NULL, FALSE);
  INSERT INTO resource_parents (id, organization_id, resource_kind, parent_id, parent_kind) VALUES
    ('{F1}', '{O1}', 'folder', '{O1}', 'organization'),
    ('{P1}', '{O1}', 'project', '{O1}', 'organization'),
    ('{P2}', '{O1}', 'project', '{F1}', 'folder'),
    ('{F2}', '{O1}', 'folder', '{O1}', 'organization'),
    ('{P3}', '{O1}', 'project', '{F2}', 'folder'),
    ('{P4}', '{O2}', 'project', '{O2}', 'organization');
  INSERT INTO ownables (id, organization_id, project_id, created_by_id) VALUES
    ('{W1}', '{O1}', '{P1}', '{BOB}'),
    ('{W2}', '{O1}', '{P2}', '{ALICE}'),
    ('{W3}', '{O1}', '{P3}', '{ALICE}'),
    ('{W4}', '{O2}', '{P4}', '{OSCAR}'),
    ('{W5}', '{O1}', '{P1}', '{QUINN}');
  INSERT INTO invitations (id, organization_id, email, expires_at, invited_by_id) VALUES
    ('{I1}', '{O1}', 'grace@example.com', now() + interval '7 days', '{ALICE}'),
    ('{I2}', '{O1}', 'erin@example.com', now() + interval '7 days', '{ALICE}'),
    ('{I3}', '{O1}', 'grace@example.com', now() - interval '1 day', '{ALICE}'),
    ('{I4}', '{O1}', 'quinn-guest@example.com', now() + interval '7 days', '{QUINN}');
  INSERT INTO memberships (organization_id, user_id, state, invitation_id) VALUES
    ('{O1}', '{ALICE}', 'active', NULL),
    ('{O1}', '{BOB}', 'active', NULL),
    ('{O1}', '{CAROL}', 'active', NULL),
    ('{O1}', '{DAVE}', 'active', NULL),
    ('{O1}', '{ERIN}', 'active', '{I2}'),
    ('{O1}', '{IVAN}', 'active', NULL),
    ('{O1}', '{JUDY}', 'active', NULL),
    ('{O1}', '{KATE}', 'active', NULL),
    ('{O1}', '{LEO}', 'active', NULL),
    ('{O1}', '{NINA}', 'deactivated', NULL),
    ('{O1}', '{QUINN}', 'active', NULL),
    ('{O2}', '{OSCAR}', 'active', NULL);
  INSERT INTO teams (id, organization_id) VALUES ('{T2}', '{O1}'), ('{T1}', '{O1}');
  INSERT INTO team_parents (id, organization_id, parent_id) VALUES ('{T1}', '{O1}', '{T2}');
  INSERT INTO team_members (team_id, organization_id, user_id, team_role) VALUES
    ('{T1}', '{O1}', '{DAVE}', 'member'),
    ('{T2}', '{O1}', '{CAROL}', 'admin');
  INSERT INTO share_links (id, organization_id, token_hash, revoked_at, created_by_id) VALUES
    ('{L1}', '{O1}', decode(repeat('01', 32), 'hex'), NULL, '{BOB}'),
    ('{L2}', '{O1}', decode(repeat('02', 32), 'hex'), now(), '{CAROL}'),
    ('{L3}', '{O1}', decode(repeat('04', 32), 'hex'), NULL, '{QUINN}');
  INSERT INTO grants (resource_id, organization_id, grantee_id, grantee_kind, role, expires_at) VALUES
    ('{O1}', '{O1}', '{ALICE}', 'user', 'admin', NULL),
    ('{O1}', '{O1}', '{BOB}', 'user', 'writer', NULL),
    ('{O1}', '{O1}', '{CAROL}', 'user', 'reader', NULL),
    ('{P1}', '{O1}', '{T2}', 'team', 'writer', NULL),
    ('{F1}', '{O1}', '{ERIN}', 'user', 'reader', NULL),
    ('{P1}', '{O1}', '{L1}', 'link', 'reader', NULL),
    ('{F1}', '{O1}', '{L2}', 'link', 'reader', NULL),
    ('{O1}', '{O1}', '{IVAN}', 'user', 'admin', NULL),
    ('{O1}', '{O1}', '{JUDY}', 'user', 'writer', NULL),
    ('{O1}', '{O1}', '{KATE}', 'user', 'admin', NULL),
    ('{P1}', '{O1}', '{LEO}', 'user', 'writer', now() - interval '1 day'),
    ('{P2}', '{O1}', '{NINA}', 'user', 'writer', NULL),
    ('{O2}', '{O2}', '{OSCAR}', 'user', 'admin', NULL),
    ('{O1}', '{O1}', '{QUINN}', 'user', 'admin', NULL),
    ('{P3}', '{O1}', '{BOB}', 'user', 'reader', NULL),
    ('{W2}', '{O1}', '{ERIN}', 'user', 'admin', NULL),
    ('{F1}', '{O1}', '{CAROL}', 'user', 'admin', NULL);
  INSERT INTO grants (resource_id, organization_id, grantee_id, grantee_kind, role)
    SELECT '{P1}', '{O1}', id, kind, 'reader' FROM grantees WHERE kind = 'everyone';
  INSERT INTO grants (resource_id, organization_id, grantee_id, grantee_kind, role)
    SELECT '{P4}', '{O2}', id, kind, 'reader' FROM grantees WHERE kind = 'signed_in';
  INSERT INTO apps (id, organization_id, name) VALUES ('{A1}', '{O1}', 'sync');
  INSERT INTO app_installations (id, app_id, organization_id) VALUES
    ('{IN1}', '{A1}', '{O1}'), ('{IN2}', '{A1}', '{O1}');
  INSERT INTO installation_permissions (installation_id, organization_id, kind, max_role) VALUES
    ('{IN1}', '{O1}', 'organization', 'reader'),
    ('{IN1}', '{O1}', 'project', 'writer'),
    ('{IN1}', '{O1}', 'ownable', 'writer'),
    ('{IN2}', '{O1}', 'organization', 'admin'),
    ('{IN2}', '{O1}', 'project', 'admin');
  INSERT INTO organization_blocks (organization_id, principal_id, principal_kind, expires_at) VALUES
    ('{O1}', '{JUDY}', 'user', NULL),
    ('{O1}', '{IN2}', 'installation', NULL),
    ('{O1}', '{LEO}', 'user', now() - interval '1 day'),
    ('{O1}', '{QUINN}', 'user', NULL);
  INSERT INTO platform_operators (id) VALUES ('{MIA}');
END $$"
    )
}

/// A caller identified by `app.user_id`, which also sets `settings`.
fn user(subject: &str, settings: &[(&str, &str)]) -> Principal {
    let mut principal = Principal::with_setting(subject, "app", "app.user_id", subject);
    principal.session.extend(
        settings
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string())),
    );
    holding_links(principal, &[])
}

/// A caller identified by nothing but the role it acts as.
fn role(subject: &str, login_role: &str) -> Principal {
    holding_links(Principal::as_role(subject, login_role), &[])
}

/// The caller, its checks carrying the links it holds as a list, empty where it set none,
/// and the request clock the expiries are compared against.
fn holding_links(principal: Principal, links: &[&str]) -> Principal {
    principal
        .with_context(serde_json::json!({ "app_link_ids": links }))
        .with_clock()
}

/// The schema with its deployment, registry and attribute columns, and an update on every
/// table the core lets a caller update, each writing a column its privileges let a caller
/// write.
///
/// A clause side no seed can decide is declared with the reason it cannot.
fn core_case(name: &str, seed: &str, principals: Vec<Principal>) -> ParityCase {
    const UNWRITABLE: &str = "the check reads only columns the caller may not update, so it \
                              repeats USING on the same values";
    const REPEATS_SELECT: &str = "repeats the SELECT policy's USING, which a statement naming \
                                  its rows applies first";
    let mut case = ParityCase::from_fixture(name, FIXTURE, &[seed], principals)
        .with_attribute_columns(&ATTRIBUTE_COLUMNS)
        .updating("memberships", "state = state")
        .updating("team_parents", "parent_id = parent_id")
        .updating("team_members", "team_role = team_role")
        .updating("resources", "writers_can_share = writers_can_share")
        .updating("resource_parents", "parent_kind = parent_kind")
        .updating("ownables", "project_id = project_id")
        .updating("grants", "role = role")
        .updating("share_links", "expires_at = expires_at")
        .updating("organization_blocks", "expires_at = expires_at")
        .updating("apps", "name = name")
        // Column privileges let a caller insert these columns alone.
        .inserting_columns("organizations", &["id", "created_by_id"])
        .inserting_columns(
            "invitations",
            &[
                "id",
                "organization_id",
                "email",
                "expires_at",
                "invited_by_id",
            ],
        )
        .unobservable(
            "audit_events",
            "audit_events_blocked",
            ClauseKind::Check,
            Side::Denies,
            "app may only read audit events, so no write of app reaches the check",
        )
        .unobservable(
            "audit_events",
            "audit_events_blocked",
            ClauseKind::Check,
            Side::Grants,
            "app may only read audit events, so no write of app reaches the check",
        )
        .unobservable(
            "organizations",
            "organizations_blocked",
            ClauseKind::Check,
            Side::Denies,
            "a new organization's id is fresh, and no block names an organization before it \
             exists",
        )
        .unobservable(
            "resources",
            "resources_archived_update",
            ClauseKind::UsingAsCheck,
            Side::Denies,
            "reads only the row's ancestors, which an update of the row leaves as stored",
        );
    for (table, policy) in [
        ("apps", "apps_update"),
        ("memberships", "memberships_update"),
        ("organization_blocks", "organization_blocks_update"),
        ("resources", "resources_update"),
        ("share_links", "share_links_update"),
        ("team_members", "team_members_update"),
        ("team_parents", "team_parents_update"),
        ("grants", "grants_archived_update"),
    ] {
        case = case.unobservable(table, policy, ClauseKind::Check, Side::Denies, UNWRITABLE);
    }
    for (table, policy) in [
        ("app_installations", "app_installations_delete"),
        (
            "installation_permissions",
            "installation_permissions_delete",
        ),
        ("organization_blocks", "organization_blocks_delete"),
        ("organization_blocks", "organization_blocks_update"),
    ] {
        case = case.unobservable(
            table,
            policy,
            ClauseKind::Using,
            Side::Denies,
            REPEATS_SELECT,
        );
    }
    case
}

/// Every principal of the committed state, each a way the core grants or refuses access.
fn committed_principals() -> Vec<Principal> {
    let links = format!("{L1},{L2}");
    vec![
        user(ALICE, &[]),
        user(BOB, &[]),
        user(CAROL, &[]),
        user(DAVE, &[]),
        user(ERIN, &[]),
        user(GRACE, &[("app.verified_email", "grace@example.com")]),
        user(IVAN, &[("app.installation_id", IN1)]),
        user(JUDY, &[]),
        user(KATE, &[("app.installation_id", IN2)]),
        user(LEO, &[]),
        user(MIA, &[]),
        user(NINA, &[]),
        user(OSCAR, &[]),
        user(PAUL, &[]),
        user(QUINN, &[]),
        holding_links(
            Principal::with_setting("link-holder", "app", "app.link_ids", &links),
            &[L1, L2],
        ),
        role("anonymous", "app"),
        role("identity-writer", "identity_writer"),
    ]
}

/// The committed state, its inserts written onto keys an arm admits: a grant of each
/// granted resource and a block, a membership and a team membership for callers who hold
/// none yet, a permission for a kind `IN1` is not capped to, and a link token no link
/// holds.
///
/// Three updates move a row where a check refuses it while the caller still reads it.
/// `ERIN` moves `W2` into `P1`, which she does not write, and `ALICE` moves `W1` into the
/// archived `P3`. `CAROL` lifts `P2` from `F1` to `O1`, which she does not administer, and
/// `ALICE` moves `P1` below the archived `F2`. The grant of `P1` to `T2` is raised to
/// admin, a role `BOB` may not share.
fn committed(major: &str) -> ParityCase {
    core_case(
        &format!("core-schema-pg{major}"),
        &committed_seed(),
        committed_principals(),
    )
    .updating(
        "ownables",
        &format!(
            "project_id = CASE id WHEN '{W2}' THEN '{P1}'::uuid WHEN '{W1}' THEN '{P3}'::uuid \
             ELSE project_id END"
        ),
    )
    .updating(
        "resource_parents",
        &format!(
            "parent_id = CASE id WHEN '{P2}' THEN '{O1}'::uuid WHEN '{P1}' THEN '{F2}'::uuid \
             ELSE parent_id END, \
             parent_kind = CASE id WHEN '{P2}' THEN 'organization'::authz.resource_kind \
             WHEN '{P1}' THEN 'folder'::authz.resource_kind ELSE parent_kind END"
        ),
    )
    .updating(
        "grants",
        &format!("role = CASE WHEN grantee_id = '{T2}' THEN 'admin'::authz.role ELSE role END"),
    )
    .inserting_values("memberships", &[("organization_id", O1), ("user_id", PAUL)])
    // A copied invitation belongs to another membership, so a new one is left to its
    // default of none.
    .inserting_columns("memberships", &["organization_id", "user_id", "state"])
    .inserting_values("grants", &[("grantee_id", PAUL)])
    .inserting_values("team_members", &[("team_id", T2), ("user_id", ERIN)])
    .inserting_values(
        "organization_blocks",
        &[("organization_id", O1), ("principal_id", PAUL)],
    )
    .inserting_values(
        "installation_permissions",
        &[("installation_id", IN1), ("kind", "folder")],
    )
    .inserting_values("share_links", &[("token_hash", &unused_token())])
}

/// A link token no seeded link holds, since a copied one would break the column's
/// uniqueness after the policy admitted the row.
fn unused_token() -> String {
    format!("\\x{}", "03".repeat(32))
}

/// The committed state, its membership inserts accepting `GRACE`'s pending invitation,
/// directly and through the blocked installation `IN2`, whose permissions admit the
/// acceptance and whose block refuses it.
fn accepting_an_invitation(major: &str) -> ParityCase {
    let mut case = committed(major)
        .inserting_values(
            "memberships",
            &[
                ("organization_id", O1),
                ("user_id", GRACE),
                ("invitation_id", I1),
            ],
        )
        .inserting_columns(
            "memberships",
            &["organization_id", "user_id", "state", "invitation_id"],
        );
    let mut through_blocked =
        Principal::with_setting("grace-via-in2", "app", "app.user_id", GRACE).acting_for(GRACE);
    through_blocked.session.extend([
        (
            "app.verified_email".to_string(),
            "grace@example.com".to_string(),
        ),
        ("app.installation_id".to_string(), IN2.to_string()),
    ]);
    case.principals.push(holding_links(through_blocked, &[]));
    case.name = format!("core-schema-invitation-pg{major}");
    case
}

/// `O3` between its creation and its first admin grant, beside the founded `O4`.
///
/// The schema refuses to commit an organization without an active admin, so this moment
/// exists only inside the founding transaction, and it is the one state where the
/// founding arms of `memberships_insert`, `grants_insert` and `resources_insert` decide
/// anything. A replica session skips the triggers that refuse it, which plants it as rows,
/// grantees included since their trigger is skipped too.
fn before_founding(major: &str) -> ParityCase {
    let seed = format!(
        "DO $$
BEGIN
  PERFORM set_config('session_replication_role', 'replica', true);
  INSERT INTO grantees (id, kind) VALUES
    ('{HENRY}', 'user'), ('{PAUL}', 'user'), ('{O3}', 'organization'), ('{O4}', 'organization');
  INSERT INTO users (id) VALUES ('{HENRY}'), ('{PAUL}');
  INSERT INTO organizations (id, created_by_id, founded_at) VALUES
    ('{O3}', '{HENRY}', NULL), ('{O4}', '{PAUL}', now());
  INSERT INTO resources (id, kind, organization_id) VALUES
    ('{O3}', 'organization', '{O3}'), ('{O4}', 'organization', '{O4}');
  INSERT INTO memberships (organization_id, user_id, state) VALUES ('{O4}', '{PAUL}', 'active');
  INSERT INTO grants (resource_id, organization_id, grantee_id, grantee_kind, role) VALUES
    ('{O4}', '{O4}', '{PAUL}', 'user', 'admin');
END $$"
    );
    core_case(
        &format!("core-schema-founding-pg{major}"),
        &seed,
        vec![user(HENRY, &[]), user(PAUL, &[]), role("anonymous", "app")],
    )
    .inserting_values(
        "memberships",
        &[("organization_id", O3), ("user_id", HENRY)],
    )
    .inserting_values(
        "grants",
        &[
            ("resource_id", O3),
            ("organization_id", O3),
            ("grantee_id", HENRY),
        ],
    )
}

/// The three states together decide every clause side, the founding state reaching the
/// founding arms the others never can.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn the_core_schema_agrees_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        let variants = [
            committed(major),
            accepting_an_invitation(major),
            before_founding(major),
        ];
        let runs = run_variants_before(&cluster, &variants, DEADLINE).await;
        for (case, run) in variants.iter().zip(&runs) {
            assert_agrees(case, run);
            assert_two_sided(case, run);
        }
    }
}
