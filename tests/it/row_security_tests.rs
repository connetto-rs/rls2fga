//! Policies applied per acting role, as `row_security` answers for each role a request runs as.

use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{NoteSeverity, TranslationNote};

use crate::support::deployment::{caller_deployment_acting_as, scalar};
use crate::support::footgun::{db_of, relation_definition, relation_denies};

/// Two acting kinds, two roles neither is, `auditors` inherited by `authenticated` and
/// `reviewers` granted to it without inheritance.
const KINDS: &str = "
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE support_staff NOLOGIN;
CREATE ROLE auditors NOLOGIN;
CREATE ROLE reviewers NOLOGIN;
GRANT auditors TO authenticated;
GRANT reviewers TO authenticated WITH INHERIT FALSE;
CREATE TABLE docs (id TEXT PRIMARY KEY, owner TEXT, status TEXT NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON docs FOR SELECT USING (owner = current_setting('app.user_id', true));
";

/// `policies` over [`KINDS`], translated for a deployment acting as `acting` that declares
/// the scalar `app.read_caps`.
fn acting_as(acting: &[&str], policies: &str) -> Outputs {
    TranslatorBuilder::new(caller_deployment_acting_as(
        acting,
        [scalar("app.read_caps")],
    ))
    .build()
    .translate(&db_of(&format!("{KINDS}{policies}")))
    .expect("translation should plan")
    .outputs_accepting_gaps()
}

/// `policies` over [`KINDS`], for a deployment acting as `anon` and `authenticated`.
fn kinds(policies: &str) -> Outputs {
    acting_as(&["anon", "authenticated"], policies)
}

/// A policy whose `TO` list reaches no acting role applies to no request, so the model
/// reads as if it were absent, in either mode.
#[test]
fn a_role_no_acting_role_reaches_leaves_the_policy_out() {
    let without = kinds("").model();
    for policy in [
        "CREATE POLICY staff ON docs FOR SELECT TO support_staff USING (true);",
        "CREATE POLICY hide ON docs AS RESTRICTIVE FOR SELECT TO support_staff USING (status = 'draft');",
        "CREATE POLICY review ON docs FOR SELECT TO reviewers USING (true);",
    ] {
        assert_eq!(kinds(policy).model(), without, "{policy}");
    }
}

/// A role an acting role inherits reaches it, so `TO auditors` binds exactly the requests
/// acting as `authenticated`, and naming every acting role binds every request.
#[test]
fn a_to_list_reaches_the_acting_roles_inheriting_it() {
    for (inherited, named) in [
        ("TO auditors", "TO authenticated"),
        (
            "AS RESTRICTIVE FOR SELECT TO auditors",
            "AS RESTRICTIVE FOR SELECT TO authenticated",
        ),
        ("TO anon, authenticated", ""),
    ] {
        let spell = |to: &str| {
            let to = if to.contains("FOR SELECT") {
                to.to_string()
            } else {
                format!("FOR SELECT {to}")
            };
            format!("CREATE POLICY p ON docs {to} USING (status = 'published');")
        };
        assert_eq!(
            kinds(&spell(inherited)).model(),
            kinds(&spell(named)).model(),
            "`{inherited}` against `{named}`"
        );
    }
}

/// A `NOINHERIT` member reaches nothing its memberships hold, so a role granted through
/// one reaches no acting role.
#[test]
fn a_membership_without_inheritance_does_not_reach() {
    let outputs = acting_as(
        &["anon", "quiet"],
        "CREATE ROLE quiet NOINHERIT; GRANT quiet TO authenticated; GRANT auditors TO quiet;
         CREATE POLICY p ON docs FOR SELECT TO auditors USING (true);",
    );
    let without = acting_as(
        &["anon", "quiet"],
        "CREATE ROLE quiet NOINHERIT; GRANT quiet TO authenticated; GRANT auditors TO quiet;",
    );
    assert_eq!(outputs.model(), without.model());
}

/// A `TO` role the schema never creates cannot be settled, so the statement is refused for
/// each acting role it would decide, and the refusal blocks the outputs.
#[test]
fn a_role_the_schema_never_creates_is_refused() {
    let outputs = kinds("CREATE POLICY p ON docs FOR SELECT TO ghost USING (true);");
    let refusals: Vec<&TranslationNote> = outputs
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::RowSecurityRefused { reason, .. } if reason.contains("ghost")))
        .collect();
    assert_eq!(refusals.len(), 2, "{:#?}", outputs.notes());
    assert!(refusals
        .iter()
        .all(|note| note.severity() == NoteSeverity::Unhandled));
    assert!(
        relation_denies(&outputs.model(), "docs", "can_select"),
        "{}",
        outputs.model()
    );
}

/// A docs grant through a membership table only `members_to` reads.
fn membership(members_to: &str) -> String {
    format!(
        "CREATE TABLE members (doc_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (doc_id, user_id));
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_read ON members FOR SELECT TO {members_to} USING (true);
CREATE POLICY shared ON docs FOR SELECT
  USING (id IN (SELECT doc_id FROM members WHERE user_id = current_setting('app.user_id', true)));
"
    )
}

/// The membership reaches exactly the acting roles that read the membership table.
#[test]
fn a_membership_reaches_the_acting_roles_reading_its_table() {
    assert_eq!(
        kinds(&membership("auditors")).model(),
        kinds(&membership("authenticated")).model()
    );
    let nobody = kinds(&membership("support_staff"));
    assert!(
        nobody.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGrantsNoReads { policy, .. } if policy == "shared"
        )),
        "{:#?}",
        nobody.notes()
    );
    let can_select =
        relation_definition(&nobody.model(), "docs", "can_select").expect("docs keeps can_select");
    assert!(!can_select.contains("member"), "{}", nobody.model());
}

/// A read cap on the membership table that binds only `anon` gates only the requests
/// acting as `anon`, and a deployment acting only as `authenticated` reads it open.
#[test]
fn a_membership_read_cap_binds_only_the_roles_it_names() {
    let capped = "
CREATE TABLE members (doc_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (doc_id, user_id));
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_open ON members FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY members_cap ON members AS RESTRICTIVE FOR SELECT TO anon
  USING (current_setting('app.read_caps', true) = 'members:read');
CREATE POLICY shared ON docs FOR SELECT
  USING (id IN (SELECT doc_id FROM members WHERE user_id = current_setting('app.user_id', true)));
";
    let open = acting_as(&["authenticated"], capped);
    let unguarded = acting_as(
        &["authenticated"],
        &capped.replace("ALTER TABLE members ENABLE ROW LEVEL SECURITY;", ""),
    );
    assert_eq!(
        relation_definition(&open.model(), "docs", "can_select"),
        relation_definition(&unguarded.model(), "docs", "can_select"),
        "{}",
        open.model()
    );
    assert_ne!(
        relation_definition(&kinds(capped).model(), "docs", "can_select"),
        relation_definition(
            &kinds(&capped.replace("ALTER TABLE members ENABLE ROW LEVEL SECURITY;", "")).model(),
            "docs",
            "can_select"
        ),
        "the cap gates the anon branch"
    );
}

/// An acting role that owns the table skips its policies unless the table forces them.
#[test]
fn an_owning_acting_role_skips_the_policies_only_without_force() {
    let owned = "ALTER TABLE docs OWNER TO authenticated;";
    let exempt = kinds(owned);
    assert!(
        exempt.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ActingRoleExempt { role, .. } if role == "authenticated"
        )),
        "{:#?}",
        exempt.notes()
    );
    let forced = kinds(&format!(
        "{owned} ALTER TABLE docs FORCE ROW LEVEL SECURITY;"
    ));
    assert!(
        !forced
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ActingRoleExempt { .. })),
        "{:#?}",
        forced.notes()
    );
    assert_eq!(forced.model(), kinds("").model());
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
mod parity {
    use rls2fga::types::ActionStatement;

    use super::{membership, KINDS};
    use crate::support;
    use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    const POLICIES: &str = "
CREATE POLICY staff ON docs FOR SELECT TO support_staff USING (true);
CREATE POLICY audit ON docs FOR SELECT TO auditors USING (status = 'published');
CREATE POLICY review ON docs FOR SELECT TO reviewers USING (true);
CREATE POLICY everyone ON docs FOR SELECT TO anon, authenticated USING (id = 'd-public');
CREATE POLICY hide ON docs AS RESTRICTIVE FOR SELECT TO support_staff USING (status = 'draft');
CREATE POLICY anon_barrier ON docs AS RESTRICTIVE FOR SELECT TO anon USING (status = 'published');
";

    fn callers() -> Vec<Principal> {
        [
            ("alice", "authenticated"),
            ("bob", "authenticated"),
            ("visitor", "anon"),
        ]
        .into_iter()
        .map(|(subject, kind)| Principal::with_setting(subject, kind, "app.user_id", subject))
        .collect()
    }

    /// Each acting role meets the policies its `TO` lists reach, inherited roles and
    /// role-scoped barriers included, in `PostgreSQL` and in the model alike.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn each_acting_role_agrees_with_postgres() {
        let cluster = Cluster::start().await;
        for from_rows in [false, true] {
            let mut case = ParityCase::reading(
                &format!("acting-roles-{from_rows}"),
                &format!("{KINDS}{POLICIES}"),
                &[
                    "INSERT INTO docs VALUES
                       ('d1', 'alice', 'published'), ('d2', 'bob', 'draft'),
                       ('d3', 'carol', 'published'), ('d4', 'visitor', 'draft'),
                       ('d-public', NULL, 'published')",
                    "GRANT SELECT ON docs TO anon, authenticated",
                ],
                callers(),
            );
            if from_rows {
                case = case.loading_from_rows();
            }
            let run = support::parity::run(&cluster, &case).await;
            for (subject, object, visible) in [
                ("alice", "docs:d1", true),
                ("alice", "docs:d2", false),
                ("alice", "docs:d3", true),
                ("bob", "docs:d2", true),
                ("visitor", "docs:d-public", true),
                ("visitor", "docs:d4", false),
                ("visitor", "docs:d3", false),
            ] {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    object,
                    ActionStatement::Select,
                    visible,
                );
            }
            assert_agrees(&case, &run);
        }
    }

    /// A membership table only `authenticated` reads grants through it to requests acting
    /// as `authenticated` alone.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn a_membership_table_read_by_one_acting_role_agrees_with_postgres() {
        let cluster = Cluster::start().await;
        let case = ParityCase::reading(
            "acting-roles-membership",
            &format!("{KINDS}{}", membership("auditors")),
            &[
                "INSERT INTO docs VALUES
                   ('d1', 'alice', 'published'), ('d2', 'bob', 'draft'),
                   ('d3', 'carol', 'published'), ('d4', 'visitor', 'draft')",
                "INSERT INTO members VALUES ('d2', 'alice'), ('d3', 'visitor')",
                "GRANT SELECT ON docs, members TO anon, authenticated",
            ],
            callers(),
        );
        let run = support::parity::run(&cluster, &case).await;
        for (subject, object, visible) in [
            ("alice", "docs:d2", true),
            ("visitor", "docs:d3", false),
            ("visitor", "docs:d4", true),
        ] {
            assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                visible,
            );
        }
        assert_agrees(&case, &run);
    }

    /// An acting role owning the table reads every row unless the table forces its
    /// policies on the owner.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn an_owning_acting_role_agrees_with_and_without_force() {
        let cluster = Cluster::start().await;
        for force in ["", "ALTER TABLE docs FORCE ROW LEVEL SECURITY;"] {
            let case = ParityCase::reading(
                &format!("owner-force-{}", !force.is_empty()),
                &format!(
                    "CREATE ROLE app_owner;
                     CREATE TABLE docs (id TEXT PRIMARY KEY, owner TEXT NOT NULL);
                     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
                     CREATE POLICY own ON docs FOR SELECT
                       USING (owner = current_setting('app.user_id', true));
                     ALTER TABLE docs OWNER TO app_owner;
                     {force}"
                ),
                &["INSERT INTO docs VALUES ('d1', 'alice'), ('d2', 'bob')"],
                vec![Principal::with_setting(
                    "alice",
                    "app_owner",
                    "app.user_id",
                    "alice",
                )],
            );
            let run = support::parity::run(&cluster, &case).await;
            assert_postgres(
                &case,
                &run,
                "alice",
                "docs:d2",
                ActionStatement::Select,
                force.is_empty(),
            );
            assert_agrees(&case, &run);
        }
    }
}
