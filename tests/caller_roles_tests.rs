//! A policy's `TO` roles settled against the database roles every caller runs as.

extern crate alloc;

use alloc::collections::BTreeSet;

use rls2fga::generator::caller_roles::CallerRoles;
use rls2fga::translator::{Outputs, Translation, TranslatorBuilder};
use rls2fga::types::{NoteSeverity, TranslationNote};

mod support;

use support::footgun::{db_of, relation_definition};

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

fn translate(policies: &str, callers: Option<&[&str]>) -> Translation {
    let mut builder = TranslatorBuilder::new().with_current_user_setting_keys(["app.user_id"]);
    if let Some(callers) = callers {
        builder = builder
            .with_caller_roles(CallerRoles::new(callers.iter().copied()).expect("callers named"));
    }
    builder
        .build()
        .translate(&db_of(&format!("{KINDS}{policies}")))
        .expect("translation should plan")
}

fn kinds(policies: &str) -> Outputs {
    translate(policies, Some(&["anon", "authenticated"])).outputs_accepting_gaps()
}

/// Every `pg_role` the tuples name, which is every role fact the consumer must load.
fn pg_roles_named(outputs: &Outputs) -> BTreeSet<String> {
    outputs
        .tuple_queries()
        .iter()
        .flat_map(|query| query.sql.split("'pg_role:").skip(1))
        .filter_map(|tail| tail.split_once('\'').map(|(role, _)| role.to_string()))
        .collect()
}

fn notes_about<'a>(outputs: &'a Outputs, policy: &str) -> Vec<&'a TranslationNote> {
    outputs
        .notes()
        .iter()
        .filter(|note| note.subject() == policy)
        .collect()
}

#[test]
fn a_role_no_caller_role_reaches_leaves_the_policy_out() {
    let outputs = kinds("CREATE POLICY staff ON docs FOR SELECT TO support_staff USING (true);");
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::new(),
        "{}",
        outputs.model()
    );
    let notes = notes_about(&outputs, "staff");
    assert!(
        matches!(
            notes.as_slice(),
            [note @ TranslationNote::PolicyAppliesToNoCallerRole { roles, .. }]
                if note.severity() == NoteSeverity::Exempt && roles == &["support_staff"]
        ),
        "{notes:#?}"
    );
    let unscoped = kinds("");
    assert_eq!(
        relation_definition(&outputs.model(), "docs", "can_select"),
        relation_definition(&unscoped.model(), "docs", "can_select"),
        "{}",
        outputs.model()
    );
}

#[test]
fn an_inherited_role_scopes_to_the_caller_roles_inheriting_it() {
    let outputs =
        kinds("CREATE POLICY audit ON docs FOR SELECT TO auditors USING (status = 'published');");
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::from(["authenticated".to_string()]),
        "{}",
        outputs.model()
    );
    assert!(outputs.notes().iter().any(|note| matches!(
        note,
        TranslationNote::PolicyRoleScope { policy, roles, .. }
            if policy == "audit" && roles == &["authenticated"]
    )));
}

#[test]
fn a_membership_without_inherit_does_not_reach() {
    for grant in [
        "",
        "CREATE ROLE quiet NOINHERIT; GRANT quiet TO authenticated; GRANT auditors TO quiet;",
    ] {
        let to = if grant.is_empty() {
            "reviewers"
        } else {
            "auditors"
        };
        let sql = format!("{grant} CREATE POLICY p ON docs FOR SELECT TO {to} USING (true);");
        let callers: &[&str] = if grant.is_empty() {
            &["anon", "authenticated"]
        } else {
            &["anon", "quiet"]
        };
        let outputs = translate(&sql, Some(callers)).outputs_accepting_gaps();
        assert!(
            notes_about(&outputs, "p")
                .iter()
                .any(|note| matches!(note, TranslationNote::PolicyAppliesToNoCallerRole { .. })),
            "{sql}: {:#?}",
            outputs.notes()
        );
        assert_eq!(pg_roles_named(&outputs), BTreeSet::new(), "{sql}");
    }
}

#[test]
fn a_role_every_caller_role_reaches_reads_as_unscoped() {
    let scoped = kinds(
        "CREATE POLICY everyone ON docs FOR SELECT TO anon, authenticated USING (status = 'published');",
    );
    let public = kinds("CREATE POLICY everyone ON docs FOR SELECT USING (status = 'published');");
    assert_eq!(
        pg_roles_named(&scoped),
        BTreeSet::new(),
        "{}",
        scoped.model()
    );
    assert_eq!(scoped.model(), public.model());
}

#[test]
fn a_restrictive_policy_no_caller_role_reaches_binds_nobody() {
    let outputs = kinds(
        "CREATE POLICY hide ON docs AS RESTRICTIVE FOR SELECT TO support_staff USING (status = 'draft');",
    );
    assert_eq!(outputs.model(), kinds("").model());
    assert!(notes_about(&outputs, "hide")
        .iter()
        .any(|note| matches!(note, TranslationNote::PolicyAppliesToNoCallerRole { .. })));
}

#[test]
fn a_restrictive_policy_some_caller_roles_reach_binds_only_them() {
    let outputs = kinds(
        "CREATE POLICY hide ON docs AS RESTRICTIVE FOR SELECT TO auditors USING (status = 'draft');",
    );
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::from(["authenticated".to_string()]),
        "{}",
        outputs.model()
    );
}

#[test]
fn a_role_the_schema_never_creates_is_refused() {
    for (policy, callers) in [
        (
            "CREATE POLICY p ON docs FOR SELECT TO ghost USING (true);",
            &["anon", "authenticated"][..],
        ),
        (
            "CREATE POLICY p ON docs FOR SELECT TO auditors USING (true);",
            &["anon", "authenticated", "bot"][..],
        ),
    ] {
        let translation = translate(policy, Some(callers));
        let outputs = translation.clone().outputs_accepting_gaps();
        let refused = translation
            .outputs()
            .expect_err("an unsettled role diverges from the database");
        assert!(
            notes_about(&outputs, "p").iter().any(|note| matches!(
                note,
                TranslationNote::PolicyRoleUnsettled { .. }
                    if note.severity() == NoteSeverity::Unhandled
            )),
            "{refused}"
        );
        assert_eq!(pg_roles_named(&outputs), BTreeSet::new(), "{policy}");
        assert_eq!(
            relation_definition(&outputs.model(), "docs", "can_select"),
            relation_definition(&kinds("").model(), "docs", "can_select"),
            "a permissive policy falls closed: {}",
            outputs.model()
        );
    }
}

#[test]
fn an_unsettled_restrictive_policy_binds_every_caller() {
    let outputs =
        kinds("CREATE POLICY hide ON docs AS RESTRICTIVE FOR SELECT TO ghost USING (false);");
    assert!(
        support::footgun::relation_denies(&outputs.model(), "docs", "can_select"),
        "{}",
        outputs.model()
    );
}

#[test]
fn without_caller_roles_every_named_role_stays_a_fact_to_load() {
    let outputs = translate(
        "CREATE POLICY staff ON docs FOR SELECT TO support_staff USING (true);
         CREATE POLICY audit ON docs FOR SELECT TO auditors USING (status = 'published');",
        None,
    )
    .outputs_accepting_gaps();
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::from(["auditors".to_string(), "support_staff".to_string()])
    );
}

#[test]
fn caller_roles_cannot_be_empty() {
    assert!(CallerRoles::new(core::iter::empty::<&str>()).is_err());
}

/// A docs grant through a membership table whose rows only `members_to` may read.
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

#[test]
fn a_membership_read_scope_names_only_caller_roles() {
    let outputs = kinds(&membership("auditors"));
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::from(["authenticated".to_string()]),
        "{}",
        outputs.model()
    );
}

#[test]
fn a_membership_table_every_caller_role_reads_needs_no_scope() {
    let outputs = kinds(&membership("anon, authenticated"));
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::new(),
        "{}",
        outputs.model()
    );
}

#[test]
fn a_membership_table_no_caller_role_reads_grants_nothing() {
    let outputs = kinds(&membership("support_staff"));
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::new(),
        "{}",
        outputs.model()
    );
    assert!(
        notes_about(&outputs, "shared")
            .iter()
            .any(|note| matches!(note, TranslationNote::MembershipTableGrantsNoReads { .. })),
        "{:#?}",
        outputs.notes()
    );
}

#[test]
fn an_unsettled_membership_read_role_is_refused() {
    let outputs = kinds(&membership("ghost"));
    assert_eq!(
        pg_roles_named(&outputs),
        BTreeSet::new(),
        "{}",
        outputs.model()
    );
    assert!(
        notes_about(&outputs, "shared").iter().any(|note| matches!(
            note,
            TranslationNote::PolicyRoleUnsettled { roles, .. } if roles == &["ghost"]
        )),
        "{:#?}",
        outputs.notes()
    );
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
mod parity {
    use rls2fga::types::ActionStatement;

    use super::{membership, KINDS};
    use crate::support::parity::{
        assert_agrees, assert_disclosed_where_noted, assert_postgres, run, run_disclosing, Cluster,
        ParityCase, Principal,
    };

    const ATTRIBUTES: &str = r#"[{"key":"app.user_id","kind":"caller_id"}]"#;
    const POLICIES: &str = "
CREATE POLICY staff ON docs FOR SELECT TO support_staff USING (true);
CREATE POLICY audit ON docs FOR SELECT TO auditors USING (status = 'published');
CREATE POLICY review ON docs FOR SELECT TO reviewers USING (true);
CREATE POLICY everyone ON docs FOR SELECT TO anon, authenticated USING (id = 'd-public');
CREATE POLICY hide ON docs AS RESTRICTIVE FOR SELECT TO support_staff USING (status = 'draft');
CREATE POLICY anon_barrier ON docs AS RESTRICTIVE FOR SELECT TO anon USING (status = 'published');
";
    const SEED: &[&str] = &[
        "INSERT INTO docs VALUES
           ('d1', 'alice', 'published'), ('d2', 'bob', 'draft'),
           ('d3', 'carol', 'published'), ('d4', 'visitor', 'draft'),
           ('d-public', NULL, 'published')",
        "GRANT SELECT ON docs TO anon, authenticated",
    ];

    fn callers() -> Vec<Principal> {
        [
            ("alice", "authenticated"),
            ("bob", "authenticated"),
            ("visitor", "anon"),
        ]
        .into_iter()
        .map(|(subject, kind)| {
            Principal::with_setting(subject, kind, "app.user_id", subject).holding(&[kind])
        })
        .collect()
    }

    fn case(name: &str, callers: Option<&[&str]>) -> ParityCase {
        let case = ParityCase::reading(name, &format!("{KINDS}{POLICIES}"), SEED, self::callers())
            .with_attributes(ATTRIBUTES);
        match callers {
            Some(callers) => case.with_caller_roles(callers),
            None => case,
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn each_caller_role_agrees_with_postgres() {
        tokio::time::timeout(core::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            for from_rows in [false, true] {
                let mut settled = case(
                    &format!("caller-roles-{from_rows}"),
                    Some(&["anon", "authenticated"]),
                );
                if from_rows {
                    settled = settled.loading_from_rows();
                }
                let run = run(&cluster, &settled).await;
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
                        &settled,
                        &run,
                        subject,
                        object,
                        ActionStatement::Select,
                        visible,
                    );
                }
                assert_agrees(&settled, &run);
            }
            let unsettled = case("caller-roles-unset", None);
            let run = run(&cluster, &unsettled).await;
            assert!(
                run.observations.iter().any(|pair| pair.disagrees()
                    && pair.subject == "alice"
                    && pair.object == "docs:d3"),
                "without caller roles an inherited role asks for a fact no caller holds"
            );
        })
        .await
        .expect("caller-roles-1 must finish within 300 seconds");
    }

    #[tokio::test]
    #[ignore = "requires Docker, PostgreSQL and OpenFGA"]
    async fn a_membership_table_read_by_some_caller_roles_agrees_with_postgres() {
        tokio::time::timeout(core::time::Duration::from_secs(300), async {
            let cluster = Cluster::start().await;
            for from_rows in [false, true] {
                let mut case = ParityCase::reading(
                    &format!("caller-roles-membership-{from_rows}"),
                    &format!("{KINDS}{}", membership("auditors")),
                    &[
                        "INSERT INTO docs VALUES
                           ('d1', 'alice', 'published'), ('d2', 'bob', 'draft'),
                           ('d3', 'carol', 'published'), ('d4', 'visitor', 'draft')",
                        "INSERT INTO members VALUES ('d2', 'alice'), ('d3', 'visitor')",
                        "GRANT SELECT ON docs, members TO anon, authenticated",
                    ],
                    callers(),
                )
                .with_attributes(ATTRIBUTES)
                .with_caller_roles(&["anon", "authenticated"]);
                if from_rows {
                    case = case.loading_from_rows();
                }
                let run = run_disclosing(&cluster, &case).await;
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
                assert!(
                    run.observations
                        .iter()
                        .all(|pair| !pair.disagrees() || pair.table != "docs"),
                    "{:#?}",
                    run.observations
                );
                assert_disclosed_where_noted(&case, &run);
            }
        })
        .await
        .expect("caller-roles-membership-1 must finish within 300 seconds");
    }
}
