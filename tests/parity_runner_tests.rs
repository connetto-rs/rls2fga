//! The generic parity runner, and what it has to catch.
//!
//! A case here declares a schema, a seed and its callers. Which relations answer which
//! statement, and how a row is named, come from the translation, so nothing in a case
//! repeats that analysis. The runner compares every principal against every object for
//! every statement, in both directions.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rls2fga::types::{ActionAnswer, ActionStatement};

mod support;

use support::parity::{assert_agrees, Cluster, Mutations, ParityCase, Principal};

/// One case, ready to run, beside the name a failure reports.
type Case = (&'static str, Pin<Box<dyn Future<Output = ()> + Send>>);

/// Every case, named from the function that is it.
///
/// One list rather than a list beside a mirror of it: the count a failure reports and the
/// cases that ran cannot disagree, and adding a case is one edit.
macro_rules! cases {
    ($cluster:expr, [$($name:ident),+ $(,)?]) => {{
        let cases: Vec<Case> = vec![$((
            stringify!($name),
            Box::pin($name(Arc::clone(&$cluster))),
        )),+];
        cases
    }};
}

/// Every case, one at a time against one container pair.
///
/// One test rather than twenty-two: the pair has to outlive every case, and a container
/// that is removed when it drops cannot be parked in a static without leaking it after the
/// process exits. Each case still runs in its own task, so a panic fails that case, names
/// it, and leaves the rest to run.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn every_parity_case_agrees() {
    let cluster = Arc::new(Cluster::start().await);
    let cases = cases![
        cluster,
        [
            the_runner_agrees_on_direct_ownership,
            the_runner_agrees_on_membership,
            the_runner_agrees_on_a_role_scoped_restriction,
            both_one_sided_cases_pass,
            the_runner_finds_a_planted_divergence,
            an_update_candidate_exercises_with_check,
            a_nested_protected_read_denies_on_both_sides,
            a_split_function_owner_does_not_bypass_row_level_security,
            a_strict_function_hides_the_null_row,
            a_reserved_name_collision_keeps_two_types,
            a_reserved_parent_is_referenced_by_its_defined_name,
            a_qualified_call_is_not_the_declared_accessor,
            a_function_local_search_path_picks_the_membership_table,
            an_unplaceable_membership_table_grants_nothing,
            a_restrictive_flag_narrows_a_blanket_read,
            a_blanket_delete_does_not_widen_the_read,
            a_shadowed_clock_is_not_the_request_clock,
            an_update_policy_without_using_updates_nothing,
            a_locking_read_applies_the_update_policy,
            an_altered_policy_is_read_as_altered,
            folded_identifiers_name_one_table,
            two_owner_columns_grant_independently,
            an_uncorrelated_membership_admits_every_row,
            a_parent_key_subquery_inherits_the_parents_rule,
            a_correlated_column_membership_compares_the_named_columns,
            a_read_and_a_write_are_judged_separately,
            an_aliased_quoted_guard_falls_closed,
            mutually_recursive_policies_return_no_row,
            a_partition_is_named_after_its_root,
            a_composite_foreign_key_membership_joins_on_both_columns,
            a_joined_inner_rule_drops_the_unjoined_row,
            a_quoted_role_is_a_different_role,
            a_declared_session_set_grants_beside_the_owner,
            an_array_and_a_jsonb_field_name_the_caller,
            a_clock_guard_holds_on_a_zoned_and_a_dated_column,
            a_cross_row_residual_is_decided_by_rows_the_grant_does_not_name,
            a_composite_key_share_stays_within_its_tenant,
            a_caller_role_residual_falls_closed,
            a_computed_argument_is_not_captured_by_the_body,
            a_failed_case_leaves_no_role_behind,
            a_role_scoped_membership_read_gates_the_parent,
            a_noinherit_member_of_a_scoped_role_reads_nothing,
            a_shared_paper_reads_through_either_arm,
            a_team_share_reaches_items_through_the_team,
            a_batch_share_grants_every_paper_of_the_batch,
            a_composite_key_share_in_the_callers_set_stays_within_its_tenant,
            a_row_valued_set_share_reaches_items_through_the_team,
            a_membership_row_compared_to_the_caller_twice_denies_either_half,
            a_token_claim_list_grants_by_membership,
            one_shared_grant_ladder_answers_two_thresholds,
            three_refused_spellings_fall_closed,
            a_missing_session_setting_is_not_a_denial,
            a_request_time_guard_holds_at_two_instants,
            a_grace_period_keeps_its_offset,
            an_expiring_share_leaves_the_owner_arm_alone,
            an_expiring_share_keeps_its_grace_period,
            an_expiring_membership_row_gates_its_own_document,
            an_expiring_holder_row_admits_the_caller_to_everything,
            a_definer_wrapper_answers_for_a_caller_without_the_grant,
            a_restrictive_policy_binds_only_its_role,
            one_policy_name_on_two_tables_keeps_two_comparisons,
            two_viewers_of_one_paper_load_and_union,
            two_expiring_viewers_of_one_paper_gate_independently,
            two_deadlines_need_one_witnessing_row,
            a_clock_gated_record_replays_from_its_own_row,
            a_share_record_replays_onto_another_types_object,
            a_role_ladder_answers_four_thresholds,
            an_insert_that_reads_back_applies_the_select_policy,
            an_upsert_applies_the_update_policy_too,
            every_exact_support_case_agrees,
            a_missing_statement_answer_fails_the_case,
            a_row_the_model_cannot_name_fails_the_case,
            a_declared_write_stays_on_its_own_table,
            a_mutation_spelling_resolves_to_exactly_one_table,
            the_oracle_rejects_a_note_excused_mismatch,
            a_witness_link_and_a_caller_set_gate_do_not_share_a_tupleset,
            distinct_acl_tables_do_not_share_a_member_relation,
            distinct_team_membership_tables_do_not_share_access,
            a_plain_and_a_gated_read_of_the_same_join_table_do_not_share_access,
        ]
    ];
    let total = cases.len();

    let mut failures = Vec::new();
    for (name, case) in cases {
        // Each case in its own task, so a panic fails that case, names it, and leaves the
        // rest to run.
        if let Err(joined) = tokio::spawn(case).await {
            failures.push(format!("{name}: {}", panic_message(joined)));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {total} cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Table privileges, compared on `PostgreSQL` 17 and 18.
///
/// A cluster per major rather than one more case in the list above, which runs on one
/// pair.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn table_privileges_agree_on_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on_postgres(major).await;
        a_withheld_privilege_refuses_what_the_policy_admits(&cluster, major).await;
        every_grant_shape_gates_its_command(&cluster, major).await;
        a_privilege_settles_to_the_caller_roles_reaching_its_holder(&cluster, major).await;
    }
}

/// With caller roles, a grant to a role the callers inherit gates on the callers reaching it.
///
/// `UPDATE` is granted to `writers`, which `kind_user` inherits, so the gate names `kind_user`
/// and each caller's one fact says which caller role it runs as.
async fn a_privilege_settles_to_the_caller_roles_reaching_its_holder(
    cluster: &Cluster,
    major: &str,
) {
    let case = ParityCase::reading(
        &format!("privileges-caller-roles-{major}"),
        "
CREATE ROLE kind_anon NOLOGIN;
CREATE ROLE kind_user NOLOGIN;
CREATE ROLE writers NOLOGIN;
GRANT writers TO kind_user;
CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT NOT NULL, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (true);
CREATE POLICY notes_write ON notes FOR UPDATE
    USING (owner = current_setting('app.user_id', true));
GRANT SELECT ON notes TO kind_anon, kind_user;
GRANT UPDATE ON notes TO writers;
",
        &["INSERT INTO notes(id, owner, body) VALUES (1, 'bob', 'b'), (2, 'carol', 'c')"],
        vec![
            Principal::with_setting("bob", "kind_anon", "app.user_id", "bob")
                .holding(&["kind_anon"]),
            Principal::with_setting("carol", "kind_user", "app.user_id", "carol")
                .holding(&["kind_user"]),
        ],
    )
    .writing(
        "notes",
        Mutations {
            update_set: Some("body = body".to_string()),
            check_neutral: true,
        },
    )
    .with_caller_roles(&["kind_anon", "kind_user"])
    .modelling_table_privileges();

    let run = support::parity::run(cluster, &case).await;
    for (subject, object, statement, allowed) in [
        ("bob", "notes:1", ActionStatement::Update, false),
        ("bob", "notes:2", ActionStatement::Select, true),
        ("carol", "notes:2", ActionStatement::Update, true),
    ] {
        support::parity::assert_postgres(&case, &run, subject, object, statement, allowed);
    }
    assert_agrees(&case, &run);
}

/// The rows a policy admits, refused to a role lacking the command's privilege.
///
/// `kind_anon` may read but not update, so the owner of a row acting as `kind_anon` is
/// refused the update the policy grants. `alice` holds `kind_user` by inheriting it, which
/// `has_privs_of_role` honours and `pg_role#usage` carries.
async fn a_withheld_privilege_refuses_what_the_policy_admits(cluster: &Cluster, major: &str) {
    let case = |name: &str, modelled: bool| {
        // Only a model carrying privileges declares `pg_role`, so only that one is told
        // who holds which role.
        let held = |roles: &'static [&'static str]| -> &'static [&'static str] {
            if modelled {
                roles
            } else {
                &[]
            }
        };
        let case = ParityCase::reading(
            name,
            "
CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT NOT NULL, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (true);
CREATE POLICY notes_write ON notes FOR UPDATE
    USING (owner = current_setting('app.user_id', true));
GRANT SELECT ON notes TO kind_anon;
GRANT SELECT, UPDATE ON notes TO kind_user;
",
            &["INSERT INTO notes(id, owner, body) VALUES (1, 'alice', 'a'), (2, 'bob', 'b'), (3, 'carol', 'c')"],
            vec![
                Principal::with_setting("alice", "alice", "app.user_id", "alice")
                    .holding(held(&["kind_user"])),
                Principal::with_setting("bob", "kind_anon", "app.user_id", "bob")
                    .holding(held(&["kind_anon"])),
                Principal::with_setting("carol", "kind_user", "app.user_id", "carol")
                    .holding(held(&["kind_user"])),
            ],
        )
        .after(&[
            "CREATE ROLE kind_anon NOLOGIN; CREATE ROLE kind_user NOLOGIN;
             CREATE ROLE alice LOGIN IN ROLE kind_user",
        ])
        .writing(
            "notes",
            Mutations {
                update_set: Some("body = body".to_string()),
                // The policies read the owner, never the body.
                check_neutral: true,
            },
        );
        if modelled {
            case.modelling_table_privileges()
        } else {
            case
        }
    };

    let modelled = case(&format!("privileges-withheld-{major}"), true);
    let run = support::parity::run(cluster, &modelled).await;
    for (subject, object, statement, allowed) in [
        ("bob", "notes:2", ActionStatement::Update, false),
        ("bob", "notes:1", ActionStatement::Select, true),
        ("alice", "notes:1", ActionStatement::Update, true),
        ("carol", "notes:3", ActionStatement::Update, true),
        ("carol", "notes:3", ActionStatement::Delete, false),
    ] {
        support::parity::assert_postgres(&modelled, &run, subject, object, statement, allowed);
    }
    assert_agrees(&modelled, &run);

    // Without the option the model says nothing about privileges, so the pair a privilege
    // refuses is left uncompared and every other one still agrees.
    let unmodelled = case(&format!("privileges-unmodelled-{major}"), false);
    let run = support::parity::run(cluster, &unmodelled).await;
    assert_eq!(
        run.postgres_answered("bob", "notes:2", ActionStatement::Update),
        None,
        "{}: a pair only the privilege refuses was compared",
        unmodelled.name
    );
    assert_agrees(&unmodelled, &run);
}

/// `PUBLIC`, `ALL PRIVILEGES`, a `REVOKE`, and a role holding nothing on a policied table.
///
/// Every policy admits every row, so each answer is the privilege's alone.
async fn every_grant_shape_gates_its_command(cluster: &Cluster, major: &str) {
    let neutral = || Mutations {
        update_set: Some("body = body".to_string()),
        check_neutral: true,
    };
    let case = ParityCase::reading(
        &format!("privileges-every-shape-{major}"),
        "
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
CREATE TABLE secrets (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY secrets_all ON secrets USING (true) WITH CHECK (true);
GRANT SELECT ON docs TO PUBLIC;
GRANT ALL PRIVILEGES ON docs, secrets TO admin;
GRANT UPDATE, DELETE ON docs TO editor;
REVOKE DELETE ON docs FROM editor;
",
        &[
            "INSERT INTO docs(id, body) VALUES ('d1', 'one')",
            "INSERT INTO secrets(id, body) VALUES ('s1', 'one')",
        ],
        vec![
            Principal::as_role("admin", "admin").holding(&["admin"]),
            Principal::as_role("editor", "editor").holding(&["editor"]),
            Principal::as_role("stranger", "stranger").holding(&["stranger"]),
        ],
    )
    .after(&["CREATE ROLE admin LOGIN; CREATE ROLE editor LOGIN; CREATE ROLE stranger LOGIN"])
    .writing("docs", neutral())
    .writing("secrets", neutral())
    .modelling_table_privileges();

    let run = support::parity::run(cluster, &case).await;
    for (subject, object, statement, allowed) in [
        // `PUBLIC` reads docs, and nobody else's grant is needed for it.
        ("stranger", "docs:d1", ActionStatement::Select, true),
        ("stranger", "docs:d1", ActionStatement::Update, false),
        // `ALL PRIVILEGES` holds every command.
        ("admin", "secrets:s1", ActionStatement::Delete, true),
        ("admin", "docs:d1", ActionStatement::Insert, true),
        // The revoke took `DELETE` and left `UPDATE`.
        ("editor", "docs:d1", ActionStatement::Update, true),
        ("editor", "docs:d1", ActionStatement::Delete, false),
        // Nothing on secrets at all.
        ("stranger", "secrets:s1", ActionStatement::Select, false),
        ("editor", "secrets:s1", ActionStatement::Select, false),
    ] {
        support::parity::assert_postgres(&case, &run, subject, object, statement, allowed);
    }
    assert_agrees(&case, &run);
}

/// The message a panicking case left, so a failure reads like a test failure.
fn panic_message(joined: tokio::task::JoinError) -> String {
    if !joined.is_panic() {
        return joined.to_string();
    }
    let payload = joined.into_panic();
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
        })
        .unwrap_or_else(|| "panicked with no message".to_string())
}

const OWNERSHIP: &str = "
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_delete ON docs FOR DELETE
    USING (owner_id = current_setting('app.user_id', true));
";

const MEMBERSHIP: &str = "
CREATE TABLE projects(id TEXT PRIMARY KEY, name TEXT);
CREATE TABLE project_members(project_id TEXT REFERENCES projects(id), user_id TEXT);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_select ON projects FOR SELECT USING (EXISTS (
    SELECT 1 FROM project_members m
    WHERE m.project_id = projects.id
      AND m.user_id = current_setting('app.user_id', true)));
";

/// Two readers, one of whom owns nothing.
fn ownership_case() -> ParityCase {
    ParityCase::reading(
        "runner-ownership",
        OWNERSHIP,
        &[
            "INSERT INTO docs(id, owner_id, title) VALUES ('d1', 'alice', 'first'),
                                                          ('d2', 'bob', 'second')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT, UPDATE, DELETE ON docs TO alice, bob",
        ],
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("bob", "bob", "app.user_id", "bob"),
        ],
    )
}

async fn the_runner_agrees_on_direct_ownership(cluster: Arc<Cluster>) {
    let case = ownership_case();
    let mismatches = support::parity::run(&cluster, &case).await;
    assert_agrees(&case, &mismatches);
}

async fn the_runner_agrees_on_membership(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-membership",
        MEMBERSHIP,
        &[
            "INSERT INTO projects(id, name) VALUES ('p1', 'one'), ('p2', 'two')",
            "INSERT INTO project_members(project_id, user_id) VALUES ('p1', 'alice')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON projects, project_members TO alice, bob",
        ],
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("bob", "bob", "app.user_id", "bob"),
        ],
    );
    let mismatches = support::parity::run(&cluster, &case).await;
    assert_agrees(&case, &mismatches);
}

/// A RESTRICTIVE policy scoped to a role, which the model expresses by subtracting the
/// role from the grant. The caller's role memberships are declared, since no tuple query
/// can know them.
async fn the_runner_agrees_on_a_role_scoped_restriction(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-role-scoped",
        "
CREATE TABLE notes(id TEXT PRIMARY KEY, owner_id TEXT, reviewed BOOLEAN);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_select ON notes FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY notes_reviewed ON notes AS RESTRICTIVE FOR SELECT TO contractor
    USING (reviewed = TRUE);
",
        &[
            "INSERT INTO notes(id, owner_id, reviewed) VALUES
                ('n1', 'alice', TRUE), ('n2', 'alice', FALSE),
                ('n3', 'carol', TRUE), ('n4', 'carol', FALSE)",
            "CREATE ROLE alice LOGIN; CREATE ROLE carol LOGIN;
             GRANT SELECT ON notes TO alice, carol;
             GRANT contractor TO carol",
        ],
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("carol", "carol", "app.user_id", "carol")
                .holding(&["contractor"]),
        ],
    )
    .after(&["CREATE ROLE contractor"]);
    let mismatches = support::parity::run(&cluster, &case).await;
    assert_agrees(&case, &mismatches);
}

/// Agreement is agreement, whichever way it goes.
///
/// The runner carries no one-sidedness rejection. A hand-written case counted grants and
/// denials because it checked the pairs its author chose; this one checks every pair, so a
/// model that answered everything the same way would be caught by the comparison itself.
async fn both_one_sided_cases_pass(cluster: Arc<Cluster>) {
    let all_granted = ParityCase::reading(
        "runner-all-granted",
        "
CREATE TABLE docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (true);
",
        &[
            "INSERT INTO docs(id) VALUES ('d1'), ('d2')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON docs TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    assert_agrees(
        &all_granted,
        &support::parity::run(&cluster, &all_granted).await,
    );

    let all_denied = ParityCase::reading(
        "runner-all-denied",
        "
CREATE TABLE docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (false);
",
        &[
            "INSERT INTO docs(id) VALUES ('d1'), ('d2')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON docs TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    assert_agrees(
        &all_denied,
        &support::parity::run(&cluster, &all_denied).await,
    );
}

/// A harness that has never caught anything is not yet a harness.
///
/// The statement answers are doctored on their way in, so `can_select` grants with nothing
/// asked. Every row the database hides from a caller then has to be reported.
async fn the_runner_finds_a_planted_divergence(cluster: Arc<Cluster>) {
    let case = ownership_case();
    let mismatches =
        support::parity::run_with(&cluster, &case, support::parity::Class::Exact, |answers| {
            answers
                .into_iter()
                .map(|mut entry| {
                    if entry.statement == ActionStatement::Select {
                        entry.answer = ActionAnswer::Judged(Vec::new());
                    }
                    entry
                })
                .collect()
        })
        .await;

    let over_grants = mismatches
        .mismatches()
        .into_iter()
        .filter(|mismatch| {
            mismatch.statement == ActionStatement::Select && mismatch.openfga && !mismatch.postgres
        })
        .count();
    assert_eq!(
        over_grants, 2,
        "each reader is hidden from one row, so both are over-grants: {mismatches:#?}"
    );
    assert!(
        mismatches
            .mismatches()
            .into_iter()
            .all(|mismatch| mismatch.statement == ActionStatement::Select),
        "only the doctored statement diverges: {mismatches:#?}"
    );
}

/// A no-op `UPDATE` exercises `USING` and never `WITH CHECK`, so the new row is named.
///
/// The policy admits the caller's own rows and its `WITH CHECK` refuses handing a row to
/// somebody else, which only a declared change can reach.
async fn an_update_candidate_exercises_with_check(cluster: Arc<Cluster>) {
    let schema = "
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_update ON docs FOR UPDATE
    USING (owner_id = current_setting('app.user_id', true))
    WITH CHECK (owner_id = current_setting('app.user_id', true));
";
    let seed = [
        "INSERT INTO docs(id, owner_id) VALUES ('d1', 'alice'), ('d2', 'bob')",
        "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
         GRANT SELECT, UPDATE ON docs TO alice, bob",
    ];
    let principals = || {
        vec![
            Principal::with_setting("alice", "alice", "app.user_id", "alice"),
            Principal::with_setting("bob", "bob", "app.user_id", "bob"),
        ]
    };

    // Keeping the owner passes both clauses, so every own row updates.
    let keeps_owner = ParityCase::reading("runner-update-keeps", schema, &seed, principals())
        .writing(
            "docs",
            Mutations {
                // `owner_id = owner_id` leaves the value the policy reads unchanged, so
                // the resulting row decides as the existing one does.
                update_set: Some("owner_id = owner_id".to_string()),
                check_neutral: true,
            },
        );
    let kept = support::parity::run(&cluster, &keeps_owner).await;
    assert_agrees(&keeps_owner, &kept);

    // Handing the row away passes `USING` and fails `WITH CHECK`, so PostgreSQL refuses
    // and no row is updated. The model judges the row the write would produce, which the
    // stored tuples say nothing about, so the runner declines to compare rather than
    // comparing against the row that still exists. Naming that limit here is what stops a
    // later reader believing this direction is covered.
    let gives_away = ParityCase::reading("runner-update-gives", schema, &seed, principals())
        .writing(
            "docs",
            Mutations {
                update_set: Some("owner_id = 'somebody_else'".to_string()),
                check_neutral: false,
            },
        );
    let given = support::parity::run(&cluster, &gives_away).await;
    assert_agrees(&gives_away, &given);
    assert!(
        kept.mismatches().is_empty() && given.mismatches().is_empty(),
        "neither shape may disagree"
    );
}

/// Ported from `quoted_nested_membership_parity_postgres18_and_openfga`.
///
/// A membership subquery whose own nested read is on a protected table: the model cannot
/// prove the nested read, so the shape falls closed, and `PostgreSQL` denies too because
/// the reader sees no row of `"Memberships"`.
async fn a_nested_protected_read_denies_on_both_sides(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-quoted-nested-membership",
        r#"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE memberships(doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE TABLE "Memberships"(doc_id TEXT REFERENCES docs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Memberships" ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM memberships m
    WHERE m.doc_id = docs.id
      AND m.user_id = current_user
      AND EXISTS (
        SELECT 1 FROM "Memberships"
      )
  )
);
"#,
        &[
            r#"INSERT INTO docs(id) VALUES ('d1');
               INSERT INTO memberships(doc_id, user_id) VALUES ('d1', 'app_reader');
               INSERT INTO "Memberships"(doc_id) VALUES ('d1')"#,
            r#"CREATE ROLE app_reader LOGIN;
               GRANT SELECT ON docs, memberships, "Memberships" TO app_reader"#,
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    support::parity::expect_denied(&cluster, &case, "app_reader", "docs:d1").await;
}

/// Ported from `quoted_definer_owner_parity_postgres18_and_openfga`.
///
/// `actor` and `"Actor"` are different roles, so the function's owner is not the table's
/// and the definer read does not bypass row-level security.
async fn a_split_function_owner_does_not_bypass_row_level_security(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-quoted-definer-owner",
        r#"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(id TEXT PRIMARY KEY, doc_id TEXT REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members OWNER TO actor;
GRANT SELECT ON doc_members TO "Actor";
CREATE FUNCTION is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
SET search_path TO public, pg_temp AS
'SELECT EXISTS (
    SELECT 1 FROM doc_members m
    WHERE m.doc_id = d
      AND m.user_id = current_setting(''app.current_user_id'', true)
)';
ALTER FUNCTION is_member(TEXT) OWNER TO "Actor";
CREATE POLICY docs_members ON docs FOR SELECT USING (is_member(id));
"#,
        &[
            "INSERT INTO docs(id) VALUES ('d1');
             INSERT INTO doc_members(id, doc_id, user_id) VALUES ('dm1', 'd1', 'app_reader')",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader",
        ],
        vec![Principal::with_setting(
            "app_reader",
            "app_reader",
            "app.current_user_id",
            "app_reader",
        )],
    )
    .after(&[r#"CREATE ROLE actor; CREATE ROLE "Actor""#]);
    support::parity::expect_denied(&cluster, &case, "app_reader", "docs:d1").await;
}

/// Ported from `strict_function_null_parity_postgres18_and_openfga`.
///
/// A `STRICT` function returns NULL for a NULL argument, so the row with no gate value
/// is hidden however the body reads.
async fn a_strict_function_hides_the_null_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-strict-function-null",
        "
CREATE TABLE docs(id TEXT PRIMARY KEY, gate TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION strict_true(value TEXT) RETURNS BOOLEAN LANGUAGE sql STRICT AS
'SELECT true';
CREATE POLICY docs_select ON docs FOR SELECT USING (strict_true(gate));
",
        &[
            "INSERT INTO docs(id, gate) VALUES ('d-null', NULL), ('d-value', 'present')",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (row, visible) in [("d-null", false), ("d-value", true)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_reader",
            &format!("docs:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `reserved_type_name_parity_postgres18_and_openfga`.
///
/// Two tables whose canonical names differ and whose reserved-word rename collides. A
/// shared type would name a row of each as one object, which the runner sees because it
/// asks both readers about both tables.
async fn a_reserved_name_collision_keeps_two_types(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-reserved-type-name",
        r#"
CREATE TABLE "self"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE t_self(id TEXT PRIMARY KEY, editor_id TEXT);
ALTER TABLE "self" ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_self ENABLE ROW LEVEL SECURITY;
CREATE POLICY a ON "self" FOR SELECT USING (owner_id = current_user);
CREATE POLICY b ON t_self FOR SELECT USING (editor_id = current_user);
"#,
        &[
            r#"INSERT INTO "self"(id, owner_id) VALUES ('shared', 'alice');
               INSERT INTO t_self(id, editor_id) VALUES ('shared', 'bob')"#,
            r#"CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
               GRANT SELECT ON "self", t_self TO alice, bob"#,
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    assert_agrees(&case, &run);
    // One key value in two tables, so a shared type shows up as a grant the database
    // denies. Four pairs, one granted each way.
    assert_eq!(
        run.observations
            .iter()
            .filter(
                |observation| observation.statement == ActionStatement::Select
                    && observation.postgres
            )
            .count(),
        2,
        "each reader owns exactly one of the two rows: {run:#?}"
    );
}

/// Ported from `reserved_parent_type_parity_postgres18_and_openfga`.
///
/// A parent whose name `OpenFGA` reserves, reached through a child's membership policy.
async fn a_reserved_parent_is_referenced_by_its_defined_name(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-reserved-parent-type",
        r#"
CREATE TABLE "self"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE child_docs(id TEXT PRIMARY KEY, parent_id TEXT REFERENCES "self"(id));
ALTER TABLE "self" ENABLE ROW LEVEL SECURITY;
ALTER TABLE child_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_owner ON "self" FOR SELECT USING (owner_id = current_user);
CREATE POLICY inherit ON child_docs FOR SELECT USING (EXISTS (
    SELECT 1 FROM "self" p WHERE p.id = child_docs.parent_id AND p.owner_id = current_user));
"#,
        &[
            r#"INSERT INTO "self"(id, owner_id) VALUES ('p1', 'alice');
               INSERT INTO child_docs(id, parent_id) VALUES ('c1', 'p1')"#,
            r#"CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
               GRANT SELECT ON "self", child_docs TO alice, bob"#,
        ],
        vec![
            Principal::as_role("alice", "alice"),
            Principal::as_role("bob", "bob"),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, visible) in [("alice", true), ("bob", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            "child_docs:c1",
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// A caller identified by the ordinary session setting.
fn app_reader() -> Vec<Principal> {
    vec![Principal::with_setting(
        "app_reader",
        "app_reader",
        "app.current_user_id",
        "app_reader",
    )]
}

/// A caller identified by `app.current_user_id`, logged in as `login`.
fn setting_reader(subject: &str, login: &str) -> Principal {
    Principal::with_setting(subject, login, "app.current_user_id", subject)
}

/// Ported from `qualified_registry_identity_parity_postgres18_and_openfga`.
///
/// `other.uid()` is not the accessor the registry names, so the policy is not an
/// ownership check and the shape falls closed.
async fn a_qualified_call_is_not_the_declared_accessor(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-qualified-registry-identity",
        r"
CREATE SCHEMA auth;
CREATE SCHEMA other;
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION auth.uid() RETURNS TEXT LANGUAGE sql AS
    'SELECT current_setting(''app.current_user_id'', true)';
CREATE FUNCTION other.uid() RETURNS TEXT LANGUAGE sql AS
    'SELECT ''nobody''';
CREATE POLICY docs_select ON docs FOR SELECT USING (owner_id = other.uid());
",
        &[
            "INSERT INTO docs(id, owner_id) VALUES ('d1', 'app_reader')",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON docs TO app_reader",
        ],
        app_reader(),
    )
    .with_registry(r#"{"auth.uid": {"kind": "current_user_accessor", "returns": "text"}}"#);
    support::parity::expect_denied(&cluster, &case, "app_reader", "docs:d1").await;
}

/// Ported from `function_local_search_path_parity_postgres18_and_openfga`.
///
/// The function sets its own `search_path`, so the membership table it reads is the one
/// that path names, not the caller's.
async fn a_function_local_search_path_picks_the_membership_table(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-function-local-search-path",
        r"
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE a.doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES public.docs(id),
    user_id TEXT NOT NULL
);
CREATE TABLE b.doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES public.docs(id),
    user_id TEXT NOT NULL
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO b, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_select ON docs FOR SELECT USING (public.is_member(id));
SET search_path TO a, public;
",
        &[
            "INSERT INTO public.docs(id) VALUES ('d1');
             INSERT INTO b.doc_members(id, doc_id, user_id) VALUES ('m1', 'd1', 'app_reader')",
            "CREATE ROLE app_reader LOGIN;
             GRANT USAGE ON SCHEMA b TO app_reader;
             GRANT SELECT ON docs, b.doc_members TO app_reader",
        ],
        app_reader(),
    );
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "docs:d1",
        ActionStatement::Select,
        true,
    );
    assert_agrees(&case, &run);
}

/// Ported from `resolved_membership_table_parity_postgres18_and_openfga`.
///
/// Two schemas hold a table of the same name and the policy names it unqualified, which
/// the catalog cannot place, so nothing is granted on a guess.
async fn an_unplaceable_membership_table_grants_nothing(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-resolved-membership-table",
        r"
CREATE SCHEMA app;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
CREATE TABLE app.memberships(doc_id TEXT NOT NULL, user_id TEXT NOT NULL);
CREATE TABLE public.memberships(doc_id TEXT NOT NULL, user_id TEXT NOT NULL);
CREATE ROLE app_reader LOGIN;
GRANT USAGE ON SCHEMA app TO app_reader;
GRANT SELECT ON public.docs, app.memberships, public.memberships TO app_reader;
SET search_path TO app, public;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON public.docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM memberships m
        WHERE m.doc_id = docs.id
          AND m.user_id = current_setting('app.current_user_id', true)));
INSERT INTO public.docs VALUES ('d1');
INSERT INTO app.memberships VALUES ('d1', 'other_user');
INSERT INTO public.memberships VALUES ('d1', 'app_reader');
",
        &[],
        app_reader(),
    );
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "app_reader",
        "docs:d1",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `restrictive_flag_pair_parity_postgres18_and_openfga`.
///
/// A blanket permissive read beside a RESTRICTIVE flag: only the flagged row is visible,
/// which the model can only express with a relation per predicate.
async fn a_restrictive_flag_narrows_a_blanket_read(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-restrictive-flag-pair",
        r"
CREATE TABLE union_docs(id TEXT PRIMARY KEY, is_public BOOLEAN NOT NULL);
ALTER TABLE union_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON union_docs FOR SELECT USING (true);
CREATE POLICY r ON union_docs AS RESTRICTIVE FOR SELECT USING (is_public);
",
        &[
            "INSERT INTO union_docs(id, is_public) VALUES ('p1', TRUE), ('h1', FALSE)",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON union_docs TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (row, visible) in [("p1", true), ("h1", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_reader",
            &format!("union_docs:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `cross_command_wildcard_parity_postgres18_and_openfga`.
///
/// A blanket DELETE beside a flag-gated SELECT: the wildcard the DELETE needs must not
/// widen the read.
async fn a_blanket_delete_does_not_widen_the_read(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-cross-command-wildcard",
        r"
CREATE TABLE union_docs(id TEXT PRIMARY KEY, is_public BOOLEAN NOT NULL);
ALTER TABLE union_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY s ON union_docs FOR SELECT USING (is_public);
CREATE POLICY d ON union_docs FOR DELETE USING (true);
",
        &[
            "INSERT INTO union_docs(id, is_public) VALUES ('p1', TRUE), ('h1', FALSE)",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT, DELETE ON union_docs TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (row, visible) in [("p1", true), ("h1", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_reader",
            &format!("union_docs:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `qualified_clock_shadow_parity_postgres18_and_openfga`.
///
/// `app.now()` is a declared function, not the builtin clock, so a temporal condition
/// against the request clock would answer a different question.
async fn a_shadowed_clock_is_not_the_request_clock(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-qualified-clock-shadow",
        "
CREATE SCHEMA app;
CREATE FUNCTION app.now() RETURNS TIMESTAMPTZ LANGUAGE sql IMMUTABLE
    AS $$SELECT 'infinity'::timestamptz$$;
CREATE TABLE docs (id INT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (expires_at > app.now());
",
        &[
            "INSERT INTO docs (id, expires_at) VALUES (1, now() + interval '1 year')",
            "CREATE ROLE alice LOGIN;
             GRANT USAGE ON SCHEMA app TO alice;
             GRANT SELECT ON docs TO alice",
        ],
        vec![Principal::as_role("alice", "alice").with_clock()],
    );
    support::parity::expect_denied(&cluster, &case, "alice", "docs:1").await;
}

/// Two readers of one fixture, told apart by the setting alone.
fn two_setting_readers(first: &str, second: &str) -> Vec<Principal> {
    vec![
        Principal::with_setting(first, "app_user", "app.current_user_id", first),
        Principal::with_setting(second, "app_user", "app.current_user_id", second),
    ]
}

/// Rows two owners hold, and the role that may read them.
const OWNED_NOTES_SEED: &str = "INSERT INTO users(id) VALUES ('alice'), ('bob');
     INSERT INTO notes(id, owner_id) VALUES ('note-alice', 'alice'), ('note-bob', 'bob')";

/// Ported from `absent_clause_parity_postgres18_and_openfga`.
///
/// An `UPDATE` policy storing only `WITH CHECK` says nothing about the existing row, so
/// no row is updatable however the check reads.
async fn an_update_policy_without_using_updates_nothing(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-clause-absent",
        "clause_absent",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .writing(
        "notes",
        Mutations {
            update_set: Some("owner_id = owner_id".to_string()),
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:note-alice",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:note-alice",
        ActionStatement::Update,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `locking_read_parity_postgres18_and_openfga`.
///
/// A locking read is filtered by the `UPDATE` policies' `USING` clause on top of the
/// `SELECT` policies, so it returns fewer rows than a plain read.
async fn a_locking_read_applies_the_update_policy(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-locking-read",
        "locking_read",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
    // Every row reads, only the caller's own row locks.
    for (row, plain, locking) in [("note-alice", true, true), ("note-bob", true, false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            plain,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::SelectForUpdate,
            locking,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `altered_policy_parity_postgres18_and_openfga`.
///
/// `ALTER POLICY` supersedes the clause the policy was created with, so the rule enforced
/// is the narrowed one and never the original.
async fn an_altered_policy_is_read_as_altered(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-policy-altered",
        "policy_altered",
        &[
            OWNED_NOTES_SEED,
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
    // The original clause admitted everything; the altered one admits the owner alone.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:note-bob",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `folded_identifier_parity_postgres18_and_openfga`.
///
/// `PostgreSQL` folds an unquoted identifier, so the schema's spelling is not the stored
/// name, and every comparison has to use the stored one.
async fn folded_identifiers_name_one_table(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-folded-identifiers",
        "folded_identifiers",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id) VALUES ('own', 'alice'), ('shared', 'bob');
             INSERT INTO note_members(id, note_id, user_id) VALUES ('m1', 'shared', 'alice')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON notes, note_members TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
    // Alice owns one row and is a member of the other, so both read for her.
    for row in ["own", "shared"] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            true,
        );
    }
    support::parity::assert_postgres(
        &case,
        &run,
        "bob",
        "notes:own",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `two_owner_columns_parity_postgres18_and_openfga`.
///
/// One table judged through two owner values with different thresholds, so a delegate
/// needs a higher role than an owner to read the same row.
async fn two_owner_columns_grant_independently(cluster: Arc<Cluster>) {
    const ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
    const BOB: &str = "00000000-0000-0000-0000-0000000000a2";
    const CAROL: &str = "00000000-0000-0000-0000-0000000000a3";
    const RECORD: &str = "00000000-0000-0000-0000-00000000ee01";

    let case = ParityCase::from_fixture(
        "runner-two-owner-columns",
        "two_owner_columns",
        &[
            &format!(
                "INSERT INTO users(id) VALUES ('{ALICE}'), ('{BOB}'), ('{CAROL}');
                 INSERT INTO records(id, owner_id, delegate_id)
                     VALUES ('{RECORD}', '{ALICE}', '{BOB}');
                 INSERT INTO owner_grants(grantee_owner_id, granted_owner_id, role_id)
                     VALUES ('{CAROL}', '{BOB}', 2)"
            ),
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON records, users, owner_grants TO app_user",
        ],
        vec![
            Principal::with_setting(ALICE, "app_user", "app.current_user_id", ALICE),
            Principal::with_setting(BOB, "app_user", "app.current_user_id", BOB),
            Principal::with_setting(CAROL, "app_user", "app.current_user_id", CAROL),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    // The owner reads at 2, the delegate itself reads at 4, and a viewer of the delegate
    // holds only 2, which the delegate pointer does not admit.
    for (subject, visible) in [(ALICE, true), (BOB, true), (CAROL, false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("records:{RECORD}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// The accessor these inline schemas declare.
const ACCESSOR: &str =
    r#"{"auth_current_user_id": {"kind":"current_user_accessor","returns":"text"}}"#;

/// Ported from `uncorrelated_membership_parity_postgres18_and_openfga`.
///
/// A membership check naming no column of the guarded table admits every row, and two
/// membership rows for one member are one fact, not two.
#[allow(clippy::too_many_lines)]
async fn an_uncorrelated_membership_admits_every_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-uncorrelated-membership",
        "
CREATE TABLE staff (id TEXT PRIMARY KEY, user_id TEXT NOT NULL);
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_staff ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = auth_current_user_id()));
",
        &[
            // Two rows for one member, so a holder written per membership row rather than
            // per member shows up as a duplicate.
            "INSERT INTO staff(id, user_id) VALUES ('s-1', 'alice'), ('s-2', 'alice');
             INSERT INTO docs(id) VALUES ('d-1'), ('d-2'), ('d-3')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON docs, staff TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for row in ["d-1", "d-2", "d-3"] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("docs:{row}"),
            ActionStatement::Select,
            true,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            "bob",
            &format!("docs:{row}"),
            ActionStatement::Select,
            false,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `parent_key_in_subquery_parity_postgres18_and_openfga`.
///
/// `parent_id IN (SELECT id FROM parent_docs WHERE ...)` is the parent's own rule reached
/// through the key, so the child inherits it.
async fn a_parent_key_subquery_inherits_the_parents_rule(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-parent-key-in-subquery",
        "
CREATE TABLE parent_docs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
CREATE TABLE doc_links (
    id TEXT PRIMARY KEY,
    parent_id TEXT NOT NULL REFERENCES parent_docs(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE parent_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_docs_owner ON parent_docs FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY doc_links_visible ON doc_links FOR SELECT
    USING (parent_id IN (SELECT id FROM parent_docs WHERE owner_id = auth_current_user_id()));
",
        &[
            "INSERT INTO parent_docs(id, owner_id) VALUES ('p-alice', 'alice'), ('p-bob', 'bob');
             INSERT INTO doc_links(id, parent_id)
                 VALUES ('l-alice', 'p-alice'), ('l-bob', 'p-bob')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON parent_docs, doc_links TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, own, other) in [("alice", "l-alice", "l-bob"), ("bob", "l-bob", "l-alice")] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("doc_links:{own}"),
            ActionStatement::Select,
            true,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("doc_links:{other}"),
            ActionStatement::Select,
            false,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `correlated_column_membership_parity_postgres18_and_openfga`.
///
/// The subquery projects `status` and the outer column is `sku`, so the comparison is not
/// the one a key-shaped read would make.
async fn a_correlated_column_membership_compares_the_named_columns(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-correlated-column-membership",
        "
CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE line_items (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id),
    sku TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY line_items_visible ON line_items FOR SELECT
    USING (sku IN (SELECT status FROM orders WHERE customer_id = auth_current_user_id()));
",
        &[
            // Each caller owns one order status, and each line item carries the other
            // caller's status in its own `status` column.
            "INSERT INTO orders(id, customer_id, status) VALUES
                 ('o-alice', 'alice', 'WIDGET'), ('o-bob', 'bob', 'GADGET');
             INSERT INTO line_items(id, order_id, sku, status) VALUES
                 ('li-alice', 'o-alice', 'WIDGET', 'GADGET'),
                 ('li-bob', 'o-bob', 'GADGET', 'WIDGET')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON orders, line_items TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "line_items:li-alice",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "line_items:li-bob",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `blanket_update_parity_postgres18_and_openfga`.
///
/// The read and the write are judged by different columns, so a row readable to one
/// caller is writable to another.
async fn a_read_and_a_write_are_judged_separately(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-blanket-update",
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    reader_user_id TEXT NOT NULL REFERENCES users(id),
    writer_user_id TEXT NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (reader_user_id = auth_current_user_id());
CREATE POLICY notes_write ON notes FOR UPDATE USING (writer_user_id = auth_current_user_id());
",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, reader_user_id, writer_user_id, body) VALUES
                 ('bu-both', 'alice', 'alice', 'original'),
                 ('bu-write-only', 'bob', 'alice', 'original'),
                 ('bu-read-only', 'alice', 'bob', 'original'),
                 ('bu-neither', 'bob', 'bob', 'original')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT, UPDATE ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR)
    .writing(
        "notes",
        Mutations {
            // `body` is read by no policy, so the resulting row decides as the
            // existing one does.
            update_set: Some("body = 'changed'".to_string()),
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    // A `WHERE` reads the row, so an `UPDATE` naming rows needs the read as well as the
    // write, which is why the row the caller may write but not read updates nothing. The
    // blanket form, which the original case asserted from its seed rather than measuring,
    // is not compared: see `COMPARED` in the runner for why it cannot be.
    for (row, readable, writable) in [
        ("bu-both", true, true),
        ("bu-write-only", false, false),
        ("bu-read-only", true, false),
        ("bu-neither", false, false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            readable,
        );
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Update,
            writable,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `aliased_quoted_guard_parity_postgres18_and_openfga`.
///
/// The guard reads the outer table's own column through its quoted name, which is not a
/// membership condition, so the shape falls closed.
async fn an_aliased_quoted_guard_falls_closed(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-aliased-quoted-guard",
        r#"
CREATE TABLE "M"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE members(doc_id TEXT REFERENCES "M"(id), owner_id TEXT);
ALTER TABLE "M" ENABLE ROW LEVEL SECURITY;
CREATE POLICY m_owner ON "M" FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM members m
    WHERE m.doc_id = "M".id
      AND "M".owner_id = current_user
  )
);
"#,
        &[
            r#"INSERT INTO "M"(id, owner_id) VALUES ('d1', 'other_owner');
               INSERT INTO members(doc_id, owner_id) VALUES ('d1', 'app_reader')"#,
            r#"CREATE ROLE app_reader LOGIN; GRANT SELECT ON "M", members TO app_reader"#,
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    support::parity::expect_denied(&cluster, &case, "app_reader", "m:d1").await;
}

/// Ported from `read_recursion_parity_postgres18_and_openfga`.
///
/// Two policies each reading the other: `PostgreSQL` raises `42P17` on every read of
/// either, so no row is returned and the model must grant nothing.
async fn mutually_recursive_policies_return_no_row(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-read-recursion",
        "read_recursion",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO folders(id, owner_id) VALUES ('f-alice', 'alice'), ('f-bob', 'bob');
             INSERT INTO notes(id, owner_id, folder_id) VALUES
                 ('n-alice', 'alice', 'f-alice'), ('n-bob', 'bob', 'f-bob');
             UPDATE folders SET note_id = 'n-alice' WHERE id = 'f-alice';
             UPDATE folders SET note_id = 'n-bob' WHERE id = 'f-bob'",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON users, notes, folders TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
    // Every read raises, so the database returns nothing to anybody.
    for subject in ["alice", "bob"] {
        for object in ["notes:n-alice", "folders:f-alice"] {
            support::parity::assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                false,
            );
        }
    }
    assert_agrees(&case, &run);
}

/// Ported from `partitioned_table_parity_postgres18_and_openfga`.
///
/// A partition has no type of its own: its rows are named as objects of the root, so a
/// read through either the root or a partition asks the same question.
async fn a_partition_is_named_after_its_root(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-partitioned-table",
        "
CREATE TABLE events (id TEXT, tenant TEXT NOT NULL, region TEXT NOT NULL, PRIMARY KEY (id, region))
    PARTITION BY LIST (region);
CREATE TABLE events_eu PARTITION OF events FOR VALUES IN ('eu');
CREATE TABLE events_us PARTITION OF events FOR VALUES IN ('us');
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY events_visible ON events FOR SELECT USING (tenant = auth_current_user_id());
",
        &[
            "INSERT INTO events(id, tenant, region) VALUES
                 ('e-eu', 'alice', 'eu'), ('e-us', 'bob', 'us')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON events, events_eu, events_us TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR)
    // Reading a partition directly is unfiltered, since a parent's policies apply only to
    // rows reached through the parent. The runner found that, and the translation now
    // discloses it through `PartitionReadDirectlyIsUnfiltered`, pinned offline by
    // `a_partition_of_a_protected_root_discloses_its_direct_read`.
    .not_reading_directly(&["events_eu", "events_us"]);
    let run = support::parity::run(&cluster, &case).await;
    // The key is composite, so the object carries both parts.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "events:e-eu|eu",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "bob",
        "events:e-eu|eu",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `composite_fk_membership_parity_postgres18_and_openfga`.
///
/// The membership row is joined on two columns, so the bridge has to carry both or it
/// admits a row of another tenant.
async fn a_composite_foreign_key_membership_joins_on_both_columns(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-composite-fk-membership",
        "
CREATE TABLE projects (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE docs (
    doc_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE TABLE project_members (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, project_id, user_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_visible ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM project_members m
        WHERE m.tenant_id = docs.tenant_id
          AND m.project_id = docs.project_id
          AND m.user_id = auth_current_user_id()));
",
        &[
            // One project id in two tenants, so a bridge on the project alone would admit
            // the other tenant's document.
            "INSERT INTO projects(tenant_id, id) VALUES ('t1', 'p1'), ('t2', 'p1');
             INSERT INTO docs(doc_id, tenant_id, project_id) VALUES
                 ('d-t1', 't1', 'p1'), ('d-t2', 't2', 'p1');
             INSERT INTO project_members(tenant_id, project_id, user_id) VALUES
                 ('t1', 'p1', 'alice')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON projects, docs, project_members TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "docs:d-t1",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "docs:d-t2",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `joined_inner_rule_parity_postgres18_and_openfga`.
///
/// The inner rule joins two tables, and the join drops an order with no customer, so a
/// bridge built from the key alone would admit it.
async fn a_joined_inner_rule_drops_the_unjoined_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-joined-inner-rule",
        "
CREATE TABLE customers (id TEXT PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT REFERENCES customers(id));
CREATE TABLE line_items (id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY line_items_visible ON line_items FOR SELECT
    USING (order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id
                        WHERE c.id = auth_current_user_id()));
",
        &[
            "INSERT INTO customers(id, org_id) VALUES ('alice', 'acme'), ('bob', 'acme');
             INSERT INTO orders(id, customer_id) VALUES
                 ('o-alice', 'alice'), ('o-bob', 'bob'), ('o-none', NULL);
             INSERT INTO line_items(id, order_id) VALUES
                 ('li-alice', 'o-alice'), ('li-bob', 'o-bob'), ('li-none', 'o-none')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON customers, orders, line_items TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for (row, visible) in [("li-alice", true), ("li-bob", false), ("li-none", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("line_items:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `quoted_role_identity_parity_postgres18_and_openfga`.
///
/// `admin` and `"Admin"` are different roles, so a policy scoped to one admits nothing
/// through the other, and two policies of one name on two tables stay apart.
async fn a_quoted_role_is_a_different_role(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-quoted-role-identity",
        r#"
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE memos (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO admin USING (TRUE);
CREATE POLICY p ON memos FOR SELECT TO "Admin" USING (TRUE);
"#,
        &[
            "INSERT INTO docs (id) VALUES ('d1'); INSERT INTO memos (id) VALUES ('m1')",
            "CREATE ROLE alice LOGIN;
             GRANT SELECT ON docs, memos TO alice;
             GRANT admin TO alice",
        ],
        vec![Principal::as_role("alice", "alice").holding(&["admin"])],
    )
    .after(&[r#"CREATE ROLE admin; CREATE ROLE "Admin""#]);
    let run = support::parity::run(&cluster, &case).await;
    // The policy on `memos` names the quoted role, which alice does not hold.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "docs:d1",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "memos:m1",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `session_attribute_parity_postgres18_and_openfga`.
///
/// One policy unioning the caller's own id with the set of keys it holds. A caller holding
/// no key leaves the setting unset, so the second arm is NULL rather than true.
async fn a_declared_session_set_grants_beside_the_owner(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-session-attribute",
        "connetto_or_policy",
        &[
            "INSERT INTO notes (id, owner) VALUES
                 (1, 'alice'), (2, 'team-a'), (3, 'bob'), (4, NULL)",
            "CREATE ROLE app_writer LOGIN; GRANT SELECT ON notes TO app_writer",
        ],
        vec![
            // The owner arm alone, the set arm alone, and both together.
            user_holder("alice", "app_writer", &[]),
            user_holder("bob", "app_writer", &["team-a"]),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    // Row 1 reads through the owner arm, row 2 through the set arm, row 4 through neither.
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:1",
        ActionStatement::Select,
        true,
    );
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:2",
        ActionStatement::Select,
        false,
    );
    support::parity::assert_postgres(&case, &run, "bob", "notes:2", ActionStatement::Select, true);
    support::parity::assert_postgres(
        &case,
        &run,
        "bob",
        "notes:4",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&case, &run);
}

/// Ported from `array_and_jsonb_membership_parity_postgres18_and_openfga`.
///
/// The caller as an element of an array column, and the caller named by a jsonb field.
/// An empty or NULL array admits nobody, and those rows stay readable only because the
/// jsonb arm still names the caller.
async fn an_array_and_a_jsonb_field_name_the_caller(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-array-jsonb-membership",
        "array_jsonb_membership",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, editors, meta) VALUES
                 ('aj-editor-only', ARRAY['alice'], '{\"owner_id\":\"bob\"}'),
                 ('aj-meta-only', ARRAY['bob'], '{\"owner_id\":\"alice\"}'),
                 ('aj-both', ARRAY['alice'], '{\"owner_id\":\"alice\"}'),
                 ('aj-neither', ARRAY['bob'], '{\"owner_id\":\"bob\"}'),
                 ('aj-empty-array', ARRAY[]::TEXT[], '{\"owner_id\":\"alice\"}'),
                 ('aj-null-array', NULL, '{\"owner_id\":\"alice\"}'),
                 ('aj-null-element', ARRAY[NULL]::TEXT[], '{}'),
                 ('aj-missing-key', ARRAY['alice'], '{}')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON notes TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    );
    let run = support::parity::run(&cluster, &case).await;
    for (row, visible) in [
        ("aj-editor-only", true),
        ("aj-meta-only", true),
        ("aj-both", true),
        ("aj-neither", false),
        // The array arm admits nobody here, the jsonb arm carries both rows.
        ("aj-empty-array", true),
        ("aj-null-array", true),
        ("aj-null-element", false),
        ("aj-missing-key", true),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "alice",
            &format!("notes:{row}"),
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `zoneless_temporal_guard_parity_postgres18_and_openfga`.
///
/// A guard against the clock on a zoned column and on a date, where the comparison
/// promotes the date to a timestamp in the session's zone.
async fn a_clock_guard_holds_on_a_zoned_and_a_dated_column(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-zoneless-temporal-guard",
        "
CREATE TABLE zoned_docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
CREATE TABLE dated_docs (id TEXT PRIMARY KEY, expires_on DATE);
ALTER TABLE zoned_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE dated_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zoned_unexpired ON zoned_docs FOR SELECT USING (expires_at > now());
CREATE POLICY dated_unexpired ON dated_docs FOR SELECT USING (expires_on > now());
",
        &[
            "INSERT INTO zoned_docs (id, expires_at) VALUES
                 ('z-live', TIMESTAMPTZ '2099-01-01 00:00:00+00'),
                 ('z-stale', TIMESTAMPTZ '2000-01-01 00:00:00+00');
             INSERT INTO dated_docs (id, expires_on) VALUES
                 ('d-live', DATE '2099-01-01'),
                 ('d-stale', DATE '2000-01-01')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON zoned_docs, dated_docs TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    );
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (object, visible) in [
        ("zoned_docs:z-live", true),
        ("zoned_docs:z-stale", false),
        ("dated_docs:d-live", true),
        ("dated_docs:d-stale", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    // The dated guard alone diverges: no tuple can carry a value the row does not decide,
    // so the live dated row is denied. The zoned guard has to keep its conditional tuples,
    // which losing them all would also satisfy under a bare no-over-grant check.
    support::parity::assert_only_disagreements(
        &case,
        &run,
        &[("app_user", "dated_docs:d-live", ActionStatement::Select)],
    );
}

/// Ported from `cross_row_residual_parity_postgres18_and_openfga`.
///
/// A share grants only when its weight beats the average across the whole share table,
/// which rows the granted row does not name decide.
async fn a_cross_row_residual_is_decided_by_rows_the_grant_does_not_name(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-cross-row-residual",
        "cross_row_residual",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'owner'), (2, 'owner'), (3, 'owner');
             INSERT INTO paper_shares (paper_id, viewer, weight) VALUES
                 (1, 'alice', 50), (2, 'bob', 30), (3, 'alice', 1)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![
            Principal::with_setting("alice", "app_reader", "app.user_id", "alice"),
            Principal::with_setting("bob", "app_reader", "app.user_id", "bob"),
            Principal::with_setting("carol", "app_reader", "app.user_id", "carol"),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    // The average of 50, 30 and 1 is 27, so only the first two shares beat it.
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        ("alice", "papers:3", false),
        ("bob", "papers:2", true),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `composite_key_self_membership_parity_postgres18_and_openfga`.
///
/// The share is keyed on the tenant as well as the paper, so a bridge on the paper alone
/// would hand one tenant's reader the other tenant's paper of the same id.
async fn a_composite_key_share_stays_within_its_tenant(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-composite-key-self-membership",
        "
CREATE TABLE tenant_papers (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    title TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE tenant_shares (
    tenant_id TEXT NOT NULL,
    paper_id TEXT NOT NULL,
    viewer TEXT NOT NULL,
    PRIMARY KEY (tenant_id, paper_id, viewer)
);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE tenant_papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_visible ON tenant_papers FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM tenant_shares s
        WHERE s.tenant_id = tenant_papers.tenant_id
          AND s.paper_id = tenant_papers.id
          AND s.viewer = auth_current_user_id()));
",
        &[
            // One paper id in both tenants, plus one unshared paper.
            "INSERT INTO tenant_papers(tenant_id, id, title) VALUES
                 ('t1', 'p-shared', 'alpha'), ('t2', 'p-shared', 'beta'),
                 ('t1', 'p-solo', 'gamma');
             INSERT INTO tenant_shares(tenant_id, paper_id, viewer) VALUES
                 ('t1', 'p-shared', 'alice'), ('t2', 'p-shared', 'bob')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT ON tenant_papers, tenant_shares TO app_user",
        ],
        two_setting_readers("alice", "bob"),
    )
    .with_registry(ACCESSOR);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "tenant_papers:t1|p-shared", true),
        ("alice", "tenant_papers:t2|p-shared", false),
        ("bob", "tenant_papers:t2|p-shared", true),
        ("bob", "tenant_papers:t1|p-shared", false),
        ("alice", "tenant_papers:t1|p-solo", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `caller_role_residual_parity_postgres18_and_openfga`.
///
/// The residual asks whether the caller holds the role the membership row names. The
/// runner reads rows as the owning superuser, for whom `pg_has_role` is true of every
/// role, so a translation deciding that residual while loading would grant the row to a
/// caller the database denies it to.
async fn a_caller_role_residual_falls_closed(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-caller-role-residual",
        r"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(doc_id TEXT REFERENCES docs(id), user_id TEXT, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM doc_members m
    WHERE m.doc_id = docs.id
      AND m.user_id = current_user
      AND pg_has_role(m.tenant, 'USAGE')
  )
);
",
        &[
            "INSERT INTO docs(id) VALUES ('d1');
             INSERT INTO doc_members(doc_id, user_id, tenant)
                 VALUES ('d1', 'app_reader', 'tenant_a')",
            // The caller is deliberately not granted `tenant_a`.
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON docs, doc_members TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    )
    .after(&["CREATE ROLE tenant_a"]);
    support::parity::expect_denied(&cluster, &case, "app_reader", "docs:d1").await;
}

/// Ported from `computed_argument_capture_parity_postgres18_and_openfga`.
///
/// A computed call argument is evaluated in the caller's scope, so a bare column inside it
/// must reach the body qualified or the body's own scan captures it.
async fn a_computed_argument_is_not_captured_by_the_body(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-computed-argument-capture",
        r"
CREATE TABLE leveled_docs(id TEXT PRIMARY KEY, level INT NOT NULL);
CREATE TABLE leveled_members(doc_id TEXT REFERENCES leveled_docs(id), user_id TEXT,
  level INT NOT NULL, min_level INT NOT NULL);
ALTER TABLE leveled_docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION can_see(d TEXT, req INT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM leveled_members m WHERE m.doc_id = d AND m.user_id = current_user AND m.min_level <= req)';
CREATE POLICY p ON leveled_docs FOR SELECT USING (can_see(id, coalesce(level, 0)));
",
        &[
            // The poisoning row: the member's own `level` is high and `min_level` sits
            // between the two, so a captured reading admits what the row's level denies.
            "INSERT INTO leveled_docs(id, level) VALUES ('d1', 0);
             INSERT INTO leveled_members(doc_id, user_id, level, min_level)
                 VALUES ('d1', 'app_reader', 99, 50)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON leveled_docs, leveled_members TO app_reader",
        ],
        vec![Principal::as_role("app_reader", "app_reader")],
    );
    // `min_level` 50 against the row's level 0, so the database denies.
    support::parity::expect_denied(&cluster, &case, "app_reader", "leveled_docs:d1").await;
}

/// A case that fails must still drop its database and roles.
///
/// Roles are cluster-wide, so a case that kept its database left grants the next case's
/// reset could not drop, and one failure failed every later case. The planted case fails
/// on its last seed, after creating the role the successor reuses.
async fn a_failed_case_leaves_no_role_behind(cluster: Arc<Cluster>) {
    let planted = || {
        ParityCase::reading(
            "runner-planted-panic",
            "CREATE TABLE only_docs(id TEXT PRIMARY KEY);
             ALTER TABLE only_docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON only_docs FOR SELECT USING (id = current_user);",
            &[
                "CREATE ROLE reused_reader LOGIN; GRANT SELECT ON only_docs TO reused_reader",
                "INSERT INTO absent_table(id) VALUES ('x')",
            ],
            vec![Principal::as_role("reused_reader", "reused_reader")],
        )
    };
    let shared = Arc::clone(&cluster);
    let planted_case = planted();
    let failure = tokio::spawn(async move {
        support::parity::run(&shared, &planted_case).await;
    })
    .await;
    assert!(
        failure.is_err(),
        "the planted case has to fail, or it pins nothing"
    );

    // Same role name, so it can only be created if the failed case's cleanup ran.
    let successor = ParityCase::reading(
        "runner-planted-panic-successor",
        "CREATE TABLE only_docs(id TEXT PRIMARY KEY);
         ALTER TABLE only_docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON only_docs FOR SELECT USING (id = current_user);",
        &[
            "INSERT INTO only_docs(id) VALUES ('reused_reader'), ('someone_else')",
            "CREATE ROLE reused_reader LOGIN; GRANT SELECT ON only_docs TO reused_reader",
        ],
        vec![Principal::as_role("reused_reader", "reused_reader")],
    );
    let run = support::parity::run(&cluster, &successor).await;
    support::parity::assert_postgres(
        &successor,
        &run,
        "reused_reader",
        "only_docs:reused_reader",
        ActionStatement::Select,
        true,
    );
    assert_agrees(&successor, &run);
}

/// Ported from `role_scoped_membership_parity_postgres18_and_openfga`.
///
/// Only `auditor` may read the membership table, so a caller outside that role sees no
/// membership row and the parent policy grants nothing.
async fn a_role_scoped_membership_read_gates_the_parent(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-role-scoped-membership",
        "role_scoped_membership",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO docs(id) VALUES ('d1'), ('d2');
             INSERT INTO doc_members(id, doc_id, user_id)
                 VALUES ('dm-alice', 'd1', 'alice'), ('dm-bob', 'd1', 'bob')",
            "CREATE ROLE app_alice LOGIN;
             GRANT SELECT ON docs, doc_members TO app_alice;
             GRANT auditor TO app_alice;
             CREATE ROLE app_bob LOGIN;
             GRANT SELECT ON docs, doc_members TO app_bob",
        ],
        vec![
            setting_reader("alice", "app_alice").holding(&["auditor"]),
            setting_reader("bob", "app_bob"),
        ],
    )
    // The policy names the role, so it exists before the schema.
    .after(&["CREATE ROLE auditor"]);
    // The membership table's own row security is disclosed, and the answers still agree:
    // the tuple loader reads only the rows the auditor scope exposes.
    support::parity::run_disclosing_and_check(
        &cluster,
        &case,
        &[
            ("alice", "docs:d1", true),
            ("alice", "docs:d2", false),
            // Bob's membership row exists and he cannot see it, so the parent denies.
            ("bob", "docs:d1", false),
        ],
    )
    .await;
}

/// Ported from `noinherit_member_parity_postgres18_and_openfga`.
///
/// A policy `TO editors` admits the role's inheriting members only: `PostgreSQL` applies
/// the clause with `has_privs_of_role`, so a `NOINHERIT` member holds MEMBER and reads
/// nothing. Only the inheriting caller declares the holding.
async fn a_noinherit_member_of_a_scoped_role_reads_nothing(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-noinherit-member",
        "role_scope_inherit",
        &[
            "INSERT INTO docs(id) VALUES ('d1'), ('d2')",
            "CREATE ROLE app_alice LOGIN;
             GRANT editors TO app_alice;
             GRANT SELECT ON docs TO app_alice;
             CREATE ROLE app_bob LOGIN NOINHERIT;
             GRANT editors TO app_bob;
             GRANT SELECT ON docs TO app_bob",
        ],
        vec![
            Principal::as_role("alice", "app_alice").holding(&["editors"]),
            Principal::as_role("bob", "app_bob"),
        ],
    )
    .after(&["CREATE ROLE editors"]);
    let run = support::parity::run(&cluster, &case).await;
    // Two sided by construction: a model granting or denying everything cannot pass.
    for (subject, visible) in [("alice", true), ("bob", false)] {
        for object in ["docs:d1", "docs:d2"] {
            support::parity::assert_postgres(
                &case,
                &run,
                subject,
                object,
                ActionStatement::Select,
                visible,
            );
        }
    }
    assert_agrees(&case, &run);
}

/// Ported from `shared_paper_parity_postgres18_and_openfga`.
///
/// One policy carrying two arms, ownership by the caller's identity and a share row whose
/// viewer is in the caller's held set, beside the share table's own set policy.
async fn a_shared_paper_reads_through_either_arm(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-shared-paper",
        "connetto_capability",
        &[
            // Paper 2 is shared with a key alice carries, paper 3 with one she does not.
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer) VALUES (2, 'team-a'), (3, 'team-z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![
            user_holder("alice", "app_reader", &["team-a"]),
            user_holder("carol", "app_reader", &[]),
        ],
    );
    // The share table carries its own set policy, which is disclosed, and the answers
    // still agree because the loader reads the shares each caller may see.
    support::parity::run_disclosing_and_check(
        &cluster,
        &case,
        &[
            ("alice", "papers:1", true),
            ("alice", "papers:2", true),
            ("alice", "papers:3", false),
            ("carol", "papers:1", false),
        ],
    )
    .await;
}

/// The share arm correlated on the team an item belongs to rather than on the item, so the
/// gate rides the membership row and the item reaches it through its team.
async fn a_team_share_reaches_items_through_the_team(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-team-share",
        "connetto_team_share",
        &[
            // Team 1 is granted to a key alice carries, team 2 to one dave carries.
            "INSERT INTO teams (id) VALUES (1), (2);
             INSERT INTO team_members (team_id, member) VALUES (1, 'team-a'), (2, 'team-z');
             INSERT INTO items (id, owner, team_id) VALUES
                 (1, 'alice', 1), (2, 'bob', 1), (3, 'bob', 2)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON items, teams, team_members TO app_reader",
        ],
        vec![
            user_holder("alice", "app_reader", &["team-a"]),
            user_holder("dave", "app_reader", &["team-z"]),
            user_holder("carol", "app_reader", &[]),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "items:1", true),
        ("alice", "items:2", true),
        ("alice", "items:3", false),
        ("dave", "items:3", true),
        ("dave", "items:2", false),
        ("carol", "items:1", false),
    ] {
        support::parity::assert_postgres(
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

/// A share correlated on a column that is no key of either table groups the guarded rows
/// by the value they share, which is what the database grants too. A key holding one
/// batch's share sees every paper of that batch and none of another.
async fn a_batch_share_grants_every_paper_of_the_batch(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-batch-share",
        "
CREATE TABLE papers (id INT PRIMARY KEY, batch TEXT NOT NULL);
CREATE TABLE shares (id INT PRIMARY KEY, paper_batch TEXT NOT NULL, viewer TEXT NOT NULL);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (EXISTS (
    SELECT 1 FROM shares s WHERE s.paper_batch = papers.batch
      AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
        &[
            "INSERT INTO papers (id, batch) VALUES (1, 'b1'), (2, 'b1'), (3, 'b2');
             INSERT INTO shares (id, paper_batch, viewer) VALUES (10, 'b1', 'team-a'), (11, 'b2', 'team-z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, shares TO app_reader",
        ],
        vec![
            subject_holder("alice", &["team-a"]),
            subject_holder("dave", &["team-z"]),
            subject_holder("carol", &[]),
        ],
    )
    .with_attributes(SUBJECTS_ONLY);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        ("alice", "papers:2", true),
        ("alice", "papers:3", false),
        ("dave", "papers:3", true),
        ("dave", "papers:1", false),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
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

/// A share keyed on the tenant as well as the paper, compared against the caller's set,
/// so a bridge on the paper alone would hand one tenant's key the other tenant's paper
/// of the same id.
async fn a_composite_key_share_in_the_callers_set_stays_within_its_tenant(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-composite-key-set-share",
        "
CREATE TABLE tenant_papers (tenant_id TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY (tenant_id, id));
CREATE TABLE tenant_shares (
    tenant_id TEXT NOT NULL,
    paper_id TEXT NOT NULL,
    viewer TEXT NOT NULL,
    PRIMARY KEY (tenant_id, paper_id, viewer)
);
ALTER TABLE tenant_papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_visible ON tenant_papers FOR SELECT USING (EXISTS (
    SELECT 1 FROM tenant_shares s
    WHERE s.tenant_id = tenant_papers.tenant_id AND s.paper_id = tenant_papers.id
      AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
        &[
            "INSERT INTO tenant_papers (tenant_id, id) VALUES
                 ('t1', 'p-shared'), ('t2', 'p-shared'), ('t1', 'p-solo');
             INSERT INTO tenant_shares (tenant_id, paper_id, viewer) VALUES
                 ('t1', 'p-shared', 'team-a'), ('t2', 'p-shared', 'team-z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON tenant_papers, tenant_shares TO app_reader",
        ],
        vec![
            subject_holder("alice", &["team-a"]),
            subject_holder("dave", &["team-z"]),
        ],
    )
    .with_attributes(SUBJECTS_ONLY);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "tenant_papers:t1|p-shared", true),
        ("alice", "tenant_papers:t2|p-shared", false),
        ("dave", "tenant_papers:t2|p-shared", true),
        ("dave", "tenant_papers:t1|p-shared", false),
        ("alice", "tenant_papers:t1|p-solo", false),
    ] {
        support::parity::assert_postgres(
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

/// The membership row compared with `IN (SELECT unnest(...))` reads the same set as the
/// `= ANY(string_to_array(...))` spelling, so it grants the same readers the same items.
async fn a_row_valued_set_share_reaches_items_through_the_team(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-row-valued-team-share",
        "
CREATE TABLE teams (id INT PRIMARY KEY);
CREATE TABLE team_members (member TEXT NOT NULL, team_id INT REFERENCES teams(id),
                           PRIMARY KEY (team_id, member));
CREATE TABLE items (id INT PRIMARY KEY, team_id INT NOT NULL REFERENCES teams(id));
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR SELECT USING (EXISTS (
    SELECT 1 FROM team_members
    WHERE team_members.team_id = items.team_id
      AND team_members.member IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ',')))));
",
        &[
            "INSERT INTO teams (id) VALUES (1), (2);
             INSERT INTO team_members (team_id, member) VALUES (1, 'team-a'), (2, 'team-z');
             INSERT INTO items (id, team_id) VALUES (1, 1), (2, 1), (3, 2)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON items, teams, team_members TO app_reader",
        ],
        vec![
            subject_holder("alice", &["team-a"]),
            subject_holder("dave", &["team-z"]),
            subject_holder("carol", &[]),
        ],
    )
    .with_attributes(SUBJECTS_ONLY);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "items:1", true),
        ("alice", "items:2", true),
        ("alice", "items:3", false),
        ("dave", "items:3", true),
        ("dave", "items:1", false),
        ("carol", "items:1", false),
    ] {
        support::parity::assert_postgres(
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

/// A membership row compared to the caller on two columns requires both in the database.
/// Keeping the last comparison alone granted whoever matched it, so the shape now falls
/// closed, and a caller matching either column alone is denied on both sides.
async fn a_membership_row_compared_to_the_caller_twice_denies_either_half(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-two-member-columns",
        "
CREATE TABLE teams (id INT PRIMARY KEY);
CREATE TABLE team_members (member TEXT NOT NULL, role TEXT NOT NULL,
                           team_id INT REFERENCES teams(id), PRIMARY KEY (team_id, member));
CREATE TABLE items (id INT PRIMARY KEY, team_id INT NOT NULL REFERENCES teams(id));
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR SELECT USING (EXISTS (
    SELECT 1 FROM team_members
    WHERE team_members.team_id = items.team_id
      AND team_members.member = current_setting('app.user_id', true)
      AND team_members.role = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
        &[
            // alice is the member but holds no key, dave holds the key but is not the member.
            "INSERT INTO teams (id) VALUES (1);
             INSERT INTO team_members (team_id, member, role) VALUES (1, 'alice', 'team-a');
             INSERT INTO items (id, team_id) VALUES (1, 1)",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON items, teams, team_members TO app_reader",
        ],
        vec![
            user_holder("alice", "app_reader", &[]),
            user_holder("dave", "app_reader", &["team-a"]),
        ],
    )
    .with_attributes(CALLER_AND_SUBJECTS);
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for subject in ["alice", "dave"] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            "items:1",
            ActionStatement::Select,
            false,
        );
    }
    support::parity::assert_discloses(&case, &run, &["items"]);
    support::parity::assert_disclosed_where_noted(&case, &run);
}

/// Ported from `token_claim_set_parity_postgres18_and_openfga`.
///
/// The caller's set arrives as a real list inside the token rather than as a delimited
/// string. Two tables, one per spelling, because they are the same database and must land
/// the same way. The numeric claim against the row named `1` is what makes the rendering
/// rule load bearing: `jsonb_array_elements_text` yields a JSON number as its text, so a
/// model shipping the number unrendered answers differently.
async fn a_token_claim_list_grants_by_membership(cluster: Arc<Cluster>) {
    /// The caller's claim, as the token's jsonb and as the condition's list.
    ///
    /// The list is what `jsonb_array_elements_text` would produce, so a number renders as
    /// its text. An absent claim sends the empty list, and its read raises.
    fn bearer(subject: &str, teams: &[serde_json::Value]) -> Principal {
        let rendered: Vec<String> = teams
            .iter()
            .map(|team| match team {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .collect();
        let mut principal = Principal::as_role(subject, "app_reader")
            .with_context(serde_json::json!({ "request_jwt_claims_teams": rendered }));
        if subject == "unset" {
            return principal.reading_an_unset_setting();
        }
        principal.session.push((
            "request.jwt.claims".to_string(),
            serde_json::json!({ "teams": teams }).to_string(),
        ));
        principal
    }

    let case = ParityCase::from_fixture(
        "runner-token-claim-set",
        "token_claim_set",
        &[
            // Row 4 is named by the numeric claim, row 3 by nobody.
            "INSERT INTO documents (id, team_id) VALUES
                 (1, 'team-a'), (2, 'team-b'), (3, NULL), (4, '1');
             INSERT INTO reports (id, team_id) VALUES
                 (1, 'team-a'), (2, 'team-b'), (3, NULL), (4, '1')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON documents, reports TO app_reader",
        ],
        vec![
            // Every claim state the source covered: unset, empty, one team, two, numeric.
            bearer("unset", &[]),
            bearer("empty", &[]),
            bearer("team_a", &[serde_json::json!("team-a")]),
            bearer(
                "both",
                &[serde_json::json!("team-a"), serde_json::json!("team-b")],
            ),
            bearer("numeric", &[serde_json::json!(1)]),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    // Both spellings have to land the same way, and a NULL team belongs to nobody.
    for table in ["documents", "reports"] {
        for (subject, row, visible) in [
            // An unset setting raises, which is the caller holding no token reading nothing.
            ("unset", 1, false),
            ("empty", 1, false),
            ("team_a", 1, true),
            ("team_a", 2, false),
            ("team_a", 3, false),
            ("team_a", 4, false),
            ("both", 1, true),
            ("both", 2, true),
            // The number renders as text, so it names the row spelled '1'.
            ("numeric", 4, true),
            ("numeric", 1, false),
        ] {
            support::parity::assert_postgres(
                &case,
                &run,
                subject,
                &format!("{table}:{row}"),
                ActionStatement::Select,
                visible,
            );
        }
    }
    assert_agrees(&case, &run);
}

/// Ported from `shared_owner_grants_parity_postgres18_and_openfga`.
///
/// Two guarded tables read one role-threshold function at different levels, so a caller
/// between the thresholds reads a sample and not a spectrum. That caller is the point: a
/// model collapsing the two tables onto one ladder level fails here.
async fn one_shared_grant_ladder_answers_two_thresholds(cluster: Arc<Cluster>) {
    const ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
    const BOB: &str = "00000000-0000-0000-0000-0000000000a2";
    const CAROL: &str = "00000000-0000-0000-0000-0000000000a3";
    const DAVE: &str = "00000000-0000-0000-0000-0000000000a4";
    const EVE: &str = "00000000-0000-0000-0000-0000000000a5";
    const ALPHA: &str = "00000000-0000-0000-0000-0000000000b1";
    const BETA: &str = "00000000-0000-0000-0000-0000000000b2";

    let reader = |subject: &str| {
        Principal::with_setting(subject, "app_reader", "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-shared-owner-grants",
        "shared_owner_grants",
        &[
            &format!(
                "INSERT INTO users (id) VALUES
                     ('{ALICE}'), ('{BOB}'), ('{CAROL}'), ('{DAVE}'), ('{EVE}');
                 INSERT INTO teams (id) VALUES ('{ALPHA}'), ('{BETA}');
                 INSERT INTO team_members (team_id, user_id) VALUES
                     ('{ALPHA}', '{BOB}'), ('{BETA}', '{CAROL}'), ('{BETA}', '{DAVE}');
                 INSERT INTO samples (id, owner_id) VALUES
                     ('{ALICE}', '{ALICE}'), ('{ALPHA}', '{ALPHA}');
                 INSERT INTO spectra (id, owner_id) VALUES
                     ('{ALICE}', '{ALICE}'), ('{ALPHA}', '{ALPHA}');
                 INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
                     ('{CAROL}', '{ALICE}', 3), ('{BETA}', '{ALICE}', 2), ('{EVE}', '{ALPHA}', 4)"
            ),
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON users, teams, team_members, owner_grants, samples, spectra
                 TO app_reader",
        ],
        vec![
            reader(ALICE),
            reader(BOB),
            reader(CAROL),
            reader(DAVE),
            reader(EVE),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        // Alice owns hers outright, so both thresholds pass.
        (ALICE, format!("samples:{ALICE}"), true),
        (ALICE, format!("spectra:{ALICE}"), true),
        // Dave reaches Alice's owner at level 2 through team beta: the sample only.
        (DAVE, format!("samples:{ALICE}"), true),
        (DAVE, format!("spectra:{ALICE}"), false),
        // Carol's own grant is level 3, so both.
        (CAROL, format!("samples:{ALICE}"), true),
        (CAROL, format!("spectra:{ALICE}"), true),
        // Bob holds nothing over Alice's owner.
        (BOB, format!("samples:{ALICE}"), false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `refused_spellings_fall_closed_parity_postgres18_and_openfga`.
///
/// Three spellings the classifier must refuse rather than widen: a CASE whose FALSE arm
/// vetoes, an EXISTS carrying a comparison between two columns of the guarded table, and
/// a NULLIF hiding a row from its own principal. Every one denies in the database.
async fn three_refused_spellings_fall_closed(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-refused-spellings",
        r"
CREATE TABLE case_docs(id TEXT PRIMARY KEY, archived BOOLEAN NOT NULL, is_public BOOLEAN NOT NULL);
CREATE TABLE filter_docs(id TEXT PRIMARY KEY, owner_id TEXT, reviewer_id TEXT);
CREATE TABLE filter_members(doc_id TEXT REFERENCES filter_docs(id), user_id TEXT);
CREATE TABLE sentinel_docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE case_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE filter_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sentinel_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY case_p ON case_docs FOR SELECT USING (
  CASE WHEN archived THEN FALSE WHEN is_public THEN TRUE ELSE FALSE END
);
CREATE POLICY filter_p ON filter_docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM filter_members m
    WHERE m.doc_id = filter_docs.id
      AND m.user_id = current_user
      AND filter_docs.owner_id = filter_docs.reviewer_id
  )
);
CREATE POLICY sentinel_p ON sentinel_docs FOR SELECT USING (
  NULLIF(owner_id, 'system') = current_user
);
",
        &[
            "INSERT INTO case_docs(id, archived, is_public) VALUES ('c1', TRUE, TRUE);
             INSERT INTO filter_docs(id, owner_id, reviewer_id)
                 VALUES ('f1', 'someone', 'someone_else');
             INSERT INTO filter_members(doc_id, user_id) VALUES ('f1', 'app_reader');
             INSERT INTO sentinel_docs(id, owner_id) VALUES ('s1', 'system')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON case_docs, filter_docs, filter_members TO app_reader;
             CREATE ROLE system LOGIN;
             GRANT SELECT ON sentinel_docs TO system",
        ],
        vec![
            Principal::as_role("app_reader", "app_reader"),
            Principal::as_role("system", "system"),
        ],
    );
    let run = support::parity::run_disclosing(&cluster, &case).await;
    for (subject, object) in [
        // The CASE veto denies the archived public row.
        ("app_reader", "case_docs:c1"),
        // Owner and reviewer differ, so the filter denies.
        ("app_reader", "filter_docs:f1"),
        // NULLIF hides the sentinel row from its own principal.
        ("system", "sentinel_docs:s1"),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            object,
            ActionStatement::Select,
            false,
        );
    }
    // All three refusals have to be reported, not just the one that makes the case
    // disclosed: a policy falling closed silently is the defect.
    support::parity::assert_discloses(&case, &run, &["case_docs", "filter_docs", "sentinel_docs"]);
    support::parity::assert_disclosed_where_noted(&case, &run);
}

/// A caller missing a setting its policies read fails the case, unless it says so.
///
/// The runner reads a raise as a denial only where the caller declares it, because
/// everywhere else the raise is the case granting no privilege or naming no column. The
/// token fixture is the shape that raises: `current_setting` without `missing_ok`.
async fn a_missing_session_setting_is_not_a_denial(cluster: Arc<Cluster>) {
    let seed = [
        "INSERT INTO documents (id, team_id) VALUES (1, 'team-a');
         INSERT INTO reports (id, team_id) VALUES (1, 'team-a')",
        "CREATE ROLE app_reader LOGIN; GRANT SELECT ON documents, reports TO app_reader",
    ];
    let empty = || serde_json::json!({ "request_jwt_claims_teams": [] });
    // The same caller twice: once silently misconfigured, once declaring the raise.
    let planted = ParityCase::from_fixture(
        "runner-missing-setting",
        "token_claim_set",
        &seed,
        vec![Principal::as_role("nobody", "app_reader").with_context(empty())],
    );
    let shared = Arc::clone(&cluster);
    let failure = tokio::spawn(async move {
        support::parity::run(&shared, &planted).await;
    })
    .await;
    assert!(
        failure.is_err(),
        "a caller whose read raises without declaring it has to fail the case"
    );

    // Declared, yet the setting is there: the claim is stale and has to fail too.
    let stale_principal = {
        let mut principal = Principal::as_role("nobody", "app_reader")
            .with_context(empty())
            .reading_an_unset_setting();
        principal.session.push((
            "request.jwt.claims".to_string(),
            serde_json::json!({ "teams": [] }).to_string(),
        ));
        principal
    };
    let stale = ParityCase::from_fixture(
        "runner-stale-unset-claim",
        "token_claim_set",
        &seed,
        vec![stale_principal],
    );
    let shared = Arc::clone(&cluster);
    let stale_failure = tokio::spawn(async move {
        support::parity::run(&shared, &stale).await;
    })
    .await;
    assert!(
        stale_failure.is_err(),
        "a caller declaring a raise whose read succeeds has to fail the case"
    );

    let declared = ParityCase::from_fixture(
        "runner-missing-setting-declared",
        "token_claim_set",
        &seed,
        vec![Principal::as_role("nobody", "app_reader")
            .with_context(empty())
            .reading_an_unset_setting()],
    );
    let run = support::parity::run(&cluster, &declared).await;
    support::parity::assert_postgres(
        &declared,
        &run,
        "nobody",
        "documents:1",
        ActionStatement::Select,
        false,
    );
    assert_agrees(&declared, &run);
}

/// The request-scoped values the share cases declare.
const CALLER_AND_SUBJECTS: &str = r#"[
      { "key": "app.user_id", "kind": "caller_id" },
      { "key": "app.subjects", "kind": "set_attribute" }
    ]"#;

/// A caller identified by `app.user_id` and holding `keys` as `app.subjects`, logged in as `login`.
fn user_holder(subject: &str, login: &str, keys: &[&str]) -> Principal {
    let mut principal = Principal::with_setting(subject, login, "app.user_id", subject)
        .with_context(serde_json::json!({ "app_subjects": keys }));
    principal
        .session
        .push(("app.subjects".to_string(), keys.join(",")));
    principal
}

/// A caller identified by `app.user_id` and holding `keys` as `app.subjects`.
fn key_holder(subject: &str, keys: &[&str]) -> Principal {
    user_holder(subject, "app_reader", keys).with_clock()
}

/// Ported from `request_time_condition_parity_postgres18_and_openfga`.
///
/// A guard against `now()` cannot become tuples, since a tuple computed once keeps
/// granting after the value passed. It becomes a condition, and the second instant is what
/// proves the service evaluates it rather than the loader having baked the clock in.
async fn a_request_time_guard_holds_at_two_instants(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-request-time-condition",
        r#"
CREATE TABLE docs (id TEXT PRIMARY KEY, foo TEXT, "Foo" TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_unexpired ON docs FOR SELECT USING ("Foo" > now());
"#,
        &[
            // The quoted column carries the boundary, the unquoted one is a decoy. The
            // middle row is relative to the run clock: an absolute date passes into the
            // past and takes both the assertion and the took-away guard with it.
            "INSERT INTO docs (id, foo, \"Foo\") VALUES
                 ('d-live', 'text', '2099-01-01T00:00:00+00:00'),
                 ('d-stale', 'text', '2000-01-01T00:00:00+00:00'),
                 ('d-soon', 'text', now() + interval '6 months'),
                 ('d-null', 'text', NULL)",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON docs TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    .also_at(
        "1 year",
        "SELECT 'app_user'::text AS subject, 'docs:' || id AS object
         FROM docs WHERE \"Foo\" > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (object, visible) in [
        ("docs:d-live", true),
        ("docs:d-stale", false),
        ("docs:d-soon", true),
        // A NULL boundary compares as unknown, so the row admits nobody.
        ("docs:d-null", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `interval_grace_condition_parity_postgres18_and_openfga`.
///
/// A grace period spelled `now() - interval '30 days'` must survive with its offset
/// intact, so a row that expired inside the window still reads and one past it does not.
async fn a_grace_period_keeps_its_offset(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-interval-grace-condition",
        "
CREATE TABLE docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_grace ON docs FOR SELECT USING (expires_at > now() - interval '30 days');
",
        &[
            // Relative to the run clock: valid, expired inside the grace, past it, none.
            "INSERT INTO docs (id, expires_at) VALUES
                 ('g-fresh', now() + interval '5 days'),
                 ('g-grace', now() - interval '10 days'),
                 ('g-stale', now() - interval '40 days'),
                 ('g-null', NULL)",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON docs TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    // Twenty five days on, not a year: the fresh row expired twenty days ago and the
    // thirty day window still admits it, while the graced row has fallen out of it. Both
    // answers depend on the offset, so a future instant a year away would prove less.
    .also_at(
        "25 days",
        "SELECT 'app_user'::text AS subject, 'docs:' || id AS object
         FROM docs WHERE expires_at > $1::timestamptz - interval '30 days'",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (object, visible) in [
        ("docs:g-fresh", true),
        // Expired ten days ago, which the thirty-day window still admits.
        ("docs:g-grace", true),
        ("docs:g-stale", false),
        ("docs:g-null", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `expiring_share_condition_parity_postgres18_and_openfga`.
///
/// The share arm carries a deadline, so the share expires while the ownership arm does
/// not. A year on the owner still reads and the shared paper is gone.
async fn an_expiring_share_leaves_the_owner_arm_alone(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-expiring-share-condition",
        r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now()
    )
);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES
                 (2, 'team-a', now() + interval '1 day'),
                 (3, 'team-z', now() - interval '1 day')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![key_holder("alice", &["team-a"]), key_holder("carol", &[])],
    )
    .with_attributes(CALLER_AND_SUBJECTS)
    .also_at(
        "1 year",
        "SELECT c.subject, 'papers:' || p.id AS object
         FROM papers p
         CROSS JOIN (VALUES ('alice', 'team-a'), ('carol', '')) AS c(subject, keys)
         WHERE p.owner = c.subject
            OR EXISTS (
                SELECT 1 FROM paper_shares s
                WHERE s.paper_id = p.id
                  AND s.viewer = ANY(string_to_array(c.keys, ','))
                  AND s.expires_at > $1::timestamptz)",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        ("alice", "papers:2", true),
        ("alice", "papers:3", false),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `interval_grace_membership_condition_parity_postgres18_and_openfga`.
///
/// The same shape with a grace period on the share's deadline, so a share that expired ten
/// days ago still grants and one forty days ago does not.
async fn an_expiring_share_keeps_its_grace_period(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-interval-grace-membership",
        r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now() - interval '30 days'
    )
);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES
                 (2, 'team-a', now() - interval '10 days'),
                 (3, 'team-z', now() - interval '40 days')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![key_holder("alice", &["team-a"]), key_holder("carol", &[])],
    )
    .with_attributes(CALLER_AND_SUBJECTS)
    .also_at(
        "1 year",
        "SELECT c.subject, 'papers:' || p.id AS object
         FROM papers p
         CROSS JOIN (VALUES ('alice', 'team-a'), ('carol', '')) AS c(subject, keys)
         WHERE p.owner = c.subject
            OR EXISTS (
                SELECT 1 FROM paper_shares s
                WHERE s.paper_id = p.id
                  AND s.viewer = ANY(string_to_array(c.keys, ','))
                  AND s.expires_at > $1::timestamptz - interval '30 days')",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "papers:1", true),
        // Ten days expired, inside the window.
        ("alice", "papers:2", true),
        ("alice", "papers:3", false),
        ("carol", "papers:1", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `expiring_exists_membership_condition_parity_postgres18_and_openfga`.
///
/// The deadline sits on the membership row an EXISTS names, so each share gates its own
/// row rather than the caller as a whole.
async fn an_expiring_membership_row_gates_its_own_document(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-expiring-exists-membership",
        "
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE doc_shares (
    doc_id INT,
    user_id TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (doc_id, user_id)
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM doc_shares s
        WHERE s.doc_id = docs.id AND s.user_id = current_user AND s.expires_at > now()
    )
);
",
        &[
            "INSERT INTO docs (id) VALUES (1), (2), (3);
             INSERT INTO doc_shares (doc_id, user_id, expires_at) VALUES
                 (1, 'alice', now() + interval '1 day'),
                 (2, 'bob', now() - interval '1 day'),
                 (3, 'alice', now() + interval '1 day')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON docs, doc_shares TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice").with_clock(),
            Principal::as_role("bob", "bob").with_clock(),
        ],
    )
    .also_at(
        "1 year",
        "SELECT s.user_id AS subject, 'docs:' || d.id AS object
         FROM docs d JOIN doc_shares s ON s.doc_id = d.id
         WHERE s.expires_at > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "docs:1", true),
        ("alice", "docs:2", false),
        ("alice", "docs:3", true),
        // Bob's only share expired yesterday.
        ("bob", "docs:2", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `expiring_holder_membership_condition_parity_postgres18_and_openfga`.
///
/// The membership row names no document, so one live row admits the caller to every memo.
/// Alice holds an expired row beside a live one, which a model reading the wrong row of
/// the two would answer for.
async fn an_expiring_holder_row_admits_the_caller_to_everything(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-expiring-holder-membership",
        "
CREATE TABLE memos (id INT PRIMARY KEY);
CREATE TABLE reviewers (user_id TEXT, vetted_at TIMESTAMPTZ);
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY memos_p ON memos FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM reviewers
        WHERE reviewers.user_id = current_user AND reviewers.vetted_at > now()
    )
);
",
        &[
            "INSERT INTO memos (id) VALUES (1), (2);
             INSERT INTO reviewers (user_id, vetted_at) VALUES
                 ('alice', now() - interval '1 day'),
                 ('alice', now() + interval '1 day'),
                 ('bob', now() - interval '1 day')",
            "CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;
             GRANT SELECT ON memos, reviewers TO alice, bob",
        ],
        vec![
            Principal::as_role("alice", "alice").with_clock(),
            Principal::as_role("bob", "bob").with_clock(),
        ],
    )
    .also_at(
        "1 year",
        "SELECT r.user_id AS subject, 'memos:' || m.id AS object
         FROM memos m CROSS JOIN reviewers r
         WHERE r.vetted_at > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "memos:1", true),
        ("alice", "memos:2", true),
        // Bob's one row is expired, so he reads nothing.
        ("bob", "memos:1", false),
        ("bob", "memos:2", false),
    ] {
        support::parity::assert_postgres(
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

/// The set attribute the viewer cases declare.
const SUBJECTS_ONLY: &str = r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#;

/// A caller identified only by the keys it holds as `app.subjects`.
fn subject_holder(subject: &str, keys: &[&str]) -> Principal {
    let mut principal = Principal::as_role(subject, "app_reader")
        .with_context(serde_json::json!({ "app_subjects": keys }));
    principal
        .session
        .push(("app.subjects".to_string(), keys.join(",")));
    principal
}

/// Ported from `definer_membership_parity_postgres18_and_openfga`.
///
/// A `SECURITY DEFINER` wrapper around the membership EXISTS, called by the guarded table
/// and by the membership table's own policy, so the self-reference `PostgreSQL` would
/// refuse to plan runs as the owner. The third caller holds no grant on the membership
/// table at all and the definer still answers for its docs.
async fn a_definer_wrapper_answers_for_a_caller_without_the_grant(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-definer-membership",
        "definer_membership",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob'), ('carol');
             INSERT INTO docs(id) VALUES ('d1'), ('d2');
             INSERT INTO doc_members(id, doc_id, user_id) VALUES
                 ('dm-alice', 'd1', 'alice'),
                 ('dm-bob', 'd1', 'bob'),
                 ('dm-carol', 'd2', 'carol')",
            // Carol is deliberately given nothing on the membership table.
            "CREATE ROLE app_alice LOGIN;
             GRANT SELECT ON docs, doc_members TO app_alice;
             CREATE ROLE app_bob LOGIN;
             GRANT SELECT ON docs, doc_members TO app_bob;
             CREATE ROLE app_carol LOGIN;
             GRANT SELECT ON docs TO app_carol",
        ],
        vec![
            setting_reader("alice", "app_alice"),
            setting_reader("bob", "app_bob"),
            setting_reader("carol", "app_carol"),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "docs:d1", true),
        ("alice", "docs:d2", false),
        ("bob", "docs:d1", true),
        ("carol", "docs:d2", true),
        ("carol", "docs:d1", false),
        // The membership policy calls the same wrapper, so a member of d1 sees both rows.
        ("alice", "doc_members:dm-bob", true),
        ("alice", "doc_members:dm-carol", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `role_scoped_restrictive_parity_postgres18_and_openfga`.
///
/// A RESTRICTIVE policy scoped to `contractor` binds only that role, so an owner outside
/// it keeps the read the permissive policy grants.
async fn a_restrictive_policy_binds_only_its_role(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-role-scoped-restrictive",
        "role_scoped_restrictive",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id, reviewer_id) VALUES
                 ('note-reviewed', 'alice', 'alice'),
                 ('note-unreviewed', 'alice', 'bob'),
                 ('note-outside-the-role', 'bob', 'alice')",
            "CREATE ROLE app_alice LOGIN;
             GRANT SELECT ON users, notes TO app_alice;
             GRANT contractor TO app_alice;
             CREATE ROLE app_bob LOGIN;
             GRANT SELECT ON users, notes TO app_bob",
        ],
        vec![
            setting_reader("alice", "app_alice").holding(&["contractor"]),
            setting_reader("bob", "app_bob"),
        ],
    )
    .after(&["CREATE ROLE contractor"]);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "notes:note-reviewed", true),
        // Alice owns it and is a contractor, but is not its reviewer.
        ("alice", "notes:note-unreviewed", false),
        ("alice", "notes:note-outside-the-role", false),
        // Bob owns it and the barrier does not reach him.
        ("bob", "notes:note-outside-the-role", true),
        ("bob", "notes:note-reviewed", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `shared_policy_name_condition_parity_postgres18_and_openfga`.
///
/// One policy name on two tables, comparing against the clock in opposite directions. A
/// condition named after the policy would collide, and one table would answer with the
/// other's comparison.
async fn one_policy_name_on_two_tables_keeps_two_comparisons(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-shared-policy-name",
        "
CREATE TABLE campaigns (id TEXT PRIMARY KEY, at TIMESTAMPTZ NOT NULL);
CREATE TABLE embargoes (id TEXT PRIMARY KEY, at TIMESTAMPTZ NOT NULL);
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE embargoes ENABLE ROW LEVEL SECURITY;
CREATE POLICY visible_now ON campaigns FOR SELECT TO PUBLIC USING (at <= now());
CREATE POLICY visible_now ON embargoes FOR SELECT TO PUBLIC USING (at > now());
",
        &[
            "INSERT INTO campaigns (id, at) VALUES
                 ('c-running', now() - interval '1 day'),
                 ('c-upcoming', now() + interval '1 day');
             INSERT INTO embargoes (id, at) VALUES
                 ('e-held', now() + interval '1 day'),
                 ('e-lifted', now() - interval '1 day')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON campaigns, embargoes TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    .also_at(
        "1 year",
        "SELECT 'app_user'::text AS subject, 'campaigns:' || id AS object
         FROM campaigns WHERE at <= $1::timestamptz
         UNION ALL
         SELECT 'app_user'::text AS subject, 'embargoes:' || id AS object
         FROM embargoes WHERE at > $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    // The two comparisons are mirror images, so a collision shows as a swapped answer.
    for (object, visible) in [
        ("campaigns:c-running", true),
        ("campaigns:c-upcoming", false),
        ("embargoes:e-held", true),
        ("embargoes:e-lifted", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `two_viewers_of_one_paper_load_and_union_parity_postgres18_and_openfga`.
///
/// A paper shared to two viewers must load and union rather than collide. Keying every
/// share tuple on the paper put both viewers on one triple, which `OpenFGA` refuses as a
/// duplicate write, so the load itself is half the assertion.
async fn two_viewers_of_one_paper_load_and_union(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-two-viewers-of-one-paper",
        "
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob');
             INSERT INTO paper_shares (paper_id, viewer) VALUES
                 (1, 'viewer_x'), (1, 'viewer_y'), (2, 'viewer_z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![
            subject_holder("viewer_x", &["viewer_x"]),
            subject_holder("viewer_y", &["viewer_y"]),
            subject_holder("viewer_z", &["viewer_z"]),
        ],
    )
    .with_attributes(SUBJECTS_ONLY);
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("viewer_x", "papers:1", true),
        ("viewer_y", "papers:1", true),
        ("viewer_x", "papers:2", false),
        ("viewer_z", "papers:2", true),
        ("viewer_z", "papers:1", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from
/// `two_expiring_viewers_of_one_paper_gate_independently_parity_postgres18_and_openfga`.
///
/// Two shares of one paper, each carrying its own deadline, so one viewer's expiry must
/// not take the other's grant with it.
async fn two_expiring_viewers_of_one_paper_gate_independently(cluster: Arc<Cluster>) {
    let holder = |subject: &str| subject_holder(subject, &[subject]).with_clock();
    let case = ParityCase::reading(
        "runner-two-expiring-viewers",
        r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now()
    )
);
",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice');
             INSERT INTO paper_shares (paper_id, viewer, expires_at) VALUES
                 (1, 'viewer_live', now() + interval '1 day'),
                 (1, 'viewer_gone', now() - interval '1 day')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![holder("viewer_live"), holder("viewer_gone")],
    )
    .with_attributes(SUBJECTS_ONLY)
    .also_at(
        "1 year",
        "SELECT c.subject, 'papers:' || p.id AS object
         FROM papers p
         CROSS JOIN (VALUES ('viewer_live', 'viewer_live'), ('viewer_gone', 'viewer_gone'))
             AS c(subject, keys)
         WHERE EXISTS (
             SELECT 1 FROM paper_shares s
             WHERE s.paper_id = p.id
               AND s.viewer = ANY(string_to_array(c.keys, ','))
               AND s.expires_at > $1::timestamptz)
         UNION ALL
         SELECT c.subject, 'paper_shares:' || s.paper_id || '|' || s.viewer AS object
         FROM paper_shares s
         CROSS JOIN (VALUES ('viewer_live'), ('viewer_gone')) AS c(subject)",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, visible) in [("viewer_live", true), ("viewer_gone", false)] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            "papers:1",
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `two_deadline_witness_parity_postgres18_and_openfga`.
///
/// Two deadlines on a membership table whose rows are not uniquely keyed by
/// `(doc, user)`. `PostgreSQL` grants only where one single row passes both comparisons,
/// so a model compressing the rows per column grants Bob, whose two rows each pass one
/// comparison and fail the other.
async fn two_deadlines_need_one_witnessing_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-two-deadline-witness",
        "
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE members (
    id INT PRIMARY KEY,
    doc_id INT NOT NULL REFERENCES docs(id),
    user_id TEXT NOT NULL,
    trial_ends TIMESTAMPTZ NOT NULL,
    support_ends TIMESTAMPTZ NOT NULL
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM members m
        WHERE m.doc_id = docs.id AND m.user_id = current_user
          AND m.trial_ends > now() AND m.support_ends > now()
    )
);
",
        &[
            // Bob's two rows each pass one comparison, Carol's one row passes both.
            "INSERT INTO docs (id) VALUES (1), (2);
             INSERT INTO members (id, doc_id, user_id, trial_ends, support_ends) VALUES
                 (1, 1, 'bob', now() + interval '10 days', now() - interval '10 days'),
                 (2, 1, 'bob', now() - interval '10 days', now() + interval '10 days'),
                 (3, 1, 'carol', now() + interval '10 days', now() + interval '10 days'),
                 (4, 2, 'carol', now() + interval '10 days', now() - interval '10 days')",
            "CREATE ROLE bob LOGIN; CREATE ROLE carol LOGIN;
             GRANT SELECT ON docs, members TO bob, carol",
        ],
        vec![
            Principal::as_role("bob", "bob").with_clock(),
            Principal::as_role("carol", "carol").with_clock(),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        // Each column's latest value alone would admit Bob, one row does not.
        ("bob", "docs:1", false),
        ("carol", "docs:1", true),
        ("carol", "docs:2", false),
    ] {
        support::parity::assert_postgres(
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

/// Ported from `clock_gated_from_row_parity_postgres18_and_openfga`.
///
/// A record keyed on the guarded table's own compound key, replayed from the row alone. One
/// row each side of `now()` per tenant, so a replay keyed on the tenant would answer for
/// both and a prefix of the key could not name the row it came from.
async fn a_clock_gated_record_replays_from_its_own_row(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-clock-gated-from-row",
        "
CREATE TABLE readings (
    tenant_id INT,
    reading_id INT,
    starts_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, reading_id)
);
ALTER TABLE readings ENABLE ROW LEVEL SECURITY;
CREATE POLICY readings_visible ON readings FOR SELECT TO PUBLIC USING (starts_at <= now());
",
        &[
            "INSERT INTO readings (tenant_id, reading_id, starts_at) VALUES
                 (7, 9, now() - interval '1 day'),
                 (7, 10, now() + interval '1 day'),
                 (8, 9, now() - interval '1 day'),
                 (8, 10, now() + interval '1 day')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT ON readings TO app_user",
        ],
        vec![Principal::as_role("app_user", "app_user").with_clock()],
    )
    .loading_from_rows()
    // A year back, not on: this guard admits more as time passes, so a later instant
    // takes nothing away and the runner refuses it. Earlier, nothing has started yet.
    .also_at(
        "-1 year",
        "SELECT 'app_user'::text AS subject,
                'readings:' || tenant_id || '|' || reading_id AS object
         FROM readings WHERE starts_at <= $1::timestamptz",
    );
    let run = support::parity::run(&cluster, &case).await;
    for (object, visible) in [
        ("readings:7|9", true),
        ("readings:7|10", false),
        ("readings:8|9", true),
        ("readings:8|10", false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "app_user",
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `shared_paper_from_row_parity_postgres18_and_openfga`.
///
/// A record keyed on a foreign column, so one membership row states a record about another
/// type's object. The share arm replays from the share row and nothing runs its whole-table
/// query, while the owner arm and the share table's own rows still load whole.
async fn a_share_record_replays_onto_another_types_object(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-shared-paper-from-row",
        "connetto_capability",
        &[
            "INSERT INTO papers (id, owner) VALUES (1, 'alice'), (2, 'bob'), (3, 'bob');
             INSERT INTO paper_shares (paper_id, viewer) VALUES (2, 'team-a'), (3, 'team-z')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON papers, paper_shares TO app_reader",
        ],
        vec![
            user_holder("alice", "app_reader", &["team-a"]),
            user_holder("carol", "app_reader", &[]),
        ],
    )
    .loading_from_rows();
    // The share table carries its own set policy, which is disclosed, and the answers agree.
    support::parity::run_disclosing_and_check(
        &cluster,
        &case,
        &[
            // The owner arm, which loads whole.
            ("alice", "papers:1", true),
            // The share arm, which only the replay loads.
            ("alice", "papers:2", true),
            ("alice", "papers:3", false),
            ("carol", "papers:1", false),
        ],
    )
    .await;
}

/// Ported from `translated_schema_parity_postgres18_and_openfga`.
///
/// The role ladder: one shared grant function answers four thresholds, read at 2, inserted
/// and updated at 3, deleted at 4. Five callers sit at different rungs, so a model
/// collapsing the thresholds answers one of them wrongly.
async fn a_role_ladder_answers_four_thresholds(cluster: Arc<Cluster>) {
    const ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
    const BOB: &str = "00000000-0000-0000-0000-0000000000a2";
    const CAROL: &str = "00000000-0000-0000-0000-0000000000a3";
    const DAVE: &str = "00000000-0000-0000-0000-0000000000a4";
    const EVE: &str = "00000000-0000-0000-0000-0000000000a5";
    const ALPHA: &str = "00000000-0000-0000-0000-0000000000b1";
    const BETA: &str = "00000000-0000-0000-0000-0000000000b2";
    const DOC_1: &str = "00000000-0000-0000-0000-0000000000d1";
    const DOC_2: &str = "00000000-0000-0000-0000-0000000000d2";

    let reader = |subject: &str| {
        Principal::with_setting(subject, "app_reader", "app.current_user_id", subject)
    };
    let case = ParityCase::from_fixture(
        "runner-translated-schema",
        "earth_metabolome",
        &[
            &format!(
                "INSERT INTO users (id) VALUES
                     ('{ALICE}'), ('{BOB}'), ('{CAROL}'), ('{DAVE}'), ('{EVE}');
                 INSERT INTO teams (id) VALUES ('{ALPHA}'), ('{BETA}');
                 INSERT INTO team_members (team_id, user_id) VALUES
                     ('{ALPHA}', '{BOB}'), ('{BETA}', '{DAVE}');
                 INSERT INTO ownables (id, owner_id) VALUES
                     ('{DOC_1}', '{ALICE}'), ('{DOC_2}', '{ALPHA}');
                 INSERT INTO owner_grants (grantee_owner_id, granted_owner_id, role_id) VALUES
                     ('{CAROL}', '{ALICE}', 3), ('{BETA}', '{ALICE}', 2), ('{EVE}', '{ALPHA}', 4)"
            ),
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT ON users, teams, team_members, owner_grants TO app_reader;
             GRANT SELECT, INSERT, UPDATE, DELETE ON ownables TO app_reader",
        ],
        vec![
            reader(ALICE),
            reader(BOB),
            reader(CAROL),
            reader(DAVE),
            reader(EVE),
        ],
    )
    .writing(
        "ownables",
        Mutations {
            // Rewriting the owner with itself exercises USING and WITH CHECK together, and
            // the ladder reads the owner alone, so the probe's fresh key changes no answer.
            update_set: Some("owner_id = owner_id".to_string()),
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    let doc_1 = format!("ownables:{DOC_1}");
    for (subject, statement, allowed) in [
        // Alice owns doc 1 outright, which is rung 4.
        (ALICE, ActionStatement::Select, true),
        (ALICE, ActionStatement::Delete, true),
        // Carol's own grant is rung 3: reads, writes, no delete.
        (CAROL, ActionStatement::Select, true),
        (CAROL, ActionStatement::Insert, true),
        (CAROL, ActionStatement::Delete, false),
        // Dave reaches rung 2 through team beta: reads only.
        (DAVE, ActionStatement::Select, true),
        (DAVE, ActionStatement::Insert, false),
        (DAVE, ActionStatement::Update, false),
        // Bob holds nothing over alice's owner.
        (BOB, ActionStatement::Select, false),
    ] {
        support::parity::assert_postgres(&case, &run, subject, &doc_1, statement, allowed);
    }
    assert_agrees(&case, &run);
}

/// Ported from `insert_readback_parity_postgres18_and_openfga`.
///
/// Split `INSERT` and `SELECT` policies: the author may insert a row, the owner may read
/// it. `PostgreSQL` applies both to `INSERT ... RETURNING`, and only the `WITH CHECK` to a
/// plain `INSERT`, which is what leaves one relation ungated and the other not.
async fn an_insert_that_reads_back_applies_the_select_policy(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-insert-readback",
        "insert_readback",
        &[
            // One row per combination of owning and authoring.
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id, author_id) VALUES
                 ('note-author-only', 'bob', 'alice'),
                 ('note-owner-only', 'alice', 'bob'),
                 ('note-both', 'alice', 'alice'),
                 ('note-neither', 'bob', 'bob')",
            "CREATE ROLE app_user LOGIN; GRANT SELECT, INSERT ON notes TO app_user",
        ],
        vec![
            setting_reader("alice", "app_user"),
            setting_reader("bob", "app_user"),
        ],
    )
    .writing(
        "notes",
        Mutations {
            update_set: None,
            // The policies read owner and author, never the key.
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, row, statement, allowed) in [
        // Alice authors it, so the plain insert stands and the readback does not.
        ("alice", "note-author-only", ActionStatement::Insert, true),
        (
            "alice",
            "note-author-only",
            ActionStatement::InsertReturning,
            false,
        ),
        // Owned and authored by her, so both.
        ("alice", "note-both", ActionStatement::Insert, true),
        ("alice", "note-both", ActionStatement::InsertReturning, true),
        // Hers to read, not hers to write.
        ("alice", "note-owner-only", ActionStatement::Insert, false),
        ("bob", "note-owner-only", ActionStatement::Insert, true),
        (
            "bob",
            "note-neither",
            ActionStatement::InsertReturning,
            true,
        ),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("notes:{row}"),
            statement,
            allowed,
        );
    }
    assert_agrees(&case, &run);
}

/// Ported from `upsert_parity_postgres18_and_openfga`.
///
/// An upsert may change the conflicting row, so `PostgreSQL` applies the `UPDATE` policies
/// on top of the `INSERT` one. A row the author may insert and the editor may not change
/// separates the two relations.
async fn an_upsert_applies_the_update_policy_too(cluster: Arc<Cluster>) {
    let case = ParityCase::from_fixture(
        "runner-upsert",
        "upsert",
        &[
            "INSERT INTO users(id) VALUES ('alice'), ('bob');
             INSERT INTO notes(id, owner_id, author_id, editor_id) VALUES
                 ('note-alice-all', 'alice', 'alice', 'alice'),
                 ('note-author-only', 'bob', 'alice', 'bob'),
                 ('note-author-editor', 'bob', 'alice', 'alice'),
                 ('note-owner-author', 'alice', 'alice', 'bob'),
                 ('note-bob-all', 'bob', 'bob', 'bob')",
            "CREATE ROLE app_user LOGIN;
             GRANT SELECT, INSERT, UPDATE ON notes TO app_user",
        ],
        vec![
            setting_reader("alice", "app_user"),
            setting_reader("bob", "app_user"),
        ],
    )
    .writing(
        "notes",
        Mutations {
            update_set: None,
            // The policies read owner, author and editor, never the key.
            check_neutral: true,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, row, statement, allowed) in [
        // Alice authors it and does not edit it: the insert stands, the upsert does not.
        ("alice", "note-author-only", ActionStatement::Insert, true),
        (
            "alice",
            "note-author-only",
            ActionStatement::InsertOnConflictUpdate,
            false,
        ),
        // She authors and edits it, and bob owns it. Naming the arbiter reads the
        // conflicting row, so the SELECT policy denies the upsert anyway.
        (
            "alice",
            "note-author-editor",
            ActionStatement::InsertOnConflictUpdate,
            false,
        ),
        // Hers to read and to author, bob's to edit: the insert stands, the upsert does not.
        ("alice", "note-owner-author", ActionStatement::Insert, true),
        (
            "alice",
            "note-owner-author",
            ActionStatement::InsertOnConflictUpdate,
            false,
        ),
        // Hers throughout, so both.
        (
            "alice",
            "note-alice-all",
            ActionStatement::InsertOnConflictUpdate,
            true,
        ),
        ("bob", "note-bob-all", ActionStatement::Insert, true),
        ("bob", "note-author-only", ActionStatement::Insert, false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            subject,
            &format!("notes:{row}"),
            statement,
            allowed,
        );
    }
    assert_agrees(&case, &run);
}

/// Every case the exact-support grammar admits, against both services.
///
/// The grammar decides membership, so there is nothing to declare per case and nothing to
/// exempt: a case it admits agrees with `PostgreSQL` on every caller, row and statement.
/// `run` refuses a case the translation says it diverges on, which is the property, since
/// one row settles each of these answers and there is nothing to disclose.
///
/// Two sided per case, so a model granting or denying everything cannot pass, and the
/// caller that set nothing is compared too: whether that read raises is the accessor
/// spelling's business, which the grammar knows from `PostgreSQL`'s rules.
async fn every_exact_support_case_agrees(cluster: Arc<Cluster>) {
    for generated in support::exact_support::every_case() {
        let seed: Vec<&str> = generated.seed.iter().map(String::as_str).collect();
        let principals = support::exact_support::CALLERS
            .iter()
            .map(|caller| match caller.value {
                Some(value) => {
                    Principal::with_setting(caller.subject, caller.subject, "app.who", value)
                }
                None if generated.accessor.raises_when_unset() => {
                    Principal::as_role(caller.subject, caller.subject).reading_an_unset_setting()
                }
                None => Principal::as_role(caller.subject, caller.subject),
            })
            .collect();
        let partitions: Vec<&str> = generated
            .not_read_directly
            .iter()
            .map(String::as_str)
            .collect();
        let prelude: Vec<&str> = generated.prelude.iter().map(String::as_str).collect();
        let case = ParityCase::reading(&generated.name, &generated.schema, &seed, principals)
            .with_attributes(support::exact_support::DECLARED_KEY)
            // The roles exist before the schema, which may name one as the table's owner.
            .after(&prelude)
            // A partition is filtered by nothing when a read names it, so the case compares
            // reads through the root, which is what the model answers for.
            .not_reading_directly(&partitions);
        // The grammar's write cases change a column no policy reads, and the probe changes
        // the key alone, so the row a write produces carries the existing row's facts.
        let case = match &generated.writes {
            Some(write) => case.writing(
                "guarded",
                Mutations {
                    update_set: Some(write.update_set.clone()),
                    check_neutral: true,
                },
            ),
            None => case,
        };
        let run = support::parity::run(&cluster, &case).await;
        support::parity::assert_two_sided(&case, &run);
        assert_agrees(&case, &run);
    }
}

/// A statement the model says nothing about is a failure, not a pair to leave out.
///
/// The runner used to skip a pair whose `ActionRelations` entry was missing, and the
/// non-vacuity guard still passed on the pairs that remained, so a whole table or statement
/// could stop being compared without anything saying so.
async fn a_missing_statement_answer_fails_the_case(cluster: Arc<Cluster>) {
    let case = ownership_case();
    let shared = Arc::clone(&cluster);
    let failure = tokio::spawn(async move {
        support::parity::run_with(
            &shared,
            &case,
            support::parity::Class::Exact,
            // The model answers for everything except reading, which is the one the case
            // is about.
            |answers| {
                answers
                    .into_iter()
                    .filter(|entry| entry.statement != ActionStatement::Select)
                    .collect()
            },
        )
        .await;
    })
    .await;
    assert!(
        failure.is_err(),
        "a missing answer for SELECT has to fail rather than quietly drop every read"
    );
}

/// A row the model cannot name is a failure, not a row to leave out.
///
/// An object name is capped, and a row past the cap makes rendering raise. Dropping it
/// removed the row from the comparison while the case still passed on its other rows,
/// which is the row-naming divergence the suite exists to find.
async fn a_row_the_model_cannot_name_fails_the_case(cluster: Arc<Cluster>) {
    let long = "l".repeat(300);
    let case = ParityCase::reading(
        "runner-unnameable-row",
        OWNERSHIP,
        &[
            &format!(
                "INSERT INTO docs(id, owner_id, title) VALUES
                     ('d1', 'alice', 'first'), ('{long}', 'alice', 'too long')"
            ),
            "CREATE ROLE alice LOGIN; GRANT SELECT, UPDATE, DELETE ON docs TO alice",
        ],
        vec![Principal::with_setting(
            "alice",
            "alice",
            "app.user_id",
            "alice",
        )],
    );
    let shared = Arc::clone(&cluster);
    let failure = tokio::spawn(async move {
        support::parity::run(&shared, &case).await;
    })
    .await;
    assert!(
        failure.is_err(),
        "a row whose name cannot be rendered has to fail rather than leave the row out"
    );
}

/// A write declared for one table is not applied to another.
///
/// Two tables, and only the second declares a change. The first has no candidate, so its
/// `UPDATE` is not compared at all: running the other table's `SET` against it names a
/// column it does not have, which used to be recorded as the policy denying the write.
async fn a_declared_write_stays_on_its_own_table(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-write-per-table",
        "
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT, title TEXT);
CREATE TABLE notes(id TEXT PRIMARY KEY, owner_id TEXT, body TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs FOR ALL
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY notes_all ON notes FOR ALL
    USING (owner_id = current_setting('app.user_id', true));
",
        &[
            "INSERT INTO docs(id, owner_id, title) VALUES ('d1', 'alice', 'first');
             INSERT INTO notes(id, owner_id, body) VALUES ('n1', 'alice', 'first')",
            "CREATE ROLE alice LOGIN;
             GRANT SELECT, INSERT, UPDATE, DELETE ON docs, notes TO alice",
        ],
        vec![Principal::with_setting(
            "alice",
            "alice",
            "app.user_id",
            "alice",
        )],
    )
    // Two tables declaring different changes, and disagreeing about neutrality: rewriting
    // the body cannot alter any policy's answer, while handing the row to somebody else is
    // the whole question, so that one may not be asked of the row that exists.
    .writing(
        "notes",
        Mutations {
            update_set: Some("body = body".to_string()),
            check_neutral: true,
        },
    )
    .writing(
        "docs",
        Mutations {
            update_set: Some("owner_id = 'someone_else'".to_string()),
            check_neutral: false,
        },
    );
    let run = support::parity::run(&cluster, &case).await;
    support::parity::assert_postgres(
        &case,
        &run,
        "alice",
        "notes:n1",
        ActionStatement::Update,
        true,
    );
    // The database refuses to hand the row away, and the model is not asked about a row
    // that does not exist, so the pair is declined rather than compared.
    assert!(
        run.observations.iter().all(|observation| {
            observation.object != "docs:d1" || observation.statement != ActionStatement::Update
        }),
        "a change the case does not call neutral must not be asked of the existing row: {:#?}",
        run.observations
    );
    assert_agrees(&case, &run);
}

/// A declared change names exactly one table, whichever way the case spells it.
///
/// The resolver has to accept the spellings that mean the same table and refuse the ones
/// that mean none or several. A first match would pick one of two same-named tables in
/// different schemas, and two spellings of one table would overwrite each other, either way
/// probing a change the case did not declare for that table.
async fn a_mutation_spelling_resolves_to_exactly_one_table(cluster: Arc<Cluster>) {
    const TWO_SCHEMAS: &str = "
CREATE SCHEMA left_hand;
CREATE SCHEMA right_hand;
CREATE TABLE left_hand.notes(id TEXT PRIMARY KEY, owner_id TEXT, body TEXT);
CREATE TABLE right_hand.notes(id TEXT PRIMARY KEY, owner_id TEXT, body TEXT);
ALTER TABLE left_hand.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE right_hand.notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY left_all ON left_hand.notes FOR ALL
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY right_all ON right_hand.notes FOR ALL
    USING (owner_id = current_setting('app.user_id', true));
";
    let neutral = || Mutations {
        update_set: Some("body = body".to_string()),
        check_neutral: true,
    };
    let two_schema_case = |name: &str| {
        ParityCase::reading(
            name,
            TWO_SCHEMAS,
            &[
                "INSERT INTO left_hand.notes(id, owner_id, body) VALUES ('l1', 'alice', 'x');
                 INSERT INTO right_hand.notes(id, owner_id, body) VALUES ('r1', 'alice', 'x')",
                "CREATE ROLE alice LOGIN;
                 GRANT USAGE ON SCHEMA left_hand, right_hand TO alice;
                 GRANT SELECT, INSERT, UPDATE, DELETE
                     ON left_hand.notes, right_hand.notes TO alice",
            ],
            vec![Principal::with_setting(
                "alice",
                "alice",
                "app.user_id",
                "alice",
            )],
        )
    };

    // A bare name two schemas both carry names neither of them.
    let ambiguous = two_schema_case("runner-ambiguous-spelling").writing("notes", neutral());
    let shared = Arc::clone(&cluster);
    let refused = tokio::spawn(async move {
        support::parity::run(&shared, &ambiguous).await;
    })
    .await;
    assert!(
        refused.is_err(),
        "a spelling two tables answer to has to be refused, not resolved to the first"
    );

    // Two spellings of one table are one declaration twice, and the second would win.
    let doubled = two_schema_case("runner-doubled-spelling")
        .writing("left_hand.notes", neutral())
        .writing("\"left_hand\".\"notes\"", neutral());
    let shared = Arc::clone(&cluster);
    let refused = tokio::spawn(async move {
        support::parity::run(&shared, &doubled).await;
    })
    .await;
    assert!(
        refused.is_err(),
        "two declarations for one table have to be refused rather than silently merged"
    );

    // The implicit schema, spelled out. The table is stored without one, so the resolver
    // has to know that a table with no schema lives in `public`.
    let qualified = ParityCase::reading(
        "runner-qualified-spelling",
        "
CREATE TABLE notes(id TEXT PRIMARY KEY, owner_id TEXT, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_all ON notes FOR ALL
    USING (owner_id = current_setting('app.user_id', true));
",
        &[
            "INSERT INTO notes(id, owner_id, body) VALUES ('n1', 'alice', 'x')",
            "CREATE ROLE alice LOGIN; GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO alice",
        ],
        vec![Principal::with_setting(
            "alice",
            "alice",
            "app.user_id",
            "alice",
        )],
    )
    .writing("public.notes", neutral());
    let run = support::parity::run(&cluster, &qualified).await;
    support::parity::assert_postgres(
        &qualified,
        &run,
        "alice",
        "notes:n1",
        ActionStatement::Update,
        true,
    );
    assert_agrees(&qualified, &run);
}

/// A note licenses a divergence at its own table, in its own direction, on its own command.
///
/// The hole this closes: requiring merely that *some* note diverge let one dropped clause
/// license a mismatch anywhere in the schema. Three plants, each licensed by nothing: one
/// on another table, one going the other way, and one on a command the note never fed. The
/// first two would pass a no-over-grant check as well, since a narrowing plant grants
/// nothing.
async fn the_oracle_rejects_a_note_excused_mismatch(cluster: Arc<Cluster>) {
    const SCHEMA: &str = "
CREATE TABLE plain(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE refused(id TEXT PRIMARY KEY, owner_id TEXT, archived BOOLEAN NOT NULL);
ALTER TABLE plain ENABLE ROW LEVEL SECURITY;
ALTER TABLE refused ENABLE ROW LEVEL SECURITY;
CREATE POLICY plain_own ON plain FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY refused_case ON refused FOR SELECT USING (
  CASE WHEN archived THEN FALSE WHEN owner_id IS NOT NULL THEN TRUE ELSE FALSE END
);
-- Beside the refused clause, so reads are not denied outright and the model can still
-- name rows of this table for a write. Without it every leg carries a second divergence
-- and the plants are not what fails.
CREATE POLICY refused_own ON refused FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY refused_delete ON refused FOR DELETE
    USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY refused_insert ON refused FOR INSERT
    WITH CHECK (owner_id = current_setting('app.user_id', true));
";
    let planted = |name: &'static str,
                   doctor: fn(
        Vec<rls2fga::types::ActionRelations>,
    ) -> Vec<rls2fga::types::ActionRelations>| {
        let cluster = Arc::clone(&cluster);
        async move {
            let case = ParityCase::reading(
                name,
                SCHEMA,
                &[
                    "INSERT INTO plain(id, owner_id) VALUES ('p1', 'alice');
                     INSERT INTO refused(id, owner_id, archived) VALUES
                         ('r1', 'alice', FALSE), ('r2', 'alice', TRUE),
                         ('r3', 'bob', TRUE)",
                    "CREATE ROLE alice LOGIN;
                     GRANT SELECT, INSERT, DELETE ON plain, refused TO alice",
                ],
                vec![Principal::with_setting(
                    "alice",
                    "alice",
                    "app.user_id",
                    "alice",
                )],
            )
            // So the insert probe is compared: the policies read the owner, never the key.
            .writing(
                "refused",
                Mutations {
                    update_set: None,
                    check_neutral: true,
                },
            );
            let outcome = tokio::spawn(async move {
                let run = support::parity::run_with(
                    &cluster,
                    &case,
                    support::parity::Class::Disclosed,
                    doctor,
                )
                .await;
                support::parity::assert_disclosed_where_noted(&case, &run);
            })
            .await;
            assert!(
                outcome.is_err(),
                "{name}: the note about the refused clause has to leave this unlicensed"
            );
        }
    };

    // Another table. `plain` translates and nothing is disclosed about it, so denying its
    // reads is a divergence the note about `refused` must not cover.
    planted("runner-plant-other-table", |answers| {
        answers
            .into_iter()
            .map(|mut entry| {
                if entry.type_name.as_str() == "plain" {
                    entry.answer = ActionAnswer::Denied;
                }
                entry
            })
            .collect()
    })
    .await;

    // The other direction. A clause the threshold dropped can only make the model narrower,
    // so granting the archived row on the noted table is licensed by nothing.
    planted("runner-plant-other-direction", |answers| {
        answers
            .into_iter()
            .map(|mut entry| {
                if entry.type_name.as_str() == "refused"
                    && entry.statement == ActionStatement::Select
                {
                    entry.answer = ActionAnswer::Unrestricted;
                }
                entry
            })
            .collect()
    })
    .await;

    // Another command. The dropped clause fed SELECT, and a per-row DELETE reads the SELECT
    // policies, so that one is explained by the note. A plain INSERT reads nothing back, so
    // denying inserts is the divergence the note cannot reach.
    planted("runner-plant-other-command", |answers| {
        answers
            .into_iter()
            .map(|mut entry| {
                if entry.type_name.as_str() == "refused"
                    && entry.statement == ActionStatement::Insert
                {
                    entry.answer = ActionAnswer::Denied;
                }
                entry
            })
            .collect()
    })
    .await;
}

/// A `P4` witness membership and a `P18` caller-set gate correlating to the same owner
/// type through different columns of one membership table must not share a link relation.
async fn a_witness_link_and_a_caller_set_gate_do_not_share_a_tupleset(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-witness-link-caller-set-gate",
        "
CREATE TABLE principals (id TEXT PRIMARY KEY);
CREATE TABLE owners (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
CREATE TABLE projects (id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
CREATE TABLE memberships (
    id TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES owners(id),
    lead_id TEXT NOT NULL REFERENCES owners(id),
    user_id TEXT NOT NULL REFERENCES principals(id),
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = docs.owner_id
        AND m.user_id = current_setting('app.user_id', true) AND m.expires_at > now()));
CREATE POLICY projects_select ON projects FOR SELECT USING (
    EXISTS (SELECT 1 FROM memberships m WHERE m.lead_id = projects.owner_id
        AND m.user_id = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
        &[
            "INSERT INTO principals VALUES ('alice'), ('bob'), ('carol')",
            "INSERT INTO owners VALUES ('A'), ('B')",
            "INSERT INTO docs VALUES ('d1','B'), ('d2','A')",
            "INSERT INTO projects VALUES ('p1','A')",
            "INSERT INTO memberships VALUES ('m1','A','B','alice','2100-01-01T00:00:00Z')",
            "INSERT INTO memberships VALUES ('m2','A','A','carol','2100-01-01T00:00:00Z')",
            "CREATE ROLE app_reader LOGIN; GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader",
        ],
        vec![
            user_holder("alice", "app_reader", &["alice"]).with_clock(),
            user_holder("bob", "app_reader", &["bob"]).with_clock(),
            user_holder("carol", "app_reader", &["carol"]).with_clock(),
        ],
    )
    .with_attributes(
        r#"[{"key":"app.user_id","kind":"caller_id"},{"key":"app.subjects","kind":"set_attribute"}]"#,
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, visible) in [
        // alice's row ties her to A via owner_id and to B via lead_id, so each
        // policy's own column denies her and must not grant through the other.
        ("alice", "docs:d1", false),
        ("alice", "projects:p1", false),
        ("carol", "docs:d2", true),
        ("carol", "projects:p1", true),
        ("bob", "docs:d1", false),
        ("bob", "projects:p1", false),
    ] {
        support::parity::assert_postgres(
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

/// Two `ACL` tables gating two different privileges on one guarded table must not share a
/// member relation: membership in either table must not grant the other's privilege.
async fn distinct_acl_tables_do_not_share_a_member_relation(cluster: Arc<Cluster>) {
    let case = ParityCase::reading(
        "runner-distinct-acl-tables",
        "
CREATE TABLE principals (id TEXT PRIMARY KEY);
CREATE TABLE resources (id TEXT PRIMARY KEY);
CREATE TABLE read_acl (
    resource_id TEXT REFERENCES resources(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES principals(id),
    PRIMARY KEY (resource_id, user_id));
CREATE TABLE delete_acl (
    resource_id TEXT REFERENCES resources(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES principals(id),
    PRIMARY KEY (resource_id, user_id));
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
CREATE POLICY resources_read ON resources FOR SELECT USING (
    EXISTS (SELECT 1 FROM read_acl m
        WHERE m.resource_id = resources.id AND m.user_id = current_setting('app.user_id', true)));
CREATE POLICY resources_delete ON resources FOR DELETE USING (
    EXISTS (SELECT 1 FROM delete_acl m
        WHERE m.resource_id = resources.id AND m.user_id = current_setting('app.user_id', true)));
",
        &[
            "INSERT INTO principals VALUES ('alice'), ('bob'), ('carol')",
            "INSERT INTO resources VALUES ('r1')",
            "INSERT INTO read_acl VALUES ('r1', 'bob'), ('r1', 'carol')",
            "INSERT INTO delete_acl VALUES ('r1', 'alice'), ('r1', 'carol')",
            "CREATE ROLE app_reader LOGIN; \
             GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader; \
             GRANT DELETE ON resources TO app_reader",
        ],
        vec![
            Principal::with_setting("alice", "app_reader", "app.user_id", "alice"),
            Principal::with_setting("bob", "app_reader", "app.user_id", "bob"),
            Principal::with_setting("carol", "app_reader", "app.user_id", "carol"),
        ],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, statement, allowed) in [
        // Alice is only in delete_acl, not read_acl, which the harness's delete probe
        // also needs: two pools, not one, so being in one alone must not suffice.
        ("alice", ActionStatement::Select, false),
        ("alice", ActionStatement::Delete, false),
        // Bob is only in read_acl: a read, not a delete.
        ("bob", ActionStatement::Select, true),
        ("bob", ActionStatement::Delete, false),
        // Carol is in both.
        ("carol", ActionStatement::Select, true),
        ("carol", ActionStatement::Delete, true),
    ] {
        support::parity::assert_postgres(&case, &run, subject, "resources:r1", statement, allowed);
    }
    assert_agrees(&case, &run);
}

/// Two `role_threshold` functions, each with its own grant table and its own
/// `team_membership` table, must not pool their team rows into one `team` type: a caller
/// who joined one function's team table must not inherit the other function's grants to
/// a team of the same id.
async fn distinct_team_membership_tables_do_not_share_access(cluster: Arc<Cluster>) {
    const TEAM: &str = "00000000-0000-0000-0000-00000000001f";
    const ALICE: &str = "00000000-0000-0000-0000-0000000000a1";
    const BOB: &str = "00000000-0000-0000-0000-0000000000a2";
    const OWNER_A: &str = "00000000-0000-0000-0000-0000000000b1";
    const OWNER_B: &str = "00000000-0000-0000-0000-0000000000b2";
    let case = ParityCase::reading(
        "runner-distinct-team-membership-tables",
        "
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE teams(id UUID PRIMARY KEY);
CREATE TABLE team_members_a(team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id), PRIMARY KEY(team_id, user_id));
CREATE TABLE team_members_b(team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id), PRIMARY KEY(team_id, user_id));
CREATE TABLE owner_grants_a(grantee_owner_id UUID NOT NULL, granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL);
CREATE TABLE owner_grants_b(grantee_owner_id UUID NOT NULL, granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL);
CREATE TABLE docs_a(id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE TABLE docs_b(id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
    LANGUAGE sql STABLE AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_role_a(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE AS '
    SELECT COALESCE(MAX(role), 0) FROM (
        SELECT og.role_id AS role FROM owner_grants_a og
        WHERE og.granted_owner_id = target_owner_id
        AND (og.grantee_owner_id = user_uuid OR og.grantee_owner_id IN (
            SELECT tm.team_id FROM team_members_a tm WHERE tm.user_id = user_uuid))
    ) sub';
CREATE FUNCTION get_role_b(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE AS '
    SELECT COALESCE(MAX(role), 0) FROM (
        SELECT og.role_id AS role FROM owner_grants_b og
        WHERE og.granted_owner_id = target_owner_id
        AND (og.grantee_owner_id = user_uuid OR og.grantee_owner_id IN (
            SELECT tm.team_id FROM team_members_b tm WHERE tm.user_id = user_uuid))
    ) sub';
ALTER TABLE docs_a ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs_b ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_a_select ON docs_a FOR SELECT TO PUBLIC
    USING (get_role_a(auth_current_user_id(), owner_id) >= 2);
CREATE POLICY docs_b_select ON docs_b FOR SELECT TO PUBLIC
    USING (get_role_b(auth_current_user_id(), owner_id) >= 2);
",
        &[
            &format!("INSERT INTO users (id) VALUES ('{ALICE}'), ('{BOB}')"),
            &format!("INSERT INTO teams (id) VALUES ('{TEAM}')"),
            // Alice joins the team through function A's table only.
            &format!(
                "INSERT INTO team_members_a (team_id, user_id) VALUES ('{TEAM}', '{ALICE}')"
            ),
            // Bob joins the same team id, but through function B's table only.
            &format!("INSERT INTO team_members_b (team_id, user_id) VALUES ('{TEAM}', '{BOB}')"),
            // Only function B's grant table gives the team viewer access to owner_b.
            &format!(
                "INSERT INTO owner_grants_b (grantee_owner_id, granted_owner_id, role_id) \
                 VALUES ('{TEAM}', '{OWNER_B}', 2)"
            ),
            &format!("INSERT INTO docs_a (id, owner_id) VALUES ('{OWNER_A}', '{OWNER_A}')"),
            &format!("INSERT INTO docs_b (id, owner_id) VALUES ('{OWNER_B}', '{OWNER_B}')"),
            "CREATE ROLE app_reader LOGIN; \
             GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_reader",
        ],
        vec![
            Principal::with_setting(ALICE, "app_reader", "app.current_user_id", ALICE),
            Principal::with_setting(BOB, "app_reader", "app.current_user_id", BOB),
        ],
    )
    .with_registry(
        r#"{
          "get_role_a": {
            "kind": "role_threshold", "user_param_index": 0, "resource_param_index": 1,
            "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
            "grant_table": "owner_grants_a", "grant_grantee_col": "grantee_owner_id",
            "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id",
            "team_membership": {"table": "team_members_a", "user_col": "user_id", "team_col": "team_id"}
          },
          "get_role_b": {
            "kind": "role_threshold", "user_param_index": 0, "resource_param_index": 1,
            "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
            "grant_table": "owner_grants_b", "grant_grantee_col": "grantee_owner_id",
            "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id",
            "team_membership": {"table": "team_members_b", "user_col": "user_id", "team_col": "team_id"}
          },
          "auth_current_user_id": {"kind": "current_user_accessor", "returns": "uuid"}
        }"#,
    );
    let run = support::parity::run(&cluster, &case).await;
    for (subject, object, allowed) in [
        // Alice joined the team only through function A's table, which function B never
        // reads, so function B's grant to the team must not reach her.
        (ALICE, "docs_b:00000000-0000-0000-0000-0000000000b2", false),
        // Bob joined the team only through function B's table, which the grant targets:
        // the legitimate pairing must still work.
        (BOB, "docs_b:00000000-0000-0000-0000-0000000000b2", true),
        // Neither function A's table nor its grant table ever names the team, so neither
        // caller sees docs_a through it.
        (ALICE, "docs_a:00000000-0000-0000-0000-0000000000b1", false),
        (BOB, "docs_a:00000000-0000-0000-0000-0000000000b1", false),
    ] {
        support::parity::assert_postgres(
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

/// A plain read and a temporally-gated read of the same join table through the same
/// foreign key and user column must not pool. An expired member must still pass the
/// plain policy but fail the gated one.
async fn a_plain_and_a_gated_read_of_the_same_join_table_do_not_share_access(
    cluster: Arc<Cluster>,
) {
    let case = ParityCase::reading(
        "runner-plain-and-gated-same-join-table",
        r"
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE members (
    doc_id INT REFERENCES docs(id),
    user_id TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (doc_id, user_id)
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM members m WHERE m.doc_id = docs.id
        AND m.user_id = current_setting('app.user_id', true)));
CREATE POLICY docs_delete ON docs FOR DELETE USING (
    EXISTS (SELECT 1 FROM members m WHERE m.doc_id = docs.id
        AND m.user_id = current_setting('app.user_id', true) AND m.expires_at > now()));
",
        &[
            "INSERT INTO docs (id) VALUES (1);
             INSERT INTO members (doc_id, user_id, expires_at) VALUES
                 (1, 'expired_member', now() - interval '1 day')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT, DELETE ON docs TO app_reader;
             GRANT SELECT ON members TO app_reader",
        ],
        vec![Principal::with_setting(
            "expired_member",
            "app_reader",
            "app.user_id",
            "expired_member",
        )
        .with_clock()],
    );
    let run = support::parity::run(&cluster, &case).await;
    for (statement, allowed) in [
        // The plain policy never checks expiry, so an expired row still satisfies it.
        (ActionStatement::Select, true),
        // The gated policy requires expires_at > now(), which this row no longer meets:
        // the plain source's unconditional tuple must not leak into the gated relation.
        (ActionStatement::Delete, false),
    ] {
        support::parity::assert_postgres(
            &case,
            &run,
            "expired_member",
            "docs:1",
            statement,
            allowed,
        );
    }
    assert_agrees(&case, &run);
}
