//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! The acting roles a `TO` list reaches, the barriers that bind them, and the
//! exemptions the notes report.

use rls2fga::parser::sql_parser::ParserDB;
use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{ActionAnswer, ActionStatement, NoteSeverity, TranslationNote};

use crate::support::deployment::{caller, caller_deployment_acting_as, delimited_set};
use crate::support::footgun::{
    action_answer, assert_model_is_internally_consistent, db_of, relation_definition,
    relation_denies, translator,
};

/// RLS is `(permissive OR ...) AND restrictive AND ...`, so dropping a
/// RESTRICTIVE policy grants access it forbids.
#[test]
fn untranslatable_restrictive_policy_denies_instead_of_widening_access() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_tenant ON docs AS RESTRICTIVE FOR SELECT
  USING (tenant = current_setting('app.tenant'));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains("no_access"),
        "an untranslatable RESTRICTIVE policy must gate can_select, got 'define can_select: {can_select}'\n{}",
        model.model()
    );
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.subject() == "docs_tenant"),
        "the dropped RESTRICTIVE policy must be reported, got: {:#?}",
        model.notes()
    );
}

/// `sql` translated for a deployment acting as `acting_roles`.
fn translate_for(acting_roles: &[&str], db: &ParserDB) -> Outputs {
    TranslatorBuilder::new(caller_deployment_acting_as(acting_roles, []))
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
}

/// One permissive read plus a barrier only `contractor` is subject to.
const ROLE_SCOPED_BARRIER: &str = r"
CREATE ROLE contractor NOLOGIN;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_setting('app.user_id', true));
";

/// A RESTRICTIVE policy reaches only the acting roles its `TO` list names, so a
/// deployment acting as a role outside the list keeps whatever the permissive
/// policies grant.
#[test]
fn a_role_scoped_restrictive_policy_leaves_other_roles_unconstrained() {
    let model = translate_for(&["app_user", "contractor"], &db_of(ROLE_SCOPED_BARRIER)).model();
    let can_select =
        relation_definition(&model, "docs", "can_select").expect("docs should define can_select");
    assert_eq!(
        can_select,
        "(owner and acting_app_user from request_gate) \
         or (owner and reviewer and acting_contractor from request_gate)",
        "the barrier reaches the contractor branch alone, and the app_user branch \
         keeps the permissive grant:\n{model}"
    );
}

/// A barrier reaches the JSON model as a conjunct of the branch its `TO` list names,
/// which `OpenFGA` validates like any other userset.
#[test]
fn a_role_scoped_barrier_emits_a_consistent_json_model() {
    let outputs = translate_for(&["app_user", "contractor"], &db_of(ROLE_SCOPED_BARRIER));
    let json = outputs.json_model();

    assert_model_is_internally_consistent(&json);
    assert_eq!(
        relation_definition(&outputs.model(), "docs", "reviewer").as_deref(),
        Some("[user]"),
        "the barrier's clause must survive as a relation of the table:\n{}",
        outputs.model()
    );
    let serialized = serde_json::to_string(&json).expect("model should serialize");
    assert!(
        serialized.contains("acting_contractor"),
        "the barrier's branch must survive into the JSON model, got:\n{serialized}"
    );
}

/// Two barriers name two roles, so each binds the branch its `TO` list names and
/// neither crosses into the other's branch.
#[test]
fn two_role_scoped_barriers_each_bind_their_own_role() {
    let db = db_of(
        r"
CREATE ROLE contractor NOLOGIN;
CREATE ROLE auditor NOLOGIN;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID, approver_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_setting('app.user_id', true));
CREATE POLICY docs_approve ON docs AS RESTRICTIVE FOR SELECT TO auditor
  USING (approver_id = current_setting('app.user_id', true));
",
    );
    let model = translate_for(&["contractor", "auditor"], &db).model();
    let can_select =
        relation_definition(&model, "docs", "can_select").expect("docs should define can_select");
    assert_eq!(
        can_select,
        "(owner and reviewer and acting_contractor from request_gate) \
         or (owner and approver and acting_auditor from request_gate)",
        "each barrier binds its own branch:\n{model}"
    );
}

/// Changing a row needs it readable, and a barrier can take that readability away, so
/// the read gate stays even when the rule sits behind one.
#[test]
fn a_write_behind_a_barrier_keeps_its_read_gate() {
    let db = db_of(
        r"
CREATE ROLE contractor NOLOGIN;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_edit ON docs FOR UPDATE USING (editor_id = current_setting('app.user_id', true));
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR ALL TO contractor
  USING (reviewer_id = current_setting('app.user_id', true));
",
    );
    let dsl = translate_for(&["contractor"], &db).model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner and reviewer and acting_contractor from request_gate"),
        "the barrier narrows the read the update depends on:\n{dsl}"
    );
    let can_update =
        relation_definition(&dsl, "docs", "can_update").expect("docs should define can_update");
    assert!(
        can_update.contains("can_select"),
        "an editor who cannot read the row cannot change it, got '{can_update}':\n{dsl}"
    );
}

/// A barrier over an inherited rule holds a reference the alias passes rewrite, so a
/// pass that skips one side leaves the model dangling.
#[test]
fn a_barrier_over_an_inherited_rule_keeps_its_references() {
    let db = db_of(
        r"
CREATE ROLE contractor NOLOGIN;
CREATE TABLE parents(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE parents ENABLE ROW LEVEL SECURITY;
CREATE POLICY parents_own ON parents FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES parents(id), reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_inherit ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM parents p WHERE p.id = docs.parent_id AND p.owner_id = current_setting('app.user_id', true)));
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_setting('app.user_id', true));
",
    );
    let outputs = translate_for(&["app_user", "contractor"], &db);
    assert_eq!(
        relation_definition(&outputs.model(), "docs", "reviewer").as_deref(),
        Some("[user]"),
        "the barrier branch keeps its clause beside the inherited grant:\n{}",
        outputs.model()
    );
    assert_model_is_internally_consistent(&outputs.json_model());
}

/// An unscoped RESTRICTIVE policy binds everyone, so nothing is subtracted.
#[test]
fn an_unscoped_restrictive_policy_binds_every_role() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT
  USING (reviewer_id = current_setting('app.user_id', true));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert!(
        !model.model().contains("but not"),
        "a barrier every role is subject to needs no exclusion:\n{}",
        model.model()
    );
    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains(" and "),
        "the barrier stays a conjunct, got '{can_select}':\n{}",
        model.model()
    );
}

/// Permissive read policies are an OR per acting role, so a deployment whose acting
/// roles each read the membership table through their own policy gets the grant in
/// every branch.
#[test]
fn membership_readable_by_two_roles_admits_either_role() {
    let sql = r"
CREATE ROLE auditor NOLOGIN;
CREATE ROLE support NOLOGIN;
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_audit ON doc_members FOR SELECT TO auditor USING (true);
CREATE POLICY dm_support ON doc_members FOR SELECT TO support USING (true);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id', true)));
";
    let model = translate_for(&["auditor", "support"], &db_of(sql)).model();
    let can_select =
        relation_definition(&model, "docs", "can_select").expect("docs should define can_select");
    for role in ["auditor", "support"] {
        assert!(
            can_select.contains(&format!("and acting_{role} from request_gate")),
            "either role can read the membership rows, so {role} needs its own branch: \
             '{can_select}':\n{model}"
        );
    }
    assert_eq!(
        can_select.matches(" from docs").count(),
        2,
        "both branches walk the same membership relation, got '{can_select}':\n{model}"
    );
}

/// A membership read cap restricted to `anon`.
const CAPPED_FOR_ANON: &str = r"
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE TABLE members (doc_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (doc_id, user_id));
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_open ON members FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY members_cap ON members AS RESTRICTIVE FOR SELECT TO anon
  USING ('members:read' = ANY(string_to_array(current_setting('app.read_caps', true), ',')));
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY shared ON docs FOR SELECT
  USING (id IN (SELECT doc_id FROM members WHERE user_id = current_setting('app.user_id', true)));
";

/// Translate the membership cap for the deployment's acting roles.
fn translate_capped(acting_roles: &[&str], sql: &str) -> Outputs {
    TranslatorBuilder::new(caller_deployment_acting_as(
        acting_roles,
        [caller("app.user_id"), delimited_set("app.read_caps", ",")],
    ))
    .with_min_confidence(ConfidenceLevel::B)
    .build()
    .translate(&db_of(sql))
    .expect("translation should plan")
    .outputs_accepting_gaps()
}

/// A membership cap outside every acting role leaves the table open.
#[test]
fn a_membership_read_cap_no_caller_role_runs_under_leaves_the_table_open() {
    let outputs = translate_capped(&["authenticated"], CAPPED_FOR_ANON);
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "the cap reaches no acting role, so nothing may be refused or guarded: {:#?}",
        outputs.notes()
    );
    let unguarded = translate_capped(
        &["authenticated"],
        &CAPPED_FOR_ANON.replace("ALTER TABLE members ENABLE ROW LEVEL SECURITY;", ""),
    );
    assert_eq!(
        relation_definition(&outputs.model(), "docs", "can_select"),
        relation_definition(&unguarded.model(), "docs", "can_select"),
        "the branch outside the cap must read the membership table as open:\n{}",
        outputs.model()
    );
}

/// A membership cap constrains `anon` while another acting role retains its reads.
#[cfg(all(not(target_os = "windows"), feature = "client"))]
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_membership_read_cap_some_caller_roles_run_under_keeps_the_table_guarded() {
    use crate::support::parity::{
        assert_agrees, assert_postgres, run, Cluster, ParityCase, Principal,
    };
    use rls2fga::types::ActionStatement;

    let cluster = Cluster::start().await;
    let mut permitted = Principal::with_setting("carol", "anon", "app.user_id", "carol")
        .with_context(serde_json::json!({"app_read_caps": ["members:read"]}));
    permitted
        .session
        .push(("app.read_caps".into(), "members:read".into()));
    let case = ParityCase::reading(
        "membership-cap-by-acting-role",
        CAPPED_FOR_ANON,
        &["GRANT SELECT ON docs, members TO anon, authenticated;
             INSERT INTO docs VALUES ('d1'), ('d2');
             INSERT INTO members VALUES ('d1', 'alice'), ('d2', 'alice'), ('d1', 'bob'), ('d1', 'carol')"],
        vec![
            Principal::with_setting("alice", "anon", "app.user_id", "alice")
                .with_context(serde_json::json!({"app_read_caps": []})),
            Principal::with_setting("bob", "authenticated", "app.user_id", "bob")
                .with_context(serde_json::json!({"app_read_caps": []})),
            permitted,
        ],
    )
    .with_settings([delimited_set("app.read_caps", ",")]);
    let result = run(&cluster, &case).await;
    for (subject, object, visible) in [
        ("alice", "docs:d1", false),
        ("alice", "docs:d2", false),
        ("bob", "docs:d1", true),
        ("bob", "docs:d2", false),
        ("carol", "docs:d1", true),
        ("carol", "docs:d2", false),
    ] {
        assert_postgres(
            &case,
            &result,
            subject,
            object,
            ActionStatement::Select,
            visible,
        );
    }
    assert_agrees(&case, &result);
}

/// A policy the schema gives no clause constrains nothing, so it must not leave a
/// relation nothing can read, or a tuple loading a role fact nothing consults.
#[test]
fn a_clauseless_policy_mints_no_role_scope() {
    let db = db_of(
        r"
CREATE ROLE auditor NOLOGIN;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR ALL TO auditor;
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let model = outputs.model();

    assert_eq!(
        relation_definition(&model, "docs", "can_select").as_deref(),
        Some("owner and acting_app_user from request_gate"),
        "the clauseless barrier reaches no acting role, and it would subtract \
         nothing anyway:\n{model}"
    );
    assert!(
        !outputs
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains("pg_role:auditor")),
        "no tuple may load a role fact nothing reads, got: {:#?}",
        outputs
            .tuple_queries()
            .iter()
            .map(|query| &query.sql)
            .collect::<Vec<_>>()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("inheriting members")),
        "asking for facts nothing consults is noise: {:#?}",
        outputs.notes()
    );
}

/// A RESTRICTIVE `UPDATE` policy storing a `USING` binds the existing row, and
/// `PostgreSQL` mirrors that clause onto the new row as well, so both halves of the
/// update carry it and a locking read is narrowed too.
#[test]
fn a_restrictive_update_barrier_binds_both_halves_of_the_update() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_setting('app.user_id', true))
  WITH CHECK (editor_id = current_setting('app.user_id', true));
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR UPDATE USING (reviewer_id = current_setting('app.user_id', true));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    for relation in ["can_update_using", "can_update_check"] {
        let definition = relation_definition(&dsl, "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{dsl}"));
        assert!(
            definition.contains("reviewer"),
            "the barrier binds {relation}, got 'define {relation}: {definition}'"
        );
    }
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select_for_update").as_deref(),
        Some("can_update_using"),
        "and a locking read carries it through the USING half:\n{dsl}"
    );
}

/// An acting role the database exempts from row level security holds more than the
/// model's policies say, and the note is the only channel that says so. Staying
/// silent is what makes an exempt service account look constrained.
#[test]
fn a_role_that_bypasses_row_level_security_is_reported() {
    let schema = "CREATE ROLE reporting BYPASSRLS;\n\
                  CREATE ROLE plain_user NOLOGIN;\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  ALTER TABLE docs FORCE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));\n";
    let outputs = translate_for(&["reporting", "plain_user"], &db_of(schema));

    let exempt: Vec<&TranslationNote> = outputs
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ActingRoleExempt { reason, .. } if reason == "the role has BYPASSRLS"))
        .collect();
    assert_eq!(
        exempt.len(),
        1,
        "one role bypasses, got {:#?}",
        outputs.notes()
    );
    let TranslationNote::ActingRoleExempt { role, .. } = exempt[0] else {
        unreachable!("filtered above")
    };
    assert_eq!(
        role.as_str(),
        "reporting",
        "the report has to name the role: {:#?}",
        outputs.notes()
    );
    // The model still describes the rules the bypassed policies give up.
    assert!(
        outputs
            .model()
            .contains("owner and acting_plain_user from request_gate"),
        "the policy still translates for the role that meets it:\n{}",
        outputs.model()
    );
}

/// The messages of the exemption notes translating `sql` produces.
fn exempt_notes(sql: &str) -> Vec<String> {
    translator(ConfidenceLevel::B)
        .translate(&db_of(sql))
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ActingRoleExempt { .. }))
        .map(TranslationNote::message)
        .collect()
}

/// An acting role that owns a table without `FORCE ROW LEVEL SECURITY` is exempt from
/// every policy on it, so the model is wider than the database for them. With it, the
/// policies hold.
#[test]
fn a_table_that_does_not_force_row_level_security_is_reported() {
    let schema = |force: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
             ALTER TABLE docs OWNER TO app_user;\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             {force}\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));\n"
        )
    };
    let unforced = exempt_notes(&schema(""));
    assert_eq!(
        unforced.len(),
        1,
        "the owner bypass is a finding: {unforced:?}"
    );
    assert!(
        unforced[0].contains("app_user") && unforced[0].contains("docs"),
        "and it names the role and the table: {unforced:?}"
    );

    let forced = exempt_notes(&schema("ALTER TABLE docs FORCE ROW LEVEL SECURITY;\n"));
    assert!(
        forced.is_empty(),
        "FORCE removes the owner bypass, so there is nothing to report: {forced:?}"
    );
}

/// The exempt role is the acting role itself, so the note names the account the
/// application connects as, when the schema says who owns the table.
#[test]
fn the_exempt_table_owner_is_named_when_the_schema_says_who_it_is() {
    let owned = "CREATE ROLE app_owner NOLOGIN;\n\
                 CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                 ALTER TABLE docs OWNER TO app_owner;\n\
                 ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                 CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));\n";
    let outputs = translate_for(&["app_owner"], &db_of(owned));
    let named: Vec<&TranslationNote> = outputs
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ActingRoleExempt { .. }))
        .collect();
    let [note] = named.as_slice() else {
        panic!("one table, one owner bypass: {:#?}", outputs.notes())
    };
    let TranslationNote::ActingRoleExempt { role, .. } = note else {
        unreachable!("filtered above")
    };
    assert_eq!(
        role.as_str(),
        "app_owner",
        "the exempt role has a name, so the note uses it: {:#?}",
        outputs.notes()
    );

    // A schema that never says who owns the table exempts no acting role, so there is
    // nothing to report.
    let unowned = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));\n";
    let anonymous = exempt_notes(unowned);
    assert!(
        anonymous.is_empty(),
        "with no owner recorded, no acting role is exempt: {anonymous:?}"
    );
}

/// A barrier naming a role the schema never creates cannot be settled, so it binds
/// everyone by refusing the statement rather than excusing anyone. Denying more than
/// RLS is safe, granting more is not.
#[test]
fn a_barrier_role_the_schema_never_creates_binds_everyone() {
    let db = db_of(
        r"
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id UUID, secret BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT TO contractor
    USING (secret = false);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert!(
        relation_denies(&dsl, "docs", "can_select"),
        "nothing may be excused from a barrier whose role cannot be settled:\n{dsl}"
    );
    let note = outputs.notes().iter().find(|note| {
        matches!(
            note,
            TranslationNote::RowSecurityRefused { reason, .. }
                if reason.contains("contractor")
        )
    });
    assert!(
        note.is_some(),
        "the refusal must name the role the schema cannot settle: {:#?}",
        outputs.notes()
    );
    let note = note.expect("checked above");
    assert!(
        note.to_string().contains("docs_bar"),
        "and the barrier that caused it: {note}"
    );
    assert_eq!(
        note.severity(),
        NoteSeverity::Unhandled,
        "the model denies what the created policy would grant, which has to block \
         the outputs"
    );
}

/// A barrier naming a role the schema creates binds exactly the acting roles the role
/// reaches, and leaves the other branches alone, which is what `PostgreSQL` does.
#[test]
fn a_created_barrier_role_binds_only_its_own_branch() {
    let db = db_of(
        r"
CREATE ROLE contractor NOLOGIN;
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id UUID, secret BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT TO contractor
    USING (secret = false);
",
    );
    let model = translate_for(&["app_user", "contractor"], &db).model();
    let can_select =
        relation_definition(&model, "docs", "can_select").expect("docs should define can_select");
    assert!(
        can_select.contains("acting_app_user from request_gate"),
        "the other branch keeps the grant the barrier never saw:\n{model}"
    );
    let contractor_branch = can_select
        .split(" or ")
        .find(|branch| branch.contains("acting_contractor from request_gate"))
        .expect("the contractor branch is missing:\n{model}");
    assert!(
        contractor_branch.contains("owner and ")
            && contractor_branch
                .replace("owner and ", "")
                .contains(" and acting_contractor from request_gate"),
        "the barrier joins its own clause into the contractor branch, got \
         '{contractor_branch}':\n{model}"
    );
}

/// `PostgreSQL` applies a `TO role` clause with `has_privs_of_role` semantics: an
/// inheriting member of the role is admitted, a `NOINHERIT` member and a
/// `GRANT ... WITH INHERIT FALSE` grantee are not, while `pg_has_role(.., 'MEMBER')`
/// holds for all three. Probed on 18.4: `USING (true) TO editors` over three rows
/// answers 3 to the inheriting member and 0 to the other two. So a `TO` list reaches
/// exactly the acting roles that inherit the role, and never the plain members.
#[test]
fn a_to_scoped_policy_walks_usage_not_member() {
    let db = db_of(
        r"
CREATE ROLE editors NOLOGIN;
CREATE ROLE member NOLOGIN;
CREATE ROLE nomember NOLOGIN;
GRANT editors TO member;
GRANT editors TO nomember WITH INHERIT FALSE;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO editors USING (owner_id = current_setting('app.user_id', true));
",
    );
    let dsl = translate_for(&["member", "nomember"], &db).model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner and acting_member from request_gate"),
        "the TO list reaches the inheriting member alone, which is the usage kind: \
         {dsl}"
    );
    assert!(
        !dsl.contains("acting_nomember"),
        "a non-inheriting member admits nothing the grant can name:\n{dsl}"
    );
}

/// The RESTRICTIVE fold excuses everyone outside the bound roles, and `PostgreSQL`
/// draws that line with `has_privs_of_role` too. Probed on 18.4: a barrier
/// `TO editors` binds the inheriting member (1 of 3 rows) and leaves the `NOINHERIT`
/// member alone (3 of 3). So a barrier reaches exactly the acting roles that
/// inherit its `TO` roles.
#[test]
fn a_to_scoped_barrier_excuses_by_usage_not_membership() {
    let db = db_of(
        r"
CREATE ROLE editors NOLOGIN;
CREATE ROLE member NOLOGIN;
CREATE ROLE nomember NOLOGIN;
GRANT editors TO member;
GRANT editors TO nomember WITH INHERIT FALSE;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (true);
CREATE POLICY r ON docs AS RESTRICTIVE FOR SELECT TO editors USING (owner_id = current_setting('app.user_id', true));
",
    );
    let dsl = translate_for(&["member", "nomember"], &db).model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some(
            "(public_viewer and owner and acting_member from request_gate) \
              or (public_viewer and acting_nomember from request_gate)"
        ),
        "the barrier binds the inheriting member's branch alone, and excusing by \
         plain membership would bind the branch PostgreSQL leaves open:\n{dsl}"
    );
}

/// A membership table readable only by named roles grants through it to exactly the
/// acting roles that read it, and a branch whose role cannot read the table gets no
/// grant at all, the way `PostgreSQL` leaves the subquery empty for it.
#[test]
fn a_membership_read_scope_walks_usage() {
    let db = db_of(
        r"
CREATE ROLE auditor NOLOGIN;
CREATE ROLE plain NOLOGIN;
CREATE TABLE users(id TEXT PRIMARY KEY);
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES docs(id),
    user_id TEXT NOT NULL REFERENCES users(id)
);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY m ON doc_members FOR SELECT TO auditor USING (true);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_setting('app.user_id', true))
);
",
    );
    let outputs = translate_for(&["auditor", "plain"], &db);
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
    assert!(
        can_select.contains("and acting_auditor from request_gate"),
        "only the roles that may read memberships inherit the grant:\n{dsl}"
    );
    assert!(
        can_select.contains("no_access and acting_plain from request_gate"),
        "a role that cannot read the membership table gets no grant through it: \
         {dsl}"
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGrantsNoReads { policy, .. } if policy == "p"
        )),
        "the unreadable branch is disclosed: {:#?}",
        outputs.notes()
    );
}

/// `PostgreSQL` resolves `TO CURRENT_USER`, `TO CURRENT_ROLE` and `TO SESSION_USER`
/// to the role executing `CREATE POLICY` (probed on 18.4: `pg_policies.roles` stores
/// `{postgres}`, or `{app_admin}` under `SET ROLE app_admin`), so the symbolic form
/// never reaches a dump and a schema file cannot know the role. Minting a
/// `pg_role:current_user` object asks the operator to populate a role that does not
/// exist, so the spelling is refused instead: a permissive policy falls closed.
#[test]
fn a_pseudo_role_scope_is_refused_not_minted() {
    for spelling in ["CURRENT_USER", "CURRENT_ROLE", "SESSION_USER"] {
        let db = db_of(&format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO {spelling} USING (owner_id = current_setting('app.user_id', true));
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        assert!(
            relation_denies(&dsl, "docs", "can_select"),
            "`TO {spelling}` binds a role the schema cannot name, so the grant falls \
             closed:\n{dsl}"
        );
        assert!(
            !outputs
                .tuple_queries()
                .iter()
                .any(|q| q.sql.contains("pg_role:")),
            "no tuple may name a pseudo-role object (`TO {spelling}`), got: {:#?}",
            outputs
                .tuple_queries()
                .iter()
                .map(|q| &q.sql)
                .collect::<Vec<_>>()
        );
        let note = outputs.notes().iter().find(|note| {
            matches!(
                note,
                TranslationNote::RowSecurityRefused { reason, .. }
                    if reason.contains(spelling)
            )
        });
        assert!(
            note.is_some(),
            "the refusal must name the spelling (`TO {spelling}`), got: {:#?}",
            outputs.notes()
        );
        assert_eq!(
            note.map(TranslationNote::severity),
            Some(NoteSeverity::Unhandled),
            "the model denies what the created policy would grant, which has to block \
             the outputs (`TO {spelling}`)"
        );
    }
}

/// The restrictive direction is the over-grant: probed on 18.4, a `LOGIN` owner under
/// `FORCE ROW LEVEL SECURITY` creating `AS RESTRICTIVE ... TO CURRENT_USER` sees 1 of
/// 2 rows. An unknowable scope cannot be narrowed to anyone, so the statement is
/// refused for the acting role it would decide, named roles beside it included,
/// since a barrier that also binds the DDL runner cannot be split into the names.
#[test]
fn a_pseudo_role_barrier_binds_everyone() {
    for to_clause in ["CURRENT_USER", "editors, CURRENT_USER"] {
        let db = db_of(&format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (true);
CREATE POLICY r ON docs AS RESTRICTIVE FOR SELECT TO {to_clause} USING (owner_id = current_setting('app.user_id', true));
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        assert!(
            relation_denies(&dsl, "docs", "can_select"),
            "an unfillable scope must not excuse anyone (`TO {to_clause}`):\n{dsl}"
        );
        assert!(
            !dsl.contains("but not"),
            "a refused statement subtracts nothing (`TO {to_clause}`):\n{dsl}"
        );
        assert!(
            !outputs
                .tuple_queries()
                .iter()
                .any(|q| q.sql.contains("pg_role:")),
            "no tuple may name a pseudo-role object (`TO {to_clause}`), got: {:#?}",
            outputs
                .tuple_queries()
                .iter()
                .map(|q| &q.sql)
                .collect::<Vec<_>>()
        );
        // The schema settles the list left to right, so the refusal names the first
        // spelling it cannot: the pseudo-role alone, or the created role beside it.
        let named = to_clause
            .split(',')
            .next()
            .expect("the clause names at least one role")
            .trim();
        let note = outputs.notes().iter().find(|note| {
            matches!(
                note,
                TranslationNote::RowSecurityRefused { reason, .. } if reason.contains(named)
            )
        });
        assert!(
            note.is_some(),
            "the refusal must name the spelling it settles on (`TO {to_clause}`), got: \
             {:#?}",
            outputs.notes()
        );
        assert_eq!(
            note.map(TranslationNote::severity),
            Some(NoteSeverity::Unhandled),
            "the model denies what the created policy would grant, which has to block \
             the outputs (`TO {to_clause}`)"
        );
    }
}

/// A permissive policy the threshold empties is retained through the filter, so
/// the generator can say what was lost. Retaining it must not resurrect its side
/// effects: registration runs before translation, so a policy contributing no
/// expression would otherwise still ask for `pg_role` facts that nothing consults.
#[test]
fn a_policy_the_threshold_emptied_mints_no_scope_relation() {
    let db = db_of(
        "CREATE ROLE auditor;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_scoped ON docs FOR SELECT TO auditor USING (opaque_gate(id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert!(
        !dsl.contains("scope_"),
        "the emptied policy contributes no expression, so nothing may reference a \
         scope relation for it:\n{dsl}"
    );
    assert!(
        !outputs
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains("pg_role:auditor")),
        "and no tuple may load a role fact the emptied policy leaves unread, got: \
         {:#?}",
        outputs
            .tuple_queries()
            .iter()
            .map(|query| &query.sql)
            .collect::<Vec<_>>()
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ClauseBelowThreshold { policy, .. } if policy == "docs_scoped"
        )),
        "but the loss itself is still reported: {:?}",
        outputs.notes()
    );
}

/// A `PostgreSQL` policy name is unique per table, so two tables may share a policy
/// name with different rules. The `TO` lists decide per acting role, so each table
/// reaches exactly the branch of its own role and no other.
#[test]
fn two_tables_with_a_same_named_policy_do_not_pool_their_role_scopes() {
    let db = db_of(
        r"
CREATE ROLE auditor;
CREATE ROLE support;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
CREATE TABLE public.memos(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO auditor USING (TRUE);
CREATE POLICY p ON memos FOR SELECT TO support USING (TRUE);
",
    );
    let model = translate_for(&["auditor", "support"], &db).model();

    assert_eq!(
        relation_definition(&model, "docs", "can_select").as_deref(),
        Some("public_viewer and acting_auditor from request_gate"),
        "docs is scoped TO auditor alone:\n{model}"
    );
    assert_eq!(
        relation_definition(&model, "memos", "can_select").as_deref(),
        Some("public_viewer and acting_support from request_gate"),
        "memos is scoped TO support alone, so support must not reach its rows and \
         auditor must not reach docs':\n{model}"
    );
}

#[test]
fn quoted_and_unquoted_roles_keep_distinct_scope_identities() {
    let db = db_of(
        r#"
CREATE ROLE admin;
CREATE ROLE "Admin";
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
CREATE TABLE public.memos(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO admin USING (TRUE);
CREATE POLICY p ON memos FOR SELECT TO "Admin" USING (TRUE);
"#,
    );
    let outputs = translate_for(&["admin", "Admin"], &db);
    let dsl = outputs.model();

    let docs_read =
        relation_definition(&dsl, "docs", "can_select").expect("docs should define can_select");
    let memos_read =
        relation_definition(&dsl, "memos", "can_select").expect("memos should define can_select");
    assert_eq!(
        docs_read, "public_viewer and acting_admin from request_gate",
        "docs is scoped TO admin alone:\n{dsl}"
    );
    assert_ne!(
        memos_read, docs_read,
        "memos is scoped TO \"Admin\", a distinct identity from admin:\n{dsl}"
    );
    assert!(
        outputs
            .tuple_queries()
            .iter()
            .any(|q| q.sql.contains("'pg_role:Admin'")),
        "the quoted role keeps its own kind tuples, got: {:#?}",
        outputs
            .tuple_queries()
            .iter()
            .map(|q| &q.sql)
            .collect::<Vec<_>>()
    );
    assert!(outputs
        .notes()
        .iter()
        .all(|note| !note.message().contains("role") || !note.message().contains("rewritten")));
}

/// A `pg_has_role` gate asks about roles the schema creates, so the schema's
/// memberships answer it per acting role. One that answers yes is a constant the
/// classifier folds away, and the `TO` clause alone decides which branch the grant
/// reaches.
#[test]
fn a_role_gate_the_schema_answers_yes_keeps_only_the_to_scope() {
    let db = db_of(
        r"
CREATE ROLE editor;
GRANT editor TO app_user;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO editor USING (pg_has_role('editor', 'MEMBER'));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        action_answer(&outputs, "docs", ActionStatement::Select),
        Some(&ActionAnswer::Unrestricted),
        "the gate is a constant the schema answers, so the TO clause alone decides"
    );
    assert!(
        !outputs
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains("pg_role:editor")),
        "nothing may load a role fact the gate folded away, got: {:#?}",
        outputs
            .tuple_queries()
            .iter()
            .map(|query| &query.sql)
            .collect::<Vec<_>>()
    );

    // The same gate answered no keeps the no.
    let denied = db_of(
        r"
CREATE ROLE editor;
GRANT editor TO app_user;
CREATE ROLE outsider;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO editor USING (pg_has_role('outsider', 'MEMBER'));
",
    );
    let denied_dsl = translator(ConfidenceLevel::B)
        .translate(&denied)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert!(
        relation_denies(&denied_dsl, "docs", "can_select"),
        "a grant the gate denies has to stay a denial:\n{denied_dsl}"
    );
}

/// Two gates joined by `AND` are two constants the schema's memberships answer, so the
/// conjunction admits exactly where the acting role is a member of both. A grant missing
/// on either side is a no the conjunction has to keep.
#[test]
fn two_role_gates_joined_by_and_answer_as_their_conjunction() {
    let schema = |grants: &str| {
        format!(
            r"
CREATE ROLE alpha;
CREATE ROLE beta;
{grants}
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (pg_has_role('alpha', 'MEMBER') AND pg_has_role('beta', 'MEMBER'));
"
        )
    };

    let outputs = translator(ConfidenceLevel::B)
        .translate(&db_of(&schema(
            "GRANT alpha TO app_user;\nGRANT beta TO app_user;\n",
        )))
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert!(
        !relation_denies(&dsl, "docs", "can_select"),
        "the schema grants both roles to the acting one, so the conjunction admits:\n{dsl}"
    );

    let one = translator(ConfidenceLevel::B)
        .translate(&db_of(&schema("GRANT alpha TO app_user;\n")))
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = one.model();
    assert!(
        relation_denies(&dsl, "docs", "can_select"),
        "the missing grant is a no the conjunction has to keep:\n{dsl}"
    );
}
