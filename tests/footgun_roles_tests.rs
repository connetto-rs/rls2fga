//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Role scopes, restrictive barriers, and the principals a policy binds.

use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{NoteSeverity, TranslationNote};

mod support;

use support::footgun::{
    assert_model_is_internally_consistent, db_of, pg_role_relation, relation_definition,
    relation_definitions, relation_denies, scope_admits_role, translator, type_names,
};

/// RLS is `(permissive OR ...) AND restrictive AND ...`, so dropping a
/// RESTRICTIVE policy grants access it forbids.
#[test]
fn untranslatable_restrictive_policy_denies_instead_of_widening_access() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
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

/// One permissive read plus a barrier only `contractor` is subject to.
const ROLE_SCOPED_BARRIER: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
";

/// A RESTRICTIVE policy binds only the roles it names, so a user outside them keeps
/// whatever the permissive policies grant.
#[test]
fn a_role_scoped_restrictive_policy_leaves_other_roles_unconstrained() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "the contractor scope must reach the model:\n{}",
            model.model()
        )
    });
    let limited = relation_definition(&model.model(), "docs", "can_select")
        .and_then(|can_select| {
            relation_definition(&model.model(), "docs", can_select.trim()).or(Some(can_select))
        })
        .expect("docs should define can_select");
    assert!(
        limited.contains(&format!("but not usage from {scope}")),
        "a user outside the role's inherited privileges must keep the grant, got \
         '{limited}':\n{}",
        model.model()
    );
}

/// The subtracted side of a barrier is consulted like any other, so its tuples must
/// survive the reachability filter. Without them the barrier subtracts nobody and the
/// bound role keeps the access it forbids.
#[test]
fn a_role_scoped_barrier_keeps_the_tuples_it_subtracts() {
    let sql = ROLE_SCOPED_BARRIER;
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::B);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "the contractor scope must reach the model:\n{}",
            model.model()
        )
    });

    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();
    assert!(
        scope_admits_role(tuples, "docs:", &scope, "contractor"),
        "the subtracted role needs its tuples, got: {:#?}",
        tuples.iter().map(|query| &query.sql).collect::<Vec<_>>()
    );
}

/// A barrier reaches the JSON model as a `difference` node, which `OpenFGA` validates
/// like any other userset.
#[test]
fn a_role_scoped_barrier_emits_a_consistent_json_model() {
    let db = db_of(ROLE_SCOPED_BARRIER);
    let json = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();

    assert_model_is_internally_consistent(&json);
    let serialized = serde_json::to_string(&json).expect("model should serialize");
    assert!(
        serialized.contains(r#""difference""#),
        "the barrier must survive into the JSON model, got:\n{serialized}"
    );
}

/// Two barriers bind two roles, so each wraps the result of the one before it rather
/// than replacing it.
#[test]
fn two_role_scoped_barriers_each_bind_their_own_role() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID, approver_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
CREATE POLICY docs_approve ON docs AS RESTRICTIVE FOR SELECT TO auditor
  USING (approver_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let limits: Vec<String> = model
        .model()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("define limit_"))
        .filter_map(|rest| rest.split_once(':'))
        .map(|(name, _)| format!("limit_{name}"))
        .collect();
    let [first, second] = limits.as_slice() else {
        panic!(
            "each barrier needs its own relation, got {limits:?}:\n{}",
            model.model()
        );
    };

    let outer = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    let (outer, inner) = if outer.trim() == *second {
        (second, first)
    } else {
        (first, second)
    };
    let outer_body = relation_definition(&model.model(), "docs", outer)
        .unwrap_or_else(|| panic!("{outer} should be defined:\n{}", model.model()));
    assert_eq!(
        outer_body.matches(inner.as_str()).count(),
        2,
        "the outer barrier applies to both sides of the inner one, got '{outer_body}':\n{}",
        model.model()
    );
    assert_eq!(
        model.model().matches("but not").count(),
        2,
        "each barrier subtracts its own role:\n{}",
        model.model()
    );
}

/// Changing a row needs it readable, and a barrier can take that readability away, so
/// the read gate stays even when the rule sits behind one.
#[test]
fn a_write_behind_a_barrier_keeps_its_read_gate() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_edit ON docs FOR UPDATE USING (editor_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR ALL TO contractor
  USING (reviewer_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let can_update_using = relation_definition(&model.model(), "docs", "can_update_using")
        .or_else(|| relation_definition(&model.model(), "docs", "can_update"))
        .expect("docs should define the update phase");
    assert!(
        can_update_using.contains("can_select"),
        "an editor who cannot read the row cannot change it, got '{can_update_using}':\n{}",
        model.model()
    );
}

/// A barrier over an inherited rule holds a reference the alias passes rewrite, so a
/// pass that skips one side leaves the model dangling.
#[test]
fn a_barrier_over_an_inherited_rule_keeps_its_references() {
    let db = db_of(
        r"
CREATE TABLE parents(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE parents ENABLE ROW LEVEL SECURITY;
CREATE POLICY parents_own ON parents FOR SELECT USING (owner_id = current_user);
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES parents(id), reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_inherit ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM parents p WHERE p.id = docs.parent_id AND p.owner_id = current_user));
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (reviewer_id = current_user);
",
    );
    let json = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();

    assert_model_is_internally_consistent(&json);
}

/// An unscoped RESTRICTIVE policy binds everyone, so nothing is subtracted.
#[test]
fn an_unscoped_restrictive_policy_binds_every_role() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_review ON docs AS RESTRICTIVE FOR SELECT
  USING (reviewer_id = current_user);
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

/// Permissive read policies are an OR, so being in either role is enough.
#[test]
fn membership_readable_by_two_roles_admits_either_role() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_audit ON doc_members FOR SELECT TO auditor USING (true);
CREATE POLICY dm_support ON doc_members FOR SELECT TO support USING (true);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
";
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::B);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "docs must scope the membership grant by role:\n{}",
            model.model()
        )
    });
    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();
    for role in ["auditor", "support"] {
        assert!(
            scope_admits_role(tuples, "docs:", &scope, role),
            "either role can read the membership rows, so {role} needs scope tuples, got: {:#?}",
            tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
        );
    }
}

/// A policy the schema gives no clause constrains nothing, so it must not mint a
/// role scope relation, a `pg_role` type, or a note asking for memberships that
/// nothing consults.
#[test]
fn a_clauseless_policy_mints_no_role_scope() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR ALL TO auditor;
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        pg_role_relation(&model.model(), "docs"),
        None,
        "the barrier stores no clause, so it binds nothing:\n{}",
        model.model()
    );
    assert!(
        !type_names(&model.model())
            .iter()
            .any(|name| name == "pg_role"),
        "no relation reads a role here:\n{}",
        model.model()
    );
    assert!(
        !model
            .notes()
            .iter()
            .any(|note| note.message().contains("inheriting members")),
        "asking for tuples nothing consults is noise: {:#?}",
        model.notes()
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
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user)
  WITH CHECK (editor_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR UPDATE USING (reviewer_id = current_user);
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

/// A role the database exempts from row level security holds more than the model says,
/// and the model cannot say otherwise: it describes the rules, and the bypass is the
/// absence of them. Reporting it is the only honest option, and staying silent is what
/// makes an exempt service account look constrained.
#[test]
fn a_role_that_bypasses_row_level_security_is_reported() {
    let schema = "CREATE ROLE reporting BYPASSRLS;\n\
                  CREATE ROLE app_user LOGIN;\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  ALTER TABLE docs FORCE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let db = db_of(schema);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let exempt: Vec<String> = outputs
        .notes()
        .iter()
        .filter(|note| note.severity() == NoteSeverity::Exempt)
        .map(TranslationNote::message)
        .collect();
    assert_eq!(exempt.len(), 1, "one role bypasses, got {exempt:?}");
    assert!(
        exempt[0].contains("reporting"),
        "the report has to name the role: {exempt:?}"
    );
    assert!(
        !exempt[0].contains("app_user"),
        "a plain role is not exempt: {exempt:?}"
    );
    // The model still describes only the rules that do apply.
    assert!(
        outputs.model().contains("define can_select: owner"),
        "the policy still translates:\n{}",
        outputs.model()
    );
}

/// The messages of the exemption notes translating `sql` produces.
fn exempt_notes(sql: &str) -> Vec<String> {
    let db = db_of(sql);
    translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .notes()
        .iter()
        .filter(|note| note.severity() == NoteSeverity::Exempt)
        .map(TranslationNote::message)
        .collect()
}

/// Without `FORCE ROW LEVEL SECURITY` the table's owner is exempt from every policy on
/// it, so the model is stricter than the database for them. With it, nobody is.
#[test]
fn a_table_that_does_not_force_row_level_security_is_reported() {
    let schema = |force: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             {force}\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n"
        )
    };
    let unforced = exempt_notes(&schema(""));
    assert_eq!(
        unforced.len(),
        1,
        "the owner bypass is a finding: {unforced:?}"
    );
    assert!(
        unforced[0].contains("docs"),
        "and it names the table: {unforced:?}"
    );

    let forced = exempt_notes(&schema("ALTER TABLE docs FORCE ROW LEVEL SECURITY;\n"));
    assert!(
        forced.is_empty(),
        "FORCE removes the owner bypass, so there is nothing to report: {forced:?}"
    );
}

/// Saying "the table's owner" sends the reader back to their schema to find out whether
/// the exempt principal is the account their application connects as. Now that
/// `sql-traits` keeps `ALTER TABLE ... OWNER TO`, the note can just say who.
#[test]
fn the_exempt_table_owner_is_named_when_the_schema_says_who_it_is() {
    let owned = "CREATE ROLE app_owner;\n\
                 CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                 ALTER TABLE docs OWNER TO app_owner;\n\
                 ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                 CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let unowned = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let named = exempt_notes(owned);
    assert_eq!(named.len(), 1, "one table, one owner bypass: {named:?}");
    assert!(
        named[0].contains("app_owner"),
        "the exempt role has a name, so the note uses it: {named:?}"
    );

    // A schema that never says who owns the table still has the bypass, and the note
    // still has to report it without inventing a role.
    let anonymous = exempt_notes(unowned);
    assert_eq!(
        anonymous.len(),
        1,
        "the bypass is there either way: {anonymous:?}"
    );
    assert!(
        anonymous[0].contains("owner") && !anonymous[0].contains("app_owner"),
        "with no owner recorded it stays generic: {anonymous:?}"
    );
}

/// The model and the notes for a table whose primary key is `key`.
fn barrier_outputs(key: &str) -> (String, Vec<String>) {
    let db = db_of(&format!(
        r"
CREATE TABLE docs ({key}, owner_id UUID, secret BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT TO contractor
    USING (secret = false);
"
    ));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let notes = outputs
        .notes()
        .iter()
        .map(|note| note.message().clone())
        .collect();
    (outputs.model(), notes)
}

/// A barrier bound to roles is folded as `(base and rule) or (base but not member from
/// scope)`, so the roles it binds are whoever the scope relation holds. Without a
/// single-column key no scope tuples can be emitted, and subtracting an empty set leaves the
/// barrier binding nobody, which is the one direction a missing input must never take. It has
/// to bind everyone instead: denying more than RLS is safe, granting more is not.
#[test]
fn a_role_limited_barrier_with_no_scope_tuples_binds_everyone() {
    let (dsl, notes) = barrier_outputs("tenant TEXT, id TEXT");

    assert!(
        !dsl.contains("but not"),
        "no scope tuples can say who is bound, so nothing may be excused from the barrier:\n{dsl}"
    );
    assert!(
        !dsl.contains("[pg_role]"),
        "a scope relation nothing can fill must not be published:\n{dsl}"
    );
    assert!(
        !dsl.contains("type pg_role"),
        "and neither must the type it would need:\n{dsl}"
    );
    assert!(
        notes
            .iter()
            .any(|note| note.contains("docs_bar") && note.contains("everyone")),
        "the operator must be told the barrier now binds more than RLS does, got {notes:#?}"
    );
    assert!(
        !notes.iter().any(|note| note.contains("inheriting members")),
        "nothing may ask for memberships no relation reads, got {notes:#?}"
    );
}

/// The guard must not over-fire: with a key the scope tuples can name, the barrier binds the
/// roles it names and leaves everyone else alone, which is what `PostgreSQL` does.
#[test]
fn a_role_limited_barrier_with_scope_tuples_still_binds_only_its_roles() {
    let (dsl, notes) = barrier_outputs("id TEXT PRIMARY KEY");

    assert!(
        dsl.contains("but not"),
        "a fillable scope excuses everyone outside the bound roles:\n{dsl}"
    );
    assert!(
        dsl.contains("[pg_role]"),
        "the scope relation the exclusion reads has to be declared:\n{dsl}"
    );
    assert!(
        notes
            .iter()
            .any(|note| note.contains("docs_bar") && note.contains("pg_role")),
        "and the operator is asked to fill it, got {notes:#?}"
    );
}

/// `PostgreSQL` applies a `TO role` clause with `has_privs_of_role` semantics: an
/// inheriting member of the role is admitted, a `NOINHERIT` member and a
/// `GRANT ... WITH INHERIT FALSE` grantee are not, while `pg_has_role(.., 'MEMBER')`
/// holds for all three. Probed on 18.4: `USING (true) TO editors` over three rows
/// answers 3 to the inheriting member and 0 to the other two. So a `TO` scope walks
/// `usage`, the kind the crate already defines as "every grant in the chain
/// inherits", never plain membership.
#[test]
fn a_to_scoped_policy_walks_usage_not_member() {
    let db = db_of(
        r"
CREATE ROLE editors;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO editors USING (owner_id = current_user);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
    assert!(
        can_select.contains("usage from scope_"),
        "a TO scope admits inheriting members, which is the usage kind:\n{dsl}"
    );
    assert!(
        !can_select.contains("member from scope_"),
        "membership admits NOINHERIT members PostgreSQL refuses:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "pg_role", "usage").as_deref(),
        Some("[user]"),
        "the walked relation must be declared for the operator to load:\n{dsl}"
    );
    assert!(
        relation_definition(&dsl, "pg_role", "member").is_none(),
        "nothing reads plain membership here, so declaring it would mislead:\n{dsl}"
    );
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.to_string().contains("reads pg_role 'usage'")),
        "the note must name the kind the operator loads, got: {:#?}",
        outputs.notes()
    );
}

/// The RESTRICTIVE fold excuses everyone outside the bound roles, and `PostgreSQL`
/// draws that line with `has_privs_of_role` too. Probed on 18.4: a barrier
/// `TO editors` binds the inheriting member (1 of 3 rows) and leaves the `NOINHERIT`
/// member alone (3 of 3). Excusing by `member` would bind users `PostgreSQL` excuses.
#[test]
fn a_to_scoped_barrier_excuses_by_usage_not_membership() {
    let db = db_of(
        r"
CREATE ROLE editors;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (true);
CREATE POLICY r ON docs AS RESTRICTIVE FOR SELECT TO editors USING (owner_id = current_user);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let limit = relation_definitions(&dsl, "docs")
        .into_iter()
        .find(|(name, _)| name.starts_with("limit_"))
        .map(|(_, body)| body)
        .expect("the barrier must fold into a limit_ relation");
    assert!(
        limit.contains("but not usage from scope_"),
        "the excused set is who lacks the role's inherited privileges:\n{dsl}"
    );
    assert!(
        !limit.contains("but not member from scope_"),
        "excusing non-members binds NOINHERIT members PostgreSQL excuses:\n{dsl}"
    );
}

/// A membership table readable only by named roles scopes the parent grant, and the
/// reader `PostgreSQL` admits is again the inheriting member, so the read scope walks
/// `usage` like every other `TO` consumer.
#[test]
fn a_membership_read_scope_walks_usage() {
    let db = db_of(
        r"
CREATE ROLE auditor;
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
  EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)
);
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
    assert!(
        can_select.contains("usage from read_scope_"),
        "only the roles that may read memberships inherit the grant:\n{dsl}"
    );
    assert!(
        !can_select.contains("member from read_scope_"),
        "membership admits readers PostgreSQL refuses:\n{dsl}"
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
CREATE POLICY p ON docs FOR SELECT TO {spelling} USING (owner_id = current_user);
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
            pg_role_relation(&dsl, "docs").is_none(),
            "no scope relation may ask for tuples of a role that does not exist \
             (`TO {spelling}`):\n{dsl}"
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
                TranslationNote::PolicyBoundToDdlTimeRole { policy, spellings }
                    if policy == "p" && spellings == &[spelling.to_string()]
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
/// 2 rows while the old model excused everyone from the unfillable scope and granted
/// both. An unknowable scope has to bind everyone instead, named roles beside it
/// included, since a barrier that also binds the DDL runner cannot be narrowed to the
/// names alone.
#[test]
fn a_pseudo_role_barrier_binds_everyone() {
    for to_clause in ["CURRENT_USER", "editors, CURRENT_USER"] {
        let db = db_of(&format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (true);
CREATE POLICY r ON docs AS RESTRICTIVE FOR SELECT TO {to_clause} USING (owner_id = current_user);
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        assert!(
            !dsl.contains("but not"),
            "an unfillable scope must not excuse anyone (`TO {to_clause}`):\n{dsl}"
        );
        let can_select =
            relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
        assert!(
            can_select.contains("public_viewer and owner"),
            "the barrier binds everyone, so the rule intersects the grant \
             (`TO {to_clause}`):\n{dsl}"
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
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::PolicyBoundToDdlTimeRole { policy, .. } if policy == "r"
            )),
            "the widening must be disclosed (`TO {to_clause}`), got: {:#?}",
            outputs.notes()
        );
    }
}

/// A permissive policy the threshold empties is now retained through the filter, so
/// the generator can say what was lost. Retaining it must not resurrect its side
/// effects: registration runs before translation, so a policy contributing no
/// expression would otherwise still mint a role scope relation and ask the operator
/// to load `pg_role` memberships that nothing consults.
#[test]
fn a_policy_the_threshold_emptied_mints_no_scope_relation() {
    let db = db_of(
        "CREATE ROLE auditor;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
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
        !dsl.contains("type pg_role"),
        "and no role type is minted for it:\n{dsl}"
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::PolicyRoleScope { .. })),
        "nor a note asking for memberships nothing reads: {:?}",
        outputs.notes()
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

/// A `PostgreSQL` policy name is unique per table, so a scope **object** keyed on the
/// name alone pools two tables' roles.
///
/// The scope relation may stay keyed on the policy, since relations are scoped to a
/// type. The object id may not: it lives in the shared `pg_role_scope` type, so two
/// tables whose policies happen to share a name land on one object and each one's roles
/// are written onto it. Every row of both tables then admits the union, which grants
/// each table the other's roles.
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
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let tuples = outputs.tuple_queries();

    let scope_of = |type_name: &str| -> String {
        let found = relation_definitions(&dsl, type_name)
            .into_iter()
            .find(|(_, body)| body == "[pg_role_scope]");
        match found {
            Some((name, _)) => name,
            None => panic!("{type_name} should point at a role scope:\n{dsl}"),
        }
    };
    let docs_scope = scope_of("docs");
    let memos_scope = scope_of("memos");

    // The companion halves, so pooling cannot be hidden by admitting nothing at all.
    assert!(
        scope_admits_role(tuples, "docs:", &docs_scope, "auditor"),
        "docs is scoped TO auditor:\n{dsl}"
    );
    assert!(
        scope_admits_role(tuples, "memos:", &memos_scope, "support"),
        "memos is scoped TO support:\n{dsl}"
    );

    assert!(
        !scope_admits_role(tuples, "docs:", &docs_scope, "support"),
        "docs is scoped TO auditor alone, so support must not reach its rows"
    );
    assert!(
        !scope_admits_role(tuples, "memos:", &memos_scope, "auditor"),
        "memos is scoped TO support alone, so auditor must not reach its rows"
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
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let tuples = outputs.tuple_queries();
    let docs_scope = pg_role_relation(&dsl, "docs").expect("docs should have a role scope");
    let memos_scope = pg_role_relation(&dsl, "memos").expect("memos should have a role scope");

    assert_ne!(docs_scope, memos_scope);
    assert!(scope_admits_role(tuples, "docs:", &docs_scope, "admin"));
    assert!(scope_admits_role(tuples, "memos:", &memos_scope, "Admin"));
    assert!(!scope_admits_role(tuples, "docs:", &docs_scope, "Admin"));
    assert!(!scope_admits_role(tuples, "memos:", &memos_scope, "admin"));
    assert!(outputs
        .notes()
        .iter()
        .all(|note| !note.message().contains("role") || !note.message().contains("rewritten")));
}

/// Every scope relation a type declares, in declaration order.
fn scope_relations(dsl: &str, type_name: &str) -> Vec<String> {
    relation_definitions(dsl, type_name)
        .into_iter()
        .filter(|(_, body)| body == "[pg_role_scope]")
        .map(|(name, _)| name)
        .collect()
}

/// A `TO` list and a role gate in one policy are two scopes, read through two different
/// privileges, so they cannot share one object.
///
/// **One role under both privileges**, so the privilege is the only thing telling the two
/// scopes apart and a key built from the roles alone cannot pass this. `TO editor` is
/// checked as usage of `editor` and `pg_has_role('editor', 'member')` as membership of it,
/// and `PostgreSQL` demands both. Pooled onto one object the rule asks for usage of the
/// pooled set and membership of the pooled set, which is the same question twice.
/// Separating them needs two relations: one relation pointing at two objects still unions
/// them.
#[test]
fn a_to_list_and_a_role_gate_in_one_policy_do_not_share_a_scope() {
    let db = db_of(
        r"
CREATE ROLE editor;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO editor USING (pg_has_role('editor', 'member'));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let tuples = outputs.tuple_queries();
    let scopes = scope_relations(&dsl, "docs");

    assert_eq!(
        scopes.len(),
        2,
        "the TO list and the role gate are two scopes, so docs points at two:\n{dsl}"
    );
    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("docs should define can_select");
    let [first, second] = scopes.as_slice() else {
        unreachable!("checked above")
    };
    assert_ne!(
        first, second,
        "two scopes cannot be one name, or the walks below ask the same question twice"
    );
    for scope in &scopes {
        assert!(
            can_select.contains(scope.as_str()),
            "both scopes have to be read, and {scope} is not in 'define can_select: {can_select}'"
        );
        // The companion half: each scope really does carry the role, so declaring two
        // relations and filling neither would not pass.
        assert!(
            scope_admits_role(tuples, "docs:", scope, "editor"),
            "{scope} stands for a test on editor, so its object carries editor"
        );
    }
}

/// Two role gates joined by `AND` are two scopes, and pooling them turns the `AND` into
/// an `OR`.
///
/// `pg_has_role('alpha', 'member') AND pg_has_role('beta', 'member')` demands both. On one
/// pooled object the rule reads `member from x and member from x`, which is `member from x`,
/// so membership of either role passes.
#[test]
fn two_role_gates_joined_by_and_do_not_share_a_scope() {
    let db = db_of(
        r"
CREATE ROLE alpha;
CREATE ROLE beta;
CREATE TABLE public.docs(id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (pg_has_role('alpha', 'member') AND pg_has_role('beta', 'member'));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let tuples = outputs.tuple_queries();
    let scopes = scope_relations(&dsl, "docs");

    assert_eq!(
        scopes.len(),
        2,
        "each gate is its own scope, so the conjunction stays a conjunction:\n{dsl}"
    );
    for scope in &scopes {
        let roles: Vec<&str> = ["alpha", "beta"]
            .into_iter()
            .filter(|role| scope_admits_role(tuples, "docs:", scope, role))
            .collect();
        assert_eq!(
            roles.len(),
            1,
            "{scope} stands for one gate, so it admits one role, admitted {roles:?}"
        );
    }
}
