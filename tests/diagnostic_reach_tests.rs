//! Every diagnostic a schema can reach has a schema here that reaches it.
//!
//! A diagnostic nobody can see is not a diagnostic. Measured over the whole fixture corpus
//! at all four confidence levels, 18 of the 33 notes fire and 2 of the 10 skipped-tuple
//! reasons do, so the rest were carried on the word of their construction sites. Each case
//! below is the smallest schema that makes one of them render, which is what turns "it
//! exists" into "an operator would read this".
//!
//! The cases are written against the operator-visible text, since that is what a reader
//! acts on, and a reworded message has to be looked at rather than silently accepted.
//!
//! Not here on purpose: `OwnerBoundFunction`, which
//! `footgun_requests_tests::an_owner_bound_accessor_is_reported_by_name` already covers. A
//! census that greps variant names misses that test, because it asserts the message text,
//! which is how this one came to look unreached.

use rls2fga::generator::tuple_generator::SkippedTuples;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;

mod support;

/// The notes and the skipped-tuple comments one schema produces at one threshold.
fn reported(
    sql: &str,
    registry: Option<&str>,
    level: ConfidenceLevel,
) -> (Vec<String>, Vec<String>) {
    let (classified, db, reg) = support::classify_sql(sql, registry);
    let planned = support::plan_at(classified, &db, &reg, level);
    let notes = planned
        .notes()
        .iter()
        .map(TranslationNote::message)
        .collect::<Vec<_>>();
    let skips = planned
        .tuple_queries()
        .iter()
        .filter(|query| query.skipped.is_some())
        .map(|query| query.comment.clone())
        .collect();
    (notes, skips)
}

/// A role threshold over `owner_grants`, with no team support declared.
const GRANTS: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id"
  }
}"#;

/// The same, declaring the team membership table that makes a team arm exist.
const GRANTS_WITH_TEAMS: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id",
    "team_membership": {
      "table": "team_members",
      "user_col": "user_id",
      "team_col": "team_id"
    }
  }
}"#;

/// The grant scaffolding a role threshold needs, minus whichever piece a case removes.
const GRANT_TABLE: &str = "
CREATE TABLE owner_grants(granted_owner_id TEXT, grantee_owner_id TEXT, role_id INT);
CREATE FUNCTION get_owner_role(a TEXT, b TEXT) RETURNS INT LANGUAGE sql STABLE AS 'SELECT 1';
";

fn assert_reports(label: &str, haystack: &[String], fragment: &str) {
    assert!(
        haystack.iter().any(|line| line.contains(fragment)),
        "{label}: nothing reported {fragment:?}, got {haystack:#?}"
    );
}

/// A role that bypasses row level security is named, since no model can express it.
#[test]
fn a_bypassing_role_is_reported() {
    let (notes, _) = reported(
        "CREATE ROLE auditor BYPASSRLS;
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user);",
        None,
        ConfidenceLevel::B,
    );
    assert_reports("bypassing role", &notes, "'auditor'");
    assert_reports(
        "bypassing role",
        &notes,
        "has BYPASSRLS, so every policy is skipped",
    );
}

/// A RESTRICTIVE barrier scoped to a role cannot bind that role alone when no tuple can
/// name the row, so it binds everyone and the widening is reported.
#[test]
fn a_barrier_that_cannot_be_scoped_is_reported() {
    let (notes, _) = reported(
        "CREATE ROLE auditor;
CREATE TABLE docs(owner_id TEXT, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY bar ON docs AS RESTRICTIVE FOR SELECT TO auditor USING (tenant = 'x');",
        None,
        ConfidenceLevel::B,
    );
    assert_reports(
        "unscopable barrier",
        &notes,
        "the barrier is applied to everyone",
    );
}

/// A parent with `INHERITS` children reads `FROM ONLY`, so its policy stops covering the
/// children's rows and the operator has to know which tables those are.
#[test]
fn an_inheritance_parent_reading_its_own_rows_is_reported() {
    let (notes, _) = reported(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE archived_docs() INHERITS (docs);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user);",
        None,
        ConfidenceLevel::B,
    );
    assert_reports("inheritance parent", &notes, "archived_docs");
}

/// A membership correlated against a column the guarded table does not have names no row,
/// so the bridge is refused rather than keyed on a guess.
#[test]
fn a_bridge_on_an_absent_column_is_reported_and_skipped() {
    let (notes, skips) = reported(
        "CREATE TABLE users(id TEXT PRIMARY KEY);
CREATE TABLE projects(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE members(project_id TEXT REFERENCES projects(id), user_id TEXT);
CREATE TABLE docs(id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY dp ON docs FOR SELECT
    USING (EXISTS (SELECT 1 FROM members WHERE members.project_id = docs.missing_col
        AND members.user_id = current_user));",
        None,
        ConfidenceLevel::B,
    );
    assert_reports("absent bridge column", &notes, "missing_col");
    assert_reports(
        "absent bridge column",
        &skips,
        "missing column 'missing_col'",
    );
}

/// Ownership on a table nothing can name a row of emits no tuple, and says which column
/// it looked for.
#[test]
fn ownership_without_a_row_identity_is_skipped() {
    let (_, skips) = reported(
        "CREATE TABLE users(id TEXT PRIMARY KEY);
CREATE TABLE docs(owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user);",
        None,
        ConfidenceLevel::B,
    );
    assert_reports(
        "no row identity",
        &skips,
        "missing object identifier column",
    );
}

/// A caller receives the gaps in the same list as the statements, and running a gap loads
/// nothing while succeeding. So the entry states which it is, rather than leaving a caller
/// to notice that the text opens with a comment.
#[test]
fn a_gap_carries_its_reason_and_a_statement_carries_none() {
    let (classified, db, registry) = support::classify_sql(
        "CREATE TABLE docs(owner_id TEXT);
CREATE TABLE memos(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY memos_owner ON memos FOR SELECT USING (owner_id = current_user);",
        None,
    );
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let queries = planned.tuple_queries();

    assert!(
        queries.iter().any(|query| matches!(
            query.skipped,
            Some(SkippedTuples::NoObjectIdentifier { .. })
        )),
        "nothing names a row of docs, so that entry states the gap: {queries:#?}"
    );
    assert!(
        queries
            .iter()
            .any(|query| query.skipped.is_none() && query.sql.contains("FROM \"public\".\"memos\"")),
        "memos names its rows, so its entry is a statement: {queries:#?}"
    );
    for query in queries {
        assert_eq!(
            query.skipped.is_some(),
            query.sql.trim_start().starts_with("--"),
            "a gap and a statement must not be told apart two ways:\n{}\n{}",
            query.comment,
            query.sql
        );
    }
}

/// A role threshold on such a table cannot even point the row at its owner.
#[test]
fn an_owner_pointer_without_a_row_identity_is_skipped() {
    let (_, skips) = reported(
        &format!(
            "CREATE TABLE users(id TEXT PRIMARY KEY);{GRANT_TABLE}
CREATE TABLE docs(owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (get_owner_role(current_user, owner_id) >= 2);"
        ),
        Some(GRANTS),
        ConfidenceLevel::B,
    );
    assert_reports(
        "no bridge",
        &skips,
        "bridge (missing object identifier column)",
    );
}

/// The ladder judges the value the function was given, so a call passing an expression
/// rather than a column leaves nothing to key the pointer on.
#[test]
fn an_owner_pointer_without_a_column_is_skipped() {
    let (_, skips) = reported(
        &format!(
            "CREATE TABLE users(id TEXT PRIMARY KEY);{GRANT_TABLE}
CREATE TABLE docs(id TEXT PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (get_owner_role(current_user, lower(title)) >= 2);"
        ),
        Some(GRANTS),
        ConfidenceLevel::B,
    );
    assert_reports(
        "no owner column",
        &skips,
        "no column carries the owner the policy compares",
    );
}

/// With no table the principals live in, the identity facts cannot be read and the grant
/// expansion cannot name a subject type either.
#[test]
fn a_grant_without_a_principal_table_is_skipped_twice() {
    let sql = format!(
        "{GRANT_TABLE}
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (get_owner_role(current_user, owner_id) >= 2);"
    );
    let (_, skips) = reported(&sql, Some(GRANTS), ConfidenceLevel::B);
    assert_reports(
        "no user principal",
        &skips,
        "unresolved user principal table",
    );
    assert_reports(
        "no principal type",
        &skips,
        "could not resolve principal type",
    );
}

/// A declared team membership table with no team table to key the identities on.
#[test]
fn a_team_arm_without_a_team_table_is_skipped() {
    let (_, skips) = reported(
        &format!(
            "CREATE TABLE users(id TEXT PRIMARY KEY);
CREATE TABLE team_members(user_id TEXT, team_id TEXT);{GRANT_TABLE}
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (get_owner_role(current_user, owner_id) >= 2);"
        ),
        Some(GRANTS_WITH_TEAMS),
        ConfidenceLevel::B,
    );
    assert_reports(
        "no team principal",
        &skips,
        "unresolved team principal table",
    );
}

/// An attribute the model hands to the application, which only appears below the default
/// threshold, so it is the one family that needs a lower one to be seen at all. A `LIKE`
/// guard beside the threshold is a shape the translator leaves to the application.
#[test]
fn an_attribute_left_to_the_application_is_reported_and_skipped() {
    let (classified, db, registry) = support::classify_sql(
        &format!(
            "{GRANT_TABLE}
CREATE TABLE ownables(id TEXT PRIMARY KEY, owner_id TEXT, status TEXT);
ALTER TABLE ownables ENABLE ROW LEVEL SECURITY;
CREATE POLICY ownables_update ON ownables FOR UPDATE
    USING (get_owner_role(current_user, owner_id) >= 3 AND status LIKE 'live%');"
        ),
        Some(GRANTS),
    );
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::C);
    let notes: Vec<String> = planned
        .notes()
        .iter()
        .map(TranslationNote::message)
        .collect();
    let skips: Vec<String> = planned
        .tuple_queries()
        .iter()
        .filter(|query| query.skipped.is_some())
        .map(|query| query.comment.clone())
        .collect();

    assert_reports(
        "runtime attribute",
        &notes,
        "still requires runtime enforcement",
    );
    assert_reports("runtime attribute", &skips, "requires runtime enforcement");
}

/// An expression nobody classified, retained because the threshold was lowered to keep it.
#[test]
fn an_unclassified_expression_is_skipped() {
    let (_, skips) = reported(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, data JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (data ->> 'kind' = 'public');",
        None,
        ConfidenceLevel::D,
    );
    assert_reports("unclassified", &skips, "unsupported pattern Unknown");
}

/// An attribute guard the row does not decide, which is graded for review rather than
/// translated, so it appears only below the default threshold.
///
/// `policy_classifier.rs` grades an attribute condition C exactly when it carries neither a
/// literal to compare against nor a request value, and `LIKE` is such a comparison: the
/// operator has no counterpart in the model, so the row's value cannot settle it. Two
/// earlier attempts at this shape (a column compared to another column, and a jsonb path)
/// both classify as unrecognized instead, which is what made it look unreachable.
#[test]
fn an_attribute_the_row_does_not_decide_is_reported_and_skipped() {
    let (notes, skips) = reported(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (status LIKE 'draft%');",
        None,
        ConfidenceLevel::C,
    );
    assert_reports(
        "standalone attribute",
        &notes,
        "Standalone attribute policy on 'status'",
    );
    assert_reports("standalone attribute", &skips, "unsupported pattern P9");
}

/// A table inheriting permission from a parent whose own rule the crate cannot translate,
/// which denies rather than guessing.
///
/// The rule that matters here is the one written **inside the child's subquery**, not the
/// parent's separate policy: `recognize_p5` classifies that inner clause against the parent
/// and stores the result. Eight exotic clauses put on the parent's own policy therefore
/// missed this entirely. Here the inner clause is an ordinary membership check, and the
/// table it reads has row level security with no policy, so no membership row is visible and
/// the inner rule collapses to a denial.
///
/// Fires at the default threshold, so an operator meets it without lowering anything.
#[test]
fn a_parent_rule_that_cannot_be_translated_is_reported() {
    let (notes, _) = reported(
        "CREATE TABLE members(project_id TEXT, user_id TEXT);
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
CREATE TABLE projects(id TEXT PRIMARY KEY);
CREATE TABLE docs(id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY pp ON projects FOR SELECT USING (true);
CREATE POLICY dp ON docs FOR SELECT USING (project_id IN (SELECT id FROM projects WHERE id IN (SELECT project_id FROM members WHERE user_id = current_user)));",
        None,
        ConfidenceLevel::B,
    );
    assert_reports(
        "parent rule untranslated",
        &notes,
        "Parent inheritance from 'projects' could not translate the parent-side rule",
    );
}
