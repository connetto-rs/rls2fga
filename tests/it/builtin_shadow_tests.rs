//! Only unqualified and `pg_catalog` qualified builtins receive builtin semantics.

use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};
use rls2fga::types::ConfidenceLevel;

use crate::support;

use crate::support::footgun::{db_of, translator};

fn using_pattern(sql: &str, table: &str) -> PatternClass {
    let db = db_of(sql);
    let classified = translator(ConfidenceLevel::B).classify(&db);
    let policy = classified
        .iter()
        .find(|policy| policy.table_name() == table)
        .expect("the policy should classify");
    policy
        .using_classification()
        .expect("USING should classify")
        .pattern
        .clone()
}

/// A mocked clock must never become a real-clock condition: the model would
/// re-evaluate against check time what the database compares against the mock.
#[test]
fn a_qualified_now_is_not_the_clock() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);
CREATE FUNCTION app.now() RETURNS TIMESTAMPTZ LANGUAGE sql IMMUTABLE AS 'SELECT ''infinity''::timestamptz';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (expires_at > app.now());
";
    let db = db_of(sql);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let dsl = translation.outputs_accepting_gaps().model();
    assert!(
        !dsl.contains("request_time"),
        "`app.now()` is not the request clock:\n{dsl}"
    );
}

/// Unqualified and `pg_catalog` qualified clocks keep the condition.
#[test]
fn the_builtin_clock_spellings_keep_the_condition() {
    for clock in ["now()", "pg_catalog.now()", r#""pg_catalog".now()"#] {
        let sql = format!(
            "
CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (expires_at > {clock});
"
        );
        let db = db_of(&sql);
        let translation = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan");
        let dsl = translation.outputs_accepting_gaps().model();
        assert!(
            dsl.contains("request_time"),
            "`{clock}` is the request clock:\n{dsl}"
        );
    }
}

/// `pg_has_role` tests the caller, so a user function under another schema must not
/// inherit the role-gate classification.
#[test]
fn a_qualified_pg_has_role_is_not_the_role_gate() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (app.pg_has_role('editor', 'MEMBER'));
";
    let pattern = using_pattern(sql, "docs");
    assert!(
        matches!(&pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "`app.pg_has_role` is somebody's function, got {pattern:?}"
    );
    let control = "
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (pg_has_role('editor', 'MEMBER'));
";
    let pattern = using_pattern(control, "docs");
    assert!(
        matches!(&pattern, PatternClass::P2RoleNameInList(_)),
        "the unqualified spelling is the builtin, got {pattern:?}"
    );
}

/// `current_setting` reads the caller's session, so a user function under another
/// schema must not mint P3 ownership off a key it may never read.
#[test]
fn a_qualified_current_setting_is_not_the_session_reader() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = app.current_setting('app.user_id'));
";
    let pattern = using_pattern(sql, "docs");
    assert!(
        !matches!(&pattern, PatternClass::P3DirectOwnership(_)),
        "`app.current_setting` is somebody's function, got {pattern:?}"
    );
    let control = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
";
    let pattern = using_pattern(control, "docs");
    assert!(
        matches!(&pattern, PatternClass::P3DirectOwnership(_)),
        "the unqualified spelling is the builtin, got {pattern:?}"
    );
}

/// The residual purity proof admits a fixed list of row-pure builtins. A user function
/// under another schema may read session state and answer as the loader.
#[test]
fn a_qualified_row_pure_name_poisons_the_residual() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE members(doc_id UUID REFERENCES docs(id), user_id TEXT, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_user
    AND app.lower(m.status) = 'active'));
";
    let pattern = using_pattern(sql, "docs");
    assert!(
        matches!(&pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "`app.lower` is somebody's function, got {pattern:?}"
    );
    let control = "
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE members(doc_id UUID REFERENCES docs(id), user_id TEXT, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_user
    AND lower(m.status) = 'active'));
";
    let pattern = using_pattern(control, "docs");
    assert!(
        matches!(&pattern, PatternClass::P4ExistsMembership(_)),
        "the unqualified spelling is the row-pure builtin, got {pattern:?}"
    );
}

/// The caller-set splitter reads `string_to_array` by name. A user function under
/// another schema may split differently or not at all.
#[test]
fn a_qualified_string_to_array_is_not_the_splitter() {
    let attributes = r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#;
    let sql = |splitter: &str| {
        format!(
            "
CREATE TABLE docs(id UUID PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  owner = ANY({splitter}(current_setting('app.subjects', true), ',')));
"
        )
    };
    let (classified, _db, _registry) =
        support::classify_sql_with_session_attributes(&sql("app.string_to_array"), attributes);
    let pattern = classified[0]
        .using_classification()
        .expect("USING classifies")
        .pattern
        .clone();
    assert!(
        !matches!(&pattern, PatternClass::P14RowValueInCallerSet(_)),
        "`app.string_to_array` is somebody's function, got {pattern:?}"
    );
    let (classified, _db, _registry) =
        support::classify_sql_with_session_attributes(&sql("string_to_array"), attributes);
    let pattern = classified[0]
        .using_classification()
        .expect("USING classifies")
        .pattern
        .clone();
    assert!(
        matches!(&pattern, PatternClass::P14RowValueInCallerSet(_)),
        "the unqualified spelling is the splitter, got {pattern:?}"
    );
}

/// The catalog-qualified spellings are the builtins by definition, so they must keep
/// the classification the bare spellings get. The raw-name comparison in
/// `row_valued_set` fell closed on them, losing dump-shaped coverage.
#[test]
fn the_catalog_qualified_set_spellings_stay_classified() {
    let attributes = r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#;
    for (label, clause) in [
        (
            "pg_catalog.string_to_array",
            "owner = ANY(pg_catalog.string_to_array(current_setting('app.subjects', true), ','))",
        ),
        (
            "pg_catalog.jsonb_array_elements_text",
            "owner IN (SELECT pg_catalog.jsonb_array_elements_text(\
             current_setting('app.subjects', true)::jsonb))",
        ),
    ] {
        let sql = format!(
            "
CREATE TABLE docs(id UUID PRIMARY KEY, owner TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING ({clause});
"
        );
        let (classified, _db, _registry) =
            support::classify_sql_with_session_attributes(&sql, attributes);
        let pattern = classified[0]
            .using_classification()
            .expect("USING classifies")
            .pattern
            .clone();
        assert!(
            matches!(&pattern, PatternClass::P14RowValueInCallerSet(_)),
            "`{label}` is the builtin, got {pattern:?}"
        );
    }
}
