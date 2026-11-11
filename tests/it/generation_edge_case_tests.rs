use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::tuple_generator;
use rls2fga::output::formatter::WriteError;
use rls2fga::parser::sql_parser::ParserDB;
use rls2fga::translator::Outputs;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;

use crate::support;

// ── Output validation ────────────────────────────────────────────────────────

/// A translation of the smallest schema there is, for tests about filenames rather
/// than about models.
fn any_outputs(db: &ParserDB) -> Outputs {
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(
        db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    support::plan_at(classified, db, &registry, ConfidenceLevel::D)
}

#[test]
fn write_output_rejects_empty_name() {
    let dir = support::unique_temp_dir("rls2fga_empty_name");
    let db = support::deployment::db("CREATE TABLE docs(id uuid primary key);");
    let err = any_outputs(&db)
        .write(&dir, "")
        .expect_err("empty name should be rejected");
    assert!(
        matches!(&err, WriteError::InvalidName { reason, .. } if reason.contains("empty")),
        "Error: {err}"
    );
}

#[test]
fn write_output_rejects_absolute_path() {
    let dir = support::unique_temp_dir("rls2fga_abs_path");
    let db = support::deployment::db("CREATE TABLE docs(id uuid primary key);");
    let err = any_outputs(&db)
        .write(&dir, "/etc/passwd")
        .expect_err("absolute path should be rejected");
    assert!(
        matches!(&err, WriteError::InvalidName { .. }),
        "Error: {err}"
    );
}

// ── Type/relation collisions ─────────────────────────────────────────────────

#[test]
fn role_relations_token_collision_produces_distinct_types() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE teams(id UUID PRIMARY KEY);
CREATE TABLE team_memberships(id UUID PRIMARY KEY, user_id UUID, team_id UUID);
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE POLICY p ON docs FOR SELECT USING (role_level(current_setting('app.user_id'), id) >= 1);
";
    let db = support::deployment::db(sql);
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"role-a": 1, "role a": 2, "role_a": 3},
            "grant_table": "object_grants",
            "grant_grantee_col": "grantee_id",
            "grant_resource_col": "resource_id",
            "grant_role_col": "role_level",
            "team_membership": {
                "table": "team_memberships",
                "user_col": "user_id",
                "team_col": "team_id"
            }
        }
    }"#,
        )
        .unwrap();

    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);

    let grant_count = model
        .model()
        .lines()
        .filter(|l| l.trim().starts_with("define grant_role_a"))
        .count();
    assert_eq!(
        grant_count,
        3,
        "Three colliding role names should produce 3 distinct grant relations. DSL:\n{}",
        model.model()
    );
}

// ── Tuple generation ─────────────────────────────────────────────────────────

#[test]
fn team_only_principal_generates_team_prefixed_tuples() {
    let sql = r"
CREATE TABLE teams(id UUID PRIMARY KEY);
CREATE TABLE team_memberships(id UUID PRIMARY KEY, user_id UUID, team_id UUID);
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE POLICY p ON docs FOR SELECT USING (role_level(current_setting('app.user_id'), id) >= 1);
";
    let db = support::deployment::db(sql);
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"viewer": 1},
            "grant_table": "object_grants",
            "grant_grantee_col": "grantee_id",
            "grant_resource_col": "resource_id",
            "grant_role_col": "role_level",
            "team_membership": {
                "table": "team_memberships",
                "user_col": "user_id",
                "team_col": "team_id"
            }
        }
    }"#,
        )
        .unwrap();

    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    let formatted = tuple_generator::format_tuples(tuples);

    assert!(
        formatted.contains("team_memberships"),
        "Expected team membership tuple query in output:\n{formatted}"
    );
}

#[test]
fn p6_table_without_pk_generates_note_in_tuples() {
    let sql = r"
CREATE TABLE items(val TEXT, is_public BOOLEAN);
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON items FOR SELECT USING (is_public = TRUE);
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    assert!(outputs.tuple_queries().iter().any(|query| matches!(
        &query.skipped,
        Some(tuple_generator::SkippedTuples::NoObjectIdentifier { table, what, .. })
            if table.to_string() == "public.items" && what == "public-flag tuples"
    )));
}

#[test]
fn a_declared_parent_fk_emits_its_tuple_to_userset_bridge() {
    let sql = r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = tasks.project_id AND p.owner_id = current_setting('app.user_id')
    ));
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    assert!(outputs.tuple_queries().iter().any(|query| {
        query.sql.contains(r#"FROM "public"."tasks""#)
            && query.sql.contains("'projects' AS relation")
            && query.sql.contains(r#""project_id"::text"#)
    }));
}

#[test]
fn p4_reading_the_guarded_table_fails_closed_without_invalid_membership_sql() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1
        FROM doc_members dm
        JOIN docs d ON dm.doc_id = d.id
        WHERE dm.doc_id = docs.id
          AND dm.user_id = current_setting('app.user_id')
          AND is_public = TRUE
    ));
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);

    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("infinite recursion")),
        "a subquery reading the guarded table should fail closed, got: {:?}",
        using.pattern
    );

    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    let has_invalid_membership_filter = tuples.iter().any(|query| {
        let lower = query.sql.to_ascii_lowercase();
        lower.contains("from \"doc_members\"") && lower.contains("is_public = true")
    });
    assert!(
        !has_invalid_membership_filter,
        "invalid membership filter leaked into tuple SQL: {:?}",
        tuples.iter().map(|q| q.sql.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn p4_derived_joined_unqualified_extra_fails_closed_without_invalid_membership_sql() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1
        FROM doc_members dm
        JOIN (SELECT id, is_public FROM docs) d ON dm.doc_id = d.id
        WHERE dm.doc_id = docs.id
          AND dm.user_id = current_setting('app.user_id')
          AND is_public = TRUE
    ));
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);

    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("Ambiguous membership pattern")),
        "derived joined unqualified extra should fail closed to Unknown ambiguity, got: {:?}",
        using.pattern
    );

    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    let has_invalid_membership_filter = tuples.iter().any(|query| {
        let lower = query.sql.to_ascii_lowercase();
        lower.contains("from \"doc_members\"") && lower.contains("is_public = true")
    });
    assert!(
        !has_invalid_membership_filter,
        "invalid membership filter leaked into tuple SQL: {:?}",
        tuples.iter().map(|q| q.sql.clone()).collect::<Vec<_>>()
    );
}

// ── Report ───────────────────────────────────────────────────────────────────

#[test]
fn report_contains_pattern_short_names() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_own ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY p_flag ON docs FOR SELECT USING (is_public = TRUE);
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

    let dir = support::unique_temp_dir("rls2fga_short_names");
    outputs.write(&dir, "docs").unwrap();
    let report = std::fs::read_to_string(dir.join("docs_report.md")).unwrap();

    assert!(
        report.contains("direct-ownership") || report.contains("P3"),
        "Report should describe P3 pattern"
    );
}

// ── Multi-policy generation ──────────────────────────────────────────────────

#[test]
fn multi_policy_table_generates_combined_model() {
    let (classified, db, registry) = support::try_load_fixture_classified("multi_policy_table");
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    assert!(
        !model.model().is_empty(),
        "Multi-policy table should produce DSL output"
    );
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    let formatted = tuple_generator::format_tuples(tuples);
    assert!(
        !formatted.is_empty(),
        "Multi-policy table should produce tuple queries"
    );
}

// ── P5 generation edge cases ─────────────────────────────────────────────────

#[test]
fn p5_with_unknown_inner_generates_no_access_and_note() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY, custom_check TEXT);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND o.custom_check LIKE '%special%'
    ));
";
    let db = support::deployment::db(sql);
    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &FunctionRegistry::new(),
        &support::deployment::caller_deployment(),
    );

    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);

    assert!(
        model.model().contains("define can_select: no_access"),
        "docs should define can_select as no_access:\n{}",
        model.model()
    );
    assert!(model.notes().iter().any(|note| matches!(
        note,
        TranslationNote::CoveringPoliciesBelowThreshold { table, commands }
            if table.to_string() == "public.docs" && commands == &["SELECT"]
    )));
}

#[test]
fn p5_source_table_without_pk_generates_bridge_note() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE docs(org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND o.owner_id = current_setting('app.user_id')
    ));
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );

    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    assert!(outputs.tuple_queries().iter().any(|query| matches!(
        &query.skipped,
        Some(tuple_generator::SkippedTuples::NoBridge { table, parent_type, .. })
            if table.to_string() == "public.docs" && parent_type == "orgs"
    )));
    assert!(outputs.notes().iter().any(|note| matches!(
        note,
        TranslationNote::RowsCannotBeNamed { table, sources, .. }
            if table.to_string() == "public.docs"
                && sources == &["bridge tuples to 'orgs'"]
    )));
}

/// A constant conjunct leaves the parent's own rule as the whole requirement, so an
/// unrestricted parent offers no gate and the read falls closed with its reason named.
#[test]
fn p5_with_a_constant_inner_falls_closed_on_an_unrestricted_parent() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND TRUE
    ));
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

    let model = outputs.model();
    assert!(
        model.contains("define can_select: no_access"),
        "a delegation with no gate behind it must fall closed:\n{model}"
    );
    let report = outputs.report();
    assert!(
        report.contains("enforces no row security, so there is nothing to inherit"),
        "the operator has to learn why the read was refused:\n{report}"
    );
}

// ── P1 generation edge cases ─────────────────────────────────────────────────

#[test]
fn role_threshold_table_without_pk_generates_grant_note() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE items(val TEXT, owner_id UUID);
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE POLICY p ON items FOR SELECT USING (role_level(current_setting('app.user_id'), val) >= 1);
";
    let db = support::deployment::db(sql);
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"viewer": 1, "editor": 2},
            "grant_table": "object_grants",
            "grant_grantee_col": "grantee_id",
            "grant_resource_col": "resource_id",
            "grant_role_col": "role_level"
        }
    }"#,
        )
        .unwrap();

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    assert!(outputs.tuple_queries().iter().any(|query| matches!(
        &query.skipped,
        Some(tuple_generator::SkippedTuples::NoBridge { table, parent_type, .. })
            if table.to_string() == "public.items" && parent_type == "object_grants_owner"
    )));
}
