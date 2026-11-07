use rls2fga::classifier::patterns::{DirectOwnership, ParentInheritance};
use rls2fga::generator::tuple_generator;
use rls2fga::types::ConfidenceLevel;

use crate::support;

#[test]
fn p4_membership_uses_actual_fk_column_from_subquery() {
    let sql = r"
CREATE TABLE public.users (id UUID PRIMARY KEY);
CREATE TABLE public.projects (id UUID PRIMARY KEY);
CREATE TABLE public.project_members (
  project_id UUID NOT NULL REFERENCES projects(id),
  user_id UUID NOT NULL REFERENCES users(id),
  role TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
-- FOR ALL so the clause also grants reads, which an UPDATE needs to name its row.
CREATE POLICY p ON projects FOR ALL TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM project_members
    WHERE project_id = projects.id
      AND user_id = auth_current_user_id()
      AND role = 'admin'
  )
);
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);
    let tuples = tuple_generator::format_tuples(
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D).tuple_queries(),
    );

    assert!(
        model.model().contains("define project: [project]")
            || model.model().contains("define projects:"),
        "expected parent relation based on project_id, got:\n{}",
        model.model()
    );
    assert!(
        model.model().contains("define can_update:"),
        "membership policy on UPDATE should produce can_update action, got:\n{}",
        model.model()
    );
    assert!(
        tuples.contains("project_id"),
        "tuple SQL should use real fk column, got:\n{tuples}"
    );
    assert!(
        !tuples.contains("team_id"),
        "tuple SQL should not invent team_id, got:\n{tuples}"
    );
}

#[test]
fn p4_membership_generates_resource_bridge_tuples() {
    let sql = r"
CREATE TABLE public.users (id UUID PRIMARY KEY);
CREATE TABLE public.projects (id UUID PRIMARY KEY);
CREATE TABLE public.project_members (
  project_id UUID NOT NULL REFERENCES projects(id),
  user_id UUID NOT NULL REFERENCES users(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON projects FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM project_members
    WHERE project_id = projects.id
      AND user_id = auth_current_user_id()
  )
);
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let tuples = support::plan_tuples(classified, &db, &registry);

    assert!(
        tuples.contains("'projects' AS relation"),
        "expected resource bridge tuples for tuple-to-userset relation, got:\n{tuples}"
    );
    assert!(
        tuples.contains("FROM \"public\".\"projects\""),
        "expected bridge tuples sourced from resource table, got:\n{tuples}"
    );
}

#[test]
fn p4_membership_queries_are_not_deduped_only_by_join_table() {
    let sql = r"
CREATE TABLE public.users (id UUID PRIMARY KEY);
CREATE TABLE public.docs (id UUID PRIMARY KEY);
CREATE TABLE public.tasks (id UUID PRIMARY KEY);
CREATE TABLE public.memberships (
  doc_id UUID REFERENCES docs(id),
  task_id UUID REFERENCES tasks(id),
  user_id UUID NOT NULL REFERENCES users(id),
  role TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM memberships
    WHERE memberships.doc_id = docs.id
      AND memberships.user_id = auth_current_user_id()
      AND memberships.role = 'editor'
  )
);
CREATE POLICY tasks_member ON tasks FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1 FROM memberships
    WHERE memberships.task_id = tasks.id
      AND memberships.user_id = auth_current_user_id()
      AND memberships.role = 'admin'
  )
);
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let tuples = support::plan_tuples(classified, &db, &registry);

    assert!(
        tuples.contains(r#"'docs:' || CASE WHEN "doc_id"::text"#),
        "expected doc membership tuples, got:\n{tuples}"
    );
    assert!(
        tuples.contains(r#"'tasks:' || CASE WHEN "task_id"::text"#),
        "expected task membership tuples, got:\n{tuples}"
    );
}

#[test]
fn p5_parent_inheritance_classifies_and_translates_end_to_end() {
    let sql = r"
CREATE TABLE public.users (id UUID PRIMARY KEY);
CREATE TABLE public.projects (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id)
);
CREATE TABLE public.tasks (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES projects(id)
);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_owner ON projects FOR SELECT TO PUBLIC
  USING (owner_id = current_setting('app.user_id'));
CREATE POLICY tasks_inherit_project ON tasks FOR SELECT TO PUBLIC USING (
  EXISTS (
    SELECT 1
    FROM projects p
    WHERE p.id = tasks.project_id
      AND p.owner_id = current_setting('app.user_id')
  )
);
";

    let (classified, db, registry) = support::classify_sql(sql, None);
    let task_policy = classified
        .iter()
        .find(|cp| cp.name() == "tasks_inherit_project")
        .expect("expected tasks_inherit_project policy");

    let using = task_policy
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(
            &using.pattern,
            rls2fga::classifier::patterns::PatternClass::P5ParentInheritance(ParentInheritance {
                parent_table,
                fk_column,
                ..
            }) if parent_table.name() == "projects" && fk_column == "project_id"
        ),
        "expected tasks policy to classify as P5, got: {:?}",
        using.pattern
    );

    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);
    assert!(
        model.model().contains("type tasks"),
        "expected tasks type in model, got:\n{}",
        model.model()
    );
    // The policy names ownership of the project, so that is what the task requires.
    assert!(
        model
            .model()
            .contains("define can_select: owner from projects"),
        "expected task select permission to require project ownership, got:\n{}",
        model.model()
    );

    let tuples = tuple_generator::format_tuples(
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D).tuple_queries(),
    );
    assert!(
        tuples.contains("'projects' AS relation"),
        "expected tasks->projects bridge tuples for P5 inheritance, got:\n{tuples}"
    );
}

#[test]
fn a_literal_guard_beside_ownership_emits_gate_tuples() {
    let sql = r"
CREATE TABLE public.users (id UUID PRIMARY KEY);
CREATE TABLE public.docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id),
  status TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT TO PUBLIC
  USING (status = 'active' AND owner_id = auth_current_user_id());
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let tuples = support::plan_tuples(classified, &db, &registry);

    assert!(
        tuples.contains("'owner' AS relation"),
        "the relationship half still emits its tuples, got:\n{tuples}"
    );
    assert!(
        tuples.contains("\"status\" = 'active'"),
        "the literal guard is row data, so its gate emits per-row tuples, got:\n{tuples}"
    );
}

#[test]
fn schema_qualified_tables_use_real_columns_in_tuple_sql() {
    let sql = r"
CREATE SCHEMA app;
CREATE TABLE app.users (uid UUID PRIMARY KEY);
CREATE TABLE app.docs (
  doc_uuid UUID PRIMARY KEY,
  owner_user UUID REFERENCES app.users(uid)
);
CREATE FUNCTION app.auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON app.docs FOR SELECT TO PUBLIC
  USING (owner_user = app.auth_current_user_id());
";
    let reg_json = r#"{
      "app.auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let tuples = support::plan_tuples(classified, &db, &registry);

    assert!(
        tuples.contains(r#"'docs:' || CASE WHEN "doc_uuid"::text"#),
        "tuple SQL should canonicalize schema-qualified table names while using real PK columns, got:\n{tuples}"
    );
    assert!(
        tuples.contains(r#"'user:' || CASE WHEN "owner_user"::text"#),
        "tuple SQL should use the real owner FK column, got:\n{tuples}"
    );
    assert!(
        !tuples.contains("'docs:' || \"id\" AS object"),
        "tuple SQL must not fall back to non-existent id column for canonicalized schema-qualified tables, got:\n{tuples}"
    );
}

#[test]
fn casted_current_user_accessor_is_classified_as_direct_ownership() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id)
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON docs FOR SELECT TO PUBLIC
  USING (owner_id = CAST(auth_current_user_id() AS UUID));
";
    let (classified, _db, _registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let policy = classified
        .iter()
        .find(|cp| cp.name() == "p_select")
        .expect("expected p_select policy");

    let using = policy
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(
            using.pattern,
            rls2fga::classifier::patterns::PatternClass::P3DirectOwnership(DirectOwnership { .. })
        ),
        "casted current-user equality should classify as P3, got: {:?}",
        using.pattern
    );
}

#[test]
fn p2_role_in_list_generates_action_permissions() {
    let sql = support::read_fixture_sql("role_in_list");
    let reg_json = support::read_fixture_registry_json("role_in_list");

    let (classified, db, registry) = support::classify_sql(&sql, Some(&reg_json));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    assert!(
        model.model().contains("define can_select:"),
        "P2 policy should generate command permission, got:\n{}",
        model.model()
    );
}

#[test]
fn threshold_operator_and_registry_levels_are_respected() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE TABLE grants (grantee UUID NOT NULL, resource UUID NOT NULL, role INTEGER NOT NULL);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_role(uid UUID, rid UUID) RETURNS INTEGER
  LANGUAGE sql STABLE
  AS 'SELECT 0';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON docs FOR SELECT TO PUBLIC
  USING (get_role(auth_current_user_id(), owner_id) > 2);
";
    let reg_json = r#"{
      "get_role": {
        "kind": "role_threshold",
        "user_param_index": 0,
        "resource_param_index": 1,
        "role_levels": {"viewer": 1, "editor": 2, "admin": 3},
        "grant_table": "grants",
        "grant_grantee_col": "grantee",
        "grant_resource_col": "resource",
        "grant_role_col": "role"
      },
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    assert!(
        model.model().contains("define can_select: role_admin"),
        "strict >2 with levels 1/2/3 should map to admin, got:\n{}",
        model.model()
    );
}

#[test]
fn p2_in_list_does_not_collapse_to_min_threshold() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE TABLE grants (grantee UUID NOT NULL, resource UUID NOT NULL, role INTEGER NOT NULL);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_role(uid UUID, rid UUID) RETURNS INTEGER
  LANGUAGE sql STABLE
  AS 'SELECT 0';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_select ON docs FOR SELECT TO PUBLIC
  USING (get_role(auth_current_user_id(), owner_id) IN (2, 4));
";
    let reg_json = r#"{
      "get_role": {
        "kind": "role_threshold",
        "user_param_index": 0,
        "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
        "grant_table": "grants",
        "grant_grantee_col": "grantee",
        "grant_resource_col": "resource",
        "grant_role_col": "role"
      },
      "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
    }"#;

    let (classified, db, registry) = support::classify_sql(sql, Some(reg_json));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    assert!(
        !model.model().contains("define can_select: role_viewer"),
        "IN (2,4) should not collapse to >=2 threshold semantics, got:\n{}",
        model.model()
    );
}
