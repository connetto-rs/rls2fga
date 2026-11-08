use rls2fga::types::ConfidenceLevel;

use crate::support;

#[test]
fn multi_policy_table_combines_patterns_for_select() {
    let sql = support::read_fixture_sql("multi_policy_table");
    let (classified, db, registry) = support::classify_sql(&sql, Some(support::ACCESSOR_REGISTRY));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    // `author_id` yields an `author` relation, and the status check compares a column
    // against a literal constant, which the row decides, so it contributes the same
    // wildcard a boolean flag would rather than `no_access`.
    assert!(
        model
            .model()
            .contains("define can_select: author or public_where_status_131bc6df")
            || model
                .model()
                .contains("define can_select: public_where_status_131bc6df or author"),
        "expected composed select permission, got:\n{}",
        model.model()
    );
}

#[test]
fn restrictive_policy_is_anded_with_permissive() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id),
  is_public BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs AS PERMISSIVE FOR SELECT TO PUBLIC
  USING (owner_id = auth_current_user_id());
CREATE POLICY p_public ON docs AS RESTRICTIVE FOR SELECT TO PUBLIC
  USING (is_public = TRUE);
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    assert!(
        model
            .model()
            .contains("define can_select: owner and public_when_is_public")
            || model
                .model()
                .contains("define can_select: public_when_is_public and owner"),
        "restrictive policy should intersect with permissive policy, got:\n{}",
        model.model()
    );
}

#[test]
fn update_using_and_with_check_are_split() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE teams (id UUID PRIMARY KEY);
CREATE TABLE team_members (
  team_id UUID NOT NULL REFERENCES teams(id),
  user_id UUID NOT NULL REFERENCES users(id)
);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL
);
CREATE TABLE owner_grants (
  grantee_owner_id UUID NOT NULL,
  granted_owner_id UUID NOT NULL,
  role_id INTEGER NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_owner_role(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
  LANGUAGE sql STABLE
  AS 'SELECT 0';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_update ON docs FOR UPDATE TO PUBLIC
  USING (get_owner_role(auth_current_user_id(), owner_id) >= 2)
  WITH CHECK (get_owner_role(auth_current_user_id(), owner_id) >= 3);
";
    let reg_json = support::read_fixture_registry_json("earth_metabolome");

    let (classified, db, registry) = support::classify_sql(sql, Some(&reg_json));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    assert!(
        model.model().contains("define can_update_using:"),
        "expected separate UPDATE visibility relation, got:\n{}",
        model.model()
    );
    assert!(
        model.model().contains("define can_update_check:"),
        "expected separate UPDATE check relation, got:\n{}",
        model.model()
    );
    assert!(
        model
            .model()
            .contains("define can_update: can_update_using and can_update_check"),
        "expected combined UPDATE relation, got:\n{}",
        model.model()
    );
}

#[test]
fn for_all_expands_to_crud_actions() {
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
CREATE POLICY p_all ON docs FOR ALL TO PUBLIC
  USING (owner_id = auth_current_user_id());
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    for action in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert!(
            model.model().contains(&format!("define {action}:")),
            "FOR ALL should emit {action}, got:\n{}",
            model.model()
        );
    }
    assert!(
        !model.model().contains("define can_all:"),
        "FOR ALL should be expanded, got:\n{}",
        model.model()
    );
}

#[test]
fn constant_true_false_policies_are_not_unknown() {
    let sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_true ON docs FOR SELECT TO PUBLIC USING (TRUE);
CREATE POLICY p_false ON docs AS RESTRICTIVE FOR SELECT TO PUBLIC USING (FALSE);
";

    let (classified, db, registry) = support::classify_sql(sql, None);
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D);

    assert!(
        !model.model().contains("TODO [Level D]"),
        "constant policies should be recognized without Level D fallback, got:\n{}",
        model.model()
    );
    assert!(
        model.model().contains("define can_select:"),
        "expected selectable relation output, got:\n{}",
        model.model()
    );
}

/// A comparison between two literals settles before classification, so the guard
/// translates as the owner rule with the folded `true` granting everyone.
#[test]
fn a_true_constant_comparison_translates_as_the_rule_it_guards() {
    let owner_sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY, owner UUID NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs FOR SELECT TO PUBLIC
  USING (owner = current_setting('app.user_id', true));
";
    let guarded_sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY, owner UUID NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs FOR SELECT TO PUBLIC
  USING ('on' = 'on' AND owner = current_setting('app.user_id', true));
";
    let (classified, db, registry) = support::classify_sql(owner_sql, None);
    let owner_model = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);
    let (classified, db, registry) = support::classify_sql(guarded_sql, None);
    let guarded_model = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);

    // Strip the grant the folded `true` arm adds and what is left must be the owner
    // rule's model.
    let without_true_arm = guarded_model
        .model()
        .replace("    define public_viewer: [user:*]\n", "")
        .replace(
            "define can_select: owner and public_viewer",
            "define can_select: owner",
        )
        .replace(
            "define can_select: public_viewer and owner",
            "define can_select: owner",
        );
    assert_eq!(
        owner_model.model(),
        without_true_arm,
        "'on' = 'on' settles to true, so the clause reads as the owner rule alone, got:\n{}",
        guarded_model.model()
    );
}

/// A comparison settling to `false` in a restrictive policy denies the reads the
/// permissive rule alone would grant.
#[test]
fn a_false_constant_comparison_in_restrictive_denies() {
    let sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY, owner UUID NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs FOR SELECT TO PUBLIC
  USING (owner = current_setting('app.user_id', true));
CREATE POLICY p_off ON docs AS RESTRICTIVE FOR SELECT TO PUBLIC
  USING ('on' = 'off');
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);
    let dsl = model.model();
    let select = support::footgun::relation_definition(&dsl, "docs", "can_select")
        .expect("docs defines can_select");
    assert!(
        select == "owner and no_access" || select == "no_access and owner",
        "'on' = 'off' settles to false, so the read denies beside the grant, got \
         'define can_select: {select}':\n{dsl}"
    );
}

#[test]
fn json_and_dsl_are_semantically_aligned_for_composite() {
    let sql = support::read_fixture_sql("compound_or");
    let (classified, db, registry) = support::classify_sql(&sql, Some(support::ACCESSOR_REGISTRY));
    let dsl = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D).model();
    let json =
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D).json_model();

    assert!(dsl.contains("type documents"), "dsl missing documents type");
    let doc_type = json
        .type_definitions
        .iter()
        .find(|t| t.type_name.as_str() == "documents")
        .expect("json should contain documents type");

    let rels = doc_type
        .relations
        .as_ref()
        .expect("documents should have relations in json");
    assert!(rels.contains_key("owner"), "json missing owner relation");
    assert!(
        rels.contains_key("public_when_is_public"),
        "json missing the flag's gate relation"
    );
    assert!(
        rels.contains_key("can_select"),
        "json missing can_select relation"
    );
}

#[test]
fn report_includes_with_check_pattern_when_present() {
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
CREATE POLICY p_upd ON docs FOR UPDATE TO PUBLIC
  USING (owner_id = auth_current_user_id())
  WITH CHECK (FALSE);
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);
    let report_md = outputs.report();

    assert!(
        report_md.contains("p_upd (WITH CHECK)"),
        "report should include separate WITH CHECK entry, got:\n{report_md}"
    );
    assert!(
        report_md.contains("P10 (constant false)"),
        "report should show WITH CHECK pattern details, got:\n{report_md}"
    );
}
