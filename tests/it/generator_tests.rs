use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::tuple_generator;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::names::role_scope_name;
use rls2fga::parser::sql_parser;
use rls2fga::types::ConfidenceLevel;

use crate::support;

fn load_emi() -> (
    Vec<rls2fga::classifier::patterns::ClassifiedPolicy>,
    sql_parser::ParserDB,
    FunctionRegistry,
) {
    support::load_fixture_classified("earth_metabolome")
}

fn fixture_model_and_tuples(
    fixture: &str,
    registry: &FunctionRegistry,
    confidence: ConfidenceLevel,
) {
    let db = support::parse_fixture_db(fixture);
    let classified = policy_classifier::classify_policies(&db, registry);
    let outputs = support::plan_at(classified, &db, registry, confidence);
    insta::assert_snapshot!(format!("generate_{fixture}_model"), outputs.model().trim());
    insta::assert_snapshot!(
        format!("generate_{fixture}_tuples"),
        tuple_generator::format_tuples(outputs.tuple_queries())
    );
}

#[test]
fn generate_emi_model() {
    let (classified, db, registry) = load_emi();
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(model.model().trim());
}

#[test]
fn generate_emi_tuples() {
    let db = support::parse_fixture_db("earth_metabolome");
    let registry = support::load_fixture_registry("earth_metabolome");
    let classified = policy_classifier::classify_policies(&db, &registry);
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    insta::assert_snapshot!(tuple_generator::format_tuples(tuples));
}

#[test]
fn generate_emi_json_model() {
    let (classified, db, registry) = load_emi();
    let model =
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B).json_model();
    insta::assert_json_snapshot!(model);
}

#[test]
fn generate_simple_ownership_model() {
    let db = support::parse_fixture_db("simple_ownership");

    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth_current_user_id",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(model.model().trim());
}

#[test]
fn generate_public_flag_model() {
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!(model.model().trim());
}

// ── P2: role name IN-list ────────────────────────────────────────────────────

#[test]
fn generate_role_in_list_model_and_tuples() {
    fixture_model_and_tuples(
        "role_in_list",
        &support::load_fixture_registry("role_in_list"),
        ConfidenceLevel::B,
    );
}

// ── P5: parent inheritance ───────────────────────────────────────────────────

#[test]
fn generate_parent_inheritance_model_and_tuples() {
    fixture_model_and_tuples(
        "parent_inheritance",
        &FunctionRegistry::new(),
        ConfidenceLevel::B,
    );
}

// ── P6: boolean flag tuples (model snapshot already exists) ─────────────────

#[test]
fn generate_public_flag_tuples() {
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    insta::assert_snapshot!(tuple_generator::format_tuples(tuples));
}

// ── P7: ABAC AND (relationship + attribute) ──────────────────────────────────

#[test]
fn generate_abac_status_model_and_tuples() {
    fixture_model_and_tuples(
        "abac_status",
        &support::load_fixture_registry("abac_status"),
        ConfidenceLevel::C,
    );
}

// ── P8: composite OR (P3 + P6) ───────────────────────────────────────────────

#[test]
fn generate_compound_or_model_and_tuples() {
    fixture_model_and_tuples(
        "compound_or",
        &support::try_load_fixture_registry("compound_or"),
        ConfidenceLevel::B,
    );
}

// ── P10: constant TRUE / FALSE ───────────────────────────────────────────────

#[test]
fn schema_collision_tables_get_disambiguated_type_names() {
    // Two schema-qualified tables that canonicalize to the same base name must receive
    // distinct OpenFGA type names.  The generator should append a stable hex suffix to
    // the colliding entry and emit a TranslationNote describing the collision.
    let sql = r"
CREATE SCHEMA app;
CREATE SCHEMA auth;
CREATE TABLE app.users (id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_users_select ON app.users FOR SELECT USING (owner_id = current_user);

CREATE TABLE auth.users (id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth_users_select ON auth.users FOR SELECT USING (owner_id = current_user);
";
    let db = sql_parser::parse_schema(sql).expect("schema should parse");
    let registry = FunctionRegistry::new();
    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);

    // Both tables must have a type in the DSL. They should NOT be merged.
    let type_count = model.model().matches("type users").count()
        + model
            .model()
            .split('\n')
            .filter(|l| l.trim().starts_with("type "))
            .count();
    assert!(
        type_count > 1,
        "Two tables canonicalizing to 'users' must produce at least two resource types;\n\nDSL:\n{}",
        model.model()
    );
    // A TODO item should flag the collision.
    assert!(
        model
            .notes()
            .iter()
            .any(|t| t.message().contains("collision")),
        "Expected a TODO item describing the type-name collision"
    );
}

#[test]
fn generate_constant_bool_model_and_tuples() {
    fixture_model_and_tuples(
        "constant_bool",
        &FunctionRegistry::new(),
        ConfidenceLevel::B,
    );
}

// ── Gap 1: pg_has_role / RoleAccessor → a walked pg_role scope ───────────────

/// The relation holds `[pg_role]` subjects, so pointing an action straight at it admits a
/// `pg_role:` object and never a `user:`. The action has to walk it to the role's members,
/// which is also what makes `pg_role#member` exist for the operator to load into.
#[test]
fn pg_has_role_walks_the_scope_to_the_roles_members() {
    let sql = r"
CREATE TABLE public.docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', 'MEMBER'));
";
    let (classified, db, registry) = support::classify_sql(sql, None);

    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    assert_eq!(
        support::footgun::relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some(
            format!(
                "member from {}",
                role_scope_name("member", &["editor".to_string()])
            )
            .as_str()
        ),
        "pg_has_role admits every member of the role, so the grant walks the scope:\n{}",
        model.model()
    );
    assert!(
        model.model().contains("define member: [user]"),
        "the walked relation has to exist for the operator to load memberships into:\n{}",
        model.model()
    );
    insta::assert_snapshot!("pg_has_role_model", model.model().trim());

    insta::assert_snapshot!(
        "pg_has_role_tuples",
        tuple_generator::format_tuples(model.tuple_queries())
    );
}

/// The accessor spelling reaches the same gate, so it needs the same walk.
#[test]
fn role_accessor_walks_the_scope_to_the_roles_members() {
    let sql = r"
CREATE TABLE public.docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (auth.role() = 'authenticated');
";
    let registry_json = r#"{
  "auth.role": {"kind": "role_accessor"}
}"#;
    let (classified, db, registry) = support::classify_sql(sql, Some(registry_json));

    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    assert_eq!(
        support::footgun::relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some(
            format!(
                "member from {}",
                role_scope_name("member", &["authenticated".to_string()])
            )
            .as_str()
        ),
        "the role accessor admits every member of the role:\n{}",
        model.model()
    );
    insta::assert_snapshot!("role_accessor_model", model.model().trim());

    insta::assert_snapshot!(
        "role_accessor_tuples",
        tuple_generator::format_tuples(model.tuple_queries())
    );
}

/// The privilege decides which members the policy admits, so it decides which relation the
/// gate walks. Probed on `postgres:18`: a member granted without inheritance has `MEMBER`
/// and not `USAGE`, one granted with `SET FALSE` has `MEMBER` and not `SET`, and only an
/// administrator has any `WITH ADMIN OPTION` form, whichever kind precedes it.
#[test]
fn each_pg_has_role_privilege_walks_its_own_relation() {
    let mut complaints = Vec::new();
    for (privilege, relation) in [
        ("MEMBER", "member"),
        ("USAGE", "usage"),
        ("SET", "set_role"),
        // All three admin spellings are one answer: PostgreSQL ignores the kind once the
        // admin option is asked about.
        ("MEMBER WITH ADMIN OPTION", "admin_option"),
        ("USAGE WITH ADMIN OPTION", "admin_option"),
        ("SET WITH ADMIN OPTION", "admin_option"),
        // Case and surrounding space do not change the answer in PostgreSQL either.
        ("usage", "usage"),
        (" MEMBER ", "member"),
        ("member with admin option", "admin_option"),
    ] {
        let sql = format!(
            r"
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', '{privilege}'));
"
        );
        let (classified, db, registry) = support::classify_sql(&sql, None);
        let dsl = support::plan_at(classified, &db, &registry, ConfidenceLevel::B).model();

        let expected = format!(
            "{relation} from {}",
            role_scope_name(relation, &["editor".to_string()])
        );
        if support::footgun::relation_definition(&dsl, "docs", "can_select").as_deref()
            != Some(expected.as_str())
        {
            complaints.push(format!(
                "'{privilege}' should walk `{expected}`, got `{:?}`",
                support::footgun::relation_definition(&dsl, "docs", "can_select")
            ));
        }
        if support::footgun::relation_definition(&dsl, "pg_role", relation).as_deref()
            != Some("[user]")
        {
            complaints.push(format!(
                "'{privilege}' needs pg_role#{relation} for the operator to load into:\n{dsl}"
            ));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

/// Two policies naming different privileges of one role is the shape that forces a relation
/// per privilege: sharing one would make the operator's single set of facts mean both.
#[test]
fn two_privileges_of_one_role_get_their_own_relations() {
    let sql = r"
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', 'USAGE'));
CREATE POLICY docs_admin ON docs FOR DELETE
    USING (pg_has_role(current_user, 'editor', 'MEMBER WITH ADMIN OPTION'));
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let dsl = support::plan_at(classified, &db, &registry, ConfidenceLevel::B).model();

    assert_eq!(
        support::footgun::relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some(
            format!(
                "usage from {}",
                role_scope_name("usage", &["editor".to_string()])
            )
            .as_str()
        ),
        "the read policy asked about inheriting members:\n{dsl}"
    );
    assert_eq!(
        support::footgun::relation_definition(&dsl, "docs", "can_delete").as_deref(),
        Some(
            format!(
                "admin_option from {} and can_select",
                role_scope_name("admin_option", &["editor".to_string()])
            )
            .as_str()
        ),
        "the delete policy asked about the role's administrators:\n{dsl}"
    );
    for relation in ["usage", "admin_option"] {
        assert_eq!(
            support::footgun::relation_definition(&dsl, "pg_role", relation).as_deref(),
            Some("[user]"),
            "each privilege needs its own set of facts:\n{dsl}"
        );
    }
    assert_eq!(
        support::footgun::relation_definition(&dsl, "pg_role", "member"),
        None,
        "no policy asked about plain membership, so nothing may offer to hold it:\n{dsl}"
    );
}

/// A privilege the crate cannot read is not plain membership. `PostgreSQL` answers false for
/// an unrecognised string, so falling closed is faithful, and a privilege that is not a
/// literal cannot be known at all.
#[test]
fn a_pg_has_role_privilege_the_crate_cannot_read_falls_closed() {
    for privilege in ["'MEMBER WITH GRANT OPTION'", "'nonsense'", "some_column"] {
        let sql = format!(
            r"
CREATE TABLE docs (id TEXT PRIMARY KEY, some_column TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', {privilege}));
"
        );
        let (classified, db, registry) = support::classify_sql(&sql, None);
        let dsl = support::plan_at(classified, &db, &registry, ConfidenceLevel::B).model();
        assert_eq!(
            support::footgun::relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "{privilege} names no privilege the crate can act on:\n{dsl}"
        );
    }
}

// ── P9: standalone attribute condition ──────────────────────────────────────

#[test]
fn generate_attribute_guard_model_and_tuples() {
    fixture_model_and_tuples(
        "attribute_guard",
        &FunctionRegistry::new(),
        ConfidenceLevel::C,
    );
}

// ── Request-time conditions ──────────────────────────────────────────────────

/// The only fixture carrying conditions, so it is the only mechanical check on the
/// condition block and on the context column the tuple SQL builds beside it.
#[test]
fn generate_shared_policy_name_model_and_tuples() {
    fixture_model_and_tuples(
        "shared_policy_name",
        &FunctionRegistry::new(),
        ConfidenceLevel::B,
    );
}

// ── One owner shared by two guarded tables ───────────────────────────────────

/// A grant is a fact about the owner it names, so two tables reading one role function
/// share the owner and the grants are loaded once for both.
///
/// The thresholds differ, which is what shows one ladder answering two tables: a viewer
/// reads a sample and not a spectrum.
#[test]
fn generate_shared_owner_grants_model_and_tuples() {
    let db = support::parse_fixture_db("shared_owner_grants");
    let registry = support::load_fixture_registry("shared_owner_grants");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let dsl = model.model();
    assert_eq!(
        dsl.matches("type owner_grants_owner").count(),
        1,
        "one owner serves both tables:\n{dsl}"
    );
    assert!(
        dsl.contains("define can_select: role_viewer from owner_id"),
        "the sample reads at the viewer level:\n{dsl}"
    );
    assert!(
        dsl.contains("define can_select: role_editor from owner_id"),
        "the spectrum reads at the editor level:\n{dsl}"
    );
    insta::assert_snapshot!("generate_shared_owner_grants_model", dsl.trim());

    let script = tuple_generator::format_tuples(model.tuple_queries());
    assert_eq!(
        script.matches("Explicit grants over").count(),
        1,
        "the grants load once for both tables:\n{script}"
    );
    assert_eq!(
        script
            .matches("Owner identities that are rows of users")
            .count(),
        1,
        "the identity facts load once for both tables:\n{script}"
    );
    assert_eq!(
        script.matches("bridge for tuple-to-userset").count(),
        2,
        "each guarded table points its own rows at the owner:\n{script}"
    );
    insta::assert_snapshot!("generate_shared_owner_grants_tuples", script);
}

// ── Two owner columns on one table ───────────────────────────────────────────

/// A row judged through two owner values gets one pointer per value, and the rule is the
/// union of the two. Reading both through one pointer would judge a row by a value the call
/// never passed, which is why this shape used to be refused outright.
#[test]
fn generate_two_owner_columns_model_and_tuples() {
    let db = support::parse_fixture_db("two_owner_columns");
    let registry = support::load_fixture_registry("two_owner_columns");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let dsl = model.model();
    assert!(
        dsl.contains("define owner_id: [owner_grants_owner]")
            && dsl.contains("define delegate_id: [owner_grants_owner]"),
        "each owner value the policy names gets its own pointer:\n{dsl}"
    );
    assert!(
        dsl.contains("define can_select: role_viewer from owner_id or role_admin from delegate_id"),
        "the rule is the union, each side at the level its own call required:\n{dsl}"
    );
    insta::assert_snapshot!("generate_two_owner_columns_model", dsl.trim());

    let script = tuple_generator::format_tuples(model.tuple_queries());
    assert_eq!(
        script.matches("bridge for tuple-to-userset").count(),
        2,
        "one pointer query per owner column:\n{script}"
    );
    assert_eq!(
        script.matches("Explicit grants over").count(),
        1,
        "the grants are about the owner, so both columns read one load:\n{script}"
    );
    insta::assert_snapshot!("generate_two_owner_columns_tuples", script);
}

// ── Two role functions over one grant table ──────────────────────────────────

/// Two functions counting one grant column on two scales get one owner each.
///
/// Sharing the owner would make `grant_viewer` at level 2 and `grant_clerk` at level 5 the
/// same relation on the same object, so a grant on either scale would answer for both. The
/// name carries the function for exactly that reason, and both take the suffix rather than
/// the first keeping the bare name, since a name that depends on translation order is how a
/// barrier gets overwritten.
#[test]
fn generate_two_role_functions_keeps_their_ladders_apart() {
    let (db, registry) = support::load_fixture_db_and_registry("two_role_functions");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let dsl = model.model();
    let owners: Vec<&str> = dsl
        .lines()
        .filter_map(|line| line.strip_prefix("type "))
        .filter(|name| name.starts_with("owner_grants_owner"))
        .collect();
    assert_eq!(
        owners.len(),
        2,
        "each function owns its own scale, so neither may take the bare name: {owners:?}\n{dsl}"
    );
    for owner in &owners {
        assert_ne!(
            *owner, "owner_grants_owner",
            "both take the suffix, so the name cannot depend on which function came first"
        );
    }
    // The scales stay apart: one owner carries the viewer ladder, the other the clerk one,
    // and no owner carries both.
    let scale_of = |relation: &str| {
        dsl.split("\ntype ")
            .filter(|block| block.contains(&format!("define {relation}: ")))
            .count()
    };
    assert_eq!(
        scale_of("grant_viewer"),
        1,
        "one owner reads the role scale:\n{dsl}"
    );
    assert_eq!(
        scale_of("grant_clerk"),
        1,
        "one owner reads the tier scale:\n{dsl}"
    );
    for block in dsl.split("\ntype ") {
        assert!(
            !(block.contains("define grant_viewer: ") && block.contains("define grant_clerk: ")),
            "one owner carrying both scales answers a grant on either for both:\n{dsl}"
        );
    }
    insta::assert_snapshot!("generate_two_role_functions_model", dsl.trim());
}

/// The grant SQL two ladders over one grant table produce.
///
/// The model half is pinned above. Which facts get written is the other half of "the
/// grants are stored once and serve both tables", and only the SQL says it.
#[test]
fn generate_two_role_functions_tuples() {
    let db = support::parse_fixture_db("two_role_functions");
    let registry = support::load_fixture_registry("two_role_functions");
    let classified = policy_classifier::classify_policies(&db, &registry);

    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    insta::assert_snapshot!(
        "generate_two_role_functions_tuples",
        tuple_generator::format_tuples(tuples)
    );
}

/// The caller-set share family, which no snapshot pins today.
///
/// This is the only fixture emitting a share type, and it also carries a condition, so
/// it is where a change to either shape becomes visible as text rather than only inside
/// a container run.
#[test]
fn generate_connetto_capability_model_and_tuples() {
    fixture_model_and_tuples(
        "connetto_capability",
        &support::try_load_fixture_registry("connetto_capability"),
        ConfidenceLevel::B,
    );
}

/// The caller-set share reached through a parent, the one shape of the family where the
/// gate rides the share row and the guarded row reaches it through the team it belongs to.
#[test]
fn generate_connetto_team_share_model_and_tuples() {
    fixture_model_and_tuples(
        "connetto_team_share",
        &support::try_load_fixture_registry("connetto_team_share"),
        ConfidenceLevel::B,
    );
}

/// The plainest shape the crate emits, pinned as SQL as well as as a model.
///
/// Ownership is what every other shape is read against, and the identity encoding, the
/// null guards and the subject budget all show up here first.
#[test]
fn generate_simple_ownership_tuples() {
    let db = support::parse_fixture_db("simple_ownership");
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth_current_user_id",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );
    let outputs = support::plan_at(
        policy_classifier::classify_policies(&db, &registry),
        &db,
        &registry,
        ConfidenceLevel::B,
    );
    let tuples = outputs.tuple_queries();
    insta::assert_snapshot!(tuple_generator::format_tuples(tuples));
}
