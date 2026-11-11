use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::{ConstantBool, PatternClass};
use rls2fga::classifier::policy_classifier;
use rls2fga::generator::tuple_generator;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{ActionAnswer, ActionStatement};

use crate::support;

fn fixture_model_and_tuples(
    fixture: &str,
    registry: &FunctionRegistry,
    confidence: ConfidenceLevel,
) {
    let db = support::parse_fixture_db(fixture);
    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        registry,
        &support::deployment::fixture_deployment(fixture),
    );
    let outputs = support::plan_at(classified, &db, &registry, confidence);
    insta::assert_snapshot!(format!("generate_{fixture}_model"), outputs.model().trim());
    insta::assert_snapshot!(
        format!("generate_{fixture}_tuples"),
        tuple_generator::format_tuples(outputs.tuple_queries())
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
CREATE POLICY app_users_select ON app.users FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));

CREATE TABLE auth.users (id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth_users_select ON auth.users FOR SELECT
    USING (owner_id = current_setting('app.user_id', true));
";
    let db = support::deployment::db(sql);
    let registry = FunctionRegistry::new();
    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
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

/// The constant fixtures are answered without a check. A permissive `TRUE` beside a
/// restrictive `FALSE` refuses every read, and a `pg_has_role` the schema answers yes
/// grants it.
#[test]
fn constant_fixtures_answer_their_reads_locally() {
    for (fixture, expected) in [
        ("constant_bool", ActionAnswer::Denied),
        ("pg_role_gate", ActionAnswer::Unrestricted),
    ] {
        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        assert_eq!(
            support::footgun::action_answer(&outputs, "docs", ActionStatement::Select),
            Some(&expected),
            "{fixture}"
        );
    }
}

// ── Gap 1: the role gate, a constant for `pg_has_role` and a walked scope for
// the role accessor ────────────────────────────────────────────────────────────

/// `pg_has_role` names roles, so the schema's role memberships decide it before any row
/// is read, and the policy grants exactly what they say.
#[test]
fn pg_has_role_is_the_constant_the_memberships_decide() {
    let sql = r"
CREATE ROLE editor NOLOGIN;
GRANT editor TO app_user;
CREATE TABLE docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', 'MEMBER'));
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let pattern = &classified[0]
        .using_classification()
        .expect("USING classifies")
        .pattern;
    assert!(
        matches!(
            pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: true })
        ),
        "the acting role's membership decides the call, got {pattern:?}"
    );
    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    assert_eq!(
        support::footgun::action_answer(&model, "docs", ActionStatement::Select),
        Some(&ActionAnswer::Unrestricted),
        "the membership admits every row"
    );
}

/// The same call about a role the schema never creates cannot be answered, so it is
/// refused and the table stays closed.
#[test]
fn a_pg_has_role_about_a_role_the_schema_never_creates_refuses() {
    let sql = r"
CREATE TABLE docs (id UUID PRIMARY KEY, title TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', 'MEMBER'));
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let pattern = &classified[0]
        .using_classification()
        .expect("USING classifies")
        .pattern;
    let PatternClass::Unknown(refused) = pattern else {
        panic!("the call names a role the schema never creates, got {pattern:?}");
    };
    assert!(
        refused.reason.contains("does not create both"),
        "the refusal names the missing role, got {}",
        refused.reason
    );
    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    assert_eq!(
        support::footgun::relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "the refusal keeps the table closed:\n{}",
        model.model()
    );
}

/// The privilege decides which members the call admits, so it decides the constant the
/// memberships answer, one privilege at a time.
#[test]
fn each_pg_has_role_privilege_answers_from_its_own_membership() {
    let mut complaints = Vec::new();
    for (privilege, grant_options, expected) in [
        ("MEMBER", "", true),
        ("USAGE", "", true),
        ("SET", "", true),
        ("MEMBER WITH ADMIN OPTION", "", false),
        // All three admin spellings are one answer: PostgreSQL ignores the kind once the
        // admin option is asked about.
        ("MEMBER WITH ADMIN OPTION", " WITH ADMIN OPTION", true),
        ("USAGE WITH ADMIN OPTION", " WITH ADMIN OPTION", true),
        ("SET WITH ADMIN OPTION", " WITH ADMIN OPTION", true),
        // A member granted without inheritance holds `MEMBER` and not `USAGE`, one
        // granted with `SET FALSE` holds `MEMBER` and not `SET`.
        ("MEMBER", " WITH INHERIT FALSE", true),
        ("USAGE", " WITH INHERIT FALSE", false),
        ("SET", " WITH SET FALSE", false),
        // Case and surrounding space do not change the answer in PostgreSQL either.
        ("usage", "", true),
        (" MEMBER ", "", true),
        ("member with admin option", " WITH ADMIN OPTION", true),
    ] {
        let sql = format!(
            r"
CREATE ROLE editor NOLOGIN;
GRANT editor TO app_user{grant_options};
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', '{privilege}'));
"
        );
        let (classified, _db, _registry) = support::classify_sql(&sql, None);
        let pattern = &classified[0]
            .using_classification()
            .expect("USING classifies")
            .pattern;
        let answered = match pattern {
            PatternClass::P10ConstantBool(ConstantBool { value }) => *value,
            other => {
                complaints.push(format!(
                    "'{privilege}'{grant_options:?} is answered by a constant, got {other:?}"
                ));
                continue;
            }
        };
        if answered != expected {
            complaints.push(format!(
                "'{privilege}'{grant_options:?} answers {answered}, expected {expected}"
            ));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

/// Two policies asking about different privileges of one role each decide their own
/// constant, so a grant beside a denial composes into the action each one guards.
#[test]
fn two_privileges_of_one_role_each_decide_their_own_constant() {
    let sql = r"
CREATE ROLE editor NOLOGIN;
GRANT editor TO app_user;
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT
    USING (pg_has_role(current_user, 'editor', 'MEMBER'));
CREATE POLICY docs_admin ON docs FOR DELETE
    USING (pg_has_role(current_user, 'editor', 'MEMBER WITH ADMIN OPTION'));
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let dsl = support::plan_at(classified, &db, &registry, ConfidenceLevel::B).model();

    assert_eq!(
        support::footgun::relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("public_viewer and acting_app_user from request_gate"),
        "the acting role's membership admits the read:\n{dsl}"
    );
    assert_eq!(
        support::footgun::relation_definition(&dsl, "docs", "can_delete").as_deref(),
        Some("no_access and acting_app_user from request_gate and can_select"),
        "the acting role holds no admin option on the role:\n{dsl}"
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
    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &registry,
        &support::deployment::fixture_deployment("shared_owner_grants"),
    );

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

    let script = tuple_generator::format_tuples(model.tuple_queries());
    assert_eq!(
        script.matches("Explicit grants over").count(),
        1,
        "the grants load once for both tables:\n{script}"
    );
    assert_eq!(
        script
            .matches("Owner identities that are rows of public.users")
            .count(),
        1,
        "the identity facts load once for both tables:\n{script}"
    );
    assert_eq!(
        script.matches("bridge for tuple-to-userset").count(),
        2,
        "each guarded table points its own rows at the owner:\n{script}"
    );
}

// ── Two owner columns on one table ───────────────────────────────────────────

/// A row judged through two owner values gets one pointer per value, and the rule is the
/// union of the two. Reading both through one pointer would judge a row by a value the call
/// never passed, which is why this shape used to be refused outright.
#[test]
fn generate_two_owner_columns_model_and_tuples() {
    let db = support::parse_fixture_db("two_owner_columns");
    let registry = support::load_fixture_registry("two_owner_columns");
    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &registry,
        &support::deployment::fixture_deployment("two_owner_columns"),
    );

    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let dsl = model.model();
    assert!(
        dsl.contains("define owner_id: [owner_grants_owner]")
            && dsl.contains("define delegate_id: [owner_grants_owner]"),
        "each owner value the policy names gets its own pointer:\n{dsl}"
    );
    assert!(
        dsl.contains("define can_select: (role_viewer from owner_id or role_admin from delegate_id) and acting_app_user from request_gate"),
        "the rule is the union, each side at the level its own call required:\n{dsl}"
    );

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
    let (classified, registry) = policy_classifier::classify_policies_with_effective_registry(
        &db,
        &registry,
        &support::deployment::fixture_deployment("two_role_functions"),
    );

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
