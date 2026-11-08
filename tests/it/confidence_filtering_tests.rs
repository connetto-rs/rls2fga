use rls2fga::generator::tuple_generator;
use rls2fga::types::ConfidenceLevel;

use crate::support;

#[test]
fn json_model_respects_min_confidence_threshold() {
    let sql = support::read_fixture_sql("multi_policy_table");
    let (classified, db, registry) = support::classify_sql(&sql, Some(support::ACCESSOR_REGISTRY));
    let json =
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::A).json_model();

    let posts = json
        .type_definitions
        .iter()
        .find(|t| t.type_name.as_str() == "posts")
        .expect("posts type should exist");
    let relations = posts
        .relations
        .as_ref()
        .expect("posts should have relations");

    assert!(
        !relations.contains_key("public_viewer"),
        "A-threshold JSON output should exclude C-level public_viewer relation, got: {json:#?}"
    );
}

#[test]
fn model_generation_respects_min_confidence_threshold() {
    let sql = support::read_fixture_sql("multi_policy_table");
    let (classified, db, registry) = support::classify_sql(&sql, Some(support::ACCESSOR_REGISTRY));
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::A);

    assert!(
        !model.model().contains("public_viewer"),
        "A-threshold model output should exclude C-level public_viewer relation, got:\n{}",
        model.model()
    );
}

#[test]
fn tuple_generation_respects_min_confidence_threshold() {
    let sql = r"
CREATE TABLE users (id UUID PRIMARY KEY);
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES users(id),
  status TEXT NOT NULL
);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT TO PUBLIC
  USING (status = 'published' AND owner_id = auth_current_user_id());
";
    let (classified, db, registry) = support::classify_sql(sql, Some(support::ACCESSOR_REGISTRY));
    let tuples_a = tuple_generator::format_tuples(
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::A).tuple_queries(),
    );

    assert!(
        !tuples_a.contains("'owner' AS relation"),
        "A-threshold tuple output should exclude C-level ABAC tuples, got:\n{tuples_a}"
    );

    let tuples_d = tuple_generator::format_tuples(
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D).tuple_queries(),
    );

    assert!(
        tuples_d.contains("'owner' AS relation"),
        "D-threshold tuple output should include ABAC-derived ownership tuples, got:\n{tuples_d}"
    );
}

#[test]
fn p9_attribute_policy_does_not_emit_placeholder_tuple_sql() {
    let sql = support::read_fixture_sql("multi_policy_table");
    let (classified, db, registry) = support::classify_sql(&sql, Some(support::ACCESSOR_REGISTRY));
    let tuples = tuple_generator::format_tuples(
        support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::D).tuple_queries(),
    );

    assert!(
        !tuples.contains("TODO [Level C]: Attribute condition"),
        "attribute-only policies should not emit broad placeholder tuple SQL, got:\n{tuples}"
    );
    assert!(
        !tuples.contains("IS NOT NULL; -- TODO: replace with actual condition"),
        "attribute-only policies should not emit IS NOT NULL tuple filters, got:\n{tuples}"
    );
}

// ── Per arm thresholding: one OR policy and two policies are the same database ──

const OR_INSIDE: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_a TEXT, owner_b TEXT);
CREATE FUNCTION auth_uid() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_a = auth_uid() OR owner_b = auth_uid());
";

const TWO_POLICIES: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_a TEXT, owner_b TEXT);
CREATE FUNCTION auth_uid() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON docs FOR SELECT USING (owner_a = auth_uid());
CREATE POLICY pb ON docs FOR SELECT USING (owner_b = auth_uid());
";

/// An arm nothing can read, beside an arm at the top grade.
const OR_WITH_UNKNOWN_ARM: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_a TEXT, owner_b TEXT);
CREATE FUNCTION auth_uid() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_a = auth_uid() OR unreadable(owner_b));
";

const TWO_POLICIES_ONE_UNKNOWN: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_a TEXT, owner_b TEXT);
CREATE FUNCTION auth_uid() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON docs FOR SELECT USING (owner_a = auth_uid());
CREATE POLICY pb ON docs FOR SELECT USING (unreadable(owner_b));
";

fn can_select_of(sql: &str, min: ConfidenceLevel) -> String {
    let (classified, db, registry) = support::classify_sql(sql, None);
    let outputs = support::plan_at(classified, &db, &registry, min);
    outputs
        .model()
        .lines()
        .find(|line| line.contains("define can_select:"))
        .unwrap_or("    define can_select: <absent>")
        .trim()
        .to_string()
}

/// Principle 6, first breach: one weak arm must not take the strong one with it.
#[test]
fn a_weak_arm_does_not_drag_the_strong_one_out_of_the_model() {
    assert_eq!(
        can_select_of(OR_WITH_UNKNOWN_ARM, ConfidenceLevel::B),
        can_select_of(TWO_POLICIES_ONE_UNKNOWN, ConfidenceLevel::B),
        "the same database written two ways must land in the same behaviour"
    );
    assert_eq!(
        can_select_of(OR_WITH_UNKNOWN_ARM, ConfidenceLevel::B),
        "define can_select: owner_a and acting_app_user from request_gate",
        "the arm the caller's bar admits stays in the model"
    );
}

/// Principle 6, second breach: two strong arms must survive the strictest bar, which the
/// cap on a composite's grade used to prevent with nothing weak anywhere.
#[test]
fn two_strong_arms_survive_the_strictest_bar() {
    assert_eq!(
        can_select_of(OR_INSIDE, ConfidenceLevel::A),
        can_select_of(TWO_POLICIES, ConfidenceLevel::A),
        "the same database written two ways must land in the same behaviour"
    );
    assert_eq!(
        can_select_of(OR_INSIDE, ConfidenceLevel::A),
        "define can_select: (owner_a or owner_b) and acting_app_user from request_gate",
        "nothing here is below the bar, so nothing may be dropped"
    );
}

/// Dropping an arm of an `AND` would widen, so it never happens: the whole conjunction
/// goes, exactly as its lowest arm's grade already said.
#[test]
fn a_weak_arm_of_a_conjunction_takes_the_whole_conjunction() {
    let sql = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_a TEXT, owner_b TEXT);
CREATE FUNCTION auth_uid() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_a = auth_uid() AND unreadable(owner_b));
";
    assert_eq!(
        can_select_of(sql, ConfidenceLevel::B),
        "define can_select: no_access",
        "keeping half a conjunction would grant rows the other half refuses"
    );
}

/// One survivor is that arm, not a union of one. A composite's grade is capped at second
/// best, so wrapping the survivor would drop it at the strictest bar while the same
/// database written as two policies keeps it.
#[test]
fn one_surviving_arm_keeps_its_own_grade() {
    assert_eq!(
        can_select_of(OR_WITH_UNKNOWN_ARM, ConfidenceLevel::A),
        can_select_of(TWO_POLICIES_ONE_UNKNOWN, ConfidenceLevel::A),
        "the same database written two ways must land in the same behaviour"
    );
    assert_eq!(
        can_select_of(OR_WITH_UNKNOWN_ARM, ConfidenceLevel::A),
        "define can_select: owner_a and acting_app_user from request_gate",
        "the surviving arm is what the model carries"
    );
    // The grade is the observable that separates the two: a union of one is capped at
    // second best, so reporting B here would tell an operator the ownership arm was
    // guessed at when it was read exactly.
    assert_eq!(
        summary_of(OR_WITH_UNKNOWN_ARM, ConfidenceLevel::A),
        summary_of(TWO_POLICIES_ONE_UNKNOWN, ConfidenceLevel::A),
        "the same database reports the same grade whichever way it is written"
    );
    assert_eq!(
        summary_of(OR_WITH_UNKNOWN_ARM, ConfidenceLevel::A),
        vec![ConfidenceLevel::A],
        "the surviving arm is graded as itself, not as a union of one"
    );
}

/// The grades the report says are in the model.
fn summary_of(sql: &str, min: ConfidenceLevel) -> Vec<ConfidenceLevel> {
    let (classified, db, registry) = support::classify_sql(sql, None);
    support::plan_at(classified, &db, &registry, min)
        .confidence_summary()
        .iter()
        .map(|(_, level)| *level)
        .collect()
}
