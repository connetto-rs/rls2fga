//! A gated membership whose rows are not uniquely keyed by (fk, user) must
//! evaluate its clock per row, as `PostgreSQL` evaluates `EXISTS`: one witness
//! object per membership row, never per-column aggregates that mix rows.

use rls2fga::types::{ConfidenceLevel, TranslationNote};

use crate::support::footgun::{db_of, relation_definition, relation_definitions, translator};

/// The review's finding 5 schema: a surrogate key, so several rows can back one
/// `(doc, user)`, and two future deadlines whose per-column maxima mix rows.
const TWO_DEADLINES: &str = "
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE members(id INT PRIMARY KEY, doc_id TEXT NOT NULL REFERENCES docs(id),
  user_id TEXT NOT NULL, trial_ends TIMESTAMPTZ NOT NULL, support_ends TIMESTAMPTZ NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_user
    AND m.trial_ends > now() AND m.support_ends > now()));
";

fn model_and_tuples(sql: &str) -> (String, String) {
    let db = db_of(sql);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let outputs = translation.outputs_accepting_gaps();
    let tuples = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.clone())
        .collect::<Vec<_>>()
        .join("\n");
    (outputs.model(), tuples)
}

#[test]
fn a_multi_deadline_membership_evaluates_per_row() {
    let (dsl, tuples) = model_and_tuples(TWO_DEADLINES);
    assert!(
        !tuples.contains("GROUP BY") && !tuples.contains("MAX("),
        "per-column aggregates mix rows, so no gated query may group:\n{tuples}"
    );
    assert!(
        dsl.contains("type members_share"),
        "each membership row is its own witness object:\n{dsl}"
    );
    let (witness_relation, witness_body) = relation_definitions(&dsl, "members_share")
        .into_iter()
        .find(|(_, body)| body.contains("user with "))
        .expect("the share type defines its conditional member");
    assert!(
        witness_body.contains("user with "),
        "each witness admits its member only through the condition:\n{dsl}"
    );
    let expected = format!("{witness_relation} from members_share");
    let (access_relation, _) = relation_definitions(&dsl, "docs")
        .into_iter()
        .find(|(_, body)| body == &expected)
        .expect("docs reaches the witness member over the share link");
    assert_ne!(
        access_relation, "member",
        "the witness walk must not reserve the direct member relation:\n{dsl}"
    );
}

/// The witness object is keyed by the membership row's own identity, and its
/// member tuple carries that row's two deadline values for the condition.
#[test]
fn the_witness_tuple_carries_its_own_rows_values() {
    let (_, tuples) = model_and_tuples(TWO_DEADLINES);
    let witness = tuples
        .split_inclusive(';')
        .find(|query| query.contains("members_share:"))
        .expect("a query mints the witness objects");
    assert!(
        witness.contains(
            "jsonb_build_object('trial_ends', \"trial_ends\", 'support_ends', \"support_ends\")"
        ) || witness.contains(
            "jsonb_build_object('support_ends', \"support_ends\", 'trial_ends', \"trial_ends\")"
        ),
        "the context is the row's own values, unaggregated:\n{witness}"
    );
}

/// Rows uniquely keyed by (fk, user) keep the direct one-tuple form, which is
/// already exact: no witness type is minted for them.
#[test]
fn a_uniquely_keyed_membership_keeps_the_direct_form() {
    let sql = "
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE members(id INT PRIMARY KEY, doc_id TEXT NOT NULL REFERENCES docs(id),
  user_id TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, UNIQUE (doc_id, user_id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_user
    AND m.expires_at > now()));
";
    let (dsl, tuples) = model_and_tuples(sql);
    assert!(
        !dsl.contains("members_share"),
        "a uniquely keyed row needs no witness object:\n{dsl}"
    );
    assert!(
        !tuples.contains("GROUP BY"),
        "a uniquely keyed row needs no aggregation either:\n{tuples}"
    );
}

/// The parent admits membership tuples only with their clock condition.
#[test]
fn a_uniquely_keyed_membership_conditions_the_parents_member() {
    let sql = "
CREATE TABLE projects(id TEXT PRIMARY KEY);
CREATE TABLE tasks(id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id));
CREATE TABLE project_members(project_id TEXT NOT NULL REFERENCES projects(id),
  user_id TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (project_id, user_id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT USING (EXISTS (
  SELECT 1 FROM project_members m WHERE m.project_id = tasks.project_id
    AND m.user_id = current_user AND m.expires_at > now()));
";
    let (dsl, _) = model_and_tuples(sql);
    assert!(
        !dsl.contains("project_members_share"),
        "a uniquely keyed row needs no witness object:\n{dsl}"
    );
    let (_, member) = relation_definitions(&dsl, "projects")
        .into_iter()
        .find(|(_, body)| body.starts_with("[user"))
        .expect("the parent admits user membership tuples");
    assert!(
        member.starts_with("[user with ") && member.ends_with(']'),
        "the parent admits its member only through the clock:\n{dsl}"
    );
}

/// The membership's parent is another table, so the witness chain must ride the
/// existing parent indirection: tasks reach projects, projects reach the witnesses.
#[test]
fn a_non_self_parent_keeps_its_indirection_through_the_witnesses() {
    let sql = "
CREATE TABLE projects(id TEXT PRIMARY KEY);
CREATE TABLE tasks(id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id));
CREATE TABLE project_members(id INT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  user_id TEXT NOT NULL, trial_ends TIMESTAMPTZ NOT NULL, support_ends TIMESTAMPTZ NOT NULL);
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT USING (EXISTS (
  SELECT 1 FROM project_members m WHERE m.project_id = tasks.project_id
    AND m.user_id = current_user AND m.trial_ends > now() AND m.support_ends > now()));
";
    let (dsl, tuples) = model_and_tuples(sql);
    assert!(
        !tuples.contains("GROUP BY") && !tuples.contains("MAX("),
        "per-column aggregates mix rows on the parent route too:\n{tuples}"
    );
    let (witness_relation, _) = relation_definitions(&dsl, "project_members_share")
        .into_iter()
        .find(|(_, body)| body.contains("user with "))
        .expect("the share type defines its conditional member");
    let expected = format!("{witness_relation} from project_members_share");
    let (access_relation, _) = relation_definitions(&dsl, "projects")
        .into_iter()
        .find(|(_, body)| body == &expected)
        .expect("the parent reaches the witness member over the share link");
    assert_ne!(
        access_relation, "member",
        "the witness walk must not reserve the direct member relation:\n{dsl}"
    );
    let can_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks defines can_select");
    assert_eq!(
        can_select,
        format!("{access_relation} from projects"),
        "tasks must reach the grant through the exact parent indirection:\n{dsl}"
    );
    // One witness query and one link query name the share objects.
    let share_queries = tuples
        .split_inclusive(';')
        .filter(|query| query.contains("'project_members_share:'"))
        .count();
    assert_eq!(
        share_queries, 2,
        "one witness query and one link query name the share objects:\n{tuples}"
    );
}

/// Two policies over one join table declare different conditions, so their witness
/// member relations must stay distinct or one policy's clock replaces the other's.
#[test]
fn two_policies_over_one_join_table_keep_distinct_witness_relations() {
    let sql = "
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE notes(id TEXT PRIMARY KEY);
CREATE TABLE members(id INT PRIMARY KEY, doc_id TEXT NOT NULL REFERENCES docs(id),
  user_id TEXT NOT NULL, trial_ends TIMESTAMPTZ NOT NULL, support_ends TIMESTAMPTZ NOT NULL);
CREATE TABLE note_links(id INT PRIMARY KEY, note_id TEXT NOT NULL REFERENCES notes(id),
  member_id INT NOT NULL REFERENCES members(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_user
    AND m.trial_ends > now() AND m.support_ends > now()));
CREATE POLICY q ON docs FOR DELETE USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_user
    AND m.trial_ends > now()));
";
    let (dsl, _) = model_and_tuples(sql);
    let witnesses: Vec<(String, String)> = relation_definitions(&dsl, "members_share")
        .into_iter()
        .filter(|(_, body)| body.contains("user with "))
        .collect();
    assert_eq!(
        witnesses.len(),
        2,
        "each policy's condition needs its own witness relation:\n{dsl}"
    );
    assert_ne!(
        witnesses[0].0, witnesses[1].0,
        "two conditions under one name would collide their tuples:\n{dsl}"
    );
}

/// The uncorrelated holder: several reviewer rows per user, two deadlines. The one
/// holder object cannot carry per-column maxima without mixing rows, so it reaches
/// per-row witnesses through a shares link instead.
#[test]
fn an_uncorrelated_holder_reaches_per_row_witnesses() {
    let sql = "
CREATE TABLE memos(id TEXT PRIMARY KEY);
CREATE TABLE reviewers(id INT PRIMARY KEY, user_id TEXT NOT NULL,
  vetted_until TIMESTAMPTZ NOT NULL, cleared_until TIMESTAMPTZ NOT NULL);
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON memos FOR SELECT USING (EXISTS (
  SELECT 1 FROM reviewers r WHERE r.user_id = current_user
    AND r.vetted_until > now() AND r.cleared_until > now()));
";
    let (dsl, tuples) = model_and_tuples(sql);
    assert!(
        !tuples.contains("GROUP BY") && !tuples.contains("MAX("),
        "per-column aggregates mix rows on the holder route too:\n{tuples}"
    );
    let (witness_relation, _) = relation_definitions(&dsl, "reviewers_share")
        .into_iter()
        .find(|(_, body)| body.contains("user with "))
        .expect("the share type defines its conditional member");
    let expected = format!("{witness_relation} from reviewers_share");
    let (access_relation, _) = relation_definitions(&dsl, "reviewers_holder")
        .into_iter()
        .find(|(_, body)| body == &expected)
        .expect("the holder reaches the witness member over the shares link");
    assert_ne!(
        access_relation, "member",
        "the witness walk must not reserve the direct member relation:\n{dsl}"
    );
}

/// A member table nothing identifies cannot mint witnesses. A single past-direction
/// comparison still compresses soundly, but only through the earliest value: the
/// latest is the wrong witness for "since" dates.
#[test]
fn an_identity_less_single_past_comparison_carries_the_earliest_value() {
    let sql = "
CREATE TABLE memos(id TEXT PRIMARY KEY);
CREATE TABLE reviewers(user_id TEXT NOT NULL, vetted_since TIMESTAMPTZ NOT NULL);
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON memos FOR SELECT USING (EXISTS (
  SELECT 1 FROM reviewers r WHERE r.user_id = current_user AND r.vetted_since <= now()));
";
    let (_, tuples) = model_and_tuples(sql);
    assert!(
        tuples.contains("MIN(\"vetted_since\")"),
        "the earliest since-date witnesses whether any row has begun:\n{tuples}"
    );
    assert!(
        !tuples.contains("MAX(\"vetted_since\")"),
        "the latest since-date denies rows PostgreSQL grants:\n{tuples}"
    );
}

/// The same identity-less table with two clock comparisons has no sound compression
/// at all, so the policy falls closed with its reason.
#[test]
fn an_identity_less_multi_comparison_gate_falls_closed() {
    let sql = "
CREATE TABLE memos(id TEXT PRIMARY KEY);
CREATE TABLE reviewers(user_id TEXT NOT NULL,
  vetted_until TIMESTAMPTZ NOT NULL, cleared_until TIMESTAMPTZ NOT NULL);
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON memos FOR SELECT USING (EXISTS (
  SELECT 1 FROM reviewers r WHERE r.user_id = current_user
    AND r.vetted_until > now() AND r.cleared_until > now()));
";
    let db = db_of(sql);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let refused = translation.notes().iter().any(|note| {
        note.to_string()
            .contains("cannot be compressed into one fact without mixing rows")
    });
    assert!(
        refused,
        "falling closed on the unrepresentable corner has to say why: {:?}",
        translation.notes()
    );
    let dsl = translation.outputs_accepting_gaps().model();
    let can_select =
        relation_definition(&dsl, "memos", "can_select").expect("memos defines can_select");
    assert_eq!(
        can_select, "no_access",
        "no sound compression exists, so the command denies:\n{dsl}"
    );
}

#[test]
fn a_witness_membership_announces_the_request_clock() {
    let db = db_of(TWO_DEADLINES);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    assert!(
        translation.notes().iter().any(|note| matches!(
            note,
            TranslationNote::CallerSuppliesConditionParameter {
                parameter,
                setting_key: None,
                ..
            } if parameter == "request_time"
        )),
        "the caller contract must name the witness clock: {:?}",
        translation.notes()
    );
}

#[test]
fn a_holder_witness_applies_the_subject_size_limit_to_its_share() {
    let sql = "
CREATE TABLE memos(id TEXT PRIMARY KEY);
CREATE TABLE reviewers(id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
  vetted_until TIMESTAMPTZ NOT NULL, cleared_until TIMESTAMPTZ NOT NULL);
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON memos FOR SELECT USING (EXISTS (
  SELECT 1 FROM reviewers r WHERE r.user_id = current_user
    AND r.vetted_until > now() AND r.cleared_until > now()));
";
    let (_, tuples) = model_and_tuples(sql);
    let holder_link = tuples
        .split_inclusive(';')
        .find(|query| {
            query.contains("'reviewers_holder:all' AS object")
                && query.contains("'reviewers_share:'")
        })
        .expect("the holder links to each witness");
    assert!(
        holder_link.contains("octet_length('reviewers_share:'"),
        "the witness is a subject and must use the byte limit:\n{holder_link}"
    );
    assert!(
        !holder_link.contains("\nAND length('reviewers_share:'"),
        "the holder object is fixed and needs no column-derived object guard:\n{holder_link}"
    );
}
