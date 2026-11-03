//! Which tables each policy's clauses read.
//!
//! A consumer refusing a table whose change stream lost its previous images refuses every
//! policy reading it too, so the report errs toward naming more. What the database reads
//! counts whether or not the model translated it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::{NoteSeverity, PolicyCommand, PolicyReads};

fn translate(sql: &str) -> Translation {
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    TranslatorBuilder::new()
        .build()
        .translate(&db)
        .expect("translation should plan")
}

/// The one entry for the policy named `name`.
fn entry<'t>(translation: &'t Translation, name: &str) -> &'t PolicyReads {
    let mut named = translation
        .policy_reads()
        .iter()
        .filter(|entry| entry.name == name);
    let found = named.next().expect("the policy has an entry");
    assert!(named.next().is_none(), "one entry per policy");
    found
}

fn reads(entry: &PolicyReads) -> Vec<String> {
    entry.reads.iter().map(ToString::to_string).collect()
}

/// The request's reproduction, a membership subquery in the shape share policies take.
const MEMBERSHIP: &str = "
CREATE TABLE docs (id uuid PRIMARY KEY, owner_id uuid, title text);
CREATE TABLE members (doc_id uuid, user_id uuid, role text);
CREATE TABLE unrelated (id uuid PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT TO public
  USING (EXISTS (
    SELECT 1 FROM members
    WHERE members.doc_id = docs.id
      AND members.user_id = current_setting('app.user_id')::uuid
  ));
";

#[test]
fn a_membership_policy_reads_its_table_and_the_membership_table() {
    let translation = translate(MEMBERSHIP);
    let entry = entry(&translation, "docs_member");
    assert_eq!(entry.table.to_string(), "docs");
    assert_eq!(entry.command, PolicyCommand::Select);
    assert_eq!(reads(entry), ["docs", "members"]);
    assert!(
        entry.unresolved.is_empty(),
        "a built-in call reads no table, so nothing is left unknown: {:?}",
        entry.unresolved
    );
}

#[test]
fn each_policy_on_one_table_reports_its_own_clauses() {
    let translation = translate(
        "
CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE members (doc_id INT, user_id TEXT);
CREATE TABLE editors (doc_id INT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY readers ON docs FOR SELECT
  USING (id IN (SELECT doc_id FROM members WHERE user_id = current_user));
CREATE POLICY writers ON docs FOR INSERT
  WITH CHECK (id IN (SELECT doc_id FROM editors WHERE user_id = current_user));
",
    );
    let readers = entry(&translation, "readers");
    assert_eq!(readers.command, PolicyCommand::Select);
    assert_eq!(reads(readers), ["docs", "members"]);
    let writers = entry(&translation, "writers");
    assert_eq!(writers.command, PolicyCommand::Insert);
    assert_eq!(
        reads(writers),
        ["docs", "editors"],
        "the WITH CHECK clause is read as much as USING is"
    );
}

#[test]
fn reads_resolve_through_the_search_path_to_the_schema_that_holds_them() {
    let translation = translate(
        "
CREATE SCHEMA app;
SET search_path TO app, public;
CREATE TABLE app.docs (id INT PRIMARY KEY);
CREATE TABLE app.members (doc_id INT, user_id TEXT);
CREATE TABLE public.members (doc_id INT, user_id TEXT);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs
  USING (id IN (SELECT doc_id FROM members WHERE user_id = current_user));
",
    );
    let entry = entry(&translation, "d");
    assert_eq!(entry.table.to_string(), "app.docs");
    assert_eq!(reads(entry), ["app.docs", "app.members"]);
}

/// A body the classifier never inlines still runs when the database evaluates the clause.
#[test]
fn a_plpgsql_body_the_clause_calls_counts_as_read() {
    let translation = translate(
        "
CREATE TABLE docs (id INT PRIMARY KEY, owner_id INT);
CREATE TABLE roles (user_id INT, lvl INT);
CREATE FUNCTION lvl(u INT) RETURNS INT LANGUAGE plpgsql STABLE AS $$
BEGIN
  RETURN (SELECT roles.lvl FROM roles WHERE roles.user_id = u);
END
$$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (lvl(owner_id) > 2);
",
    );
    let entry = entry(&translation, "d");
    assert_eq!(reads(entry), ["docs", "roles"]);
    assert!(entry.unresolved.is_empty(), "{:?}", entry.unresolved);
}

#[test]
fn a_function_reached_through_another_counts_as_read() {
    let translation = translate(
        "
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE members (doc_id TEXT, user_id TEXT);
CREATE FUNCTION is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
  AS $$ SELECT EXISTS (SELECT 1 FROM members WHERE doc_id = d AND user_id = current_user) $$;
CREATE FUNCTION can_read(d TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
  AS $$ SELECT is_member(d) $$;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (can_read(id));
",
    );
    assert_eq!(reads(entry(&translation, "d")), ["docs", "members"]);
}

#[test]
fn a_body_the_schema_cannot_show_leaves_the_policy_unresolved() {
    let translation = translate(
        "
CREATE TABLE docs (id INT PRIMARY KEY, owner_id INT);
CREATE FUNCTION allowed(u INT) RETURNS BOOLEAN LANGUAGE c AS 'access', 'allowed';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (allowed(owner_id));
",
    );
    let entry = entry(&translation, "d");
    assert_eq!(reads(entry), ["docs"]);
    assert!(
        entry
            .unresolved
            .iter()
            .any(|reason| reason.contains("allowed")),
        "the unreadable body is named: {:?}",
        entry.unresolved
    );
}

/// Confidence decides what the model enforces, never what the database reads.
#[test]
fn a_clause_the_translation_dropped_still_counts() {
    let translation = translate(
        "
CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE audit (doc_id INT, seen INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs
  USING ((SELECT sum(seen) FROM audit WHERE audit.doc_id = docs.id) * 7 % 3 = 1);
",
    );
    assert!(
        translation
            .notes()
            .iter()
            .any(|note| note.severity() == NoteSeverity::BelowThreshold),
        "the clause falls below the confidence threshold and leaves the model"
    );
    assert_eq!(reads(entry(&translation, "d")), ["audit", "docs"]);
}

#[test]
fn a_view_the_clause_reads_counts_as_its_base_tables() {
    let translation = translate(
        "
CREATE TABLE docs (id INT PRIMARY KEY);
CREATE TABLE members (doc_id INT, user_id TEXT, active BOOLEAN);
CREATE VIEW active_members AS SELECT doc_id, user_id FROM members WHERE active;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs
  USING (id IN (SELECT doc_id FROM active_members WHERE user_id = current_user));
",
    );
    assert_eq!(reads(entry(&translation, "d")), ["docs", "members"]);
}

/// The policy on a root filters its partitions' rows on every read through the root, and a
/// subquery reading a parent without `ONLY` reads its children.
#[test]
fn partitions_and_children_below_a_read_table_count_as_read() {
    let translation = translate(
        "
CREATE TABLE events (id INT, tenant TEXT, at DATE, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
CREATE TABLE tenants (name TEXT, user_id TEXT);
CREATE TABLE vip_tenants (tier INT) INHERITS (tenants);
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY e ON events
  USING (tenant IN (SELECT name FROM tenants WHERE user_id = current_user));
",
    );
    assert_eq!(
        reads(entry(&translation, "e")),
        ["events", "events_2026", "tenants", "vip_tenants"]
    );
}
