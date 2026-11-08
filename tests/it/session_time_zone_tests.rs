//! A policy's date and time literals are read in the zone of the session that created it.

use rls2fga::parser::sql_parser::{parse_schema, parse_schema_in_time_zone, ParserDB};
use rls2fga::types::{ConfidenceLevel, TranslationNote};

use crate::support::deployment::ROLES;
use crate::support::footgun::translator;

const DEADLINE: &str = "
CREATE TABLE public.docs(id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_deadline ON docs FOR SELECT USING (expires_at < '2026-01-01 12:00');
";

/// The deadline policy after the roles the suite's deployment names.
fn schema() -> String {
    format!("{ROLES}{DEADLINE}")
}
/// The tuple SQL and the notes the deadline policy translates to.
fn translated(db: &ParserDB) -> (String, Vec<TranslationNote>) {
    let outputs = translator(ConfidenceLevel::B)
        .translate(db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let sql = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    (sql, outputs.notes().to_vec())
}

#[test]
fn a_literal_without_an_offset_is_read_in_the_session_zone() {
    let db = parse_schema_in_time_zone(&schema(), "Europe/Rome").expect("schema parses");
    let (sql, _) = translated(&db);
    assert!(
        sql.contains("'2026-01-01 11:00:00+00'"),
        "noon in Rome is 11:00 UTC in winter:\n{sql}"
    );
}

#[test]
fn the_same_literal_in_another_zone_is_another_instant() {
    let db = parse_schema_in_time_zone(&schema(), "Pacific/Kiritimati").expect("schema parses");
    let (sql, _) = translated(&db);
    assert!(
        sql.contains("'2025-12-31 22:00:00+00'"),
        "noon at UTC+14 is 22:00 UTC the day before:\n{sql}"
    );
}

#[test]
fn without_a_session_zone_the_policy_falls_closed() {
    let db = parse_schema(&schema()).expect("schema parses");
    let (sql, notes) = translated(&db);
    assert!(
        !sql.contains("2026-01-01") && !sql.contains("2025-12-31"),
        "no zone reads the literal, so no threshold is guessed:\n{sql}"
    );
    assert!(
        notes.iter().any(|note| matches!(
            note,
            TranslationNote::ExpressionRefused { policy, .. } if policy == "docs_deadline"
        )),
        "the refusal names the policy: {notes:?}"
    );
}

#[test]
fn a_zone_postgresql_does_not_know_is_refused() {
    assert!(parse_schema_in_time_zone(&schema(), "Mars/Olympus_Mons").is_err());
}
