//! Regression tests for the family of leftover membership conditions the tuple loader
//! evaluates instead of the caller.
//!
//! A membership check can carry conditions beyond the join, and what the model cannot
//! express is kept as SQL in the query that loads the tuples. That query runs once, as the
//! loader, so a condition reading the caller's identity, the caller's session or the clock
//! answers a different question there than `PostgreSQL` answers at check time.

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::types::{ConfidenceLevel, RecordDerivation};

use crate::support::footgun::{db_of, translator};

/// One membership policy over a join table carrying every column the cases need.
fn membership_with(conjunct: &str) -> String {
    format!(
        r"
CREATE TABLE public.docs (id TEXT PRIMARY KEY);
CREATE TABLE public.doc_members (
    doc_id TEXT NOT NULL REFERENCES public.docs(id),
    user_id NAME NOT NULL,
    active BOOLEAN NOT NULL,
    role TEXT NOT NULL,
    score INTEGER NOT NULL,
    tenant TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    local_at TIMESTAMP NOT NULL,
    starts_at TIMETZ NOT NULL,
    expires_at TIMESTAMPTZ,
    qualified_at pg_catalog.timestamptz NOT NULL,
    qualified_starts_at pg_catalog.timetz NOT NULL
);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM public.doc_members AS m
        WHERE m.doc_id = docs.id
          AND m.user_id = CURRENT_USER
          AND {conjunct}
    )
);
"
    )
}

/// The SQL of every query that loads the `doc_members` tuples for the membership above.
fn member_query_sql(conjunct: &str) -> String {
    let db = db_of(&membership_with(conjunct));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let mut sql = String::new();
    for query in outputs.tuple_queries() {
        let Some(description) = &query.description else {
            continue;
        };
        if !description
            .tables
            .iter()
            .any(|table| table.name() == "doc_members")
        {
            continue;
        }
        if !sql.is_empty() {
            sql.push('\n');
        }
        sql.push_str(&query.sql);
    }
    sql
}

/// `pg_has_role(role, privilege)` tests `current_user`, so the loader's own role decides
/// it and a loader running as owner admits every membership row.
#[test]
fn a_caller_role_test_never_reaches_the_loader() {
    let sql = member_query_sql("pg_has_role(m.tenant, 'USAGE')");
    assert!(
        !sql.contains("pg_has_role"),
        "the loader's role would decide this, not the caller's:\n{sql}"
    );
}

/// A session setting is the caller's, and the loader has its own session.
#[test]
fn a_session_setting_never_reaches_the_loader() {
    let sql = member_query_sql("m.tenant = current_setting('app.tenant', true)");
    assert!(
        !sql.contains("current_setting"),
        "the loader's session would decide this, not the caller's:\n{sql}"
    );
}

/// A clock reading inside a wrapper is still the clock, so it cannot be frozen into a
/// tuple that outlives the moment it was loaded.
#[test]
fn a_wrapped_clock_reading_never_reaches_the_loader() {
    let sql = member_query_sql("date_trunc('day', m.granted_at) < date_trunc('day', now())");
    assert!(
        !sql.contains("now()"),
        "load-time truth would be frozen into a permanent tuple:\n{sql}"
    );
}

/// A function reading the caller is caller-dependent whatever it is called.
#[test]
fn a_user_function_reading_the_caller_never_reaches_the_loader() {
    let schema = format!(
        "{}\nCREATE FUNCTION public.mine(flag BOOLEAN) RETURNS BOOLEAN LANGUAGE sql STABLE AS\n'SELECT flag AND CURRENT_USER = ''postgres''';",
        membership_with("public.mine(m.active)")
    );
    let db = db_of(&schema);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = format_tuples(outputs.tuple_queries());
    assert!(
        !tuples.contains("public.mine"),
        "an opaque function cannot be proven to read only the row:\n{tuples}"
    );
}

/// A bare boolean column is decided by the row alone, so it stays.
#[test]
fn a_row_column_guard_still_loads() {
    let sql = member_query_sql("m.active");
    assert!(
        sql.contains("(active)"),
        "the row decides this one, so it belongs in the query:\n{sql}"
    );
}

/// A comparison against a literal is decided by the row alone.
#[test]
fn a_literal_comparison_still_loads() {
    let sql = member_query_sql("m.role = 'admin'");
    assert!(
        sql.contains("role = 'admin'"),
        "the row decides this one:\n{sql}"
    );
}

/// An offset-less zoned literal is interpreted through the evaluating session.
#[test]
fn an_offsetless_zoned_literal_never_reaches_the_loader() {
    for predicate in [
        "m.granted_at < '2030-01-01 00:00:00'::timestamptz",
        "m.granted_at < '2030-01-01 00:00:00'",
        "m.starts_at < '09:00:00'::timetz",
    ] {
        let sql = member_query_sql(predicate);
        assert!(
            !sql.contains("2030-01-01") && !sql.contains("09:00:00"),
            "the loader's time zone would interpret {predicate}:\n{sql}"
        );
    }
}

/// A schema-qualified spelling names the same zoned type.
#[test]
fn a_qualified_zoned_type_is_still_session_interpreted() {
    for predicate in [
        "m.qualified_at < '2030-01-01 00:00:00'",
        "m.qualified_starts_at < '09:00:00'",
    ] {
        let sql = member_query_sql(predicate);
        assert!(
            !sql.contains("2030-01-01") && !sql.contains("09:00:00"),
            "the loader's time zone would interpret {predicate}:\n{sql}"
        );
    }
}

/// A zone-naive literal gains the session zone when compared to a zoned column.
#[test]
fn a_zone_naive_literal_against_a_zoned_column_never_reaches_the_loader() {
    let sql = member_query_sql("m.granted_at < TIMESTAMP '2030-01-01 00:00:00'");
    assert!(
        !sql.contains("2030-01-01"),
        "the comparison coerces through the loader's time zone:\n{sql}"
    );
}

/// An explicit offset makes the instant independent of the evaluating session.
#[test]
fn explicit_offset_literals_still_load() {
    for predicate in [
        "m.granted_at < '2030-01-01 00:00:00+02:00'::timestamptz",
        "m.starts_at < '09:00:00+02:00'::timetz",
    ] {
        let sql = member_query_sql(predicate);
        assert!(
            sql.contains("+02:00"),
            "the row and explicit offset decide {predicate}:\n{sql}"
        );
    }
}

/// A zone-naive literal stays deterministic against a zone-naive column.
#[test]
fn a_zone_naive_literal_against_a_zone_naive_column_still_loads() {
    let sql = member_query_sql("m.local_at < TIMESTAMP '2030-01-01 00:00:00'");
    assert!(
        sql.contains("2030-01-01"),
        "the row and wall-clock value decide this comparison:\n{sql}"
    );
}

/// So is a numeric comparison and a null test.
#[test]
fn numeric_and_null_guards_still_load() {
    let numeric = member_query_sql("m.score > 3");
    assert!(
        numeric.contains("score > 3"),
        "the row decides it:\n{numeric}"
    );
    let null = member_query_sql("m.expires_at IS NOT NULL");
    assert!(
        null.contains("expires_at IS NOT NULL"),
        "the row decides it:\n{null}"
    );
}

/// A case-folding call on a row column is decided by the row, so it keeps loading.
#[test]
fn a_pure_function_on_a_row_column_still_loads() {
    let sql = member_query_sql("lower(m.role) = 'admin'");
    assert!(
        sql.contains("lower(role) = 'admin'"),
        "case folding reads nothing but the row:\n{sql}"
    );
}

/// A bare clock comparison already becomes a condition, and must keep doing so.
#[test]
fn a_bare_clock_comparison_still_becomes_a_condition() {
    let sql = member_query_sql("m.expires_at > now()");
    assert!(
        !sql.contains("now()"),
        "the clock belongs in the condition, not the query:\n{sql}"
    );
    assert!(
        sql.contains("expires_at"),
        "the row's value still travels with the tuple:\n{sql}"
    );
}

/// A membership conjunct cast so the value can change stays SQL with its cast, which the
/// loader's `PostgreSQL` evaluates as the policy does. Read from the row instead, the
/// record would compare `score` with 2.7 where the policy compares it with 3.
#[test]
fn a_value_changing_cast_keeps_the_conjunct_in_sql() {
    let db = db_of(&membership_with("m.score >= 2.7::int"));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let members = outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| {
            query
                .description
                .as_ref()
                .map(|description| (query, description))
        })
        .find(|(_, description)| {
            description
                .tables
                .iter()
                .any(|table| table.name() == "doc_members")
        })
        .expect("the membership still loads");
    assert!(
        members.0.sql.contains("score >= 2.7::INT"),
        "the cast stays for the loader to evaluate:\n{}",
        members.0.sql
    );
    assert!(
        !matches!(members.1.derivation, RecordDerivation::FromRow { .. }),
        "no record may be derived from the row against the uncast literal: {:?}",
        members.1.derivation
    );
}

/// The clock cast to a date is the session's midnight, which no request clock is, so a
/// membership conjunct reading it falls closed.
#[test]
fn a_clock_cast_to_a_date_falls_closed_in_a_membership() {
    let db = db_of(&membership_with("m.expires_at > now()::date"));
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert!(
        dsl.contains("define can_select: no_access"),
        "the session's midnight is no request clock:\n{dsl}"
    );
}
