//! Guards comparing a `timestamptz` column with a `date` or `timestamp` literal.
//!
//! `PostgreSQL` stores such a literal as written and converts it to an instant in the
//! session `TimeZone` of each query, so the same policy admits different rows in different
//! zones. The literal becomes a condition parameter the checker computes per check with
//! [`Translation::clock_context`]. Every expected instant sits beside the answer
//! `PostgreSQL` 18.6 gives for it.

use rls2fga::translator::Translation;
use rls2fga::types::{ConfidenceLevel, TranslationNote};
use sql_values::{InputContext, PgTimeZone, PgTimestampTz};

use crate::support::footgun::{db_of, relation_definition, translation, translator};

/// A table with one column of each kind a literal is compared with.
fn schema(clause: &str) -> String {
    format!(
        "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ, starts_on TIMESTAMP, \
         due DATE);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    )
}

fn translated(clause: &str) -> Translation {
    translator(ConfidenceLevel::B)
        .translate(&db_of(&schema(clause)))
        .expect("translation should plan")
}

fn zone(name: &str) -> PgTimeZone {
    PgTimeZone::parse(name).expect("a zone PostgreSQL reads")
}

/// Any instant, since a literal's threshold does not read the clock.
fn request_time() -> PgTimestampTz {
    PgTimestampTz::parse("2026-06-15 12:00+00", InputContext::new()).expect("a valid instant")
}

/// Each spelling of a `date` or `timestamp` literal compares the row with a parameter named
/// after the local time, instead of a tuple filter the loader evaluates in its own zone.
#[test]
fn a_local_literal_against_an_instant_column_becomes_a_threshold() {
    for (clause, fragment, parameter) in [
        (
            "expires_at < '2026-01-01'::date",
            "expires_at < request_time_at_2026_01_01",
            "request_time_at_2026_01_01",
        ),
        (
            "expires_at < DATE '2026-01-01'",
            "expires_at < request_time_at_2026_01_01",
            "request_time_at_2026_01_01",
        ),
        (
            "expires_at < CAST('2026-01-01' AS date)",
            "expires_at < request_time_at_2026_01_01",
            "request_time_at_2026_01_01",
        ),
        (
            "expires_at < '2026-01-01 12:00+05'::date",
            "expires_at < request_time_at_2026_01_01",
            "request_time_at_2026_01_01",
        ),
        (
            "expires_at < '2026-01-01 12:00'::timestamp",
            "expires_at < request_time_at_2026_01_01_12_00_00",
            "request_time_at_2026_01_01_12_00_00",
        ),
        (
            "expires_at = '2026-01-01 12:00:00.5'::timestamp",
            "expires_at == request_time_at_2026_01_01_12_00_00_5",
            "request_time_at_2026_01_01_12_00_00_5",
        ),
        (
            "expires_at < TIMESTAMP '2026-01-01 12:00'",
            "expires_at < request_time_at_2026_01_01_12_00_00",
            "request_time_at_2026_01_01_12_00_00",
        ),
        (
            "expires_at < '2026-01-01 12:00+05'::timestamp",
            "expires_at < request_time_at_2026_01_01_12_00_00",
            "request_time_at_2026_01_01_12_00_00",
        ),
        (
            "expires_at < '2026-01-01 23:00:00.6'::timestamp(0)",
            "expires_at < request_time_at_2026_01_01_23_00_01",
            "request_time_at_2026_01_01_23_00_01",
        ),
        (
            "'2026-01-01'::date > expires_at",
            "expires_at < request_time_at_2026_01_01",
            "request_time_at_2026_01_01",
        ),
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        assert!(
            dsl.contains(fragment),
            "`{clause}` must compare the row with `{parameter}`:\n{dsl}"
        );
        assert!(
            dsl.contains(&format!("{parameter}: timestamp")),
            "`{clause}` must declare `{parameter}`:\n{dsl}"
        );
        assert!(
            !tuples.contains("AND \"expires_at\" <") && !tuples.contains("AND \"expires_at\" ="),
            "`{clause}` must leave no filter the loader evaluates in its own zone:\n{tuples}"
        );
        assert!(
            tuples.contains("jsonb_build_object('expires_at', \"expires_at\")"),
            "the row's own value travels as context:\n{tuples}"
        );
        let translation = translated(clause);
        assert!(
            translation.notes().iter().any(|note| matches!(
                note,
                TranslationNote::CallerSuppliesConditionParameter { parameter: supplied, .. }
                    if supplied == parameter
            )),
            "the checker must be told to supply `{parameter}`: {:?}",
            translation.notes()
        );
    }
}

/// A range or a list of local literals is a comparison per bound or per value, as
/// `PostgreSQL` stores `BETWEEN` as two comparisons, each with its own threshold.
#[test]
fn a_range_or_a_list_of_local_literals_compares_each_value() {
    for (clause, fragments) in [
        (
            "expires_at BETWEEN '2026-01-01'::date AND '2026-02-01'::date",
            &[
                "expires_at >= request_time_at_2026_01_01",
                "expires_at <= request_time_at_2026_02_01",
            ][..],
        ),
        (
            "expires_at IN ('2026-01-01'::date, '2026-02-01'::date)",
            &[
                "expires_at == request_time_at_2026_01_01",
                "expires_at == request_time_at_2026_02_01",
            ],
        ),
    ] {
        let (dsl, _) = translation(&schema(clause));
        for fragment in fragments {
            assert!(
                dsl.contains(fragment),
                "`{clause}` must compare `{fragment}`:\n{dsl}"
            );
        }
    }
}

/// The threshold is the instant the local time names in the request's zone, measured on
/// `PostgreSQL` 18.6 as `('<literal>')::timestamptz AT TIME ZONE 'UTC'` after `SET TIME
/// ZONE`, a skipped hour read an hour later.
#[test]
fn a_local_literal_threshold_is_the_instant_postgres_reads_in_the_request_zone() {
    for (clause, zone_name, parameter, expected) in [
        (
            "expires_at < '2026-01-01'::date",
            "Europe/Rome",
            "request_time_at_2026_01_01",
            "2025-12-31T23:00:00Z",
        ),
        (
            "expires_at < '2026-01-01'::date",
            "Pacific/Kiritimati",
            "request_time_at_2026_01_01",
            "2025-12-31T10:00:00Z",
        ),
        (
            "expires_at < '2026-01-01'::date",
            "UTC",
            "request_time_at_2026_01_01",
            "2026-01-01T00:00:00Z",
        ),
        (
            "expires_at < '2026-01-01'::date",
            "America/New_York",
            "request_time_at_2026_01_01",
            "2026-01-01T05:00:00Z",
        ),
        (
            "expires_at < '2026-03-29'::date",
            "Europe/Rome",
            "request_time_at_2026_03_29",
            "2026-03-28T23:00:00Z",
        ),
        (
            "expires_at < '2026-01-01 12:00'::timestamp",
            "Pacific/Kiritimati",
            "request_time_at_2026_01_01_12_00_00",
            "2025-12-31T22:00:00Z",
        ),
        (
            "expires_at < '2026-03-29 02:30'::timestamp",
            "Europe/Rome",
            "request_time_at_2026_03_29_02_30_00",
            "2026-03-29T01:30:00Z",
        ),
        (
            "expires_at < '2026-10-25 02:30'::timestamp",
            "Europe/Rome",
            "request_time_at_2026_10_25_02_30_00",
            "2026-10-25T01:30:00Z",
        ),
        (
            "expires_at < '2026-03-08 02:30'::timestamp",
            "America/New_York",
            "request_time_at_2026_03_08_02_30_00",
            "2026-03-08T07:30:00Z",
        ),
        (
            "expires_at < '2026-11-01 01:30'::timestamp",
            "America/New_York",
            "request_time_at_2026_11_01_01_30_00",
            "2026-11-01T06:30:00Z",
        ),
        (
            "expires_at < '2026-01-01 23:00:00.6'::timestamp(0)",
            "Europe/Rome",
            "request_time_at_2026_01_01_23_00_01",
            "2026-01-01T22:00:01Z",
        ),
    ] {
        let context = translated(clause)
            .clock_context(request_time(), &zone(zone_name))
            .expect("the threshold is in range");
        assert_eq!(
            context.get(parameter).and_then(serde_json::Value::as_str),
            Some(expected),
            "`{clause}` in {zone_name}: {context:?}"
        );
    }
}

/// A null-safe comparison, which no threshold condition carries, falls closed and the report
/// names why.
#[test]
fn a_local_literal_with_no_threshold_falls_closed_naming_why() {
    for (clause, stored) in [
        (
            "expires_at IS DISTINCT FROM '2026-01-01'::date",
            "expires_at IS DISTINCT FROM '2026-01-01'::DATE",
        ),
        (
            "expires_at IS NOT DISTINCT FROM '2026-01-01'::date",
            "expires_at IS NOT DISTINCT FROM '2026-01-01'::DATE",
        ),
    ] {
        let outputs = translated(clause).outputs_accepting_gaps();
        let dsl = outputs.model();
        assert_eq!(
            relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` must fall closed:\n{dsl}"
        );
        let reason = format!(
            "Unknown: {stored} compares expires_at with a local time PostgreSQL converts in \
             the session TimeZone, which only an ordering or an equality carries as a \
             threshold"
        );
        assert!(
            outputs.report().contains(&reason),
            "`{clause}` must be refused naming why:\n{}",
            outputs.report()
        );
    }
}

/// A literal naming its instant, and a literal against a column with no zone, read alike
/// in every zone, so they stay filters on the row.
#[test]
fn a_literal_no_zone_decides_stays_a_row_filter() {
    for (clause, column) in [
        ("expires_at < '2026-01-01 00:00+00'", "expires_at"),
        ("expires_at < '2026-01-01 12:00 Europe/Rome'", "expires_at"),
        ("starts_on < '2026-01-01 12:00'", "starts_on"),
        ("due < '2026-01-01'", "due"),
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        assert!(
            tuples.contains(&format!("AND \"{column}\" < '")),
            "`{clause}` must stay a filter on the row:\n{tuples}"
        );
        assert!(
            !dsl.contains("request_time_at_"),
            "`{clause}` needs no threshold:\n{dsl}"
        );
    }
}
