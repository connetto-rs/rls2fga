//! Guards comparing a date or time column with a literal of another date or time type.
//!
//! Where no zone enters the comparison, `PostgreSQL` answers it the same in every session, so
//! the tuple query keeps the literal typed as the policy stores it. Where it converts a
//! zoneless column into a `timestamptz`, the session zone decides it and no row filter can,
//! so the guard falls closed. Every expected row set was measured on `PostgreSQL` 18.6.

use rls2fga::types::ConfidenceLevel;

use crate::support::footgun::{db_of, relation_definition, translation, translator};

fn schema(clause: &str) -> String {
    format!(
        "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ, starts_on TIMESTAMP, \
         due DATE);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    )
}

/// A literal no zone reads stays in the tuple query typed as `PostgreSQL` stores it, a
/// precision rounding it already applied.
#[test]
fn a_zone_free_literal_of_another_type_stays_typed_in_the_tuple_query() {
    for (clause, fragment) in [
        (
            "starts_on < '2026-01-01'::date",
            "AND \"starts_on\" < DATE '2026-01-01';",
        ),
        (
            "due < '2026-01-01 12:00'::timestamp",
            "AND \"due\" < TIMESTAMP '2026-01-01 12:00:00';",
        ),
        (
            "due = '2026-01-01 00:00'::timestamp",
            "AND \"due\" = TIMESTAMP '2026-01-01 00:00:00';",
        ),
        (
            "starts_on < '2026-01-01 23:00:00.6'::timestamp(0)",
            "AND \"starts_on\" < TIMESTAMP '2026-01-01 23:00:01';",
        ),
        (
            "due < '2026-01-01 23:00:00.6'::timestamp(0)",
            "AND \"due\" < TIMESTAMP '2026-01-01 23:00:01';",
        ),
        (
            "expires_at < '2026-01-01 12:00:00.6+00'::timestamptz(0)",
            "AND \"expires_at\" < TIMESTAMPTZ '2026-01-01 12:00:01+00';",
        ),
        (
            "expires_at < 'infinity'::date",
            "AND \"expires_at\" < DATE 'infinity';",
        ),
        (
            "'2026-01-01'::date > starts_on",
            "AND \"starts_on\" < DATE '2026-01-01';",
        ),
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        assert!(
            tuples.contains(fragment),
            "`{clause}` must load as `{fragment}`:\n{tuples}"
        );
        assert!(
            !dsl.contains("request_time"),
            "`{clause}` needs no request value:\n{dsl}"
        );
    }
}

/// A range or a list of such literals is a comparison per bound or per value.
#[test]
fn a_range_or_a_list_of_zone_free_literals_stays_typed() {
    for (clause, fragments) in [
        (
            "starts_on BETWEEN '2026-01-01'::date AND '2026-02-01'::date",
            &[
                "\"starts_on\" >= DATE '2026-01-01'",
                "\"starts_on\" <= DATE '2026-02-01'",
            ][..],
        ),
        (
            "due IN ('2026-01-01 00:00'::timestamp, '2026-02-01 00:00'::timestamp)",
            &[
                "\"due\" = TIMESTAMP '2026-01-01 00:00:00'",
                "\"due\" = TIMESTAMP '2026-02-01 00:00:00'",
            ],
        ),
    ] {
        let (_, tuples) = translation(&schema(clause));
        for fragment in fragments {
            assert!(
                tuples.contains(fragment),
                "`{clause}` must load `{fragment}`:\n{tuples}"
            );
        }
    }
}

/// An instant compared with a zoneless column converts the column in the session zone, so
/// the same row reads differently in each zone and the guard falls closed naming why.
#[test]
fn an_instant_against_a_zoneless_column_falls_closed_naming_the_zone() {
    for (clause, column) in [
        (
            "starts_on < '2026-01-01 00:00+00'::timestamptz",
            "starts_on",
        ),
        ("due < '2026-01-01 12:00+00'::timestamptz", "due"),
    ] {
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db_of(&schema(clause)))
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        assert_eq!(
            relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` must fall closed:\n{dsl}"
        );
        let reason = format!(
            "PostgreSQL converts {column} to a timestamptz in the session TimeZone to compare \
             it with an instant"
        );
        assert!(
            outputs.report().contains(&reason),
            "`{clause}` must be refused naming the zone:\n{}",
            outputs.report()
        );
    }
}
