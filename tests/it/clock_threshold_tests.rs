//! Guards against a clock shifted on the calendar of the request's `TimeZone`.
//!
//! `PostgreSQL` adds a day or a month to a `timestamptz` on the calendar of the session
//! zone, and `current_date` and `localtimestamp` read the clock in that zone. CEL has no
//! zone arithmetic, so each such threshold is a condition parameter the checker computes
//! per check with [`Translation::clock_context`]. Every expected value sits beside the
//! answer `PostgreSQL` 18.6 gives for it.

use rls2fga::clock::{ClockError, ClockOffset, ClockReading};
use rls2fga::translator::Translation;
use rls2fga::types::{ConfidenceLevel, TranslationNote};
use sql_values::{InputContext, PgTimeZone, PgTimestampTz};

use crate::support::deployment;
use crate::support::footgun::{db_of, relation_definition, translation, translator};

fn schema(clause: &str) -> String {
    format!(
        "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    )
}

fn translated(clause: &str) -> Translation {
    translator(ConfidenceLevel::B)
        .translate(&db_of(&schema(clause)))
        .expect("translation should plan")
}

fn instant(text: &str) -> PgTimestampTz {
    PgTimestampTz::parse(text, InputContext::new()).expect("a valid timestamptz")
}

fn zone(name: &str) -> PgTimeZone {
    PgTimeZone::parse(name).expect("a zone PostgreSQL reads")
}

/// The context `clause`'s translation asks for at `request_time` in `zone_name`.
fn context(
    clause: &str,
    request_time: &str,
    zone_name: &str,
) -> serde_json::Map<String, serde_json::Value> {
    translated(clause)
        .clock_context(instant(request_time), &zone(zone_name))
        .expect("the thresholds are in range")
}

/// Each threshold the request's table measured, computed for the parameter the window
/// becomes.
#[test]
fn a_calendar_window_is_computed_in_the_request_zone() {
    for (clause, request_time, zone_name, parameter, expected) in [
        // 2026-03-28 12:00:00+01, 23 hours back across the spring change.
        (
            "expires_at > now() - interval '1 day'",
            "2026-03-29 12:00+02",
            "Europe/Rome",
            "request_time_minus_1_day",
            "2026-03-28T11:00:00Z",
        ),
        // 2026-10-24 12:00:00+02, 25 hours back across the autumn change.
        (
            "expires_at > now() - interval '1 day'",
            "2026-10-25 12:00+01",
            "Europe/Rome",
            "request_time_minus_1_day",
            "2026-10-24T10:00:00Z",
        ),
        // 2026-02-28 12:00:00+01, the 31st clamped to the end of February.
        (
            "expires_at > now() - interval '1 month'",
            "2026-03-31 12:00+02",
            "Europe/Rome",
            "request_time_minus_1_mon",
            "2026-02-28T11:00:00Z",
        ),
        // 2026-03-28 10:00:00+01, the day on the calendar and the hours on the instant.
        (
            "expires_at > now() - interval '1 day 2 hours'",
            "2026-03-29 12:00+02",
            "Europe/Rome",
            "request_time_minus_1_day_2h",
            "2026-03-28T09:00:00Z",
        ),
        // 2026-03-28 10:00:00+00 under `SET TIME ZONE 'UTC'`.
        (
            "expires_at > now() - interval '1 day'",
            "2026-03-29 12:00+02",
            "UTC",
            "request_time_minus_1_day",
            "2026-03-28T10:00:00Z",
        ),
    ] {
        let context = context(clause, request_time, zone_name);
        assert_eq!(
            context.get(parameter).and_then(serde_json::Value::as_str),
            Some(expected),
            "`{clause}` at {request_time} in {zone_name}: {context:?}"
        );
    }
}

/// `current_date` compares as the local midnight of the request's day and
/// `localtimestamp` as its local clock, each read back in the zone, and either shifts as
/// a zoneless timestamp before that. Neither is the request instant, `current_date`
/// not even in `UTC`.
#[test]
fn a_local_clock_is_read_and_shifted_in_the_request_zone() {
    for (clause, request_time, zone_name, parameter, expected) in [
        // 2026-03-29 00:00:00+01, local midnight.
        (
            "expires_at > current_date",
            "2026-03-29 12:00+02",
            "Europe/Rome",
            "request_time_current_date",
            "2026-03-28T23:00:00Z",
        ),
        // 2026-03-29 00:00:00+01, the local date already the 29th at 23:30 UTC.
        (
            "expires_at > current_date",
            "2026-03-28 23:30Z",
            "Europe/Rome",
            "request_time_current_date",
            "2026-03-28T23:00:00Z",
        ),
        // 2026-03-28 00:00:00+00, the same instant in `UTC` still on the 28th.
        (
            "expires_at > current_date",
            "2026-03-28 23:30Z",
            "UTC",
            "request_time_current_date",
            "2026-03-28T00:00:00Z",
        ),
        // 2026-03-29 00:00:00+01, a day back from the 30th.
        (
            "expires_at > current_date - interval '1 day'",
            "2026-03-30 12:00+02",
            "Europe/Rome",
            "request_time_current_date_minus_1_day",
            "2026-03-28T23:00:00Z",
        ),
        // 2026-03-29 03:00:00+02, three hours on the local clock, two on the instant.
        (
            "expires_at > current_date + interval '3 hours'",
            "2026-03-29 12:00+02",
            "Europe/Rome",
            "request_time_current_date_plus_3h",
            "2026-03-29T01:00:00Z",
        ),
        // 2026-10-25 02:30:00+01, the repeated local hour read as its later instant.
        (
            "expires_at > localtimestamp",
            "2026-10-25 00:30Z",
            "Europe/Rome",
            "request_time_localtimestamp",
            "2026-10-25T01:30:00Z",
        ),
        // 2026-03-28 00:00:00+01, where `now() - interval '36 hours'` is 23:00 the day
        // before.
        (
            "expires_at > localtimestamp - interval '36 hours'",
            "2026-03-29 12:00+02",
            "Europe/Rome",
            "request_time_localtimestamp_minus_36h",
            "2026-03-27T23:00:00Z",
        ),
    ] {
        let context = context(clause, request_time, zone_name);
        assert_eq!(
            context.get(parameter).and_then(serde_json::Value::as_str),
            Some(expected),
            "`{clause}` at {request_time} in {zone_name}: {context:?}"
        );
    }
}

/// The condition compares the row with the threshold parameter directly, and the checker
/// is told to supply it.
#[test]
fn a_calendar_window_compares_the_row_with_its_threshold_parameter() {
    for (clause, parameter) in [
        (
            "expires_at > now() - interval '1 day'",
            "request_time_minus_1_day",
        ),
        (
            "expires_at > now() + interval '-1 day'",
            "request_time_minus_1_day",
        ),
        (
            "expires_at > now() - interval '30 days'",
            "request_time_minus_30_days",
        ),
        (
            "expires_at > now() - interval '1 mon'",
            "request_time_minus_1_mon",
        ),
        (
            "expires_at > now() - interval '1 year 2 mons'",
            "request_time_minus_1_year_2_mons",
        ),
        (
            "expires_at > now() - '1 mon'::interval",
            "request_time_minus_1_mon",
        ),
        (
            "expires_at > now() - interval '1.5 days'",
            "request_time_minus_1_day_12h",
        ),
        (
            "expires_at > now() - interval '1 day ago'",
            "request_time_plus_1_day",
        ),
        (
            "expires_at > now() - interval '1 mon -1 day'",
            "request_time_minus_1_mon_plus_1_day",
        ),
        (
            "now() - interval '1 day' < expires_at",
            "request_time_minus_1_day",
        ),
        (
            "expires_at > interval '2 days' + now()",
            "request_time_plus_2_days",
        ),
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        assert!(
            dsl.contains(&format!("expires_at > {parameter}")),
            "`{clause}` must compare the row with `{parameter}`:\n{dsl}"
        );
        assert!(
            dsl.contains(&format!("{parameter}: timestamp")),
            "`{clause}` must declare `{parameter}`:\n{dsl}"
        );
        assert!(
            !dsl.contains("request_time:") && !dsl.contains("duration("),
            "`{clause}` reads no other clock:\n{dsl}"
        );
        assert!(
            tuples.contains("jsonb_build_object('expires_at', \"expires_at\")"),
            "the row's own boundary still travels as context:\n{tuples}"
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

/// One parameter per distinct shift and clock across the model, read field by field: a
/// month and thirty days are equal intervals in `PostgreSQL` and different thresholds.
#[test]
fn every_distinct_threshold_is_one_parameter_shared_across_the_model() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
         CREATE TABLE notes(id UUID PRIMARY KEY, seen_at TIMESTAMPTZ, due_at TIMESTAMPTZ);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING (expires_at > now() - interval '1 mon');\n\
         CREATE POLICY notes_sel ON notes FOR SELECT USING \
         (seen_at > now() + interval '-1 mon' AND due_at > now() - interval '30 days' \
          AND due_at < now());\n",
    );
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let parameters: Vec<(&str, ClockReading, ClockOffset)> = translation
        .clock_parameters()
        .iter()
        .map(|parameter| {
            (
                parameter.name().as_str(),
                parameter.threshold().reading,
                parameter.threshold().offset,
            )
        })
        .collect();
    assert_eq!(
        parameters,
        [
            (
                "request_time",
                ClockReading::Instant,
                ClockOffset {
                    months: 0,
                    days: 0,
                    microseconds: 0
                }
            ),
            (
                "request_time_minus_1_mon",
                ClockReading::Instant,
                ClockOffset {
                    months: -1,
                    days: 0,
                    microseconds: 0
                }
            ),
            (
                "request_time_minus_30_days",
                ClockReading::Instant,
                ClockOffset {
                    months: 0,
                    days: -30,
                    microseconds: 0
                }
            ),
        ]
    );
    let context = translation
        .clock_context(instant("2026-03-31 12:00+02"), &zone("Europe/Rome"))
        .expect("the thresholds are in range");
    assert_eq!(
        serde_json::Value::Object(context),
        serde_json::json!({
            "request_time": "2026-03-31T10:00:00Z",
            // 2026-02-28 12:00:00+01
            "request_time_minus_1_mon": "2026-02-28T11:00:00Z",
            // 2026-03-01 12:00:00+01
            "request_time_minus_30_days": "2026-03-01T11:00:00Z",
        })
    );
}

/// Every spelling of a calendar interval names the interval `PostgreSQL` 18.6 stores for
/// it, whether a literal, a qualified literal or a quoted string cast to an interval type.
#[test]
fn every_calendar_spelling_reads_the_interval_postgres_stores() {
    for (interval_sql, stored, parameter) in [
        ("interval '1 day'", "1 day", "request_time_minus_1_day"),
        (
            "interval '30 days'",
            "30 days",
            "request_time_minus_30_days",
        ),
        (
            "interval '1.5 days'",
            "1 day 12:00:00",
            "request_time_minus_1_day_12h",
        ),
        ("interval '30' day", "30 days", "request_time_minus_30_days"),
        ("interval 'P30D'", "30 days", "request_time_minus_30_days"),
        ("interval '1 day ago'", "-1 days", "request_time_plus_1_day"),
        ("interval '1 week'", "7 days", "request_time_minus_7_days"),
        (
            "interval 'P1DT2H'",
            "1 day 02:00:00",
            "request_time_minus_1_day_2h",
        ),
        ("interval '1 mon'", "1 mon", "request_time_minus_1_mon"),
        ("interval '1 year'", "1 year", "request_time_minus_1_year"),
        ("interval '2' year", "2 years", "request_time_minus_2_years"),
        ("interval '3' month", "3 mons", "request_time_minus_3_mons"),
        (
            "interval '1-2' year to month",
            "1 year 2 mons",
            "request_time_minus_1_year_2_mons",
        ),
        (
            "interval '1 2' day to hour",
            "1 day 02:00:00",
            "request_time_minus_1_day_2h",
        ),
        (
            "interval '1 2:03' day to minute",
            "1 day 02:03:00",
            "request_time_minus_1_day_123m",
        ),
        (
            "interval '1 2:03:04' day to second",
            "1 day 02:03:04",
            "request_time_minus_1_day_7384s",
        ),
        (
            "interval '1 mon 2 days'",
            "1 mon 2 days",
            "request_time_minus_1_mon_2_days",
        ),
        (
            "'30 days'::interval",
            "30 days",
            "request_time_minus_30_days",
        ),
        (
            "CAST('1 mon' AS interval)",
            "1 mon",
            "request_time_minus_1_mon",
        ),
        (
            "'2'::interval year",
            "2 years",
            "request_time_minus_2_years",
        ),
        ("'3'::interval month", "3 mons", "request_time_minus_3_mons"),
        ("'4'::interval day", "4 days", "request_time_minus_4_days"),
        (
            "'1-2'::interval year to month",
            "1 year 2 mons",
            "request_time_minus_1_year_2_mons",
        ),
        (
            "'1 2'::interval day to hour",
            "1 day 02:00:00",
            "request_time_minus_1_day_2h",
        ),
        (
            "'1 2:03'::interval day to minute",
            "1 day 02:03:00",
            "request_time_minus_1_day_123m",
        ),
        (
            "'1 2:03:04'::interval day to second",
            "1 day 02:03:04",
            "request_time_minus_1_day_7384s",
        ),
    ] {
        let predicate = format!("expires_at > now() - {interval_sql}");
        let (dsl, _tuples) = translation(&schema(&predicate));
        assert!(
            dsl.contains(&format!("expires_at > {parameter}")),
            "`{interval_sql}` stores `{stored}`, so `{predicate}` must read `{parameter}`:\n{dsl}"
        );
    }
}

/// A fixed-length window keeps riding the request clock as a CEL duration, so its model
/// asks for no parameter beyond the clock.
#[test]
fn a_fixed_length_window_still_rides_the_request_clock() {
    let translation = translated("expires_at > now() - interval '36 hours'");
    let names: Vec<&str> = translation
        .clock_parameters()
        .iter()
        .map(|parameter| parameter.name().as_str())
        .collect();
    assert_eq!(names, ["request_time"]);
    let dsl = translation.outputs_accepting_gaps().model();
    assert!(
        dsl.contains("expires_at > request_time - duration(\"36h\")"),
        "{dsl}"
    );
}

/// The parameter is named after the configured clock, a column named like it keeps a
/// parameter of its own, and an over-long name is clamped to the 50 characters `OpenFGA`
/// takes with a hash keeping it apart.
#[test]
fn a_threshold_parameter_is_named_after_the_configured_clock() {
    let db = db_of(&schema("expires_at > now() - interval '1 day'"));
    let dsl = rls2fga::translator::TranslatorBuilder::new(deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .with_request_time_parameter("as_of")
        .expect("as_of is a valid parameter")
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert!(dsl.contains("expires_at > as_of_minus_1_day"), "{dsl}");

    let long = "a".repeat(45);
    let clamped = rls2fga::translator::TranslatorBuilder::new(deployment::caller_deployment())
        .with_min_confidence(ConfidenceLevel::B)
        .with_request_time_parameter(long.as_str())
        .expect("forty five letters are a valid parameter")
        .build()
        .translate(&db)
        .expect("a clamped name keeps the translation within the bound");
    let [parameter] = clamped.clock_parameters() else {
        panic!("one threshold: {:?}", clamped.clock_parameters());
    };
    let name = parameter.name().as_str();
    assert_eq!(name.len(), 50, "{name}");
    assert!(name.starts_with(&long[..41]), "{name}");

    let (dsl, tuples) = translation(
        "CREATE TABLE docs(id UUID PRIMARY KEY, request_time_minus_1_day TIMESTAMPTZ);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING \
         (request_time_minus_1_day > now() - interval '1 day');\n",
    );
    let expression = dsl
        .lines()
        .find(|line| line.contains(" > request_time_minus_1_day"))
        .unwrap_or_else(|| panic!("the condition reads the threshold:\n{dsl}"));
    let row_parameter = expression.trim().split(' ').next().expect("a row side");
    assert_ne!(row_parameter, "request_time_minus_1_day", "{dsl}");
    assert!(
        tuples.contains(&format!(
            "jsonb_build_object('{row_parameter}', \"request_time_minus_1_day\")"
        )),
        "{tuples}"
    );
}

/// A request parameter the deployment declares under the name a threshold would take
/// keeps it, and the threshold takes that name with a hash after it.
#[test]
fn a_configured_request_parameter_keeps_the_name_a_threshold_would_take() {
    let translation =
        rls2fga::translator::TranslatorBuilder::new(deployment::deployment([deployment::scalar(
            "request_time.minus_1_day",
        )]))
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db_of(&schema("expires_at > now() - interval '1 day'")))
        .expect("translation should plan");
    let [parameter] = translation.clock_parameters() else {
        panic!("one threshold: {:?}", translation.clock_parameters());
    };
    let name = parameter.name().to_string();
    assert!(
        name.starts_with("request_time_minus_1_day_") && name.len() == 33,
        "{name}"
    );
    let dsl = translation.outputs_accepting_gaps().model();
    assert!(dsl.contains(&format!("expires_at > {name}")), "{dsl}");
}

/// `localtime` and `current_time` are times of day, which `PostgreSQL` does not compare
/// with a `timestamptz` (`operator does not exist`), and no timestamp parameter carries.
#[test]
fn a_time_of_day_clock_falls_closed_naming_why() {
    for clause in [
        "expires_at > localtime",
        "expires_at > current_time",
        "expires_at > current_time - interval '1 hour'",
    ] {
        let outputs = translated(clause).outputs_accepting_gaps();
        let dsl = outputs.model();
        assert_eq!(
            relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` must fall closed:\n{dsl}"
        );
        let report = outputs.report();
        assert!(
            report.contains("is a time of day, which no timestamp condition parameter carries"),
            "`{clause}` must be refused naming why:\n{report}"
        );
    }
}

/// A local clock cast to `timestamptz` before it is shifted is shifted on the zone's
/// calendar as an instant, which this does not follow: `current_date::timestamptz +
/// interval '3 hours'` is 2026-03-29 04:00:00+02 in Europe/Rome where `current_date +
/// interval '3 hours'` is 03:00:00+02.
#[test]
fn a_local_clock_cast_before_its_shift_falls_closed_naming_why() {
    for clause in [
        "expires_at > current_date::timestamptz + interval '3 hours'",
        "expires_at > localtimestamp::timestamptz - interval '1 day'",
    ] {
        let outputs = translated(clause).outputs_accepting_gaps();
        let dsl = outputs.model();
        assert_eq!(
            relation_definition(&dsl, "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` must fall closed:\n{dsl}"
        );
        let report = outputs.report();
        assert!(
            report.contains("before shifting it, which this does not follow"),
            "`{clause}` must be refused naming why:\n{report}"
        );
    }
}

/// A threshold outside the years a CEL timestamp holds is an error the checker sees,
/// where `PostgreSQL` itself computes it.
#[test]
fn a_threshold_beyond_cel_timestamps_is_an_error() {
    let error = translated("expires_at > now() - interval '3000 years'")
        .clock_context(instant("2026-03-29 12:00+02"), &zone("UTC"))
        .expect_err("year -974 has no CEL timestamp");
    assert_eq!(error.parameter().as_str(), "request_time_minus_3000_years");
    assert!(
        matches!(error.error(), ClockError::OutsideCelRange(at)
            if at.to_string() == "0975-03-29 10:00:00+00 BC"),
        "{error}"
    );
}
