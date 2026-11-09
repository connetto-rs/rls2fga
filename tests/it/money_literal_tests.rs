//! A `money` literal is read under the `lc_monetary` its schema was written in, which only
//! the deployment knows, so it translates where that locale is declared and falls closed
//! where it is not.

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{records_from_row, ConfidenceLevel, RecordError};

use crate::support::deployment::caller_deployment;
use crate::support::footgun::{db_of, relation_definition};
use crate::support::row;

/// The guard `clause` on a `money` column, as `pg_policies` prints it.
fn schema(clause: &str) -> String {
    format!(
        "CREATE TABLE public.docs(id TEXT PRIMARY KEY, code MONEY);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    )
}

fn translate(clause: &str, locale: Option<&str>) -> Outputs {
    let mut builder = TranslatorBuilder::new(caller_deployment());
    if let Some(locale) = locale {
        builder = builder.with_monetary_locale(locale);
    }
    builder
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db_of(&schema(clause)))
        .expect("translation should plan")
        .outputs_accepting_gaps()
}

#[test]
fn a_money_literal_falls_closed_without_a_declared_monetary_locale() {
    let outputs = translate("(code > '$10.00'::money)", None);
    assert_eq!(
        relation_definition(&outputs.model(), "docs", "can_select").as_deref(),
        Some("no_access")
    );
    let report = outputs.report();
    assert!(
        report.contains("lc_monetary") && report.contains("with_monetary_locale"),
        "the refusal must name the setting and how to declare it:\n{report}"
    );
}

#[test]
fn a_money_literal_is_compared_by_the_database_under_the_declared_locale() {
    for (clause, compared) in [
        ("(code > '$10.00'::money)", "\"code\" > '$10.00'::money"),
        ("(code > (10)::money)", "\"code\" > 10::money"),
        (
            "(code = ANY (ARRAY['$5.50'::money, '$10.00'::money]))",
            "\"code\" IN ('$10.00'::money, '$5.50'::money)",
        ),
        (
            "((code >= '$1.00'::money) AND (code <= '$2.00'::money))",
            "\"code\" >= '$1.00'::money",
        ),
        ("(code > (10.5)::money)", "\"code\" > 10.5::money"),
        ("(code > ('10'::text)::money)", "\"code\" > '10'::money"),
        (
            "(code > ('10.5'::numeric)::money)",
            "\"code\" > 10.5::money",
        ),
    ] {
        let outputs = translate(clause, Some("en_US.UTF-8"));
        assert_ne!(
            relation_definition(&outputs.model(), "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` translates under a declared locale:\n{}",
            outputs.report()
        );
        let queries = outputs.tuple_queries();
        let gate = queries
            .iter()
            .find(|query| query.sql.contains(compared))
            .unwrap_or_else(|| {
                panic!(
                    "`{clause}` keeps `{compared}` for the database:\n{}",
                    format_tuples(queries)
                )
            });
        assert!(
            queries
                .iter()
                .all(|query| query.monetary_locale.as_deref() == Some("en_US.UTF-8")),
            "every query runs under the declared locale"
        );
        assert!(
            format_tuples(queries).contains("SET lc_monetary = 'en_US.UTF-8';\n"),
            "the loader sets the locale before any query"
        );
        let description = gate.description.as_ref().expect("the gate is described");
        assert!(
            matches!(
                records_from_row(description, &row(&[("id", "d1"), ("code", "$10.50")])),
                Err(RecordError::NotDerivableFromOneRow(_))
            ),
            "a `money` cell prints by the loader's locale, so the row never decides `{clause}`"
        );
    }
}

/// A value `PostgreSQL` cannot make money of, which it refuses on every read or at
/// `CREATE POLICY`, falls closed even under a declared locale.
#[test]
fn a_value_no_money_cast_reads_falls_closed() {
    for clause in [
        "(code > ('NaN'::numeric)::money)",
        "(code > ('true'::boolean)::money)",
    ] {
        let outputs = translate(clause, Some("en_US.UTF-8"));
        assert_eq!(
            relation_definition(&outputs.model(), "docs", "can_select").as_deref(),
            Some("no_access"),
            "`{clause}` has no money value:\n{}",
            outputs.report()
        );
    }
}

#[test]
fn no_query_sets_a_monetary_locale_nobody_declared() {
    let outputs = translate("(code IS NOT NULL)", None);
    assert!(outputs
        .tuple_queries()
        .iter()
        .all(|query| query.monetary_locale.is_none()));
    assert!(!format_tuples(outputs.tuple_queries()).contains("lc_monetary"));
}
