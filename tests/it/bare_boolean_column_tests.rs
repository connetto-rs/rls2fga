//! A bare boolean column of the guarded row is the test `column = TRUE` spells, and `NOT column`
//! the test `column = FALSE` spells, which `PostgreSQL` evaluates alike on every row.

use rls2fga::translator::{DivergentTranslation, Outputs};
use rls2fga::types::ConfidenceLevel;

use crate::support::footgun::{db_of, translator};

const CALLER_OWNS: &str = "owner = current_setting('app.user_id', true)";

/// `t0` guarded by `clause` for every command. `confirmed` is a boolean through a domain.
fn schema_guarded_by(clause: &str) -> String {
    format!(
        "CREATE DOMAIN yes_no AS BOOLEAN;\n\
         CREATE TABLE t0 (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, team TEXT NOT NULL, \
         flag BOOLEAN NOT NULL, confirmed yes_no NOT NULL);\n\
         ALTER TABLE t0 ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY p ON t0 USING ({clause});\n"
    )
}

/// The outputs for `t0` guarded by `clause`, or the notes refusing it, below `B` as a
/// deployment refuses.
fn translated(clause: &str) -> Result<Outputs, DivergentTranslation> {
    translator(ConfidenceLevel::B)
        .translate(&db_of(&schema_guarded_by(clause)))
        .expect("translation should plan")
        .outputs()
}

fn outputs_for(clause: &str) -> Outputs {
    translated(clause)
        .unwrap_or_else(|divergent| panic!("`{clause}` must translate in full: {divergent:?}"))
}

/// The model `outputs` holds, with the SQL of every tuple query loading it.
fn translation(outputs: &Outputs) -> (String, Vec<&str>) {
    let queries = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .collect();
    (outputs.model(), queries)
}

#[test]
fn a_bare_boolean_column_translates_as_its_comparison() {
    for (bare, compared) in [
        ("flag".to_string(), "flag = true".to_string()),
        ("t0.flag".to_string(), "t0.flag = true".to_string()),
        ("NOT flag".to_string(), "flag = false".to_string()),
        ("NOT (flag)".to_string(), "flag = false".to_string()),
        (
            format!("flag AND {CALLER_OWNS}"),
            format!("flag = true AND {CALLER_OWNS}"),
        ),
        (
            format!("{CALLER_OWNS} OR flag"),
            format!("{CALLER_OWNS} OR flag = true"),
        ),
        (
            format!("NOT flag AND {CALLER_OWNS}"),
            format!("flag = false AND {CALLER_OWNS}"),
        ),
    ] {
        let (bare_outputs, compared_outputs) = (outputs_for(&bare), outputs_for(&compared));
        assert_eq!(
            translation(&bare_outputs),
            translation(&compared_outputs),
            "`{bare}` against `{compared}`"
        );
    }
}

/// A domain over `boolean` tests as `boolean` does, so its bare column reads as its comparison,
/// gaps that comparison leaves included.
#[test]
fn a_bare_domain_over_boolean_column_translates_as_its_comparison() {
    let outcome = |clause| match translated(clause) {
        Ok(outputs) => format!("{:?}", translation(&outputs)),
        Err(divergent) => format!("{:?}", divergent.notes()),
    };
    for (bare, compared) in [
        ("confirmed", "confirmed = true"),
        ("NOT confirmed", "confirmed = false"),
    ] {
        assert_eq!(
            outcome(bare),
            outcome(compared),
            "`{bare}` against `{compared}`"
        );
    }
}

/// A bare column of another type is no boolean test, so the classifier never reads it as
/// `column = TRUE`.
#[test]
fn a_bare_text_column_stays_unclassified() {
    for clause in ["team", "NOT team"] {
        let classified =
            translator(ConfidenceLevel::B).classify(&db_of(&schema_guarded_by(clause)));
        let using = classified[0]
            .using_classification()
            .expect("the policy carries a USING clause");
        assert_eq!(
            using.confidence,
            ConfidenceLevel::D,
            "`{clause}`: {:?}",
            using.pattern
        );
    }
}
