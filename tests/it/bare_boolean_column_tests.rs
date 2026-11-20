//! A bare boolean column of the guarded row is the test `column = TRUE` spells, and `NOT column`
//! the test `column = FALSE` spells, which `PostgreSQL` evaluates alike on every row.

use rls2fga::translator::Outputs;
use rls2fga::types::ConfidenceLevel;

use crate::support::footgun::{db_of, translator};

const CALLER_OWNS: &str = "owner = current_setting('app.user_id', true)";

/// The outputs for `t0` guarded by `clause` for every command, refusing any clause below `B`
/// as a deployment does.
fn outputs_for(clause: &str) -> Outputs {
    let schema = format!(
        "CREATE TABLE t0 (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, team TEXT NOT NULL, \
         flag BOOLEAN NOT NULL);\n\
         ALTER TABLE t0 ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY p ON t0 USING ({clause});\n"
    );
    translator(ConfidenceLevel::B)
        .translate(&db_of(&schema))
        .expect("translation should plan")
        .outputs()
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
