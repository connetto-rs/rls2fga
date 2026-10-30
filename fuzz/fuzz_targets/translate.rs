#![no_main]

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use rls2fga::classifier::oracle::{consult_oracle, OracleAnswer, PolicyOracle, RefusedExpr};
use rls2fga::classifier::patterns::{ClassifiedExpr, ConstantBool, PatternClass};
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::{PlanningError, Translation, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{records_from_row, ColumnKind, RowCell, RowList, RowValues};

/// Answers out of the refused text alone, so one input always draws one answer and a
/// crash replays. Spreads across all three states, since each reaches the pipeline
/// differently: a bail leaves the refusal standing, a denial substitutes a constant
/// false, and a classification faces `min_confidence` like any other.
struct TextOracle;

impl PolicyOracle for TextOracle {
    fn classify(&self, refused: &RefusedExpr<'_>) -> OracleAnswer {
        let len = refused.sql_text().len();
        match len % 3 {
            0 => OracleAnswer::Bailed,
            1 => OracleAnswer::Denied,
            _ => OracleAnswer::Classified(Box::new(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool {
                    value: len.is_multiple_of(2),
                }),
                confidence: ConfidenceLevel::B,
            })),
        }
    }
}

/// One row's values, answered from the input so every column is decided by the same
/// bytes the schema came from. Each accessor withholds a value on some columns, which
/// is what drives the `NULL` and absent-column branches.
struct FuzzRow<'a>(&'a str);

impl FuzzRow<'_> {
    fn mix(&self, column: &str) -> usize {
        column.len().wrapping_add(self.0.len())
    }
}

impl RowValues for FuzzRow<'_> {
    fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
        if self.mix(column).is_multiple_of(4) {
            return RowCell::Absent;
        }
        match kind {
            ColumnKind::Text => RowCell::Text(self.0.into()),
            ColumnKind::Integer => RowCell::Integer("1".into()),
            ColumnKind::Decimal => RowCell::Decimal("1.0".into()),
            ColumnKind::Bool => RowCell::Bool(self.mix(column).is_multiple_of(2)),
            ColumnKind::Date => RowCell::Date("2026-01-01".into()),
            ColumnKind::Time => RowCell::Time("01:02:03".into()),
            ColumnKind::Timestamp => RowCell::Timestamp("2026-01-01T01:02:03".into()),
            ColumnKind::TimestampTz => RowCell::TimestampTz("2026-01-01T01:02:03+00:00".into()),
            ColumnKind::Uuid => RowCell::Uuid("00000000-0000-0000-0000-000000000000".into()),
            _ => RowCell::Undecodable,
        }
    }

    fn list(&self, column: &str, kind: ColumnKind) -> RowList<'_> {
        if self.mix(column).is_multiple_of(6) {
            return RowList::Absent;
        }
        RowList::Values(vec![
            self.cell(column, kind),
            RowCell::Null,
            RowCell::Text("".into()),
        ])
    }

    fn json_text(&self, column: &str, path: &[String]) -> RowCell<'_> {
        if self.mix(column).wrapping_add(path.len()).is_multiple_of(7) {
            RowCell::Absent
        } else {
            RowCell::Text(self.0.into())
        }
    }
}

/// Render every output, and walk the records every shape describes.
fn exercise(translation: Translation, sql: &str) {
    let diverges = translation
        .notes()
        .iter()
        .any(|note| note.severity().diverges_from_database());
    assert_eq!(
        translation.clone().outputs().is_err(),
        diverges,
        "outputs() and divergence notes disagree"
    );

    let shapes = translation.relations();
    let outputs = translation.clone().outputs_accepting_gaps();
    black_box(outputs.model());
    black_box(outputs.json_model());
    black_box(outputs.notes().len());
    black_box(outputs.confidence_summary().len());

    let queries = outputs.tuple_queries();
    let row = FuzzRow(sql);
    for query in queries {
        if let Some(description) = query.description.as_ref() {
            black_box(records_from_row(description, &row).is_ok());
            black_box(description.is_pure());
            black_box(description.row_table());
        }
    }
    for entry in shapes {
        black_box(entry.from_one_row);
        for shape in &entry.shapes {
            black_box(records_from_row(shape, &row).is_ok());
            black_box(shape.is_pure());
            black_box(shape.row_table());
        }
    }
    black_box(format_tuples(queries));
    black_box(outputs.report());
}

fn exercise_planned(result: Result<Translation, PlanningError>, sql: &str) {
    match result {
        Ok(translation) => exercise(translation, sql),
        Err(error) => {
            black_box(error.to_string());
        }
    }
}

/// Without a registry no function is ever an accessor, so the whole role-threshold
/// pattern and the relations it scaffolds are unreachable at any runtime. Naming the
/// same functions the fixtures use puts those paths behind a token the dictionary
/// carries rather than behind nothing at all.
const REGISTRY: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id",
    "team_membership": {
      "table": "team_members",
      "user_col": "user_id",
      "team_col": "team_id"
    }
  },
  "auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"},
  "auth_role": {"kind": "role_accessor", "returns": "text"}
}"#;

fn translator_at(level: ConfidenceLevel) -> rls2fga::translator::Translator {
    TranslatorBuilder::new()
        .with_min_confidence(level)
        .with_registry_json(REGISTRY)
        .expect("the harness registry is a fixed literal")
        .build()
}

/// Drive the full translation pipeline on one SQL input.
///
/// The property under test is that no input, however malformed, may panic or abort.
/// Parse errors are an expected outcome for random bytes and are not failures.
fn translate(sql: &str) {
    let Ok(db) = parse_schema(sql) else {
        return;
    };

    // Every confidence threshold, since the level gates which policies reach model,
    // tuple, and report generation.
    for level in [
        ConfidenceLevel::A,
        ConfidenceLevel::B,
        ConfidenceLevel::C,
        ConfidenceLevel::D,
    ] {
        exercise_planned(translator_at(level).translate(&db), sql);
    }

    // An oracle's answers reach the generators only through `Translation::plan`, and at
    // one level rather than four because it doubles the work per input.
    let translator = translator_at(ConfidenceLevel::B);
    let mut policies = translator.classify(&db);
    black_box(consult_oracle(&mut policies, &TextOracle).len());
    exercise_planned(
        Translation::plan(
            policies,
            &db,
            translator.registry(),
            translator.min_confidence(),
            &GeneratorSettings::default(),
        ),
        sql,
    );
}

// `&str` rather than `&[u8]`: a mutation that breaks UTF-8 becomes SQL truncated at the
// bad byte instead of a discarded run.
fuzz_target!(|sql: &str| {
    translate(sql);
});
