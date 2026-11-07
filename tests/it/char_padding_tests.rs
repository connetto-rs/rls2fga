//! A `char(n)` cell arrives blank-padded, and a guard on it replays as `PostgreSQL` compares
//! it: ignoring trailing blanks, except against a value compared as `text`.

use rls2fga::types::{records_from_row, ConfidenceLevel, RecordDerivation, RecordDescription};

use crate::support::footgun::{db_of, translator};
use crate::support::row;

/// The record description of the gate `clause` opens on a `char(4)` column.
fn gate_description(clause: &str) -> RecordDescription {
    let schema = format!(
        "CREATE TABLE public.docs(id TEXT PRIMARY KEY, code CHAR(4));\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db_of(&schema))
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let description = outputs
        .tuple_queries()
        .iter()
        .find(|query| query.sql.contains("\"code\""))
        .and_then(|query| query.description.clone())
        .unwrap_or_else(|| panic!("`{clause}` opens a described gate"));
    assert!(
        matches!(description.derivation, RecordDerivation::FromRow { .. }),
        "the row alone decides `{clause}`"
    );
    description
}

/// Which of the padded cells `clause` admits, each as `to_jsonb` prints a `char(4)` value.
fn admitted(clause: &str, cells: &[&'static str]) -> Vec<&'static str> {
    let description = gate_description(clause);
    cells
        .iter()
        .copied()
        .filter(|cell| {
            let records = records_from_row(&description, &row(&[("id", "d"), ("code", cell)]))
                .unwrap_or_else(|error| panic!("`{clause}` on `{cell:?}`: {error:?}"));
            !records.is_empty()
        })
        .collect()
}

/// `'ab'`, `' ab'`, `'ab' || chr(9)` and `''` stored in a `char(4)` column.
const CELLS: &[&str] = &["ab  ", " ab ", "ab\t ", "    "];

#[test]
fn an_equality_ignores_the_trailing_blanks_on_both_sides() {
    assert_eq!(admitted("code = 'ab'", CELLS), ["ab  "]);
    assert_eq!(admitted("code = 'ab   '", CELLS), ["ab  "]);
    assert_eq!(admitted("'ab' = code", CELLS), ["ab  "]);
    assert_eq!(admitted("code = 'ab'::varchar", CELLS), ["ab  "]);
    assert_eq!(admitted("code = 'ab '::varchar(5)", CELLS), ["ab  "]);
    assert_eq!(admitted("code = 'ab'::char(3)", CELLS), ["ab  "]);
}

#[test]
fn leading_blanks_and_tabs_still_count() {
    assert_eq!(admitted("code = ' ab'", CELLS), [" ab "]);
    assert_eq!(admitted("code = 'ab\t'", CELLS), ["ab\t "]);
    assert_eq!(admitted("code = ''", CELLS), ["    "]);
}

#[test]
fn an_inequality_is_the_equality_negated() {
    assert_eq!(admitted("code <> 'ab '", CELLS), [" ab ", "ab\t ", "    "]);
}

#[test]
fn a_value_compared_as_text_keeps_its_trailing_blanks() {
    assert_eq!(admitted("code = 'ab'::text", CELLS), ["ab  "]);
    assert_eq!(admitted("code = 'ab '::text", CELLS), Vec::<&str>::new());
    assert_eq!(admitted("code <> 'ab '::text", CELLS), CELLS);
    assert_eq!(admitted("'ab '::text <> code", CELLS), CELLS);
    assert_eq!(admitted("code::text <> 'ab '", CELLS), CELLS);
    assert_eq!(admitted("code::varchar <> 'ab '", CELLS), CELLS);
}

#[test]
fn a_list_compares_every_item_as_char() {
    assert_eq!(admitted("code IN ('ab ', 'x'::text)", CELLS), ["ab  "]);
    assert_eq!(
        admitted("code IN ('ab '::text, 'x'::text)", CELLS),
        ["ab  "]
    );
    assert_eq!(
        admitted("code IN ('ab '::text, 'ab '::text)", CELLS),
        ["ab  "]
    );
    assert_eq!(admitted("code IN ('ab '::text)", CELLS), Vec::<&str>::new());
    assert_eq!(
        admitted("code::text IN ('ab ', 'x')", CELLS),
        Vec::<&str>::new()
    );
}

#[test]
fn an_array_compares_as_its_own_element_type() {
    assert_eq!(
        admitted("code = ANY (ARRAY['ab ', 'x'])", CELLS),
        Vec::<&str>::new()
    );
    assert_eq!(
        admitted("code = ANY (ARRAY['ab '::varchar, 'x'])", CELLS),
        ["ab  "]
    );
    assert_eq!(
        admitted("code = ANY (ARRAY['ab ', 'x']::text[])", CELLS),
        Vec::<&str>::new()
    );
    assert_eq!(admitted("code = ANY (ARRAY['ab', 'x'])", CELLS), ["ab  "]);
}
