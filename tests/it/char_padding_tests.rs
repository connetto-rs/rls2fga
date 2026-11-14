//! A `char(n)` cell arrives blank-padded, and a guard on it replays as `PostgreSQL` compares
//! it: ignoring trailing blanks, except against a value compared as `text`.

use rls2fga::types::{records_from_row, ConfidenceLevel, RecordDerivation, RecordDescription};

use crate::support::footgun::{db_of, translator};
use crate::support::row;

/// The record description of the gate `clause` opens on a `code` column of `column_type`.
fn gate_description_on(column_type: &str, clause: &str) -> RecordDescription {
    let schema = format!(
        "CREATE TABLE public.docs(id TEXT PRIMARY KEY, code {column_type});\n\
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
        .unwrap_or_else(|| panic!("`{clause}` on {column_type} opens a described gate"));
    assert!(
        matches!(description.derivation, RecordDerivation::FromRow { .. }),
        "the row alone decides `{clause}` on {column_type}"
    );
    description
}

/// Which of the padded cells `clause` admits, each as `to_jsonb` prints a `char(4)` value.
fn admitted(clause: &str, cells: &[&'static str]) -> Vec<&'static str> {
    admitted_on("CHAR(4)", clause, cells)
}

/// Which of `cells` the gate `clause` on a `code` column of `column_type` admits.
fn admitted_on(column_type: &str, clause: &str, cells: &[&'static str]) -> Vec<&'static str> {
    let description = gate_description_on(column_type, clause);
    cells
        .iter()
        .copied()
        .filter(|cell| {
            let records = records_from_row(&description, &row(&[("id", "d"), ("code", cell)]))
                .unwrap_or_else(|error| {
                    panic!("`{clause}` on {column_type} `{cell:?}`: {error:?}")
                });
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
        admitted("code = ANY (ARRAY['ab '::char(3), 'x'])", CELLS),
        ["ab  "]
    );
    assert_eq!(
        admitted("code = ANY (ARRAY['x'::char(2), 'ab '::varchar])", CELLS),
        ["ab  "]
    );
    assert_eq!(
        admitted("code = ANY (ARRAY['ab ', 'x']::text[])", CELLS),
        Vec::<&str>::new()
    );
    assert_eq!(admitted("code = ANY (ARRAY['ab', 'x'])", CELLS), ["ab  "]);
}

/// `pg_policies` and `pg_dump` print every literal compared with a `char(n)` column cast to
/// the unbounded `bpchar`, which keeps the literal's own blanks and compares as `char`.
#[test]
fn a_literal_printed_as_bpchar_compares_as_char() {
    assert_eq!(admitted("code = 'ab'::bpchar", CELLS), ["ab  "]);
    assert_eq!(admitted("code = 'ab   '::bpchar", CELLS), ["ab  "]);
    assert_eq!(admitted("'ab '::bpchar = code", CELLS), ["ab  "]);
    assert_eq!(admitted("code = ' ab'::bpchar", CELLS), [" ab "]);
    assert_eq!(
        admitted("code <> 'ab '::bpchar", CELLS),
        [" ab ", "ab\t ", "    "]
    );
    assert_eq!(admitted("(code = 'ab'::bpchar)", CELLS), ["ab  "]);
    assert_eq!(
        admitted("code = ANY (ARRAY['ab '::bpchar, 'x'::bpchar])", CELLS),
        ["ab  "]
    );
    assert_eq!(
        admitted("code IN ('ab '::bpchar, 'x'::bpchar)", CELLS),
        ["ab  "]
    );
    assert_eq!(
        admitted("code = ('ab'::character varying)::bpchar", CELLS),
        ["ab  "]
    );
    assert_eq!(admitted("code = 'ab '::bpchar::text", CELLS), ["ab  "]);
    assert_eq!(
        admitted("code = 'ab  x'::bpchar::text", CELLS),
        Vec::<&str>::new()
    );
    assert_eq!(
        admitted("code = 'ab'::character", CELLS),
        Vec::<&str>::new()
    );
    assert_eq!(admitted("code = 'abcd'::bpchar(2)", CELLS), ["ab  "]);
    assert_eq!(
        admitted("code = 'ab '::pg_catalog.bpchar(3)", CELLS),
        ["ab  "]
    );
}

/// The national spellings are `char(n)` and `varchar(n)` under another name, so the fixed
/// ones drop their padding and the varying ones keep every blank, as on `PostgreSQL` 18.6.
#[test]
fn the_national_spellings_compare_as_char_and_varchar() {
    for column_type in ["NATIONAL CHARACTER(4)", "NATIONAL CHAR(4)", "NCHAR(4)"] {
        assert_eq!(
            admitted_on(column_type, "code = 'ab '", CELLS),
            ["ab  "],
            "{column_type} pads"
        );
        assert_eq!(
            admitted_on(column_type, "code <> 'ab '", CELLS),
            [" ab ", "ab\t ", "    "],
            "{column_type} pads"
        );
    }
    for column_type in [
        "NATIONAL CHARACTER VARYING(4)",
        "NATIONAL CHAR VARYING(4)",
        "NCHAR VARYING(4)",
    ] {
        assert_eq!(
            admitted_on(column_type, "code = 'ab '", &["ab", " ab", "ab "]),
            ["ab "],
            "{column_type} keeps every blank"
        );
    }
}
