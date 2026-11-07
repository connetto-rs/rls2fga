//! A text guard replays from the row only where `PostgreSQL` compares the column byte for
//! byte, which a nondeterministic collation does not.

use rls2fga::types::{ConfidenceLevel, RecordDerivation};

use crate::support::footgun::{db_of, translator};

const CASE_INSENSITIVE: &str = "CREATE COLLATION case_insensitive \
     (provider = icu, locale = 'und-u-ks-level2', deterministic = false);";

/// Whether the gate `clause` opens on a `code` column of `column_type` replays from the row.
fn replays_from_row(column_type: &str, clause: &str) -> bool {
    let schema = format!(
        "{CASE_INSENSITIVE}\n\
         CREATE TABLE public.docs(id TEXT PRIMARY KEY, code {column_type});\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db_of(&schema))
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let query = outputs
        .tuple_queries()
        .iter()
        .find(|query| query.sql.contains("\"code\""))
        .unwrap_or_else(|| panic!("`{clause}` on {column_type} loads its gate"));
    query.description.as_ref().is_some_and(|description| {
        matches!(description.derivation, RecordDerivation::FromRow { .. })
    })
}

#[test]
fn a_nondeterministic_column_leaves_its_text_guard_to_the_database() {
    for clause in ["code = 'ab'", "code <> 'ab'", "code IN ('ab', 'x')"] {
        assert!(
            !replays_from_row("TEXT COLLATE case_insensitive", clause),
            "`{clause}` compares 'AB' and 'ab' as equal, which the row cannot tell"
        );
    }
}

#[test]
fn a_deterministic_column_still_replays_its_text_guard() {
    for column_type in ["TEXT", "TEXT COLLATE \"C\"", "CHAR(4) COLLATE \"C\""] {
        assert!(
            replays_from_row(column_type, "code <> 'ab'"),
            "{column_type} compares byte for byte"
        );
    }
}

#[test]
fn a_null_test_on_a_nondeterministic_column_still_replays() {
    assert!(replays_from_row(
        "TEXT COLLATE case_insensitive",
        "code IS NOT NULL"
    ));
}
