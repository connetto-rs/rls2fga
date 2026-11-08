//! One place a database value becomes SQL that renders an identifier.
//!
//! The Rust rendering lives in `rls2fga_types::identity`; this is its SQL twin, and the
//! two must agree for every input.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::fmt::Write;

use crate::types::TypeName;

#[cfg(test)]
pub(crate) use crate::types::identity::encode_identity;
pub(crate) use crate::types::identity::{
    encode_part, ESCAPE_MARKER, MAX_OBJECT_NAME_CHARS, MAX_SUBJECT_NAME_BYTES, PART_SEPARATOR,
    SAFE_PUNCTUATION, WILDCARD_SUBJECT_ID,
};

/// The regex character class matching a value the target spells verbatim.
///
/// Built from [`SAFE_PUNCTUATION`], so the SQL side and [`is_spelled_verbatim`]
/// cannot describe different sets.
fn safe_character_class() -> String {
    format!("A-Za-z0-9{SAFE_PUNCTUATION}")
}

/// SQL rendering one value expression as one part of an identifier.
///
/// Must agree with [`encode_part`] for every input. The pair is what the per
/// row record parity suite compares, since no assertion on either alone can
/// see them drift.
///
/// The test runs under `"C"`, since `PostgreSQL` refuses a regular expression on a column
/// whose collation is nondeterministic.
pub(crate) fn encode_part_sql(value_sql: &str) -> String {
    let class = safe_character_class();
    format!(
        "CASE WHEN {value_sql}::text COLLATE \"C\" ~ '^[{class}]+$' THEN {value_sql}::text \
         ELSE '{ESCAPE_MARKER}' || encode(convert_to({value_sql}::text, 'UTF8'), 'hex') END"
    )
}

/// SQL rendering an ordered list of value expressions as one identifier.
pub(crate) fn encode_identity_sql<'a, I>(parts: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = String::new();
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 {
            let _ = write!(out, " || '{PART_SEPARATOR}' || ");
        }
        out.push_str(&encode_part_sql(part));
    }
    out
}

/// SQL for a typed name whose key is read from `parts`.
///
/// The type name is deliberately **not** encoded: it has to match the type the
/// model declares, and `canonical_fga_type_name` already restricts it to
/// `[a-z0-9_]`, so there is nothing here to escape.
pub(crate) fn typed_name_sql<'a, I>(type_name: &TypeName, parts: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    format!("'{type_name}:' || {}", encode_identity_sql(parts))
}

/// A typed name whose key is already known, as a SQL string literal.
///
/// For a key the crate holds at generation time (a role name, a fixed holder
/// id) rather than one a column supplies. An encoded key never contains a
/// quote, so the literal needs no further escaping.
pub(crate) fn typed_name_literal(type_name: &TypeName, key: &str) -> String {
    format!("'{type_name}:{}'", encode_part(key))
}

/// The typed wildcard subject as a SQL literal. The `*` stays verbatim: it is
/// the target's wildcard, not a value to encode.
pub(crate) fn wildcard_subject_literal(user_type: &TypeName) -> String {
    format!("'{user_type}:{WILDCARD_SUBJECT_ID}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_value_is_spelled_verbatim() {
        for value in [
            "alice",
            "42",
            "11111111-2222-3333-4444-555555555555",
            "a.b@example.com",
            "Docs_1",
        ] {
            assert_eq!(
                encode_part(value),
                value,
                "expected {value} to need no escaping"
            );
        }
    }

    #[test]
    fn a_value_the_target_refuses_is_escaped_behind_the_marker() {
        // Every expectation is the hex PostgreSQL's `encode(convert_to(v,'UTF8'),'hex')`
        // produces for the same input, so the two renderings are pinned to one answer.
        for (value, expected) in [
            ("alice smith", "~616c69636520736d697468"),
            ("", "~"),
            ("a:b", "~613a62"),
            ("ali\u{e7}e", "~616c69c3a765"),
            ("a\nb", "~610a62"),
        ] {
            assert_eq!(encode_part(value), expected, "for {value:?}");
        }
    }

    #[test]
    fn a_value_the_target_silently_reinterprets_is_escaped_too() {
        // Neither of these fails on write. `user:*` is the typed wildcard and grants
        // everyone, and `user:alice#member` is a userset granting that relation's
        // members, so leaving either verbatim is a wrong allow rather than a failed load.
        assert_eq!(encode_part("*"), "~2a");
        assert_eq!(encode_part("alice#member"), "~616c696365236d656d626572");
    }

    #[test]
    fn the_marker_and_the_separator_escape_themselves() {
        // Without this the mapping stops being injective and a compound identity
        // built from encoded parts can be read back two ways.
        assert_eq!(encode_part("~tilde"), "~7e74696c6465");
        assert_eq!(encode_part("a|b"), "~617c62");
    }

    #[test]
    fn two_compound_keys_splitting_differently_do_not_render_alike() {
        let left = encode_identity(["1", "a|b"]);
        let right = encode_identity(["1|a", "b"]);
        assert_eq!(left, "1|~617c62");
        assert_eq!(right, "~317c61|b");
        assert_ne!(
            left, right,
            "a separator inside a part must escape or the parts cannot be told apart"
        );
    }

    #[test]
    fn a_single_column_key_is_a_list_of_one() {
        assert_eq!(encode_identity(["alice"]), "alice");
        assert_eq!(encode_identity(["alice smith"]), "~616c69636520736d697468");
    }

    #[test]
    fn the_sql_joins_compound_parts_with_the_separator() {
        let sql = encode_identity_sql([r#""paper_id""#, r#""viewer""#]);
        assert!(
            sql.contains(" || '|' || "),
            "expected the parts joined by the separator: {sql}"
        );
        assert_eq!(
            sql.matches("CASE WHEN").count(),
            2,
            "every part is encoded before joining, or the join is not injective: {sql}"
        );
    }

    #[test]
    fn both_readers_take_the_safe_set_from_one_place() {
        // The Rust predicate accepts exactly ASCII alphanumerics plus the declared
        // punctuation, and the SQL class is built from the same constant, so the two
        // cannot disagree about which values are spelled verbatim. Whether PostgreSQL
        // reads that class as intended is settled by the parity case, not here.
        let class = safe_character_class();
        assert_eq!(class, "A-Za-z0-9._@-");
        assert!(
            class.ends_with('-'),
            "a hyphen anywhere but last reads as a range inside a character class: {class}"
        );
        for byte in 0u8..=127 {
            let value = (byte as char).to_string();
            let verbatim = encode_part(&value) == value;
            let expected =
                byte.is_ascii_alphanumeric() || SAFE_PUNCTUATION.as_bytes().contains(&byte);
            assert_eq!(verbatim, expected, "for byte {byte:#04x}");
        }
    }

    #[test]
    fn a_typed_name_keeps_its_type_unencoded_and_encodes_only_the_key() {
        // The type has to match what the model declares, and `canonical_fga_type_name`
        // already restricts it to `[a-z0-9_]`, so encoding it here would rename the type.
        let sql = typed_name_sql(
            &TypeName::canonicalized("paper_shares"),
            [r#""paper_id""#, r#""viewer""#],
        );
        assert!(sql.starts_with("'paper_shares:' || "), "{sql}");
        assert_eq!(sql.matches("CASE WHEN").count(), 2, "{sql}");
    }

    #[test]
    fn a_generation_time_key_is_encoded_into_the_literal() {
        // A role name comes from the schema and may hold anything PostgreSQL allows.
        assert_eq!(
            typed_name_literal(&TypeName::canonicalized("pg_role"), "app_admin"),
            "'pg_role:app_admin'"
        );
        assert_eq!(
            typed_name_literal(&TypeName::canonicalized("pg_role"), "read only"),
            "'pg_role:~72656164206f6e6c79'"
        );
    }

    #[test]
    fn an_encoded_key_can_never_close_a_sql_string_literal() {
        // `typed_name_literal` interpolates without escaping, which is only safe
        // because the encoding admits no quote. Swept rather than argued.
        for byte in 0u8..=127 {
            let value = (byte as char).to_string();
            let encoded = encode_part(&value);
            assert!(
                !encoded.contains('\'') && !encoded.contains('\\'),
                "byte {byte:#04x} encoded to {encoded:?}"
            );
        }
    }
}
