//! A row read as `PostgreSQL`'s `to_jsonb` prints it, for the row interface the
//! translation evaluates.
//!
//! ```
//! use rls2fga::json_row::JsonRow;
//! use rls2fga::types::{ColumnKind, RowCell, RowValues};
//!
//! let row = serde_json::json!({"id": 7, "owner": "alice", "blob": "\\x0aff"});
//! let row = JsonRow(&row);
//! assert_eq!(row.cell("id", ColumnKind::Integer), RowCell::Integer("7".into()));
//! assert_eq!(row.cell("owner", ColumnKind::Text), RowCell::Text("alice".into()));
//! assert_eq!(row.cell("blob", ColumnKind::Bytea), RowCell::Bytea(vec![0x0a, 0xff].into()));
//! assert_eq!(row.cell("missing", ColumnKind::Text), RowCell::Absent);
//! ```

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use alloc::borrow::Cow;

use serde_json::Value;

use crate::types::{ColumnKind, RowCell, RowList, RowValues};

/// One row as a JSON object keyed by column name, `bytea` in `PostgreSQL`'s hex
/// output.
#[derive(Debug, Clone, Copy)]
pub struct JsonRow<'a>(pub &'a Value);

impl RowValues for JsonRow<'_> {
    fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
        self.0
            .get(column)
            .map_or(RowCell::Absent, |value| scalar_cell(value, kind))
    }

    fn list(&self, column: &str, kind: ColumnKind) -> RowList<'_> {
        match self.0.get(column) {
            Some(Value::Null) => RowList::Null,
            Some(Value::Array(values)) => RowList::Values(
                values
                    .iter()
                    .map(|value| scalar_cell(value, kind))
                    .collect(),
            ),
            Some(_) => RowList::Undecodable,
            None => RowList::Absent,
        }
    }

    fn json_text(&self, column: &str, path: &[String]) -> RowCell<'_> {
        let Some(mut current) = self.0.get(column) else {
            return RowCell::Absent;
        };
        for step in path {
            let Some(next) = current.get(step) else {
                return RowCell::Null;
            };
            current = next;
        }
        match current {
            Value::Null => RowCell::Null,
            Value::String(text) => RowCell::Text(Cow::Borrowed(text)),
            Value::Number(_) | Value::Bool(_) => RowCell::Text(Cow::Owned(current.to_string())),
            Value::Array(_) | Value::Object(_) => RowCell::Undecodable,
        }
    }
}

/// A typed scalar the way the translation's row evaluator reads it.
fn scalar_cell(value: &Value, kind: ColumnKind) -> RowCell<'_> {
    match (value, kind) {
        (Value::Null, _) => RowCell::Null,
        (Value::String(text), ColumnKind::Text | ColumnKind::Bpchar) => {
            RowCell::Text(Cow::Borrowed(text))
        }
        (Value::String(text), ColumnKind::Uuid) => RowCell::Uuid(Cow::Borrowed(text)),
        (Value::String(text), ColumnKind::Date) => RowCell::Date(Cow::Borrowed(text)),
        (Value::String(text), ColumnKind::Time) => RowCell::Time(Cow::Borrowed(text)),
        (Value::String(text), ColumnKind::Timestamp) => RowCell::Timestamp(Cow::Borrowed(text)),
        (Value::String(text), ColumnKind::TimestampTz) => RowCell::TimestampTz(Cow::Borrowed(text)),
        (Value::String(text), ColumnKind::Bytea) => parse_bytea(text)
            .map_or(RowCell::Undecodable, |bytes| {
                RowCell::Bytea(Cow::Owned(bytes))
            }),
        (Value::Number(number), ColumnKind::Integer) => {
            RowCell::Integer(Cow::Owned(number.to_string()))
        }
        (Value::Number(number), ColumnKind::Decimal) => {
            RowCell::Decimal(Cow::Owned(number.to_string()))
        }
        (Value::Bool(flag), ColumnKind::Bool) => RowCell::Bool(*flag),
        _ => RowCell::Undecodable,
    }
}

/// The bytes of `PostgreSQL`'s hex `bytea` output, `\x` and two digits per byte.
fn parse_bytea(text: &str) -> Option<Vec<u8>> {
    let hex = text.strip_prefix("\\x")?;
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[high, low]| Some((hex_nibble(*high)? << 4) | hex_nibble(*low)?))
        .collect()
}

/// The value of one hexadecimal digit.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use serde_json::json;

    /// Typed scalar cells retain their kind and reject incompatible input.
    #[test]
    fn scalar_cells() {
        let text = json!("value");
        for (kind, expected) in [
            (ColumnKind::Text, RowCell::Text("value".into())),
            (ColumnKind::Bpchar, RowCell::Text("value".into())),
            (ColumnKind::Uuid, RowCell::Uuid("value".into())),
            (ColumnKind::Date, RowCell::Date("value".into())),
            (ColumnKind::Time, RowCell::Time("value".into())),
            (ColumnKind::Timestamp, RowCell::Timestamp("value".into())),
            (
                ColumnKind::TimestampTz,
                RowCell::TimestampTz("value".into()),
            ),
        ] {
            assert_eq!(scalar_cell(&text, kind), expected);
        }
        assert_eq!(scalar_cell(&Value::Null, ColumnKind::Text), RowCell::Null);
        assert_eq!(
            scalar_cell(&json!(7), ColumnKind::Integer),
            RowCell::Integer("7".into())
        );
        assert_eq!(
            scalar_cell(&json!(1.5), ColumnKind::Decimal),
            RowCell::Decimal("1.5".into())
        );
        assert_eq!(
            scalar_cell(&json!(true), ColumnKind::Bool),
            RowCell::Bool(true)
        );
        assert_eq!(scalar_cell(&text, ColumnKind::Bool), RowCell::Undecodable);
    }

    /// Hex `bytea` decodes, and anything else is undecodable rather than empty.
    #[test]
    fn bytea_cells() {
        assert_eq!(
            scalar_cell(&json!("\\x0aFf"), ColumnKind::Bytea),
            RowCell::Bytea(vec![0x0a, 0xff].into())
        );
        assert_eq!(
            scalar_cell(&json!("\\x"), ColumnKind::Bytea),
            RowCell::Bytea(vec![].into())
        );
        for undecodable in ["0aff", "\\x0af", "\\x0g"] {
            assert_eq!(
                scalar_cell(&json!(undecodable), ColumnKind::Bytea),
                RowCell::Undecodable,
                "{undecodable}"
            );
        }
    }

    /// Missing, null and malformed values remain distinct for lists and cells.
    #[test]
    fn cells_and_lists() {
        let value = json!({"null":null,"text":"value","list":["a",null,7]});
        let row = JsonRow(&value);
        assert_eq!(row.cell("missing", ColumnKind::Text), RowCell::Absent);
        assert_eq!(row.cell("null", ColumnKind::Text), RowCell::Null);
        assert_eq!(
            row.cell("text", ColumnKind::Text),
            RowCell::Text("value".into())
        );
        assert_eq!(row.list("missing", ColumnKind::Text), RowList::Absent);
        assert_eq!(row.list("null", ColumnKind::Text), RowList::Null);
        assert_eq!(row.list("text", ColumnKind::Text), RowList::Undecodable);
        assert_eq!(
            row.list("list", ColumnKind::Text),
            RowList::Values(vec![
                RowCell::Text("a".into()),
                RowCell::Null,
                RowCell::Undecodable
            ])
        );
    }

    /// JSON text extraction distinguishes absent columns from absent object keys.
    #[test]
    fn json_text_paths() {
        let value =
            json!({"doc":{"nested":{"text":"a","number":7,"bool":true,"null":null,"array":[]}}});
        let row = JsonRow(&value);
        assert_eq!(row.json_text("missing", &[]), RowCell::Absent);
        assert_eq!(row.json_text("doc", &["missing".into()]), RowCell::Null);
        assert_eq!(row.json_text("doc", &[]), RowCell::Undecodable);
        for (key, expected) in [
            ("text", RowCell::Text("a".into())),
            ("number", RowCell::Text("7".into())),
            ("bool", RowCell::Text("true".into())),
            ("null", RowCell::Null),
            ("array", RowCell::Undecodable),
        ] {
            assert_eq!(
                row.json_text("doc", &["nested".into(), key.into()]),
                expected
            );
        }
    }
}
