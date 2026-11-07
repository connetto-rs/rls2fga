//! Cost of deriving records from one row.
//!
//! The evaluator answers per change, so its cost is paid on every write a change
//! stream carries, not once per translation. Descriptions come from the public
//! pipeline rather than hand-built literals, so a bench cannot drift from the
//! shapes production actually emits.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rls2fga::parser::sql_parser::{parse_schema, Deployment};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{
    records_from_row, ColumnKind, RecordDerivation, RecordDescription, RowCell, RowList, RowValues,
    ValueSource,
};

/// A row held as plain values, which is the cheapest thing a caller can pass.
/// Anything slower than this is the caller's cost, not the evaluator's.
#[derive(Default)]
struct MapRow {
    text: BTreeMap<String, String>,
    lists: BTreeMap<String, Vec<String>>,
}

impl RowValues for MapRow {
    fn cell(&self, column: &str, kind: ColumnKind) -> RowCell<'_> {
        match self.text.get(column) {
            Some(value) => match kind {
                ColumnKind::Text => RowCell::Text(value.as_str().into()),
                ColumnKind::Uuid => RowCell::Uuid(value.as_str().into()),
                _ => RowCell::Undecodable,
            },
            None => RowCell::Absent,
        }
    }

    fn list(&self, column: &str, kind: ColumnKind) -> RowList<'_> {
        if kind != ColumnKind::Text {
            return RowList::Undecodable;
        }
        match self.lists.get(column) {
            Some(values) => RowList::Values(
                values
                    .iter()
                    .map(|value| RowCell::Text(value.as_str().into()))
                    .collect(),
            ),
            None => RowList::Absent,
        }
    }

    fn json_text(&self, _column: &str, _path: &[String]) -> RowCell<'_> {
        RowCell::Absent
    }
}

/// Every pure description a schema's tuple queries carry, read for a deployment acting as
/// one role, which the schema is parsed after.
fn descriptions(schema: &str) -> Vec<RecordDescription> {
    let db = parse_schema(&format!(
        "CREATE ROLE bench_login LOGIN; CREATE ROLE bench_user;\n{schema}"
    ))
    .expect("benchmark schema parses");
    let deployment = Deployment::new("bench_login", ["bench_user"], []).expect("one acting role");
    let translator = TranslatorBuilder::new(deployment)
        .with_min_confidence(ConfidenceLevel::C)
        .build();
    translator
        .translate(&db)
        .expect("benchmark schema should plan")
        .outputs_accepting_gaps()
        .tuple_queries()
        .iter()
        .filter_map(|query| query.description.clone())
        .collect()
}

/// The one description whose subject reads `source`, so a bench names the shape it
/// measures instead of trusting an index.
fn by_subject(schema: &str, want: &dyn Fn(&ValueSource) -> bool) -> RecordDescription {
    let found: Vec<_> = descriptions(schema)
        .into_iter()
        .filter(|d| match &d.derivation {
            RecordDerivation::FromRow { template, .. } => want(template.subject_key.part()),
            _ => false,
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one matching description, got {}",
        found.len()
    );
    found.into_iter().next().expect("checked above")
}

const OWNERSHIP: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);";

const ARRAY: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, editors TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (current_user = ANY (editors));";

const GUARDED: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (status = 'published');";

fn one_record(c: &mut Criterion) {
    let description = by_subject(OWNERSHIP, &|s| matches!(s, ValueSource::Column(_)));
    let mut row = MapRow::default();
    row.text.insert("id".to_string(), "d1".to_string());
    row.text.insert("owner_id".to_string(), "u1".to_string());

    c.bench_function("one_record", |b| {
        b.iter(|| {
            let records = records_from_row(black_box(&description), black_box(&row))
                .expect("a pure description answers");
            debug_assert_eq!(records.len(), 1);
            records
        });
    });
}

fn expanding_record(c: &mut Criterion) {
    let description = by_subject(ARRAY, &|s| matches!(s, ValueSource::ListElements(_)));
    let mut group = c.benchmark_group("expanding_record");

    for editors in [1_u64, 8, 64, 512] {
        let mut row = MapRow::default();
        row.text.insert("id".to_string(), "d1".to_string());
        row.lists.insert(
            "editors".to_string(),
            (0..editors).map(|i| format!("u{i}")).collect(),
        );

        group.throughput(Throughput::Elements(editors));
        group.bench_with_input(BenchmarkId::from_parameter(editors), &row, |b, row| {
            b.iter(|| {
                records_from_row(black_box(&description), black_box(row))
                    .expect("a pure description answers")
            });
        });
    }
    group.finish();
}

/// A guard the row fails costs only the guard, and it is the common case for a
/// change stream carrying every row of a table.
fn guard_rejects(c: &mut Criterion) {
    let description = by_subject(GUARDED, &|s| matches!(s, ValueSource::Literal(_)));
    let mut row = MapRow::default();
    row.text.insert("id".to_string(), "d1".to_string());
    row.text.insert("status".to_string(), "draft".to_string());

    c.bench_function("guard_rejects", |b| {
        b.iter(|| {
            let records = records_from_row(black_box(&description), black_box(&row))
                .expect("a pure description answers");
            debug_assert_eq!(records, Vec::new());
            records
        });
    });
}

criterion_group!(benches, one_record, expanding_record, guard_rejects);
criterion_main!(benches);
