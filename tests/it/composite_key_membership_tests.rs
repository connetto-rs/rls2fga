//! A membership subquery joined on every column of a composite key, from
//! `connetto-rs/upstream/rls2fga-two-column-join-graded-below-threshold.md`.
//!
//! The two-column policy states the same relationship as the one-column control,
//! with the share scoped by tenant, so it grades no worse and its bound query
//! binds every key column.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::parser::sql_parser::ParserDB;
use rls2fga::translator::Translation;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RecordDerivation;
use rls2fga::types::TranslationNote;

use crate::support::deployment::{db, translator_builder};

/// The control: one join column, classifies today.
const ONE_COLUMN: &str = "
CREATE TABLE p1(id INT PRIMARY KEY, owner TEXT);
ALTER TABLE p1 ENABLE ROW LEVEL SECURITY;
CREATE TABLE s1(paper_id INT NOT NULL, viewer TEXT NOT NULL, PRIMARY KEY(paper_id, viewer));
CREATE POLICY p1_p ON p1 FOR SELECT USING (
  EXISTS (SELECT 1 FROM s1 s WHERE s.paper_id = p1.id
            AND s.viewer = current_setting('app.user_id', true)));
";

/// The report: the same shape joined on the guarded table's two-column key.
const TWO_COLUMNS: &str = "
CREATE TABLE p2(tenant_id INT NOT NULL, id INT NOT NULL, owner TEXT, PRIMARY KEY(tenant_id, id));
ALTER TABLE p2 ENABLE ROW LEVEL SECURITY;
CREATE TABLE s2(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
                PRIMARY KEY(tenant_id, paper_id, viewer));
CREATE POLICY p2_p ON p2 FOR SELECT USING (
  EXISTS (SELECT 1 FROM s2 s WHERE s.tenant_id = p2.tenant_id AND s.paper_id = p2.id
            AND s.viewer = current_setting('app.user_id', true)));
";

fn parse(sql: &str) -> ParserDB {
    db(sql)
}

fn translation(db: &ParserDB) -> Translation {
    translator_builder()
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(db)
        .expect("translation plans")
}

fn below_threshold_notes(translation: &Translation) -> Vec<String> {
    translation
        .notes()
        .iter()
        .filter(|note| {
            matches!(
                note,
                TranslationNote::ClauseBelowThreshold { .. }
                    | TranslationNote::CoveringPoliciesBelowThreshold { .. }
            )
        })
        .map(ToString::to_string)
        .collect()
}

/// Expected behaviour 1 and 3 of the report: the two-column policy grades no
/// worse than the one-column control, so neither fixture drops a clause.
#[test]
fn a_composite_key_membership_join_is_not_graded_below_its_one_column_shape() {
    let control_db = parse(ONE_COLUMN);
    let control = translation(&control_db);
    assert_eq!(
        below_threshold_notes(&control),
        Vec::<String>::new(),
        "the control must classify, or this test proves nothing"
    );

    let db = parse(TWO_COLUMNS);
    let translated = translation(&db);
    assert_eq!(
        below_threshold_notes(&translated),
        Vec::<String>::new(),
        "one added equality between two key columns narrows the relationship"
    );
}

/// The same shape with a residual only SQL can evaluate, which forces the joined
/// derivation whose bound query the report probed.
const TWO_COLUMNS_SQL_RESIDUAL: &str = "
CREATE TABLE p2(tenant_id INT NOT NULL, id INT NOT NULL, owner TEXT, PRIMARY KEY(tenant_id, id));
ALTER TABLE p2 ENABLE ROW LEVEL SECURITY;
CREATE TABLE s2(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
                note TEXT, PRIMARY KEY(tenant_id, paper_id, viewer));
CREATE POLICY p2_p ON p2 FOR SELECT USING (
  EXISTS (SELECT 1 FROM s2 s WHERE s.tenant_id = p2.tenant_id AND s.paper_id = p2.id
            AND s.viewer = current_setting('app.user_id', true)
            AND lower(s.note) = 'ok'));
";

/// Expected behaviour 2 of the report, on the plain shape: one membership row
/// decides its records, and the object it names is keyed on both join columns.
#[test]
fn a_composite_key_membership_row_keys_its_object_on_every_join_column() {
    let db = parse(TWO_COLUMNS);
    let translated = translation(&db);

    let key_widths: Vec<usize> = translated
        .relations()
        .iter()
        .flat_map(|entry| entry.shapes.iter())
        .filter_map(|shape| match &shape.derivation {
            RecordDerivation::FromRow {
                table, template, ..
            } if table.to_string() == "public.s2" => Some(template.object_key.parts().len()),
            _ => None,
        })
        .collect();

    assert!(
        key_widths.contains(&2),
        "the membership record names its object by both join columns, got: {key_widths:?}"
    );
}

/// Expected behaviour 2 of the report, on the joined shape: the bound query on the
/// share table binds every join column, in declaration order, since a query bound
/// to a prefix of a compound key answers for every row sharing that prefix.
#[test]
fn a_composite_key_membership_bound_query_binds_every_join_column() {
    let sql = TWO_COLUMNS_SQL_RESIDUAL;
    let db = parse(sql);
    let translated = translation(&db);

    let bound: Vec<Vec<String>> = translated
        .relations()
        .iter()
        .flat_map(|entry| entry.shapes.iter())
        .filter_map(|shape| match &shape.derivation {
            RecordDerivation::Joined { queries, .. } => Some(queries),
            _ => None,
        })
        .flatten()
        .filter(|query| query.table().to_string() == "public.s2")
        .map(|query| {
            query
                .key_columns()
                .iter()
                .map(|column| column.as_str().to_string())
                .collect()
        })
        .collect();

    assert!(
        bound.contains(&vec!["tenant_id".to_string(), "paper_id".to_string()]),
        "the share requery binds both key columns, got: {bound:?}"
    );
}

/// A composite-FK-backed membership: the pairs are the host columns of one declared
/// foreign key onto the parent's full primary key, so the parent is that table.
const COMPOSITE_FK_PARENT: &str = "
CREATE TABLE projects(tenant_id INT NOT NULL, id INT NOT NULL, PRIMARY KEY(tenant_id, id));
CREATE TABLE docs(doc_id INT PRIMARY KEY, tenant_id INT NOT NULL, project_id INT NOT NULL,
                  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id));
CREATE TABLE project_members(tenant_id INT NOT NULL, project_id INT NOT NULL,
                             user_id TEXT NOT NULL,
                             PRIMARY KEY(tenant_id, project_id, user_id),
                             FOREIGN KEY (tenant_id, project_id)
                               REFERENCES projects(tenant_id, id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM project_members m
  WHERE m.tenant_id = docs.tenant_id AND m.project_id = docs.project_id
    AND m.user_id = current_setting('app.user_id', true)));
";

fn tuple_sql(sql: &str) -> String {
    let db = parse(sql);
    let translated = translation(&db);
    let outputs = translated.outputs_accepting_gaps();
    rls2fga::generator::tuple_generator::format_tuples(outputs.tuple_queries())
}

/// Membership tuples preserve every column of the guarded key.
#[test]
fn a_self_keyed_membership_names_the_guarded_row_by_its_whole_key() {
    let sql = TWO_COLUMNS;
    let tuples = tuple_sql(sql);
    assert!(
        tuples.contains(r#"'p2:' || CASE WHEN "tenant_id""#)
            && tuples.contains(r#"'|' || CASE WHEN "paper_id""#),
        "the membership object carries both share columns in the guarded key's \
         order:\n{tuples}"
    );
}

/// Membership tuples preserve the referenced parent's compound key.
#[test]
fn a_composite_fk_membership_names_the_referenced_parent_by_its_whole_key() {
    let sql = COMPOSITE_FK_PARENT;
    let tuples = tuple_sql(sql);
    assert!(
        tuples.contains(r#"'projects:' || CASE WHEN "tenant_id""#)
            && tuples.contains(r#"'|' || CASE WHEN "project_id""#),
        "the parent object carries both host columns in its key's order:\n{tuples}"
    );
}
