//! A column reference has to resolve against a table before it becomes a relation.
//!
//! Nothing checked that a policy's column exists, so a name no table has became a
//! relation nobody can fill, and a name borrowed from a joined relation became a
//! grant `PostgreSQL` refuses. Both read exactly like a correct translation.

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::{parse_schema, ColumnLike, ParserDB, TableLike};
use rls2fga::term::describe_membership_term;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TableId;
use rls2fga::types::{RecordDerivation, ValueSource};
use sqlparser::ast::Expr;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::support;

const CALLER: &str = "current_setting('app.user_id', true)";

const DOCS: &str = "CREATE TABLE docs (
    id TEXT PRIMARY KEY, owner TEXT, tags TEXT[], data JSONB, flag BOOLEAN, status TEXT);";

/// The model, the tuple SQL, and the report, which is where a clause dropped below the
/// threshold is disclosed.
fn outputs_for(schema: &str, using: &str) -> (String, String, String) {
    let sql = format!(
        "{schema}\nALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY p ON docs FOR SELECT USING ({using});"
    );
    let db = support::deployment::db(&sql);
    let outputs = TranslatorBuilder::new(support::deployment::deployment([
        support::deployment::caller("app.user_id"),
        support::deployment::caller("app.subjects"),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .build()
    .translate(&db)
    .expect("translation should plan")
    .outputs_accepting_gaps();
    (
        outputs.model(),
        format_tuples(outputs.tuple_queries()),
        outputs.report(),
    )
}

/// Every shape a recogniser reads a single column through. Each names `ghost`, which
/// `docs` does not have.
#[test]
fn a_clause_naming_a_column_the_table_does_not_have_is_refused() {
    for using in [
        // P3, ownership.
        &format!("ghost = {CALLER}") as &str,
        // P6, the boolean flag. The bare `ghost` spelling was already refused, this one
        // was not, and one spelling of a shape must not translate while the other does.
        "ghost = TRUE",
        // P9, an attribute guard the row decides.
        "ghost = 'published'",
        // P11, the caller among a list column's elements.
        &format!("{CALLER} = ANY (ghost)"),
        // P12, the caller named by a jsonb field.
        &format!("ghost ->> 'owner' = {CALLER}"),
    ] {
        let (model, tuples, report) = outputs_for(DOCS, using);
        assert!(
            !tuples.contains("ghost"),
            "no query may read docs.ghost, which does not exist: {using}\n{tuples}"
        );
        assert!(
            model.contains("define can_select: no_access"),
            "a refused clause grants nothing: {using}\n{model}"
        );
        assert!(
            report.contains("ghost"),
            "the report has to name the column it refused, got:\n{report}"
        );
    }
}

/// The shape the downstream report reproduced, through the term surface it used.
#[test]
fn a_membership_term_never_compiles_against_an_absent_inner_column() {
    let db: ParserDB = parse_schema(
        "CREATE TABLE projects (id TEXT PRIMARY KEY, owner TEXT);
         CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));",
    )
    .expect("the schema should parse");
    let mut registry = FunctionRegistry::new();
    registry.enrich_from_schema(
        &db,
        &support::deployment::deployment([support::deployment::caller("app.user_id")]),
    );

    let term = parse_expr(&format!(
        "project_id IN (SELECT id FROM projects WHERE nonexistent = {CALLER})"
    ));
    let Ok(shapes) = describe_membership_term(&term, &db, &registry, "docs", ConfidenceLevel::B)
    else {
        return;
    };

    for entry in &shapes.relations {
        for shape in &entry.shapes {
            let RecordDerivation::FromRow { template, .. } = &shape.derivation else {
                continue;
            };
            if let ValueSource::Column(subject) = template.subject_key.part() {
                assert_ne!(
                    subject.to_string(),
                    "nonexistent",
                    "'projects' has no column 'nonexistent', so no shape may read one, \
                     notes were {:?}",
                    shapes.notes
                );
            }
        }
    }
}

/// The same defect reached the way a deployment reaches it, through a policy whose
/// subquery selects a parent by its key.
#[test]
fn an_inherited_parent_rule_naming_an_absent_column_is_refused() {
    let (model, tuples, report) = outputs_for(
        "CREATE TABLE projects (id TEXT PRIMARY KEY, owner TEXT);
         CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));",
        &format!("project_id IN (SELECT id FROM projects WHERE nonexistent = {CALLER})"),
    );

    assert!(
        !tuples.contains("nonexistent"),
        "no query may read projects.nonexistent:\n{tuples}"
    );
    assert!(
        !model.contains("nonexistent"),
        "the model may not name a relation after a column that does not exist:\n{model}"
    );
    assert!(
        report.contains("nonexistent"),
        "the report has to name the column it refused, got:\n{report}"
    );
}

/// The wrong allow: the qualifier names the joined relation, and dropping it resolves
/// the column against the subquery's own table, where the name happens to exist.
#[test]
fn a_column_borrowed_from_a_joined_relation_is_refused() {
    let sql = format!(
        "CREATE TABLE customers (id TEXT PRIMARY KEY, org_id TEXT);
         CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT REFERENCES customers(id));
         CREATE TABLE line_items (
             id TEXT PRIMARY KEY, order_id TEXT REFERENCES orders(id), sku TEXT);
         ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON line_items FOR SELECT USING (
             order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id
                          WHERE c.id = {CALLER}));"
    );
    let db = support::deployment::db(&sql);
    let outputs = TranslatorBuilder::new(support::deployment::deployment([
        support::deployment::caller("app.user_id"),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .build()
    .translate(&db)
    .expect("translation should plan")
    .outputs_accepting_gaps();
    let tuples = format_tuples(outputs.tuple_queries());

    assert!(
        !tuples.contains("'id' AS relation"),
        "granting orders to the user whose id equals the order's own key is a wrong \
         allow, the caller was compared against customers.id:\n{tuples}"
    );
}

/// The invariant that keeps this closed, over the whole corpus rather than over the
/// five shapes a probe happened to name.
#[test]
fn no_generated_query_reads_a_column_its_table_does_not_declare() {
    let mut checked = 0usize;
    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

        for query in outputs.tuple_queries() {
            let Some(description) = query.description.as_ref() else {
                continue;
            };
            // Every name the query may legitimately spell in quotes: the columns of
            // every table it reads, and the parts of those tables' own names.
            let mut spellable: Vec<String> = Vec::new();
            for table in &description.tables {
                // A table stored without a schema resides in `public`, which is what the
                // query spells.
                spellable.push(table.schema().unwrap_or("public").to_string());
                spellable.push(table.name().to_string());
                spellable.extend(declared_columns(&db, table).unwrap_or_default());
            }
            for quoted in quoted_identifiers(&query.sql) {
                assert!(
                    spellable.contains(&quoted),
                    "{fixture}: the query for {} spells \"{quoted}\", which is neither a \
                     column nor a table of {:?}\n{}",
                    query.comment,
                    description.tables,
                    query.sql
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 0, "the corpus has to exercise the invariant");
}

fn declared_columns(db: &ParserDB, table_id: &TableId) -> Option<Vec<String>> {
    let table = rls2fga::parser::names::lookup_table(db, &table_id.to_string())?;
    Some(
        table
            .columns(db)
            .into_iter()
            .flatten()
            .map(|column| column.stored_column_name().into_owned())
            .collect(),
    )
}

/// Every double-quoted identifier in the query, which is how the generator spells a
/// table or a column. Everything else it emits is a literal or an unquoted alias.
fn quoted_identifiers(sql: &str) -> Vec<String> {
    sql.split('"')
        .skip(1)
        .step_by(2)
        .map(ToString::to_string)
        .collect()
}

fn parse_expr(sql: &str) -> Expr {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(sql)
        .expect("the term should tokenize")
        .parse_expr()
        .expect("the term should parse")
}
