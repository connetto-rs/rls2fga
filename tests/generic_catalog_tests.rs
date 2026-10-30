//! The schema catalog reaches the public surface as a `DatabaseLike`.
//!
//! rls2fga reads a catalog only through the traits, so demanding the one instantiation
//! `parse_schema` returns would refuse a caller holding any other, a different dialect
//! or a catalog read from a live server rather than parsed from DDL. The proof is a body
//! the compiler checks against the bound alone: every public entry point that takes a
//! catalog is called here through `DB`, so a concrete catalog reappearing anywhere on
//! the surface fails to build.

mod support;

use std::sync::Arc;

use sql_traits::errors::LookupError;
use sql_traits::structs::metadata::{ExpressionCalls, PolicyMetadata};
use sql_traits::structs::{TableAttribute, TableMetadata};
use sqlparser::ast::{
    ColumnDef, ColumnOption, CreatePolicy, CreateTable, Expr, ForeignKeyConstraint, Statement,
    TableConstraint,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use rls2fga::classifier::function_registry::{
    FunctionRegistry, SessionAttribute, SessionAttributeKind,
};
use rls2fga::classifier::patterns::{
    ClassifiedExpr, DirectOwnership, MembershipJoinPair, PatternClass, PolicyCommand,
};
use rls2fga::classifier::policy_classifier::{classify_expr, classify_policies};
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::function_analyzer::AccessorInferenceSettings;
use rls2fga::parser::sql_parser::{
    parse_schema, ColumnLike, DatabaseLike, ForeignKeyLike, ParserDB, PolicyLike, TableLike,
};
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RelationShapes;

const SCHEMA: &str = "
CREATE TABLE public.users (id UUID PRIMARY KEY);
CREATE TABLE public.docs (id UUID PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
";

/// What the generic pass produced, so the assertions can see it answered rather than
/// compiled vacuously.
struct Driven {
    classified: usize,
    enriched_accessor: bool,
    expr_pattern: PatternClass,
    model: String,
    json_types: Vec<String>,
    tuples: String,
    report: String,
    relations: Vec<RelationShapes>,
    notes: usize,
    unhandled: usize,
    confidence: Vec<(String, ConfidenceLevel)>,
    written: String,
}

/// Every public entry point that takes a catalog, called through `DB`.
fn drive<DB: DatabaseLike>(db: &DB) -> Driven {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(support::ACCESSOR_REGISTRY)
        .expect("the registry parses");

    let settings = AccessorInferenceSettings::default();
    let generator = GeneratorSettings::default();

    // The free classifier, plus the two registry enrichers.
    let classified = classify_policies(db, &registry);

    let mut enriched = FunctionRegistry::new();
    enriched.enrich_from_schema(db);
    let mut enriched_with_settings = FunctionRegistry::new();
    enriched_with_settings.enrich_from_schema_with_settings(db, &settings);
    let enriched_accessor = enriched.is_current_user_accessor("auth_current_user_id")
        && enriched_with_settings.is_current_user_accessor("auth_current_user_id");

    // One expression, classified on its own, which is how an oracle reaches the
    // pattern tree without going through the whole schema.
    let policy = db.policies().next().expect("the schema declares a policy");
    let expr = policy
        .using_expression(db)
        .expect("the policy stores a USING clause")
        .clone();
    let expr_pattern = classify_expr(&expr, db, &registry, "docs", PolicyCommand::Select).pattern;

    // The facade, then the plan built from answers somebody else classified.
    let translator = TranslatorBuilder::new()
        .with_registry(registry.clone())
        .with_min_confidence(ConfidenceLevel::B)
        .build();
    assert_eq!(translator.classify(db).len(), classified.len());
    let (facade_classified, effective) = translator.classify_with_effective_registry(db);
    assert_eq!(facade_classified.len(), classified.len());

    let translation = translator.translate(db).expect("translation should plan");
    let notes = translation.notes().len();
    let unhandled = translation.unhandled().count();
    let relations = translation.relations().to_vec();
    let outputs = translation.outputs().expect("nothing goes unhandled");

    let model = outputs.model();
    let json_types = outputs
        .json_model()
        .type_definitions
        .iter()
        .map(|definition| definition.type_name.to_string())
        .collect();
    let tuples = format_tuples(outputs.tuple_queries());
    let report = outputs.report();
    assert_eq!(outputs.notes().len(), notes);
    let confidence = outputs.confidence_summary().to_vec();

    let dir = support::unique_temp_dir("rls2fga_generic_catalog");
    outputs.write(&dir, "docs").expect("the write succeeds");
    let written = std::fs::read_to_string(dir.join("docs.fga")).expect("the model is written");

    // The plan door, reached with the answers the free classifier gave.
    let replanned = Translation::plan(
        classified.clone(),
        db,
        &effective,
        ConfidenceLevel::B,
        &generator,
    )
    .expect("translation should plan");
    assert_eq!(replanned.relations().len(), relations.len());

    Driven {
        classified: classified.len(),
        enriched_accessor,
        expr_pattern,
        model,
        json_types,
        tuples,
        report,
        relations,
        notes,
        unhandled,
        confidence,
        written,
    }
}

/// The generic pass translates, rather than compiling against a surface it never
/// exercises.
#[test]
fn a_catalog_known_only_as_database_like_drives_the_whole_surface() {
    let db = parse_schema(SCHEMA).expect("the schema parses");
    let driven = drive(&db);

    assert_eq!(driven.classified, 1);
    assert!(
        driven.enriched_accessor,
        "schema enrichment must recognise the accessor, saw it refused"
    );
    assert!(
        matches!(&driven.expr_pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "classifying the clause on its own must reach direct ownership, saw {:?}",
        driven.expr_pattern
    );
    assert!(
        driven.model.contains("type docs") && driven.model.contains("can_select"),
        "the DSL must carry the policied table and its read action, saw:\n{}",
        driven.model
    );
    assert!(
        driven.json_types.iter().any(|name| name == "docs"),
        "the JSON model must declare the policied type, saw {:?}",
        driven.json_types
    );
    assert!(
        driven.tuples.contains("owner_id"),
        "the tuple SQL must read the ownership column, saw:\n{}",
        driven.tuples
    );
    assert!(
        driven.report.contains("docs_owner"),
        "the report must name the policy, saw:\n{}",
        driven.report
    );
    assert!(
        driven
            .relations
            .iter()
            .any(|shapes| shapes.relation == "can_select"),
        "the relation report must reach the read action, saw {:?}",
        driven
            .relations
            .iter()
            .map(|shapes| shapes.relation.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(driven.unhandled, 0);
    assert_eq!(
        driven.confidence,
        vec![("docs_owner".to_string(), ConfidenceLevel::A)]
    );
    assert_eq!(driven.written, driven.model);
    assert!(driven.notes >= driven.unhandled);
}

/// The `P19` policy every edge catalog guards.
const P19_POLICY: &str = "
CREATE POLICY orders_read ON orders FOR SELECT USING (EXISTS (
    SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
    AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
        AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')));
";

/// The one edge a catalog variant moves on the `ownable_ancestors` to `owners` hop.
#[derive(Clone, Copy)]
enum LinkEdge {
    Valid,
    /// The key's host list names a column the link table does not declare.
    DanglingHost,
    /// The key reaches a table the catalog does not hold.
    DanglingTarget,
    /// The key names a column the target table does not declare.
    DanglingTargetColumn,
    /// The target's key holds more columns than the key's host list.
    WiderTargetKey,
    /// The target holds a unique column and no primary key.
    NoTargetKey,
}

/// The DDL every edge rebuilds, and the only two lines that differ per edge.
fn edge_ddl(edge: LinkEdge) -> String {
    let (owners, link) = match edge {
        LinkEdge::Valid => (
            "CREATE TABLE owners (id TEXT PRIMARY KEY);",
            "CREATE TABLE ownable_ancestors (\n    ownable TEXT NOT NULL REFERENCES ownables(id),\n    owner TEXT NOT NULL REFERENCES owners(id),\n    PRIMARY KEY (ownable, owner));",
        ),
        LinkEdge::DanglingHost => (
            "CREATE TABLE owners (id TEXT PRIMARY KEY);",
            "CREATE TABLE ownable_ancestors (\n    ownable TEXT NOT NULL REFERENCES ownables(id),\n    owner TEXT NOT NULL,\n    PRIMARY KEY (ownable, owner),\n    CONSTRAINT fk_owner FOREIGN KEY (owner_fk) REFERENCES owners(id));",
        ),
        LinkEdge::DanglingTarget => (
            "CREATE TABLE owners (id TEXT PRIMARY KEY);",
            "CREATE TABLE ownable_ancestors (\n    ownable TEXT NOT NULL REFERENCES ownables(id),\n    owner TEXT NOT NULL CONSTRAINT fk_owner REFERENCES ghosts(id),\n    PRIMARY KEY (ownable, owner));",
        ),
        LinkEdge::DanglingTargetColumn => (
            "CREATE TABLE owners (id TEXT PRIMARY KEY);",
            "CREATE TABLE ownable_ancestors (\n    ownable TEXT NOT NULL REFERENCES ownables(id),\n    owner TEXT NOT NULL CONSTRAINT fk_owner REFERENCES owners(owner_missing),\n    PRIMARY KEY (ownable, owner));",
        ),
        LinkEdge::WiderTargetKey => (
            "CREATE TABLE owners (id TEXT, extra TEXT, PRIMARY KEY (id, extra));",
            "CREATE TABLE ownable_ancestors (\n    ownable TEXT NOT NULL REFERENCES ownables(id),\n    owner TEXT NOT NULL CONSTRAINT fk_owner REFERENCES owners(id, extra),\n    PRIMARY KEY (ownable, owner));",
        ),
        LinkEdge::NoTargetKey => (
            "CREATE TABLE owners (id TEXT, UNIQUE (id));",
            "CREATE TABLE ownable_ancestors (\n    ownable TEXT NOT NULL REFERENCES ownables(id),\n    owner TEXT NOT NULL CONSTRAINT fk_owner REFERENCES owners(id),\n    PRIMARY KEY (ownable, owner));",
        ),
    };
    format!(
        "
CREATE TABLE principals (id TEXT PRIMARY KEY);
{owners}
CREATE TABLE ownables (id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
CREATE TABLE memberships (
    owner_id TEXT NOT NULL REFERENCES owners(id),
    member_id TEXT NOT NULL REFERENCES principals(id),
    role TEXT NOT NULL,
    PRIMARY KEY (owner_id, member_id));
{link}
CREATE TABLE orders (id TEXT PRIMARY KEY REFERENCES ownables(id), title TEXT);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
{P19_POLICY}
"
    )
}

/// Rebuilds a catalog without schema-ingestion validation.
fn rebuilt_catalog(ddl: &str) -> ParserDB {
    let dialect = *parse_schema("CREATE TABLE dialect_source (id TEXT PRIMARY KEY);")
        .expect("a catalog ingests")
        .dialect();
    let statements =
        Parser::parse_sql(&PostgreSqlDialect {}, ddl).expect("the edge is grammatical");
    let mut tables: Vec<CreateTable> = Vec::new();
    let mut policy: Option<CreatePolicy> = None;
    for statement in statements {
        match statement {
            Statement::CreateTable(table) => tables.push(table),
            Statement::CreatePolicy(created) => policy = Some(created),
            _ => {}
        }
    }
    let policy = policy.expect("the catalog carries its policy");
    let mut builder = ParserDB::new("catalog".to_string(), dialect);
    for table in tables {
        let table = Arc::new(table);
        let mut metadata = TableMetadata::default();
        let columns: Vec<Arc<TableAttribute<CreateTable, ColumnDef>>> = table
            .columns
            .iter()
            .map(|column| Arc::new(TableAttribute::new(table.clone(), column.clone())))
            .collect();
        for column in &columns {
            metadata.add_column(column.clone());
        }
        metadata.set_primary_key(
            columns
                .into_iter()
                .filter(|column| is_primary_key_column(&table, column))
                .collect(),
        );
        for key in foreign_keys_of(&table) {
            metadata.add_foreign_key(Arc::new(TableAttribute::new(table.clone(), key)));
        }
        // RLS lives in the metadata beside the node, not on the grammar's `ALTER`.
        metadata.set_rls_enabled(table.table_name() == "orders");
        builder = builder
            .add_table(table, metadata)
            .expect("the table takes its name");
    }
    builder = builder.add_policy(
        Arc::new(policy),
        PolicyMetadata::new(ExpressionCalls::default(), ExpressionCalls::default()),
    );
    builder.into()
}

/// Whether the table's primary key names `column`, in either DDL spelling.
fn is_primary_key_column(
    table: &CreateTable,
    column: &TableAttribute<CreateTable, ColumnDef>,
) -> bool {
    column
        .attribute()
        .options
        .iter()
        .any(|option| matches!(option.option, ColumnOption::PrimaryKey(_)))
        || table
            .constraints
            .iter()
            .flat_map(|constraint| match constraint {
                TableConstraint::PrimaryKey(key) => key.columns.iter(),
                _ => [][..].iter(),
            })
            .any(|entry| {
                matches!(&entry.column.expr, Expr::Identifier(name)
                    if name.value == column.attribute().name.value)
            })
}

/// Every foreign key the table writes, in the column and table-constraint spellings.
fn foreign_keys_of(table: &CreateTable) -> Vec<ForeignKeyConstraint> {
    let mut keys = Vec::new();
    for column in &table.columns {
        for option in &column.options {
            if let ColumnOption::ForeignKey(key) = &option.option {
                let mut key = key.clone();
                key.columns = vec![column.name.clone()];
                key.name.clone_from(&option.name);
                keys.push(key);
            }
        }
    }
    for constraint in &table.constraints {
        if let TableConstraint::ForeignKey(key) = constraint {
            keys.push(key.clone());
        }
    }
    keys
}

/// The `fk_owner` edge the fixture puts on the link table.
fn the_named_key(db: &ParserDB) -> &<ParserDB as DatabaseLike>::ForeignKey {
    let link = db
        .table_by_stored_identity(None, "ownable_ancestors")
        .expect("the link table is stored");
    link.foreign_keys(db)
        .expect("the link table's metadata is held")
        .find(|key| key.foreign_key_name() == Some("fk_owner"))
        .expect("the fixture named the edge")
}

/// The policy's USING classification under the session attribute the pattern names.
fn classify_orders_read(db: &ParserDB) -> ClassifiedExpr {
    let translator = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build();
    let classified = translator.classify(db);
    assert_eq!(classified.len(), 1);
    classified[0]
        .using_classification()
        .expect("the policy carries a USING clause")
        .clone()
}

fn pair_names(pairs: &[MembershipJoinPair]) -> Vec<(&str, &str)> {
    pairs
        .iter()
        .map(|pair| (pair.join_column.as_str(), pair.outer_column.as_str()))
        .collect()
}

fn assert_indirect_payload(classified: &ClassifiedExpr) {
    let indirect = match &classified.pattern {
        PatternClass::P19IndirectMembership(indirect) => indirect,
        other => panic!("expected P19, got {other:?}"),
    };
    assert_eq!(indirect.link_table.name(), "ownable_ancestors");
    assert_eq!(pair_names(&indirect.pairs), [("ownable", "id")]);
    assert_eq!(indirect.owner_table.name(), "owners");
    assert_eq!(
        indirect
            .owner_columns
            .iter()
            .map(rls2fga::types::ColumnName::as_str)
            .collect::<Vec<_>>(),
        ["owner"]
    );
    assert_eq!(indirect.memberships.len(), 1);
    assert_eq!(indirect.memberships[0].join_table.name(), "memberships");
    assert_eq!(
        pair_names(&indirect.memberships[0].pairs),
        [("owner_id", "id")]
    );
    assert_eq!(indirect.memberships[0].user_column.as_str(), "member_id");
    assert_eq!(
        indirect.memberships[0].extra_predicates.sql(),
        Some("role = 'read'".to_string())
    );
    assert!(indirect.extra_predicates.is_empty());
}

/// The fail-closed answer each broken edge must earn, through both doors.
fn assert_indirect_membership_refused(db: &ParserDB) {
    let translator = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build();
    let classified = translator.classify(db);
    assert_eq!(classified.len(), 1);
    let pattern = classified[0]
        .using_classification()
        .expect("the policy carries a USING clause");
    assert!(
        !matches!(&pattern.pattern, PatternClass::P19IndirectMembership(_)),
        "P19 lit up over a broken edge, got {pattern:?}"
    );
    let translation = translator
        .translate(db)
        .expect("the translation should plan");
    assert!(
        translation.outputs().is_err(),
        "an invalid owner mapping must prevent authorization outputs, got {pattern:?}"
    );
}

#[test]
fn the_parsed_catalog_reaches_indirect_membership() {
    let ddl = edge_ddl(LinkEdge::Valid);
    let db = parse_schema(&ddl).expect("the valid catalog ingests");
    assert_indirect_payload(&classify_orders_read(&db));
}

/// The catalog rebuilt through the public builder reaches the same pattern.
#[test]
fn the_rebuilt_catalog_reaches_the_same_indirect_membership() {
    let ddl = edge_ddl(LinkEdge::Valid);
    assert_indirect_payload(&classify_orders_read(&rebuilt_catalog(&ddl)));
}

/// A key whose host list names no declared column keeps the policy fail-closed.
#[test]
fn a_host_list_naming_an_undeclared_column_fails_closed() {
    let edge = LinkEdge::DanglingHost;
    let ddl = edge_ddl(edge);
    assert!(
        parse_schema(&ddl).is_err(),
        "ingestion must refuse the edge"
    );
    let db = rebuilt_catalog(&ddl);
    assert!(
        matches!(
            the_named_key(&db).host_columns(&db),
            Err(LookupError::ColumnNotFound {
                table_name,
                column_name
            }) if table_name == "ownable_ancestors" && column_name == "owner_fk"
        ),
        "the fixture must carry the dangling host list"
    );
    assert_indirect_membership_refused(&db);
}

/// A key reaching a table the catalog does not hold keeps the policy fail-closed.
#[test]
fn a_key_reaching_an_absent_table_fails_closed() {
    let edge = LinkEdge::DanglingTarget;
    let ddl = edge_ddl(edge);
    assert!(
        parse_schema(&ddl).is_err(),
        "ingestion must refuse the edge"
    );
    let db = rebuilt_catalog(&ddl);
    assert!(
        matches!(
            the_named_key(&db).referenced_table(&db),
            Err(LookupError::TableNotFound { object_name }) if object_name == "ghosts"
        ),
        "the fixture must carry the absent target"
    );
    assert_indirect_membership_refused(&db);
}

/// A key naming a column the target does not hold keeps the policy fail-closed.
#[test]
fn a_key_naming_an_absent_target_column_fails_closed() {
    let edge = LinkEdge::DanglingTargetColumn;
    let ddl = edge_ddl(edge);
    assert!(
        parse_schema(&ddl).is_err(),
        "ingestion must refuse the edge"
    );
    let db = rebuilt_catalog(&ddl);
    assert!(
        matches!(
            the_named_key(&db).referenced_columns(&db),
            Err(LookupError::ColumnNotFound {
                table_name,
                column_name
            }) if table_name == "owners" && column_name == "owner_missing"
        ),
        "the fixture must carry the absent target column"
    );
    assert_indirect_membership_refused(&db);
}

/// A key shorter than the target's key cannot pair columns by position.
#[test]
fn a_key_narrower_than_the_target_key_fails_closed() {
    let edge = LinkEdge::WiderTargetKey;
    let ddl = edge_ddl(edge);
    assert!(
        parse_schema(&ddl).is_err(),
        "ingestion must refuse the edge"
    );
    let db = rebuilt_catalog(&ddl);
    let key = the_named_key(&db);
    let host = key
        .host_columns(&db)
        .expect("the host list is whole")
        .map(|column| column.stored_column_name().into_owned())
        .collect::<Vec<String>>();
    let referenced = key
        .referenced_columns(&db)
        .expect("the target list is whole")
        .map(|column| column.stored_column_name().into_owned())
        .collect::<Vec<String>>();
    assert_eq!(host.len(), 1, "the key names one host column");
    assert_eq!(referenced.len(), 2, "the target key holds two");
    assert_indirect_membership_refused(&db);
}

/// A referenced table without a primary key cannot supply an owner identity.
#[test]
fn a_target_without_a_primary_key_fails_closed() {
    let edge = LinkEdge::NoTargetKey;
    let ddl = edge_ddl(edge);
    assert!(parse_schema(&ddl).is_ok(), "the catalog is legal DDL");
    let db = rebuilt_catalog(&ddl);
    let target = db
        .table_by_stored_identity(None, "owners")
        .expect("the target table is stored");
    let key = target
        .primary_key_columns(&db)
        .expect("the target's metadata is held")
        .map(|column| column.stored_column_name().into_owned())
        .collect::<Vec<String>>();
    assert!(key.is_empty(), "the target must hold no primary key");
    assert_indirect_membership_refused(&db);
}
