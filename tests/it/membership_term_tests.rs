//! Compiling one subscription filter, rather than a whole schema's policies.
//!
//! The assertions come from the request in `plans/membership-term-surface.md`, and the
//! refusals from the decisions recorded there.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::classifier::function_registry::{
    FunctionRegistry, SessionAttribute, SessionAttributeKind,
};
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::term::{describe_membership_term, TermCaller, TermChain, TermShapes};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RelationName;
use rls2fga::types::RelationShapes;
use rls2fga::types::{RecordDerivation, TranslationNote, ValueSource};
use sqlparser::ast::Expr;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// The request's own three-table shop, with no row-level security anywhere, which is
/// what a subscription engine's catalog holds.
const SHOP: &str = "
CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT REFERENCES customers(id), status TEXT);
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), sku TEXT);
";

const CALLER: &str = "current_setting('app.user_id', true)";

/// The set of subjects the caller holds, declared as one.
const SUBJECTS: &str = "ANY(string_to_array(current_setting('app.subjects', true), ','))";

/// The request's schema for the set spellings: a membership table keyed on both its
/// columns, and a filtered table naming an owner and a project.
const PROJECTS: &str = "
CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE project_members(project_id INTEGER REFERENCES projects(id), user_id TEXT, PRIMARY KEY(project_id, user_id));
CREATE TABLE docs(id INTEGER PRIMARY KEY, project_id INTEGER, title TEXT, owner TEXT);
";

fn parse_term(sql: &str) -> Expr {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(sql)
        .expect("the term should tokenize")
        .parse_expr()
        .expect("the term should parse")
}

fn registry() -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    registry.declare_session_attributes([
        SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
        SessionAttribute::setting("app.subjects", SessionAttributeKind::SetAttribute),
    ]);
    registry
}

fn compile_on(schema: &str, table: &str, term: &str, min: ConfidenceLevel) -> TermShapes {
    let db: ParserDB = parse_schema(schema).expect("the schema should parse");
    describe_membership_term(&parse_term(term), &db, &registry(), table, min)
        .unwrap_or_else(|refusal| panic!("the term should compile, refused: {}", refusal.reason))
}

fn refuse_on(schema: &str, table: &str, term: &str, min: ConfidenceLevel) -> String {
    refuse_with(schema, table, term, min, &registry())
}

fn refuse_with(
    schema: &str,
    table: &str,
    term: &str,
    min: ConfidenceLevel,
    registry: &FunctionRegistry,
) -> String {
    let db: ParserDB = parse_schema(schema).expect("the schema should parse");
    match describe_membership_term(&parse_term(term), &db, registry, table, min) {
        Ok(shapes) => panic!("the term should be refused, compiled to {:?}", shapes.chain),
        Err(refusal) => refusal.reason,
    }
}

fn compile(term: &str) -> TermShapes {
    compile_on(SHOP, "line_items", term, ConfidenceLevel::B)
}

fn refuse(term: &str) -> String {
    refuse_on(SHOP, "line_items", term, ConfidenceLevel::B)
}

/// The one shape a relation's records are read from, as `(table, subject column)`.
fn row_shape(entry: &RelationShapes) -> (String, String) {
    let shape = match entry.shapes.as_slice() {
        [only] => only,
        other => panic!("one shape fills {}, found {}", entry.relation, other.len()),
    };
    let RecordDerivation::FromRow {
        table, template, ..
    } = &shape.derivation
    else {
        panic!("{} is not filled from one row", entry.relation);
    };
    let ValueSource::Column(subject) = template.subject_key.part() else {
        panic!(
            "{} names its subject from something other than a column",
            entry.relation
        );
    };
    (table.to_string(), subject.clone().to_string())
}

fn entry<'a>(
    shapes: &'a TermShapes,
    type_name: &str,
    relation: &RelationName,
) -> &'a RelationShapes {
    shapes
        .relations
        .iter()
        .find(|entry| entry.type_name.as_str() == type_name && entry.relation == *relation)
        .unwrap_or_else(|| {
            panic!(
                "{type_name}#{relation} is missing, got {:?}",
                shapes
                    .relations
                    .iter()
                    .map(|entry| format!("{}#{}", entry.type_name, entry.relation))
                    .collect::<Vec<_>>()
            )
        })
}

/// Assertion 1: the two links, and the shapes behind each of them.
#[test]
fn a_membership_term_names_both_links() {
    let shapes = compile(&format!(
        "order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"
    ));

    assert_eq!(shapes.object_type, "line_items");
    let TermChain::Through {
        link,
        through_type,
        member,
    } = &shapes.chain
    else {
        panic!("a membership term reaches the caller through a second row: {shapes:?}");
    };
    assert_eq!(through_type, "orders");

    // The link out of the filtered row is keyed on the column the term compares.
    assert_eq!(
        row_shape(entry(&shapes, "line_items", link)),
        ("line_items".to_string(), "order_id".to_string())
    );
    // The second link names the caller from the related row.
    assert_eq!(
        row_shape(entry(&shapes, "orders", member)),
        ("orders".to_string(), "customer_id".to_string())
    );
    assert_eq!(
        shapes.relations.len(),
        2,
        "only the chain's own relations are returned, got {:?}",
        shapes
            .relations
            .iter()
            .map(|entry| format!("{}#{}", entry.type_name, entry.relation))
            .collect::<Vec<_>>()
    );
}

/// Assertion 2: the refusal carries the wording the classifier already produces.
#[test]
fn a_negated_membership_term_is_refused() {
    let reason = refuse(&format!(
        "order_id NOT IN (SELECT id FROM orders WHERE customer_id = {CALLER})"
    ));
    assert!(
        reason.contains("negation requires runtime filtering"),
        "the refusal keeps the classifier's own wording, got: {reason}"
    );
}

/// Assertion 3: a term naming no caller admits rows nobody can be checked against.
#[test]
fn a_term_naming_no_caller_is_refused() {
    let reason = refuse("order_id IN (SELECT id FROM orders WHERE customer_id = 'x')");
    assert!(
        !reason.is_empty(),
        "a refusal states why, since it reaches an operator"
    );
}

/// Assertion 4: a residual no chain of records can express refuses, whatever
/// confidence the caller asked for. The parent's rule became the membership
/// subject beside a row gate, which one chain cannot carry, so serving the
/// chain alone would admit every order of the caller whatever its status.
#[test]
fn a_residual_no_tuple_can_express_is_refused() {
    for min in [ConfidenceLevel::C, ConfidenceLevel::D] {
        let reason = refuse_on(
            SHOP,
            "line_items",
            &format!(
                "order_id IN (SELECT id FROM orders \
                 WHERE customer_id = {CALLER} AND status = 'open')"
            ),
            min,
        );
        assert!(
            reason.contains("no record can carry it"),
            "the refusal says the chain cannot carry the rule at {min:?}, got: {reason}"
        );
    }
}

/// Assertion 6: the flag and the recipe agree, as they do for a whole translation.
#[test]
fn a_decision_is_reported_exactly_when_one_row_decides() {
    let shapes = compile(&format!(
        "order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"
    ));
    for entry in &shapes.relations {
        assert_eq!(
            entry.decision.is_some(),
            entry.from_one_row,
            "{}#{} disagrees about whether one row decides it",
            entry.type_name,
            entry.relation
        );
    }
}

/// Assertion 7: two spellings of one membership compile to one answer.
#[test]
fn the_two_spellings_of_one_membership_agree() {
    let in_form = compile(&format!(
        "order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"
    ));
    let any_form = compile(&format!(
        "order_id = ANY (SELECT id FROM orders WHERE customer_id = {CALLER})"
    ));
    assert_eq!(in_form, any_form);
}

/// D2: a subscription filter is not a policy, so the filtered table needs no row-level
/// security switched on. Every other test here relies on this, and this one states it.
#[test]
fn a_term_over_a_table_without_row_level_security_is_served() {
    let shapes = compile(&format!(
        "order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"
    ));
    assert!(
        !shapes.relations.is_empty(),
        "a plain table still yields the term's relations"
    );
}

/// D3: run as SQL by a reader exempt from the related table's own rules, the filter
/// returns rows the compiled form would deny, so the term is refused instead.
#[test]
fn a_term_whose_related_table_has_its_own_read_rules_is_refused() {
    let reason = refuse_on(
        "CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT REFERENCES customers(id));
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id));
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
",
        "line_items",
        &format!("order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("orders"),
        "the refusal names the table whose own rules decide it, got: {reason}"
    );
}

/// D5: a filter satisfied by a column of the filtered row alone is one link.
#[test]
fn an_ownership_term_names_one_link() {
    let shapes = compile_on(
        "CREATE TABLE notes (id TEXT PRIMARY KEY, owner_id TEXT);",
        "notes",
        &format!("owner_id = {CALLER}"),
        ConfidenceLevel::B,
    );
    let TermChain::Direct { relation } = &shapes.chain else {
        panic!("ownership reaches the caller from the row itself: {shapes:?}");
    };
    assert_eq!(
        row_shape(entry(&shapes, "notes", relation)),
        ("notes".to_string(), "owner_id".to_string())
    );
}

/// D5: a filter that admits every row narrows nothing and would cost one stored record
/// per row of the filtered table.
#[test]
fn a_term_that_admits_every_row_is_refused() {
    let reason = refuse_on(
        "CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE staff (user_id TEXT);
",
        "docs",
        &format!("EXISTS (SELECT 1 FROM staff WHERE user_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    assert!(
        !reason.is_empty(),
        "a refusal states why, since it reaches an operator"
    );
}

/// F5: reading the filtered table inside its own filter is the shape `PostgreSQL` refuses
/// to plan, and the classifier already says so.
#[test]
fn a_term_reading_the_filtered_table_is_refused() {
    let reason = refuse_on(
        "CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, parent_id TEXT);",
        "docs",
        &format!("parent_id IN (SELECT id FROM docs WHERE owner_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("recursion"),
        "the refusal keeps the classifier's own wording, got: {reason}"
    );
}

/// F4: a row named by two key columns is named the same way on the link out of it.
#[test]
fn a_term_over_a_composite_key_names_every_key_column() {
    let shapes = compile_on(
        "CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT REFERENCES customers(id));
CREATE TABLE line_items (order_id INTEGER REFERENCES orders(id), line_no INTEGER, PRIMARY KEY (order_id, line_no));
",
        "line_items",
        &format!("order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    let TermChain::Through { link, .. } = &shapes.chain else {
        panic!("a membership term reaches the caller through a second row: {shapes:?}");
    };
    let shape = &entry(&shapes, "line_items", link).shapes[0];
    let RecordDerivation::FromRow { template, .. } = &shape.derivation else {
        panic!("the link is filled from one row");
    };
    let key: Vec<String> = template
        .object_key
        .parts()
        .iter()
        .map(|part| match part {
            ValueSource::Column(name) => name.to_string(),
            other => panic!("a key column is a column, got {other:?}"),
        })
        .collect();
    assert_eq!(key, vec!["order_id".to_string(), "line_no".to_string()]);
}

/// A filter two different chains satisfy is not one chain. Returning either alone admits
/// fewer rows than the filter's own SQL, which is the wrong-deny direction of the same
/// divergence the surface exists to remove.
#[test]
fn a_filter_with_two_chains_is_refused() {
    let reason = refuse_on(
        "CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT);
CREATE TABLE teams (id INTEGER PRIMARY KEY, lead TEXT);
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), team_id INTEGER REFERENCES teams(id));
",
        "line_items",
        &format!(
            "order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER}) \
             OR team_id IN (SELECT id FROM teams WHERE lead = {CALLER})"
        ),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("more than one"),
        "the refusal says the filter is satisfied more than one way, got: {reason}"
    );
}

/// The same, where one of the two is satisfied by the row itself. The single link reads
/// as a complete answer, which is what makes dropping the other arm silent.
#[test]
fn a_filter_answered_by_a_row_or_a_relationship_is_refused() {
    let reason = refuse_on(
        "CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT);
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), picker TEXT);
",
        "line_items",
        &format!(
            "picker = {CALLER} OR order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"
        ),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("more than one"),
        "the refusal says the filter is satisfied more than one way, got: {reason}"
    );
}

/// A related table carrying policies of its own makes the plan report a confidence
/// threshold, because this surface never classified those policies. The refusal has to
/// name the table whose rules actually decide it, or an operator reads the wrong cause.
#[test]
fn a_related_table_with_a_clean_policy_is_refused_by_name() {
    let reason = refuse_on(
        "CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT);
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id));
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY o ON orders FOR SELECT USING (customer_id = current_setting('app.user_id', true));
",
        "line_items",
        &format!("order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("'orders' carries its own read rules"),
        "the refusal names the table whose rules decide it, got: {reason}"
    );
}

/// The membership table carries its own read rules while the chain's related type is the
/// filtered type itself, so the rules that decide the filter belong to a table the
/// filtered type does not name.
#[test]
fn a_membership_table_with_its_own_read_rules_is_refused_by_name() {
    let reason = refuse_on(
        "CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE doc_members (doc_id TEXT REFERENCES docs(id), user_id TEXT);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY m ON doc_members FOR SELECT USING (user_id = current_setting('app.user_id', true));
",
        "docs",
        &format!("id IN (SELECT doc_id FROM doc_members WHERE user_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("'doc_members' carries its own read rules"),
        "the refusal names the membership table rather than the filtered one, got: {reason}"
    );
}

/// The canonical membership: the filtered row names a parent, and a third table lists
/// who belongs to it. This is the shape the request was written for.
#[test]
fn a_membership_through_a_third_table_names_both_links() {
    let shapes = compile_on(
        "CREATE TABLE projects (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));
CREATE TABLE project_members (project_id TEXT REFERENCES projects(id), user_id TEXT);
",
        "docs",
        &format!("project_id IN (SELECT project_id FROM project_members WHERE user_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    let TermChain::Through {
        link,
        through_type,
        member,
    } = &shapes.chain
    else {
        panic!("the filtered row reaches the caller through its project: {shapes:?}");
    };
    assert_eq!(through_type, "projects");
    assert_eq!(
        row_shape(entry(&shapes, "docs", link)),
        ("docs".to_string(), "project_id".to_string())
    );
    assert_eq!(
        row_shape(entry(&shapes, "projects", member)),
        ("project_members".to_string(), "user_id".to_string())
    );
}

/// A value the row carries in a JSON field is still a value the row carries, so the
/// filter compiles. Only a value the row does not carry at all cannot be a link.
#[test]
fn a_filter_reading_a_json_field_names_one_link() {
    let shapes = compile_on(
        "CREATE TABLE docs (id TEXT PRIMARY KEY, meta JSONB);",
        "docs",
        &format!("meta ->> 'owner' = {CALLER}"),
        ConfidenceLevel::B,
    );
    let TermChain::Direct { relation } = &shapes.chain else {
        panic!("the row itself names the caller: {shapes:?}");
    };
    let shape = &entry(&shapes, "docs", relation).shapes[0];
    let RecordDerivation::FromRow { template, .. } = &shape.derivation else {
        panic!("the link is filled from one row");
    };
    assert!(
        matches!(
            template.subject_key.part(),
            ValueSource::JsonPath { column, path } if column == "meta" && path == &["owner".to_string()]
        ),
        "the subject is read from the JSON field the filter names, got {:?}",
        template.subject_key.part()
    );
}

/// The caller's threshold no longer decides this shape: the row gate translates
/// at `B`, so the same chain refusal answers at every threshold rather than a
/// grade-dependent one.
#[test]
fn the_callers_threshold_still_refuses() {
    let reason = refuse_on(
        SHOP,
        "line_items",
        &format!(
            "order_id IN (SELECT id FROM orders \
             WHERE customer_id = {CALLER} AND status = 'open')"
        ),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("no record can carry it"),
        "the refusal is the chain's at B too, got: {reason}"
    );
}

/// The type a filter reports and the type a consumer names the row with come from one
/// place, so a schema where the name is not the table's own still agrees.
#[test]
fn the_filter_and_the_row_naming_agree_on_the_type() {
    let sql = "CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE a.notes (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE b.notes (id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE a.notes ENABLE ROW LEVEL SECURITY;
";
    let db: ParserDB = parse_schema(sql).expect("the schema should parse");
    let registry = registry();
    let compiled = describe_membership_term(
        &parse_term(&format!("owner_id = {CALLER}")),
        &db,
        &registry,
        "b.notes",
        ConfidenceLevel::B,
    )
    .expect("the filter compiles");

    let planned = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build()
        .translate(&db)
        .expect("translation should plan");
    let named = planned.row_naming();
    let entry = named
        .iter()
        .find(|entry| entry.table.to_string() == "a.notes")
        .expect("the guarded table is named");
    assert_ne!(
        compiled.object_type, entry.type_name,
        "two tables canonicalising alike must not share a type"
    );
    assert_eq!(
        compiled.object_type, "notes_4ad706ae",
        "the filter reports the suffixed type the model assigned b.notes"
    );
}

/// A filter that also narrows on the row's own value is not answered by the chain alone.
/// Serving the chain admits every row the relationship reaches, whatever the other half
/// says, which is the wrong-allow direction.
#[test]
fn a_filter_that_narrows_further_is_refused() {
    let db: ParserDB = parse_schema(
        "CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT);
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), tenant TEXT);
",
    )
    .expect("the schema should parse");
    let mut registry = registry();
    registry.declare_session_attributes([SessionAttribute::setting(
        "app.tenant_id",
        SessionAttributeKind::ScalarAttribute,
    )]);

    let term = parse_term(&format!(
        "tenant = current_setting('app.tenant_id', true) \
         AND order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"
    ));
    let refusal = describe_membership_term(&term, &db, &registry, "line_items", ConfidenceLevel::B)
        .expect_err("half the filter cannot be dropped");
    assert!(
        refusal.reason.contains("narrows"),
        "the refusal says the filter asks for more than the chain, got: {}",
        refusal.reason
    );
}

/// Assertion 5 of the filter request: a correlation the bridge cannot honour is refused
/// rather than compiled against a column the filter never mentioned.
#[test]
fn a_correlation_the_bridge_cannot_honour_is_refused() {
    let reason = refuse_on(
        "CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(doc_id TEXT, user_id TEXT);
",
        "docs",
        &format!(
            "EXISTS (SELECT 1 FROM doc_members m \
             WHERE m.doc_id = nonexistent AND m.user_id = {CALLER})"
        ),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("has no column 'nonexistent'"),
        "the refusal names the column the filter correlates, got: {reason}"
    );
}

/// The correlation that can be honoured is keyed on the column the filter compares, even
/// where the filtered table carries a column named like the subquery's projection.
#[test]
fn a_correlation_the_bridge_honours_reads_the_compared_column() {
    let shapes = compile_on(
        "CREATE TABLE customers(id TEXT PRIMARY KEY);
CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id TEXT, status TEXT);
CREATE TABLE line_items(id INTEGER PRIMARY KEY, sku TEXT, status TEXT);
",
        "line_items",
        &format!("sku IN (SELECT status FROM orders WHERE customer_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    let TermChain::Through { link, .. } = &shapes.chain else {
        panic!("the filter reaches the caller through the order's status: {shapes:?}");
    };
    assert_eq!(
        row_shape(entry(&shapes, "line_items", link)),
        ("line_items".to_string(), "sku".to_string()),
        "the link reads the column the filter compares, not the one it is named after"
    );
}

/// A declared caller set names the caller on this surface: the consumer holds the
/// subjects and matches a record's subject against them, so the records answering the
/// set spelling are the records answering the identity spelling. Only the caller side
/// the shapes report differs, so the consumer knows which comparison the SQL runs.
#[test]
fn a_declared_set_names_the_caller_on_an_ownership_term() {
    let identity = compile_on(
        PROJECTS,
        "docs",
        &format!("owner = {CALLER}"),
        ConfidenceLevel::B,
    );
    let set = compile_on(
        PROJECTS,
        "docs",
        &format!("owner = {SUBJECTS}"),
        ConfidenceLevel::B,
    );

    assert_eq!(
        set.chain,
        TermChain::Direct {
            relation: RelationName::canonicalized("owner")
        }
    );
    assert_eq!(set.chain, identity.chain);
    assert_eq!(set.relations, identity.relations);
    assert_eq!(identity.caller, TermCaller::Identity);
    let TermCaller::Subjects { source, separator } = &set.caller else {
        panic!(
            "the set spelling names the caller by its subjects, got {:?}",
            set.caller
        );
    };
    assert_eq!(source.setting_key(), "app.subjects");
    assert_eq!(separator.as_deref(), Some(","));

    // The row valued spelling of the same set is the same set.
    let unnested = compile_on(
        PROJECTS,
        "docs",
        "owner IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ',')))",
        ConfidenceLevel::B,
    );
    assert_eq!(unnested, set);
}

#[test]
fn direct_read_terms_are_independent_of_catalog_write_coverage() {
    for term in [format!("owner = {CALLER}"), format!("owner = {SUBJECTS}")] {
        let expected = compile_on(PROJECTS, "docs", &term, ConfidenceLevel::B);
        for policy in [
            "FOR SELECT USING (TRUE)".to_string(),
            "FOR ALL USING (TRUE)".to_string(),
            format!("FOR ALL USING (owner = {CALLER} OR owner = {SUBJECTS})"),
            "FOR INSERT WITH CHECK (FALSE)".to_string(),
            "FOR UPDATE USING (FALSE) WITH CHECK (FALSE)".to_string(),
            "FOR DELETE USING (FALSE)".to_string(),
            "FOR SELECT".to_string(),
            "FOR ALL".to_string(),
            "FOR INSERT".to_string(),
            "FOR UPDATE".to_string(),
            "FOR DELETE".to_string(),
        ] {
            let schema = format!(
                "{PROJECTS}
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs {policy};"
            );
            let actual = compile_on(&schema, "docs", &term, ConfidenceLevel::B);
            assert_eq!(actual, expected, "{policy}, {term}");
        }
    }
}

#[test]
fn read_terms_ignore_guarded_table_read_policy_recursion() {
    for term in [format!("owner = {CALLER}"), format!("owner = {SUBJECTS}")] {
        let expected = compile_on(PROJECTS, "docs", &term, ConfidenceLevel::B);
        for command in ["SELECT", "ALL"] {
            let schema = format!(
                "{PROJECTS}
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR {command} USING (
    EXISTS (SELECT 1 FROM docs d WHERE d.id = docs.id)
);"
            );
            let actual = compile_on(&schema, "docs", &term, ConfidenceLevel::B);
            assert_eq!(actual, expected, "{command}, {term}");
        }
    }
}

#[test]
fn read_terms_ignore_unrelated_catalog_policy_coverage() {
    let term = format!("owner = {SUBJECTS}");
    let expected = compile_on(PROJECTS, "docs", &term, ConfidenceLevel::B);
    for command in ["SELECT", "ALL"] {
        let schema = format!(
            "{PROJECTS}
ALTER TABLE project_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_p ON project_members FOR {command} USING (TRUE);"
        );
        let actual = compile_on(&schema, "docs", &term, ConfidenceLevel::B);
        assert_eq!(actual, expected, "{command}");
    }
}

#[test]
fn read_terms_report_only_relevant_type_name_collisions() {
    let schema = format!(
        "{PROJECTS}
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE a.members(id TEXT PRIMARY KEY, owner TEXT);
CREATE TABLE b.members(id TEXT PRIMARY KEY, owner TEXT);
ALTER TABLE a.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE b.members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_a ON a.members FOR ALL USING (TRUE);
CREATE POLICY members_b ON b.members FOR ALL USING (TRUE);"
    );
    let term = format!("owner = {CALLER}");
    let expected = compile_on(PROJECTS, "docs", &term, ConfidenceLevel::B);
    let unrelated = compile_on(&schema, "docs", &term, ConfidenceLevel::B);
    assert_eq!(unrelated, expected);

    let related = compile_on(&schema, "b.members", &term, ConfidenceLevel::B);
    let db: ParserDB = parse_schema(&schema).expect("the schema should parse");
    let planned = TranslatorBuilder::new()
        .with_registry(registry())
        .build()
        .translate(&db)
        .expect("the policies should plan");
    let named = planned.row_naming();
    let table = named
        .iter()
        .find(|entry| entry.table.to_string() == "b.members")
        .expect("the policy plan names the guarded table");
    assert_eq!(related.object_type, table.type_name);
    assert!(related.notes.iter().any(|note| {
        matches!(note, TranslationNote::TypeNameCollision { spelling, .. }
            if spelling.to_string() == "b.members")
    }));
}

#[test]
fn read_terms_ignore_unused_catalog_enforcement_metadata() {
    let schema = format!(
        "{PROJECTS}
CREATE ROLE reporting BYPASSRLS;
CREATE FUNCTION current_user_id() RETURNS TEXT LANGUAGE sql SECURITY DEFINER
    AS 'SELECT current_user';"
    );
    let db: ParserDB = parse_schema(&schema).expect("the schema should parse");
    let mut enriched = registry();
    enriched.enrich_from_schema(&db);
    let term = format!("owner = {CALLER}");
    let expected = compile_on(PROJECTS, "docs", &term, ConfidenceLevel::B);
    let actual = describe_membership_term(
        &parse_term(&term),
        &db,
        &enriched,
        "docs",
        ConfidenceLevel::B,
    )
    .expect("unused enforcement metadata does not affect the filter");
    assert_eq!(actual, expected);
    describe_membership_term(
        &parse_term("owner = current_user_id()"),
        &db,
        &enriched,
        "docs",
        ConfidenceLevel::B,
    )
    .expect_err("an owner-bound accessor cannot identify the caller");
}

#[test]
fn read_terms_ignore_catalog_write_policy_recursion() {
    let term = format!("owner = {CALLER}");
    let expected = compile_on(PROJECTS, "docs", &term, ConfidenceLevel::B);
    let recursive_members = format!(
        "{PROJECTS}
ALTER TABLE project_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_p ON project_members FOR SELECT USING (
    EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id = project_members.project_id)
);"
    );
    for policy in [
        "FOR INSERT WITH CHECK",
        "FOR UPDATE USING",
        "FOR DELETE USING",
    ] {
        let schema = format!(
            "{recursive_members}
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs {policy} (
    EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id = docs.project_id)
);"
        );
        let actual = compile_on(&schema, "docs", &term, ConfidenceLevel::B);
        assert_eq!(actual, expected, "{policy}");
    }
    let db: ParserDB = parse_schema(&recursive_members).expect("the schema should parse");
    let membership = parse_term(&format!(
        "project_id IN (SELECT project_id FROM project_members WHERE user_id = {CALLER})"
    ));
    describe_membership_term(&membership, &db, &registry(), "docs", ConfidenceLevel::B)
        .expect_err("a read term cannot ignore row security on its membership table");
}

#[test]
fn membership_read_terms_ignore_guarded_table_writes_but_require_readable_members() {
    let schema = format!(
        "{PROJECTS}
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR ALL USING (TRUE);"
    );
    for caller in [CALLER, SUBJECTS] {
        let term = format!(
            "project_id IN (SELECT project_id FROM project_members WHERE user_id = {caller})"
        );
        let expected = compile_on(PROJECTS, "docs", &term, ConfidenceLevel::B);
        let actual = compile_on(&schema, "docs", &term, ConfidenceLevel::B);
        assert_eq!(actual, expected, "{term}");

        let guarded_members = format!(
            "{schema}
ALTER TABLE project_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_p ON project_members FOR ALL USING (TRUE);"
        );
        let db: ParserDB = parse_schema(&guarded_members).expect("the schema should parse");
        describe_membership_term(
            &parse_term(&term),
            &db,
            &registry(),
            "docs",
            ConfidenceLevel::B,
        )
        .expect_err("membership-table read rules cannot be ignored");
    }
}

#[test]
fn catalog_write_coverage_does_not_license_read_terms_below_the_threshold() {
    let term = parse_term(&format!("owner = {CALLER} AND title = 'published'"));
    for policy in [
        "FOR SELECT USING (TRUE)",
        "FOR ALL USING (TRUE)",
        "FOR INSERT WITH CHECK (TRUE)",
    ] {
        let schema = format!(
            "{PROJECTS}
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs {policy};"
        );
        let db: ParserDB = parse_schema(&schema).expect("the schema should parse");
        let refusal = describe_membership_term(&term, &db, &registry(), "docs", ConfidenceLevel::A)
            .expect_err("the read term must satisfy its own confidence threshold");
        assert_eq!(refusal.classified.confidence, ConfidenceLevel::B);
    }
}

/// The same through a membership table: a membership row whose member the caller's set
/// holds names one of the caller's subjects, in both spellings of the subquery.
#[test]
fn a_declared_set_names_the_caller_on_a_membership_term() {
    let identity = compile_on(
        PROJECTS,
        "docs",
        &format!("project_id IN (SELECT project_id FROM project_members WHERE user_id = {CALLER})"),
        ConfidenceLevel::B,
    );
    let TermChain::Through {
        link,
        through_type,
        member,
    } = &identity.chain
    else {
        panic!("the identity membership reaches the caller through its project: {identity:?}");
    };
    assert_eq!(through_type, "projects");

    for spelling in [
        format!(
            "project_id IN (SELECT project_id FROM project_members WHERE user_id = {SUBJECTS})"
        ),
        format!(
            "EXISTS (SELECT 1 FROM project_members pm \
             WHERE pm.project_id = docs.project_id AND pm.user_id = {SUBJECTS})"
        ),
    ] {
        let set = compile_on(PROJECTS, "docs", &spelling, ConfidenceLevel::B);
        assert_eq!(set.chain, identity.chain, "{spelling}");
        assert_eq!(set.relations, identity.relations, "{spelling}");
        assert_eq!(
            row_shape(entry(&set, "docs", link)),
            ("docs".to_string(), "project_id".to_string())
        );
        assert_eq!(
            row_shape(entry(&set, "projects", member)),
            ("project_members".to_string(), "user_id".to_string())
        );
        assert!(
            matches!(&set.caller, TermCaller::Subjects { source, .. }
                if source.setting_key() == "app.subjects"),
            "{spelling} names the caller by its subjects, got {:?}",
            set.caller
        );
    }
}

/// A set membership joined on every column of a composite key is the same membership
/// the identity spelling states, so both links compile as they do for one column.
#[test]
fn a_declared_set_membership_on_a_composite_key_names_both_links() {
    const TENANTED: &str = "
CREATE TABLE tenants(id INT PRIMARY KEY);
CREATE TABLE papers(tenant_id INT NOT NULL REFERENCES tenants(id), id INT NOT NULL, PRIMARY KEY(tenant_id, id));
CREATE TABLE shares(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
    PRIMARY KEY(tenant_id, paper_id, viewer),
    FOREIGN KEY (tenant_id, paper_id) REFERENCES papers(tenant_id, id));
";
    let membership = |caller: &str| {
        format!(
            "EXISTS (SELECT 1 FROM shares s WHERE s.tenant_id = papers.tenant_id \
             AND s.paper_id = papers.id AND s.viewer = {caller})"
        )
    };
    let identity = compile_on(TENANTED, "papers", &membership(CALLER), ConfidenceLevel::B);
    let set = compile_on(
        TENANTED,
        "papers",
        &membership(SUBJECTS),
        ConfidenceLevel::B,
    );
    assert_eq!(set.chain, identity.chain);
    assert_eq!(set.relations, identity.relations);
    assert!(matches!(set.caller, TermCaller::Subjects { .. }));
}

/// A filter comparing the caller's identity in one arm and its subjects in the other
/// names the caller two ways, and a consumer matches one chain of records one way. Both
/// arms mint the same relation, so the rule shape alone would not tell them apart.
#[test]
fn a_filter_comparing_the_caller_two_ways_is_refused() {
    let reason = refuse_on(
        PROJECTS,
        "docs",
        &format!("owner = {CALLER} OR owner = {SUBJECTS}"),
        ConfidenceLevel::B,
    );
    assert!(
        reason.contains("its identity") && reason.contains("current_setting('app.subjects')"),
        "the refusal names both comparisons, got: {reason}"
    );
}

/// Only a declared set names the caller. A declared single value is still the request's
/// half of a gate, so a tenant filter compiles to no chain of records here either.
#[test]
fn a_declared_single_value_still_compiles_to_no_chain() {
    let mut registry = registry();
    registry.declare_session_attributes([SessionAttribute::setting(
        "app.tenant_id",
        SessionAttributeKind::ScalarAttribute,
    )]);
    let reason = refuse_with(
        "CREATE TABLE docs(id INTEGER PRIMARY KEY, tenant_id TEXT);",
        "docs",
        "tenant_id = current_setting('app.tenant_id', true)",
        ConfidenceLevel::B,
        &registry,
    );
    assert!(
        reason.contains("nothing about a row of 'docs' decides this filter"),
        "one value is not the caller, got: {reason}"
    );
}

/// A set read that nothing declares is refused naming the declaration it lacks, since
/// the missing piece is the declaration and not a function body.
#[test]
fn an_undeclared_set_is_refused_naming_the_declaration() {
    let mut undeclared = FunctionRegistry::new();
    undeclared.trust_current_user_setting_keys(["app.user_id"]);
    for spelling in [
        format!("owner = {SUBJECTS}"),
        format!(
            "project_id IN (SELECT project_id FROM project_members WHERE user_id = {SUBJECTS})"
        ),
    ] {
        let reason = refuse_with(PROJECTS, "docs", &spelling, ConfidenceLevel::B, &undeclared);
        assert!(
            reason.contains("current_setting('app.subjects')")
                && reason.contains("read as a set")
                && reason.contains("SetAttribute"),
            "{spelling}: the refusal names the missing declaration, got: {reason}"
        );
        assert!(
            !reason.contains("string_to_array"),
            "{spelling}: the splitter is not what is missing, got: {reason}"
        );
    }
}
