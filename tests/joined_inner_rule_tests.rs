//! An inner rule that reads a relation the subquery joined.
//!
//! `WHERE c.id = <caller>` over `ON o.customer_id = c.id` asks exactly what
//! `WHERE o.customer_id = <caller>` asks, so the crate answers it as that. Every
//! condition making the two equal is required, and each one alone has a case here,
//! because a rewrite that holds only usually is a grant `PostgreSQL` refuses.

use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

mod support;

const CALLER: &str = "current_setting('app.user_id', true)";

/// `orders.customer_id` keys `customers`, and `line_items` is the guarded table.
fn schema(customer_fk: &str) -> String {
    format!(
        "CREATE TABLE orgs (id TEXT PRIMARY KEY);
         CREATE TABLE customers (id TEXT PRIMARY KEY, org_id TEXT REFERENCES orgs(id));
         CREATE TABLE orders (id TEXT PRIMARY KEY, customer_id TEXT {customer_fk});
         CREATE TABLE line_items (id TEXT PRIMARY KEY, order_id TEXT REFERENCES orders(id));
         ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;"
    )
}

const WITH_FK: &str = "REFERENCES customers(id)";

fn translate(customer_fk: &str, using: &str) -> (String, String) {
    translate_sql(&format!(
        "{}\nCREATE POLICY p ON line_items FOR SELECT USING ({using});",
        schema(customer_fk)
    ))
}

fn translate_qualified(customer_fk: &str, using: &str) -> (String, String) {
    let sql = format!(
        "{}\nCREATE POLICY p ON line_items FOR SELECT USING ({using});",
        schema(customer_fk)
    );
    translate_sql(&sql)
}

fn translate_sql(sql: &str) -> (String, String) {
    let db: ParserDB = parse_schema(sql).expect("the schema should parse");
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    (outputs.model(), format_tuples(outputs.tuple_queries()))
}

fn refused(model: &str) -> bool {
    model.contains("define can_select: no_access")
}

/// The three spellings of one question have to answer alike, or the translation depends
/// on how the policy was typed rather than on what it means.
#[test]
fn every_spelling_of_one_join_yields_one_model() {
    let (unjoined, unjoined_sql) = translate_qualified(
        WITH_FK,
        &format!("order_id IN (SELECT id FROM orders WHERE customer_id = {CALLER})"),
    );
    let (explicit, explicit_sql) = translate_qualified(
        WITH_FK,
        &format!(
            "order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id \
             WHERE c.id = {CALLER})"
        ),
    );
    let (comma, comma_sql) = translate_qualified(
        WITH_FK,
        &format!(
            "order_id IN (SELECT o.id FROM orders o, customers c \
             WHERE o.customer_id = c.id AND c.id = {CALLER})"
        ),
    );

    assert!(
        !refused(&unjoined),
        "the unjoined baseline has to translate, or this test proves nothing:\n{unjoined}"
    );
    assert_eq!(
        explicit, unjoined,
        "the join states an equality, so asking about the joined key is asking about the \
         parent's own column"
    );
    assert_eq!(comma, unjoined, "the comma spelling is the same join");
    assert_eq!(explicit_sql, unjoined_sql, "and the same tuples");
    assert_eq!(comma_sql, unjoined_sql);
    assert!(
        unjoined_sql.contains("\"customer_id\""),
        "the tuples come from the parent's own column:\n{unjoined_sql}"
    );
}

/// Without the key an order may name a customer that does not exist. The join drops that
/// row and the rewritten filter keeps it, so the rewrite would grant what the database
/// refuses.
#[test]
fn a_join_that_can_drop_a_row_is_not_rewritten() {
    let (model, _) = translate(
        "",
        &format!(
            "order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id \
             WHERE c.id = {CALLER})"
        ),
    );
    assert!(
        refused(&model),
        "no foreign key means the join filters, so the filter is not the parent's own:\n{model}"
    );
}

/// An outer join keeps the parent row and fills the joined side with nulls, and
/// `NULL = <caller>` grants nobody, so the rewritten comparison is a different question.
#[test]
fn an_outer_join_is_not_rewritten() {
    for spelling in [
        "LEFT JOIN",
        "LEFT OUTER JOIN",
        "RIGHT JOIN",
        "FULL OUTER JOIN",
    ] {
        let (model, _) = translate(
            WITH_FK,
            &format!(
                "order_id IN (SELECT o.id FROM orders o {spelling} customers c \
                 ON o.customer_id = c.id WHERE c.id = {CALLER})"
            ),
        );
        assert!(
            refused(&model),
            "{spelling} admits a row the rewrite would compare against nothing:\n{model}"
        );
    }
}

/// The rewrite substitutes one value for another, which holds only while the join lands
/// on the column the key targets. Here the key exists and points at `customers.id`,
/// while the join and the caller comparison both name `org_id`, so nothing guarantees a
/// match and the join can drop the row.
#[test]
fn a_join_landing_beside_the_key_is_not_rewritten() {
    let (model, _) = translate(
        WITH_FK,
        &format!(
            "order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.org_id \
             WHERE c.org_id = {CALLER})"
        ),
    );
    assert!(
        refused(&model),
        "orders.customer_id keys customers.id, not customers.org_id, so the join it \
         states is not the one the key guarantees:\n{model}"
    );
}

/// The same shape with no equality tying the joined column to the parent at all.
#[test]
fn a_join_on_a_column_the_parent_never_names_is_not_rewritten() {
    let (model, _) = translate(
        WITH_FK,
        &format!(
            "order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id \
             WHERE c.org_id = {CALLER})"
        ),
    );
    assert!(
        refused(&model),
        "the join ties customers.id to the parent, and says nothing about org_id:\n{model}"
    );
}

/// One hop, deliberately. Chasing a second needs a second soundness argument, and
/// refusing costs a narrower model rather than a wrong grant.
#[test]
fn a_second_hop_is_not_chased() {
    let (model, _) = translate(
        WITH_FK,
        &format!(
            "order_id IN (SELECT o.id FROM orders o \
             JOIN customers c ON o.customer_id = c.id \
             JOIN orgs g ON c.org_id = g.id \
             WHERE g.id = {CALLER})"
        ),
    );
    assert!(
        refused(&model),
        "the caller is compared against a relation two joins away from the parent:\n{model}"
    );
}

/// A join the rule never mentions still decides which rows the subquery returns.
///
/// `... JOIN customers c ON o.customer_id = c.id WHERE o.customer_id = <caller>` returns
/// the caller's orders that have a customer row. Translating only the `WHERE` grants the
/// ones that do not, so the join has to be answered even where nothing reads it.
#[test]
fn a_join_that_filters_is_answered_even_when_the_rule_ignores_it() {
    let using = format!(
        "order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id \
         WHERE o.customer_id = {CALLER})"
    );

    let (keyed, _) = translate(WITH_FK, &using);
    assert!(
        !refused(&keyed),
        "the key makes the join drop nothing, so this still translates:\n{keyed}"
    );

    let (unkeyed, _) = translate("", &using);
    assert!(
        refused(&unkeyed),
        "without the key an order may name a customer that is not there, which the join \
         drops and the model would grant:\n{unkeyed}"
    );
}

/// A refused rule is explained as the rule the join folds it into, so naming the joined
/// key or the parent's own column yields one reason.
#[test]
fn a_refused_rule_through_the_join_is_explained_as_the_parent_rule() {
    let on_parent = refusal_reason(&format!(
        "order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id \
         WHERE NOT (o.customer_id = {CALLER}))"
    ));
    let through_join = refusal_reason(&format!(
        "order_id IN (SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id \
         WHERE NOT (c.id = {CALLER}))"
    ));
    assert!(
        !on_parent.contains("another relation"),
        "the parent's own column reads no other relation: {on_parent}"
    );
    assert_eq!(through_join, on_parent);
}

fn refusal_reason(using: &str) -> String {
    let sql = format!(
        "{}\nCREATE POLICY p ON line_items FOR SELECT USING ({using});",
        schema(WITH_FK)
    );
    let db: ParserDB = parse_schema(&sql).expect("the schema should parse");
    let classified = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build()
        .classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected one policy");
    };
    match &policy.using_classification().expect("USING").pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}
