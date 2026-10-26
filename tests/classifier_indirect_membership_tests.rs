//! Scope and key boundaries for indirect membership.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{ClassifiedExpr, IndirectMembership, PatternClass};
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;

const SCHEMA: &str = "
CREATE TABLE principals (id TEXT PRIMARY KEY);
CREATE TABLE owners (id TEXT PRIMARY KEY);
CREATE TABLE ownables (id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
CREATE TABLE memberships (
    owner_id TEXT NOT NULL REFERENCES owners(id),
    member_id TEXT NOT NULL REFERENCES principals(id),
    role TEXT NOT NULL,
    PRIMARY KEY (owner_id, member_id));
CREATE TABLE ownable_ancestors (
    ownable TEXT NOT NULL REFERENCES ownables(id),
    owner TEXT NOT NULL REFERENCES owners(id),
    PRIMARY KEY (ownable, owner));
CREATE TABLE orders (id TEXT PRIMARY KEY REFERENCES ownables(id), title TEXT);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
";

const NESTED_ROLE: &str = "EXISTS (
    SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
    AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
        AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))";

fn classify(predicate: &str) -> ClassifiedExpr {
    classify_in(SCHEMA, predicate)
}

fn classify_in(schema: &str, predicate: &str) -> ClassifiedExpr {
    let sql =
        format!("{schema}CREATE POLICY orders_read ON orders FOR SELECT USING ({predicate});");
    let db = parse_schema(&sql).unwrap();
    let translator = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build();
    let classified = translator.classify(&db);
    assert_eq!(classified.len(), 1);
    classified[0]
        .using_classification()
        .expect("the policy carries a USING clause")
        .clone()
}

fn p19(c: &ClassifiedExpr) -> &IndirectMembership {
    match &c.pattern {
        PatternClass::P19IndirectMembership(payload) => payload,
        other => panic!("expected P19, got {other:?}"),
    }
}

#[test]
fn refusals_do_not_match_p19() {
    let not_p19 = |predicate: &str, why: &str| {
        let c = classify(predicate);
        assert!(
            !matches!(&c.pattern, PatternClass::P19IndirectMembership(_)),
            "P19 matched {why}, got {c:?}"
        );
    };

    not_p19(
        "EXISTS (SELECT 1 FROM ownable_ancestors a
            LEFT JOIN memberships m ON m.owner_id = a.owner
            WHERE a.ownable = orders.id
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')",
        "a LEFT JOIN is not a membership hop",
    );

    not_p19(
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND EXISTS (SELECT 1 FROM memberships m
                WHERE m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
        "the far hop is uncorrelated to the link",
    );

    not_p19(
        "EXISTS (SELECT 1 FROM ownable_ancestors a
            JOIN memberships m ON m.owner_id = a.owner
            WHERE (a.ownable = orders.id OR m.role = 'read')
            AND m.member_id = current_setting('app.user_id', true))",
        "an OR crosses the two hops",
    );

    not_p19(
        "EXISTS (SELECT 1 FROM ownable_ancestors a
            JOIN memberships m ON m.owner_id = a.owner
            JOIN ownables o ON o.id = a.ownable
            WHERE a.ownable = orders.id
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')",
        "a third source is beside the two hops",
    );
}

#[test]
fn native_caller_membership_uses_the_same_two_hop_shape() {
    let c = classify(&NESTED_ROLE.replace("current_setting('app.user_id', true)", "current_user"));
    assert_eq!(p19(&c).memberships[0].user_column.as_str(), "member_id");
}

#[test]
fn composite_owner_equalities_preserve_foreign_key_positions() {
    let schema = "
        CREATE TABLE owners (tenant TEXT, id TEXT, PRIMARY KEY (tenant, id));
        CREATE TABLE orders (id TEXT PRIMARY KEY);
        CREATE TABLE ancestors (doc TEXT REFERENCES orders(id), owner_tenant TEXT, owner_id TEXT,
            FOREIGN KEY (owner_tenant, owner_id) REFERENCES owners (tenant, id));
        CREATE TABLE members (tenant TEXT, owner TEXT, member_id TEXT,
            FOREIGN KEY (tenant, owner) REFERENCES owners (tenant, id));
        ALTER TABLE orders ENABLE ROW LEVEL SECURITY;";
    let correct = "EXISTS (SELECT 1 FROM ancestors a WHERE a.doc = orders.id
        AND EXISTS (SELECT 1 FROM members m
            WHERE m.tenant = a.owner_tenant AND m.owner = a.owner_id
            AND m.member_id = current_setting('app.user_id', true)))";
    let c = classify_in(schema, correct);
    assert_eq!(
        p19(&c)
            .owner_columns
            .iter()
            .map(rls2fga::types::ColumnName::as_str)
            .collect::<Vec<_>>(),
        ["owner_tenant", "owner_id"]
    );
    let crossed = correct.replace(
        "m.tenant = a.owner_tenant AND m.owner = a.owner_id",
        "m.tenant = a.owner_id AND m.owner = a.owner_tenant",
    );
    assert!(!matches!(
        classify_in(schema, &crossed).pattern,
        PatternClass::P19IndirectMembership(_)
    ));
}

#[test]
fn indirect_membership_requires_unmodified_table_sources() {
    let accepted: Vec<_> = [
        ("ownable_ancestors a", "ownable_ancestors() a"),
        ("memberships m", "memberships() m"),
        ("ownable_ancestors a", "ownable_ancestors a(owner, ownable)"),
        ("memberships m", "memberships m(owner_id, role, member_id)"),
    ]
    .into_iter()
    .filter(|&(source, replacement)| {
        matches!(
            classify(&NESTED_ROLE.replace(source, replacement)).pattern,
            PatternClass::P19IndirectMembership(_)
        )
    })
    .collect();
    assert!(
        accepted.is_empty(),
        "modified sources classified as physical tables {accepted:?}"
    );
}
