//! Scope and key boundaries for indirect membership.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{
    ClassifiedExpr, IndirectMembership, MembershipJoinPair, PatternClass,
};
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
    classify_in_on("orders", schema, predicate)
}

fn classify_in_on(table: &str, schema: &str, predicate: &str) -> ClassifiedExpr {
    classify_in_attrs(
        table,
        schema,
        predicate,
        [SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )],
    )
}

fn classify_in_attrs(
    table: &str,
    schema: &str,
    predicate: &str,
    attributes: impl IntoIterator<Item = SessionAttribute>,
) -> ClassifiedExpr {
    let sql =
        format!("{schema}CREATE POLICY {table}_read ON {table} FOR SELECT USING ({predicate});");
    let db = parse_schema(&sql).unwrap();
    let translator = TranslatorBuilder::new()
        .with_session_attributes(attributes)
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

fn pair_names(pairs: &[MembershipJoinPair]) -> Vec<(&str, &str)> {
    pairs
        .iter()
        .map(|pair| (pair.join_column.as_str(), pair.outer_column.as_str()))
        .collect()
}

fn assert_standard_payload(c: &ClassifiedExpr, why: &str) {
    let p19 = p19(c);
    assert_eq!(p19.link_table.name(), "ownable_ancestors", "{why}");
    assert_eq!(pair_names(&p19.pairs), [("ownable", "id")], "{why}");
    assert_eq!(p19.owner_table.name(), "owners", "{why}");
    assert_eq!(
        p19.owner_columns
            .iter()
            .map(rls2fga::types::ColumnName::as_str)
            .collect::<Vec<_>>(),
        ["owner"],
        "{why}"
    );
    assert_eq!(p19.memberships.len(), 1, "{why}");
    assert_eq!(p19.memberships[0].join_table.name(), "memberships", "{why}");
    assert_eq!(
        pair_names(&p19.memberships[0].pairs),
        [("owner_id", "id")],
        "{why}"
    );
    assert_eq!(
        p19.memberships[0].user_column.as_str(),
        "member_id",
        "{why}"
    );
    assert_eq!(
        p19.memberships[0].extra_predicates.sql(),
        Some("role = 'read'".to_string()),
        "{why}"
    );
    assert!(p19.extra_predicates.is_empty(), "{why}");
}

fn not_p19(schema: &str, predicate: &str, why: &str) {
    let c = classify_in(schema, predicate);
    assert!(
        !matches!(&c.pattern, PatternClass::P19IndirectMembership(_)),
        "P19 matched {why}, got {c:?}"
    );
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

#[test]
fn joined_spelling_carries_the_same_payload() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = a.owner
        WHERE a.ownable = orders.id
        AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')",
    );
    assert_standard_payload(&c, "the joined spelling");
}

#[test]
fn unqualified_columns_resolve_against_their_side() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = owner
        WHERE ownable = id
        AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')",
    );
    assert_standard_payload(&c, "the unqualified spelling");
}

#[test]
fn reversed_link_equality_pairs_the_same_way() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a WHERE orders.id = a.ownable
        AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    assert_standard_payload(&c, "the reversed link equality");
}

#[test]
fn repeated_link_equality_is_one_condition() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id AND a.ownable = orders.id
        AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    assert_standard_payload(&c, "the repeated link equality");
}

#[test]
fn link_equality_in_on_and_where_is_one_condition() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a JOIN memberships m
            ON m.owner_id = a.owner AND a.ownable = orders.id
        WHERE a.ownable = orders.id
        AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')",
    );
    assert_standard_payload(&c, "the link equality in ON and WHERE");
}

#[test]
fn link_internal_equality_filters_the_closure_row() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id AND a.ownable = a.owner
        AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    let p19 = p19(&c);
    assert_eq!(pair_names(&p19.pairs), [("ownable", "id")]);
    assert_eq!(
        p19.extra_predicates.sql(),
        Some("ownable = owner".to_string())
    );
}

#[test]
fn far_internal_equality_filters_the_membership_row() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
        AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
            AND m.owner_id = m.member_id
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    let p19 = p19(&c);
    assert_eq!(pair_names(&p19.pairs), [("ownable", "id")]);
    assert_eq!(
        p19.memberships[0].extra_predicates.sql(),
        Some("owner_id = member_id AND role = 'read'".to_string())
    );
}

#[test]
fn listed_roles_expand_into_one_membership_each() {
    let c = classify(
        "EXISTS (
        SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
        AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
            AND m.member_id = current_setting('app.user_id', true) AND role IN ('read', 'write')))",
    );
    let p19 = p19(&c);
    assert_eq!(p19.memberships.len(), 2);
    for (membership, role) in p19.memberships.iter().zip(["read", "write"]) {
        assert_eq!(membership.user_column.as_str(), "member_id");
        assert_eq!(pair_names(&membership.pairs), [("owner_id", "id")]);
        assert_eq!(
            membership.extra_predicates.sql(),
            Some(format!("role = '{role}'"))
        );
    }
}

#[test]
fn in_subquery_spelling_matches_the_exists_spelling() {
    let c = classify(
        "orders.id IN (
        SELECT a.ownable FROM ownable_ancestors a WHERE a.owner IN (
            SELECT m.owner_id FROM memberships m
            WHERE m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    assert_standard_payload(&c, "the IN spelling");
}

#[test]
fn foreign_key_link_pairs_in_the_guarded_key_order() {
    let schema = "
        CREATE TABLE owners (id TEXT PRIMARY KEY);
        CREATE TABLE guards (id TEXT, zone TEXT, PRIMARY KEY (id, zone));
        CREATE TABLE bridges (
            id TEXT NOT NULL, zone TEXT NOT NULL, owner_id TEXT NOT NULL REFERENCES owners(id),
            PRIMARY KEY (id, zone, owner_id),
            FOREIGN KEY (id, zone) REFERENCES guards (id, zone));
        CREATE TABLE members (owner_id TEXT NOT NULL REFERENCES owners(id), member_id TEXT NOT NULL,
            role TEXT NOT NULL, PRIMARY KEY (owner_id, member_id));
        ALTER TABLE guards ENABLE ROW LEVEL SECURITY;";
    let c = classify_in_on(
        "guards",
        schema,
        "EXISTS (
        SELECT 1 FROM bridges b WHERE b.id = guards.id AND b.zone = guards.zone
        AND EXISTS (SELECT 1 FROM members m WHERE m.owner_id = b.owner_id
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    let p19 = p19(&c);
    assert_eq!(p19.link_table.name(), "bridges");
    assert_eq!(pair_names(&p19.pairs), [("id", "id"), ("zone", "zone")]);
    assert_eq!(p19.owner_table.name(), "owners");
    assert_eq!(
        p19.owner_columns
            .iter()
            .map(rls2fga::types::ColumnName::as_str)
            .collect::<Vec<_>>(),
        ["owner_id"]
    );
    assert_eq!(p19.memberships.len(), 1);
    assert_eq!(p19.memberships[0].join_table.name(), "members");
    assert_eq!(pair_names(&p19.memberships[0].pairs), [("owner_id", "id")]);
    assert_eq!(p19.memberships[0].user_column.as_str(), "member_id");
    assert_eq!(
        p19.memberships[0].extra_predicates.sql(),
        Some("role = 'read'".to_string())
    );
}

#[test]
fn membership_join_without_outer_correlation_is_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = a.owner
            WHERE m.member_id = current_setting('app.user_id', true) AND m.role = 'read')",
        "a membership join that names no guarded column",
    );
}

#[test]
fn closure_scan_without_outer_correlation_is_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a
            WHERE EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
        "a closure scan that names no guarded column",
    );
}

#[test]
fn conflicting_far_pairs_are_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.owner_id = a.ownable
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
        "one far column joined to two different closure columns",
    );
}

#[test]
fn far_residuals_smuggling_link_reads_are_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.role = lower(a.owner)
                AND m.member_id = current_setting('app.user_id', true)))",
        "a far residual that reads the closure row inside a function",
    );
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.role = (SELECT owner FROM ownable_ancestors a WHERE a.ownable = orders.id)
                AND m.member_id = current_setting('app.user_id', true)))",
        "a far residual that reads the closure row inside a nested subquery",
    );
}

#[test]
fn link_residual_reading_the_clock_is_refused() {
    let schema = format!("{SCHEMA}ALTER TABLE ownable_ancestors ADD COLUMN expires_at TIMESTAMP;");
    not_p19(
        &schema,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND a.expires_at > now()
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
        "a clock condition on the closure row",
    );
}

#[test]
fn link_residual_the_row_cannot_decide_is_refused() {
    let schema = format!("{SCHEMA}ALTER TABLE ownable_ancestors ADD COLUMN kind TEXT;");
    not_p19(
        &schema,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND a.kind = random()
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
        "a link filter the closure row alone cannot answer",
    );
}

#[test]
fn membership_without_a_caller_comparison_is_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = a.owner
            WHERE a.ownable = orders.id AND m.role = 'read')",
        "a membership scan with no caller comparison",
    );
}

#[test]
fn caller_set_membership_is_not_a_caller_grant() {
    let c = classify_in_attrs(
        "orders",
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.member_id = ANY(string_to_array(current_setting('app.members', true), ','))
                AND m.role = 'read'))",
        [
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.members", SessionAttributeKind::SetAttribute),
        ],
    );
    assert!(
        !matches!(c.pattern, PatternClass::P19IndirectMembership(_)),
        "a caller-set membership matched P19, got {c:?}"
    );
}

#[test]
fn link_pairs_on_a_non_key_column_are_refused() {
    let schema = "
        CREATE TABLE owners (id TEXT PRIMARY KEY);
        CREATE TABLE items (id TEXT PRIMARY KEY, code TEXT);
        CREATE TABLE links (code TEXT NOT NULL, owner_id TEXT NOT NULL REFERENCES owners(id),
            PRIMARY KEY (code, owner_id));
        CREATE TABLE members (owner_id TEXT NOT NULL REFERENCES owners(id), member_id TEXT NOT NULL,
            role TEXT NOT NULL, PRIMARY KEY (owner_id, member_id));
        ALTER TABLE items ENABLE ROW LEVEL SECURITY;";
    let c = classify_in_on(
        "items",
        schema,
        "EXISTS (SELECT 1 FROM links l WHERE l.code = items.code
            AND EXISTS (SELECT 1 FROM members m WHERE m.owner_id = l.owner_id
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    assert!(
        !matches!(c.pattern, PatternClass::P19IndirectMembership(_)),
        "{c:?}"
    );
}

#[test]
fn foreign_key_link_pairs_to_another_parent_are_refused() {
    let schema = "
        CREATE TABLE owners (id TEXT PRIMARY KEY);
        CREATE TABLE zones (id TEXT, zone TEXT, PRIMARY KEY (id, zone));
        CREATE TABLE guards (id TEXT, zone TEXT, PRIMARY KEY (id, zone));
        CREATE TABLE bridges (
            id TEXT NOT NULL, zone TEXT NOT NULL, owner_id TEXT NOT NULL REFERENCES owners(id),
            PRIMARY KEY (id, zone, owner_id),
            FOREIGN KEY (id, zone) REFERENCES zones (id, zone));
        CREATE TABLE members (owner_id TEXT NOT NULL REFERENCES owners(id), member_id TEXT NOT NULL,
            role TEXT NOT NULL, PRIMARY KEY (owner_id, member_id));
        ALTER TABLE guards ENABLE ROW LEVEL SECURITY;";
    let c = classify_in_on(
        "guards",
        schema,
        "EXISTS (SELECT 1 FROM bridges b WHERE b.id = guards.id AND b.zone = guards.zone
            AND EXISTS (SELECT 1 FROM members m WHERE m.owner_id = b.owner_id
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
    );
    assert!(
        !matches!(c.pattern, PatternClass::P19IndirectMembership(_)),
        "{c:?}"
    );
}

#[test]
fn unknown_alias_in_a_correlation_is_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a JOIN memberships m ON m.owner_id = a.owner
            WHERE a.ownable = orders.id AND m.member_id = ghost.id
            AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')",
        "a conjunct that reads an alias no scan admits",
    );
}

#[test]
fn two_membership_subqueries_are_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read')
            AND EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = a.owner
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'write'))",
        "two membership subqueries over one closure row",
    );
}

#[test]
fn far_hop_with_a_join_is_refused() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND EXISTS (SELECT 1 FROM memberships m JOIN owners o ON o.id = m.owner_id
                WHERE m.owner_id = a.owner
                AND m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
        "a far hop that joins the owner table",
    );
}

#[test]
fn negating_indirect_membership_keeps_the_expression_unclassified() {
    for predicate in [
        format!("NOT ({NESTED_ROLE})"),
        format!("NOT (({NESTED_ROLE}) IS TRUE)"),
    ] {
        let c = classify(&predicate);
        assert!(matches!(c.pattern, PatternClass::Unknown(_)), "{c:?}");
        assert_eq!(c.confidence, rls2fga::types::ConfidenceLevel::D);
    }
}

#[test]
fn repeated_far_equality_keeps_the_same_membership() {
    let predicate = NESTED_ROLE.replace(
        "m.owner_id = a.owner",
        "m.owner_id = a.owner AND m.owner_id = a.owner",
    );
    assert_standard_payload(&classify(&predicate), "a repeated far equality");
}

#[test]
fn both_hops_must_name_distinct_tables() {
    let schema = SCHEMA.replace(
        "owner TEXT NOT NULL REFERENCES owners(id),",
        "owner TEXT NOT NULL REFERENCES owners(id),
         member_id TEXT REFERENCES principals(id), role TEXT,",
    );
    let predicate = NESTED_ROLE
        .replace("FROM memberships m", "FROM ownable_ancestors m")
        .replace("m.owner_id", "m.owner");
    not_p19(&schema, &predicate, "two aliases of the closure table");
}

#[test]
fn far_correlation_to_a_missing_closure_column_is_refused() {
    not_p19(
        SCHEMA,
        &NESTED_ROLE.replace("m.owner_id = a.owner", "m.owner_id = a.missing"),
        "a correlation to a missing closure column",
    );
}

#[test]
fn a_computed_far_correlation_is_not_an_owner_identity() {
    not_p19(
        SCHEMA,
        "EXISTS (SELECT 1 FROM ownable_ancestors a WHERE a.ownable = orders.id
            AND lower(a.owner) IN (SELECT m.owner_id FROM memberships m
                WHERE m.member_id = current_setting('app.user_id', true) AND m.role = 'read'))",
        "a transformed closure key",
    );
}

#[test]
fn owner_foreign_keys_must_unambiguously_name_a_primary_key() {
    let no_primary_key = SCHEMA.replace(
        "CREATE TABLE owners (id TEXT PRIMARY KEY);",
        "CREATE TABLE owners (id TEXT UNIQUE);",
    );
    let alternate_key = SCHEMA
        .replace(
            "CREATE TABLE owners (id TEXT PRIMARY KEY);",
            "CREATE TABLE owners (id TEXT PRIMARY KEY, legacy_id TEXT UNIQUE);",
        )
        .replace("REFERENCES owners(id)", "REFERENCES owners(legacy_id)");
    let ambiguous_owner = format!(
        "CREATE TABLE other_owners (id TEXT PRIMARY KEY);{}",
        SCHEMA.replace(
            "PRIMARY KEY (ownable, owner)",
            "FOREIGN KEY (owner) REFERENCES other_owners(id), PRIMARY KEY (ownable, owner)",
        )
    );
    for (schema, why) in [
        (no_primary_key, "an owner table without a primary key"),
        (
            alternate_key,
            "an owner foreign key naming an alternate key",
        ),
        (
            ambiguous_owner,
            "one closure column naming two different owner tables",
        ),
    ] {
        not_p19(&schema, NESTED_ROLE, why);
    }
}
