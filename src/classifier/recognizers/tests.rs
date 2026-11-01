use super::subquery::*;
use super::*;
use crate::classifier::expansion::ExpansionState;
use crate::parser::sql_parser::{parse_schema, ParserDB};
use sqlparser::ast::{SetExpr, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::parser::expr::parse_expr_for_tests as parse_expr;

fn parse_select(sql: &str) -> Select {
    let stmts = Parser::parse_sql(&PostgreSqlDialect {}, sql).expect("query should parse");
    let stmt = stmts.first().expect("expected one statement");
    let Statement::Query(query) = stmt else {
        panic!("expected query statement");
    };
    let SetExpr::Select(select) = query.body.as_ref() else {
        panic!("expected select body");
    };
    select.as_ref().clone()
}

/// The membership columns of one source, spelled out rather than through a scope value.
fn membership_columns(
    select: &Select,
    table: &str,
    alias: Option<&str>,
    columns: &[String],
    guarded_table: &str,
    registry: &FunctionRegistry,
) -> Option<(Vec<MembershipJoinPair>, ColumnName, ResidualPredicates)> {
    extract_membership_columns(
        select,
        &MembershipScope {
            table,
            alias,
            columns,
            guarded_table,
        },
        registry,
    )
}

fn db_with_docs_and_members() -> ParserDB {
    parse_schema(
        r"
CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID,
  tenant_uuid UUID,
  is_public BOOLEAN,
  published BOOLEAN
);
CREATE TABLE doc_members (
  doc_id UUID,
  user_id UUID,
  member_id UUID,
  role TEXT
);
",
    )
    .expect("schema should parse")
}

fn registry_with_role_level() -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
  "role_level": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 1, "editor": 2},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"
  },
  "auth_current_user_id": {"kind":"current_user_accessor","returns":"uuid"}
}"#,
        )
        .expect("registry json should parse");
    registry
}

#[test]
fn recognize_p1_supports_gt_and_rejects_unknown_functions() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("role_level(auth_current_user_id(), id) > 2");

    let classified =
        recognize_p1(&expr, &db, &registry, PolicyCommand::Delete).expect("expected P1 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P1NumericThreshold(NumericThreshold {
            resource_column: Some(column),
            function_name,
            operator: ThresholdOperator::Gt,
            threshold,
            command: PolicyCommand::Delete,
        }) if function_name == "role_level" && *threshold == 2 && column == "id"
    ));

    let unknown = parse_expr("unknown_role(auth_current_user_id(), id) >= 1");
    assert!(recognize_p1(&unknown, &db, &registry, PolicyCommand::Select).is_none());
}

/// Two calls in one clause pass two different columns, and each recognized threshold keeps
/// its own. Collapsing them to one would judge a row by a value the call never passed.
#[test]
fn each_threshold_keeps_the_column_its_own_call_passes() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let columns: Vec<String> = ["id", "owner_id"]
        .iter()
        .map(|column| {
            let expr = parse_expr(&format!(
                "role_level(auth_current_user_id(), {column}) >= 2"
            ));
            let classified = recognize_p1(&expr, &db, &registry, PolicyCommand::Select)
                .expect("expected P1 match");
            let PatternClass::P1NumericThreshold(NumericThreshold {
                resource_column: Some(column),
                ..
            }) = classified.pattern
            else {
                panic!("the call passes a column, so the pattern carries it");
            };
            column.as_str().to_string()
        })
        .collect();
    assert_eq!(columns, ["id", "owner_id"]);

    // An expression rather than a column leaves nothing to point at, and the translation
    // falls back to the schema rather than guessing.
    let computed = parse_expr("role_level(auth_current_user_id(), COALESCE(owner_id, id)) >= 2");
    let classified =
        recognize_p1(&computed, &db, &registry, PolicyCommand::Select).expect("expected P1 match");
    assert!(matches!(
        classified.pattern,
        PatternClass::P1NumericThreshold(NumericThreshold {
            resource_column: None,
            ..
        })
    ));
}

#[test]
fn recognize_p1_accepts_reversed_comparators() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let gte = parse_expr("2 <= role_level(auth_current_user_id(), id)");
    let classified_gte =
        recognize_p1(&gte, &db, &registry, PolicyCommand::Select).expect("expected P1 match");
    assert!(matches!(
        &classified_gte.pattern,
        PatternClass::P1NumericThreshold(NumericThreshold {
            operator: ThresholdOperator::Gte,
            threshold,
            ..
        }) if *threshold == 2
    ));

    let gt = parse_expr("2 < role_level(auth_current_user_id(), id)");
    let classified_gt =
        recognize_p1(&gt, &db, &registry, PolicyCommand::Delete).expect("expected P1 match");
    assert!(matches!(
        &classified_gt.pattern,
        PatternClass::P1NumericThreshold(NumericThreshold {
            operator: ThresholdOperator::Gt,
            threshold,
            command: PolicyCommand::Delete,
            ..
        }) if *threshold == 2
    ));
}

#[test]
fn recognize_p2_handles_negation_and_literal_filtering() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let negated = parse_expr("role_level(auth_current_user_id(), id) NOT IN ('viewer')");
    assert!(recognize_p2(&negated, &db, &registry).is_none());

    let non_threshold = parse_expr("unknown_role(auth_current_user_id(), id) IN ('viewer')");
    assert!(recognize_p2(&non_threshold, &db, &registry).is_none());

    let non_string_literals = parse_expr("role_level(auth_current_user_id(), id) IN (TRUE)");
    assert!(recognize_p2(&non_string_literals, &db, &registry).is_none());

    let ok = parse_expr("role_level(auth_current_user_id(), id) IN ('viewer', 2)");
    let classified = recognize_p2(&ok, &db, &registry).expect("expected P2 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P2RoleNameInList(RoleNameInList {
            function_name,
            role_names,
            ..
        }) if function_name == "role_level"
            && role_names == &vec!["viewer".to_string(), "2".to_string()]
    ));
}

#[test]
fn recognize_p2_role_in_list_refuses_the_clickhouse_global_modifier() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let ok = parse_expr("role_level(auth_current_user_id(), id) IN ('viewer', 2)");
    let Expr::In {
        expr,
        target: target @ InTarget::List(_),
        negated,
        ..
    } = &ok
    else {
        panic!("expected an IN list");
    };
    let global = Expr::In {
        expr: expr.clone(),
        target: target.clone(),
        negated: *negated,
        global: true,
    };
    assert!(
        recognize_p2(&global, &db, &registry).is_none(),
        "a ClickHouse GLOBAL IN is not PostgreSQL's role name IN-list"
    );
}

#[test]
fn recognize_p2_pg_has_role_three_and_two_arg_forms() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new(); // pg_has_role is a built-in, no registry needed.

    // Three-arg form: pg_has_role(current_user, 'admin', 'MEMBER').
    let three_arg = parse_expr("pg_has_role(current_user, 'admin', 'MEMBER')");
    let c3 = recognize_p2(&three_arg, &db, &registry).expect("expected P2 for pg_has_role 3-arg");
    assert!(
        matches!(
            &c3.pattern,
            PatternClass::P2RoleNameInList(RoleNameInList { function_name, role_names, .. })
                if function_name == "pg_has_role" && role_names == &["admin"]
        ),
        "three-arg pg_has_role should produce P2 with role 'admin', got: {:?}",
        c3.pattern
    );
    assert_eq!(c3.confidence, ConfidenceLevel::A);

    // Two-arg form: pg_has_role('editor', 'USAGE'), current user is implied.
    let two_arg = parse_expr("pg_has_role('editor', 'USAGE')");
    let c2 = recognize_p2(&two_arg, &db, &registry).expect("expected P2 for pg_has_role 2-arg");
    assert!(
        matches!(
            &c2.pattern,
            PatternClass::P2RoleNameInList(RoleNameInList { function_name, role_names, .. })
                if function_name == "pg_has_role" && role_names == &["editor"]
        ),
        "two-arg pg_has_role should produce P2 with role 'editor', got: {:?}",
        c2.pattern
    );

    let bad_user = parse_expr("pg_has_role(other_user_id, 'admin', 'MEMBER')");
    assert!(
        recognize_p2(&bad_user, &db, &registry).is_none(),
        "pg_has_role with non-current-user first arg should not match"
    );
}

#[test]
fn recognize_p2_role_accessor_equality_and_in_list() {
    let db = db_with_docs_and_members();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth.role",
        &FunctionSemantic::RoleAccessor {
            returns: "text".to_string(),
        },
    );

    let eq_expr = parse_expr("auth.role() = 'authenticated'");
    let c_eq =
        recognize_p2(&eq_expr, &db, &registry).expect("expected P2 for role_accessor = literal");
    assert!(
        matches!(
            &c_eq.pattern,
            PatternClass::P2RoleNameInList(RoleNameInList { function_name, role_names, .. })
                if function_name == "auth.role" && role_names == &["authenticated"]
        ),
        "auth.role() = 'authenticated' should produce P2, got: {:?}",
        c_eq.pattern
    );
    assert_eq!(c_eq.confidence, ConfidenceLevel::A);

    // IN-list form: auth.role() IN ('authenticated', 'service_role')
    let in_expr = parse_expr("auth.role() IN ('authenticated', 'service_role')");
    let c_in =
        recognize_p2(&in_expr, &db, &registry).expect("expected P2 for role_accessor IN list");
    assert!(
        matches!(
            &c_in.pattern,
            PatternClass::P2RoleNameInList(RoleNameInList { function_name, role_names, .. })
                if function_name == "auth.role"
                    && role_names == &["authenticated", "service_role"]
        ),
        "auth.role() IN (...) should produce P2, got: {:?}",
        c_in.pattern
    );

    // Unregistered role function should not match.
    let empty_registry = FunctionRegistry::new();
    let not_matched = parse_expr("auth.role() = 'authenticated'");
    assert!(
        recognize_p2(&not_matched, &db, &empty_registry).is_none(),
        "unregistered role function should not match P2"
    );
}

/// A non-literal element of a role IN-list is a per-row grant the literals cannot
/// stand in for: `IN ('viewer', owner_id)` admits a row whose threshold equals the
/// row's own `owner_id`, and keeping only the literal would translate a subset of
/// the policy and report it as faithful.
#[test]
fn p2_in_list_refuses_a_mixed_literal_and_non_literal_list() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let mixed_threshold =
        parse_expr("role_level(auth_current_user_id(), id) IN ('viewer', owner_id)");
    assert!(
        recognize_p2(&mixed_threshold, &db, &registry).is_none(),
        "a non-literal element in a threshold IN-list fails closed"
    );

    let mut accessor_registry = FunctionRegistry::new();
    accessor_registry.register_if_absent(
        "role",
        &FunctionSemantic::RoleAccessor {
            returns: "text".to_string(),
        },
    );
    let mixed_accessor = parse_expr("auth.role() IN ('admin', owner_id)");
    assert!(
        recognize_p2(&mixed_accessor, &db, &accessor_registry).is_none(),
        "a non-literal element in a role-accessor IN-list fails closed"
    );
}

#[test]
fn recognize_array_patterns_matches_the_caller_in_every_spelling() {
    let registry = FunctionRegistry::new();

    // The caller as an element is an exact relationship, verified on PostgreSQL 18
    // against an UNNEST enumeration, so it is P11 at confidence A.
    for spelling in [
        "current_user = ANY(allowed_users)",
        "allowed_users @> ARRAY[current_user]",
        "ARRAY[current_user] <@ allowed_users",
        "ARRAY[current_user] && allowed_users",
        "allowed_users && ARRAY[current_user]",
    ] {
        let expr = parse_expr(spelling);
        let classified = recognize_array_patterns(&expr, &registry)
            .unwrap_or_else(|| panic!("`{spelling}` should match array membership"));
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P11ArrayMembership(ArrayMembership { column }) if column == "allowed_users"
            ),
            "`{spelling}` should name the array column, got: {:?}",
            classified.pattern
        );
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::A,
            "`{spelling}` is exact"
        );
    }

    // A literal array is a value, not the caller, so it stays an attribute guard.
    let overlap_expr = parse_expr("allowed_roles && ARRAY['admin', 'editor']");
    assert!(
        recognize_array_patterns(&overlap_expr, &registry).is_none(),
        "a literal array names no principal to relate"
    );
    assert_eq!(
        is_attribute_check(&overlap_expr)
            .as_ref()
            .map(ColumnName::as_str),
        Some("allowed_roles"),
        "overlap against a literal is an attribute guard"
    );

    let non_array = parse_expr("owner_id = current_user");
    assert!(recognize_array_patterns(&non_array, &registry).is_none());

    // A subquery is membership through a table, and expanding it would name a column
    // that does not exist.
    let subquery = parse_expr("current_user = ANY(SELECT user_id FROM doc_members)");
    assert!(recognize_array_patterns(&subquery, &registry).is_none());
}

#[test]
fn recognize_p3_requires_registration_for_unregistered_current_user_like_names() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    // Unregistered function names that merely contain `current_user` must not match.
    let a = parse_expr("owner_id = auth_current_user_id()");
    assert!(recognize_p3(&a, &db, &registry).is_none());

    let b = parse_expr("tenant_uuid = auth_current_user_id()");
    assert!(recognize_p3(&b, &db, &registry).is_none());

    let none = parse_expr("tenant_uuid = actor_id()");
    assert!(
        recognize_p3(&none, &db, &registry).is_none(),
        "non-user-like function should not match ownership"
    );

    let not_eq = parse_expr("owner_id <> auth_current_user_id()");
    assert!(recognize_p3(&not_eq, &db, &registry).is_none());

    let mut registered = FunctionRegistry::new();
    registered.register_if_absent(
        "auth_current_user_id",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );
    let registered_expr = parse_expr("owner_id = auth_current_user_id()");
    let registered_classified = recognize_p3(&registered_expr, &db, &registered)
        .expect("expected registered accessor to match");
    assert_eq!(registered_classified.confidence, ConfidenceLevel::A);
}

#[test]
fn recognize_p3_refuses_null_safe_equality() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("owner_id IS NOT DISTINCT FROM auth_current_user_id()");

    assert!(
        recognize_p3(&expr, &db, &registry).is_none(),
        "NULL equals NULL here, unlike direct ownership"
    );
}

#[test]
fn recognize_p3_accepts_null_safe_equality_for_the_sql_caller() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("owner_id IS NOT DISTINCT FROM current_user");

    assert!(matches!(
        recognize_p3(&expr, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership(DirectOwnership { column }),
            confidence: ConfidenceLevel::A,
        }) if column == "owner_id"
    ));
}

#[test]
fn recognize_p3_scalar_subquery_wrapper_caps_confidence_at_b() {
    let db = db_with_docs_and_members();
    // `registry_with_role_level` has `auth_current_user_id` as a confirmed accessor.
    let registry = registry_with_role_level();

    // Bare function call → confidence A (registry-confirmed).
    let bare = parse_expr("owner_id = auth_current_user_id()");
    let c_bare = recognize_p3(&bare, &db, &registry).expect("expected P3 match");
    assert_eq!(
        c_bare.confidence,
        ConfidenceLevel::A,
        "bare registry call should be A"
    );

    // Scalar subquery wrapping the same registry-confirmed function → confidence B.
    let subquery = parse_expr("owner_id = (SELECT auth_current_user_id())");
    let c_subquery = recognize_p3(&subquery, &db, &registry).expect("expected P3 match");
    assert!(
        matches!(
            &c_subquery.pattern,
            PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"
        ),
        "subquery-wrapped accessor should still produce P3, got: {:?}",
        c_subquery.pattern
    );
    assert_eq!(
        c_subquery.confidence,
        ConfidenceLevel::B,
        "subquery-wrapped registry accessor should be capped at B"
    );

    // SQL keyword in subquery → still B (subquery always caps).
    let kw_subquery = parse_expr("owner_id = (SELECT current_user)");
    let c_kw = recognize_p3(&kw_subquery, &db, &registry).expect("expected P3 match");
    assert_eq!(
        c_kw.confidence,
        ConfidenceLevel::B,
        "subquery around SQL keyword should also be capped at B"
    );
}

#[test]
fn recognize_p3_current_setting_requires_registration() {
    let db = db_with_docs_and_members();

    // Without explicit registration: no match.
    let empty_registry = FunctionRegistry::new();
    let expr = parse_expr("owner_id = current_setting('app.current_user_id')");
    assert!(
        recognize_p3(&expr, &db, &empty_registry).is_none(),
        "unregistered current_setting must not match P3"
    );

    // After explicit registration: current_setting → confidence A.
    let mut registered_registry = FunctionRegistry::new();
    registered_registry.register_if_absent(
        "current_setting",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );
    let classified_a = recognize_p3(&expr, &db, &registered_registry)
        .expect("expected P3 match for registered current_setting");
    assert_eq!(
        classified_a.confidence,
        ConfidenceLevel::A,
        "registered current_setting should be confidence A"
    );
}

/// The key carries the meaning, so naming it is enough: the function itself stays
/// unregistered, which is what keeps a call reading some other key unrecognised.
#[test]
fn recognize_p3_reads_a_named_setting_key_without_registering_the_function() {
    let db = db_with_docs_and_members();
    let mut registry = FunctionRegistry::new();
    registry.trust_current_user_setting_keys(["app.current_user_id"]);

    let named = parse_expr("owner_id = current_setting('app.current_user_id')");
    let classified = recognize_p3(&named, &db, &registry)
        .expect("expected P3 match for a named current_setting key");
    assert!(
        matches!(&classified.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "the column keyed by the caller owns the row, got: {:?}",
        classified.pattern
    );
    assert_eq!(
        classified.confidence,
        ConfidenceLevel::A,
        "a named key is as explicit as a registered accessor"
    );

    let unnamed = parse_expr("owner_id = current_setting('app.tenant_id')");
    assert!(
        recognize_p3(&unnamed, &db, &registry).is_none(),
        "the key decides, so an unnamed one must not match through the same function"
    );
}

#[test]
fn recognize_p3_rejects_unregistered_current_user_like_function_names() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let near_miss_functions = [
        "owner_id = is_current_user_admin()",
        "owner_id = current_user_is_admin()",
        "owner_id = get_current_user_role()",
        "owner_id = foo_current_user_bar()",
        "owner_id = (SELECT is_current_user_admin())",
        "owner_id = current_setting('request.jwt.claims')::json->>'sub'",
    ];

    for sql in near_miss_functions {
        let expr = parse_expr(sql);
        assert!(
            recognize_p3(&expr, &db, &registry).is_none(),
            "unregistered current_user-like function `{sql}` must not match P3"
        );
    }
}

#[test]
fn recognize_p3_rejects_quoted_user_keyword_identifier() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let expr = parse_expr("owner_id = \"user\"");
    assert!(
        recognize_p3(&expr, &db, &registry).is_none(),
        "quoted identifiers must not be treated as SQL current-user keywords"
    );
}

#[test]
fn recognize_p3_rejects_unregistered_function_names_that_match_sql_keywords() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let keyword_named_functions = [
        "owner_id = user",
        "owner_id = auth.user()",
        "owner_id = auth.current_role()",
        "owner_id = user(42)",
        "owner_id = \"current_user\"()",
        "owner_id = x.current_user()",
        "owner_id = \"x\".\"current_user\"()",
    ];

    for sql in keyword_named_functions {
        let expr = parse_expr(sql);
        assert!(
            recognize_p3(&expr, &db, &registry).is_none(),
            "unregistered function call `{sql}` must not be treated as SQL keyword accessor"
        );
    }
}

#[test]
fn recognize_p3_rejects_unregistered_oauth_like_function_name() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let expr = parse_expr("owner_id = oauth_token()");
    assert!(
        recognize_p3(&expr, &db, &registry).is_none(),
        "oauth-like function names must not match P3 without explicit registration"
    );
}

#[test]
fn recognize_p4_exists_supports_extra_predicates_and_negation() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let negated = parse_expr(
        "NOT EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
             )",
    );
    assert!(recognize_p4(&negated, &db, &registry, "docs", &ExpansionState::new()).is_none());

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = auth_current_user_id()
                 AND doc_members.role = 'admin'
             )",
    );
    let classified = recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new())
        .expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership(ExistsMembership {
            join_table,
            pairs,
            user_column,
            extra_predicates,
            ..
        }) if join_table.to_string() == "doc_members"
            && matches!(pairs.as_slice(), [pair]
                if pair.join_column == "doc_id" && pair.outer_column == "id")
            && user_column == "user_id"
            && extra_predicates
                .sql()
                .is_some_and(|s| s.contains("role = 'admin'"))
    ));
}

/// Reading the guarded table inside its own policy is a read `PostgreSQL` refuses to plan,
/// and the scan is a fresh one regardless, so the join correlates nothing.
#[test]
fn recognize_p4_exists_refuses_a_subquery_reading_the_guarded_table() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE d.id = docs.id
                 AND dm.user_id = auth_current_user_id()
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "a subquery scanning 'docs' cannot name the guarded row"
    );
}

#[test]
fn recognize_p4_with_alias_and_current_user_keyword_strips_correlated_predicates() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND dm.role = 'admin'
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new())
        .expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership(ExistsMembership {
            join_table,
            pairs,
            user_column,
            extra_predicates,
            ..
        }) if join_table.to_string() == "doc_members"
            && matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id")
            && user_column == "user_id"
            && extra_predicates
                .sql()
                .is_some_and(|s| s == "role = 'admin'")
    ));
}

#[test]
fn recognize_p4_fails_closed_for_outer_table_is_false_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND docs.published IS FALSE
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "outer-table IS FALSE predicate should fail closed for P4"
    );
}

#[test]
fn recognize_p4_fails_closed_for_outer_table_boolean_is_wrappers() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let clauses = [
        "docs.published IS TRUE",
        "docs.published IS NOT TRUE",
        "docs.published IS NOT FALSE",
    ];

    for clause in clauses {
        let exists_expr = parse_expr(&format!(
            "EXISTS (
                   SELECT 1
                   FROM doc_members dm
                   WHERE dm.doc_id = docs.id
                     AND dm.user_id = current_user
                     AND {clause}
                 )"
        ));

        assert!(
            recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
            "outer-table predicate `{clause}` should fail closed for P4"
        );
    }
}

#[test]
fn recognize_p4_fails_closed_for_outer_table_distinct_predicates() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let clauses = [
        "docs.id IS DISTINCT FROM dm.member_id",
        "docs.id IS NOT DISTINCT FROM dm.member_id",
    ];

    for clause in clauses {
        let exists_expr = parse_expr(&format!(
            "EXISTS (
                   SELECT 1
                   FROM doc_members dm
                   WHERE dm.doc_id = docs.id
                     AND dm.user_id = current_user
                     AND {clause}
                 )"
        ));

        assert!(
            recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
            "outer-table DISTINCT predicate `{clause}` should fail closed for P4"
        );
    }
}

#[test]
fn recognize_p4_supports_function_wrapped_membership_predicates_without_alias_leak() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND lower(dm.role) = 'admin'
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new())
        .expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership(ExistsMembership { extra_predicates, .. })
            if extra_predicates
                .sql()
                .is_some_and(|s| {
                    let lower = s.to_ascii_lowercase();
                    lower.contains("lower(role) = 'admin'")
                        && !lower.contains("dm.")
                        && !lower.contains("docs.")
                })
    ));
}

#[test]
fn recognize_p4_fails_closed_for_function_wrapped_outer_table_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND lower(docs.owner_id::text) = lower(dm.member_id::text)
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "function-wrapped outer-table predicate should fail closed for P4"
    );
}

#[test]
fn recognize_p4_fails_closed_for_joined_source_unqualified_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               JOIN docs d ON dm.doc_id = d.id
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND is_public = TRUE
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "joined-source unqualified extra predicate should fail closed for P4"
    );
}

#[test]
fn recognize_p4_fails_closed_for_derived_join_unqualified_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               JOIN (SELECT id, is_public FROM docs) d ON dm.doc_id = d.id
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = current_user
                 AND is_public = TRUE
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "derived joined-source unqualified extra predicate should fail closed for P4"
    );
}

/// A guarded third table would be precomputed from the loader's view of it.
#[test]
fn recognize_p4_fails_closed_for_extra_predicate_reading_a_third_table_in_a_subquery() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID, role_name TEXT);
CREATE TABLE roles(name TEXT);
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = current_user
                 AND role_name = ANY (SELECT name FROM roles)
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "an extra predicate whose subquery reads a third table fails closed for P4"
    );
}

/// The holder shape carries the same extras.
#[test]
fn uncorrelated_membership_fails_closed_for_extra_predicate_reading_a_third_table_in_a_subquery() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID, role_name TEXT);
CREATE TABLE roles(name TEXT);
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE user_id = current_user
                 AND role_name = ANY (SELECT name FROM roles)
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "an uncorrelated membership whose extra predicate reads a third table fails closed"
    );
}

/// The `IN` and `= ANY` spellings reach the analyzer through the rewrite.
#[test]
fn recognize_p4_in_subquery_fails_closed_for_extra_predicate_reading_a_third_table_in_a_subquery() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID, role_name TEXT);
CREATE TABLE roles(name TEXT);
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
",
    )
    .expect("schema should parse");
    let registry = registry_with_role_level();

    let in_expr = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
                 AND dm.role_name = ANY (SELECT name FROM roles)
             )",
    );

    assert!(
        recognize_p4_in_subquery(
            &in_expr,
            &db,
            &registry,
            "docs",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "the IN spelling of a third-table-subquery extra predicate fails closed"
    );
}

/// The `IN` spelling reaches the same resolver.
#[test]
fn recognize_p4_in_subquery_allows_an_unrestricted_third_table_in_a_subquery() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID, role_name TEXT);
CREATE TABLE roles(name TEXT);
",
    )
    .expect("schema should parse");
    let registry = registry_with_role_level();

    let in_expr = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
                 AND dm.role_name = ANY (SELECT name FROM roles)
             )",
    );

    let classified = recognize_p4_in_subquery(
        &in_expr,
        &db,
        &registry,
        "docs",
        PolicyCommand::Select,
        &ExpansionState::new(),
    )
    .expect("a third table the database filters nothing on is translatable");
    let PatternClass::P4ExistsMembership(membership) = &classified.pattern else {
        panic!(
            "expected an EXISTS membership, got {:?}",
            classified.pattern
        );
    };
    let sql = membership
        .extra_predicates
        .sql()
        .expect("the residual rides the tuple query");
    assert!(
        sql.contains(r#"FROM "public"."roles""#),
        "the third relation is named as the catalog carries it, got: {sql}"
    );
}

/// A membership subquery joined on every column of the guarded table's composite
/// primary key states the same relationship as the single-column shape, with the
/// share scoped by the extra key columns, so it classifies no worse.
#[test]
fn recognize_p4_accepts_a_join_on_every_column_of_a_composite_key() {
    let db = parse_schema(
        r"
CREATE TABLE p2(tenant_id INT NOT NULL, id INT NOT NULL, owner TEXT,
                PRIMARY KEY(tenant_id, id));
CREATE TABLE s2(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
                PRIMARY KEY(tenant_id, paper_id, viewer));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM s2 s
               WHERE s.tenant_id = p2.tenant_id
                 AND s.paper_id = p2.id
                 AND s.viewer = current_user
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "p2", &ExpansionState::new())
        .expect("a two-column composite-key join is the one-column shape scoped by tenant");
    let PatternClass::P4ExistsMembership(membership) = &classified.pattern else {
        panic!("expected P4ExistsMembership, got {:?}", classified.pattern);
    };
    assert_eq!(
        membership.pairs,
        vec![
            MembershipJoinPair {
                join_column: ColumnName::from_stored("tenant_id"),
                outer_column: ColumnName::from_stored("tenant_id"),
            },
            MembershipJoinPair {
                join_column: ColumnName::from_stored("paper_id"),
                outer_column: ColumnName::from_stored("id"),
            },
        ],
        "recognizer must emit both composite-key columns in PK order"
    );
    assert_eq!(membership.user_column, ColumnName::from_stored("viewer"));
}

/// Three key columns behave as two do: the join names one guarded row per share row.
#[test]
fn recognize_p4_accepts_a_join_on_three_columns_of_a_composite_key() {
    let db = parse_schema(
        r"
CREATE TABLE p3(region_id INT NOT NULL, tenant_id INT NOT NULL, id INT NOT NULL, owner TEXT,
                PRIMARY KEY(region_id, tenant_id, id));
CREATE TABLE s3(region_id INT NOT NULL, tenant_id INT NOT NULL, paper_id INT NOT NULL,
                viewer TEXT NOT NULL,
                PRIMARY KEY(region_id, tenant_id, paper_id, viewer));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM s3 s
               WHERE s.region_id = p3.region_id
                 AND s.tenant_id = p3.tenant_id
                 AND s.paper_id = p3.id
                 AND s.viewer = current_user
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "p3", &ExpansionState::new())
        .expect("a three-column composite-key join is the same shape again");
    let PatternClass::P4ExistsMembership(membership) = &classified.pattern else {
        panic!("expected P4ExistsMembership, got {:?}", classified.pattern);
    };
    assert_eq!(
        membership.pairs,
        vec![
            MembershipJoinPair {
                join_column: ColumnName::from_stored("region_id"),
                outer_column: ColumnName::from_stored("region_id"),
            },
            MembershipJoinPair {
                join_column: ColumnName::from_stored("tenant_id"),
                outer_column: ColumnName::from_stored("tenant_id"),
            },
            MembershipJoinPair {
                join_column: ColumnName::from_stored("paper_id"),
                outer_column: ColumnName::from_stored("id"),
            },
        ],
        "recognizer must emit all three composite-key columns in PK order"
    );
    assert_eq!(membership.user_column, ColumnName::from_stored("viewer"));
}

/// The join columns carry one declared composite foreign key to a parent table, so
/// each membership row names exactly one parent object, the same relationship the
/// single-column FK-backed shape states.
#[test]
fn recognize_p4_accepts_a_join_backed_by_a_composite_foreign_key() {
    let db = parse_schema(
        r"
CREATE TABLE projects(tenant_id INT NOT NULL, id INT NOT NULL,
                      PRIMARY KEY(tenant_id, id));
CREATE TABLE docs(doc_id INT PRIMARY KEY, tenant_id INT NOT NULL, project_id INT NOT NULL,
                  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id));
CREATE TABLE project_members(tenant_id INT NOT NULL, project_id INT NOT NULL,
                             user_id TEXT NOT NULL,
                             PRIMARY KEY(tenant_id, project_id, user_id),
                             FOREIGN KEY (tenant_id, project_id)
                               REFERENCES projects(tenant_id, id));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM project_members m
               WHERE m.tenant_id = docs.tenant_id
                 AND m.project_id = docs.project_id
                 AND m.user_id = current_user
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new())
        .expect("a composite-FK-backed join is the single-column FK shape widened");
    assert_eq!(classified.confidence, ConfidenceLevel::A);
}

/// A strict subset of the composite key answers for every row sharing the prefix,
/// so the pairing names no single guarded row and fails closed.
#[test]
fn recognize_p4_refuses_a_join_on_a_subset_of_a_composite_key() {
    let db = parse_schema(
        r"
CREATE TABLE p4(region_id INT NOT NULL, tenant_id INT NOT NULL, id INT NOT NULL,
                PRIMARY KEY(region_id, tenant_id, id));
CREATE TABLE s4(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
                PRIMARY KEY(tenant_id, paper_id, viewer));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM s4 s
               WHERE s.tenant_id = p4.tenant_id
                 AND s.paper_id = p4.id
                 AND s.viewer = current_user
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "p4", &ExpansionState::new()).is_none(),
        "two pairs cannot stand in for a three-column key"
    );
}

/// A duplicate outer column is not a key pairing: two share columns matching one
/// guarded column names no bijection onto any key.
#[test]
fn recognize_p4_refuses_a_pairing_naming_one_outer_column_twice() {
    let db = parse_schema(
        r"
CREATE TABLE p5(tenant_id INT NOT NULL, id INT NOT NULL, PRIMARY KEY(tenant_id, id));
CREATE TABLE s5(a INT NOT NULL, b INT NOT NULL, viewer TEXT NOT NULL,
                PRIMARY KEY(a, b, viewer));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM s5 s
               WHERE s.a = p5.tenant_id
                 AND s.b = p5.tenant_id
                 AND s.viewer = current_user
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "p5", &ExpansionState::new()).is_none(),
        "a duplicate outer column fails closed"
    );
}

/// Two declared foreign keys cover the same joined columns, so the parent they
/// name is ambiguous and the pairing fails closed.
#[test]
fn recognize_p4_refuses_a_pairing_two_foreign_keys_cover() {
    let db = parse_schema(
        r"
CREATE TABLE pa(x INT NOT NULL, y INT NOT NULL, PRIMARY KEY(x, y));
CREATE TABLE pb(x INT NOT NULL, y INT NOT NULL, PRIMARY KEY(x, y));
CREATE TABLE docs(doc_id INT PRIMARY KEY, a INT NOT NULL, b INT NOT NULL);
CREATE TABLE grants_two(a INT NOT NULL, b INT NOT NULL, user_id TEXT NOT NULL,
                        PRIMARY KEY(a, b, user_id),
                        FOREIGN KEY (a, b) REFERENCES pa(x, y),
                        FOREIGN KEY (a, b) REFERENCES pb(x, y));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM grants_two g
               WHERE g.a = docs.a
                 AND g.b = docs.b
                 AND g.user_id = current_user
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "two covering foreign keys leave the parent ambiguous"
    );
}

/// The refusal names what failed, so the operator reads a decision rather than
/// "does not match any known pattern".
#[test]
fn an_unkeyed_pairing_is_diagnosed_with_its_reason() {
    let db = parse_schema(
        r"
CREATE TABLE p6(region_id INT NOT NULL, tenant_id INT NOT NULL, id INT NOT NULL,
                PRIMARY KEY(region_id, tenant_id, id));
CREATE TABLE s6(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
                PRIMARY KEY(tenant_id, paper_id, viewer));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM s6 s
               WHERE s.tenant_id = p6.tenant_id
                 AND s.paper_id = p6.id
                 AND s.viewer = current_user
             )",
    );

    let reason = diagnose_p4_membership_ambiguity(
        &exists_expr,
        &db,
        &registry,
        "p6",
        &ExpansionState::new(),
    )
    .expect("an unkeyed pairing carries a reason");
    assert!(
        reason.contains("neither a declared foreign key") && reason.contains("s6"),
        "the reason names the failed routes, got: {reason}"
    );
}

/// The row-value `IN` spelling of a composite-key membership is refused, and the
/// reason names the `EXISTS` respelling that translates, not a projection problem.
#[test]
fn a_row_value_in_subquery_is_diagnosed_with_its_respelling() {
    let db = parse_schema(
        r"
CREATE TABLE p7(tenant_id INT NOT NULL, id INT NOT NULL, PRIMARY KEY(tenant_id, id));
CREATE TABLE s7(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
                PRIMARY KEY(tenant_id, paper_id, viewer));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let in_expr = parse_expr(
        "(tenant_id, id) IN (
               SELECT s.tenant_id, s.paper_id
               FROM s7 s
               WHERE s.viewer = current_user
             )",
    );

    assert!(
        recognize_p4_in_subquery(
            &in_expr,
            &db,
            &registry,
            "p7",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "the row-value spelling stays refused"
    );
    let reason =
        diagnose_p4_membership_ambiguity(&in_expr, &db, &registry, "p7", &ExpansionState::new())
            .expect("the refusal carries a reason");
    assert!(
        reason.contains("EXISTS") && reason.contains("row-value"),
        "the reason names the respelling, got: {reason}"
    );
}
/// A relation the loader and the caller can read differently refuses.
#[test]
fn recognize_p4_refuses_an_extra_predicate_subquery_over_the_join_table() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID, role_name TEXT);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = current_user
                 AND role_name = ANY (SELECT role_name FROM doc_members)
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "a residual the row does not decide over a guarded relation cannot be precomputed"
    );
}

/// The guarded table, an open share table and a second open table.
fn papers_schema(extra: &str) -> ParserDB {
    parse_schema(&format!(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT);
CREATE TABLE tiers(cutoff INT);
{extra}
"
    ))
    .expect("schema should parse")
}

fn papers_membership(residual: &str) -> Expr {
    parse_expr(&format!(
        "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND {residual}
             )"
    ))
}

fn papers_refuses(extra: &str, residual: &str) -> bool {
    recognize_p4(
        &papers_membership(residual),
        &papers_schema(extra),
        &FunctionRegistry::new(),
        "papers",
        &ExpansionState::new(),
    )
    .is_none()
}

fn papers_refuses_on(db: &ParserDB, residual: &str) -> bool {
    recognize_p4(
        &papers_membership(residual),
        db,
        &FunctionRegistry::new(),
        "papers",
        &ExpansionState::new(),
    )
    .is_none()
}

/// Membership qualified by beating the average weight of the whole share table.
fn average_weight_membership() -> Expr {
    parse_expr(
        "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND s.weight > (SELECT avg(weight) FROM paper_shares)
             )",
    )
}

fn recognized_residual_sql(db: &ParserDB, expr: &Expr) -> String {
    let registry = FunctionRegistry::new();
    let classified = recognize_p4(expr, db, &registry, "papers", &ExpansionState::new())
        .expect("a residual over relations the database filters nothing on is translatable");
    assert_eq!(
        classified.confidence,
        ConfidenceLevel::A,
        "the exemption changes what is recognized, never how well"
    );
    let PatternClass::P4ExistsMembership(membership) = &classified.pattern else {
        panic!(
            "expected an EXISTS membership, got {:?}",
            classified.pattern
        );
    };
    membership
        .extra_predicates
        .sql()
        .expect("the residual rides the tuple query")
}

/// Row security off on every relation read means one answer serves every caller.
#[test]
fn a_residual_over_an_unrestricted_relation_is_recognized() {
    let db = papers_schema("");
    let sql = recognized_residual_sql(&db, &average_weight_membership());
    assert!(
        sql.contains("avg(weight)") && sql.contains("paper_shares"),
        "the residual keeps its aggregate for the tuple query, got: {sql}"
    );
}

/// The same policy refuses once the share table filters rows.
#[test]
fn a_residual_over_a_row_secured_relation_is_refused() {
    let db = papers_schema("ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;");
    let registry = FunctionRegistry::new();
    assert!(
        recognize_p4(
            &average_weight_membership(),
            &db,
            &registry,
            "papers",
            &ExpansionState::new()
        )
        .is_none(),
        "a relation with row security on answers differently per caller"
    );
}

/// A policy on a relation that never enabled row security is inert.
#[test]
fn a_residual_over_a_relation_with_an_inert_policy_is_recognized() {
    let db = papers_schema(
        "CREATE POLICY shares_p ON paper_shares FOR SELECT USING (viewer = current_user);",
    );
    let sql = recognized_residual_sql(&db, &average_weight_membership());
    assert!(
        sql.contains("avg(weight)"),
        "policy presence is not the test, got: {sql}"
    );
}

/// `FORCE` activates nothing by itself.
#[test]
fn a_residual_over_a_forced_but_disabled_relation_is_recognized() {
    let db = papers_schema("ALTER TABLE paper_shares FORCE ROW LEVEL SECURITY;");
    let sql = recognized_residual_sql(&db, &average_weight_membership());
    assert!(
        sql.contains("avg(weight)"),
        "FORCE alone activates nothing, got: {sql}"
    );
}

/// The exemption is about the relations read, not about which table is scanned.
#[test]
fn a_residual_reading_a_third_unrestricted_relation_is_recognized() {
    let db = papers_schema("");
    let sql = recognized_residual_sql(
        &db,
        &parse_expr(
            "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND s.weight > (SELECT max(cutoff) FROM tiers)
             )",
        ),
    );
    assert!(
        sql.contains("max(cutoff)") && sql.contains("tiers"),
        "the third relation's read rides the tuple query, got: {sql}"
    );
}

/// The share table gated by a request-only RESTRICTIVE policy beside an open permissive read.
const GATED_SHARES: &str = "
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_open ON paper_shares FOR SELECT USING (true);
CREATE POLICY shares_cap ON paper_shares AS RESTRICTIVE FOR SELECT USING (
    'paper_shares:read' = ANY(string_to_array(current_setting('app.bot_list', true), ','))
    OR '*' = ANY(string_to_array(current_setting('app.bot_list', true), ','))
);";

fn gated_registry() -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    registry.declare_session_attributes([
        SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
        SessionAttribute::setting("app.bot_list", SessionAttributeKind::SetAttribute),
    ]);
    registry
}

fn gated_residual(residual: &str) -> Expr {
    parse_expr(&format!(
        "EXISTS (
           SELECT 1
           FROM paper_shares s
           WHERE s.paper_id = papers.id
             AND s.viewer = current_user
             AND {residual}
       )"
    ))
}

/// The residual the row and the caller's gate decide, over the request-gated share table.
fn gated_recognizes(residual: &str) -> String {
    let db = papers_schema(GATED_SHARES);
    let classified = recognize_p4(
        &gated_residual(residual),
        &db,
        &gated_registry(),
        "papers",
        &ExpansionState::new(),
    )
    .expect("a residual the gate decides over a request-gated table is translatable");
    assert_eq!(
        classified.confidence,
        ConfidenceLevel::A,
        "the gate decides the residual, so the recognition is as strong as without it"
    );
    let PatternClass::P4ExistsMembership(membership) = &classified.pattern else {
        panic!(
            "expected an EXISTS membership, got {:?}",
            classified.pattern
        );
    };
    membership
        .extra_predicates
        .sql()
        .expect("the residual rides the tuple query")
}

fn gated_refuses(residual: &str) -> bool {
    recognize_p4(
        &gated_residual(residual),
        &papers_schema(GATED_SHARES),
        &gated_registry(),
        "papers",
        &ExpansionState::new(),
    )
    .is_none()
}

/// A strict comparison against the gated table's aggregate is never true when it is empty.
#[test]
fn a_residual_over_a_request_gated_relation_is_recognized() {
    for residual in [
        "s.weight > (SELECT avg(weight) FROM paper_shares)",
        "s.weight < (SELECT min(weight) FROM paper_shares)",
        "s.weight > (SELECT max(weight) FROM paper_shares)",
        "s.weight < (SELECT sum(weight) FROM paper_shares)",
    ] {
        let sql = gated_recognizes(residual);
        assert!(
            sql.contains("paper_shares"),
            "the gated residual rides the tuple query, got: {sql}"
        );
    }
}

/// `count` on an empty table is `0`, so `count(*) > 0` is never true when it is empty.
#[test]
fn a_count_greater_than_zero_over_a_gated_relation_is_recognized() {
    let sql = gated_recognizes("(SELECT count(*) FROM paper_shares) > 0");
    assert!(sql.contains("count(*)"), "got: {sql}");
}

/// `EXISTS` over an empty table is false, so the residual is never true when it is empty.
#[test]
fn an_exists_over_a_gated_relation_is_recognized() {
    let sql = gated_recognizes("EXISTS (SELECT 1 FROM paper_shares)");
    assert!(sql.contains("EXISTS"), "got: {sql}");
}

/// `count(*) = 0` is true on an empty table, so the caller the gate excludes could read a row.
#[test]
fn a_count_equal_to_zero_over_a_gated_relation_is_refused() {
    assert!(
        gated_refuses("(SELECT count(*) FROM paper_shares) = 0"),
        "count is zero on the empty table, so the residual is true for the excluded caller"
    );
}

/// `NOT EXISTS` over an empty table is true, so the caller the gate excludes could read a row.
#[test]
fn a_not_exists_over_a_gated_relation_is_refused() {
    assert!(
        gated_refuses("NOT EXISTS (SELECT 1 FROM paper_shares)"),
        "NOT EXISTS is true on the empty table, so the residual is true for the excluded caller"
    );
}

/// `COALESCE` of the aggregate with a constant is a value the evaluation cannot place.
#[test]
fn a_coalesce_of_a_gated_aggregate_is_refused() {
    assert!(
        gated_refuses("COALESCE((SELECT avg(weight) FROM paper_shares), 0) > 5"),
        "COALESCE hides whether the table is empty"
    );
}

/// A cast can round a constant, and `0.4::int` is `0`, so `count(*) >= 0.4::int` is true on
/// the empty table even though `0 >= 0.4` is false.
#[test]
fn a_cast_constant_beside_a_gated_aggregate_is_refused() {
    assert!(
        gated_refuses("(SELECT count(*) FROM paper_shares) >= 0.4::int"),
        "the cast decides the comparison, so the empty table cannot be placed"
    );
}

/// Each residual is false or `NULL` once the gated table reads empty, so the caller the
/// gate excludes reads no row through it either.
#[test]
fn residuals_false_on_an_empty_gated_table_are_recognized() {
    for residual in [
        // `IN` over no rows is false.
        "s.paper_id IN (SELECT paper_id FROM paper_shares)",
        // A projection without an aggregate yields no row, so the subquery is `NULL`.
        "s.weight > (SELECT weight FROM paper_shares WHERE viewer = 'x')",
        // `EXISTS` over no rows is false, and false is not true.
        "EXISTS (SELECT 1 FROM paper_shares) = true",
        // `count` of no rows is 0.
        "(SELECT count(*) FROM paper_shares) >= 1",
        "(SELECT count(*) FROM paper_shares) <> 0",
        "(SELECT count(*) FROM paper_shares) < 0",
        // A numeric cast of that 0 is still 0.
        "(SELECT count(*)::int FROM paper_shares) > 0",
        // A row-pure function of no row is no row either.
        "s.weight > (SELECT abs(weight) FROM paper_shares WHERE viewer = 'x')",
    ] {
        let sql = gated_recognizes(residual);
        assert!(sql.contains("paper_shares"), "{residual}: got {sql}");
    }
}

/// Each residual is true once the gated table reads empty, or depends on what the
/// evaluation cannot place, so the caller the gate excludes might read a row.
#[test]
fn residuals_not_proven_false_on_an_empty_gated_table_are_refused() {
    for residual in [
        // `NOT IN` over no rows is true.
        "s.paper_id NOT IN (SELECT paper_id FROM paper_shares)",
        // `count` of no rows is 0, and `0 <= 0` holds.
        "(SELECT count(*) FROM paper_shares) <= 0",
        // A grouped projection yields no row where an ungrouped one yields one.
        "s.weight > (SELECT max(weight) FROM paper_shares GROUP BY viewer)",
        // An aggregate inside arithmetic is not the bare value the evaluation places.
        "(SELECT count(*) + 1 FROM paper_shares) > 1",
        // A cast to text leaves a comparison the evaluation does not place.
        "(SELECT count(*)::text FROM paper_shares) = '0'",
        // A boolean against an integer is a comparison the evaluation does not place.
        "EXISTS (SELECT 1 FROM paper_shares) = 1",
        // `IS NULL` is true on the `NULL` an empty aggregate yields.
        "(SELECT max(weight) FROM paper_shares) IS NULL",
        // `OR` lets the other side decide.
        "(SELECT max(weight) FROM paper_shares) > 1 OR s.weight > 0",
        // A set operation is not a projection the evaluation places.
        "s.weight > (SELECT max(weight) FROM paper_shares UNION SELECT 1)",
        // Two columns are not one value.
        "s.weight > (SELECT max(weight), 1 FROM paper_shares)",
        // A table function is not a plain table.
        "EXISTS (SELECT 1 FROM paper_shares, generate_series(1, 2))",
        // An outer subquery over another table still stands after the inner one empties.
        "s.weight > (SELECT max(cutoff) FROM tiers \
         WHERE cutoff < (SELECT max(weight) FROM paper_shares))",
        // An ungrouped aggregate yields one row on the empty table, so `EXISTS` holds.
        "EXISTS (SELECT count(*) FROM paper_shares)",
        // `HAVING` folds the empty table into one row as well.
        "EXISTS (SELECT 1 FROM paper_shares HAVING true)",
        // That row is `0`, so `IN` finds it.
        "0 IN (SELECT count(*) FROM paper_shares)",
    ] {
        assert!(gated_refuses(residual), "{residual} must be refused");
    }
}

/// A subquery that joins the gated table to another cannot be placed on the empty table.
#[test]
fn a_gated_aggregate_behind_a_join_is_refused() {
    assert!(
        gated_refuses(
            "s.weight > (SELECT avg(weight) \
             FROM paper_shares JOIN papers p ON p.id = paper_shares.paper_id)"
        ),
        "a join over the gated table reads rows the empty-set value cannot place"
    );
}

/// A restrictive policy that reads a row column guards the table rather than gating it.
#[test]
fn a_residual_over_a_row_column_gated_relation_is_refused() {
    let db = papers_schema(
        "ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_open ON paper_shares FOR SELECT USING (true);
CREATE POLICY shares_owner ON paper_shares AS RESTRICTIVE FOR SELECT \
         USING (viewer = current_user);",
    );
    assert!(
        recognize_p4(
            &gated_residual("s.weight > (SELECT avg(weight) FROM paper_shares)"),
            &db,
            &gated_registry(),
            "papers",
            &ExpansionState::new()
        )
        .is_none(),
        "a row-column gate reads the caller's rows, so the residual is not caller-independent"
    );
}

/// A partition read directly is filtered by its own flag, never by its root's.
#[test]
fn a_residual_over_a_child_of_a_row_secured_root_is_recognized() {
    let db = parse_schema(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT);
CREATE TABLE weights(weight INT, region TEXT) PARTITION BY LIST (region);
CREATE TABLE weights_eu PARTITION OF weights FOR VALUES IN ('eu');
ALTER TABLE weights ENABLE ROW LEVEL SECURITY;
",
    )
    .expect("schema should parse");
    let sql = recognized_residual_sql(
        &db,
        &parse_expr(
            "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND s.weight > (SELECT avg(weight) FROM weights_eu)
             )",
        ),
    );
    assert!(
        sql.contains("weights_eu"),
        "the partition is read under its own flag, got: {sql}"
    );
}

/// The root's own flag still governs a query naming the root.
#[test]
fn a_residual_over_a_row_secured_root_is_refused() {
    assert!(
        papers_refuses(
            "CREATE TABLE weights(weight INT, region TEXT) PARTITION BY LIST (region);
CREATE TABLE weights_eu PARTITION OF weights FOR VALUES IN ('eu');
ALTER TABLE weights ENABLE ROW LEVEL SECURITY;",
            "s.weight > (SELECT avg(weight) FROM weights)",
        ),
        "the root carries the policies the query naming it reads under"
    );
}

/// Nothing is proven about a relation the catalog does not carry.
#[test]
fn a_residual_naming_an_unresolvable_relation_is_refused() {
    assert!(
        papers_refuses("", "s.weight > (SELECT avg(weight) FROM elsewhere)"),
        "an unread relation cannot be proven to answer everyone alike"
    );
}

/// Row security is not the only way an answer can depend on who is asking.
#[test]
fn a_residual_whose_subquery_reads_the_caller_is_refused() {
    assert!(
        papers_refuses(
            "",
            "s.weight > (SELECT avg(weight) FROM paper_shares WHERE viewer = current_user)",
        ),
        "an average over the caller's own rows is the caller's average"
    );
}

/// A qualifier does not exempt a zoned column from the session's time zone.
#[test]
fn a_residual_comparing_a_qualified_zoned_column_is_refused() {
    assert!(
        papers_refuses(
            "CREATE TABLE windows(opens_at TIMESTAMPTZ);",
            "s.weight > (SELECT count(*) FROM windows w WHERE w.opens_at > '2020-01-01')",
        ),
        "the session's time zone decides the comparison, qualifier or not"
    );
}

/// A session setting decides a date's rendering and an inexact number's sum.
#[test]
fn a_residual_reading_a_session_rendered_column_is_refused() {
    for (column, residual) in [
        (
            "published_on DATE",
            "(SELECT max(published_on::text) FROM tiers)",
        ),
        ("cutoff DOUBLE PRECISION", "(SELECT avg(cutoff) FROM tiers)"),
    ] {
        let db = parse_schema(&format!(
            r"
CREATE TABLE papers(id UUID PRIMARY KEY);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT);
CREATE TABLE tiers({column});
"
        ))
        .expect("schema should parse");
        let registry = FunctionRegistry::new();
        assert!(
            recognize_p4(
                &parse_expr(&format!(
                    "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND s.weight::text > {residual}
             )"
                )),
                &db,
                &registry,
                "papers",
                &ExpansionState::new()
            )
            .is_none(),
            "{column} is not answered alike for every caller"
        );
    }
}

/// An exact numeric cast is the same number whoever computes it.
#[test]
fn a_residual_casting_between_exact_numbers_is_recognized() {
    let db = papers_schema("");
    let sql = recognized_residual_sql(
        &db,
        &parse_expr(
            "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND (s.weight)::numeric > (SELECT avg(weight) FROM paper_shares)
             )",
        ),
    );
    assert!(
        sql.contains("avg(weight)"),
        "the dumped cast keeps the exemption, got: {sql}"
    );
}

/// A bare name two joined relations both carry binds to neither.
#[test]
fn a_residual_naming_a_column_two_joined_relations_share_is_refused() {
    let db = parse_schema(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT);
CREATE TABLE tiers(cutoff INT, band TEXT);
CREATE TABLE bands(band TEXT, floor INT);
",
    )
    .expect("schema should parse");
    assert!(
        papers_refuses_on(
            &db,
            "s.weight > (SELECT max(cutoff) FROM tiers, bands WHERE band = 'gold')",
        ),
        "an ambiguous name is bound by neither relation"
    );
}

/// An alias carrying a dot still names the membership scan.
#[test]
fn a_residual_correlating_through_a_dotted_alias_is_refused() {
    let db = parse_schema(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY, category TEXT);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT, category TEXT);
CREATE TABLE tiers(cutoff INT);
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();
    assert!(
        recognize_p4(
            &parse_expr(
                r#"EXISTS (
               SELECT 1
               FROM paper_shares "m.v"
               WHERE "m.v".paper_id = papers.id
                 AND "m.v".viewer = current_user
                 AND "m.v".weight > (
                   SELECT max(cutoff) FROM tiers WHERE cutoff < "m.v".category
                 )
             )"#
            ),
            &db,
            &registry,
            "papers",
            &ExpansionState::new()
        )
        .is_none(),
        "the generated query gives the scan no alias, whatever the alias contains"
    );
}

/// A sample is not the relation the flag was proven about.
#[test]
fn a_residual_sampling_its_relation_is_refused() {
    assert!(
        papers_refuses(
            "",
            "s.weight > (SELECT avg(weight) FROM paper_shares TABLESAMPLE BERNOULLI (50))",
        ),
        "a sample is not the relation the flag was proven about"
    );
}

/// A guarded table whose name carries a dot is still the guarded table.
#[test]
fn a_residual_correlating_to_a_dotted_guarded_table_is_refused() {
    let db = parse_schema(
        r#"
CREATE TABLE "papers.v1"(id UUID PRIMARY KEY, category TEXT);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT);
CREATE TABLE tiers(cutoff INT, category TEXT);
"#,
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();
    assert!(
        recognize_p4(
            &parse_expr(
                r#"EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = "papers.v1".id
                 AND s.viewer = current_user
                 AND s.weight > (
                   SELECT max(cutoff) FROM tiers WHERE category = "papers.v1".category
                 )
             )"#
            ),
            &db,
            &registry,
            r#""papers.v1""#,
            &ExpansionState::new()
        )
        .is_none(),
        "the generated query scans the membership table alone, whatever the name contains"
    );
}

/// An unplaceable function's body may read anything.
#[test]
fn a_residual_calling_an_unknown_function_is_refused() {
    assert!(
        papers_refuses(
            "",
            "s.weight > (SELECT house_cutoff(weight) FROM paper_shares)"
        ),
        "a function the crate cannot place may read the caller"
    );
}

/// `LIMIT` picks a row per evaluation rather than per identity.
#[test]
fn a_residual_whose_subquery_limits_its_rows_is_refused() {
    assert!(
        papers_refuses("", "s.weight > (SELECT weight FROM paper_shares LIMIT 1)"),
        "an unordered single row is whichever row the evaluation reached"
    );
}

/// The nested relation is spelled the way the scan spells its own table.
#[test]
fn a_recognized_residual_qualifies_its_nested_relation() {
    let db = papers_schema("");
    let sql = recognized_residual_sql(&db, &average_weight_membership());
    assert!(
        sql.contains(r#"FROM "public"."paper_shares""#),
        "the residual names the relation as the scan names it, got: {sql}"
    );
}

/// The exemption widens which relations may be read, not which expressions.
#[test]
fn a_relation_free_residual_the_row_cannot_decide_is_still_refused() {
    assert!(
        papers_refuses("", "house_cutoff(s.weight)"),
        "an unplaceable function is no more decidable for reading no table"
    );
}

/// The generated query does not scan the guarded table a nested reference names.
#[test]
fn a_residual_correlating_to_the_guarded_row_is_refused() {
    let db = parse_schema(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY, category TEXT);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT);
CREATE TABLE tiers(cutoff INT, category TEXT);
",
    )
    .expect("schema should parse");
    assert!(
        papers_refuses_on(
            &db,
            "s.weight > (SELECT max(cutoff) FROM tiers WHERE category = papers.category)",
        ),
        "the generated query scans the membership table alone, so the guarded row is absent"
    );
}

/// A bare name only the guarded row carries binds outward.
#[test]
fn a_residual_binding_a_bare_column_to_the_guarded_row_is_refused() {
    let db = parse_schema(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY, category TEXT);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT);
CREATE TABLE tiers(cutoff INT);
",
    )
    .expect("schema should parse");
    assert!(
        papers_refuses_on(
            &db,
            "s.weight > (SELECT max(cutoff) FROM tiers WHERE category = 'gold')",
        ),
        "only the guarded row carries the name, and the generated query never scans it"
    );
}

/// A bare name the membership row carries resolves alike in both queries.
#[test]
fn a_residual_correlating_to_the_membership_row_is_recognized() {
    let db = parse_schema(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY, category TEXT);
CREATE TABLE paper_shares(paper_id UUID, viewer TEXT, weight INT, category TEXT);
CREATE TABLE tiers(cutoff INT);
",
    )
    .expect("schema should parse");
    let sql = recognized_residual_sql(
        &db,
        &parse_expr(
            "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND s.weight > (SELECT max(cutoff) FROM tiers WHERE cutoff < category)
             )",
        ),
    );
    assert!(
        sql.contains("category"),
        "the membership row's column keeps its correlation, got: {sql}"
    );
}

#[test]
fn recognize_p4_allows_single_source_unqualified_extra_predicate() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.doc_id = docs.id
                 AND doc_members.user_id = current_user
                 AND role = 'admin'
             )",
    );

    let classified = recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new())
        .expect("expected P4 match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership(ExistsMembership { extra_predicates, .. })
            if extra_predicates
                .sql()
                .is_some_and(|s| s.to_ascii_lowercase().contains("role = 'admin'"))
    ));
}

#[test]
fn recognize_p4_in_subquery_handles_negation_and_projection_alias() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let negated = parse_expr(
        "doc_id NOT IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
    );
    assert!(recognize_p4_in_subquery(
        &negated,
        &db,
        &registry,
        "docs",
        PolicyCommand::Select,
        &ExpansionState::new()
    )
    .is_none());

    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id AS projected_doc
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
    );
    let classified = recognize_p4_in_subquery(
        &in_subquery,
        &db,
        &registry,
        "docs",
        PolicyCommand::Select,
        &ExpansionState::new(),
    )
    .expect("expected match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P4ExistsMembership(ExistsMembership {
            pairs,
            user_column,
            ..
        }) if matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id")
            && user_column == "user_id"
    ));
}

#[test]
fn recognize_p4_in_subquery_refuses_the_clickhouse_global_modifier() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
    );
    let Expr::In {
        expr,
        target: target @ InTarget::Subquery(_),
        negated,
        ..
    } = &in_subquery
    else {
        panic!("expected an IN subquery");
    };
    let global = Expr::In {
        expr: expr.clone(),
        target: target.clone(),
        negated: *negated,
        global: true,
    };
    assert!(
        recognize_p4_in_subquery(
            &global,
            &db,
            &registry,
            "docs",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "a ClickHouse GLOBAL IN is not PostgreSQL's membership subquery"
    );
}

#[test]
fn recognize_p4_in_subquery_refuses_a_subquery_reading_the_guarded_table() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE dm.user_id = auth_current_user_id()
             )",
    );

    assert!(
        recognize_p4_in_subquery(
            &in_subquery,
            &db,
            &registry,
            "docs",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "a subquery scanning 'docs' cannot name the guarded row"
    );
}

#[test]
fn recognize_p4_in_subquery_fails_closed_for_non_membership_distinct_predicates() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let clauses = [
        "d.id IS DISTINCT FROM dm.member_id",
        "d.id IS NOT DISTINCT FROM dm.member_id",
    ];

    for clause in clauses {
        let in_subquery = parse_expr(&format!(
            "doc_id IN (
                   SELECT dm.doc_id
                   FROM docs d
                   JOIN doc_members dm ON dm.doc_id = d.id
                   WHERE dm.user_id = current_user
                     AND {clause}
                 )"
        ));

        assert!(
            recognize_p4_in_subquery(
                &in_subquery,
                &db,
                &registry,
                "docs",
                PolicyCommand::Select,
                &ExpansionState::new()
            )
            .is_none(),
            "non-membership DISTINCT predicate `{clause}` should fail closed for P4 IN-subquery"
        );
    }
}

#[test]
fn recognize_p4_in_subquery_fails_closed_for_function_wrapped_non_membership_ref() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let in_subquery = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM docs d
               JOIN doc_members dm ON dm.doc_id = d.id
               WHERE dm.user_id = current_user
                 AND lower(d.id::text) = lower(dm.member_id::text)
             )",
    );

    assert!(
        recognize_p4_in_subquery(
            &in_subquery,
            &db,
            &registry,
            "docs",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "function-wrapped non-membership reference should fail closed for P4 IN-subquery"
    );
}

#[test]
fn recognize_p4_paths_remain_parity_aligned_for_membership_shape() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm
               WHERE dm.doc_id = docs.id
                 AND dm.user_id = auth_current_user_id()
                 AND dm.role = 'admin'
             )",
    );
    let in_subquery = parse_expr(
        "id IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
                 AND dm.role = 'admin'
             )",
    );

    let exists = recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new())
        .expect("expected EXISTS match");
    let in_sub = recognize_p4_in_subquery(
        &in_subquery,
        &db,
        &registry,
        "docs",
        PolicyCommand::Select,
        &ExpansionState::new(),
    )
    .expect("expected IN-subquery match");

    let (exists_join_table, exists_pairs, exists_user_column, exists_extra_predicates) =
        match exists.pattern {
            PatternClass::P4ExistsMembership(ExistsMembership {
                join_table,
                pairs,
                user_column,
                extra_predicates,
                ..
            }) => (join_table, pairs, user_column, extra_predicates),
            other => panic!("expected P4 EXISTS classification, got: {other:?}"),
        };

    let (in_join_table, in_pairs, in_user_column, in_extra_predicates) = match in_sub.pattern {
        PatternClass::P4ExistsMembership(ExistsMembership {
            join_table,
            pairs,
            user_column,
            extra_predicates,
            ..
        }) => (join_table, pairs, user_column, extra_predicates),
        other => panic!("expected P4 IN-subquery classification, got: {other:?}"),
    };

    assert_eq!(exists_join_table, in_join_table);
    assert_eq!(exists_pairs, in_pairs);
    assert_eq!(exists_user_column, in_user_column);
    assert_eq!(exists_extra_predicates, in_extra_predicates);
}

#[test]
fn recognize_p4_paths_fail_closed_on_ambiguous_sources() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE memberships(doc_id UUID, user_id UUID);
",
    )
    .expect("schema should parse");
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM memberships a
               JOIN memberships b ON b.doc_id = a.doc_id
               WHERE a.user_id = auth_current_user_id()
             )",
    );
    let in_subquery = parse_expr(
        "id IN (
               SELECT a.doc_id
               FROM memberships a
               JOIN memberships b ON b.doc_id = a.doc_id
               WHERE a.user_id = auth_current_user_id()
             )",
    );

    assert!(
        recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none(),
        "ambiguous EXISTS sources should fail closed"
    );
    assert!(
        recognize_p4_in_subquery(
            &in_subquery,
            &db,
            &registry,
            "docs",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "ambiguous IN-subquery sources should fail closed"
    );
}

#[test]
fn recognize_p10_and_p6_cover_non_matching_variants() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let p10_true = parse_expr("TRUE");
    assert!(matches!(
        recognize_p10_constant_bool(&p10_true, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
            ..
        })
    ));
    let p10_not_true = parse_expr("NOT TRUE");
    assert!(matches!(
        recognize_p10_constant_bool(&p10_not_true, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P10ConstantBool(ConstantBool { value: false }),
            ..
        })
    ));
    let p10_cast = parse_expr("CAST(TRUE AS BOOLEAN)");
    assert!(matches!(
        recognize_p10_constant_bool(&p10_cast, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
            ..
        })
    ));

    let p10_not_bool = parse_expr("1");
    assert!(recognize_p10_constant_bool(&p10_not_bool, &db, &registry).is_none());

    let p6_false = parse_expr("FALSE = is_public");
    assert!(recognize_p6(&p6_false, &db, &registry).is_none());
    let p6_is_true = parse_expr("is_public IS TRUE");
    assert!(matches!(
        recognize_p6(&p6_is_true, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P6BooleanFlag(BooleanFlag { column, .. }),
            ..
        }) if column == "is_public"
    ));
    let p6_is_not_false = parse_expr("is_public IS NOT FALSE");
    assert!(matches!(
        recognize_p6(&p6_is_not_false, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P6BooleanFlag(BooleanFlag { column, .. }),
            ..
        }) if column == "is_public"
    ));

    let p6_ident = parse_expr("published");
    assert!(matches!(
        recognize_p6(&p6_ident, &db, &registry),
        Some(ClassifiedExpr {
            pattern: PatternClass::P6BooleanFlag(BooleanFlag { column, .. }),
            ..
        }) if column == "published"
    ));

    let p6_non_public = parse_expr("private_flag");
    assert!(recognize_p6(&p6_non_public, &db, &registry).is_none());
}

#[test]
fn extractor_helpers_and_attribute_detection_work_for_edge_cases() {
    let fun = parse_expr("auth_current_user_id()");
    assert_eq!(
        extract_function_name(&fun).as_deref(),
        Some("auth_current_user_id")
    );
    let schema_fun = parse_expr(r#""auth"."uid"()"#);
    assert_eq!(
        extract_function_name(&schema_fun).as_deref(),
        Some(r#""auth"."uid""#)
    );

    let id_expr = parse_expr("owner_id");
    assert!(extract_function_name(&id_expr).is_none());

    let qualified = parse_expr("docs.owner_id");
    assert_eq!(
        extract_column_name(&qualified)
            .as_ref()
            .map(ColumnName::as_str),
        Some("owner_id")
    );
    assert_eq!(
        extract_qualified_column(&qualified),
        Some((
            Some("docs".to_string()),
            ColumnName::from_stored("owner_id")
        ))
    );

    let simple = parse_expr("owner_id");
    assert_eq!(
        extract_qualified_column(&simple),
        Some((None, ColumnName::from_stored("owner_id")))
    );

    let attr = parse_expr("priority >= 3");
    assert_eq!(
        is_attribute_check(&attr).as_ref().map(ColumnName::as_str),
        Some("priority")
    );

    let user_attr = parse_expr("user_id = 'x'");
    assert!(is_attribute_check(&user_attr).is_none());

    let non_literal = parse_expr("status = other_status");
    assert!(is_attribute_check(&non_literal).is_none());
}

#[test]
fn membership_column_extraction_requires_explicit_user_predicate() {
    // WHERE clause has only a role predicate, no current-user equality.
    // Without an explicit user predicate, extract_membership_columns must
    // return None to avoid "exists any admin" false positives.
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE dm.role = 'admin'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "member_id".to_string(),
        "role".to_string(),
    ];

    assert!(
        membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry).is_none(),
        "membership without user predicate must fail closed"
    );
}

#[test]
fn table_extractors_cover_non_table_and_alias_paths() {
    let table_select = parse_select("SELECT dm.doc_id AS projected FROM doc_members dm");
    let from = &table_select.from[0];
    let (table_name, alias) =
        table_factor_parts(&from.relation).expect("table factor should resolve");
    assert_eq!(table_name, "doc_members");
    assert_eq!(alias.as_deref(), Some("dm"));

    let derived_select = parse_select("SELECT x.id FROM (SELECT 1 AS id) x WHERE x.id = 1");
    let derived_from = &derived_select.from[0];
    assert!(
        table_factor_parts(&derived_from.relation).is_none(),
        "derived table should not resolve to a table name"
    );
}

#[test]
fn current_user_expr_detection_supports_identity_casts_and_nested() {
    let registry = registry_with_role_level();
    let nested = parse_expr("(auth_current_user_id())");
    let casted = parse_expr("CAST(auth_current_user_id() AS TEXT)");
    let own_type = parse_expr("CAST(auth_current_user_id() AS UUID)");
    let renamed = parse_expr("CAST(auth_current_user_id() AS INTEGER)");
    let keyword = parse_expr("current_user");
    let quoted_keyword = parse_expr("\"user\"");
    let schema_qualified_keyword_fn = parse_expr("auth.user()");
    let other = parse_expr("owner_id");

    assert!(is_current_user_expr(&nested, &registry));
    assert!(is_current_user_expr(&casted, &registry));
    assert!(
        is_current_user_expr(&own_type, &registry),
        "a cast to the type the accessor returns changes nothing"
    );
    assert!(
        !is_current_user_expr(&renamed, &registry),
        "an accessor declares no identity cast, so a cast to another type renames the caller"
    );
    assert!(is_current_user_expr(&keyword, &registry));
    assert!(
        !is_current_user_expr(&quoted_keyword, &registry),
        "quoted keyword identifier must not be treated as current-user accessor"
    );
    assert!(
        !is_current_user_expr(&schema_qualified_keyword_fn, &registry),
        "schema-qualified function names that normalize to SQL keywords are not accessors"
    );
    assert!(!is_current_user_expr(&other, &registry));
}

#[test]
fn is_attribute_check_supports_literal_on_left_and_not_equal_operator() {
    let reverse_literal = parse_expr("3 <= priority");
    assert_eq!(
        is_attribute_check(&reverse_literal)
            .as_ref()
            .map(ColumnName::as_str),
        Some("priority")
    );

    let not_equal = parse_expr("status <> 'draft'");
    assert_eq!(
        is_attribute_check(&not_equal)
            .as_ref()
            .map(ColumnName::as_str),
        Some("status")
    );
}

#[test]
fn extract_integer_value_supports_nested_cast_and_signed_literals() {
    let nested_cast = parse_expr("CAST((2) AS INTEGER)");
    assert_eq!(extract_integer_value(&nested_cast), Some(2));

    let signed = parse_expr("-2");
    assert_eq!(extract_integer_value(&signed), Some(-2));
}

#[test]
fn is_attribute_check_accepts_casted_literal_values() {
    let expr = parse_expr("status = CAST('draft' AS TEXT)");
    assert_eq!(
        is_attribute_check(&expr).as_ref().map(ColumnName::as_str),
        Some("status")
    );
}

#[test]
fn strip_qualifier_from_expr_strips_join_alias_and_handles_quoted_identifiers() {
    let mut expr = parse_expr("dm.status = 'active'");
    strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
    assert_eq!(
        expr.to_string(),
        "status = 'active'",
        "alias-qualified column should be stripped"
    );

    // `stored_ident_name` strips quotes before the comparison, so `"dm"` matches alias `dm` and is stripped.
    let mut quoted_expr = parse_expr(r#""dm"."status" = 'active'"#);
    strip_qualifier_from_expr(&mut quoted_expr, "doc_members", Some("dm"));
    assert_eq!(
        quoted_expr.to_string(),
        r#""status" = 'active'"#,
        "quoted alias should be stripped; column keeps its quote style"
    );

    // Table-name qualifying: `doc_members.status` → `status`
    let mut tbl_expr = parse_expr("doc_members.status = 1");
    strip_qualifier_from_expr(&mut tbl_expr, "doc_members", None);
    assert_eq!(
        tbl_expr.to_string(),
        "status = 1",
        "table-name qualified column should be stripped"
    );
}

#[test]
fn extract_membership_columns_detects_reversed_predicates() {
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE auth_current_user_id() = dm.user_id
               AND docs.id = dm.doc_id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    let (pairs, user_column, _) =
        membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry)
            .expect("reversed predicates should still infer membership columns");
    assert!(
        matches!(pairs.as_slice(), [pair]
            if pair.join_column == "doc_id" && pair.outer_column == "id"),
        "got: {pairs:?}"
    );
    assert_eq!(user_column, "user_id");
}

#[test]
fn recognize_p1_rejects_non_numeric_threshold_expressions() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let bool_threshold = parse_expr("role_level(auth_current_user_id(), id) >= TRUE");
    assert!(recognize_p1(&bool_threshold, &db, &registry, PolicyCommand::Select).is_none());

    let non_value_threshold = parse_expr("role_level(auth_current_user_id(), id) >= owner_id");
    assert!(recognize_p1(&non_value_threshold, &db, &registry, PolicyCommand::Select).is_none());
}

#[test]
fn recognize_p2_ignores_non_literal_in_list_items() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let expr = parse_expr("role_level(auth_current_user_id(), id) IN (owner_id)");
    assert!(recognize_p2(&expr, &db, &registry).is_none());
}

#[test]
fn recognize_p1_p2_reject_when_no_current_user_argument() {
    // `get_owner_role(owner_id, id)`, both arguments are resource columns, not
    // current_user.  Without a current-user arg the function cannot express P1/P2
    // semantics (it would be a resource-attribute comparison, not a user-level check).
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let p1_no_user = parse_expr("role_level(owner_id, id) >= 2");
    assert!(
        recognize_p1(&p1_no_user, &db, &registry, PolicyCommand::Select).is_none(),
        "P1 must reject role_level without a current-user argument"
    );

    let p2_no_user = parse_expr("role_level(owner_id, id) IN ('admin', 'editor')");
    assert!(
        recognize_p2(&p2_no_user, &db, &registry).is_none(),
        "P2 must reject role_level without a current-user argument"
    );
}

#[test]
fn recognize_p3_accepts_function_on_left_side() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let expr = parse_expr("auth_current_user_id() = owner_id");
    let classified = recognize_p3(&expr, &db, &registry).expect("expected ownership match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"
    ));
}

#[test]
fn recognize_p4_and_in_subquery_fail_when_membership_columns_cannot_be_inferred() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE odd_members(alpha text, beta text);
",
    )
    .expect("schema should parse");
    let registry = registry_with_role_level();

    let exists_expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM odd_members
               WHERE odd_members.alpha = 'x'
             )",
    );
    assert!(recognize_p4(&exists_expr, &db, &registry, "docs", &ExpansionState::new()).is_none());

    let in_subquery_expr = parse_expr(
        "id IN (
               SELECT odd_members.alpha
               FROM odd_members
               WHERE odd_members.beta = 'x'
             )",
    );
    assert!(recognize_p4_in_subquery(
        &in_subquery_expr,
        &db,
        &registry,
        "docs",
        PolicyCommand::Select,
        &ExpansionState::new()
    )
    .is_none());
}

#[test]
fn recognize_p4_exists_without_outer_row_correlation_is_not_per_row_membership() {
    // EXISTS (SELECT 1 FROM members WHERE user_id = current_user), with no predicate
    // tying members to the outer row. Reading it as P4 would key the membership by
    // `doc_id` and grant every doc the user belongs to, which is the over-grant this
    // test was written for. It is now translated through a holder instead, which grants
    // every row of the guarded table together, exactly as PostgreSQL does.
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID NOT NULL, user_id UUID NOT NULL);
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();

    let uncorrelated = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members
               WHERE doc_members.user_id = current_user
             )",
    );
    let classified = recognize_p4(
        &uncorrelated,
        &db,
        &registry,
        "docs",
        &ExpansionState::new(),
    )
    .expect("an uncorrelated membership check translates through a holder");
    assert!(
        matches!(
            classified.pattern,
            PatternClass::P13UncorrelatedMembership(UncorrelatedMembership { .. })
        ),
        "it must not become a per-row membership, got {:?}",
        classified.pattern
    );
}

#[test]
fn recognize_p4_and_in_subquery_fail_for_unknown_or_unsupported_subqueries() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let unknown_table = parse_expr(
        "EXISTS (
               SELECT 1
               FROM ghost_members
               WHERE ghost_members.doc_id = docs.id
             )",
    );
    assert!(recognize_p4(
        &unknown_table,
        &db,
        &registry,
        "docs",
        &ExpansionState::new()
    )
    .is_none());

    let unsupported = parse_expr(
        "doc_id IN (
               (SELECT dm.doc_id FROM doc_members dm)
               UNION
               (SELECT dm.doc_id FROM doc_members dm)
             )",
    );
    assert!(recognize_p4_in_subquery(
        &unsupported,
        &db,
        &registry,
        "docs",
        PolicyCommand::Select,
        &ExpansionState::new()
    )
    .is_none());
}

#[test]
fn recognize_p4_paths_fail_closed_for_values_subqueries() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    let exists_values = parse_expr("EXISTS (VALUES (1))");
    let in_values = parse_expr("id IN (VALUES (1))");

    assert!(recognize_p4(
        &exists_values,
        &db,
        &registry,
        "docs",
        &ExpansionState::new()
    )
    .is_none());
    assert!(recognize_p4_in_subquery(
        &in_values,
        &db,
        &registry,
        "docs",
        PolicyCommand::Select,
        &ExpansionState::new()
    )
    .is_none());
}

#[test]
fn recognize_p4_multi_from_requires_user_predicate() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();

    // No user predicate in EXISTS → must fail closed even when the membership
    // table is present alongside a second resource table.
    let exists_no_user = parse_expr(
        "EXISTS (
               SELECT 1
               FROM doc_members dm, docs d
               WHERE dm.doc_id = d.id
             )",
    );
    assert!(
        recognize_p4(
            &exists_no_user,
            &db,
            &registry,
            "docs",
            &ExpansionState::new()
        )
        .is_none(),
        "EXISTS with no user predicate is an 'exists any row' false positive"
    );

    // An IN-subquery with an explicit user predicate is accepted, correlated by the
    // column the projection names.
    let in_with_user = parse_expr(
        "doc_id IN (
               SELECT dm.doc_id
               FROM doc_members dm
               WHERE dm.user_id = auth_current_user_id()
             )",
    );
    assert!(matches!(
        recognize_p4_in_subquery(&in_with_user, &db, &registry, "docs", PolicyCommand::Select, &ExpansionState::new()),
        Some(ClassifiedExpr {
            pattern: PatternClass::P4ExistsMembership(ExistsMembership { ref join_table, .. }),
            ..
        }) if join_table.to_string() == "doc_members"
    ));
}

#[test]
fn recognize_p6_covers_visible_branch_and_non_literal_binary_case() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();

    let visible = parse_expr("visible = TRUE");
    let classified = recognize_p6(&visible, &db, &registry).expect("expected visible match");
    assert!(matches!(
        &classified.pattern,
        PatternClass::P6BooleanFlag(BooleanFlag { column, .. }) if column == "visible"
    ));

    let non_literal = parse_expr("is_public = owner_id");
    assert!(recognize_p6(&non_literal, &db, &registry).is_none());
}

#[test]
fn extract_membership_columns_covers_right_join_side_and_extra_predicates() {
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE auth_current_user_id() = dm.user_id
               AND docs.id = doc_id
               AND dm.role > 'a'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    let (pairs, user_column, extras) =
        membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry)
            .expect("columns should still be inferred");
    assert!(
        matches!(pairs.as_slice(), [pair]
            if pair.join_column == "doc_id" && pair.outer_column == "id"),
        "got: {pairs:?}"
    );
    assert_eq!(user_column, "user_id");
    assert!(extras.sql().is_some_and(|s| s.contains("role > 'a'")));
}

#[test]
fn extract_membership_columns_returns_none_without_user_predicate() {
    // No WHERE clause at all → no user predicate → must fail closed.
    let select = parse_select("SELECT dm.doc_id FROM doc_members dm");
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    assert!(
        membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry).is_none(),
        "membership without any WHERE must fail closed"
    );
}

#[test]
fn membership_column_extraction_requires_user_predicate_not_just_role() {
    // WHERE has only a role predicate and no current-user equality:
    // even with a tenant_id column present, must still fail closed.
    let select = parse_select(
        "SELECT dm.doc_id
             FROM doc_members dm
             WHERE dm.role = 'admin'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "tenant_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    assert!(
        membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry).is_none(),
        "membership with only a role predicate must fail closed"
    );
}

#[test]
fn membership_column_extraction_fails_when_fk_remains_ambiguous() {
    let select = parse_select(
        "SELECT m.alpha_id
             FROM memberships m
             WHERE m.role = 'admin'",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "alpha_id".to_string(),
        "beta_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];

    let extracted = membership_columns(&select, "memberships", Some("m"), &cols, "docs", &registry);
    assert!(
        extracted.is_none(),
        "ambiguous membership FK should fail closed"
    );
}

/// Extraction accumulates every correlated pair. Whether the pairing names one
/// parent object is decided by `resolve_membership_pairing`, pinned through
/// `recognize_p4` in the composite-key tests.
#[test]
fn extract_membership_columns_accumulates_every_correlated_pair() {
    let select = parse_select(
        "SELECT m.doc_id
             FROM doc_members m
             WHERE m.user_id = auth_current_user_id()
               AND m.doc_id = docs.id
               AND m.project_id = docs.project_id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "project_id".to_string(),
        "user_id".to_string(),
    ];

    let (pairs, _, _) =
        membership_columns(&select, "doc_members", Some("m"), &cols, "docs", &registry)
            .expect("both correlated pairs are accumulated");
    assert!(
        matches!(pairs.as_slice(), [first, second]
            if first.join_column == "doc_id"
                && first.outer_column == "id"
                && second.join_column == "project_id"
                && second.outer_column == "project_id"),
        "got: {pairs:?}"
    );
}

#[test]
fn recognize_p5_accepts_unqualified_parent_column_when_unambiguous() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(project_uuid UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(project_uuid));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM projects p
               WHERE project_uuid = tasks.project_id
                 AND p.owner_id = current_user
             )",
    );

    let classified = recognize_p5(
        &expr,
        &db,
        &registry,
        "tasks",
        PolicyCommand::Select,
        &ExpansionState::new(),
    )
    .expect("expected P5 classification");
    assert!(matches!(
        classified.pattern,
        PatternClass::P5ParentInheritance(ParentInheritance { ref parent_table, ref fk_column, .. })
            if parent_table.to_string() == "projects" && fk_column == "project_id"
    ));
}

/// A joined parent source used to classify as `P5`, ignoring what the join does.
///
/// It filters: a project with no tag row is dropped by the inner join, so `PostgreSQL`
/// hides a task under it while the model, which only ever saw `owner_id = current_user`,
/// grants it. Measured on `postgres:18` over this schema before the refusal landed:
/// alice reads `t-tagged` alone, while the loader wrote `projects:p-bare#owner@user:alice`
/// and the bridge that reaches `t-bare` through it.
///
/// `project_tags.project_id REFERENCES projects(project_uuid)` does not save it. That key
/// says every tag row has a project, not that every project has a tag row, and the second
/// is what the join needs.
#[test]
fn recognize_p5_refuses_a_joined_source_the_parent_does_not_key() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(project_uuid UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE project_tags(project_id UUID REFERENCES projects(project_uuid), tag TEXT);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(project_uuid));
",
    )
    .expect("schema should parse");
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
        "EXISTS (
               SELECT 1
               FROM projects p
               JOIN project_tags pt ON pt.project_id = p.project_uuid
               WHERE p.project_uuid = tasks.project_id
                 AND p.owner_id = current_user
             )",
    );

    assert!(
        recognize_p5(
            &expr,
            &db,
            &registry,
            "tasks",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "the join drops a project with no tags, so the parent's rule is not the whole rule"
    );
}

#[test]
fn is_attribute_check_recognizes_like_ilike_in_list_and_null_forms() {
    // LIKE and ILIKE are now attribute checks (Phase 3g).
    let like_expr = parse_expr("status LIKE 'draft%'");
    assert_eq!(
        is_attribute_check(&like_expr),
        Some(ColumnName::from_stored("status"))
    );

    let ilike_name_expr = parse_expr("name ILIKE '%admin%'");
    assert_eq!(
        is_attribute_check(&ilike_name_expr),
        Some(ColumnName::from_stored("name"))
    );

    // IN list with all literals is an attribute check.
    let in_expr = parse_expr("status IN ('active', 'pending')");
    assert_eq!(
        is_attribute_check(&in_expr),
        Some(ColumnName::from_stored("status"))
    );

    // IS NULL / IS NOT NULL are attribute checks.
    let is_null_expr = parse_expr("deleted_at IS NULL");
    assert_eq!(
        is_attribute_check(&is_null_expr),
        Some(ColumnName::from_stored("deleted_at"))
    );

    // Negated forms are NOT attribute checks (they restrict, not grant).
    let negated_in = parse_expr("status NOT IN ('active', 'pending')");
    assert!(
        is_attribute_check(&negated_in).is_none(),
        "negated IN list should not be an attribute check"
    );

    // User-related columns are excluded.
    let user_like = parse_expr("user_id LIKE '%admin%'");
    assert!(
        is_attribute_check(&user_like).is_none(),
        "user-related column should not be classified as attribute"
    );
}

#[test]
fn parse_select_panics_for_non_query_and_non_select_body() {
    let non_query = std::panic::catch_unwind(|| parse_select("DELETE FROM doc_members"));
    assert!(non_query.is_err());

    let non_select = std::panic::catch_unwind(|| parse_select("VALUES (1)"));
    assert!(non_select.is_err());
}

#[test]
fn pg_has_role_rejects_non_string_role_value() {
    let registry = FunctionRegistry::new();
    let expr = parse_expr("pg_has_role(current_user, 42, 'MEMBER')");
    assert!(recognize_pg_has_role(&expr, &registry).is_none());
}

#[test]
fn pg_has_role_rejects_wrong_arg_count() {
    let registry = FunctionRegistry::new();
    // Single arg
    let expr = parse_expr("pg_has_role('admin')");
    assert!(recognize_pg_has_role(&expr, &registry).is_none());
    // Four args
    let expr = parse_expr("pg_has_role(current_user, 'admin', 'MEMBER', 'extra')");
    assert!(recognize_pg_has_role(&expr, &registry).is_none());
}

#[test]
fn role_accessor_comparison_reversed_eq() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    // reversed: 'authenticated' = auth.role()
    let expr = parse_expr("'authenticated' = auth.role()");
    let classified = recognize_role_accessor_comparison(&expr, &registry);
    assert!(classified.is_some());
    let c = classified.unwrap();
    assert!(matches!(
        c.pattern,
        PatternClass::P2RoleNameInList(RoleNameInList {
            ref role_names, ..
        }) if role_names == &["authenticated"]
    ));
}

#[test]
fn role_accessor_comparison_rejects_non_string_literal() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    let expr = parse_expr("auth.role() = 42");
    assert!(recognize_role_accessor_comparison(&expr, &registry).is_none());
}

#[test]
fn role_accessor_comparison_rejects_column_rhs() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    let expr = parse_expr("auth.role() = some_column");
    assert!(recognize_role_accessor_comparison(&expr, &registry).is_none());
}

#[test]
fn role_accessor_in_list_rejects_non_string_items() {
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();
    // All non-string items -> empty role_names -> returns None
    let expr = parse_expr("auth.role() IN (42, 99)");
    assert!(recognize_role_accessor_comparison(&expr, &registry).is_none());
}

#[test]
fn recognize_p5_rejects_negated_exists() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
",
    )
    .unwrap();
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
            "NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user)",
        );
    assert!(recognize_p5(
        &expr,
        &db,
        &registry,
        "tasks",
        PolicyCommand::Select,
        &ExpansionState::new()
    )
    .is_none());
}

#[test]
fn is_negated_boolean_flag_is_false_and_is_not_true() {
    let is_false = parse_expr("is_public IS FALSE");
    assert_eq!(
        is_negated_boolean_flag(&is_false),
        Some("is_public".to_string())
    );

    let is_not_true = parse_expr("is_published IS NOT TRUE");
    assert_eq!(
        is_negated_boolean_flag(&is_not_true),
        Some("is_published".to_string())
    );

    // Non-public-flag column -> None
    let non_flag = parse_expr("status IS FALSE");
    assert!(is_negated_boolean_flag(&non_flag).is_none());
}

#[test]
fn function_has_current_user_arg_returns_false_for_non_function() {
    let registry = FunctionRegistry::new();
    let expr = parse_expr("42");
    assert!(!function_has_current_user_arg(&expr, &registry));
}

#[test]
fn function_has_current_user_arg_returns_false_for_no_args() {
    let registry = FunctionRegistry::new();
    let expr = parse_expr("my_func()");
    assert!(!function_has_current_user_arg(&expr, &registry));
}

/// One value is one projection. `(SELECT a, b FROM t)` is refused for reading a table
/// before the count is even looked at, so the count needs its own case.
#[test]
fn current_user_accessor_name_subquery_with_multiple_projections_returns_none() {
    for sql in ["(SELECT a, b FROM t)", "(SELECT a, b)", "(SELECT *)"] {
        let expr = parse_expr(sql);
        assert!(
            current_user_accessor_name(&expr).is_none(),
            "`{sql}` projects more than one value, so it names nobody"
        );
    }
}

/// A set operation is two queries, so which row it yields is not the projection of one.
#[test]
fn current_user_accessor_name_set_operation_subquery_returns_none() {
    let mut registry = FunctionRegistry::new();
    registry.trust_current_user_setting_keys(["app.user_id"]);
    let expr = parse_expr(
        "(SELECT current_setting('app.user_id') UNION SELECT current_setting('app.tenant_id'))",
    );

    assert!(current_user_accessor_name(&expr).is_none());
    assert!(
        !is_current_user_expr(&expr, &registry),
        "a union of two settings names neither of them"
    );
}

#[test]
fn strip_qualifier_from_expr_handles_unary_cast_is_null_is_not_null_in_list() {
    // UnaryOp: NOT dm.active
    let mut unary = parse_expr("NOT dm.active");
    strip_qualifier_from_expr(&mut unary, "doc_members", Some("dm"));
    assert!(!unary.to_string().contains("dm."));

    // Cast: dm.role::text
    let mut cast = parse_expr("CAST(dm.role AS text)");
    strip_qualifier_from_expr(&mut cast, "doc_members", Some("dm"));
    assert!(!cast.to_string().contains("dm."));

    // IsNull: dm.deleted_at IS NULL
    let mut is_null = parse_expr("dm.deleted_at IS NULL");
    strip_qualifier_from_expr(&mut is_null, "doc_members", Some("dm"));
    assert!(!is_null.to_string().contains("dm."));

    // IsNotNull: dm.active IS NOT NULL
    let mut is_not_null = parse_expr("dm.active IS NOT NULL");
    strip_qualifier_from_expr(&mut is_not_null, "doc_members", Some("dm"));
    assert!(!is_not_null.to_string().contains("dm."));

    // IN list: dm.role IN ('admin', 'editor')
    let mut in_list = parse_expr("dm.role IN ('admin', 'editor')");
    strip_qualifier_from_expr(&mut in_list, "doc_members", Some("dm"));
    assert!(!in_list.to_string().contains("dm."));
}

#[test]
fn strip_qualifier_from_expr_handles_boolean_is_variants() {
    let mut is_true = parse_expr("dm.active IS TRUE");
    strip_qualifier_from_expr(&mut is_true, "doc_members", Some("dm"));
    assert!(!is_true.to_string().contains("dm."));

    let mut is_not_false = parse_expr("dm.active IS NOT FALSE");
    strip_qualifier_from_expr(&mut is_not_false, "doc_members", Some("dm"));
    assert!(!is_not_false.to_string().contains("dm."));

    let mut is_false = parse_expr("dm.active IS FALSE");
    strip_qualifier_from_expr(&mut is_false, "doc_members", Some("dm"));
    assert!(!is_false.to_string().contains("dm."));

    let mut is_not_true = parse_expr("dm.active IS NOT TRUE");
    strip_qualifier_from_expr(&mut is_not_true, "doc_members", Some("dm"));
    assert!(!is_not_true.to_string().contains("dm."));
}

#[test]
fn strip_qualifier_from_expr_handles_function_wrapped_identifiers() {
    let mut expr = parse_expr("lower(dm.role) = 'admin'");
    strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
    let rendered = expr.to_string().to_ascii_lowercase();
    assert!(
        rendered.contains("lower(role) = 'admin'"),
        "expected stripped function-wrapped predicate, got: {rendered}"
    );
    assert!(
        !rendered.contains("dm."),
        "function-wrapped identifier should have qualifier stripped, got: {rendered}"
    );
}

#[test]
fn predicate_references_other_table_recursive_arms() {
    // IN list with other-table reference
    let inlist = parse_expr("other.col IN ('a', 'b')");
    assert!(predicate_references_other_table(
        &inlist,
        "members",
        Some("m")
    ));

    // UnaryOp with other-table reference
    let unary = parse_expr("NOT other.active");
    assert!(predicate_references_other_table(
        &unary,
        "members",
        Some("m")
    ));

    // IsNull with other-table reference
    let is_null = parse_expr("other.deleted_at IS NULL");
    assert!(predicate_references_other_table(
        &is_null,
        "members",
        Some("m")
    ));

    // IsNotNull with other-table reference
    let is_not_null = parse_expr("other.active IS NOT NULL");
    assert!(predicate_references_other_table(
        &is_not_null,
        "members",
        Some("m")
    ));

    // IsDistinctFrom with other-table reference
    let is_distinct = parse_expr("other.col IS DISTINCT FROM m.col");
    assert!(predicate_references_other_table(
        &is_distinct,
        "members",
        Some("m")
    ));

    // IsNotDistinctFrom with other-table reference
    let is_not_distinct = parse_expr("other.col IS NOT DISTINCT FROM m.col");
    assert!(predicate_references_other_table(
        &is_not_distinct,
        "members",
        Some("m")
    ));

    // Function wrapper with other-table reference
    let function_wrapped = parse_expr("lower(other.col) = lower(m.col)");
    assert!(predicate_references_other_table(
        &function_wrapped,
        "members",
        Some("m")
    ));

    // Same table reference -> false
    let same = parse_expr("m.status IN ('a', 'b')");
    assert!(!predicate_references_other_table(
        &same,
        "members",
        Some("m")
    ));
}

#[test]
fn extract_parent_join_columns_rejects_non_eq_predicate() {
    let pred = parse_expr("p.id > tasks.project_id");
    let outer_cols = vec!["id".to_string(), "project_id".to_string()];
    let parent_cols = vec!["id".to_string(), "owner_id".to_string()];
    assert!(extract_parent_join_columns(
        &pred,
        "tasks",
        &outer_cols,
        "projects",
        Some("p"),
        &parent_cols
    )
    .is_none());
}

#[test]
fn extract_parent_join_columns_right_is_parent_left_is_outer() {
    let pred = parse_expr("tasks.project_id = p.id");
    let outer_cols = vec!["id".to_string(), "project_id".to_string()];
    let parent_cols = vec!["id".to_string(), "owner_id".to_string()];
    let result = extract_parent_join_columns(
        &pred,
        "tasks",
        &outer_cols,
        "projects",
        Some("p"),
        &parent_cols,
    );
    assert!(result.is_some());
    let (fk, pk) = result.unwrap();
    assert_eq!(fk, "project_id");
    assert_eq!(pk, "id");
}

#[test]
fn diagnose_p4_membership_ambiguity_in_subquery_form() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)");
    let result =
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs", &ExpansionState::new());
    assert!(
        result.is_none(),
        "a single membership source is unambiguous"
    );
}

#[test]
fn diagnose_p5_parent_inheritance_ambiguity_returns_none_for_non_exists() {
    let db = parse_schema(
        r"CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);",
    )
    .unwrap();
    // Not an EXISTS expression at all
    let expr = parse_expr("tasks.project_id = current_user");
    assert!(diagnose_p5_parent_inheritance_ambiguity(
        &expr,
        &db,
        &FunctionRegistry::new(),
        "tasks",
        PolicyCommand::Select,
        &ExpansionState::new()
    )
    .is_none());
}

#[test]
fn extract_membership_columns_via_join_on_clause() {
    // FK correlation in ON clause, user predicate in WHERE.
    // This exercises the ON-clause FK extraction path.
    let select = parse_select(
        "SELECT m.doc_id FROM doc_members m
             JOIN doc_labels l ON m.doc_id = docs.id
             WHERE m.user_id = auth_current_user_id()
               AND m.role >= 2",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result = membership_columns(&select, "doc_members", Some("m"), &cols, "docs", &registry);
    assert!(
        result.is_some(),
        "ON-clause fk_col and WHERE user_col should be extracted"
    );
    let (pairs, user, _extras) = result.unwrap();
    assert!(matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id"));
    assert_eq!(user, "user_id");
}

#[test]
fn recognize_array_patterns_rejects_non_current_user_any() {
    let registry = FunctionRegistry::new();
    // some_column = ANY(array_col) -- not current_user
    let expr = parse_expr("some_column = ANY(tags)");
    assert!(recognize_array_patterns(&expr, &registry).is_none());
}

// 1. extract_integer_value: Nested, Cast, UnaryPlus recursion
#[test]
fn extract_integer_value_nested_wrapping() {
    // Nested: (42) → 42
    let nested = parse_expr("(42)");
    assert_eq!(extract_integer_value(&nested), Some(42));
}

#[test]
fn extract_integer_value_cast_wrapping() {
    // Cast: CAST(7 AS INTEGER) → 7
    let cast = parse_expr("CAST(7 AS INTEGER)");
    assert_eq!(extract_integer_value(&cast), Some(7));
}

#[test]
fn extract_integer_value_unary_plus() {
    // UnaryPlus: +42 → 42
    let plus = parse_expr("+42");
    assert_eq!(extract_integer_value(&plus), Some(42));
}

#[test]
fn extract_integer_value_nested_combinations() {
    // Nested inside Cast: CAST((5) AS INT) → 5
    let nested_in_cast = parse_expr("CAST((5) AS INT)");
    assert_eq!(extract_integer_value(&nested_in_cast), Some(5));

    // UnaryPlus inside Nested: (+3) → 3
    let plus_in_nested = parse_expr("(+3)");
    assert_eq!(extract_integer_value(&plus_in_nested), Some(3));

    // UnaryMinus inside Nested: (-10) → -10
    let minus_in_nested = parse_expr("(-10)");
    assert_eq!(extract_integer_value(&minus_in_nested), Some(-10));

    // Non-integer expression → None
    let non_int = parse_expr("'hello'");
    assert_eq!(extract_integer_value(&non_int), None);
}

// 2. extract_table_alias_from_table_factor: non-Table variant
#[test]
fn extract_table_alias_from_table_factor_returns_none_for_derived() {
    // Parse a SELECT with a derived table (subquery in FROM).
    let select = parse_select("SELECT x.id FROM (SELECT 1 AS id) AS x");
    let from = &select.from[0];
    // The relation is a Derived subquery, not a Table.
    assert!(
        table_factor_parts(&from.relation).is_none(),
        "Derived subquery should return None from table_factor_parts"
    );
}

// 3. join_on_expr: non-matching JoinOperator variant returns None
//    and non-On JoinConstraint returns None
#[test]
fn join_on_expr_returns_none_for_non_standard_join_operators() {
    use sqlparser::ast::JoinOperator;

    // Cross Apply / non-standard variant → None
    let cross_apply = JoinOperator::CrossApply;
    assert!(
        join_on_expr(&cross_apply).is_none(),
        "CrossApply should return None from join_on_expr"
    );

    let outer_apply = JoinOperator::OuterApply;
    assert!(
        join_on_expr(&outer_apply).is_none(),
        "OuterApply should return None from join_on_expr"
    );
}

#[test]
fn join_on_expr_returns_none_for_using_constraint() {
    use sqlparser::ast::{JoinConstraint, JoinOperator};

    // JoinConstraint::Using → None
    let using_constraint = JoinOperator::Inner(JoinConstraint::Using(vec![]));
    assert!(
        join_on_expr(&using_constraint).is_none(),
        "USING constraint should return None from join_on_expr"
    );

    // JoinConstraint::Natural → None
    let natural_constraint = JoinOperator::Inner(JoinConstraint::Natural);
    assert!(
        join_on_expr(&natural_constraint).is_none(),
        "Natural constraint should return None from join_on_expr"
    );

    // JoinConstraint::None → None
    let none_constraint = JoinOperator::Inner(JoinConstraint::None);
    assert!(
        join_on_expr(&none_constraint).is_none(),
        "None constraint should return None from join_on_expr"
    );
}

// 4. extract_membership_columns: ON-clause user detection
//    and ON-clause FK detection with right_is_join path
#[test]
fn extract_membership_columns_on_clause_user_left_join_right_current_user() {
    // ON clause: dm.user_id = auth_current_user_id() (left is join, right is current_user)
    let select = parse_select(
        "SELECT dm.doc_id FROM doc_labels l
             JOIN doc_members dm ON dm.user_id = auth_current_user_id()
                 AND dm.doc_id = docs.id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result = membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry);
    assert!(
        result.is_some(),
        "ON-clause user_col (left=join) should be extracted"
    );
    let (pairs, user, _extras) = result.unwrap();
    assert!(matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id"));
    assert_eq!(user, "user_id");
}

#[test]
fn extract_membership_columns_on_clause_user_right_join_left_current_user() {
    // ON clause: auth_current_user_id() = dm.user_id (right is join, left is current_user)
    let select = parse_select(
        "SELECT dm.doc_id FROM doc_labels l
             JOIN doc_members dm ON auth_current_user_id() = dm.user_id
                 AND dm.doc_id = docs.id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result = membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry);
    assert!(
        result.is_some(),
        "ON-clause user_col (right=join) should be extracted"
    );
    let (pairs, user, _extras) = result.unwrap();
    assert!(matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id"));
    assert_eq!(user, "user_id");
}

#[test]
fn extract_membership_columns_on_clause_fk_right_is_join() {
    // ON clause: d.id = dm.doc_id (right is join, left is not join)
    let select = parse_select(
        "SELECT dm.doc_id FROM doc_labels l
             JOIN doc_members dm ON docs.id = dm.doc_id
             WHERE dm.user_id = auth_current_user_id()",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result = membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry);
    assert!(
        result.is_some(),
        "ON-clause FK (right_is_join) should be extracted"
    );
    let (pairs, user, _extras) = result.unwrap();
    assert!(matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id"));
    assert_eq!(user, "user_id");
}

#[test]
fn extract_membership_columns_where_right_is_join_fk_conflict_returns_none() {
    // WHERE clause has two different FK columns both with right_is_join:
    //   docs.id = dm.doc_id AND projects.pid = dm.project_id
    // The first sets fk_col = "doc_id", the second conflicts → return None.
    let select = parse_select(
        "SELECT dm.doc_id FROM doc_members dm
             WHERE dm.user_id = auth_current_user_id()
               AND docs.id = dm.doc_id
               AND projects.pid = dm.member_id",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "member_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result = membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry);
    assert!(
        result.is_none(),
        "conflicting right_is_join FK columns should return None"
    );
}

#[test]
fn flatten_and_predicates_recognizes_and_chains_and_non_and_leaves() {
    for (sql, expected, msg) in [
        (
            "x = 1 AND y = 2 AND z = 3",
            3usize,
            "a AND b AND c should flatten to 3 predicates",
        ),
        (
            "a = 1 AND b = 2 AND c = 3 AND d = 4",
            4,
            "a AND b AND c AND d should flatten to 4 predicates",
        ),
        (
            "x = 1 OR y = 2",
            1,
            "OR should not be flattened, yielding 1 leaf",
        ),
    ] {
        let expr = parse_expr(sql);
        let mut out = Vec::new();
        flatten_and_predicates(&expr, &mut out);
        assert_eq!(out.len(), expected, "{msg}");
    }
}

#[test]
fn strip_qualifier_from_expr_handles_nested_and_distinct_forms() {
    for sql in [
        "(dm.status)",
        "dm.status IS DISTINCT FROM 'archived'",
        "dm.status IS NOT DISTINCT FROM 'archived'",
    ] {
        let mut expr = parse_expr(sql);
        strip_qualifier_from_expr(&mut expr, "doc_members", Some("dm"));
        let result = expr.to_string();
        assert!(
            !result.contains("dm."),
            "qualifier should be stripped from `{sql}`, got: {result}"
        );
    }
}

/// A qualifier is a stored identifier, so it answers for a scan exactly when `PostgreSQL`
/// would resolve it there.
#[test]
fn qualifier_matches_table_compares_stored_identifiers() {
    // The terminal part of a schema-qualified table is what a column qualifier names.
    assert!(qualifier_matches_table("docs", "public.docs", None));
    assert!(!qualifier_matches_table("other", "public.docs", None));
    // An alias replaces the table's own name for its scope.
    assert!(qualifier_matches_table("d", "public.docs", Some("d")));
    assert!(!qualifier_matches_table("docs", "public.docs", Some("d")));
    // An unquoted spelling folded on the way in, so it answers for the folded table.
    assert!(qualifier_matches_table("m", "public.m", None));
    // A quoted spelling kept its case, so it is a different identifier.
    assert!(!qualifier_matches_table("M", "public.m", None));
    assert!(!qualifier_matches_table("m", r#"public."M""#, None));
    assert!(qualifier_matches_table("M", r#"public."M""#, None));
    // The same rule for an alias, which is where the guarded row's column was read as
    // the membership row's.
    assert!(!qualifier_matches_table("M", "public.members", Some("m")));
    assert!(!qualifier_matches_table("m", "public.members", Some("M")));
    assert!(qualifier_matches_table("M", "public.members", Some("M")));
}

// 9. diagnose_p4_membership_ambiguity: IN subquery form
#[test]
fn diagnose_p4_membership_ambiguity_in_subquery_with_multiple_sources() {
    // Two membership-like tables make the IN subquery match ambiguously.
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID, member_id UUID);
CREATE TABLE doc_editors(doc_id UUID, user_id UUID);
",
    )
    .unwrap();
    let registry = FunctionRegistry::new();

    // IN subquery form with two FROM sources
    let expr = parse_expr(
        "id IN (
                SELECT dm.doc_id
                FROM doc_members dm, doc_editors de
                WHERE dm.user_id = current_user
                  AND de.user_id = current_user
                  AND dm.doc_id = docs.id
                  AND de.doc_id = docs.id
            )",
    );
    let result =
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs", &ExpansionState::new());
    // Either "multiple candidate" or "could not infer" is a diagnostic.
    assert!(
        result.is_some(),
        "IN subquery with multiple membership sources should be diagnosed as ambiguous"
    );
}

#[test]
fn diagnose_p4_membership_ambiguity_returns_none_for_non_exists_non_insubquery() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr = parse_expr("owner_id = current_user");
    assert!(diagnose_p4_membership_ambiguity(
        &expr,
        &db,
        &registry,
        "docs",
        &ExpansionState::new()
    )
    .is_none());
}

// 10. diagnose_p5_parent_inheritance_ambiguity: negated, non-Select, conflicting join
#[test]
fn diagnose_p5_returns_none_for_negated_exists() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
",
    )
    .unwrap();
    let expr = parse_expr(
            "NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user)",
        );
    assert!(
        diagnose_p5_parent_inheritance_ambiguity(
            &expr,
            &db,
            &FunctionRegistry::new(),
            "tasks",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "negated EXISTS should return None"
    );
}

#[test]
fn diagnose_p5_returns_none_for_non_select_body() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);
",
    )
    .unwrap();
    let expr = parse_expr("EXISTS (VALUES (1))");
    assert!(
        diagnose_p5_parent_inheritance_ambiguity(
            &expr,
            &db,
            &FunctionRegistry::new(),
            "tasks",
            PolicyCommand::Select,
            &ExpansionState::new()
        )
        .is_none(),
        "non-Select body should return None"
    );
}

#[test]
fn diagnose_p5_returns_conflicting_join_message() {
    // When the same parent source has two different FK columns from the outer table,
    let db = parse_schema(
            r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, code UUID UNIQUE, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id), project_code UUID REFERENCES projects(code));
",
        )
        .unwrap();
    let expr = parse_expr(
        "EXISTS (
                SELECT 1 FROM projects p
                WHERE p.id = tasks.project_id
                  AND p.code = tasks.project_code
                  AND p.owner_id = current_user
            )",
    );
    let result = diagnose_p5_parent_inheritance_ambiguity(
        &expr,
        &db,
        &FunctionRegistry::new(),
        "tasks",
        PolicyCommand::Select,
        &ExpansionState::new(),
    );
    assert!(
        result.is_some(),
        "conflicting join columns should produce a diagnostic"
    );
    assert!(
        result.unwrap().contains("conflicting"),
        "diagnostic should mention conflicting"
    );
}

// 11. analyze_p5_parent_inheritance: empty sources
#[test]
fn analyze_p5_returns_none_for_empty_sources() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);
",
    )
    .unwrap();
    // We cannot parse "SELECT 1 WHERE ..." without FROM in standard SQL,
    // but we can construct via parse_select with a derived table that has no relation sources.
    // Actually, sqlparser does allow `SELECT 1 WHERE true`.
    let select = parse_select("SELECT 1");
    let result = analyze_p5_parent_inheritance(&select, &db, "tasks");
    assert!(result.is_none(), "empty sources should return None");
}

// 11b. analyze_p5: no inner predicate is the bare delegation
/// A correlated `EXISTS` on the parent with no predicate of its own says "you may do this
/// over a parent row you can already see". P5 gates on the parent's `can_select` anyway,
/// so the inherited rule is the constant and the gate is the whole requirement.
///
/// This replaces `analyze_p5_skips_candidate_with_only_join_predicates_and_no_inner`,
/// which pinned the over-denial: inventory row 4 is exactly this shape and connetto
/// writes it verbatim.
#[test]
fn analyze_p5_reads_a_bare_correlation_as_delegation_to_the_parent() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
",
    )
    .unwrap();
    let expr = parse_expr("EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id)");
    let result = recognize_p5(
        &expr,
        &db,
        &FunctionRegistry::new(),
        "tasks",
        PolicyCommand::Select,
        &ExpansionState::new(),
    );
    let Some(classified) = result else {
        panic!("a bare correlation delegates to the parent's own rule");
    };
    assert!(
        matches!(
            &classified.pattern,
            PatternClass::P5ParentInheritance(ParentInheritance { parent_table, fk_column, inner_pattern })
                if parent_table.to_string() == "projects"
                    && fk_column == "project_id"
                    && matches!(
                        inner_pattern.pattern,
                        PatternClass::P10ConstantBool(ConstantBool { value: true })
                    )
        ),
        "the parent's gate is the whole rule, got {:?}",
        classified.pattern
    );
    assert_eq!(
        classified.confidence,
        ConfidenceLevel::A,
        "nothing here is guessed"
    );
}

/// The parent's gate is the whole rule, so a parent enforcing nothing offers none and the
/// delegation is refused rather than emitted against a type the model never declares.
#[test]
fn analyze_p5_refuses_a_bare_correlation_to_an_unrestricted_parent() {
    let db = parse_schema(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
",
    )
    .unwrap();
    let expr = parse_expr("EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id)");
    assert!(
        recognize_p5(
            &expr,
            &db,
            &FunctionRegistry::new(),
            "tasks",
            PolicyCommand::Select,
            &ExpansionState::new(),
        )
        .is_none(),
        "an unrestricted parent has no gate to delegate to"
    );
}

/// A bare correlation is taken at the policy's word, declared key or not: the policy
/// names the parent and says which columns join, and nothing else competes for that
/// reading, because a membership lookup always carries a predicate naming the caller.
///
/// This replaces `analyze_p5_still_refuses_a_bare_correlation_with_no_declared_key`,
/// which pinned the refusal. Requiring the key there refused a shape whose meaning the
/// policy had already stated, and connetto declares no such key.
#[test]
fn analyze_p5_reads_a_bare_correlation_without_a_declared_key() {
    let db = parse_schema(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
",
    )
    .unwrap();
    let expr = parse_expr("EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id)");
    assert!(
        matches!(
            recognize_p5(
                &expr,
                &db,
                &FunctionRegistry::new(),
                "tasks",
                PolicyCommand::Select,
                &ExpansionState::new(),
            )
            .map(|classified| classified.pattern),
            Some(PatternClass::P5ParentInheritance(ParentInheritance { ref parent_table, .. }))
                if parent_table.to_string() == "projects"
        ),
        "the policy states the join, so it is the evidence"
    );
}

/// Where the subquery carries a rule of its own, the declared key still decides: that
/// shape competes with a lookup in a side table naming the caller, and the key is what
/// tells the two apart. Removing it there made parent inheritance claim shapes the
/// membership analysis correctly refuses as ambiguous.
#[test]
fn analyze_p5_still_requires_a_declared_key_when_the_subquery_has_its_own_rule() {
    let db = parse_schema(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID);
",
    )
    .unwrap();
    let expr = parse_expr(
        "EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id \
         AND p.owner_id = current_user)",
    );
    assert!(
        recognize_p5(
            &expr,
            &db,
            &FunctionRegistry::new(),
            "tasks",
            PolicyCommand::Select,
            &ExpansionState::new(),
        )
        .is_none(),
        "a rule of its own competes with a membership lookup, so the key still decides"
    );
}

// 12. function_has_current_user_arg: non-List args
#[test]
fn function_has_current_user_arg_returns_false_for_function_with_no_arg_list() {
    use sqlparser::ast::{Function, FunctionArguments, ObjectName};
    let registry = FunctionRegistry::new();
    // Build a Function AST node with FunctionArguments::None
    let func = Expr::Function(Function {
        name: ObjectName::from(vec![sqlparser::ast::Ident::new("my_func")]),
        args: FunctionArguments::None,
        filter: None,
        null_treatment: None,
        over: None,
        within_group: Vec::new(),
        parameters: FunctionArguments::None,
        uses_odbc_syntax: false,
    });
    assert!(
        !function_has_current_user_arg(&func, &registry),
        "FunctionArguments::None should return false"
    );
}

// 13. recognize_pg_has_role: non-List args
#[test]
fn recognize_pg_has_role_returns_none_for_no_arg_list() {
    use sqlparser::ast::{Function, FunctionArguments, ObjectName};
    let registry = FunctionRegistry::new();
    // Build a pg_has_role function with FunctionArguments::None
    let func_expr = Expr::Function(Function {
        name: ObjectName::from(vec![sqlparser::ast::Ident::new("pg_has_role")]),
        args: FunctionArguments::None,
        filter: None,
        null_treatment: None,
        over: None,
        within_group: Vec::new(),
        parameters: FunctionArguments::None,
        uses_odbc_syntax: false,
    });
    assert!(
        recognize_pg_has_role(&func_expr, &registry).is_none(),
        "pg_has_role with FunctionArguments::None should return None"
    );
}

/// A `WHERE` that spells the caller in any comparison references it, a bare
/// `current_user` references it too, and a selection without a `WHERE` references nobody.
#[test]
fn selection_references_current_user_across_its_where_clause_spellings() {
    let registry = FunctionRegistry::new();
    for (sql, references, note) in [
        (
            "SELECT 1 FROM doc_members WHERE user_id IS NOT DISTINCT FROM current_user",
            true,
            "IS NOT DISTINCT FROM current_user should be detected",
        ),
        (
            "SELECT 1 FROM doc_members WHERE user_id IS DISTINCT FROM current_user",
            true,
            "IS DISTINCT FROM current_user should be detected",
        ),
        (
            "SELECT 1 FROM doc_members WHERE current_user",
            true,
            "bare current_user in WHERE should be detected via catch-all",
        ),
        (
            "SELECT 1 FROM doc_members",
            false,
            "no WHERE clause should return false",
        ),
    ] {
        let select = parse_select(sql);
        assert_eq!(
            selection_references_current_user(&select, &registry),
            references,
            "{note}"
        );
    }
}

/// The same caller comparison written in both `ON` and `WHERE` is one condition.
#[test]
fn extract_membership_columns_keeps_a_repeated_identical_member_comparison() {
    let select = parse_select(
        "SELECT dm.doc_id FROM doc_labels l
             JOIN doc_members dm ON dm.user_id = auth_current_user_id()
                 AND dm.doc_id = docs.id
             WHERE dm.user_id = auth_current_user_id()",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    let result = membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry);
    let (pairs, user, _) = result.expect("one condition written twice is still the shape");
    assert!(matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id"));
    assert_eq!(user, "user_id");
}

/// Two columns compared to the caller are two conditions, and a membership names one
/// member column, so keeping either alone would grant on half the policy.
#[test]
fn extract_membership_columns_refuses_two_member_columns() {
    let select = parse_select(
        "SELECT dm.doc_id FROM doc_members dm
             WHERE dm.doc_id = docs.id
               AND dm.user_id = auth_current_user_id()
               AND dm.role = auth_current_user_id()",
    );
    let registry = registry_with_role_level();
    let cols = vec![
        "doc_id".to_string(),
        "user_id".to_string(),
        "role".to_string(),
    ];
    assert!(
        membership_columns(&select, "doc_members", Some("dm"), &cols, "docs", &registry).is_none()
    );
}

// Additional: diagnose_p4 for EXISTS with a non-Select body
#[test]
fn diagnose_p4_membership_ambiguity_exists_non_select_body() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr = parse_expr("EXISTS (VALUES (1))");
    assert!(
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs", &ExpansionState::new())
            .is_none(),
        "EXISTS with non-Select body should return None"
    );
}

// Additional: diagnose_p4 negated EXISTS returns _ => None
#[test]
fn diagnose_p4_membership_ambiguity_negated_exists() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr = parse_expr(
        "NOT EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );
    assert!(
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs", &ExpansionState::new())
            .is_none(),
        "negated EXISTS should return None from diagnose_p4"
    );
}

// Additional: diagnose_p4 IN subquery negated → falls to _ => None
#[test]
fn diagnose_p4_membership_ambiguity_negated_in_subquery() {
    let db = db_with_docs_and_members();
    let registry = FunctionRegistry::new();
    let expr =
        parse_expr("id NOT IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)");
    assert!(
        diagnose_p4_membership_ambiguity(&expr, &db, &registry, "docs", &ExpansionState::new())
            .is_none(),
        "negated IN subquery should return None"
    );
}

// ── Gap 6: temporal predicates ──────────────────────────────────────────

#[test]
fn is_attribute_check_handles_now_comparison() {
    let expr = parse_expr("valid_until > now()");
    assert_eq!(
        is_attribute_check(&expr).as_ref().map(ColumnName::as_str),
        Some("valid_until"),
        "now() should be accepted as a temporal literal"
    );
}

#[test]
fn is_attribute_check_handles_current_timestamp() {
    let expr = parse_expr("created_at <= current_timestamp");
    assert_eq!(
        is_attribute_check(&expr).as_ref().map(ColumnName::as_str),
        Some("created_at"),
    );
}

#[test]
fn residual_predicate_extracts_a_temporal_request() {
    let conjunct = residual_predicate(&parse_expr("expires_at > now()"));
    let request = conjunct
        .request
        .expect("a clock comparison is completed by the request, not the row");
    assert_eq!(request.column.as_str(), "expires_at");
    assert_eq!(request.operator, AttributeOperator::Gt);
    assert_eq!(request.request_value, RequestValue::StatementTimestamp);
    assert!(
        conjunct.guard.is_none(),
        "the clock is nobody's, so no row guard decides it"
    );
}

#[test]
fn residual_predicate_keeps_a_literal_conjunct_as_a_row_guard() {
    let conjunct = residual_predicate(&parse_expr("role = 'admin'"));
    assert!(
        conjunct.request.is_none(),
        "a literal comparison names no request value"
    );
    assert!(matches!(conjunct.guard, Some(ResidualGuard::Compare(_))));
}

#[test]
fn residual_predicate_keeps_a_literal_list_as_a_row_guard() {
    let conjunct = residual_predicate(&parse_expr("role IN ('editor', 'admin')"));
    let Some(ResidualGuard::Compare(predicate)) = conjunct.guard else {
        panic!("a literal list is row data, got {:?}", conjunct.guard);
    };
    assert_eq!(
        predicate.test,
        AttributeTest::In(vec![
            AttributeLiteral::Text("admin".to_string()),
            AttributeLiteral::Text("editor".to_string()),
        ])
    );
}

#[test]
fn a_list_no_gate_may_carry_yields_no_literal_predicate() {
    for sql in [
        "owner_id IN ('alice', 'bob')",
        "status = ANY (ARRAY[]::text[])",
    ] {
        assert!(
            attribute_literal_predicate(&parse_expr(sql)).is_none(),
            "`{sql}`"
        );
    }
}

#[test]
fn residual_predicates_split_requests_from_the_where_they_leave_behind() {
    let residual = ResidualPredicates::new(vec![
        residual_predicate(&parse_expr("role = 'admin'")),
        residual_predicate(&parse_expr("expires_at > now()")),
    ]);
    let decidable = residual
        .decidable()
        .expect("a guard and a request are both decidable off the row and the clock");
    assert_eq!(decidable.guards.len(), 1, "the role check is the one guard");
    assert_eq!(decidable.requests.len(), 1, "the clock is the one request");
    assert_eq!(decidable.requests[0].column.as_str(), "expires_at");
    assert_eq!(
        residual.sql_excluding_requests().as_deref(),
        Some("role = 'admin'"),
        "only the clock leaves the WHERE, since it moves into the condition"
    );
    assert_eq!(
        residual.requests().len(),
        1,
        "the clock is the residual's one request"
    );
}

#[test]
fn residual_predicates_refuse_to_decide_a_pure_sql_conjunct() {
    let residual = ResidualPredicates::new(vec![
        residual_predicate(&parse_expr("expires_at > now()")),
        residual_predicate(&parse_expr("weight > other_weight")),
    ]);
    assert!(
        residual.decidable().is_none(),
        "a column-to-column comparison only SQL can evaluate keeps the shape joined"
    );
}

// ── Gap 3: COALESCE/NULLIF → P3 ────────────────────────────────────────

#[test]
fn coalesce_wrapped_ownership_classified_as_p3_confidence_b() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr =
        parse_expr("COALESCE(owner_id, '00000000-0000-0000-0000-000000000000') = current_user");
    let classified = recognize_p3(&expr, &db, &registry);
    assert!(
        matches!(&classified, Some(c) if matches!(&c.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id")),
        "COALESCE-wrapped column should classify as P3, got: {classified:?}"
    );
    assert_eq!(
        classified.unwrap().confidence,
        ConfidenceLevel::B,
        "COALESCE wrapping should cap confidence at B"
    );
}

#[test]
fn nullif_wrapped_ownership_refuses() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("NULLIF(owner_id, '') = current_user");
    let classified = recognize_p3(&expr, &db, &registry);
    assert!(
        classified.is_none(),
        "the NULLIF sentinel excludes a principal a raw-column grant would readmit, got: {classified:?}"
    );
}

/// `PostgreSQL` does not care which side of the comparison the caller sits on, and a
/// column reached through a default is still that column on either side.
#[test]
fn coalesce_wrapped_ownership_classified_as_p3_with_the_caller_on_the_left() {
    let db = db_with_docs_and_members();
    let registry = registry_with_role_level();
    let expr = parse_expr("current_user = COALESCE(owner_id, '')");
    let classified = recognize_p3(&expr, &db, &registry);
    assert!(
        matches!(&classified, Some(c) if matches!(&c.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id")),
        "the operand order says nothing about who owns the row, got: {classified:?}"
    );
    assert_eq!(
        classified.unwrap().confidence,
        ConfidenceLevel::B,
        "COALESCE wrapping caps confidence whichever side it is on"
    );
}

// ── A field of the caller's value is not the caller ────────────────────

/// `sub` inside a token is an identity, and so is `tenant`. Nothing in the expression
/// says which one the caller is, and the pattern keeps only a column name, so the field
/// selector would vanish and the model would call that column's values people.
#[test]
fn a_field_read_out_of_an_accessor_is_not_the_caller() {
    for sql in [
        "current_setting('request.jwt.claims')::json->>'sub'",
        "auth.jwt()->'user_metadata'->>'id'",
        "auth.jwt()#>>'{user_metadata,id}'",
    ] {
        let expr = parse_expr(sql);
        assert!(
            current_user_accessor_name(&expr).is_none(),
            "`{sql}` reads a field of the caller's value, not the caller"
        );
    }
}

/// The refusal holds however the accessor was named, so one shape has one answer.
#[test]
fn a_field_read_is_refused_for_a_registered_accessor_and_a_named_key_alike() {
    let db = db_with_docs_and_members();
    let mut registered = FunctionRegistry::new();
    registered
        .load_from_json(r#"{"current_setting": {"kind":"current_user_accessor","returns":"text"}}"#)
        .unwrap();
    let mut keyed = FunctionRegistry::new();
    keyed.trust_current_user_setting_keys(["request.jwt.claims"]);

    let expr = parse_expr("owner_id = current_setting('request.jwt.claims')::json->>'sub'");
    for (how, registry) in [("registered function", &registered), ("named key", &keyed)] {
        assert!(
            recognize_p3(&expr, &db, registry).is_none(),
            "{how}: a field of the value is not the value"
        );
    }
}

// ── Gap 8: IS DISTINCT FROM ───────────────────────────────────────────

#[test]
fn is_attribute_check_handles_is_not_distinct_from() {
    let expr = parse_expr("status IS NOT DISTINCT FROM 'active'");
    assert_eq!(
        is_attribute_check(&expr).as_ref().map(ColumnName::as_str),
        Some("status"),
    );
}

#[test]
fn is_attribute_check_handles_is_distinct_from() {
    let expr = parse_expr("status IS DISTINCT FROM 'deleted'");
    assert_eq!(
        is_attribute_check(&expr).as_ref().map(ColumnName::as_str),
        Some("status"),
    );
}

// ── Gap 5: BETWEEN ───────────────────────────────────────────────────

#[test]
fn is_attribute_check_handles_between() {
    let expr = parse_expr("priority BETWEEN 1 AND 10");
    assert_eq!(
        is_attribute_check(&expr).as_ref().map(ColumnName::as_str),
        Some("priority"),
    );
}

#[test]
fn is_attribute_check_rejects_negated_between() {
    let expr = parse_expr("priority NOT BETWEEN 1 AND 10");
    assert!(
        is_attribute_check(&expr).is_none(),
        "negated BETWEEN should not match"
    );
}

#[test]
fn is_attribute_check_between_with_temporal_bounds() {
    let expr = parse_expr("created_at BETWEEN '2024-01-01' AND now()");
    assert_eq!(
        is_attribute_check(&expr).as_ref().map(ColumnName::as_str),
        Some("created_at"),
    );
}

#[test]
fn is_literal_or_temporal_rejects_arbitrary_functions() {
    // random_func() should NOT be accepted as temporal
    let expr = parse_expr("col > random_func()");
    assert!(
        is_attribute_check(&expr).is_none(),
        "arbitrary functions should not match as temporal"
    );
}

/// A qual that is not true rejects the row, so the question is whether the expression can
/// ever be true. Only what the crate can prove counts: it folds no arithmetic and reads no
/// data, so `1 = 2` and a comparison against a literal are both live as far as it knows.
#[test]
fn is_constantly_false_propagates_over_the_boolean_tree() {
    for empty in [
        "false",
        "(false)",
        "((false))",
        "NOT true",
        "false AND owner = current_user",
        "owner = current_user AND false",
        "false AND false",
        "false OR false",
        "(false OR false) AND owner = current_user",
        // An unknown side cannot save an AND.
        "false AND some_function(owner)",
    ] {
        assert!(
            is_constantly_false(&parse_expr(empty)),
            "`{empty}` admits no row whatever the data holds"
        );
    }

    for live in [
        "true",
        "owner = current_user",
        "false OR owner = current_user",
        "owner = current_user OR false",
        "true AND owner = current_user",
        // Not folded, so not proven.
        "1 = 2",
        "owner = 'nobody'",
        // Nothing is proven about an unknown alone.
        "some_function(owner)",
        "NOT false",
    ] {
        assert!(
            !is_constantly_false(&parse_expr(live)),
            "`{live}` may admit a row, so nothing may claim otherwise"
        );
    }
}

/// The schema the review's cases share: a guarded column the membership lacks, an inexact
/// column, and two zoned columns.
fn review_schema() -> ParserDB {
    parse_schema(
        r"
CREATE TABLE papers(id UUID PRIMARY KEY, band INT);
CREATE TABLE paper_shares(
  paper_id UUID,
  viewer TEXT,
  weight DOUBLE PRECISION,
  opens_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ
);
CREATE TABLE tiers(cutoff INT, price NUMERIC, rate DOUBLE PRECISION, published_on DATE);
",
    )
    .expect("schema should parse")
}

fn review_membership(residual: &str) -> Expr {
    parse_expr(&format!(
        "EXISTS (
               SELECT 1
               FROM paper_shares s
               WHERE s.paper_id = papers.id
                 AND s.viewer = current_user
                 AND {residual}
             )"
    ))
}

fn review_refuses(residual: &str) -> bool {
    recognize_p4(
        &review_membership(residual),
        &review_schema(),
        &FunctionRegistry::new(),
        "papers",
        &ExpansionState::new(),
    )
    .is_none()
}

/// A binding resolves a name the catalog would resolve differently, and the crate already
/// refuses every one on the membership subquery.
#[test]
fn a_residual_binding_its_own_names_is_refused() {
    assert!(
        review_refuses(
            "s.cutoff > (WITH tiers AS (SELECT 0 AS cutoff) SELECT max(cutoff) FROM tiers)"
        ),
        "a binding shadowing a relation is not the relation the proof was taken on"
    );
}

/// A name only the guarded row supplies binds outward at the conjunct's own level too.
#[test]
fn a_residual_binding_a_bare_guarded_column_at_its_own_level_is_refused() {
    assert!(
        review_refuses("band > (SELECT max(cutoff) FROM tiers)"),
        "the generated query scans the membership table alone"
    );
}

/// A cast to a temporal type reads the session's zone and date style, literal or not.
#[test]
fn a_residual_casting_to_a_temporal_type_is_refused() {
    assert!(
        review_refuses(
            "s.weight > (SELECT count(*) FROM tiers \
             WHERE 'now'::timestamptz > '2026-01-01 00:00+00'::timestamptz)"
        ),
        "a clock-valued literal outlives the tuple it was baked into"
    );
}

/// Rendering a temporal column as text reads the session's date style.
#[test]
fn a_residual_casting_a_temporal_column_to_text_is_refused() {
    assert!(
        review_refuses("s.viewer > (SELECT max(published_on::text) FROM tiers)"),
        "the date style decides the rendering"
    );
}

/// Summing floating point is not associative, whether the type comes from the column or
/// from a cast.
#[test]
fn a_residual_summing_inexact_numbers_is_refused() {
    for residual in [
        "s.weight > (SELECT sum(price::double precision) FROM tiers)",
        "s.weight > (SELECT avg(rate) FROM tiers)",
    ] {
        assert!(
            review_refuses(residual),
            "parallel aggregation may order the partial sums differently: {residual}"
        );
    }
}

/// A comparison between a zoned column and a zone-less literal is completed by the
/// session's own zone.
#[test]
fn a_residual_comparing_a_zoned_column_to_a_literal_is_refused() {
    assert!(
        review_refuses(
            "s.viewer > (SELECT count(*)::text FROM tiers WHERE cutoff > 1) \
             AND s.opens_at > '2026-01-01 00:00'"
        ),
        "the session's zone completes the literal"
    );
}

/// Both operands stored, so the comparison is between two absolute instants and neither
/// side is the session's to decide.
#[test]
fn a_residual_comparing_two_stored_columns_is_recognized() {
    let db = review_schema();
    let sql = recognized_residual_sql(
        &db,
        &review_membership(
            "s.opens_at < s.expires_at AND s.weight > (SELECT max(cutoff) FROM tiers)",
        ),
    );
    assert!(
        sql.contains("opens_at < expires_at"),
        "a comparison of two stored instants is decided by the rows, got: {sql}"
    );
}

/// An inexact column compared against a literal is the stored value against a constant,
/// which every caller reads alike.
#[test]
fn a_residual_comparing_an_inexact_column_to_a_literal_is_recognized() {
    let db = review_schema();
    let sql = recognized_residual_sql(
        &db,
        &review_membership("s.weight > 3 AND s.weight > (SELECT max(cutoff) FROM tiers)"),
    );
    assert!(
        sql.contains("weight > 3"),
        "a stored number against a constant needs no session, got: {sql}"
    );
}

/// An expression kind the allow-list does not name refuses, which is what makes the list a
/// list rather than a suggestion.
#[test]
fn a_residual_using_an_unlisted_expression_is_refused() {
    for residual in [
        "s.weight > (SELECT extract(year FROM published_on) FROM tiers)",
        "s.viewer > (SELECT count(*)::text FROM tiers WHERE cutoff = ANY(ARRAY[1, 2]))",
    ] {
        assert!(
            review_refuses(residual),
            "an unlisted expression is not a proven one: {residual}"
        );
    }
}

/// A placeholder is filled by whoever runs the query.
#[test]
fn a_residual_carrying_a_placeholder_is_refused() {
    assert!(
        review_refuses("s.weight > (SELECT max(cutoff) FROM tiers WHERE cutoff > $1)"),
        "the caller fills a placeholder, so the loader cannot answer it"
    );
}

/// `IS DISTINCT FROM` compares as a comparison does, so a zoned column against a literal
/// reads the session's zone there too.
#[test]
fn a_residual_distinguishing_a_zoned_column_from_a_literal_is_refused() {
    assert!(
        review_refuses(
            "s.weight > (SELECT count(*) FROM tiers \
             WHERE published_on IS DISTINCT FROM '2026-01-01')"
        ),
        "the session's date style completes the literal whichever comparison spells it"
    );
}

/// A set operation binds its output columns to no single relation, so nothing places a name
/// it carries.
#[test]
fn a_residual_reading_a_set_operation_is_refused() {
    assert!(
        review_refuses("s.weight > (SELECT max(cutoff) FROM tiers UNION SELECT 1)"),
        "a set operation binds no relation the names can be placed against"
    );
}

/// A nested relation's own alias places its columns, so the qualifier resolves there rather
/// than reaching outward.
#[test]
fn a_residual_qualifying_a_nested_alias_is_recognized() {
    let db = review_schema();
    let sql = recognized_residual_sql(
        &db,
        &review_membership("s.weight > (SELECT max(t.cutoff) FROM tiers t)"),
    );
    assert!(
        sql.contains("max(t.cutoff)"),
        "the nested alias places its own column, got: {sql}"
    );
}

/// A window makes an aggregate answer per frame rather than per relation.
#[test]
fn a_residual_windowing_an_aggregate_is_refused() {
    assert!(
        review_refuses("s.weight > (SELECT max(cutoff) OVER () FROM tiers)"),
        "a framed aggregate is not the order-free one the name promises"
    );
}
