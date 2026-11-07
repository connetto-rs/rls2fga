use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::types::ConfidenceLevel;

use crate::support;

// ── Registered function fallbacks ────────────────────────────────────────────

#[test]
fn registered_function_not_matching_any_pattern_falls_to_unknown() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, val INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (val + my_user_func() > 0);

CREATE FUNCTION my_user_func() RETURNS UUID LANGUAGE sql AS
'SELECT current_setting(''app.current_user_id'')::uuid';
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "my_user_func",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);

    let c = classified[0]
        .using_classification()
        .expect("should have USING");
    assert!(
        matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "Expected Unknown for non-matching pattern, got {:?}",
        c.pattern
    );
}

#[test]
fn registered_unknown_function_produces_registered_as_unknown_message() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, val INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (mystery_func(val));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "mystery_func",
        &FunctionSemantic::Unknown {
            reason: "semantics not analyzable".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    if let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &c.pattern {
        assert!(
            reason.contains("registered as Unknown"),
            "Expected 'registered as Unknown' message, got: {reason}"
        );
    } else {
        panic!("Expected Unknown, got: {:?}", c.pattern);
    }
}

#[test]
fn registered_role_threshold_function_bare_call_gives_specific_message() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, val INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (role_level(val, id));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(
            r#"{
        "role_level": {
            "kind": "role_threshold",
            "user_param_index": 0,
            "resource_param_index": 1,
            "role_levels": {"viewer": 1, "editor": 2},
            "grant_table": "grants",
            "grant_grantee_col": "grantee",
            "grant_resource_col": "resource",
            "grant_role_col": "role"
        }
    }"#,
        )
        .unwrap();

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    if let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &c.pattern {
        assert!(
            reason.contains("did not match any recognized translation pattern"),
            "Expected 'did not match' message, got: {reason}"
        );
    } else {
        panic!("Expected Unknown, got: {:?}", c.pattern);
    }
}

// ── classifications() iterator ───────────────────────────────────────────────

#[test]
fn classifications_iterator_yields_both_using_and_with_check() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR UPDATE
    USING (owner_id = current_setting('app.user_id'))
    WITH CHECK (owner_id = current_setting('app.user_id'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);

    let count = classified[0].classifications().count();
    assert_eq!(
        count, 2,
        "UPDATE policy with both USING and WITH CHECK should yield 2 classifications"
    );
}

#[test]
fn classifications_iterator_yields_one_for_select() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);

    let count = classified[0].classifications().count();
    assert_eq!(count, 1, "SELECT-only policy should yield 1 classification");
}

// ── scoped_roles() ───────────────────────────────────────────────────────────

#[test]
fn scoped_roles_returns_empty_for_public() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO PUBLIC USING (owner_id = current_setting('app.user_id'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    assert!(
        classified[0].scoped_roles().is_empty(),
        "TO PUBLIC should return empty scoped_roles"
    );
}

#[test]
fn scoped_roles_returns_role_names() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO app_user, admin_role USING (owner_id = current_setting('app.user_id'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let roles = classified[0].scoped_roles();
    assert_eq!(roles.len(), 2);
    assert!(roles.contains(&"admin_role".to_string()));
    assert!(roles.contains(&"app_user".to_string()));
}

#[test]
fn an_equality_between_two_guarded_row_columns_refuses_the_membership() {
    // PostgreSQL filters every membership hit through the guarded row's own
    // comparison. The tuple query reads only the membership table, so the
    // conjunct is inexpressible there and the classification must refuse.
    for conjunct in ["docs.owner_id = docs.reviewer_id", "owner_id = reviewer_id"] {
        let sql = format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, reviewer_id TEXT);
CREATE TABLE members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id')
    AND {conjunct}));
"
        );
        let (classified, _db, _registry) = support::classify_sql_no_registry(&sql);
        assert_eq!(classified.len(), 1);
        let c = classified[0].using_classification().unwrap();
        assert!(
            matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
            "`{conjunct}`: a guarded-row filter the tuple query cannot carry must refuse, got: {:?}",
            c.pattern
        );
    }
}

#[test]
fn the_same_membership_without_the_guarded_row_filter_stays_p4() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, reviewer_id TEXT);
CREATE TABLE members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM members m WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id')));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P4ExistsMembership(_)),
        "the clean membership shape must keep translating, got: {:?}",
        c.pattern
    );
    assert_eq!(c.confidence, ConfidenceLevel::A);
}

#[test]
fn a_nullif_wrapped_ownership_refuses() {
    // NULLIF(owner_id, 'system') = current_setting('app.user_id') denies the sentinel principal
    // its rows. Tuples built from the raw column would reverse that exclusion.
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (NULLIF(owner_id, 'system') = current_setting('app.user_id'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "the sentinel exclusion is unrepresentable in a P3 grant, got: {:?}",
        c.pattern
    );
}

#[test]
fn a_coalesce_wrapped_ownership_still_classifies_at_b() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (COALESCE(owner_id, 'nobody') = current_setting('app.user_id'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "COALESCE only narrows, so it keeps classifying, got: {:?}",
        c.pattern
    );
    assert_eq!(c.confidence, ConfidenceLevel::B);
}

// ── Composite patterns ───────────────────────────────────────────────────────

#[test]
fn ownership_beside_a_literal_guard_keeps_the_composite_structure() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (owner_id = current_setting('app.user_id') AND status = 'published');
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    // A literal guard is row data the tuples carry, so the pair keeps its
    // structure instead of flattening to the partial P7 column name.
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P8Composite(Composite { parts, .. })
                if parts.iter().any(|part| matches!(
                    &part.pattern,
                    PatternClass::P9AttributeCondition(AttributeCondition { predicate: Some(_), .. })
                ))
        ),
        "Expected the literal guard to keep its predicate, got: {:?}",
        c.pattern
    );
}

#[test]
fn p8_composite_or_with_all_relationship_parts() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (owner_id = current_setting('app.user_id') OR editor_id = current_setting('app.user_id'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P8Composite(Composite { op: BoolOp::Or, .. })
        ),
        "Expected P8 OR composite, got: {:?}",
        c.pattern
    );
}

/// Was P9 at confidence B, an attribute the model then denied. `PostgreSQL` 18 grants
/// exactly the rows holding the caller, and an UNNEST enumeration reproduces them, so it
/// is a relationship at confidence A.
#[test]
fn array_any_membership_classified_as_array_membership() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, allowed_users TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (current_setting('app.user_id') = ANY(allowed_users));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P11ArrayMembership(ArrayMembership { column }) if column == "allowed_users"
        ),
        "Expected P11 for = ANY(...), got: {:?}",
        c.pattern
    );
    assert_eq!(c.confidence, ConfidenceLevel::A);
}

/// Two array columns overlapping name no principal, so this stays an attribute guard the
/// application has to enforce. Only the spelling that puts the caller on one side became
/// a relationship.
#[test]
fn array_overlap_of_two_columns_stays_an_attribute_condition() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, tags TEXT[], user_tags TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (tags && user_tags);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P9AttributeCondition(AttributeCondition { .. })
        ),
        "Expected P9 for array overlap (&&), got: {:?}",
        c.pattern
    );
    assert_eq!(c.confidence, ConfidenceLevel::C);
}

#[test]
fn p5_with_p6_inner_does_not_classify_as_p5() {
    let sql = r"
CREATE TABLE projects(id UUID PRIMARY KEY, is_public BOOLEAN);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = tasks.project_id AND p.is_public = TRUE
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        !matches!(
            &c.pattern,
            PatternClass::P5ParentInheritance(ParentInheritance { .. })
        ),
        "P5 with P6 inner should be rejected, got: {:?}",
        c.pattern
    );
}

#[test]
fn p5_with_unknown_inner_generates_no_access_todo() {
    let sql = r"
CREATE TABLE projects(id UUID PRIMARY KEY);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON tasks FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = tasks.project_id AND p.val + mystery() > 0
    ));
";
    let (classified, db, registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0]
        .using_classification()
        .expect("should have USING classification");
    assert!(
        matches!(
            &c.pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. })
                if reason.contains("The rule inherited from 'projects' is not translatable")
        ),
        "P5-shaped EXISTS with untranslatable inner should classify as Unknown, got: {:?}",
        c.pattern
    );
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);
    let model = outputs.model();
    assert!(
        model.contains("define can_select: no_access"),
        "model should deny can_select via no_access, got:\n{model}"
    );
    let tuples = rls2fga::generator::tuple_generator::format_tuples(outputs.tuple_queries());
    assert!(
        tuples.contains(
            "TODO [Level D]: skipped tuple generation for tasks (unsupported pattern Unknown)"
        ),
        "tuple SQL should carry the TODO marker naming the table and pattern, got:\n{tuples}"
    );
    assert!(
        tuples.contains("The rule inherited from 'projects' is not translatable"),
        "tuple SQL body should name the reason the inner predicate was refused, got:\n{tuples}"
    );
}

// ── Confidence filtering ─────────────────────────────────────────────────────

#[test]
fn confidence_filter_drops_below_threshold_classifications() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_own ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY p_flag ON docs FOR SELECT USING (is_public = TRUE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);

    let filtered = filter_policies_for_output(&classified, ConfidenceLevel::A);
    let has_p3 = filtered.iter().any(|cp| {
        cp.classifications().any(|c| {
            matches!(
                &c.pattern,
                PatternClass::P3DirectOwnership(DirectOwnership { .. })
            )
        })
    });
    assert!(has_p3, "P3 (confidence A) should survive A-level filter");

    let has_p6 = filtered.iter().any(|cp| {
        cp.classifications()
            .any(|c| matches!(&c.pattern, PatternClass::P6BooleanFlag(BooleanFlag { .. })))
    });
    assert!(
        !has_p6,
        "P6 (confidence B) should be dropped at A-level filter"
    );
}

// ── P2 variations ────────────────────────────────────────────────────────────

#[test]
fn role_accessor_equality_classified_as_p2() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (auth.role() = 'authenticated');
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P2RoleNameInList(RoleNameInList { role_names, .. }) if role_names == &["authenticated"]
        ),
        "Expected P2 for role accessor = 'authenticated', got: {:?}",
        c.pattern
    );
}

#[test]
fn role_accessor_in_list_classified_as_p2() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (auth.role() IN ('authenticated', 'admin'));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(r#"{"auth.role": {"kind": "role_accessor"}}"#)
        .unwrap();

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P2RoleNameInList(RoleNameInList { role_names, .. }) if role_names.len() == 2
        ),
        "Expected P2 with 2 role names, got: {:?}",
        c.pattern
    );
}

/// The two-argument `pg_has_role` asks about the acting role, and the schema's role
/// memberships settle the answer, so the call classifies as the constant they decide.
#[test]
fn pg_has_role_two_arg_is_a_constant_the_schema_decides() {
    let sql = r"
CREATE ROLE app_user;
CREATE ROLE admin;
GRANT admin TO app_user;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (pg_has_role('admin', 'MEMBER'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: true })
        ),
        "the grant settles the acting role's membership, got: {:?}",
        c.pattern
    );
}

/// The three-argument form reads its member from the acting role the same way, so a
/// policy written with the keyword classifies as the constant the memberships decide.
#[test]
fn pg_has_role_three_arg_is_a_constant_the_schema_decides() {
    let sql = r"
CREATE ROLE app_user;
CREATE ROLE editor;
GRANT editor TO app_user;
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (pg_has_role(current_user, 'editor', 'MEMBER'));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: true })
        ),
        "the keyword reads the acting role and the grant settles it, got: {:?}",
        c.pattern
    );
}

// ── P3 variations ────────────────────────────────────────────────────────────

#[test]
fn current_setting_as_user_accessor() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "current_setting",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "text".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "Expected P3 for current_setting accessor, got: {:?}",
        c.pattern
    );
}

#[test]
fn subquery_wrapped_accessor_caps_confidence_at_b() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = (SELECT auth.uid()));
";
    let db = parse_schema(sql).unwrap();
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "auth.uid",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::caller_deployment(),
    );
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P3DirectOwnership(DirectOwnership { .. })
        ),
        "Expected P3, got: {:?}",
        c.pattern
    );
    assert_eq!(
        c.confidence,
        ConfidenceLevel::B,
        "Subquery-wrapped accessor should cap confidence at B"
    );
}

// ── Boolean / constant ───────────────────────────────────────────────────────

#[test]
fn negated_boolean_flag_classified_as_unknown() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (is_public = FALSE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "Negated boolean flag (= FALSE) should classify as Unknown, got: {:?}",
        c.pattern
    );
}

#[test]
fn is_false_boolean_flag_classified_as_unknown() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (is_public IS FALSE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "IS FALSE boolean flag should classify as Unknown, got: {:?}",
        c.pattern
    );
}

#[test]
fn constant_true_classified_as_p10() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (TRUE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: true })
        ),
        "TRUE should classify as P10, got: {:?}",
        c.pattern
    );
}

#[test]
fn constant_false_classified_as_p10() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (FALSE);
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: false })
        ),
        "FALSE should classify as P10, got: {:?}",
        c.pattern
    );
}

// ── P4 variations ────────────────────────────────────────────────────────────

#[test]
fn p4_in_subquery_form_classified_as_membership() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE shares(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (id IN (SELECT doc_id FROM shares WHERE shares.user_id = current_setting('app.user_id')));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P4ExistsMembership(ExistsMembership { .. })
        ),
        "IN subquery form should classify as P4, got: {:?}",
        c.pattern
    );
}

/// A policy whose membership subquery reads the guarded table is a read `PostgreSQL`
/// refuses to plan, raising `infinite recursion detected in policy` (verified on
/// `PostgreSQL` 18), and the inner scan names its own rows rather than the guarded one.
#[test]
fn p4_reading_the_guarded_table_in_the_join_is_refused() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID, member_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM doc_members m
        JOIN docs d ON m.doc_id = d.id
        WHERE m.member_id = current_setting('app.user_id')
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. })
            if reason.contains("infinite recursion")),
        "reading 'docs' inside its own policy must be refused, got: {:?}",
        c.pattern
    );
}

#[test]
fn p4_on_clause_joining_guarded_table_is_refused() {
    for sql in [
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE shares(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM shares s
        JOIN docs d ON s.user_id = current_setting('app.user_id')
        WHERE s.doc_id = docs.id
    ));
",
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE shares(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM shares s
        JOIN docs d ON current_setting('app.user_id') = s.user_id
        WHERE s.doc_id = docs.id
    ));
",
    ] {
        let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
        assert_eq!(classified.len(), 1);
        let c = classified[0].using_classification().unwrap();
        assert!(
            matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. })
                if reason.contains("infinite recursion")),
            "joining the guarded table in an ON clause must be refused, got: {:?}",
            c.pattern
        );
    }
}

#[test]
fn p4_reversed_correlation_names_the_guarded_column() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_access(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM doc_access a
        WHERE docs.id = a.doc_id
          AND a.user_id = current_setting('app.user_id')
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::P4ExistsMembership(ExistsMembership { pairs, .. })
            if matches!(pairs.as_slice(), [pair]
                if pair.join_column == "doc_id" && pair.outer_column == "id")),
        "the guarded side of the correlation is docs.id, got: {:?}",
        c.pattern
    );
}

#[test]
fn p4_conflicting_fk_columns_in_where_rejects() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, project_id UUID);
CREATE TABLE access(id UUID PRIMARY KEY, doc_id UUID, project_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM access a
        WHERE a.doc_id = docs.id AND a.project_id = docs.project_id AND a.user_id = current_setting('app.user_id')
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(&c.pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. })
            if reason.contains("conflicting outer FK join columns")),
        "two outer correlations with no composite foreign key must be refused, got: {:?}",
        c.pattern
    );
}

#[test]
fn p13_uncorrelated_membership_when_subquery_has_no_fk_to_guarded_table() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE log(id UUID PRIMARY KEY, doc_id UUID, editor UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM log WHERE log.editor = current_setting('app.user_id')
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0]
        .using_classification()
        .expect("should have USING classification");
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P13UncorrelatedMembership(UncorrelatedMembership {
                member_table,
                user_column,
                ..
            }) if member_table.name() == "log" && user_column == "editor"
        ),
        "subquery with no FK back to the guarded table should classify as P13, got: {:?}",
        c.pattern
    );
}

// ── P5 variations ────────────────────────────────────────────────────────────

#[test]
fn p5_conflicting_join_columns_classified_as_unknown() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id), alt_org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o
        WHERE o.id = docs.org_id AND o.id = docs.alt_org_id AND o.owner_id = current_setting('app.user_id')
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        !matches!(
            &c.pattern,
            PatternClass::P5ParentInheritance(ParentInheritance { .. })
        ),
        "Conflicting join columns should NOT classify as P5, got: {:?}",
        c.pattern
    );
}

/// A read policy that only requires the parent row to exist inherits the parent's own
/// read rule, which requires the parent to enforce one.
#[test]
fn p5_no_inner_predicates_delegates_to_the_parent() {
    let sql = r"
CREATE TABLE orgs(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM orgs o WHERE o.id = docs.org_id
    ));
";
    let (classified, _db, _registry) = support::classify_sql_no_registry(sql);
    assert_eq!(classified.len(), 1);
    let c = classified[0].using_classification().unwrap();
    assert!(
        matches!(
            &c.pattern,
            PatternClass::P5ParentInheritance(ParentInheritance { parent_table, inner_pattern, .. })
                if parent_table.name() == "orgs"
                    && matches!(
                        inner_pattern.pattern,
                        PatternClass::P10ConstantBool(ConstantBool { value: true })
                    )
        ),
        "the parent's own rule is the whole requirement, got: {:?}",
        c.pattern
    );
}
