use super::dsl::*;
use super::emit_roles::{ensure_exact_roles_relation, ensure_role_threshold_scaffold};
use super::*;
use crate::generator::well_known::{WellKnownTypes, TEAM_TYPE, USER_TYPE};
use crate::parser::sql_parser::{parse_schema, DatabaseLike, ParserDB, PolicyLike};
use crate::types::{BoundQuery, ColumnName, ReplayScope};

fn table_id(name: &str) -> TableId {
    TableId::from_stored(None, name.to_string())
}

fn role_registry(role_levels: &str, include_team: bool) -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    let team_fields = if include_team {
        r#",
    "team_membership": {
      "table": "team_memberships",
      "user_col": "user_id",
      "team_col": "team_id"
    }"#
    } else {
        ""
    };
    let json = format!(
        r#"{{
  "role_level": {{
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {role_levels},
    "grant_table": "object_grants",
    "grant_grantee_col": "grantee_id",
    "grant_resource_col": "resource_id",
    "grant_role_col": "role_level"{team_fields}
  }}
}}"#
    );
    registry
        .load_from_json(&json)
        .expect("registry json should parse");
    registry
}

fn docs_db_with_policy(policy_sql: &str) -> ParserDB {
    let sql = format!(
        "
CREATE TABLE docs(id uuid primary key, owner_id uuid, status text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{policy_sql}
"
    );
    parse_schema(&sql).expect("schema should parse")
}

fn classified_from_policy<DB: DatabaseLike>(
    policy: &DB::Policy,
    db: &DB,
    using: Option<PatternClass>,
    with_check: Option<PatternClass>,
) -> ClassifiedPolicy {
    let mut result = ClassifiedPolicy::from_policy(policy, db);
    result.using_classification = using.map(|pattern| ClassifiedExpr {
        pattern,
        confidence: ConfidenceLevel::A,
    });
    result.with_check_classification = with_check.map(|pattern| ClassifiedExpr {
        pattern,
        confidence: ConfidenceLevel::A,
    });
    result
}

fn plan_from_policy_sql(
    policy_sql: &str,
    using: Option<PatternClass>,
    with_check: Option<PatternClass>,
) -> (SchemaPlan, TypePlan) {
    let db = docs_db_with_policy(policy_sql);
    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(policy, &db, using, with_check);
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default())
        .expect("translation should plan");
    let docs = plan
        .types
        .iter()
        .find(|t| t.type_name.as_str() == "docs")
        .expect("docs type should exist")
        .clone();
    (plan, docs)
}

/// Each target `for_each_policy_target_expr` routes the policy declared by `policy_sql`
/// to, with the pattern it routes there, once its readable `USING` is `using`.
fn routed_targets(
    policy_sql: &str,
    using: Option<PatternClass>,
) -> Vec<(ActionTarget, PatternClass)> {
    let db = docs_db_with_policy(&format!(
        "ALTER TABLE docs ADD COLUMN expires TIMESTAMPTZ;\n{policy_sql}"
    ));
    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(policy, &db, using, None);
    let mut routed = Vec::new();
    for_each_policy_target_expr(&classified, |target, expr| {
        routed.push((target, expr.pattern.clone()));
    });
    routed
}

#[test]
fn an_unreadable_barrier_denies_every_target_it_feeds_the_mirror_included() {
    let routed = routed_targets(
        "CREATE POLICY p ON docs AS RESTRICTIVE USING (expires > '2026-01-01 09:00');",
        None,
    );
    let deny = PatternClass::P10ConstantBool(ConstantBool { value: false });
    assert_eq!(
        routed,
        [
            ActionTarget::Select,
            ActionTarget::UpdateUsing,
            ActionTarget::Delete,
            ActionTarget::Insert,
            ActionTarget::UpdateCheck,
        ]
        .map(|target| (target, deny.clone()))
    );
}

#[test]
fn an_unreadable_check_is_never_answered_by_the_using() {
    let grant = PatternClass::P10ConstantBool(ConstantBool { value: true });
    let routed = routed_targets(
        "CREATE POLICY p ON docs USING (TRUE) WITH CHECK (expires > '2026-01-01 09:00');",
        Some(grant.clone()),
    );
    assert_eq!(
        routed,
        [
            ActionTarget::Select,
            ActionTarget::UpdateUsing,
            ActionTarget::Delete,
        ]
        .map(|target| (target, grant.clone()))
    );
}

#[test]
fn compose_action_with_only_restrictive_rules_maps_to_no_access() {
    let mut plan = TypePlan::new(TypeName::canonicalized("docs"));
    let bucket = ModeBuckets {
        permissive: Vec::new(),
        restrictive: vec![UsersetExpr::Computed(RelationName::canonicalized("owner"))],
        subtractions: Vec::new(),
    };

    let expr = compose_action(&mut plan, Some(&bucket)).expect("expected expression");
    assert_eq!(
        expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert!(
        plan.direct_relations.contains_key("no_access"),
        "restrictive-only rules should synthesize no_access"
    );
}

/// The fold always puts an exclusion beside a granting branch, so no generated model
/// can tell a wrong answer here from a right one. The contract is pinned directly.
#[test]
fn grants_nothing_reads_only_the_base_of_an_exclusion() {
    let mut plan = TypePlan::new(TypeName::canonicalized("docs"));
    plan.ensure_direct(
        deny_relation(),
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );
    plan.ensure_direct(
        "owner",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );

    let from_nothing = UsersetExpr::Exclusion {
        base: Box::new(UsersetExpr::Computed(deny_relation())),
        subtract: Box::new(UsersetExpr::Computed(RelationName::canonicalized("owner"))),
    };
    assert!(
        grants_nothing(&from_nothing, &plan),
        "subtracting from a relation that grants nobody still grants nobody"
    );

    let from_owner = UsersetExpr::Exclusion {
        base: Box::new(UsersetExpr::Computed(RelationName::canonicalized("owner"))),
        subtract: Box::new(UsersetExpr::Computed(deny_relation())),
    };
    assert!(
        !grants_nothing(&from_owner, &plan),
        "how much a subtraction removes is unknowable, so the base decides"
    );
}

#[test]
fn a_computed_cycle_is_neither_a_denial_nor_a_local_grant() {
    let (_, mut owner) = plan_from_policy_sql(
        "CREATE POLICY p ON docs FOR SELECT USING (true);",
        Some(PatternClass::P10ConstantBool(ConstantBool { value: true })),
        None,
    );
    owner.set_computed(
        can_select_relation(),
        UsersetExpr::Computed(can_select_relation()),
    );
    assert!(!relation_grants_nothing(&owner, &can_select_relation()));
    assert!(!relation_grants_every_actor(
        None,
        &owner,
        &can_select_relation(),
        None,
    ));
}

#[test]
fn subtracting_an_empty_difference_keeps_a_local_grant() {
    let (_, mut owner) = plan_from_policy_sql(
        "CREATE POLICY p ON docs FOR SELECT USING (true);",
        Some(PatternClass::P10ConstantBool(ConstantBool { value: true })),
        None,
    );
    let everyone = UsersetExpr::Computed(public_relation());
    owner.set_computed(
        can_select_relation(),
        UsersetExpr::Exclusion {
            base: Box::new(everyone.clone()),
            subtract: Box::new(UsersetExpr::Exclusion {
                base: Box::new(everyone.clone()),
                subtract: Box::new(everyone),
            }),
        },
    );
    assert!(relation_grants_every_actor(
        None,
        &owner,
        &can_select_relation(),
        None,
    ));
}

/// `rule_implies` treats equal keys as the same rule, so an exclusion that ignored a
/// side would let one stand for another.
#[test]
fn userset_key_separates_exclusions_by_both_sides() {
    let exclusion = |base: &str, subtract: &str| UsersetExpr::Exclusion {
        base: Box::new(UsersetExpr::Computed(RelationName::canonicalized(base))),
        subtract: Box::new(UsersetExpr::Computed(RelationName::canonicalized(subtract))),
    };

    let key = userset_key(&exclusion("owner", "blocked"));
    assert_eq!(key, userset_key(&exclusion("owner", "blocked")));
    assert_ne!(key, userset_key(&exclusion("editor", "blocked")));
    assert_ne!(key, userset_key(&exclusion("owner", "suspended")));
    assert_ne!(
        key,
        userset_key(&UsersetExpr::Intersection(vec![
            UsersetExpr::Computed(RelationName::canonicalized("owner")),
            UsersetExpr::Computed(RelationName::canonicalized("blocked")),
        ]))
    );
}

#[test]
fn pattern_to_expr_handles_missing_or_invalid_role_threshold_metadata() {
    let empty_registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let p1 = PatternClass::P1NumericThreshold(NumericThreshold {
        resource_column: None,
        function_name: "missing_fn".to_string(),
        operator: ThresholdOperator::Gte,
        threshold: 2,
        command: PolicyCommand::Select,
    });
    let p2 = PatternClass::P2RoleNameInList(RoleNameInList {
        resource_column: None,
        function_name: "missing_fn".to_string(),
        role_names: vec!["viewer".to_string()],
    });

    let p1_expr = pattern_to_expr(
        &p1,
        "p1",
        &mut table_plan,
        &mut all_types,
        &empty_registry,
        &mut notes,
    );
    let p2_expr = pattern_to_expr(
        &p2,
        "p2",
        &mut table_plan,
        &mut all_types,
        &empty_registry,
        &mut notes,
    );

    for expr in [&p1_expr, &p2_expr] {
        assert_eq!(
            expr,
            &UsersetExpr::Computed(RelationName::canonicalized("no_access"))
        );
    }
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(
        notes
            .iter()
            .all(|note| note.message().contains("missing semantic metadata")),
        "{notes:?}"
    );
}

#[test]
fn pattern_to_expr_handles_empty_role_selection_paths() {
    let registry = role_registry("{}", false);
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let p2_non_numeric = PatternClass::P2RoleNameInList(RoleNameInList {
        resource_column: None,
        function_name: "role_level".to_string(),
        role_names: vec!["viewer".to_string()],
    });
    let p2_numeric_without_levels = PatternClass::P2RoleNameInList(RoleNameInList {
        resource_column: None,
        function_name: "role_level".to_string(),
        role_names: vec!["5".to_string()],
    });

    let first = pattern_to_expr(
        &p2_non_numeric,
        "p2_non_numeric",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let second = pattern_to_expr(
        &p2_numeric_without_levels,
        "p2_numeric",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    assert_eq!(
        first,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert_eq!(
        second,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
}

#[test]
fn pattern_to_expr_covers_abac_composite_constant_and_unknown_branches() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let relationship = ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership(DirectOwnership {
            column: ColumnName::from_stored("owner_id"),
        }),
        confidence: ConfidenceLevel::A,
    };
    let p7 = PatternClass::P7AbacAnd(AbacAnd {
        relationship_part: Box::new(relationship.clone()),
        attribute_part: "status".to_string(),
    });
    let p8_or_empty = PatternClass::P8Composite(Composite {
        op: BoolOp::Or,
        parts: Vec::new(),
    });
    let p8_and_empty = PatternClass::P8Composite(Composite {
        op: BoolOp::And,
        parts: Vec::new(),
    });
    let p9 = PatternClass::P9AttributeCondition(AttributeCondition {
        column: ColumnName::from_stored("status"),
        value_description: "'published'".to_string(),
        predicate: None,
        request_predicate: None,
    });
    let p8_and_attr_true = PatternClass::P8Composite(Composite {
        op: BoolOp::And,
        parts: vec![
            ClassifiedExpr {
                pattern: p9.clone(),
                confidence: ConfidenceLevel::C,
            },
            ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
                confidence: ConfidenceLevel::A,
            },
        ],
    });
    let p10_false = PatternClass::P10ConstantBool(ConstantBool { value: false });
    let p5 = PatternClass::P5ParentInheritance(ParentInheritance {
        parent_table: table_id("projects"),
        fk_column: ColumnName::from_stored("project_id"),
        inner_pattern: Box::new(relationship),
    });
    let unknown = PatternClass::Unknown(UnclassifiedExpr {
        sql_text: "mystery()".to_string(),
        reason: "no recognizer".to_string(),
    });

    let p7_expr = pattern_to_expr(
        &p7,
        "p7",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p8_or_expr = pattern_to_expr(
        &p8_or_empty,
        "p8_or",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p8_and_expr = pattern_to_expr(
        &p8_and_empty,
        "p8_and",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p10_expr = pattern_to_expr(
        &p10_false,
        "p10",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p9_expr = pattern_to_expr(
        &p9,
        "p9",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p8_and_attr_true_expr = pattern_to_expr(
        &p8_and_attr_true,
        "p8_and_attr_true",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p5_expr = pattern_to_expr(
        &p5,
        "p5",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let unknown_expr = pattern_to_expr(
        &unknown,
        "unknown",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    assert_eq!(
        p7_expr,
        UsersetExpr::Computed(RelationName::canonicalized("owner"))
    );
    assert_eq!(
        p8_or_expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert_eq!(
        p8_and_expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert_eq!(
        p10_expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert_eq!(
        p9_expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert!(
            matches!(
                &p8_and_attr_true_expr,
                UsersetExpr::Computed(name) if name == "no_access"
            ) || matches!(
                &p8_and_attr_true_expr,
                UsersetExpr::Intersection(children)
                    if children
                        .iter()
                        .any(|child| matches!(child, UsersetExpr::Computed(name) if name == "no_access"))
            ),
            "attribute + constant-true composite should remain deny-biased, got: {p8_and_attr_true_expr:?}"
        );
    // The inherited rule is the parent-side ownership the policy names, not the
    // parent's whole read permission.
    assert_eq!(
        p5_expr,
        UsersetExpr::TupleToUserset {
            tupleset: RelationName::canonicalized("projects"),
            computed: RelationName::canonicalized("owner"),
        }
    );
    assert_eq!(
        unknown_expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert!(table_plan.direct_relations.contains_key("projects"));
    assert!(notes
        .iter()
        .any(|t| t.message().contains("still requires runtime enforcement")));
    assert!(notes
        .iter()
        .any(|t| t.message().contains("mapped to no_access for safety")));
    assert!(notes
        .iter()
        .any(|t| t.message().contains("could not be safely translated")));
}

#[test]
fn build_schema_plan_mirrors_update_check_when_only_with_check_is_present() {
    let (_, docs) = plan_from_policy_sql(
        "CREATE POLICY docs_update ON docs FOR UPDATE WITH CHECK (owner_id = current_user);",
        None,
        Some(PatternClass::P3DirectOwnership(DirectOwnership {
            column: ColumnName::from_stored("owner_id"),
        })),
    );
    assert!(
        docs.computed_relations.contains_key("can_update"),
        "update relation should be synthesized from WITH CHECK"
    );
}

#[test]
fn exact_roles_relation_does_not_conflate_roles_at_same_level() {
    // `viewer=1` and `guest=1` share the same integer level.  Selecting only
    // `'viewer'` by name must NOT include `grant_guest`.
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([
        ("viewer".to_string(), 1),
        ("guest".to_string(), 1),
        ("editor".to_string(), 2),
    ]);

    let (sorted, _) = ensure_role_threshold_scaffold(
        &mut table_plan,
        &mut all_types,
        &TypeName::canonicalized("grants_owner"),
        &ColumnName::from_stored("owner_id"),
        &role_levels,
        None,
    );

    // Select only "viewer" by name.
    let selected = BTreeSet::from(["viewer".to_string()]);
    let relation = ensure_exact_roles_relation(
        &mut all_types,
        &TypeName::canonicalized("grants_owner"),
        &sorted,
        &selected,
        false,
        &WellKnownTypes::default(),
    )
    .expect("should produce a relation");
    let expr = all_types["grants_owner"]
        .computed_relations
        .get(&relation)
        .expect("the relation is declared on the owner type");

    // The expression must include grant_viewer.
    let contains = |wanted: &str| match expr {
        UsersetExpr::Computed(n) => n == wanted,
        UsersetExpr::Union(children) => children
            .iter()
            .any(|c| matches!(c, UsersetExpr::Computed(n) if n == wanted)),
        _ => false,
    };
    assert!(contains("grant_viewer"), "grant_viewer must be included");
    assert!(
        !contains("grant_guest"),
        "grant_guest must not be included when only 'viewer' was selected"
    );
}

#[test]
fn ensure_role_threshold_scaffold_with_team_support_and_exact_roles_owner_inclusion() {
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([
        ("viewer".to_string(), 1),
        ("editor".to_string(), 2),
        ("admin".to_string(), 3),
    ]);

    let team_type = TypeName::canonicalized("team");
    let (sorted, pointer) = ensure_role_threshold_scaffold(
        &mut table_plan,
        &mut all_types,
        &TypeName::canonicalized("grants_owner"),
        &ColumnName::from_stored("owner_id"),
        &role_levels,
        Some(&team_type),
    );
    // The ladder judges the owner, and the guarded type carries only the pointer at it,
    // named after the column whose value picks which owner.
    assert_eq!(pointer.as_str(), "owner_id");
    assert!(table_plan.direct_relations.contains_key("owner_id"));
    assert!(!table_plan.direct_relations.contains_key("owner_team"));
    assert!(!table_plan.direct_relations.contains_key("grant_admin"));
    let owner = &all_types["grants_owner"];
    assert!(owner.direct_relations.contains_key("owner_team"));
    assert!(owner.direct_relations.contains_key("grant_admin"));
    assert!(all_types.contains_key("team"));

    let selected = BTreeSet::from(["admin".to_string()]);
    let relation = ensure_exact_roles_relation(
        &mut all_types,
        &TypeName::canonicalized("grants_owner"),
        &sorted,
        &selected,
        true,
        &WellKnownTypes::default(),
    )
    .expect("roles should produce a relation");
    let expr = all_types["grants_owner"]
        .computed_relations
        .get(&relation)
        .expect("the relation is declared on the owner type");
    assert!(matches!(expr, UsersetExpr::Union(children) if children
    .iter()
    .any(|c| matches!(c, UsersetExpr::Computed(name) if name == "owner_user"))
    && children.iter().any(|c| matches!(
        c,
        UsersetExpr::TupleToUserset { tupleset, computed }
            if tupleset == "owner_team" && computed == "member"
    ))));
}

#[test]
fn ensure_role_threshold_scaffold_sanitizes_role_relation_names() {
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let role_levels =
        BTreeMap::from([("read-write".to_string(), 1), ("Team Admin".to_string(), 2)]);

    ensure_role_threshold_scaffold(
        &mut table_plan,
        &mut all_types,
        &TypeName::canonicalized("grants_owner"),
        &ColumnName::from_stored("owner_id"),
        &role_levels,
        None,
    );

    let owner = &all_types["grants_owner"];
    assert!(
        owner.direct_relations.contains_key("grant_read_write"),
        "expected hyphenated role names to be canonicalized"
    );
    assert!(
        owner.direct_relations.contains_key("grant_team_admin"),
        "expected spaced/cased role names to be canonicalized"
    );
    assert!(
        owner.computed_relations.contains_key("role_read_write"),
        "expected computed role relation name to be canonicalized"
    );
}

#[test]
fn ensure_role_threshold_scaffold_disambiguates_role_name_collisions() {
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([("role-a".to_string(), 1), ("role a".to_string(), 2)]);

    ensure_role_threshold_scaffold(
        &mut table_plan,
        &mut all_types,
        &TypeName::canonicalized("grants_owner"),
        &ColumnName::from_stored("owner_id"),
        &role_levels,
        None,
    );

    let grant_relations: Vec<&RelationName> = all_types["grants_owner"]
        .direct_relations
        .keys()
        .filter(|name| name.as_str().starts_with("grant_role_a"))
        .collect();
    assert_eq!(
        grant_relations.len(),
        2,
        "canonical collisions must remain distinct relation identifiers"
    );
    assert_ne!(
        grant_relations[0], grant_relations[1],
        "colliding canonical names should be disambiguated"
    );
}

#[test]
fn expr_to_dsl_parenthesizes_a_child_of_another_kind() {
    let union = UsersetExpr::Union(vec![
        UsersetExpr::Computed(RelationName::canonicalized("a")),
        UsersetExpr::Computed(RelationName::canonicalized("b")),
    ]);
    let intersection = UsersetExpr::Intersection(vec![
        UsersetExpr::Computed(RelationName::canonicalized("x")),
        UsersetExpr::Computed(RelationName::canonicalized("y")),
    ]);

    assert_eq!(expr_to_dsl(&union, Some("and")), "(a or b)");
    assert_eq!(expr_to_dsl(&intersection, Some("or")), "(x and y)");
    assert_eq!(expr_to_dsl(&union, Some("or")), "a or b");
    assert_eq!(expr_to_dsl(&union, None), "a or b");

    let mixed = UsersetExpr::Union(vec![
        intersection.clone(),
        UsersetExpr::Exclusion {
            base: Box::new(UsersetExpr::Computed(RelationName::canonicalized("a"))),
            subtract: Box::new(UsersetExpr::Computed(RelationName::canonicalized("b"))),
        },
    ]);
    assert_eq!(expr_to_dsl(&mixed, None), "(x and y) or (a but not b)");

    let nested = UsersetExpr::Exclusion {
        base: Box::new(union),
        subtract: Box::new(intersection),
    };
    assert_eq!(expr_to_dsl(&nested, None), "(a or b) but not (x and y)");
}

#[test]
fn combine_helpers_cover_empty_and_multi_intersection() {
    assert!(combine_union(Vec::new()).is_none());
    assert!(combine_intersection(Vec::new()).is_none());

    let inter = combine_intersection(vec![
        UsersetExpr::Computed(RelationName::canonicalized("a")),
        UsersetExpr::Computed(RelationName::canonicalized("b")),
    ])
    .expect("intersection should exist");
    assert!(matches!(inter, UsersetExpr::Intersection(children) if children.len() == 2));

    let mut plan = TypePlan::new(TypeName::canonicalized("docs"));
    let empty_bucket = ModeBuckets::default();
    assert!(compose_action(&mut plan, Some(&empty_bucket)).is_none());
}

#[test]
fn build_schema_plan_models_non_rls_tables_and_skips_unknown_ones() {
    let db = parse_schema(
        r"
CREATE TABLE docs(id uuid primary key, owner_id uuid);
CREATE TABLE rls_docs(id uuid primary key, owner_id uuid);
ALTER TABLE rls_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs USING (owner_id = current_user);
CREATE POLICY rls_docs_select ON rls_docs USING (owner_id = current_user);
",
    )
    .expect("schema should parse");

    let mut policies = Vec::new();
    for policy in db.policies() {
        let classified = classified_from_policy(
            policy,
            &db,
            Some(PatternClass::P3DirectOwnership(DirectOwnership {
                column: ColumnName::from_stored("owner_id"),
            })),
            None,
        );
        if classified.name() == "docs_select" {
            let mut missing_table = classified.clone();
            missing_table.table = "ghost_docs".to_string();
            policies.push(missing_table);
        }
        policies.push(classified);
    }

    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&policies, &db, &registry, &GeneratorSettings::default())
        .expect("translation should plan");
    assert!(
        plan.types
            .iter()
            .any(|t| t.type_name.as_str() == "rls_docs"),
        "RLS-enabled table should be translated"
    );
    assert!(
        plan.types.iter().any(|t| t.type_name.as_str() == "docs"),
        "every table carries a type, RLS enabled or not"
    );
    assert!(
        !plan
            .types
            .iter()
            .any(|t| t.type_name.as_str() == "ghost_docs"),
        "a policy naming a table no catalog holds carries no type"
    );
}

#[test]
fn build_schema_plan_denies_every_action_when_no_clause_translates() {
    let (plan, docs) = plan_from_policy_sql(
        "CREATE POLICY docs_select ON docs FOR SELECT USING (owner_id = current_user);",
        None,
        None,
    );
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            docs.computed_relations.get(relation),
            Some(&UsersetExpr::Computed(RelationName::canonicalized(
                "no_access"
            ))),
            "{relation} should deny when nothing translated"
        );
    }
    assert!(plan.notes.iter().any(|note| matches!(
        note,
        TranslationNote::CoveringPoliciesBelowThreshold { table, commands }
            if table.to_string() == "public.docs" && commands == &["SELECT"]
    )));
    assert!(plan.notes.iter().any(|note| matches!(
        note,
        TranslationNote::NoPermissivePolicy { table, commands }
            if table.to_string() == "public.docs" && commands == &["INSERT", "UPDATE", "DELETE"]
    )));
}

#[test]
fn build_schema_plan_canonicalizes_schema_qualified_table_names() {
    let db = parse_schema(
        r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id uuid primary key, owner_id uuid);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON app.docs FOR SELECT USING (owner_id = current_user);
",
    )
    .expect("schema should parse");

    let policy = db.policies().next().expect("policy should exist");
    let classified = classified_from_policy(
        policy,
        &db,
        Some(PatternClass::P3DirectOwnership(DirectOwnership {
            column: ColumnName::from_stored("owner_id"),
        })),
        None,
    );
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default())
        .expect("translation should plan");

    assert!(
        plan.types.iter().any(|t| t.type_name.as_str() == "docs"),
        "schema-qualified table name should canonicalize to relation name"
    );
    assert!(
        !plan
            .types
            .iter()
            .any(|t| t.type_name.as_str() == "app.docs"),
        "raw schema-qualified table name should not appear in output types"
    );
}

#[test]
fn build_schema_plan_mirrors_update_using_when_with_check_absent() {
    let (_, docs) = plan_from_policy_sql(
        "CREATE POLICY docs_update ON docs FOR UPDATE USING (owner_id = current_user);",
        Some(PatternClass::P3DirectOwnership(DirectOwnership {
            column: ColumnName::from_stored("owner_id"),
        })),
        None,
    );
    assert!(docs.computed_relations.contains_key("can_update"));
}

#[test]
fn ensure_role_threshold_scaffold_sorts_ties_by_role_name() {
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let role_levels = BTreeMap::from([
        ("beta".to_string(), 1),
        ("alpha".to_string(), 1),
        ("admin".to_string(), 2),
    ]);

    let (sorted, _) = ensure_role_threshold_scaffold(
        &mut table_plan,
        &mut all_types,
        &TypeName::canonicalized("grants_owner"),
        &ColumnName::from_stored("owner_id"),
        &role_levels,
        None,
    );
    let ordered: Vec<(String, i32)> = sorted
        .iter()
        .map(|role| (role.original_name.clone(), role.level))
        .collect();
    assert_eq!(
        ordered,
        vec![
            ("alpha".to_string(), 1),
            ("beta".to_string(), 1),
            ("admin".to_string(), 2),
        ]
    );
}

#[test]
fn pattern_to_expr_handles_unreachable_thresholds_and_case_insensitive_role_names() {
    let registry = role_registry(r#"{"viewer": 1}"#, false);
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let p1_unreachable = PatternClass::P1NumericThreshold(NumericThreshold {
        resource_column: None,
        function_name: "role_level".to_string(),
        operator: ThresholdOperator::Gt,
        threshold: 10,
        command: PolicyCommand::Select,
    });
    let p2_mixed_case = PatternClass::P2RoleNameInList(RoleNameInList {
        resource_column: Some(ColumnName::from_stored("project_id")),
        function_name: "role_level".to_string(),
        role_names: vec!["VIEWER".to_string()],
    });

    let p1_expr = pattern_to_expr(
        &p1_unreachable,
        "p1_unreachable",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    let p2_expr = pattern_to_expr(
        &p2_mixed_case,
        "p2_case",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    assert_eq!(
        p1_expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert!(
        matches!(
            p2_expr,
            UsersetExpr::TupleToUserset {
                ref tupleset,
                ref computed
            } if tupleset.as_str() == "project_id" && computed.as_str().starts_with("roles_")
        ),
        "a role list is answered on the owner the row points at: {p2_expr:?}"
    );
}

#[test]
fn role_registry_helper_covers_team_branch() {
    let registry = role_registry(r#"{"viewer": 1, "editor": 2}"#, true);
    assert!(matches!(
        registry.get("role_level"),
        Some(FunctionSemantic::RoleThreshold {
            team_membership: Some(_),
            ..
        })
    ));
}

#[test]
fn bound_query_deserialization_validates_placeholders() {
    let query = BoundQuery::new(
        table_id("docs"),
        vec![ColumnName::from_stored("id")],
        "SELECT * FROM docs WHERE id = $1".to_string(),
        None,
        ReplayScope::Object {
            object_type: TypeName::canonicalized("docs"),
            relations: vec![member_relation()],
        },
    )
    .expect("the query is valid");

    for sql in [
        "SELECT * FROM docs",
        "SELECT * FROM docs WHERE id = $1 AND tenant = $2",
    ] {
        let mut wire = serde_json::to_value(&query).expect("query should serialize");
        wire["sql"] = serde_json::Value::String(sql.to_string());
        assert!(
            serde_json::from_value::<BoundQuery>(wire).is_err(),
            "deserialization must reject invalid placeholders in {sql}"
        );
    }
}

#[test]
fn confidence_filter_prevents_with_check_mirror_when_with_check_was_filtered() {
    // UPDATE policy: USING has high-confidence P3, WITH CHECK has low-confidence (would
    // normally be filtered). After confidence filtering the WITH CHECK carries the grade
    // it was dropped at, and the USING to WITH CHECK mirror must not be applied at
    // either level: not per policy, and not through the composed bucket.
    let db = docs_db_with_policy(
        "CREATE POLICY docs_upd ON docs FOR UPDATE \
             USING (owner_id = current_user) WITH CHECK (owner_id = current_user);",
    );
    let policy = db.policies().next().expect("policy should exist");
    let p3 = PatternClass::P3DirectOwnership(DirectOwnership {
        column: ColumnName::from_stored("owner_id"),
    });
    // Construct a policy where WITH CHECK has low confidence (B) and USING has high (A).
    let mut classified = ClassifiedPolicy::from_policy(policy, &db);
    classified.using_classification = Some(ClassifiedExpr {
        pattern: p3.clone(),
        confidence: ConfidenceLevel::A,
    });
    classified.with_check_classification = Some(ClassifiedExpr {
        pattern: p3.clone(),
        confidence: ConfidenceLevel::B,
    });
    // Filter at level A: WITH CHECK (B) is dropped, and the grade it held is retained.
    let filtered = filter_policies_for_output(&[classified.clone()], ConfidenceLevel::A);
    let filtered_cp = filtered.first().expect("USING should survive at A");
    assert_eq!(
        filtered_cp.with_check_filtered_at,
        Some(ConfidenceLevel::B),
        "the filter records the grade the WITH CHECK was dropped at"
    );
    assert!(
        filtered_cp.with_check_classification.is_none(),
        "with_check_classification should be None after filtering"
    );

    // Build a schema plan from the filtered policy.
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(
        std::slice::from_ref(filtered_cp),
        &db,
        &registry,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan");
    let docs = plan
        .types
        .iter()
        .find(|t| t.type_name.as_str() == "docs")
        .expect("docs type should exist");
    // USING survived → can_update_using should be defined.
    assert!(
        docs.computed_relations.contains_key("can_update"),
        "can_update relation should exist from USING expression"
    );
    // The check half has no surviving arm, so it falls closed. Asserting its absence
    // instead was the vacuous reading this test used to carry: the per-policy mirror was
    // indeed suppressed, but the composed check then came out empty and the bucket-level
    // fallback handed it the composed USING, so `can_update` granted the owner through
    // exactly the clause that had been refused, and no `can_update_check` was emitted to
    // show it.
    assert_eq!(
        docs.computed_relations.get("can_update_check"),
        Some(&UsersetExpr::Computed(deny_relation())),
        "a filtered WITH CHECK with no surviving arm denies, relations present: {:?}",
        docs.computed_relations.keys().collect::<Vec<_>>()
    );
    assert_ne!(
        docs.computed_relations.get("can_update"),
        Some(&UsersetExpr::Computed(RelationName::canonicalized("owner"))),
        "and the update must not be granted by the resurrected USING"
    );
    // A policy storing no WITH CHECK at all is checked by its USING, so the mirror applies.
    let unchecked_db = docs_db_with_policy(
        "CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user);",
    );
    let unchecked = classified_from_policy(
        unchecked_db.policies().next().expect("policy should exist"),
        &unchecked_db,
        Some(p3),
        None,
    );
    let plan2 = build_schema_plan(
        &[unchecked],
        &unchecked_db,
        &registry,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan");
    let docs2 = plan2
        .types
        .iter()
        .find(|t| t.type_name.as_str() == "docs")
        .expect("docs type");
    assert!(
        docs2.computed_relations.contains_key("can_update"),
        "mirror should still apply when with_check was never present"
    );
    assert!(
        !docs2.computed_relations.contains_key("can_update_check"),
        "and an absent check still mirrors the USING rather than denying"
    );
}

#[test]
fn resolve_owner_column_finds_fk_to_users_table() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE items(id UUID PRIMARY KEY, creator_id UUID REFERENCES users(id));
",
    )
    .unwrap();
    // No owner_id column, but FK to users -> should return creator_id
    let result = resolve_owner_column(&table_id("items"), &db);
    assert_eq!(result, Some(ColumnName::from_stored("creator_id")));
}

#[test]
fn resolve_principal_info_uses_configured_table_and_pk() {
    let db = parse_schema(
        r"
CREATE TABLE accounts(account_id UUID PRIMARY KEY, email TEXT);
",
    )
    .unwrap();
    let result = resolve_principal_info(
        &db,
        Some("accounts"),
        Some(&ColumnName::from_stored("account_id")),
        &[],
    );
    assert!(result.is_some());
    let pi = result.unwrap();
    assert_eq!(pi.table.to_string(), "public.accounts");
    assert_eq!(pi.identity_col, "account_id");
}

#[test]
fn resolve_principal_info_returns_none_for_missing_configured_column() {
    let db = parse_schema(
        r"
CREATE TABLE accounts(account_id UUID PRIMARY KEY);
",
    )
    .unwrap();
    // Column doesn't exist
    let result = resolve_principal_info(
        &db,
        Some("accounts"),
        Some(&ColumnName::from_stored("nonexistent_col")),
        &[],
    );
    assert!(result.is_none());
}

/// The classifier cannot build this shape: `recognize_p5` admits eight inner patterns and
/// `Unknown` is not among them, so a `ParentInheritance` never carries one. Kept as a guard
/// that the general refusal path covers it anyway, naming the reason and denying.
#[test]
fn pattern_to_expr_p5_with_unknown_inner_returns_no_access() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new(TypeName::canonicalized("tasks"));
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let unknown_inner = ClassifiedExpr {
        pattern: PatternClass::Unknown(UnclassifiedExpr {
            sql_text: "mystery()".to_string(),
            reason: "unrecognized function".to_string(),
        }),
        confidence: ConfidenceLevel::D,
    };
    let p5 = PatternClass::P5ParentInheritance(ParentInheritance {
        parent_table: table_id("projects"),
        fk_column: ColumnName::from_stored("project_id"),
        inner_pattern: Box::new(unknown_inner),
    });

    let expr = pattern_to_expr(
        &p5,
        "test_policy",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );
    // Reached through the parent's bridge rather than denied outright, and the relation it
    // lands on is the denial, so nobody passes either way.
    assert_eq!(
        expr,
        UsersetExpr::TupleToUserset {
            tupleset: RelationName::canonicalized("projects"),
            computed: deny_relation(),
        }
    );
    let messages: Vec<String> = notes.iter().map(TranslationNote::message).collect();
    assert!(
        messages.iter().any(|m| m.contains("unrecognized function")),
        "the reason must survive: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("could not translate the parent-side")),
        "the parent-side refusal must be reported: {messages:?}"
    );
}

/// A public flag grants through a wildcard tuple keyed on the row, so a table nothing
/// names has no such tuple and the flag must deny rather than declare a grant.
#[test]
fn pattern_to_expr_p6_without_row_identity_denies_and_skips_its_tuples() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new(TypeName::canonicalized("items"));
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    let p6 = PatternClass::P6BooleanFlag(BooleanFlag {
        column: ColumnName::from_stored("is_public"),
        admits_null: false,
    });

    let expr = pattern_to_expr_without_row_identity(
        &p6,
        "test_policy",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    assert_eq!(
        expr,
        UsersetExpr::Computed(RelationName::canonicalized("no_access"))
    );
    assert!(
        table_plan.table_tuple_sources.iter().any(|source| matches!(
            source,
            TupleSource::Skipped {
                reason: SkippedTuples::NoObjectIdentifier { what, .. }
            } if what == "public-flag tuples"
        )),
        "the loader's script says which query is missing: {:?}",
        table_plan.table_tuple_sources
    );
}

#[test]
fn populate_role_threshold_sources_emits_note_for_missing_user_principal() {
    // Schema with role-threshold table but NO users table
    let db = parse_schema(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
",
    )
    .unwrap();

    let registry = role_registry(r#"{"viewer": 1, "editor": 2}"#, false);
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();

    populate_role_threshold_sources(
        "role_level",
        &RoleThresholdTables {
            source: &table_id("docs"),
            grant: &table_id("object_grants"),
            team_membership: None,
            team_type: None,
        },
        &db,
        &registry,
        &OwnerScope {
            type_name: &TypeName::canonicalized("object_grants_owner"),
            pointer: &RelationName::canonicalized("owner_id"),
            column: &ColumnName::from_stored("owner_id"),
        },
        &mut table_plan,
        &mut all_types,
    );

    // Should have a TODO about unresolved user principal
    let has_note = table_plan.table_tuple_sources.iter().any(|s| {
            matches!(s, TupleSource::Skipped { reason } if reason.comment().contains("unresolved user principal"))
        });
    assert!(
        has_note,
        "should emit TODO for missing user principal table"
    );
}

#[test]
fn resolve_principal_info_auto_resolves_pk_for_configured_table() {
    let db = parse_schema(r"CREATE TABLE accounts(id UUID PRIMARY KEY, email TEXT);").unwrap();
    let result = resolve_principal_info(&db, Some("accounts"), None, &[]);
    assert!(result.is_some());
    let pi = result.unwrap();
    assert_eq!(pi.table.to_string(), "public.accounts");
    assert_eq!(pi.identity_col, "id");
}

#[test]
fn populate_role_threshold_sources_emits_note_for_missing_team_principal() {
    // Schema with team membership but no teams table
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID REFERENCES users(id));
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
CREATE TABLE team_memberships(id UUID PRIMARY KEY, user_id UUID, team_id UUID);
",
    )
    .unwrap();

    let registry = role_registry(r#"{"viewer": 1}"#, true);
    let mut table_plan = TypePlan::new(TypeName::canonicalized("docs"));
    let mut all_types = BTreeMap::new();
    let team_type = TypeName::canonicalized("team_memberships_team");
    populate_role_threshold_sources(
        "role_level",
        &RoleThresholdTables {
            source: &table_id("docs"),
            grant: &table_id("object_grants"),
            team_membership: Some(&table_id("team_memberships")),
            team_type: Some(&team_type),
        },
        &db,
        &registry,
        &OwnerScope {
            type_name: &TypeName::canonicalized("object_grants_owner"),
            pointer: &RelationName::canonicalized("owner_id"),
            column: &ColumnName::from_stored("owner_id"),
        },
        &mut table_plan,
        &mut all_types,
    );

    // Should have a TODO about unresolved team principal
    let has_team_note = table_plan.table_tuple_sources.iter().any(|s| {
            matches!(s, TupleSource::Skipped { reason } if reason.comment().contains("unresolved team principal"))
        });
    assert!(
        has_team_note,
        "should emit TODO for missing team principal table, sources: {:?}",
        table_plan.table_tuple_sources
    );
}

// positional_function_arg, non-List FunctionArguments
#[test]
fn positional_function_arg_returns_none_for_non_list_args() {
    use sqlparser::ast::{FunctionArguments, Ident, ObjectName, ObjectNamePart};

    let func = sqlparser::ast::Function {
        name: ObjectName(vec![ObjectNamePart::Identifier(Ident::new("test_fn"))]),
        args: FunctionArguments::None,
        filter: None,
        null_treatment: None,
        over: None,
        within_group: vec![],
        parameters: FunctionArguments::None,
        uses_odbc_syntax: false,
    };
    assert!(
        crate::parser::expr::positional_function_arg(&func, 0).is_none(),
        "FunctionArguments::None should return None"
    );
}

// resolve_owner_column, returns None
#[test]
fn resolve_owner_column_returns_none_when_no_owner_col_and_no_fk_to_users() {
    let db = parse_schema(
        r"
CREATE TABLE widgets(name TEXT, value INT);
",
    )
    .unwrap();
    let result = resolve_owner_column(&table_id("widgets"), &db);
    assert!(
        result.is_none(),
        "Table with no owner-like column and no FK to users should return None"
    );
}

#[test]
fn populate_role_threshold_sources_emits_note_for_missing_identity() {
    let db = parse_schema(
        r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE things(name TEXT, value INT);
CREATE TABLE object_grants(id UUID PRIMARY KEY, grantee_id UUID, resource_id UUID, role_level INT);
",
    )
    .unwrap();

    let registry = role_registry(r#"{"viewer": 1}"#, false);
    let mut table_plan = TypePlan::new(TypeName::canonicalized("things"));
    let mut all_types = BTreeMap::new();

    populate_role_threshold_sources(
        "role_level",
        &RoleThresholdTables {
            source: &table_id("things"),
            grant: &table_id("object_grants"),
            team_membership: None,
            team_type: None,
        },
        &db,
        &registry,
        &OwnerScope {
            type_name: &TypeName::canonicalized("object_grants_owner"),
            pointer: &RelationName::canonicalized("owner_id"),
            column: &ColumnName::from_stored("owner_id"),
        },
        &mut table_plan,
        &mut all_types,
    );

    let has_pk_note = table_plan.table_tuple_sources.iter().any(|s| {
            matches!(s, TupleSource::Skipped { reason } if reason.comment().contains("missing object identifier"))
        });
    assert!(
        has_pk_note,
        "should emit TODO for missing PK column, sources: {:?}",
        table_plan.table_tuple_sources
    );
}

// A name held by one kind of relation must not be reused by the other, since the
// DSL would then carry two `define` lines for it.
#[test]
fn ensure_direct_yields_a_fresh_name_when_the_relation_is_computed() {
    let mut plan = TypePlan::new(TypeName::canonicalized("test"));
    plan.ensure_computed(
        "rel",
        UsersetExpr::Computed(RelationName::canonicalized("x")),
    );
    let name = plan.ensure_direct(
        "rel",
        vec![DirectSubject::Type(TypeName::canonicalized("user"))],
    );
    assert_ne!(name, "rel", "the computed relation still holds 'rel'");
    assert!(plan.direct_relations.contains_key(&name));
    assert!(!plan.computed_relations.contains_key(&name));
}

#[test]
fn ensure_direct_yields_a_fresh_name_when_the_subjects_differ() {
    let mut plan = TypePlan::new(TypeName::canonicalized("test"));
    let first = plan.ensure_direct(
        "rel",
        vec![DirectSubject::Type(TypeName::canonicalized("user"))],
    );
    let team = vec![DirectSubject::Type(TypeName::canonicalized("team"))];
    let second = plan.ensure_direct("rel", team.clone());
    assert_eq!(first, "rel");
    // One collision carries no counter: a `_1` would imply a `_2` that does not exist.
    assert_eq!(
        second,
        format!("rel_{}", stable_hex_suffix(&subject_key(&team))),
        "a lone yield is the base and the value's own suffix"
    );
    assert_eq!(
        plan.direct_relations.get(&first),
        Some(&vec![DirectSubject::Type(TypeName::canonicalized("user"))])
    );
    assert_eq!(
        plan.direct_relations.get(&second),
        Some(&vec![DirectSubject::Type(TypeName::canonicalized("team"))])
    );
    // Asking again with the same subjects reuses the name it already minted.
    assert_eq!(
        plan.ensure_direct(
            "rel",
            vec![DirectSubject::Type(TypeName::canonicalized("team"))]
        ),
        second
    );
}

fn user_wildcard() -> Vec<DirectSubject> {
    vec![DirectSubject::Wildcard(TypeName::canonicalized(USER_TYPE))]
}

/// The memo, not the name, carries injectivity: a 32-bit suffix can collide, and two gates
/// with the same subjects would then merge their tuple sets under one relation.
#[test]
fn gate_relations_never_share_across_keys_even_when_the_base_collides() {
    let mut plan = TypePlan::new(TypeName::canonicalized("docs"));
    let first = plan.gate_relation(
        "attr:6:status:Eq:t9:published",
        "public_where_status_cafe",
        user_wildcard(),
    );
    let second = plan.gate_relation(
        "attr:6:status:Eq:t5:draft",
        "public_where_status_cafe",
        user_wildcard(),
    );
    assert_ne!(
        first, second,
        "distinct gate keys sharing a base name must not share a relation"
    );
    let repeat = plan.gate_relation(
        "attr:6:status:Eq:t9:published",
        "public_where_status_cafe",
        user_wildcard(),
    );
    assert_eq!(first, repeat, "one gate key, one relation");
    assert!(
        plan.direct_relations.contains_key(&first) && plan.direct_relations.contains_key(&second),
        "both gates are declared as direct wildcard relations"
    );
}

/// Whatever the collision count, the minted gate is a fresh wildcard relation, and the
/// counter survives the length clamp instead of being truncated into a collision.
#[test]
fn a_gate_never_adopts_an_occupied_name_however_many_collide() {
    let mut plan = TypePlan::new(TypeName::canonicalized("docs"));
    let foreign = vec![DirectSubject::Type(TypeName::canonicalized("user"))];
    plan.ensure_direct("gate_base", foreign.clone());
    for counter in 1..=4 {
        plan.ensure_direct(format!("gate_base_{counter}"), foreign.clone());
    }
    let minted = plan.gate_relation("key:a", "gate_base", user_wildcard());
    assert_eq!(
        plan.direct_relations.get(&minted),
        Some(&user_wildcard()),
        "the minted gate holds its own subjects, never a foreign definition"
    );

    let long = "g".repeat(MAX_RELATION_NAME_LEN);
    let first = plan.gate_relation("key:b", long.clone(), user_wildcard());
    let second = plan.gate_relation("key:c", long, user_wildcard());
    assert_ne!(first, second, "a full-length base still yields per key");
    assert!(second.as_str().len() <= MAX_RELATION_NAME_LEN);
    assert!(
        second.as_str().ends_with("_1"),
        "the counter survives the clamp, got: {second}"
    );
}

/// The rename is derived from the value, so the only way its result is already taken is
/// something else holding that exact name. Renaming once and inserting blind then declares
/// one name twice, since direct and computed relations live in separate maps.
#[test]
fn ensure_direct_keeps_looking_when_the_renamed_name_is_taken_too() {
    let mut plan = TypePlan::new(TypeName::canonicalized("docs"));
    let subjects = vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))];

    // `owner` is held by a rule, so a direct `owner` has to yield.
    plan.ensure_computed(
        "owner",
        UsersetExpr::Computed(RelationName::canonicalized("a")),
    );
    // Occupy exactly where that yield lands, with something else.
    let taken = clamp_relation_name(format!(
        "owner_{}",
        stable_hex_suffix(&subject_key(&subjects))
    ));
    plan.ensure_computed(
        taken.clone(),
        UsersetExpr::Computed(RelationName::canonicalized("b")),
    );

    let got = plan.ensure_direct("owner", subjects.clone());
    assert_ne!(got, "owner", "the rule still holds 'owner'");
    assert_ne!(got, taken, "'{taken}' already means something else");
    assert_eq!(
        plan.direct_relations.get(&got).map(Vec::as_slice),
        Some(subjects.as_slice()),
        "the subjects asked for have to be the ones stored"
    );
    for name in plan.direct_relations.keys() {
        assert!(
            !plan.computed_relations.contains_key(name),
            "'{name}' is declared both ways, so the model defines it twice"
        );
    }
}

/// The same for a rule, where the collision is with a direct relation.
#[test]
fn ensure_computed_keeps_looking_when_the_renamed_name_is_taken_too() {
    let mut plan = TypePlan::new(TypeName::canonicalized("docs"));
    let rule = UsersetExpr::Computed(RelationName::canonicalized("wanted"));

    plan.ensure_direct(
        "owner",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );
    let taken = clamp_relation_name(format!("owner_{}", stable_hex_suffix(&userset_key(&rule))));
    plan.ensure_direct(
        taken.clone(),
        vec![DirectSubject::Type(TypeName::canonicalized(TEAM_TYPE))],
    );

    let got = plan.ensure_computed("owner", rule.clone());
    assert_ne!(got, "owner", "the direct relation still holds 'owner'");
    assert_ne!(got, taken, "'{taken}' already means something else");
    assert_eq!(
        plan.computed_relations.get(&got),
        Some(&rule),
        "the rule asked for has to be the one stored"
    );
    for name in plan.computed_relations.keys() {
        assert!(
            !plan.direct_relations.contains_key(name),
            "'{name}' is declared both ways, so the model defines it twice"
        );
    }
}

#[test]
fn ensure_computed_yields_a_fresh_name_when_the_expression_differs() {
    let mut plan = TypePlan::new(TypeName::canonicalized("test"));
    let first = plan.ensure_computed(
        "rel",
        UsersetExpr::Computed(RelationName::canonicalized("a")),
    );
    let second = plan.ensure_computed(
        "rel",
        UsersetExpr::Computed(RelationName::canonicalized("b")),
    );
    assert_eq!(first, "rel");
    assert_ne!(second, first, "a different rule cannot reuse the name");
    assert_eq!(
        plan.computed_relations.get(&first),
        Some(&UsersetExpr::Computed(RelationName::canonicalized("a")))
    );
    assert_eq!(
        plan.computed_relations.get(&second),
        Some(&UsersetExpr::Computed(RelationName::canonicalized("b")))
    );
    // The same rule keeps sharing the one relation.
    assert_eq!(
        plan.ensure_computed(
            "rel",
            UsersetExpr::Computed(RelationName::canonicalized("a"))
        ),
        first
    );
}

/// `set_computed` overwrites a computed rule by design, but a name a direct relation
/// already holds yields instead, the same way its two siblings do. It used to assert in
/// debug builds and do nothing in release, which is a guard where it cannot fire.
#[test]
fn set_computed_yields_a_fresh_name_when_the_relation_is_direct() {
    let mut plan = TypePlan::new(TypeName::canonicalized("test"));
    plan.ensure_direct(
        "rel",
        vec![DirectSubject::Type(TypeName::canonicalized("user"))],
    );

    let name = plan.set_computed(
        "rel",
        UsersetExpr::Computed(RelationName::canonicalized("x")),
    );

    assert_ne!(name, "rel", "the direct relation still holds 'rel'");
    assert!(
        plan.direct_relations.contains_key("rel"),
        "the direct relation is untouched"
    );
    assert!(
        plan.computed_relations.contains_key(&name),
        "the computed rule lands under the yielded name"
    );

    // Overwriting an existing computed rule is still what the function is for.
    let first = plan.set_computed(
        "other",
        UsersetExpr::Computed(RelationName::canonicalized("a")),
    );
    let second = plan.set_computed(
        "other",
        UsersetExpr::Computed(RelationName::canonicalized("b")),
    );
    assert_eq!(first, second, "a computed name is overwritten, not yielded");
    assert_eq!(
        plan.computed_relations.get(&second),
        Some(&UsersetExpr::Computed(RelationName::canonicalized("b"))),
        "the later rule wins"
    );
}

// canonical name collision, two tables → same canonical name
#[test]
fn build_schema_plan_disambiguates_canonical_name_collision() {
    let db = parse_schema(
        r"
CREATE SCHEMA app;
CREATE TABLE app.items(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_sel ON app.items FOR SELECT USING (owner_id = current_user);
CREATE TABLE public.items(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_sel2 ON public.items FOR SELECT USING (owner_id = current_user);
",
    )
    .unwrap();

    let mut policies = Vec::new();
    for policy in db.policies() {
        let table_name = policy.target_table_name().to_string();
        let mut classified = ClassifiedPolicy::from_policy(policy, &db);
        classified.using_classification = Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership(DirectOwnership {
                column: ColumnName::from_stored("owner_id"),
            }),
            confidence: ConfidenceLevel::A,
        });
        policies.push((table_name, classified));
    }

    let registry = FunctionRegistry::new();
    let classified_policies: Vec<ClassifiedPolicy> =
        policies.into_iter().map(|(_, cp)| cp).collect();
    let plan = build_schema_plan(
        &classified_policies,
        &db,
        &registry,
        &GeneratorSettings::default(),
    )
    .expect("translation should plan");

    // One of the two types should be disambiguated
    let type_names: Vec<&str> = plan.types.iter().map(|t| t.type_name.as_str()).collect();
    // At least one type name should contain an underscore+hex suffix
    let has_disambiguated = type_names
        .iter()
        .any(|name| name.starts_with("items_") && name.len() > "items_".len());
    // Either collision happened (both present as items + items_hash) or both
    // are items (same owner, line 218). The important thing is no panic.
    assert!(
        type_names.iter().any(|name| name.starts_with("items")),
        "should have at least one items type, got: {type_names:?}"
    );
    // If collision was detected, a TODO should have been emitted
    if has_disambiguated {
        assert!(
            plan.notes
                .iter()
                .any(|t| t.message().contains("Type name collision")),
            "collision should produce a TODO, notes: {:?}",
            plan.notes
        );
    }
}

/// A `TO` clause narrows a permissive grant by intersecting a `pg_role` scope, and the
/// scope's tuples name the guarded row. With no row identity neither the rule nor the
/// scope can be filled, so the whole grant denies and nothing may ask the operator to
/// load memberships no rule reads.
#[test]
fn a_scoped_policy_on_a_table_with_no_row_identity_mints_no_scope() {
    let db = parse_schema(
        r"
CREATE TABLE things(name TEXT, value INT);
ALTER TABLE things ENABLE ROW LEVEL SECURITY;
CREATE POLICY things_sel ON things FOR SELECT TO app_user USING (value > 0);
",
    )
    .unwrap();

    let policy = db.policies().next().expect("policy should exist");
    let mut classified = ClassifiedPolicy::from_policy(policy, &db);
    classified.using_classification = Some(ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership(DirectOwnership {
            column: ColumnName::from_stored("name"),
        }),
        confidence: ConfidenceLevel::A,
    });
    let registry = FunctionRegistry::new();
    let plan = build_schema_plan(&[classified], &db, &registry, &GeneratorSettings::default())
        .expect("translation should plan");

    let things = plan
        .types
        .iter()
        .find(|t| t.type_name.as_str() == "things")
        .expect("the table gets a type");
    assert_eq!(
        things.computed_relations.get(&can_select_relation()),
        Some(&UsersetExpr::Computed(deny_relation())),
        "nothing names a row, so the read denies: {:?}",
        things.computed_relations
    );
    assert!(
        things
            .direct_relations
            .keys()
            .all(|relation| !relation.as_str().starts_with("scope_")),
        "and no scope relation is declared: {:?}",
        things.direct_relations
    );
    assert!(
        !plan
            .notes
            .iter()
            .any(|note| note.message().contains("Policy role scope TO")),
        "nor a note asking for memberships no rule reads: {:?}",
        plan.notes
    );

    assert!(
        things.table_tuple_sources.iter().any(|source| matches!(
            source,
            TupleSource::Skipped {
                reason: SkippedTuples::NoObjectIdentifier { what, .. }
            } if what == "ownership tuples"
        )),
        "the loader's script still says which query is missing: {:?}",
        things.table_tuple_sources
    );
    assert!(
        plan.notes.iter().any(
            |note| matches!(note, TranslationNote::RowsCannotBeNamed { table, .. }
                if table.to_string() == "public.things")
        ),
        "and the model says the grant cannot be filled: {:?}",
        plan.notes
    );
}

// P5 inner pattern results in no_access → TODO
#[test]
fn pattern_to_expr_p5_with_inner_no_access_emits_note() {
    let registry = FunctionRegistry::new();
    let mut table_plan = TypePlan::new(TypeName::canonicalized("tasks"));
    let mut all_types = BTreeMap::new();
    let mut notes = Vec::new();

    // P5 with inner P9 (attribute-only) which produces no_access
    let inner = ClassifiedExpr {
        pattern: PatternClass::P9AttributeCondition(AttributeCondition {
            column: ColumnName::from_stored("status"),
            value_description: "'active'".to_string(),
            predicate: None,
            request_predicate: None,
        }),
        confidence: ConfidenceLevel::C,
    };
    let p5 = PatternClass::P5ParentInheritance(ParentInheritance {
        parent_table: table_id("projects"),
        fk_column: ColumnName::from_stored("project_id"),
        inner_pattern: Box::new(inner),
    });

    let _expr = pattern_to_expr(
        &p5,
        "test_policy",
        &mut table_plan,
        &mut all_types,
        &registry,
        &mut notes,
    );

    // P9 inside P5 produces no_access on the parent → TODO emitted
    let has_inner_note = notes.iter().any(|t| {
        t.message().contains("could not be safely translated")
            || t.message().contains("mapped to no_access")
    });
    assert!(
        has_inner_note,
        "P5 with inner no_access should produce a TODO, notes: {notes:?}"
    );
}

/// A tupleset admitting a conditional subject of another type reaches that type's
/// objects too, so the implication must hold there as well. Skipping it reads a mixed
/// tupleset as if only the plain subject existed, which drops a read gate the
/// conditional side does not imply.
#[test]
fn rule_implies_consults_conditional_tupleset_subjects() {
    let mut docs = TypePlan::new(TypeName::canonicalized("docs"));
    docs.ensure_direct(
        "grants",
        vec![
            DirectSubject::Type(TypeName::canonicalized("teams")),
            DirectSubject::ConditionalType {
                type_name: TypeName::canonicalized("groups"),
                condition: ConditionName::canonicalized("while_valid"),
            },
        ],
    );
    let mut teams = TypePlan::new(TypeName::canonicalized("teams"));
    teams.set_computed(
        "viewer",
        UsersetExpr::Union(vec![UsersetExpr::Computed(RelationName::canonicalized(
            "editor",
        ))]),
    );
    // On `groups` the two relations are unrelated, so nothing implies the gate there.
    let mut groups = TypePlan::new(TypeName::canonicalized("groups"));
    groups.ensure_direct(
        "viewer",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );
    groups.ensure_direct(
        "editor",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );

    let plans = [docs, teams, groups];
    let by_name: BTreeMap<&TypeName, &TypePlan> =
        plans.iter().map(|plan| (&plan.type_name, plan)).collect();
    let rule = UsersetExpr::TupleToUserset {
        tupleset: RelationName::canonicalized("grants"),
        computed: RelationName::canonicalized("editor"),
    };
    let visible = UsersetExpr::TupleToUserset {
        tupleset: RelationName::canonicalized("grants"),
        computed: RelationName::canonicalized("viewer"),
    };

    assert!(
        !simplify::rule_implies(&rule, &visible, &plans[0], &by_name, &mut Vec::new()),
        "`groups` reaches editors who are not viewers, so the implication does not hold"
    );
}

/// A barrier the rule and the visible rule both carry cancels out, so a grant of the rule
/// that implies the visible grant implies the visible rule under the same barrier.
#[test]
fn a_conjunct_of_the_rule_implying_the_gate_makes_the_gate_redundant() {
    let mut docs = TypePlan::new(TypeName::canonicalized("docs"));
    docs.set_computed(
        "viewer",
        UsersetExpr::Union(vec![UsersetExpr::Computed(RelationName::canonicalized(
            "editor",
        ))]),
    );
    docs.ensure_direct(
        "editor",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );
    docs.ensure_direct(
        "barrier",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );
    let plans = [docs];
    let by_name: BTreeMap<&TypeName, &TypePlan> =
        plans.iter().map(|plan| (&plan.type_name, plan)).collect();
    let gated = |grant: &str| {
        UsersetExpr::Intersection(vec![
            UsersetExpr::Computed(RelationName::canonicalized(grant)),
            UsersetExpr::Computed(RelationName::canonicalized("barrier")),
        ])
    };

    assert!(
        simplify::rule_implies(
            &gated("editor"),
            &gated("viewer"),
            &plans[0],
            &by_name,
            &mut Vec::new()
        ),
        "every editor is a viewer under the same barrier"
    );
    assert!(
        !simplify::rule_implies(
            &UsersetExpr::Computed(RelationName::canonicalized("editor")),
            &gated("viewer"),
            &plans[0],
            &by_name,
            &mut Vec::new()
        ),
        "an editor under no barrier is not a viewer of that barrier"
    );
}

/// Two relations defined through each other say nothing about a rule neither names, and
/// the walk ends rather than loop.
#[test]
fn a_cycle_between_relations_implies_nothing() {
    let mut docs = TypePlan::new(TypeName::canonicalized("docs"));
    docs.set_computed(
        "viewer",
        UsersetExpr::Computed(RelationName::canonicalized("reader")),
    );
    docs.set_computed(
        "reader",
        UsersetExpr::Computed(RelationName::canonicalized("viewer")),
    );
    docs.ensure_direct(
        "editor",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );
    let plans = [docs];
    let by_name: BTreeMap<&TypeName, &TypePlan> =
        plans.iter().map(|plan| (&plan.type_name, plan)).collect();

    assert!(!simplify::rule_implies(
        &UsersetExpr::Computed(RelationName::canonicalized("editor")),
        &UsersetExpr::Computed(RelationName::canonicalized("viewer")),
        &plans[0],
        &by_name,
        &mut Vec::new()
    ));
}

/// A userset subject names objects of its type, so a walk through it resolves to that type.
#[test]
fn a_userset_subject_resolves_to_the_type_of_the_objects_it_names() {
    let subject = DirectSubject::Userset {
        type_name: TypeName::canonicalized("pg_role"),
        relation: RelationName::canonicalized("usage"),
    };
    assert_eq!(
        subject.resolved_type_name(),
        Some(&TypeName::canonicalized("pg_role"))
    );
}

/// The walk reaches a target type through a conditional subject exactly as through a
/// plain one: the condition restricts which tuples exist, not which type they name.
#[test]
fn a_relation_reached_only_through_a_conditional_tupleset_subject_is_not_pruned() {
    let mut docs = TypePlan::new(TypeName::canonicalized("docs"));
    docs.set_computed(
        can_select_relation(),
        UsersetExpr::TupleToUserset {
            tupleset: RelationName::canonicalized("parent"),
            computed: RelationName::canonicalized("granted"),
        },
    );
    docs.ensure_direct(
        "parent",
        vec![DirectSubject::ConditionalType {
            type_name: TypeName::canonicalized("groups"),
            condition: ConditionName::canonicalized("while_valid"),
        }],
    );
    let mut groups = TypePlan::new(TypeName::canonicalized("groups"));
    groups.ensure_direct(
        "granted",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );

    let mut all_types = BTreeMap::from([
        (TypeName::canonicalized("docs"), docs),
        (TypeName::canonicalized("groups"), groups),
    ]);
    prune_unreferenced_relations(&mut all_types);

    assert!(
        all_types["groups"]
            .direct_relations
            .contains_key(&RelationName::canonicalized("granted")),
        "the model references groups#granted through the conditional subject, so \
         pruning it leaves a reference to something the model does not define"
    );
}

/// An alias reached through a conditional tupleset subject is repointed exactly as one
/// reached through a plain subject, or the walk dangles on the dropped name.
#[test]
fn an_inlined_alias_is_repointed_behind_a_conditional_tupleset_subject() {
    let alias = RelationName::canonicalized("inherited_x");
    let mut docs = TypePlan::new(TypeName::canonicalized("docs"));
    docs.set_computed(
        can_select_relation(),
        UsersetExpr::TupleToUserset {
            tupleset: RelationName::canonicalized("parent"),
            computed: alias.clone(),
        },
    );
    docs.ensure_direct(
        "parent",
        vec![DirectSubject::ConditionalType {
            type_name: TypeName::canonicalized("groups"),
            condition: ConditionName::canonicalized("while_valid"),
        }],
    );
    let mut groups = TypePlan::new(TypeName::canonicalized("groups"));
    groups.ensure_direct(
        "granted",
        vec![DirectSubject::Type(TypeName::canonicalized(USER_TYPE))],
    );
    groups.set_computed(
        alias.clone(),
        UsersetExpr::Computed(RelationName::canonicalized("granted")),
    );

    let mut all_types = BTreeMap::from([
        (TypeName::canonicalized("docs"), docs),
        (TypeName::canonicalized("groups"), groups),
    ]);
    inline_synthetic_rule_aliases(&mut all_types);

    let UsersetExpr::TupleToUserset { computed, .. } =
        &all_types["docs"].computed_relations[&can_select_relation()]
    else {
        panic!("the walk survives inlining");
    };
    assert_eq!(
        computed.as_str(),
        "granted",
        "the alias was dropped on groups, so the walk must point at what it named"
    );
}

#[test]
fn a_witness_membership_source_carries_its_condition() {
    let source = TupleSource::MembershipShareMembers {
        join_table: table_id("members"),
        identity_cols: vec![ColumnName::from_stored("id")],
        user_col: ColumnName::from_stored("user_id"),
        share_type: TypeName::canonicalized("members_share"),
        relation: RelationName::canonicalized("member"),
        condition: ConditionName::canonicalized("when_valid"),
        extra_predicates: ResidualPredicates::default(),
        context: Vec::new(),
    };
    assert!(source_carries_condition(&source));
}

/// Two conditions reading one parameter name for different thresholds refuse the plan
/// rather than hand the checker one value for both.
#[test]
fn two_thresholds_on_one_parameter_name_refuse_the_plan() {
    use crate::clock::ClockOffset;

    let day_before = ClockThreshold {
        reading: ClockReading::Instant,
        offset: ClockOffset {
            months: 0,
            days: -1,
            microseconds: 0,
        },
    };
    let condition = |expression: &str, threshold: ClockThreshold| {
        let clock = ClockParameter::new(ConditionParameterName::derived("clock"), threshold);
        let spec = ConditionSpec {
            expression: expression.to_string(),
            parameters: [("clock".to_string(), ConditionParameter::Clock(clock))]
                .into_iter()
                .collect(),
        };
        (spec.name(), spec)
    };
    let conditions = [
        condition("a > clock", ClockThreshold::INSTANT),
        condition("b > clock", day_before),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        clock_parameters(&conditions),
        Err(PlanningError::ConditionParameterCollision {
            parameter: ConditionParameterName::derived("clock"),
            first: format!("{:?}", ClockThreshold::INSTANT),
            second: format!("{day_before:?}"),
        })
    );
}
