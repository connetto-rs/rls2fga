use rls2fga::classifier::function_registry::{
    FunctionRegistry, SessionAttribute, SessionAttributeKind,
};
use rls2fga::classifier::patterns::*;
use rls2fga::classifier::policy_classifier;
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

use crate::support;

fn load_emi_fixture() -> (rls2fga::parser::sql_parser::ParserDB, FunctionRegistry) {
    support::load_fixture_db_and_registry("earth_metabolome")
}

fn p1_threshold_for(policy_name: &str) -> i32 {
    let (db, registry) = load_emi_fixture();
    let classified = policy_classifier::classify_policies(&db, &registry);
    let policy = classified.iter().find(|c| c.name() == policy_name).unwrap();
    match policy.using_classification() {
        Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold(NumericThreshold { threshold, .. }),
            ..
        }) => *threshold,
        other => panic!("expected P1NumericThreshold for {policy_name}, got: {other:?}"),
    }
}

#[test]
fn classify_emi_policies_as_p1() {
    let (db, registry) = load_emi_fixture();
    let classified = policy_classifier::classify_policies(&db, &registry);

    assert_eq!(classified.len(), 4);

    for cp in &classified {
        let classification = cp
            .using_classification()
            .or(cp.with_check_classification())
            .expect("Should have at least one classification");

        assert!(
            matches!(
                classification.pattern,
                PatternClass::P1NumericThreshold(NumericThreshold { .. })
            ),
            "Policy '{}' should be P1, got {:?}",
            cp.name(),
            classification.pattern,
        );

        assert_eq!(
            classification.confidence,
            ConfidenceLevel::A,
            "Policy '{}' should be Level A",
            cp.name(),
        );
    }
}

#[test]
fn classify_emi_select_threshold() {
    assert_eq!(p1_threshold_for("ownables_select_policy"), 2);
}

#[test]
fn classify_emi_delete_threshold() {
    assert_eq!(p1_threshold_for("ownables_delete_policy"), 4);
}

#[test]
fn classify_simple_ownership_as_p3() {
    let db = support::parse_fixture_db("simple_ownership");

    let mut registry = FunctionRegistry::new();
    // Register auth_current_user_id from the parsed functions
    registry.register_if_absent(
        "auth_current_user_id",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );

    let classified = policy_classifier::classify_policies(&db, &registry);

    for cp in &classified {
        let classification = cp
            .using_classification()
            .expect("Should have USING classification");

        assert!(
            matches!(
                classification.pattern,
                PatternClass::P3DirectOwnership(DirectOwnership { .. })
            ),
            "Expected P3, got {:?}",
            classification.pattern,
        );
        assert_eq!(classification.confidence, ConfidenceLevel::A);
    }
}

#[test]
fn classify_public_flag_as_p6_heuristic_gives_confidence_b() {
    // Without explicit registration the heuristic match is capped at B so that
    // wildcard public-access grants always surface for manual review.
    let db = support::parse_fixture_db("public_flag");
    let registry = FunctionRegistry::new();

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp.using_classification().unwrap();
    assert!(
        matches!(
            classification.pattern,
            PatternClass::P6BooleanFlag(BooleanFlag { .. })
        ),
        "Expected P6, got {:?}",
        classification.pattern,
    );
    assert_eq!(
        classification.confidence,
        ConfidenceLevel::B,
        "Unregistered public-flag column should produce confidence B, not A"
    );
}

#[test]
fn classify_public_flag_registered_column_gives_confidence_a() {
    let db = support::parse_fixture_db("public_flag");
    let mut registry = FunctionRegistry::new();
    registry.register_public_flag_column("is_public");

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp.using_classification().unwrap();
    assert!(
        matches!(
            classification.pattern,
            PatternClass::P6BooleanFlag(BooleanFlag { .. })
        ),
        "Expected P6, got {:?}",
        classification.pattern,
    );
    assert_eq!(
        classification.confidence,
        ConfidenceLevel::A,
        "Explicitly registered public-flag column should produce confidence A"
    );
}

#[test]
fn classify_abac_status_as_a_threshold_beside_a_literal_guard() {
    let (db, registry) = support::load_fixture_db_and_registry("abac_status");

    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp.using_classification().unwrap();
    // The literal guard is row data the tuples carry, so the pair keeps its
    // structure instead of flattening to the partial P7 column name.
    assert!(
        matches!(
            &classification.pattern,
            PatternClass::P8Composite(Composite { parts, .. })
                if parts.iter().any(|part| matches!(
                    &part.pattern,
                    PatternClass::P1NumericThreshold(NumericThreshold { .. })
                )) && parts.iter().any(|part| matches!(
                    &part.pattern,
                    PatternClass::P9AttributeCondition(AttributeCondition { predicate: Some(_), .. })
                ))
        ),
        "Expected threshold beside the literal guard, got {:?}",
        classification.pattern,
    );
    assert_eq!(classification.confidence, ConfidenceLevel::B);
}

#[test]
fn classify_tenant_isolation_without_registry_via_function_body_inference() {
    let db = support::parse_fixture_db("tenant_isolation");
    let classified = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "app.tenant_id",
            SessionAttributeKind::CallerId,
        )
        .with_identity_cast("uuid")])
        .build()
        .classify(&db);
    assert_eq!(classified.len(), 1);

    let cp = &classified[0];
    let classification = cp
        .using_classification()
        .expect("tenant policy should have USING classification");
    match &classification.pattern {
        PatternClass::P3DirectOwnership(DirectOwnership { column }) => {
            assert_eq!(column, "tenant_id");
            assert_eq!(classification.confidence, ConfidenceLevel::A);
        }
        other => panic!("expected inferred P3 for tenant isolation, got: {other:?}"),
    }
}
