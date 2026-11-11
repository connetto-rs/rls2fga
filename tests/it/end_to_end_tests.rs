use rls2fga::classifier::policy_classifier;
use rls2fga::types::ConfidenceLevel;

use crate::support;

/// Full pipeline end-to-end test for the EMI schema.
/// This is the primary acceptance test.
#[test]
fn end_to_end_earth_metabolome() {
    // Stage 1-2: Parse
    let sql = support::read_fixture_sql("earth_metabolome");
    let db = rls2fga::parser::sql_parser::parse_schema(&sql).expect("fixture SQL should parse");
    let registry = support::load_fixture_registry("earth_metabolome");

    // Stage 4: Classify
    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::fixture_deployment("earth_metabolome"),
    );
    assert_eq!(classified.len(), 4, "Should classify all 4 policies");

    // Stage 5: Generate model
    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

    // Nothing about the translation itself falls short at Level A/B. Every RLS table
    // still carries the owner-bypass note, which is a fact about the database rather
    // than a shortfall, so it is excluded here by severity rather than by wording.
    let shortfalls: Vec<&rls2fga::types::TranslationNote> = model
        .notes()
        .iter()
        .filter(|note| note.severity().diverges_from_database())
        .collect();
    assert!(
        shortfalls.is_empty(),
        "EMI schema should translate fully, got {shortfalls:?}"
    );
}

/// Pipeline test: all EMI policies should be Level A confidence.
#[test]
fn end_to_end_emi_all_level_a() {
    let (db, registry) = support::load_fixture_db_and_registry("earth_metabolome");

    let classified = policy_classifier::classify_policies(
        &db,
        &registry,
        &support::deployment::fixture_deployment("earth_metabolome"),
    );

    for cp in &classified {
        for c in cp.classifications() {
            assert_eq!(
                c.confidence,
                ConfidenceLevel::A,
                "Policy '{}' should be Level A, got Level {}",
                cp.name(),
                c.confidence,
            );
        }
    }
}
