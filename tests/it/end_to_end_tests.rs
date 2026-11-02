use rls2fga::classifier::policy_classifier;
use rls2fga::generator::tuple_generator;
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
    let classified = policy_classifier::classify_policies(&db, &registry);
    assert_eq!(classified.len(), 4, "Should classify all 4 policies");

    // Stage 5: Generate model
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    insta::assert_snapshot!("emi_model", model.model().trim());

    // Stage 6: Generate tuples
    let outputs = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);
    let tuples = outputs.tuple_queries();
    insta::assert_snapshot!("emi_tuples", tuple_generator::format_tuples(tuples));

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

/// A role hierarchy already orders its levels, so `role_admin` implies the
/// `role_viewer` that `can_select` grants and requiring the read again adds
/// nothing. The gate has to recognize that through the levels between them.
#[test]
fn end_to_end_emi_role_hierarchy_needs_no_read_gate() {
    let (db, registry) = support::load_fixture_db_and_registry("earth_metabolome");
    let classified = policy_classifier::classify_policies(&db, &registry);
    let model = support::plan_at(classified.clone(), &db, &registry, ConfidenceLevel::B);

    for line in model.model().lines().map(str::trim) {
        let Some(body) = line
            .strip_prefix("define can_delete:")
            .or_else(|| line.strip_prefix("define can_update:"))
        else {
            continue;
        };
        assert!(
            !body.contains("can_select"),
            "'{line}' gates on a read the role level already implies:\n{}",
            model.model()
        );
    }
}

/// Pipeline test: all EMI policies should be Level A confidence.
#[test]
fn end_to_end_emi_all_level_a() {
    let (db, registry) = support::load_fixture_db_and_registry("earth_metabolome");

    let classified = policy_classifier::classify_policies(&db, &registry);

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
