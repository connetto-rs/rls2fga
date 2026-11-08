use rls2fga::generator::tuple_generator;
use rls2fga::types::ConfidenceLevel;

use crate::support;

#[test]
fn formatter_uses_same_tuple_format_as_tuple_generator_helper() {
    let (classified, db, registry) = support::load_fixture_classified("earth_metabolome");
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);
    let expected = tuple_generator::format_tuples(outputs.tuple_queries());

    let out_dir = support::unique_temp_dir("rls2fga_formatter");
    outputs.write(&out_dir, "emi").unwrap();
    let written = std::fs::read_to_string(out_dir.join("emi_tuples.sql")).unwrap();

    assert_eq!(
        written, expected,
        "output formatter should match tuple_generator::format_tuples exactly"
    );
}

/// A dropped policy is missing from the model and tuples, so only the report can
/// tell the operator it was lost.
#[test]
fn formatter_report_discloses_policies_below_min_confidence() {
    let (classified, db, registry) = support::classify_sql(
        r"
CREATE TABLE docs(id uuid primary key, owner_id uuid);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY p_unknown ON docs FOR SELECT USING (mystery_auth(owner_id));
",
        None,
    );
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

    let out_dir = support::unique_temp_dir("rls2fga_formatter_report_threshold");
    outputs
        .write(&out_dir, "docs")
        .expect("write should succeed");

    let report =
        std::fs::read_to_string(out_dir.join("docs_report.md")).expect("report should be written");

    assert!(
        report.contains("p_owner (USING)"),
        "high-confidence policy should remain in report"
    );
    assert!(
        report.contains("Dropped Below Confidence B"),
        "the report must carry a dropped-clause section:\n{report}"
    );
    assert!(
        report.contains("`p_unknown` (USING"),
        "a below-threshold policy must be named as dropped:\n{report}"
    );
}
