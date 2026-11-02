//! The example schemas the web app offers, translated with the settings the app uses.
//!
//! The app builds outside this workspace, so a library change that demotes an example
//! shows up here rather than on the deployed site.

#[expect(
    dead_code,
    unreachable_pub,
    reason = "the web app reads the icons and exports these"
)]
#[path = "../../web/src/examples.rs"]
mod examples;

#[expect(unreachable_pub, reason = "the web app imports these")]
#[path = "../../web/src/settings.rs"]
mod settings;

use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::types::ConfidenceLevel;

/// The level every policy of every example classifies at.
#[test]
fn every_example_classifies_at_its_documented_level() {
    let expected: &[(&str, &[(&str, ConfidenceLevel)])] = &[
        (
            "Ownership",
            &[
                ("resources_delete", ConfidenceLevel::A),
                ("resources_select", ConfidenceLevel::A),
            ],
        ),
        ("Membership", &[("projects_select", ConfidenceLevel::A)]),
        (
            "Parent",
            &[
                ("projects_owner", ConfidenceLevel::A),
                ("tasks_inherit_project", ConfidenceLevel::A),
            ],
        ),
        ("Public flag", &[("articles_select", ConfidenceLevel::B)]),
        ("Role list", &[("ownables_read", ConfidenceLevel::A)]),
        ("Composite OR", &[("documents_select", ConfidenceLevel::B)]),
        ("Attribute", &[("documents_active", ConfidenceLevel::B)]),
    ];
    assert_eq!(
        expected.len(),
        examples::EXAMPLES.len(),
        "every example the app offers is pinned"
    );
    for (label, levels) in expected {
        let example = examples::EXAMPLES
            .iter()
            .find(|example| example.label == *label)
            .unwrap_or_else(|| panic!("the app offers {label}"));
        let db = parse_schema(example.sql).expect("the example parses");
        let outputs = settings::translator(ConfidenceLevel::D)
            .expect("the app's registry loads")
            .translate(&db)
            .expect("the example plans")
            .outputs_accepting_gaps();
        let reported: Vec<(&str, ConfidenceLevel)> = outputs
            .confidence_summary()
            .iter()
            .map(|(policy, level)| (policy.as_str(), *level))
            .collect();
        assert_eq!(reported, *levels, "{label}");
    }
}
