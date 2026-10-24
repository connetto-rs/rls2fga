//! A literal `IN` list guard is row data, so it translates as a single literal does.

use rls2fga::generator::tuple_generator::{format_tuples, TupleQuery};
use rls2fga::translator::Outputs;
use rls2fga::types::{
    records_from_row, ConfidenceLevel, NoteSeverity, RecordDerivation, TranslationNote,
};

mod support;

use support::footgun::{db_of, relation_definition, translator};
use support::row;

const DOC_ID: &str = "11111111-1111-1111-1111-111111111111";

fn outputs_for(clause: &str) -> Outputs {
    let schema = format!(
        "CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id TEXT, status TEXT, priority INT);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    );
    translator(ConfidenceLevel::B)
        .translate(&db_of(&schema))
        .expect("translation should plan")
        .outputs_accepting_gaps()
}

fn can_select(outputs: &Outputs) -> String {
    relation_definition(&outputs.model(), "docs", "can_select").expect("docs defines can_select")
}

/// The gate relation one clause grants `can_select` through, refusing any other shape.
fn gate_for(clause: &str) -> String {
    let can_select = can_select(&outputs_for(clause));
    assert!(
        can_select.starts_with("public_where_"),
        "`{clause}` must grant through a gate, got `{can_select}`"
    );
    can_select
}

fn severities(outputs: &Outputs) -> Vec<NoteSeverity> {
    outputs
        .notes()
        .iter()
        .map(TranslationNote::severity)
        .collect()
}

fn gate_query<'a>(outputs: &'a Outputs, column: &str) -> Option<&'a TupleQuery> {
    let needle = format!("\"{column}\" IN (");
    outputs
        .tuple_queries()
        .iter()
        .find(|query| query.sql.contains(&needle))
}

#[test]
fn an_in_list_beside_ownership_translates_both_halves() {
    let outputs = outputs_for("owner_id = current_user AND status IN ('active', 'pending')");
    let can_select = can_select(&outputs);
    assert!(
        can_select.starts_with("owner and public_where_status_"),
        "both halves reach the model, got `{can_select}`"
    );
    let tuples = format_tuples(outputs.tuple_queries());
    assert!(
        tuples.contains("AND \"status\" IN ('active', 'pending');"),
        "the list qualifies rows in SQL:\n{tuples}"
    );
    assert!(
        !outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::AttributeNeedsRuntimeEnforcement { .. }
        )),
        "nothing is left to the application: {:#?}",
        outputs.notes()
    );
    let severities = severities(&outputs);
    assert!(
        !severities.contains(&NoteSeverity::BelowThreshold)
            && !severities.contains(&NoteSeverity::Partial),
        "the clause translates in full at B: {severities:?}"
    );
}

#[test]
fn a_standalone_in_list_grants_the_rows_it_lists() {
    let outputs = outputs_for("status IN ('active', 'pending')");
    let can_select = can_select(&outputs);
    assert!(
        can_select.starts_with("public_where_status_"),
        "the list grants through its own gate, got `{can_select}`"
    );
    assert!(
        gate_query(&outputs, "status").is_some(),
        "the gate is loaded from the rows the list admits:\n{}",
        format_tuples(outputs.tuple_queries())
    );
    assert!(
        !severities(&outputs).contains(&NoteSeverity::Unhandled),
        "{:#?}",
        outputs.notes()
    );
}

#[test]
fn the_order_and_repeats_of_a_list_do_not_change_its_gate() {
    assert_eq!(
        gate_for("status IN ('pending', 'active', 'active')"),
        gate_for("status IN ('active', 'pending')"),
    );
}

#[test]
fn the_dumped_any_array_spelling_is_the_same_gate() {
    assert_eq!(
        gate_for("status = ANY (ARRAY['active'::text, 'pending'::text])"),
        gate_for("status IN ('active', 'pending')"),
    );
}

#[test]
fn a_one_element_list_is_the_equality_it_spells() {
    assert_eq!(
        gate_for("status IN ('published')"),
        gate_for("status = 'published'"),
    );
}

#[test]
fn different_lists_are_different_gates() {
    let listed = gate_for("status IN ('active', 'pending')");
    assert_ne!(listed, gate_for("status IN ('active', 'archived')"));
    assert_ne!(listed, gate_for("status = 'active'"));
    assert_ne!(listed, gate_for("priority IN (1, 2)"));
}

#[test]
fn the_report_names_the_guard_as_its_predicate_states_it() {
    for (clause, described) in [
        (
            "status IN ('active', 'pending')",
            "P9 (status IN ('active', 'pending'))",
        ),
        ("priority >= 3", "P9 (priority >= 3)"),
    ] {
        let report = outputs_for(clause).report();
        assert!(report.contains(described), "`{clause}`:\n{report}");
    }
}

#[test]
fn a_numeric_list_keeps_its_spelling() {
    let tuples = format_tuples(outputs_for("priority IN (1, 2)").tuple_queries());
    assert!(
        tuples.contains("AND \"priority\" IN (1, 2);"),
        "the numbers compare as the policy wrote them:\n{tuples}"
    );
}

#[test]
fn the_gate_record_admits_exactly_the_listed_values() {
    let outputs = outputs_for("status IN ('active', 'pending')");
    let description = gate_query(&outputs, "status")
        .and_then(|query| query.description.as_ref())
        .expect("the gate query describes its records");
    assert!(
        matches!(description.derivation, RecordDerivation::FromRow { .. }),
        "the row alone decides the list"
    );
    for (status, expected) in [("active", 1), ("pending", 1), ("archived", 0)] {
        let records = records_from_row(description, &row(&[("id", DOC_ID), ("status", status)]))
            .expect("the row decides its records");
        assert_eq!(records.len(), expected, "status `{status}`: {records:?}");
    }
}

/// A gate grants the wildcard, so a list that excludes rows must never open one.
#[test]
fn a_negated_list_never_opens_a_gate() {
    for clause in [
        "status NOT IN ('active', 'pending')",
        "owner_id = current_user AND status NOT IN ('active', 'pending')",
    ] {
        let outputs = outputs_for(clause);
        let can_select = can_select(&outputs);
        assert!(
            !can_select.contains("public_where_status"),
            "`{clause}` would grant the rows it excludes, got `{can_select}`"
        );
    }
}

/// A value the caller supplies would hand one caller's rows to everyone.
#[test]
fn a_list_naming_a_caller_value_never_opens_a_gate() {
    let outputs = outputs_for(
        "owner_id = current_user AND status IN ('active', current_setting('app.status', true))",
    );
    let can_select = can_select(&outputs);
    assert!(
        !can_select.contains("public_where_status"),
        "the setting is the caller's, got `{can_select}`"
    );
}
