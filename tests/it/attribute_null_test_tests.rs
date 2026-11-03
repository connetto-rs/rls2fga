//! A column tested for NULL is row data, so `team_id IS NULL` translates as `team_id = 'solo'` does.

use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{records_from_row, ConfidenceLevel, RecordDerivation};
use serde_json::json;

use crate::support::footgun::{db_of, relation_definition};
use crate::support::JsonRowValues;

const PHOTO_ID: &str = "11111111-1111-1111-1111-111111111111";
const CALLER_OWNS: &str = "owner_id = current_setting('app.user_id', true)";

/// The outputs for one `photos` policy, refusing any clause below `B` as a deployment does.
fn outputs_for(policy: &str) -> Outputs {
    let schema = format!(
        "CREATE TABLE public.photos(id UUID PRIMARY KEY, owner_id TEXT, team_id TEXT, thumb_id TEXT);\n\
         ALTER TABLE photos ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY photos_p ON photos {policy};\n"
    );
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build()
        .translate(&db_of(&schema))
        .expect("translation should plan")
        .outputs()
        .unwrap_or_else(|divergent| panic!("`{policy}` must translate in full: {divergent:?}"))
}

fn relation(outputs: &Outputs, relation: &str) -> String {
    relation_definition(&outputs.model(), "photos", relation)
        .unwrap_or_else(|| panic!("photos defines {relation}"))
}

/// The gate relation a standalone `SELECT` clause grants through, refusing any other shape.
fn gate_for(clause: &str) -> String {
    let can_select = relation(
        &outputs_for(&format!("FOR SELECT USING ({clause})")),
        "can_select",
    );
    assert!(
        can_select.starts_with("public_where_"),
        "`{clause}` must grant through a gate, got `{can_select}`"
    );
    can_select
}

#[test]
fn a_null_test_beside_ownership_translates_both_halves() {
    for (command, relation_name) in [
        ("FOR INSERT WITH CHECK", "can_insert"),
        ("FOR SELECT USING", "can_select"),
    ] {
        for guard in ["team_id IS NULL", "thumb_id IS NOT NULL"] {
            let policy = format!("{command} ({CALLER_OWNS} AND {guard})");
            let granted = relation(&outputs_for(&policy), relation_name);
            assert!(
                granted.starts_with("owner and public_where_"),
                "both halves of `{policy}` reach the model, got `{granted}`"
            );
        }
    }
}

#[test]
fn a_standalone_null_test_qualifies_rows_in_sql() {
    for (guard, sql) in [
        ("team_id IS NULL", "AND \"team_id\" IS NULL;"),
        ("thumb_id IS NOT NULL", "AND \"thumb_id\" IS NOT NULL;"),
    ] {
        let outputs = outputs_for(&format!("FOR INSERT WITH CHECK ({guard})"));
        assert!(
            relation(&outputs, "can_insert").starts_with("public_where_"),
            "`{guard}` grants through its own gate"
        );
        assert!(
            outputs
                .tuple_queries()
                .iter()
                .any(|query| query.sql.contains(sql)),
            "`{guard}` loads its gate from the rows it admits: {:#?}",
            outputs.tuple_queries()
        );
    }
}

#[test]
fn each_null_test_is_a_gate_of_its_own() {
    let null = gate_for("team_id IS NULL");
    let not_null = gate_for("team_id IS NOT NULL");
    assert_ne!(null, not_null);
    assert_ne!(null, gate_for("team_id = 'null'"));
    assert_ne!(not_null, gate_for("team_id = 'not_null'"));
    assert_ne!(null, gate_for("thumb_id IS NULL"));
    assert_eq!(null, gate_for("(team_id) IS NULL"));
}

#[test]
fn the_report_names_the_null_test() {
    for (guard, described) in [
        ("team_id IS NULL", "P9 (team_id IS NULL)"),
        ("team_id IS NOT NULL", "P9 (team_id IS NOT NULL)"),
    ] {
        let report = outputs_for(&format!("FOR SELECT USING ({guard})")).report();
        assert!(report.contains(described), "`{guard}`:\n{report}");
    }
}

#[test]
fn the_gate_record_admits_rows_by_nullness_alone() {
    for (guard, team, expected) in [
        ("team_id IS NULL", json!(null), 1),
        ("team_id IS NULL", json!("t1"), 0),
        ("team_id IS NOT NULL", json!(null), 0),
        ("team_id IS NOT NULL", json!("t1"), 1),
    ] {
        let outputs = outputs_for(&format!("FOR SELECT USING ({guard})"));
        let description = outputs
            .tuple_queries()
            .iter()
            .find(|query| query.sql.contains("\"team_id\" IS"))
            .and_then(|query| query.description.as_ref())
            .expect("the gate query describes its records");
        assert!(
            matches!(description.derivation, RecordDerivation::FromRow { .. }),
            "the row alone decides `{guard}`"
        );
        let row = json!({ "id": PHOTO_ID, "team_id": team });
        let records = records_from_row(description, &JsonRowValues(&row))
            .expect("the row decides its records");
        assert_eq!(records.len(), expected, "`{guard}` on {team}: {records:?}");
    }
}
