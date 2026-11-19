//! Consumer contracts for types judging written rows.

use rls2fga::translator::Translation;
use rls2fga::types::{ActionAnswer, ActionJudgement, ConfidenceLevel, RowVersion, TranslationNote};

use crate::support;
use crate::support::footgun::{declared_userset, relation_definition, relation_denies, targets_of};

pub(super) const UNREADABLE_METADATA: &str = "
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, metadata JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT
  USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_update ON docs FOR UPDATE
  USING (owner_id = current_setting('app.user_id', true))
  WITH CHECK (owner_id = current_setting('app.user_id', true) AND metadata IS NOT NULL);
";

/// Translate a schema with the suite's caller and table privileges.
fn translate(schema: &str) -> Translation {
    support::deployment::translator_builder()
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&support::deployment::db(schema))
        .unwrap()
}

/// Every row judgement carried by an action, including column-scoped actions.
fn judgements(answer: &ActionAnswer) -> &[ActionJudgement] {
    match answer {
        ActionAnswer::Judged(judgements) => judgements,
        ActionAnswer::ByColumn(columns) => judgements(&columns.rows),
        _ => &[],
    }
}

/// Table names cannot capture another table's resulting judgements.
#[test]
fn resulting_type_names_do_not_collide_with_stored_table_names() {
    let translation = translate(
        "CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
         CREATE TABLE docs_resulting (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         ALTER TABLE docs_resulting ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_insert ON docs FOR INSERT
           WITH CHECK (owner_id = current_setting('app.user_id', true));
         CREATE POLICY other_insert ON docs_resulting FOR INSERT
           WITH CHECK (owner_id = current_setting('app.user_id', true));",
    );
    let outputs = translation.outputs().unwrap();
    let translation = outputs.translation();
    let rows = translation.resulting_rows();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].type_name, rows[1].type_name);
    let model = outputs.model();
    let json = outputs.json_model();
    for row in rows {
        let stored = translation
            .row_naming()
            .iter()
            .find(|naming| naming.table == row.table)
            .unwrap();
        assert!(translation
            .row_naming()
            .iter()
            .all(|naming| naming.type_name != row.type_name));
        let mut compared = 0;
        for entry in translation
            .action_relations()
            .iter()
            .filter(|entry| entry.type_name == stored.type_name)
        {
            for judgement in judgements(&entry.answer)
                .iter()
                .filter(|judgement| judgement.version == RowVersion::Resulting)
            {
                compared += 1;
                assert_eq!(judgement.type_name, row.type_name);
                assert!(relation_definition(
                    &model,
                    judgement.type_name.as_str(),
                    judgement.relation.as_str(),
                )
                .is_some());
                assert!(declared_userset(
                    &json.type_definitions,
                    judgement.type_name.as_str(),
                    judgement.relation.as_str(),
                )
                .is_some());
            }
        }
        assert!(compared > 0);
    }
}

/// A caller column named `stored` remains distinct from the link to the stored row.
#[test]
fn a_stored_relation_does_not_capture_the_stored_row_link() {
    let outputs = translate(
        "CREATE TABLE docs (id TEXT PRIMARY KEY, stored TEXT NOT NULL);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_insert ON docs FOR INSERT
           WITH CHECK (stored = current_setting('app.user_id', true));",
    )
    .outputs()
    .unwrap();
    let model = outputs.model();
    assert_eq!(
        relation_definition(&model, "docs", "stored").as_deref(),
        Some("[user]"),
    );
    let resulting = outputs.translation().resulting_rows().first().unwrap();
    let values = serde_json::json!({"id": "new", "stored": "alice"});
    let values = support::JsonRowValues(&values);
    let object = resulting.object(&values).unwrap().unwrap();
    let records = resulting.records(&values).unwrap();
    let owner = records
        .iter()
        .find(|record| record.subject == "user:alice")
        .unwrap();
    let link = records
        .iter()
        .find(|record| record.subject == "docs:new")
        .unwrap();
    assert_eq!(owner.object, object);
    assert_eq!(link.object, object);
    assert_eq!(owner.relation.as_str(), "stored");
    assert_ne!(owner.relation, link.relation);
    let json = outputs.json_model();
    assert_eq!(
        targets_of(
            &json.type_definitions,
            resulting.type_name.as_str(),
            link.relation.as_str(),
        ),
        vec!["docs".to_string()],
    );
    assert_eq!(
        targets_of(
            &json.type_definitions,
            resulting.type_name.as_str(),
            owner.relation.as_str(),
        ),
        vec!["user".to_string()],
    );
}

/// A query-only written fact refuses its action without refusing the stored read.
#[test]
fn an_unreadable_written_fact_discloses_and_denies_only_its_resulting_actions() {
    let translation = translate(UNREADABLE_METADATA);
    let refusals: Vec<_> = translation
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::ResultingRowFactUnreadable { table, relation } => {
                Some((table.clone(), relation.clone()))
            }
            _ => None,
        })
        .collect();
    assert!(!refusals.is_empty(), "{:?}", translation.notes());
    assert!(translation.clone().outputs().is_err());
    let outputs = translation.outputs_accepting_gaps();
    let model = outputs.model();
    let resulting = outputs.translation().resulting_rows().first().unwrap();
    for (table, relation) in refusals {
        assert_eq!(table, resulting.table);
        assert!(relation_denies(
            &model,
            resulting.type_name.as_str(),
            relation.as_str(),
        ));
    }
    assert!(!relation_denies(&model, "docs", "can_select"));
}

/// Both parts of a compound key reach the stored row in the contextual records.
#[test]
fn a_composite_key_names_both_ends_of_the_stored_row_link() {
    let outputs = translate(
        "CREATE TABLE pairs (a TEXT, b TEXT, owner_id TEXT NOT NULL, PRIMARY KEY (a, b));
         ALTER TABLE pairs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY pairs_insert ON pairs FOR INSERT
           WITH CHECK (owner_id = current_setting('app.user_id', true));",
    )
    .outputs()
    .unwrap();
    let resulting = outputs.translation().resulting_rows().first().unwrap();
    let values = serde_json::json!({"a": "first", "b": "second", "owner_id": "alice"});
    let values = support::JsonRowValues(&values);
    let object = resulting.object(&values).unwrap().unwrap();
    assert_eq!(object, format!("{}:first|second", resulting.type_name));
    let records = resulting.records(&values).unwrap();
    let link = records
        .iter()
        .find(|record| record.subject == "pairs:first|second")
        .unwrap();
    assert_eq!(link.object, object);
    assert_eq!(
        targets_of(
            &outputs.json_model().type_definitions,
            resulting.type_name.as_str(),
            link.relation.as_str(),
        ),
        vec!["pairs".to_string()],
    );
}
