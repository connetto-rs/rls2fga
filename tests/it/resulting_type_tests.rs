//! Consumer contracts for types judging written rows.

use rls2fga::json_row::JsonRow;
use rls2fga::translator::Translation;
use rls2fga::types::{
    records_from_row, ActionAnswer, ActionJudgement, ActionStatement, ConfidenceLevel, Record,
    RecordDescription, RequestPredicate, RowDecision, RowVersion, TranslationNote,
};

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
    let values = JsonRow(&values);
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
    let values = JsonRow(&values);
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

/// Notes their author reads, writes and moves, every check reading the row's own columns.
const AUTHORED: &str = "
CREATE TABLE notes (id TEXT PRIMARY KEY, author_id TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_select ON notes FOR SELECT
  USING (author_id = current_setting('app.user_id', true));
CREATE POLICY notes_insert ON notes FOR INSERT
  WITH CHECK (author_id = current_setting('app.user_id', true));
CREATE POLICY notes_update ON notes FOR UPDATE
  USING (author_id = current_setting('app.user_id', true));
";

/// [`AUTHORED`] beside a second `INSERT` policy the threshold drops, so the emitted
/// `INSERT` rule is narrower than the database's.
const AUTHORED_WITH_OPAQUE_INSERT: &str = "
CREATE TABLE notes (id TEXT PRIMARY KEY, author_id TEXT);
CREATE FUNCTION opaque_gate(TEXT) RETURNS BOOLEAN LANGUAGE plpgsql STABLE
  AS $$ BEGIN RETURN NULL; END $$;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_select ON notes FOR SELECT
  USING (author_id = current_setting('app.user_id', true));
CREATE POLICY notes_insert ON notes FOR INSERT
  WITH CHECK (author_id = current_setting('app.user_id', true));
CREATE POLICY notes_insert_opaque ON notes FOR INSERT WITH CHECK (opaque_gate(id));
";

/// Whether a caller acting as the suite's role satisfies `predicate`.
fn acting_role_holds(predicate: &RequestPredicate) -> bool {
    match predicate {
        RequestPredicate::ActsAs { role } => role == support::deployment::ACTING_ROLE,
        RequestPredicate::Any(children) => children.iter().any(acting_role_holds),
        RequestPredicate::All(children) => children.iter().all(acting_role_holds),
        other => panic!("a predicate this suite does not supply: {other:?}"),
    }
}

/// Every record `decision`'s leaves derive from `row`.
fn decision_records(decision: &RowDecision, row: &serde_json::Value) -> Vec<Record> {
    let from = |shapes: &[RecordDescription]| -> Vec<Record> {
        shapes
            .iter()
            .flat_map(|shape| records_from_row(shape, &JsonRow(row)).unwrap())
            .collect()
    };
    match decision {
        RowDecision::Leaf { shapes, .. }
        | RowDecision::Everyone { shapes, .. }
        | RowDecision::RequestGated { shapes, .. }
        | RowDecision::Request { shapes, .. } => from(shapes),
        RowDecision::Any(children) | RowDecision::All(children) => children
            .iter()
            .flat_map(|child| decision_records(child, row))
            .collect(),
    }
}

/// Whether `decision` grants `user` on `row`, read the way a consumer answering locally
/// reads it.
fn decision_grants(decision: &RowDecision, row: &serde_json::Value, user: &str) -> bool {
    match decision {
        RowDecision::Leaf { .. } => decision_records(decision, row)
            .iter()
            .any(|record| record.subject == format!("user:{user}")),
        RowDecision::Everyone { .. } => !decision_records(decision, row).is_empty(),
        RowDecision::Request { predicate, .. } => {
            !decision_records(decision, row).is_empty() && acting_role_holds(predicate)
        }
        RowDecision::Any(children) => children
            .iter()
            .any(|child| decision_grants(child, row, user)),
        RowDecision::All(children) => children
            .iter()
            .all(|child| decision_grants(child, row, user)),
        other @ RowDecision::RequestGated { .. } => {
            panic!("a decision this suite does not build: {other:?}")
        }
    }
}

/// Each written-row judgement `statements` ask on `translation`, with the decision the
/// translation reports for it.
fn written_row_decisions<'a>(
    translation: &'a Translation,
    statements: &[ActionStatement],
) -> Vec<(&'a ActionJudgement, Option<&'a RowDecision>)> {
    translation
        .action_relations()
        .iter()
        .filter(|entry| statements.contains(&entry.statement))
        .flat_map(|entry| judgements(&entry.answer))
        .filter(|judgement| judgement.version == RowVersion::Resulting)
        .map(|judgement| {
            let reported = translation
                .relations()
                .iter()
                .find(|entry| {
                    entry.type_name == judgement.type_name && entry.relation == judgement.relation
                })
                .unwrap_or_else(|| panic!("{judgement:?} is not reported"));
            assert_eq!(reported.from_one_row, reported.decision.is_some());
            (judgement, reported.decision.as_ref())
        })
        .collect()
}

/// A check on a written row that reads only that row's columns is decided by the row the
/// write produces, from the same facts a check about it carries.
#[test]
fn a_written_row_reading_only_its_own_columns_is_decided_by_that_row() {
    let outputs = translate(AUTHORED).outputs().unwrap();
    let translation = outputs.translation();
    let resulting = translation.resulting_rows().first().unwrap();
    let written = serde_json::json!({"id": "n1", "author_id": "alice"});
    let carried = resulting.records(&JsonRow(&written)).unwrap();
    let decisions = written_row_decisions(
        translation,
        &[
            ActionStatement::Insert,
            ActionStatement::InsertReturning,
            ActionStatement::Update,
        ],
    );
    assert!(decisions.len() >= 3, "{decisions:#?}");
    for (judgement, decision) in decisions {
        let decision = decision.unwrap_or_else(|| panic!("{judgement:?} costs a round trip"));
        assert!(
            decision_grants(decision, &written, "alice"),
            "{decision:#?}"
        );
        assert!(!decision_grants(decision, &written, "bob"), "{decision:#?}");
        for record in decision_records(decision, &written) {
            assert!(
                carried.contains(&record),
                "{record:?} is not a fact the check carries: {carried:#?}"
            );
        }
    }
}

/// A written-row check the threshold narrowed answers less than the database, so the row
/// cannot decide it.
#[test]
fn a_narrowed_written_row_check_is_not_decided_by_the_row() {
    let translation = translate(AUTHORED_WITH_OPAQUE_INSERT);
    let decisions = written_row_decisions(&translation, &[ActionStatement::Insert]);
    assert_ne!(decisions.len(), 0);
    for (judgement, decision) in decisions {
        assert!(decision.is_none(), "{judgement:?} decided as {decision:#?}");
    }
    let control = translate(AUTHORED);
    assert!(written_row_decisions(&control, &[ActionStatement::Insert])
        .iter()
        .all(|(_, decision)| decision.is_some()));
}
