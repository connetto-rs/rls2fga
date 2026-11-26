//! Statements a view running with its owner's rights lets an acting role run on its table's
//! rows, beside what the table's own policies grant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::{
    ActionAnswer, ActionJudgement, ActionStatement, ConfidenceLevel, RowVersion, TranslationNote,
};

use crate::support::deployment::{db, deployment};

/// Resources whose own `UPDATE` policy refuses every row, moved through a view its owner
/// writes for the acting role. `VIEW` stands for the view's options and `WHERE` for its
/// condition.
const MOVES: &str = "
CREATE ROLE authz_writer NOLOGIN BYPASSRLS;
CREATE TABLE resources (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER REFERENCES resources (id),
  archived BOOLEAN NOT NULL DEFAULT FALSE
);
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE resources FORCE ROW LEVEL SECURITY;
REVOKE ALL ON resources FROM app_user;
GRANT SELECT, UPDATE (archived) ON resources TO app_user;
GRANT SELECT, UPDATE (parent_id) ON resources TO authz_writer;
CREATE POLICY resources_select ON resources FOR SELECT TO app_user USING (TRUE);
CREATE POLICY resources_update ON resources FOR UPDATE TO app_user
  USING (FALSE) WITH CHECK (FALSE);
CREATE VIEW resource_moves VIEW AS
  SELECT id, parent_id FROM resources WHERE;
ALTER VIEW resource_moves OWNER TO authz_writer;
REVOKE ALL ON resource_moves FROM app_user;
GRANT SELECT, UPDATE (parent_id) ON resource_moves TO app_user;
";

fn moves(options: &str, condition: &str) -> String {
    MOVES
        .replace(" VIEW AS", &format!(" {options} AS"))
        .replace("WHERE;", &format!("WHERE {condition};"))
}

fn translate(sql: &str) -> Translation {
    let mut registry = FunctionRegistry::new();
    registry.register_attribute_column("resources", "parent_id");
    registry.register_attribute_column("resources", "archived");
    TranslatorBuilder::new(deployment([]))
        .with_registry(registry)
        .with_min_confidence(ConfidenceLevel::A)
        .build()
        .translate(&db(sql))
        .expect("translation should plan")
}

fn answer(translation: &Translation, statement: ActionStatement) -> ActionAnswer {
    translation
        .action_relations()
        .iter()
        .find(|entry| entry.type_name == *"resources" && entry.statement == statement)
        .unwrap_or_else(|| panic!("no {statement:?} answer for resources"))
        .answer
        .clone()
}

/// The judgements an answer's rows need, through its column gate if it has one.
fn rows(answer: &ActionAnswer) -> &[ActionJudgement] {
    match answer {
        ActionAnswer::Judged(judgements) => judgements,
        ActionAnswer::ByColumn(columns) => rows(&columns.rows),
        other => panic!("{other:?} judges no row"),
    }
}

fn refusals(translation: &Translation) -> Vec<String> {
    translation
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::OwnerRightsViewRefused { view, role, .. } => {
                Some(format!("{view} {role}"))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn the_view_moves_rows_the_table_refuses_to_update() {
    let translation = translate(&moves("WITH (check_option = cascaded)", "parent_id > 0"));
    let update = answer(&translation, ActionStatement::Update);
    let ActionAnswer::ByColumn(columns) = &update else {
        panic!("the move is gated on the column the view grants, got {update:?}");
    };
    assert!(
        columns.gate.ends_with(":resource_moves"),
        "the column gate is the view's, got {}",
        columns.gate
    );
    let judged = rows(&update);
    assert!(
        judged
            .iter()
            .all(|judgement| judgement.type_name.as_str().starts_with("resource_moves")),
        "every judgement is asked on the view's path, got {judged:?}"
    );
    for version in [RowVersion::Existing, RowVersion::Resulting] {
        assert!(
            judged.iter().any(|judgement| judgement.version == version),
            "the move judges the {version:?} row, got {judged:?}"
        );
    }
    assert_eq!(refusals(&translation), Vec::<String>::new());
}

#[test]
fn a_view_admitting_no_row_moves_nothing() {
    let translation = translate(&moves("WITH (check_option = cascaded)", "FALSE"));
    assert_eq!(
        answer(&translation, ActionStatement::Update),
        ActionAnswer::Denied
    );
}

#[test]
fn the_three_views_translate_apart() {
    let model = |sql: &str| translate(sql).outputs_accepting_gaps().model();
    let checked = model(&moves("WITH (check_option = cascaded)", "parent_id > 0"));
    let admitting_none = model(&moves("WITH (check_option = cascaded)", "FALSE"));
    let unchecked = model(&moves("", "parent_id > 0"));
    assert_ne!(checked, admitting_none);
    assert_ne!(checked, unchecked);
}

#[test]
fn a_view_running_with_its_readers_rights_opens_no_path() {
    let translation = translate(&moves("WITH (security_invoker = true)", "parent_id > 0"));
    assert_eq!(
        answer(&translation, ActionStatement::Update),
        ActionAnswer::Denied
    );
    assert_eq!(refusals(&translation), Vec::<String>::new());
}

#[test]
fn an_owner_the_table_policies_reach_is_refused() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0")
        .replace("NOLOGIN BYPASSRLS", "NOLOGIN");
    let translation = translate(&sql);
    assert_eq!(refusals(&translation), ["public.resource_moves app_user"]);
    assert_eq!(
        answer(&translation, ActionStatement::Update),
        ActionAnswer::Denied
    );
    assert!(translation.outputs().is_err());
}

#[test]
fn a_view_over_a_view_is_refused() {
    let sql = format!(
        "{}
CREATE VIEW nested_moves AS SELECT id, parent_id FROM resource_moves;
ALTER VIEW nested_moves OWNER TO authz_writer;
REVOKE ALL ON nested_moves FROM app_user;
GRANT UPDATE (parent_id) ON nested_moves TO app_user;",
        moves("WITH (check_option = cascaded)", "parent_id > 0")
    );
    let translation = translate(&sql);
    assert_eq!(refusals(&translation), ["public.nested_moves app_user"]);
}
