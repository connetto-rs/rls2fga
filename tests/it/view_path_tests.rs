//! Statements a view running with its owner's rights lets an acting role run on its table's
//! rows, beside what the table's own policies grant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::parser::sql_parser::Deployment;
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::{
    ActionAnswer, ActionJudgement, ActionStatement, ColumnName, ConfidenceLevel, Holding,
    RowVersion, TableId, TranslationNote, TypeName, ViewPath,
};

use crate::support::deployment::{caller_deployment_acting_as, db, deployment};

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
    translate_for(sql, deployment([]))
}

fn translate_for(sql: &str, deployment: Deployment) -> Translation {
    let mut registry = FunctionRegistry::new();
    registry.register_attribute_column("resources", "parent_id");
    registry.register_attribute_column("resources", "archived");
    TranslatorBuilder::new(deployment)
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

/// Why each refused view is refused, as its note says.
fn refusal_messages(translation: &Translation) -> Vec<String> {
    translation
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::OwnerRightsViewRefused { .. }))
        .map(ToString::to_string)
        .collect()
}

/// The checked move with `extra` appended.
fn checked_moves_with(extra: &str) -> String {
    format!(
        "{}\n{extra}",
        moves("WITH (check_option = cascaded)", "parent_id > 0")
    )
}

/// Every judgement `answer` asks, through column gates and every path of an alternative.
fn every_judgement(answer: &ActionAnswer) -> Vec<&ActionJudgement> {
    match answer {
        ActionAnswer::Judged(judgements) => judgements.iter().collect(),
        ActionAnswer::ByColumn(columns) => every_judgement(&columns.rows),
        ActionAnswer::AnyOf(paths) => paths.iter().flat_map(every_judgement).collect(),
        _ => Vec::new(),
    }
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

#[test]
fn each_view_path_names_its_view_table_and_type() {
    let translation = translate(&moves("WITH (check_option = cascaded)", "parent_id > 0"));
    let path_type = TypeName::canonicalized("resource_moves");
    assert_eq!(
        translation.view_paths(),
        [ViewPath {
            view: TableId::from_stored(None, "resource_moves".into()),
            table: TableId::from_stored(None, "resources".into()),
            type_name: path_type.clone(),
        }]
    );
    let held: Vec<&str> = translation
        .acting_privileges()
        .iter()
        .filter(|held| held.type_name == path_type)
        .map(|held| held.role.as_str())
        .collect();
    assert_eq!(held, ["app_user"]);
}

#[test]
fn a_view_outside_public_is_named_with_its_schema() {
    let sql = MOVES
        .replace(" resource_moves", " moves.resource_moves")
        .replace(" VIEW AS", " WITH (check_option = cascaded) AS")
        .replace("WHERE;", "WHERE parent_id > 0;");
    let translation = translate(&format!("CREATE SCHEMA moves;\n{sql}"));
    let views: Vec<String> = translation
        .view_paths()
        .iter()
        .map(|path| path.view.to_string())
        .collect();
    assert_eq!(views, ["moves.resource_moves"]);
}

#[test]
fn a_view_granting_only_delete_carries_only_delete() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0").replace(
        "GRANT SELECT, UPDATE (parent_id) ON resource_moves",
        "GRANT DELETE ON resources TO authz_writer;\nGRANT DELETE ON resource_moves",
    );
    let translation = translate(&sql);
    let held = translation
        .acting_privileges()
        .iter()
        .find(|held| held.type_name == *"resource_moves")
        .expect("a role holding only DELETE on the view still reaches the table");
    assert!(held.delete);
    for holding in [&held.select, &held.insert, &held.update] {
        assert_eq!(holding, &Holding::Absent);
    }
}

#[test]
fn a_view_no_acting_role_holds_opens_no_path() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0").replace(
        "GRANT SELECT, UPDATE (parent_id) ON resource_moves TO app_user;",
        "",
    );
    let translation = translate(&sql);
    assert_eq!(translation.view_paths(), []);
    assert_eq!(refusals(&translation), Vec::<String>::new());
}

#[test]
fn an_owner_holding_nothing_on_the_table_opens_no_path() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0").replace(
        "GRANT SELECT, UPDATE (parent_id) ON resources TO authz_writer;",
        "",
    );
    let translation = translate(&sql);
    assert_eq!(translation.view_paths(), []);
    assert_eq!(
        answer(&translation, ActionStatement::Update),
        ActionAnswer::Denied
    );
}

#[test]
fn a_view_reading_every_column_carries_the_whole_table_grant() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0")
        .replace(
            "SELECT id, parent_id FROM resources",
            "SELECT id, parent_id, archived FROM resources",
        )
        .replace(
            "GRANT SELECT, UPDATE (parent_id) ON resources TO authz_writer;",
            "GRANT SELECT, UPDATE ON resources TO authz_writer;",
        );
    let translation = translate(&sql);
    let held = translation
        .acting_privileges()
        .iter()
        .find(|held| held.type_name == *"resource_moves")
        .expect("the view's path holds privileges");
    assert_eq!(held.select, Holding::Table);
    assert_eq!(
        held.update,
        Holding::Columns([ColumnName::from_stored("parent_id")].into_iter().collect())
    );
}

#[test]
fn a_second_acting_role_without_the_view_holds_nothing_through_it() {
    let sql = format!(
        "CREATE ROLE app_auditor NOLOGIN;\n\
         GRANT app_auditor TO app_login WITH INHERIT FALSE, SET TRUE;\n{}",
        moves("WITH (check_option = cascaded)", "parent_id > 0")
    );
    let translation = translate_for(
        &sql,
        caller_deployment_acting_as(&["app_user", "app_auditor"], []),
    );
    let held: Vec<&str> = translation
        .acting_privileges()
        .iter()
        .filter(|held| held.type_name == *"resource_moves")
        .map(|held| held.role.as_str())
        .collect();
    assert_eq!(held, ["app_user"]);
}

#[test]
fn a_table_without_policies_is_moved_through_the_view_alone() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0")
        .replace(
            "CREATE POLICY resources_select ON resources FOR SELECT TO app_user USING (TRUE);",
            "",
        )
        .replace(
            "CREATE POLICY resources_update ON resources FOR UPDATE TO app_user\n  USING (FALSE) WITH CHECK (FALSE);",
            "",
        );
    let translation = translate(&sql);
    let update = answer(&translation, ActionStatement::Update);
    let ActionAnswer::ByColumn(columns) = &update else {
        panic!("the view's gated move is the table's only answer, got {update:?}");
    };
    assert!(
        columns.gate.ends_with(":resource_moves"),
        "{}",
        columns.gate
    );
}

#[test]
fn a_move_both_the_table_and_the_view_check_names_both_written_rows() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0")
        .replace(
            "GRANT SELECT, UPDATE (archived) ON resources TO app_user;",
            "GRANT SELECT, UPDATE (archived, parent_id) ON resources TO app_user;",
        )
        .replace(
            "USING (FALSE) WITH CHECK (FALSE);",
            "USING (TRUE) WITH CHECK (archived = FALSE);",
        );
    let translation = translate(&sql);
    let update = answer(&translation, ActionStatement::Update);
    let ActionAnswer::AnyOf(paths) = &update else {
        panic!("the table and the view each move rows, got {update:?}");
    };
    assert_eq!(paths.len(), 2, "{paths:?}");
    let written: Vec<&TypeName> = translation
        .resulting_rows()
        .iter()
        .map(|row| &row.type_name)
        .collect();
    let produced: Vec<&ActionJudgement> = every_judgement(&update)
        .into_iter()
        .filter(|judgement| judgement.version == RowVersion::Resulting)
        .collect();
    assert!(
        produced.len() >= 2,
        "both paths judge the written row, got {produced:?}"
    );
    for judgement in produced {
        assert!(
            written.contains(&&judgement.type_name),
            "{} names a written row, among {written:?}",
            judgement.type_name
        );
    }
}

#[test]
fn a_materialized_view_a_role_reads_is_refused() {
    let translation = translate(&checked_moves_with(
        "CREATE MATERIALIZED VIEW resource_list AS SELECT id FROM resources;",
    ));
    assert_eq!(refusals(&translation), ["public.resource_list app_user"]);
    assert_eq!(
        refusal_messages(&translation),
        [
            "View 'public.resource_list' runs with its owner's rights and acting role 'app_user' \
          holds a privilege on it, but it is materialized, so the model denies what the view \
          grants"
        ]
    );
}

#[test]
fn a_view_postgres_cannot_write_through_is_refused() {
    let translation = translate(&checked_moves_with(
        "CREATE VIEW resource_counts AS \
           SELECT parent_id, count(*) AS children FROM resources GROUP BY parent_id;
         ALTER VIEW resource_counts OWNER TO authz_writer;",
    ));
    assert_eq!(refusals(&translation), ["public.resource_counts app_user"]);
    assert!(
        refusal_messages(&translation)[0].contains("it is not automatically updatable"),
        "{:?}",
        refusal_messages(&translation)
    );
}

#[test]
fn a_view_over_a_foreign_table_is_refused() {
    let translation = translate(&checked_moves_with(
        "CREATE SERVER remote FOREIGN DATA WRAPPER postgres_fdw;
         CREATE FOREIGN TABLE remote_resources (id INTEGER, parent_id INTEGER) SERVER remote;
         CREATE VIEW remote_moves AS SELECT id, parent_id FROM remote_resources;
         ALTER VIEW remote_moves OWNER TO authz_writer;",
    ));
    assert_eq!(refusals(&translation), ["public.remote_moves app_user"]);
    assert!(
        refusal_messages(&translation)[0].contains("it reads a foreign table"),
        "{:?}",
        refusal_messages(&translation)
    );
}

#[test]
fn a_view_a_trigger_or_a_rule_writes_for_is_refused() {
    let trigger = translate(&checked_moves_with(
        "CREATE FUNCTION move_resource() RETURNS trigger LANGUAGE plpgsql
           AS $$ BEGIN RETURN NEW; END $$;
         CREATE TRIGGER moves_instead INSTEAD OF UPDATE ON resource_moves
           FOR EACH ROW EXECUTE FUNCTION move_resource();",
    ));
    assert_eq!(refusals(&trigger), ["public.resource_moves app_user"]);
    assert!(
        refusal_messages(&trigger)[0].contains("trigger 'moves_instead' takes a write to it"),
        "{:?}",
        refusal_messages(&trigger)
    );
    let rule = translate(&checked_moves_with(
        "CREATE RULE moves_rule AS ON UPDATE TO resource_moves DO INSTEAD NOTHING;",
    ));
    assert_eq!(refusals(&rule), ["public.resource_moves app_user"]);
    assert!(
        refusal_messages(&rule)[0].contains("rule 'moves_rule' takes a write to it"),
        "{:?}",
        refusal_messages(&rule)
    );
}

#[test]
fn a_view_over_a_table_others_inherit_from_is_refused() {
    let translation = translate(&checked_moves_with(
        "CREATE TABLE archived_resources () INHERITS (resources);",
    ));
    assert_eq!(refusals(&translation), ["public.resource_moves app_user"]);
    assert!(
        refusal_messages(&translation)[0].contains("tables inherit from 'public.resources'"),
        "{:?}",
        refusal_messages(&translation)
    );
}

#[test]
fn a_view_over_a_keyless_table_moves_nothing() {
    let sql = moves("WITH (check_option = cascaded)", "parent_id > 0").replace(
        "id INTEGER PRIMARY KEY,\n  parent_id INTEGER REFERENCES resources (id),",
        "id INTEGER NOT NULL,\n  parent_id INTEGER,",
    );
    let translation = translate(&sql);
    assert!(
        every_judgement(&answer(&translation, ActionStatement::Update)).is_empty(),
        "a row without identity is never asked about"
    );
}

#[test]
fn a_view_condition_below_the_threshold_is_reported_and_moves_nothing() {
    let translation = translate(&moves(
        "WITH (check_option = cascaded)",
        "CAST(parent_id AS TEXT) ~ '^1'",
    ));
    let lost: Vec<String> = translation
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::ClauseBelowThreshold { table, clause, .. } => {
                Some(format!("{table} {clause}"))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        lost,
        [
            "public.resource_moves USING",
            "public.resource_moves WITH CHECK"
        ]
    );
    assert_eq!(
        answer(&translation, ActionStatement::Update),
        ActionAnswer::Denied
    );
}
