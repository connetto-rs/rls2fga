//! Table privileges gate each acting role's action branches.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Tests use panics to reject invalid fixtures."
)]

use std::collections::BTreeMap;

use rls2fga::parser::sql_parser::{parse_schema, Deployment, SessionSetting, SettingValue};
use rls2fga::translator::{Outputs, Translation, TranslatorBuilder};
use rls2fga::types::{
    ActionAnswer, ActionStatement, ColumnAnswer, ColumnCommand, ColumnName, ColumnRelations,
    RelationName, TableId, TranslationNote,
};
use sqlparser::ast::DataType;

use crate::support::footgun::relation_definition;

/// The login role and a neutral table owner no deployment acts as.
const PREAMBLE: &str = "
CREATE ROLE app_login LOGIN NOINHERIT;
CREATE ROLE keeper NOLOGIN;
";

/// The `app.user_id` setting holding the caller as text, for a policy that reads it.
fn user_id_setting() -> SessionSetting {
    SessionSetting::value("app.user_id", SettingValue::Caller(DataType::Text))
        .expect("a valid caller setting")
}

/// Translate `sql` for the given acting roles and settings.
fn translate(settings: Vec<SessionSetting>, acting: &[&str], sql: &str) -> Translation {
    let db = parse_schema(&format!("{PREAMBLE}{sql}")).expect("the schema parses");
    let deployment = Deployment::new("app_login", acting.iter().copied(), settings)
        .expect("a valid test deployment");
    TranslatorBuilder::new(deployment)
        .build()
        .translate(&db)
        .expect("the translation plans")
}

/// `sql` translated for a deployment acting as `acting` that declares no setting.
fn acting(acting: &[&str], sql: &str) -> Translation {
    translate(Vec::new(), acting, sql)
}

/// The answer a type gives one statement, as the consumer reads it.
fn answer<'a>(
    planned: &'a Translation,
    type_name: &str,
    statement: ActionStatement,
) -> &'a ActionAnswer {
    planned
        .action_relations()
        .iter()
        .find(|entry| entry.type_name.as_str() == type_name && entry.statement == statement)
        .map_or_else(
            || panic!("{type_name} answers {statement:?}"),
            |entry| &entry.answer,
        )
}

/// Whether the model refuses the statement for every row.
fn denies(planned: &Translation, type_name: &str, statement: ActionStatement) -> bool {
    answer(planned, type_name, statement) == &ActionAnswer::Denied
}

/// Whether a local grant or a satisfiable relation admits the statement.
fn admits(planned: &Translation, type_name: &str, statement: ActionStatement) -> bool {
    matches!(
        answer(planned, type_name, statement),
        ActionAnswer::Unrestricted | ActionAnswer::Judged(_)
    )
}

/// Whether a relation joins the kind of `role`.
fn kind_in(body: Option<&str>, role: &str) -> bool {
    let needle = format!("acting_{} from request_gate", role.to_ascii_lowercase());
    body.is_some_and(|body| body.contains(&needle))
}

/// The column relations a statement's answer asks, failing where it asks none.
fn by_column<'a>(
    planned: &'a Translation,
    type_name: &str,
    statement: ActionStatement,
) -> &'a ColumnAnswer {
    match answer(planned, type_name, statement) {
        ActionAnswer::ByColumn(columns) => columns,
        other => panic!("{type_name} answers {statement:?} without columns: {other:?}"),
    }
}

/// One command's relations on `table`'s gate, for `columns` and the rest.
fn column_relations(command: ColumnCommand, verb: &str, columns: &[&str]) -> ColumnRelations {
    ColumnRelations {
        command,
        columns: columns
            .iter()
            .map(|column| {
                (
                    ColumnName::from_stored(*column),
                    RelationName::canonicalized(format!("can_{verb}_{column}")),
                )
            })
            .collect::<BTreeMap<_, _>>(),
        on_table: RelationName::canonicalized(format!("can_{verb}_on_table")),
    }
}

/// Whether the tuple queries hold `relation` on `table`'s gate object for `role`.
fn gate_holds(outputs: &Outputs, table: &str, relation: &str, role: &str) -> bool {
    let needle = format!(
        "'request_gate:{table}' AS object, '{relation}' AS relation, 'pg_role:{role}' || '#usage'"
    );
    outputs
        .tuple_queries()
        .iter()
        .any(|query| query.sql.contains(&needle))
}

fn table(name: &str) -> TableId {
    TableId::from_stored(None, name.to_string())
}

/// An acting role without `UPDATE` cannot update rows its policy admits.
#[test]
fn each_command_is_gated_on_the_acting_roles_holding_it() {
    let planned = translate(
        vec![user_id_setting()],
        &["kind_anon", "kind_user"],
        "
CREATE ROLE kind_anon NOLOGIN;
CREATE ROLE kind_user NOLOGIN;
CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT NOT NULL, body TEXT);
ALTER TABLE notes OWNER TO keeper;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (true);
CREATE POLICY notes_write ON notes FOR UPDATE USING (owner = current_setting('app.user_id', true));
GRANT SELECT ON notes TO kind_anon;
GRANT SELECT, UPDATE ON notes TO kind_user;
",
    );
    assert!(
        admits(&planned, "notes", ActionStatement::Select),
        "{:?}",
        planned.action_relations()
    );
    assert!(admits(&planned, "notes", ActionStatement::Update));
    assert!(
        denies(&planned, "notes", ActionStatement::Insert),
        "no acting role holds INSERT"
    );
    assert!(denies(&planned, "notes", ActionStatement::Delete));
    let outputs = planned
        .outputs()
        .expect("every grant is on the whole table");
    let model = outputs.model();
    let can_select = relation_definition(&model, "notes", "can_select").unwrap();
    let can_update = relation_definition(&model, "notes", "can_update_without_reading").unwrap();
    assert!(kind_in(Some(can_select.as_str()), "kind_anon"), "{model}");
    assert!(kind_in(Some(can_select.as_str()), "kind_user"), "{model}");
    assert!(
        kind_in(Some(can_update.as_str()), "kind_user"),
        "kind_user holds UPDATE:\n{model}"
    );
    assert!(
        !kind_in(Some(can_update.as_str()), "kind_anon"),
        "kind_anon's UPDATE is withheld:\n{model}"
    );
}

/// Public grants, all privileges and revokes gate their respective commands.
#[test]
fn public_all_privileges_and_a_revoke_gate_their_commands_per_acting_role() {
    let planned = acting(
        &["admin", "editor", "stranger"],
        "
CREATE ROLE admin NOLOGIN;
CREATE ROLE editor NOLOGIN;
CREATE ROLE stranger NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
CREATE TABLE secrets (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE secrets OWNER TO keeper;
GRANT SELECT ON docs TO PUBLIC;
GRANT ALL PRIVILEGES ON docs, secrets TO admin;
GRANT UPDATE, DELETE ON docs TO editor;
REVOKE DELETE ON docs FROM editor;
",
    );
    for statement in [
        ActionStatement::Select,
        ActionStatement::Insert,
        ActionStatement::Update,
        ActionStatement::Delete,
    ] {
        assert!(
            admits(&planned, "docs", statement),
            "docs answers {statement:?} through a branch"
        );
        assert!(admits(&planned, "secrets", statement));
    }
    let outputs = planned
        .outputs()
        .expect("every grant is on the whole table");
    let model = outputs.model();
    let docs = |relation: &str| relation_definition(&model, "docs", relation).unwrap();
    let secrets = |relation: &str| relation_definition(&model, "secrets", relation).unwrap();
    // PUBLIC reads docs for every acting role.
    for role in ["admin", "editor", "stranger"] {
        assert!(
            kind_in(Some(docs("can_select").as_str()), role),
            "{role} reads through PUBLIC:\n{model}"
        );
    }
    // ALL PRIVILEGES reaches both tables for admin alone.
    assert!(
        kind_in(Some(docs("can_insert").as_str()), "admin"),
        "{model}"
    );
    assert!(
        !kind_in(Some(docs("can_insert").as_str()), "editor"),
        "{model}"
    );
    assert!(
        !kind_in(Some(docs("can_insert").as_str()), "stranger"),
        "{model}"
    );
    // The revoke took DELETE and left UPDATE.
    assert!(
        kind_in(Some(docs("can_update_without_reading").as_str()), "admin"),
        "{model}"
    );
    assert!(
        kind_in(Some(docs("can_update_without_reading").as_str()), "editor"),
        "{model}"
    );
    assert!(
        !kind_in(
            Some(docs("can_update_without_reading").as_str()),
            "stranger"
        ),
        "{model}"
    );
    assert!(
        kind_in(Some(docs("can_delete").as_str()), "admin"),
        "{model}"
    );
    assert!(
        !kind_in(Some(docs("can_delete").as_str()), "editor"),
        "the revoke took DELETE:\n{model}"
    );
    assert!(
        !kind_in(Some(docs("can_delete").as_str()), "stranger"),
        "{model}"
    );
    // secrets has no PUBLIC grant, so admin is its only branch.
    assert!(
        kind_in(Some(secrets("can_select").as_str()), "admin"),
        "{model}"
    );
    assert!(
        !kind_in(Some(secrets("can_select").as_str()), "editor"),
        "{model}"
    );
    assert!(
        !kind_in(Some(secrets("can_select").as_str()), "stranger"),
        "{model}"
    );
}

/// A command with no privilege holder denies every acting role.
#[test]
fn a_command_no_acting_role_holds_is_denied() {
    let planned = acting(
        &["app_user"],
        "
CREATE ROLE app_user NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
GRANT SELECT ON docs TO PUBLIC;
",
    );
    assert_eq!(
        answer(&planned, "docs", ActionStatement::Select),
        &ActionAnswer::Unrestricted,
        "the one acting role reads every row through PUBLIC"
    );
    for statement in [
        ActionStatement::Insert,
        ActionStatement::Update,
        ActionStatement::Delete,
        ActionStatement::UpdateWithoutWhere,
        ActionStatement::SelectForUpdate,
        ActionStatement::InsertReturning,
        ActionStatement::InsertOnConflictUpdate,
    ] {
        assert!(
            denies(&planned, "docs", statement),
            "no acting role holds {statement:?}"
        );
    }
}

/// A role holding `UPDATE` on one column gets its branch, and the column it may set is asked
/// on the gate object beside the rows.
#[test]
fn a_column_grant_answers_the_command_per_column() {
    let planned = acting(
        &["writer"],
        "
CREATE ROLE writer NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (true);
CREATE POLICY docs_write ON docs FOR UPDATE USING (true);
GRANT SELECT ON docs TO writer;
GRANT UPDATE (body) ON docs TO writer;
GRANT INSERT (body) ON docs TO writer;
",
    );
    assert_eq!(
        answer(&planned, "docs", ActionStatement::Select),
        &ActionAnswer::Unrestricted,
        "SELECT is held on the table, so no column is asked"
    );
    let update = by_column(&planned, "docs", ActionStatement::Update);
    assert_eq!(*update.rows, ActionAnswer::Unrestricted);
    assert_eq!(update.gate, "request_gate:docs");
    assert_eq!(
        update.commands,
        [column_relations(ColumnCommand::Update, "update", &["body"])]
    );
    assert_eq!(
        answer(&planned, "docs", ActionStatement::SelectForUpdate),
        &ActionAnswer::Unrestricted,
        "UPDATE on one column is enough for a locking read"
    );
    assert!(
        denies(&planned, "docs", ActionStatement::Insert),
        "no policy admits an insert, so its column grant asks nothing"
    );
    let notes = planned.notes().to_vec();
    let outputs = planned
        .outputs()
        .unwrap_or_else(|_| panic!("nothing diverges: {notes:#?}"));
    assert!(gate_holds(&outputs, "docs", "can_update_body", "writer"));
    assert!(
        !gate_holds(&outputs, "docs", "can_update_on_table", "writer"),
        "the writer holds UPDATE on no other column"
    );
}

/// A read held on one column is asked per column read.
#[test]
fn a_column_grant_on_a_read_answers_it_per_column() {
    let planned = acting(
        &["reader"],
        "
CREATE ROLE reader NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (true);
GRANT SELECT (body) ON docs TO reader;
",
    );
    let select = by_column(&planned, "docs", ActionStatement::Select);
    assert_eq!(*select.rows, ActionAnswer::Unrestricted);
    assert_eq!(
        select.commands,
        [column_relations(ColumnCommand::Select, "select", &["body"])]
    );
    for statement in [
        ActionStatement::Insert,
        ActionStatement::Update,
        ActionStatement::Delete,
    ] {
        assert!(
            denies(&planned, "docs", statement),
            "the role holds no other command"
        );
    }
    let outputs = planned.outputs().expect("nothing diverges");
    assert!(gate_holds(&outputs, "docs", "can_select_body", "reader"));
}

/// An insert held on one column is asked per column assigned, and reading it back needs
/// `SELECT` the role does not hold.
#[test]
fn a_column_grant_on_an_insert_answers_it_per_column() {
    let planned = acting(
        &["writer"],
        "
CREATE ROLE writer NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_insert ON docs FOR INSERT WITH CHECK (true);
GRANT INSERT (body) ON docs TO writer;
",
    );
    let insert = by_column(&planned, "docs", ActionStatement::Insert);
    assert_eq!(*insert.rows, ActionAnswer::Unrestricted);
    assert_eq!(
        insert.commands,
        [column_relations(ColumnCommand::Insert, "insert", &["body"])]
    );
    for statement in [
        ActionStatement::InsertReturning,
        ActionStatement::Select,
        ActionStatement::Update,
        ActionStatement::Delete,
    ] {
        assert!(
            denies(&planned, "docs", statement),
            "{statement:?} needs a command the role does not hold"
        );
    }
}

/// Rows no gate admits stay a refusal, whatever the columns hold.
#[test]
fn a_column_grant_beside_a_gate_admitting_no_row_stays_a_refusal() {
    for (label, policies) in [
        (
            "a permissive gate constant false",
            "CREATE POLICY docs_read ON docs FOR SELECT USING (false);
CREATE POLICY docs_write ON docs FOR UPDATE USING (false);",
        ),
        (
            "a restrictive gate constant false beside the open grant",
            "CREATE POLICY docs_read ON docs FOR SELECT USING (true);
CREATE POLICY docs_read_bar ON docs AS RESTRICTIVE FOR SELECT USING (false);
CREATE POLICY docs_write ON docs FOR UPDATE USING (true);
CREATE POLICY docs_write_bar ON docs AS RESTRICTIVE FOR UPDATE USING (false);",
        ),
    ] {
        let planned = acting(
            &["writer"],
            &format!(
                "
CREATE ROLE writer NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{policies}
GRANT SELECT ON docs TO writer;
GRANT UPDATE (body) ON docs TO writer;
"
            ),
        );
        assert!(
            denies(&planned, "docs", ActionStatement::Select),
            "{label}: the gate admits no row"
        );
        assert!(
            denies(&planned, "docs", ActionStatement::Update),
            "{label}: no row passes, so no column is asked"
        );
        assert!(
            planned.outputs().is_ok(),
            "{label}: a gate admitting no row diverges nothing"
        );
    }
}

/// Session grantees bind to the known DDL role.
#[test]
fn a_session_grantee_binds_to_the_ddl_time_role() {
    let ddl = |session: &str| {
        format!(
            "
CREATE ROLE app_owner NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO app_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
{session}
"
        )
    };
    let revoked = acting(
        &["app_owner"],
        &ddl("
SET ROLE app_owner;
REVOKE UPDATE ON docs FROM CURRENT_USER;
RESET ROLE;
"),
    );
    for statement in [
        ActionStatement::Select,
        ActionStatement::Insert,
        ActionStatement::Delete,
    ] {
        assert!(
            admits(&revoked, "docs", statement),
            "the owner entry holds {statement:?}"
        );
    }
    assert!(
        denies(&revoked, "docs", ActionStatement::Update),
        "the revoked command is gone"
    );
    let restored = acting(
        &["app_owner"],
        &ddl("
SET ROLE app_owner;
REVOKE UPDATE ON docs FROM CURRENT_USER;
GRANT UPDATE ON docs TO CURRENT_USER;
RESET ROLE;
"),
    );
    assert!(
        admits(&restored, "docs", ActionStatement::Update),
        "the restored command is held"
    );
    assert!(admits(&restored, "docs", ActionStatement::Select));
}

/// Owner exemptions preserve the owner's command privileges.
#[test]
fn a_named_owner_holds_its_privileges_where_the_rules_bind_it() {
    let schema = |force: &str| {
        format!(
            "
CREATE ROLE app_owner NOLOGIN;
CREATE ROLE reader NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs OWNER TO app_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{force}
CREATE POLICY docs_read ON docs FOR SELECT USING (true);
GRANT SELECT ON docs TO reader;
"
        )
    };
    for force in ["ALTER TABLE docs FORCE ROW LEVEL SECURITY;", ""] {
        let planned = acting(&["app_owner", "reader"], &schema(force));
        assert_eq!(
            answer(&planned, "docs", ActionStatement::Select),
            &ActionAnswer::Unrestricted,
            "the owner through its owner entry and the reader through its grant read every \
             row, {force}"
        );
    }
    let forced = acting(
        &["app_owner", "reader"],
        &schema("ALTER TABLE docs FORCE ROW LEVEL SECURITY;"),
    );
    let unforced = acting(&["app_owner", "reader"], &schema(""));
    assert!(
        !forced.notes().iter().any(|note| {
            matches!(note, TranslationNote::ActingRoleExempt { role, .. } if role == "app_owner")
        }),
        "FORCE binds the owner to the rules: {:#?}",
        forced.notes()
    );
    assert!(
        unforced.notes().iter().any(|note| {
            matches!(note, TranslationNote::ActingRoleExempt { role, .. } if role == "app_owner")
        }),
        "without FORCE the owner skips the rules: {:#?}",
        unforced.notes()
    );
}

/// Public and quoted role grantees retain their SQL meanings.
#[test]
fn public_and_quoted_role_spellings_resolve_as_postgresql() {
    let schema = r#"
CREATE ROLE "Reader" NOLOGIN;
CREATE ROLE reader NOLOGIN;
CREATE ROLE other NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
GRANT SELECT ON docs TO GROUP public;
GRANT INSERT ON docs TO "public";
GRANT UPDATE ON docs TO "Reader";
GRANT DELETE ON docs TO Reader;
"#;
    let quoted = acting(&["Reader"], schema);
    let unquoted = acting(&["reader"], schema);
    let other = acting(&["other"], schema);
    for planned in [&quoted, &unquoted, &other] {
        // PUBLIC, in either spelling, reaches every role.
        assert!(
            admits(planned, "docs", ActionStatement::Select),
            "GROUP public settles to PUBLIC"
        );
        assert!(
            admits(planned, "docs", ActionStatement::Insert),
            "quoted \"public\" settles to PUBLIC"
        );
    }
    // The quoted grantee is the role `Reader`, the unquoted one the role `reader`.
    assert!(admits(&quoted, "docs", ActionStatement::Update));
    assert!(denies(&quoted, "docs", ActionStatement::Delete));
    assert!(admits(&unquoted, "docs", ActionStatement::Delete));
    assert!(denies(&unquoted, "docs", ActionStatement::Update));
    // The role no grant names holds only what PUBLIC holds.
    assert!(denies(&other, "docs", ActionStatement::Update));
    assert!(denies(&other, "docs", ActionStatement::Delete));
}

/// A column grant to `PUBLIC` holds the gate relation for the acting role it reaches.
#[test]
fn a_column_grant_to_public_holds_the_acting_role() {
    let planned = acting(
        &["app_user"],
        "
CREATE ROLE app_user NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (true);
CREATE POLICY docs_write ON docs FOR UPDATE USING (true);
GRANT SELECT ON docs TO PUBLIC;
GRANT UPDATE (body) ON docs TO PUBLIC;
",
    );
    assert_eq!(
        by_column(&planned, "docs", ActionStatement::Update).commands,
        [column_relations(ColumnCommand::Update, "update", &["body"])]
    );
    let outputs = planned.outputs().expect("nothing diverges");
    assert!(
        gate_holds(&outputs, "docs", "can_update_body", "app_user"),
        "the gate names the acting role, never the PUBLIC the grant spelled"
    );
}

/// Owner exemptions cannot restore a revoked privilege.
#[test]
fn a_revoked_owner_privilege_denies_the_owner_even_where_the_rules_exempt_it() {
    let planned = acting(
        &["app_owner", "reader"],
        "
CREATE ROLE app_owner NOLOGIN;
CREATE ROLE reader NOLOGIN;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO app_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
GRANT SELECT, UPDATE ON docs TO reader;
REVOKE UPDATE ON docs FROM app_owner;
",
    );
    assert!(
        planned.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ActingRoleExempt { role, .. } if role == "app_owner"
        )),
        "without FORCE the owner skips the rules: {:#?}",
        planned.notes()
    );
    assert!(admits(&planned, "docs", ActionStatement::Select));
    assert!(admits(&planned, "docs", ActionStatement::Update));
    let outputs = planned
        .outputs()
        .expect("the whole-table grants diverge nothing");
    let model = outputs.model();
    let can_select = relation_definition(&model, "docs", "can_select").unwrap();
    let can_update = relation_definition(&model, "docs", "can_update_without_reading").unwrap();
    assert!(
        kind_in(Some(can_select.as_str()), "app_owner"),
        "the owner still holds SELECT:\n{model}"
    );
    assert!(kind_in(Some(can_select.as_str()), "reader"), "{model}");
    assert!(
        !kind_in(Some(can_update.as_str()), "app_owner"),
        "the revoked UPDATE is gone from the owner whatever the exemption says:\n{model}"
    );
    assert!(kind_in(Some(can_update.as_str()), "reader"), "{model}");
}

/// Inherited privileges reach acting roles.
#[test]
fn grants_reach_the_acting_roles_through_their_inherited_roles() {
    let planned = acting(
        &["anon", "authenticated"],
        "
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE writers NOLOGIN;
GRANT writers TO authenticated;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
GRANT SELECT ON docs TO anon, authenticated;
GRANT INSERT ON docs TO writers;
GRANT UPDATE ON docs TO ghost, authenticated;
",
    );
    assert!(admits(&planned, "docs", ActionStatement::Select));
    assert!(admits(&planned, "docs", ActionStatement::Insert));
    assert!(admits(&planned, "docs", ActionStatement::Update));
    assert!(
        denies(&planned, "docs", ActionStatement::Delete),
        "no acting role holds DELETE"
    );
    let outputs = planned
        .outputs()
        .expect("every grant settles to a declared role or to nobody");
    let model = outputs.model();
    let can_select = relation_definition(&model, "docs", "can_select").unwrap();
    let can_insert = relation_definition(&model, "docs", "can_insert").unwrap();
    let can_update = relation_definition(&model, "docs", "can_update_without_reading").unwrap();
    assert!(kind_in(Some(can_select.as_str()), "anon"), "{model}");
    assert!(
        kind_in(Some(can_select.as_str()), "authenticated"),
        "{model}"
    );
    // `writers` is inherited by `authenticated` alone, and no kind is minted for it.
    assert!(
        kind_in(Some(can_insert.as_str()), "authenticated"),
        "the inherited grant reaches its member:\n{model}"
    );
    assert!(!kind_in(Some(can_insert.as_str()), "anon"), "{model}");
    assert!(!model.contains("acting_writers"), "{model}");
    // `ghost` is never created, so only `authenticated`'s own grant is reached.
    assert!(
        kind_in(Some(can_update.as_str()), "authenticated"),
        "{model}"
    );
    assert!(!kind_in(Some(can_update.as_str()), "anon"), "{model}");
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.to_string().contains("ghost")),
        "an unsettled grantee settles to nobody without a note: {:#?}",
        outputs.notes()
    );
}

/// A holder that reaches every acting role opens every branch.
#[test]
fn a_holder_reaching_every_acting_role_opens_every_branch() {
    let planned = acting(
        &["anon", "authenticated"],
        "
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE members NOLOGIN;
GRANT members TO anon, authenticated;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
GRANT SELECT ON docs TO members;
",
    );
    assert_eq!(
        answer(&planned, "docs", ActionStatement::Select),
        &ActionAnswer::Unrestricted,
        "the holder reaches every acting role"
    );
    assert!(
        denies(&planned, "docs", ActionStatement::Insert),
        "no acting role holds INSERT"
    );
}

/// A holder outside the acting roles grants no command.
#[test]
fn a_holder_reaching_no_acting_role_denies_the_command() {
    let planned = acting(
        &["anon", "authenticated"],
        "
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE members NOLOGIN;
CREATE ROLE support_staff NOLOGIN;
GRANT members TO anon, authenticated;
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs OWNER TO keeper;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
GRANT SELECT ON docs TO members;
GRANT DELETE ON docs TO support_staff;
",
    );
    assert_eq!(
        answer(&planned, "docs", ActionStatement::Select),
        &ActionAnswer::Unrestricted,
        "members reaches both acting roles"
    );
    assert!(
        denies(&planned, "docs", ActionStatement::Delete),
        "support_staff reaches no acting role"
    );
    let outputs = planned
        .outputs()
        .expect("the grants settle to the acting roles or to nobody");
    let model = outputs.model();
    let can_delete = relation_definition(&model, "docs", "can_delete").unwrap();
    assert!(
        !kind_in(Some(can_delete.as_str()), "anon"),
        "no acting role branch joins the denied command:\n{model}"
    );
    assert!(
        !kind_in(Some(can_delete.as_str()), "authenticated"),
        "{model}"
    );
    assert!(can_delete.contains("no_access"), "{model}");
}

#[test]
fn a_keyless_table_without_privileges_needs_no_row_identity() {
    let planned = acting(
        &["visitor"],
        "CREATE ROLE visitor; CREATE TABLE scratch(note TEXT);",
    );
    for statement in [
        ActionStatement::Select,
        ActionStatement::Insert,
        ActionStatement::Update,
        ActionStatement::Delete,
    ] {
        assert!(denies(&planned, "scratch", statement));
    }
    assert!(planned.outputs().is_ok());
}

#[test]
fn a_keyless_unfiltered_table_keeps_role_permissions_row_independent() {
    let planned = acting(
        &["reader", "stranger"],
        "CREATE ROLE reader;
         CREATE ROLE stranger;
         CREATE TABLE scratch(note TEXT);
         GRANT SELECT ON scratch TO reader;",
    );
    assert!(admits(&planned, "scratch", ActionStatement::Select));
    assert!(denies(&planned, "scratch", ActionStatement::Update));
    let outputs = planned
        .outputs()
        .expect("row-independent permissions need no row key");
    let naming = outputs
        .translation()
        .row_naming()
        .iter()
        .find(|entry| entry.table == table("scratch"))
        .expect("the table has an object naming contract");
    let left = naming
        .render(&crate::support::row(&[("note", "left")]))
        .unwrap();
    let right = naming
        .render(&crate::support::row(&[("note", "right")]))
        .unwrap();
    assert!(left.is_some());
    assert_eq!(left, right);
    let model = outputs.model();
    let select = relation_definition(&model, "scratch", "can_select").unwrap();
    assert!(kind_in(Some(&select), "reader"));
    assert!(!kind_in(Some(&select), "stranger"));
}
