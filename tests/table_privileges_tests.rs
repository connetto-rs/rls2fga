//! Table privileges gating each action, behind `with_table_privileges`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rls2fga::generator::caller_roles::CallerRoles;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::{
    ActionAnswer, ActionStatement, NoteSeverity, PrivilegeHolders, TableId, TablePrivileges,
    TranslationNote,
};

/// The request's own example: `kind_anon` may read but not update.
const WITHHELD_UPDATE: &str = "
CREATE TABLE notes (id BIGINT PRIMARY KEY, owner TEXT NOT NULL, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_read ON notes FOR SELECT USING (true);
CREATE POLICY notes_write ON notes FOR UPDATE USING (owner = current_setting('app.user_id', true));
GRANT SELECT ON notes TO kind_anon;
GRANT SELECT, UPDATE ON notes TO kind_user;
";

fn translate(sql: &str, privileges: bool) -> Translation {
    let db = parse_schema(sql).expect("schema parses");
    let builder = TranslatorBuilder::new().with_current_user_setting_keys(["app.user_id"]);
    let builder = if privileges {
        builder.with_table_privileges()
    } else {
        builder
    };
    builder.build().translate(&db).expect("translation plans")
}

fn roles(names: &[&str]) -> PrivilegeHolders {
    PrivilegeHolders::Roles(names.iter().map(|name| (*name).to_string()).collect())
}

fn docs() -> TableId {
    TableId::from_stored(None, "docs".to_string())
}

fn answer(translation: &Translation, type_name: &str, statement: ActionStatement) -> ActionAnswer {
    translation
        .action_relations()
        .iter()
        .find(|entry| entry.type_name.as_str() == type_name && entry.statement == statement)
        .map(|entry| entry.answer.clone())
        .expect("the statement is answered")
}

fn scope_roles(translation: &Translation, command: &str) -> Vec<Vec<String>> {
    translation
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::TablePrivilegeScope {
                commands, roles, ..
            } if commands.iter().any(|named| named == command) => Some(roles.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn each_command_is_gated_on_the_roles_holding_its_privilege() {
    let translation = translate(WITHHELD_UPDATE, true);
    let outputs = translation.outputs().expect("nothing diverges");
    insta::assert_snapshot!("withheld_update_model", outputs.model().trim());
    insta::assert_snapshot!(
        "withheld_update_tuples",
        rls2fga::generator::tuple_generator::format_tuples(outputs.tuple_queries())
    );
}

#[test]
fn without_the_option_no_privilege_is_read() {
    let with_grants = translate(WITHHELD_UPDATE, false);
    let without_grants = translate(
        &WITHHELD_UPDATE
            .replace("GRANT SELECT ON notes TO kind_anon;", "")
            .replace("GRANT SELECT, UPDATE ON notes TO kind_user;", ""),
        false,
    );
    assert_eq!(
        with_grants.clone().outputs().unwrap().model(),
        without_grants.outputs().unwrap().model()
    );
    assert_eq!(
        scope_roles(&with_grants, "SELECT"),
        Vec::<Vec<String>>::new()
    );
}

#[test]
fn public_all_privileges_and_a_revoke_are_each_read() {
    let translation = translate(
        "
CREATE TABLE docs (id TEXT PRIMARY KEY);
GRANT SELECT ON docs TO PUBLIC;
GRANT ALL PRIVILEGES ON docs TO admin;
GRANT UPDATE, DELETE ON docs TO editor;
REVOKE DELETE ON docs FROM editor;
",
        true,
    );
    let [docs] = translation.unrestricted_tables() else {
        panic!("one table is unrestricted");
    };
    assert_eq!(
        docs.privileges,
        Some(TablePrivileges {
            select: PrivilegeHolders::Everyone,
            insert: roles(&["admin"]),
            update: roles(&["admin", "editor"]),
            delete: roles(&["admin"]),
        })
    );
}

#[test]
fn an_unrestricted_table_reports_no_privileges_without_the_option() {
    let translation = translate("CREATE TABLE docs (id TEXT PRIMARY KEY);", false);
    let [docs] = translation.unrestricted_tables() else {
        panic!("one table is unrestricted");
    };
    assert_eq!(docs.privileges, None);
}

#[test]
fn a_command_nobody_holds_is_denied() {
    let translation = translate(
        "
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
GRANT SELECT ON docs TO PUBLIC;
",
        true,
    );
    assert_eq!(
        answer(&translation, "docs", ActionStatement::Delete),
        ActionAnswer::Denied
    );
    assert!(matches!(
        answer(&translation, "docs", ActionStatement::Select),
        ActionAnswer::Judged(_)
    ));
    assert_eq!(
        scope_roles(&translation, "SELECT"),
        Vec::<Vec<String>>::new(),
        "a privilege granted to PUBLIC gates nothing"
    );
}

#[test]
fn a_column_grant_on_an_admitted_command_narrows_and_diverges() {
    let translation = translate(
        "
CREATE TABLE docs (id TEXT PRIMARY KEY, body TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (true);
CREATE POLICY docs_write ON docs FOR UPDATE USING (true);
GRANT SELECT ON docs TO writer;
GRANT UPDATE (body) ON docs TO writer;
GRANT INSERT (body) ON docs TO writer;
",
        true,
    );
    let column_notes: Vec<&TranslationNote> = translation
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ColumnPrivilegeOnly { .. }))
        .collect();
    // INSERT has no policy, so the database refuses it too and nothing narrows there.
    assert_eq!(
        column_notes,
        [&TranslationNote::ColumnPrivilegeOnly {
            table: docs(),
            command: "UPDATE".to_string(),
            roles: vec!["writer".to_string()],
        }]
    );
    assert_eq!(column_notes[0].severity(), NoteSeverity::Partial);
    assert_eq!(
        answer(&translation, "docs", ActionStatement::Update),
        ActionAnswer::Denied
    );
    assert!(translation.outputs().is_err());
}

#[test]
fn a_grantee_resolved_when_granted_is_modelled_as_nobody_and_diverges() {
    let translation = translate(
        "
CREATE TABLE docs (id TEXT PRIMARY KEY);
GRANT SELECT ON docs TO CURRENT_USER, reader;
",
        true,
    );
    assert!(translation
        .notes()
        .contains(&TranslationNote::TablePrivilegeGrantedToDdlTimeRole {
            table: docs(),
            commands: vec!["SELECT".to_string()],
            spellings: vec!["CURRENT_USER".to_string()],
        }));
    assert_eq!(
        translation.unrestricted_tables()[0]
            .privileges
            .as_ref()
            .map(|privileges| &privileges.select),
        Some(&roles(&["reader"]))
    );
    assert!(translation.outputs().is_err());
}

#[test]
fn a_named_owner_holds_its_privileges_where_the_rules_bind_it() {
    let schema = |force: &str| {
        format!(
            "
CREATE TABLE docs (id TEXT PRIMARY KEY);
ALTER TABLE docs OWNER TO app_owner;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{force}
CREATE POLICY docs_read ON docs FOR SELECT USING (true);
GRANT SELECT ON docs TO reader;
"
        )
    };
    let forced = translate(&schema("ALTER TABLE docs FORCE ROW LEVEL SECURITY;"), true);
    assert_eq!(
        scope_roles(&forced, "SELECT"),
        [vec!["app_owner".to_string(), "reader".to_string()]]
    );
    // Unforced, the owner bypasses every policy, which is reported as an exemption already.
    let unforced = translate(&schema(""), true);
    assert_eq!(
        scope_roles(&unforced, "SELECT"),
        [vec!["reader".to_string()]]
    );
}

#[test]
fn an_unnamed_owner_bound_by_the_rules_is_exempt() {
    let translation = translate(
        "
CREATE TABLE docs (id TEXT PRIMARY KEY);
GRANT SELECT ON docs TO reader;
",
        true,
    );
    let note = TranslationNote::TableOwnerUnnamed { table: docs() };
    assert!(translation.notes().contains(&note));
    assert_eq!(note.severity(), NoteSeverity::Exempt);
    assert!(translation.outputs().is_ok());
}

fn translate_for_callers(sql: &str, callers: &[&str]) -> Translation {
    let db = parse_schema(sql).expect("schema parses");
    TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .with_caller_roles(CallerRoles::new(callers.iter().copied()).expect("callers given"))
        .with_table_privileges()
        .build()
        .translate(&db)
        .expect("translation plans")
}

const CALLER_GRANTS: &str = "
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE writers NOLOGIN;
GRANT writers TO authenticated;
CREATE TABLE docs (id TEXT PRIMARY KEY);
GRANT SELECT ON docs TO anon, authenticated;
GRANT INSERT ON docs TO writers;
GRANT UPDATE ON docs TO ghost, authenticated;
";

#[test]
fn caller_roles_settle_each_holder_through_the_memberships_the_schema_declares() {
    let translation = translate_for_callers(CALLER_GRANTS, &["anon", "authenticated"]);
    assert_eq!(
        translation.unrestricted_tables()[0].privileges,
        Some(TablePrivileges {
            // Held by every caller role, so nothing gates it.
            select: PrivilegeHolders::Everyone,
            // Granted to a role only `authenticated` inherits.
            insert: roles(&["authenticated"]),
            // `ghost` is never created, so only the holder the schema shows is reached.
            update: roles(&["authenticated"]),
            delete: roles(&[]),
        })
    );
    assert!(translation
        .notes()
        .contains(&TranslationNote::TablePrivilegeRoleUnsettled {
            table: docs(),
            commands: vec!["UPDATE".to_string()],
            roles: vec!["ghost".to_string()],
        }));
}

#[test]
fn a_gate_with_caller_roles_names_the_caller_roles_alone() {
    let translation = translate_for_callers(
        &format!(
            "{CALLER_GRANTS}
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs USING (true) WITH CHECK (true);
"
        ),
        &["anon", "authenticated"],
    );
    assert_eq!(
        scope_roles(&translation, "SELECT"),
        Vec::<Vec<String>>::new()
    );
    assert_eq!(
        scope_roles(&translation, "INSERT"),
        [vec!["authenticated".to_string()]]
    );
}
