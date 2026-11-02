use rls2fga::parser::sql_parser::parse_schema;
use sql_traits::prelude::*;

use crate::support;

fn table<'db, DB: DatabaseLike>(db: &'db DB, name: &str) -> Option<&'db DB::Table> {
    db.table_by_target(TargetName::new(name, false), IdentifierCase::AsWritten)
        .expect("table lookup does not error against a fixture's own database")
}

fn function<'db, DB: DatabaseLike>(db: &'db DB, name: &str) -> Option<&'db DB::Function> {
    db.function_by_target(TargetName::new(name, false), IdentifierCase::AsWritten)
        .expect("function lookup does not error against a fixture's own database")
}

#[test]
fn parse_emi_schema_tables() {
    let db = support::parse_fixture_db("earth_metabolome");

    assert_eq!(db.number_of_tables(), 5, "Expected 5 tables");
    assert!(table(&db, "users").is_some());
    assert!(table(&db, "teams").is_some());
    assert!(table(&db, "team_members").is_some());
    assert!(table(&db, "ownables").is_some());
    assert!(table(&db, "owner_grants").is_some());
}

#[test]
fn parse_emi_schema_columns() {
    let db = support::parse_fixture_db("earth_metabolome");

    let ownables = table(&db, "ownables").expect("ownables table");
    let cols: Vec<String> = ownables
        .columns(&db)
        .expect("ownables columns")
        .map(|c| c.column_name().to_string())
        .collect();
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0], "id");
    assert_eq!(cols[1], "owner_id");

    let team_members = table(&db, "team_members").expect("team_members table");
    let tm_col_count = team_members
        .columns(&db)
        .expect("team_members columns")
        .count();
    assert_eq!(tm_col_count, 2);
}

#[test]
fn parse_emi_schema_foreign_keys() {
    let db = support::parse_fixture_db("earth_metabolome");

    let team_members = table(&db, "team_members").expect("team_members table");
    let fk_count = team_members
        .foreign_keys(&db)
        .expect("team_members foreign keys")
        .count();
    assert!(
        fk_count >= 2,
        "team_members should have at least 2 foreign keys, got {fk_count}",
    );
}

#[test]
fn parse_emi_functions() {
    let db = support::parse_fixture_db("earth_metabolome");

    // sql-traits tracks all function references, not just CREATE FUNCTION statements.
    // Verify the two user-defined functions are present.
    assert!(function(&db, "auth_current_user_id").is_some());
    assert!(function(&db, "get_owner_role").is_some());
}

#[test]
fn parse_emi_policies() {
    let db = support::parse_fixture_db("earth_metabolome");

    let policies: Vec<_> = db.policies().collect();
    assert_eq!(policies.len(), 4, "Expected 4 policies");

    let select_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_select_policy")
        .unwrap();
    assert_eq!(select_policy.table_name.to_string(), "ownables");
    assert!(matches!(
        select_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Select)
    ));
    assert!(select_policy.using.is_some());
    assert!(select_policy.with_check.is_none());

    let insert_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_insert_policy")
        .unwrap();
    assert!(matches!(
        insert_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Insert)
    ));
    assert!(insert_policy.using.is_none());
    assert!(insert_policy.with_check.is_some());

    let update_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_update_policy")
        .unwrap();
    assert!(matches!(
        update_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Update)
    ));
    assert!(update_policy.using.is_some());
    assert!(update_policy.with_check.is_some());

    let delete_policy = policies
        .iter()
        .find(|p| p.name.value == "ownables_delete_policy")
        .unwrap();
    assert!(matches!(
        delete_policy.command,
        Some(sqlparser::ast::CreatePolicyCommand::Delete)
    ));
    assert!(delete_policy.using.is_some());
}

#[test]
fn parse_emi_rls_enabled() {
    let db = support::parse_fixture_db("earth_metabolome");

    let rls_tables: Vec<_> = db.rls_tables().expect("rls tables").collect();
    assert_eq!(rls_tables.len(), 1);
    assert_eq!(rls_tables[0].table_name(), "ownables");
}

/// `ALTER POLICY ... USING` supersedes the expression the policy was created with, and
/// the model has to follow it. Using the original instead is an over-grant whenever the
/// alteration narrowed the policy, which is why the schema used to be refused outright.
#[test]
fn a_policy_expression_altered_after_creation_is_the_one_translated() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
ALTER POLICY docs_sel ON docs USING (FALSE);
";
    let db = parse_schema(sql).expect("an altered policy no longer refuses the schema");
    let policy = db.policies().next().expect("the policy survives the alter");
    assert_eq!(
        policy
            .using_expression(&db)
            .map(ToString::to_string)
            .as_deref(),
        Some("false"),
        "the altered expression is what PostgreSQL enforces"
    );
}

/// Renaming a policy leaves its expression alone, so the schema still describes
/// what `PostgreSQL` enforces.
#[test]
fn renaming_a_policy_is_still_accepted() {
    let sql = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
ALTER POLICY docs_sel ON docs RENAME TO docs_select;
";
    parse_schema(sql).expect("a rename does not change the expression");
}

/// Roles are cluster objects that `pg_dump` never emits, so a dumped schema grants to
/// roles it does not create. rls2fga models policies rather than privileges, so a
/// statement it would ignore must not refuse the schema.
#[test]
fn a_grant_naming_a_role_the_schema_does_not_create_is_accepted() {
    const SCHEMA: &str = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
";
    for dcl in [
        "GRANT SELECT ON docs TO app;",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON docs TO app;",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO app;",
        "GRANT USAGE ON SCHEMA public TO app;",
        "REVOKE ALL ON docs FROM app;",
    ] {
        parse_schema(&format!("{SCHEMA}{dcl}\n"))
            .unwrap_or_else(|error| panic!("`{dcl}` must not refuse the schema: {error}"));
    }
}

/// Every schema accessor rls2fga calls is fallible upstream, and rls2fga reads an error
/// as "the schema does not say" so the decision falls closed. That is only safe because
/// the error cannot occur: every object is fetched from the same database it is then
/// queried against, which is exactly what `LookupError::ObjectNotInDatabase` reports.
/// Nothing in the type system enforces that, so assert it over the whole corpus. A
/// failure here means a fail-closed default has started hiding a real diagnosis.
#[test]
fn no_schema_lookup_fails_on_any_fixture() {
    let mut dirs: Vec<_> = std::fs::read_dir("tests/fixtures")
        .expect("fixtures directory")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| path.join("input.sql").is_file())
        .collect();
    dirs.sort();
    assert!(dirs.len() > 20, "the corpus should not have shrunk");

    let mut failures: Vec<String> = Vec::new();
    let mut visited = 0usize;

    for dir in dirs {
        let name = dir.file_name().expect("fixture name").to_string_lossy();
        let sql = std::fs::read_to_string(dir.join("input.sql")).expect("fixture SQL");
        let Ok(db) = parse_schema(&sql) else {
            continue;
        };

        if db.rls_tables().map(Iterator::count).is_err() {
            failures.push(format!("{name}: rls_tables"));
        }
        for table in db.tables() {
            let table_name = table.table_name();
            visited += 1;
            let mut note = |what: &str| failures.push(format!("{name}: {table_name} {what}"));

            if table.has_row_level_security(&db).is_err() {
                note("has_row_level_security");
            }
            if table.has_composite_primary_key(&db).is_err() {
                note("has_composite_primary_key");
            }
            if table.primary_key_column(&db).is_err() {
                note("primary_key_column");
            }
            if table.primary_key_columns(&db).map(Iterator::count).is_err() {
                note("primary_key_columns");
            }
            if table.policies(&db).map(Iterator::count).is_err() {
                note("policies");
            }

            match table.columns(&db) {
                Ok(columns) => {
                    for column in columns {
                        if column.is_nullable(&db).is_err() {
                            note("column is_nullable");
                        }
                    }
                }
                Err(_) => note("columns"),
            }
            match table.unique_indices(&db) {
                Ok(indices) => {
                    for index in indices {
                        if index.columns(&db).map(Iterator::count).is_err() {
                            note("unique index columns");
                        }
                    }
                }
                Err(_) => note("unique_indices"),
            }
            match table.foreign_keys(&db) {
                Ok(foreign_keys) => {
                    for foreign_key in foreign_keys {
                        if foreign_key.host_column(&db).is_err() {
                            note("fk host_column");
                        }
                        if foreign_key.host_columns(&db).map(Iterator::count).is_err() {
                            note("fk host_columns");
                        }
                        if foreign_key.referenced_table(&db).is_err() {
                            note("fk referenced_table");
                        }
                    }
                }
                Err(_) => note("foreign_keys"),
            }
        }
    }

    assert!(
        visited > 20,
        "only {visited} tables checked, so the corpus is not being walked"
    );
    assert!(
        failures.is_empty(),
        "a fail-closed default is hiding a real diagnosis:\n{}",
        failures.join("\n")
    );
}

/// The invariant above is worth asserting only because violating it is reported rather
/// than ignored. Querying a table against a database that does not hold it is exactly
/// the mistake `LookupError::ObjectNotInDatabase` exists for, and upstream used to abort
/// on it. This pins that it now returns an error, so the fail-closed defaults in
/// `db_lookup` and the generator are covering a condition that can genuinely arise.
#[test]
fn a_table_queried_against_another_database_is_reported() {
    let owning = parse_schema("CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);")
        .expect("schema should parse");
    let other = parse_schema("CREATE TABLE notes(id UUID PRIMARY KEY);").expect("schema parses");

    let docs = table(&owning, "docs").expect("docs table");
    assert!(
        docs.columns(&owning).is_ok(),
        "its own database resolves it"
    );
    assert!(
        docs.columns(&other).is_err(),
        "a database without the table must report rather than answer"
    );
}

/// A reference the search path cannot reach is refused, not guessed at.
///
/// This is what replaced an older fallback that resolved an unqualified name to the
/// only table bearing it, wherever that table lived. `PostgreSQL` refuses such DDL,
/// so resolving it invented a policy the database would never have accepted, and
/// every model built from one bound the policy to rows RLS never guarded.
#[test]
fn a_policy_naming_a_table_the_search_path_cannot_reach_is_refused() {
    let error = parse_schema(
        "CREATE SCHEMA app;\
         CREATE TABLE app.docs(id INT, owner_id INT);\
         ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;\
         CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = 1);",
    )
    .expect_err("an unreachable policy target must refuse the schema");

    let message = error.to_string();
    assert!(
        message.contains("not found") && message.contains("docs_sel"),
        "the refusal must say the target was not found and name the policy, got: {message}"
    );

    // The same schema with the path that makes the reference legal.
    parse_schema(
        "CREATE SCHEMA app;\
         SET search_path TO app;\
         CREATE TABLE app.docs(id INT, owner_id INT);\
         ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;\
         CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = 1);",
    )
    .expect("the path makes the reference resolve");
}

/// A foreign key the schema does not satisfy is refused. Downstream inference resolves
/// referenced tables eagerly, so an orphan reference has to stop at the parse.
#[test]
fn a_foreign_key_the_schema_does_not_satisfy_is_refused() {
    for (what, sql) in [
        (
            "absent table",
            "CREATE TABLE tasks(id INT, project_id INT REFERENCES projects(id));",
        ),
        (
            "absent column",
            "CREATE TABLE projects(id INT PRIMARY KEY);\
             CREATE TABLE tasks(id INT, ghost INT REFERENCES projects(ghost));",
        ),
        (
            "column under no unique constraint",
            "CREATE TABLE projects(id INT PRIMARY KEY, code INT);\
             CREATE TABLE tasks(id INT, code INT REFERENCES projects(code));",
        ),
    ] {
        assert!(
            parse_schema(sql).is_err(),
            "a foreign key naming a {what} must refuse the schema"
        );
    }
}

/// The constraint spellings `pg_dump -s` emits: keys and foreign keys arrive
/// through `ALTER TABLE ONLY ... ADD CONSTRAINT` after every `CREATE TABLE`,
/// with the keyed columns `NOT NULL` inline, and inheritance children present.
/// `sql-traits` `57555a1` grants the `ONLY` per constraint kind, so a dumped
/// schema's keys resolve instead of refusing the whole input.
#[test]
fn the_dumped_constraint_spelling_parses_and_translates() {
    let db = parse_schema(
        r"
CREATE TABLE docs (id UUID NOT NULL, owner TEXT);
CREATE TABLE doc_members (id UUID NOT NULL, doc_id UUID, user_id TEXT);
CREATE TABLE archived_docs (stale BOOLEAN) INHERITS (docs);
ALTER TABLE ONLY docs ADD CONSTRAINT docs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY doc_members ADD CONSTRAINT doc_members_pkey PRIMARY KEY (id);
ALTER TABLE ONLY doc_members ADD CONSTRAINT doc_members_doc_id_fkey FOREIGN KEY (doc_id) REFERENCES docs(id);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT
  USING (EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    )
    .expect("the dumped constraint spelling should parse and apply");
    let translation = rls2fga::translator::TranslatorBuilder::new()
        .with_min_confidence(rls2fga::types::ConfidenceLevel::B)
        .build()
        .translate(&db)
        .expect("translation should plan");
    let dsl = translation.outputs_accepting_gaps().model();
    assert!(
        dsl.contains("type docs"),
        "the dumped keys should resolve and the membership translate:\n{dsl}"
    );
}

/// The same `ONLY` primary key over a column the inheriting child leaves
/// nullable is a key `PostgreSQL` would let child rows escape, so the schema
/// refuses rather than keying objects on a column that may be NULL below.
#[test]
fn an_only_primary_key_on_a_nullable_inherited_column_refuses() {
    let refused = parse_schema(
        r"
CREATE TABLE docs (id UUID, owner TEXT);
CREATE TABLE archived_docs (stale BOOLEAN) INHERITS (docs);
ALTER TABLE ONLY docs ADD CONSTRAINT docs_pkey PRIMARY KEY (id);
",
    );
    assert!(
        refused.is_err_and(|error| error.to_string().contains("id")),
        "a nullable keyed column below the ONLY must refuse the schema"
    );
}
