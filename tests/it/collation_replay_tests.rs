//! A comparison is decided outside `PostgreSQL` only where `PostgreSQL` compares the column
//! byte for byte, which a nondeterministic collation does not.

use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::{ConfidenceLevel, RecordDerivation};

use crate::support::deployment::{caller_deployment_with, scalar};
use crate::support::footgun::{db_of, relation_definition, translator};

const CASE_INSENSITIVE: &str = "CREATE COLLATION case_insensitive \
     (provider = icu, locale = 'und-u-ks-level2', deterministic = false);";

/// Whether the gate `clause` opens on a `code` column of `column_type` replays from the row.
fn replays_from_row(column_type: &str, clause: &str) -> bool {
    let schema = format!(
        "{CASE_INSENSITIVE}\n\
         CREATE TABLE public.docs(id TEXT PRIMARY KEY, code {column_type});\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING ({clause});\n"
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db_of(&schema))
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let query = outputs
        .tuple_queries()
        .iter()
        .find(|query| query.sql.contains("\"code\""))
        .unwrap_or_else(|| panic!("`{clause}` on {column_type} loads its gate"));
    query.description.as_ref().is_some_and(|description| {
        matches!(description.derivation, RecordDerivation::FromRow { .. })
    })
}

#[test]
fn a_nondeterministic_column_leaves_its_text_guard_to_the_database() {
    for clause in ["code = 'ab'", "code <> 'ab'", "code IN ('ab', 'x')"] {
        assert!(
            !replays_from_row("TEXT COLLATE case_insensitive", clause),
            "`{clause}` compares 'AB' and 'ab' as equal, which the row cannot tell"
        );
    }
}

#[test]
fn a_deterministic_column_still_replays_its_text_guard() {
    for column_type in ["TEXT", "TEXT COLLATE \"C\"", "CHAR(4) COLLATE \"C\""] {
        assert!(
            replays_from_row(column_type, "code <> 'ab'"),
            "{column_type} compares byte for byte"
        );
    }
}

#[test]
fn a_null_test_on_a_nondeterministic_column_still_replays() {
    assert!(replays_from_row(
        "TEXT COLLATE case_insensitive",
        "code IS NOT NULL"
    ));
}

#[test]
fn a_column_naming_its_character_set_leaves_its_text_guard_to_the_database() {
    assert!(!replays_from_row(
        "TEXT CHARACTER SET utf8mb4",
        "code <> 'ab'"
    ));
}

/// The `can_select` relation on `docs` or `projects` and the report, for `schema` read by a
/// caller in `app.user_id` with `app.region` declared as a request value.
fn read_relation_and_report(schema: &str, object_type: &str) -> (Option<String>, String) {
    read_with_registry(schema, object_type, "{}")
}

/// [`read_relation_and_report`] with the functions `registry` declares.
fn read_with_registry(schema: &str, object_type: &str, registry: &str) -> (Option<String>, String) {
    let outputs = TranslatorBuilder::new(caller_deployment_with([scalar("app.region")]))
        .with_registry_json(registry)
        .expect("the registry loads")
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db_of(&format!("{CASE_INSENSITIVE}\n{schema}")))
        .expect("translation should plan")
        .outputs_accepting_gaps();
    (
        relation_definition(&outputs.model(), object_type, "can_select"),
        outputs.report(),
    )
}

/// `PostgreSQL` finds `'ALICE'` equal to a caller sending `alice` on a case-insensitive
/// column, while `OpenFGA` compares the two keys byte for byte. Each grant falls closed and
/// the report names the column and its collation.
#[test]
fn a_key_compared_on_a_nondeterministic_column_falls_closed_naming_its_collation() {
    for (shape, object_type, schema) in [
        (
            "owner",
            "docs",
            "CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT COLLATE case_insensitive);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON docs FOR SELECT
                 USING (owner_id = current_setting('app.user_id', true));",
        ),
        (
            "member",
            "projects",
            "CREATE TABLE projects(id TEXT PRIMARY KEY);
             CREATE TABLE project_members(project_id TEXT REFERENCES projects(id),
                 user_id TEXT COLLATE case_insensitive);
             ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON projects FOR SELECT USING (EXISTS (
                 SELECT 1 FROM project_members m WHERE m.project_id = projects.id
                   AND m.user_id = current_setting('app.user_id', true)));",
        ),
        (
            "membership join",
            "projects",
            "CREATE TABLE projects(id TEXT COLLATE case_insensitive PRIMARY KEY);
             CREATE TABLE project_members(project_id TEXT COLLATE case_insensitive
                 REFERENCES projects(id), user_id TEXT);
             ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON projects FOR SELECT USING (EXISTS (
                 SELECT 1 FROM project_members m WHERE m.project_id = projects.id
                   AND m.user_id = current_setting('app.user_id', true)));",
        ),
        (
            "request value",
            "docs",
            "CREATE TABLE docs(id TEXT PRIMARY KEY, region TEXT COLLATE case_insensitive);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON docs FOR SELECT
                 USING (region = current_setting('app.region', true));",
        ),
    ] {
        let (can_select, report) = read_relation_and_report(schema, object_type);
        assert_eq!(
            can_select.as_deref(),
            Some("no_access"),
            "the {shape} comparison must fall closed:\n{report}"
        );
        assert!(
            report.contains("compares under the collation case_insensitive"),
            "the report must name the {shape} column's collation:\n{report}"
        );
    }
}

/// An object's own key is never compared with the caller, so a case-insensitive key still
/// names the row it was read from.
#[test]
fn a_nondeterministic_object_key_still_translates() {
    let (can_select, report) = read_relation_and_report(
        "CREATE TABLE docs(id TEXT COLLATE case_insensitive PRIMARY KEY, owner_id TEXT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs FOR SELECT
             USING (owner_id = current_setting('app.user_id', true));",
        "docs",
    );
    assert_ne!(can_select.as_deref(), Some("no_access"), "{report}");
}

/// A named collation that compares byte for byte, such as `"C"`, keeps the owner's key the
/// one `OpenFGA` compares, so the grant still translates.
#[test]
fn an_owner_under_a_deterministic_collation_still_translates() {
    let (can_select, report) = read_relation_and_report(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT COLLATE \"C\");
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs FOR SELECT
             USING (owner_id = current_setting('app.user_id', true));",
        "docs",
    );
    assert_ne!(can_select.as_deref(), Some("no_access"), "{report}");
}

/// A character set changes how the owner compares without naming a collation the schema
/// can resolve, so the grant falls closed rather than assume the bytes decide.
#[test]
fn an_owner_under_an_unresolved_collation_falls_closed() {
    let (can_select, report) = read_relation_and_report(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT CHARACTER SET utf8mb4);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs FOR SELECT
             USING (owner_id = current_setting('app.user_id', true));",
        "docs",
    );
    assert_eq!(can_select.as_deref(), Some("no_access"), "{report}");
    assert!(
        report.contains("compares under a collation the schema does not resolve"),
        "{report}"
    );
}

/// A role function's grant rows and team memberships are keys `OpenFGA` matches with the
/// caller and the owner, so a case-insensitive one among them refuses the threshold too.
#[test]
fn a_role_threshold_reading_a_nondeterministic_key_falls_closed_naming_its_collation() {
    const REGISTRY: &str = r#"{"get_role": {
        "kind": "role_threshold", "user_param_index": 0, "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3},
        "grant_table": "owner_grants", "grant_grantee_col": "grantee_id",
        "grant_resource_col": "owner_id", "grant_role_col": "role_id",
        "team_membership": {"table": "team_members", "user_col": "user_id", "team_col": "team_id"}
    }}"#;
    for (shape, grantee, member) in [
        ("grantee", "TEXT COLLATE case_insensitive", "TEXT"),
        ("team member", "TEXT", "TEXT COLLATE case_insensitive"),
    ] {
        let schema = format!(
            "CREATE TABLE users(id TEXT PRIMARY KEY);
             CREATE TABLE teams(id TEXT PRIMARY KEY);
             CREATE TABLE team_members(team_id TEXT NOT NULL REFERENCES teams(id),
                 user_id {member} NOT NULL);
             CREATE TABLE owner_grants(grantee_id {grantee} NOT NULL, owner_id TEXT NOT NULL,
                 role_id INTEGER NOT NULL);
             CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
             CREATE FUNCTION get_role(user_id TEXT, target TEXT) RETURNS INTEGER
                 LANGUAGE sql STABLE AS 'SELECT 0';
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p ON docs FOR SELECT
                 USING (get_role(current_setting('app.user_id', true), owner_id) >= 2);"
        );
        let (can_select, report) = read_with_registry(&schema, "docs", REGISTRY);
        assert_eq!(
            can_select.as_deref(),
            Some("no_access"),
            "a case-insensitive {shape} must refuse the threshold:\n{report}"
        );
        assert!(
            report.contains("compares under the collation case_insensitive"),
            "the report must name the {shape} column's collation:\n{report}"
        );
    }
}
