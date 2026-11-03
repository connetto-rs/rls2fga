//! A column compared with the set a declared `SECURITY DEFINER` helper returns becomes
//! the grants the helper's body reads, `role from parent` through each parent arm.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{
    ClassifiedExpr, GrantRows, HelperSetArm, PatternClass, UnclassifiedExpr,
};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{AttributeLiteral, AttributePredicate, AttributeTest, ConfidenceLevel};
use rls2fga::types::{ColumnName, TranslationNote};

use crate::support::footgun::{db_of, relation_definition};

/// The request's reduced ownership schema, two levels of grants under the orders.
pub(crate) const LEVELS: &str = "
CREATE TABLE teams (id TEXT PRIMARY KEY);
CREATE TABLE projects (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams (id));
CREATE TABLE orders (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id),
  title TEXT);
CREATE TABLE team_grants (team_id TEXT NOT NULL REFERENCES teams (id), principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), PRIMARY KEY (team_id, principal_id));
CREATE TABLE project_grants (project_id TEXT NOT NULL REFERENCES projects (id), principal_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin')), PRIMARY KEY (project_id, principal_id));
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
CREATE FUNCTION authz.teams_with(min_role TEXT) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT g.team_id FROM public.team_grants g
  WHERE g.principal_id = current_setting('app.user_id', true)
    AND (g.role = 'admin' OR min_role = 'read' OR (min_role = 'write' AND g.role = 'write'))
$$;
CREATE FUNCTION authz.projects_with(min_role TEXT) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT g.project_id FROM public.project_grants g
  WHERE g.principal_id = current_setting('app.user_id', true)
    AND (g.role = 'admin' OR min_role = 'read' OR (min_role = 'write' AND g.role = 'write'))
  UNION
  SELECT p.id FROM public.projects p WHERE p.team_id IN (SELECT authz.teams_with(min_role))
$$;
ALTER FUNCTION authz.teams_with(TEXT) OWNER TO authz_owner;
ALTER FUNCTION authz.projects_with(TEXT) OWNER TO authz_owner;
GRANT USAGE ON SCHEMA authz TO authz_owner;
";

/// What the owner reads, without which every call raises `42501`.
pub(crate) const OWNER_READS: &str =
    "GRANT SELECT ON team_grants, project_grants, projects TO authz_owner;";

/// The request's two policies on `orders`.
pub(crate) const ORDERS: &str = "
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_read ON orders FOR SELECT USING (
  project_id = ANY (ARRAY(SELECT authz.projects_with('read'))));
CREATE POLICY orders_update ON orders FOR UPDATE
  USING (project_id = ANY (ARRAY(SELECT authz.projects_with('write'))))
  WITH CHECK (project_id = ANY (ARRAY(SELECT authz.projects_with('write'))));
";

/// Both level helpers declared.
const BOTH: &[&str] = &["authz.projects_with", "authz.teams_with"];

fn translator(min_confidence: ConfidenceLevel, helpers: &[&str]) -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(min_confidence)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .with_declared_helpers(helpers)
        .build()
}

fn model(sql: &str, helpers: &[&str]) -> String {
    translator(ConfidenceLevel::B, helpers)
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .model()
        .clone()
}

/// The `USING` classification of the policy named `policy`.
fn using_of(sql: &str, helpers: &[&str], policy: &str) -> ClassifiedExpr {
    translator(ConfidenceLevel::B, helpers)
        .classify(&db_of(sql))
        .into_iter()
        .find(|classified| classified.name() == policy)
        .unwrap_or_else(|| panic!("{policy} should classify"))
        .using_classification()
        .expect("USING should classify")
        .clone()
}

fn refusal_of(sql: &str, helpers: &[&str], policy: &str) -> String {
    let classified = using_of(sql, helpers, policy);
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
    match classified.pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason,
        other => panic!("{policy} should be refused, got {other:?}"),
    }
}

#[test]
fn the_reduced_schema_reads_each_role_from_its_parent() {
    assert_eq!(
        model(&format!("{LEVELS}{OWNER_READS}{ORDERS}"), BOTH),
        "model
  schema 1.1

type user

type nobody

type orders
  relations
    define no_access: [nobody]
    define projects: [projects]
    define can_delete: no_access
    define can_insert: no_access
    define can_select: projects_with_read from projects
    define can_select_for_update: can_update
    define can_update: projects_with_write from projects and can_select
    define can_update_without_reading: projects_with_write from projects

type projects
  relations
    define admin: [user]
    define read: [user]
    define teams: [teams]
    define write: [user]
    define projects_with_read: read or write or admin or teams_with_read from teams
    define projects_with_write: write or admin or teams_with_write from teams

type teams
  relations
    define admin: [user]
    define read: [user]
    define write: [user]
    define teams_with_read: read or write or admin
    define teams_with_write: write or admin
"
    );
}

/// Every call reads the same role relations, so one grant row is one tuple however many
/// calls admit its role.
#[test]
fn each_grant_row_is_loaded_once() {
    let outputs = translator(ConfidenceLevel::B, BOTH)
        .translate(&db_of(&format!("{LEVELS}{OWNER_READS}{ORDERS}")))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    for table in ["team_grants", "project_grants"] {
        let mut roles: Vec<&str> = outputs
            .tuple_queries()
            .iter()
            .filter(|query| query.sql.contains(&format!("FROM \"public\".\"{table}\"")))
            .map(|query| {
                let (_, role) = query
                    .sql
                    .rsplit_once("\"role\" = ")
                    .expect("each grant query keeps one role");
                role
            })
            .collect();
        roles.sort_unstable();
        assert_eq!(roles, ["'admin');", "'read');", "'write');"], "{table}");
    }
}

#[test]
fn a_policy_on_the_level_itself_reads_the_call_relation() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}
         ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
         CREATE POLICY projects_read ON projects FOR SELECT USING (
           id = ANY (ARRAY(SELECT authz.projects_with('read'))));"
    );
    assert_eq!(
        relation_definition(&model(&sql, BOTH), "projects", "can_select").as_deref(),
        Some("projects_with_read")
    );
}

#[test]
fn every_spelling_of_set_membership_reads_alike() {
    let spelled = |membership: &str| {
        model(
            &format!(
                "{LEVELS}{OWNER_READS}
                 ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY orders_read ON orders FOR SELECT USING ({membership});"
            ),
            BOTH,
        )
    };
    let array = spelled("project_id = ANY (ARRAY(SELECT authz.projects_with('read')))");
    assert_eq!(
        spelled("orders.project_id IN (SELECT authz.projects_with('read'))"),
        array
    );
    assert_eq!(
        spelled("project_id = ANY (SELECT authz.projects_with('read'))"),
        array
    );
}

#[test]
fn an_owner_lacking_select_is_refused_naming_the_table() {
    let sql = format!("{LEVELS}{ORDERS}");
    let notes = translator(ConfidenceLevel::D, BOTH)
        .translate(&db_of(&sql))
        .expect("the schema should plan")
        .outputs_accepting_gaps()
        .notes()
        .to_vec();
    let refused = notes.iter().any(|note| {
        matches!(
            note,
            TranslationNote::ExpressionRefused { policy, reason }
                if policy == "orders_read"
                    && reason.contains("authz.projects_with")
                    && reason.contains("lacks SELECT on `project_grants`")
        )
    });
    assert!(refused, "{notes:#?}");
}

#[test]
fn an_undeclared_definer_helper_stays_refused() {
    let classified = using_of(
        &format!("{LEVELS}{OWNER_READS}{ORDERS}"),
        &[],
        "orders_read",
    );
    assert!(
        matches!(classified.pattern, PatternClass::Unknown(_)),
        "{classified:?}"
    );
    assert_eq!(classified.confidence, ConfidenceLevel::D);
}

#[test]
fn a_parent_arm_reaching_an_undeclared_helper_is_refused_naming_it() {
    let reason = refusal_of(
        &format!("{LEVELS}{OWNER_READS}{ORDERS}"),
        &["authz.projects_with"],
        "orders_read",
    );
    assert!(reason.contains("'authz.teams_with'"), "{reason}");
}

#[test]
fn a_union_of_calls_is_refused() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}
         CREATE FUNCTION authz.owners_with(min_role TEXT) RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT authz.teams_with(min_role) UNION SELECT authz.projects_with(min_role)
         $$;
         ALTER FUNCTION authz.owners_with(TEXT) OWNER TO authz_owner;
         ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
         CREATE POLICY orders_read ON orders FOR SELECT USING (
           project_id = ANY (ARRAY(SELECT authz.owners_with('read'))));"
    );
    let reason = refusal_of(
        &sql,
        &[
            "authz.owners_with",
            "authz.projects_with",
            "authz.teams_with",
        ],
        "orders_read",
    );
    assert!(reason.contains("authz.owners_with"), "{reason}");
}

/// A column the helper returns that names another table's rows than the compared one
/// would grant on a key of the wrong table.
#[test]
fn a_column_naming_other_rows_is_refused() {
    let sql = format!(
        "{LEVELS}{OWNER_READS}
         ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
         CREATE POLICY orders_read ON orders FOR SELECT USING (
           project_id = ANY (ARRAY(SELECT authz.teams_with('read'))));"
    );
    let reason = refusal_of(&sql, BOTH, "orders_read");
    assert!(
        reason.contains("'projects'") && reason.contains("'teams'"),
        "{reason}"
    );
}

/// A role column `NULL` can fill is not closed, so the rows are kept by the body's own
/// condition rather than split into roles.
#[test]
fn a_nullable_role_column_keeps_the_body_condition() {
    let sql = format!("{LEVELS}{OWNER_READS}{ORDERS}").replace(
        "project_grants (project_id TEXT NOT NULL REFERENCES projects (id), principal_id TEXT NOT NULL,
  role TEXT NOT NULL",
        "project_grants (project_id TEXT NOT NULL REFERENCES projects (id), principal_id TEXT NOT NULL,
  role TEXT",
    );
    let PatternClass::P20DeclaredHelper(helper) = using_of(&sql, BOTH, "orders_update").pattern
    else {
        panic!("orders_update should translate");
    };
    let HelperSetArm::Grant(grant) = &helper.call.arms[0] else {
        panic!("the first arm reads the grants");
    };
    assert_eq!(
        grant.rows,
        GrantRows::Matching {
            predicate: Some(AttributePredicate {
                column: ColumnName::from_stored("role"),
                test: AttributeTest::In(vec![
                    AttributeLiteral::Text("admin".into()),
                    AttributeLiteral::Text("write".into()),
                ]),
            }),
        }
    );
}
