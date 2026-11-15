//! A clause keeping the rows a declared helper does not return subtracts the helper's set
//! with `but not`, from every command relation a restrictive policy covers.

use rls2fga::classifier::patterns::{ClassifiedExpr, PatternClass, UnclassifiedExpr};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;

use crate::support::deployment::{caller, deployment};
use crate::support::footgun::{db_of, relation_definition, relation_definitions};

/// Organizations blocking principals, the projects those blocks reach, and the documents
/// of each project.
pub(crate) const BLOCKS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (id TEXT PRIMARY KEY);
CREATE TABLE projects (id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id), owner_id TEXT NOT NULL,
  label TEXT);
CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects (id),
  author_id TEXT NOT NULL, title TEXT);
CREATE TABLE organization_blocks (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  principal_id TEXT NOT NULL,
  PRIMARY KEY (organization_id, principal_id)
);
GRANT SELECT ON projects, organization_blocks TO authz_owner;
CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT b.organization_id FROM public.organization_blocks b
  WHERE b.principal_id = current_setting('app.user_id', true)
$$;
CREATE FUNCTION authz.blocked_projects() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.id FROM public.projects p
  WHERE p.organization_id IN (SELECT authz.blocking_organizations())
$$;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.blocked_projects() OWNER TO authz_owner;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_owner ON projects FOR ALL
  USING (owner_id = current_setting('app.user_id', true))
  WITH CHECK (owner_id = current_setting('app.user_id', true));
";

/// The projects' owners, kept only outside the blocked projects, the policy the request
/// reports refused.
pub(crate) const PROJECTS_UNBLOCKED: &str = "
CREATE POLICY projects_unblocked ON projects AS RESTRICTIVE FOR ALL
  USING (id <> ALL (ARRAY(SELECT authz.blocked_projects())))
  WITH CHECK (id <> ALL (ARRAY(SELECT authz.blocked_projects())));
";

/// The documents' authors, kept only outside the blocked projects through the
/// document's project.
pub(crate) const DOCS_UNBLOCKED: &str = "
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_author ON docs FOR SELECT
  USING (author_id = current_setting('app.user_id', true));
CREATE POLICY docs_unblocked ON docs AS RESTRICTIVE FOR SELECT
  USING (NOT (project_id = ANY (ARRAY(SELECT authz.blocked_projects()))));
";

/// Both helpers the blocks read.
const HELPERS: &[&str] = &["authz.blocked_projects", "authz.blocking_organizations"];

fn translator(helpers: &[&str]) -> Translator {
    TranslatorBuilder::new(deployment([caller("app.user_id")]))
        .with_min_confidence(ConfidenceLevel::B)
        .with_declared_helpers(helpers)
        .build()
}

/// The schema with one restrictive `SELECT` policy on `projects` keeping the rows
/// `using` holds.
fn restricted(using: &str) -> String {
    format!(
        "{BLOCKS}
         CREATE POLICY projects_unblocked ON projects AS RESTRICTIVE FOR SELECT
           USING ({using});"
    )
}

fn model(sql: &str) -> String {
    translator(HELPERS)
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .model()
        .clone()
}

fn using_of(sql: &str, helpers: &[&str], policy: &str) -> ClassifiedExpr {
    translator(helpers)
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
fn a_restrictive_negated_helper_subtracts_its_set() {
    let dsl = model(&restricted(
        "NOT (id = ANY (ARRAY(SELECT authz.blocked_projects())))",
    ));
    assert_eq!(
        relation_definition(&dsl, "projects", "can_select").as_deref(),
        Some("(owner but not blocked_projects) and acting_app_user from request_gate"),
        "{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "projects", "blocked_projects").as_deref(),
        Some("blocking_organizations from organizations"),
        "{dsl}"
    );
}

#[test]
fn every_spelling_of_set_exclusion_reads_alike() {
    let written = model(&restricted(
        "NOT (id = ANY (ARRAY(SELECT authz.blocked_projects())))",
    ));
    for spelling in [
        "NOT (id = ANY (SELECT authz.blocked_projects()))",
        "NOT (projects.id IN (SELECT authz.blocked_projects()))",
        "id NOT IN (SELECT authz.blocked_projects())",
        "id <> ALL (ARRAY(SELECT authz.blocked_projects()))",
        "(id <> ALL (SELECT authz.blocked_projects()))",
    ] {
        assert_eq!(model(&restricted(spelling)), written, "`{spelling}`");
    }
}

#[test]
fn a_restrictive_policy_subtracts_from_every_command_it_covers() {
    let dsl = model(&format!("{BLOCKS}{PROJECTS_UNBLOCKED}"));
    let definitions = relation_definitions(&dsl, "projects");
    for relation in [
        "can_select",
        "can_insert",
        "can_update_without_reading",
        "can_delete",
    ] {
        let (_, definition) = definitions
            .iter()
            .find(|(name, _)| name == relation)
            .unwrap_or_else(|| panic!("{relation} should be defined: {dsl}"));
        assert!(
            definition.contains("owner but not blocked_projects"),
            "{relation}: {definition}"
        );
    }
}

#[test]
fn a_compared_foreign_key_subtracts_through_its_bridge() {
    let dsl = model(&format!("{BLOCKS}{DOCS_UNBLOCKED}"));
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some(
            "(author but not blocked_projects from projects) \
             and acting_app_user from request_gate"
        ),
        "{dsl}"
    );
}

#[test]
fn a_permissive_grant_minus_a_negated_helper_subtracts_its_set() {
    let dsl = model(&format!(
        "{BLOCKS}
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_read ON docs FOR SELECT USING (
           author_id = current_setting('app.user_id', true)
           AND NOT (project_id = ANY (ARRAY(SELECT authz.blocked_projects()))));"
    ));
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some(
            "(author but not blocked_projects from projects) \
             and acting_app_user from request_gate"
        ),
        "{dsl}"
    );
}

/// A row holding `NULL` in the compared column is hidden from exactly the callers whose
/// set is not empty, which no tuple can say.
#[test]
fn a_nullable_compared_column_is_refused() {
    let sql = format!(
        "{BLOCKS}
         CREATE TABLE notes (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects (id),
           author_id TEXT NOT NULL);
         ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY notes_author ON notes FOR SELECT
           USING (author_id = current_setting('app.user_id', true));
         CREATE POLICY notes_unblocked ON notes AS RESTRICTIVE FOR SELECT
           USING (NOT (project_id = ANY (ARRAY(SELECT authz.blocked_projects()))));"
    );
    let reason = refusal_of(&sql, HELPERS, "notes_unblocked");
    assert!(
        reason.contains("'notes.project_id'") && reason.contains("provably non-null"),
        "{reason}"
    );
}

/// A `NULL` in the set makes `x <> ALL` unknown for every `x` outside it, which hides the
/// row, while a `NULL` loads no tuple and so hides nothing.
#[test]
fn a_helper_returning_a_nullable_column_is_refused() {
    let sql = format!(
        "{BLOCKS}
         CREATE TABLE project_blocks (project_id TEXT REFERENCES projects (id),
           principal_id TEXT NOT NULL);
         GRANT SELECT ON project_blocks TO authz_owner;
         CREATE FUNCTION authz.directly_blocked() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT b.project_id FROM public.project_blocks b
           WHERE b.principal_id = current_setting('app.user_id', true)
         $$;
         ALTER FUNCTION authz.directly_blocked() OWNER TO authz_owner;
         CREATE POLICY projects_unblocked ON projects AS RESTRICTIVE FOR SELECT
           USING (id NOT IN (SELECT authz.directly_blocked()));"
    );
    let reason = refusal_of(&sql, &["authz.directly_blocked"], "projects_unblocked");
    assert!(
        reason.contains("project_blocks.project_id") && reason.contains("provably non-null"),
        "{reason}"
    );
}

/// The refusal names why the helper does not translate rather than refusing negation.
#[test]
fn an_untranslatable_helper_keeps_its_own_reason() {
    let reason = refusal_of(
        &restricted("NOT (id = ANY (ARRAY(SELECT authz.blocked_projects())))"),
        &["authz.blocked_projects"],
        "projects_unblocked",
    );
    assert!(
        reason.contains("'authz.blocking_organizations' is not declared"),
        "{reason}"
    );
}
