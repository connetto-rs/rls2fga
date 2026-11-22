//! A clause keeping the rows a declared helper does not return subtracts the helper's set
//! with `but not`, from every command relation a restrictive policy covers.

use rls2fga::types::ConfidenceLevel;

use crate::declared_helper_tests::{refusal_of, translator};
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
    crate::declared_helper_tests::model(sql, HELPERS)
}

/// The report names each blocklist by the helper call it subtracts, after the grant it
/// subtracts from where the clause holds one.
#[test]
fn the_report_names_the_excluded_helper_call() {
    let report = translator(ConfidenceLevel::B, HELPERS)
        .translate(&db_of(&format!(
            "{BLOCKS}{PROJECTS_UNBLOCKED}
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_read ON docs FOR SELECT USING (
               author_id = current_setting('app.user_id', true)
               AND NOT (project_id = ANY (ARRAY(SELECT authz.blocked_projects()))));"
        )))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .report();
    for named in [
        "restrictive blocklist id in authz.blocked_projects()",
        "P3 (author_id = user) but not project_id in authz.blocked_projects()",
    ] {
        assert!(report.contains(named), "{named}: {report}");
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

/// A walk down an edge table keyed on the child returns that `NOT NULL` key, so a
/// blocklist through it subtracts every folder below a blocked one.
#[test]
fn a_blocklist_walking_down_an_edge_table_subtracts_every_row_below() {
    let sql = format!(
        "{BLOCKS}
         CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL);
         CREATE TABLE folder_parents (folder_id TEXT PRIMARY KEY REFERENCES folders (id),
           parent_id TEXT NOT NULL REFERENCES folders (id));
         CREATE TABLE folder_blocks (folder_id TEXT NOT NULL REFERENCES folders (id),
           principal_id TEXT NOT NULL, PRIMARY KEY (folder_id, principal_id));
         GRANT SELECT ON folder_parents, folder_blocks TO authz_owner;
         CREATE FUNCTION authz.blocked_folders() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           WITH RECURSIVE reached (id) AS (
             SELECT b.folder_id FROM public.folder_blocks b
             WHERE b.principal_id = current_setting('app.user_id', true)
             UNION
             SELECT fp.folder_id FROM public.folder_parents fp JOIN reached ON fp.parent_id = reached.id
           )
           SELECT id FROM reached
         $$;
         ALTER FUNCTION authz.blocked_folders() OWNER TO authz_owner;
         ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
         CREATE POLICY folders_owner ON folders FOR SELECT
           USING (owner_id = current_setting('app.user_id', true));
         CREATE POLICY folders_unblocked ON folders AS RESTRICTIVE FOR SELECT
           USING (id NOT IN (SELECT authz.blocked_folders()));"
    );
    let dsl = crate::declared_helper_tests::model(&sql, &["authz.blocked_folders"]);
    assert_eq!(
        relation_definition(&dsl, "folders", "can_select").as_deref(),
        Some("(owner but not blocked_folders) and acting_app_user from request_gate"),
        "{dsl}"
    );
    assert!(
        relation_definition(&dsl, "folders", "blocked_folders")
            .is_some_and(|rule| rule.ends_with(" or blocked_folders from folders")),
        "{dsl}"
    );
}

/// A parent arm through an edge table returns the edge table's child column, which a
/// `UNIQUE` constraint lets hold `NULL`, so the column has to be proven `NOT NULL`.
#[test]
fn an_edge_table_returning_a_nullable_child_is_refused() {
    let sql = format!(
        "{BLOCKS}
         CREATE TABLE project_marks (id TEXT PRIMARY KEY,
           project_id TEXT UNIQUE REFERENCES projects (id),
           organization_id TEXT NOT NULL REFERENCES organizations (id));
         GRANT SELECT ON project_marks TO authz_owner;
         CREATE FUNCTION authz.marked_projects() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT m.project_id FROM public.project_marks m
           WHERE m.organization_id IN (SELECT authz.blocking_organizations())
         $$;
         ALTER FUNCTION authz.marked_projects() OWNER TO authz_owner;
         CREATE POLICY projects_unblocked ON projects AS RESTRICTIVE FOR SELECT
           USING (id NOT IN (SELECT authz.marked_projects()));"
    );
    let reason = refusal_of(
        &sql,
        &["authz.blocking_organizations", "authz.marked_projects"],
        "projects_unblocked",
    );
    assert!(
        reason.contains("project_marks.project_id") && reason.contains("provably non-null"),
        "{reason}"
    );
}

/// [`BLOCKS`] with units under one another, each owner reading their own, outside the
/// units `authz.blocked_units` returns through `last`, its walk going up from the units
/// blocking the caller.
pub(crate) fn blocked_units(last: &str) -> String {
    format!(
        "{BLOCKS}
         CREATE TABLE units (id TEXT PRIMARY KEY, parent_id TEXT REFERENCES units (id),
           owner_id TEXT NOT NULL, kind TEXT NOT NULL);
         CREATE TABLE unit_blocks (unit_id TEXT NOT NULL REFERENCES units (id),
           principal_id TEXT NOT NULL, PRIMARY KEY (unit_id, principal_id));
         GRANT SELECT ON units, unit_blocks TO authz_owner;
         CREATE FUNCTION authz.blocked_units() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           WITH RECURSIVE reached (id) AS (
             SELECT b.unit_id FROM public.unit_blocks b
             WHERE b.principal_id = current_setting('app.user_id', true)
             UNION
             SELECT u.parent_id FROM public.units u JOIN reached ON u.id = reached.id
           )
           {last}
         $$;
         ALTER FUNCTION authz.blocked_units() OWNER TO authz_owner;
         ALTER TABLE units ENABLE ROW LEVEL SECURITY;
         CREATE POLICY units_owner ON units FOR SELECT
           USING (owner_id = current_setting('app.user_id', true));
         CREATE POLICY units_unblocked ON units AS RESTRICTIVE FOR SELECT
           USING (id NOT IN (SELECT authz.blocked_units()));"
    )
}

/// A walk's final query returning the teams and projects it reached by their key.
pub(crate) const UNITS_RESELECTED: &str = "SELECT u.id FROM public.units u \
    WHERE u.id IN (SELECT id FROM reached) AND u.kind IN ('team', 'project')";

/// A walk up adds the parent column of every row it reaches, the `NULL` of a root
/// included, so the parent column has to be proven `NOT NULL`.
#[test]
fn a_walk_up_to_a_nullable_parent_is_refused() {
    let sql = blocked_units("SELECT id FROM reached");
    let reason = refusal_of(&sql, &["authz.blocked_units"], "units_unblocked");
    assert!(
        reason.contains("units.parent_id") && reason.contains("provably non-null"),
        "{reason}"
    );
}

/// A final query reselecting the units a walk up reached returns their keys, never the
/// `NULL` above a root, so the units it returns are subtracted.
#[test]
fn a_walk_up_reselecting_its_units_by_key_subtracts_them() {
    let dsl = crate::declared_helper_tests::model(
        &blocked_units(UNITS_RESELECTED),
        &["authz.blocked_units"],
    );
    assert_eq!(
        relation_definition(&dsl, "units", "can_select").as_deref(),
        Some("(owner but not blocked_units) and acting_app_user from request_gate"),
        "{dsl}"
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
        reason.contains("calls 'authz.blocking_organizations', which is not declared"),
        "{reason}"
    );
}

/// Marks a principal puts on projects, of the kinds the `CHECK` lists, and the helper
/// returning the projects the caller marked with one kind.
const MARKS: &str = "
CREATE TABLE project_marks (project_id TEXT NOT NULL REFERENCES projects (id),
  principal_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('block', 'mute')),
  PRIMARY KEY (project_id, principal_id, kind));
GRANT SELECT ON project_marks TO authz_owner;
CREATE FUNCTION authz.marked_projects(k TEXT) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT m.project_id FROM public.project_marks m
  WHERE m.principal_id = current_setting('app.user_id', true) AND m.kind = k
$$;
ALTER FUNCTION authz.marked_projects(TEXT) OWNER TO authz_owner;
";

/// The model of the blocks and marks with `policies` added.
fn marked_model(policies: &str) -> String {
    crate::declared_helper_tests::model(
        &format!("{BLOCKS}{MARKS}{policies}"),
        &[
            "authz.blocked_projects",
            "authz.blocking_organizations",
            "authz.marked_projects",
        ],
    )
}

/// `NOT (x = ANY ('{}'))` holds for every `x`, so a call returning no row, here a kind
/// the `CHECK` never admits, takes nothing away from the grant it is subtracted from.
#[test]
fn a_permissive_grant_minus_a_set_returning_no_row_keeps_the_grant() {
    let docs = |using: &str| {
        let dsl = marked_model(&format!(
            "ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_read ON docs FOR SELECT USING ({using});"
        ));
        relation_definition(&dsl, "docs", "can_select")
    };
    let authored = docs("author_id = current_setting('app.user_id', true)");
    for exclusion in [
        "NOT (project_id = ANY (ARRAY(SELECT authz.marked_projects('ban'))))",
        "project_id <> ALL (ARRAY(SELECT authz.marked_projects('ban')))",
    ] {
        assert_eq!(
            docs(&format!(
                "author_id = current_setting('app.user_id', true) AND {exclusion}"
            )),
            authored,
            "`{exclusion}`"
        );
    }
}

/// A restrictive policy subtracting a set no row is in keeps every row the permissive
/// policies grant.
#[test]
fn a_restrictive_set_returning_no_row_keeps_every_granted_row() {
    let projects =
        |policies: &str| relation_definition(&marked_model(policies), "projects", "can_select");
    assert_eq!(
        projects(
            "CREATE POLICY projects_unmarked ON projects AS RESTRICTIVE FOR SELECT
               USING (NOT (id = ANY (ARRAY(SELECT authz.marked_projects('ban')))));"
        ),
        projects(""),
    );
}
