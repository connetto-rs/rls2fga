//! A clause keeping the rows a declared helper does not return subtracts the helper's set
//! with `but not`, from every command relation a restrictive policy covers.

use rls2fga::types::ConfidenceLevel;

use crate::declared_helper_tests::{refusal_of, translator, using_of};
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

/// A blocklist beside other arms of an `OR` takes away only the blocked rows none of those
/// arms holds, since the clause keeps every row one of them holds.
#[test]
fn a_restrictive_blocklist_beside_other_arms_spares_their_rows() {
    let sql = restricted(
        "NOT (id = ANY (ARRAY(SELECT authz.blocked_projects())))
           OR owner_id = current_setting('app.user_id', true)
           OR owner_id = current_setting('app.tenant', true)",
    );
    assert_eq!(
        using_of(&sql, HELPERS, "projects_unblocked").confidence,
        ConfidenceLevel::A
    );
    let dsl = model(&sql);
    assert_eq!(
        relation_definition(&dsl, "projects", "can_select").as_deref(),
        Some(
            "(owner but not (blocked_projects but not (owner or gate_projects_unblocked_469c5685))) \
             and acting_app_user from request_gate"
        ),
        "{dsl}"
    );
}

/// Outside a restrictive policy no grant is beside the blocklist to subtract it from.
#[test]
fn a_permissive_blocklist_beside_other_arms_is_refused() {
    let sql = format!(
        "{BLOCKS}
         CREATE POLICY projects_unblocked ON projects FOR SELECT
           USING (NOT (id = ANY (ARRAY(SELECT authz.blocked_projects())))
             OR owner_id = current_setting('app.tenant', true));"
    );
    assert_eq!(
        using_of(&sql, HELPERS, "projects_unblocked").confidence,
        ConfidenceLevel::D
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

/// An `OR` keeps every row once one of its blocklist arms subtracts a set no row is in.
#[test]
fn a_restrictive_or_with_a_blocklist_returning_no_row_keeps_every_granted_row() {
    let projects =
        |policies: &str| relation_definition(&marked_model(policies), "projects", "can_select");
    assert_eq!(
        projects(
            "CREATE POLICY projects_unmarked ON projects AS RESTRICTIVE FOR SELECT
               USING (NOT (id = ANY (ARRAY(SELECT authz.marked_projects('ban'))))
                 OR owner_id = current_setting('app.tenant', true));"
        ),
        projects(""),
    );
}

/// An `OR` of blocklists alone takes away only the rows every one of them blocks.
#[test]
fn a_restrictive_or_of_blocklists_subtracts_their_intersection() {
    let dsl = marked_model(
        "CREATE POLICY projects_unmarked ON projects AS RESTRICTIVE FOR SELECT
           USING (NOT (id = ANY (ARRAY(SELECT authz.blocked_projects())))
             OR NOT (id = ANY (ARRAY(SELECT authz.marked_projects('mute')))));",
    );
    assert_eq!(
        relation_definition(&dsl, "projects", "can_select").as_deref(),
        Some(
            "(owner but not (blocked_projects and marked_projects_mute)) \
             and acting_app_user from request_gate"
        ),
        "{dsl}"
    );
}

pub(crate) const PAIR_BLOCKS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (namespace_id TEXT NOT NULL, id TEXT NOT NULL,
  PRIMARY KEY (namespace_id, id));
CREATE TABLE memberships (
  organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY (organization_namespace_id, organization_id, user_id),
  FOREIGN KEY (organization_namespace_id, organization_id)
    REFERENCES organizations (namespace_id, id)
);
CREATE TABLE organization_blocks (
  organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  PRIMARY KEY (organization_namespace_id, organization_id, principal_id),
  FOREIGN KEY (organization_namespace_id, organization_id)
    REFERENCES organizations (namespace_id, id)
);
GRANT SELECT ON organization_blocks TO authz_owner;
CREATE FUNCTION authz.blocking_organizations() RETURNS TABLE (namespace_id TEXT, id TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT b.organization_namespace_id, b.organization_id FROM public.organization_blocks b
  WHERE b.principal_id = current_setting('app.user_id', true)
$$;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY memberships_own ON memberships FOR ALL
  USING (user_id = current_setting('app.user_id', true))
  WITH CHECK (user_id = current_setting('app.user_id', true));
";

pub(crate) const PAIR_BLOCK_HELPERS: &[&str] = &["authz.blocking_organizations"];

/// [`PAIR_BLOCKS`] with a restrictive policy on `memberships` keeping the rows `using`
/// holds.
pub(crate) fn pair_restricted(using: &str) -> String {
    format!(
        "{PAIR_BLOCKS}
         CREATE POLICY memberships_unblocked ON memberships AS RESTRICTIVE FOR ALL
           USING ({using}) WITH CHECK ({using});"
    )
}

pub(crate) const PAIR_EXCLUDED: &str = "NOT ((organization_namespace_id, organization_id) \
     IN (SELECT * FROM authz.blocking_organizations()))";

/// A row whose columns name a pair the helper returns is taken away from every command the
/// restrictive policy covers, and the report names the pair.
#[test]
fn a_restrictive_pair_exclusion_subtracts_the_helpers_pairs() {
    let sql = pair_restricted(PAIR_EXCLUDED);
    assert_eq!(
        using_of(&sql, PAIR_BLOCK_HELPERS, "memberships_unblocked").confidence,
        ConfidenceLevel::A
    );
    let outputs = translator(ConfidenceLevel::B, PAIR_BLOCK_HELPERS)
        .translate(&db_of(&sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let dsl = outputs.model();
    let definitions = relation_definitions(&dsl, "memberships");
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
            definition.contains("user but not blocking_organizations from "),
            "{relation}: {definition}"
        );
    }
    let report = outputs.report();
    let named = "restrictive blocklist (organization_namespace_id, organization_id) in \
                 authz.blocking_organizations()";
    assert!(report.contains(named), "{named}: {report}");
}

#[test]
fn every_spelling_of_pair_exclusion_reads_alike() {
    let written = model_of_pairs(&pair_restricted(PAIR_EXCLUDED));
    for spelling in [
        "NOT ((organization_namespace_id, organization_id) \
         = ANY (SELECT * FROM authz.blocking_organizations()))",
        "(memberships.organization_namespace_id, memberships.organization_id) \
         NOT IN (SELECT * FROM authz.blocking_organizations())",
        "(organization_namespace_id, organization_id) \
         <> ALL (SELECT b.namespace_id, b.id FROM authz.blocking_organizations() b)",
    ] {
        assert_eq!(
            model_of_pairs(&pair_restricted(spelling)),
            written,
            "`{spelling}`"
        );
    }
}

/// A permissive grant beside a pair exclusion keeps the granted rows outside the pairs.
#[test]
fn a_permissive_grant_minus_a_pair_exclusion_subtracts_its_pairs() {
    let dsl = model_of_pairs(&PAIR_BLOCKS.replace(
        "USING (user_id = current_setting('app.user_id', true))",
        &format!("USING (user_id = current_setting('app.user_id', true) AND {PAIR_EXCLUDED})"),
    ));
    let selected = relation_definition(&dsl, "memberships", "can_select")
        .unwrap_or_else(|| panic!("memberships defines can_select: {dsl}"));
    assert!(
        selected.starts_with("(user but not blocking_organizations from "),
        "{selected}"
    );
}

/// A column of the compared row or of the pairs the helper returns that may hold `NULL`
/// leaves the comparison `NULL`, which hides the row where no tuple names it.
#[test]
fn a_pair_exclusion_with_a_nullable_side_is_refused() {
    for (sql, column) in [
        (
            pair_restricted(PAIR_EXCLUDED).replace(
                "  organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,\n  \
                 user_id TEXT NOT NULL,\n  PRIMARY KEY (organization_namespace_id, \
                 organization_id, user_id),",
                "  organization_namespace_id TEXT NOT NULL, organization_id TEXT,\n  \
                 user_id TEXT NOT NULL,",
            ),
            "'memberships.organization_id'",
        ),
        (
            pair_restricted(PAIR_EXCLUDED).replace(
                "  organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,\n  \
                 principal_id TEXT NOT NULL,\n  PRIMARY KEY (organization_namespace_id, \
                 organization_id, principal_id),",
                "  organization_namespace_id TEXT, organization_id TEXT NOT NULL,\n  \
                 principal_id TEXT NOT NULL,",
            ),
            "organization_blocks.organization_namespace_id",
        ),
    ] {
        let reason = refusal_of(&sql, PAIR_BLOCK_HELPERS, "memberships_unblocked");
        assert!(
            reason.contains(column) && reason.contains("provably non-null"),
            "{column}: {reason}"
        );
    }
}

/// `NOT ((x, y) IN (<no row>))` holds for every row, so a call returning no row, here a
/// reason the `CHECK` never admits, takes nothing away from the grant.
#[test]
fn a_pair_exclusion_returning_no_row_keeps_every_granted_row() {
    let reasoned = reasoned_blocks(&pair_restricted(
        "NOT ((organization_namespace_id, organization_id) \
         IN (SELECT * FROM authz.blocking_organizations('ban')))",
    ));
    assert_eq!(
        relation_definition(&model_of_pairs(&reasoned), "memberships", "can_select"),
        relation_definition(&model_of_pairs(PAIR_BLOCKS), "memberships", "can_select"),
    );
}

/// The exclusion every arm of [`arm_pair_blocks`] writes on its row `m` or `n`.
pub(crate) const ARM_PAIR_EXCLUDED: &str = "NOT (({row}.organization_namespace_id, \
     {row}.organization_id) IN (SELECT * FROM authz.blocking_organizations()))";

/// [`PAIR_BLOCKS`] with notes on each organization, which its members read through the
/// pairs `authz.member_organizations()` returns and their authors through the notes
/// `authz.authored_notes()` returns, each arm keeping only the rows `excluded` holds for
/// with `{row}` naming the arm's row, every row where `excluded` is empty.
pub(crate) fn arm_pair_blocks(excluded: &str) -> String {
    let kept = |row: &str| {
        if excluded.is_empty() {
            String::new()
        } else {
            format!(" AND {}", excluded.replace("{row}", row))
        }
    };
    let (member, note) = (kept("m"), kept("n"));
    format!(
        "{PAIR_BLOCKS}
         GRANT SELECT ON memberships TO authz_owner;
         CREATE TABLE organization_notes (id TEXT PRIMARY KEY,
           organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,
           author_id TEXT NOT NULL,
           FOREIGN KEY (organization_namespace_id, organization_id)
             REFERENCES organizations (namespace_id, id));
         GRANT SELECT ON organization_notes TO authz_owner;
         CREATE FUNCTION authz.member_organizations()
         RETURNS TABLE (namespace_id TEXT, id TEXT)
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT m.organization_namespace_id, m.organization_id FROM public.memberships m
           WHERE m.user_id = current_setting('app.user_id', true){member}
         $$;
         CREATE FUNCTION authz.authored_notes() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT n.id FROM public.organization_notes n
           WHERE n.author_id = current_setting('app.user_id', true){note}
         $$;
         ALTER FUNCTION authz.member_organizations() OWNER TO authz_owner;
         ALTER FUNCTION authz.authored_notes() OWNER TO authz_owner;
         ALTER TABLE organization_notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY organization_notes_members ON organization_notes FOR SELECT
           USING ((organization_namespace_id, organization_id)
             IN (SELECT * FROM authz.member_organizations()));
         CREATE POLICY organization_notes_authors ON organization_notes FOR SELECT
           USING (id IN (SELECT authz.authored_notes()));"
    )
}

pub(crate) const ARM_PAIR_HELPERS: &[&str] = &[
    "authz.blocking_organizations",
    "authz.member_organizations",
    "authz.authored_notes",
];

fn model_of_arm_pairs(sql: &str) -> String {
    crate::declared_helper_tests::model(sql, ARM_PAIR_HELPERS)
}

/// An arm keeping only the rows whose pair another helper does not return subtracts those
/// pairs, from the pairs a helper returns and from the rows of a level alike, in every
/// spelling.
#[test]
fn a_pair_exclusion_in_a_helper_arm_subtracts_the_helpers_pairs() {
    let sql = arm_pair_blocks(ARM_PAIR_EXCLUDED);
    for policy in ["organization_notes_members", "organization_notes_authors"] {
        let read = using_of(&sql, ARM_PAIR_HELPERS, policy);
        assert_eq!(read.confidence, ConfidenceLevel::A, "{policy}: {read:?}");
    }
    let dsl = model_of_arm_pairs(&sql);
    assert_eq!(
        dsl.matches("but not blocking_organizations from ").count(),
        2,
        "{dsl}"
    );
    for spelling in [
        "({row}.organization_namespace_id, {row}.organization_id) \
         NOT IN (SELECT * FROM authz.blocking_organizations())",
        "({row}.organization_namespace_id, {row}.organization_id) \
         <> ALL (SELECT * FROM authz.blocking_organizations())",
    ] {
        assert_eq!(
            model_of_arm_pairs(&arm_pair_blocks(spelling)),
            dsl,
            "`{spelling}`"
        );
    }
}

/// A column of the arm's row or of the pairs the helper returns that may hold `NULL`
/// leaves the comparison `NULL`, which drops the row where no tuple names it.
#[test]
fn a_pair_exclusion_in_a_helper_arm_with_a_nullable_side_is_refused() {
    let sql = arm_pair_blocks(ARM_PAIR_EXCLUDED);
    for (sql, column) in [
        (
            sql.replace(
                "organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,\n           \
                 author_id",
                "organization_namespace_id TEXT NOT NULL, organization_id TEXT,\n           \
                 author_id",
            ),
            "'public.organization_notes.organization_id'",
        ),
        (
            sql.replace(
                "  organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,\n  \
                 principal_id TEXT NOT NULL,\n  PRIMARY KEY (organization_namespace_id, \
                 organization_id, principal_id),",
                "  organization_namespace_id TEXT, organization_id TEXT NOT NULL,\n  \
                 principal_id TEXT NOT NULL,",
            ),
            "organization_blocks.organization_namespace_id",
        ),
    ] {
        assert_ne!(sql, arm_pair_blocks(ARM_PAIR_EXCLUDED), "{column} is made nullable");
        let reason = refusal_of(&sql, ARM_PAIR_HELPERS, "organization_notes_authors");
        assert!(
            reason.contains("excludes the set 'authz.blocking_organizations' returns")
                && reason.contains(column)
                && reason.contains("provably non-null"),
            "{column}: {reason}"
        );
    }
}

/// [`PAIR_BLOCKS`] with `authz.blocking_organizations` returning only the blocks given for
/// its argument, a reason the `CHECK` admits only `'spam'` for.
pub(crate) fn reasoned_blocks(sql: &str) -> String {
    sql.replace(
        "  principal_id TEXT NOT NULL,\n",
        "  principal_id TEXT NOT NULL,\n  reason TEXT NOT NULL CHECK (reason IN ('spam')),\n",
    )
    .replace(
        "authz.blocking_organizations() RETURNS",
        "authz.blocking_organizations(r TEXT) RETURNS",
    )
    .replace(
        "WHERE b.principal_id = current_setting('app.user_id', true)",
        "WHERE b.principal_id = current_setting('app.user_id', true) AND b.reason = r",
    )
    .replace(
        "ALTER FUNCTION authz.blocking_organizations()",
        "ALTER FUNCTION authz.blocking_organizations(TEXT)",
    )
}

/// `NOT ((x, y) IN (<no row>))` holds for every row, so an arm's exclusion whose call
/// returns no pair takes nothing away from the notes or the pairs it returns.
#[test]
fn a_pair_exclusion_in_a_helper_arm_returning_no_row_takes_nothing_away() {
    let banned = model_of_arm_pairs(&reasoned_blocks(&arm_pair_blocks(
        &ARM_PAIR_EXCLUDED.replace(
            "authz.blocking_organizations()",
            "authz.blocking_organizations('ban')",
        ),
    )));
    let unexcluded = model_of_arm_pairs(&reasoned_blocks(&arm_pair_blocks("")));
    for type_name in ["organization_notes", "member_organizations_pair"] {
        let definitions = relation_definitions(&unexcluded, type_name);
        assert!(!definitions.is_empty(), "{type_name}: {unexcluded}");
        assert_eq!(
            relation_definitions(&banned, type_name),
            definitions,
            "{type_name}"
        );
    }
}

/// `(x, y) IN (<no row>)` holds for no row, so an arm kept within the pairs of a call
/// returning no pair grants nothing, to the members and to the authors alike.
#[test]
fn a_helper_arm_kept_within_pairs_returning_no_row_grants_nothing() {
    let within = |reason: &str| {
        reasoned_blocks(&arm_pair_blocks(&format!(
            "(({{row}}.organization_namespace_id, {{row}}.organization_id) \
             IN (SELECT * FROM authz.blocking_organizations('{reason}')))"
        )))
    };
    let banned = within("ban");
    for policy in ["organization_notes_members", "organization_notes_authors"] {
        let read = using_of(&banned, ARM_PAIR_HELPERS, policy);
        assert_eq!(read.confidence, ConfidenceLevel::A, "{policy}: {read:?}");
    }
    let selecting = |sql: &str| {
        let dsl = model_of_arm_pairs(sql);
        relation_definition(&dsl, "organization_notes", "can_select")
            .unwrap_or_else(|| panic!("organization_notes is selectable: {dsl}"))
    };
    let granting = ["authored_notes", "member_organizations from "];
    let spam = selecting(&within("spam"));
    assert!(granting.iter().all(|arm| spam.contains(arm)), "{spam}");
    let ban = selecting(&banned);
    assert!(!granting.iter().any(|arm| ban.contains(arm)), "{ban}");
}

/// An arm kept while a note has not expired grants by one rule per way the bound holds, and
/// the pairs it stays outside are taken from all of them.
#[test]
fn a_pair_exclusion_beside_a_time_bound_is_subtracted_from_every_rule() {
    let plain = arm_pair_blocks(ARM_PAIR_EXCLUDED);
    let bounded = plain
        .replace(
            "author_id TEXT NOT NULL,",
            "author_id TEXT NOT NULL, expires_at TIMESTAMPTZ,",
        )
        .replace(
            "WHERE n.author_id = current_setting('app.user_id', true)",
            "WHERE n.author_id = current_setting('app.user_id', true)
               AND (n.expires_at IS NULL OR n.expires_at > now())",
        );
    assert_ne!(bounded, plain, "the bound is written");
    let read = using_of(&bounded, ARM_PAIR_HELPERS, "organization_notes_authors");
    assert_eq!(read.confidence, ConfidenceLevel::A, "{read:?}");
    let dsl = model_of_arm_pairs(&bounded);
    assert!(
        dsl.lines()
            .any(|line| line.contains(" or ")
                && line.contains("but not blocking_organizations from ")),
        "{dsl}"
    );
}

/// [`arm_pair_blocks`] without exclusions, with topics read by the authors of their notes
/// through `authz.noted_topics()`, whose arm keeps only the topic notes outside the pairs
/// `call` returns.
fn noted_topics(call: &str) -> String {
    format!(
        "{}
         CREATE TABLE topics (id TEXT PRIMARY KEY);
         CREATE TABLE topic_notes (topic_id TEXT NOT NULL REFERENCES topics (id),
           note_id TEXT NOT NULL REFERENCES organization_notes (id),
           organization_namespace_id TEXT NOT NULL, organization_id TEXT NOT NULL,
           author_id TEXT NOT NULL, PRIMARY KEY (topic_id, note_id));
         GRANT SELECT ON topic_notes TO authz_owner;
         CREATE FUNCTION authz.noted_topics() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT t.topic_id FROM public.topic_notes t
           WHERE t.author_id = current_setting('app.user_id', true)
             AND {}
         $$;
         ALTER FUNCTION authz.noted_topics() OWNER TO authz_owner;
         ALTER TABLE topics ENABLE ROW LEVEL SECURITY;
         CREATE POLICY topics_noted ON topics FOR SELECT
           USING (id IN (SELECT authz.noted_topics()));",
        arm_pair_blocks(""),
        ARM_PAIR_EXCLUDED
            .replace("{row}", "t")
            .replace("authz.blocking_organizations()", call),
    )
}

/// The definitions of the relations on each topic note held as its own object, once
/// `topics_noted` reads at A.
fn held_topic_notes(sql: &str) -> Vec<(String, String)> {
    let mut helpers = ARM_PAIR_HELPERS.to_vec();
    helpers.push("authz.noted_topics");
    let read = using_of(sql, &helpers, "topics_noted");
    assert_eq!(read.confidence, ConfidenceLevel::A, "{read:?}");
    relation_definitions(
        &crate::declared_helper_tests::model(sql, &helpers),
        "topic_notes",
    )
}

/// An exclusion on columns that name neither the level's row nor the arm's own row alone
/// is read on each row of the arm held as its own object.
#[test]
fn a_pair_exclusion_beside_another_object_is_subtracted_from_each_held_row() {
    let held = held_topic_notes(&noted_topics("authz.blocking_organizations()"));
    assert!(
        held.iter()
            .any(|(_, definition)| definition.contains("but not blocking_organizations from ")),
        "{held:?}"
    );
}

/// A held row's exclusion whose call returns no pair takes nothing away from the row.
#[test]
fn a_held_rows_pair_exclusion_returning_no_row_takes_nothing_away() {
    let held = held_topic_notes(&reasoned_blocks(&noted_topics(
        "authz.blocking_organizations('ban')",
    )));
    assert!(
        !held.is_empty(),
        "each topic note is held as its own object"
    );
    assert!(
        held.iter()
            .all(|(_, definition)| !definition.contains(" but not ")),
        "{held:?}"
    );
}

fn model_of_pairs(sql: &str) -> String {
    crate::declared_helper_tests::model(sql, PAIR_BLOCK_HELPERS)
}
