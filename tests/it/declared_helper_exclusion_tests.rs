//! A declared helper keeping only the rows outside the set another declared helper returns
//! subtracts that set with `but not` from its own relation.

use rls2fga::types::ConfidenceLevel;

use crate::declared_helper_blocklist_tests::BLOCKS;
use crate::declared_helper_tests::{model, refusal_of, using_of};
use crate::support::footgun::relation_definition;

pub(crate) const EXCLUDING: &str = "
GRANT SELECT ON docs TO authz_owner;
CREATE TABLE doc_blocks (doc_id TEXT NOT NULL REFERENCES docs (id),
  principal_id TEXT NOT NULL, PRIMARY KEY (doc_id, principal_id));
GRANT SELECT ON doc_blocks TO authz_owner;
CREATE FUNCTION authz.blocked_docs() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT b.doc_id FROM public.doc_blocks b
  WHERE b.principal_id = current_setting('app.user_id', true)
$$;
CREATE FUNCTION authz.owned_unblocked() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.id FROM public.projects p
  WHERE p.owner_id = current_setting('app.user_id', true)
    AND NOT (p.id = ANY (ARRAY(SELECT authz.blocked_projects())))
$$;
CREATE FUNCTION authz.owned_outside_blocks() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.id FROM public.projects p
  WHERE p.owner_id = current_setting('app.user_id', true)
    AND NOT (p.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))
$$;
CREATE FUNCTION authz.authored_unblocked() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT d.project_id FROM public.docs d
  WHERE d.author_id = current_setting('app.user_id', true)
    AND d.project_id NOT IN (SELECT authz.blocked_projects())
$$;
CREATE FUNCTION authz.authored_unblocked_docs() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT d.project_id FROM public.docs d
  WHERE d.author_id = current_setting('app.user_id', true)
    AND d.id <> ALL (ARRAY(SELECT authz.blocked_docs()))
$$;
ALTER FUNCTION authz.blocked_docs() OWNER TO authz_owner;
ALTER FUNCTION authz.owned_unblocked() OWNER TO authz_owner;
ALTER FUNCTION authz.owned_outside_blocks() OWNER TO authz_owner;
ALTER FUNCTION authz.authored_unblocked() OWNER TO authz_owner;
ALTER FUNCTION authz.authored_unblocked_docs() OWNER TO authz_owner;
";

const HELPERS: &[&str] = &[
    "authz.blocked_projects",
    "authz.blocking_organizations",
    "authz.blocked_docs",
    "authz.owned_unblocked",
    "authz.owned_outside_blocks",
    "authz.authored_unblocked",
    "authz.authored_unblocked_docs",
];

/// The schema with `docs_read` keeping the documents of the projects `helper` returns,
/// `extra` declaring what else the helper reads.
fn reading(extra: &str, helper: &str) -> String {
    format!(
        "{BLOCKS}{EXCLUDING}{extra}
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_read ON docs FOR SELECT
           USING (project_id IN (SELECT {helper}()));"
    )
}

fn projects_relation(helper: &str, relation: &str) -> Option<String> {
    let dsl = model(&reading("", helper), HELPERS);
    relation_definition(&dsl, "projects", relation)
}

#[test]
fn every_policy_calling_an_excluding_helper_grades_a() {
    for helper in [
        "authz.owned_unblocked",
        "authz.owned_outside_blocks",
        "authz.authored_unblocked",
        "authz.authored_unblocked_docs",
    ] {
        let classified = using_of(&reading("", helper), HELPERS, "docs_read");
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::A,
            "{helper}: {classified:?}"
        );
    }
}

#[test]
fn a_set_excluding_the_levels_own_key_is_subtracted_from_it() {
    assert_eq!(
        projects_relation("authz.owned_unblocked", "owned_unblocked").as_deref(),
        Some("projects_outside_blocked_projects")
    );
    let outside = projects_relation("authz.owned_unblocked", "projects_outside_blocked_projects")
        .expect("the arm's relation is defined");
    assert!(outside.ends_with(" but not blocked_projects"), "{outside}");
}

#[test]
fn a_set_excluding_a_foreign_key_of_the_levels_row_is_subtracted_through_its_bridge() {
    let outside = projects_relation(
        "authz.owned_outside_blocks",
        "projects_outside_blocking_organizations",
    )
    .expect("the arm's relation is defined");
    assert!(
        outside.ends_with(" but not blocking_organizations from organizations"),
        "{outside}"
    );
}

#[test]
fn a_set_excluding_the_arms_object_is_subtracted_from_the_level() {
    assert_eq!(
        projects_relation("authz.authored_unblocked", "authored_unblocked").as_deref(),
        Some("docs_outside_blocked_projects")
    );
    let outside = projects_relation("authz.authored_unblocked", "docs_outside_blocked_projects")
        .expect("the arm's relation is defined");
    assert!(outside.ends_with(" but not blocked_projects"), "{outside}");
}

/// A document blocked for the caller takes away only that document, so a project stays
/// returned while another document of it is not blocked, which each document held as its
/// own object says.
#[test]
fn a_set_excluding_another_column_of_the_arm_is_subtracted_from_each_held_row() {
    let dsl = model(&reading("", "authz.authored_unblocked_docs"), HELPERS);
    assert_eq!(
        relation_definition(&dsl, "projects", "authored_unblocked_docs").as_deref(),
        Some("docs_outside_blocked_docs from docs"),
        "{dsl}"
    );
    let held = relation_definition(&dsl, "docs", "docs_outside_blocked_docs")
        .expect("each held document's relation is defined");
    assert!(held.ends_with(" but not blocked_docs"), "{dsl}");
}

const NULLABLE: &str = "
CREATE TABLE tasks (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects (id),
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  assignee_id TEXT NOT NULL);
CREATE TABLE project_flags (project_id TEXT REFERENCES projects (id),
  principal_id TEXT NOT NULL);
GRANT SELECT ON tasks, project_flags TO authz_owner;
CREATE FUNCTION authz.flagged_projects() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT f.project_id FROM public.project_flags f
  WHERE f.principal_id = current_setting('app.user_id', true)
$$;
CREATE FUNCTION authz.owned_unflagged() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.id FROM public.projects p
  WHERE p.owner_id = current_setting('app.user_id', true)
    AND p.id NOT IN (SELECT authz.flagged_projects())
$$;
CREATE FUNCTION authz.assigned_unblocked() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT t.id FROM public.tasks t
  WHERE t.assignee_id = current_setting('app.user_id', true)
    AND NOT (t.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))
    AND NOT (t.project_id = ANY (ARRAY(SELECT authz.blocked_projects())))
$$;
ALTER FUNCTION authz.flagged_projects() OWNER TO authz_owner;
ALTER FUNCTION authz.owned_unflagged() OWNER TO authz_owner;
ALTER FUNCTION authz.assigned_unblocked() OWNER TO authz_owner;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_read ON tasks FOR SELECT
  USING (id IN (SELECT authz.assigned_unblocked()));
";

/// A row holding `NULL` in the compared column is hidden from exactly the callers whose
/// excluded set is not empty, which no tuple can say, so the arm is refused whole although
/// its other exclusion translates.
#[test]
fn a_nullable_compared_column_refuses_the_arm_whole() {
    let mut helpers = HELPERS.to_vec();
    helpers.push("authz.assigned_unblocked");
    let reason = refusal_of(
        &format!("{BLOCKS}{EXCLUDING}{NULLABLE}"),
        &helpers,
        "tasks_read",
    );
    assert!(
        reason.contains("excludes the set 'authz.blocked_projects' returns")
            && reason.contains("'public.tasks.project_id'")
            && reason.contains("provably non-null"),
        "{reason}"
    );
}

/// A `NULL` in the excluded set makes `x <> ALL` unknown for every `x` outside it, which
/// hides the row, while a `NULL` loads no tuple and so hides nothing.
#[test]
fn an_excluded_set_returning_a_nullable_column_is_refused() {
    let mut helpers = HELPERS.to_vec();
    helpers.extend(["authz.flagged_projects", "authz.owned_unflagged"]);
    let reason = refusal_of(
        &reading(NULLABLE, "authz.owned_unflagged"),
        &helpers,
        "docs_read",
    );
    assert!(
        reason.contains("excludes the set 'authz.flagged_projects' returns")
            && reason.contains("project_flags.project_id")
            && reason.contains("provably non-null"),
        "{reason}"
    );
}

#[test]
fn an_excluded_set_that_does_not_translate_refuses_the_helper() {
    let helpers: Vec<_> = HELPERS
        .iter()
        .copied()
        .filter(|helper| *helper != "authz.blocking_organizations")
        .collect();
    for helper in ["authz.owned_unblocked", "authz.owned_outside_blocks"] {
        let reason = refusal_of(&reading("", helper), &helpers, "docs_read");
        assert!(
            reason.contains("'authz.blocking_organizations', which is not declared"),
            "{helper}: {reason}"
        );
    }
}

/// A request value compared with a helper's values reads every value as a fact the loader
/// writes once, which a set depending on the caller cannot take away from.
#[test]
fn a_request_value_set_excluding_another_set_is_refused() {
    let sql = format!(
        "{BLOCKS}{EXCLUDING}
         GRANT SELECT ON organizations TO authz_owner;
         CREATE FUNCTION authz.open_organizations() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT o.id FROM public.organizations o
           WHERE NOT (o.id = ANY (ARRAY(SELECT authz.blocking_organizations())))
         $$;
         ALTER FUNCTION authz.open_organizations() OWNER TO authz_owner;
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_read ON docs FOR SELECT
           USING (current_setting('app.tenant', true) IN (SELECT authz.open_organizations()));"
    );
    let mut helpers = HELPERS.to_vec();
    helpers.push("authz.open_organizations");
    let reason = refusal_of(&sql, &helpers, "docs_read");
    assert!(
        reason.contains("only outside the set 'authz.blocking_organizations' returns"),
        "{reason}"
    );
}
