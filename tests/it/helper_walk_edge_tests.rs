//! Declared helpers whose recursive walk follows only the edges its term keeps, by the
//! edge's own columns, by the statement time and outside the sets other helpers return.

use rls2fga::types::ConfidenceLevel;

use crate::declared_helper_tests::{model, refusal_of, using_of};
use crate::support::footgun::relation_definition;

pub(crate) const EDGE_CONDITIONS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (id TEXT PRIMARY KEY);
CREATE TABLE organization_blocks (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  principal_id TEXT NOT NULL,
  PRIMARY KEY (organization_id, principal_id));
CREATE TABLE templates (id TEXT PRIMARY KEY);
CREATE TABLE template_grants (template_id TEXT NOT NULL REFERENCES templates (id),
  user_id TEXT NOT NULL, PRIMARY KEY (template_id, user_id));
CREATE TABLE template_steps (id TEXT PRIMARY KEY,
  parent_template_id TEXT NOT NULL REFERENCES templates (id),
  child_template_id TEXT NOT NULL REFERENCES templates (id),
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  kind TEXT NOT NULL, ends_at TIMESTAMPTZ);
CREATE TABLE template_watchers (template_id TEXT NOT NULL REFERENCES templates (id),
  user_id TEXT NOT NULL, PRIMARY KEY (template_id, user_id));
CREATE TABLE assets (id TEXT PRIMARY KEY);
CREATE TABLE asset_grants (asset_id TEXT NOT NULL REFERENCES assets (id),
  user_id TEXT NOT NULL, PRIMARY KEY (asset_id, user_id));
CREATE TABLE placements (asset_id TEXT NOT NULL REFERENCES assets (id),
  container_id TEXT NOT NULL REFERENCES assets (id), kind TEXT NOT NULL,
  status TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations (id),
  PRIMARY KEY (asset_id, container_id, kind));
CREATE TABLE folders (id TEXT PRIMARY KEY, parent_id TEXT REFERENCES folders (id),
  kind TEXT NOT NULL, organization_id TEXT NOT NULL REFERENCES organizations (id));
CREATE TABLE folder_grants (folder_id TEXT NOT NULL REFERENCES folders (id),
  user_id TEXT NOT NULL, PRIMARY KEY (folder_id, user_id));
GRANT SELECT ON organization_blocks, template_grants, template_steps, template_watchers,
  asset_grants, placements, folders, folder_grants TO authz_owner;
CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT b.organization_id FROM public.organization_blocks b
  WHERE b.principal_id = current_setting('app.user_id', true)
$$;
CREATE FUNCTION authz.readable_templates() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE readable (id) AS (
    SELECT g.template_id FROM public.template_grants g
    WHERE g.user_id = current_setting('app.user_id', true)
    UNION
    SELECT step.child_template_id FROM public.template_steps step
    JOIN readable ON readable.id = step.parent_template_id
    WHERE step.kind = 'run' AND (step.ends_at IS NULL OR step.ends_at > now())
      AND NOT (step.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))
  )
  SELECT readable.id FROM readable
$$;
CREATE FUNCTION authz.watched_templates() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE watched (id) AS (
    SELECT w.template_id FROM public.template_watchers w
    WHERE w.user_id = current_setting('app.user_id', true)
    UNION
    SELECT step.child_template_id FROM public.template_steps step
    JOIN watched ON watched.id = step.parent_template_id
    WHERE step.kind = 'run'
  )
  SELECT watched.id FROM watched
$$;
CREATE FUNCTION authz.enclosing_assets() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE enclosing (id) AS (
    SELECT g.asset_id FROM public.asset_grants g
    WHERE g.user_id = current_setting('app.user_id', true)
    UNION
    SELECT placement.container_id FROM public.placements placement
    JOIN enclosing ON enclosing.id = placement.asset_id
    WHERE placement.kind = 'into' AND placement.status = 'completed'
      AND NOT (placement.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))
  )
  SELECT enclosing.id FROM enclosing
$$;
CREATE FUNCTION authz.folders_below() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE below (id) AS (
    SELECT g.folder_id FROM public.folder_grants g
    WHERE g.user_id = current_setting('app.user_id', true)
    UNION
    SELECT child.id FROM public.folders child JOIN below ON child.parent_id = below.id
    WHERE child.kind = 'shared'
      AND NOT (child.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))
  )
  SELECT below.id FROM below
$$;
CREATE FUNCTION authz.folders_above() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE above (id) AS (
    SELECT g.folder_id FROM public.folder_grants g
    WHERE g.user_id = current_setting('app.user_id', true)
    UNION
    SELECT folder.parent_id FROM public.folders folder JOIN above ON folder.id = above.id
    WHERE NOT (folder.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))
  )
  SELECT above.id FROM above
$$;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.readable_templates() OWNER TO authz_owner;
ALTER FUNCTION authz.watched_templates() OWNER TO authz_owner;
ALTER FUNCTION authz.enclosing_assets() OWNER TO authz_owner;
ALTER FUNCTION authz.folders_below() OWNER TO authz_owner;
ALTER FUNCTION authz.folders_above() OWNER TO authz_owner;
";

pub(crate) const TEMPLATES_SELECT: &str = "
ALTER TABLE templates ENABLE ROW LEVEL SECURITY;
CREATE POLICY templates_select ON templates FOR SELECT USING (
  id = ANY (ARRAY(SELECT authz.readable_templates()))
  OR id = ANY (ARRAY(SELECT authz.watched_templates())));
";

pub(crate) const CONTAINERS_SELECT: &str = "
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY assets_select ON assets FOR SELECT USING (
  id = ANY (ARRAY(SELECT authz.enclosing_assets())));
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_select ON folders FOR SELECT USING (
  id = ANY (ARRAY(SELECT authz.folders_below()))
  OR id = ANY (ARRAY(SELECT authz.folders_above())));
";

/// The schema with every policy.
fn guarded() -> String {
    format!("{EDGE_CONDITIONS}{TEMPLATES_SELECT}{CONTAINERS_SELECT}")
}

pub(crate) const EDGE_HELPERS: &[&str] = &[
    "authz.blocking_organizations",
    "authz.readable_templates",
    "authz.watched_templates",
    "authz.enclosing_assets",
    "authz.folders_below",
    "authz.folders_above",
];

#[test]
fn walks_over_filtered_edges_classify() {
    for policy in ["templates_select", "assets_select", "folders_select"] {
        let classified = using_of(&guarded(), EDGE_HELPERS, policy);
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::A,
            "{policy}: {classified:?}"
        );
    }
}

/// The part of a walk's relation past its grant arm, the caller's own grant rows.
fn walked<'a>(definition: &'a str, dsl: &str) -> &'a str {
    let (granted, walked) = definition
        .split_once(" or ")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert!(granted.starts_with("member"), "{dsl}");
    walked
}

/// A step blocked for the caller, or out of its time, stops the walk through that step
/// alone, so each step is an object of its own between the two templates it joins, and a
/// step of another kind is never loaded.
#[test]
fn a_step_a_block_or_a_bound_stops_is_an_object_between_its_templates() {
    let dsl = model(&guarded(), EDGE_HELPERS);
    let definition = |type_name: &str, relation: &str| {
        relation_definition(&dsl, type_name, relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(
        walked(&definition("templates", "readable_templates"), &dsl),
        "readable_templates_followed from template_steps"
    );
    assert_eq!(
        definition("templates", "template_steps"),
        "[template_steps]"
    );
    let followed = definition("template_steps", "readable_templates_followed");
    let (kept, blocked) = followed
        .split_once(" but not ")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert_eq!(blocked, "blocking_organizations from organizations");
    let (reached, bounded) = kept
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split_once(" and ")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert_eq!(reached, "readable_templates from parent_template_id");
    assert!(
        !bounded.contains(" from "),
        "the bounds are read on the step itself: {dsl}"
    );
}

/// A walk keeping its edges by their own columns alone links each template to its parents
/// through the steps of that kind, with no step held as an object.
#[test]
fn a_walk_kept_by_the_edge_columns_alone_links_through_the_kept_steps() {
    let dsl = model(&guarded(), EDGE_HELPERS);
    let walk = relation_definition(&dsl, "templates", "watched_templates")
        .unwrap_or_else(|| panic!("{dsl}"));
    let (computed, tupleset) = walked(&walk, &dsl)
        .split_once(" from ")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert_eq!(computed, "watched_templates");
    assert_eq!(
        relation_definition(&dsl, "templates", tupleset).as_deref(),
        Some("[templates]"),
        "{dsl}"
    );
    assert!(
        relation_definition(&dsl, "template_steps", "watched_templates_followed").is_none(),
        "{dsl}"
    );
}

/// A walk over edges no key orients goes down to the column its term adds, each edge an
/// object of its own, so a container reached through several placements keeps every one.
#[test]
fn a_walk_over_unkeyed_edges_holds_each_placement() {
    let dsl = model(&guarded(), EDGE_HELPERS);
    let definition = |type_name: &str, relation: &str| {
        relation_definition(&dsl, type_name, relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(
        walked(&definition("assets", "enclosing_assets"), &dsl),
        "enclosing_assets_followed from placements"
    );
    assert_eq!(
        definition("placements", "enclosing_assets_followed"),
        "enclosing_assets from asset_id but not blocking_organizations from organizations"
    );
}

/// A tree holding its own edges reads the conditions on the child, the row the walk adds
/// walking down and the row it leaves walking up.
#[test]
fn a_tree_of_its_own_rows_reads_the_conditions_on_the_child() {
    let dsl = model(&guarded(), EDGE_HELPERS);
    let definition = |relation: &str| {
        relation_definition(&dsl, "folders", relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    assert_eq!(
        walked(&definition("folders_below"), &dsl),
        "folders_below_followed"
    );
    assert_eq!(
        definition("folders_below_followed"),
        "folders_below from parent_id but not blocking_organizations from organizations"
    );
    assert_eq!(
        walked(&definition("folders_above"), &dsl),
        "folders_above_followed from folders"
    );
    assert_eq!(
        definition("folders_above_followed"),
        "folders_above but not blocking_organizations from organizations"
    );
}

/// An edge whose bounds or sets hold it as its own object needs a key naming one row of
/// its table.
#[test]
fn a_blocked_walk_over_edges_no_key_names_is_refused() {
    let sql = format!(
        "{EDGE_CONDITIONS}
         ALTER TABLE templates ENABLE ROW LEVEL SECURITY;
         CREATE POLICY templates_select ON templates FOR SELECT USING (
           id = ANY (ARRAY(SELECT authz.readable_templates())));"
    )
    .replace(
        "CREATE TABLE template_steps (id TEXT PRIMARY KEY,",
        "CREATE TABLE template_steps (id TEXT NOT NULL,",
    );
    let refusal = refusal_of(&sql, EDGE_HELPERS, "templates_select");
    assert!(
        refusal.contains(
            "declared helper 'authz.readable_templates' holds each row of \
             'public.template_steps' as its own object, which no key names one row of"
        ),
        "{refusal}"
    );
}
