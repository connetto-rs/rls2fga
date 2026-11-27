//! Declared helpers capping the rows their walks reach and their parent arms return by the
//! pairs another helper returns.

use rls2fga::classifier::patterns::ClassifiedExpr;
use rls2fga::types::ConfidenceLevel;

use crate::row_cap_tests::installation_translator;
use crate::support::footgun::{db_of, relation_definition};

pub(crate) const CAPPED_WALKS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
CREATE TYPE authz.resource_kind AS ENUM ('organization', 'folder', 'project');
CREATE TABLE organizations (id UUID PRIMARY KEY);
CREATE TABLE organization_blocks (
  organization_id UUID NOT NULL REFERENCES organizations (id),
  user_id UUID NOT NULL,
  PRIMARY KEY (organization_id, user_id)
);
CREATE TABLE app_installations (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  UNIQUE (organization_id, id)
);
CREATE TABLE installation_permissions (
  installation_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  kind authz.resource_kind NOT NULL,
  max_role authz.role NOT NULL,
  PRIMARY KEY (installation_id, kind),
  FOREIGN KEY (organization_id, installation_id) REFERENCES app_installations (organization_id, id)
);
CREATE TABLE resources (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id),
  kind authz.resource_kind NOT NULL,
  parent_id UUID REFERENCES resources (id),
  archived_at TIMESTAMPTZ
);
CREATE TABLE resource_grants (
  resource_id UUID NOT NULL REFERENCES resources (id),
  user_id UUID NOT NULL,
  PRIMARY KEY (resource_id, user_id)
);
CREATE TABLE resource_shortcuts (
  id UUID PRIMARY KEY,
  parent_id UUID NOT NULL REFERENCES resources (id),
  target_id UUID NOT NULL REFERENCES resources (id),
  organization_id UUID NOT NULL,
  kind authz.resource_kind NOT NULL
);
CREATE TABLE notes (id UUID PRIMARY KEY, resource_id UUID NOT NULL REFERENCES resources (id));
CREATE TABLE tasks (id UUID PRIMARY KEY, resource_id UUID NOT NULL REFERENCES resources (id));
CREATE TABLE files (id UUID PRIMARY KEY, resource_id UUID NOT NULL REFERENCES resources (id));
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE files ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON organization_blocks, installation_permissions, resources, resource_grants,
  resource_shortcuts TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid
$$;
CREATE FUNCTION authz.capped_kinds(min_role authz.role)
RETURNS TABLE (organization_id UUID, kind authz.resource_kind)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT permission.organization_id, permission.kind FROM public.installation_permissions permission
  WHERE permission.installation_id = authz.acting_installation_id()
    AND permission.max_role >= min_role
$$;
CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT block.organization_id FROM public.organization_blocks block
  WHERE block.user_id = authz.caller_id()
$$;
CREATE FUNCTION authz.reached_resources(min_role authz.role) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE reached (id) AS (
    SELECT g.resource_id FROM public.resource_grants g WHERE g.user_id = authz.caller_id()
    UNION
    SELECT child.id FROM reached JOIN public.resources child ON child.parent_id = reached.id
    WHERE (SELECT authz.acting_installation_id()) IS NULL
      OR (child.organization_id, child.kind) IN (SELECT * FROM authz.capped_kinds(min_role))
  )
  SELECT reached.id FROM reached
$$;
CREATE FUNCTION authz.capped_children(min_role authz.role) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT child.id FROM public.resources child
  WHERE child.parent_id IN (SELECT authz.reached_resources(min_role))
    AND (authz.acting_installation_id() IS NULL
      OR (child.organization_id, child.kind) IN (SELECT * FROM authz.capped_kinds(min_role)))
$$;
CREATE FUNCTION authz.open_projects() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT child.id FROM public.resources child
  WHERE child.parent_id IN (SELECT authz.reached_resources('reader'))
    AND child.kind = 'project'
    AND (child.archived_at IS NULL OR child.archived_at > now())
    AND NOT (child.organization_id = ANY (ARRAY(SELECT authz.blocking_organizations())))
$$;
CREATE FUNCTION authz.shortcut_targets(min_role authz.role) RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT shortcut.target_id FROM public.resource_shortcuts shortcut
  WHERE shortcut.parent_id IN (SELECT authz.reached_resources(min_role))
    AND (authz.acting_installation_id() IS NULL
      OR (shortcut.organization_id, shortcut.kind) IN (SELECT * FROM authz.capped_kinds(min_role)))
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.capped_kinds(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
ALTER FUNCTION authz.reached_resources(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.capped_children(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.open_projects() OWNER TO authz_owner;
ALTER FUNCTION authz.shortcut_targets(authz.role) OWNER TO authz_owner;
CREATE POLICY resources_select ON resources FOR SELECT
  USING (id = ANY (ARRAY(SELECT authz.reached_resources('reader'))));
CREATE POLICY notes_select ON notes FOR SELECT
  USING (resource_id IN (SELECT authz.capped_children('writer')));
CREATE POLICY tasks_select ON tasks FOR SELECT
  USING (resource_id IN (SELECT authz.open_projects()));
CREATE POLICY files_select ON files FOR SELECT
  USING (resource_id IN (SELECT authz.shortcut_targets('writer')));
";

pub(crate) const CAPPED_WALK_HELPERS: &[&str] = &[
    "authz.capped_kinds",
    "authz.blocking_organizations",
    "authz.reached_resources",
    "authz.capped_children",
    "authz.open_projects",
    "authz.shortcut_targets",
];

/// The `USING` classification of `policy` in `schema`, `helpers` declared.
fn using_with(schema: &str, helpers: &[&str], policy: &str) -> ClassifiedExpr {
    installation_translator(helpers)
        .classify(&db_of(schema))
        .into_iter()
        .find(|classified| classified.name() == policy)
        .unwrap_or_else(|| panic!("{policy} should classify"))
        .using_classification()
        .unwrap_or_else(|| panic!("{policy} USING should classify"))
        .clone()
}

/// The `USING` classification of `policy` in `schema`.
fn using_of(schema: &str, policy: &str) -> ClassifiedExpr {
    using_with(schema, CAPPED_WALK_HELPERS, policy)
}

/// The model [`CAPPED_WALKS`] translates to.
fn capped_model() -> String {
    installation_translator(CAPPED_WALK_HELPERS)
        .translate(&db_of(CAPPED_WALKS))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model()
        .clone()
}

#[test]
fn caps_on_walk_steps_and_parent_rows_translate() {
    for policy in [
        "resources_select",
        "notes_select",
        "tasks_select",
        "files_select",
    ] {
        let using = using_of(CAPPED_WALKS, policy);
        assert_eq!(
            using.confidence,
            ConfidenceLevel::A,
            "{policy}: {:?}",
            using.pattern
        );
    }
    capped_model();
}

/// The walk adds a child only while its cap keeps it, so a container the cap leaves out
/// ends the walk below it, and the rows the walk starts from stay uncapped.
#[test]
fn a_capped_step_holds_each_child_through_its_cap() {
    let dsl = capped_model();
    let definition = |relation: &str| {
        relation_definition(&dsl, "resources", relation).unwrap_or_else(|| panic!("{dsl}"))
    };
    let walk = definition("reached_resources_reader");
    let (granted, walked) = walk.split_once(" or ").unwrap_or_else(|| panic!("{dsl}"));
    assert!(!granted.contains("capped_kinds"), "{dsl}");
    assert_eq!(walked, "reached_resources_reader_followed");
    let followed = definition("reached_resources_reader_followed");
    let (reached, capped) = followed
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split_once(" and ")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert_eq!(reached, "reached_resources_reader from parent_id");
    assert!(capped.contains("capped_kinds_reader"), "{dsl}");
}

/// A parent arm returns a child only while its cap keeps the child.
#[test]
fn a_capped_parent_arm_holds_each_child_through_its_cap() {
    let dsl = capped_model();
    let children = relation_definition(&dsl, "resources", "capped_children_writer")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert!(
        children.contains("reached_resources_writer from parent_id"),
        "{dsl}"
    );
    assert!(children.contains("capped_kinds_writer"), "{dsl}");
}

/// A parent arm over an edge table of its own holds each edge row through its cap, and
/// returns the row the edge names only while one edge row naming it is kept.
#[test]
fn a_capped_parent_arm_over_an_edge_table_holds_each_edge_row() {
    let dsl = capped_model();
    let targets = relation_definition(&dsl, "resources", "shortcut_targets_writer")
        .unwrap_or_else(|| panic!("{dsl}"));
    let held = targets
        .strip_suffix(" from resource_shortcuts")
        .unwrap_or_else(|| panic!("{dsl}"));
    let shortcut =
        relation_definition(&dsl, "resource_shortcuts", held).unwrap_or_else(|| panic!("{dsl}"));
    let (reached, capped) = shortcut
        .split_once(" and ")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert_eq!(
        relation_definition(&dsl, "resource_shortcuts", reached).as_deref(),
        Some("[resources#reached_resources_writer]"),
        "{dsl}"
    );
    assert!(
        capped.contains("capped_kinds_writer from capped_kinds_writer_pair"),
        "{dsl}"
    );
}

/// A walk step capped by a helper never declared is refused.
#[test]
fn a_walk_step_capped_by_an_undeclared_helper_is_refused() {
    let helpers: Vec<&str> = CAPPED_WALK_HELPERS
        .iter()
        .copied()
        .filter(|helper| *helper != "authz.capped_kinds")
        .collect();
    let using = using_with(CAPPED_WALKS, &helpers, "resources_select");
    assert_eq!(using.confidence, ConfidenceLevel::D, "{:?}", using.pattern);
    let refusal = format!("{:?}", using.pattern);
    assert!(
        refusal.contains(
            "declared helper 'authz.reached_resources' calls 'authz.capped_kinds', \
             which is not declared"
        ),
        "{refusal}"
    );
}

/// A capped step needs a key naming one row of its edge table to hold each edge.
#[test]
fn a_capped_walk_over_edges_no_key_names_is_refused() {
    let schema = CAPPED_WALKS
        .replace(
            "CREATE TABLE resource_grants (",
            "CREATE TABLE resource_links (
  parent_id UUID NOT NULL REFERENCES resources (id),
  child_id UUID NOT NULL REFERENCES resources (id),
  organization_id UUID NOT NULL,
  kind authz.resource_kind NOT NULL
);
GRANT SELECT ON resource_links TO authz_owner;
CREATE TABLE resource_grants (",
        )
        .replace(
            "SELECT child.id FROM reached JOIN public.resources child ON child.parent_id = reached.id",
            "SELECT child.child_id FROM reached JOIN public.resource_links child \
             ON child.parent_id = reached.id",
        );
    let using = using_of(&schema, "resources_select");
    assert_eq!(using.confidence, ConfidenceLevel::D, "{:?}", using.pattern);
    let refusal = format!("{:?}", using.pattern);
    assert!(
        refusal.contains(
            "declared helper 'authz.reached_resources' holds each row of \
             'public.resource_links' as its own object, which no key names one row of"
        ),
        "{refusal}"
    );
}
