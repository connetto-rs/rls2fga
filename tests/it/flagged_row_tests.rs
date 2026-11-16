//! A row flagged by its own columns, read through a `SECURITY DEFINER` boolean body either
//! by its key or up a recursive walk of edge tables, grants as a relation on the flagged
//! table's type, and `NOT` of it subtracts that relation with `but not`.

use rls2fga::types::ConfidenceLevel;

use crate::declared_helper_tests::{model, refusal_of, translator};
use crate::support::footgun::{db_of, relation_definition, relation_definitions};

/// Objects their owner reads, flagged archived by a boolean column read through a definer
/// function that looks the row up by its key.
const OBJECTS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE objects (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
  archived BOOLEAN NOT NULL DEFAULT false);
GRANT SELECT ON objects TO authz_owner;
CREATE FUNCTION authz.is_archived(resource TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.objects object
                 WHERE object.id = resource AND object.archived)
$$;
ALTER FUNCTION authz.is_archived(TEXT) OWNER TO authz_owner;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY objects_owner ON objects FOR SELECT
  USING (owner_id = current_setting('app.user_id', true));
";

/// Resources placed under parents by two edge tables, archived when any ancestor is, the
/// walk read through a definer function, and the grants naming each resource.
const RESOURCES: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE resources (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, archived_at TIMESTAMPTZ);
CREATE TABLE resource_parents (id TEXT PRIMARY KEY REFERENCES resources (id),
  parent_id TEXT NOT NULL REFERENCES resources (id));
CREATE TABLE ownables (id TEXT PRIMARY KEY REFERENCES resources (id),
  project_id TEXT NOT NULL REFERENCES resources (id));
CREATE TABLE grants (id TEXT PRIMARY KEY, resource_id TEXT NOT NULL REFERENCES resources (id),
  user_id TEXT NOT NULL);
GRANT SELECT ON resources, resource_parents, ownables TO authz_owner;
CREATE FUNCTION authz.is_archived(resource TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE ancestors (id) AS (
    SELECT resource
    UNION
    SELECT parent.id FROM ancestors CROSS JOIN LATERAL (
      SELECT edge.parent_id AS id FROM public.resource_parents edge WHERE edge.id = ancestors.id
      UNION ALL
      SELECT ownable.project_id FROM public.ownables ownable WHERE ownable.id = ancestors.id
    ) parent
  )
  SELECT EXISTS (SELECT 1 FROM ancestors
                 JOIN public.resources ancestor ON ancestor.id = ancestors.id
                 WHERE ancestor.archived_at IS NOT NULL)
$$;
ALTER FUNCTION authz.is_archived(TEXT) OWNER TO authz_owner;
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_parents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownables ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY resources_owner ON resources FOR SELECT
  USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY grants_holder ON grants FOR SELECT
  USING (user_id = current_setting('app.user_id', true));
";

/// The one relation of `type_name` whose name starts with `prefix`, with its definition.
fn relation_named_like(dsl: &str, type_name: &str, prefix: &str) -> (String, String) {
    let found: Vec<_> = relation_definitions(dsl, type_name)
        .into_iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .collect();
    let [one] = <[_; 1]>::try_from(found).unwrap_or_else(|found| {
        panic!("one {type_name} relation should start with {prefix}, found {found:?}: {dsl}")
    });
    one
}

fn archive_model(base: &str, policies: &str) -> String {
    model(&format!("{base}{policies}"), &[])
}

#[test]
fn a_restrictive_negated_keyed_flag_subtracts_the_flagged_rows() {
    let dsl = archive_model(
        OBJECTS,
        "CREATE POLICY archived ON objects AS RESTRICTIVE FOR SELECT
           USING (NOT authz.is_archived(id));",
    );
    let (gate, definition) = relation_named_like(&dsl, "objects", "public_where_archived_");
    assert_eq!(definition, "[user:*]", "{dsl}");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(format!("(owner but not {gate}) and acting_app_user from request_gate").as_str()),
        "{dsl}"
    );
}

#[test]
fn a_keyed_flag_grants_the_flagged_rows() {
    let dsl = archive_model(
        OBJECTS,
        "CREATE POLICY archive_positive ON objects FOR SELECT USING (authz.is_archived(id));",
    );
    let (gate, _) = relation_named_like(&dsl, "objects", "public_where_archived_");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(format!("({gate} or owner) and acting_app_user from request_gate").as_str()),
        "{dsl}"
    );
}

#[test]
fn a_permissive_grant_beside_a_negated_flag_subtracts_the_flagged_rows() {
    let dsl = archive_model(
        &OBJECTS.replace(
            "USING (owner_id = current_setting('app.user_id', true));",
            "USING (owner_id = current_setting('app.user_id', true)
                    AND NOT authz.is_archived(id));",
        ),
        "",
    );
    let (gate, _) = relation_named_like(&dsl, "objects", "public_where_archived_");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(format!("(owner but not {gate}) and acting_app_user from request_gate").as_str()),
        "{dsl}"
    );
}

#[test]
fn a_permissive_negated_flag_alone_grants_every_row_but_the_flagged_ones() {
    let dsl = archive_model(
        OBJECTS,
        "CREATE POLICY live ON objects FOR SELECT USING (NOT authz.is_archived(id));",
    );
    let (gate, _) = relation_named_like(&dsl, "objects", "public_where_archived_");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(
            format!(
                "((public_viewer but not {gate}) or owner) and acting_app_user from request_gate"
            )
            .as_str()
        ),
        "{dsl}"
    );
}

#[test]
fn the_flag_gate_loads_the_rows_its_columns_flag() {
    let outputs = translator(ConfidenceLevel::B, &[])
        .translate(&db_of(&format!(
            "{OBJECTS}
             CREATE POLICY archived ON objects AS RESTRICTIVE FOR SELECT
               USING (NOT authz.is_archived(id));"
        )))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let gate = outputs
        .tuple_queries()
        .iter()
        .find(|query| query.sql.contains("'public_where_archived_"))
        .unwrap_or_else(|| panic!("a gate query should load: {:?}", outputs.tuple_queries()))
        .sql
        .clone();
    assert!(gate.contains("FROM \"public\".\"objects\""), "{gate}");
    assert!(gate.contains("AND \"archived\" = TRUE"), "{gate}");
}

#[test]
fn a_negated_archive_walk_subtracts_the_flag_inherited_up_both_edge_tables() {
    let dsl = archive_model(
        RESOURCES,
        "CREATE POLICY resources_archived ON resources AS RESTRICTIVE FOR SELECT
           USING (NOT authz.is_archived(id));",
    );
    let (gate, gate_definition) =
        relation_named_like(&dsl, "resources", "public_where_archived_at_");
    assert_eq!(gate_definition, "[user:*]", "{dsl}");
    let (walked, walked_definition) = relation_named_like(&dsl, "resources", "flag_archived_at_");
    assert_eq!(
        walked_definition,
        format!(
            "{gate} or {walked} from resource_parents_parent_id or {walked} from \
             ownables_project_id"
        ),
        "{dsl}"
    );
    for edge in ["resource_parents_parent_id", "ownables_project_id"] {
        assert_eq!(
            relation_definition(&dsl, "resources", edge).as_deref(),
            Some("[resources]"),
            "{dsl}"
        );
    }
    assert_eq!(
        relation_definition(&dsl, "resources", "can_select").as_deref(),
        Some(format!("(owner but not {walked}) and acting_app_user from request_gate").as_str()),
        "{dsl}"
    );
}

#[test]
fn a_negated_archive_walk_over_a_foreign_key_subtracts_through_the_named_row() {
    let dsl = archive_model(
        RESOURCES,
        "CREATE POLICY grants_archived ON grants AS RESTRICTIVE FOR SELECT
           USING (NOT authz.is_archived(resource_id));",
    );
    let (walked, _) = relation_named_like(&dsl, "resources", "flag_archived_at_");
    assert_eq!(
        relation_definition(&dsl, "grants", "can_select").as_deref(),
        Some(
            format!("(user but not {walked} from resources) and acting_app_user from request_gate")
                .as_str()
        ),
        "{dsl}"
    );
}

#[test]
fn the_edge_links_load_each_edge_row() {
    let outputs = translator(ConfidenceLevel::B, &[])
        .translate(&db_of(&format!(
            "{RESOURCES}
             CREATE POLICY resources_archived ON resources AS RESTRICTIVE FOR SELECT
               USING (NOT authz.is_archived(id));"
        )))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate");
    let link = outputs
        .tuple_queries()
        .iter()
        .find(|query| query.sql.contains("'ownables_project_id' AS relation"))
        .unwrap_or_else(|| panic!("an edge query should load: {:?}", outputs.tuple_queries()))
        .sql
        .clone();
    assert!(link.contains("FROM \"public\".\"ownables\""), "{link}");
    assert!(link.contains("\"project_id\" IS NOT NULL"), "{link}");
}

/// A walk keeping a depth column stops where its bound does, which nothing proves covers
/// the data, and a walk of `UNION ALL` never ends on a cycle.
#[test]
fn a_walk_the_model_cannot_follow_exactly_is_refused_by_name() {
    let depth_bounded = RESOURCES.replace(
        "WITH RECURSIVE ancestors (id) AS (
    SELECT resource
    UNION
    SELECT parent.id FROM ancestors",
        "WITH RECURSIVE ancestors (id, depth) AS (
    SELECT resource, 0
    UNION
    SELECT parent.id, ancestors.depth + 1 FROM ancestors",
    );
    let union_all = RESOURCES.replace(
        "SELECT resource
    UNION
",
        "SELECT resource
    UNION ALL
",
    );
    for (schema, named) in [(depth_bounded, "depth"), (union_all, "UNION ALL")] {
        let reason = refusal_of(
            &format!(
                "{schema}
                 CREATE POLICY resources_archived ON resources AS RESTRICTIVE FOR SELECT
                   USING (NOT authz.is_archived(id));"
            ),
            &[],
            "resources_archived",
        );
        assert!(reason.contains(named), "{named}: {reason}");
        assert!(!reason.contains("negation cannot be expressed"), "{reason}");
    }
}

/// Read as the caller, a guarded table shows only the rows the caller's own policies let
/// through, so the flag is the caller's and no row decides it.
#[test]
fn a_flag_read_through_the_callers_own_policies_is_refused() {
    let reason = refusal_of(
        &format!(
            "{OBJECTS}
             CREATE TABLE notes (id TEXT PRIMARY KEY, object_id TEXT NOT NULL REFERENCES objects (id),
               author_id TEXT NOT NULL);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_live ON notes FOR SELECT USING (
               NOT EXISTS (SELECT 1 FROM objects object
                           WHERE object.id = notes.object_id AND object.archived));"
        ),
        &[],
        "notes_live",
    );
    assert!(reason.contains("row level security"), "{reason}");
}

/// A strict function returns `NULL` for a `NULL` argument, which `NOT` keeps `NULL`, so
/// the row is hidden where no tuple flags it.
#[test]
fn a_negated_strict_flag_over_a_nullable_column_is_refused() {
    let reason = refusal_of(
        &format!(
            "{RESOURCES}
             CREATE TABLE notes (id TEXT PRIMARY KEY, resource_id TEXT REFERENCES resources (id));
             CREATE FUNCTION authz.is_archived_strict(resource TEXT) RETURNS BOOLEAN
             LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = '' AS $$
               SELECT EXISTS (SELECT 1 FROM public.resources r
                              WHERE r.id = resource AND r.archived_at IS NOT NULL)
             $$;
             ALTER FUNCTION authz.is_archived_strict(TEXT) OWNER TO authz_owner;
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_live ON notes FOR SELECT
               USING (NOT authz.is_archived_strict(resource_id));"
        ),
        &[],
        "notes_live",
    );
    assert!(reason.contains("resource_id"), "{reason}");
    assert!(reason.contains("NULL"), "{reason}");
}

/// Read through a restrictive clause's own call, a `STRICT` body is still `NULL` for a
/// `NULL` argument, so the presence of the argument gates the rows the subtraction leaves.
#[test]
fn a_restrictive_strict_negated_flag_keeps_the_argument_presence() {
    let dsl = archive_model(
        RESOURCES,
        "CREATE TABLE notes (id TEXT PRIMARY KEY, resource_id TEXT REFERENCES resources (id),
           author_id TEXT NOT NULL);
         CREATE FUNCTION authz.is_live(resource TEXT) RETURNS BOOLEAN
         LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path = '' AS $$
           SELECT NOT EXISTS (SELECT 1 FROM public.resources r
                              WHERE r.id = resource AND r.archived_at IS NOT NULL)
         $$;
         ALTER FUNCTION authz.is_live(TEXT) OWNER TO authz_owner;
         ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
         CREATE POLICY notes_author ON notes FOR SELECT
           USING (author_id = current_setting('app.user_id', true));
         CREATE POLICY notes_live ON notes AS RESTRICTIVE FOR SELECT
           USING (authz.is_live(resource_id));",
    );
    let (gate, _) = relation_named_like(&dsl, "resources", "public_where_archived_at_");
    let (present, _) = relation_named_like(&dsl, "notes", "present_resource_id_");
    assert_eq!(
        relation_definition(&dsl, "notes", "can_select").as_deref(),
        Some(
            format!(
                "author and (public_viewer but not {gate} from resources) and {present} and \
                 acting_app_user from request_gate"
            )
            .as_str()
        ),
        "{dsl}"
    );
}

/// Inside a lateral branch an edge read under the walk's name hides the walk, so the branch
/// compares the edge row with itself and reaches every parent in the table.
#[test]
fn an_edge_hiding_the_walk_is_not_read_as_a_step() {
    let shadowed = RESOURCES.replace(
        "SELECT edge.parent_id AS id FROM public.resource_parents edge WHERE edge.id = ancestors.id",
        "SELECT ancestors.parent_id AS id FROM public.resource_parents ancestors \
         WHERE ancestors.id = ancestors.id",
    );
    assert_ne!(shadowed, RESOURCES);
    refusal_of(
        &format!(
            "{shadowed}
             CREATE POLICY resources_archived ON resources AS RESTRICTIVE FOR SELECT
               USING (NOT authz.is_archived(id));"
        ),
        &[],
        "resources_archived",
    );
}

/// A key under a nondeterministic collation finds `'ABC'` and `'abc'` equal, which `OpenFGA`
/// keys apart, so the subtraction would miss the archived row.
#[test]
fn a_negated_flag_over_a_case_insensitive_key_is_refused() {
    let reason = refusal_of(
        &format!(
            "CREATE COLLATION ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false);
             {}
             CREATE POLICY archived ON objects AS RESTRICTIVE FOR SELECT
               USING (NOT authz.is_archived(id));",
            OBJECTS.replace("id TEXT PRIMARY KEY", "id TEXT COLLATE ci PRIMARY KEY")
        ),
        &[],
        "archived",
    );
    assert!(reason.contains("collation"), "{reason}");
}
