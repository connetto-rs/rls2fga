//! A row flagged by its own columns, read through a `SECURITY DEFINER` boolean body either
//! by its key or up a recursive walk of edge tables, grants as a relation on the flagged
//! table's type, and `NOT` of it subtracts that relation with `but not`.

use rls2fga::types::ConfidenceLevel;

use crate::declared_helper_tests::{model, refusal_of, translator, using_of};
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

/// Each edge row links the child it names to its parent, so the parent's flag reaches the
/// child and never the reverse.
#[test]
fn the_edge_links_load_each_edge_row_from_child_to_parent() {
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
    let (object, rest) = link
        .split_once(" AS object")
        .expect("the link names an object");
    let (_, subject) = rest
        .split_once(" AS relation, ")
        .expect("the link names a relation");
    let (subject, _) = subject
        .split_once(" AS subject")
        .expect("the link names a subject");
    assert!(
        object.contains("\"id\"") && !object.contains("project_id"),
        "{link}"
    );
    assert!(subject.contains("\"project_id\""), "{link}");
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

/// `schema` with the body of its one function replaced by `body`.
fn with_body(schema: &str, body: &str) -> String {
    let (head, rest) = schema
        .split_once("AS $$")
        .expect("the schema has a function body");
    let (_, tail) = rest.split_once("$$;").expect("the body closes");
    format!("{head}AS $$ {body} $$;{tail}")
}

/// The archive walk seeded with the argument and stepping as `steps`, testing `scan`.
fn archive_walk(steps: &str, scan: &str) -> String {
    format!(
        "WITH RECURSIVE ancestors (id) AS (SELECT resource UNION {steps}) SELECT EXISTS ({scan})"
    )
}

/// One step up `resource_parents` joined to the walk.
const JOIN_STEP: &str = "SELECT edge.parent_id FROM ancestors
  JOIN public.resource_parents edge ON edge.id = ancestors.id";

/// The archive test on each row the walk reaches.
const ARCHIVED_SCAN: &str = "SELECT 1 FROM ancestors
  JOIN public.resources ancestor ON ancestor.id = ancestors.id
  WHERE ancestor.archived_at IS NOT NULL";

const NEGATED_WALK: &str = "CREATE POLICY resources_archived ON resources AS RESTRICTIVE
  FOR SELECT USING (NOT authz.is_archived(id));";

/// Every spelling of one step up `resource_parents` walks that one edge table.
#[test]
fn every_spelling_of_a_one_edge_walk_inherits_the_flag_up_that_edge() {
    let spellings = [
        archive_walk(JOIN_STEP, ARCHIVED_SCAN),
        archive_walk(
            "SELECT edge.parent_id FROM ancestors
               JOIN public.resource_parents edge ON ancestors.id = edge.id",
            ARCHIVED_SCAN,
        ),
        archive_walk(
            "SELECT parent.id FROM ancestors CROSS JOIN LATERAL (
               SELECT edge.parent_id FROM public.resource_parents edge
               WHERE edge.id = ancestors.id) parent (id)",
            ARCHIVED_SCAN,
        ),
        archive_walk(
            JOIN_STEP,
            "SELECT 1 FROM ancestors CROSS JOIN public.resources ancestor
               WHERE ancestor.id = ancestors.id AND ancestor.archived_at IS NOT NULL",
        ),
        archive_walk(
            JOIN_STEP,
            "SELECT 1 FROM ancestors JOIN public.resources ancestor
               ON ancestor.id = ancestors.id AND ancestor.archived_at IS NOT NULL",
        ),
        "WITH RECURSIVE ancestors (node) AS (
           SELECT resource
           UNION
           SELECT edge.parent_id FROM ancestors
             JOIN public.resource_parents edge ON edge.id = ancestors.node)
         SELECT EXISTS (SELECT 1 FROM ancestors JOIN public.resources ancestor ON ancestor.id = node
                        WHERE archived_at IS NOT NULL)"
            .to_string(),
    ];
    for body in spellings {
        let schema = format!("{}{NEGATED_WALK}", with_body(RESOURCES, &body));
        let classified = using_of(&schema, &[], "resources_archived");
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::B,
            "{body}\n{classified:?}"
        );
        let dsl = model(&schema, &[]);
        let (gate, _) = relation_named_like(&dsl, "resources", "public_where_archived_at_");
        let (walked, definition) = relation_named_like(&dsl, "resources", "flag_archived_at_");
        assert_eq!(
            definition,
            format!("{gate} or {walked} from resource_parents_parent_id"),
            "{body}\n{dsl}"
        );
        assert_eq!(
            relation_definition(&dsl, "resources", "can_select").as_deref(),
            Some(
                format!("(owner but not {walked}) and acting_app_user from request_gate").as_str()
            ),
            "{body}\n{dsl}"
        );
    }
}

/// A walk or flag test the model could not follow row for row is no row flag, so the
/// helper's body stays untranslated.
#[test]
fn a_walk_or_test_outside_the_followed_shapes_is_refused() {
    let lateral = |branches: &str| {
        archive_walk(
            &format!("SELECT parent.id FROM ancestors CROSS JOIN LATERAL ({branches}) parent"),
            ARCHIVED_SCAN,
        )
    };
    let bodies = [
        format!(
            "WITH RECURSIVE ancestors (id) AS (SELECT resource UNION {JOIN_STEP}),
               unused (id) AS (SELECT 1)
             SELECT EXISTS ({ARCHIVED_SCAN})"
        ),
        format!(
            "WITH RECURSIVE ancestors AS (SELECT resource AS id UNION {JOIN_STEP})
             SELECT EXISTS ({ARCHIVED_SCAN})"
        ),
        format!(
            "WITH RECURSIVE ancestors (id) AS (WITH start (id) AS (SELECT resource)
               SELECT start.id FROM start UNION {JOIN_STEP})
             SELECT EXISTS ({ARCHIVED_SCAN})"
        ),
        format!(
            "WITH RECURSIVE ancestors (id) AS (SELECT resource) SELECT EXISTS ({ARCHIVED_SCAN})"
        ),
        format!(
            "WITH RECURSIVE ancestors (id) AS (SELECT resource UNION SELECT resource UNION {JOIN_STEP})
             SELECT EXISTS ({ARCHIVED_SCAN})"
        ),
        format!(
            "WITH RECURSIVE ancestors (id) AS (
               SELECT link.parent_id FROM public.resource_parents link WHERE link.id = resource
               UNION {JOIN_STEP})
             SELECT EXISTS ({ARCHIVED_SCAN})"
        ),
        archive_walk(&format!("({JOIN_STEP})"), ARCHIVED_SCAN),
        archive_walk(
            &format!("{JOIN_STEP} WHERE edge.parent_id <> 'root'"),
            ARCHIVED_SCAN,
        ),
        archive_walk(&format!("{JOIN_STEP}, public.ownables extra"), ARCHIVED_SCAN),
        archive_walk(
            "SELECT edge.parent_id FROM public.resource_parents edge
               JOIN ancestors ON edge.id = ancestors.id",
            ARCHIVED_SCAN,
        ),
        archive_walk(
            &format!("{JOIN_STEP} JOIN public.ownables kept ON kept.id = edge.parent_id"),
            ARCHIVED_SCAN,
        ),
        archive_walk(
            "SELECT edge.parent_id FROM ancestors
               LEFT JOIN public.resource_parents edge ON edge.id = ancestors.id",
            ARCHIVED_SCAN,
        ),
        archive_walk(
            "SELECT ancestors.id FROM ancestors
               JOIN public.resource_parents edge ON edge.id = ancestors.id",
            ARCHIVED_SCAN,
        ),
        archive_walk(
            "SELECT edge.parent_id FROM ancestors
               JOIN public.resource_parents edge ON edge.id = edge.parent_id",
            ARCHIVED_SCAN,
        ),
        archive_walk(
            "SELECT ancestors.id FROM ancestors CROSS JOIN LATERAL (
               SELECT edge.parent_id AS id FROM public.resource_parents edge
               WHERE edge.id = ancestors.id) parent",
            ARCHIVED_SCAN,
        ),
        lateral(
            "SELECT edge.parent_id AS id FROM public.resource_parents edge
             WHERE edge.id = ancestors.id LIMIT 1",
        ),
        lateral(
            "SELECT edge.parent_id AS id FROM public.resource_parents edge
             WHERE edge.id = ancestors.id GROUP BY edge.parent_id HAVING count(*) > 1",
        ),
        lateral(
            "SELECT edge.parent_id AS id FROM public.resource_parents edge, public.ownables extra
             WHERE edge.id = ancestors.id",
        ),
        lateral(
            "SELECT edge.parent_id AS id FROM public.resource_parents edge
               JOIN public.ownables kept ON kept.id = edge.parent_id
             WHERE edge.id = ancestors.id",
        ),
        lateral(
            "SELECT edge.parent_id AS id, edge.id AS child FROM public.resource_parents edge
             WHERE edge.id = ancestors.id",
        ),
        lateral(
            "SELECT ancestors.id AS id FROM public.resource_parents edge
             WHERE edge.id = ancestors.id",
        ),
        lateral(
            "SELECT edge.parent_id AS id FROM public.resource_parents edge
             WHERE edge.id = ancestors.id
             INTERSECT
             SELECT ownable.project_id FROM public.ownables ownable
             WHERE ownable.id = ancestors.id",
        ),
        archive_walk(
            JOIN_STEP,
            "SELECT 1 FROM ancestors JOIN public.resources ancestor ON ancestor.id = ancestors.id
             WHERE ancestor.archived_at IS NOT NULL AND ancestor.owner_id = ancestor.id",
        ),
        format!(
            "WITH RECURSIVE ancestors (id) AS (SELECT resource UNION {JOIN_STEP})
             SELECT EXISTS (SELECT 1 FROM public.resources ancestor
                            WHERE ancestor.id = resource AND ancestor.archived_at IS NOT NULL)"
        ),
        archive_walk(
            "SELECT public.resource_parents.parent_id FROM ancestors
               JOIN public.resource_parents ON resource_parents.id = ancestors.id",
            ARCHIVED_SCAN,
        ),
        format!(
            "WITH RECURSIVE ancestors (id) AS (SELECT resource UNION BY NAME {JOIN_STEP})
             SELECT EXISTS ({ARCHIVED_SCAN})"
        ),
    ];
    for body in bodies {
        let reason = refusal_of(
            &format!("{}{NEGATED_WALK}", with_body(RESOURCES, &body)),
            &[],
            "resources_archived",
        );
        assert!(
            !reason.contains("negation cannot be expressed"),
            "{body}\n{reason}"
        );
    }
}

/// A body binding a table's own name leaves which of the two a reference reads open.
#[test]
fn a_walk_named_after_a_table_is_refused() {
    let body = "WITH RECURSIVE resources (id) AS (
                  SELECT resource
                  UNION
                  SELECT edge.parent_id FROM resources
                    JOIN public.resource_parents edge ON edge.id = resources.id)
                SELECT EXISTS (SELECT 1 FROM resources
                  JOIN public.resources ancestor ON ancestor.id = resources.id
                  WHERE ancestor.archived_at IS NOT NULL)";
    let reason = refusal_of(
        &format!("{}{NEGATED_WALK}", with_body(RESOURCES, body)),
        &[],
        "resources_archived",
    );
    assert!(reason.contains("also names a table"), "{reason}");
}

/// A `char(n)` key compares without its blank padding, which the key of a `text` column
/// keeps, so the two cannot share one `OpenFGA` key.
#[test]
fn a_flag_keyed_by_another_type_than_the_guarded_column_is_refused() {
    let reason = refusal_of(
        &format!(
            "{}
             CREATE TABLE notes (id TEXT PRIMARY KEY, object_id TEXT NOT NULL);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             CREATE POLICY notes_live ON notes AS RESTRICTIVE FOR SELECT
               USING (NOT authz.is_archived(object_id));",
            OBJECTS.replace("id TEXT PRIMARY KEY", "id CHAR(8) PRIMARY KEY")
        ),
        &[],
        "notes_live",
    );
    assert!(reason.contains("declared types differ"), "{reason}");
}

/// Objects carrying a text state beside their archive flag.
fn objects_with_state(test: &str) -> String {
    with_body(
        &OBJECTS.replace(
            "archived BOOLEAN NOT NULL DEFAULT false",
            "archived BOOLEAN NOT NULL DEFAULT false, state TEXT NOT NULL",
        ),
        &format!(
            "SELECT EXISTS (SELECT 1 FROM public.objects object
                            WHERE object.id = resource AND {test})"
        ),
    )
}

const NEGATED_KEYED: &str = "CREATE POLICY archived ON objects AS RESTRICTIVE FOR SELECT
  USING (NOT authz.is_archived(id));";

#[test]
fn a_flag_tested_with_is_true_reads_as_the_bare_column() {
    let dsl = archive_model(
        &objects_with_state("object.archived IS TRUE"),
        NEGATED_KEYED,
    );
    let (gate, _) = relation_named_like(&dsl, "objects", "public_where_archived_");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(format!("(owner but not {gate}) and acting_app_user from request_gate").as_str()),
        "{dsl}"
    );
}

#[test]
fn a_flag_testing_a_list_of_states_gates_on_the_list() {
    let dsl = archive_model(
        &objects_with_state("object.state IN ('closed', 'deleted')"),
        NEGATED_KEYED,
    );
    let (gate, _) = relation_named_like(&dsl, "objects", "public_where_state_");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(format!("(owner but not {gate}) and acting_app_user from request_gate").as_str()),
        "{dsl}"
    );
}

/// Two tests on the flagged row hold together, so the flag is the intersection of both
/// gates.
#[test]
fn a_flag_testing_two_columns_subtracts_rows_passing_both() {
    let dsl = archive_model(
        &objects_with_state("object.archived AND object.state = 'closed'"),
        NEGATED_KEYED,
    );
    let (archived, _) = relation_named_like(&dsl, "objects", "public_where_archived_");
    let (closed, _) = relation_named_like(&dsl, "objects", "public_where_state_");
    let (flag, definition) = relation_named_like(&dsl, "objects", "flag_archived_");
    assert_eq!(definition, format!("{archived} and {closed}"), "{dsl}");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(format!("(owner but not {flag}) and acting_app_user from request_gate").as_str()),
        "{dsl}"
    );
}

#[test]
fn a_flag_testing_a_comparison_with_is_true_is_refused() {
    let reason = refusal_of(
        &format!(
            "{}{NEGATED_KEYED}",
            objects_with_state("(object.state = 'closed') IS TRUE")
        ),
        &[],
        "archived",
    );
    assert!(!reason.contains("negation cannot be expressed"), "{reason}");
}

/// `owner OR NOT flagged` admits the owner's rows and every row not flagged.
#[test]
fn a_negated_flag_inside_an_or_grants_every_row_but_the_flagged_ones() {
    let dsl = archive_model(
        OBJECTS,
        "CREATE POLICY live ON objects AS RESTRICTIVE FOR SELECT
           USING (owner_id = current_setting('app.user_id', true) OR NOT authz.is_archived(id));",
    );
    let (gate, _) = relation_named_like(&dsl, "objects", "public_where_archived_");
    assert_eq!(
        relation_definition(&dsl, "objects", "can_select").as_deref(),
        Some(
            format!(
                "owner and (owner or (public_viewer but not {gate})) and acting_app_user from \
                 request_gate"
            )
            .as_str()
        ),
        "{dsl}"
    );
}

/// The report names the flag, the edges it climbs and the key it reads alone, and warns
/// of the walk's depth.
#[test]
fn the_report_names_the_flag_and_the_walk_depth() {
    let report_of = |schema: String| {
        translator(ConfidenceLevel::B, &[])
            .translate(&db_of(&schema))
            .expect("the schema should plan")
            .outputs()
            .expect("every clause should translate")
            .report()
    };
    let walked = report_of(format!("{RESOURCES}{NEGATED_WALK}"));
    assert!(
        walked.contains(
            "P29 (public.resources flagged at id or above it through \
             public.resource_parents.parent_id, public.ownables.project_id)"
        ),
        "{walked}"
    );
    assert!(walked.contains("resolveNodeLimit"), "{walked}");
    let keyed = report_of(format!("{OBJECTS}{NEGATED_KEYED}"));
    assert!(
        keyed.contains("P29 (public.objects flagged at id)"),
        "{keyed}"
    );
}

/// `NOT (flag IS TRUE)` shows a row whose `STRICT` flag is `NULL`, which `NOT flag` hides,
/// so it is no subtraction of the flag, and the refusal says how to spell one.
#[test]
fn a_negated_flag_under_is_true_is_refused_without_ruling_out_negation() {
    let reason = refusal_of(
        &format!(
            "{OBJECTS}CREATE POLICY archived ON objects AS RESTRICTIVE FOR SELECT
               USING (NOT (authz.is_archived(id) IS TRUE));"
        ),
        &[],
        "archived",
    );
    assert!(!reason.contains("negation cannot be expressed"), "{reason}");
    assert!(reason.contains("row flag"), "{reason}");
}

/// A chain of helpers longer than one clause's expansion budget is refused, never followed
/// until the stack runs out.
#[test]
fn a_flag_behind_too_many_helpers_is_refused() {
    let chain = (0..70)
        .map(|at| {
            format!(
                "CREATE FUNCTION authz.hop{at}(resource TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
                 AS $$ SELECT authz.hop{}(resource) $$;",
                at + 1
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let reason = refusal_of(
        &format!(
            "{OBJECTS}{chain}
             CREATE FUNCTION authz.hop70(resource TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
             AS $$ SELECT authz.is_archived(resource) $$;
             CREATE POLICY archived ON objects AS RESTRICTIVE FOR SELECT
               USING (NOT authz.hop0(id));"
        ),
        &[],
        "archived",
    );
    assert!(reason.contains("expansion budget"), "{reason}");
}

/// A text literal compared with a `timestamptz` column reads in the loader session's time
/// zone, so the session, not the row, decides the flag.
#[test]
fn a_flag_comparing_a_zoned_column_with_text_is_refused() {
    let schema = with_body(
        &OBJECTS.replace(
            "archived BOOLEAN NOT NULL DEFAULT false",
            "archived BOOLEAN NOT NULL DEFAULT false, archived_at TIMESTAMPTZ",
        ),
        "SELECT EXISTS (SELECT 1 FROM public.objects object
                        WHERE object.id = resource AND object.archived_at < '2024-01-01')",
    );
    refusal_of(&format!("{schema}{NEGATED_KEYED}"), &[], "archived");
}

/// A key whose text form does not name its value apart keys two rows `PostgreSQL` finds
/// equal as two `OpenFGA` objects, or the reverse.
#[test]
fn a_flag_keyed_by_a_type_without_one_text_form_is_refused() {
    for (key, compared) in [
        ("CITEXT", "CITEXT"),
        ("REAL", "DOUBLE PRECISION"),
        ("NUMERIC", "NUMERIC"),
    ] {
        let reason = refusal_of(
            &format!(
                "CREATE EXTENSION citext;
                 CREATE TABLE objects (id {key} PRIMARY KEY, archived BOOLEAN NOT NULL);
                 CREATE TABLE notes (id TEXT PRIMARY KEY, object_id {compared} NOT NULL,
                   author_id TEXT NOT NULL);
                 ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY notes_author ON notes FOR SELECT
                   USING (author_id = current_setting('app.user_id', true));
                 CREATE POLICY notes_live ON notes AS RESTRICTIVE FOR SELECT USING (NOT EXISTS (
                   SELECT 1 FROM objects o WHERE o.id = notes.object_id AND o.archived));"
            ),
            &[],
            "notes_live",
        );
        assert!(reason.contains("objects.id"), "{key}: {reason}");
    }
}

/// A policy's own walk named after a table hides that table wherever a one-part name reads
/// it, the flagged scan and the edges alike.
#[test]
fn a_walk_hiding_a_table_is_never_read_as_that_table() {
    let schema = "
CREATE TABLE objects (id TEXT PRIMARY KEY, archived BOOLEAN NOT NULL);
CREATE TABLE edges (child_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL);
CREATE TABLE notes (id TEXT PRIMARY KEY, object_id TEXT NOT NULL, author_id TEXT NOT NULL);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_author ON notes FOR SELECT
  USING (author_id = current_setting('app.user_id', true));
";
    for walk in [
        "WITH RECURSIVE objects (id) AS (SELECT notes.object_id UNION
           SELECT e.parent_id FROM objects JOIN edges e ON e.child_id = objects.id)
         SELECT 1 FROM objects walk JOIN objects o ON o.id = walk.id WHERE o.id = 'root'",
        "WITH RECURSIVE edges (id) AS (SELECT notes.object_id UNION
           SELECT e.parent_id FROM edges JOIN edges e ON e.child_id = edges.id)
         SELECT 1 FROM edges JOIN objects o ON o.id = edges.id WHERE o.archived",
    ] {
        refusal_of(
            &format!(
                "{schema}CREATE POLICY notes_live ON notes AS RESTRICTIVE FOR SELECT
                   USING (NOT EXISTS ({walk}));"
            ),
            &[],
            "notes_live",
        );
    }
}

/// A flag over columns the deployment confirms as row attributes grades as the same test
/// on the guarded row does.
#[test]
fn a_flag_over_confirmed_attribute_columns_grades_a() {
    use rls2fga::classifier::function_registry::FunctionRegistry;
    use rls2fga::translator::TranslatorBuilder;

    use crate::support::deployment::{caller, deployment};

    let grades = |confirm: bool| {
        let mut registry = FunctionRegistry::new();
        if confirm {
            registry.register_attribute_column("objects", "archived");
        }
        TranslatorBuilder::new(deployment([caller("app.user_id")]))
            .with_registry(registry)
            .build()
            .classify(&db_of(&format!(
                "{OBJECTS}{NEGATED_KEYED}
                 CREATE POLICY archive_positive ON objects FOR SELECT
                   USING (authz.is_archived(id));"
            )))
            .into_iter()
            .filter(|policy| policy.name() != "objects_owner")
            .map(|policy| {
                (
                    policy.name().to_string(),
                    policy
                        .using_classification()
                        .expect("USING classifies")
                        .confidence,
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = |grade| {
        vec![
            ("archive_positive".to_string(), grade),
            ("archived".to_string(), grade),
        ]
    };
    assert_eq!(grades(true), expected(ConfidenceLevel::A));
    assert_eq!(grades(false), expected(ConfidenceLevel::B));
}
