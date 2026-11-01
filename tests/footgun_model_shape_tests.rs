//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Structural invariants every emitted model keeps.

use rls2fga::parser::sql_parser::ParserDB;
use rls2fga::types::ConfidenceLevel;

mod support;

use support::footgun::{
    assert_model_is_internally_consistent, db_of, feeds, overlength_name_schema,
    relation_definition, relation_definitions, subtracted_relations_on_the_object, translator,
    type_names,
};

/// The DSL and the JSON model are rendered from one plan, so they must describe
/// the same relations. A variant handled by only one renderer would let an
/// operator load a model that grants more than the `.fga` file they reviewed.
#[test]
fn json_model_declares_the_same_relations_as_the_dsl() {
    // Exercises collision renaming, role scoping, inheritance, a public flag, a
    // union, and a table present only as a deny-all.
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
CREATE TABLE aaa.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE aaa.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE zzz.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.projects FOR SELECT TO analyst USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES zzz.projects(id), is_public BOOLEAN);
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_all ON tasks FOR ALL USING (
  EXISTS (SELECT 1 FROM zzz.projects p
          WHERE p.id = tasks.project_id AND p.owner_id = current_user));
CREATE POLICY tasks_public ON tasks FOR SELECT USING (is_public = TRUE);
CREATE TABLE audit(id UUID PRIMARY KEY);
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let json = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();

    let mut from_dsl: Vec<String> = Vec::new();
    let mut current_type = String::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            current_type = name.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("define ") {
            if let Some((relation, _)) = rest.split_once(':') {
                from_dsl.push(format!("{current_type}#{}", relation.trim()));
            }
        }
    }

    let mut from_json: Vec<String> = json
        .type_definitions
        .iter()
        .flat_map(|definition| {
            definition
                .relations
                .iter()
                .flat_map(|relations| relations.keys())
                .map(|relation| format!("{}#{relation}", definition.type_name))
        })
        .collect();

    from_dsl.sort();
    from_json.sort();
    assert!(
        from_dsl.len() > 20,
        "expected a substantial model to compare, got {from_dsl:?}"
    );
    assert_eq!(from_dsl, from_json, "DSL and JSON must agree\n{dsl}");
}

/// `OpenFGA` refuses a model with a dangling reference, so every name a userset
/// reaches must exist.
#[test]
fn no_userset_references_an_undefined_relation() {
    let db = db_of(&overlength_name_schema(None));
    let json = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();

    assert_model_is_internally_consistent(&json);
}

/// Wildcards, a role scope and two levels of indirection still satisfy every rule
/// `OpenFGA` enforces on a write.
#[test]
fn a_layered_model_stays_internally_consistent() {
    let db = db_of(
        r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN);
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY orgs_own ON orgs FOR SELECT USING (owner_id = current_user);
CREATE POLICY orgs_pub ON orgs FOR SELECT USING (is_public = TRUE);
CREATE TABLE projects(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT TO analyst USING (
  EXISTS (SELECT 1 FROM orgs o WHERE o.id = projects.org_id AND o.owner_id = current_user));
CREATE TABLE members(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id), user_id UUID);
CREATE TABLE notes(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_sel ON notes FOR SELECT USING (
  EXISTS (SELECT 1 FROM members m WHERE m.project_id = notes.project_id
          AND m.user_id = current_user));
",
    );
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .json_model(),
    );
}

/// Two `define` lines for one relation make the DSL unparseable.
#[test]
fn no_type_defines_a_relation_twice() {
    let db = db_of(
        r"
CREATE TABLE teams(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
CREATE POLICY teams_sel ON teams FOR SELECT USING (owner_id = current_user);
CREATE TABLE docs(
  id UUID PRIMARY KEY,
  can_select_id UUID,
  no_access_id UUID,
  owner_id UUID,
  teams_id UUID,
  team_ref UUID REFERENCES teams(id)
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_a_reserved ON docs FOR SELECT USING (can_select_id = current_user);
CREATE POLICY docs_b_deny ON docs FOR UPDATE USING (no_access_id = current_user);
CREATE POLICY docs_c_owner ON docs FOR DELETE USING (owner_id = current_user);
CREATE POLICY docs_d_named ON docs FOR INSERT WITH CHECK (teams_id = current_user);
CREATE POLICY docs_e_parent ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM teams t WHERE t.id = docs.team_ref AND t.owner_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let mut current = String::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            current = name.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("define ") {
            let relation = rest.split_once(':').map_or(rest, |(name, _)| name).trim();
            assert!(
                seen.insert((current.clone(), relation.to_string())),
                "type {current} defines '{relation}' twice:\n{dsl}"
            );
        }
    }
    assert!(seen.len() > 8, "expected a populated model, got:\n{dsl}");
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .json_model(),
    );
}

/// A relation no permission can reach needs no tuple query.
#[test]
fn no_tuple_query_feeds_a_relation_no_permission_reaches() {
    let db = db_of(
        r"
CREATE TABLE t1(id INTEGER PRIMARY KEY, parent_id INTEGER, owner TEXT);
ALTER TABLE t1 ENABLE ROW LEVEL SECURITY;
CREATE POLICY t1_own ON t1 FOR SELECT USING (owner = current_user);
CREATE POLICY t1_tree ON t1 FOR SELECT USING (
  EXISTS (SELECT 1 FROM t1 p WHERE p.id = t1.parent_id AND p.owner = current_user));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    // The recursive policy makes every read fail.
    for action in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            relation_definition(&dsl, "t1", action).as_deref(),
            Some("no_access"),
            "{action} should deny for this schema:\n{dsl}"
        );
    }

    for query in translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries()
    {
        assert!(
            !query.sql.contains("AS relation"),
            "nothing can consult a t1 relation, so this query is dead:\n{}",
            query.sql
        );
    }
}

/// Walk every `Difference` in the model, yielding `(type, subtracted relation)`.
fn subtractions(
    json: &rls2fga::generator::json_model::AuthorizationModel,
) -> Vec<(String, String)> {
    use rls2fga::generator::json_model::Userset;

    fn walk(userset: &Userset, type_name: &str, out: &mut Vec<(String, String)>) {
        match userset {
            Userset::Difference { difference } => {
                let mut subtracted = std::collections::BTreeSet::new();
                subtracted_relations_on_the_object(&difference.subtract, &mut subtracted);
                out.extend(
                    subtracted
                        .into_iter()
                        .map(|relation| (type_name.to_string(), relation)),
                );
                walk(&difference.base, type_name, out);
                walk(&difference.subtract, type_name, out);
            }
            Userset::Union { union } => {
                for child in &union.child {
                    walk(child, type_name, out);
                }
            }
            Userset::Intersection { intersection } => {
                for child in &intersection.child {
                    walk(child, type_name, out);
                }
            }
            Userset::This { .. }
            | Userset::ComputedUserset { .. }
            | Userset::TupleToUserset { .. } => {}
        }
    }

    let mut out = Vec::new();
    for definition in &json.type_definitions {
        for (name, userset) in definition.relations.iter().flatten() {
            let _ = name;
            walk(userset, definition.type_name.as_str(), &mut out);
        }
    }
    out
}

/// On reconnect the consumer replays from an earlier point and reconstructs what a
/// row used to imply by supplying the previous version's records as extra context.
/// That is exact only while adding a record cannot revoke access. Union and
/// intersection preserve it, exclusion does not, so nothing an exclusion subtracts
/// may depend on the object's own column values.
///
/// Holds today: the one exclusion the generator emits subtracts `member` reached
/// through a role scope, whose tuple names a literal role and exists for every row
/// of the table regardless of its values.
#[test]
fn no_exclusion_subtracts_anything_derived_from_the_object_row() {
    use rls2fga::types::{Guard, RecordDerivation, ValueSource};

    let mut checked = 0;
    for schema in exclusion_emitting_schemas() {
        let db = db_of(&schema);
        let translator = translator(ConfidenceLevel::B);
        let json = translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .json_model();
        let outputs = translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let queries = outputs.tuple_queries();

        for (type_name, relation) in subtractions(&json) {
            checked += 1;
            for query in queries {
                let Some(description) = &query.description else {
                    continue;
                };
                let RecordDerivation::FromRow {
                    template, guards, ..
                } = &description.derivation
                else {
                    // A joining source reads a second table, so a change there could
                    // withdraw the subtraction without the row changing at all.
                    assert!(
                        !feeds(description, &type_name, &relation),
                        "{type_name}#{relation} is subtracted yet fed by a joining source: {}",
                        query.comment
                    );
                    continue;
                };
                if template.object_type != type_name || template.relation != relation {
                    continue;
                }

                assert!(
                    matches!(template.subject_key.part(), &ValueSource::Literal(_)),
                    "{type_name}#{relation} is subtracted, so its subject may not come \
                 from the row: {:?} in {}",
                    template.subject_key,
                    query.comment
                );
                let identity = match template.object_key.parts() {
                    [ValueSource::Column(column)] => column.clone(),
                    other => panic!("an object key is one column, got {other:?}"),
                };
                for guard in guards {
                    assert!(
                        matches!(guard, Guard::NotNull(column) if column == &identity),
                        "{type_name}#{relation} is subtracted, so no row value may decide \
                     whether its tuple exists: {guard:?} in {}",
                        query.comment
                    );
                }
            }
        }
    }

    assert!(
        checked >= 2,
        "the corpus must actually emit exclusions, checked {checked}"
    );
}

/// Schemas whose emitted model contains an exclusion. A RESTRICTIVE policy bound to
/// a role is the only shape that produces one today.
///
/// The fixture corpus emits none at the default threshold: `role_scoped_restrictive`
/// carries a RESTRICTIVE policy that falls below it and so falls closed instead,
/// which is why these are written here rather than read from a fixture.
fn exclusion_emitting_schemas() -> Vec<String> {
    vec![
        "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN NOT NULL DEFAULT FALSE);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_public ON docs FOR SELECT USING (is_public = TRUE);
CREATE POLICY docs_barrier ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (owner_id = current_user);
"
        .to_string(),
        // Two barriers, so the outer exclusion subtracts a scope while its base
        // already contains one.
        "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, is_public BOOLEAN NOT NULL DEFAULT FALSE);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_public ON docs FOR SELECT USING (is_public = TRUE);
CREATE POLICY docs_contractor ON docs AS RESTRICTIVE FOR SELECT TO contractor
  USING (owner_id = current_user);
CREATE POLICY docs_auditor ON docs AS RESTRICTIVE FOR SELECT TO auditor
  USING (owner_id = current_user);
"
        .to_string(),
    ]
}

/// Does `relation`'s transitive expansion on `type_name` cross a type boundary or
/// subtract anything? Both make a relation undecidable from one row, and both are
/// visible in the emitted model without consulting the analysis under test.
fn expansion_leaves_the_row(
    json: &rls2fga::generator::json_model::AuthorizationModel,
    type_name: &str,
    relation: &str,
    seen: &mut std::collections::BTreeSet<String>,
) -> bool {
    use rls2fga::generator::json_model::Userset;

    fn walk(
        json: &rls2fga::generator::json_model::AuthorizationModel,
        type_name: &str,
        userset: &Userset,
        seen: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        match userset {
            Userset::This { .. } => false,
            Userset::ComputedUserset { computed_userset } => {
                expansion_leaves_the_row(json, type_name, computed_userset.relation.as_str(), seen)
            }
            Userset::TupleToUserset { .. } | Userset::Difference { .. } => true,
            Userset::Union { union } => union
                .child
                .iter()
                .any(|child| walk(json, type_name, child, seen)),
            Userset::Intersection { intersection } => intersection
                .child
                .iter()
                .any(|child| walk(json, type_name, child, seen)),
        }
    }

    if !seen.insert(format!("{type_name}#{relation}")) {
        // A cycle is not a boundary crossing by itself.
        return false;
    }
    json.type_definitions
        .iter()
        .filter(|definition| definition.type_name.as_str() == type_name)
        .filter_map(|definition| definition.relations.as_ref())
        .filter_map(|relations| relations.get(relation))
        .any(|userset| walk(json, type_name, userset, seen))
}

/// A wrongly true flag grants access no policy granted, so the test asserts that
/// direction: nothing flagged decidable may cross a type boundary, subtract, or take
/// its records from a table other than the one keying the object.
#[test]
fn no_relation_is_flagged_decidable_that_leaves_its_own_row() {
    use rls2fga::types::{RecordDerivation, ValueSource};

    let registry_json =
        r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#;
    let (mut trues, mut falses) = (0, 0);

    for schema in decidability_schemas() {
        let (classified, db, registry) = support_classify(&schema, registry_json);
        // The same classification the analysis reads, or the test inspects a model
        // the analysis never saw. Building it through a registry-less translator was
        // exactly that mistake: the analysis saw `member from docs` while the model
        // said `no_access`, and a wrongly true flag passed unnoticed.
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        let shapes = planned.translation().relations();
        let json = planned.json_model();
        let queries = planned.tuple_queries();
        for row in shapes {
            if !row.from_one_row {
                falses += 1;
                continue;
            }
            trues += 1;

            let mut seen = std::collections::BTreeSet::new();
            assert!(
                !expansion_leaves_the_row(
                    &json,
                    row.type_name.as_str(),
                    row.relation.as_str(),
                    &mut seen
                ),
                "{}#{} is flagged decidable yet its expansion crosses a type boundary \
                 or subtracts",
                row.type_name,
                row.relation
            );

            // Every source feeding it must read one table, key the object by that
            // table's own primary key, and name a user from the row. A record keyed
            // by a foreign column describes a different object, which a change to
            // this row does not own.
            let mut tables = std::collections::BTreeSet::new();
            for query in queries {
                let Some(description) = &query.description else {
                    continue;
                };
                let RecordDerivation::FromRow {
                    table, template, ..
                } = &description.derivation
                else {
                    continue;
                };
                if row.type_name != template.object_type || template.relation != row.relation {
                    continue;
                }
                tables.insert(table.clone());
                // The typed wildcard grants every user, which the row decides through
                // the record's existence alone.
                assert!(
                    template.subject_key.is_wildcard()
                        || !matches!(template.subject_key.part(), &ValueSource::Literal(_)),
                    "{}#{} is flagged decidable yet its subject is a literal: {}",
                    row.type_name,
                    row.relation,
                    query.comment
                );
                let [ValueSource::Column(object_column)] = template.object_key.parts() else {
                    panic!("an object key is one column, got {:?}", template.object_key);
                };
                assert_eq!(
                    Some(object_column.as_str()),
                    primary_key_of(&db, &table.to_string()).as_deref(),
                    "{}#{} is flagged decidable yet its object is keyed by a column that \
                 is not {table}'s primary key: {}",
                    row.type_name,
                    row.relation,
                    query.comment
                );
            }
            assert!(
                tables.len() <= 1,
                "{}#{} is flagged decidable yet its records come from {tables:?}",
                row.type_name,
                row.relation
            );
        }
    }
    assert!(
        trues >= 4,
        "the corpus must contain decidable relations or the direction is untested, saw {trues}"
    );
    assert!(
        falses >= 4,
        "and undecidable ones, or the analysis is answering true for everything, saw {falses}"
    );
}

/// The single-column primary key of `table`, through the public schema accessors.
fn primary_key_of(db: &ParserDB, table: &str) -> Option<String> {
    use rls2fga::parser::names::lookup_table;
    use rls2fga::parser::sql_parser::{ColumnLike, TableLike};

    lookup_table(db, table)?
        .primary_key_column(db)
        .ok()
        .flatten()
        .map(|column| column.column_name().to_string())
}

/// Classify `sql` with a registry, mirroring what the container tests do.
fn support_classify(
    sql: &str,
    registry_json: &str,
) -> (
    Vec<rls2fga::classifier::patterns::ClassifiedPolicy>,
    ParserDB,
    rls2fga::classifier::function_registry::FunctionRegistry,
) {
    let db = db_of(sql);
    let mut registry = rls2fga::classifier::function_registry::FunctionRegistry::new();
    registry
        .load_from_json(registry_json)
        .expect("the registry parses");
    let classified = rls2fga::classifier::policy_classifier::classify_policies(&db, &registry);
    (classified, db, registry)
}

/// Schemas covering both answers: ownership and list membership resolve from the row
/// to a user, while a flag, a membership table, a parent link and a role scope do not.
///
/// The last two matter for the direction that counts. In the first schema every
/// action relation also unions the wildcard, which makes it undecidable whatever the
/// analysis says about the other children, so a rule wrongly reporting a type
/// boundary as decidable would stay invisible. A table whose only policy is a
/// membership subquery, and one whose only policy inherits from a parent, each give
/// an action relation that is nothing but a tuple-to-userset.
fn decidability_schemas() -> Vec<String> {
    let mut schemas = vec![
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE notes (id TEXT PRIMARY KEY, folder_id TEXT REFERENCES folders(id), owner_id TEXT,
                    editors TEXT[], meta JSONB, is_public BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE note_members (note_id TEXT REFERENCES notes(id), user_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_owner ON folders FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY notes_owner ON notes FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY notes_editors ON notes FOR SELECT USING (auth_current_user_id() = ANY (editors));
CREATE POLICY notes_meta ON notes FOR SELECT
    USING (meta ->> 'owner_id' = auth_current_user_id());
CREATE POLICY notes_public ON notes FOR SELECT USING (is_public = TRUE);
CREATE POLICY notes_members ON notes FOR SELECT USING (EXISTS (
    SELECT 1 FROM note_members WHERE note_members.note_id = notes.id
      AND note_members.user_id = auth_current_user_id()));
"
        .to_string(),
        // Membership alone: `can_select` is exactly `member from notes`.
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY);
-- A primary key of its own, so nothing but the object key being a foreign
-- column can decide this shape is undecidable.
CREATE TABLE doc_members (id TEXT PRIMARY KEY, doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (EXISTS (
    SELECT 1 FROM doc_members WHERE doc_members.doc_id = docs.id
      AND doc_members.user_id = auth_current_user_id()));
"
        .to_string(),
        // Parent inheritance alone: `can_select` is exactly `owner from projects`.
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE projects (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE tasks (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_own ON projects FOR SELECT
    USING (owner_id = auth_current_user_id());
CREATE POLICY tasks_inherit ON tasks FOR SELECT USING (EXISTS (
    SELECT 1 FROM projects p WHERE p.id = tasks.project_id
      AND p.owner_id = auth_current_user_id()));
"
        .to_string(),
    ];
    schemas.extend(exclusion_emitting_schemas());
    schemas
}

/// A relation nothing names is declared, receives no tuple query, and can never be
/// granted, so the model advertises access it cannot give.
///
/// The plan asked for the pruned set to equal the set the tuple side skips. It cannot:
/// the tuple side also skips a relation only a denying permission names, and dropping
/// that one would leave the model referring to something it does not define. The
/// property that does hold, and is the one worth keeping, is the other direction, so
/// this asserts both that nothing unnamed survives and that nothing named was taken.
#[test]
fn no_type_declares_a_relation_no_permission_names() {
    let mut cases: Vec<(String, Option<String>)> = decidability_schemas()
        .into_iter()
        .map(|schema| (schema, None))
        .collect();
    // The role hierarchy is the shape that produced orphans: `can_select` inlines it,
    // and its own relations then name nothing.
    cases.push((
        std::fs::read_to_string("tests/fixtures/role_in_list/input.sql")
            .expect("the role_in_list fixture should exist"),
        Some(
            std::fs::read_to_string("tests/fixtures/role_in_list/function_registry.json")
                .expect("the role_in_list registry should exist"),
        ),
    ));

    for (schema, registry_json) in &cases {
        let db = db_of(schema);
        let mut registry = rls2fga::classifier::function_registry::FunctionRegistry::new();
        if let Some(json) = registry_json {
            registry.load_from_json(json).expect("registry parses");
        }
        let classified = rls2fga::classifier::policy_classifier::classify_policies(&db, &registry);
        let dsl = support::plan_at(classified, &db, &registry, ConfidenceLevel::B).model();
        // Not `assert_model_is_internally_consistent` here: its tupleset-assignability
        // rule is stricter than `OpenFGA` v1.11.6, which accepts this fixture's model
        // in the `P2_role_in_list` container scenario. Pruning too much would show up
        // there and in every parity case.
        let named = relation_names_definitions_use(&dsl);
        for relation in defined_relation_names(&dsl) {
            assert!(
                relation.starts_with("can_") || named.contains(&relation),
                "`{relation}` is declared and no definition names it:\n{dsl}"
            );
        }
    }
}

/// Every relation the DSL declares, across every type.
fn defined_relation_names(dsl: &str) -> Vec<String> {
    dsl.lines()
        .filter_map(|line| line.trim().strip_prefix("define "))
        .filter_map(|rest| rest.split_once(':'))
        .map(|(name, _)| name.trim().to_string())
        .collect()
}

/// Every name a definition body mentions. Loose across types on purpose: a relation
/// reached through a tuple-to-userset is named from the type that walks to it.
fn relation_names_definitions_use(dsl: &str) -> std::collections::BTreeSet<String> {
    dsl.lines()
        .filter_map(|line| line.trim().strip_prefix("define "))
        .filter_map(|rest| rest.split_once(':'))
        .flat_map(|(_, body)| {
            body.split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|token| !token.is_empty())
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
        .collect()
}

/// The denial admits a type no caller is, so no fact can make it grant.
///
/// Pointed at `user`, the relation held for whoever a fact said it held for, and v1.11.6
/// accepts such a write: probed, one hand-written tuple turned `can_insert` from denied
/// into allowed. The type declares no relation of its own, so an object of it reaches
/// nothing either.
#[test]
fn the_denial_admits_nobody_and_nobody_reaches_nothing() {
    let db = db_of(
        r"
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    // The companion half: the commands no policy covers really are denied here, so the
    // relation under test is load bearing rather than absent.
    for command in ["can_insert", "can_update", "can_delete"] {
        assert_eq!(
            relation_definition(&dsl, "docs", command).as_deref(),
            Some("no_access"),
            "{command} has no policy, so it denies:\n{dsl}"
        );
    }
    assert_eq!(
        relation_definition(&dsl, "docs", "no_access").as_deref(),
        Some("[nobody]"),
        "a denial admitting a person is a denial a fact can lift:\n{dsl}"
    );
    assert!(
        type_names(&dsl).iter().any(|name| name == "nobody"),
        "the model has to declare the type it denies through:\n{dsl}"
    );
    assert!(
        relation_definitions(&dsl, "nobody").is_empty(),
        "nobody reaches nothing, or an object of it would carry access:\n{dsl}"
    );
}

/// Every fixture's model must satisfy the same structural invariants the hand-picked
/// shapes are checked against, since a dangling reference makes `OpenFGA` refuse the write.
#[test]
fn every_fixture_model_is_internally_consistent() {
    let names = support::fixture_names();
    for fixture in &names {
        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);
        assert_model_is_internally_consistent(&outputs.json_model());
    }
}

/// Row security off on one table must not leave a reference to a type nothing declares,
/// which is how a delegation to an unrestricted parent escaped every other check.
#[test]
fn every_fixture_stays_consistent_without_one_row_security_flag() {
    for fixture in support::fixture_names() {
        let sql = support::read_fixture_sql(&fixture);
        let flags: Vec<usize> = sql
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                line.to_ascii_uppercase()
                    .contains("ENABLE ROW LEVEL SECURITY")
            })
            .map(|(index, _)| index)
            .collect();
        for dropped in flags {
            let mut variant = String::with_capacity(sql.len());
            for (_, line) in sql
                .lines()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
            {
                variant.push_str(line);
                variant.push('\n');
            }
            let Ok(db) = rls2fga::parser::sql_parser::parse_schema(&variant) else {
                continue;
            };
            let registry = support::try_load_fixture_classified(&fixture).2;
            let classified =
                rls2fga::classifier::policy_classifier::classify_policies(&db, &registry);
            let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::D);
            assert_model_is_internally_consistent(&outputs.json_model());
        }
    }
}
