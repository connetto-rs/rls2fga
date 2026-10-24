//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! The names the model assigns, and the collisions it has to survive.

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::generator::well_known::{
    WellKnownTypes, WellKnownTypesError, NOBODY_TYPE, PG_ROLE_SCOPE_TYPE, PG_ROLE_TYPE,
    REQUEST_GATE_TYPE, TEAM_TYPE, USER_TYPE,
};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;

mod support;

use support::footgun::{
    assert_model_is_internally_consistent, db_of, docs_read_definition, is_structural_type,
    relation_definition, relation_definitions, translator, tuples_reading_from, type_names,
};

const COLLIDING_SCHEMAS: &str = r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_docs_sel ON app.docs FOR SELECT USING (owner_id = current_user);
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY public_docs_sel ON public.docs FOR SELECT USING (owner_id = current_user);
";

/// `app.docs` and `public.docs` both canonicalize to `docs`, so the second type
/// is renamed. Emitting its rows as `docs:<id>` would grant a `public.docs` owner
/// access to the `app.docs` row with the same key.
#[test]
fn disambiguated_type_receives_tuples_under_its_own_type_name() {
    let db = db_of(COLLIDING_SCHEMAS);
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "docs" && name.starts_with("docs"))
        .expect("collision should produce a renamed second type");

    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();
    assert_eq!(
        tuples.len(),
        2,
        "each colliding table needs its own ownership query, got: {tuples:#?}"
    );

    for (from_clause, expected_type) in [
        (r#"FROM "app"."docs""#, "docs"),
        (r#"FROM "public"."docs""#, renamed.as_str()),
    ] {
        let matching = tuples_reading_from(tuples, from_clause);
        let [sql] = matching.as_slice() else {
            panic!("expected exactly one query reading {from_clause}, got: {matching:#?}");
        };
        assert!(
            sql.contains(&format!("'{expected_type}:'")),
            "query reading {from_clause} must emit '{expected_type}:' objects, got:\n{sql}"
        );
    }
}

/// A type without tuples can never be satisfied, so its policy is never enforced.
#[test]
fn disambiguated_type_is_not_left_without_tuples() {
    let db = db_of(COLLIDING_SCHEMAS);
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();
    let rendered = format_tuples(tuples);

    for type_name in type_names(&dsl) {
        if is_structural_type(&type_name) {
            continue;
        }
        assert!(
            rendered.contains(&format!("'{type_name}:'")),
            "type '{type_name}' has no tuple query, so its relations can never be populated:\n{rendered}"
        );
    }
}

/// The generator refers to its own structural relations by name, so a table
/// named after one must not take it on a type that also needs it. Holding
/// `no_access` turns every denied action into a granted parent link.
#[test]
fn a_table_named_after_a_structural_relation_does_not_take_it() {
    for reserved in [
        "no_access",
        "public_viewer",
        "member",
        "owner_user",
        "owner_team",
    ] {
        let db = db_of(&format!(
            "
CREATE TABLE {reserved}(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE {reserved} ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_sel ON {reserved} FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, parent_id UUID REFERENCES {reserved}(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM {reserved} p
          WHERE p.id = tasks.parent_id AND p.owner_id = current_user));
"
        ));
        let dsl = translator(ConfidenceLevel::A)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model();

        assert_ne!(
            relation_definition(&dsl, "tasks", reserved).as_deref(),
            Some(format!("[{reserved}]").as_str()),
            "the parent link took the structural relation '{reserved}':\n{dsl}"
        );
    }
}

/// The generator assembles an action from relations it names, so a column whose
/// relation would take one of those names leaves it defined twice and pointing at
/// itself.
#[test]
fn a_column_named_after_an_action_relation_does_not_take_it() {
    for reserved in [
        "can_select",
        "can_insert",
        "can_update",
        "can_delete",
        "can_update_using",
        "can_update_check",
        "can_insert_returning",
        "can_upsert",
        "can_select_for_update",
    ] {
        let db = db_of(&format!(
            "
CREATE TABLE docs(id UUID PRIMARY KEY, {reserved}_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING ({reserved}_id = current_user);
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING ({reserved}_id = current_user)
  WITH CHECK (editor_id = current_user);
"
        ));
        let dsl = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model();

        let defined = relation_definitions(&dsl, "docs");
        let mut names: Vec<&str> = defined.iter().map(|(name, _)| name.as_str()).collect();
        let declared = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            declared,
            names.len(),
            "a column named '{reserved}_id' took the action relation:\n{dsl}"
        );
        for (name, body) in &defined {
            assert!(
                !body.split_whitespace().any(|token| token == name),
                "'{name}' is defined as itself:\n{dsl}"
            );
        }
    }
}

/// Two policies on one table may spell its name differently. Grouping them by that
/// spelling builds the table twice, and the second group's actions overwrite the
/// first, so a RESTRICTIVE barrier can disappear.
#[test]
fn policies_compose_however_each_one_spells_the_table() {
    let schema = |restrictive_on: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);\n\
             CREATE POLICY docs_reviewed ON {restrictive_on} AS RESTRICTIVE FOR SELECT\n\
               USING (reviewer_id = current_user);\n"
        )
    };
    let read_of = |restrictive_on: &str| docs_read_definition(&schema(restrictive_on));

    assert_eq!(
        read_of("docs").as_deref(),
        Some("owner and reviewer"),
        "the bare spelling must keep the barrier, or this comparison proves nothing"
    );
    assert_eq!(
        read_of("\"docs\"").as_deref(),
        Some("owner and reviewer"),
        "quoting the table in the RESTRICTIVE policy must not drop it"
    );
}

/// `PostgreSQL` resolves an unqualified table reference through the search path, so a
/// policy may name a table in another schema without qualifying it. Leaving it
/// unresolved drops the policy and denies what RLS grants.
#[test]
fn a_policy_naming_its_table_without_the_schema_still_translates() {
    let db = db_of(
        r"
CREATE SCHEMA app;
SET search_path TO app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the policy names the table the search path resolves:\n{dsl}"
    );
    assert!(
        !tuples_reading_from(
            translator
                .translate(&db)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .tuple_queries(),
            r#""docs""#
        )
        .is_empty(),
        "the ownership relation needs its rows"
    );
}

/// Two schemas may hold a table of the same name, and the search path decides which one
/// an unqualified policy means: the first entry holding it wins, which is what
/// `PostgreSQL` does. Guessing the other one binds the policy to the wrong rows.
#[test]
fn a_policy_naming_a_table_two_schemas_hold_follows_the_search_path() {
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
SET search_path TO aaa, public;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = model.model();

    let reads: Vec<(String, Option<String>)> = type_names(&dsl)
        .into_iter()
        .filter(|name| name != "user")
        .map(|name| {
            let definition = relation_definition(&dsl, &name, "can_select");
            (name, definition)
        })
        .collect();

    assert_eq!(
        reads
            .iter()
            .filter(|(_, definition)| definition.as_deref() == Some("owner"))
            .count(),
        1,
        "exactly one of the two tables carries the policy:\n{dsl}"
    );
    assert_eq!(
        reads
            .iter()
            .filter(|(_, definition)| definition.as_deref() == Some("no_access"))
            .count(),
        1,
        "the table the path does not select must read nothing:\n{dsl}"
    );

    // The policy resolves to `aaa.docs`, and a table carrying a policy claims the
    // canonical type name, so the untouched `public.docs` is the renamed one.
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the first path entry holding the name wins:\n{dsl}"
    );
}

/// A policy may name its table without the schema. Matching that spelling against the
/// schema qualified name as text tells the operator RLS denies a command that its own
/// policy grants.
#[test]
fn a_filtered_policy_named_without_its_schema_is_reported_as_filtered() {
    let db = db_of(
        r"
CREATE SCHEMA app;
SET search_path TO app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, tenant TEXT);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (tenant = current_setting('app.tenant'));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        model.notes().iter().any(|note| {
            note.message()
                .contains("fell below the confidence threshold")
                && note.message().contains("SELECT")
        }),
        "the dropped SELECT policy must be reported as dropped, got {:#?}",
        model.notes()
    );
    assert!(
        !model.notes().iter().any(|note| {
            note.message().contains("No permissive policy") && note.message().contains("SELECT")
        }),
        "a policy PostgreSQL applies must not be reported as absent, got {:#?}",
        model.notes()
    );
}

/// A table that only appears as a deny-all must not take the canonical name from
/// a table with real policies: enabling RLS on an unrelated empty table would
/// otherwise rename a type whose tuples are already loaded.
#[test]
fn deny_only_table_does_not_take_the_name_of_a_table_with_policies() {
    let db = db_of(
        r"
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the table with policies keeps the canonical name:\n{dsl}"
    );
    let renamed = type_names(&dsl)
        .into_iter()
        .find(|name| name != "docs" && name.starts_with("docs"))
        .expect("the deny-all table should be the renamed one");
    assert_eq!(
        relation_definition(&dsl, &renamed, "can_select").as_deref(),
        Some("no_access"),
        "the deny-all table is the one that gets renamed:\n{dsl}"
    );
}

/// Canonicalizing a quoted role can map it onto a different existing role, which
/// changes who the policy admits.
#[test]
fn pg_role_identifier_rewrite_is_reported() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT TO "billing admin" USING (owner_id = current_user);
"#,
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.message().contains("billing admin")
                && note.message().contains("billing_admin")),
        "the role-name rewrite must name both the original and the OpenFGA identifier, got: {:#?}",
        model.notes()
    );
}

/// Each ownership column is a distinct relationship. Collapsing two of them into
/// one relation unions their subjects, so a policy that only admits `owner_id`
/// starts admitting everyone named by the other column.
#[test]
fn distinct_ownership_columns_get_distinct_relations() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (editor_id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let select =
        relation_definition(&dsl, "docs", "can_select").expect("docs should define can_select");
    let update =
        relation_definition(&dsl, "docs", "can_update").expect("docs should define can_update");
    assert_ne!(
        select, update,
        "SELECT admits owner_id and UPDATE admits editor_id, so they cannot share a relation:\n{dsl}"
    );

    // Every ownership query must populate the relation its own column feeds.
    for query in translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries()
    {
        // An action body may carry a trailing read gate.
        let leading = |body: &str| {
            body.split(" and ")
                .next()
                .unwrap_or(body)
                .trim()
                .to_string()
        };
        let column = if query.sql.contains(r#"|| "owner_id""#) {
            leading(&select)
        } else if query.sql.contains(r#"|| "editor_id""#) {
            leading(&update)
        } else {
            continue;
        };
        assert!(
            query.sql.contains(&format!("'{column}' AS relation")),
            "this query feeds the wrong relation, expected '{column}':\n{}",
            query.sql
        );
    }
}

/// `min_confidence` selects how much of a schema is translated. It must not
/// change what the types are called, or tuples loaded from one run stop matching
/// a model generated by another.
#[test]
fn type_names_do_not_depend_on_the_confidence_threshold() {
    let sql = r"
CREATE SCHEMA aaa;
CREATE SCHEMA zzz;
CREATE TABLE aaa.docs(id UUID PRIMARY KEY, tenant TEXT);
ALTER TABLE aaa.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY aaa_sel ON aaa.docs FOR SELECT USING (tenant = current_setting('app.tenant'));
CREATE TABLE zzz.docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE zzz.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY zzz_sel ON zzz.docs FOR SELECT USING (owner_id = current_user);
";
    let db = db_of(sql);
    let at_b = type_names(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model(),
    );
    let at_d = type_names(
        &translator(ConfidenceLevel::D)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model(),
    );

    assert_eq!(
        at_b, at_d,
        "the same schema must yield the same type names at every threshold"
    );
}

/// `OpenFGA` caps relation names at 50 characters and type names at 254. A longer
/// name is rejected when the model is written, which makes the whole artifact
/// unusable rather than just that relation.
#[test]
fn generated_names_respect_openfga_length_limits() {
    let long_column = "c".repeat(60);
    let long_table = "t".repeat(60);
    let long_parent = "p".repeat(60);
    let db = db_of(&format!(
        "CREATE TABLE {long_parent}(id UUID PRIMARY KEY, owner_id UUID);\n\
         ALTER TABLE {long_parent} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY parent_sel ON {long_parent} FOR SELECT USING (owner_id = current_user);\n\
         CREATE TABLE {long_table}(\n\
           id UUID PRIMARY KEY,\n\
           {long_column}_id UUID,\n\
           parent_ref UUID REFERENCES {long_parent}(id)\n\
         );\n\
         ALTER TABLE {long_table} ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY own_sel ON {long_table} FOR SELECT USING ({long_column}_id = current_user);\n\
         CREATE POLICY inherit_upd ON {long_table} FOR UPDATE TO some_long_reporting_role USING (\n\
           EXISTS (SELECT 1 FROM {long_parent} p\n\
                   WHERE p.id = {long_table}.parent_ref AND p.owner_id = current_user));\n"
    ));
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let mut relations = 0;
    let mut seen_types: Vec<&str> = Vec::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            let name = name.trim();
            assert!(
                name.chars().count() <= 254,
                "type '{name}' is {} characters, over the 254 limit",
                name.chars().count()
            );
            assert!(
                !seen_types.contains(&name),
                "type '{name}' is defined twice, which OpenFGA rejects:\n{dsl}"
            );
            seen_types.push(name);
        } else if let Some(rest) = trimmed.strip_prefix("define ") {
            let relation = rest.split_once(':').map_or(rest, |(name, _)| name).trim();
            relations += 1;
            assert!(
                relation.chars().count() <= 50,
                "relation '{relation}' is {} characters, over the 50 limit:\n{dsl}",
                relation.chars().count()
            );
        }
    }
    assert!(relations > 5, "expected a populated model, got:\n{dsl}");
}

/// Two schemas holding a table of the same name must not collapse into one type.
///
/// Collapsing them would let a policy on one answer for rows of the other, which is the
/// over-grant an earlier session traced to grouping policies by their raw spelling. The
/// `schema_search_path` fixture carries the shape: `app.docs` guarded by a policy that
/// names its table bare, `archive.docs` guarded by one that names it in full, and only
/// the search path says which `docs` the bare one means.
#[test]
fn two_schemas_holding_one_table_name_get_two_types() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/schema_search_path/input.sql")
            .expect("the fixture is readable"),
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let guarded: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| {
            relation_definition(&dsl, name, "can_select").as_deref() == Some("owner_login")
        })
        .collect();

    assert_eq!(
        guarded.len(),
        2,
        "each table keeps its own read rule, so two types carry it:\n{dsl}"
    );

    // The renaming has to be reported, or an operator loading tuples under the canonical
    // name feeds them to whichever table won it.
    let renamed = guarded
        .iter()
        .find(|name| *name != "docs")
        .expect("one of the two is renamed");
    assert!(
        translator(ConfidenceLevel::A)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .any(|note| note.message().contains(renamed.as_str())
                && note.message().contains("collision")),
        "the collision must be named, got {:#?}",
        translator(ConfidenceLevel::A)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .notes()
    );
}

/// A dump carries roles, grants, sequences, indexes, views, enums, domains, generated
/// columns, comments, an owner and a composite key. None of that is a policy, and the
/// translator has to walk past all of it and still read the policies that are there.
#[test]
fn the_furniture_of_a_real_schema_does_not_disturb_the_policies() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/schema_objects/input.sql")
            .expect("the fixture is readable"),
    );
    let outputs = translator(ConfidenceLevel::C)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select")
            .as_deref()
            .map(|d| d.contains("owner_login")),
        Some(true),
        "the ownership policy still reads its column:\n{dsl}"
    );

    // The owner the table was handed is exempt from every policy on it, and saying so is
    // the only way an operator learns the model is narrower than the database.
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("auditor") && note.message().contains("exempt")),
        "the exempt owner must be named, got {:#?}",
        outputs.notes()
    );

    // A key over two columns leaves no single-column object identifier, so the table it
    // keys cannot take one from somewhere else.
    assert!(
        type_names(&dsl).iter().any(|name| name == "doc_links"),
        "the composite-key table is still translated:\n{dsl}"
    );
}

fn reserved_type_collision_schema(table: &str) -> String {
    format!(
        "
CREATE TABLE {table}(id UUID PRIMARY KEY);
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
CREATE POLICY {table}_sel ON {table} FOR SELECT USING (TRUE);
"
    )
}

fn custom_well_known_types(setting: &str, replacement: &str) -> WellKnownTypes {
    WellKnownTypes::new(
        if setting == "user" {
            replacement
        } else {
            USER_TYPE
        },
        if setting == "team" {
            replacement
        } else {
            TEAM_TYPE
        },
        if setting == "pg_role" {
            replacement
        } else {
            PG_ROLE_TYPE
        },
        if setting == "pg_role_scope" {
            replacement
        } else {
            PG_ROLE_SCOPE_TYPE
        },
        if setting == "request_gate" {
            replacement
        } else {
            REQUEST_GATE_TYPE
        },
        if setting == "nobody" {
            replacement
        } else {
            NOBODY_TYPE
        },
    )
    .expect("the custom type name should be valid")
}

fn translator_with_types(names: WellKnownTypes) -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::A)
        .with_well_known_types(names)
        .build()
}

#[test]
fn invalid_configured_well_known_type_names_are_rejected_at_construction() {
    for name in [
        "",
        "self",
        "this",
        "1principal",
        "principal name",
        "principal..name",
        "principal-",
        "principal#name",
        "princ\u{ed}pal",
    ] {
        let result = WellKnownTypes::new(
            name,
            TEAM_TYPE,
            PG_ROLE_TYPE,
            PG_ROLE_SCOPE_TYPE,
            REQUEST_GATE_TYPE,
            NOBODY_TYPE,
        );
        assert!(
            matches!(result, Err(WellKnownTypesError::InvalidTypeName { .. })),
            "{name:?} must be rejected as an invalid type name"
        );
    }
}

#[test]
fn duplicate_configured_well_known_type_names_are_rejected_at_construction() {
    let result = WellKnownTypes::new(
        "principal",
        "principal",
        PG_ROLE_TYPE,
        PG_ROLE_SCOPE_TYPE,
        REQUEST_GATE_TYPE,
        NOBODY_TYPE,
    );
    assert!(matches!(
        result,
        Err(WellKnownTypesError::DuplicateTypeName {
            first_setting: "user",
            second_setting: "team",
            name,
        }) if name.as_str() == "principal"
    ));
}

#[test]
fn tables_cannot_take_configured_well_known_type_names() {
    for setting in ["user", "team", "pg_role", "pg_role_scope", "nobody"] {
        let db = db_of(&reserved_type_collision_schema(setting));
        let error = translator(ConfidenceLevel::A)
            .translate(&db)
            .expect_err("a table must not take a reserved type name");
        let message = error.to_string();
        assert!(
            message.contains(setting) && message.contains("well-known type"),
            "the refusal should name the table and setting, got {message}"
        );
    }
}

#[test]
fn renaming_the_well_known_type_releases_the_table_name() {
    for setting in ["user", "team", "pg_role", "pg_role_scope", "nobody"] {
        let db = db_of(&reserved_type_collision_schema(setting));
        let type_name = format!("configured_{setting}");
        let outputs = translator_with_types(custom_well_known_types(setting, &type_name))
            .translate(&db)
            .expect("renaming the reserved type should let the table translate")
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        assert!(
            type_names(&dsl).contains(&setting.to_string()),
            "the table should keep its own type after the configured name moves:\n{dsl}"
        );
    }
}

#[test]
fn a_schema_without_well_known_type_collisions_still_translates() {
    let db = db_of(&reserved_type_collision_schema("docs"));
    let outputs = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("unreserved table name should translate")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert!(
        type_names(&dsl).contains(&"docs".to_string()),
        "the ordinary table type should still exist:\n{dsl}"
    );
}

#[test]
fn well_known_names_have_a_single_source_of_truth() {
    let names = WellKnownTypes::new(
        "principal",
        "principal_group",
        "database_role",
        "database_role_scope",
        "request_check",
        "empty_principal",
    )
    .expect("custom type names should be valid");
    let mut rendered = String::new();
    for fixture in ["abac_status", "pg_role_gate", "role_threshold_compound_key"] {
        let sql = support::read_fixture_sql(fixture);
        let registry =
            std::fs::read_to_string(format!("tests/fixtures/{fixture}/function_registry.json"))
                .ok();
        let mut builder = TranslatorBuilder::new()
            .with_min_confidence(ConfidenceLevel::B)
            .with_well_known_types(names.clone());
        if let Some(registry) = registry {
            builder = builder
                .with_registry_json(&registry)
                .expect("fixture registry should parse");
        }
        let db = db_of(&sql);
        let translation = builder
            .build()
            .translate(&db)
            .expect("fixture should translate");
        if fixture == "role_threshold_compound_key" {
            let relations = translation.relations();
            let expected_team_type = format!("team_members_{}", names.team().as_str());
            assert!(
                relations
                    .iter()
                    .any(|entry| entry.type_name.as_str() == expected_team_type
                        && entry.relation.as_str() == "member"
                        && !entry.shapes.is_empty()),
                "the configured team type should carry the team membership source"
            );
        }
        let outputs = translation.outputs_accepting_gaps();
        rendered.push_str(&outputs.model());
        rendered.push_str(&format_tuples(outputs.tuple_queries()));
    }
    for expected in [
        names.user().as_str(),
        names.team().as_str(),
        names.pg_role().as_str(),
        names.pg_role_scope().as_str(),
        names.nobody().as_str(),
    ] {
        assert!(
            rendered.contains(expected),
            "custom type name {expected} should reach every output:\n{rendered}"
        );
    }
    for default in [
        "user",
        "team",
        "pg_role",
        "pg_role_scope",
        "request_gate",
        "nobody",
    ] {
        assert!(
            !rendered.contains(&format!("type {default}\n"))
                && !rendered.contains(&format!("'{default}:")),
            "default type name {default} leaked into custom output:\n{rendered}"
        );
    }
}

#[test]
fn valid_extended_well_known_type_name_keeps_its_exact_spelling() {
    let user = "Principal-Team/V2.member";
    let names = WellKnownTypes::new(
        user,
        TEAM_TYPE,
        PG_ROLE_TYPE,
        PG_ROLE_SCOPE_TYPE,
        REQUEST_GATE_TYPE,
        NOBODY_TYPE,
    )
    .expect("the extended identifier should be valid");
    assert_eq!(names.user().as_str(), user);

    let schema = reserved_type_collision_schema("docs");
    let db = db_of(&schema);
    let outputs = translator_with_types(names)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert!(outputs.model().contains(&format!("type {user}\n")));
    assert!(format_tuples(outputs.tuple_queries()).contains(&format!("'{user}:*'")));
}

#[test]
fn collision_suffixed_table_type_cannot_alias_a_configured_principal_type() {
    let db = db_of(COLLIDING_SCHEMAS);
    let names = custom_well_known_types("team", "docs_83297e85");
    let error = translator_with_types(names)
        .translate(&db)
        .expect_err("reserved suffixed type must be refused");
    let message = error.to_string();
    assert!(
        message.contains("docs_83297e85") && message.contains("well-known type"),
        "reserved collision not reported: {message}"
    );
}

#[test]
fn exhausted_ownership_relation_candidates_stay_distinct_across_commands() {
    let db = db_of(
        r#"
CREATE TABLE public.widgets(
    id UUID PRIMARY KEY,
    foo UUID,
    "owner_foo_iD" UUID,
    owner_foo_id_52ed0fe5 UUID,
    foo_id UUID
);
ALTER TABLE widgets ENABLE ROW LEVEL SECURITY;
CREATE POLICY sel_foo    ON widgets FOR SELECT USING (foo                    = current_user);
CREATE POLICY sel_owner  ON widgets FOR SELECT USING ("owner_foo_iD"         = current_user);
CREATE POLICY sel_hash   ON widgets FOR SELECT USING (owner_foo_id_52ed0fe5  = current_user);
CREATE POLICY upd_foo_id ON widgets FOR UPDATE USING (foo_id                 = current_user);
"#,
    );

    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let select_body =
        relation_definition(&dsl, "widgets", "can_select").expect("widgets must define can_select");
    let update_body =
        relation_definition(&dsl, "widgets", "can_update").expect("widgets must define can_update");

    let leading = |body: &str| -> String {
        body.split(" and ")
            .next()
            .unwrap_or(body)
            .trim()
            .to_string()
    };
    let update_relation = leading(&update_body);

    assert!(
        !select_body
            .split_whitespace()
            .any(|token| token == update_relation.as_str()),
        "update relation aliases select: {dsl}"
    );

    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();

    let query = tuples
        .iter()
        .find(|query| query.sql.contains(r#""foo_id"::text"#))
        .expect("foo_id tuple source");
    assert!(
        query
            .sql
            .contains(&format!("'{update_relation}' AS relation")),
        "foo_id populated the wrong relation: {}",
        query.sql
    );
}

#[test]
fn the_stable_suffix_has_one_public_implementation() {
    assert_eq!(rls2fga::stable_hex_suffix("rls2fga"), "b7b4bbb4");
    assert_eq!(
        rls2fga::stable_hex_suffix("rls2fga"),
        rls2fga::types::stable_hex_suffix("rls2fga")
    );
}

/// A table named after a reserved word is renamed, and the rename is a collision like
/// any other.
///
/// `self` and `t_self` canonicalize to different names and then to the same one, so the
/// disambiguation that catches `app.docs` beside `public.docs` has to catch this too.
/// Sharing the type would name a row of each table as one object.
#[test]
fn a_reserved_table_name_collides_with_the_name_it_is_renamed_to() {
    let db = db_of(
        r#"
CREATE TABLE "self"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE t_self(id TEXT PRIMARY KEY, editor_id TEXT);
ALTER TABLE "self" ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_self ENABLE ROW LEVEL SECURITY;
CREATE POLICY a ON "self" FOR SELECT USING (owner_id = current_user);
CREATE POLICY b ON t_self FOR SELECT USING (editor_id = current_user);
"#,
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_model_is_internally_consistent(&outputs.json_model());

    let named: Vec<String> = outputs
        .translation()
        .row_naming()
        .iter()
        .map(|naming| naming.type_name.to_string())
        .collect();
    let distinct: std::collections::BTreeSet<&String> = named.iter().collect();
    assert_eq!(
        distinct.len(),
        named.len(),
        "two tables share one type name, so their rows share one object: {named:?}"
    );
}

/// A parent whose name is reserved is referenced by the name its definition carries.
///
/// The bridge relation names the parent type, and a reference to a name the model never
/// declares is a model the service refuses.
#[test]
fn a_reserved_parent_type_is_referenced_by_the_name_it_is_defined_under() {
    let db = db_of(
        r#"
CREATE TABLE "self"(id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE docs(id TEXT PRIMARY KEY, parent_id TEXT REFERENCES "self"(id));
ALTER TABLE "self" ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY parent_owner ON "self" FOR SELECT USING (owner_id = current_user);
CREATE POLICY inherit ON docs FOR SELECT USING (EXISTS (
    SELECT 1 FROM "self" p WHERE p.id = docs.parent_id AND p.owner_id = current_user));
"#,
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_model_is_internally_consistent(&outputs.json_model());

    let declared = type_names(&outputs.model());
    for query in outputs.tuple_queries() {
        for named in query.sql.split('\'').filter(|piece| {
            piece.ends_with(':')
                && piece
                    .trim_end_matches(':')
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        }) {
            let type_name = named.trim_end_matches(':');
            if type_name.is_empty() || is_structural_type(type_name) {
                continue;
            }
            assert!(
                declared.iter().any(|name| name == type_name),
                "tuple SQL names objects of '{type_name}', which the model does not define: {}",
                query.sql
            );
        }
    }
}
