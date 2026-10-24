//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! How an identifier is spelled, and the name `PostgreSQL` stores it under.

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;

mod support;

use support::footgun::{db_of, docs_read_definition, relation_definition, translator, type_names};

/// A quoted identifier may contain a dot. Treating it as a schema separator names
/// the type after a fragment of the table name.
#[test]
fn quoted_dot_in_a_table_name_is_not_read_as_a_schema_separator() {
    let db = db_of(
        "CREATE TABLE \"we.ird\"(id UUID PRIMARY KEY);\n\
         ALTER TABLE \"we.ird\" ENABLE ROW LEVEL SECURITY;\n",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert!(
        type_names(&dsl).iter().any(|name| name == "we_ird"),
        "the type must derive from the whole quoted name, got: {:?}\n{dsl}",
        type_names(&dsl)
    );
}

/// A policy may spell the parent table quoted. Matching that spelling against the
/// declared foreign key as raw text loses the inheritance and tells the operator to
/// declare a foreign key the schema already has.
#[test]
fn a_quoted_parent_reference_still_inherits() {
    let schema = |parent_ref: &str| {
        format!(
            "CREATE TABLE parents(id UUID PRIMARY KEY, owner_id UUID);\n\
             ALTER TABLE parents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY parents_sel ON parents FOR SELECT USING (owner_id = current_user);\n\
             CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES parents(id));\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\n\
               SELECT 1 FROM {parent_ref} p\n\
               WHERE p.id = docs.parent_id AND p.owner_id = current_user));\n"
        )
    };
    let read_of = |parent_ref: &str| docs_read_definition(&schema(parent_ref));

    assert_eq!(
        read_of("parents").as_deref(),
        Some("owner from parents"),
        "the bare spelling must inherit, or this comparison proves nothing"
    );
    assert_eq!(
        read_of("\"parents\"").as_deref(),
        Some("owner from parents"),
        "quoting the parent table in the policy must not lose the inheritance"
    );
}

/// `PostgreSQL` folds an unquoted identifier to lowercase, so a table declared
/// `Docs` with a column `ID` is stored as `docs` and `id`. Emitting the source
/// spelling quoted asks for a relation and a column that do not exist.
#[test]
fn generated_sql_names_identifiers_the_way_postgres_stores_them() {
    let db = db_of(
        r"
CREATE TABLE public.Docs(ID UUID PRIMARY KEY, Owner_Id TEXT);
ALTER TABLE Docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON Docs FOR SELECT USING (owner_id = current_user);
",
    );
    let rendered = format_tuples(
        translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"FROM "public"."docs""#),
        "the stored relation name is docs:\n{rendered}"
    );
    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "the stored column name is id:\n{rendered}"
    );
    assert!(
        rendered.contains(r#""owner_id""#),
        "the stored column name is owner_id:\n{rendered}"
    );
}

/// A dotted column must not resolve as the table's ordinary identity column.
#[test]
fn generated_sql_does_not_split_dotted_column_names() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY, "docs.id" TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING ("docs.id" = current_user);
"#,
    );
    let rendered = format_tuples(
        translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"'user:' || CASE WHEN "docs.id"::text"#),
        "the subject must use the dotted column as one identifier:\n{rendered}"
    );
    assert!(
        !rendered.contains(r#""docs"."id""#),
        "splitting the dotted column silently reads docs.id:\n{rendered}"
    );
}

/// A quoted declaration keeps its case, and both spellings may name distinct
/// columns of one table, so folding must follow the quoting.
#[test]
fn a_quoted_column_keeps_the_case_postgres_stores_it_under() {
    let db = db_of(
        r#"
CREATE TABLE public.docs(id UUID PRIMARY KEY, "Owner_Id" TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING ("Owner_Id" = current_user);
"#,
    );
    let rendered = format_tuples(
        translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#""Owner_Id""#),
        "a quoted column is stored verbatim:\n{rendered}"
    );
}

/// The policy and the declaration may spell one column in different cases, and
/// unquoted they still name the same stored column.
#[test]
fn a_policy_reaches_a_column_the_declaration_spells_in_another_case() {
    let db = db_of(
        r"
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (Owner_Id = current_user);
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let rendered = format_tuples(
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner"),
        "the relation name follows the stored column, not the policy's spelling:\n{dsl}"
    );
    assert!(
        rendered.contains(r#""owner_id""#) && !rendered.contains(r#""Owner_Id""#),
        "the stored column name is owner_id:\n{rendered}"
    );
}

/// A membership join whose columns are declared in mixed case still resolves,
/// since `PostgreSQL` reads the policy's folded spelling as the same column.
#[test]
fn mixed_case_membership_columns_still_infer_the_join() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(Doc_Id UUID REFERENCES docs(id), User_Id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user)
);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert_ne!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the membership join resolves, so reads are granted:\n{dsl}"
    );

    // The other direction: the declaration is lowercase and the policy spells
    // the same columns in another case.
    let policy_side = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.Doc_Id = docs.ID AND m.User_Id = current_user)
);
",
    );
    let policy_side_dsl = translator(ConfidenceLevel::B)
        .translate(&policy_side)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert_ne!(
        relation_definition(&policy_side_dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the policy's spelling folds to the declared columns:\n{policy_side_dsl}"
    );
}

/// A foreign key declared in mixed case still carries parent inheritance.
#[test]
fn a_mixed_case_foreign_key_still_inherits_the_parent_rule() {
    let db = db_of(
        r"
CREATE TABLE public.projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE public.tasks(id UUID PRIMARY KEY, Project_Id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert_eq!(
        relation_definition(&dsl, "tasks", "can_select").as_deref(),
        Some("owner from projects"),
        "the parent link resolves through the stored column name:\n{dsl}"
    );
    assert!(
        format_tuples(
            translator
                .translate(&db)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .tuple_queries()
        )
        .contains(r#"'projects:' || CASE WHEN "project_id"::text"#),
        "the bridge query reads the stored column name"
    );

    // The other direction: the declaration is lowercase and the policy spells
    // the join columns in another case.
    let policy_side = db_of(
        r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.ID = tasks.Project_Id AND p.Owner_Id = current_user));
",
    );
    assert_eq!(
        relation_definition(
            &translator
                .translate(&policy_side)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .model(),
            "tasks",
            "can_select"
        )
        .as_deref(),
        Some("owner from projects"),
        "the policy's spelling folds to the declared columns"
    );
}

/// The `id` fallback for a row identifier answers for a column declared `ID`.
#[test]
fn a_mixed_case_unique_id_column_identifies_a_row() {
    let db = db_of(
        r"
CREATE TABLE public.docs(ID UUID UNIQUE NOT NULL, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let rendered = format_tuples(
        translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "the unique NOT NULL id column identifies the row:\n{rendered}"
    );
}

/// A quoted `"current_user"` names a real role, not the keyword, and the `Owner` enum
/// tells them apart, so the role keeps its ordinary scope.
#[test]
fn a_quoted_current_user_role_is_a_role() {
    let db = db_of(
        r#"
CREATE ROLE "current_user";
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO "current_user" USING (owner_id = current_user);
"#,
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let can_select =
        relation_definition(&dsl, "docs", "can_select").expect("can_select must be defined");
    assert!(
        can_select.contains("usage from scope_"),
        "a quoted role scopes like any other:\n{dsl}"
    );
    assert!(
        outputs
            .tuple_queries()
            .iter()
            .any(|q| q.sql.contains("'pg_role:current_user'")),
        "the real role's scope tuples are wanted, got: {:#?}",
        outputs
            .tuple_queries()
            .iter()
            .map(|q| &q.sql)
            .collect::<Vec<_>>()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::PolicyBoundToDdlTimeRole { .. })),
        "a real role is not the keyword, got: {:#?}",
        outputs.notes()
    );
}

/// The model one schema translates to at `threshold`, with `attributes` declared.
fn model_at(
    sql: &str,
    registry_json: Option<&str>,
    attributes: &str,
    threshold: ConfidenceLevel,
) -> String {
    let declared: Vec<rls2fga::classifier::function_registry::SessionAttribute> =
        serde_json::from_str(attributes).expect("attribute json should parse");
    let mut builder = rls2fga::translator::TranslatorBuilder::new()
        .with_min_confidence(threshold)
        .with_session_attributes(declared);
    if let Some(json) = registry_json {
        builder = builder
            .with_registry_json(json)
            .expect("registry json should parse");
    }
    builder
        .build()
        .translate(&db_of(sql))
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model()
}

/// The model one schema translates to at threshold B, with `attributes` declared.
fn model_with_attributes(sql: &str, registry_json: Option<&str>, attributes: &str) -> String {
    model_at(sql, registry_json, attributes, ConfidenceLevel::B)
}

/// `pg_dump` deparses every stored policy expression, so a literal argument
/// comes back with a type cast: `pg_has_role(CURRENT_USER, 'editor'::name,
/// 'MEMBER'::text)`. The dumped spelling must classify as the written one.
#[test]
fn a_cast_role_literal_in_pg_has_role_classifies_as_the_plain_one() {
    let schema = |using: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING ({using});\n"
        )
    };
    let plain = model_with_attributes(
        &schema("pg_has_role(current_user, 'editor', 'MEMBER')"),
        None,
        "[]",
    );
    let dumped = model_with_attributes(
        &schema("pg_has_role(CURRENT_USER, 'editor'::name, 'MEMBER'::text)"),
        None,
        "[]",
    );
    assert!(
        plain.contains("pg_role"),
        "the plain spelling must gate on the role, or this proves nothing:\n{plain}"
    );
    assert_eq!(plain, dumped, "the cast literals are the same policy");
}

/// `pg_dump` deparses `IN (2, 3, 4)` as `= ANY (ARRAY[2, 3, 4])`, one
/// expression with two spellings.
#[test]
fn an_any_array_list_classifies_as_the_in_list() {
    let registry = std::fs::read_to_string("tests/fixtures/role_in_list/function_registry.json")
        .expect("fixture registry should be readable");
    let written = std::fs::read_to_string("tests/fixtures/role_in_list/input.sql")
        .expect("fixture SQL should be readable");
    let written_spelling = "get_owner_role(auth_current_user_id(), owner_id) IN (2, 3, 4)";
    assert!(
        written.contains(written_spelling),
        "the fixture must carry the written IN-list this test respells"
    );
    let dumped_sql = written.replace(
        written_spelling,
        "(get_owner_role(auth_current_user_id(), owner_id) = ANY (ARRAY[2, 3, 4]))",
    );
    let attributes = std::fs::read_to_string("tests/fixtures/role_in_list/session_attributes.json")
        .expect("fixture attributes should be readable");
    let plain = model_with_attributes(&written, Some(&registry), &attributes);
    let dumped = model_with_attributes(&dumped_sql, Some(&registry), &attributes);
    assert!(
        !support::footgun::relation_denies(&plain, "ownables", "can_select"),
        "the written IN-list must translate, or this proves nothing:\n{plain}"
    );
    assert_eq!(plain, dumped, "= ANY (ARRAY[...]) is the dumped IN-list");
}

/// `pg_dump` casts the setting key itself: `current_setting('app.tenant_id'::text)`.
#[test]
fn a_cast_setting_key_classifies_as_the_plain_one() {
    let attributes =
        r#"[{ "key": "app.tenant_id", "kind": "scalar_attribute", "identity_cast": "uuid" }]"#;
    let schema = |using: &str| {
        format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, tenant_id UUID);\n\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY documents_tenant ON documents USING ({using});\n"
        )
    };
    let plain = model_with_attributes(
        &schema("tenant_id = current_setting('app.tenant_id')::uuid"),
        None,
        attributes,
    );
    let dumped = model_with_attributes(
        &schema("tenant_id = (current_setting('app.tenant_id'::text))::uuid"),
        None,
        attributes,
    );
    assert!(
        plain.contains("with when_"),
        "the written key must become a condition gate, or this proves nothing:\n{plain}"
    );
    assert_eq!(plain, dumped, "the cast on the key is the same setting");
}

/// The dumped spelling of a jsonb claim set carries the cast key inside the
/// subquery: `current_setting('request.jwt.claims'::text)::jsonb -> 'teams'::text`.
#[test]
fn a_cast_claim_set_key_classifies_as_the_plain_one() {
    let attributes =
        r#"[{ "key": "request.jwt.claims", "path": ["teams"], "kind": "set_attribute" }]"#;
    let schema = |using: &str| {
        format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY documents_team ON documents FOR SELECT USING ({using});\n"
        )
    };
    let plain = model_with_attributes(
        &schema(
            "team_id IN (SELECT jsonb_array_elements_text(current_setting('request.jwt.claims')::jsonb -> 'teams'))",
        ),
        None,
        attributes,
    );
    let dumped = model_with_attributes(
        &schema(
            "team_id IN ( SELECT jsonb_array_elements_text(((current_setting('request.jwt.claims'::text))::jsonb -> 'teams'::text)) AS jsonb_array_elements_text)",
        ),
        None,
        attributes,
    );
    assert!(
        plain.contains("with when_"),
        "the written claim set must become a condition gate, or this proves nothing:\n{plain}"
    );
    assert_eq!(plain, dumped, "the cast claim key is the same declared set");
}

/// A dumped policy spells the membership table schema-qualified. The read
/// scope relation's name must not change with the spelling, or a dumped
/// schema asks the operator for tuples under a different name.
#[test]
fn a_qualified_membership_spelling_keeps_the_scope_relation_name() {
    let schema = |members_ref: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY);\n\
             CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID, user_id TEXT);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY members_read ON doc_members FOR SELECT TO auditor USING (true);\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\n\
               SELECT 1 FROM {members_ref} m WHERE m.doc_id = docs.id AND m.user_id = current_user));\n"
        )
    };
    let plain = model_with_attributes(&schema("doc_members"), None, "[]");
    let qualified = model_with_attributes(&schema("public.doc_members"), None, "[]");
    assert!(
        plain.contains("read_scope_doc_members_"),
        "the guarded membership must mint a read scope, or this proves nothing:\n{plain}"
    );
    assert_eq!(plain, qualified, "one table, one scope relation name");
}

/// The holder type standing for everyone in an uncorrelated member table must
/// keep its name across spellings too, when a declared table claims the base.
#[test]
fn a_qualified_member_table_spelling_keeps_the_holder_type_name() {
    let schema = |staff_ref: &str| {
        format!(
            "CREATE TABLE staff_holder(id UUID PRIMARY KEY);\n\
             ALTER TABLE staff_holder ENABLE ROW LEVEL SECURITY;\n\
             CREATE TABLE staff(id UUID PRIMARY KEY, user_id TEXT);\n\
             CREATE TABLE docs(id UUID PRIMARY KEY);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\n\
               SELECT 1 FROM {staff_ref} WHERE user_id = current_user));\n"
        )
    };
    let plain = model_with_attributes(&schema("staff"), None, "[]");
    let qualified = model_with_attributes(&schema("public.staff"), None, "[]");
    assert!(
        plain.contains("staff_holder_"),
        "the claimed base must force the disambiguating suffix, or this proves nothing:\n{plain}"
    );
    assert_eq!(plain, qualified, "one member table, one holder type name");
}

/// The share type of a caller-set membership keeps its name across spellings,
/// when a declared table claims the base.
#[test]
fn a_qualified_share_table_spelling_keeps_the_share_type_name() {
    let attributes = r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#;
    let schema = |shares_ref: &str| {
        format!(
            "CREATE TABLE shares_share(id UUID PRIMARY KEY);\n\
             ALTER TABLE shares_share ENABLE ROW LEVEL SECURITY;\n\
             CREATE TABLE shares(id UUID PRIMARY KEY, parent_id UUID, viewer TEXT);\n\
             CREATE TABLE docs(id UUID PRIMARY KEY);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\n\
               SELECT 1 FROM {shares_ref} s WHERE s.parent_id = docs.id\n\
               AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))));\n"
        )
    };
    let plain = model_with_attributes(&schema("shares"), None, attributes);
    let qualified = model_with_attributes(&schema("public.shares"), None, attributes);
    assert!(
        plain.contains("shares_share_"),
        "the claimed base must force the disambiguating suffix, or this proves nothing:\n{plain}"
    );
    assert_eq!(plain, qualified, "one share table, one share type name");
}

/// `pg_dump` parenthesizes every conjunct. A parenthesized attribute guard must
/// not classify differently from the bare one: both spellings carry a literal
/// the row decides, which translates, so both must reach the same model.
#[test]
fn a_parenthesized_attribute_conjunct_classifies_as_the_bare_one() {
    let registry = std::fs::read_to_string("tests/fixtures/abac_status/function_registry.json")
        .expect("fixture registry should be readable");
    let schema = |using: &str| {
        format!(
            "CREATE TABLE ownables(id UUID PRIMARY KEY, owner_id UUID, status TEXT);\n\
             CREATE TABLE owner_grants(grantee_owner_id UUID, granted_owner_id UUID, role_id INTEGER);\n\
             CREATE TABLE team_members(user_id UUID, team_id UUID);\n\
             ALTER TABLE ownables ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY ownables_update ON ownables FOR UPDATE USING ({using});\n"
        )
    };
    let plain = model_with_attributes(
        &schema("get_owner_role(auth_current_user_id(), owner_id) >= 3 AND status = 'active'"),
        Some(&registry),
        "[]",
    );
    let dumped = model_with_attributes(
        &schema(
            "((get_owner_role(auth_current_user_id(), owner_id) >= 3) AND (status = 'active'::text))",
        ),
        Some(&registry),
        "[]",
    );
    assert!(
        !support::footgun::relation_denies(&plain, "ownables", "can_update_without_reading"),
        "a literal guard is row data the tuples carry, so the pair translates:\n{plain}"
    );
    assert_eq!(
        plain, dumped,
        "parentheses and the cast are the same policy"
    );
}

/// The same pair with a literal IN-list guard: both spellings must reach the same
/// model, and the dumped list spelling is `= ANY (ARRAY[...])` with cast elements.
#[test]
fn a_parenthesized_list_attribute_conjunct_classifies_as_the_bare_one() {
    let registry = std::fs::read_to_string("tests/fixtures/abac_status/function_registry.json")
        .expect("fixture registry should be readable");
    let schema = |using: &str| {
        format!(
            "CREATE TABLE ownables(id UUID PRIMARY KEY, owner_id UUID, status TEXT);\n\
             CREATE TABLE owner_grants(grantee_owner_id UUID, granted_owner_id UUID, role_id INTEGER);\n\
             CREATE TABLE team_members(user_id UUID, team_id UUID);\n\
             ALTER TABLE ownables ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY ownables_update ON ownables FOR UPDATE USING ({using});\n"
        )
    };
    let plain = model_at(
        &schema(
            "get_owner_role(auth_current_user_id(), owner_id) >= 3 \
             AND status IN ('active', 'draft')",
        ),
        Some(&registry),
        "[]",
        ConfidenceLevel::C,
    );
    let dumped = model_at(
        &schema(
            "((get_owner_role(auth_current_user_id(), owner_id) >= 3) \
             AND (status = ANY (ARRAY['active'::text, 'draft'::text])))",
        ),
        Some(&registry),
        "[]",
        ConfidenceLevel::C,
    );
    assert!(
        relation_definition(&plain, "ownables", "can_update_without_reading").is_some_and(|body| {
            body.starts_with("role_editor from owner_id and public_where_status_")
        }),
        "the pair keeps its relationship half and gates it by the list:\n{plain}"
    );
    assert_eq!(
        plain, dumped,
        "parentheses and the list spelling are not a classification"
    );
}

/// A schema text that writes a table with no schema name places it in `public`, so the
/// loader has to read it there. Emitting nothing loads no facts and denies every request,
/// and emitting the bare name lets the reading session's search path redirect it.
#[test]
fn a_table_written_without_a_schema_loads_its_rows_from_public() {
    let db = db_of(
        "CREATE TABLE notes(id UUID PRIMARY KEY, owner TEXT);\n\
         ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY notes_owner ON notes FOR SELECT USING (owner = current_user);\n",
    );
    let outputs = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();

    assert!(
        !tuples.is_empty(),
        "an owned table has facts to load, so it needs a query"
    );
    for query in tuples {
        assert!(
            query.sql.contains("FROM \"public\".\"notes\""),
            "the query must read the schema the declaration places the table in:\n{}\n{}",
            query.comment,
            query.sql
        );
    }
}
