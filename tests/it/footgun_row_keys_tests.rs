//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! What names a row, and what happens when nothing does.

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;

use crate::support::deployment::caller_deployment;

use crate::support::footgun::{
    db_of, is_structural_type, relation_denies, translation, translator,
};

/// Every type the model declares with no relation under it, in declaration order.
fn types_declaring_no_relation(dsl: &str) -> Vec<String> {
    let mut empty = Vec::new();
    let mut current: Option<String> = None;
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            if let Some(previous) = current.take() {
                empty.push(previous);
            }
            current = Some(name.trim().to_string());
        } else if trimmed.starts_with("define ") {
            current = None;
        }
    }
    empty.extend(current);
    empty
}

/// `PRIMARY KEY (tenant_id, id)` says `id` alone is not unique, so using it as
/// the object identifier merges rows across tenants. Phase 4 names such a row by
/// every key column instead, which is the only answer that keeps two rows apart:
/// shortening the name, by truncation or by taking one column, hands each row the
/// other's access.
#[test]
fn a_composite_primary_key_names_a_row_by_every_key_column() {
    let db = db_of(
        r"
CREATE TABLE public.docs(tenant_id UUID, id UUID, owner_id UUID, PRIMARY KEY (tenant_id, id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let rendered = format_tuples(
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "tenant_id"::text"#),
        "the name starts at the first key column, in declared order:\n{rendered}"
    );
    assert!(
        rendered.contains(r#"|| '|' || CASE WHEN "id"::text"#),
        "the second key column joins the first, or two tenants share one object:\n{rendered}"
    );
    assert!(
        !rendered.contains("composite primary key"),
        "the loss this reported is gone, so nothing may still claim it:\n{rendered}"
    );
    assert!(
        !rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "one column of the key alone must never name the row:\n{rendered}"
    );
}

/// The target caps an identifier, and the crate never sees the data, so it states the
/// budget rather than listing the rows past it. Only where the key's type could reach
/// the cap: a note on every table would say nothing.
#[test]
fn a_table_whose_key_could_overrun_is_told_its_budget() {
    let budget_of = |declaration: &str, table: &str| -> Option<usize> {
        let db = db_of(&format!(
            "{declaration}
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON {table} FOR SELECT USING (owner_id = current_setting('app.user_id'));
"
        ));
        translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .find_map(|note| match note {
                TranslationNote::RowIdentifierBudget { table: t, budget } if t.name() == table => {
                    Some(*budget)
                }
                _ => None,
            })
    };

    assert_eq!(
        budget_of(
            "CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);",
            "docs"
        ),
        Some(251),
        "a text key can reach the cap, so the operator gets the exact number"
    );
    assert_eq!(
        budget_of(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);",
            "docs"
        ),
        None,
        "a uuid renders 36 safe characters, so saying anything here would be noise"
    );
    assert_eq!(
        budget_of(
            "CREATE TABLE a_longer_table_name(id TEXT PRIMARY KEY, owner_id TEXT);",
            "a_longer_table_name"
        ),
        Some(236),
        "the cap covers the whole name, so a longer type leaves the key less room"
    );
}

/// The budget note states a contract the operator has to check, and the model is
/// complete without it, so it must not read as the model diverging from the database.
#[test]
fn the_budget_note_does_not_claim_a_divergence() {
    let db = db_of(
        r"
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
",
    );
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    assert_eq!(
        translation
            .clone()
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .filter(|note| note.severity().diverges_from_database())
            .count(),
        0,
        "a stated budget is not a loss the model already took"
    );
    assert!(
        translation.outputs().is_ok(),
        "and it must not close the ordinary door"
    );
}

/// The subject side has its own cap and its own unit, so the generated query needs its
/// own guard: an owner name past it aborts the whole load exactly as an object does.
#[test]
fn the_generated_query_guards_the_subject_length_too() {
    let db = db_of(
        r"
CREATE TABLE public.docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
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
        rendered.contains("octet_length("),
        "a text owner can overrun the subject cap, so the query must leave it out:\n{rendered}"
    );
    assert!(
        rendered.contains("<= 512"),
        "and the subject cap is 512, not the object's 256:\n{rendered}"
    );
    assert!(
        !rendered.contains("AND length("),
        "the uuid key cannot overrun, so no object guard belongs here:\n{rendered}"
    );
}

/// Without a primary key or a unique constraint two rows can share `id`, so
/// keying objects on it merges their permissions.
#[test]
fn column_no_constraint_makes_unique_does_not_identify_objects() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let rendered = format_tuples(
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        !rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "a non-unique column must not identify objects:\n{rendered}"
    );
    assert!(
        rendered.contains("does not identify a row"),
        "the operator must be told why no ownership tuples were emitted:\n{rendered}"
    );
}

/// A `NOT NULL UNIQUE` column identifies a row as well as a primary key does,
/// so refusing it would deny access the policy grants.
#[test]
fn not_null_unique_column_identifies_objects_without_a_primary_key() {
    let db = db_of(
        r"
CREATE TABLE public.docs(id UUID NOT NULL UNIQUE, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let rendered = format_tuples(
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    assert!(
        rendered.contains(r#"'docs:' || CASE WHEN "id"::text"#),
        "a uniquely constrained column identifies objects:\n{rendered}"
    );
}

/// `pg_dump` never declares a key inline: it emits `ALTER TABLE ONLY t ADD CONSTRAINT`
/// as a separate statement. Without the primary key nothing identifies a row, so the
/// table gets no tuple query at all and the operator has a model they cannot populate.
#[test]
fn a_primary_key_declared_by_alter_table_identifies_rows() {
    let schema = |key: &str, constraint: &str| {
        format!(
            "CREATE TABLE public.users (id UUID PRIMARY KEY);\n\
             CREATE TABLE public.docs (id UUID {key}, owner_id UUID NOT NULL REFERENCES users(id));\n\
             {constraint}\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));\n"
        )
    };
    let (inline_dsl, inline_tuples) = translation(&schema("PRIMARY KEY", ""));
    assert!(
        inline_tuples.contains("FROM \"public\".\"docs\""),
        "guard precondition: the inline spelling must emit an ownership query:\n{inline_tuples}"
    );

    let (dsl, tuples) = translation(&schema(
        "NOT NULL",
        "ALTER TABLE ONLY docs ADD CONSTRAINT docs_pkey PRIMARY KEY (id);\n",
    ));
    assert_eq!(
        dsl, inline_dsl,
        "a key declared by ALTER TABLE is the same key"
    );
    assert_eq!(
        tuples, inline_tuples,
        "a key declared by ALTER TABLE still identifies the object"
    );
}

/// The `id` fallback needs the column to be unique and `NOT NULL` before it will name a
/// row, and `pg_dump` declares uniqueness the same separate way.
#[test]
fn a_unique_constraint_declared_by_alter_table_identifies_rows() {
    let schema = |unique: &str, constraint: &str| {
        format!(
            "CREATE TABLE public.users (id UUID PRIMARY KEY);\n\
             CREATE TABLE public.docs (id UUID NOT NULL {unique}, \
             owner_id UUID NOT NULL REFERENCES users(id));\n\
             {constraint}\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));\n"
        )
    };
    let (inline_dsl, inline_tuples) = translation(&schema("UNIQUE", ""));
    assert!(
        inline_tuples.contains("FROM \"public\".\"docs\""),
        "guard precondition: the inline spelling must emit an ownership query:\n{inline_tuples}"
    );

    let (dsl, tuples) = translation(&schema(
        "",
        "ALTER TABLE ONLY docs ADD CONSTRAINT docs_id_key UNIQUE (id);\n",
    ));
    assert_eq!(
        dsl, inline_dsl,
        "a unique constraint declared by ALTER TABLE is the same constraint"
    );
    assert_eq!(
        tuples, inline_tuples,
        "a unique NOT NULL id still identifies the object"
    );
}

/// Phase 2, test 7, corpus shaped. An `OpenFGA` grant names an object, so every pattern
/// that grants needs a row identity, and a pattern arm that forgets leaves a permission
/// nothing can satisfy. This ranges over every arm that emits a tuple source keyed on
/// the guarded table's rows, so a new arm forgetting the check fails here.
#[test]
fn no_pattern_grants_on_a_table_whose_rows_cannot_be_named() {
    // Each case names the tuple query its arm would have emitted, so a denial reached
    // through some other refusal cannot pass for the guard under test.
    const GRANT_SCHEMA: &str = "CREATE TABLE owner_grants(grantee_owner_id UUID,
  granted_owner_id UUID, role_id INTEGER);
CREATE FUNCTION get_owner_role(u TEXT, t TEXT) RETURNS INTEGER LANGUAGE sql STABLE
AS 'SELECT 0';";
    const GRANT_REGISTRY: &str = r#"{"get_owner_role": {"kind": "role_threshold",
        "user_param_index": 0, "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3},
        "grant_table": "owner_grants", "grant_grantee_col": "grantee_owner_id",
        "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id"}}"#;
    let cases: [(&str, &str, &str, Option<&str>); 12] = [
        ("ownership", "", "USING (viewer = current_setting('app.user_id'))", None),
        (
            "array membership",
            "",
            "USING (current_setting('app.user_id') = ANY (editors))",
            None,
        ),
        (
            "jsonb field ownership",
            "",
            "USING (meta ->> 'owner' = current_setting('app.user_id'))",
            None,
        ),
        ("public-flag", "", "USING (is_public)", None),
        ("constant-TRUE", "", "USING (true)", None),
        ("attribute-gate", "", "USING (status = 'open')", None),
        (
            "policy scope",
            "CREATE ROLE auditor;",
            "TO auditor USING (viewer = current_setting('app.user_id'))",
            None,
        ),
        (
            "bridge tuples to 'link'",
            "CREATE TABLE links(link_id UUID, user_id TEXT);",
            "USING (EXISTS (SELECT 1 FROM links l WHERE l.link_id = shares.paper_id \
             AND l.user_id = current_setting('app.user_id')))",
            None,
        ),
        (
            "bridge tuples to 'papers'",
            "",
            "USING (EXISTS (SELECT 1 FROM papers p WHERE p.id = shares.paper_id \
             AND p.owner = current_setting('app.user_id')))",
            None,
        ),
        (
            "membership holder",
            "CREATE TABLE staff(user_id TEXT);",
            "USING (EXISTS (SELECT 1 FROM staff s WHERE s.user_id = current_setting('app.user_id')))",
            None,
        ),
        (
            "bridge tuples to 'owner_grants_owner'",
            GRANT_SCHEMA,
            "USING (get_owner_role(current_setting('app.user_id'), viewer) >= 2)",
            Some(GRANT_REGISTRY),
        ),
        (
            "bridge tuples to 'owner_grants_owner'",
            GRANT_SCHEMA,
            "USING (get_owner_role(current_setting('app.user_id'), viewer) IN (2, 3))",
            Some(GRANT_REGISTRY),
        ),
    ];

    for (what, extra_schema, policy_tail, registry_json) in cases {
        let db = db_of(&format!(
            "CREATE TABLE papers(id UUID PRIMARY KEY, owner TEXT);
{extra_schema}
CREATE TABLE shares(paper_id UUID REFERENCES papers(id), viewer TEXT, editors TEXT[],
  meta JSONB, is_public BOOLEAN, status TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_own ON papers FOR SELECT USING (owner = current_setting('app.user_id'));
CREATE POLICY shares_read ON shares FOR SELECT {policy_tail};
"
        ));
        let mut builder =
            TranslatorBuilder::new(caller_deployment()).with_min_confidence(ConfidenceLevel::C);
        if let Some(json) = registry_json {
            builder = builder.with_registry_json(json).expect("registry json");
        }
        let outputs = builder
            .build()
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        let sources: Vec<String> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::RowsCannotBeNamed { table, sources, .. }
                    if table.name() == "shares" =>
                {
                    Some(sources.clone())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            sources.iter().any(|source| source.starts_with(what)),
            "{what}: the arm has to say which tuple query it could not emit, got \
             {sources:?} from {:#?}",
            outputs.notes()
        );

        for relation in [
            "can_select",
            "can_insert",
            "can_update",
            "can_delete",
            "can_update_without_reading",
            "can_select_for_update",
        ] {
            assert!(
                relation_denies(&dsl, "shares", relation),
                "{what}: nothing can name a row of 'shares', so '{relation}' grants \
                 nobody:\n{dsl}"
            );
        }

        // Whatever the arm minted before it fell closed has to go with it. A scope
        // relation nothing can fill asks the operator for `pg_role` memberships no rule
        // reads, and a type left with no relation is a holder or a parent the grant no
        // longer reaches.
        assert!(
            !dsl.contains("scope_"),
            "{what}: no tuple can fill a scope on 'shares', so none may be declared:\n{dsl}"
        );
        for empty in types_declaring_no_relation(&dsl) {
            assert!(
                is_structural_type(&empty),
                "{what}: '{empty}' outlived the expression that minted it:\n{dsl}"
            );
        }
    }
}

/// Phase 2, test 7, the trap. `PostgreSQL` raises on a looping read rather than
/// granting, so the model denying is faithful and nothing may claim a divergence. A
/// table whose rows also cannot be named must not scar for the commands the loop
/// already blocks, since the policy loop never translates them and no tuple query was
/// ever going to be emitted.
#[test]
fn a_table_whose_reads_loop_does_not_scar_for_rows_it_cannot_name() {
    let db = db_of(
        "CREATE TABLE a(k UUID, viewer TEXT, PRIMARY KEY (k, viewer));
CREATE TABLE b(k UUID, viewer TEXT, PRIMARY KEY (k, viewer));
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY a_read ON a FOR SELECT USING (EXISTS (SELECT 1 FROM b WHERE b.k = a.k));
CREATE POLICY b_read ON b FOR SELECT USING (EXISTS (SELECT 1 FROM a WHERE a.k = b.k));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::PolicyReadRecursion { .. })),
        "the loop itself is still reported: {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "PostgreSQL raises here rather than granting, so nothing may claim the model \
         denies what RLS grants, got {:#?}",
        outputs.notes()
    );
}

/// A bridge the schema cannot write leaves the grant above it satisfiable by nobody.
/// The renderer can only say so in a comment, so the loss is settled while the plan is
/// built and reaches `notes`.
#[test]
fn a_bridge_the_schema_cannot_write_is_reported() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM doc_members dm WHERE dm.doc_id = nonexistent AND dm.user_id = current_setting('app.user_id')));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let reported = outputs.notes().iter().any(|note| {
        matches!(note, TranslationNote::BridgeColumnMissing { table, column, .. }
            if table.name() == "docs" && column == "nonexistent")
    });
    assert!(
        reported,
        "the missing bridge column has to be a note: {:?}",
        outputs.notes()
    );
    assert!(
        relation_denies(&outputs.model(), "docs", "can_select"),
        "a grant whose bridge nobody writes has to fall closed:\n{}",
        outputs.model()
    );
}

/// A row named by a two-column key is named the same way on both ends of a bridge. The
/// bridge used to demand a single-column key and vanish into a comment without one.
#[test]
fn a_bridge_names_a_row_by_its_whole_key() {
    let db = db_of(
        "CREATE TABLE public.papers(id INT PRIMARY KEY);
CREATE TABLE public.paper_shares(paper_id INT REFERENCES papers(id), viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON paper_shares FOR SELECT USING (
  EXISTS (SELECT 1 FROM papers p WHERE p.id = paper_id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let bridge = outputs
        .tuple_queries()
        .iter()
        .find(|query| query.comment.contains("bridge"))
        .expect("the delegation to the parent needs a bridge");
    assert!(
        bridge.skipped.is_none(),
        "the bridge has to be a query, not a comment: {}",
        bridge.sql
    );
    assert!(
        bridge.sql.contains("\"paper_id\"") && bridge.sql.contains("\"viewer\""),
        "both key columns name the row: {}",
        bridge.sql
    );
}

/// A correlated column the schema does not have is a missing column whatever it is
/// called. Naming it after the guarded table used to buy a self-reference bridge, so
/// the one spelling `projects.project_id` granted where every other spelling refused.
#[test]
fn a_bridge_column_named_after_its_table_is_still_missing() {
    let db = db_of(
        "CREATE TABLE projects(id TEXT PRIMARY KEY);
CREATE TABLE project_members(project_id TEXT, user_id TEXT);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON projects FOR SELECT USING (EXISTS (
  SELECT 1 FROM project_members m WHERE m.project_id = projects.project_id
    AND m.user_id = current_setting('app.user_id')));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        outputs.notes().iter().any(|note| {
            matches!(note, TranslationNote::BridgeColumnMissing { table, column, .. }
                if table.name() == "projects" && column == "project_id")
        }),
        "the missing bridge column has to be a note: {:?}",
        outputs.notes()
    );
    assert!(
        relation_denies(&outputs.model(), "projects", "can_select"),
        "a grant whose bridge nobody writes has to fall closed:\n{}",
        outputs.model()
    );
}
