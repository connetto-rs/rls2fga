//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Values the request supplies rather than the row, and the guards that read them.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{DirectOwnership, PatternClass, UnclassifiedExpr};
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RelationShapes;
use rls2fga::types::TranslationNote;
use rls2fga::types::{ColumnName, RelationName};
use rls2fga::types::{RecordDerivation, ValueSource};

use crate::support::footgun::{
    db_of, relation_definition, relation_definitions, relation_denies, translation, translator,
};

/// The missing-key-tolerant `current_setting(key, true)` identifies the current
/// user exactly like the single-argument form.
#[test]
fn current_setting_with_missing_ok_infers_a_current_user_accessor() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION app_user_id() RETURNS TEXT
    LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'', true)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = app_user_id());
",
    );
    let classified = translator(ConfidenceLevel::A).classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected exactly one classified policy");
    };
    let using = policy
        .using_classification()
        .expect("USING should classify");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "missing_ok current_setting should still yield P3 ownership, got: {:?}",
        using.pattern
    );
}

/// Extract the relation each wildcard tuple query writes, paired with whether the
/// query is gated by a row predicate beyond the key `NOT NULL` guards.
fn wildcard_query_relations(db: &rls2fga::parser::sql_parser::ParserDB) -> Vec<(String, bool)> {
    let translation = translator(ConfidenceLevel::B)
        .translate(db)
        .expect("translation should plan");
    let outputs = translation.outputs_accepting_gaps();
    outputs
        .tuple_queries()
        .iter()
        .filter(|query| query.sql.contains("user:*"))
        .map(|query| {
            let relation = query
                .sql
                .split(" AS relation")
                .next()
                .and_then(|head| head.rsplit('\'').nth(1))
                .expect("every tuple query names its relation")
                .to_string();
            let gated = query.sql.lines().any(|line| {
                line.starts_with("AND ")
                    && !line.contains("IS NOT NULL")
                    && !line.contains("length(")
            });
            (relation, gated)
        })
        .collect()
}

/// One ungated and one gated wildcard query, located by shape rather than order.
fn one_ungated_and_one_gated(queries: &[(String, bool)]) -> (String, String) {
    let ungated: Vec<&String> = queries
        .iter()
        .filter(|(_, gated)| !gated)
        .map(|(relation, _)| relation)
        .collect();
    let gated: Vec<&String> = queries
        .iter()
        .filter(|(_, gated)| *gated)
        .map(|(relation, _)| relation)
        .collect();
    let ([everyone], [flagged]) = (ungated.as_slice(), gated.as_slice()) else {
        panic!("expected one ungated and one gated wildcard query, got: {queries:?}");
    };
    ((*everyone).clone(), (*flagged).clone())
}

/// A permissive `USING (true)` loads a wildcard for every row. If the RESTRICTIVE
/// flag barrier grants through the same relation, those tuples satisfy it and the
/// barrier vanishes.
#[test]
fn a_restrictive_flag_barrier_survives_a_permissive_true() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN NOT NULL DEFAULT false);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs FOR SELECT USING (true);
         CREATE POLICY r ON docs AS RESTRICTIVE FOR SELECT USING (is_public);",
    );
    let queries = wildcard_query_relations(&db);
    let (everyone, flagged) = one_ungated_and_one_gated(&queries);
    assert_ne!(
        everyone, flagged,
        "the unconditional tuples must not satisfy the flag barrier's relation"
    );
}

/// `USING (true)` on DELETE must not widen the flag-gated SELECT: the two commands
/// grant through different predicates, so they need different relations.
#[test]
fn a_cross_command_true_does_not_widen_the_flag_gated_select() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN NOT NULL DEFAULT false);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY s ON docs FOR SELECT USING (is_public);
         CREATE POLICY d ON docs FOR DELETE USING (true);",
    );
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let dsl = translation.outputs_accepting_gaps().model();
    let can_select = relation_definition(&dsl, "docs", "can_select").expect("can_select defined");
    let can_delete = relation_definition(&dsl, "docs", "can_delete").expect("can_delete defined");
    assert_ne!(
        can_select, can_delete,
        "SELECT is flag-gated and DELETE is unconditional, so one relation cannot serve both:\n{dsl}"
    );
    let queries = wildcard_query_relations(&db);
    let (everyone, flagged) = one_ungated_and_one_gated(&queries);
    assert_eq!(
        can_select.as_str(),
        flagged.as_str(),
        "SELECT must grant only through the flag-gated relation"
    );
    // DELETE keeps its unconditional grant, intersected with the read the crate's
    // read-gating contract requires (naming a row to change means reading it).
    assert_eq!(
        can_delete,
        format!("{everyone} and can_select"),
        "DELETE grants through the unconditional relation intersected with the read"
    );
}

/// The same flag predicate on two commands loads identical tuples, so sharing one
/// relation and one query is correct and the dedup must survive the split.
#[test]
fn the_same_flag_on_two_commands_shares_one_relation_and_one_query() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN NOT NULL DEFAULT false);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY s ON docs FOR SELECT USING (is_public);
         CREATE POLICY d ON docs FOR DELETE USING (is_public);",
    );
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let dsl = translation.outputs_accepting_gaps().model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select"),
        relation_definition(&dsl, "docs", "can_delete"),
        "one predicate, one relation, whatever the command:\n{dsl}"
    );
    let queries = wildcard_query_relations(&db);
    assert_eq!(
        queries.len(),
        1,
        "identical predicates dedup to one query, got: {queries:?}"
    );
}

/// Two attribute guards inside one OR policy admit different row sets, so each
/// needs its own relation or the wider guard's tuples satisfy the narrower arm.
#[test]
fn two_guards_in_one_or_policy_mint_two_distinct_gates() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, status TEXT, priority INTEGER);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY p ON docs FOR SELECT
           USING (status = 'published' OR priority >= 3);",
    );
    let queries = wildcard_query_relations(&db);
    let [(first, true), (second, true)] = queries.as_slice() else {
        panic!("expected two gated wildcard queries, got: {queries:?}");
    };
    assert_ne!(
        first, second,
        "each guard admits a different row set, so the relations must differ"
    );
}

/// A RESTRICTIVE clause is a barrier, so a conjunct the model cannot express has to
/// keep denying.
#[test]
fn a_restrictive_clause_never_drops_an_attribute_conjunct() {
    let schema = |restriction: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, deleted_at TIMESTAMP, \
             tenant_id UUID, title TEXT);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_user);\n\
             CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT USING ({restriction});\n"
        )
    };
    let body = |restriction: &str| {
        // At a stricter threshold the policy is dropped and the deny-fill hides this.
        let db = db_of(&schema(restriction));
        let model = translator(ConfidenceLevel::C)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        relation_definition(&model.model(), "docs", "can_select")
            .unwrap_or_else(|| panic!("docs should define can_select for '{restriction}'"))
    };

    let barrier_only = body("title LIKE 'draft%'");
    assert!(
        barrier_only.contains("no_access"),
        "an inexpressible restriction must deny, got '{barrier_only}'"
    );

    // Anding a relationship onto the same barrier must not discard the barrier.
    let with_relationship = body("title LIKE 'draft%' AND tenant_id = current_user");
    assert!(
        with_relationship.contains("no_access"),
        "the 'title LIKE' barrier vanished, leaving '{with_relationship}'"
    );
    assert_ne!(
        with_relationship,
        body("tenant_id = current_user"),
        "the restriction with a barrier must be stricter than the one without it"
    );

    // The same holds when the barrier hides inside a branch of a union.
    let nested =
        body("(title LIKE 'draft%' AND tenant_id = current_user) OR owner_id = current_user");
    assert!(
        nested.contains("no_access"),
        "a barrier nested in a union vanished, leaving '{nested}'"
    );

    // A barrier the row decides is kept as its gate rather than denied.
    let row_decided = body("deleted_at IS NULL");
    assert!(
        row_decided.contains(" and public_where_deleted_at_") && !row_decided.contains("no_access"),
        "the row decides 'deleted_at IS NULL', got '{row_decided}'"
    );

    // A denied barrier must not also ask for runtime enforcement.
    let db = db_of(&schema("title LIKE 'draft%' AND tenant_id = current_user"));
    let model = translator(ConfidenceLevel::C)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let notes: Vec<String> = model
        .notes()
        .iter()
        .filter(|note| note.subject() == "docs_bar")
        .map(TranslationNote::message)
        .collect();
    assert!(
        notes.iter().any(|note| note.contains("denied")),
        "the denial must be reported, got {notes:?}"
    );
    assert!(
        !notes
            .iter()
            .any(|note| note.contains("requires runtime enforcement")),
        "a denied barrier cannot also ask for runtime enforcement, got {notes:?}"
    );
}

/// `current_user` inside a `SECURITY DEFINER` function is the function owner, the
/// same value for every caller, so the policy is not per-user ownership.
#[test]
fn security_definer_current_user_is_not_the_caller() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION app_uid() RETURNS TEXT LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user::text';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "the definer's identity is not the caller's, so the row owner is not the caller:\n{}",
        model.model()
    );
}

/// Declaring the function in the registry asserts its semantics, which outranks what
/// the body and the security mode suggest.
#[test]
fn an_explicitly_registered_accessor_outranks_its_security_mode() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION app_uid() RETURNS TEXT LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user::text';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = TranslatorBuilder::new()
        .with_registry_json(r#"{"app_uid": {"kind": "current_user_accessor", "returns": "text"}}"#)
        .expect("registry should parse")
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "a declared accessor stays one:\n{}",
        model.model()
    );
    assert!(
        !model
            .notes()
            .iter()
            .any(|note| note.message().contains("runs as its owner")),
        "the note only fires where the translation refused, got {:#?}",
        model.notes()
    );
}

/// A dropped policy tells the operator nothing about the cause, so the function that
/// cannot identify the caller is named.
#[test]
fn an_owner_bound_accessor_is_reported_by_name() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION app_uid() RETURNS TEXT LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user::text';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.message().contains("app_uid") && note.message().contains("owner")),
        "the operator must be told which function runs as its owner, got {:#?}",
        model.notes()
    );
}

#[test]
fn owner_bound_accessor_quote_identity_does_not_block_other_function() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE FUNCTION "UID"() RETURNS TEXT LANGUAGE sql SECURITY DEFINER
  AS 'SELECT current_user::text';
CREATE FUNCTION uid(value UUID) RETURNS BOOLEAN LANGUAGE sql
  AS 'SELECT true';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (uid(id));
"#,
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("public_viewer")
    );
}

/// The same body under the default `SECURITY INVOKER` does identify the caller.
#[test]
fn security_invoker_current_user_stays_the_caller() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION app_uid() RETURNS TEXT LANGUAGE sql AS 'SELECT current_user::text';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "an invoker accessor is per-caller ownership:\n{}",
        model.model()
    );
}

/// A session setting is unaffected by whose privileges the function runs with, so a
/// `SECURITY DEFINER` body reading one still identifies the caller.
#[test]
fn security_definer_current_setting_still_identifies_the_caller() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION app_uid() RETURNS TEXT LANGUAGE sql SECURITY DEFINER
  AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = app_uid());
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "a session setting is per-caller regardless of the security mode:\n{}",
        model.model()
    );
}

/// `PostgreSQL` 18, role alice, rows carrying `ARRAY['alice']`, `ARRAY['alice','bob']`,
/// `ARRAY[]`, `NULL`, `ARRAY[NULL]`, `ARRAY['alice',NULL]` and `ARRAY['bob']`: a
/// policy `USING (current_user = ANY (editors))` returns exactly the three rows
/// holding 'alice', and `SELECT id, unnest(editors)` filtered to 'alice' returns
/// the same three. The translation is exact, not a widening, so it earns a
/// relation rather than a refusal.
#[test]
fn caller_listed_in_an_array_column_is_a_relationship_not_a_refusal() {
    for clause in [
        "current_user = ANY (editors)",
        "editors @> ARRAY[current_user]",
        "ARRAY[current_user] <@ editors",
        "ARRAY[current_user] && editors",
    ] {
        let db = db_of(&format!(
            "CREATE TABLE public.docs(id UUID PRIMARY KEY, editors TEXT[]);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_editors ON docs FOR SELECT USING ({clause});"
        ));
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

        let can_select = relation_definition(&dsl, "docs", "can_select")
            .unwrap_or_else(|| panic!("`{clause}`: docs must define can_select:\n{dsl}"));
        assert_ne!(
            can_select, "no_access",
            "`{clause}`: RLS grants three rows, so the model must not deny:\n{dsl}"
        );

        let relation = can_select.trim().to_string();
        let body = relation_definition(&dsl, "docs", &relation).unwrap_or_else(|| {
            panic!("`{clause}`: can_select points at '{relation}' which is undefined:\n{dsl}")
        });
        assert!(
            body.contains("user"),
            "`{clause}`: '{relation}' must admit users, got '{body}':\n{dsl}"
        );

        // Without the unnesting scan the relation exists but can never be populated,
        // which denies exactly the rows PostgreSQL grants.
        assert!(
            rendered.to_lowercase().contains("unnest"),
            "`{clause}`: the array column has to be expanded to produce tuples:\n{rendered}"
        );
        assert!(
            rendered.contains(r#""editors""#),
            "`{clause}`: the tuple query must read the array column:\n{rendered}"
        );
    }
}

/// An array column and a subquery both sit to the right of `= ANY`, and only the
/// column can be expanded. Treating a subquery as one emitted
/// `UNNEST("(SELECT user_id FROM doc_members WHERE doc_id = docs"."id)")`, which
/// splits on the dot and names two columns that do not exist, under a relation named
/// after the same text. The caller has to sit on the left for the array recognizer to
/// look at the right at all, so that is the shape this pins.
#[test]
fn any_over_a_subquery_is_never_expanded_as_an_array_column() {
    const MEMBERS: &str = "
CREATE TABLE public.docs(id UUID PRIMARY KEY, editors TEXT[]);
CREATE TABLE public.doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

    for clause in [
        "current_user = ANY (SELECT user_id FROM doc_members WHERE doc_id = docs.id)",
        "current_user = ANY (SELECT user_id FROM doc_members)",
    ] {
        let db = db_of(&format!(
            "{MEMBERS}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
        ));
        let translator = translator(ConfidenceLevel::B);
        let rendered = format_tuples(
            translator
                .translate(&db)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .tuple_queries(),
        );

        assert!(
            !rendered.to_lowercase().contains("unnest"),
            "`{clause}`: a subquery is not an array to expand:\n{rendered}"
        );
        assert!(
            !rendered.contains("SELECT user_id"),
            "`{clause}`: the subquery text must not reach the generated SQL:\n{rendered}"
        );
    }

    // The object-key spelling is real membership and must keep its P4 translation.
    let db = db_of(&format!(
        "{MEMBERS}CREATE POLICY docs_members ON docs FOR SELECT
           USING (id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user));"
    ));
    let translator = translator(ConfidenceLevel::B);
    let rendered = format_tuples(
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );
    assert!(
        rendered.contains(r#"FROM "public"."doc_members""#),
        "membership through the join table still produces its tuples:\n{rendered}"
    );
}

/// `PostgreSQL` 18, role alice, rows carrying `{"owner":"alice"}`, `{"owner":"bob"}`,
/// `{"owner":null}`, `{}`, a NULL column and `{"owner":"carol"}`: a policy
/// `USING (data ->> 'owner' = current_user)` returns exactly the rows whose extracted
/// text equals the caller, since `->>` yields NULL for a missing key, a null value and
/// a null column, and the comparison then filters. `SELECT id, data ->> 'owner'` with
/// the NULLs dropped enumerates the same pairs, so this is exact too.
#[test]
fn caller_named_in_a_jsonb_field_is_ownership_not_a_refusal() {
    for clause in [
        "data ->> 'owner' = current_user",
        "current_user = data ->> 'owner'",
        "(data ->> 'owner')::text = current_user",
    ] {
        let db = db_of(&format!(
            "CREATE TABLE public.docs(id UUID PRIMARY KEY, data JSONB);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_json ON docs FOR SELECT USING ({clause});"
        ));
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

        let can_select = relation_definition(&dsl, "docs", "can_select")
            .unwrap_or_else(|| panic!("`{clause}`: docs must define can_select:\n{dsl}"));
        assert_ne!(
            can_select, "no_access",
            "`{clause}`: RLS grants the matching rows, so the model must not deny:\n{dsl}"
        );

        assert!(
            rendered.contains(r#""data" ->> 'owner'"#),
            "`{clause}`: the tuple query must extract the field:\n{rendered}"
        );
    }
}

/// A JSON key is a SQL string literal, and a quote inside it would close that literal
/// and let the rest execute. The identifier path is already guarded by
/// `quote_sql_identifier`, so the key is the remaining injection point.
#[test]
fn a_quote_in_a_jsonb_key_cannot_break_out_of_its_literal() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, data JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_json ON docs FOR SELECT
  USING (data ->> 'ow''ner' = current_user);
",
    );
    let translator = translator(ConfidenceLevel::B);
    let rendered = format_tuples(
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries(),
    );

    if rendered.contains("->>") {
        assert!(
            rendered.contains("'ow''ner'"),
            "the quote must stay doubled inside the literal:\n{rendered}"
        );
    }
}

/// A jsonb or array comparison against a literal is an attribute guard, exactly as
/// `status = 'published'` is. Leaving it unrecognized made the same policy shape behave
/// differently depending on whether the attribute lived in a column or a document: the
/// jsonb spelling collapsed the whole `AND` to `no_access` and lost the relationship
/// half. A plain column literal now goes further and becomes per-row tuples, while a
/// document-held guard keeps the relationship half beside a runtime-enforcement note.
#[test]
fn a_jsonb_or_array_attribute_guard_keeps_the_relationship_it_guards() {
    let plain_db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, data JSONB, tags TEXT[], status TEXT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_hybrid ON docs FOR SELECT
           USING (owner_id = current_user AND status = 'published');",
    );
    assert_eq!(
        relation_definition(
            &translator(ConfidenceLevel::C)
                .translate(&plain_db)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .model(),
            "docs",
            "can_select",
        )
        .as_deref(),
        Some("owner and public_where_status_131bc6df"),
        "a plain column literal is row data the tuples carry"
    );

    for guard in [
        "data ->> 'status' = 'published'",
        "data @> '{\"public\": true}'",
        "tags && ARRAY['x', 'y']",
        "tags @> ARRAY['x']",
    ] {
        let db = db_of(&format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, data JSONB, tags TEXT[], status TEXT);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_hybrid ON docs FOR SELECT
               USING (owner_id = current_user AND {guard});"
        ));
        let outputs = translator(ConfidenceLevel::C)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        let can_select = relation_definition(&dsl, "docs", "can_select")
            .unwrap_or_else(|| panic!("`{guard}`: docs must define can_select:\n{dsl}"));
        assert_eq!(
            can_select, "owner",
            "`{guard}`: the relationship half survives the guard the tuples cannot carry:\n{dsl}"
        );
        assert!(
            outputs.notes().iter().any(|note| {
                matches!(
                    note,
                    TranslationNote::AttributeNeedsRuntimeEnforcement { .. }
                )
            }),
            "`{guard}`: the dropped guard is disclosed:\n{:#?}",
            outputs.notes()
        );
    }
}

/// A dropped attribute guard is a widening, so the operator has to be told which guard
/// they are now enforcing themselves.
#[test]
fn a_dropped_jsonb_attribute_guard_names_the_field_it_stopped_checking() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, data JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_hybrid ON docs FOR SELECT
  USING (owner_id = current_user AND data ->> 'status' = 'published');
",
    );
    let model = translator(ConfidenceLevel::C)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages.iter().any(|m| m.contains("status")),
        "the field no longer being checked must be named: {messages:#?}"
    );
}

/// A column compared against a literal constant is decided by the row, exactly as a
/// boolean flag is, so it earns the same wildcard rather than falling closed. The
/// tuple query then qualifies rows the way the flag's query already does.
#[test]
fn an_attribute_guard_over_a_literal_grants_the_rows_it_admits() {
    let schema = |clause: &str| {
        format!(
            "CREATE TABLE public.articles(id UUID PRIMARY KEY, status TEXT, priority INT, \
             is_public BOOLEAN NOT NULL DEFAULT FALSE);\n\
             ALTER TABLE articles ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY articles_sel ON articles FOR SELECT USING ({clause});\n"
        )
    };

    // The boolean flag is the shape this generalises, so it is the reference.
    let (flag_dsl, flag_tuples) = translation(&schema("is_public = TRUE"));
    assert_eq!(
        relation_definition(&flag_dsl, "articles", "can_select").as_deref(),
        Some("public_when_is_public"),
        "guard precondition: the boolean flag must grant the wildcard through its own gate:\n{flag_dsl}"
    );
    let mut minted: Vec<(&str, String)> = Vec::new();

    for (clause, expected_sql) in [
        ("status = 'published'", "AND \"status\" = 'published';"),
        ("priority >= 3", "AND \"priority\" >= 3;"),
        ("status <> 'draft'", "AND \"status\" <> 'draft';"),
        // The column may sit on the right, and the operator reads column-first.
        ("3 <= priority", "AND \"priority\" >= 3;"),
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        let select = relation_definition(&dsl, "articles", "can_select")
            .expect("articles defines can_select");
        assert!(
            select.starts_with("public_where_"),
            "`{clause}` is decided by the row, so it grants through its own gate, got `{select}`:\n{dsl}"
        );
        minted.push((clause, select));
        assert!(
            tuples.contains(expected_sql),
            "`{clause}` must qualify rows in SQL, got:\n{tuples}"
        );
        // The flag's own query is the shape being copied, so the rest must match.
        assert_eq!(
            tuples.lines().count(),
            flag_tuples.lines().count(),
            "`{clause}` must emit one query, like the flag:\n{tuples}"
        );
    }
    // The reversed spelling normalizes column-first, so both mint one gate.
    let straight = minted
        .iter()
        .find(|(clause, _)| *clause == "priority >= 3")
        .map(|(_, name)| name.clone())
        .expect("the straight spelling is in the list");
    let reversed = minted
        .iter()
        .find(|(clause, _)| *clause == "3 <= priority")
        .map(|(_, name)| name.clone())
        .expect("the reversed spelling is in the list");
    assert_eq!(
        straight, reversed,
        "two spellings of one predicate must share one gate"
    );
}

/// The wildcard is only correct because the compared value is a literal constant. A
/// value the caller supplies would grant everyone access to rows scoped to one
/// caller, and one the clock supplies would outlive the row it was computed from, so
/// neither may reach that emission.
#[test]
fn only_a_literal_constant_earns_the_attribute_wildcard() {
    use rls2fga::classifier::recognizers::attribute_literal_predicate;

    let schema = |clause: &str| {
        format!(
            "CREATE TABLE public.articles(id UUID PRIMARY KEY, status TEXT, owner_id TEXT, \
             expires_at TIMESTAMPTZ);\n\
             ALTER TABLE articles ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY articles_sel ON articles FOR SELECT USING ({clause});\n"
        )
    };

    for clause in [
        // The clock decides these, not the row, so a static tuple computed once would
        // keep granting after the value passed. They earn a condition instead, which
        // the service re-evaluates on every check.
        "expires_at > now()",
        "expires_at <= current_timestamp",
        "expires_at > CURRENT_DATE",
    ] {
        let (dsl, tuples) = translation(&schema(clause));
        let select = relation_definition(&dsl, "articles", "can_select")
            .expect("articles defines can_select");
        assert_ne!(
            select, "public_viewer",
            "`{clause}` must not earn the unconditional wildcard:\n{dsl}"
        );
        assert!(
            select.starts_with("gate_"),
            "`{clause}` must resolve through a conditional gate, got `{select}`:\n{dsl}"
        );
        // The gate's wildcard is admitted only through a condition, and the model
        // declares that condition.
        assert!(
            dsl.contains(":* with when_"),
            "the gate's wildcard must carry its condition:\n{dsl}"
        );
        assert!(
            dsl.contains("condition when_"),
            "the model must declare the condition it names:\n{dsl}"
        );
        // And the tuple carries the row's own value, since the request cannot know it.
        assert!(
            tuples.contains("jsonb_build_object('expires_at', \"expires_at\")"),
            "the tuple must carry the row's value as context:\n{tuples}"
        );
        assert!(
            !tuples.contains("'public_viewer' AS relation"),
            "`{clause}` must emit no unconditional wildcard tuple:\n{tuples}"
        );
    }

    // And the recognizer itself refuses anything that is not a literal, which is what
    // the emission depends on.
    for clause in [
        "status = current_user",
        "status > now()",
        "status = owner_id",
        "status = upper('a')",
    ] {
        let expr = parse_using_expr(&schema(clause));
        assert!(
            attribute_literal_predicate(&expr).is_none(),
            "`{clause}` compares against something the row does not fix, so it must \
             carry no predicate"
        );
    }
}

/// The `USING` expression of the one policy `schema` declares.
fn parse_using_expr(schema: &str) -> sqlparser::ast::Expr {
    use rls2fga::parser::sql_parser::{DatabaseLike, PolicyLike};

    let db = db_of(schema);
    let expr = db
        .policies()
        .next()
        .expect("the schema declares one policy")
        .using_expression(&db)
        .expect("the policy stores a USING clause")
        .clone();
    expr
}

/// Two condition parameters cannot share one name. A column named exactly like the
/// parameter the request supplies collapsed them into one, and the expression compared
/// the value against itself.
#[test]
fn a_column_named_after_the_request_parameter_keeps_its_own_condition_parameter() {
    let schema = "CREATE TABLE public.jobs(id UUID PRIMARY KEY, request_time TIMESTAMPTZ);\n\
                  ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY jobs_sel ON jobs FOR SELECT USING (request_time > now());\n";

    let (dsl, tuples) = translation(schema);

    let condition = dsl
        .lines()
        .find(|line| line.trim_start().starts_with("condition when_"))
        .expect("the model declares its condition");
    let expression = dsl
        .lines()
        .find(|line| line.contains(" > "))
        .expect("the condition compares the row against the request")
        .trim()
        .to_string();

    // The comparison must have two distinct sides, whatever the row's parameter ends
    // up being called.
    let (left, right) = expression
        .split_once(" > ")
        .expect("the expression is a comparison");
    assert_ne!(
        left.trim(),
        right.trim(),
        "the row and the request must be separate parameters:\n{dsl}"
    );
    assert!(
        condition.matches("timestamp").count() == 2,
        "both parameters must survive in the signature, got `{condition}`"
    );
    // The context supplies the row's parameter, so the key has to be the renamed
    // parameter while the value still reads the real column.
    let row_parameter = left.trim();
    assert!(
        tuples.contains(&format!(
            "jsonb_build_object('{row_parameter}', \"request_time\")"
        )),
        "the context key must be the row's parameter `{row_parameter}`:\n{tuples}"
    );
    assert!(
        condition.contains(&format!("{row_parameter}: timestamp")),
        "the signature must declare that parameter, got `{condition}`"
    );
}

/// The name is a contract with the caller, who has to pass exactly that key at check
/// time, so a deployment with its own convention configures it.
#[test]
fn the_request_time_parameter_name_is_configurable() {
    let schema = "CREATE TABLE jobs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
                  ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY jobs_sel ON jobs FOR SELECT USING (expires_at > now());\n";
    let db = db_of(schema);

    let default_dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert!(
        default_dsl.contains("request_time: timestamp"),
        "the default name is request_time:\n{default_dsl}"
    );

    let configured = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_request_time_parameter("as_of")
        .expect("as_of is a valid parameter")
        .build();
    let dsl = configured
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert!(
        dsl.contains("as_of: timestamp"),
        "the configured name reaches the signature:\n{dsl}"
    );
    assert!(
        dsl.contains("expires_at > as_of"),
        "the configured name reaches the expression:\n{dsl}"
    );
    assert!(
        !dsl.contains("request_time"),
        "the default must not survive alongside it:\n{dsl}"
    );
}

/// A tuple's context must be RFC 3339. `DATE` renders as `2099-01-01` and `TIMESTAMP`
/// as `2099-01-01T12:00:00`, and `OpenFGA` v1.11.6 refuses both at load while accepting
/// the model that named them, so the guard shipped a relation whose tuples could never
/// arrive. Rendering an instant instead would not save either: resolving one needs a
/// time zone, and the loader's session decides it while the reader's differs.
#[test]
fn only_a_zoned_timestamp_column_earns_a_condition_parameter() {
    let schema = |column_type: &str| {
        format!(
            "CREATE TABLE public.docs(id UUID PRIMARY KEY, expires_at {column_type});\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (expires_at > now());\n"
        )
    };

    for zoneless in ["DATE", "TIMESTAMP", "TIMESTAMP WITHOUT TIME ZONE"] {
        let (dsl, tuples) = translation(&schema(zoneless));
        assert!(
            !dsl.contains("condition when_"),
            "{zoneless} must declare no condition:\n{dsl}"
        );
        assert!(
            !tuples.contains("jsonb_build_object"),
            "{zoneless} must emit no context OpenFGA would refuse:\n{tuples}"
        );
        // The refusal has to precede every mint, or the type keeps a gate relation
        // nothing defines a condition for.
        assert!(
            !dsl.contains("gate_"),
            "{zoneless} must leave no gate relation behind:\n{dsl}"
        );
        assert!(
            dsl.contains("define can_select: no_access"),
            "{zoneless} must fall closed:\n{dsl}"
        );
    }

    for zoned in ["TIMESTAMPTZ", "TIMESTAMP WITH TIME ZONE"] {
        let (dsl, tuples) = translation(&schema(zoned));
        assert!(
            dsl.contains("expires_at > request_time"),
            "{zoned} must keep its condition:\n{dsl}"
        );
        assert!(
            tuples.contains("jsonb_build_object('expires_at', \"expires_at\")"),
            "{zoned} must supply the row's value as context:\n{tuples}"
        );
    }
}

#[test]
fn case_distinct_stored_columns_keep_their_declared_types() {
    for columns in [
        r#"foo TEXT, "Foo" TIMESTAMPTZ"#,
        r#""Foo" TIMESTAMPTZ, foo TEXT"#,
    ] {
        let schema = format!(
            r#"
CREATE TABLE public.docs(id UUID PRIMARY KEY, {columns});
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY text_guard ON docs FOR SELECT USING (foo = 'active');
CREATE POLICY clock_guard ON docs FOR SELECT USING ("Foo" > now());
"#
        );
        let (dsl, tuples) = translation(&schema);

        assert!(
            tuples.contains("AND \"foo\" = 'active';"),
            "the unquoted column must keep its text guard:\n{tuples}"
        );
        assert!(
            dsl.contains("condition when_") && dsl.contains("foo > request_time"),
            "the quoted timestamp must keep its condition:\n{dsl}"
        );
        assert!(
            tuples.contains("jsonb_build_object('foo', \"Foo\")"),
            "the quoted timestamp must supply its own context:\n{tuples}"
        );
    }
}

/// A grace period spelled `expires_at > now() - interval '36 hours'` is still the clock's
/// to judge, not the writer's: the row keeps its own boundary and the check reads the
/// request clock, taking the fixed offset from it as a CEL duration. Leaving the
/// arithmetic in SQL would fire no boundary event, so the tuple would keep answering
/// allowed past the grace window.
///
/// Each literal sits beside the value `PostgreSQL` 18.6 stores for it. A finite interval of
/// microseconds alone has one length in every time zone, so that length is the duration,
/// in the coarsest unit that holds it exactly, and a negative one turns the shift around.
#[test]
fn a_fixed_temporal_offset_rides_the_request_clock_as_a_duration() {
    for (offset_sql, stored, offset_cel) in [
        (
            "now() - interval '24 hours'",
            "24:00:00",
            "request_time - duration(\"24h\")",
        ),
        (
            "now() - interval '36 hours'",
            "36:00:00",
            "request_time - duration(\"36h\")",
        ),
        (
            "now() + interval '2 hours'",
            "02:00:00",
            "request_time + duration(\"2h\")",
        ),
        (
            "now() - interval '90 minutes'",
            "01:30:00",
            "request_time - duration(\"90m\")",
        ),
        (
            "now() - interval '45 seconds'",
            "00:00:45",
            "request_time - duration(\"45s\")",
        ),
        (
            "now() - interval '01:30:00'",
            "01:30:00",
            "request_time - duration(\"90m\")",
        ),
        (
            "now() - interval '0.5 seconds'",
            "00:00:00.5",
            "request_time - duration(\"500ms\")",
        ),
        (
            "now() - interval '90' minute",
            "01:30:00",
            "request_time - duration(\"90m\")",
        ),
        (
            "now() - interval '1.5' second(3)",
            "00:00:01.5",
            "request_time - duration(\"1500ms\")",
        ),
        (
            "now() - interval '1:30.5' minute to second(0)",
            "00:01:31",
            "request_time - duration(\"91s\")",
        ),
        (
            "now() - interval '1 hour ago'",
            "-01:00:00",
            "request_time + duration(\"1h\")",
        ),
        (
            "now() - interval '5' hour",
            "05:00:00",
            "request_time - duration(\"5h\")",
        ),
        (
            "now() - interval '2:03' hour to minute",
            "02:03:00",
            "request_time - duration(\"123m\")",
        ),
        (
            "now() - interval '2:03:04' hour to second",
            "02:03:04",
            "request_time - duration(\"7384s\")",
        ),
        (
            "now() - interval '0 2:03:04' day to second",
            "02:03:04",
            "request_time - duration(\"7384s\")",
        ),
        (
            "now() - interval $$90 minutes$$",
            "01:30:00",
            "request_time - duration(\"90m\")",
        ),
        ("now() - interval '0'", "00:00:00", "request_time\n"),
        (
            "now() - '1 hour'::interval",
            "01:00:00",
            "request_time - duration(\"1h\")",
        ),
        (
            "now() - CAST('90 minutes' AS interval)",
            "01:30:00",
            "request_time - duration(\"90m\")",
        ),
        (
            "now() - '90'::interval minute",
            "01:30:00",
            "request_time - duration(\"90m\")",
        ),
        (
            "now() - ('90 seconds')::interval minute",
            "00:01:00",
            "request_time - duration(\"1m\")",
        ),
        (
            "now() - '5'::interval hour",
            "05:00:00",
            "request_time - duration(\"5h\")",
        ),
        (
            "now() - '45'::interval second",
            "00:00:45",
            "request_time - duration(\"45s\")",
        ),
        (
            "now() - '2:03'::interval hour to minute",
            "02:03:00",
            "request_time - duration(\"123m\")",
        ),
        (
            "now() - '2:03:04'::interval hour to second",
            "02:03:04",
            "request_time - duration(\"7384s\")",
        ),
        (
            "now() - '1:30.5'::interval minute to second(0)",
            "00:01:31",
            "request_time - duration(\"91s\")",
        ),
        (
            "now() - $$2 hours$$::interval",
            "02:00:00",
            "request_time - duration(\"2h\")",
        ),
        (
            "now() + '1 hour ago'::interval",
            "-01:00:00",
            "request_time - duration(\"1h\")",
        ),
        (
            "now() - (interval '90 minutes')::interval",
            "01:30:00",
            "request_time - duration(\"90m\")",
        ),
    ] {
        let schema = format!(
            "CREATE TABLE public.docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING (expires_at > {offset_sql});\n"
        );
        let (dsl, tuples) = translation(&schema);
        assert!(
            dsl.contains(&format!("expires_at > {offset_cel}")),
            "`{offset_sql}` stores `{stored}`, so it must ride the clock as `{offset_cel}`:\n{dsl}"
        );
        assert!(
            tuples.contains("jsonb_build_object('expires_at', \"expires_at\")"),
            "the row's own boundary still travels as context:\n{tuples}"
        );
    }
}

/// An interval no threshold follows falls closed: an infinite one, text `PostgreSQL` does
/// not read, a qualifier it refuses, a cast this does not follow, and a fixed length
/// beyond a CEL duration. The report names why, beside the value `PostgreSQL` 18.6 stores
/// for the literal.
#[test]
fn an_offset_no_threshold_follows_falls_closed_naming_why() {
    for (interval_sql, stored, reason) in [
        (
            "interval '1' day(3)",
            "a syntax error",
            "PostgreSQL does not read the field qualifier of INTERVAL '1' DAY (3)",
        ),
        (
            "interval '1' minute to hour",
            "a syntax error",
            "PostgreSQL does not read the field qualifier of INTERVAL '1' MINUTE TO HOUR",
        ),
        (
            "interval 1 hour",
            "a syntax error",
            "INTERVAL 1 HOUR is not a quoted string, so it has no fixed CEL duration",
        ),
        (
            "interval 'infinity'",
            "infinity",
            "INTERVAL 'infinity' has no finite length, so it has no CEL duration",
        ),
        (
            "interval '2562048 hours'",
            "2562048:00:00",
            "INTERVAL '2562048 hours' is longer than a CEL duration holds",
        ),
        (
            "interval '-2147483648 days'",
            "-2147483648 days, the subtraction raising interval out of range",
            "PostgreSQL raises interval out of range subtracting INTERVAL '-2147483648 days'",
        ),
        (
            "interval 'fortnight'",
            "an error",
            "PostgreSQL does not read 'fortnight' as an interval \
             (invalid input syntax for type interval)",
        ),
        (
            "'fortnight'::interval",
            "an error",
            "PostgreSQL does not read 'fortnight' as an interval \
             (invalid input syntax for type interval)",
        ),
        (
            "'1.75'::text::interval minute",
            "00:00:00, where '1.75'::interval minute stores 00:01:00",
            "'1.75'::TEXT::INTERVAL MINUTE casts through another type before the interval, \
             which this does not follow, so it has no fixed CEL duration",
        ),
        (
            "(interval '90 minutes')::interval hour",
            "01:00:00",
            "(INTERVAL '90 minutes')::INTERVAL HOUR casts the interval again, which this \
             does not follow, so it has no fixed CEL duration",
        ),
        (
            "now()::interval",
            "an error",
            "now()::INTERVAL is not a quoted string, so it has no fixed CEL duration",
        ),
    ] {
        for predicate in [
            format!("expires_at > now() - {interval_sql}"),
            format!("expires_at BETWEEN now() - {interval_sql} AND now()"),
        ] {
            let schema = format!(
                "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
                 ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                 CREATE POLICY docs_sel ON docs FOR SELECT USING ({predicate});\n"
            );
            let outputs = translator(ConfidenceLevel::B)
                .translate(&db_of(&schema))
                .expect("translation should plan")
                .outputs_accepting_gaps();
            let dsl = outputs.model();
            assert_eq!(
                relation_definition(&dsl, "docs", "can_select").as_deref(),
                Some("no_access"),
                "`{interval_sql}` stores `{stored}`, so `{predicate}` must fall closed:\n{dsl}"
            );
            let report = outputs.report();
            assert!(
                report.contains(reason),
                "`{predicate}` must be refused with `{reason}`:\n{report}"
            );
        }
    }
}

/// The offset carries across the spellings a policy may use: the interval leading the
/// clock, and the column on the right mirroring the comparison. Each still yields the same
/// duration on the request clock.
#[test]
fn interval_offsets_carry_across_spellings() {
    for (predicate, fragment) in [
        (
            "expires_at > interval '2 hours' + now()",
            "expires_at > request_time + duration(\"2h\")",
        ),
        (
            "now() - interval '36 hours' < expires_at",
            "expires_at > request_time - duration(\"36h\")",
        ),
    ] {
        let schema = format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY docs_sel ON docs FOR SELECT USING ({predicate});\n"
        );
        let (dsl, _tuples) = translation(&schema);
        assert!(
            dsl.contains(fragment),
            "`{predicate}` must carry as `{fragment}`:\n{dsl}"
        );
    }
}

/// The schema the cast tests guard, one column per family a cast can rename.
const CAST_GUARDED: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, \
                            level NUMERIC, amount NUMERIC, code TEXT, flag BOOLEAN, \
                            starts_on TIMESTAMP, expires_at TIMESTAMPTZ);\n\
                            ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n";

/// A cast that can change a compared value makes `PostgreSQL` compare something other
/// than the column or the clock as written, or a literal whose cast this cannot compute.
/// The tuple SQL and the request clock read them as written, so each falls closed and the
/// report names the cast. Beside each is what `PostgreSQL` 18.6 answers differently.
#[test]
fn a_cast_that_can_change_a_compared_value_falls_closed_naming_it() {
    const CHANGES: &str = "which can change the value PostgreSQL compares while the model \
                           compares it as written, so compare it uncast or as text";
    for (guard, diverging_row, cast) in [
        (
            "level >= '2.5'::int",
            "every row, PostgreSQL raising invalid input syntax for type integer",
            "'2.5'::INT is cast to int",
        ),
        (
            "level >= 2.7::text::int",
            "every row, PostgreSQL raising invalid input syntax for type integer",
            "2.7::TEXT::INT is cast to int",
        ),
        (
            "amount::int > 5",
            "amount 5.4",
            "amount::INT is cast to int",
        ),
        (
            "level = 'NaN'::numeric",
            "no bare SQL number, the cast being NaN",
            "'NaN'::NUMERIC is cast to numeric",
        ),
        (
            "level >= true::int",
            "every row as level >= 1, the uncast true not comparing with a number",
            "true::INT is cast to int",
        ),
        (
            "code = 'ab'::varchar(MAX)",
            "every row, PostgreSQL refusing the type at MAX",
            "'ab'::VARCHAR(MAX) is cast to varchar(max)",
        ),
        (
            "level >= 1::numeric(0,0)",
            "every row, PostgreSQL refusing NUMERIC precision 0",
            "1::NUMERIC(0,0) is cast to numeric(0,0)",
        ),
        (
            "starts_on < '2030-01-01 00:00:00+02'::timestamptz",
            "starts_on 2029-12-31 23:00, false under UTC and true under Europe/Athens",
            "'2030-01-01 00:00:00+02'::TIMESTAMPTZ is cast to timestamptz",
        ),
        (
            "starts_on < '2026-01-01 23:00'::date",
            "starts_on 2026-01-01 12:00",
            "'2026-01-01 23:00'::DATE is cast to date",
        ),
        (
            "starts_on < '2026-01-01 23:00:00.6'::timestamp(0)",
            "starts_on 2026-01-01 23:00:00.8, the cast rounding to 23:00:01",
            "'2026-01-01 23:00:00.6'::TIMESTAMP(0) is cast to timestamp(0)",
        ),
        (
            "expires_at > now()::date",
            "expires_at earlier today",
            "now()::DATE is cast to date",
        ),
        (
            "expires_at > (now() - interval '1 hour')::date",
            "expires_at earlier today",
            "(now() - INTERVAL '1 hour')::DATE is cast to date",
        ),
        (
            "expires_at BETWEEN now()::date AND now()",
            "expires_at earlier today",
            "now()::DATE is cast to date",
        ),
        (
            "expires_at > now()::timestamptz(0)",
            "expires_at within the second",
            "now()::TIMESTAMPTZ(0) is cast to timestamptz(0)",
        ),
    ] {
        let reason = format!("{cast}, {CHANGES}");
        let schema = format!(
            "{CAST_GUARDED}CREATE POLICY p ON docs FOR SELECT USING ({guard});\n\
             CREATE POLICY q ON docs FOR UPDATE USING \
             (owner_id = current_user AND {guard});\n"
        );
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db_of(&schema))
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        for action in ["can_select", "can_update"] {
            assert_eq!(
                relation_definition(&dsl, "docs", action).as_deref(),
                Some("no_access"),
                "`{guard}` answers {diverging_row} differently, so {action} must fall \
                 closed:\n{dsl}"
            );
        }
        let report = outputs.report();
        assert!(
            report.contains(&format!("| p (USING) | Unknown: {reason} |")),
            "`{guard}` must be refused naming the cast with `{reason}`:\n{report}"
        );
        assert!(
            report.contains(&format!(
                "| q (USING) | P8 (And of 2 parts, graded D by Unknown: {reason}) |"
            )),
            "the conjunction must name the cast too:\n{report}"
        );
    }
}

/// A literal cast once to a type whose cast `sql-values` computes compares as the value
/// `PostgreSQL` 18.6 makes of it, so the tuple SQL carries that value. Each folded guard
/// answered every row of a sample the same way as the cast one on 18.6.
#[test]
fn a_literal_cast_folds_into_the_value_postgresql_compares() {
    for (guard, stored, fragment) in [
        ("level >= 2.7::int", "3", "AND \"level\" >= 3;"),
        ("level >= CAST(2.7 AS integer)", "3", "AND \"level\" >= 3;"),
        ("level = 2.5::bigint", "3", "AND \"level\" = 3;"),
        ("level >= '07'::smallint", "7", "AND \"level\" >= 7;"),
        (
            "level >= '12.345'::numeric(4,1)",
            "12.3",
            "AND \"level\" >= 12.3;",
        ),
        ("code = 'abc'::char(2)", "ab", "AND \"code\" = 'ab';"),
        (
            "code = 'ab'::char(4)",
            "ab followed by two blanks",
            "AND \"code\" = 'ab';",
        ),
        (
            "code IN ('abc'::char(2), 'x')",
            "ab",
            "AND \"code\" IN ('ab', 'x');",
        ),
        ("code = 'ab'::varchar(1)", "a", "AND \"code\" = 'a';"),
        ("flag = 'yes'::boolean", "t", "AND \"flag\" = TRUE;"),
        ("flag = 'on'::bool", "t", "AND \"flag\" = TRUE;"),
        ("level >= '7'::int2", "7", "AND \"level\" >= 7;"),
        ("level >= '7'::int4", "7", "AND \"level\" >= 7;"),
        ("level >= '7'::int8", "7", "AND \"level\" >= 7;"),
        (
            "level >= 12.345::dec(4,1)",
            "12.3",
            "AND \"level\" >= 12.3;",
        ),
        (
            "level >= 12.345::decimal(4,1)",
            "12.3",
            "AND \"level\" >= 12.3;",
        ),
        ("level >= 12.5::numeric(3)", "13", "AND \"level\" >= 13;"),
        ("code = 'ab'::char varying(1)", "a", "AND \"code\" = 'a';"),
        (
            "code = 'ab'::character varying(1)",
            "a",
            "AND \"code\" = 'a';",
        ),
        ("code = 'abc'::character(2)", "ab", "AND \"code\" = 'ab';"),
        ("code = 'ab'::char", "a", "AND \"code\" = 'a';"),
        ("code = $$abc$$::char(2)", "ab", "AND \"code\" = 'ab';"),
    ] {
        let (dsl, tuples) = translation(&format!(
            "{CAST_GUARDED}CREATE POLICY p ON docs FOR SELECT USING ({guard});\n"
        ));
        assert!(
            tuples.contains(fragment),
            "`{guard}` casts to {stored}, so its tuples must read `{fragment}`:\n{tuples}"
        );
        assert!(
            !dsl.contains("define can_select: no_access"),
            "`{guard}` must translate:\n{dsl}"
        );
    }
}

/// A cast that renders text, or the clock cast to its own type, compares the value as
/// written, so the guard keeps translating.
#[test]
fn a_cast_that_keeps_a_compared_value_still_translates() {
    for (guard, fragment) in [
        ("code = 'x'::text", "AND \"code\" = 'x';"),
        ("code = 'x'::varchar", "AND \"code\" = 'x';"),
        ("code::text = 'x'", "AND \"code\" = 'x';"),
        (
            "code IN ('x'::text, 'y'::text)",
            "AND \"code\" IN ('x', 'y');",
        ),
        (
            "expires_at > now()::timestamptz",
            "expires_at > request_time",
        ),
        (
            "expires_at > CURRENT_TIMESTAMP::timestamp with time zone",
            "expires_at > request_time",
        ),
        (
            "expires_at > (now() - interval '1 hour')::timestamptz",
            "expires_at > request_time - duration(\"1h\")",
        ),
    ] {
        let (dsl, tuples) = translation(&format!(
            "{CAST_GUARDED}CREATE POLICY p ON docs FOR SELECT USING ({guard});\n"
        ));
        assert!(
            dsl.contains(fragment) || tuples.contains(fragment),
            "`{guard}` must still translate with `{fragment}`:\n{dsl}\n{tuples}"
        );
    }
}

/// A condition name is global to the model while a `PostgreSQL` policy name is unique
/// only per table, so one name reused across tables must not collapse two guards into
/// one spec. Here the two guards compare opposite ways, so sharing a spec inverts one of
/// them: rows of `campaigns` that have not started pass the model check while the
/// database hides them.
#[test]
fn two_tables_reusing_one_policy_name_get_their_own_condition() {
    let db = db_of(
        &std::fs::read_to_string("tests/fixtures/shared_policy_name/input.sql")
            .expect("the shared_policy_name fixture is readable"),
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    let campaigns = condition_of_gate(&dsl, "campaigns");
    let embargoes = condition_of_gate(&dsl, "embargoes");
    assert_ne!(
        campaigns, embargoes,
        "the two guards are different rules, so they cannot share one condition:\n{dsl}"
    );

    let specs = condition_expressions(&dsl);
    assert_eq!(
        specs.get(&campaigns).map(String::as_str),
        Some("starts_at <= request_time"),
        "the campaigns guard admits what already started:\n{dsl}"
    );
    assert_eq!(
        specs.get(&embargoes).map(String::as_str),
        Some("lifts_at > request_time"),
        "the embargoes guard admits what has not lifted:\n{dsl}"
    );
}

/// The condition a type's conditional gate points at.
fn condition_of_gate(dsl: &str, type_name: &str) -> String {
    let (_, subjects) = relation_definitions(dsl, type_name)
        .into_iter()
        .find(|(name, _)| name.starts_with("gate_"))
        .unwrap_or_else(|| panic!("{type_name} should define a conditional gate:\n{dsl}"));
    subjects
        .split(" with ")
        .nth(1)
        .unwrap_or_else(|| panic!("the gate of {type_name} carries no condition:\n{dsl}"))
        .trim_end_matches(']')
        .trim()
        .to_string()
}

/// Every condition the DSL declares, by name, with its expression.
fn condition_expressions(dsl: &str) -> std::collections::BTreeMap<String, String> {
    let mut found = std::collections::BTreeMap::new();
    let mut lines = dsl.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(rest) = line.trim().strip_prefix("condition ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once('(') else {
            continue;
        };
        if let Some(body) = lines.peek() {
            found.insert(name.trim().to_string(), body.trim().to_string());
        }
    }
    found
}

/// Every `(relation, subject column)` a relation takes from a row of its own table.
fn row_subject_columns(shapes: &[RelationShapes]) -> Vec<(RelationName, ColumnName)> {
    let mut out = Vec::new();
    for entry in shapes {
        for shape in &entry.shapes {
            if let RecordDerivation::FromRow { template, .. } = &shape.derivation {
                if let ValueSource::Column(column) = template.subject_key.part() {
                    out.push((entry.relation.clone(), column.column().clone()));
                }
            }
        }
    }
    out
}

/// `current_setting` returns whatever the key holds, so which key it names is the whole
/// question. Reading every call as the caller turns a tenant identifier into a user and
/// grants one tuple per tenant, and reading none of them leaves a policy that only ever
/// spells the call inline undecidable.
#[test]
fn only_a_named_setting_key_becomes_a_user_subject() {
    let owner_sql = r"
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_p ON notes USING (owner = current_setting('app.user_id', true));
";
    let tenant_sql = r"
CREATE TABLE rows_(id INTEGER PRIMARY KEY, tenant_id TEXT);
ALTER TABLE rows_ ENABLE ROW LEVEL SECURITY;
CREATE POLICY rows_p ON rows_ USING (tenant_id = current_setting('app.tenant_id', true));
";
    let translator = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    let owner_db = db_of(owner_sql);
    let granted = row_subject_columns(
        translator
            .translate(&owner_db)
            .expect("translation should plan")
            .relations(),
    );
    assert!(
        !granted.is_empty(),
        "the named key is the caller, so the owner column decides the row"
    );
    for (relation, column) in &granted {
        assert_eq!(
            column, "owner",
            "notes#{relation} grants the wrong column as a user"
        );
    }

    let tenant_db = db_of(tenant_sql);
    let translation = translator
        .translate(&tenant_db)
        .expect("translation should plan");
    let tenant_relations = translation.relations();
    assert!(
        row_subject_columns(tenant_relations).is_empty(),
        "no key names the caller here, so nothing may become a user subject: {tenant_relations:#?}"
    );
}

/// One predicate decides who the caller is, so a named key read inline reaches every
/// recognizer that asks it. The call itself never reaches what the loader runs: the
/// subject comes from the row, and a `current_setting` in a loader query would read the
/// loader's own session and load nothing.
#[test]
fn a_named_key_read_inline_reaches_every_recognizer_and_leaves_the_loader_clean() {
    let cases = [
        (
            "ownership",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
",
        ),
        (
            "membership through a subquery",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  current_setting('app.user_id', true) IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id)
);
",
        ),
        (
            "an array column's elements",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, viewers TEXT[]);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (current_setting('app.user_id', true) = ANY (viewers));
",
        ),
        (
            "a jsonb field",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, data JSONB);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (data ->> 'owner' = current_setting('app.user_id', true));
",
        ),
        (
            "a role the caller holds",
            r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (pg_has_role(current_setting('app.user_id', true), 'editors', 'MEMBER'));
",
        ),
    ];

    for (label, sql) in cases {
        let db = db_of(sql);
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        assert!(
            !relation_denies(&dsl, "docs", "can_select"),
            "{label}: the named key is the caller, so reads are not denied:\n{dsl}"
        );
        let queries = outputs.tuple_queries();
        assert!(
            !queries.is_empty(),
            "{label}: a granting relation needs tuples to grant through:\n{dsl}"
        );
        let tuples = format_tuples(queries);
        assert!(
            !tuples.contains("current_setting"),
            "{label}: the loader reads rows, not the caller's own session:\n{tuples}"
        );
    }
}

/// A scalar subquery in the accessor position is read as the caller, but only when it is
/// nothing but its projection. Given a `FROM` or a `WHERE` it is a conjunct in disguise:
/// it yields NULL when nothing survives, which filters every row out, while the pattern
/// keeps only a column name and would grant the column unconditionally.
#[test]
fn a_filtering_accessor_subquery_is_refused_not_read_as_the_caller() {
    let guarded = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
CREATE TABLE kill_switch(name TEXT PRIMARY KEY, enabled BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  owner_id = (SELECT current_setting('app.user_id', true)
              FROM kill_switch WHERE name = 'docs_read' AND enabled)
);
";
    let bare = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = (SELECT current_setting('app.user_id', true)));
";
    let emptied = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = (SELECT current_setting('app.user_id', true) LIMIT 0));
";

    for (label, sql) in [("a read of a table", guarded), ("a row limit", emptied)] {
        let db = db_of(sql);
        let translation = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan");
        let relations = translation.relations();
        assert!(
            row_subject_columns(relations).is_empty(),
            "{label} can empty the subquery, so the column it compares is not the caller"
        );
    }

    let db = db_of(bare);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let relations = translation.relations();
    assert_eq!(
        row_subject_columns(relations)
            .iter()
            .map(|(_, column)| column.as_str())
            .collect::<Vec<_>>(),
        ["owner_id"],
        "a subquery that is only its projection is still the caller"
    );
}

/// One database written two ways must not land in two behaviours, so the two spellings
/// of each caller carried set emit byte identical DSL.
///
/// Asserted per database rather than across the family: jsonb containment is a different
/// predicate, which the probe behind D6 established, so nothing here compares against it.
#[test]
fn one_caller_carried_set_written_two_ways_emits_one_model() {
    fn model(clause: &str, preamble: &str, attribute: SessionAttribute) -> String {
        let db = db_of(&format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
             {preamble}\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY p ON documents FOR SELECT USING ({clause});\n"
        ));
        TranslatorBuilder::new()
            .with_min_confidence(ConfidenceLevel::B)
            .with_session_attributes(vec![attribute])
            .build()
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model()
            .clone()
    }

    const CLAIM: &str = "jsonb_array_elements_text(\
                         current_setting('request.jwt.claims')::jsonb -> 'teams')";
    const WRAPPER: &str = "CREATE FUNCTION user_teams() RETURNS SETOF TEXT LANGUAGE sql STABLE\n\
          AS 'SELECT unnest(string_to_array(current_setting(''app.teams'', true), '','')) ';\n";
    let token = || {
        SessionAttribute::claim(
            "request.jwt.claims",
            ["teams"],
            SessionAttributeKind::SetAttribute,
        )
    };
    let in_form = model(&format!("team_id IN (SELECT {CLAIM})"), "", token());
    let array_form = model(
        &format!("team_id = ANY (ARRAY(SELECT {CLAIM}))"),
        "",
        token(),
    );
    assert_eq!(
        in_form, array_form,
        "a token carried list must not answer differently for being spelled with ARRAY"
    );
    assert!(
        in_form.contains("define can_select: gate_p_"),
        "the shape must actually translate rather than agreeing on a denial: {in_form}"
    );

    let setting = || SessionAttribute::setting("app.teams", SessionAttributeKind::SetAttribute);
    let in_form = model("team_id IN (SELECT user_teams())", WRAPPER, setting());
    let array_form = model(
        "team_id = ANY (ARRAY(SELECT user_teams()))",
        WRAPPER,
        setting(),
    );
    assert_eq!(
        in_form, array_form,
        "a function carried set must not answer differently for being spelled with ARRAY"
    );
    assert!(
        in_form.contains("define can_select: gate_p_"),
        "the shape must actually translate rather than agreeing on a denial: {in_form}"
    );
}

/// The two shapes D6 and D7 refuse, pinned so admitting either needs a red test first.
///
/// Containment matches only the string elements of a jsonb array, so a claim of `[1,2]`
/// against `'1'` answers false where the two admitted spellings answer true. A function
/// body reading a table puts the authority in that table, where a value the caller sends
/// would let it assert its own membership.
#[test]
fn a_set_the_authority_does_not_supply_is_refused() {
    fn classify(preamble: &str, clause: &str, attribute: SessionAttribute) -> PatternClass {
        let db = db_of(&format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
             CREATE TABLE members(user_id TEXT, team_id TEXT);\n\
             {preamble}\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY p ON documents FOR SELECT USING ({clause});\n"
        ));
        TranslatorBuilder::new()
            .with_session_attributes(vec![attribute])
            .build()
            .classify(&db)[0]
            .using_classification()
            .expect("expected a USING classification")
            .pattern
            .clone()
    }

    let containment = classify(
        "",
        "current_setting('request.jwt.claims')::jsonb -> 'teams' ? team_id",
        SessionAttribute::claim(
            "request.jwt.claims",
            ["teams"],
            SessionAttributeKind::SetAttribute,
        ),
    );
    assert!(
        matches!(containment, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "containment is a different predicate, not a third spelling, got {containment:?}"
    );

    let from_a_table = classify(
        "CREATE FUNCTION user_teams() RETURNS SETOF TEXT LANGUAGE sql STABLE\n\
           AS 'SELECT team_id FROM members WHERE user_id = current_setting(''app.teams'', true)';\n",
        "team_id IN (SELECT user_teams())",
        SessionAttribute::setting("app.teams", SessionAttributeKind::SetAttribute),
    );
    assert!(
        matches!(from_a_table, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "a table owns its own facts, so the caller may not assert them, got {from_a_table:?}"
    );
}

/// A real list has no delimiter, so nothing may synthesise one into the caller contract.
///
/// The delimited string contract tells the caller to send what `string_to_array` would
/// produce, which is the one reachable wrong allow in the feature. Leaking that sentence
/// onto a shape with no delimiter would state a hazard that does not exist and name a
/// separator the policy never wrote.
#[test]
fn a_list_source_states_no_separator_in_its_caller_contract() {
    let db = db_of(
        "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
         ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY p ON documents FOR SELECT USING (team_id IN (SELECT \
         jsonb_array_elements_text(current_setting('request.jwt.claims')::jsonb -> 'teams')));\n",
    );
    let outputs = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes(vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["teams"],
            SessionAttributeKind::SetAttribute,
        )])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let contract = outputs
        .notes()
        .iter()
        .find_map(|note| match note {
            TranslationNote::CallerSuppliesConditionParameter {
                parameter,
                separator,
                ..
            } => Some((parameter.clone(), separator.clone())),
            _ => None,
        })
        .expect("every request scoped gate states its contract with the caller");
    assert_eq!(contract.0, "request_jwt_claims_teams");
    assert_eq!(
        contract.1, None,
        "a list carries no separator, so none may be invented"
    );
    assert!(
        !outputs.report().contains("string_to_array"),
        "the delimited string contract must not leak onto a shape with no delimiter"
    );
}
#[test]
fn derived_condition_parameter_collisions_are_rejected_model_wide() {
    let sql = r"
CREATE TABLE left_docs(id UUID PRIMARY KEY, tenant_id TEXT);
CREATE TABLE right_docs(id UUID PRIMARY KEY, tenant_id TEXT);
ALTER TABLE left_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE right_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON left_docs FOR SELECT
    USING (tenant_id = current_setting('a.b'));
CREATE POLICY p ON right_docs FOR SELECT
    USING (tenant_id = current_setting('a_b'));
";
    let db = db_of(sql);
    let result = TranslatorBuilder::new()
        .with_session_attributes([
            SessionAttribute::setting("a.b", SessionAttributeKind::ScalarAttribute),
            SessionAttribute::setting("a_b", SessionAttributeKind::ScalarAttribute),
        ])
        .build()
        .translate(&db);
    assert!(
        result.is_err(),
        "two request sources must not share a parameter"
    );
}

#[test]
fn session_attribute_cannot_alias_request_time_parameter() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, tenant_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (tenant_id = current_setting('request.time'));
";
    let db = db_of(sql);
    let result = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "request.time",
            SessionAttributeKind::ScalarAttribute,
        )])
        .build()
        .translate(&db);
    assert!(
        result.is_err(),
        "a session source must not alias request time"
    );
}

#[test]
fn valid_custom_condition_parameter_name_is_preserved() {
    let attribute = serde_json::from_value::<SessionAttribute>(serde_json::json!({
        "key": "app.tenant_id",
        "kind": "scalar_attribute",
        "parameter": "TenantValue_2",
    }))
    .expect("the custom parameter should parse");
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, tenant_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id'));
";
    let db = db_of(sql);
    let model = TranslatorBuilder::new()
        .with_session_attributes([attribute])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .json_model();
    let condition = model
        .conditions
        .as_ref()
        .and_then(|conditions| {
            conditions
                .values()
                .find(|condition| condition.parameters.contains_key("TenantValue_2"))
        })
        .expect("the model should keep the custom parameter");
    assert!(condition.expression.contains("TenantValue_2"));
}
