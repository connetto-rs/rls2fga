//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! What the report says, and which denial it attributes to whom.

use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{NoteSeverity, TranslationNote};

mod support;

use support::footgun::{
    db_of, relation_definition, relation_denies, translation, translator, type_names,
};

/// `PostgreSQL` identifiers may contain newlines, which end a `--` comment early
/// and turn the rest of the identifier into an executable statement.
#[test]
fn generated_comments_cannot_escape_into_executable_sql() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY);\n\
         CREATE TABLE \"doc_mem\nSELECT 1; --\"(doc_id UUID, user_id UUID);\n\
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\n\
           SELECT 1 FROM \"doc_mem\nSELECT 1; --\" m\n\
           WHERE m.doc_id = docs.id AND m.user_id = current_user));\n",
    );
    let outputs = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();

    assert!(!tuples.is_empty(), "expected membership tuple queries");
    for query in tuples {
        assert!(
            query.comment.starts_with("--"),
            "a query comment must be a comment: {:?}",
            query.comment
        );
        assert!(
            !query.comment.contains('\n') && !query.comment.contains('\r'),
            "comment spans multiple lines, so its tail executes as SQL: {:?}",
            query.comment
        );
        assert!(
            !query.comment.chars().any(char::is_control),
            "control characters in a comment can terminate it: {:?}",
            query.comment
        );
    }
    assert!(
        tuples
            .iter()
            .any(|query| query.comment.contains("doc_mem SELECT 1; --")),
        "the comment must still name the source table, collapsed onto one line: {tuples:#?}"
    );
}

/// Enabling RLS without any policy denies every row. Omitting the table from the
/// model instead implies unrestricted access.
#[test]
fn rls_enabled_table_without_policies_denies_every_command() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        type_names(&model.model()).iter().any(|name| name == "docs"),
        "an RLS-enabled table must appear in the model:\n{}",
        model.model()
    );
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        let definition = relation_definition(&model.model(), "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.model()));
        assert!(
            definition.contains("no_access"),
            "RLS with no policy denies {relation}, got 'define {relation}: {definition}'"
        );
    }
}

/// `FOR INSERT`-only RLS makes the table unreadable.
#[test]
fn command_without_permissive_policy_is_denied() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_insert").as_deref(),
        Some("owner"),
        "the INSERT policy must still translate:\n{}",
        model.model()
    );
    for relation in ["can_select", "can_update", "can_delete"] {
        let definition = relation_definition(&model.model(), "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.model()));
        assert!(
            definition.contains("no_access"),
            "no policy covers {relation}, so RLS denies it, got 'define {relation}: {definition}'"
        );
    }
}

/// A table whose only policy is dropped must still be denied, not omitted.
#[test]
fn table_whose_only_policy_is_filtered_denies_every_command() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_tenant ON docs FOR ALL USING (tenant = current_setting('app.tenant'));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        let definition = relation_definition(&model.model(), "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.model()));
        assert!(
            definition.contains("no_access"),
            "filtered-out policies leave the table denied, got 'define {relation}: {definition}'"
        );
    }
}

/// A dropped permissive policy leaves the model denying what RLS grants. Saying
/// no policy covers the command instead tells the operator that `PostgreSQL`
/// denies it, which is the opposite of the truth.
#[test]
fn a_command_denied_only_by_filtering_is_not_reported_as_unpolicied() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_pub ON docs FOR SELECT USING (is_public = TRUE);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        !messages
            .iter()
            .any(|message| message.contains("No permissive policy on 'docs' covers SELECT")),
        "a permissive SELECT policy exists and was dropped: {messages:#?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("confidence threshold") && message.contains("SELECT")),
        "the operator must be told the policy was dropped: {messages:#?}"
    );
}

/// A dropped PERMISSIVE clause narrows the model rather than widening it, but the
/// operator still loses a policy they wrote.
#[test]
fn report_names_dropped_permissive_policies_and_their_reason() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_tenant ON docs FOR SELECT USING (tenant = current_setting('app.tenant'));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let _classified = translator.classify(&db);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let report = model.report();
    assert!(
        report.contains("docs_tenant"),
        "a dropped permissive policy must still be named:\n{report}"
    );
    assert!(
        report.contains("`docs_tenant` (USING, PERMISSIVE SELECT, confidence D)"),
        "the dropped-policy line must state the clause, the mode, the command and the confidence that caused the drop:\n{report}"
    );
}

/// The report is where an operator learns why a policy vanished, so "no known
/// pattern" sends them re-reading a clause the translator could have named.
#[test]
fn report_names_the_function_call_that_defeated_recognition() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (tenant_of(owner_id) = 'acme');
",
    );
    let translator = translator(ConfidenceLevel::B);
    let _classified = translator.classify(&db);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let report = model.report();
    assert!(
        report.contains("tenant_of"),
        "the call the operator has to go read must be named:\n{report}"
    );
    assert!(
        !report.contains("does not match any known pattern"),
        "a named call replaces the generic reason rather than joining it:\n{report}"
    );
}

/// A dropped clause appears in neither the model nor the tuples, so the report is
/// the only place its loss is visible.
#[test]
fn report_enumerates_policies_dropped_by_confidence_filtering() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, tenant TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_tenant ON docs AS RESTRICTIVE FOR SELECT
  USING (tenant = current_setting('app.tenant'));
",
    );
    let translator = translator(ConfidenceLevel::B);
    let _classified = translator.classify(&db);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let report = model.report();
    assert!(
        report.contains("docs_owner"),
        "translated policies stay in the report:\n{report}"
    );
    assert!(
        report.contains("docs_tenant"),
        "a policy dropped below the confidence threshold must still be listed:\n{report}"
    );
}

/// `FOR UPDATE` covers two phases, so one untranslatable clause is translated
/// twice. The operator should still be told once: a doubled list inflates the
/// apparent amount of manual work and hides how many policies really need review.
/// The guard is a `LIKE`, a shape the translator leaves to the application.
#[test]
fn one_clause_is_reported_once_even_when_it_covers_two_phases() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user AND status LIKE 'live%');
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user AND status LIKE 'live%');
",
    );
    let model = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    for policy in ["docs_sel", "docs_upd"] {
        let count = model
            .notes()
            .iter()
            .filter(|note| note.subject() == policy && note.message().contains("status"))
            .count();
        assert_eq!(
            count,
            1,
            "{policy} should report its attribute guard once, got {count}: {:#?}",
            model.notes()
        );
    }
}

/// A rule the parent's own `can_select` already allows needs no gate.
#[test]
fn a_redundant_select_gate_is_left_out() {
    let inherited_body = |parent_policies: &str| {
        let db = db_of(&format!(
            "CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID, \
             is_public BOOLEAN);\n\
             ALTER TABLE projects ENABLE ROW LEVEL SECURITY;\n\
             {parent_policies}\
             CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));\n\
             ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY tasks_sel ON tasks FOR SELECT USING (\n\
               EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id\n\
                       AND p.owner_id = current_user));\n"
        ));
        let dsl = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model();
        let can_select = relation_definition(&dsl, "tasks", "can_select")
            .expect("tasks should define can_select");
        let (walked, _) = can_select
            .split_once(" from ")
            .expect("inheritance walks a tupleset");
        (
            walked.to_string(),
            relation_definition(&dsl, "projects", walked),
            dsl,
        )
    };

    // The parent admits exactly the rule the child names, so no gate is needed.
    let (walked, body, dsl) = inherited_body(
        "CREATE POLICY proj_own ON projects FOR SELECT USING (owner_id = current_user);\n",
    );
    assert_eq!(
        walked, "owner",
        "the child should walk the parent's own relation, got '{walked}':\n{dsl}"
    );
    assert_eq!(
        body.as_deref(),
        Some("[user]"),
        "no gated relation should be synthesized:\n{dsl}"
    );

    // The rule is one branch of the parent's union, so it still implies visibility.
    let (walked, _, dsl) = inherited_body(
        "CREATE POLICY proj_own ON projects FOR SELECT USING (owner_id = current_user);\n\
         CREATE POLICY proj_pub ON projects FOR SELECT USING (is_public = TRUE);\n",
    );
    assert_eq!(
        walked, "owner",
        "a rule the parent's union already contains needs no gate, got '{walked}':\n{dsl}"
    );

    // The parent admits strictly less than the rule, so the gate has to stay.
    let (walked, body, dsl) = inherited_body(
        "CREATE POLICY proj_editor ON projects FOR SELECT USING (editor_id = current_user);\n",
    );
    assert!(
        body.is_some_and(|body| body.contains("can_select")),
        "a rule the parent does not already allow must stay gated, got '{walked}':\n{dsl}"
    );
}

/// Per relation, not per table: a table denying reads can still grant inserts.
#[test]
fn a_relation_reached_only_by_insert_keeps_its_tuples() {
    let sql = r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, parent_id INTEGER, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.editor_id = current_user));
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
";
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::B);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the recursive read policy denies reads:\n{dsl}"
    );
    let can_insert =
        relation_definition(&dsl, "docs", "can_insert").expect("docs should define can_insert");
    assert_ne!(can_insert, "no_access", "the INSERT policy grants:\n{dsl}");

    assert!(
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains(&format!("'{can_insert}' AS relation"))),
        "can_insert reads '{can_insert}', so its tuples are still needed:\n{dsl}"
    );
}

/// A model that grants normally keeps every query it needs.
#[test]
fn a_granting_model_keeps_its_tuple_queries() {
    let sql = r"
CREATE TABLE projects(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (owner_id = current_user);
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id AND p.owner_id = current_user));
";
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::B);
    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let queries = outputs.tuple_queries();
    assert!(
        queries
            .iter()
            .any(|query| query.sql.contains("'owner' AS relation")),
        "the ownership query is still needed: {queries:#?}"
    );
    assert!(
        queries
            .iter()
            .any(|query| query.sql.contains("'projects' AS relation")),
        "the parent bridge is still needed: {queries:#?}"
    );
}

/// A write policy on a table whose reads are denied can never match, so say so.
#[test]
fn a_write_policy_without_readable_rows_is_reported() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let reports = model
        .notes()
        .iter()
        .filter(|note| note.message().contains("docs") && note.message().contains("SELECT policy"))
        .count();
    assert_eq!(
        reports,
        1,
        "the unreachable DELETE policy must be reported once, got {:#?}",
        model.notes()
    );

    // A table that grants reads has nothing to report.
    let readable = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
",
    );
    assert!(
        !translator(ConfidenceLevel::B)
            .translate(&readable)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .any(|note| note.message().contains("SELECT policy")),
        "a readable table needs no such note"
    );

    // An INSERT reads nothing, so an insert-only table is not affected either.
    let insert_only = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
",
    );
    assert!(
        !translator(ConfidenceLevel::B)
            .translate(&insert_only)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .any(|note| note.message().contains("SELECT policy")),
        "an INSERT needs no read, so nothing is unreachable"
    );
}

/// A clauseless policy fails both halves, and the two halves read different
/// clauses, so the operator needs both named.
#[test]
fn report_names_both_clauses_a_bare_policy_omits() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_bare ON docs;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages.iter().any(|message| {
            message.contains("'docs_bare' names SELECT, UPDATE, DELETE without a USING clause")
        }),
        "the commands a missing USING denies must be named: {messages:#?}"
    );
    assert!(
        messages.iter().any(|message| {
            message.contains("'docs_bare' names INSERT without a WITH CHECK clause")
        }),
        "an INSERT reads the WITH CHECK alone: {messages:#?}"
    );
}

/// The three outcomes that shared one prose channel have to be separable by type,
/// because only one of them is a failure. The sharpest case is the same schema at two
/// thresholds: at `D` the crate could not classify the expression, at `B` the caller's
/// own threshold dropped it, and a message-matching consumer cannot tell those apart.
#[test]
fn each_outcome_carries_its_own_severity() {
    let refused = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING ((bits & 2) = 2);\n";
    let db = db_of(refused);

    let severities = |level: ConfidenceLevel| -> Vec<NoteSeverity> {
        translator(level)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .notes()
            .iter()
            .map(TranslationNote::severity)
            .collect()
    };

    assert!(
        severities(ConfidenceLevel::D).contains(&NoteSeverity::Unhandled),
        "nobody classified the expression, so it is a gap: {:?}",
        severities(ConfidenceLevel::D)
    );
    assert!(
        !severities(ConfidenceLevel::D).contains(&NoteSeverity::BelowThreshold),
        "the threshold admitted it, so it did not drop it"
    );
    assert!(
        severities(ConfidenceLevel::B).contains(&NoteSeverity::BelowThreshold),
        "the caller's own threshold dropped it: {:?}",
        severities(ConfidenceLevel::B)
    );
    assert!(
        !severities(ConfidenceLevel::B).contains(&NoteSeverity::Unhandled),
        "a clause the caller chose to drop is not an unhandled expression"
    );

    // A hybrid whose guard the translator leaves to the application (a `LIKE`)
    // keeps that half out, which is neither a gap nor complete.
    let hybrid = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, status TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT \
                  USING (owner_id = current_user AND status LIKE 'live%');\n";
    let hybrid_db = db_of(hybrid);
    let hybrid_outputs = translator(ConfidenceLevel::C)
        .translate(&hybrid_db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let hybrid_notes = hybrid_outputs.notes();
    assert!(
        hybrid_notes
            .iter()
            .any(|note| note.severity() == NoteSeverity::Partial),
        "the attribute half is a documented partial: {hybrid_notes:?}"
    );

    // And a command the database itself denies is not a failure of anything.
    assert!(
        hybrid_notes
            .iter()
            .any(|note| note.severity() == NoteSeverity::Faithful),
        "no policy covers INSERT, which RLS denies too: {hybrid_notes:?}"
    );
    assert!(
        !hybrid_notes
            .iter()
            .any(|note| note.severity() == NoteSeverity::Unhandled),
        "nothing here went unclassified: {hybrid_notes:?}"
    );
}

/// A policy is created once and then tuned, so a migration bundle carries the final
/// rule in an `ALTER POLICY` rather than in the `CREATE POLICY`. Translating the
/// original is an over-grant whenever the alteration narrowed the policy, which is the
/// whole reason such a schema used to be refused outright.
#[test]
fn the_model_follows_a_policy_altered_after_creation() {
    let created = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n";
    let narrowed = format!("{created}ALTER POLICY docs_sel ON docs USING (FALSE);\n");

    let (before, _) = translation(created);
    assert_eq!(
        relation_definition(&before, "docs", "can_select").as_deref(),
        Some("owner"),
        "the created policy grants the owner:\n{before}"
    );

    let (after, tuples) = translation(&narrowed);
    assert_eq!(
        relation_definition(&after, "docs", "can_select").as_deref(),
        Some("no_access"),
        "the altered policy grants nobody, and the model has to say so:\n{after}"
    );
    assert!(
        !tuples.contains("'owner' AS relation"),
        "and no tuple may still feed the superseded rule:\n{tuples}"
    );
}

/// Phase 1, test 4. A permissive `WITH CHECK` the threshold dropped must not come
/// back through the bucket-level mirror. `for_each_policy_target_expr` honours the
/// suppression per policy, but the composed check falls back to the composed
/// `USING` when the bucket ends up empty, which resurrects exactly the clause that
/// was refused and grants the update the model meant to deny. Only the check half
/// falls closed: the surviving `USING` still answers a locking read.
#[test]
fn a_filtered_with_check_does_not_resurrect_through_the_bucket_mirror() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user)
  WITH CHECK (opaque_gate(id));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert_ne!(
        relation_definition(&dsl, "docs", "can_update").as_deref(),
        Some("owner"),
        "the dropped WITH CHECK came back as the USING:\n{dsl}"
    );
    assert!(
        relation_denies(&dsl, "docs", "can_update_check"),
        "a check with no surviving arm has to fall closed:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select_for_update").as_deref(),
        Some("can_update_using"),
        "a locking read filters by the USING alone, which survived:\n{dsl}"
    );
}

/// Phase 1, test 5. A clause the caller's threshold dropped is named by a typed note
/// carrying what it cost, which is the only machine readable channel for it: the
/// surviving-policy summary is built from the filtered set by design, and prose in
/// the report is not something a program reads.
#[test]
fn a_clause_the_threshold_dropped_is_named_by_a_typed_note() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_opaque ON docs FOR SELECT USING (opaque_gate(id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let dropped: Vec<&TranslationNote> = outputs
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. }))
        .collect();
    assert_eq!(
        dropped.len(),
        1,
        "one note per dropped clause: {:?}",
        outputs.notes()
    );
    let TranslationNote::ClauseBelowThreshold {
        table,
        policy,
        mode,
        clause,
        confidence,
        commands,
        relations,
    } = dropped[0]
    else {
        unreachable!("filtered above")
    };
    assert_eq!(
        (
            table.to_string(),
            policy.as_str(),
            mode.as_str(),
            clause.as_str(),
            *confidence
        ),
        (
            "docs".to_string(),
            "docs_opaque",
            "PERMISSIVE",
            "USING",
            ConfidenceLevel::D
        )
    );
    assert_eq!(commands, &["SELECT".to_string()]);
    assert_eq!(relations, &["can_select".to_string()]);
    assert_eq!(
        dropped[0].severity(),
        NoteSeverity::BelowThreshold,
        "the caller's own threshold is not an unhandled expression"
    );
}

/// Phase 1, test 5, second half. A `FOR ALL` policy is translated once per phase, so
/// the note has to be one per lost clause rather than one per phase it fed.
#[test]
fn a_dropped_for_all_policy_reports_one_note_per_clause_not_per_phase() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR ALL USING (owner_id = current_user)
  WITH CHECK (owner_id = current_user);
CREATE POLICY docs_opaque ON docs FOR ALL USING (opaque_gate(id))
  WITH CHECK (opaque_gate(id));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let clauses: Vec<(&str, &[String])> = outputs
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::ClauseBelowThreshold {
                clause, commands, ..
            } => Some((clause.as_str(), commands.as_slice())),
            _ => None,
        })
        .collect();

    assert_eq!(
        clauses,
        vec![
            (
                "USING",
                ["SELECT", "UPDATE", "DELETE"].map(String::from).as_slice()
            ),
            (
                "WITH CHECK",
                ["INSERT", "UPDATE"].map(String::from).as_slice()
            ),
        ],
        "two stored clauses, two notes, each naming the commands it fed"
    );

    // A FOR ALL USING feeds both UPDATE targets, which share `can_update` and
    // `can_update_without_reading`, so an undeduplicated list names each twice and
    // stops matching the scar it is supposed to describe.
    for note in outputs.notes() {
        let TranslationNote::ClauseBelowThreshold { relations, .. } = note else {
            continue;
        };
        let mut unique = relations.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            &unique, relations,
            "the note names each diverged relation once: {relations:?}"
        );
    }
}

/// Phase 2, test 7. A table whose rows no tuple can name still carried its policy's
/// grant into the model, so `OpenFGA` denied everyone where `PostgreSQL` grants the
/// viewer and the only place that said so was a comment in the tuple SQL.
#[test]
fn a_grant_no_tuple_can_fill_denies_and_is_reported() {
    for (cause, declaration, expected_reason) in [
        (
            "no primary key and an 'id' that identifies no row",
            "CREATE TABLE shares(id UUID, viewer TEXT);",
            "no primary key, and 'id' is nullable or not uniquely constrained, so it does \
             not identify a row",
        ),
        (
            "no primary key and no 'id'",
            "CREATE TABLE shares(paper_id UUID, viewer TEXT);",
            "missing object identifier column",
        ),
    ] {
        let db = db_of(&format!(
            "{declaration}
ALTER TABLE shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON shares FOR SELECT USING (viewer = current_user);
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        assert_eq!(
            relation_definition(&dsl, "shares", "can_select").as_deref(),
            Some("no_access"),
            "{cause}: no fact can name a row, so the read denies rather than standing as \
             a permission nothing can satisfy:\n{dsl}"
        );
        let named: Vec<&TranslationNote> = outputs
            .notes()
            .iter()
            .filter(|note| matches!(note, TranslationNote::RowsCannotBeNamed { .. }))
            .collect();
        let [note] = named.as_slice() else {
            panic!(
                "{cause}: the model denies what PostgreSQL grants, so exactly one note \
                 has to say so: {:#?}",
                outputs.notes()
            );
        };
        let TranslationNote::RowsCannotBeNamed {
            table,
            reason,
            sources,
        } = note
        else {
            unreachable!("filtered above")
        };
        assert_eq!(
            (table.to_string(), sources.as_slice()),
            ("shares".to_string(), &["ownership tuples".to_string()][..])
        );
        assert_eq!(
            reason, expected_reason,
            "{cause}: the note names the cause the tuple script names"
        );
        assert!(
            note.severity().diverges_from_database(),
            "{cause}: a grant nothing can fill is a disagreement with the database"
        );
    }
}

/// A barrier with nothing permissive to narrow refuses every command, exactly as row-level
/// security with no policy at all does. The model is the same either way, so the report has
/// to be too, and coverage was read off whether a relation existed rather than whether it
/// grants.
#[test]
fn a_barrier_with_nothing_to_narrow_reports_the_commands_it_refuses() {
    let db = db_of(
        "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_barrier ON docs AS RESTRICTIVE USING (owner_id = current_user);
",
    );
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let notes: Vec<TranslationNote> = translation.notes().to_vec();
    let dsl = translation.outputs_accepting_gaps().model();
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert!(
            relation_denies(&dsl, "docs", relation),
            "the barrier alone grants nobody {relation}:\n{dsl}"
        );
    }
    let named: Vec<&TranslationNote> = notes
        .iter()
        .filter(|note| matches!(note, TranslationNote::NoPermissivePolicy { .. }))
        .collect();
    let [note] = named.as_slice() else {
        panic!("one note names the commands nothing covers: {notes:#?}");
    };
    let TranslationNote::NoPermissivePolicy { table, commands } = note else {
        unreachable!("filtered above")
    };
    assert_eq!(
        (table.to_string(), commands.as_slice()),
        (
            "docs".to_string(),
            &[
                "SELECT".to_string(),
                "INSERT".to_string(),
                "UPDATE".to_string(),
                "DELETE".to_string(),
            ][..]
        )
    );
    assert!(
        !note.severity().diverges_from_database(),
        "PostgreSQL refuses the same commands, so nothing here disagrees with it"
    );
}

/// The read gate is a different denial from a missing policy: a permissive `UPDATE` policy
/// covers the command and the database still refuses it, so nothing may claim the
/// threshold dropped a clause here.
#[test]
fn a_write_the_read_gate_blocks_names_the_commands_it_blocks() {
    for (label, sql, expected) in [
        (
            "update alone",
            "CREATE TABLE docs(id UUID PRIMARY KEY, editor TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_u ON docs FOR UPDATE USING (editor = current_user);
",
            vec!["UPDATE".to_string()],
        ),
        (
            "update and delete",
            "CREATE TABLE docs(id UUID PRIMARY KEY, editor TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_u ON docs FOR UPDATE USING (editor = current_user);
CREATE POLICY docs_d ON docs FOR DELETE USING (editor = current_user);
",
            vec!["UPDATE".to_string(), "DELETE".to_string()],
        ),
    ] {
        let db = db_of(sql);
        let notes: Vec<TranslationNote> = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .notes()
            .to_vec();
        let named: Vec<&TranslationNote> = notes
            .iter()
            .filter(|note| matches!(note, TranslationNote::ReadsDeniedSoWritesCannotName { .. }))
            .collect();
        let [note] = named.as_slice() else {
            panic!("{label}: one note says the read gate closed the writes: {notes:#?}");
        };
        let TranslationNote::ReadsDeniedSoWritesCannotName { commands, .. } = note else {
            unreachable!("filtered above")
        };
        assert_eq!(commands, &expected, "{label}: the blocked commands");
        assert!(
            note.to_string().contains("UPDATE"),
            "{label}: and the line names them: {note}"
        );
        assert!(
            !notes
                .iter()
                .any(|note| matches!(note, TranslationNote::CoveringPoliciesBelowThreshold { .. })),
            "{label}: no clause fell below the bar, the read gate closed it: {notes:#?}"
        );
    }
}

/// `IS NOT FALSE` also admits NULL, while public-flag tuples include only TRUE rows.
#[test]
fn nullable_boolean_flag_narrowing_is_disclosed() {
    let schema = |constraint: &str, predicate: &str| {
        format!(
            "CREATE TABLE docs(id UUID PRIMARY KEY, is_public BOOLEAN{constraint});\n\
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY p ON docs FOR SELECT USING ({predicate});\n"
        )
    };

    let db = db_of(&schema("", "is_public IS NOT FALSE"));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let note = outputs
        .notes()
        .iter()
        .find(|note| note.subject() == "p" && note.message().contains("NULL"))
        .expect("the missing NULL rows must be disclosed");
    assert_eq!(note.severity(), NoteSeverity::Partial);

    let db = db_of(&schema("", "is_public IS TRUE"));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.subject() == "p" && note.severity() == NoteSeverity::Partial),
        "IS TRUE has no nullable narrowing: {:#?}",
        outputs.notes()
    );

    let db = db_of(&schema(" NOT NULL", "is_public IS NOT FALSE"));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.subject() == "p" && note.severity() == NoteSeverity::Partial),
        "NOT NULL makes IS NOT FALSE exact: {:#?}",
        outputs.notes()
    );
}
