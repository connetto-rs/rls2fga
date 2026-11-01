//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Which clause a command needs, and what an absent one grants.

use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;

mod support;

use support::footgun::{
    assert_model_is_internally_consistent, db_of, relation_definition, relation_denies,
    translation, translator,
};

const SPLIT_INSERT_AND_SELECT: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, author_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (author_id = current_user);
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
";

/// A `docs` the owner reads by `SELECT`, with an `UPDATE` whose only stored clause is
/// `WITH CHECK`.
const CLAUSELESS_UPDATE: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE WITH CHECK (owner_id = current_user);
";

/// Returning a table column, or naming an `ON CONFLICT` target, also checks the
/// new row against the `SELECT` policies, so inserting a row the author cannot
/// read back fails even though plain `INSERT` succeeds.
#[test]
fn reading_the_inserted_row_back_needs_select_as_well_as_insert() {
    let db = db_of(SPLIT_INSERT_AND_SELECT);
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let insert = relation_definition(&dsl, "docs", "can_insert")
        .expect("an INSERT policy defines can_insert");
    let readback = relation_definition(&dsl, "docs", "can_insert_returning")
        .unwrap_or_else(|| panic!("reading the new row back needs its own relation:\n{dsl}"));

    assert_eq!(
        readback,
        format!("{insert} and can_select"),
        "reading back requires the insert rule and the read:\n{dsl}"
    );
}

/// When the same expression governs both commands the readback relation repeats
/// `can_insert`, and a relation that says nothing is noise.
#[test]
fn readback_relation_is_absent_when_inserting_implies_reading() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_all ON docs FOR ALL USING (owner_id = current_user)
    WITH CHECK (owner_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert!(
        relation_definition(&dsl, "docs", "can_insert_returning").is_none(),
        "the insert rule already implies the read:\n{dsl}"
    );
}

/// `INSERT ... ON CONFLICT ... DO UPDATE` updates the conflicting row, so
/// `PostgreSQL` applies the UPDATE policies to it and to the merged row. An insert
/// policy alone does not allow it.
#[test]
fn an_upsert_requires_the_update_policies_as_well_as_the_insert() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (owner_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_upsert").as_deref(),
        Some("can_insert and can_update"),
        "an upsert needs the UPDATE policies as well as the INSERT ones:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_update").as_deref(),
        Some("no_access"),
        "no UPDATE policy leaves the upsert denied:\n{dsl}"
    );
}

/// Where no row can be inserted at all the upsert relation repeats `can_insert`,
/// and a relation that says nothing is noise.
#[test]
fn upsert_relation_is_absent_where_no_row_can_be_inserted() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_insert").as_deref(),
        Some("no_access"),
        "no INSERT policy denies inserts:\n{dsl}"
    );
    assert!(
        relation_definition(&dsl, "docs", "can_upsert").is_none(),
        "a denied insert already denies the upsert:\n{dsl}"
    );
}

/// Naming a row to update or delete reads it, which `PostgreSQL` gates on the
/// `SELECT` policies. `INSERT` reads nothing.
#[test]
fn updating_and_deleting_a_row_requires_being_able_to_select_it() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (editor_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    for action in ["can_update", "can_delete"] {
        let body = relation_definition(&dsl, "docs", action)
            .unwrap_or_else(|| panic!("docs should define {action}:\n{dsl}"));
        assert!(
            body.contains("can_select"),
            "{action} = '{body}' must require reading the row:\n{dsl}"
        );
    }
    let insert =
        relation_definition(&dsl, "docs", "can_insert").expect("docs should define can_insert");
    assert!(
        !insert.contains("can_select"),
        "an INSERT reads nothing, so can_insert = '{insert}' must stay ungated:\n{dsl}"
    );
    assert_model_is_internally_consistent(
        &translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .json_model(),
    );
}

/// No `SELECT` policy means no row can be named for a per-row update or delete.
#[test]
fn without_a_select_policy_no_row_can_be_updated_or_deleted() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, editor_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let can_delete =
        relation_definition(&dsl, "docs", "can_delete").expect("docs should define can_delete");
    assert!(
        can_delete.contains("can_select"),
        "can_delete = '{can_delete}' must require reading the row:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "with no SELECT policy the read must be denied, which denies the delete with it:\n{dsl}"
    );
}

/// `CREATE POLICY p ON docs;` stores neither clause. `PostgreSQL` then has no
/// permissive `USING` qual and no permissive `WITH CHECK`, so the table is
/// closed on every command. Reading the missing clause as `TRUE` opens the
/// table to everyone.
#[test]
fn a_policy_with_no_clause_at_all_grants_nothing() {
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

    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        let definition = relation_definition(&model.model(), "docs", relation)
            .unwrap_or_else(|| panic!("docs should define {relation}:\n{}", model.model()));
        assert!(
            definition.contains("no_access"),
            "a clauseless policy admits no row, so {relation} must deny, got \
             'define {relation}: {definition}'"
        );
    }
}

/// A `SELECT` policy with no `USING` contributes no permissive read qual, and it
/// is the only one here, so nothing is readable.
#[test]
fn a_select_policy_with_no_using_clause_grants_no_read() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{}", model.model()));
    assert!(
        can_select.contains("no_access"),
        "a SELECT policy with no USING reads nothing, got 'define can_select: {can_select}'"
    );
}

/// `WITH CHECK` admits the new row and says nothing about the existing one. With
/// no `USING` clause anywhere, `PostgreSQL` finds no permissive qual for the row
/// being changed, so no `UPDATE` can ever succeed. Mirroring the check backwards
/// onto the `USING` side grants what `PostgreSQL` refuses.
#[test]
fn an_update_policy_with_no_using_clause_updates_no_row() {
    let db = db_of(CLAUSELESS_UPDATE);
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let can_update = relation_definition(&model.model(), "docs", "can_update")
        .unwrap_or_else(|| panic!("docs should define can_update:\n{}", model.model()));
    assert!(
        can_update.contains("no_access"),
        "no USING clause admits the row to change, got 'define can_update: {can_update}'"
    );
}

/// The clause a command reads decides whether a policy covers it. Telling the
/// operator the `UPDATE` policy fell below the confidence threshold says
/// `PostgreSQL` grants the update, which is the opposite of the truth.
#[test]
fn a_command_a_policy_names_without_the_clause_it_needs_is_reported_as_unpolicied() {
    let db = db_of(CLAUSELESS_UPDATE);
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages.iter().any(|message| {
            message.contains("No permissive policy on 'docs' covers") && message.contains("UPDATE")
        }),
        "RLS denies the UPDATE outright and the report must say so: {messages:#?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("confidence threshold")),
        "nothing was dropped by confidence here: {messages:#?}"
    );
}

/// A locking read (`SELECT ... FOR UPDATE`, `FOR SHARE`, `FOR NO KEY UPDATE`,
/// `FOR KEY SHARE`) is filtered by the `UPDATE` policies' `USING` clause as well
/// as by the `SELECT` policies, so `can_select` answers for more rows than
/// `PostgreSQL` returns.
#[test]
fn a_locking_read_needs_the_rows_an_update_may_touch() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (TRUE);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user) WITH CHECK (TRUE);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let locking = relation_definition(&model.model(), "docs", "can_select_for_update")
        .unwrap_or_else(|| {
            panic!(
                "docs should define can_select_for_update:\n{}",
                model.model()
            )
        });
    assert_eq!(
        locking,
        "can_update_using",
        "a locking read sees the rows an UPDATE may touch:\n{}",
        model.model()
    );
    assert_ne!(
        Some(locking.as_str()),
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        "everyone reads this table, but only an owner may lock a row"
    );
}

/// With no `UPDATE` policy, `PostgreSQL` has no permissive `USING` qual for the
/// row being locked, so a locking read returns nothing even where a plain read
/// returns every row.
#[test]
fn a_locking_read_is_denied_where_no_policy_admits_an_update() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (TRUE);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select_for_update").as_deref(),
        Some("can_update"),
        "the locking read answers with the update rule:\n{}",
        model.model()
    );
    let can_update = relation_definition(&model.model(), "docs", "can_update")
        .unwrap_or_else(|| panic!("docs should define can_update:\n{}", model.model()));
    assert!(
        can_update.contains("no_access"),
        "and that rule denies, got 'define can_update: {can_update}'"
    );
}

/// Where the two `UPDATE` clauses agree there is no separate `USING` relation, so
/// the locking read still needs a name of its own to point at.
#[test]
fn a_locking_read_is_answered_even_where_the_update_clauses_agree() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (TRUE);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user);
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        relation_definition(&model.model(), "docs", "can_update_using").is_none(),
        "one clause means one relation:\n{}",
        model.model()
    );
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select_for_update").as_deref(),
        Some("can_update"),
        "the locking read answers with the update rule:\n{}",
        model.model()
    );
}

/// "No permissive policy covers UPDATE" sends the operator looking for a policy
/// they already wrote. The report has to name the one that stores no clause.
#[test]
fn report_names_the_policy_whose_clause_is_absent() {
    let db = db_of(CLAUSELESS_UPDATE);
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert!(
        messages
            .iter()
            .any(|message| message.contains("'docs_upd' names UPDATE without a USING clause")),
        "the policy at fault must be named: {messages:#?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("'docs_sel'")),
        "a policy storing the clause it needs is not at fault: {messages:#?}"
    );
}

/// A policy storing no clause contributes nothing, but another policy may still
/// grant the command, so the note must not claim the command is denied.
#[test]
fn a_clauseless_policy_beside_a_working_one_is_not_reported_as_a_denial() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bare ON docs FOR SELECT;
",
    );
    let model = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let messages: Vec<String> = model.notes().iter().map(TranslationNote::message).collect();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "the working policy still grants reads:\n{}",
        model.model()
    );
    let note = messages
        .iter()
        .find(|message| message.contains("'docs_bare'"))
        .unwrap_or_else(|| panic!("the clauseless policy is worth naming: {messages:#?}"));
    assert!(
        note.contains("names SELECT without a USING clause"),
        "the absent clause is the point: {note}"
    );
    assert!(
        !note.contains("denie"),
        "reads are granted by the other policy, so this note claims no denial: {note}"
    );
}

/// A RESTRICTIVE `UPDATE` policy storing only a `WITH CHECK` guards the new row and
/// says nothing about the existing one, so it narrows `can_update` while leaving a
/// locking read alone. `SELECT ... FOR UPDATE` returns the rows the permissive
/// `USING` admits, whatever the barrier would refuse to write.
#[test]
fn a_restrictive_update_check_narrows_the_write_but_not_the_lock() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, reviewer_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR UPDATE WITH CHECK (reviewer_id = current_user);
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let check = relation_definition(&dsl, "docs", "can_update_check")
        .unwrap_or_else(|| panic!("docs should define can_update_check:\n{dsl}"));
    assert!(
        check.contains("reviewer"),
        "the barrier guards the new row, got 'define can_update_check: {check}'"
    );

    let using = relation_definition(&dsl, "docs", "can_update_using")
        .unwrap_or_else(|| panic!("docs should define can_update_using:\n{dsl}"));
    assert!(
        !using.contains("reviewer"),
        "a WITH CHECK says nothing about the existing row, got \
         'define can_update_using: {using}'"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select_for_update").as_deref(),
        Some("can_update_using"),
        "so a locking read is not narrowed by the barrier either:\n{dsl}"
    );
}

/// Coverage reads the schema's own policies, grouped by the table each name resolves
/// to. Grouping by the spelling instead loses the clauseless policy for a table
/// another policy spells differently, and the operator is never told which policy
/// admits nothing.
#[test]
fn a_clauseless_policy_is_found_through_any_spelling_of_its_table() {
    let db = db_of(
        r#"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bare ON "docs" FOR SELECT;
"#,
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner"),
        "the policy that stores a clause still grants reads:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| note
            .message()
            .contains("'docs_bare' names SELECT without a USING clause")),
        "the clauseless policy belongs to the same table however it spells it: {:#?}",
        model.notes()
    );
}

/// `UPDATE t SET c = 1` names no row, so it reads none, and `PostgreSQL` applies the
/// `UPDATE` policies to it without the `SELECT` policies. `can_update` intersects
/// `can_select`, so for that one statement shape it demands a permission the database
/// does not, and no relation answered for it.
#[test]
fn a_blanket_update_answers_through_its_own_relation() {
    let schema = "CREATE TABLE notes(id UUID PRIMARY KEY, reader_id TEXT, writer_id TEXT);\n\
                  ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY notes_read ON notes FOR SELECT USING (reader_id = current_user);\n\
                  CREATE POLICY notes_write ON notes FOR UPDATE USING (writer_id = current_user);\n";
    let (dsl, _) = translation(schema);

    assert_eq!(
        relation_definition(&dsl, "notes", "can_update").as_deref(),
        Some("writer and can_select"),
        "a per-row update still reads the row it names:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "notes", "can_update_without_reading").as_deref(),
        Some("writer"),
        "a blanket update reads nothing, so the read gate must not apply:\n{dsl}"
    );
}

/// An action relation nobody defined reads as "the consumer decides", which is how a
/// coverage gap becomes open access. Every table type carries the relation even where
/// no rule admits an update.
#[test]
fn every_table_defines_the_blanket_update_relation() {
    let schema = "CREATE TABLE notes(id UUID PRIMARY KEY, owner_id TEXT);\n\
                  ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY notes_read ON notes FOR SELECT USING (owner_id = current_user);\n";
    let (dsl, _) = translation(schema);

    assert_eq!(
        relation_definition(&dsl, "notes", "can_update_without_reading").as_deref(),
        Some("can_update"),
        "with no update rule it points at the denial rather than going missing:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "notes", "can_update").as_deref(),
        Some("no_access"),
        "and that denial is what it points at:\n{dsl}"
    );
}

/// `PostgreSQL` refuses to store these shapes at all: `only WITH CHECK expression
/// allowed for INSERT` and `WITH CHECK cannot be applied to SELECT or DELETE`, both
/// probed verbatim on 18.4. Translating one describes a database that cannot exist,
/// and the `FOR INSERT USING` spelling used to mint `can_insert` through the
/// USING-to-check mirror.
#[test]
fn an_illegal_clause_refuses_the_policy() {
    let cases = [
        (
            "CREATE POLICY p ON docs FOR INSERT USING (owner_id = current_user);",
            "only WITH CHECK expression allowed for INSERT",
        ),
        (
            "CREATE POLICY p ON docs FOR SELECT WITH CHECK (owner_id = current_user);",
            "WITH CHECK cannot be applied to SELECT or DELETE",
        ),
        (
            "CREATE POLICY p ON docs FOR DELETE WITH CHECK (owner_id = current_user);",
            "WITH CHECK cannot be applied to SELECT or DELETE",
        ),
    ];
    for (policy_sql, rule) in cases {
        let db = db_of(&format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{policy_sql}
"
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();

        for action in ["can_select", "can_insert", "can_update", "can_delete"] {
            assert!(
                relation_denies(&dsl, "docs", action),
                "an impossible policy grants nothing ({policy_sql}), {action}:\n{dsl}"
            );
        }
        assert!(
            outputs.tuple_queries().is_empty(),
            "an impossible policy asks for no tuples ({policy_sql}), got: {:#?}",
            outputs
                .tuple_queries()
                .iter()
                .map(|q| &q.sql)
                .collect::<Vec<_>>()
        );
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::PolicyClauseIllegal { policy, rule: r }
                    if policy == "p" && r == rule
            )),
            "the refusal must quote PostgreSQL's own sentence ({policy_sql}), got: {:#?}",
            outputs.notes()
        );
        assert!(
            !outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::PolicyClauseAbsent { policy, .. } if policy == "p"
            )),
            "an illegal clause is not an absent one, and saying both misleads \
             ({policy_sql}), got: {:#?}",
            outputs.notes()
        );
    }
}
