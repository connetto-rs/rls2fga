//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Which clause a command needs, and what an absent one grants.

use rls2fga::parser::sql_parser::{DatabaseLike, ParserDB, PolicyLike};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;
use rls2fga::types::{ActionAnswer, ActionStatement};

use crate::support::footgun::{
    assert_model_is_internally_consistent, db_of, relation_definition, relation_denies,
    translation, translator,
};

const SPLIT_INSERT_AND_SELECT: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID, author_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (author_id = current_setting('app.user_id'));
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
";

/// A `docs` the owner reads by `SELECT`, with an `UPDATE` whose only stored clause is
/// `WITH CHECK`.
const CLAUSELESS_UPDATE: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY docs_upd ON docs FOR UPDATE WITH CHECK (owner_id = current_setting('app.user_id'));
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
CREATE POLICY docs_all ON docs FOR ALL USING (owner_id = current_setting('app.user_id'))
    WITH CHECK (owner_id = current_setting('app.user_id'));
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
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (owner_id = current_setting('app.user_id'));
",
    );
    let planned = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan");
    let entries = planned.action_relations().to_vec();
    let dsl = planned.outputs_accepting_gaps().model();

    let insert = entries
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "docs" && entry.statement == ActionStatement::Insert
        })
        .expect("an INSERT entry for docs");
    assert!(
        matches!(insert.answer, ActionAnswer::Judged(_)),
        "the insert policy admits the insert:\n{dsl}"
    );
    let upsert = entries
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "docs"
                && entry.statement == ActionStatement::InsertOnConflictUpdate
        })
        .expect("an upsert entry for docs");
    assert_eq!(
        upsert.answer,
        ActionAnswer::Denied,
        "no UPDATE policy leaves the upsert denied:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_update").as_deref(),
        Some("no_access"),
        "the denial is the update half's:\n{dsl}"
    );
}

/// Where no row can be inserted at all the upsert is refused outright, rather than
/// naming a relation that can only be no.
#[test]
fn an_upsert_where_no_row_can_be_inserted_is_refused() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
",
    );
    let planned = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan");
    let entries = planned.action_relations().to_vec();
    let dsl = planned.outputs_accepting_gaps().model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_insert").as_deref(),
        Some("no_access"),
        "no INSERT policy denies inserts:\n{dsl}"
    );
    let upsert = entries
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "docs"
                && entry.statement == ActionStatement::InsertOnConflictUpdate
        })
        .expect("an upsert entry for docs");
    assert_eq!(
        upsert.answer,
        ActionAnswer::Denied,
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
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY docs_upd ON docs FOR UPDATE USING (editor_id = current_setting('app.user_id'));
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_setting('app.user_id'));
CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK (editor_id = current_setting('app.user_id'));
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
CREATE POLICY docs_del ON docs FOR DELETE USING (editor_id = current_setting('app.user_id'));
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
    let notes = model.notes();
    assert!(
        notes.iter().any(|note| matches!(
            note,
            TranslationNote::NoPermissivePolicy { table, commands }
                if table.to_string() == "public.docs"
                    && commands.iter().any(|command| command == "UPDATE")
        )),
        "{notes:#?}"
    );
    assert!(
        !notes
            .iter()
            .any(|note| note.message().contains("confidence threshold")),
        "{notes:#?}"
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
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_setting('app.user_id')) WITH CHECK (TRUE);
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
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_setting('app.user_id'));
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
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
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
        Some("owner and acting_app_user from request_gate"),
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
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = current_setting('app.user_id'));
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR UPDATE WITH CHECK (reviewer_id = current_setting('app.user_id'));
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
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id'));
CREATE POLICY docs_bare ON "docs" FOR SELECT;
"#,
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("owner and acting_app_user from request_gate"),
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
                  CREATE POLICY notes_read ON notes FOR SELECT USING (reader_id = current_setting('app.user_id'));\n\
                  CREATE POLICY notes_write ON notes FOR UPDATE USING (writer_id = current_setting('app.user_id'));\n";
    let (dsl, _) = translation(schema);

    assert_eq!(
        relation_definition(&dsl, "notes", "can_update").as_deref(),
        Some("writer and acting_app_user from request_gate and can_select"),
        "a per-row update still reads the row it names:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "notes", "can_update_without_reading").as_deref(),
        Some("writer and acting_app_user from request_gate"),
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
                  CREATE POLICY notes_read ON notes FOR SELECT USING (owner_id = current_setting('app.user_id'));\n";
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
            "CREATE POLICY p ON docs FOR INSERT USING (owner_id = current_setting('app.user_id'));",
            "only WITH CHECK expression allowed for INSERT",
        ),
        (
            "CREATE POLICY p ON docs FOR SELECT WITH CHECK (owner_id = current_setting('app.user_id'));",
            "WITH CHECK cannot be applied to SELECT or DELETE",
        ),
        (
            "CREATE POLICY p ON docs FOR DELETE WITH CHECK (owner_id = current_setting('app.user_id'));",
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

/// A `timestamptz` literal holds the instant `PostgreSQL` read in the `TimeZone` of the
/// session that ran `CREATE POLICY`, and a schema that never sets one does not say which.
const UNREADABLE_LITERAL_TABLE: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, expires TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

/// Whether `notes` refuse policy `p` with the reason the catalog gives for its `USING`.
fn refuses_the_unreadable_literal(db: &ParserDB, notes: &[TranslationNote]) -> bool {
    let policy = db
        .policies()
        .find(|policy| policy.name() == "p")
        .expect("the schema declares p");
    let expected = policy
        .using_expression(db)
        .expect_err("the literal cannot be read")
        .to_string();
    notes.iter().any(|note| {
        matches!(
            note,
            TranslationNote::ExpressionRefused { policy, reason }
                if policy == "p" && *reason == expected
        )
    })
}

/// The clause's value is unknown, so the policy grants nothing and says why, and its
/// `USING` still answers for the missing `WITH CHECK`, so no command reads as uncovered.
#[test]
fn a_permissive_policy_whose_literal_cannot_be_read_is_refused() {
    let db = db_of(&format!(
        "{UNREADABLE_LITERAL_TABLE}\
         CREATE POLICY p ON docs USING (owner_id = current_user AND expires > '2026-01-01 09:00');"
    ));
    let outputs = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    for action in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert!(
            relation_denies(&dsl, "docs", action),
            "a clause of unknown value grants nothing, {action}:\n{dsl}"
        );
    }
    assert!(
        outputs.tuple_queries().is_empty(),
        "a refused policy asks for no tuples, got: {:#?}",
        outputs.tuple_queries()
    );
    assert!(
        refuses_the_unreadable_literal(&db, outputs.notes()),
        "the refusal must name the literal, got: {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::PolicyClauseAbsent { policy, .. } if policy == "p"
        )),
        "the clause is stored, only its value is unknown, got: {:#?}",
        outputs.notes()
    );
}

/// A permissive policy of unknown value grants nothing, and the readable permissive policy
/// beside it still grants what it grants.
#[test]
fn an_unreadable_permissive_policy_leaves_the_others_granting() {
    let db = db_of(&format!(
        "{UNREADABLE_LITERAL_TABLE}\
         CREATE POLICY owner ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
         CREATE POLICY p ON docs FOR SELECT USING (expires > '2026-01-01 09:00');"
    ));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner and acting_app_user from request_gate"),
        "the owner policy still grants:\n{dsl}"
    );
    assert!(
        refuses_the_unreadable_literal(&db, outputs.notes()),
        "the refusal must name the literal, got: {:#?}",
        outputs.notes()
    );
}

/// `PostgreSQL` scopes a policy name to its table, so a policy named like another table's
/// answers for its own clause alone, in whichever order the two are created.
#[test]
fn same_named_policies_on_two_tables_translate_apart() {
    let unreadable = "CREATE POLICY p ON docs USING (expires > '2026-01-01 09:00');";
    let readable = "CREATE POLICY p ON notes FOR SELECT USING (owner_id = current_user);";
    for policies in [[unreadable, readable], [readable, unreadable]] {
        let db = db_of(&format!(
            "{UNREADABLE_LITERAL_TABLE}\
             CREATE TABLE notes(id UUID PRIMARY KEY, owner_id TEXT);
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
             {}\n{}",
            policies[0], policies[1]
        ));
        let outputs = translator(ConfidenceLevel::B)
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        let dsl = outputs.model();
        assert!(
            relation_denies(&dsl, "docs", "can_select")
                && relation_definition(&dsl, "notes", "can_select").is_some()
                && !relation_denies(&dsl, "notes", "can_select"),
            "each `p` answers for its own table ({policies:?}):\n{dsl}"
        );
        let refused: Vec<&str> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::ExpressionRefused { policy, reason } if policy == "p" => {
                    Some(reason.as_str())
                }
                _ => None,
            })
            .collect();
        assert!(
            refused.len() == 1 && refused[0].contains("'2026-01-01 09:00'"),
            "only the clause on docs is refused, for its literal ({policies:?}): {refused:?}"
        );
    }
}

/// A barrier of unknown value may admit nothing, so it denies what it guards rather than
/// stepping aside for the grant beside it.
#[test]
fn a_restrictive_policy_whose_literal_cannot_be_read_denies() {
    let db = db_of(&format!(
        "{UNREADABLE_LITERAL_TABLE}\
         CREATE POLICY owner ON docs FOR SELECT USING (owner_id = current_user);
         CREATE POLICY p ON docs AS RESTRICTIVE FOR SELECT USING (expires > '2026-01-01 09:00');"
    ));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert!(
        relation_denies(&dsl, "docs", "can_select"),
        "the owner grant must not survive a barrier nobody can read:\n{dsl}"
    );
    assert!(
        refuses_the_unreadable_literal(&db, outputs.notes()),
        "the refusal must name the literal, got: {:#?}",
        outputs.notes()
    );
}

/// A `WITH CHECK` of unknown value refuses the new rows it judges, while the readable `USING`
/// beside it still grants reads.
#[test]
fn a_check_whose_literal_cannot_be_read_closes_only_the_writes_it_judges() {
    let db = db_of(&format!(
        "{UNREADABLE_LITERAL_TABLE}\
         CREATE POLICY p ON docs USING (owner_id = current_user)
           WITH CHECK (owner_id = current_user AND expires > '2026-01-01 09:00');"
    ));
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();

    assert!(
        !relation_denies(&dsl, "docs", "can_select"),
        "the readable USING still grants reads:\n{dsl}"
    );
    for action in ["can_insert", "can_update"] {
        assert!(
            relation_denies(&dsl, "docs", action),
            "a check of unknown value admits no new row, {action}:\n{dsl}"
        );
    }
    let expected = db
        .policies()
        .next()
        .expect("the schema declares p")
        .check_expression(&db)
        .expect_err("the literal cannot be read")
        .to_string();
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ExpressionRefused { policy, reason }
                if policy == "p" && *reason == expected
        )),
        "the refusal must name the check's literal, got: {:#?}",
        outputs.notes()
    );
}

/// A restrictive `FOR ALL` barrier storing no `WITH CHECK` checks the new row with its
/// `USING`, so a `USING` the threshold drops still closes inserts.
#[test]
fn a_restrictive_using_below_the_threshold_still_checks_inserts() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY ins ON docs FOR INSERT WITH CHECK (owner_id = current_user);
CREATE POLICY p ON docs AS RESTRICTIVE USING (unreadable(owner_id));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert!(
        relation_denies(&dsl, "docs", "can_insert"),
        "the dropped barrier must not let inserts through:\n{dsl}"
    );
}
