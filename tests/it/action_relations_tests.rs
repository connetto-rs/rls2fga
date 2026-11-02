//! Which relations answer an action, and which row version each judges.
//!
//! The assertions come from the request recorded in `plans/action-relations.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use crate::support::footgun::{relation_definition, relation_denies};
use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{ActionAnswer, ActionRelations, ActionStatement, RowVersion};

/// One permissive policy giving one condition, which is what every connetto table
/// writes. `PostgreSQL` applies that condition to the existing row and to the result.
const ONE_CONDITION: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_p ON notes USING (
  owner = current_setting('app.user_id', true)
  OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));
";

/// The same table with the two clauses spelled out separately.
const TWO_CONDITIONS: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (
  owner = current_setting('app.user_id', true)
  OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));
CREATE POLICY notes_u ON notes FOR UPDATE
  USING (owner = current_setting('app.user_id', true))
  WITH CHECK (owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));
";

/// Reads alone, so every writing action denies while the table is still restricted.
const READS_ONLY: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
";

/// Three rules that differ from each other, so an upsert asks more than an insert and
/// reading back an inserted row asks more than writing it.
const INSERT_AND_UPDATE: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, editor TEXT, author TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
CREATE POLICY notes_i ON notes FOR INSERT WITH CHECK (author = current_setting('app.user_id', true));
CREATE POLICY notes_u ON notes FOR UPDATE USING (editor = current_setting('app.user_id', true));
";

/// A parent the model reaches only through a membership table, and which the database
/// itself restricts not at all.
const UNRESTRICTED_PARENT: &str = "
CREATE TABLE projects(id INTEGER PRIMARY KEY);
CREATE TABLE docs(id INTEGER PRIMARY KEY, project_id INTEGER REFERENCES projects(id));
CREATE TABLE project_members(project_id INTEGER REFERENCES projects(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY d ON docs USING (project_id IN (
  SELECT project_id FROM project_members WHERE user_id = current_setting('app.user_id', true)));
";

/// Row-level security on with no policy at all, which `PostgreSQL` reads as nobody sees
/// anything and no statement succeeds.
const DENIES_EVERYTHING: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
";

/// A readable read policy beside an `UPDATE` whose `WITH CHECK` admits no result, so the
/// fused blind-update relation is an intersection that grants nobody.
const CHECK_DENIES_THE_RESULT: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
CREATE POLICY notes_u ON notes FOR UPDATE
  USING (owner = current_setting('app.user_id', true))
  WITH CHECK (false);
";

/// Two clauses that both classify but differ, with a read policy beside them, so the
/// `USING` half must exist somewhere without the read gate a blind update does not need.
const DIFFERING_CLAUSES: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT, editor TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_s ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
CREATE POLICY notes_u ON notes FOR UPDATE
  USING (owner = current_setting('app.user_id', true))
  WITH CHECK (editor = current_setting('app.user_id', true));
";

/// An `UPDATE` policy alone: reads are denied, so every statement that names a row is
/// refused, while a blanket `UPDATE` reads nothing and still grants.
const BLANKET_UPDATE_ONLY: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, editor TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_u ON notes FOR UPDATE
  USING (editor = current_setting('app.user_id', true));
";

/// A restrictive policy with no permissive one to narrow, which `PostgreSQL` reads as
/// nobody sees anything, and which no note names.
const RESTRICTIVE_ONLY: &str = "
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_r ON notes AS RESTRICTIVE USING (owner = current_setting('app.user_id', true));
";

const EVERY_SCHEMA: [(&str, &str); 10] = [
    ("one condition", ONE_CONDITION),
    ("two conditions", TWO_CONDITIONS),
    ("reads only", READS_ONLY),
    ("insert and update", INSERT_AND_UPDATE),
    ("unrestricted parent", UNRESTRICTED_PARENT),
    ("denies everything", DENIES_EVERYTHING),
    ("check denies the result", CHECK_DENIES_THE_RESULT),
    ("blanket update only", BLANKET_UPDATE_ONLY),
    ("restrictive only", RESTRICTIVE_ONLY),
    ("differing clauses", DIFFERING_CLAUSES),
];

/// Every statement the report answers for, read off the report rather than restated.
///
/// A second copy of `EVERY_STATEMENT` lived here, so a ninth variant would have been
/// missing from both the production array and the test that should have caught it.
/// Deriving it is only safe because
/// `the_report_answers_for_every_statement_the_enum_declares` pins this against the enum
/// declaration, so a short list is a failing test rather than a quietly weaker sweep.
fn every_statement() -> Vec<ActionStatement> {
    let mut statements: Vec<ActionStatement> = report(ONE_CONDITION)
        .iter()
        .filter(|entry| entry.type_name == *"notes")
        .map(|entry| entry.statement)
        .collect();
    statements.sort();
    statements.dedup();
    assert!(
        !statements.is_empty(),
        "a guarded table answers for something"
    );
    statements
}

/// The variant names `ActionStatement` declares, from the declaration itself.
fn declared_statements() -> BTreeSet<String> {
    let source =
        std::fs::read_to_string("types/src/action_relations.rs").expect("the module is readable");
    source
        .split_once("pub enum ActionStatement {")
        .expect("ActionStatement is declared")
        .1
        .split_once("\n}")
        .expect("the declaration closes")
        .0
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_suffix(','))
        .filter(|name| {
            name.starts_with(|ch: char| ch.is_ascii_uppercase())
                && name.chars().all(char::is_alphanumeric)
        })
        .map(ToString::to_string)
        .collect()
}

/// A statement the enum declares but the report never answers for is invisible.
///
/// `EVERY_STATEMENT` in `action_relations.rs` is `[ActionStatement; 8]`, and its length
/// is part of its type, so a ninth variant leaves it valid and the new statement is
/// simply never reported. `command()` is an exhaustive match and forces one edit, which
/// is what makes the omission look handled. This is the same shape as
/// `every_pattern_has_a_readme_row`: read the variants off the declaration, which cannot
/// drift from itself, and require the running report to cover each one.
#[test]
fn the_report_answers_for_every_statement_the_enum_declares() {
    let declared = declared_statements();
    assert!(
        declared.len() >= 8,
        "only {} variants parsed out of the enum, so this proves nothing: {declared:?}",
        declared.len()
    );

    let answered: BTreeSet<String> = every_statement()
        .iter()
        .map(|statement| format!("{statement:?}"))
        .collect();
    assert_eq!(
        answered, declared,
        "the report answers for {answered:?} while the enum declares {declared:?}"
    );
}

fn translate(db: &ParserDB) -> Translation {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.subjects", SessionAttributeKind::SetAttribute),
        ])
        .build()
        .translate(db)
        .expect("translation should plan")
}

fn report(sql: &str) -> Vec<ActionRelations> {
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    translate(&db).action_relations().to_vec()
}

fn dsl(sql: &str) -> String {
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    translate(&db).outputs_accepting_gaps().model()
}

fn entry<'a>(
    entries: &'a [ActionRelations],
    type_name: &str,
    statement: ActionStatement,
) -> &'a ActionRelations {
    entries
        .iter()
        .find(|entry| entry.type_name == *type_name && entry.statement == statement)
        .unwrap_or_else(|| panic!("no {statement:?} entry for {type_name}, got {entries:#?}"))
}

/// The judgements of one entry as `(relation, version)`, refusing any other answer.
fn judges(entry: &ActionRelations) -> Vec<(String, RowVersion)> {
    match &entry.answer {
        ActionAnswer::Judged(judges) => judges
            .iter()
            .map(|judge| (judge.relation.as_str().to_string(), judge.version))
            .collect(),
        other => panic!("{:?} is judged by nothing: {other:?}", entry.statement),
    }
}

fn judged(pairs: &[(&str, RowVersion)]) -> Vec<(String, RowVersion)> {
    pairs
        .iter()
        .map(|(relation, version)| ((*relation).to_string(), *version))
        .collect()
}

/// Every relation an entry names, whatever answer carries it.
fn named_relations(entry: &ActionRelations) -> Vec<String> {
    match &entry.answer {
        ActionAnswer::Judged(judges) => judges
            .iter()
            .map(|judge| judge.relation.as_str().to_string())
            .collect(),
        _ => Vec::new(),
    }
}

/// Every statement of one type the report refuses, in statement order.
fn refused(entries: &[ActionRelations], type_name: &str) -> Vec<ActionStatement> {
    every_statement()
        .into_iter()
        .filter(|statement| entry(entries, type_name, *statement).answer == ActionAnswer::Denied)
        .collect()
}

/// The property whose absence is the defect: a consumer can ask everything the report
/// names, whatever shape the policy was spelled in.
#[test]
fn every_relation_the_report_names_is_defined_in_the_emitted_model() {
    let mut named = 0usize;
    for (label, sql) in EVERY_SCHEMA {
        let model = dsl(sql);
        for entry in report(sql) {
            for relation in named_relations(&entry) {
                named += 1;
                assert!(
                    relation_definition(&model, entry.type_name.as_str(), &relation).is_some(),
                    "{label}: {} names {relation} on {}, which the model does not define:\n{model}",
                    format_args!("{:?}", entry.statement),
                    entry.type_name.as_str()
                );
            }
        }
    }
    assert!(
        named >= 40,
        "the corpus named only {named} relations, so the check above proves little"
    );
}

/// `PostgreSQL` applies a lone `USING` clause to the result as well, so the one
/// relation answers both versions.
#[test]
fn one_condition_names_its_relation_for_both_versions() {
    let entries = report(ONE_CONDITION);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::Update)),
        judged(&[
            ("can_update", RowVersion::Existing),
            ("can_update", RowVersion::Resulting),
        ])
    );
}

#[test]
fn two_clauses_name_the_using_half_for_the_row_and_the_check_half_for_the_result() {
    let entries = report(TWO_CONDITIONS);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::Update)),
        judged(&[
            ("can_update_using", RowVersion::Existing),
            ("can_update_check", RowVersion::Resulting),
        ])
    );
}

#[test]
fn a_read_judges_the_row_an_insert_the_result_and_a_delete_the_row() {
    let entries = report(ONE_CONDITION);
    for (statement, expected) in [
        (
            ActionStatement::Select,
            judged(&[("can_select", RowVersion::Existing)]),
        ),
        (
            ActionStatement::Insert,
            judged(&[("can_insert", RowVersion::Resulting)]),
        ),
        (
            ActionStatement::Delete,
            judged(&[("can_delete", RowVersion::Existing)]),
        ),
    ] {
        assert_eq!(judges(entry(&entries, "notes", statement)), expected);
    }
}

/// A locking read is filtered by the `SELECT` policies and by the `UPDATE` policies'
/// `USING` clause, and the relation named for it carries only the second.
#[test]
fn a_locking_read_names_the_read_gate_beside_the_update_half() {
    let entries = report(ONE_CONDITION);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::SelectForUpdate)),
        judged(&[
            ("can_select", RowVersion::Existing),
            ("can_select_for_update", RowVersion::Existing),
        ])
    );
}

/// `can_upsert` fuses an insert judging the result with an update judging both
/// versions, so the report names its halves rather than the fusion.
#[test]
fn an_upsert_names_the_insert_and_the_update_halves() {
    let entries = report(INSERT_AND_UPDATE);
    assert_eq!(
        judges(entry(
            &entries,
            "notes",
            ActionStatement::InsertOnConflictUpdate
        )),
        judged(&[
            ("can_insert", RowVersion::Resulting),
            ("can_update", RowVersion::Existing),
            ("can_update", RowVersion::Resulting),
        ])
    );
    assert!(
        relation_definition(&dsl(INSERT_AND_UPDATE), "notes", "can_upsert").is_some(),
        "the schema is pointless unless the model defines the fusion it decomposes"
    );
}

/// The returned row is the new one, and reading it needs the read gate the model
/// already folded into `can_insert_returning`. That relation is dropped wherever it
/// would repeat `can_insert`, which is where the plain insert answers instead, and it is
/// absent wherever nothing admits an insert, which is a refusal.
#[test]
fn an_insert_that_returns_rows_judges_the_result_through_the_read_gated_relation() {
    assert_eq!(
        judges(entry(
            &report(INSERT_AND_UPDATE),
            "notes",
            ActionStatement::InsertReturning
        )),
        judged(&[("can_insert_returning", RowVersion::Resulting)])
    );
    assert!(
        relation_definition(&dsl(INSERT_AND_UPDATE), "notes", "can_insert_returning").is_some(),
        "the schema is pointless unless the model defines the read-gated insert"
    );
    let one_condition = dsl(ONE_CONDITION);
    assert!(
        relation_definition(&one_condition, "notes", "can_insert_returning").is_none(),
        "one condition gates the readback exactly as it gates the insert:\n{one_condition}"
    );
    assert_eq!(
        judges(entry(
            &report(ONE_CONDITION),
            "notes",
            ActionStatement::InsertReturning
        )),
        judged(&[("can_insert", RowVersion::Resulting)]),
        "so the plain insert answers"
    );
    assert_eq!(
        entry(
            &report(READS_ONLY),
            "notes",
            ActionStatement::InsertReturning
        )
        .answer,
        ActionAnswer::Denied,
        "and with nothing admitting an insert there is nothing to name"
    );
}

#[test]
fn a_blind_update_of_one_condition_names_its_relation_for_both_versions() {
    assert_eq!(
        judges(entry(
            &report(ONE_CONDITION),
            "notes",
            ActionStatement::UpdateWithoutWhere
        )),
        judged(&[
            ("can_update_without_reading", RowVersion::Existing),
            ("can_update_without_reading", RowVersion::Resulting),
        ])
    );
}

/// A blind update applies `USING` to the row as it is and `WITH CHECK` to the result,
/// so where the clauses differ each half is judged against its own row version, and the
/// unread relation carries the `USING` half alone.
#[test]
fn a_blind_update_of_two_clauses_judges_each_clause_against_its_row_version() {
    assert_eq!(
        judges(entry(
            &report(TWO_CONDITIONS),
            "notes",
            ActionStatement::UpdateWithoutWhere
        )),
        judged(&[
            ("can_update_without_reading", RowVersion::Existing),
            ("can_update_check", RowVersion::Resulting),
        ])
    );
}

/// The unread relation is the `USING` half and nothing else: fusing the check into it
/// answers the check against the row as it is, which grants a change the clause was
/// written to refuse.
#[test]
fn the_unread_update_relation_carries_only_the_using_half() {
    let model = dsl(DIFFERING_CLAUSES);
    assert_eq!(
        relation_definition(&model, "notes", "can_update_without_reading").as_deref(),
        Some("owner"),
        "the check half must not be answered against the existing row:\n{model}"
    );
    assert_eq!(
        judges(entry(
            &report(DIFFERING_CLAUSES),
            "notes",
            ActionStatement::UpdateWithoutWhere
        )),
        judged(&[
            ("can_update_without_reading", RowVersion::Existing),
            ("can_update_check", RowVersion::Resulting),
        ])
    );
}

/// So a consumer learns the answer is no, rather than being handed a relation to ask
/// whose answer can only be no.
#[test]
fn an_action_granting_nobody_is_answered_with_the_refusal() {
    let entries = report(READS_ONLY);
    assert_eq!(
        entry(&entries, "notes", ActionStatement::Update).answer,
        ActionAnswer::Denied
    );
    assert_eq!(
        relation_definition(&dsl(READS_ONLY), "notes", "can_update").as_deref(),
        Some("no_access"),
        "and the refusal is what the model says"
    );
}

/// The database restricts nothing on it, and saying that is not the same as saying
/// nothing.
#[test]
fn a_table_the_database_does_not_restrict_reports_every_action_unrestricted() {
    let entries = report(UNRESTRICTED_PARENT);
    for statement in every_statement() {
        assert_eq!(
            entry(&entries, "projects", statement).answer,
            ActionAnswer::Unrestricted
        );
    }
    assert!(
        matches!(
            entry(&entries, "docs", ActionStatement::Select).answer,
            ActionAnswer::Judged(_)
        ),
        "and the guarded table beside it is still judged"
    );
}

#[test]
fn every_type_the_model_names_rows_of_answers_every_statement() {
    for (label, sql) in EVERY_SCHEMA {
        let db: ParserDB = parse_schema(sql).expect("schema should parse");
        let planned = translate(&db);
        let entries = planned.action_relations();
        for naming in planned.row_naming() {
            let statements: Vec<ActionStatement> = entries
                .iter()
                .filter(|entry| entry.type_name.as_str() == naming.type_name)
                .map(|entry| entry.statement)
                .collect();
            assert_eq!(
                statements,
                every_statement(),
                "{label}: {} is named as a row but answers {statements:?}",
                naming.type_name
            );
        }
    }
}

/// A type nothing keys on a row is not something a consumer asks about.
#[test]
fn a_type_that_is_no_table_has_no_entry() {
    let entries = report(UNRESTRICTED_PARENT);
    for type_name in ["user", "project_members"] {
        assert!(
            !entries
                .iter()
                .any(|entry| entry.type_name.as_str() == type_name),
            "{type_name} has no rows the model answers for, yet it has an entry"
        );
    }
}

/// The statement joins the notes, which name a SQL command and not a statement shape.
#[test]
fn every_statement_names_the_command_it_answers() {
    let commands: Vec<&str> = every_statement()
        .iter()
        .map(ActionStatement::command)
        .collect();
    assert_eq!(
        commands,
        ["SELECT", "INSERT", "UPDATE", "DELETE", "SELECT", "INSERT", "INSERT", "UPDATE"]
    );
}

/// A table nobody may touch says so, rather than naming a relation the consumer has to
/// ask about. The model already answers no for every row, and a consumer that cannot
/// name a row of it has no other way to learn that.
#[test]
fn a_table_that_refuses_every_statement_says_so() {
    let entries = report(DENIES_EVERYTHING);
    let answers: Vec<&ActionAnswer> = entries
        .iter()
        .filter(|entry| entry.type_name.as_str() == "notes")
        .map(|entry| &entry.answer)
        .collect();
    assert_eq!(answers.len(), 8, "every statement is answered: {answers:?}");
    assert!(
        answers
            .iter()
            .all(|answer| **answer == ActionAnswer::Denied),
        "every statement is refused: {answers:?}"
    );
}

/// The refusal is the model's, not the report's own reading of it.
///
/// The report walks the plan to decide that nothing can grant, and the simplifier walks
/// the same expressions to prune. Derived apart they could disagree, so this pins the
/// answer against the emitted text a reader of the model would see.
#[test]
fn a_refusal_says_what_the_emitted_model_says() {
    let model = dsl(DENIES_EVERYTHING);
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert_eq!(
            relation_definition(&model, "notes", relation).as_deref(),
            Some("no_access"),
            "{relation} is a denial in the model:\n{model}"
        );
    }
    assert_eq!(
        entry(&report(DENIES_EVERYTHING), "notes", ActionStatement::Select).answer,
        ActionAnswer::Denied,
        "and the report says so without naming a relation"
    );
}

/// The refusal needs no row name, which is the whole point: nothing keys a row of this
/// table, so a judgement naming a relation could never be asked.
#[test]
fn a_refusal_is_answered_for_a_table_whose_rows_cannot_be_named() {
    let sql = "CREATE TABLE audit(message TEXT);
ALTER TABLE audit ENABLE ROW LEVEL SECURITY;
";
    let db: ParserDB = parse_schema(sql).expect("schema should parse");
    let planned = translate(&db);
    assert!(
        planned.row_naming().is_empty(),
        "nothing names a row of a keyless table"
    );
    let entries = planned.action_relations();
    assert_eq!(entries.len(), 8, "every statement is answered: {entries:?}");
    assert!(
        entries
            .iter()
            .all(|entry| entry.answer == ActionAnswer::Denied),
        "and every one of them is a refusal: {entries:?}"
    );
}

/// The defect this fixes: a table refusing writes while granting reads used to answer
/// every refused statement with a relation to satisfy, since the refusal was read off
/// the whole type rather than the statement.
#[test]
fn a_table_that_grants_reads_refuses_every_other_statement() {
    let entries = report(READS_ONLY);
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::Select)),
        judged(&[("can_select", RowVersion::Existing)])
    );
    assert_eq!(
        refused(&entries, "notes"),
        every_statement()
            .into_iter()
            .filter(|statement| *statement != ActionStatement::Select)
            .collect::<Vec<ActionStatement>>(),
        "reads are all this table grants"
    );
}

/// The locking read is the case the notes cannot express: it calls itself a `SELECT`,
/// which no note reports refused, while the model filters it by the `UPDATE` policies
/// as `PostgreSQL` does.
#[test]
fn a_locking_read_the_update_policies_refuse_is_reported_refused() {
    let model = dsl(READS_ONLY);
    assert_eq!(
        relation_definition(&model, "notes", "can_select_for_update").as_deref(),
        Some("can_update"),
        "the locking read carries the update half:\n{model}"
    );
    assert!(relation_denies(&model, "notes", "can_select_for_update"));
    assert_eq!(
        entry(
            &report(READS_ONLY),
            "notes",
            ActionStatement::SelectForUpdate
        )
        .answer,
        ActionAnswer::Denied
    );
    assert_eq!(
        ActionStatement::SelectForUpdate.command(),
        "SELECT",
        "and the statement names a command the notes report granted"
    );
}

/// The check half admits no result, so the blind update is refused through the pair
/// while the unread relation keeps carrying the `USING` half it answers for.
#[test]
fn a_check_granting_nobody_refuses_the_blind_update_without_narrowing_the_using_half() {
    let model = dsl(CHECK_DENIES_THE_RESULT);
    assert!(
        !relation_denies(&model, "notes", "can_update_without_reading"),
        "the USING half still grants, and folding the check into it would answer the \
         check against the row as it is:\n{model}"
    );
    assert!(
        relation_denies(&model, "notes", "can_update_check"),
        "the check half is where nobody passes:\n{model}"
    );
    let entries = report(CHECK_DENIES_THE_RESULT);
    assert_eq!(
        entry(&entries, "notes", ActionStatement::UpdateWithoutWhere).answer,
        ActionAnswer::Denied
    );
    assert_eq!(
        judges(entry(&entries, "notes", ActionStatement::SelectForUpdate)),
        judged(&[
            ("can_select", RowVersion::Existing),
            ("can_select_for_update", RowVersion::Existing),
        ]),
        "and the statements it still grants keep naming their relations"
    );
}

/// A restrictive policy with nothing permissive to narrow refuses everything, and no
/// note says so, which is why the report has to.
#[test]
fn a_restrictive_policy_alone_refuses_every_statement() {
    let entries = report(RESTRICTIVE_ONLY);
    assert_eq!(refused(&entries, "notes"), every_statement());
}

/// One grants everybody and the other grants nobody, and both arrive through this report.
#[test]
fn an_unrestricted_table_is_never_refused_and_a_refused_one_is_never_unrestricted() {
    for (label, sql) in EVERY_SCHEMA {
        let entries = report(sql);
        for entry in &entries {
            let answers: Vec<&ActionAnswer> = entries
                .iter()
                .filter(|other| other.type_name == entry.type_name)
                .map(|other| &other.answer)
                .collect();
            let open = answers.contains(&&ActionAnswer::Unrestricted);
            let refused = answers.contains(&&ActionAnswer::Denied);
            assert!(
                !(open && refused),
                "{label}: {} is both open and refused: {answers:?}",
                entry.type_name.as_str()
            );
        }
    }
}

/// The report never hands over a relation whose answer can only be no, checked against
/// the emitted text rather than against the plan the report reads.
#[test]
fn no_statement_the_model_refuses_is_answered_with_a_relation_to_satisfy() {
    for (label, sql) in EVERY_SCHEMA {
        let model = dsl(sql);
        for entry in report(sql) {
            for relation in named_relations(&entry) {
                assert!(
                    !relation_denies(&model, entry.type_name.as_str(), &relation),
                    "{label}: {:?} on {} names {relation}, which the model refuses:\n{model}",
                    entry.statement,
                    entry.type_name.as_str()
                );
            }
        }
    }
}

/// The refusals of the whole corpus, so a statement some subject can perform is never
/// reported refused.
#[test]
fn every_fixture_refuses_exactly_the_statements_it_should() {
    let all = every_statement();
    let writes: Vec<ActionStatement> = all
        .iter()
        .copied()
        .filter(|statement| *statement != ActionStatement::Select)
        .collect();
    let inserts = vec![
        ActionStatement::Insert,
        ActionStatement::InsertOnConflictUpdate,
        ActionStatement::InsertReturning,
    ];
    let mut inserts_and_delete = inserts.clone();
    inserts_and_delete.push(ActionStatement::Delete);
    inserts_and_delete.sort_unstable();
    for (label, sql, type_name, expected) in [
        ("one condition", ONE_CONDITION, "notes", Vec::new()),
        (
            "two conditions",
            TWO_CONDITIONS,
            "notes",
            inserts_and_delete.clone(),
        ),
        ("reads only", READS_ONLY, "notes", writes.clone()),
        (
            "insert and update",
            INSERT_AND_UPDATE,
            "notes",
            vec![ActionStatement::Delete],
        ),
        (
            "unrestricted parent",
            UNRESTRICTED_PARENT,
            "docs",
            Vec::new(),
        ),
        (
            "unrestricted parent",
            UNRESTRICTED_PARENT,
            "projects",
            Vec::new(),
        ),
        ("denies everything", DENIES_EVERYTHING, "notes", all.clone()),
        (
            "check denies the result",
            CHECK_DENIES_THE_RESULT,
            "notes",
            {
                let mut refused = inserts_and_delete.clone();
                refused.push(ActionStatement::Update);
                refused.push(ActionStatement::UpdateWithoutWhere);
                refused.sort_unstable();
                refused
            },
        ),
        (
            "blanket update only",
            BLANKET_UPDATE_ONLY,
            "notes",
            all.iter()
                .copied()
                .filter(|statement| *statement != ActionStatement::UpdateWithoutWhere)
                .collect(),
        ),
        ("restrictive only", RESTRICTIVE_ONLY, "notes", all.clone()),
    ] {
        assert_eq!(
            refused(&report(sql), type_name),
            expected,
            "{label}: {type_name} refuses something else"
        );
    }
}

/// A table whose only policy is an `UPDATE` refuses every statement that names a row,
/// because reads are denied and a write cannot name what it cannot read, yet a blanket
/// `UPDATE` reads nothing and still grants.
#[test]
fn a_table_whose_blanket_update_still_grants_refuses_only_the_rest() {
    let entries = report(BLANKET_UPDATE_ONLY);
    assert_eq!(
        judges(entry(
            &entries,
            "notes",
            ActionStatement::UpdateWithoutWhere
        )),
        judged(&[
            ("can_update_without_reading", RowVersion::Existing),
            ("can_update_without_reading", RowVersion::Resulting),
        ]),
        "the blanket update reads nothing, so it grants"
    );
    assert_eq!(
        entry(&entries, "notes", ActionStatement::Select).answer,
        ActionAnswer::Denied,
        "while a read is refused"
    );
}
