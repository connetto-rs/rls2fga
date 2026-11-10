//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Policies whose reads loop, and the commands a loop denies.

use rls2fga::parser::sql_parser::ParserDB;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;

use crate::support::footgun::{db_of, relation_definition, relation_denies, translator};

/// A `SELECT` policy reading its own table needs itself, which `PostgreSQL` rejects
/// as infinite recursion, so one such policy makes the whole table unreadable.
#[test]
fn a_select_policy_reading_its_own_table_denies_the_table() {
    // The plain policy alone would grant every row to its owner.
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES docs(id), owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_own ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_tree ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.owner_id = current_setting('app.user_id', true)));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "a recursive SELECT policy makes every read fail, so nothing is readable:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::PolicyReadRecursion { table, role, commands, relation }
                    if table.to_string() == "public.docs"
                        && role == "app_user"
                        && commands == &["SELECT".to_string()]
                        && relation == "docs"
            )
        }),
        "the operator must be told the table's reads loop on itself, got {:#?}",
        model.notes()
    );

    // The same shape through a join recurses identically.
    let joined = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM docs d2 JOIN doc_members dm ON dm.doc_id = d2.id
          WHERE d2.id = docs.id AND dm.user_id = current_setting('app.user_id', true)));
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&joined)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("no_access"),
        "a membership subquery reading its own table recurses too:\n{dsl}"
    );
}

/// A non-`SELECT` policy may read its own table, since expanding it needs the
/// table's `SELECT` policies rather than itself.
#[test]
fn a_non_select_policy_may_read_its_own_table() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES docs(id), owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY docs_del ON docs FOR DELETE USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.owner_id = current_setting('app.user_id', true)));
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
        can_delete.contains(" from "),
        "the delete rule still walks the parent pointer, got '{can_delete}':\n{dsl}"
    );
    assert_ne!(
        can_delete, "no_access",
        "a non-SELECT self reference is valid SQL and must not be denied:\n{dsl}"
    );
}

/// The recursion is a property of the `SQL`, not of how well the pattern was
/// recognized.
#[test]
fn a_recursive_select_policy_denies_reads_even_when_unrecognized() {
    let db = db_of(
        r"
CREATE TABLE t1(id INTEGER PRIMARY KEY, parent_id INTEGER, owner TEXT);
ALTER TABLE t1 ENABLE ROW LEVEL SECURITY;
CREATE POLICY t1_own ON t1 FOR SELECT USING (owner = current_setting('app.user_id', true));
CREATE POLICY t1_tree ON t1 FOR SELECT USING (
  EXISTS (SELECT 1 FROM t1 p WHERE p.id = t1.parent_id AND p.owner = current_setting('app.user_id', true)));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "t1", "can_select").as_deref(),
        Some("no_access"),
        "every read of t1 raises infinite recursion, so nothing is readable:\n{}",
        model.model()
    );
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "the operator must be told why, got {:#?}",
        model.notes()
    );
}

/// Reading a table expands its `SELECT` policies, and any table those read expands its
/// own, so a loop anywhere in that closure makes `PostgreSQL` raise rather than filter.
/// Verified on `postgres:18`: every read of either table raises, owned rows included.
fn cycle_pair_schema(command: &str) -> ParserDB {
    db_of(&format!(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, b_id INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, a_id INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (b_id) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR {command} USING (owner_id = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM b WHERE b.id = a.b_id AND b.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pb ON b FOR {command} USING (owner_id = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM a WHERE a.id = b.a_id AND a.owner_id = current_setting('app.user_id', true)));
"
    ))
}

/// A cycle spanning two tables denies reads of both, and the owner arm does not save
/// them: `PostgreSQL` detects the loop when it expands the policy, before any row is
/// evaluated.
#[test]
fn a_read_cycle_across_two_tables_denies_both() {
    let db = cycle_pair_schema("SELECT");
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for table in ["a", "b"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "every read of '{table}' raises infinite recursion, so nothing is readable:\n{dsl}"
        );
    }

    let mut complaints = Vec::new();
    for table in ["a", "b"] {
        if !outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::PolicyReadRecursion {
                    table: spelling,
                    role,
                    commands,
                    relation,
                }
                    if spelling.to_string() == format!("public.{table}")
                        && role == "app_user"
                        && commands == &["SELECT".to_string()]
                        && relation == table
            )
        }) {
            complaints.push(format!(
                "no note names the loop that denies SELECT of '{table}'"
            ));
        }
    }
    assert!(
        complaints.is_empty(),
        "{complaints:?}, got {:#?}",
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

    for query in outputs.tuple_queries() {
        assert!(
            !query.sql.contains("AS relation"),
            "nothing can consult a relation of either table, so this query is dead:\n{}",
            query.sql
        );
    }
}

/// Written `FOR ALL`, the same loop reaches the commands that read no row. Probed: a
/// plain `INSERT` and a constant blanket `UPDATE` both raise, because the recursive
/// `USING` is what feeds them.
#[test]
fn a_read_cycle_reaches_the_commands_that_read_no_row() {
    let db = cycle_pair_schema("ALL");
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let mut granted = Vec::new();
    for table in ["a", "b"] {
        for relation in [
            "can_select",
            "can_insert",
            "can_update",
            "can_update_without_reading",
            "can_delete",
        ] {
            if !relation_denies(&dsl, table, relation) {
                granted.push(format!("{table}.{relation}"));
            }
        }
    }
    assert!(
        granted.is_empty(),
        "the recursive USING feeds every command, so {granted:?} must deny:\n{dsl}"
    );
}

/// A three-table loop is the same reachability question, and closing only the two-table
/// case would leave it open.
#[test]
fn a_read_cycle_across_three_tables_denies_all_three() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE c(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE b ADD CONSTRAINT b_c FOREIGN KEY (nx) REFERENCES c(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
ALTER TABLE c ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (owner_id = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pb ON b FOR SELECT USING (owner_id = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM c WHERE c.id = b.nx AND c.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pc ON c FOR SELECT USING (owner_id = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM a WHERE a.id = c.nx AND a.owner_id = current_setting('app.user_id', true)));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    for table in ["a", "b", "c"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "'{table}' sits on the loop, so its reads raise:\n{dsl}"
        );
    }
}

/// Reachability, not membership. Probed: reading `x` raises even though `x` is on no
/// loop, and the parent gate does not save it, since its owner arm grants on its own.
#[test]
fn a_table_that_only_reaches_a_read_cycle_is_denied_too() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
CREATE TABLE x(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
ALTER TABLE x ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_setting('app.user_id', true)));
CREATE POLICY px ON x FOR SELECT USING (owner_id = current_setting('app.user_id', true)
  OR EXISTS (SELECT 1 FROM a WHERE a.id = x.nx AND a.owner_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "x", "can_select").as_deref(),
        Some("no_access"),
        "reading 'x' expands a policy that reaches the loop, so it raises:\n{dsl}"
    );
    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| { note.subject() == "public.x" && note.message().contains("recursion") }),
        "the operator must be told why 'x' denies, got {:#?}",
        outputs.notes()
    );
}

/// A RESTRICTIVE `SELECT` policy is expanded on a read exactly like a permissive one, so
/// it carries a loop the same way. Probed: both tables raise.
#[test]
fn a_read_cycle_through_a_restrictive_policy_denies_both() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY par ON a AS RESTRICTIVE FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_setting('app.user_id', true)));
",
    );
    let dsl = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    for table in ["a", "b"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "the restrictive arm is expanded too, so '{table}' raises:\n{dsl}"
        );
    }
}

/// `PostgreSQL` finds a loop while it expands the policies, before any literal is compared,
/// so a clause whose literal's stored value is unknown here still carries one.
#[test]
fn a_read_cycle_through_a_clause_whose_literal_cannot_be_read_denies_both() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER, expires TIMESTAMPTZ);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (expires > '2026-01-01 09:00'
  AND EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_user));
CREATE POLICY pb ON b FOR SELECT USING (owner_id = current_user
  OR EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for table in ["a", "b"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "every read of '{table}' raises infinite recursion:\n{dsl}"
        );
        assert!(
            outputs.notes().iter().any(|note| {
                note.subject() == format!("public.{table}")
                    && note.message().contains("infinite recursion")
            }),
            "no note walks the loop for '{table}', got {:#?}",
            outputs.notes()
        );
    }
}

/// A write clause reading a looping table cannot be evaluated either. Probed: the read
/// of `docs` is fine while its `INSERT` raises, and a plain sibling `INSERT` policy does
/// not save it, so the command denies rather than the clause dropping.
#[test]
fn a_write_clause_reading_a_recursive_table_denies_that_command() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, owner_id UUID);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_setting('app.user_id', true)));
CREATE POLICY pds ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY pdi_plain ON docs FOR INSERT WITH CHECK (owner_id = current_setting('app.user_id', true));
CREATE POLICY pdi_loop ON docs FOR INSERT WITH CHECK (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner and acting_app_user from request_gate"),
        "the read policy of 'docs' reads nothing that loops, so reads still translate:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "docs", "can_insert").as_deref(),
        Some("no_access"),
        "one INSERT check reads 'm', whose reads raise, so the whole INSERT raises:\n{dsl}"
    );
    assert!(
        outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::PolicyReadRecursion { table, role, commands, relation }
                    if table.to_string() == "public.docs"
                        && role == "app_user"
                        && commands == &["INSERT".to_string()]
                        && relation == "m"
            )
        }),
        "the note must name the INSERT and the relation whose reads loop, got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::PolicyReadRecursion { table, commands, .. }
                    if table.to_string() == "public.docs"
                        && commands.iter().any(|command| command == "SELECT")
            )
        }),
        "reads of 'docs' are fine, so no note may deny them, got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs.notes().iter().any(|note| {
            note.severity().diverges_from_database()
                && !matches!(note, TranslationNote::ClauseBelowThreshold { .. })
        }),
        "PostgreSQL raises here rather than granting, so nothing may claim the model \
         denies what RLS grants, got {:#?}",
        outputs.notes()
    );
}

/// Either `UPDATE` clause blocking raises the whole statement. Probed: with only the
/// `WITH CHECK` reading the looping table, the read of the guarded table is fine while
/// both the blanket and the row-scoped update raise.
#[test]
fn an_update_check_reading_a_recursive_table_denies_every_update() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, owner_id UUID);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_setting('app.user_id', true)));
CREATE POLICY pds ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY pdu ON docs FOR UPDATE USING (owner_id = current_setting('app.user_id', true)) WITH CHECK (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "docs", "can_select").as_deref(),
        Some("owner and acting_app_user from request_gate"),
        "the read clause reads nothing that loops, so reads still translate:\n{dsl}"
    );
    for relation in ["can_update", "can_update_without_reading"] {
        assert!(
            relation_denies(&dsl, "docs", relation),
            "the check cannot be planned, so {relation} raises rather than filtering:\n{dsl}"
        );
    }
    assert!(
        outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::PolicyReadRecursion { table, role, commands, relation }
                    if table.to_string() == "public.docs"
                        && role == "app_user"
                        && commands == &["UPDATE".to_string()]
                        && relation == "m"
            )
        }),
        "the note must name the UPDATE and the relation whose reads loop, got {:#?}",
        outputs.notes()
    );
    // The policy is blocked on one clause and live on the other, and 'm' grants no reads,
    // so no membership row is visible and no query may go looking for one.
    assert!(
        outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::MembershipTableGrantsNoReads { join_table, .. }
                    if join_table.to_string() == "public.m"
            )
        }),
        "no membership row of 'm' is visible, so the note must say so, got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains(" m ") || query.sql.contains(" m\n")),
        "no relation reads 'm', so no query may load it, got {:#?}",
        outputs
            .tuple_queries()
            .iter()
            .map(|query| &query.sql)
            .collect::<Vec<_>>()
    );
    assert!(
        !outputs.notes().iter().any(|note| {
            note.severity().diverges_from_database()
                && !matches!(note, TranslationNote::ClauseBelowThreshold { .. })
        }),
        "PostgreSQL raises the update rather than granting it, so nothing diverges, got {:#?}",
        outputs.notes()
    );
}

/// The loop is a thing the operator has to fix in SQL, so the note carries the table in
/// the schema's own spelling rather than in the model's type names, which lowercase and
/// can carry a disambiguating suffix, and the relation in the spelling the database's
/// error names.
#[test]
fn a_read_recursion_note_names_tables_as_the_schema_spells_them() {
    let db = db_of(
        r"
CREATE SCHEMA app;
CREATE TABLE app.docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES app.docs(id), owner_id UUID);
ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_tree ON app.docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM app.docs p WHERE p.id = app.docs.parent_id AND p.owner_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert!(
        outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::PolicyReadRecursion { table, relation, .. }
                    if table.to_string() == "app.docs" && relation == "docs"
            )
        }),
        "the note must carry the table as the schema spells it and the relation as the \
         database's error names it, got {:#?}",
        outputs.notes()
    );
}

/// A `TO` role the deployment's acting roles never reach denies the policy's commands to
/// every request, and the policy contributes nothing the operator has to load.
#[test]
fn a_policy_no_acting_role_reaches_denies_and_contributes_nothing() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, parent_id UUID REFERENCES docs(id), owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_tree ON docs FOR SELECT TO auditor USING (
  EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id AND p.owner_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for relation in ["can_select", "can_insert", "can_update", "can_delete"] {
        assert!(
            relation_denies(&dsl, "docs", relation),
            "no acting role the deployment runs as reaches 'auditor', so {relation} denies:\n{dsl}"
        );
    }
    assert!(
        outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::RowSecurityRefused { table, role, commands, reason, .. }
                    if table.to_string() == "public.docs"
                        && role == "app_user"
                        && commands == &["SELECT".to_string()]
                        && reason.contains("auditor")
            )
        }),
        "the operator must be told the policy's TO clause is unreachable, got {:#?}",
        outputs.notes()
    );
    assert!(
        outputs.tuple_queries().is_empty(),
        "no relation grants, so nothing is loaded:\n{dsl}"
    );
}

/// The guard must not over-fire. A diamond sharing a table carries no loop, and probed
/// against `postgres:18` every read of it succeeds.
#[test]
fn a_diamond_sharing_a_table_without_a_cycle_still_translates() {
    let db = db_of(
        r"
CREATE TABLE g(id INTEGER PRIMARY KEY, owner_id UUID);
CREATE TABLE e(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES g(id));
CREATE TABLE f(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES g(id));
CREATE TABLE d(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES e(id));
ALTER TABLE g ENABLE ROW LEVEL SECURITY;
ALTER TABLE e ENABLE ROW LEVEL SECURITY;
ALTER TABLE f ENABLE ROW LEVEL SECURITY;
ALTER TABLE d ENABLE ROW LEVEL SECURITY;
CREATE POLICY pg ON g FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY pe ON e FOR SELECT USING (
  EXISTS (SELECT 1 FROM g WHERE g.id = e.nx AND g.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pf ON f FOR SELECT USING (
  EXISTS (SELECT 1 FROM g WHERE g.id = f.nx AND g.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pd ON d FOR SELECT USING (
  EXISTS (SELECT 1 FROM e WHERE e.id = d.nx AND e.owner_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for table in ["d", "e", "f", "g"] {
        assert_ne!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "'{table}' is on no loop, so its reads must keep translating:\n{dsl}"
        );
    }
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "no loop exists here, so nothing may report one, got {:#?}",
        outputs.notes()
    );
}

/// A non-`SELECT` `USING` clause is not part of expanding a read, so it cannot close a
/// loop. Probed: `a`'s `UPDATE USING` reads `b` while `b`'s `SELECT USING` reads `a`, and
/// no statement raises.
#[test]
fn an_update_clause_pointing_back_is_not_a_read_cycle() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pas ON a FOR SELECT USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY pau ON a FOR UPDATE USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_setting('app.user_id', true)))
  WITH CHECK (id IS NOT NULL);
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for (table, relation) in [
        ("a", "can_select"),
        ("b", "can_select"),
        ("a", "can_update"),
    ] {
        assert_ne!(
            relation_definition(&dsl, table, relation).as_deref(),
            Some("no_access"),
            "no read loop exists here, so {table}.{relation} must keep translating:\n{dsl}"
        );
    }
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "nothing loops here, got {:#?}",
        outputs.notes()
    );
}

/// A loop whose second leg sits on a table with row level security off never expands, so
/// it is not a loop. Probed: both reads succeed.
#[test]
fn a_cycle_through_a_table_without_row_level_security_is_not_a_cycle() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pb ON b FOR SELECT USING (
  EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_setting('app.user_id', true)));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_ne!(
        relation_definition(&dsl, "a", "can_select").as_deref(),
        Some("no_access"),
        "'b' expands no policy, so reading 'a' terminates:\n{dsl}"
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.message().contains("recursion")),
        "row level security is off on 'b', so nothing loops, got {:#?}",
        outputs.notes()
    );
}

/// The loop is a property of the schema, not of which policies survived filtering, so a
/// leg dropped for low confidence still makes `PostgreSQL` raise. Here `b` keeps a plain
/// ownership policy that grants on its own, so nothing gates the grant closed by accident.
#[test]
fn a_read_cycle_survives_a_leg_dropped_by_confidence_filtering() {
    let db = db_of(
        r"
CREATE TABLE a(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER);
CREATE TABLE b(id INTEGER PRIMARY KEY, owner_id UUID, nx INTEGER REFERENCES a(id));
ALTER TABLE a ADD CONSTRAINT a_b FOREIGN KEY (nx) REFERENCES b(id);
ALTER TABLE a ENABLE ROW LEVEL SECURITY;
ALTER TABLE b ENABLE ROW LEVEL SECURITY;
CREATE POLICY pa ON a FOR SELECT USING (
  EXISTS (SELECT 1 FROM b WHERE b.id = a.nx AND b.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pb_loop ON b FOR SELECT USING (
  NOT EXISTS (SELECT 1 FROM a WHERE a.id = b.nx AND a.owner_id = current_setting('app.user_id', true)));
CREATE POLICY pb_own ON b FOR SELECT USING (owner_id = current_setting('app.user_id', true));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert_eq!(
        relation_definition(&dsl, "b", "can_select").as_deref(),
        Some("no_access"),
        "'pb_loop' still reads 'a' in the database, whatever the threshold dropped:\n{dsl}"
    );
}

/// A membership table whose own reads loop makes every read of the table that joins it
/// raise, and the note names the relation `PostgreSQL` names. What this pins beyond the
/// denial is that no query may go looking for rows of a table whose reads raise. Probed on
/// `postgres:18`: `SELECT` on `docs` raises `infinite recursion detected in policy for
/// relation "m"`.
#[test]
fn a_looping_membership_table_asks_for_no_tuples() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_setting('app.user_id', true)));
CREATE POLICY pd ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id', true)));
",
    );
    assert_looping_membership_is_silent(&db, "the correlated membership spelling");
}

/// The same for the uncorrelated spelling, which reaches a different judge beside the
/// correlated one and would otherwise be one recognizer away from reporting a gap that
/// does not exist.
#[test]
fn a_looping_uncorrelated_membership_table_asks_for_no_tuples() {
    let db = db_of(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT);
CREATE TABLE m(id INTEGER PRIMARY KEY, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY pm ON m FOR SELECT USING (EXISTS (SELECT 1 FROM m m2 WHERE m2.user_id = current_setting('app.user_id', true)));
CREATE POLICY pd ON docs FOR SELECT USING (EXISTS (SELECT 1 FROM m WHERE m.user_id = current_setting('app.user_id', true)));
",
    );
    assert_looping_membership_is_silent(&db, "the uncorrelated membership spelling");
}

/// Reads of `docs` and of `m` both deny, the note names the relation whose reads loop,
/// the membership note says no row of `m` is visible, and no query goes looking for rows
/// of a table whose reads raise.
fn assert_looping_membership_is_silent(db: &ParserDB, spelling: &str) {
    let outputs = translator(ConfidenceLevel::B)
        .translate(db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    for table in ["docs", "m"] {
        assert_eq!(
            relation_definition(&dsl, table, "can_select").as_deref(),
            Some("no_access"),
            "{spelling}: reading '{table}' expands a clause whose reads loop:\n{dsl}"
        );
    }
    assert!(
        outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::PolicyReadRecursion { table, role, commands, relation }
                    if table.to_string() == "public.docs"
                        && role == "app_user"
                        && commands == &["SELECT".to_string()]
                        && relation == "m"
            )
        }),
        "{spelling}: the note must name the relation whose reads loop, got {:#?}",
        outputs.notes()
    );
    assert!(
        outputs.notes().iter().any(|note| {
            matches!(
                note,
                TranslationNote::MembershipTableGrantsNoReads { join_table, .. }
                    if join_table.to_string() == "public.m"
            )
        }),
        "{spelling}: no membership row of 'm' is visible, so the note must say so, \
         got {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs.notes().iter().any(|note| {
            note.severity().diverges_from_database()
                && !matches!(note, TranslationNote::ClauseBelowThreshold { .. })
        }),
        "{spelling}: PostgreSQL raises here rather than granting, so nothing diverges, got {:#?}",
        outputs.notes()
    );
    let queries = outputs.tuple_queries();
    let asking: Vec<&str> = queries
        .iter()
        .filter(|query| query.sql.contains(" m ") || query.sql.contains(" m\n"))
        .map(|query| query.comment.lines().next().unwrap_or(""))
        .collect();
    assert!(
        asking.is_empty(),
        "{spelling}: no relation reads 'm', so no query may load it: {asking:?}"
    );
}
