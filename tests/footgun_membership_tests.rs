//! Regression tests for inputs where the generated model or tuple SQL diverged
//! from `PostgreSQL` RLS semantics.
//!
//! Membership through a join table, and the holder a row-independent grant gets.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{ExistsMembership, PatternClass};
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RelationShapes;
use rls2fga::types::TranslationNote;
use rls2fga::types::{RecordDerivation, ValueSource};

mod support;

use support::footgun::{
    db_of, membership_translation, pg_role_relation, relation_definition, relation_definitions,
    relation_denies, scope_admits_role, translation, translator, tuples_reading_from, type_names,
    CORRELATION_SCHEMA,
};
use support::{classify_sql, plan_at};

/// `x = ANY (SELECT ...)` is another spelling of `x IN (SELECT ...)`.
#[test]
fn equals_any_subquery_classifies_as_exists_membership() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT
  USING (id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user));
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
        matches!(
            &using.pattern,
            PatternClass::P4ExistsMembership(ExistsMembership { join_table, pairs, user_column, .. })
                if join_table.name() == "doc_members"
                    && matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id")
                    && user_column == "user_id"
        ),
        "= ANY (subquery) should match IN (subquery) membership, got: {:?}",
        using.pattern
    );
}

/// When an `EXISTS` correlates to a column of an enclosing subquery, the linking
/// column is the enclosing one. Reading the scanned table's own key instead names
/// a type after that column and files two tables' rows under one object id.
#[test]
fn nested_correlated_exists_resolves_to_the_scanned_table() {
    let db = db_of(
        r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY orgs_sel ON orgs FOR SELECT USING (owner_id = current_user);
CREATE TABLE projects(id UUID PRIMARY KEY, org_id UUID REFERENCES orgs(id));
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (
  EXISTS (SELECT 1 FROM orgs o WHERE o.id = projects.org_id AND o.owner_id = current_user));
CREATE TABLE tasks(id UUID PRIMARY KEY, project_id UUID REFERENCES projects(id));
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tasks_sel ON tasks FOR SELECT USING (
  EXISTS (SELECT 1 FROM projects p WHERE p.id = tasks.project_id
          AND EXISTS (SELECT 1 FROM orgs o WHERE o.id = p.org_id AND o.owner_id = current_user)));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    assert!(
        !type_names(&dsl).iter().any(|name| name == "id"),
        "a join column must not become a type:\n{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "projects", "can_select").as_deref(),
        Some("owner from orgs"),
        "projects requires ownership of its org:\n{dsl}"
    );
    let tasks_select =
        relation_definition(&dsl, "tasks", "can_select").expect("tasks should define can_select");
    assert!(
        tasks_select.ends_with(" from projects"),
        "and tasks reaches that rule through projects, got '{tasks_select}':\n{dsl}"
    );

    // projects rows link to orgs by org_id only. Keying that link on projects.id
    // would grant a project the permissions of the org with the same identifier.
    for query in translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries()
    {
        if !query.sql.contains(r#"FROM "projects""#) || !query.sql.contains("'orgs:'") {
            continue;
        }
        assert!(
            query.sql.contains(r#"'orgs:' || CASE WHEN "org_id"::text"#),
            "a projects row must reference its org by org_id:\n{}",
            query.sql
        );
    }
}

/// A subquery scanning an entity by its own primary key is not a membership join, and
/// treating it as one pairs rows that merely share an id.
#[test]
fn membership_join_on_the_scanned_tables_own_key_is_refused() {
    // No foreign key is declared, so parent inheritance cannot be confirmed either.
    let db = db_of(
        r"
CREATE TABLE orgs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY orgs_sel ON orgs FOR SELECT USING (owner_id = current_user);
CREATE TABLE projects(id UUID PRIMARY KEY, org_id UUID);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_sel ON projects FOR SELECT USING (
  EXISTS (SELECT 1 FROM orgs o WHERE o.id = projects.org_id AND o.owner_id = current_user));
",
    );
    // Keep D-level classifications so the diagnostic itself is observable.
    let translator = translator(ConfidenceLevel::D);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        !type_names(&model.model()).iter().any(|name| name == "id"),
        "a join column must not become a type:\n{}",
        model.model()
    );
    assert_eq!(
        relation_definition(&model.model(), "projects", "can_select").as_deref(),
        Some("no_access"),
        "an unconfirmable parent link must deny, not guess:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            note.subject() == "projects_sel" && note.message().contains("own primary key")
        }),
        "the operator must be told why the subquery was refused, got: {:#?}",
        model.notes()
    );
}

/// A one-row-per-parent membership table has its foreign key as its primary key.
/// It is still a membership table, so refusing it denies access the policy grants.
#[test]
fn membership_table_whose_primary_key_is_its_foreign_key_still_translates() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_owner(doc_id UUID PRIMARY KEY REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_owner o WHERE o.doc_id = docs.id AND o.user_id = current_user));
";
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::A);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert_ne!(
        can_select,
        "no_access",
        "a membership table keyed by its foreign key must still grant access:\n{}",
        model.model()
    );
    assert!(
        format_tuples(
            translator
                .translate(&db)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .tuple_queries()
        )
        .contains(r#"FROM "public"."doc_owner""#),
        "membership rows must be collected from doc_owner"
    );
}

/// A membership subquery that joins a second table carries a condition on that
/// table. Dropping it grants access to every row the join would have excluded.
#[test]
fn membership_subquery_with_a_join_is_refused() {
    let db = db_of(
        r"
CREATE TABLE departments(id UUID PRIMARY KEY, region TEXT);
CREATE TABLE user_permissions(id UUID PRIMARY KEY, user_id UUID, dept_id UUID REFERENCES departments(id));
CREATE TABLE orders(id UUID PRIMARY KEY, region TEXT);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_sel ON orders FOR SELECT USING (
  EXISTS (SELECT 1 FROM user_permissions up JOIN departments d ON up.dept_id = d.id
          WHERE up.user_id = current_user AND d.region = orders.region));
",
    );
    let model = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&model.model(), "orders", "can_select").as_deref(),
        Some("no_access"),
        "a join the model cannot express must deny, not drop the condition:\n{}",
        model.model()
    );
    assert!(
        model
            .notes()
            .iter()
            .any(|note| note.subject() == "orders_sel"),
        "the operator must be told the subquery was refused, got: {:#?}",
        model.notes()
    );
}

#[test]
fn a_nested_quoted_table_is_not_precomputed_as_a_membership_residual() {
    let db = db_of(
        r#"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE memberships(doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE TABLE "Memberships"(doc_id TEXT REFERENCES docs(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Memberships" ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM memberships m
    WHERE m.doc_id = docs.id
      AND m.user_id = current_user
      AND EXISTS (
        SELECT 1 FROM "Memberships"
      )
  )
);
"#,
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert_eq!(
        relation_definition(&outputs.model(), "docs", "can_select").as_deref(),
        Some("no_access")
    );
    assert!(!outputs
        .tuple_queries()
        .iter()
        .any(|query| query.sql.contains(r#"FROM "memberships""#)));
}

/// A membership subquery joining back to its own table must still expose the `member`
/// relation the userset reads.
#[test]
fn self_referential_membership_defines_the_relation_it_reads() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_del ON docs FOR DELETE USING (
  EXISTS (SELECT 1 FROM doc_members dm
          WHERE dm.doc_id = docs.id AND dm.user_id = current_user));
",
    );
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();

    let can_delete =
        relation_definition(&dsl, "docs", "can_delete").expect("docs should define can_delete");
    let (read, tupleset) = can_delete
        .split_once(" from ")
        .unwrap_or_else(|| panic!("can_delete should walk a tupleset, got '{can_delete}':\n{dsl}"));
    let tupleset = tupleset.split(" and ").next().unwrap_or(tupleset).trim();
    assert!(
        relation_definition(&dsl, "docs", tupleset).is_some(),
        "can_delete walks '{tupleset}', which docs does not define:\n{dsl}"
    );
    let read = read.rsplit("and ").next().unwrap_or(read).trim();
    assert!(
        relation_definition(&dsl, "docs", read).is_some(),
        "can_delete reads '{read}', which docs does not define:\n{dsl}"
    );
    assert_ne!(
        read, "no_access",
        "the membership rule must survive:\n{dsl}"
    );
}

/// A membership table that grants no reads hides every membership row, so the
/// subquery matches nothing.
#[test]
fn membership_through_an_unreadable_join_table_grants_nothing() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        relation_definition(&model.model(), "docs", "can_select").as_deref(),
        Some("no_access"),
        "no membership row is readable, so the policy grants nothing:\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            note.message().contains("doc_members") && note.message().contains("membership")
        }),
        "the operator must be told which table hides the rows, got {:#?}",
        model.notes()
    );
}

/// Which membership rows a user sees is up to the join table's own policies, which
/// no relation can carry, so the translation says so.
#[test]
fn membership_through_a_guarded_join_table_is_disclosed() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_self ON doc_members FOR SELECT USING (user_id = current_user);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains(" from "),
        "the membership grant stays, got '{can_select}':\n{}",
        model.model()
    );
    assert!(
        model.notes().iter().any(|note| {
            note.message().contains("doc_members") && note.message().contains("membership")
        }),
        "the operator must be told the join table filters memberships, got {:#?}",
        model.notes()
    );
}

/// A join table without RLS needs no caveat.
#[test]
fn membership_through_an_open_join_table_needs_no_caveat() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert!(
        !model.notes().iter().any(|note| {
            note.message().contains("doc_members") && note.message().contains("membership")
        }),
        "an unprotected join table needs no note, got {:#?}",
        model.notes()
    );
}

/// A membership table whose only read policy targets a role hides every row from a
/// user outside that role, so the grant it feeds requires that role too.
#[test]
fn membership_readable_only_by_a_role_requires_that_role() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_read ON doc_members FOR SELECT TO auditor USING (true);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
";
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::B);
    let model = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let scope = pg_role_relation(&model.model(), "docs").unwrap_or_else(|| {
        panic!(
            "docs must scope the membership grant by role:\n{}",
            model.model()
        )
    });
    let can_select = relation_definition(&model.model(), "docs", "can_select")
        .expect("docs should define can_select");
    assert!(
        can_select.contains(&format!("from {scope}")),
        "reading docs must require the role that can read doc_members, got '{can_select}':\n{}",
        model.model()
    );

    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let tuples = outputs.tuple_queries();
    assert!(
        scope_admits_role(tuples, "docs:", &scope, "auditor"),
        "the scope relation needs auditor tuples on docs, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
}

/// One read policy any role may use makes the membership rows reachable without a
/// role, so narrowing the grant would deny access `PostgreSQL` allows.
#[test]
fn membership_readable_by_public_keeps_the_grant_unscoped() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY dm_audit ON doc_members FOR SELECT TO auditor USING (true);
CREATE POLICY dm_self ON doc_members FOR SELECT USING (user_id = current_user);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user));
",
    );
    let model = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    assert_eq!(
        pg_role_relation(&model.model(), "docs"),
        None,
        "an unscoped read policy leaves the membership grant open to every role:\n{}",
        model.model()
    );
}

/// `caller IN (SELECT user_id FROM m WHERE m.fk = outer.id)` is the membership `EXISTS`
/// written the other way round. `PostgreSQL` 18, role alice, over rows covering a member,
/// a non-member, no membership row at all, a row whose `user_id` is NULL, a member beside
/// a NULL, and a member failing a residual predicate: the `IN`, `= ANY` and `EXISTS`
/// spellings agree on every row, the only difference being NULL against false where
/// `user_id` is NULL, and both filter the row out. So all three must translate alike.
#[test]
fn the_caller_inside_a_membership_subquery_translates_like_the_exists_spelling() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );
    assert!(
        !expected_dsl.contains("can_select: no_access"),
        "guard precondition: the EXISTS spelling must translate:\n{expected_dsl}"
    );

    for clause in [
        "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id)",
        "current_user = ANY (SELECT user_id FROM doc_members WHERE doc_id = docs.id)",
        "current_user IN (SELECT dm.user_id FROM doc_members dm WHERE dm.doc_id = docs.id)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` must yield the same model as the EXISTS spelling"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the EXISTS spelling"
        );
    }
}

/// A residual predicate no tuple can express has to survive the rewrite, since it is what
/// tells the operator the membership relation is wider than the policy.
#[test]
fn a_residual_predicate_survives_the_caller_in_subquery_rewrite() {
    let (expected_dsl, _) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND role = 'admin' \
         AND user_id = current_user)",
    );
    let (dsl, _) = membership_translation(
        "current_user IN (SELECT user_id FROM doc_members WHERE doc_id = docs.id \
         AND role = 'admin')",
    );
    assert_eq!(
        dsl, expected_dsl,
        "the role predicate must reach the same place it does through EXISTS"
    );
}

/// The guard must not over-fire: inside `EXISTS` a limit of at least one row cannot change
/// whether a row exists, and `SELECT 1 ... LIMIT 1` is the idiom people write.
#[test]
fn an_exists_membership_subquery_keeping_at_least_one_row_still_translates() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );

    for clause in [
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user LIMIT 1)",
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user LIMIT ALL)",
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user OFFSET 0)",
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id \
         AND user_id = current_user FETCH FIRST 1 ROWS ONLY)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` cannot empty the subquery, so it must translate unchanged"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the unlimited spelling"
        );
    }
}

/// `EXISTS (SELECT 1 FROM m WHERE user_id = caller)` names no column of the guarded
/// table, so it admits every row at once to whoever appears in `m`. Denying instead is
/// safe but wrong, and pairing every row with every member is not loadable at any real
/// size. One holder object per member source carries the members, and every row points
/// at it, so the facts grow as rows plus members.
#[test]
fn an_uncorrelated_membership_check_translates_through_a_holder() {
    let schema = "CREATE TABLE staff(id UUID PRIMARY KEY, user_id TEXT);\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, title TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = current_user));\n";
    let (dsl, tuples) = translation(schema);

    assert!(
        dsl.contains("define staff_holder: [staff_holder]"),
        "the row points at the holder:\n{dsl}"
    );
    assert!(
        dsl.contains("type staff_holder"),
        "and the holder is a type of its own:\n{dsl}"
    );
    // Rows plus members, never rows times members.
    assert!(
        tuples.contains("'staff_holder:all' AS subject"),
        "every row points at the one holder:\n{tuples}"
    );
    assert!(
        tuples.contains("SELECT DISTINCT 'staff_holder:all' AS object"),
        "and the members attach to it once each:\n{tuples}"
    );
}

/// A clock on the only holder source must remove the plain member subject.
#[test]
fn a_clocked_holder_does_not_admit_an_unconditioned_member_tuple() {
    let schema = "CREATE TABLE reviewers(user_id TEXT, vetted_at TIMESTAMPTZ);\n\
                  CREATE TABLE memos(id UUID PRIMARY KEY);\n\
                  ALTER TABLE memos ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY memos_reviewers ON memos FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM reviewers WHERE reviewers.user_id = current_user \
                    AND reviewers.vetted_at > now()));\n";
    let (dsl, tuples) = translation(schema);

    let (_, member) = relation_definitions(&dsl, "reviewers_holder")
        .into_iter()
        .find(|(_, body)| body.starts_with("[user"))
        .expect("the holder admits user membership tuples");
    assert!(
        member.starts_with("[user with ") && member.ends_with(']'),
        "the holder should admit only the conditioned user:\n{dsl}"
    );
    assert!(
        !member.contains("[user,") && !member.contains(", user]"),
        "an unconditioned tuple would bypass the clock:\n{dsl}"
    );
    assert!(
        tuples.contains(" AS condition, jsonb_build_object('vetted_at', MAX(\"vetted_at\"))"),
        "the tuple loader still carries the clock context:\n{tuples}"
    );
}

/// Two policies reading different member tables must not pool their members, and two
/// reading the same one may share. That is why the holder is per member source rather
/// than per table or per policy.
#[test]
fn a_holder_is_shared_per_member_source_and_never_across_them() {
    let schema = "CREATE TABLE staff(id UUID PRIMARY KEY, user_id TEXT);\n\
                  CREATE TABLE auditors(id UUID PRIMARY KEY, user_id TEXT);\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY);\n\
                  CREATE TABLE notes(id UUID PRIMARY KEY);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_staff ON docs FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = current_user));\n\
                  CREATE POLICY docs_audit ON docs FOR DELETE USING (\n\
                    EXISTS (SELECT 1 FROM auditors WHERE auditors.user_id = current_user));\n\
                  CREATE POLICY notes_staff ON notes FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM staff WHERE staff.user_id = current_user));\n";
    let (dsl, tuples) = translation(schema);

    assert_eq!(
        dsl.matches("type staff_holder").count(),
        1,
        "two policies reading staff share one holder:\n{dsl}"
    );
    assert!(
        dsl.contains("type auditors_holder"),
        "and a different member table gets its own:\n{dsl}"
    );
    // Each holder is fed only from its own table.
    assert!(
        tuples.contains("'staff_holder:all' AS object,")
            && tuples.contains("'auditors_holder:all' AS object,"),
        "each holder loads its own members:\n{tuples}"
    );
}

/// A correlated check still has to translate as a per-row membership. The holder is for
/// the shape that names no outer column, and reading it too widely would grant a whole
/// table where only one row was meant.
#[test]
fn a_correlated_membership_check_does_not_become_a_holder() {
    let schema = "CREATE TABLE docs(id UUID PRIMARY KEY);\n\
                  CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), \
                  user_id TEXT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (\n\
                    EXISTS (SELECT 1 FROM doc_members WHERE doc_members.doc_id = docs.id \
                    AND doc_members.user_id = current_user));\n";
    let (dsl, _) = translation(schema);

    assert!(
        !dsl.contains("_holder"),
        "a check naming the outer row is per row, not per table:\n{dsl}"
    );
}

/// The object-key spelling is the `EXISTS` spelling written the other way round. Probed on
/// `PostgreSQL` 18 over rows covering a member, a non-member, no membership row at all, a
/// membership row whose key is NULL, a member beside a NULL key, and a member failing a
/// residual predicate: `IN`, `= ANY` and `EXISTS` disagree on zero rows. So the model and
/// the tuples have to match byte for byte, or the fix has narrowed the shape.
#[test]
fn the_object_key_in_subquery_translates_like_the_exists_spelling() {
    let (expected_dsl, expected_tuples) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND user_id = current_user)",
    );
    assert!(
        !expected_dsl.contains("can_select: no_access"),
        "guard precondition: the EXISTS spelling must translate:\n{expected_dsl}"
    );

    for clause in [
        "id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
        "id = ANY (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
        "id IN (SELECT dm.doc_id FROM doc_members dm WHERE dm.user_id = current_user)",
        "docs.id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user)",
    ] {
        let (dsl, tuples) = membership_translation(clause);
        assert_eq!(
            dsl, expected_dsl,
            "`{clause}` must yield the same model as the EXISTS spelling"
        );
        assert_eq!(
            tuples, expected_tuples,
            "`{clause}` must yield the same tuples as the EXISTS spelling"
        );
    }
}

/// A residual predicate is what tells the operator the relation is wider than the policy,
/// so it has to survive the rewrite of the object-key spelling too.
#[test]
fn a_residual_predicate_survives_the_object_key_in_subquery_rewrite() {
    let (expected_dsl, _) = membership_translation(
        "EXISTS (SELECT 1 FROM doc_members WHERE doc_id = docs.id AND role = 'admin' \
         AND user_id = current_user)",
    );
    let (dsl, _) = membership_translation(
        "id IN (SELECT doc_id FROM doc_members WHERE role = 'admin' AND user_id = current_user)",
    );
    assert_eq!(
        dsl, expected_dsl,
        "the role predicate must reach the same place it does through EXISTS"
    );
}

/// The `IN` form leaves to scoping which side of `doc_id = doc_id` is the guarded row and
/// which the membership row. Read without that scope the correlation vanishes, and the
/// policy reads as "the caller is a member of something", which grants the table whole.
#[test]
fn a_membership_column_spelled_like_the_guarded_key_still_correlates() {
    let db = db_of(
        r"
CREATE TABLE docs(doc_id UUID PRIMARY KEY, title TEXT);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(doc_id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT
  USING (doc_id IN (SELECT doc_id FROM doc_members WHERE user_id = current_user));
",
    );
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert!(
        !type_names(&dsl).iter().any(|name| name.contains("holder")),
        "a correlated policy mints no holder:\n{dsl}"
    );
}

/// `docs.can_select` and whether any query loads the membership table, for a schema whose
/// membership table carries `policies`.
fn membership_readability(policies: &str) -> (String, bool, Vec<String>) {
    let sql = format!(
        r"
CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT);
CREATE TABLE m(id INTEGER PRIMARY KEY, doc_id INTEGER REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
{policies}
CREATE POLICY pd ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM m WHERE m.doc_id = docs.id AND m.user_id = current_user));
"
    );
    let db = db_of(&sql);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let select = relation_definition(&dsl, "docs", "can_select")
        .unwrap_or_else(|| panic!("docs should define can_select:\n{dsl}"));
    let loads_m = outputs
        .tuple_queries()
        .iter()
        .any(|query| query.sql.contains("FROM \"public\".\"m\""));
    let notes = outputs
        .notes()
        .iter()
        .map(|note| note.message().clone())
        .collect();
    (select, loads_m, notes)
}

/// A membership read policy that cannot admit a row leaves the guarded table's subquery
/// with nothing to find, so the guarded table grants nothing. Probed on `postgres:18` with
/// one membership row naming the caller: the read of `m` returns 0 and so does the read of
/// `docs`, for every spelling below.
#[test]
fn a_membership_read_policy_that_cannot_admit_a_row_denies_the_guarded_table() {
    assert_membership_table_denied(&[
        "CREATE POLICY pm ON m FOR SELECT USING (false);",
        // Parenthesised the way pg_dump writes it back.
        "CREATE POLICY pm ON m FOR SELECT USING ((false));",
        "CREATE POLICY pm ON m FOR SELECT USING (NOT true);",
        // An AND is empty as soon as either side is, whatever the other side says.
        "CREATE POLICY pm ON m FOR SELECT USING (false AND m.user_id = current_user);",
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user AND false);",
        // Both sides of an OR empty is still empty.
        "CREATE POLICY pm ON m FOR SELECT USING (false OR false);",
        // Every permissive read policy empty, so none of them grants.
        "CREATE POLICY pm ON m FOR SELECT USING (false);\n\
         CREATE POLICY pm2 ON m FOR SELECT USING (false AND m.user_id = current_user);",
        // FOR ALL applies its USING to reads too.
        "CREATE POLICY pm ON m FOR ALL USING (false);",
    ]);
}

/// Every policy set in `policies` must leave the guarded table without reads, stop loading
/// membership rows, and say why.
fn assert_membership_table_denied(policies: &[&str]) {
    let mut complaints = Vec::new();
    for policy in policies {
        let (select, loads_m, notes) = membership_readability(policy);
        if select != "no_access" {
            complaints.push(format!("`{policy}` left can_select as `{select}`"));
        }
        if loads_m {
            complaints.push(format!("`{policy}` still loads membership rows"));
        }
        if !notes
            .iter()
            .any(|note| note.contains("'m' grants no reads"))
        {
            complaints.push(format!("`{policy}` reported no reason: {notes:?}"));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

/// A RESTRICTIVE read policy narrows whatever the permissive ones admit, so one that
/// cannot admit a row closes the table however wide they are. Probed: a permissive
/// `USING (true)` beside a restrictive `USING (false)` returns 0 rows.
#[test]
fn a_restrictive_kill_switch_on_a_membership_table_denies_the_guarded_table() {
    assert_membership_table_denied(&[
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT USING (false);",
        // The permissive side being a real rule changes nothing: the barrier still closes.
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT USING (false);",
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR ALL USING (false);",
    ]);
}

/// The guard must not over-fire. Anything whose emptiness depends on the data, or that the
/// crate simply does not recognise, keeps its disclosed grant: denying there would refuse
/// what RLS allows on the strength of a guess. Probed row counts are in the comments.
#[test]
fn a_membership_read_policy_that_may_admit_a_row_keeps_its_grant() {
    let mut complaints = Vec::new();
    for policy in [
        // 1 row.
        "CREATE POLICY pm ON m FOR SELECT USING (true);",
        // 1 row: the OR still has a live side.
        "CREATE POLICY pm ON m FOR SELECT USING (false OR m.user_id = current_user);",
        // 1 row.
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = current_user);",
        // 0 rows for this data only, and the crate cannot tell, so it must not claim to.
        "CREATE POLICY pm ON m FOR SELECT USING (m.user_id = 'nobody');",
        // 0 rows, but the crate folds no arithmetic, so this is not proven either.
        "CREATE POLICY pm ON m FOR SELECT USING (1 = 2);",
        // One empty policy beside a live one still leaves the live one granting.
        "CREATE POLICY pm ON m FOR SELECT USING (false);\n\
         CREATE POLICY pm2 ON m FOR SELECT USING (m.user_id = current_user);",
        // A restrictive barrier that hides only some rows is the documented widening.
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT USING (m.user_id = current_user);",
        // A non-read policy says nothing about reads.
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmd ON m FOR DELETE USING (false);",
        // A barrier bound to named roles leaves everyone outside them whatever the
        // permissive policies grant, so closing the table would refuse those readers what
        // RLS allows. The three-way answer cannot say "closed for these roles only".
        "CREATE POLICY pm ON m FOR SELECT USING (true);\n\
         CREATE POLICY pmr ON m AS RESTRICTIVE FOR SELECT TO contractor USING (false);",
    ] {
        let (select, loads_m, _) = membership_readability(policy);
        if select == "no_access" {
            complaints.push(format!("`{policy}` denied a grant RLS may allow"));
        }
        if !loads_m {
            complaints.push(format!("`{policy}` stopped loading membership rows"));
        }
    }
    assert!(complaints.is_empty(), "{}", complaints.join("\n"));
}

const TEAM_MEMBERS_OPEN: &str = "
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY tm_all ON team_members FOR SELECT USING (true);
";

const TEAM_MEMBERS_GATE: &str = "
CREATE POLICY tm_cap ON team_members AS RESTRICTIVE FOR SELECT USING (
    'team_members:read' = ANY(string_to_array(current_setting('app.bot_list', true), ','))
    OR '*' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
";

fn team_readability(members_rules: &str) -> rls2fga::translator::Outputs {
    let db = db_of(&format!(
        "
CREATE TABLE teams(id INT PRIMARY KEY);
CREATE TABLE team_members(team INT REFERENCES teams(id), user_id TEXT,
                          PRIMARY KEY (team, user_id));
CREATE TABLE docs(id INT PRIMARY KEY, team INT REFERENCES teams(id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
{members_rules}
CREATE POLICY docs_read ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM team_members m
            WHERE m.team = docs.team
              AND m.user_id = current_setting('app.user_id', true)));
"
    ));
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.bot_list", SessionAttributeKind::SetAttribute),
        ])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
}

#[test]
fn a_constant_true_membership_read_policy_is_open() {
    let baseline = team_readability("");
    for command in ["SELECT", "ALL"] {
        for extra in [
            "",
            "CREATE POLICY neutral ON team_members AS RESTRICTIVE FOR SELECT USING (true);",
            "CREATE POLICY write_gate ON team_members AS RESTRICTIVE FOR UPDATE USING (false);",
            "CREATE POLICY write_gate ON team_members AS RESTRICTIVE FOR DELETE USING (false);",
        ] {
            let outputs = team_readability(&format!(
                "ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
                 CREATE POLICY tm_all ON team_members FOR {command} TO PUBLIC USING ((true));
                 {extra}"
            ));
            assert_eq!(
                relation_definition(&outputs.model(), "docs", "can_select"),
                relation_definition(&baseline.model(), "docs", "can_select")
            );
            assert!(
                !outputs
                    .notes()
                    .iter()
                    .any(|note| note.severity().diverges_from_database()),
                "{command} {extra}\n{:#?}",
                outputs.notes()
            );
        }
    }
}

#[test]
fn a_request_gate_that_names_no_row_keeps_the_membership_translated() {
    let outputs = team_readability(&format!("{TEAM_MEMBERS_OPEN}{TEAM_MEMBERS_GATE}"));
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database()),
        "{:#?}",
        outputs.notes()
    );
    assert!(outputs.notes().iter().any(|note| matches!(
        note,
        TranslationNote::CallerSuppliesConditionParameter {
            parameter,
            setting_key: Some(key),
            separator: Some(separator),
        } if parameter == "app_bot_list" && key == "app.bot_list" && separator == ","
    )));
}

#[test]
fn unsupported_membership_read_rules_stay_guarded() {
    for policies in [
        "CREATE POLICY p ON team_members FOR SELECT USING (user_id = current_user);".to_string(),
        "CREATE POLICY p ON team_members FOR SELECT TO contractor USING (true);".to_string(),
        "CREATE POLICY p ON team_members FOR SELECT TO CURRENT_USER USING (true);".to_string(),
        format!(
            "{TEAM_MEMBERS_OPEN}
                 CREATE POLICY p ON team_members FOR SELECT USING (false);"
        ),
        format!(
            "{TEAM_MEMBERS_OPEN}
                 CREATE POLICY p ON team_members FOR SELECT USING (user_id = current_user);"
        ),
        format!(
            "{TEAM_MEMBERS_OPEN}
                 CREATE POLICY p ON team_members AS RESTRICTIVE FOR SELECT
                     USING (user_id = current_user);"
        ),
        format!(
            "{TEAM_MEMBERS_OPEN}
                 CREATE POLICY p ON team_members AS RESTRICTIVE FOR SELECT TO contractor
                     USING ('team_members:read' = ANY(string_to_array(
                         current_setting('app.bot_list', true), ',')));"
        ),
        format!(
            "{TEAM_MEMBERS_OPEN}
                 CREATE POLICY p ON team_members AS RESTRICTIVE FOR SELECT TO CURRENT_USER
                     USING (false);"
        ),
        format!(
            "{TEAM_MEMBERS_OPEN}
                 CREATE POLICY p ON team_members AS RESTRICTIVE FOR SELECT
                     USING ('team_members:read' = ANY(string_to_array(
                         current_setting('app.undeclared', true), ',')));"
        ),
        format!(
            "{TEAM_MEMBERS_OPEN}
                 CREATE POLICY p ON team_members AS RESTRICTIVE FOR SELECT;"
        ),
    ] {
        let outputs = team_readability(&format!(
            "ALTER TABLE team_members ENABLE ROW LEVEL SECURITY; {policies}"
        ));
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::MembershipTableGuarded { join_table, policy }
                    if join_table.name() == "team_members" && policy == "docs_read"
            )),
            "{policies}\n{:#?}",
            outputs.notes()
        );
    }
}

#[test]
fn a_request_gate_without_a_permissive_read_grants_nothing() {
    let outputs = team_readability(&format!(
        "ALTER TABLE team_members ENABLE ROW LEVEL SECURITY; {TEAM_MEMBERS_GATE}"
    ));
    assert!(relation_denies(&outputs.model(), "docs", "can_select"));
    assert!(outputs.notes().iter().any(|note| matches!(
        note,
        TranslationNote::MembershipTableGrantsNoReads { join_table, .. }
            if join_table.name() == "team_members"
    )));
}

/// `PostgreSQL` reads a membership table's children through the policy's plain `FROM`,
/// and the membership tuple query mirrors that read, so it must not gain `ONLY` even
/// while the guarded table's own queries do: the narrowing applies to the rows a type
/// mints objects from, never to the rows a foreign table contributes.
#[test]
fn a_membership_tables_child_rows_still_grant() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE press_docs(embargo TEXT) INHERITS (docs);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
CREATE TABLE super_members(note TEXT) INHERITS (doc_members);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = docs.id AND m.user_id = current_user)
);
";
    let db = db_of(sql);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    let tuples = outputs.tuple_queries();
    assert!(
        !tuples_reading_from(tuples, "FROM \"public\".\"doc_members\"").is_empty(),
        "membership tuples mirror the policy's inheritance-inclusive read, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        tuples_reading_from(tuples, "ONLY \"public\".\"doc_members\"").is_empty(),
        "ONLY on the membership read would deny rows PostgreSQL grants, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        !tuples_reading_from(tuples, "FROM ONLY \"public\".\"docs\"").is_empty(),
        "the guarded table has a child, so its own bridge reads ONLY, got: {:#?}",
        tuples.iter().map(|q| &q.sql).collect::<Vec<_>>()
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::InheritanceParentReadsOwnRowsOnly { table, .. } if table.name() == "docs"
        )),
        "the guarded table narrows and says so, got: {:#?}",
        outputs.notes()
    );
    assert!(
        !outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::InheritanceParentReadsOwnRowsOnly { table, .. }
                if table.name() == "doc_members"
        )),
        "doc_members has no type, so no note names it, got: {:#?}",
        outputs.notes()
    );
}

fn session_attr_plan(sql: &str) -> rls2fga::translator::Outputs {
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )])
        .build();
    let (classified, registry) = translator.classify_with_effective_registry(&db);
    plan_at(classified, &db, &registry, ConfidenceLevel::B)
}

/// The sharing subquery reads its table as the caller, so that table's own rules decide
/// which sharing rows count. A sharing table nobody can read leaves the subquery nothing
/// to find, so the parent grants nobody. Emitting facts from rows the caller cannot see
/// would grant through shares that do not exist for them.
#[test]
fn a_share_table_nobody_can_read_grants_nothing_through_it() {
    let sql = "
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_hidden ON paper_shares FOR SELECT USING (false);
CREATE POLICY papers_shared ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";
    let outputs = session_attr_plan(sql);
    let model = outputs.model();

    assert!(
        model.contains("define can_select: no_access"),
        "a sharing table nobody reads grants nobody:\n{model}"
    );
    assert!(
        !outputs
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains("FROM \"paper_shares\"")),
        "no facts are read from a table the caller cannot see"
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGrantsNoReads { join_table, .. }
                if join_table.name() == "paper_shares"
        )),
        "the reason the grant vanished is named: {:?}",
        outputs.notes()
    );
}

/// A caller-set share becomes one object per share row, keyed on the join table's own
/// primary key, so two viewers of one row do not collide on one object. A join table with
/// no primary key cannot name its rows apart, so the arm refuses and falls closed rather
/// than emit a load `OpenFGA` rejects as a duplicate.
#[test]
fn a_caller_set_membership_over_a_keyless_share_table_falls_closed() {
    let sql = "
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_read ON paper_shares FOR SELECT USING (true);
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";
    let outputs = session_attr_plan(sql);
    let model = outputs.model();

    assert!(
        model.contains("define can_select: no_access"),
        "the share arm is the only grant on papers, so a refusal falls closed:\n{model}"
    );
    assert!(
        !model.contains("paper_shares_share"),
        "no per-share type is minted when the share rows cannot be named apart:\n{model}"
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ExpressionRefused { policy, reason }
                if policy == "papers_p" && reason.contains("no primary key")
        )),
        "the reason the grant vanished is named: {:?}",
        outputs.notes()
    );
}

/// The column of `table` a bridge shape on it reads to name the parent.
fn bridge_subject_column(relations: &[RelationShapes], table: &str) -> Option<String> {
    relations
        .iter()
        .flat_map(|entry| &entry.shapes)
        .find_map(|shape| match &shape.derivation {
            RecordDerivation::FromRow {
                table: from,
                template,
                ..
            } if from.name() == table => match template.subject_key.part() {
                ValueSource::Column(name) => Some(name.to_string()),
                _ => None,
            },
            _ => None,
        })
}

fn correlated_relations(using: &str) -> Vec<RelationShapes> {
    let db = db_of(&format!(
        "{CORRELATION_SCHEMA}
ALTER TABLE line_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON line_items FOR SELECT USING ({using});
"
    ));
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_current_user_setting_keys(["app.user_id"])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .relations()
        .to_vec()
}

/// The membership bridge used to be keyed on the membership table's own column name,
/// which the guarded table may also carry under a different meaning. A row was then
/// granted through a value the policy never compared.
#[test]
fn a_membership_bridge_reads_the_column_the_policy_correlates() {
    let correlates_sku = correlated_relations(
        "sku IN (SELECT status FROM orders \
         WHERE customer_id = current_setting('app.user_id', true))",
    );
    let correlates_status = correlated_relations(
        "status IN (SELECT status FROM orders \
         WHERE customer_id = current_setting('app.user_id', true))",
    );

    assert_eq!(
        bridge_subject_column(&correlates_sku, "line_items").as_deref(),
        Some("sku"),
        "the policy compares line_items.sku, so the bridge reads sku"
    );
    assert_eq!(
        bridge_subject_column(&correlates_status, "line_items").as_deref(),
        Some("status"),
        "the policy compares line_items.status, so the bridge reads status"
    );
}

/// The share type a caller-set membership mints, the body of the gate riding it, and the
/// body of the guarded table's read.
fn share_gate_reach(model: &str, guarded: &str) -> (String, String, String) {
    let share_type = type_names(model)
        .into_iter()
        .find(|name| name.ends_with("_share"))
        .expect("a caller-set membership mints one share type");
    let gate = relation_definitions(model, &share_type)
        .into_iter()
        .find_map(|(name, body)| name.starts_with("gate_").then_some(body))
        .expect("the share type carries the request-completed gate");
    let reach = relation_definition(model, guarded, "can_select")
        .expect("the guarded table reads through the share");
    (share_type, gate, reach)
}

/// A membership row correlated on a column the guarded row shares with its parent is the
/// same membership whichever way the member column names the caller. The identity
/// spelling reaches the row through the parent the foreign key names, so the caller-set
/// spelling has to as well, with the gate riding the share row and the parent linking to
/// it. Refusing it as "not identifying a row" sent the reader to a correct correlation.
#[test]
fn a_caller_set_membership_on_a_parent_key_reaches_the_row_through_its_parent() {
    const SCHEMA: &str = "
CREATE TABLE teams (id INT PRIMARY KEY);
CREATE TABLE team_members (member TEXT NOT NULL, team_id INT REFERENCES teams(id),
                           PRIMARY KEY (team_id, member));
CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL,
                    team_id INT NOT NULL REFERENCES teams(id), label TEXT);
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR SELECT USING (
  EXISTS (SELECT 1 FROM team_members
          WHERE team_members.team_id = items.team_id
            AND team_members.member = ANY(string_to_array(current_setting('app.subjects', true), ','))));
";
    let outputs = session_attr_plan(SCHEMA);
    let model = outputs.model();
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ExpressionRefused { .. })),
        "the correlation is the one the identity spelling accepts: {:?}",
        outputs.notes()
    );

    let (share_type, gate, reach) = share_gate_reach(&model, "items");
    assert_eq!(share_type, "team_members_share");
    assert!(
        gate.contains("[user:* with "),
        "the gate is completed by the request on the share row:\n{model}"
    );
    assert!(
        reach.ends_with(" from teams"),
        "items reaches the share rows through the team the foreign key names:\n{model}"
    );
    assert_eq!(
        relation_definition(&model, "teams", &share_type).as_deref(),
        Some(format!("[{share_type}]").as_str()),
        "the team links to its share rows:\n{model}"
    );

    let queries = outputs.tuple_queries();
    let gate_query = queries
        .iter()
        .find(|query| query.condition.is_some())
        .expect("the gate is a conditional record");
    assert!(
        gate_query.sql.contains("'team_members_share:'") && !gate_query.sql.contains("'items:'"),
        "the gate is keyed on the share row alone:\n{}",
        gate_query.sql
    );
    let bridges = |object: &str, subject: &str| {
        queries.iter().any(|query| {
            query.condition.is_none()
                && query.sql.contains(&format!("'{object}:'"))
                && query.sql.contains(&format!("'{subject}:'"))
        })
    };
    assert!(
        bridges("teams", "team_members_share"),
        "each team links to its share rows"
    );
    assert!(bridges("items", "teams"), "each item links to its team");
}

/// `IN (SELECT unnest(...))` reads the same database as `= ANY(string_to_array(...))`, and
/// the direct comparison already lands both on one pattern, so a membership row compared
/// either way is one membership with one model.
#[test]
fn a_row_valued_set_spelling_is_the_same_membership_as_the_array_valued_one() {
    const SCHEMA: &str = "
CREATE TABLE teams (id INT PRIMARY KEY);
CREATE TABLE team_members (member TEXT NOT NULL, team_id INT REFERENCES teams(id),
                           PRIMARY KEY (team_id, member));
CREATE TABLE items (id INT PRIMARY KEY, team_id INT NOT NULL REFERENCES teams(id));
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR SELECT USING (
  EXISTS (SELECT 1 FROM team_members
          WHERE team_members.team_id = items.team_id
            AND team_members.member ";
    let array_valued = session_attr_plan(&format!(
        "{SCHEMA}= ANY(string_to_array(current_setting('app.subjects', true), ','))));"
    ));
    let row_valued = session_attr_plan(&format!(
        "{SCHEMA}IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ',')))));"
    ));
    assert_eq!(
        row_valued.model(),
        array_valued.model(),
        "one database, one model"
    );
    assert_eq!(
        format_tuples(row_valued.tuple_queries()),
        format_tuples(array_valued.tuple_queries()),
        "one database, one set of facts"
    );
}

/// The row-valued spelling is read only where the subquery is nothing but the set: a
/// negation reverses the grant, and a `FROM` or a filter could drop members the model
/// would still count, so each stays off the membership and falls closed.
#[test]
fn a_row_valued_set_spelling_is_refused_when_it_is_not_the_bare_set() {
    const SCHEMA: &str = "
CREATE TABLE teams (id INT PRIMARY KEY);
CREATE TABLE team_members (member TEXT NOT NULL, team_id INT REFERENCES teams(id),
                           PRIMARY KEY (team_id, member));
CREATE TABLE items (id INT PRIMARY KEY, team_id INT NOT NULL REFERENCES teams(id));
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR SELECT USING (
  EXISTS (SELECT 1 FROM team_members
          WHERE team_members.team_id = items.team_id
            AND team_members.member ";
    for (label, comparison) in [
        (
            "negated",
            "NOT IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ',')))",
        ),
        (
            "read from a FROM",
            "IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ',')) FROM generate_series(1, 1))",
        ),
        (
            "filtered",
            "IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ',')) WHERE false)",
        ),
    ] {
        let outputs = session_attr_plan(&format!("{SCHEMA}{comparison}));"));
        let model = outputs.model();
        assert!(
            !model.contains("_share"),
            "{label}: no share type may be minted for a subquery that is not the bare set:\n{model}"
        );
        assert!(
            relation_denies(&model, "items", "can_select"),
            "{label}: the shape falls closed:\n{model}"
        );
    }
}

/// Two comparisons naming the caller in one membership row are two conditions the
/// database requires together. A membership carries one member column, so the shape
/// falls closed rather than keeping the last comparison and granting on it alone.
#[test]
fn a_membership_row_compared_to_the_caller_twice_falls_closed() {
    const SCHEMA: &str = "
CREATE TABLE teams (id INT PRIMARY KEY);
CREATE TABLE team_members (member TEXT NOT NULL, role TEXT NOT NULL,
                           team_id INT REFERENCES teams(id), PRIMARY KEY (team_id, member));
CREATE TABLE items (id INT PRIMARY KEY, team_id INT NOT NULL REFERENCES teams(id));
ALTER TABLE items ENABLE ROW LEVEL SECURITY;
";
    for (label, using) in [
        (
            "a person and a key",
            "EXISTS (SELECT 1 FROM team_members
               WHERE team_members.team_id = items.team_id
                 AND team_members.member = current_setting('app.user_id', true)
                 AND team_members.role = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
        ),
        (
            "a person twice",
            "EXISTS (SELECT 1 FROM team_members
               WHERE team_members.team_id = items.team_id
                 AND team_members.member = current_setting('app.user_id', true)
                 AND team_members.role = current_setting('app.user_id', true))",
        ),
        (
            "a person in the join and a key in the filter",
            "items.team_id IN (SELECT tm.team_id FROM team_members tm
               JOIN teams t ON t.id = tm.team_id AND tm.member = current_setting('app.user_id', true)
               WHERE tm.role = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
        ),
    ] {
        let db = db_of(&format!(
            "{SCHEMA}CREATE POLICY items_p ON items FOR SELECT USING ({using});"
        ));
        let outputs = TranslatorBuilder::new()
            .with_min_confidence(ConfidenceLevel::B)
            .with_session_attributes([
                SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
                SessionAttribute::setting("app.subjects", SessionAttributeKind::SetAttribute),
            ])
            .build()
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps();
        assert!(
            relation_denies(&outputs.model(), "items", "can_select"),
            "{label}: neither comparison alone is the policy, so the shape falls closed:\n{}",
            outputs.model()
        );
    }
}

/// A correlation on a column that is no key of either table groups the guarded rows by
/// the value they share, which is the parent the identity spelling already reaches them
/// through. The caller-set spelling takes the same route.
#[test]
fn a_request_gate_correlated_on_a_non_key_column_groups_rows_by_the_shared_value() {
    let outputs = session_attr_plan(
        "CREATE TABLE papers(id INT PRIMARY KEY, batch TEXT);
CREATE TABLE shares(id INT PRIMARY KEY, paper_batch TEXT, viewer TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (EXISTS (
  SELECT 1 FROM shares s WHERE s.paper_batch = papers.batch
    AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
    );
    let model = outputs.model();
    let (share_type, _, reach) = share_gate_reach(&model, "papers");
    assert_eq!(share_type, "shares_share");
    assert!(
        reach.ends_with(" from paper_batch"),
        "papers reach their shares through the batch they share:\n{model}"
    );
    assert!(
        outputs.tuple_queries().iter().any(|query| {
            query.condition.is_none()
                && query.sql.contains("'papers:'")
                && query.sql.contains("'paper_batch:'")
                && query.sql.contains("\"batch\"")
        }),
        "the bridge reads the column the policy correlates"
    );
}

/// A share joined on every column of a composite key names the guarded row whole, so the
/// bridge from the row to its share rows reads both columns.
#[test]
fn a_request_gate_bridged_on_a_composite_key_reads_the_whole_key() {
    let outputs = session_attr_plan(
        "CREATE TABLE papers(tenant_id INT NOT NULL, id INT NOT NULL, PRIMARY KEY(tenant_id, id));
CREATE TABLE shares(tenant_id INT NOT NULL, paper_id INT NOT NULL, viewer TEXT NOT NULL,
    PRIMARY KEY(tenant_id, paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (EXISTS (
  SELECT 1 FROM shares s WHERE s.tenant_id = papers.tenant_id AND s.paper_id = papers.id
    AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
    );
    let model = outputs.model();
    let (share_type, _, reach) = share_gate_reach(&model, "papers");
    assert!(
        reach.ends_with(&format!(" from {share_type}")),
        "the guarded row reaches its share rows directly:\n{model}"
    );
    let bridge = outputs
        .tuple_queries()
        .iter()
        .find(|query| {
            query.condition.is_none()
                && query.sql.contains("'papers:'")
                && query.sql.contains("'shares_share:'")
        })
        .expect("a bridge links each paper to its share rows");
    assert!(
        bridge.sql.contains("\"tenant_id\"") && bridge.sql.contains("\"paper_id\""),
        "the bridge names the paper by both columns of its key:\n{}",
        bridge.sql
    );
}

/// Two `role_threshold` functions with their own grant table and their own
/// `team_membership` table must not pool their team rows into one `team` type:
/// membership under one function's table must not carry the other's grants.
#[test]
fn distinct_team_membership_tables_do_not_share_a_team_type() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE teams(id UUID PRIMARY KEY);
CREATE TABLE team_members_a(team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id), PRIMARY KEY(team_id, user_id));
CREATE TABLE team_members_b(team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id), PRIMARY KEY(team_id, user_id));
CREATE TABLE owner_grants_a(grantee_owner_id UUID NOT NULL, granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL);
CREATE TABLE owner_grants_b(grantee_owner_id UUID NOT NULL, granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL);
CREATE TABLE docs_a(id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE TABLE docs_b(id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
    LANGUAGE sql STABLE AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_role_a(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE AS '
    SELECT COALESCE(MAX(role), 0) FROM (
        SELECT og.role_id AS role FROM owner_grants_a og
        WHERE og.granted_owner_id = target_owner_id
        AND (og.grantee_owner_id = user_uuid OR og.grantee_owner_id IN (
            SELECT tm.team_id FROM team_members_a tm WHERE tm.user_id = user_uuid))
    ) sub';
CREATE FUNCTION get_role_b(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE AS '
    SELECT COALESCE(MAX(role), 0) FROM (
        SELECT og.role_id AS role FROM owner_grants_b og
        WHERE og.granted_owner_id = target_owner_id
        AND (og.grantee_owner_id = user_uuid OR og.grantee_owner_id IN (
            SELECT tm.team_id FROM team_members_b tm WHERE tm.user_id = user_uuid))
    ) sub';
ALTER TABLE docs_a ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs_b ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_a_select ON docs_a FOR SELECT TO PUBLIC
    USING (get_role_a(auth_current_user_id(), owner_id) >= 2);
CREATE POLICY docs_b_select ON docs_b FOR SELECT TO PUBLIC
    USING (get_role_b(auth_current_user_id(), owner_id) >= 2);
";
    let registry_json = r#"{
      "get_role_a": {
        "kind": "role_threshold", "user_param_index": 0, "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
        "grant_table": "owner_grants_a", "grant_grantee_col": "grantee_owner_id",
        "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id",
        "team_membership": {"table": "team_members_a", "user_col": "user_id", "team_col": "team_id"}
      },
      "get_role_b": {
        "kind": "role_threshold", "user_param_index": 0, "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
        "grant_table": "owner_grants_b", "grant_grantee_col": "grantee_owner_id",
        "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id",
        "team_membership": {"table": "team_members_b", "user_col": "user_id", "team_col": "team_id"}
      },
      "auth_current_user_id": {"kind": "current_user_accessor", "returns": "uuid"}
    }"#;
    let (classified, db, registry) = classify_sql(sql, Some(registry_json));
    let model = plan_at(classified, &db, &registry, ConfidenceLevel::A);
    let dsl = model.model();
    let team_types: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| name.contains("team"))
        .collect();
    assert_eq!(
        team_types.len(),
        2,
        "team_members_a and team_members_b name different rows, so get_role_a and \
         get_role_b must not pool them into one team type, got {team_types:?}:\n{dsl}"
    );
    assert_ne!(
        team_types[0], team_types[1],
        "two distinct team_membership tables must mint two distinct team types:\n{dsl}"
    );
}

/// Two `role_threshold` functions that share the very same `team_membership` table must
/// still pool it into one team type: splitting a legitimately shared source would lose
/// the sharing the schema actually declares.
#[test]
fn the_same_team_membership_table_across_two_functions_shares_one_team_type() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE teams(id UUID PRIMARY KEY);
CREATE TABLE team_members(team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id), PRIMARY KEY(team_id, user_id));
CREATE TABLE owner_grants_a(grantee_owner_id UUID NOT NULL, granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL);
CREATE TABLE owner_grants_b(grantee_owner_id UUID NOT NULL, granted_owner_id UUID NOT NULL,
    role_id INTEGER NOT NULL);
CREATE TABLE docs_a(id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE TABLE docs_b(id UUID PRIMARY KEY, owner_id UUID NOT NULL);
CREATE FUNCTION auth_current_user_id() RETURNS UUID
    LANGUAGE sql STABLE AS 'SELECT current_setting(''app.current_user_id'')::uuid';
CREATE FUNCTION get_role_a(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE AS '
    SELECT COALESCE(MAX(role), 0) FROM (
        SELECT og.role_id AS role FROM owner_grants_a og
        WHERE og.granted_owner_id = target_owner_id
        AND (og.grantee_owner_id = user_uuid OR og.grantee_owner_id IN (
            SELECT tm.team_id FROM team_members tm WHERE tm.user_id = user_uuid))
    ) sub';
CREATE FUNCTION get_role_b(user_uuid UUID, target_owner_id UUID) RETURNS INTEGER
    LANGUAGE sql STABLE AS '
    SELECT COALESCE(MAX(role), 0) FROM (
        SELECT og.role_id AS role FROM owner_grants_b og
        WHERE og.granted_owner_id = target_owner_id
        AND (og.grantee_owner_id = user_uuid OR og.grantee_owner_id IN (
            SELECT tm.team_id FROM team_members tm WHERE tm.user_id = user_uuid))
    ) sub';
ALTER TABLE docs_a ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs_b ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_a_select ON docs_a FOR SELECT TO PUBLIC
    USING (get_role_a(auth_current_user_id(), owner_id) >= 2);
CREATE POLICY docs_b_select ON docs_b FOR SELECT TO PUBLIC
    USING (get_role_b(auth_current_user_id(), owner_id) >= 2);
";
    let registry_json = r#"{
      "get_role_a": {
        "kind": "role_threshold", "user_param_index": 0, "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
        "grant_table": "owner_grants_a", "grant_grantee_col": "grantee_owner_id",
        "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id",
        "team_membership": {"table": "team_members", "user_col": "user_id", "team_col": "team_id"}
      },
      "get_role_b": {
        "kind": "role_threshold", "user_param_index": 0, "resource_param_index": 1,
        "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
        "grant_table": "owner_grants_b", "grant_grantee_col": "grantee_owner_id",
        "grant_resource_col": "granted_owner_id", "grant_role_col": "role_id",
        "team_membership": {"table": "team_members", "user_col": "user_id", "team_col": "team_id"}
      },
      "auth_current_user_id": {"kind": "current_user_accessor", "returns": "uuid"}
    }"#;
    let (classified, db, registry) = classify_sql(sql, Some(registry_json));
    let model = plan_at(classified, &db, &registry, ConfidenceLevel::A);
    let dsl = model.model();
    let team_types: Vec<String> = type_names(&dsl)
        .into_iter()
        .filter(|name| name.contains("team"))
        .collect();
    assert_eq!(
        team_types.len(),
        1,
        "both functions name the same team_members table, so they must share one \
         team type, got {team_types:?}:\n{dsl}"
    );
}

/// Two `ACL` tables gating two different privileges on one guarded table must not share a
/// member relation, so membership in either table must not grant the other's privilege.
#[test]
fn distinct_acl_tables_do_not_share_a_member_relation() {
    let db = db_of(
        r"
CREATE TABLE principals(id UUID PRIMARY KEY);
CREATE TABLE resources(id UUID PRIMARY KEY);
CREATE TABLE read_acl(resource_id UUID REFERENCES resources(id), user_id UUID REFERENCES principals(id));
CREATE TABLE delete_acl(resource_id UUID REFERENCES resources(id), user_id UUID REFERENCES principals(id));
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
CREATE POLICY resources_read ON resources FOR SELECT USING (
  EXISTS (SELECT 1 FROM read_acl m WHERE m.resource_id = resources.id AND m.user_id = current_user));
CREATE POLICY resources_delete ON resources FOR DELETE USING (
  EXISTS (SELECT 1 FROM delete_acl m WHERE m.resource_id = resources.id AND m.user_id = current_user));
",
    );
    let translator = translator(ConfidenceLevel::A);
    let dsl = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let select = relation_definition(&dsl, "resources", "can_select")
        .expect("resources should define can_select");
    let delete = relation_definition(&dsl, "resources", "can_delete")
        .expect("resources should define can_delete");
    assert_ne!(
        select, delete,
        "read_acl and delete_acl name different rows, so can_select and \
         can_delete must not share the member relation:\n{dsl}"
    );
}

/// A `P4` witness membership and a `P18` caller-set gate resolving to the same parent
/// type through different columns of one join table must not share a link relation.
#[test]
fn a_witness_link_and_a_caller_set_gate_do_not_share_a_tupleset() {
    let db = db_of(
        r"
CREATE TABLE principals(id TEXT PRIMARY KEY);
CREATE TABLE owners(id TEXT PRIMARY KEY);
CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
CREATE TABLE projects(id TEXT PRIMARY KEY, owner_id TEXT REFERENCES owners(id));
CREATE TABLE memberships(
    id TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES owners(id),
    lead_id TEXT NOT NULL REFERENCES owners(id),
    user_id TEXT NOT NULL REFERENCES principals(id),
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM memberships m WHERE m.owner_id = docs.owner_id
    AND m.user_id = current_setting('app.user_id', true) AND m.expires_at > now()));
CREATE POLICY projects_select ON projects FOR SELECT USING (
  EXISTS (SELECT 1 FROM memberships m WHERE m.lead_id = projects.owner_id
    AND m.user_id = ANY(string_to_array(current_setting('app.subjects', true), ','))));
",
    );
    let dsl = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::A)
        .with_session_attributes([
            SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId),
            SessionAttribute::setting("app.subjects", SessionAttributeKind::SetAttribute),
        ])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let share_links: Vec<_> = relation_definitions(&dsl, "owners")
        .into_iter()
        .filter(|(_, body)| body.starts_with('[') && body.contains("_share"))
        .collect();
    assert_eq!(
        share_links.len(),
        2,
        "docs reaches the owner through owner_id and projects through lead_id, two \
         different memberships columns, so owners should define two separate share \
         links, got {share_links:?}:\n{dsl}"
    );
}

/// A plain read and a temporally-gated read of the same join table through the same
/// foreign key and user column must not pool. The plain source's unconditional subject
/// would otherwise let the gated relation's policy grant access past its own deadline.
#[test]
fn a_plain_and_a_gated_read_of_the_same_join_table_do_not_share_a_relation() {
    let db = db_of(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE members(doc_id UUID REFERENCES docs(id), user_id TEXT, expires_at TIMESTAMPTZ,
    PRIMARY KEY(doc_id, user_id));
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_select ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM members m WHERE m.doc_id = docs.id
    AND m.user_id = current_setting('app.user_id', true)));
CREATE POLICY docs_delete ON docs FOR DELETE USING (
  EXISTS (SELECT 1 FROM members m WHERE m.doc_id = docs.id
    AND m.user_id = current_setting('app.user_id', true) AND m.expires_at > now()));
",
    );
    let dsl = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::A)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build()
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    let member_bodies: Vec<(String, String)> = relation_definitions(&dsl, "docs")
        .into_iter()
        .filter(|(_, body)| body.starts_with("[user"))
        .collect();
    assert_eq!(
        member_bodies.len(),
        2,
        "the plain policy and the gated policy read members through the same join \
         table and column, so docs should still define two separate member relations, \
         got {member_bodies:?}:\n{dsl}"
    );
    assert!(
        member_bodies.iter().any(|(_, body)| body == "[user]"),
        "the plain source's relation must hold only the unconditional subject, \
         got {member_bodies:?}:\n{dsl}"
    );
    assert!(
        member_bodies
            .iter()
            .any(|(_, body)| body.starts_with("[user with ") && !body.contains(", user]")),
        "the gated source's relation must hold only the conditional subject, not the \
         plain source's unconditional one, got {member_bodies:?}:\n{dsl}"
    );
}
