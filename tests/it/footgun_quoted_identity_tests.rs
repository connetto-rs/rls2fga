//! Regression tests for the family of comparisons that read two distinct `PostgreSQL`
//! identifiers as one.
//!
//! `PostgreSQL` folds an unquoted identifier to lower case and keeps a quoted one exactly,
//! so `"M"` and `m` name two different things. Every comparison that lowercases and strips
//! quotes before deciding what a name denotes belongs here, whichever stage it sits in.

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::{
    ExistsMembership, ExpandedFunction, PatternClass, UnclassifiedExpr, UncorrelatedMembership,
};
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

use crate::support::deployment::caller_deployment;
use crate::support::footgun::{db_of, relation_definition, translator};

/// The classification of the only policy's `USING` clause.
fn using_pattern(sql: &str) -> PatternClass {
    let db = db_of(sql);
    let classified = translator(ConfidenceLevel::B).classify(&db);
    let [policy] = classified.as_slice() else {
        panic!(
            "expected exactly one classified policy, got {}",
            classified.len()
        );
    };
    policy
        .using_classification()
        .expect("USING should classify")
        .pattern
        .clone()
}

/// The model and the tuple SQL at the default bar.
fn outputs_of(sql: &str) -> (String, String) {
    let db = db_of(sql);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    (outputs.model(), format_tuples(outputs.tuple_queries()))
}

/// Every query that projects `relation` as its relation column.
fn queries_feeding(tuples: &str, relation: &str) -> Vec<String> {
    tuples
        .split(";\n")
        .filter(|query| query.contains(&format!("'{relation}' AS relation")))
        .map(str::to_string)
        .collect()
}

fn confidence_for_public_flag(registered: &str) -> ConfidenceLevel {
    let sql = r#"
CREATE TABLE public.docs (id TEXT PRIMARY KEY, "Public" BOOLEAN NOT NULL);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT USING ("Public" = TRUE);
"#;
    let db = db_of(sql);
    let mut registry = FunctionRegistry::new();
    registry.register_public_flag_column(registered);
    let classified = TranslatorBuilder::new(caller_deployment())
        .with_registry(registry)
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .classify(&db);
    classified[0]
        .using_classification()
        .expect("USING should classify")
        .confidence
}

/// A guarded table quoted so its stored name differs from the alias only by case, beside a
/// membership table sharing the caller column's name.
const QUOTED_GUARD_WITH_ALIAS: &str = r#"
CREATE TABLE public."M" (id TEXT PRIMARY KEY, owner_id NAME NOT NULL);
CREATE TABLE public.members (
    doc_id TEXT NOT NULL REFERENCES public."M"(id),
    owner_id NAME NOT NULL
);
ALTER TABLE public."M" ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public."M" FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM public.members AS m
        WHERE m.doc_id = "M".id
          AND "M".owner_id = current_setting('app.user_id', true)
    )
);
"#;

/// The qualifier `"M"` names the guarded row, never the alias `m`, so the guarded table's
/// own owner column must not become the membership row's subject column.
///
/// `PostgreSQL` grants only the caller who owns the document. Reading `"M".owner_id` as
/// `m.owner_id` turns every membership row into a grant for whoever it names.
#[test]
fn a_quoted_guard_qualifier_is_not_the_membership_alias() {
    let pattern = using_pattern(QUOTED_GUARD_WITH_ALIAS);
    if let PatternClass::P4ExistsMembership(ExistsMembership {
        join_table,
        user_column,
        ..
    }) = &pattern
    {
        assert!(
            !(join_table.name() == "members" && user_column == "owner_id"),
            "the guarded row's owner column became the membership subject: {pattern:?}"
        );
    }
}

/// The same clause at the tuple level: no query may name a subject read from the
/// membership table, because no column of it names the caller.
#[test]
fn a_quoted_guard_qualifier_emits_no_membership_subject() {
    let (_, tuples) = outputs_of(QUOTED_GUARD_WITH_ALIAS);
    let member_queries = queries_feeding(&tuples, "member");
    assert!(
        member_queries.is_empty(),
        "no membership row names the caller, so nothing may feed `member`:\n{}",
        member_queries.join("\n")
    );
}

/// A subquery reading a table whose quoted name merely folds to the guarded table's name
/// is reading another table, so it stays a translatable membership.
///
/// The refusal exists for a policy that reads its own table, which `PostgreSQL` refuses to
/// plan. Two different tables are not that case.
#[test]
fn a_differently_quoted_table_is_not_a_self_scan() {
    let dsl = outputs_of(
        r#"
CREATE TABLE public."M" (id TEXT PRIMARY KEY);
CREATE TABLE public.m (doc_id TEXT NOT NULL REFERENCES public."M"(id), user_id NAME NOT NULL);
ALTER TABLE public."M" ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public."M" FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.m WHERE public.m.doc_id = "M".id AND public.m.user_id = current_setting('app.user_id', true))
);
"#,
    )
    .0;
    let can_select = relation_definition(&dsl, "m", "can_select")
        .unwrap_or_else(|| panic!("the guarded type should define can_select:\n{dsl}"));
    assert_ne!(
        can_select, "no_access",
        "reading a different table is a membership, not policy self-recursion:\n{dsl}"
    );
}

/// A subquery reading the guarded table under an unquoted spelling that folds to it is a
/// self scan, and must keep refusing.
#[test]
fn an_unquoted_spelling_of_the_guarded_table_still_refuses() {
    let pattern = using_pattern(
        r"
CREATE TABLE public.docs (id TEXT PRIMARY KEY, owner_id NAME NOT NULL);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.DOCS d WHERE d.id = docs.id AND d.owner_id = current_setting('app.user_id', true))
);
",
    );
    assert!(
        matches!(pattern, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "a policy reading its own table cannot be planned by PostgreSQL: {pattern:?}"
    );
}

/// A second source whose quoted name folds to the join table's name is still a second
/// table, so its conditions cannot be dropped.
///
/// Treating the two as one table hides the join, and the membership relation then admits
/// rows the third table never joined.
#[test]
fn a_differently_quoted_second_source_is_a_foreign_table() {
    let (dsl, tuples) = outputs_of(
        r#"
CREATE TABLE public.docs (id TEXT PRIMARY KEY);
CREATE TABLE public.m (doc_id TEXT NOT NULL REFERENCES public.docs(id), user_id NAME NOT NULL);
CREATE TABLE public."M" (user_id NAME NOT NULL, allowed BOOLEAN NOT NULL);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM public.m, public."M" AS gate
        WHERE public.m.doc_id = docs.id
          AND public.m.user_id = current_setting('app.user_id', true)
          AND gate.user_id = public.m.user_id
          AND gate.allowed
    )
);
"#,
    );
    let member_queries = queries_feeding(&tuples, "member");
    assert!(
        member_queries.is_empty(),
        "the gate table's condition cannot be expressed by one membership relation, so \
         nothing may be loaded:\n{dsl}\n{}",
        member_queries.join("\n")
    );
}

/// A function body aliasing its scan with the guarded table's quoted name claims that
/// qualifier, so the substituted column cannot be spelled and the call must refuse.
///
/// Expanding it lets the body capture the argument, and the membership then admits every
/// row of the guarded table at once.
#[test]
fn a_body_alias_matching_the_guarded_table_refuses_the_capture() {
    let pattern = using_pattern(
        r#"
CREATE TABLE public."M" (id TEXT PRIMARY KEY);
CREATE TABLE public.doc_members (id TEXT PRIMARY KEY, doc_id TEXT NOT NULL, user_id NAME NOT NULL);
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members AS "M" WHERE "M".doc_id = d AND "M".user_id = current_setting(''app.user_id'', true))';
ALTER TABLE public."M" ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public."M" FOR SELECT USING (public.is_member(id));
"#,
    );
    let captured = matches!(
        &pattern,
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("captured")
    );
    let uncorrelated = matches!(
        &pattern,
        PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
            if matches!(&inner.pattern, PatternClass::P13UncorrelatedMembership(_))
    );
    assert!(
        !uncorrelated,
        "a captured substitution grants every row of the guarded table: {pattern:?}"
    );
    assert!(
        captured,
        "an unspellable outer reference must fall closed: {pattern:?}"
    );
}

/// A body alias that does not match the guarded table's stored name still expands, so the
/// capture guard cannot become a blanket refusal.
#[test]
fn a_body_alias_unlike_the_guarded_table_still_expands() {
    let pattern = using_pattern(
        r#"
CREATE TABLE public."M" (id TEXT PRIMARY KEY);
CREATE TABLE public.doc_members (id TEXT PRIMARY KEY, doc_id TEXT NOT NULL, user_id NAME NOT NULL);
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members AS dm WHERE dm.doc_id = d AND dm.user_id = current_setting(''app.user_id'', true))';
ALTER TABLE public."M" ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public."M" FOR SELECT USING (public.is_member(id));
"#,
    );
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(&inner.pattern, PatternClass::P4ExistsMembership(_))
        ),
        "a body naming no relation like the guarded table expands: {pattern:?}"
    );
}

/// A qualifier naming neither the guarded table nor the membership alias is a third
/// scope, and reading it as the membership row would drop the correlation.
#[test]
fn an_unrelated_quoted_qualifier_is_not_the_membership_alias() {
    let pattern = using_pattern(
        r#"
CREATE TABLE public.docs (id TEXT PRIMARY KEY);
CREATE TABLE public.dm (doc_id TEXT NOT NULL REFERENCES public.docs(id), user_id NAME NOT NULL);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.dm AS "DM" WHERE "DM".doc_id = docs.id AND dm.user_id = current_setting('app.user_id', true))
);
"#,
    );
    if let PatternClass::P4ExistsMembership(ExistsMembership { user_column, .. }) = &pattern {
        panic!("`dm` does not name the aliased scan, so nothing proves the caller column: {user_column:?}");
    }
    if let PatternClass::P13UncorrelatedMembership(UncorrelatedMembership { .. }) = &pattern {
        panic!("an uncorrelated grant admits every row: {pattern:?}");
    }
}

/// A confirmed public-flag column is confirmed by its exact stored name, since what the
/// confirmation buys is a wildcard grant.
#[test]
fn a_public_flag_confirmation_keeps_quoted_identity() {
    assert_ne!(
        confidence_for_public_flag("public"),
        ConfidenceLevel::A,
        "confirming `public` says nothing about the column `\"Public\"`"
    );
}

/// The exact spelling still confirms, so the fix cannot make confirmation unreachable.
#[test]
fn a_public_flag_confirmation_still_matches_its_own_spelling() {
    assert_eq!(
        confidence_for_public_flag("\"Public\""),
        ConfidenceLevel::A,
        "the column's own stored name confirms it"
    );
}

/// Two functions whose names differ only by quoting are two functions, so one cannot
/// occupy the other's place on the expansion stack.
#[test]
fn two_functions_differing_only_by_quoting_both_expand() {
    let pattern = using_pattern(
        r#"
CREATE TABLE public.docs (id TEXT PRIMARY KEY);
CREATE TABLE public.doc_members (doc_id TEXT NOT NULL, user_id NAME NOT NULL);
CREATE FUNCTION public."IS_MEMBER"(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members dm WHERE dm.doc_id = d AND dm.user_id = current_setting(''app.user_id'', true))';
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT public."IS_MEMBER"(d)';
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT USING (public.is_member(id));
"#,
    );
    assert!(
        matches!(&pattern, PatternClass::ExpandedFunction(_)),
        "a call to a distinct function is not a cycle: {pattern:?}"
    );
}
