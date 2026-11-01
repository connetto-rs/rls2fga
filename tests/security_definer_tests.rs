//! A policy calling a single-expression `LANGUAGE sql` function expands to the
//! function body, so the documented workaround for policy self-recursion
//! translates from the dump alone. Every guard refuses by falling closed.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::patterns::{
    ExistsMembership, ExpandedFunction, PatternClass, UnclassifiedExpr,
};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{NoteSeverity, TranslationNote};

mod support;

use support::footgun::{db_of, relation_denies};

/// The bodies compare `uuid` members with the caller cast to `uuid`, which the
/// deployment declares canonical.
fn translator(min_confidence: ConfidenceLevel) -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(min_confidence)
        .with_session_attributes([SessionAttribute::setting(
            "app.current_user_id",
            SessionAttributeKind::CallerId,
        )
        .with_identity_cast("uuid")])
        .build()
}

/// The classified USING pattern of the one policy on `docs`.
fn docs_using_pattern(sql: &str) -> PatternClass {
    let db = db_of(sql);
    let classified = translator(ConfidenceLevel::B).classify(&db);
    let policy = classified
        .iter()
        .find(|policy| matches!(policy.table_name(), "docs" | "public.docs"))
        .expect("docs policy should classify");
    policy
        .using_classification()
        .expect("USING should classify")
        .pattern
        .clone()
}

/// The refusal reason when the `docs` policy falls closed.
fn docs_refusal_reason(sql: &str) -> String {
    match docs_using_pattern(sql) {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn docs_tuple_sql(sql: &str) -> String {
    let db = db_of(sql);
    translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn strict_true_schema(policy_expr: &str) -> String {
    format!(
        "
CREATE TABLE public.docs(id TEXT PRIMARY KEY, gate TEXT, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION strict_true(value TEXT) RETURNS BOOLEAN LANGUAGE sql STRICT AS
'SELECT true';
CREATE POLICY docs_sel ON docs FOR SELECT USING ({policy_expr});
"
    )
}

/// Probe A's idiom: a definer wrapper around a membership EXISTS, owner unmoved.
const DEFINER_MEMBERSHIP: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";

/// Probe A with the membership table's own policy calling the definer with its `doc_id`.
const SELF_REFERENTIAL_DEFINER_MEMBERSHIP: &str = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID REFERENCES docs(id), user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
CREATE POLICY members_self ON doc_members FOR SELECT USING (is_member(doc_id));
";

#[test]
fn a_definer_wrapped_membership_expands_to_the_body_membership() {
    let pattern = docs_using_pattern(DEFINER_MEMBERSHIP);
    let PatternClass::ExpandedFunction(ExpandedFunction {
        function,
        reads_bypass_rls,
        presence_columns,
        inner,
    }) = pattern
    else {
        panic!("expected an expanded call, got {pattern:?}");
    };
    assert_eq!(function, "is_member");
    assert!(
        reads_bypass_rls,
        "the one schema principal owns both the function and the read table"
    );
    assert_eq!(presence_columns, Vec::<rls2fga::types::ColumnName>::new());
    assert!(
        matches!(
            &inner.pattern,
            PatternClass::P4ExistsMembership(ExistsMembership { join_table, pairs, .. })
                if join_table.schema().is_none() && join_table.name() == "doc_members"
                    && matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id")
        ),
        "the body should classify as the membership it wraps, got {:?}",
        inner.pattern
    );
}

#[test]
fn an_expanded_policy_carries_a_faithful_note_naming_the_function() {
    let db = db_of(DEFINER_MEMBERSHIP);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let note = translation
        .notes()
        .iter()
        .find(|note| matches!(note, TranslationNote::FunctionExpanded { .. }))
        .expect("an expanded policy should disclose the expansion");
    assert_eq!(note.severity(), NoteSeverity::Faithful);
    let TranslationNote::FunctionExpanded { policy, function } = note else {
        unreachable!()
    };
    assert_eq!(policy, "docs_sel");
    assert_eq!(function, "is_member");
}

/// The definer bypass is what distinguishes probe C2 from C1: the caller cannot
/// read the membership table at all, and the rows still count.
#[test]
fn a_definer_bypass_grants_through_an_unreadable_membership_table() {
    let db = db_of(DEFINER_MEMBERSHIP);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    assert!(
        !translation.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGrantsNoReads { .. }
                | TranslationNote::MembershipTableGuarded { .. }
        )),
        "a provably bypassed read is not the caller's readability question: {:?}",
        translation.notes()
    );
    let dsl = translation.outputs_accepting_gaps().model();
    assert!(
        !relation_denies(&dsl, "docs", "can_select"),
        "the definer read bypasses the membership policies:\n{dsl}"
    );
}

/// The same body as `SECURITY INVOKER` runs as the caller, so the membership
/// table's own emptiness of read grants denies, exactly as an inline EXISTS.
#[test]
fn an_invoker_wrapper_keeps_the_caller_side_readability_question() {
    let sql = DEFINER_MEMBERSHIP.replace("SECURITY DEFINER", "SECURITY INVOKER");
    let db = db_of(&sql);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    assert!(
        translation
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::MembershipTableGrantsNoReads { .. })),
        "an invoker read is the caller's, and the caller reads nothing: {:?}",
        translation.notes()
    );
    let dsl = translation.outputs_accepting_gaps().model();
    assert!(
        relation_denies(&dsl, "docs", "can_select"),
        "no membership row is visible to any caller:\n{dsl}"
    );
}

#[test]
fn force_row_level_security_on_the_read_table_refuses() {
    let sql = format!("{DEFINER_MEMBERSHIP}ALTER TABLE doc_members FORCE ROW LEVEL SECURITY;");
    let reason = docs_refusal_reason(&sql);
    assert!(
        reason.contains("FORCE ROW LEVEL SECURITY"),
        "probe B raises at runtime, so the shape refuses: {reason}"
    );
}

#[test]
fn a_split_function_owner_refuses() {
    let sql = format!(
        "CREATE ROLE third_role;\n{DEFINER_MEMBERSHIP}\
         ALTER FUNCTION is_member(UUID) OWNER TO third_role;"
    );
    let reason = docs_refusal_reason(&sql);
    assert!(
        reason.contains("is_member") && reason.contains("third_role"),
        "probe C1 filters the definer's read by policies the schema cannot answer: {reason}"
    );
}

#[test]
fn quoted_and_unquoted_definer_owners_are_distinct() {
    let split = format!(
        "CREATE ROLE actor;\nCREATE ROLE \"Actor\";\n{DEFINER_MEMBERSHIP}\
         ALTER TABLE doc_members OWNER TO actor;\
         ALTER FUNCTION is_member(UUID) OWNER TO \"Actor\";"
    );
    assert!(docs_refusal_reason(&split).contains("Actor"));

    let exact = format!(
        "CREATE ROLE actor;\n{DEFINER_MEMBERSHIP}\
         ALTER TABLE doc_members OWNER TO actor;\
         ALTER FUNCTION is_member(UUID) OWNER TO actor;"
    );
    assert!(matches!(
        docs_using_pattern(&exact),
        PatternClass::ExpandedFunction(ExpandedFunction {
            reads_bypass_rls: true,
            ..
        })
    ));
}

#[test]
fn bypassrls_lookup_uses_exact_role_identity() {
    let sql = format!(
        "CREATE ROLE \"Actor\" BYPASSRLS;\nCREATE ROLE actor;\nCREATE ROLE table_owner;\
         \n{DEFINER_MEMBERSHIP}\
         ALTER TABLE doc_members OWNER TO table_owner;\
         ALTER FUNCTION is_member(UUID) OWNER TO actor;"
    );
    assert!(docs_refusal_reason(&sql).contains("actor"));
}

#[test]
fn a_bypassrls_function_owner_expands() {
    let sql = format!(
        "CREATE ROLE svc BYPASSRLS;\n{DEFINER_MEMBERSHIP}\
         ALTER FUNCTION is_member(UUID) OWNER TO svc;"
    );
    let pattern = docs_using_pattern(&sql);
    assert!(
        matches!(
            pattern,
            PatternClass::ExpandedFunction(ExpandedFunction {
                reads_bypass_rls: true,
                ..
            })
        ),
        "probe D: BYPASSRLS reads everything, got {pattern:?}"
    );
}

#[test]
fn current_user_in_a_definer_body_stays_refused() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id::text = current_user)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("current_user"),
        "the value is the owner's for every caller: {reason}"
    );
}

#[test]
fn a_plpgsql_body_refuses_naming_the_language() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS
'BEGIN RETURN TRUE; END';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("plpgsql"),
        "a second parser of record was rejected, so the language refuses: {reason}"
    );
}

#[test]
fn a_quoted_uppercase_language_name_refuses() {
    let sql = r#"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE "SQL" SECURITY DEFINER AS
'SELECT TRUE';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
"#;
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("SQL"),
        "quoted uppercase LANGUAGE \"SQL\" is not the built-in sql identifier: {reason}"
    );
}

#[test]
fn a_multi_statement_body_refuses() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql AS
'SELECT 1; SELECT TRUE';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("single-expression"),
        "earlier statements can change what the last one reads: {reason}"
    );
}

/// The Q6 hazard: inside a `LANGUAGE sql` body a bare name matching both an
/// argument and a column of a table in scope resolves to the column, silently,
/// so the clause compares the column to itself and admits every row.
#[test]
fn a_shadowed_argument_refuses_naming_the_function_and_the_argument() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(doc_id UUID) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = doc_id AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("is_member") && reason.contains("doc_id") && reason.contains("shadow"),
        "PostgreSQL resolves the bare name to the column: {reason}"
    );
}

/// The same guard through a quoted argument name, which is what sqlparser #2447
/// makes visible: `\"doc_id\"` arrives with its quote flag set and the value
/// unmangled, so the collision with the column is detected.
#[test]
fn a_quoted_shadowed_argument_refuses_too() {
    let sql = r#"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member("doc_id" UUID) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = "doc_id" AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
"#;
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("doc_id") && reason.contains("shadow"),
        "a quoted spelling of the same name is the same collision: {reason}"
    );
}

/// One membership, three spellings of the argument reference: positional,
/// bare name, and function-qualified. All three substitute to the same clause.
#[test]
fn positional_named_and_qualified_substitution_agree() {
    let bodies = [
        "'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = $1 AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)'",
        "'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)'",
        "'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = is_member.d AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)'",
    ];
    for body in bodies {
        let sql = format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS {body};
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
"
        );
        let pattern = docs_using_pattern(&sql);
        let PatternClass::ExpandedFunction(ExpandedFunction { inner, .. }) = pattern else {
            panic!("expected an expansion for body {body}, got {pattern:?}");
        };
        assert!(
            matches!(
                &inner.pattern,
                PatternClass::P4ExistsMembership(ExistsMembership { join_table, pairs, .. })
                    if join_table.schema().is_none() && join_table.name() == "doc_members"
                        && matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id")
            ),
            "body {body} should reach the same membership, got {:?}",
            inner.pattern
        );
    }
}

/// The self-referential idiom itself: the membership table's own policy calls
/// the definer wrapper with its `doc_id`. A bare substitution of that column
/// would be captured by the subquery's own `doc_id` and compare the column to
/// itself, admitting every row, so the substituted reference must stay the
/// outer table's.
#[test]
fn a_substituted_column_is_not_captured_by_the_body_scope() {
    let db = db_of(SELF_REFERENTIAL_DEFINER_MEMBERSHIP);
    let classified = translator(ConfidenceLevel::B).classify(&db);
    let policy = classified
        .iter()
        .find(|policy| policy.table_name() == "doc_members")
        .expect("doc_members policy should classify");
    let pattern = &policy
        .using_classification()
        .expect("USING should classify")
        .pattern;
    assert!(
        !matches!(
            pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(&inner.pattern, PatternClass::P13UncorrelatedMembership(_))
        ),
        "a captured substitution reads as an uncorrelated grant of every row: {pattern:?}"
    );
    assert!(
        matches!(
            pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(
                    &inner.pattern,
                    PatternClass::P4ExistsMembership(ExistsMembership { join_table, pairs, .. })
                        if join_table.schema().is_none() && join_table.name() == "doc_members"
                            && matches!(pairs.as_slice(), [pair] if pair.join_column == "doc_id")
                )
        ),
        "the row's own doc_id keys the membership: {pattern:?}"
    );
}

/// The body scans the same table without an alias, so a qualified reference to
/// the guarded row cannot be spelled from inside: the scan's own name claims it.
#[test]
fn an_unaliased_scan_of_the_arguments_table_refuses_the_capture() {
    let sql = r"
CREATE TABLE doc_members(id UUID PRIMARY KEY, doc_id UUID, user_id UUID);
ALTER TABLE doc_members ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members WHERE doc_members.doc_id = d AND doc_members.user_id = current_setting(''app.current_user_id'', true)::uuid)';
CREATE POLICY members_self ON doc_members FOR SELECT USING (is_member(doc_id));
";
    let db = db_of(sql);
    let classified = translator(ConfidenceLevel::B).classify(&db);
    let policy = classified.first().expect("one policy");
    let pattern = &policy
        .using_classification()
        .expect("USING should classify")
        .pattern;
    assert!(
        matches!(
            pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("captured")
        ),
        "an unspellable outer reference falls closed: {pattern:?}"
    );
}

/// A computed argument is evaluated in the policy's scope, so its columns must reach
/// the body as the guarded table's own references. Substituted bare, the body's scan
/// captures them and the loader reads the membership row where `PostgreSQL` reads the
/// guarded row.
#[test]
fn a_computed_arguments_column_is_not_captured_by_the_body_scope() {
    for argument in ["(level)::int", "coalesce(level, 0)"] {
        let sql = format!(
            r"
CREATE TABLE docs(id UUID PRIMARY KEY, level INT);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT, level INT, min_level INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION can_see(d UUID, req INT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_user AND m.min_level <= req)';
CREATE POLICY p ON docs FOR SELECT USING (can_see(id, {argument}));
"
        );
        let db = db_of(&sql);
        let classified = translator(ConfidenceLevel::B).classify(&db);
        let policy = classified.first().expect("one policy");
        let c = policy.using_classification().expect("USING classifies");
        assert!(
            c.confidence < ConfidenceLevel::B,
            "`{argument}`: the residual would read the loader's own `level`, so the \
             shape must fall below the threshold, got {:?} at {}",
            c.pattern,
            c.confidence
        );
    }
}

/// A computed argument whose expression carries no column stays pure under
/// substitution, so the shape keeps translating.
#[test]
fn a_pure_literal_computed_argument_still_translates() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, level INT);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT, level INT, min_level INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION can_see(d UUID, req INT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_user AND m.min_level <= req)';
CREATE POLICY p ON docs FOR SELECT USING (can_see(id, 1 + 2));
";
    let pattern = docs_using_pattern(sql);
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(&inner.pattern, PatternClass::P4ExistsMembership(_))
        ),
        "a columnless computed argument must keep the membership, got {pattern:?}"
    );
}

/// A cast-wrapped `current_user` argument is the keyword, not a column: qualifying it
/// would turn it into a column read and lose the caller comparison.
#[test]
fn a_cast_wrapped_current_user_argument_still_reaches_the_user_column() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION can_see(d UUID, u TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = u)';
CREATE POLICY p ON docs FOR SELECT USING (can_see(id, current_user::text));
";
    let pattern = docs_using_pattern(sql);
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(&inner.pattern, PatternClass::P4ExistsMembership(_))
        ),
        "the keyword must survive substitution unqualified, got {pattern:?}"
    );
}

/// The body aliases its scan with the guarded table's name, so the bare argument's
/// qualified spelling cannot be spoken from inside: it must refuse. The computed
/// argument beside it rides along; its own proof is the lone-argument test below.
#[test]
fn an_alias_hiding_scan_refuses_the_bare_arguments_capture() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, level INT);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT, min_level INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION can_see(d UUID, req INT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members AS docs WHERE docs.doc_id = d AND docs.user_id = current_user AND docs.min_level <= req)';
CREATE POLICY p ON docs FOR SELECT USING (can_see(id, coalesce(level, 0)));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("captured by the body's own scope"),
        "the alias claims the outer table's name, got: {reason}"
    );
}

/// The capture refusal must fire off the computed argument itself: with no bare
/// argument beside it, the wrapped column is the only route into the hiding scope.
#[test]
fn a_lone_computed_argument_still_triggers_the_capture_refusal() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, level INT);
CREATE TABLE doc_members(doc_id UUID, user_id TEXT, min_level INT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION cleared(req INT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members AS docs WHERE docs.min_level <= req AND docs.user_id = current_user)';
CREATE POLICY p ON docs FOR SELECT USING (cleared(coalesce(level, 0)));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("captured by the body's own scope"),
        "the alias claims the outer table's name, got: {reason}"
    );
}

/// Probe A end to end at the model level: both tables grant through the
/// definer, the membership table's rows keyed by their own doc.
#[test]
fn the_probe_a_idiom_grants_both_tables() {
    let db = db_of(SELF_REFERENTIAL_DEFINER_MEMBERSHIP);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let outputs = translation.outputs_accepting_gaps();
    let dsl = outputs.model();
    assert!(
        !relation_denies(&dsl, "docs", "can_select"),
        "members read their docs through the definer:\n{dsl}"
    );
    assert!(
        !relation_denies(&dsl, "doc_members", "can_select"),
        "members read the membership rows of their docs:\n{dsl}"
    );
    assert!(
        !outputs.tuple_queries().is_empty(),
        "the membership rows are the facts the model needs"
    );
}

/// The `RETURN expression` spelling parses the body up front, and expands the
/// same way the quoted-string spelling does.
#[test]
fn a_return_expression_body_expands() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql
RETURN EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting('app.current_user_id', true)::uuid);
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let pattern = docs_using_pattern(sql);
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(&inner.pattern, PatternClass::P4ExistsMembership(_))
        ),
        "RETURN expression is the pre-parsed spelling of the same body, got {pattern:?}"
    );
}

/// A function whose body calls itself can never finish expanding, and the
/// refusal has to name the cycle rather than hang or overflow.
#[test]
fn a_self_calling_function_refuses_the_cycle() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql AS
'SELECT is_member(d)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("cycle"),
        "expansion must terminate on self-reference and name why: {reason}"
    );
}

/// Two functions expanding each other terminate the same way a self-call does,
/// even though each expansion starts from a different name.
#[test]
fn mutually_recursive_functions_refuse() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION even_hop(d UUID) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT odd_hop(d)';
CREATE FUNCTION odd_hop(d UUID) RETURNS BOOLEAN LANGUAGE sql AS 'SELECT even_hop(d)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (even_hop(id));
";
    let reason = docs_refusal_reason(sql);
    assert!(
        reason.contains("cycle"),
        "mutual recursion must terminate and name why: {reason}"
    );
}

/// A registry declaration wins over the body: an operator who said what a
/// function means, or that it is unknown, is not second-guessed by expansion.
#[test]
fn a_registry_declared_function_is_not_expanded() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true)::uuid)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let db = db_of(sql);
    let translator = TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .with_registry_json(
            r#"{"is_member": {"kind": "unknown", "reason": "audited and declined"}}"#,
        )
        .expect("registry json should load")
        .build();
    let classified = translator.classify(&db);
    let policy = classified
        .iter()
        .find(|policy| policy.table_name() == "docs")
        .expect("docs policy should classify");
    let pattern = &policy
        .using_classification()
        .expect("USING should classify")
        .pattern;
    assert!(
        matches!(
            pattern,
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("audited and declined")
        ),
        "the declaration wins over the body: {pattern:?}"
    );
}

/// A call whose argument count disagrees with the declaration is not the
/// declared function's meaning, so it refuses rather than substituting a guess.
#[test]
fn an_arity_mismatch_refuses() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID, extra INT) RETURNS BOOLEAN LANGUAGE sql AS
'SELECT TRUE';
CREATE POLICY docs_sel ON docs FOR SELECT USING (is_member(id));
";
    let pattern = docs_using_pattern(sql);
    assert!(
        matches!(&pattern, PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains("argument")),
        "one argument against a two-argument declaration is no expansion: {pattern:?}"
    );
}

#[test]
fn a_strict_expansion_guards_its_column_argument() {
    let tuples = docs_tuple_sql(&strict_true_schema("strict_true(gate)"));
    assert!(tuples.contains("\"gate\" IS NOT NULL"), "{tuples}");
}

#[test]
fn a_strict_expansion_keeps_its_guard_under_and() {
    let tuples = docs_tuple_sql(&strict_true_schema(
        "strict_true(gate) AND status = 'active'",
    ));
    assert!(tuples.contains("\"gate\" IS NOT NULL"), "{tuples}");
    assert!(tuples.contains("\"status\" = 'active'"), "{tuples}");
}

#[test]
fn a_strict_expansion_keeps_its_guard_under_or() {
    let tuples = docs_tuple_sql(&strict_true_schema(
        "strict_true(gate) OR status = 'active'",
    ));
    assert!(tuples.contains("\"gate\" IS NOT NULL"), "{tuples}");
    assert!(tuples.contains("\"status\" = 'active'"), "{tuples}");
}

#[test]
fn is_true_keeps_a_strict_expansion_guard() {
    let tuples = docs_tuple_sql(&strict_true_schema("strict_true(gate) IS TRUE"));
    assert!(tuples.contains("\"gate\" IS NOT NULL"), "{tuples}");
}

#[test]
fn a_non_strict_expansion_does_not_gain_a_presence_guard() {
    let sql =
        strict_true_schema("strict_true(gate)").replace(" LANGUAGE sql STRICT ", " LANGUAGE sql ");
    let tuples = docs_tuple_sql(&sql);
    assert!(!tuples.contains("\"gate\" IS NOT NULL"), "{tuples}");
}

#[test]
fn a_strict_expansion_refuses_an_unrepresentable_argument() {
    let reason = docs_refusal_reason(&strict_true_schema("strict_true(lower(gate))"));
    assert!(reason.contains("null input"), "{reason}");
}

#[test]
fn negating_a_strict_expansion_stays_refused() {
    let reason = docs_refusal_reason(&strict_true_schema("NOT strict_true(gate)"));
    assert!(reason.contains("NOT"), "{reason}");
}

#[test]
fn a_string_body_uses_its_function_local_search_path() {
    let sql = r"
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE a.doc_members(doc_id TEXT, user_id TEXT);
CREATE TABLE b.doc_members(doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO b, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_sel ON docs FOR SELECT USING (public.is_member(id));
SET search_path TO a, public;
";
    let pattern = docs_using_pattern(sql);
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(
                    &inner.pattern,
                    PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. })
                        if join_table.to_string() == "b.doc_members"
                )
        ),
        "the function-local path must select b.doc_members, got {pattern:?}"
    );
}

#[test]
fn a_string_body_without_a_fixed_search_path_refuses() {
    let sql = r"
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE a.doc_members(doc_id TEXT, user_id TEXT);
CREATE TABLE b.doc_members(doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_sel ON docs FOR SELECT USING (public.is_member(id));
SET search_path TO a, public;
";
    let reason = docs_refusal_reason(sql);
    assert!(reason.contains("search_path"), "{reason}");
}

#[test]
fn unresolved_function_search_paths_refuse() {
    for setting in [
        "SET search_path TO DEFAULT",
        "SET search_path FROM CURRENT",
        "SET search_path TO 1",
    ] {
        let sql = format!(
            r"
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE doc_members(doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
{setting} AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_sel ON docs FOR SELECT USING (public.is_member(id));
"
        );
        let reason = docs_refusal_reason(&sql);
        assert!(reason.contains("search_path"), "{setting}: {reason}");
    }
}

#[test]
fn a_function_search_path_keeps_quoted_schema_identity() {
    let sql = r#"
CREATE SCHEMA b;
CREATE SCHEMA "B";
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE b.doc_members(doc_id TEXT, user_id TEXT);
CREATE TABLE "B".doc_members(doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO '"B"', 'pg_catalog', 'pg_temp' AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_sel ON docs FOR SELECT USING (public.is_member(id));
"#;
    let pattern = docs_using_pattern(sql);
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(
                    &inner.pattern,
                    PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. })
                        if join_table.to_string() == r#""B".doc_members"#
                )
        ),
        "the quoted path must select \"B\".doc_members, got {pattern:?}"
    );
}

#[test]
fn a_temp_schema_before_the_declared_table_refuses() {
    let sql = r"
CREATE SCHEMA b;
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE b.doc_members(doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO pg_temp, b, pg_catalog AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_sel ON docs FOR SELECT USING (public.is_member(id));
";
    let reason = docs_refusal_reason(sql);
    assert!(reason.contains("pg_temp"), "{reason}");
}

#[test]
fn implicit_pg_catalog_before_user_schema_refuses_b_pg_temp() {
    let make_sql = |path: &str| {
        format!(
            r"
CREATE SCHEMA b;
CREATE TABLE docs(id TEXT PRIMARY KEY);
CREATE TABLE b.doc_members(doc_id TEXT, user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION public.is_member(d TEXT) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO {path} AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = current_setting(''app.current_user_id'', true))';
CREATE POLICY docs_sel ON docs FOR SELECT USING (public.is_member(id));
"
        )
    };

    let reason = docs_refusal_reason(&make_sql("b, pg_temp"));
    assert!(
        reason.contains("pg_catalog"),
        "implicit pg_catalog was ignored: {reason}"
    );

    let pattern = docs_using_pattern(&make_sql("b, pg_catalog, pg_temp"));
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(
                    &inner.pattern,
                    PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. })
                        if join_table.to_string() == "b.doc_members"
                )
        ),
        "explicit pg_catalog order was ignored: {pattern:?}"
    );
}

#[test]
fn matching_alter_owner_without_create_role_expands() {
    let sql = format!(
        "{DEFINER_MEMBERSHIP}\
         ALTER TABLE doc_members OWNER TO app_owner;\
         ALTER FUNCTION is_member(UUID) OWNER TO app_owner;"
    );
    let pattern = docs_using_pattern(&sql);
    assert!(
        matches!(
            pattern,
            PatternClass::ExpandedFunction(ExpandedFunction {
                reads_bypass_rls: true,
                ..
            })
        ),
        "matching undeclared owners refused: {pattern:?}"
    );
}

#[test]
fn schema_qualified_call_does_not_collide_with_differently_cased_schema() {
    let sql = r#"
CREATE SCHEMA auth;
CREATE SCHEMA "Auth";
CREATE TABLE docs(id TEXT PRIMARY KEY, gate TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION auth.strict_true(value TEXT) RETURNS BOOLEAN LANGUAGE sql STRICT AS
'SELECT true';
CREATE FUNCTION "Auth".strict_true(value TEXT) RETURNS BOOLEAN LANGUAGE sql STRICT AS
'SELECT false';
CREATE POLICY docs_sel ON docs FOR SELECT USING (auth.strict_true(gate));
SET search_path TO public;
"#;
    let pattern = docs_using_pattern(sql);
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction {
                function,
                inner,
                ..
            }) if function == "strict_true"
                && matches!(
                    &inner.pattern,
                    PatternClass::P10ConstantBool(value) if value.value
                )
        ),
        "quoted schema identity was lost: {pattern:?}"
    );
}

/// `PostgreSQL` puts an unqualified `CREATE FUNCTION` in the first schema on the search
/// path, so a policy naming that function in full calls the same declaration.
///
/// `pg_dump` qualifies every call it deparses, so refusing this loses the expansion on
/// exactly the shape a dump carries.
#[test]
fn a_qualified_call_reaches_an_unqualified_declaration() {
    let pattern = docs_using_pattern(
        r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id NAME);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = CURRENT_USER)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (public.is_member(id));
",
    );
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(
                    &inner.pattern,
                    PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. })
                        if join_table.name() == "doc_members"
                )
        ),
        "the call names the declaration the search path places in public: {pattern:?}"
    );
}

/// A call naming a schema is that schema's function, so the search-path fallback cannot
/// collapse two declarations of one name onto whichever came first.
#[test]
fn a_qualified_call_reaches_its_own_schemas_declaration() {
    let pattern = docs_using_pattern(
        r"
CREATE SCHEMA other;
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID, user_id NAME);
CREATE TABLE other.other_members(doc_id UUID, user_id NAME);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO public, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM doc_members m WHERE m.doc_id = d AND m.user_id = CURRENT_USER)';
CREATE FUNCTION other.is_member(d UUID) RETURNS BOOLEAN LANGUAGE sql
SET search_path TO other, pg_catalog, pg_temp AS
'SELECT EXISTS (SELECT 1 FROM other_members m WHERE m.doc_id = d AND m.user_id = CURRENT_USER)';
CREATE POLICY docs_sel ON docs FOR SELECT USING (other.is_member(id));
",
    );
    assert!(
        matches!(
            &pattern,
            PatternClass::ExpandedFunction(ExpandedFunction { inner, .. })
                if matches!(
                    &inner.pattern,
                    PatternClass::P4ExistsMembership(ExistsMembership { join_table, .. })
                        if join_table.name() == "other_members"
                )
        ),
        "the qualified call runs its own schema's body: {pattern:?}"
    );
}
