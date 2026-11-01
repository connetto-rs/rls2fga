use rls2fga::classifier::function_registry::{
    FunctionRegistry, SessionAttribute, SessionAttributeKind,
};
use rls2fga::classifier::patterns::{
    CallerScalarEqualsConstant, ConstantInCallerSet, DirectOwnership, ExistsMembership,
    MembershipInCallerSet, PatternClass, RowValueEqualsCallerScalar, RowValueInCallerSet,
    UnclassifiedExpr,
};
use rls2fga::parser::function_analyzer::FunctionSemantic;
use rls2fga::parser::sql_parser::parse_schema;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;

#[test]
fn translator_builder_default_settings_reject_timezone_accessor_inference() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION wrong_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''timezone'')';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = wrong_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        !matches!(
            &using.pattern,
            PatternClass::P3DirectOwnership(DirectOwnership { .. })
        ),
        "timezone-based current_setting must not infer direct ownership by default, got: {:?}",
        using.pattern
    );
}

#[test]
fn translator_builder_custom_current_setting_key_enables_schema_inference() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION wrong_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''timezone'')';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = wrong_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["timezone"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "custom allowlist should infer direct ownership, got: {:?}",
        using.pattern
    );
    assert_eq!(
        using.confidence,
        ConfidenceLevel::A,
        "schema-inferred accessor should classify P3 at confidence A",
    );
}

#[test]
fn translator_builder_default_settings_rejects_uuid_array_accessor_inference() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION listed_ids_accessor() RETURNS UUID[]
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = listed_ids_accessor());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        !matches!(
            &using.pattern,
            PatternClass::P3DirectOwnership(DirectOwnership { .. })
        ),
        "UUID[] accessors must not infer direct ownership, got: {:?}",
        using.pattern
    );
}

#[test]
fn translator_builder_accepts_direct_accessor_with_keyword_substring_alias() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION current_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'') AS from_id';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "direct accessor with alias substring should still infer P3 ownership, got: {:?}",
        using.pattern
    );
}

#[test]
fn translator_builder_registry_json_and_settings_work_together() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = oauth_token());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["tenant.current_user_uuid"])
        .with_registry_json(
            r#"{
  "oauth_token": {"kind":"current_user_accessor","returns":"uuid"}
}"#,
        )
        .expect("registry json should parse")
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "registry-provided accessor should classify as direct ownership, got: {:?}",
        using.pattern
    );
    assert_eq!(using.confidence, ConfidenceLevel::A);
}

/// A key names the caller wherever the call sits. Nothing forces a policy to route
/// the read through a declared function, and a wrapper's return type says nothing
/// about whether its value identifies the caller.
#[test]
fn translator_builder_names_the_caller_from_an_inline_setting_key() {
    let sql = r"
CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner"),
        "a named key read inline should infer direct ownership, got: {:?}",
        using.pattern
    );
    assert_eq!(
        using.confidence,
        ConfidenceLevel::A,
        "naming the key is the same statement a registered accessor makes",
    );
}

/// A wrapper resolves to the key it reads, so its body has to be that read and nothing
/// else. With a `FROM` and a `WHERE` the function yields no row once the guard is gone,
/// so it returns NULL and `PostgreSQL` hides every row, while resolving it to the key
/// would grant every row the request's value matches.
///
/// The caller identity half of this door is guarded by `is_direct_accessor_body`. This
/// covers the declared attribute half, which reaches the key through `SettingReader`
/// instead and so never meets that guard.
#[test]
fn a_wrapper_whose_body_can_return_no_row_does_not_resolve_to_its_key() {
    fn schema(body: &str) -> String {
        format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, tenant_id UUID);\n\
             CREATE TABLE kill_switch(enabled BOOLEAN);\n\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE FUNCTION gated_tenant() RETURNS UUID LANGUAGE sql STABLE AS '{body}';\n\
             CREATE POLICY p ON documents FOR SELECT USING (tenant_id = gated_tenant());\n"
        )
    }
    fn classify(body: &str) -> PatternClass {
        declared(
            &schema(body),
            vec![
                SessionAttribute::setting("app.tenant_id", SessionAttributeKind::ScalarAttribute)
                    .with_identity_cast("uuid"),
            ],
        )
        .remove(0)
        .1
    }

    let gated =
        classify("SELECT current_setting(''app.tenant_id'')::uuid FROM kill_switch WHERE enabled");
    assert!(
        matches!(gated, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "a body that can return no row does not resolve to its key, got: {gated:?}"
    );

    // The companion half, so the guard is known to be narrow rather than blanket: the
    // same read with nothing around it still resolves to the declared key.
    let plain = classify("SELECT current_setting(''app.tenant_id'')::uuid");
    assert!(
        matches!(&plain, PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar { column, .. }) if column == "tenant_id"),
        "a body that is only the read still resolves to its key, got: {plain:?}"
    );
}

/// The same hole on the caller identity door, reached by a clause the token scan in
/// `is_direct_accessor_body` does not look at. `LIMIT 0` yields no row, so the function
/// returns NULL and `PostgreSQL` hides every row, while naming the caller grants owners.
#[test]
fn an_accessor_body_that_can_return_no_row_does_not_name_the_caller() {
    fn schema(body: &str) -> String {
        format!(
            "CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);\n\
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\
             CREATE FUNCTION who() RETURNS TEXT LANGUAGE sql STABLE AS '{body}';\n\
             CREATE POLICY p ON notes FOR SELECT USING (owner = who());\n"
        )
    }
    fn classify(body: &str) -> PatternClass {
        let db = parse_schema(&schema(body)).expect("schema should parse");
        TranslatorBuilder::new().build().classify(&db)[0]
            .using_classification()
            .expect("expected USING classification")
            .pattern
            .clone()
    }

    let limited = classify("SELECT current_setting(''app.user_id'', true) LIMIT 0");
    assert!(
        matches!(limited, PatternClass::Unknown(UnclassifiedExpr { .. })),
        "a body limited to no row does not name the caller, got: {limited:?}"
    );

    let plain = classify("SELECT current_setting(''app.user_id'', true)");
    assert!(
        matches!(&plain, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner"),
        "a body that is only the read still names the caller, got: {plain:?}"
    );
}

/// A helper naming the columns one translator classifies as owned, so a test asserting
/// what is refused also asserts what is admitted under the same configuration.
fn owned_columns(translator: &rls2fga::translator::Translator, sql: &str) -> Vec<String> {
    let db = parse_schema(sql).expect("schema should parse");
    let mut owned: Vec<String> = translator
        .classify(&db)
        .iter()
        .filter_map(|policy| match policy.using_classification()?.pattern {
            PatternClass::P3DirectOwnership(DirectOwnership { ref column }) => {
                Some(column.to_string())
            }
            _ => None,
        })
        .collect();
    owned.sort();
    owned
}

/// The keys are an allowlist, so a key nobody named stays unknown. Trusting every key
/// would read a tenant identifier as a user and grant one tuple per tenant. The named
/// key beside it is the control: refusing everything would satisfy the refusal alone.
#[test]
fn translator_builder_does_not_name_the_caller_from_an_unnamed_setting_key() {
    let sql = r"
CREATE TABLE rows_(id INTEGER PRIMARY KEY, tenant_id TEXT, owner_id TEXT);
ALTER TABLE rows_ ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON rows_ FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY p_owner ON rows_ FOR UPDATE USING (owner_id = current_setting('app.user_id', true));
";
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    assert_eq!(
        owned_columns(&translator, sql),
        ["owner_id"],
        "the named key names the caller and the unnamed one names nobody"
    );
}

/// `request.jwt.claims` holds the whole token as one object, so its value is not an
/// identity. It is reached through a `->> 'sub'` hop, which names the caller on its own.
/// The key beside it is a built-in one, so the refusal is selective rather than total.
#[test]
fn translator_builder_does_not_name_the_caller_from_the_default_claims_object() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, claims_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_claims ON docs FOR SELECT USING (claims_id = current_setting('request.jwt.claims', true));
CREATE POLICY p_owner ON docs FOR UPDATE USING (owner_id = current_setting('app.user_id', true));
";
    let translator = TranslatorBuilder::new().build();

    assert_eq!(
        owned_columns(&translator, sql),
        ["owner_id"],
        "a built-in key that holds an identity is the caller, the token object is not"
    );
}

/// Every recognizer asks one predicate who the caller is, so a named key reaches the
/// membership subquery too.
#[test]
fn translator_builder_names_the_caller_from_an_inline_key_inside_a_membership_subquery() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (EXISTS (
  SELECT 1 FROM doc_members m
  WHERE m.doc_id = docs.id AND m.user_id = current_setting('app.user_id', true)
));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.user_id"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(
            &using.pattern,
            PatternClass::P4ExistsMembership(ExistsMembership { join_table, user_column, .. })
                if join_table.name() == "doc_members" && user_column == "user_id"
        ),
        "a named key read inline should carry the membership too, got: {:?}",
        using.pattern
    );
}

/// A text identity is at least as common as a UUID one, and the declared return type
/// says nothing about whether the body's value identifies the caller.
#[test]
fn translator_builder_infers_a_text_returning_accessor_from_its_body() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION app_user_id() RETURNS TEXT
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.user_id'', true)';
CREATE POLICY p ON docs FOR SELECT USING (owner_id = app_user_id());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new().build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "a TEXT accessor body should infer direct ownership, got: {:?}",
        using.pattern
    );
}

/// A cast the deployment declares canonical changes the type, not who the value belongs
/// to, so it must not decide whether the key was named. Undeclared, it can rename the
/// caller and the clause is refused.
#[test]
fn translator_builder_names_the_caller_from_a_declared_cast_inline_setting_key() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('app.user_id', true)::uuid);
";
    let db = parse_schema(sql).expect("schema should parse");
    let classify = |caller: SessionAttribute| {
        TranslatorBuilder::new()
            .with_session_attributes([caller])
            .build()
            .classify(&db)
            .remove(0)
            .using_classification()
            .cloned()
            .expect("expected USING classification")
    };
    let caller = || SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId);

    let declared = classify(caller().with_identity_cast("uuid"));
    assert!(
        matches!(&declared.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "a declared cast key read inline should infer direct ownership, got: {:?}",
        declared.pattern
    );
    assert_eq!(
        declared.confidence,
        ConfidenceLevel::A,
        "a cast is not indirection",
    );
    let undeclared = classify(caller());
    assert!(
        matches!(
            &undeclared.pattern,
            PatternClass::Unknown(UnclassifiedExpr { .. })
        ),
        "an undeclared cast can rename the caller, got: {:?}",
        undeclared.pattern
    );
}

/// A login token holds the identity in a field, and no expression says which field that
/// is, so naming the token's own key names nobody. The key holding just the subject is
/// the spelling that works, and `PostgREST` sets it alongside the token.
#[test]
fn translator_builder_reads_a_token_payload_only_through_the_subject_key() {
    let payload = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = current_setting('request.jwt.claims', true)::json->>'sub');
";
    let subject = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = current_setting('request.jwt.claim.sub', true));
";
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["request.jwt.claims", "request.jwt.claim.sub"])
        .build();

    assert!(
        owned_columns(&translator, payload).is_empty(),
        "a field of the token is not the token's value, so the key names nobody here"
    );
    assert_eq!(
        owned_columns(&translator, subject),
        ["owner_id"],
        "the key holding the subject names the caller"
    );
}

/// Which key names the caller is the caller's to say, so a key the crate ships no
/// default for works the moment it is named.
#[test]
fn translator_builder_names_the_caller_from_any_key_it_is_given() {
    let sql = r"
CREATE TABLE rows_(id INTEGER PRIMARY KEY, tenant_id TEXT);
ALTER TABLE rows_ ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON rows_ FOR SELECT USING (tenant_id = current_setting('app.tenant_id', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys(["app.tenant_id"])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "tenant_id"),
        "the named key decides, whatever it is called, got: {:?}",
        using.pattern
    );
}

/// The built-in keys are the ones a schema is most likely to spell, so they have to
/// reach an inline call with nothing configured.
#[test]
fn translator_builder_names_the_caller_from_a_built_in_key_with_no_configuration() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT
  USING (owner_id = current_setting('app.current_user_id', true));
";
    let db = parse_schema(sql).expect("schema should parse");

    let classified = TranslatorBuilder::new().build().classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "a built-in key read inline should infer direct ownership, got: {:?}",
        using.pattern
    );
}

/// `PostgreSQL` folds a setting name when it looks it up, so two spellings of one key
/// name one setting and have to name one caller.
#[test]
fn translator_builder_folds_the_case_of_a_setting_key() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = current_setting('APP.User_Id', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_current_user_setting_keys([" app.USER_ID "])
        .build();

    let classified = translator.classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("expected USING classification");
    assert!(
        matches!(&using.pattern, PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "owner_id"),
        "one setting under two spellings is one caller, got: {:?}",
        using.pattern
    );
}

/// A key named on the registry and a key named through the settings are two statements
/// by the same caller, so both hold.
#[test]
fn translator_builder_keeps_a_key_the_base_registry_already_named() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, editor_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_owner ON docs FOR SELECT USING (owner_id = current_setting('one.key', true));
CREATE POLICY p_editor ON docs FOR UPDATE USING (editor_id = current_setting('other.key', true));
";
    let db = parse_schema(sql).expect("schema should parse");
    let mut registry = FunctionRegistry::new();
    registry.trust_current_user_setting_keys(["one.key"]);
    let translator = TranslatorBuilder::new()
        .with_registry(registry)
        .with_current_user_setting_keys(["other.key"])
        .build();

    let classified = translator.classify(&db);
    let mut owned: Vec<&str> = classified
        .iter()
        .filter_map(|policy| match policy.using_classification()?.pattern {
            PatternClass::P3DirectOwnership(DirectOwnership { ref column }) => {
                Some(column.as_str())
            }
            _ => None,
        })
        .collect();
    owned.sort_unstable();
    assert_eq!(
        owned,
        ["editor_id", "owner_id"],
        "both keys name the caller: {classified:#?}"
    );
}

#[test]
fn function_and_setting_names_use_separate_namespaces() {
    let sql = r"
CREATE TABLE docs(id UUID PRIMARY KEY, tenant_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (
    tenant_id = current_setting('app.tenant_id', true)
);
";
    let db = parse_schema(sql).expect("schema should parse");
    let mut registry = FunctionRegistry::new();
    registry.register_if_absent(
        "app.tenant_id",
        &FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        },
    );
    let classified = TranslatorBuilder::new()
        .with_registry(registry)
        .with_session_attributes([SessionAttribute::setting(
            "app.tenant_id",
            SessionAttributeKind::ScalarAttribute,
        )])
        .build()
        .classify(&db);
    let using = classified[0]
        .using_classification()
        .expect("the policy has a USING clause");

    assert!(matches!(
        &using.pattern,
        PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar { column, .. })
            if column == "tenant_id"
    ));
}

// ── The session attribute vocabulary ──────────────────────────────────

/// Every in-scope spelling, so one declaration list answers the whole inventory.
fn declared(
    sql: &str,
    attributes: Vec<SessionAttribute>,
) -> Vec<(String, PatternClass, ConfidenceLevel)> {
    let db = parse_schema(sql).expect("schema should parse");
    let translator = TranslatorBuilder::new()
        .with_session_attributes(attributes)
        .build();
    translator
        .classify(&db)
        .into_iter()
        .filter_map(|policy| {
            let using = policy
                .using_classification()
                .or_else(|| policy.with_check_classification())?
                .clone();
            Some((policy.name().to_string(), using.pattern, using.confidence))
        })
        .collect()
}

/// `papers` read through `paper_shares`, the caller's held set read from the request.
const PAPER_SHARES: &str = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";

/// Inventory row 1 and `shares_read`: the caller's held set against a row column.
#[test]
fn a_declared_set_holds_the_rows_value() {
    let sql = r"
CREATE TABLE notes(id INT PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notes FOR SELECT USING (
    owner = ANY(string_to_array(current_setting('app.subjects', true), ','))
);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { column, source, .. })
                if column == "owner" && source.request_parameter() == "app_subjects"
        ),
        "a declared set holding the row's value is the whole grant, got {:?}",
        classified[0].1
    );
}

/// Inventory row 6: the caller's set arrives as a real list inside the token rather than
/// as a delimited string. Both spellings are the same database, so both must land alike.
#[test]
fn a_declared_set_inside_the_token_holds_the_rows_value() {
    fn schema(clause: &str) -> String {
        format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY p ON documents FOR SELECT USING ({clause});\n"
        )
    }
    const CLAIM: &str = "jsonb_array_elements_text(\
                         current_setting('request.jwt.claims')::jsonb -> 'teams')";

    for (label, clause) in [
        ("6a", format!("team_id IN (SELECT {CLAIM})")),
        ("6c", format!("team_id = ANY (ARRAY(SELECT {CLAIM}))")),
    ] {
        let classified = declared(
            &schema(&clause),
            vec![SessionAttribute::claim(
                "request.jwt.claims",
                ["teams"],
                SessionAttributeKind::SetAttribute,
            )],
        );
        assert!(
            matches!(
                &classified[0].1,
                PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { column, source, separator })
                    if column == "team_id"
                    && source.request_parameter() == "request_jwt_claims_teams"
                    && separator.is_none()
            ),
            "{label}: a real list has no separator to send, got {:?}",
            classified[0].1
        );
        assert_eq!(
            classified[0].2,
            ConfidenceLevel::B,
            "{label}: a claim path is indirection and caps at B"
        );
    }
}

/// Inventory row 8: the caller's set arrives from a set returning function, admitted
/// only because that function's whole body expands a declared setting. Both spellings
/// are the same database, so both must land alike.
#[test]
fn a_set_returning_wrapper_over_a_declared_setting_holds_the_rows_value() {
    fn schema(clause: &str) -> String {
        format!(
            "CREATE TABLE documents(id UUID PRIMARY KEY, team_id TEXT);\n\
             CREATE FUNCTION user_teams() RETURNS SETOF TEXT LANGUAGE sql STABLE\n\
               AS 'SELECT unnest(string_to_array(current_setting(''app.teams'', true), '','')) ';\n\
             ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY p ON documents FOR SELECT USING ({clause});\n"
        )
    }

    for (label, clause) in [
        ("8b", "team_id IN (SELECT user_teams())"),
        ("8a", "team_id = ANY (ARRAY(SELECT user_teams()))"),
    ] {
        let classified = declared(
            &schema(clause),
            vec![SessionAttribute::setting(
                "app.teams",
                SessionAttributeKind::SetAttribute,
            )],
        );
        assert!(
            matches!(
                &classified[0].1,
                PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { column, source, separator })
                    if column == "team_id"
                    && source.request_parameter() == "app_teams"
                    && separator.as_deref() == Some(",")
            ),
            "{label}: the wrapper carries the split its body performs, got {:?}",
            classified[0].1
        );
    }
}

/// Inventory row 5: one request value against a row column.
#[test]
fn a_declared_scalar_equals_the_rows_value() {
    let sql = r"
CREATE TABLE tenants(id UUID PRIMARY KEY);
CREATE TABLE documents(id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id));
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON documents FOR SELECT USING (tenant_id = current_setting('app.tenant_id')::uuid);
";
    let classified = declared(
        sql,
        vec![
            SessionAttribute::setting("app.tenant_id", SessionAttributeKind::ScalarAttribute)
                .with_identity_cast("uuid"),
        ],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar { column, source })
                if column == "tenant_id" && source.request_parameter() == "app_tenant_id"
        ),
        "a declared scalar equal to the row's value is the grant, got {:?}",
        classified[0].1
    );
}

/// Inventory row 10: a constant against the caller's held set, no row column at all.
#[test]
fn a_declared_set_holds_a_constant() {
    let sql = r"
CREATE TABLE audit_log(id UUID PRIMARY KEY, actor TEXT);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON audit_log FOR SELECT USING (
    'admin' = ANY(string_to_array(current_setting('app.roles', true), ','))
);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.roles",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P16ConstantInCallerSet(ConstantInCallerSet { value, source, .. })
                if value == "admin" && source.request_parameter() == "app_roles"
        ),
        "the request alone decides this grant, got {:?}",
        classified[0].1
    );
}

/// A declared field of the caller's token reached through its helper function.
#[test]
fn a_declared_claim_field_equals_a_constant_through_its_wrapper() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE documents(id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id));
CREATE FUNCTION jwt() RETURNS JSONB LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claims'')::jsonb';
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON documents AS RESTRICTIVE FOR SELECT
    USING ((SELECT jwt() ->> 'aal') = 'aal2');
";
    let classified = declared(
        sql,
        vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["aal"],
            SessionAttributeKind::ScalarAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant { value, source })
                if value == "aal2" && source.request_parameter() == "request_jwt_claims_aal"
        ),
        "a declared token field is a request value, got {:?}",
        classified[0].1
    );
}

/// The same field written against the setting itself, so the two spellings are one
/// declaration and cannot disagree.
#[test]
fn a_declared_claim_field_is_reached_through_either_spelling() {
    let sql = r"
CREATE TABLE documents(id UUID PRIMARY KEY, owner_id UUID);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON documents FOR SELECT
    USING (current_setting('request.jwt.claims')::jsonb ->> 'aal' = 'aal2');
";
    let classified = declared(
        sql,
        vec![SessionAttribute::claim(
            "request.jwt.claims",
            ["aal"],
            SessionAttributeKind::ScalarAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant { value, .. }) if value == "aal2"
        ),
        "the inline spelling and the wrapper spelling are one declaration, got {:?}",
        classified[0].1
    );
}

/// An undeclared key stays unreadable, so the door opens only where a deployment said so.
#[test]
fn an_undeclared_key_still_yields_unknown() {
    let sql = r"
CREATE TABLE notes(id INT PRIMARY KEY, owner TEXT);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notes FOR SELECT USING (
    owner = ANY(string_to_array(current_setting('app.subjects', true), ','))
);
";
    let classified = declared(sql, Vec::new());
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::Unknown(UnclassifiedExpr { .. })
        ),
        "nothing named this key, so nothing may read it, got {:?}",
        classified[0].1
    );
}

/// Inventory row 3: the caller's held set tested inside a membership subquery. The
/// sharing row is the table's authority and the held set is the request's, so the grant
/// is a request-completed gate on the parent, keyed by the sharing row's parent column.
#[test]
fn a_declared_set_inside_a_membership_subquery_grants_through_the_parent() {
    let classified = declared(
        PAPER_SHARES,
        vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P18MembershipInCallerSet(MembershipInCallerSet {
                membership: ExistsMembership {
                    join_table,
                    pairs,
                    user_column,
                    ..
                },
                source,
                ..
            }) if join_table.name() == "paper_shares"
                && matches!(pairs.as_slice(), [pair] if pair.join_column == "paper_id")
                && user_column == "viewer"
                && source.request_parameter() == "app_subjects"
        ),
        "a share row naming a key the caller holds is the grant, got {:?}",
        classified[0].1
    );
}

/// The same subquery with nothing declared stays unreadable, so the door opens only
/// where a deployment said so.
#[test]
fn an_undeclared_set_inside_a_membership_subquery_yields_unknown() {
    let classified = declared(PAPER_SHARES, Vec::new());
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::Unknown(UnclassifiedExpr { .. })
        ),
        "nothing named this key, so nothing may read it, got {:?}",
        classified[0].1
    );
}

/// The uncorrelated shape, where the subquery names no column of the guarded table, is
/// the widest grant the crate emits: whoever appears in the member table gets the whole
/// table. A column holding a grant the caller carries names no person, so reading it
/// that way would declare grant keys to be users and hand them every row.
#[test]
fn an_uncorrelated_subquery_testing_a_declared_set_is_refused() {
    let sql = r"
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE grants_table (grant_key TEXT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM grants_table g
        WHERE g.grant_key = ANY(string_to_array(current_setting('app.subjects', true), ','))
    )
);
";
    let classified = declared(
        sql,
        vec![SessionAttribute::setting(
            "app.subjects",
            SessionAttributeKind::SetAttribute,
        )],
    );
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::Unknown(UnclassifiedExpr { .. })
        ),
        "a grant key is not a person, so it cannot hold the whole table open, got {:?}",
        classified[0].1
    );
}

/// Inventory row 9, from the Supabase documentation: "the caller is known, and the
/// caller owns this row". A fact exists only for a row that has an owner and a caller
/// with no identifier matches none, so the first half is already enforced by how facts
/// are produced and contributes nothing. Refusing the pair is pure over-denial.
#[test]
fn a_redundant_caller_is_known_check_leaves_the_ownership_half() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id));
CREATE FUNCTION uid() RETURNS UUID LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claim.sub'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (uid() IS NOT NULL AND uid() = user_id);
";
    let classified = declared(sql, vec![claim_sub_declared_uuid()]);
    assert!(
        matches!(
            &classified[0].1,
            PatternClass::P3DirectOwnership(DirectOwnership { column }) if column == "user_id"
        ),
        "the ownership half is the whole rule, got {:?}",
        classified[0].1
    );
    assert_eq!(
        classified[0].2,
        ConfidenceLevel::A,
        "dropping a conjunct that says nothing costs no confidence"
    );
}

/// The same test on a row column is a real filter and must survive: dropping it would
/// grant rows the policy refuses.
#[test]
fn a_not_null_check_on_a_row_column_is_never_dropped() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id), approved_at TIMESTAMPTZ);
CREATE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE
    AS 'SELECT current_setting(''request.jwt.claim.sub'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (approved_at IS NOT NULL AND auth.uid() = user_id);
";
    let classified = declared(sql, vec![claim_sub_declared_uuid()]);
    assert!(
        !matches!(
            &classified[0].1,
            PatternClass::P3DirectOwnership(DirectOwnership { .. })
        ),
        "the row's own guard decides which rows are granted, got {:?}",
        classified[0].1
    );
}

/// The subject key `PostgREST` sets, declared to arrive as a canonical `uuid`.
fn claim_sub_declared_uuid() -> SessionAttribute {
    SessionAttribute::setting("request.jwt.claim.sub", SessionAttributeKind::CallerId)
        .with_identity_cast("uuid")
}

/// The output types serialize and come back equal, so a consumer can store a
/// translation's results and reload them without re-planning.
#[test]
fn output_types_round_trip_through_serde() {
    let sql = r"
CREATE TABLE users(id UUID PRIMARY KEY);
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id));
CREATE FUNCTION auth_uid() RETURNS UUID LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.user_id'')::uuid';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT USING (owner_id = auth_uid());
";
    let db = parse_schema(sql).expect("schema should parse");
    let translation = TranslatorBuilder::new()
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )
        .with_identity_cast("uuid")])
        .build()
        .translate(&db)
        .expect("translation should plan");

    let notes = translation.notes().to_vec();
    let json = serde_json::to_string(&notes).expect("notes serialize");
    let reloaded: Vec<rls2fga::types::TranslationNote> =
        serde_json::from_str(&json).expect("notes deserialize");
    assert_eq!(reloaded, notes);

    let outputs = translation.outputs().expect("nothing goes unhandled");
    let description = outputs
        .tuple_queries()
        .iter()
        .find_map(|query| query.description.as_ref())
        .expect("a query describes its records");
    let json = serde_json::to_string(&description).expect("description serializes");
    let reloaded: rls2fga::types::RecordDescription =
        serde_json::from_str(&json).expect("description deserializes");
    assert_eq!(&reloaded, description);
}

#[test]
fn invalid_custom_condition_parameter_names_are_rejected_by_json() {
    for name in ["", "tenant-id", "1tenant"] {
        let json = serde_json::json!({
            "key": "app.tenant_id",
            "kind": "scalar_attribute",
            "parameter": name,
        });
        let parsed = serde_json::from_value::<SessionAttribute>(json);
        assert!(parsed.is_err(), "{name:?} is not a CEL identifier");
    }
}

#[test]
fn custom_condition_parameter_builders_reject_invalid_names() {
    for name in ["", "tenant-id", "1tenant", "in"] {
        assert!(
            TranslatorBuilder::new()
                .with_request_time_parameter(name)
                .is_err(),
            "{name:?} must be rejected for request time"
        );
        assert!(
            SessionAttribute::setting("app.tenant_id", SessionAttributeKind::ScalarAttribute)
                .with_parameter(name)
                .is_err(),
            "{name:?} must be rejected for session attributes"
        );
    }
}
