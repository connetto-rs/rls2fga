//! Functions a policy compares with role names, read by the bodies the schema gives them.

use rls2fga::classifier::patterns::{
    CallerScalarEqualsConstant, ConstantBool, FallbackScalarEqualsConstant, PatternClass,
    UnclassifiedExpr,
};
use rls2fga::types::ConfidenceLevel;
use sqlparser::ast::DataType;

use crate::support;
use crate::support::deployment::{self, json_setting, typed_scalar};
use rls2fga::parser::sql_parser::{SessionSetting, SettingValue};

/// The two acting roles the cases below run as.
const ACTING_ROLES: &str = "CREATE ROLE reader; CREATE ROLE writer;";

/// The registry declaring `auth.role` a role accessor.
const DECLARED: &str = r#"{"auth.role": {"kind": "role_accessor"}}"#;

/// Supabase's `auth.role()` body, a fallback across two settings.
const SUPABASE_BODY: &str = "SELECT coalesce(nullif(current_setting('request.jwt.claim.role', true), ''), (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'))::text";

/// `auth.role()` returning `body`.
fn accessor(body: &str) -> String {
    format!(
        "CREATE SCHEMA auth;
CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $f${body}$f$;
"
    )
}

/// A table whose one read policy is `using`.
fn docs(using: &str) -> String {
    format!(
        "CREATE TABLE docs(id INT PRIMARY KEY);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT USING ({using});
"
    )
}

/// The pattern each acting role reads the read policy of `sql` as.
fn read_per_role(
    sql: &str,
    registry_json: Option<&str>,
    acting_roles: &[&str],
) -> Vec<(String, PatternClass)> {
    read_patterns(
        sql,
        registry_json,
        acting_roles,
        &[typed_scalar("request.jwt.claim.role", DataType::Text)],
    )
}

/// The pattern each acting role reads the read policy of `sql` as, for the deployment's
/// `settings`.
fn read_patterns(
    sql: &str,
    registry_json: Option<&str>,
    acting_roles: &[&str],
    settings: &[SessionSetting],
) -> Vec<(String, PatternClass)> {
    let (classified, _, _) = support::classify_with(
        &format!("{ACTING_ROLES}{sql}"),
        registry_json,
        &deployment::caller_deployment_acting_as(acting_roles, settings.iter().cloned()),
    );
    classified
        .iter()
        .map(|policy| {
            (
                policy
                    .acting_role()
                    .expect("classified for an acting role")
                    .to_string(),
                policy
                    .using_classification()
                    .expect("the policy has a USING clause")
                    .pattern
                    .clone(),
            )
        })
        .collect()
}

/// The constant each acting role reads the read policy of `sql` as.
fn constants(sql: &str, registry_json: Option<&str>) -> Vec<(String, bool)> {
    read_per_role(sql, registry_json, &["reader", "writer"])
        .into_iter()
        .map(|(role, pattern)| {
            let PatternClass::P10ConstantBool(ConstantBool { value }) = pattern else {
                panic!("the comparison folds to a constant, got {pattern:?}");
            };
            (role, value)
        })
        .collect()
}

/// The reason the one acting role refuses the read policy of `sql` with.
fn refusal(sql: &str, registry_json: Option<&str>) -> String {
    let [(_, pattern)] = read_per_role(sql, registry_json, &["reader"])
        .try_into()
        .expect("one acting role");
    let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = pattern else {
        panic!("the policy is refused, got {pattern:?}");
    };
    reason
}

/// A body returning `current_user` names the acting role, so a comparison of the call
/// with a role's name is true for that role and false for every other, in either operand
/// order and as a list, and a registry declaration yields to the body.
#[test]
fn an_accessor_returning_current_user_is_a_constant_per_acting_role() {
    for using in [
        "auth.role() = 'reader'",
        "'reader' = auth.role()",
        "auth.role() IN ('reader', 'nobody')",
    ] {
        for registry_json in [None, Some(DECLARED)] {
            assert_eq!(
                constants(
                    &format!("{}{}", accessor("SELECT current_user"), docs(using)),
                    registry_json
                ),
                [("reader".to_string(), true), ("writer".to_string(), false)],
                "{using} with {registry_json:?}"
            );
        }
    }
}

/// A body returning `session_user` names the role a request logs in as, the same for
/// every acting role.
#[test]
fn an_accessor_returning_session_user_names_the_login_role() {
    assert_eq!(
        constants(
            &format!(
                "{}{}",
                accessor("SELECT session_user"),
                docs(&format!("auth.role() = '{}'", deployment::LOGIN_ROLE))
            ),
            None
        ),
        [("reader".to_string(), true), ("writer".to_string(), true)]
    );
}

/// A declared role accessor whose body reads one declared setting is that setting, so the
/// comparison is a request gate on it, and no role scope is minted.
#[test]
fn a_declared_accessor_reading_a_setting_is_a_request_gate() {
    let sql = format!(
        "{}{}",
        accessor("SELECT current_setting('request.jwt.claim.role', true)"),
        docs("auth.role() = 'authenticated'")
    );
    let [(_, pattern)] = read_per_role(&sql, Some(DECLARED), &["reader"])
        .try_into()
        .expect("one acting role");
    assert!(
        matches!(
            &pattern,
            PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant { value, .. })
                if value == "authenticated"
        ),
        "the call is the declared setting, got {pattern:?}"
    );

    let (classified, db, registry) = support::classify_with(
        &format!("{ACTING_ROLES}{sql}"),
        Some(DECLARED),
        &deployment::caller_deployment_acting_as(
            &["reader"],
            [typed_scalar("request.jwt.claim.role", DataType::Text)],
        ),
    );
    let model = support::plan_at(classified, &db, &registry, ConfidenceLevel::B).model();
    assert!(
        !model.contains("pg_role_scope") && !model.contains("scope_"),
        "a role accessor mints no role scope:\n{model}"
    );
}

/// A declared role accessor is read by its body, so one the schema does not define is
/// refused for that reason.
#[test]
fn a_declared_accessor_without_a_body_is_refused() {
    for using in [
        "auth.role() = 'authenticated'",
        "auth.role() IN ('authenticated', 'admin')",
    ] {
        let reason = refusal(&docs(using), Some(DECLARED));
        assert!(
            reason.contains("'auth.role' is declared a role accessor")
                && reason.contains("the schema does not define it"),
            "{using}: {reason}"
        );
    }
}

/// The `Supabase` body reads a `coalesce`/`nullif` fallback across two settings, so with
/// the sources the body reads declared the call is the request gate on the value the
/// first source that is set hands over, and with a source the deployment does not declare
/// the call is still blamed for its body, with or without a registry declaration, and
/// never as a body the schema lacks.
#[test]
fn an_accessor_body_of_neither_shape_is_blamed_for_its_body() {
    let sql = format!(
        "{}{}",
        accessor(SUPABASE_BODY),
        docs("auth.role() = 'authenticated'")
    );
    for registry_json in [None, Some(DECLARED)] {
        let reason = refusal(&sql, registry_json);
        assert!(
            reason.contains("The body of 'auth.role'") && !reason.contains("body not available"),
            "{registry_json:?}: {reason}"
        );
    }
    let settings = [
        typed_scalar("request.jwt.claim.role", DataType::Text),
        json_setting(
            "request.jwt.claims",
            [(&["role"], SettingValue::Scalar(DataType::Text))],
        ),
    ];
    let [(_, pattern)] = read_patterns(&sql, Some(DECLARED), &["reader"], &settings)
        .try_into()
        .expect("one acting role");
    assert!(
        matches!(
            &pattern,
            PatternClass::P23FallbackScalarEqualsConstant(
                FallbackScalarEqualsConstant { value, .. }
            ) if value == "authenticated"
        ),
        "the body reads the fallback it spells, got {pattern:?}"
    );
}

#[cfg(all(not(target_os = "windows"), feature = "client"))]
mod parity {
    use rls2fga::types::ActionStatement;
    use sqlparser::ast::DataType;

    use super::{accessor, docs, ACTING_ROLES, DECLARED};
    use crate::support;
    use crate::support::deployment::typed_scalar;
    use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

    /// A role accessor returning `current_user` admits every row to the role a comparison
    /// names and none to the other, in `PostgreSQL` and in the model alike.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn an_accessor_returning_current_user_admits_only_the_named_role() {
        let cluster = Cluster::start().await;
        let case = ParityCase::reading(
            "role-accessor-current-user",
            &format!(
                "{}{}",
                accessor("SELECT current_user"),
                docs("auth.role() = 'reader'")
            ),
            &[
                "INSERT INTO docs VALUES (1), (2)",
                &format!(
                    "{ACTING_ROLES} GRANT SELECT ON docs TO reader, writer;
                     GRANT USAGE ON SCHEMA auth TO reader, writer"
                ),
            ],
            vec![
                Principal::as_role("alice", "reader"),
                Principal::as_role("bob", "writer"),
            ],
        );
        let run = support::parity::run(&cluster, &case).await;
        assert_postgres(
            &case,
            &run,
            "alice",
            "docs:1",
            ActionStatement::Select,
            true,
        );
        assert_postgres(&case, &run, "bob", "docs:1", ActionStatement::Select, false);
        assert_agrees(&case, &run);
    }

    /// A declared role accessor reading one setting admits the requests whose setting the
    /// comparison names, in `PostgreSQL` and in the model alike.
    #[tokio::test]
    #[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
    async fn a_declared_accessor_reading_a_setting_agrees_with_postgres() {
        let cluster = Cluster::start().await;
        let principal = |subject: &str, role: &str| {
            Principal::with_setting(subject, "reader", "request.jwt.claim.role", role)
                .with_context(serde_json::json!({ "request_jwt_claim_role": role }))
        };
        let case = ParityCase::reading(
            "role-accessor-setting",
            &format!(
                "{}{}",
                accessor("SELECT current_setting('request.jwt.claim.role', true)"),
                docs("auth.role() = 'authenticated'")
            ),
            &[
                "INSERT INTO docs VALUES (1), (2)",
                "CREATE ROLE reader; GRANT SELECT ON docs TO reader;
                 GRANT USAGE ON SCHEMA auth TO reader",
            ],
            vec![
                principal("alice", "authenticated"),
                principal("bob", "anon"),
            ],
        )
        .with_registry(DECLARED)
        .with_settings([typed_scalar("request.jwt.claim.role", DataType::Text)]);
        let run = support::parity::run(&cluster, &case).await;
        assert_postgres(
            &case,
            &run,
            "alice",
            "docs:1",
            ActionStatement::Select,
            true,
        );
        assert_postgres(&case, &run, "bob", "docs:1", ActionStatement::Select, false);
        assert_agrees(&case, &run);
    }
}
