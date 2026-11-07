//! The translator every schema pasted into the app runs through.

use rls2fga::classifier::function_registry::RegistryLoadError;
use rls2fga::parser::sql_parser::{Deployment, SessionSetting, SettingValue};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use sqlparser::ast::DataType;

/// The session setting the example schemas read the caller from.
pub const CALLER_SETTING: &str = "app.current_user_id";

/// The role every request logs in as.
pub const LOGIN_ROLE: &str = "app_login";

/// The role every request acts as.
pub const ACTING_ROLE: &str = "app_user";

/// The roles the app's deployment runs as, read before every pasted schema so the
/// deployment resolves against it.
pub const ROLES: &str = "CREATE ROLE app_login LOGIN NOINHERIT;
CREATE ROLE app_user NOLOGIN;
GRANT app_user TO app_login WITH INHERIT FALSE, SET TRUE;
";

/// What the role-threshold example's `get_owner_role` means, which no schema can say.
pub const REGISTRY: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id",
    "team_membership": {"table": "team_members", "user_col": "user_id", "team_col": "team_id"}
  }
}"#;

/// The deployment the app translates for, whose requests log in as [`LOGIN_ROLE`], act
/// as [`ACTING_ROLE`], and carry the caller in [`CALLER_SETTING`].
///
/// The examples cast the caller to `uuid`, so the setting holds a `uuid`, which promises
/// that every request sends it in canonical form.
#[must_use]
pub fn deployment() -> Deployment {
    let caller = SessionSetting::value(CALLER_SETTING, SettingValue::Caller(DataType::Uuid))
        .expect("a custom setting name");
    Deployment::new(LOGIN_ROLE, [ACTING_ROLE], [caller]).expect("one acting role")
}

/// The translator at `level`.
///
/// # Errors
///
/// Returns [`RegistryLoadError`] when [`REGISTRY`] is not a registry payload.
pub fn translator(level: ConfidenceLevel) -> Result<Translator, RegistryLoadError> {
    Ok(TranslatorBuilder::new(deployment())
        .with_min_confidence(level)
        .with_registry_json(REGISTRY)?
        .build())
}
