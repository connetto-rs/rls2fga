//! Deployments the unit tests read schemas for.

use alloc::string::String;

use sqlparser::ast::DataType;

use crate::classifier::function_registry::{DeclaredSources, FunctionRegistry};
use crate::parser::sql_parser::{Deployment, JsonField, SessionSetting, SetPacking, SettingValue};

/// The role every test request logs in as.
pub(crate) const LOGIN_ROLE: &str = "app_login";

/// The one role every test request acts as.
pub(crate) const ACTING_ROLE: &str = "app_user";

/// The statements declaring [`LOGIN_ROLE`] and [`ACTING_ROLE`], for a schema a translator
/// resolves the deployment against.
pub(crate) const ROLES_SQL: &str = "CREATE ROLE app_login LOGIN NOINHERIT;
CREATE ROLE app_user NOLOGIN;
GRANT app_user TO app_login WITH INHERIT FALSE, SET TRUE;
";

/// A deployment logging in as [`LOGIN_ROLE`], acting as [`ACTING_ROLE`] and declaring
/// `settings`.
pub(crate) fn deployment(settings: impl IntoIterator<Item = SessionSetting>) -> Deployment {
    Deployment::new(LOGIN_ROLE, [ACTING_ROLE], settings).expect("a valid test deployment")
}

/// The deployment most unit tests read for, where `app.user_id`, `app.current_user_id`
/// and `request.jwt.claim.sub` are the caller, as text.
pub(crate) fn caller_deployment() -> Deployment {
    deployment(
        [
            "app.user_id",
            "app.current_user_id",
            "request.jwt.claim.sub",
        ]
        .map(caller),
    )
}

/// The setting `name` holding the caller's identity as text.
pub(crate) fn caller(name: &str) -> SessionSetting {
    typed_caller(name, DataType::Text)
}

/// The setting `name` holding the caller's identity as `data_type`.
pub(crate) fn typed_caller(name: &str, data_type: DataType) -> SessionSetting {
    SessionSetting::value(name, SettingValue::Caller(data_type)).expect("a custom setting name")
}

/// The setting `name` holding one text value.
pub(crate) fn scalar(name: &str) -> SessionSetting {
    SessionSetting::value(name, SettingValue::Scalar(DataType::Text))
        .expect("a custom setting name")
}

/// The setting `name` holding a set of text joined by `separator`.
pub(crate) fn delimited_set(name: &str, separator: &str) -> SessionSetting {
    SessionSetting::value(
        name,
        SettingValue::Set {
            element: DataType::Text,
            packing: SetPacking::Delimited(String::from(separator)),
        },
    )
    .expect("a custom setting name and a separator")
}

/// The setting `name` holding a JSON document whose field at `path` holds `value`.
pub(crate) fn json_field(name: &str, path: &[&str], value: SettingValue) -> SessionSetting {
    let field = JsonField::new(path.iter().copied(), value).expect("a field path");
    SessionSetting::json(name, [field]).expect("a custom setting name")
}

/// The sources `settings` declare, as the analyzers read them.
pub(crate) fn sources(settings: impl IntoIterator<Item = SessionSetting>) -> DeclaredSources {
    DeclaredSources::of(&deployment(settings))
}

/// A registry that has read [`deployment`] of `settings`, with no schema.
pub(crate) fn registry(settings: impl IntoIterator<Item = SessionSetting>) -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    registry.adopt(&deployment(settings));
    registry
}

/// A registry read for [`caller_deployment`], so a `current_setting` of a caller name
/// reads the caller and a role keyword reads the acting role's name.
pub(crate) fn caller_registry() -> FunctionRegistry {
    let mut registry = FunctionRegistry::new();
    registry.adopt(&caller_deployment());
    registry
}
