//! The deployments the suite translates for, the roles a request runs as and the session
//! settings its policies may read.

use std::collections::BTreeMap;

use rls2fga::parser::sql_parser::{
    self, Deployment, JsonField, ParserDB, SessionSetting, SetPacking, SettingValue,
};
use rls2fga::translator::TranslatorBuilder;
use sqlparser::ast::DataType;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// The role every test request logs in as.
pub(crate) const LOGIN_ROLE: &str = "app_login";

/// The one role every test request acts as.
pub(crate) const ACTING_ROLE: &str = "app_user";

/// The statements declaring [`LOGIN_ROLE`] and [`ACTING_ROLE`], which a schema needs
/// before a translator resolves a deployment against it.
pub(crate) const ROLES: &str = "CREATE ROLE app_login LOGIN NOINHERIT;
CREATE ROLE app_user NOLOGIN;
GRANT app_user TO app_login WITH INHERIT FALSE, SET TRUE;
";

/// The caller settings most of the suite reads, each holding the caller as text.
const CALLER_SETTINGS: [&str; 3] = [
    "app.user_id",
    "app.current_user_id",
    "request.jwt.claim.sub",
];

/// A deployment logging in as [`LOGIN_ROLE`], acting as [`ACTING_ROLE`], declaring
/// exactly `settings`.
pub(crate) fn deployment(settings: impl IntoIterator<Item = SessionSetting>) -> Deployment {
    Deployment::new(LOGIN_ROLE, [ACTING_ROLE], settings).expect("a valid test deployment")
}

/// The deployment most of the suite reads for, where `app.user_id`, `app.current_user_id`
/// and `request.jwt.claim.sub` hold the caller as text.
pub(crate) fn caller_deployment() -> Deployment {
    caller_deployment_with([])
}

/// [`caller_deployment`] with `settings` added, a setting named like one of its callers
/// replacing that caller.
pub(crate) fn caller_deployment_with(
    settings: impl IntoIterator<Item = SessionSetting>,
) -> Deployment {
    caller_deployment_acting_as(&[ACTING_ROLE], settings)
}

/// [`caller_deployment_with`] acting as `acting_roles` in place of [`ACTING_ROLE`].
pub(crate) fn caller_deployment_acting_as(
    acting_roles: &[&str],
    settings: impl IntoIterator<Item = SessionSetting>,
) -> Deployment {
    let mut declared: BTreeMap<String, SessionSetting> = CALLER_SETTINGS
        .into_iter()
        .map(|name| (name.to_string(), caller(name)))
        .collect();
    for setting in settings {
        declared.insert(setting.name().to_ascii_lowercase(), setting);
    }
    Deployment::new(
        LOGIN_ROLE,
        acting_roles.iter().copied(),
        declared.into_values(),
    )
    .expect("a valid test deployment")
}

/// A translator builder reading for [`caller_deployment`].
pub(crate) fn translator_builder() -> TranslatorBuilder {
    TranslatorBuilder::new(caller_deployment())
}

/// `sql` parsed after [`ROLES`], so a deployment of the suite's roles resolves against it.
pub(crate) fn db(sql: &str) -> ParserDB {
    sql_parser::parse_schema(&format!("{ROLES}{sql}")).expect("schema should parse")
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
    typed_scalar(name, DataType::Text)
}

/// The setting `name` holding one value of `data_type`.
pub(crate) fn typed_scalar(name: &str, data_type: DataType) -> SessionSetting {
    SessionSetting::value(name, SettingValue::Scalar(data_type)).expect("a custom setting name")
}

/// The setting `name` holding a set of text joined by `separator`.
pub(crate) fn delimited_set(name: &str, separator: &str) -> SessionSetting {
    SessionSetting::value(name, delimited(separator)).expect("a custom setting name")
}

/// A set of text joined by `separator`.
pub(crate) fn delimited(separator: &str) -> SettingValue {
    SettingValue::Set {
        element: DataType::Text,
        packing: SetPacking::Delimited(separator.to_string()),
    }
}

/// A set of text packed as a JSON array.
pub(crate) fn json_array() -> SettingValue {
    SettingValue::Set {
        element: DataType::Text,
        packing: SetPacking::JsonArray,
    }
}

/// The setting `name` holding a JSON document whose `fields` the policies read, each a
/// path and what it holds.
pub(crate) fn json_setting<const N: usize>(
    name: &str,
    fields: [(&[&str], SettingValue); N],
) -> SessionSetting {
    let fields = fields
        .into_iter()
        .map(|(path, value)| JsonField::new(path.iter().copied(), value).expect("a field path"));
    SessionSetting::json(name, fields).expect("a custom setting name and distinct fields")
}

/// One setting of a fixture's `deployment.json`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureSetting {
    /// The setting's name.
    setting: String,
    /// The JSON field path, absent for the whole setting.
    #[serde(default)]
    field: Vec<String>,
    /// The caller's identity, of this type.
    #[serde(default)]
    caller: Option<String>,
    /// One value, of this type.
    #[serde(default)]
    scalar: Option<String>,
    /// A set, of elements of this type.
    #[serde(default)]
    set: Option<String>,
    /// The delimiter a set is joined by.
    #[serde(default)]
    delimiter: Option<String>,
    /// Whether a set is packed as a JSON array.
    #[serde(default)]
    json_array: bool,
    /// Whether a request may leave the setting unset.
    #[serde(default)]
    may_be_unset: bool,
}

impl FixtureSetting {
    fn value(&self) -> SettingValue {
        let data_type = |name: &str| {
            Parser::new(&PostgreSqlDialect {})
                .try_with_sql(name)
                .and_then(|mut parser| parser.parse_data_type())
                .unwrap_or_else(|error| panic!("{name} is no data type: {error}"))
        };
        match (&self.caller, &self.scalar, &self.set) {
            (Some(caller), None, None) => SettingValue::Caller(data_type(caller)),
            (None, Some(scalar), None) => SettingValue::Scalar(data_type(scalar)),
            (None, None, Some(element)) => SettingValue::Set {
                element: data_type(element),
                packing: match (&self.delimiter, self.json_array) {
                    (Some(delimiter), false) => SetPacking::Delimited(delimiter.clone()),
                    (None, true) => SetPacking::JsonArray,
                    _ => panic!("{} needs exactly one packing", self.setting),
                },
            },
            _ => panic!(
                "{} needs exactly one of caller, scalar and set",
                self.setting
            ),
        }
    }
}

/// The settings `json` declares in the shape a fixture's `deployment.json` holds, one
/// entry per setting or JSON field, the fields of one setting gathered into it.
pub(crate) fn settings_from_json(json: &str) -> Vec<SessionSetting> {
    let entries: Vec<FixtureSetting> =
        serde_json::from_str(json).expect("the deployment settings should parse");
    let mut settings: Vec<SessionSetting> = Vec::new();
    let mut documents: BTreeMap<String, (Vec<JsonField>, bool)> = BTreeMap::new();
    for entry in &entries {
        if entry.field.is_empty() {
            let setting = SessionSetting::value(&entry.setting, entry.value())
                .expect("a custom setting name");
            settings.push(if entry.may_be_unset {
                setting.may_be_unset()
            } else {
                setting
            });
        } else {
            let document = documents.entry(entry.setting.clone()).or_default();
            document
                .0
                .push(JsonField::new(entry.field.clone(), entry.value()).expect("a field path"));
            document.1 |= entry.may_be_unset;
        }
    }
    for (name, (fields, may_be_unset)) in documents {
        let setting = SessionSetting::json(name, fields).expect("a JSON setting");
        settings.push(if may_be_unset {
            setting.may_be_unset()
        } else {
            setting
        });
    }
    settings
}

/// The deployment a fixture is read for: [`caller_deployment_with`] the settings its
/// `deployment.json` declares, none when it has no such file.
pub(crate) fn fixture_deployment(fixture: &str) -> Deployment {
    let path = super::fixture_dir(fixture).join("deployment.json");
    let settings = std::fs::read_to_string(path)
        .map(|json| settings_from_json(&json))
        .unwrap_or_default();
    caller_deployment_with(settings)
}
