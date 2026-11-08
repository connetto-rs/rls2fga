#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};

use crate::classifier::recognizers::row_valued_set;
use crate::parser::expr::cast_type_name;
use crate::parser::function_analyzer::{
    body_returns_acting_role, body_setting_key, body_single_projection, normalize_setting_key,
    renamed_caller_body, FunctionSemantic,
};
use crate::parser::names::stored_relation_name;
use crate::parser::sql_parser::{
    DatabaseLike, Deployment, FunctionLike, SessionSetting, SetPacking, SettingContent,
    SettingPresence, SettingValue,
};
use crate::types::ConditionParameterName;
use sql_traits::structs::{IdentifierCase, TargetName};
use sqlparser::ast::FunctionSecurity;

/// One value a policy may read from the request as the deployment declares it, a whole
/// custom setting or one field of a setting holding a JSON document.
///
/// Built only from a [`Deployment`], so the declaration a policy is read against is the
/// one every other consumer of that deployment reads. A function whose body reads the
/// setting resolves to the same source, so the inline and the wrapped spelling cannot
/// disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSource {
    key: String,
    path: Vec<String>,
    value: SettingValue,
    presence: SettingPresence,
    parameter: ConditionParameterName,
}

impl DeclaredSource {
    fn new(setting: &SessionSetting, path: Vec<String>, value: SettingValue) -> Self {
        let key = normalize_setting_key(setting.name());
        let parameter = parameter_name(&key, &path);
        Self {
            key,
            path,
            value,
            presence: setting.presence(),
            parameter,
        }
    }

    /// The `current_setting` name this source reads, lower case as `PostgreSQL` compares
    /// it.
    #[must_use]
    pub fn setting_key(&self) -> &str {
        &self.key
    }

    /// The JSON field path taken out of the setting, empty for the whole value.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// What the source holds, as the deployment declares it.
    #[must_use]
    pub fn value(&self) -> &SettingValue {
        &self.value
    }

    /// Whether every request sets the setting.
    #[must_use]
    pub fn presence(&self) -> SettingPresence {
        self.presence
    }

    /// The condition parameter the caller supplies, the source spelled as an identifier.
    #[must_use]
    pub fn request_parameter(&self) -> &str {
        self.parameter.as_str()
    }

    pub(crate) fn condition_parameter(&self) -> &ConditionParameterName {
        &self.parameter
    }

    /// Whether the source is the caller's identity.
    pub(crate) fn is_caller(&self) -> bool {
        matches!(self.value, SettingValue::Caller(_))
    }

    /// Whether the source is one value the request carries, other than the caller.
    pub(crate) fn is_scalar(&self) -> bool {
        matches!(self.value, SettingValue::Scalar(_))
    }

    /// How a set's elements are packed, or `None` for a single value.
    pub(crate) fn packing(&self) -> Option<&SetPacking> {
        match &self.value {
            SettingValue::Set { packing, .. } => Some(packing),
            SettingValue::Caller(_) | SettingValue::Scalar(_) => None,
        }
    }

    /// The delimiter `string_to_array` splits the set on, absent for a single value and
    /// for a JSON array.
    pub(crate) fn separator(&self) -> Option<&str> {
        match self.packing()? {
            SetPacking::Delimited(separator) => Some(separator),
            SetPacking::JsonArray => None,
        }
    }

    /// The type the value, or each element of a set, arrives canonical for, spelled as a
    /// cast names it. A cast to it renames nothing.
    pub(crate) fn canonical_type(&self) -> String {
        let (SettingValue::Caller(data_type)
        | SettingValue::Scalar(data_type)
        | SettingValue::Set {
            element: data_type, ..
        }) = &self.value;
        cast_type_name(data_type)
    }

    /// Whether a request may leave the setting unset, in which state `PostgreSQL` reads
    /// it as `NULL` or as `''` depending on the connection's history.
    pub(crate) fn may_be_unset(&self) -> bool {
        self.presence == SettingPresence::MayBeUnset
    }

    /// How the source is declared, for a reason naming a read that does not match it.
    pub(crate) fn declared_as(&self) -> String {
        match &self.value {
            SettingValue::Caller(_) => "the caller".to_string(),
            SettingValue::Scalar(_) => "one value".to_string(),
            SettingValue::Set {
                packing: SetPacking::Delimited(separator),
                ..
            } => format!("a set joined by '{separator}'"),
            SettingValue::Set {
                packing: SetPacking::JsonArray,
                ..
            } => "a set packed as a JSON array".to_string(),
        }
    }
}

/// A source spelled as an identifier, since a condition parameter name shares a namespace
/// with `CEL` identifiers and a setting name carries dots.
fn parameter_name(key: &str, path: &[String]) -> ConditionParameterName {
    let mut source = String::with_capacity(key.len());
    for segment in core::iter::once(key).chain(path.iter().map(String::as_str)) {
        if !source.is_empty() {
            source.push('_');
        }
        source.push_str(segment);
    }
    ConditionParameterName::derived(&source)
}

/// Every source a deployment declares, keyed on the setting and the field path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DeclaredSources(BTreeMap<(String, Vec<String>), DeclaredSource>);

impl DeclaredSources {
    /// The sources `deployment` declares, each whole setting and each field of a JSON
    /// one.
    pub(crate) fn of(deployment: &Deployment) -> Self {
        let mut sources = BTreeMap::new();
        for setting in deployment.settings() {
            let mut declare = |path: &[String], value: &SettingValue| {
                let source = DeclaredSource::new(setting, path.to_vec(), value.clone());
                sources.insert((source.key.clone(), source.path.clone()), source);
            };
            match setting.content() {
                SettingContent::Value(value) => declare(&[], value),
                SettingContent::Json(fields) => {
                    for field in fields {
                        declare(field.path(), field.value());
                    }
                }
            }
        }
        Self(sources)
    }

    /// The source at `key` and `path`, the key compared without case.
    pub(crate) fn get(&self, key: &str, path: &[String]) -> Option<&DeclaredSource> {
        self.0.get(&(normalize_setting_key(key), path.to_vec()))
    }

    /// The source at `key` and `path`, when it is the caller.
    pub(crate) fn caller(&self, key: &str, path: &[String]) -> Option<&DeclaredSource> {
        self.get(key, path).filter(|source| source.is_caller())
    }

    /// Whether `key` is declared at all, as a whole value or through a field.
    pub(crate) fn declares_key(&self, key: &str) -> bool {
        let key = normalize_setting_key(key);
        self.0.keys().any(|(declared, _)| *declared == key)
    }

    /// Every source, ordered by setting and field path.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &DeclaredSource> {
        self.0.values()
    }
}

/// Why a function registry JSON payload was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryLoadError {
    /// The payload is not the JSON object of function semantics the registry expects.
    #[error("Invalid function registry JSON: {0}")]
    InvalidJson(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FunctionKey(String);

impl FunctionKey {
    /// The key a written call or registration spells.
    ///
    /// A name the grammar refuses reaches no declaration, and its own text keeps it
    /// distinct from every readable key.
    fn parse(name: &str) -> Self {
        match crate::parser::names::parse_target(name) {
            Some(target) => Self::from_target(&target),
            None => Self::unqualified(name.trim(), true),
        }
    }

    fn from_target(target: &TargetName<'_>) -> Self {
        match target.schema() {
            Some(schema) => Self::qualified(
                schema,
                target.schema_is_quoted(),
                target.name(),
                target.name_is_quoted(),
            ),
            None => Self::unqualified(target.name(), target.name_is_quoted()),
        }
    }

    fn qualified(schema: &str, schema_quoted: bool, name: &str, name_quoted: bool) -> Self {
        let mut key = String::with_capacity(schema.len() + name.len() + 3);
        key.push('q');
        key.push('\0');
        Self::push_stored_identifier(&mut key, schema, schema_quoted);
        key.push('\0');
        Self::push_stored_identifier(&mut key, name, name_quoted);
        Self(key)
    }

    fn unqualified(name: &str, quoted: bool) -> Self {
        let mut key = String::with_capacity(name.len() + 2);
        key.push('u');
        key.push('\0');
        Self::push_stored_identifier(&mut key, name, quoted);
        Self(key)
    }

    fn push_stored_identifier(key: &mut String, identifier: &str, quoted: bool) {
        if quoted {
            key.push_str(identifier);
        } else {
            key.extend(identifier.chars().map(|ch| ch.to_ascii_lowercase()));
        }
    }

    fn schema(&self) -> Option<&str> {
        self.0
            .strip_prefix("q\0")?
            .split_once('\0')
            .map(|(schema, _)| schema)
    }

    fn name(&self) -> &str {
        self.0
            .rsplit_once('\0')
            .map_or(self.0.as_str(), |(_, name)| name)
    }

    fn display(&self) -> String {
        let mut display = String::new();
        if let Some(schema) = self.schema() {
            Self::push_display_identifier(&mut display, schema);
            display.push('.');
        }
        Self::push_display_identifier(&mut display, self.name());
        display
    }

    fn push_display_identifier(display: &mut String, identifier: &str) {
        let mut chars = identifier.chars();
        let unquoted = chars
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first == '_')
            && chars.all(|ch| {
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '$')
            });
        if unquoted {
            display.push_str(identifier);
            return;
        }
        display.push('"');
        for ch in identifier.chars() {
            if ch == '"' {
                display.push('"');
            }
            display.push(ch);
        }
        display.push('"');
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::borrow::Borrow<str> for FunctionKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// Registry of known function semantics, loaded from JSON or analyzed from bodies.
#[derive(Debug, Clone)]
pub struct FunctionRegistry {
    pub(crate) functions: BTreeMap<FunctionKey, FunctionSemantic>,
    function_names: BTreeMap<FunctionKey, String>,
    function_resolution: BTreeMap<FunctionKey, FunctionKey>,
    /// Columns confirmed as public flags. Only these reach confidence A, so an
    /// implicit wildcard grant always surfaces for review.
    pub(crate) public_flag_columns: BTreeSet<String>,
    /// Functions whose body describes a caller accessor their security mode
    /// invalidates, kept so the report can name the cause.
    owner_bound_accessors: BTreeMap<FunctionKey, String>,
    /// Functions whose body reads the caller through a cast that can rename it, with the
    /// reason the report gives.
    renamed_accessors: BTreeMap<FunctionKey, String>,
    /// The deployment the schema is read for, set by [`FunctionRegistry::enrich_from_schema`].
    deployment: Option<Deployment>,
    /// Request-scoped sources the deployment declares, keyed on the setting and the field
    /// path taken out of it.
    sources: DeclaredSources,
}

impl FunctionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            functions: BTreeMap::new(),
            function_names: BTreeMap::new(),
            function_resolution: BTreeMap::new(),
            public_flag_columns: BTreeSet::new(),
            owner_bound_accessors: BTreeMap::new(),
            renamed_accessors: BTreeMap::new(),
            deployment: None,
            sources: DeclaredSources::default(),
        }
    }

    /// Functions that would identify the caller but run as their owner, so
    /// `current_user` inside them is the owner's for every caller.
    pub fn owner_bound_accessors(&self) -> impl Iterator<Item = &str> {
        self.owner_bound_accessors.values().map(String::as_str)
    }

    pub(crate) fn is_owner_bound_accessor(&self, name: &str) -> bool {
        let key = FunctionKey::parse(name);
        let resolved = self.function_resolution.get(&key).unwrap_or(&key);
        self.owner_bound_accessors.contains_key(resolved.as_str())
    }

    /// Why the function `name` reads the caller yet is no accessor, when a cast in its body
    /// can rename what it returns.
    pub(crate) fn renamed_accessor(&self, name: &str) -> Option<&str> {
        let key = FunctionKey::parse(name);
        let resolved = self.function_resolution.get(&key).unwrap_or(&key);
        self.renamed_accessors
            .get(resolved.as_str())
            .map(String::as_str)
    }

    /// Confirm a column as a public flag, lifting its `P6BooleanFlag` to confidence A.
    ///
    /// Confirmed by the name `PostgreSQL` stores, since what the confirmation buys is a
    /// wildcard grant and `"Public"` is not the column `public`.
    pub fn register_public_flag_column(&mut self, column: impl Into<String>) {
        self.public_flag_columns
            .insert(stored_relation_name(&column.into()));
    }

    /// True when `column`, named as the schema stores it, is an explicitly registered
    /// public-flag column.
    pub(crate) fn is_confirmed_public_flag_column(&self, column: &str) -> bool {
        self.public_flag_columns.contains(column)
    }

    /// Declare `SECURITY DEFINER` helpers whose returned sets translate to the grants
    /// their bodies read, each named as a call spells it (`authz.projects_with`).
    ///
    /// Declaring one asserts that every role a request runs as may execute it. A helper
    /// another declared helper calls has to be declared too, or the caller is refused.
    pub fn declare_helpers<I, S>(&mut self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for name in names {
            let name = name.as_ref();
            let key = FunctionKey::parse(name);
            self.function_names.insert(key.clone(), name.to_string());
            self.functions
                .insert(key, FunctionSemantic::DeclaredHelper {});
        }
    }

    /// True when `function` is a declared helper.
    pub(crate) fn declares_helper<F: FunctionLike>(&self, function: &F) -> bool {
        matches!(
            self.get_target(&function.target_name()),
            Some(FunctionSemantic::DeclaredHelper {})
        )
    }

    /// The deployment the schema is read for, which answers what a declared helper
    /// returns. `None` until [`FunctionRegistry::enrich_from_schema`] has run.
    pub(crate) fn deployment(&self) -> Option<&Deployment> {
        self.deployment.as_ref()
    }

    /// The source at `key` and `path`, if the deployment declares one.
    pub(crate) fn declared_source(&self, key: &str, path: &[String]) -> Option<&DeclaredSource> {
        self.sources.get(key, path)
    }

    /// The deployment's sources, as the classifier reads them.
    pub(crate) fn sources(&self) -> &DeclaredSources {
        &self.sources
    }

    /// Load function semantics from a JSON string.
    pub fn load_from_json(&mut self, json: &str) -> Result<(), RegistryLoadError> {
        let parsed: BTreeMap<String, FunctionSemantic> = serde_json::from_str(json)
            .map_err(|e| RegistryLoadError::InvalidJson(e.to_string()))?;
        // Registry takes precedence over analyzed functions
        for (name, semantic) in parsed {
            let key = FunctionKey::parse(&name);
            self.function_names.insert(key.clone(), name);
            self.functions.insert(key, semantic);
        }
        Ok(())
    }

    /// Get the semantic for a function by name.
    pub fn get(&self, name: &str) -> Option<&FunctionSemantic> {
        let key = FunctionKey::parse(name);
        self.get_by_key(&key)
    }

    pub(crate) fn resolved_name(&self, name: &str) -> String {
        let key = FunctionKey::parse(name);
        let resolved = self.function_resolution.get(&key).unwrap_or(&key);
        self.function_names
            .get(resolved)
            .cloned()
            .unwrap_or_else(|| resolved.display())
    }

    fn get_by_key(&self, key: &FunctionKey) -> Option<&FunctionSemantic> {
        let resolved = self.function_resolution.get(key).unwrap_or(key);
        self.functions.get(resolved.as_str())
    }

    fn target_key(&self, target: &TargetName<'_>) -> FunctionKey {
        let key = FunctionKey::from_target(target);
        self.function_resolution.get(&key).cloned().unwrap_or(key)
    }

    fn get_target(&self, target: &TargetName<'_>) -> Option<&FunctionSemantic> {
        let key = self.target_key(target);
        self.functions.get(key.as_str())
    }

    /// Register a function semantic (analyzed results, won't overwrite registry entries).
    pub fn register_if_absent(&mut self, name: &str, semantic: &FunctionSemantic) {
        let key = FunctionKey::parse(name);
        self.function_names
            .entry(key.clone())
            .or_insert_with(|| name.to_string());
        self.functions
            .entry(key)
            .or_insert_with(|| semantic.clone());
    }

    fn register_target_if_absent(&mut self, target: &TargetName<'_>, semantic: &FunctionSemantic) {
        let key = self.target_key(target);
        self.function_names
            .entry(key.clone())
            .or_insert_with(|| key.display());
        self.functions
            .entry(key)
            .or_insert_with(|| semantic.clone());
    }

    /// Memoize what each written spelling denotes, so a lookup needs no catalog.
    ///
    /// The search path walk itself belongs to the catalog, which resolves an
    /// unqualified call and reports an ambiguous one rather than picking.
    fn prepare_function_resolution<DB: DatabaseLike>(&mut self, db: &DB) {
        self.function_resolution.clear();
        let canonical_key = |target: &TargetName<'_>| match target.schema() {
            Some(_) => FunctionKey::from_target(target),
            None => db.search_path().next().map_or_else(
                || FunctionKey::from_target(target),
                |(schema, quoted)| {
                    FunctionKey::qualified(schema, quoted, target.name(), target.name_is_quoted())
                },
            ),
        };
        for function in db.functions() {
            let target = function.target_name();
            let canonical = canonical_key(&target);
            self.function_resolution
                .insert(FunctionKey::from_target(&target), canonical.clone());
            self.function_resolution
                .insert(canonical.clone(), canonical.clone());

            let call = TargetName::new(target.name(), target.name_is_quoted());
            let wins = db
                .resolve_target_function(call, IdentifierCase::AsWritten)
                .ok()
                .flatten()
                .is_some_and(|winner| canonical_key(&winner.target_name()) == canonical);
            if wins {
                self.function_resolution.insert(
                    FunctionKey::unqualified(target.name(), target.name_is_quoted()),
                    canonical,
                );
            }
        }

        let configured = core::mem::take(&mut self.functions);
        let mut names = core::mem::take(&mut self.function_names);
        for (key, semantic) in configured {
            let resolved = self
                .function_resolution
                .get(&key)
                .cloned()
                .unwrap_or(key.clone());
            let name = names.remove(&key).unwrap_or_else(|| key.display());
            self.function_names.entry(resolved.clone()).or_insert(name);
            self.functions.entry(resolved).or_insert(semantic);
        }
    }

    /// Check if a function is a known role-threshold function.
    pub fn is_role_threshold(&self, name: &str) -> bool {
        matches!(self.get(name), Some(FunctionSemantic::RoleThreshold { .. }))
    }

    /// Check if a function is a current-user accessor.
    pub fn is_current_user_accessor(&self, name: &str) -> bool {
        matches!(
            self.get(name),
            Some(FunctionSemantic::CurrentUserAccessor { .. })
        )
    }

    /// Check if a function is a role-name accessor (returns the current user's role as a string).
    pub fn is_role_accessor(&self, name: &str) -> bool {
        matches!(self.get(name), Some(FunctionSemantic::RoleAccessor { .. }))
    }

    /// Read the sources `deployment` declares, which every later lookup answers from.
    pub(crate) fn adopt(&mut self, deployment: &Deployment) {
        self.sources = DeclaredSources::of(deployment);
        self.deployment = Some(deployment.clone());
    }

    /// Read `db` for `deployment` by adopting the sources it declares and then inferring
    /// the semantics of the schema's function bodies. Explicitly provided registry entries
    /// take precedence.
    pub fn enrich_from_schema<DB: DatabaseLike>(&mut self, db: &DB, deployment: &Deployment) {
        self.adopt(deployment);
        self.prepare_function_resolution(db);
        for function in db.functions() {
            let Some(body) = function.body() else {
                continue;
            };
            let Some(language) = function.stored_language() else {
                continue;
            };
            let target = function.target_name();
            // A set of identities is not one identity, so a set returning function is
            // never an accessor. It is the only thing that can be a set reader, which
            // the pass below mints once every wrapper it might read is registered.
            if function.returns_set() {
                continue;
            }
            let return_type = function
                .return_type_name(db)
                .map(|name| name.to_string())
                .unwrap_or_default();
            if let Some(semantic) = FunctionSemantic::analyze_body_with_sources(
                body,
                &return_type,
                &language,
                &self.sources,
            ) {
                self.register_target_if_absent(&target, &semantic);
            } else if self.get_target(&target).is_none()
                && matches!(function.security_mode(), FunctionSecurity::Definer)
                && body_returns_acting_role(body, &return_type, &language)
            {
                // Inside a definer body the acting role is the owner, the same name for
                // every caller.
                let target_key = self.target_key(&target);
                self.owner_bound_accessors
                    .entry(target_key)
                    .or_insert_with(|| target.to_string());
            } else if self.get_target(&target).is_none() {
                // A wrapper around a declared source is that source, so the inline and
                // the wrapped spelling reach one declaration and cannot disagree.
                if let Some(key) = body_setting_key(body)
                    .map(|(key, casts)| (normalize_setting_key(&key), casts.without_json_parse()))
                    .filter(|(key, casts)| {
                        self.sources.declares_key(key)
                            && casts
                                .renaming(
                                    self.sources
                                        .get(key, &[])
                                        .map(DeclaredSource::canonical_type)
                                        .as_deref(),
                                )
                                .is_none()
                    })
                    .map(|(key, _)| key)
                {
                    self.register_target_if_absent(
                        &target,
                        &FunctionSemantic::SettingReader { key },
                    );
                } else if let Some(reason) =
                    renamed_caller_body(body, &return_type, &language, &self.sources)
                {
                    let target_key = self.target_key(&target);
                    self.renamed_accessors.entry(target_key).or_insert(reason);
                }
            }
        }

        // A set returning wrapper whose whole body expands a declared setting is a
        // spelling of that setting. Minted after the loop above, so a body reading
        // another declared wrapper resolves rather than falling closed on ordering.
        let mut set_readers = Vec::new();
        for function in db.functions() {
            let target = function.target_name();
            if !function.returns_set() || self.get_target(&target).is_some() {
                continue;
            }
            let Some(source) = function
                .body()
                .and_then(body_single_projection)
                .and_then(|expr| row_valued_set(&expr, self))
                .filter(|source| {
                    self.sources
                        .get(&source.key, &source.path)
                        .is_some_and(|declared| source.reads_as(declared))
                })
            else {
                continue;
            };
            set_readers.push((target, source));
        }
        for (target, source) in set_readers {
            self.register_target_if_absent(
                &target,
                &FunctionSemantic::SetReader {
                    key: normalize_setting_key(&source.key),
                    path: source.path,
                    separator: source.separator,
                },
            );
        }
    }
}

impl Default for FunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;
    use crate::test_support::{caller, caller_deployment, deployment, sources};

    #[test]
    fn load_from_json_reports_invalid_payload() {
        let mut registry = FunctionRegistry::new();
        let err = registry
            .load_from_json("{not-valid-json")
            .expect_err("invalid json should fail");
        assert!(matches!(err, RegistryLoadError::InvalidJson(_)));
        assert!(err
            .to_string()
            .starts_with("Invalid function registry JSON"));
    }

    #[test]
    fn enrich_from_schema_infers_known_semantics_only() {
        let sql = r"
CREATE FUNCTION current_tenant_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')';

CREATE FUNCTION opaque_lookup() RETURNS TEXT
  LANGUAGE sql STABLE
  AS 'SELECT ''noop''::text';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db, &caller_deployment());

        assert!(registry.is_current_user_accessor("current_tenant_id"));
        assert!(
            registry.get("opaque_lookup").is_none(),
            "non-recognized function should not be registered"
        );
    }

    #[test]
    fn enrich_from_schema_skips_functions_without_body() {
        let sql = r"
CREATE FUNCTION declared_only() RETURNS UUID LANGUAGE SQL;

CREATE FUNCTION current_tenant_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db, &caller_deployment());

        assert!(
            registry.get("declared_only").is_none(),
            "functions without bodies should be ignored"
        );
        assert!(registry.is_current_user_accessor("current_tenant_id"));
    }

    #[test]
    fn function_lookup_preserves_schema_and_quote_identity() {
        let mut registry = FunctionRegistry::new();
        let accessor = FunctionSemantic::CurrentUserAccessor {
            returns: "uuid".to_string(),
        };
        registry.register_if_absent("auth.uid", &accessor);
        let is_accessor = |registry: &FunctionRegistry, name: &str| {
            matches!(
                registry.get(name),
                Some(FunctionSemantic::CurrentUserAccessor { returns }) if returns == "uuid"
            )
        };

        assert!(is_accessor(&registry, "auth.uid"));
        assert!(is_accessor(&registry, r#""auth"."uid""#));
        assert!(is_accessor(&registry, "AUTH.UID"));
        assert!(registry.get("other.uid").is_none());
        assert!(registry.get("uid").is_none());
        assert!(registry.get(r#""UID""#).is_none());

        registry.register_if_absent("uid", &accessor);
        assert!(is_accessor(&registry, "uid"));
        assert!(is_accessor(&registry, "UID"));
        assert!(registry.get(r#""UID""#).is_none());
    }

    #[test]
    fn declared_function_identity_resolves_equivalent_spellings() {
        let db = parse_schema(
            r"
CREATE SCHEMA auth;
CREATE SCHEMA other;
SET search_path TO auth, other;
CREATE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql AS 'SELECT NULL::uuid';
CREATE FUNCTION other.uid() RETURNS UUID LANGUAGE sql AS 'SELECT NULL::uuid';
",
        )
        .expect("schema should parse");
        let mut registry = FunctionRegistry::new();
        registry
            .load_from_json(r#"{"uid":{"kind":"current_user_accessor","returns":"uuid"}}"#)
            .expect("registry should parse");
        registry.enrich_from_schema(&db, &caller_deployment());

        assert!(matches!(
            registry.get("uid"),
            Some(FunctionSemantic::CurrentUserAccessor { .. })
        ));
        assert!(matches!(
            registry.get(r#""auth"."uid""#),
            Some(FunctionSemantic::CurrentUserAccessor { .. })
        ));
        assert!(registry.get("other.uid").is_none());
        assert_eq!(registry.resolved_name("uid"), "uid");
        assert_eq!(registry.resolved_name(r#""auth"."uid""#), "uid");
    }

    #[test]
    fn enrich_from_schema_does_not_register_non_allowlisted_current_setting_keys_by_default() {
        let sql = r"
CREATE FUNCTION wrong_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''timezone'')';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db, &caller_deployment());

        assert!(
            registry.get("wrong_user_id").is_none(),
            "non-allowlisted current_setting keys must not auto-register user accessors"
        );
    }

    /// A setting is declared once and looked up under whatever spelling a policy uses,
    /// since `PostgreSQL` folds a setting name when it reads it.
    #[test]
    fn a_declared_setting_is_found_under_any_spelling_and_no_other_is() {
        let sources = sources([caller("App.User_Id")]);

        assert!(sources.caller("app.user_id", &[]).is_some());
        assert!(sources.caller("APP.USER_ID", &[]).is_some());
        assert!(
            sources.caller("app.tenant_id", &[]).is_none(),
            "declaring one setting must not declare another"
        );
    }

    #[test]
    fn enrich_from_schema_with_settings_registers_custom_allowlisted_current_setting_key() {
        let sql = r"
CREATE FUNCTION tenant_user_id() RETURNS UUID
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''tenant.current_user_uuid'')';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db, &deployment([caller("tenant.current_user_uuid")]));

        assert!(
            registry.is_current_user_accessor("tenant_user_id"),
            "custom allowlisted key should allow schema-based accessor inference"
        );
    }

    #[test]
    fn enrich_from_schema_rejects_uuid_array_accessor_return_type() {
        let sql = r"
CREATE FUNCTION listed_ids_accessor() RETURNS UUID[]
  LANGUAGE sql STABLE
  AS 'SELECT string_to_array(current_setting(''app.current_user_id''), '','')';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db, &caller_deployment());

        assert!(
            !registry.is_current_user_accessor("listed_ids_accessor"),
            "UUID[] accessors must not be inferred as scalar current-user accessors"
        );
    }

    /// A set of identities is not one identity, so keying ownership on it grants by a set
    /// the model reads as a scalar. Both spellings of a set are refused, and the row shape is
    /// the one text alone would miss: `return_type_name` answers `"TABLE"` for it, which
    /// carries no `setof` token to notice.
    ///
    #[test]
    fn enrich_from_schema_rejects_set_returning_accessors() {
        for (name, declaration) in [
            ("streamed_id_accessor", "SETOF UUID"),
            ("tabled_id_accessor", "TABLE(id UUID)"),
        ] {
            let sql = format!(
                "CREATE FUNCTION {name}() RETURNS {declaration}
  LANGUAGE sql STABLE
  AS 'SELECT current_setting(''app.current_user_id'')';"
            );
            let db = parse_schema(&sql).expect("schema should parse");

            let mut registry = FunctionRegistry::new();
            registry.enrich_from_schema(&db, &caller_deployment());

            assert!(
                !registry.is_current_user_accessor(name),
                "`RETURNS {declaration}` must not be inferred as a scalar current-user accessor"
            );
        }
    }

    #[test]
    fn enrich_from_schema_does_not_register_non_sql_language_as_accessor() {
        let sql = r"
CREATE FUNCTION plpgsql_user_id() RETURNS UUID
  LANGUAGE plpgsql STABLE SECURITY INVOKER
  AS 'SELECT current_setting(''app.current_user_id'')::uuid';
";
        let db = parse_schema(sql).expect("schema should parse");

        let mut registry = FunctionRegistry::new();
        registry.enrich_from_schema(&db, &caller_deployment());

        assert!(
            !registry.is_current_user_accessor("plpgsql_user_id"),
            "a plpgsql function must not be inferred as a current-user accessor"
        );
    }
}
