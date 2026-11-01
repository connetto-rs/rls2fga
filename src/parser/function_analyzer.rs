#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{Expr, FunctionArguments, FunctionSecurity, SelectItem, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

use crate::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use crate::classifier::recognizers::{projected_select, renaming_reason};
use crate::parser::expr::{function_arg_expr, CastChain};
use crate::parser::names::{
    builtin_function_name, folded_function_name, is_current_user_keyword_name, parse_target,
};
use crate::types::ColumnName;

/// Complete metadata for a role-threshold team membership join.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamMembershipConfig {
    /// Table that stores team memberships.
    pub table: String,
    /// User column in the membership table.
    pub user_col: ColumnName,
    /// Team column in the membership table.
    pub team_col: ColumnName,
}

/// Semantic classification of a SQL function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum FunctionSemantic {
    /// A role-threshold function that returns an integer role level.
    /// Checks: direct ownership → team membership → explicit grants.
    #[serde(rename = "role_threshold")]
    RoleThreshold {
        /// Positional index of the user parameter in the function signature.
        user_param_index: usize,
        /// Positional index of the resource parameter in the function signature.
        resource_param_index: usize,
        /// Maps role name (e.g. `"viewer"`) to its integer level.
        role_levels: BTreeMap<String, i32>,
        /// Table that stores explicit role grants.
        grant_table: String,
        /// Column in `grant_table` identifying the grantee (user or team).
        grant_grantee_col: ColumnName,
        /// Column in `grant_table` identifying the target resource.
        grant_resource_col: ColumnName,
        /// Column in `grant_table` storing the integer role level.
        grant_role_col: ColumnName,
        /// Optional team membership join.
        #[serde(default)]
        team_membership: Option<TeamMembershipConfig>,
        /// Optional user principal table used for ownership/grant subject resolution.
        #[serde(default)]
        user_table: Option<String>,
        /// Primary-key column of `user_table`.
        #[serde(default)]
        user_pk_col: Option<ColumnName>,
        /// Optional team principal table used for ownership/grant subject resolution.
        #[serde(default)]
        team_table: Option<String>,
        /// Primary-key column of `team_table`.
        #[serde(default)]
        team_pk_col: Option<ColumnName>,
    },

    /// A function that returns the current authenticated user's ID.
    #[serde(rename = "current_user_accessor")]
    CurrentUserAccessor {
        /// SQL return type of the accessor (e.g. `"uuid"`).
        #[serde(default = "default_uuid")]
        returns: String,
    },

    /// A function that returns the current user's role name as a string.
    ///
    /// Typical example: Supabase `auth.role()` which returns `'authenticated'`,
    /// `'anon'`, or a custom role string.  Policies using this function compare
    /// the return value against string literals rather than integer levels.
    #[serde(rename = "role_accessor")]
    RoleAccessor {
        /// SQL return type of the accessor (e.g. `"text"`).
        #[serde(default = "default_text")]
        returns: String,
    },

    /// A function whose whole body reads one `current_setting` key, so calling it is
    /// calling that key and the two spellings are one declaration.
    #[serde(rename = "setting_reader")]
    SettingReader {
        /// The key the body reads.
        key: String,
    },

    /// A function whose whole body expands one declared setting into rows, so calling it
    /// is reading that setting as a set and the two spellings are one declaration.
    ///
    /// Distinct from [`FunctionSemantic::SettingReader`] because the body decides how the
    /// setting becomes a set, and dropping that would lose the separator a split needs.
    #[serde(rename = "set_reader")]
    SetReader {
        /// The key the body reads.
        key: String,
        /// The field path taken out of that key's value.
        #[serde(default)]
        path: Vec<String>,
        /// The separator the body splits on, absent where the source is already a list.
        #[serde(default)]
        separator: Option<String>,
    },

    /// A function whose semantics could not be determined.
    #[serde(rename = "unknown")]
    Unknown {
        /// Explanation of why analysis failed.
        reason: String,
    },
}

fn default_text() -> String {
    "text".to_string()
}

fn default_uuid() -> String {
    "uuid".to_string()
}

pub(crate) fn normalize_setting_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

/// The request-scoped values a deployment declared readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessorInferenceSettings {
    session_attributes: Vec<SessionAttribute>,
}

impl AccessorInferenceSettings {
    /// Build settings naming these keys as holding the caller's identity.
    pub fn from_keys<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::from_attributes(
            keys.into_iter()
                .map(|key| SessionAttribute::setting(key, SessionAttributeKind::CallerId)),
        )
    }

    /// Build settings from explicit declarations of any kind.
    pub fn from_attributes<I>(attributes: I) -> Self
    where
        I: IntoIterator<Item = SessionAttribute>,
    {
        Self {
            session_attributes: attributes.into_iter().collect(),
        }
    }

    /// Every declared source, whether the call sits inline in a policy or is the whole
    /// body of a function the policy calls.
    pub fn session_attributes(&self) -> &[SessionAttribute] {
        &self.session_attributes
    }

    /// The declaration of the value at `key` and `path`.
    pub(crate) fn attribute(&self, key: &str, path: &[String]) -> Option<&SessionAttribute> {
        let key = normalize_setting_key(key);
        self.session_attributes
            .iter()
            .find(|attribute| attribute.setting_key() == key && attribute.path() == path)
    }

    fn caller_attribute(&self, key: &str) -> Option<&SessionAttribute> {
        self.attribute(key, &[])
            .filter(|attribute| attribute.kind() == SessionAttributeKind::CallerId)
    }

    /// True when a deployment declared the value at `key` readable at all, whatever kind
    /// it named. A wrapper function around such a key resolves to it.
    pub(crate) fn declares_setting_key(&self, key: &str) -> bool {
        let key = normalize_setting_key(key);
        self.session_attributes
            .iter()
            .any(|attribute| attribute.setting_key() == key)
    }
}

impl Default for AccessorInferenceSettings {
    /// The keys whose value is the caller's identity.
    ///
    /// `request.jwt.claim.sub` holds one identity, which is what `PostgREST` sets it to.
    /// `request.jwt.claims` holds the whole token, so its value names nobody.
    fn default() -> Self {
        Self::from_keys([
            "app.current_user_id",
            "app.user_id",
            "request.jwt.claim.sub",
        ])
    }
}

/// The body's significant tokens, or [`None`] where the lexer cannot read it.
///
/// Whitespace carries the comments, so dropping it drops both. A literal, a
/// dollar-quoted block and a quoted identifier each arrive as their own token, so no
/// keyword spelled inside one is ever mistaken for code.
fn significant_tokens(sql: &str) -> Option<Vec<Token>> {
    Some(
        Tokenizer::new(&PostgreSqlDialect {}, sql)
            .tokenize()
            .ok()?
            .into_iter()
            .filter(|token| !matches!(token, Token::Whitespace(_)))
            .collect(),
    )
}

/// The folded value of an unquoted word, which is the only shape a keyword takes.
fn bare_word(token: &Token) -> Option<String> {
    match token {
        Token::Word(word) if word.quote_style.is_none() => Some(word.value.to_ascii_lowercase()),
        _ => None,
    }
}

fn contains_identifier_token(sql: &str, target: &str) -> bool {
    significant_tokens(sql).is_some_and(|tokens| {
        tokens
            .iter()
            .filter_map(bare_word)
            .any(|word| word == target)
    })
}

fn contains_disallowed_complex_token(tokens: &[Token]) -> bool {
    const COMPLEX_TOKENS: &[&str] = &[
        "insert", "update", "delete", "from", "where", "join", "begin", "end", "if", "loop",
        "raise", "perform", "execute", "call", "create", "drop", "alter",
    ];
    tokens
        .iter()
        .filter_map(bare_word)
        .any(|word| COMPLEX_TOKENS.contains(&word.as_str()))
}

/// True when the declaration returns one value that can name the caller.
///
/// Not a collection and not a set: those are many identities, not one. Not a document
/// either: `sub` inside a token is an identity and so is `tenant`, and a body that hands
/// back the whole token leaves nothing to say which of them the caller is.
fn returns_one_identity(return_type_lower: &str) -> bool {
    if return_type_lower.trim().is_empty() {
        return false;
    }

    // `TABLE(...)` reaches here as `"table"`, carrying no `setof` token to notice.
    !return_type_lower.contains("[]")
        && !contains_identifier_token(return_type_lower, "array")
        && !contains_identifier_token(return_type_lower, "setof")
        && !contains_identifier_token(return_type_lower, "table")
        && !contains_identifier_token(return_type_lower, "json")
        && !contains_identifier_token(return_type_lower, "jsonb")
}

/// Whether the tokens read the effective session role as code.
///
/// An alias is not a read: `AS current_user` names a column, and so does a bare
/// `current_user` following an expression, which is the alias form without `AS`. The
/// closing parens a preceding expression may end with are skipped, so
/// `(SELECT 1) current_user` reads as the alias it is.
fn reads_effective_user(tokens: &[Token]) -> bool {
    fn can_precede_an_operand(word: &str) -> bool {
        matches!(
            word,
            "select"
                | "where"
                | "and"
                | "or"
                | "not"
                | "when"
                | "then"
                | "else"
                | "case"
                | "on"
                | "from"
                | "join"
                | "left"
                | "right"
                | "inner"
                | "outer"
                | "cross"
                | "full"
                | "having"
                | "group"
                | "order"
                | "by"
                | "limit"
                | "offset"
                | "return"
                | "returning"
                | "into"
                | "values"
                | "set"
                | "is"
                | "in"
                | "exists"
                | "distinct"
                | "all"
                | "any"
                | "some"
                | "union"
                | "intersect"
                | "except"
                | "null"
                | "true"
                | "false"
        )
    }

    tokens.iter().enumerate().any(|(at, token)| {
        if !bare_word(token).is_some_and(|word| is_current_user_keyword_name(&word)) {
            return false;
        }
        // The preceding word, and whether only closing parens stand between the two.
        let mut only_closing_parens = true;
        let mut preceding = None;
        for earlier in tokens.get(..at).into_iter().flatten().rev() {
            if let Some(word) = bare_word(earlier) {
                preceding = Some(word);
                break;
            }
            if !matches!(earlier, Token::RParen) {
                only_closing_parens = false;
            }
        }
        let Some(preceding) = preceding else {
            return true;
        };
        if preceding == "as" {
            return false;
        }
        !only_closing_parens || can_precede_an_operand(&preceding)
    })
}

fn contains_function_call_token(tokens: &[Token], function_name: &str) -> bool {
    tokens.windows(2).any(|pair| {
        pair.first().and_then(bare_word).as_deref() == Some(function_name)
            && pair.get(1) == Some(&Token::LParen)
    })
}

/// Whether the body names an accessor at all, and does so as a direct expression.
///
/// [`None`] where the lexer cannot read the body, which names no accessor.
fn accessor_shape(body: &str) -> Option<bool> {
    let tokens = significant_tokens(body)?;
    let marks_an_accessor =
        contains_function_call_token(&tokens, "current_setting") || reads_effective_user(&tokens);
    Some(marks_an_accessor && !contains_disallowed_complex_token(&tokens))
}

/// Extract the literal setting key from `current_setting('key')` or
/// `current_setting('key', missing_ok)`.
///
/// The two-argument form returns NULL instead of raising when the key is unset.
/// That only makes the policy deny (a NULL comparison is never true), so the key
/// identifies the current user exactly as in the one-argument form.
pub(crate) fn current_setting_literal_key(expr: &Expr) -> Option<String> {
    let Expr::Function(func) = expr else {
        return None;
    };
    if builtin_function_name(func).as_deref() != Some("current_setting") {
        return None;
    }
    let FunctionArguments::List(arg_list) = &func.args else {
        return None;
    };
    let ([arg] | [arg, _]) = arg_list.args.as_slice() else {
        return None;
    };
    let key = crate::parser::expr::string_literal(function_arg_expr(arg)?)?;

    Some(normalize_setting_key(&key))
}

/// A body expression that reads the caller, and the cast in it that can rename what the
/// function returns. A cast is proven only by the `identity_cast` declared on the caller
/// key it reads.
struct BodyCallerRead {
    /// The caller key whose declaration would prove the cast, absent for a keyword.
    key: Option<String>,
    /// The first cast that renames the caller.
    renaming: Option<String>,
}

fn body_caller_read(expr: &Expr, settings: &AccessorInferenceSettings) -> Option<BodyCallerRead> {
    let (casts, peeled) = CastChain::peeled(expr);
    let read = |key: Option<String>, declared: Option<&str>| BodyCallerRead {
        key,
        renaming: casts.renaming(declared).map(str::to_string),
    };
    match peeled {
        Expr::Identifier(ident)
            if ident.quote_style.is_none() && is_current_user_keyword_name(&ident.value) =>
        {
            Some(read(None, None))
        }
        Expr::Function(func) => match current_setting_literal_key(peeled) {
            Some(key) => {
                let declared = settings.caller_attribute(&key)?.identity_cast();
                Some(read(Some(key), declared))
            }
            None => (folded_function_name(func)
                .is_some_and(|name| is_current_user_keyword_name(&name))
                && parse_target(&func.name.to_string())
                    .is_some_and(|target| target.schema().is_none())
                && matches!(func.args, FunctionArguments::None))
            .then(|| read(None, None)),
        },
        _ => None,
    }
}

/// The single expression a one-statement `SELECT` body projects, when nothing in the
/// body can drop that row.
///
/// The one place a body is unwrapped to its expression, so a rule applied to one reader
/// cannot be dropped by another. The narrowing check is [`projected_select`], the same
/// one a scalar subquery in the policy goes through, because a body that yields no row
/// returns NULL and a comparison against NULL hides the row while the model would grant
/// it. Sharing it is what stops the two spellings of one hazard being guarded apart.
pub(crate) fn body_single_projection(body: &str) -> Option<Expr> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, body).ok()?;
    let [Statement::Query(query)] = statements.as_slice() else {
        return None;
    };
    let select = projected_select(query)?;
    let [SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }] =
        select.projection.as_slice()
    else {
        return None;
    };
    Some(expr.clone())
}

/// The caller read a whole body makes, when the body has the shape of an accessor.
fn body_caller_read_of(
    body: &str,
    return_type: &str,
    language: &str,
    settings: &AccessorInferenceSettings,
) -> Option<BodyCallerRead> {
    // A *direct* accessor expression, not a complex function that merely references
    // current_user or current_setting incidentally, such as an audit trigger that
    // records the caller and returns something else.
    if language != "sql" || !returns_one_identity(return_type) || accessor_shape(body) != Some(true)
    {
        return None;
    }
    body_caller_read(&body_single_projection(body)?, settings)
}

/// The `current_setting` key a whole body reads and the casts around that read, so a call
/// to the function is a call to that key.
pub(crate) fn body_setting_key(body: &str) -> Option<(String, CastChain)> {
    let expr = body_single_projection(body)?;
    let (casts, peeled) = CastChain::peeled(&expr);
    Some((current_setting_literal_key(peeled)?, casts))
}

impl FunctionSemantic {
    /// Attempt to classify a function body by simple heuristic analysis with
    /// default accessor inference settings, as `SECURITY INVOKER`.
    pub fn analyze_body(body: &str, return_type: &str, language: &str) -> Option<FunctionSemantic> {
        let settings = AccessorInferenceSettings::default();
        Self::analyze_body_with_settings(
            body,
            return_type,
            language,
            &FunctionSecurity::Invoker,
            &settings,
        )
    }

    /// Attempt to classify a function body by simple heuristic analysis.
    pub fn analyze_body_with_settings(
        body: &str,
        return_type: &str,
        language: &str,
        security: &FunctionSecurity,
        settings: &AccessorInferenceSettings,
    ) -> Option<FunctionSemantic> {
        let return_type_lower = return_type.to_lowercase();
        let read = body_caller_read_of(body, &return_type_lower, language, settings)?;
        (read.renaming.is_none() && !runs_as_owner_reading_effective_user(body, security)).then(
            || FunctionSemantic::CurrentUserAccessor {
                returns: return_type_lower.trim().to_string(),
            },
        )
    }
}

/// Why a body that reads the caller is no accessor, when the reason is a cast that can
/// rename what it returns.
pub(crate) fn renamed_caller_body(
    body: &str,
    return_type: &str,
    language: &str,
    settings: &AccessorInferenceSettings,
) -> Option<String> {
    let read = body_caller_read_of(body, &return_type.to_lowercase(), language, settings)?;
    let cast = read.renaming?;
    let subject = match &read.key {
        Some(key) => format!("its body reads current_setting('{key}'), which"),
        None => "its body reads the caller, which".to_string(),
    };
    Some(renaming_reason(&subject, &cast, read.key.as_deref()))
}

/// True when the body identifies its caller through `current_user` or `current_role`
/// but runs as the owner, which makes that value the owner's for every caller.
///
/// A session setting is per session, so a `current_setting` body is unaffected.
fn runs_as_owner_reading_effective_user(body: &str, security: &FunctionSecurity) -> bool {
    matches!(security, FunctionSecurity::Definer) && body_reads_effective_user(body)
}

/// True when the body reads `current_user` or `current_role` as a token,
/// keyword spellings inside literals and comments excluded.
/// A body the lexer cannot read answers `true`: the caller refuses on it, and a body
/// nobody can read is not one to conclude anything else from.
pub(crate) fn body_reads_effective_user(body: &str) -> bool {
    significant_tokens(body).is_none_or(|tokens| reads_effective_user(&tokens))
}

#[cfg(test)]
mod tests {
    use super::{
        AccessorInferenceSettings, FunctionSecurity, FunctionSemantic, SessionAttribute,
        SessionAttributeKind, TeamMembershipConfig,
    };
    use crate::types::ColumnName;
    use alloc::collections::BTreeMap;

    /// Every non-code placement of the keyword, for the one question that decides whether a
    /// definer function is refused. A spelling inside a literal, a comment or a
    /// dollar-quoted block is text, not a read.
    #[test]
    fn the_keyword_is_read_only_where_it_is_code() {
        for body in [
            "SELECT 'current_user'",
            "SELECT 1 -- current_user",
            "SELECT 1 /* current_user */",
            "SELECT 1 /* outer /* current_user */ still */",
            "SELECT $tag$ current_user $tag$",
            "SELECT $$ current_user $$",
            r#"SELECT "current_user""#,
            "SELECT 1 AS current_user",
            "SELECT (who) current_user",
        ] {
            assert!(
                !super::body_reads_effective_user(body),
                "{body:?} spells the keyword somewhere it is not code"
            );
        }
        for body in [
            "SELECT current_user",
            "SELECT CURRENT_USER",
            "SELECT current_role",
            "SELECT (current_user)",
            "SELECT current_user /* and a comment */",
        ] {
            assert!(
                super::body_reads_effective_user(body),
                "{body:?} reads the keyword as code"
            );
        }
    }

    /// A body the lexer cannot read is refused rather than guessed at.
    #[test]
    fn an_unlexable_body_reads_as_reading_the_caller() {
        for body in ["SELECT 'unterminated", "SELECT $tag$ unterminated"] {
            assert!(
                super::body_reads_effective_user(body),
                "{body:?} cannot be lexed, so nothing may be concluded from it"
            );
        }
    }

    /// The complex-token refusal reads code only, so a keyword inside a literal or a
    /// comment does not stop a direct accessor being recognized.
    #[test]
    fn a_complex_keyword_outside_code_does_not_refuse_the_accessor() {
        for body in [
            "SELECT current_user -- update",
            "SELECT current_user /* delete from */",
            "SELECT current_setting('app.current_user_id') /* update from */",
            r#"SELECT current_user AS "from""#,
        ] {
            assert!(
                FunctionSemantic::analyze_body(body, "UUID", "sql").is_some(),
                "{body:?} is a direct accessor"
            );
        }
        for body in [
            "SELECT current_user FROM audit",
            "UPDATE audit SET who = current_user RETURNING who",
        ] {
            assert!(
                FunctionSemantic::analyze_body(body, "UUID", "sql").is_none(),
                "{body:?} is not a direct accessor"
            );
        }
    }

    /// The body-shape question answers on its own, not only through the composition that
    /// consumes it: a DML or control-flow keyword in code refuses, one in a literal or a
    /// comment does not, and an unlexable body answers nothing.
    #[test]
    fn the_accessor_shape_reads_code_only() {
        for body in [
            "SELECT current_user",
            "SELECT current_setting('app.user_id')",
            "SELECT current_user -- delete from audit",
            "SELECT current_user /* update */",
            "SELECT 'delete from' || current_user",
        ] {
            assert_eq!(
                super::accessor_shape(body),
                Some(true),
                "{body:?} is a direct accessor shape"
            );
        }
        for body in [
            "SELECT current_user FROM audit",
            "SELECT current_user WHERE true",
            "INSERT INTO audit(who) VALUES (current_user)",
            "SELECT 1",
        ] {
            assert_eq!(
                super::accessor_shape(body),
                Some(false),
                "{body:?} is not a direct accessor shape"
            );
        }
        assert_eq!(super::accessor_shape("SELECT 'unterminated"), None);
    }

    /// An unlexable body names no accessor.
    #[test]
    fn an_unlexable_body_names_no_accessor() {
        assert!(FunctionSemantic::analyze_body(
            "SELECT current_user, 'unterminated",
            "UUID",
            "sql"
        )
        .is_none());
    }

    #[test]
    fn analyze_body_detects_current_user_accessor() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id')",
            "TEXT",
            "sql",
        );

        assert!(matches!(
            semantic,
            Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "text"
        ));
    }

    /// A body that casts the caller returns the value sent only where the key it reads is
    /// declared to arrive canonical for that cast.
    #[test]
    fn analyze_body_infers_a_cast_caller_only_through_a_declared_identity_cast() {
        let analyze = |body: &str, attribute: SessionAttribute| {
            FunctionSemantic::analyze_body_with_settings(
                body,
                "UUID",
                "sql",
                &FunctionSecurity::Invoker,
                &AccessorInferenceSettings::from_attributes([attribute]),
            )
        };
        let caller = || SessionAttribute::setting("app.user_id", SessionAttributeKind::CallerId);
        let cast = "SELECT current_setting('app.user_id')::uuid";
        let renamed = "SELECT current_setting('app.user_id')::integer::text";

        assert!(analyze(cast, caller()).is_none());
        assert!(analyze(cast, caller().with_identity_cast("uuid")).is_some());
        assert!(analyze(cast, caller().with_identity_cast("integer")).is_none());
        assert!(analyze(renamed, caller()).is_none());
        assert!(analyze(renamed, caller().with_identity_cast("integer")).is_some());
        assert!(analyze("SELECT current_setting('app.user_id')::text", caller()).is_some());
        assert!(analyze("SELECT current_user::uuid", caller()).is_none());
    }

    #[test]
    fn analyze_body_detects_direct_current_user_keyword_accessor() {
        let semantic = FunctionSemantic::analyze_body("SELECT current_user::text", "TEXT", "sql");

        assert!(matches!(
            semantic,
            Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "text"
        ));

        let semantic_role =
            FunctionSemantic::analyze_body("SELECT current_role::text", "TEXT", "sql");
        assert!(matches!(
            semantic_role,
            Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "text"
        ));
    }

    #[test]
    fn analyze_body_rejects_the_keyword_accessor_when_the_function_runs_as_its_owner() {
        let settings = AccessorInferenceSettings::default();
        for body in ["SELECT current_user::text", "SELECT CURRENT_USER::text"] {
            let semantic = FunctionSemantic::analyze_body_with_settings(
                body,
                "UUID",
                "sql",
                &FunctionSecurity::Definer,
                &settings,
            );
            assert!(
                semantic.is_none(),
                "a definer body returns the owner's name, not the caller's, for {body}"
            );
        }

        let setting_body = FunctionSemantic::analyze_body_with_settings(
            "SELECT current_setting('app.current_user_id')",
            "UUID",
            "sql",
            &FunctionSecurity::Definer,
            &settings,
        );
        assert!(
            matches!(
                setting_body,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "a session setting is per session, so the security mode cannot change it"
        );
    }

    #[test]
    fn analyze_body_does_not_auto_classify_role_threshold() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT grant_level FROM grants WHERE user_id = $1",
            "integer",
            "sql",
        );

        assert!(
            semantic.is_none(),
            "role-threshold-like SQL should remain unclassified without explicit metadata"
        );
    }

    #[test]
    fn analyze_body_rejects_complex_body_that_incidentally_references_current_user() {
        // A PL/pgSQL audit function that writes current_user to a log table and
        // returns a UUID is NOT a current-user accessor.
        let audit_body = "
            INSERT INTO audit_log (table_name, performed_by)
            VALUES ($1, current_user);
            SELECT gen_random_uuid()::uuid;
        ";
        let semantic = FunctionSemantic::analyze_body(audit_body, "UUID", "plpgsql");
        assert!(
            semantic.is_none(),
            "complex body mentioning current_user should not be auto-classified as accessor"
        );

        // A function with a FROM clause is also too complex.
        let complex_body = "SELECT u.id FROM users u WHERE u.login = current_user LIMIT 1::uuid";
        let semantic2 = FunctionSemantic::analyze_body(complex_body, "UUID", "sql");
        assert!(
            semantic2.is_none(),
            "body with FROM clause should not be classified as accessor"
        );
    }

    /// A `current_setting` key that spells a SQL keyword as a substring is still a
    /// literal read, so the body stays a direct accessor.
    #[test]
    fn analyze_body_ignores_keyword_substrings_inside_literals() {
        for (key, note) in [
            (
                "app.from_user_id",
                "keyword-like substrings inside literals should not trigger complex-body rejection",
            ),
            (
                "custom.update_marker",
                "literal text containing update/from/etc must not be treated as SQL structure",
            ),
        ] {
            let settings = AccessorInferenceSettings::from_keys([key]);
            let semantic = FunctionSemantic::analyze_body_with_settings(
                &format!("SELECT current_setting('{key}')"),
                "UUID",
                "sql",
                &FunctionSecurity::Invoker,
                &settings,
            );
            assert!(
                matches!(
                    semantic,
                    Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
                ),
                "{note}, got: {semantic:?}"
            );
        }
    }

    #[test]
    fn analyze_body_rejects_comment_only_current_user_marker() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid -- current_user marker in comment",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "current_user marker in SQL comments must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_nested_block_comment_current_user_marker() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid /* outer /* inner */ current_user */",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "nested block-comment marker must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_literal_only_current_user_marker() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT '-- current_user marker in literal only'::uuid",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "current_user marker in string literals must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_alias_named_user() {
        let semantic =
            FunctionSemantic::analyze_body("SELECT gen_random_uuid()::uuid AS user", "UUID", "sql");
        assert!(
            semantic.is_none(),
            "identifier token `user` used as an alias must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_alias_named_current_user_or_current_role() {
        let alias_current_user = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid AS current_user",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_user.is_none(),
            "alias named current_user must not classify as accessor"
        );

        let alias_current_role = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid AS current_role",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_role.is_none(),
            "alias named current_role must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_alias_without_as_named_current_user_or_current_role() {
        let alias_current_user = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid current_user",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_user.is_none(),
            "implicit alias named current_user must not classify as accessor"
        );

        let alias_current_role = FunctionSemantic::analyze_body(
            "SELECT gen_random_uuid()::uuid current_role",
            "UUID",
            "sql",
        );
        assert!(
            alias_current_role.is_none(),
            "implicit alias named current_role must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_does_not_treat_user_keyword_as_accessor_marker() {
        let semantic = FunctionSemantic::analyze_body("SELECT user", "UUID", "sql");
        assert!(
            semantic.is_none(),
            "`user` keyword is too ambiguous to auto-classify as current-user accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_non_direct_current_user_expressions() {
        let case_expr = FunctionSemantic::analyze_body(
            "SELECT CASE WHEN TRUE THEN current_user ELSE gen_random_uuid() END",
            "UUID",
            "sql",
        );
        assert!(
            case_expr.is_none(),
            "CASE expression containing current_user must not classify as direct accessor"
        );

        let coalesce_expr = FunctionSemantic::analyze_body(
            "SELECT COALESCE(current_user, gen_random_uuid())",
            "UUID",
            "sql",
        );
        assert!(
            coalesce_expr.is_none(),
            "COALESCE expression containing current_user must not classify as direct accessor"
        );

        let concat_expr =
            FunctionSemantic::analyze_body("SELECT current_user || ''", "UUID", "sql");
        assert!(
            concat_expr.is_none(),
            "composed expressions around current_user must not classify as direct accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_dollar_quoted_literal_only_current_user_marker() {
        let untagged =
            FunctionSemantic::analyze_body("SELECT $$ current_user $$::uuid", "UUID", "sql");
        assert!(
            untagged.is_none(),
            "current_user marker in untagged dollar-quoted literals must not classify as accessor"
        );

        let tagged = FunctionSemantic::analyze_body(
            "SELECT $tag$current_setting('app.current_user_id')$tag$::uuid",
            "UUID",
            "sql",
        );
        assert!(
            tagged.is_none(),
            "current_setting marker in tagged dollar-quoted literals must not classify as accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_identifier_substring_current_user_marker() {
        let semantic =
            FunctionSemantic::analyze_body("SELECT my_current_user_token::uuid", "UUID", "sql");
        assert!(
            semantic.is_none(),
            "identifier substrings like my_current_user_token are not accessor markers"
        );
    }

    #[test]
    fn analyze_body_rejects_non_allowlisted_current_setting_key_by_default() {
        let semantic =
            FunctionSemantic::analyze_body("SELECT current_setting('timezone')", "UUID", "sql");
        assert!(
            semantic.is_none(),
            "non-allowlisted current_setting keys must not be inferred as current-user accessors"
        );
    }

    #[test]
    fn analyze_body_with_settings_accepts_custom_allowlisted_current_setting_key() {
        let settings = AccessorInferenceSettings::from_keys(["tenant.current_user_uuid"]);
        let semantic = FunctionSemantic::analyze_body_with_settings(
            "SELECT current_setting('tenant.current_user_uuid')",
            "UUID",
            "sql",
            &FunctionSecurity::Invoker,
            &settings,
        );
        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "custom allowlisted key should be inferred as current-user accessor"
        );
    }

    #[test]
    fn analyze_body_rejects_non_literal_current_setting_argument() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting(app.current_user_id)",
            "UUID",
            "sql",
        );
        assert!(
            semantic.is_none(),
            "non-literal current_setting arguments must not be inferred as current-user accessors"
        );
    }

    #[test]
    fn analyze_body_accepts_direct_accessor_with_keyword_substring_alias() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id') AS from_id",
            "UUID",
            "sql",
        );
        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "uuid"
            ),
            "token-aware complexity scan should not reject direct accessors aliased as from_id"
        );
    }

    /// The declared type is recorded, not assumed: a text identity is at least as
    /// common as a UUID one.
    #[test]
    fn analyze_body_records_the_declared_return_type() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.user_id', true)",
            "TEXT",
            "sql",
        );

        assert!(
            matches!(
                semantic,
                Some(FunctionSemantic::CurrentUserAccessor { ref returns }) if returns == "text"
            ),
            "the accessor carries the type it was declared with, got: {semantic:?}"
        );
    }

    /// A declaration that names no single identity refuses the body, whether it names
    /// nothing, a row, a set, an array or a document.
    #[test]
    fn analyze_body_rejects_a_return_declaration_naming_no_single_identity() {
        let read = "SELECT current_setting('app.user_id', true)";
        let legacy_read = "SELECT current_setting('app.current_user_id')";
        let document = "SELECT current_setting('app.user_id', true)::jsonb";
        for (body, declaration, note) in [
            (
                read,
                "",
                "an undeclared return type is not a scalar identity",
            ),
            (read, "TABLE", "`RETURNS TABLE` is not one identity"),
            (
                read,
                "TABLE(id TEXT)",
                "`RETURNS TABLE(id TEXT)` is not one identity",
            ),
            (
                read,
                "SETOF TEXT",
                "`RETURNS SETOF TEXT` is a set, not one identity",
            ),
            (
                legacy_read,
                "SETOF UUID",
                "`RETURNS SETOF UUID` is a set, not one identity",
            ),
            (read, "TEXT[]", "`RETURNS TEXT[]` is not one identity"),
            (
                legacy_read,
                "UUID[]",
                "`RETURNS UUID[]` is an array, not one identity",
            ),
            (
                document,
                "JSON",
                "`RETURNS JSON` is a document, not an identity",
            ),
            (
                document,
                "JSONB",
                "`RETURNS JSONB` is a document, not an identity",
            ),
        ] {
            let semantic = FunctionSemantic::analyze_body(body, declaration, "sql");

            assert!(semantic.is_none(), "{note}, got: {semantic:?}");
        }
    }

    #[test]
    fn current_user_accessor_default_return_type_deserializes_to_uuid() {
        let semantic: FunctionSemantic = serde_json::from_str(
            r#"{
  "kind": "current_user_accessor"
}"#,
        )
        .expect("semantic json should parse");

        assert!(matches!(
            semantic,
            FunctionSemantic::CurrentUserAccessor { ref returns } if returns == "uuid"
        ));
    }

    #[test]
    fn role_threshold_semantic_round_trips_with_all_fields() {
        let semantic = FunctionSemantic::RoleThreshold {
            user_param_index: 0,
            resource_param_index: 1,
            role_levels: BTreeMap::from([("viewer".to_string(), 1), ("editor".to_string(), 2)]),
            grant_table: "object_grants".to_string(),
            grant_grantee_col: ColumnName::from_stored("grantee_id"),
            grant_resource_col: ColumnName::from_stored("resource_id"),
            grant_role_col: ColumnName::from_stored("role_level"),
            team_membership: Some(TeamMembershipConfig {
                table: "team_memberships".to_string(),
                user_col: ColumnName::from_stored("user_id"),
                team_col: ColumnName::from_stored("team_id"),
            }),
            user_table: Some("users".to_string()),
            user_pk_col: Some(ColumnName::from_stored("id")),
            team_table: Some("teams".to_string()),
            team_pk_col: Some(ColumnName::from_stored("id")),
        };

        let json = serde_json::to_string(&semantic).expect("semantic should serialize");
        let parsed: FunctionSemantic =
            serde_json::from_str(&json).expect("semantic should deserialize");

        assert!(matches!(
            &parsed,
            FunctionSemantic::RoleThreshold {
                team_membership: Some(team_membership),
                user_table: Some(user_table),
                user_pk_col: Some(user_pk_col),
                team_table: Some(team_table),
                team_pk_col: Some(team_pk_col),
                ..
            } if team_membership.table == "team_memberships"
                && team_membership.user_col == "user_id"
                && team_membership.team_col == "team_id"
                && user_table == "users"
                && user_pk_col == "id"
                && team_table == "teams"
                && team_pk_col == "id"
        ));
    }

    #[test]
    fn role_threshold_team_membership_is_all_or_nothing() {
        let partial = r#"{
  "kind": "role_threshold",
  "user_param_index": 0,
  "resource_param_index": 1,
  "role_levels": {"viewer": 1},
  "grant_table": "object_grants",
  "grant_grantee_col": "grantee_id",
  "grant_resource_col": "resource_id",
  "grant_role_col": "role_level",
  "team_membership": {
    "table": "team_memberships",
    "user_col": "user_id"
  }
}"#;

        assert!(
            serde_json::from_str::<FunctionSemantic>(partial).is_err(),
            "a partial team membership configuration must be rejected"
        );

        let legacy = r#"{
  "kind": "role_threshold",
  "user_param_index": 0,
  "resource_param_index": 1,
  "role_levels": {"viewer": 1},
  "grant_table": "object_grants",
  "grant_grantee_col": "grantee_id",
  "grant_resource_col": "resource_id",
  "grant_role_col": "role_level",
  "team_membership_table": "team_memberships",
  "team_membership_user_col": "user_id",
  "team_membership_team_col": "team_id"
}"#;
        assert!(
            serde_json::from_str::<FunctionSemantic>(legacy).is_err(),
            "the three independent options must not be accepted"
        );
    }

    #[test]
    fn analyze_body_rejects_current_setting_accessor_body_when_language_is_not_sql() {
        let semantic = FunctionSemantic::analyze_body(
            "SELECT current_setting('app.current_user_id')",
            "uuid",
            "plpgsql",
        );
        assert!(
            semantic.is_none(),
            "plpgsql body cannot be a direct SQL accessor regardless of its text"
        );
    }
}
