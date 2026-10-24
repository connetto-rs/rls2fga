#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::types::{stable_hex_suffix, ColumnName, RelationName, TableId, TypeName};

/// Return the identifier without surrounding double quotes, decoding internal
/// escaped double-quote sequences (`""` → `"`).
///
/// Malformed identifiers (e.g. unterminated `"foo`) are returned unchanged so
/// the caller can still produce a reasonable output.
pub fn unquote_identifier(ident: &str) -> alloc::borrow::Cow<'_, str> {
    let Some(inner) = ident.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return alloc::borrow::Cow::Borrowed(ident);
    };
    if !inner.contains("\"\"") {
        return alloc::borrow::Cow::Borrowed(inner);
    }
    alloc::borrow::Cow::Owned(inner.replace("\"\"", "\""))
}

/// The target a written name denotes, or `None` when it is not a name this crate can
/// read.
///
/// One parse for every written name, and it is upstream's, so the spelling this crate
/// resolves and the spelling it renders cannot disagree. A name the grammar refuses
/// denotes nothing, which is the same answer an unresolvable name already gets.
pub fn parse_target(name: &str) -> Option<sql_traits::structs::TargetName<'_>> {
    sql_traits::structs::TargetName::parse(name.trim()).ok()
}

/// The name `PostgreSQL` stores for the terminal part of a written, possibly
/// schema-qualified name.
///
/// Identity between two written names is equality of their stored forms, so every
/// comparison of one written name against another goes through this or through a
/// resolved [`TableId`].
pub fn stored_relation_name(name: &str) -> String {
    parse_target(name).map_or_else(
        || name.trim().to_string(),
        |target| stored_identifier(target.name(), target.name_is_quoted()).into_owned(),
    )
}

/// The terminal part of a written name folded for builtin recognition, `None` when it
/// was quoted or unreadable.
///
/// A builtin or keyword is reached only by an unquoted spelling, so `"NOW"()` calls a
/// user function of that exact name and never the clock.
pub fn folded_builtin_name(name: &str) -> Option<String> {
    let target = parse_target(name)?;
    (!target.name_is_quoted()).then(|| target.name().to_ascii_lowercase())
}

/// The name `PostgreSQL` stores for an identifier written in SQL: unquoted folds
/// to lowercase, quoted keeps its case.
///
/// Declared identifiers use `ColumnLike::stored_column_name`,
/// `TableLike::stored_table_name` and `TableLike::stored_table_schema` instead.
/// This is the sqlparser side, which those traits do not cover.
pub fn stored_identifier(value: &str, quoted: bool) -> alloc::borrow::Cow<'_, str> {
    sql_traits::utils::identifier_resolution::normalize_identifier(value, quoted)
}

pub use sql_traits::utils::identifier_resolution::stored_ident_name;

/// True when `name` is a SQL keyword that resolves to the current session role.
///
/// `session_user` is intentionally excluded: it does not follow `SET ROLE`.
/// `user` is intentionally excluded because it is parser-ambiguous with
/// user-defined function names and can produce false positives.
pub fn is_current_user_keyword_name(name: &str) -> bool {
    matches!(
        folded_builtin_name(name).as_deref(),
        Some("current_user" | "current_role")
    )
}

pub use sql_traits::utils::identifier_resolution::{builtin_function_name, folded_function_name};

/// Canonicalize a SQL object name to the type name the model declares, keeping the
/// terminal relation when schema-qualified. Falls back to `resource` when nothing
/// survives.
///
/// The whole answer, reserved names included, so a caller that references the result and a
/// caller that defines it cannot end up with two spellings.
pub fn canonical_fga_type_name(name: &str) -> TypeName {
    let relation = parse_target(name).map_or_else(
        || unquote_identifier(name.trim()).to_string(),
        |target| target.name().to_string(),
    );

    let mut normalized = String::with_capacity(relation.len());
    let mut previous_was_underscore = false;

    for ch in relation.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() || lower == '_' {
            if lower == '_' {
                if previous_was_underscore {
                    continue;
                }
                previous_was_underscore = true;
            } else {
                previous_was_underscore = false;
            }
            normalized.push(lower);
        } else if !previous_was_underscore {
            normalized.push('_');
            previous_was_underscore = true;
        }
    }

    let trimmed = normalized.trim_matches('_');
    // A leading digit and a reserved word are both `TypeName`'s rules, applied here so
    // this is the only place a type name is decided.
    TypeName::canonicalized(if trimmed.is_empty() {
        "resource"
    } else {
        trimmed
    })
}

/// `OpenFGA` rejects a relation name longer than this.
pub const MAX_RELATION_NAME_LEN: usize = 50;

/// Shorten `name` to `OpenFGA`'s relation-name limit, keeping distinct names
/// distinct by ending an over-long one with a hash of the original.
///
/// Applies to relations only. Type names have a far larger limit and are left
/// alone, so a relation named after a long type is shortened while the type it
/// points at keeps its full name.
pub fn clamp_relation_name(name: String) -> String {
    if name.len() <= MAX_RELATION_NAME_LEN {
        return name;
    }
    let suffix = stable_hex_suffix(&name);
    let head: String = name
        .chars()
        .take(MAX_RELATION_NAME_LEN - suffix.len() - 1)
        .collect();
    format!("{head}_{suffix}")
}

/// How many times a colliding relation name yields before the crate stops looking.
///
/// The first yield is keyed on the value, so the only way it is taken too is something else
/// holding that exact name, which a schema can arrange. Bounded so such input cannot spin,
/// in the same spirit as the classifier's depth limit: each attempt appends a distinct
/// counter, so reaching this many needs that many engineered names rather than bad luck.
pub(crate) const MAX_RELATION_RENAME_ATTEMPTS: usize = 64;

/// Name for the `attempt`th yield of `base`, keyed on `key` so one value always yields one
/// name. Attempt zero is what a single rename produced, so a first collision reads as before.
pub(crate) fn yielded_relation_name(base: &str, key: &str, attempt: usize) -> RelationName {
    let suffix = stable_hex_suffix(key);
    let candidate = if attempt == 0 {
        format!("{base}_{suffix}")
    } else {
        format!("{base}_{suffix}_{}", attempt + 1)
    };
    RelationName::canonicalized(clamp_relation_name(candidate))
}

/// Derive a scope name from a privilege and an exact stored role set.
#[must_use]
pub fn role_scope_name(privilege: &str, roles: &[String]) -> RelationName {
    let mut exact = roles.to_vec();
    exact.sort_unstable();
    exact.dedup();
    let canonical: Vec<String> = exact
        .iter()
        .map(|role| canonical_fga_type_name(role).to_string())
        .collect();
    let base = canonical_fga_type_name(&format!("{privilege}_{}", canonical.join("_")));
    let key = if exact == canonical {
        format!("{privilege}.{}", exact.join("."))
    } else {
        let mut key = format!("{}:{privilege}", privilege.len());
        for role in &exact {
            key.push('.');
            key.push_str(&role.len().to_string());
            key.push(':');
            key.push_str(role);
        }
        key
    };
    let suffix = stable_hex_suffix(&key);
    RelationName::canonicalized(clamp_relation_name(format!("scope_{base}_{suffix}")))
}

/// Derive a stable relation name used to scope reads of a membership table by
/// `PostgreSQL` roles.
#[must_use]
pub fn membership_read_scope_relation_name(join_table: &str) -> RelationName {
    scope_relation_name("read_scope", join_table)
}

/// Derive a stable relation name for the part of an action a role scoped
/// RESTRICTIVE policy binds.
#[must_use]
pub fn role_limited_relation_name(policy_name: &str) -> RelationName {
    scope_relation_name("limit", policy_name)
}

/// Derive a stable relation name for a guard the authorization service evaluates per
/// check rather than one the tuples decide.
#[must_use]
pub fn conditional_gate_relation_name(policy_name: &str) -> RelationName {
    scope_relation_name("gate", policy_name)
}

/// Derive the relation containing rows whose strict-function arguments are present.
#[must_use]
pub fn row_presence_relation_name(columns: &[ColumnName]) -> RelationName {
    let base = columns
        .iter()
        .map(ColumnName::as_str)
        .collect::<Vec<_>>()
        .join("_");
    let mut key = String::new();
    for column in columns {
        key.push_str(&column.as_str().len().to_string());
        key.push(':');
        key.push_str(column.as_str());
        key.push('.');
    }
    let suffix = stable_hex_suffix(&key);
    RelationName::canonicalized(clamp_relation_name(format!("present_{base}_{suffix}")))
}

/// Derive the relation a boolean public flag grants through, one per stored column.
#[must_use]
pub fn public_flag_relation_name(column: &str) -> RelationName {
    RelationName::canonicalized(clamp_relation_name(format!(
        "public_when_{}",
        canonical_fga_type_name(column)
    )))
}

/// Derive the relation a literal attribute gate grants through, one per predicate.
///
/// `key` is the predicate's structural identity, hashed for a stable readable name.
/// Injectivity lives in the generator's memo, not in this 32-bit suffix.
#[must_use]
pub fn attribute_gate_relation_name(column: &str, key: &str) -> RelationName {
    RelationName::canonicalized(clamp_relation_name(format!(
        "public_where_{}_{}",
        canonical_fga_type_name(column),
        stable_hex_suffix(key)
    )))
}

/// Derive a relation of the request-gate type from what it tests.
///
/// `readable` says what the relation tests, and `key` is its exact structural identity,
/// since folding `readable` to a name can map two tests onto one spelling
/// (`t0:read` and `t0_read`).
#[must_use]
pub fn request_gate_relation_name(readable: &str, key: &str) -> RelationName {
    RelationName::canonicalized(format!("{readable}_{}", stable_hex_suffix(key)))
}

fn scope_relation_name(prefix: &str, key: &str) -> RelationName {
    let base = canonical_fga_type_name(key);
    let suffix = stable_hex_suffix(key);
    RelationName::canonicalized(clamp_relation_name(format!("{prefix}_{base}_{suffix}")))
}

/// Infer the parent `OpenFGA` type from a foreign-key-like column name.
pub fn parent_type_from_fk_column(fk_column: &str) -> TypeName {
    canonical_fga_type_name(fk_column.strip_suffix("_id").unwrap_or(fk_column))
}

/// True when the name looks like a public-visibility column.
///
/// Uses underscore-delimited word-boundary matching to avoid false positives on
/// names like `publication_id` (contains "public") or `is_invisible` (contains "visible").
pub fn is_public_flag_column_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .split('_')
        .any(|token| matches!(token, "public" | "published" | "visible"))
}

/// True when the name looks like a user/owner column.
///
/// Uses underscore-delimited word-boundary matching to avoid false positives
/// on names like `abuser_id` (contains `user_id` as a substring).
pub fn is_user_related_column_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    let tokens: Vec<&str> = lower.split('_').collect();
    let has_user_id = has_token_pair(&tokens, "user", "id");
    let has_owner_id = has_token_pair(&tokens, "owner", "id");
    let has_created_by = has_token_pair(&tokens, "created", "by");
    let has_author_id = has_token_pair(&tokens, "author", "id");
    has_user_id || has_owner_id || has_created_by || has_author_id
}

/// True when the name looks like a direct ownership column.
///
/// A superset of [`is_user_related_column_name`]: bare `owner` as a whole token, or any
/// name that predicate accepts.
pub fn is_owner_like_column_name(name: &str) -> bool {
    name.trim()
        .to_ascii_lowercase()
        .split('_')
        .any(|token| token == "owner")
        || is_user_related_column_name(name)
}

fn has_token_pair(tokens: &[&str], first: &str, second: &str) -> bool {
    tokens.windows(2).any(|w| w == [first, second])
}

/// Resolve a name a statement wrote into the table it denotes, by `PostgreSQL`'s
/// rules: a qualified name matches exactly, and an unqualified one walks the search
/// path in order. An ambiguous name stays unresolved.
pub fn lookup_table<'db, DB>(
    db: &'db DB,
    name: &str,
) -> Option<&'db <DB as sql_traits::prelude::DatabaseLike>::Table>
where
    DB: sql_traits::prelude::DatabaseLike,
{
    db.resolve_target_table(
        parse_target(name)?,
        sql_traits::prelude::IdentifierCase::AsWritten,
    )
    .ok()
    .flatten()
}

pub(crate) fn table_identity<T>(table: &T) -> TableId
where
    T: sql_traits::prelude::TableLike,
{
    TableId::from_stored(
        table.stored_table_schema().map(Into::into),
        table.stored_table_name().into(),
    )
}

pub(crate) fn resolve_table_id<DB>(db: &DB, name: &str) -> Option<TableId>
where
    DB: sql_traits::prelude::DatabaseLike,
{
    lookup_table(db, name).map(table_identity)
}

/// The table an identity names, through the catalog's stored-identity index.
pub(crate) fn lookup_table_id<'db, DB>(
    db: &'db DB,
    identity: &TableId,
) -> Option<&'db <DB as sql_traits::prelude::DatabaseLike>::Table>
where
    DB: sql_traits::prelude::DatabaseLike,
{
    db.table_by_stored_identity(identity.schema(), identity.name())
}

pub(crate) fn table_id_has_column<DB>(db: &DB, table: &TableId, column: &str) -> bool
where
    DB: sql_traits::prelude::DatabaseLike,
{
    lookup_table_id(db, table).is_some_and(|table| declares_column(db, table, column))
}

/// Whether `table` declares a column named `column`.
///
/// Beside [`lookup_table`] rather than in the generator, since both the classifier and
/// the generator ask it: a name no table has must never become a relation.
pub fn table_has_column<DB>(db: &DB, table: &str, column: &str) -> bool
where
    DB: sql_traits::prelude::DatabaseLike,
{
    lookup_table(db, table).is_some_and(|table| declares_column(db, table, column))
}

fn declares_column<DB>(db: &DB, table: &DB::Table, column: &str) -> bool
where
    DB: sql_traits::prelude::DatabaseLike,
{
    use sql_traits::prelude::{ColumnLike, TableLike};
    table
        .columns(db)
        .into_iter()
        .flatten()
        .any(|declared| declared.stored_column_name() == column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::{parse_schema, TableLike};

    fn resolved(sql: &str, spelling: &str) -> Option<(Option<String>, String)> {
        let db = parse_schema(sql).expect("the schema parses");
        lookup_table(&db, spelling).map(|table| {
            (
                table.table_schema().map(ToString::to_string),
                table.table_name().to_string(),
            )
        })
    }

    #[test]
    fn parse_target_reads_quoted_dots_back() {
        let target = parse_target(r#""my.schema"."table.name""#).expect("a readable name");
        assert_eq!(target.schema(), Some("my.schema"));
        assert_eq!(target.name(), "table.name");
        assert!(target.schema_is_quoted() && target.name_is_quoted());
    }

    #[test]
    fn unquote_identifier_decodes_escaped_quotes() {
        // Simple quoted identifier with no inner quotes.
        assert_eq!(unquote_identifier(r#""foo""#).as_ref(), "foo");

        // Double-quote escape: `"A""B"` → `A"B`
        assert_eq!(unquote_identifier(r#""A""B""#).as_ref(), r#"A"B"#);

        // Malformed (no closing quote) → returned unchanged.
        assert_eq!(unquote_identifier(r#""foo"#).as_ref(), r#""foo"#);

        // Unquoted identifier → returned unchanged.
        assert_eq!(unquote_identifier("foo").as_ref(), "foo");
    }

    #[test]
    fn stored_identifier_folds_only_unquoted_spellings() {
        assert_eq!(stored_identifier("Owner_Id", false), "owner_id");
        assert_eq!(stored_identifier("Owner_Id", true), "Owner_Id");

        // Both spellings can name distinct columns of one table, so folding a
        // quoted identifier would merge them.
        assert_ne!(
            stored_identifier("Owner_Id", true),
            stored_identifier("owner_id", false)
        );
    }

    #[test]
    fn stored_ident_name_follows_the_parsed_quote_style() {
        use sqlparser::ast::Ident;

        assert_eq!(stored_ident_name(&Ident::new("Owner_Id")), "owner_id");
        assert_eq!(
            stored_ident_name(&Ident::with_quote('"', "Owner_Id")),
            "Owner_Id"
        );
    }

    #[test]
    fn parse_target_reads_doubled_quotes_back() {
        let target = parse_target(r#""a""b"."c.d""#).expect("a readable name");
        assert_eq!(target.schema(), Some(r#"a"b"#));
        assert_eq!(target.name(), "c.d");
    }

    /// A spelling the grammar refuses denotes nothing, which is how an unreadable name
    /// falls closed instead of resolving to a table it does not name.
    #[test]
    fn parse_target_refuses_what_it_cannot_read() {
        assert!(parse_target(r#""unterminated"#).is_none());
        assert!(parse_target("app.").is_none());
        assert!(parse_target("catalog.app.docs").is_none());
        assert!(parse_target("").is_none());
    }

    #[test]
    fn lookup_table_resolves_a_qualified_spelling_to_that_schema() {
        assert_eq!(
            resolved(
                "CREATE SCHEMA app; CREATE TABLE app.docs(id INT); CREATE TABLE docs(id INT);",
                "app.docs"
            ),
            Some((Some("app".to_string()), "docs".to_string()))
        );
    }

    #[test]
    fn lookup_table_walks_the_search_path_for_an_unqualified_spelling() {
        assert_eq!(
            resolved(
                "CREATE SCHEMA app; SET search_path TO app; CREATE TABLE docs(id INT);",
                "docs"
            ),
            Some((Some("app".to_string()), "docs".to_string())),
            "the path carries the name into the schema it selects"
        );
    }

    /// Two schemas hold the name and the path decides, in both directions. A table written
    /// unqualified is `public`, which the resolver treats as the schema-less one it models.
    #[test]
    fn lookup_table_lets_the_path_order_decide_between_two_schemas() {
        let schema = |path: &str| {
            format!(
                "CREATE SCHEMA app;\
                 CREATE TABLE docs(id INT);\
                 CREATE TABLE app.docs(id INT);\
                 SET search_path TO {path};"
            )
        };

        assert_eq!(
            resolved(&schema("app, public"), "docs"),
            Some((Some("app".to_string()), "docs".to_string()))
        );
        assert_eq!(
            resolved(&schema("public, app"), "docs"),
            Some((None, "docs".to_string())),
            "reversing the path must reverse the answer, or the order is not being read"
        );
    }

    #[test]
    fn lookup_table_answers_nothing_for_a_name_no_table_bears() {
        assert_eq!(resolved("CREATE TABLE other(id INT);", "docs"), None);
    }

    #[test]
    fn lookup_table_keeps_quoting_case_sensitive() {
        let sql = r#"CREATE TABLE "Doc Items"(id INT);"#;
        assert_eq!(
            resolved(sql, r#""Doc Items""#),
            Some((None, "Doc Items".to_string()))
        );
        assert_eq!(
            resolved(sql, r#""doc items""#),
            None,
            "a quoted spelling matches exactly, so a folded one must not"
        );
    }

    #[test]
    fn is_current_user_keyword_name_matches_supported_keywords_only() {
        assert!(is_current_user_keyword_name("current_user"));
        assert!(is_current_user_keyword_name("CURRENT_ROLE"));
        assert!(!is_current_user_keyword_name("user"));
        assert!(!is_current_user_keyword_name("session_user"));
        assert!(!is_current_user_keyword_name("my_current_user"));
    }

    #[test]
    fn ownership_and_public_name_heuristics_are_shared() {
        assert!(is_owner_like_column_name("Owner_ID"));
        assert!(is_user_related_column_name("created_by"));
        assert!(is_public_flag_column_name("is_public"));
        assert!(!is_public_flag_column_name("tenant_id"));
    }

    #[test]
    fn is_owner_like_column_name_uses_word_boundaries() {
        // Positive: exact token matches.
        assert!(is_owner_like_column_name("owner_id"));
        assert!(is_owner_like_column_name("owner"));
        assert!(is_owner_like_column_name("user_id"));
        assert!(is_owner_like_column_name("created_by"));
        assert!(is_owner_like_column_name("author_id"));
        assert!(is_owner_like_column_name("Owner_ID")); // case-insensitive

        // Negative: "owner" or "user_id" are substrings, not complete tokens.
        assert!(
            !is_owner_like_column_name("ownership_status"),
            "ownership_status should not match: 'ownership' ≠ 'owner'"
        );
        assert!(
            !is_owner_like_column_name("abuser_id"),
            "abuser_id should not match: 'abuser' breaks the user_id window"
        );
        // team_owner_flag DOES match because "owner" appears as a complete token.
        assert!(
            is_owner_like_column_name("team_owner_flag"),
            "team_owner_flag should match: 'owner' is a complete token"
        );
    }

    #[test]
    fn is_public_flag_column_name_uses_word_boundaries() {
        // Positive: exact word match after splitting on '_'.
        assert!(is_public_flag_column_name("is_public"));
        assert!(is_public_flag_column_name("public"));
        assert!(is_public_flag_column_name("is_published"));
        assert!(is_public_flag_column_name("is_visible"));
        assert!(is_public_flag_column_name("visible"));

        // Negative: "public" is a substring of the token, not the whole token.
        assert!(!is_public_flag_column_name("publication_id"));
        assert!(!is_public_flag_column_name("publicly_accessible")); // "publicly" ≠ "public"
        assert!(!is_public_flag_column_name("is_invisible")); // "invisible" ≠ "visible"
        assert!(!is_public_flag_column_name("republish_count")); // "republish" ≠ "published"
    }

    #[test]
    fn canonical_fga_type_name_normalizes_schema_quotes_and_special_chars() {
        assert_eq!(canonical_fga_type_name("public.docs"), "docs");
        assert_eq!(
            canonical_fga_type_name(r#""Auth"."User-Docs""#),
            "user_docs"
        );
        assert_eq!(canonical_fga_type_name("___"), "resource");
        assert_eq!(canonical_fga_type_name("123-items"), "t_123_items");
    }

    /// Callers name a relation or a type straight from this, with no emptiness check of
    /// their own, so a name that survives nothing has to come back as `resource`.
    #[test]
    fn canonical_fga_type_name_never_returns_an_empty_name() {
        for name in [
            "",
            "   ",
            "___",
            "---",
            ".",
            "\"\"",
            "public.",
            "\u{65e5}\u{672c}",
        ] {
            assert!(
                !canonical_fga_type_name(name).as_str().is_empty(),
                "canonical_fga_type_name({name:?}) must name something"
            );
        }
    }

    #[test]
    fn role_scope_name_is_the_privilege_and_the_role_set() {
        let roles = |names: &[&str]| -> Vec<String> {
            names.iter().map(|name| (*name).to_string()).collect()
        };

        let first = role_scope_name("usage", &roles(&["auditor", "support"]));
        assert_eq!(
            first,
            role_scope_name("usage", &roles(&["auditor", "support"]))
        );
        assert!(first.as_str().starts_with("scope_"));

        // Listing order and exact duplicates do not change a stored role set.
        assert_eq!(
            first,
            role_scope_name("usage", &roles(&["support", "auditor"]))
        );
        assert_ne!(
            first,
            role_scope_name("usage", &roles(&["Support", "auditor"]))
        );
        assert_eq!(
            first,
            role_scope_name("usage", &roles(&["auditor", "support", "auditor"]))
        );

        // The three shapes that used to pool onto one object.
        assert_ne!(
            first,
            role_scope_name("member", &roles(&["auditor", "support"]))
        );
        assert_ne!(first, role_scope_name("usage", &roles(&["auditor"])));
        assert_ne!(
            role_scope_name("usage", &roles(&["alpha"])),
            role_scope_name("usage", &roles(&["beta"]))
        );

        // The base joins on an underscore, so the hash has to keep this pair apart.
        assert_ne!(
            role_scope_name("usage", &roles(&["a_b"])),
            role_scope_name("usage_a", &roles(&["b"]))
        );
        assert_ne!(
            role_scope_name("usage", &roles(&["a.b"])),
            role_scope_name("usage", &roles(&["a", "b"]))
        );
        assert!(
            role_scope_name("usage", &["r".repeat(80)]).as_str().len() <= MAX_RELATION_NAME_LEN
        );
    }

    #[test]
    fn role_limited_relation_name_is_stable_and_clamped() {
        let first = role_limited_relation_name("DocsReview");

        assert_eq!(first, role_limited_relation_name("DocsReview"));
        assert!(first.as_str().starts_with("limit_"));
        assert_ne!(first, role_limited_relation_name("docs_review"));
        assert!(
            role_limited_relation_name(&"p".repeat(80)).as_str().len() <= MAX_RELATION_NAME_LEN
        );
    }

    #[test]
    fn parent_type_from_fk_column_handles_fk_suffix() {
        assert_eq!(parent_type_from_fk_column("project_id"), "project");
        assert_eq!(
            parent_type_from_fk_column("organization_uuid"),
            "organization_uuid"
        );
    }
}
