#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use sqlparser::ast::{DataType, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments};

use crate::parser::names::stored_ident_name;
use crate::types::ColumnName;

/// Peel the wrappers that carry no meaning for what an expression *is*: a cast and a
/// parenthesis.
///
/// Every reader that then asks "is this a column, a call, a literal" starts here, so a
/// wrapper learned once is seen through by all of them.
///
/// A cast changes the value, so a reader that keeps the value rather than its shape must
/// not peel: see `projected_select` and the tuple SQL, which keep the cast. A reader that
/// compares the value peels through [`peel_noting_casts`] and judges what it peeled.
pub(crate) fn unwrap_cast_or_nested(expr: &Expr) -> &Expr {
    peel_noting_casts(expr, |_| {})
}

/// [`unwrap_cast_or_nested`], handing each peeled cast's target to `cast`, outermost
/// first.
///
/// The one place a cast is peeled. Spelled as a loop deliberately: a second peel written
/// as recursion inside another reader is the duplication
/// `every_cast_peel_routes_through_the_shared_peeler` forbids, and the door this crate was
/// burned through twice.
pub(crate) fn peel_noting_casts<'e>(
    mut expr: &'e Expr,
    mut cast: impl FnMut(&'e DataType),
) -> &'e Expr {
    loop {
        match expr {
            Expr::Cast {
                expr: inner,
                data_type,
                ..
            } => {
                cast(data_type);
                expr = inner.as_ref();
            }
            Expr::Nested(inner) => expr = inner.as_ref(),
            _ => return expr,
        }
    }
}

/// The casts written around one value, outermost first, each named the way a
/// deployment declares it, and the type the call the value comes from returns.
///
/// A cast through `text` or an unbounded `varchar` renders the value it is given, which is
/// how the model compares every value, so it renames nothing. Any other cast can rename
/// it: `'01'::integer` is `1`, and `uuid` lower-cases. Such a cast is proven only by a
/// declaration that the value already arrives canonical for that type, or, for a literal,
/// by its text already being that type's canonical output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CastChain {
    /// The casts, outermost first.
    casts: Vec<String>,
    /// The type the call at the bottom of the chain returns, inside every cast. The call's
    /// body was judged when the call was read as a request value, so it renames nothing
    /// here, but a literal compared with the call is coerced into it.
    returned: Option<String>,
}

impl CastChain {
    /// The casts [`peel_noting_casts`] finds around `expr`, and what they wrap.
    pub(crate) fn peeled(expr: &Expr) -> (Self, &Expr) {
        let mut chain = Self::default();
        let inner = peel_noting_casts(expr, |data_type| {
            chain.casts.push(cast_type_name(data_type));
        });
        (chain, inner)
    }

    /// The value of a call returning `returned`, under no cast.
    pub(crate) fn returning(returned: &str) -> Self {
        Self {
            casts: Vec::new(),
            returned: Some(returned.to_string()),
        }
    }

    /// Record the casts `inner` holds inside those already recorded.
    pub(crate) fn extend(&mut self, inner: CastChain) {
        self.casts.extend(inner.casts);
        if inner.returned.is_some() {
            self.returned = inner.returned;
        }
    }

    /// The first cast that can rename the value, given the type the value is declared to
    /// arrive canonical for.
    ///
    /// An array cast is judged by its element type, since the declaration speaks of each
    /// element.
    pub(crate) fn renaming(&self, canonical_for: Option<&str>) -> Option<&str> {
        self.renaming_beyond(canonical_for.as_slice())
    }

    /// The first cast that can rename the value, given the spellings of the types the
    /// value already arrives canonical for.
    pub(crate) fn renaming_beyond(&self, canonical_for: &[&str]) -> Option<&str> {
        self.casts.iter().map(String::as_str).find(|cast| {
            !renders_as_text(cast)
                && !canonical_for
                    .iter()
                    .any(|declared| element_type(cast).eq_ignore_ascii_case(declared))
        })
    }

    /// The first cast that can rename the literal `text`. A cast whose canonical output
    /// `text` already spells leaves it as written.
    pub(crate) fn renaming_literal(&self, text: &str) -> Option<&str> {
        self.casts
            .iter()
            .map(String::as_str)
            .find(|cast| !keeps_literal(cast, text))
    }

    /// The type the value is compared as, its outermost cast or else the type its call
    /// returns.
    pub(crate) fn outermost(&self) -> Option<&str> {
        self.casts
            .first()
            .or(self.returned.as_ref())
            .map(String::as_str)
    }

    /// Whether the value the chain yields is text, so a literal it is compared with keeps
    /// its spelling. Any other type coerces the literal, which can rename it.
    pub(crate) fn yields_text(&self) -> bool {
        self.outermost().is_none_or(renders_as_text)
    }

    /// Whether the outermost cast renders the value as unbounded text, so it compares as
    /// `text` whatever type it held.
    pub(crate) fn casts_to_text(&self) -> bool {
        self.casts
            .first()
            .map(String::as_str)
            .is_some_and(renders_as_text)
    }

    /// The chain without the parse into `json` or `jsonb` that an arrow or a jsonb
    /// expander needs, which is the read's structure rather than a renaming.
    pub(crate) fn without_json_parse(mut self) -> Self {
        if self
            .casts
            .first()
            .is_some_and(|outermost| matches!(outermost.as_str(), "json" | "jsonb"))
        {
            self.casts.remove(0);
        }
        self
    }
}

/// A cast's target type as a declaration names it: lower case, without the
/// `pg_catalog` schema every built-in type lives in.
pub(crate) fn cast_type_name(data_type: &DataType) -> String {
    let rendered = data_type.to_string().to_ascii_lowercase();
    match rendered.strip_prefix("pg_catalog.") {
        Some(unqualified) => unqualified.to_string(),
        None => rendered,
    }
}

/// Whether a cast to `name` renders its value as text without bounding its length. A
/// bounded `varchar(n)` truncates and `char(n)` pads, so both can rename.
fn renders_as_text(name: &str) -> bool {
    matches!(element_type(name), "text" | "varchar" | "character varying")
}

/// Whether a cast to `name` hands the literal `text` back as written, because it renders
/// text or because `text` already spells its canonical output.
///
/// An array cast is judged by its element type, which is what `= ANY` coerces the literal
/// into. A literal in array syntax never spells an element's canonical output, so it
/// stays refused.
pub(crate) fn keeps_literal(name: &str, text: &str) -> bool {
    renders_as_text(name)
        || match element_type(name) {
            "uuid" => is_canonical_uuid(text),
            _ => false,
        }
}

/// Whether `text` is how `PostgreSQL` prints a `uuid`, lower-case hex grouped 8-4-4-4-12.
fn is_canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// The element type an array cast names, or the type itself.
pub(crate) fn element_type(name: &str) -> &str {
    name.trim_end_matches("[]")
}

/// The string literal an expression spells, once its casts and parentheses are peeled.
///
/// A non-literal is not static and a literal of any other kind is not a string, so both
/// refuse. Callers add their own reason for wanting one.
pub(crate) fn string_literal(expr: &Expr) -> Option<String> {
    match unwrap_cast_or_nested(expr) {
        Expr::Value(value) => match &value.value {
            sqlparser::ast::Value::SingleQuotedString(text) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Extract a simple column name from an expression.
///
/// Supports plain identifiers (`owner_id`) and qualified identifiers
/// (`public.docs.owner_id`), returning only the terminal column component under
/// the name `PostgreSQL` stores it.
pub fn extract_column_name(expr: &Expr) -> Option<ColumnName> {
    match unwrap_cast_or_nested(expr) {
        Expr::Identifier(ident) => Some(ColumnName::from_stored(stored_ident_name(ident))),
        Expr::CompoundIdentifier(parts) => {
            Some(ColumnName::from_stored(stored_ident_name(parts.last()?)))
        }
        _ => None,
    }
}

/// Like [`extract_column_name`] but also unwraps `COALESCE(col, default)`,
/// extracting the column name from the first argument. `NULLIF` is deliberately
/// not unwrapped: its sentinel excludes a principal, which a bare column grant
/// would reverse.
pub fn extract_column_name_through_coalesce(expr: &Expr) -> Option<ColumnName> {
    if let Some(col) = extract_column_name(expr) {
        return Some(col);
    }
    if let Expr::Function(func) = expr {
        let name = crate::parser::names::folded_function_name(func);
        if matches!(name.as_deref(), Some("coalesce")) {
            if let FunctionArguments::List(arg_list) = &func.args {
                if let Some(first_arg) = arg_list.args.first() {
                    if let Some(inner) = function_arg_expr(first_arg) {
                        return extract_column_name(inner);
                    }
                }
            }
        }
    }
    None
}

/// Extract the expression payload from a SQL function argument.
pub fn function_arg_expr(arg: &FunctionArg) -> Option<&Expr> {
    match arg {
        FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))
        | FunctionArg::Named {
            arg: FunctionArgExpr::Expr(expr),
            ..
        }
        | FunctionArg::ExprNamed {
            arg: FunctionArgExpr::Expr(expr),
            ..
        } => Some(expr),
        _ => None,
    }
}

/// The function call `expr` makes, through casts and parentheses.
pub fn function_call(expr: &Expr) -> Option<&Function> {
    match unwrap_cast_or_nested(expr) {
        Expr::Function(function) => Some(function),
        _ => None,
    }
}

/// The argument `function` passes at `index`, absent where it passes fewer or names them
/// in a form that carries no expression.
pub fn positional_function_arg(function: &Function, index: usize) -> Option<&Expr> {
    let FunctionArguments::List(arg_list) = &function.args else {
        return None;
    };
    function_arg_expr(arg_list.args.get(index)?)
}

/// Returns `true` when the expression is wrapped through `COALESCE`.
pub fn is_coalesce_wrapped(expr: &Expr) -> bool {
    if let Expr::Function(func) = expr {
        let name = crate::parser::names::folded_function_name(func);
        return matches!(name.as_deref(), Some("coalesce"));
    }
    false
}

/// Whether any relation the expression or its subqueries read satisfies `matches`, which
/// stops the walk. A caller collecting every read returns `false` throughout.
/// Column qualifiers are identifiers, so `docs.owner_id` never reports `docs`.
pub fn reads_relation(expr: &Expr, mut matches: impl FnMut(&str) -> bool) -> bool {
    let mut reads = false;
    let _ = sqlparser::ast::visit_relations(expr, |name| {
        if matches(&name.to_string()) {
            reads = true;
            return core::ops::ControlFlow::Break(());
        }
        core::ops::ControlFlow::Continue(())
    });
    reads
}

#[cfg(test)]
use sqlparser::dialect::PostgreSqlDialect;
#[cfg(test)]
use sqlparser::parser::Parser;

/// Parse one SQL expression for tests.
#[cfg(test)]
pub(crate) fn parse_expr_for_tests(sql: &str) -> Expr {
    Parser::new(&PostgreSqlDialect {})
        .try_with_sql(sql)
        .expect("expression should parse")
        .parse_expr()
        .expect("expression should parse")
}

#[cfg(test)]
mod tests {
    use super::parse_expr_for_tests as parse_expr;
    use super::*;
    use sqlparser::ast::{Expr, Ident};

    #[test]
    fn extract_column_name_handles_simple_and_qualified_identifiers() {
        let simple = Expr::Identifier(Ident::new("owner_id"));
        let qualified = Expr::CompoundIdentifier(vec![
            Ident::new("public"),
            Ident::new("docs"),
            Ident::new("owner_id"),
        ]);
        let nested = Expr::Nested(Box::new(Expr::Identifier(Ident::new("owner_id"))));
        let casted = Expr::Cast {
            kind: sqlparser::ast::CastKind::Cast,
            expr: Box::new(Expr::Identifier(Ident::new("owner_id"))),
            data_type: DataType::Uuid,
            format: None,
        };

        assert_eq!(
            extract_column_name(&simple)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
        assert_eq!(
            extract_column_name(&qualified)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
        assert_eq!(
            extract_column_name(&nested)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
        assert_eq!(
            extract_column_name(&casted)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id")
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_unwraps_coalesce() {
        let expr = parse_expr("COALESCE(owner_id, '00000000-0000-0000-0000-000000000000')");
        assert_eq!(
            extract_column_name_through_coalesce(&expr)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id"),
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_refuses_nullif() {
        let expr = parse_expr("NULLIF(owner_id, '')");
        assert_eq!(
            extract_column_name_through_coalesce(&expr)
                .as_ref()
                .map(ColumnName::as_str),
            None,
        );
    }

    #[test]
    fn extract_column_name_through_coalesce_passes_through_plain_col() {
        let expr = Expr::Identifier(Ident::new("owner_id"));
        assert_eq!(
            extract_column_name_through_coalesce(&expr)
                .as_ref()
                .map(ColumnName::as_str),
            Some("owner_id"),
        );
    }
}
