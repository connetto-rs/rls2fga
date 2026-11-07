//! Values the request carries, declared by the deployment.
//!
//! PostgreSQL's request-scoped surface is open ended, so nothing in a policy says whether
//! `current_setting('app.subjects')` holds one person, one tenant or a set of grants. A
//! deployment declares that, and the kind it declares is what keeps a wrong allow
//! impossible: a set read where one value belongs finds no declaration of that kind and
//! stays unclassified, and so does the mirror case.
//!
//! The authority for these values is the token or the session, never a table, so they are
//! never copied into tuples. The row supplies its own value as tuple context, the request
//! supplies what only it knows, and a condition relates them.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sqlparser::ast::{BinaryOperator, Expr, FunctionArguments, InTarget, Query, SelectItem};

use crate::classifier::function_registry::{DeclaredSource, FunctionRegistry};
use crate::classifier::patterns::{
    CallerScalarEqualsConstant, ClassifiedExpr, ConfidenceLevel, ConstantInCallerSet, PatternClass,
    RowValueEqualsCallerScalar, RowValueInCallerSet,
};
use crate::parser::expr::{function_arg_expr, CastChain};
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::builtin_function_name;
use crate::parser::sql_parser::SetPacking;
use crate::types::ColumnName;

use super::casts::other_side_renaming;
use super::{
    accessor_read, accessor_value_read, current_setting_literal_key, extract_column_name,
    projected_select, string_literal, AccessorRead,
};

/// A value the request carries, compared against a row column or against a constant.
///
/// Four shapes, one recognizer, because they differ only in which side is the row's:
/// the caller's set holding a row value or a constant, and the caller's single value
/// equalling a row value or a constant.
pub fn recognize_session_attribute(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    set_membership(expr, registry)
        .or_else(|| set_membership_in_subquery(expr, registry))
        .or_else(|| scalar_equality(expr, registry))
}

/// `<row column or constant> = ANY (<the caller's set>)`.
fn set_membership(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::AnyOp {
        left,
        compare_op: BinaryOperator::Eq,
        right,
        ..
    } = expr
    else {
        return None;
    };
    let (source, separator, casts) = declared_set(array_valued_set(right, registry)?, registry)?;
    tested_against_set(left, source, separator, &casts)
}

/// `<row column or constant> IN (SELECT <the caller's set>)`.
///
/// The same database as the `= ANY` spelling, so it routes through the same reader and
/// lands on the same pattern. The subquery has to be only its projection, which is what
/// keeps this away from a membership subquery: that one always reads a `FROM`.
fn set_membership_in_subquery(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::In {
        expr: left,
        target: InTarget::Subquery(subquery),
        negated: false,
        global: false,
    } = expr
    else {
        return None;
    };
    let (source, separator, casts) = declared_set(
        row_valued_set(sole_projection(subquery)?, registry)?,
        registry,
    )?;
    tested_against_set(left, source, separator, &casts)
}

/// What the caller's set is compared against decides which pattern it is, and both
/// spellings answer that the same way.
fn tested_against_set(
    tested: &Expr,
    source: &DeclaredSource,
    separator: Option<String>,
    casts: &CastChain,
) -> Option<ClassifiedExpr> {
    if other_side_renaming(tested, casts).is_some() {
        return None;
    }
    let pattern = match tested_value(tested) {
        TestedValue::Column(column) => PatternClass::P14RowValueInCallerSet(RowValueInCallerSet {
            column,
            separator,
            source: source.clone(),
        }),
        TestedValue::Constant(value) => PatternClass::P16ConstantInCallerSet(ConstantInCallerSet {
            value,
            separator,
            source: source.clone(),
        }),
        TestedValue::Neither => return None,
    };
    Some(ClassifiedExpr {
        pattern,
        confidence: grade(source),
    })
}

/// `<row column or constant> = <declared single value>`, either way round.
fn scalar_equality(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };

    let ((source, casts), tested) = match declared_scalar(right, registry) {
        Some(source) => (source, left.as_ref()),
        None => (declared_scalar(left, registry)?, right.as_ref()),
    };
    if other_side_renaming(tested, &casts).is_some() {
        return None;
    }

    let pattern = match tested_value(tested) {
        TestedValue::Column(column) => {
            PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
                column,
                source: source.clone(),
            })
        }
        TestedValue::Constant(value) => {
            PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
                value,
                source: source.clone(),
            })
        }
        TestedValue::Neither => return None,
    };
    Some(ClassifiedExpr {
        pattern,
        confidence: grade(source),
    })
}

/// What the declared value is being compared against.
enum TestedValue {
    /// A column of the guarded row, so the row supplies it as tuple context.
    Column(ColumnName),
    /// A literal from the policy, so the rule supplies it as tuple context.
    Constant(String),
    Neither,
}

fn tested_value(expr: &Expr) -> TestedValue {
    if let Some(column) = extract_column_name(expr) {
        return TestedValue::Column(column);
    }
    match string_literal(expr) {
        Some(value) => TestedValue::Constant(value),
        None => TestedValue::Neither,
    }
}

/// A field taken out of the caller's value is indirection, which caps at B exactly as a
/// scalar subquery wrapper and a `COALESCE` wrapper already do.
fn grade(source: &DeclaredSource) -> ConfidenceLevel {
    if source.path().is_empty() {
        ConfidenceLevel::A
    } else {
        ConfidenceLevel::B
    }
}

/// The declared source `expr` reads, when it was declared as one single value and no cast
/// on the read renames it.
fn declared_scalar<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(&'r DeclaredSource, CastChain)> {
    declared_read(expr, registry)
        .filter(|(source, casts)| casts.renaming(Some(&source.canonical_type())).is_none())
}

/// A source the caller's set comes from, named rather than resolved, so one reader
/// answers both while classifying a policy and while the registry is still being built.
#[derive(Debug, Clone)]
pub(crate) struct SetSource {
    /// The `current_setting` key behind it.
    pub(crate) key: String,
    /// The field path taken out of that key's value.
    pub(crate) path: Vec<String>,
    /// The separator the policy splits on, absent where the source is already a list.
    pub(crate) separator: Option<String>,
    /// Every cast between the setting and the set's elements, outermost first.
    pub(crate) casts: CastChain,
}

impl SetSource {
    /// Whether this read yields the elements `declared` holds, which takes a set unpacked
    /// the way the deployment packs it under no cast that renames an element.
    ///
    /// A split on another delimiter than the declared one names elements the request never
    /// sent, and a JSON array split as text or text expanded as JSON names none at all.
    pub(crate) fn reads_as(&self, declared: &DeclaredSource) -> bool {
        let unpacked = match (declared.packing(), self.separator.as_deref()) {
            (Some(SetPacking::Delimited(declared)), Some(split)) => declared == split,
            (Some(SetPacking::JsonArray), None) => true,
            _ => false,
        };
        unpacked
            && self
                .casts
                .renaming(Some(&declared.canonical_type()))
                .is_none()
    }
}

/// An **array valued** expression yielding the caller's set, which is what `= ANY (...)`
/// takes.
///
/// Kept apart from the row valued reader because `PostgreSQL` keeps them apart: `= ANY`
/// refuses a set returning argument and `IN (SELECT ...)` refuses an array, so merging
/// the two would classify shapes the database rejects.
pub(super) fn array_valued_set(expr: &Expr, registry: &FunctionRegistry) -> Option<SetSource> {
    let (mut casts, peeled) = CastChain::peeled(expr);
    let Expr::Function(function) = peeled else {
        return None;
    };
    // `ARRAY(SELECT ...)` collects rows into an array, so its projection is read as one.
    let mut source = if let FunctionArguments::Subquery(query) = &function.args {
        row_valued_set(sole_projection(query)?, registry)?
    } else {
        if builtin_function_name(function).as_deref() != Some("string_to_array") {
            return None;
        }
        let FunctionArguments::List(list) = &function.args else {
            return None;
        };
        // A third argument names a string that reads back as NULL, which changes which
        // elements exist.
        let [value, separator] = list.args.as_slice() else {
            return None;
        };
        let separator = string_literal(function_arg_expr(separator)?)?;
        source_read_by(function_arg_expr(value)?, Some(separator), registry)?
    };
    casts.extend(source.casts);
    source.casts = casts;
    Some(source)
}

/// A **row valued** expression yielding the caller's set, which is what `IN (SELECT ...)`
/// takes and what the body of a set returning wrapper is.
pub(crate) fn row_valued_set(expr: &Expr, registry: &FunctionRegistry) -> Option<SetSource> {
    let (mut casts, peeled) = CastChain::peeled(expr);
    let Expr::Function(function) = peeled else {
        return None;
    };
    // A wrapper whose whole body reads a declared setting is a spelling of that setting,
    // which is the one route a function reaches a source by. Declared wrappers keep
    // their written name, since the registry keys on it.
    let mut source = if let Some(FunctionSemantic::SetReader {
        key,
        path,
        separator,
    }) = registry.get(&function.name.to_string())
    {
        // Inference admits a wrapper only once its own casts hold.
        SetSource {
            key: key.clone(),
            path: path.clone(),
            separator: separator.clone(),
            casts: CastChain::default(),
        }
    } else {
        let FunctionArguments::List(list) = &function.args else {
            return None;
        };
        let [argument] = list.args.as_slice() else {
            return None;
        };
        let argument = function_arg_expr(argument)?;
        match builtin_function_name(function).as_deref() {
            // A jsonb array yielded as text is the caller's list itself, so no separator
            // exists and the contract is simply to send the list.
            Some("jsonb_array_elements_text") => {
                let mut source = source_read_by(argument, None, registry)?;
                source.casts = source.casts.without_json_parse();
                source
            }
            // Expanding a split is the same database as the split, separator included.
            Some("unnest") => array_valued_set(argument, registry)?,
            _ => return None,
        }
    };
    casts.extend(source.casts);
    source.casts = casts;
    Some(source)
}

/// The single expression a subquery projects, when nothing in it can drop that row.
pub(super) fn sole_projection(query: &Query) -> Option<&Expr> {
    let [SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }] =
        projected_select(query)?.projection.as_slice()
    else {
        return None;
    };
    Some(expr)
}

/// The set source an expression reads, split on `separator` where one is given.
///
/// A jsonb array is reached through a chain ending in `->`, since `->>` renders the
/// array as text and `PostgreSQL` refuses to expand text, so this accepts either ending
/// while the scalar reader accepts only `->>`.
fn source_read_by(
    expr: &Expr,
    separator: Option<String>,
    registry: &FunctionRegistry,
) -> Option<SetSource> {
    let AccessorRead { root, path, casts } = accessor_value_read(expr)
        .filter(|read| !read.path.is_empty())
        .or_else(|| accessor_read(expr))?;
    Some(SetSource {
        key: setting_key_read_by(root, registry)?,
        path,
        separator,
        casts,
    })
}

/// The declared set an array valued expression yields.
pub(crate) fn caller_set<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(&'r DeclaredSource, Option<String>)> {
    let (source, separator, _) = declared_set(array_valued_set(expr, registry)?, registry)?;
    Some((source, separator))
}

/// The declared set a subquery projects, which is what `IN (SELECT ...)` takes.
pub(crate) fn caller_set_in_subquery<'r>(
    query: &Query,
    registry: &'r FunctionRegistry,
) -> Option<(&'r DeclaredSource, Option<String>)> {
    let (source, separator, _) =
        declared_set(row_valued_set(sole_projection(query)?, registry)?, registry)?;
    Some((source, separator))
}

/// The set declaration `source` reads, when the read unpacks it as declared and no cast
/// on the read renames its elements.
fn declared_set(
    source: SetSource,
    registry: &FunctionRegistry,
) -> Option<(&DeclaredSource, Option<String>, CastChain)> {
    let declared = resolve_declared_set(&source, registry)?;
    if !source.reads_as(declared) {
        return None;
    }
    Some((declared, source.separator, source.casts))
}

/// The declaration a named source resolves to, when the deployment declared it a set.
///
/// The kind check is what makes the two wrong allows impossible rather than checked: a
/// single value read in set position finds no set declaration and stays unclassified.
fn resolve_declared_set<'r>(
    source: &SetSource,
    registry: &'r FunctionRegistry,
) -> Option<&'r DeclaredSource> {
    registry
        .declared_source(&source.key, &source.path)
        .filter(|declared| declared.packing().is_some())
}

/// The declared set `expr` reads and the casts on its elements, renaming or not.
pub(super) fn set_read<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(&'r DeclaredSource, CastChain)> {
    let source = array_valued_set(expr, registry).or_else(|| row_valued_set(expr, registry))?;
    Some((resolve_declared_set(&source, registry)?, source.casts))
}

/// Why every set `expr` compares against stays unclassified, where the deployment did
/// not declare that set as one.
///
/// Answers for diagnosis, after recognition failed: the splitter and the setting reader
/// are then not what is missing, the declaration is.
pub(crate) fn undeclared_set_reads(expr: &Expr, registry: &FunctionRegistry) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        let source = match node {
            Expr::AnyOp {
                compare_op: BinaryOperator::Eq,
                right,
                ..
            } => array_valued_set(right, registry),
            Expr::In {
                target: InTarget::Subquery(subquery),
                negated: false,
                ..
            } => {
                sole_projection(subquery).and_then(|projected| row_valued_set(projected, registry))
            }
            _ => None,
        };
        if let Some(reason) = source.and_then(|source| undeclared_set_reason(&source, registry)) {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    reasons
}

/// Why `source`, read as a set, resolves to no set declaration it unpacks as declared, or
/// `None` when it does.
fn undeclared_set_reason(source: &SetSource, registry: &FunctionRegistry) -> Option<String> {
    let read = if source.path.is_empty() {
        format!("current_setting('{}')", source.key)
    } else {
        format!(
            "field '{}' of current_setting('{}')",
            source.path.join("."),
            source.key
        )
    };
    let unpacking = match &source.separator {
        Some(separator) => format!("split on '{separator}'"),
        None => "expanded as a JSON array".to_string(),
    };
    let declared = match registry.declared_source(&source.key, &source.path) {
        None => "the deployment declares no such setting".to_string(),
        Some(declared) if declared.packing().is_none() => {
            format!("the deployment declares it as {}", declared.declared_as())
        }
        Some(declared) if source.reads_as(declared) => return None,
        Some(declared) => format!(
            "the deployment declares it as {} of {}",
            declared.declared_as(),
            declared.canonical_type()
        ),
    };
    Some(format!("{read} is {unpacking} and {declared}"))
}

/// The single-value declaration behind whatever `expr` reads and the casts around the
/// read, however the deployment spelled it. A set is read through [`set_read`], whose
/// expander takes the parse into `jsonb` as structure, and the caller through its own
/// readers.
pub(super) fn declared_read<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(&'r DeclaredSource, CastChain)> {
    let AccessorRead { root, path, casts } = accessor_read(expr)?;
    let key = setting_key_read_by(root, registry)?;
    let source = registry
        .declared_source(&key, &path)
        .filter(|source| source.is_scalar())?;
    Some((source, casts))
}

/// The `current_setting` key a node names, written inline or wrapped in a function whose
/// whole body reads it. Both spellings reach one declaration, so they cannot disagree.
pub(super) fn setting_key_read_by(root: &Expr, registry: &FunctionRegistry) -> Option<String> {
    if let Some(key) = current_setting_literal_key(root) {
        return Some(key);
    }
    let Expr::Function(function) = root else {
        return None;
    };
    match registry.get(&function.name.to_string())? {
        FunctionSemantic::SettingReader { key } => Some(key.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::recognizers::is_current_user_expr;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use crate::parser::sql_parser::SettingValue;
    use crate::test_support::{caller, delimited_set, json_field, registry, scalar};
    use sqlparser::ast::DataType;

    /// A JSON setting whose `teams` field holds a JSON array of text.
    fn teams_claim() -> crate::parser::sql_parser::SessionSetting {
        json_field(
            "request.jwt.claims",
            &["teams"],
            SettingValue::Set {
                element: DataType::Text,
                packing: SetPacking::JsonArray,
            },
        )
    }

    /// A set read where one value belongs is the recorded tenant trap in the other
    /// direction, so the kind has to refuse it rather than fall through to ownership.
    #[test]
    fn a_declared_set_read_as_one_value_is_refused() {
        let registry = registry([delimited_set("app.subjects", ",")]);
        let expr = parse_expr("owner = current_setting('app.subjects', true)");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a set is not one value"
        );
    }

    /// The mirror: one value read as a set grants by a split of something that holds one
    /// element, which is not what the deployment declared.
    #[test]
    fn a_declared_single_value_read_as_a_set_is_refused() {
        let expr =
            parse_expr("owner = ANY(string_to_array(current_setting('app.tenant_id'), ','))");
        let registry_of_scalar = registry([scalar("app.tenant_id")]);
        assert!(
            recognize_session_attribute(&expr, &registry_of_scalar).is_none(),
            "one value is not a set"
        );
        assert_eq!(
            undeclared_set_reads(&expr, &registry_of_scalar),
            vec![
                "current_setting('app.tenant_id') is split on ',' and the deployment declares \
                 it as one value"
                    .to_string()
            ],
            "the refusal names what the deployment declared"
        );
        assert_eq!(
            undeclared_set_reads(&expr, &registry([caller("app.tenant_id")])),
            vec![
                "current_setting('app.tenant_id') is split on ',' and the deployment declares \
                 it as the caller"
                    .to_string()
            ]
        );
    }

    /// A split on another delimiter than the deployment joins the set with names elements
    /// the request never sent, as `string_to_array('a,b', ';')` is `{"a,b"}`. The read is
    /// refused, naming both delimiters.
    #[test]
    fn a_split_on_another_separator_than_declared_is_refused() {
        let registry = registry([delimited_set("app.subjects", ",")]);
        let expr = parse_expr("owner = ANY(string_to_array(current_setting('app.subjects'), ';'))");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a split on ';' of a set joined by ',' names other elements"
        );
        assert_eq!(
            undeclared_set_reads(&expr, &registry),
            vec![
                "current_setting('app.subjects') is split on ';' and the deployment declares \
                 it as a set joined by ',' of text"
                    .to_string()
            ]
        );
    }

    /// The declared delimiter is the one a policy splits on, whatever it is.
    #[test]
    fn the_declared_separator_is_read() {
        let registry = registry([delimited_set("app.subjects", ";")]);
        let expr = parse_expr("owner = ANY(string_to_array(current_setting('app.subjects'), ';'))");
        assert!(
            matches!(
                recognize_session_attribute(&expr, &registry).map(|c| c.pattern),
                Some(PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { separator, .. }))
                    if separator.as_deref() == Some(";")
            ),
            "the separator decides which elements exist"
        );
    }

    /// A set packed as a JSON array is expanded as JSON, and splitting its text names no
    /// element the request sent. A delimited set is no JSON document either.
    #[test]
    fn a_set_is_unpacked_only_the_way_it_is_packed() {
        let json = registry([teams_claim()]);
        let expanded = parse_expr(
            "team IN (SELECT jsonb_array_elements_text(current_setting('request.jwt.claims')::jsonb -> 'teams'))",
        );
        assert!(
            recognize_session_attribute(&expanded, &json).is_some(),
            "the JSON array is expanded as declared"
        );
        let split = parse_expr(
            "team = ANY(string_to_array(current_setting('request.jwt.claims')::jsonb ->> 'teams', ','))",
        );
        assert!(
            recognize_session_attribute(&split, &json).is_none(),
            "a JSON array split as text names other elements"
        );
        assert_eq!(
            undeclared_set_reads(&split, &json),
            vec![
                "field 'teams' of current_setting('request.jwt.claims') is split on ',' and \
                 the deployment declares it as a set packed as a JSON array of text"
                    .to_string()
            ]
        );

        let delimited = registry([delimited_set("app.subjects", ",")]);
        let expanded = parse_expr(
            "owner IN (SELECT jsonb_array_elements_text(current_setting('app.subjects')::jsonb))",
        );
        assert!(
            recognize_session_attribute(&expanded, &delimited).is_none(),
            "a delimited set expanded as JSON names no element"
        );
        assert_eq!(
            undeclared_set_reads(&expanded, &delimited),
            vec![
                "current_setting('app.subjects') is expanded as a JSON array and the \
                 deployment declares it as a set joined by ',' of text"
                    .to_string()
            ]
        );
    }

    /// A cast to an array splits on `PostgreSQL`'s array literal syntax rather than on a
    /// separator, so the caller contract differs and the shape falls closed.
    #[test]
    fn an_array_cast_is_not_the_declared_split() {
        let registry = registry([delimited_set("app.subjects", ",")]);
        let expr = parse_expr("owner = ANY(current_setting('app.subjects', true)::text[])");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "an array cast is a different split"
        );
    }

    /// A third argument to the split names a string that reads back as NULL, so the
    /// elements are not the ones the contract describes.
    #[test]
    fn a_null_string_argument_refuses_the_split() {
        let registry = registry([delimited_set("app.subjects", ",")]);
        let expr =
            parse_expr("owner = ANY(string_to_array(current_setting('app.subjects'), ',', 'x'))");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a null string changes which elements exist"
        );
    }

    /// A field the deployment declares as the caller is the caller, and only that field:
    /// the token holding it is not, and neither is a sibling field.
    #[test]
    fn a_field_declared_as_the_caller_is_the_caller() {
        let registry = registry([json_field(
            "request.jwt.claims",
            &["sub"],
            SettingValue::Caller(DataType::Text),
        )]);
        let sub = parse_expr("current_setting('request.jwt.claims')::json ->> 'sub'");
        assert!(is_current_user_expr(&sub, &registry));
        assert!(
            recognize_session_attribute(&parse_expr(&format!("owner = {sub}")), &registry)
                .is_none(),
            "the caller is not a value the request compares with a condition"
        );
        for other in [
            "current_setting('request.jwt.claims')",
            "current_setting('request.jwt.claims')::json ->> 'tenant'",
        ] {
            assert!(
                !is_current_user_expr(&parse_expr(other), &registry),
                "{other} is not the field declared as the caller"
            );
        }
    }

    /// A different splitter is a different split, so the caller contract would name
    /// elements the database never produces. Only `string_to_array` reaches a set.
    #[test]
    fn another_splitting_function_is_not_the_declared_split() {
        let registry = registry([delimited_set("app.subjects", ",")]);
        let expr = parse_expr(
            "owner = ANY(regexp_split_to_array(current_setting('app.subjects', true), ','))",
        );
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "a regexp split names different elements"
        );
    }

    /// `GLOBAL IN` is `ClickHouse` syntax that `PostgreSqlDialect` never parses, so the only
    /// way it reaches this matcher is a hand-built AST, and the field has to be read, not
    /// wildcarded away.
    #[test]
    fn a_global_in_subquery_is_not_the_declared_set() {
        let registry = registry([delimited_set("app.subjects", ",")]);
        let expr = parse_expr(
            "owner IN (SELECT unnest(string_to_array(current_setting('app.subjects', true), ',')))",
        );
        assert!(
            recognize_session_attribute(&expr, &registry).is_some(),
            "sanity: the ordinary IN subquery reads the declared set"
        );
        let Expr::In {
            expr: left,
            target: target @ InTarget::Subquery(_),
            negated,
            ..
        } = &expr
        else {
            panic!("expected an IN subquery");
        };
        let global = Expr::In {
            expr: left.clone(),
            target: target.clone(),
            negated: *negated,
            global: true,
        };
        assert!(
            recognize_session_attribute(&global, &registry).is_none(),
            "a ClickHouse GLOBAL IN is not PostgreSQL's declared-set membership"
        );
    }

    /// Nothing declared the setting, so nothing may read it.
    #[test]
    fn an_undeclared_setting_reads_as_nothing() {
        let registry = FunctionRegistry::new();
        let expr =
            parse_expr("owner = ANY(string_to_array(current_setting('app.subjects', true), ','))");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "an empty registry declares nothing"
        );
    }

    /// The path is part of the source, so a declaration of one field does not answer for
    /// another.
    #[test]
    fn a_declared_field_does_not_answer_for_its_sibling() {
        let registry = registry([json_field(
            "request.jwt.claims",
            &["aal"],
            SettingValue::Scalar(DataType::Text),
        )]);
        let expr = parse_expr("current_setting('request.jwt.claims')::jsonb ->> 'role' = 'admin'");
        assert!(
            recognize_session_attribute(&expr, &registry).is_none(),
            "one field is not another"
        );
        let declared =
            parse_expr("current_setting('request.jwt.claims')::jsonb ->> 'aal' = 'aal2'");
        assert!(
            recognize_session_attribute(&declared, &registry).is_some(),
            "the declared field answers"
        );
    }

    /// A field is indirection, which caps at B, while a plain key read does not.
    #[test]
    fn a_field_read_grades_below_a_plain_key_read() {
        let registry = registry([
            scalar("app.tenant_id"),
            json_field(
                "request.jwt.claims",
                &["aal"],
                SettingValue::Scalar(DataType::Text),
            ),
        ]);
        let plain = parse_expr("tenant_id = current_setting('app.tenant_id')");
        let hopped = parse_expr("current_setting('request.jwt.claims')::jsonb ->> 'aal' = 'aal2'");
        assert_eq!(
            recognize_session_attribute(&plain, &registry).map(|c| c.confidence),
            Some(ConfidenceLevel::A)
        );
        assert_eq!(
            recognize_session_attribute(&hopped, &registry).map(|c| c.confidence),
            Some(ConfidenceLevel::B)
        );
    }
}
