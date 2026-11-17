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

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArguments, InTarget, Query, SelectItem,
};

use crate::classifier::function_registry::{DeclaredSource, FunctionRegistry};
use crate::classifier::patterns::{
    CallerScalarEqualsConstant, CallerScalarInConstantList, CallerScalarUnequalsConstant,
    ClassifiedExpr, ConfidenceLevel, ConstantInCallerSet, FallbackScalarEqualsConstant,
    FallbackScalarInConstantList, FallbackScalarUnequalsConstant, PatternClass, RequestValueAbsent,
    RowValueEqualsCallerScalar, RowValueInCallerSet,
};
use crate::parser::expr::{
    function_arg_expr, function_call, positional_function_arg, unwrap_cast_or_nested, CastChain,
};
use crate::parser::function_analyzer::{
    empty_sentinel_nullif, fallback_source_shape, FallbackSourceShape, FunctionSemantic,
};
use crate::parser::names::builtin_function_name;
use crate::parser::sql_parser::SetPacking;
use crate::types::{ColumnName, FallbackStep, RequestNormalization};

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
        .or_else(|| scalar_inequality(expr, registry))
        .or_else(|| scalar_in_constant_list(expr, registry))
        .or_else(|| absence_test(expr, registry))
        .or_else(|| fallback_comparison(expr, registry))
}

/// The value a fallback read hands over, compared with a constant the policy names:
/// `auth.role() = 'authenticated'`, and the `IN` or `NOT IN`, or the `= ANY (ARRAY
/// [...])` the same value admits, spelled however the fallback is.
///
/// A column or a call the tested side names stays unclassified, since the fallback is a
/// value the request carries and a row's part in it is a different gate.
fn fallback_comparison(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    fallback_equality(expr, registry)
        .or_else(|| fallback_inequality(expr, registry))
        .or_else(|| fallback_in_constant_list(expr, registry))
}

/// `<constant> = <the value a fallback read hands over>`, either way round.
fn fallback_equality(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };
    let ((first, rest, casts), tested) = match fallback_read(right, registry) {
        Some(read) => (read, left.as_ref()),
        None => (fallback_read(left, registry)?, right.as_ref()),
    };
    let value = fallback_tested_value(tested, &casts)?;
    Some(ClassifiedExpr {
        pattern: PatternClass::P23FallbackScalarEqualsConstant(FallbackScalarEqualsConstant {
            value,
            first,
            rest,
        }),
        confidence: ConfidenceLevel::B,
    })
}

/// `<the value a fallback read hands over> <> <literal>`, either way round.
///
/// A column on the literal's side stays unclassified, since a row value the fallback
/// value has to differ from is a different gate with its own shape.
fn fallback_inequality(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::NotEq,
        right,
    } = expr
    else {
        return None;
    };
    let ((first, rest, casts), tested) = match fallback_read(left, registry) {
        Some(read) => (read, right.as_ref()),
        None => (fallback_read(right, registry)?, left.as_ref()),
    };
    let value = fallback_tested_value(tested, &casts)?;
    Some(ClassifiedExpr {
        pattern: PatternClass::P24FallbackScalarUnequalsConstant(FallbackScalarUnequalsConstant {
            value,
            first,
            rest,
        }),
        confidence: ConfidenceLevel::B,
    })
}

/// `<the value a fallback read hands over> IN (<literals>)`, however negated, and the
/// same test spelled `= ANY (ARRAY[<literals>])`, which `PostgreSQL` reads as one
/// membership.
///
/// Every element has to be a literal, since a column among them is a per-row value the
/// list cannot stand in for, and an element a cast renames reads as a different value.
fn fallback_in_constant_list(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let (tested, list, negated) = match expr {
        Expr::In {
            expr: tested,
            target: InTarget::List(list),
            negated,
            global: false,
        } => (tested.as_ref(), list.as_slice(), *negated),
        Expr::AnyOp {
            left: tested,
            compare_op: BinaryOperator::Eq,
            right,
            is_some: false,
        } => {
            let Expr::Array(array) = unwrap_cast_or_nested(right) else {
                return None;
            };
            (tested.as_ref(), array.elem.as_slice(), false)
        }
        _ => return None,
    };
    // `PostgreSQL` has no empty list, and the model has no gate to state one.
    if list.is_empty() {
        return None;
    }
    let (first, rest, casts) = fallback_read(tested, registry)?;
    if list
        .iter()
        .any(|element| other_side_renaming(element, &casts).is_some())
    {
        return None;
    }
    let values = list
        .iter()
        .map(string_literal)
        .collect::<Option<Vec<_>>>()?;
    Some(ClassifiedExpr {
        pattern: PatternClass::P25FallbackScalarInConstantList(FallbackScalarInConstantList {
            values,
            negated,
            first,
            rest,
        }),
        confidence: ConfidenceLevel::B,
    })
}

/// The constant a fallback read is compared against, a column and a cast that renames it
/// refused with the column.
fn fallback_tested_value(tested: &Expr, casts: &CastChain) -> Option<String> {
    if other_side_renaming(tested, casts).is_some() {
        return None;
    }
    match tested_value(tested) {
        TestedValue::Constant(value) => Some(value),
        _ => None,
    }
}

/// The first source the fallback `expr` tries and the ones it falls back through after
/// it, in the order the read tries them, and the casts that decide the type the tested
/// side stands in, so a literal it is compared with keeps its spelling or is refused
/// with it.
///
/// Two spellings reach one declaration: a `COALESCE` spelled where the comparison is,
/// and a call whose body is one, which the registry reads at adoption. Each source must
/// be declared one single value, and a cast that renames a source's value is a refusal.
pub(super) fn fallback_read(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<(FallbackStep, Vec<FallbackStep>, CastChain)> {
    let (outer, peeled) = CastChain::peeled(expr);
    let (first, rest, tested_side) = match peeled {
        Expr::Function(
            function @ Function {
                args: FunctionArguments::List(list),
                ..
            },
        ) if builtin_function_name(function).as_deref() == Some("coalesce") => {
            let mut args = list.args.iter().filter_map(function_arg_expr);
            // A `COALESCE` of one source is that source, which the setting read above
            // reads.
            let first = fallback_source_shape(args.next()?)?;
            let FallbackSourceShape {
                key,
                path,
                skips_empty,
                value_casts,
            } = first;
            let first_step =
                resolve_fallback_source(&key, &path, skips_empty, &value_casts, &outer, registry)?;
            let mut tested_side = outer.clone();
            if tested_side.outermost().is_none() {
                // The tested side stands in the type the first source gives, so its casts
                // decide a literal's spelling.
                tested_side.extend(value_casts);
            }
            let mut rest = Vec::new();
            for arg in args {
                let shape = fallback_source_shape(arg)?;
                let FallbackSourceShape {
                    key,
                    path,
                    skips_empty,
                    value_casts,
                } = shape;
                rest.push(resolve_fallback_source(
                    &key,
                    &path,
                    skips_empty,
                    &value_casts,
                    &outer,
                    registry,
                )?);
            }
            (first_step, rest, tested_side)
        }
        other => {
            let function = function_call(other)?;
            let FunctionSemantic::SettingFallback { sources: declared } =
                registry.get(&function.name.to_string())?
            else {
                return None;
            };
            let mut declared = declared.iter();
            let first_source = declared.next()?;
            let first = resolve_fallback_source(
                &first_source.key,
                &first_source.path,
                first_source.skips_empty,
                &CastChain::default(),
                &outer,
                registry,
            )?;
            // The body's own casts were judged at adoption; the read's are.
            let mut rest = Vec::with_capacity(declared.len());
            for source in declared {
                rest.push(resolve_fallback_source(
                    &source.key,
                    &source.path,
                    source.skips_empty,
                    &CastChain::default(),
                    &outer,
                    registry,
                )?);
            }
            (first, rest, outer)
        }
    };
    Some((first, rest, tested_side))
}

/// The source a fallback read tries, declared one single value and read by a cast that
/// cannot rename it.
fn resolve_fallback_source(
    key: &str,
    path: &[String],
    skips_empty: bool,
    value_casts: &CastChain,
    outer: &CastChain,
    registry: &FunctionRegistry,
) -> Option<FallbackStep> {
    let declared = registry
        .declared_source(key, path)
        .filter(|source| source.is_scalar())?;
    let mut casts = outer.clone();
    casts.extend(value_casts.clone());
    if casts.renaming(Some(&declared.canonical_type())).is_some() {
        return None;
    }
    Some(FallbackStep {
        setting_key: declared.setting_key().to_string(),
        parameter: declared.request_parameter().to_string(),
        from_json_field: !declared.path().is_empty(),
        skips_empty,
        may_be_unset: declared.may_be_unset(),
    })
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

    let confidence = grade(&source);
    let source = source.into_owned();
    let pattern = match tested_value(tested) {
        TestedValue::Column(column) => {
            PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
                column,
                source,
            })
        }
        TestedValue::Constant(value) => {
            PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
                value,
                source,
            })
        }
        TestedValue::Neither => return None,
    };
    Some(ClassifiedExpr {
        pattern,
        confidence,
    })
}

/// `<declared single value> <> <literal>`, either way round.
///
/// A column on the literal's side stays unclassified, since a row value the request's
/// value has to differ from is a different gate with its own shape.
fn scalar_inequality(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::NotEq,
        right,
    } = expr
    else {
        return None;
    };

    let ((source, casts), tested) = match declared_scalar(left, registry) {
        Some(source) => (source, right.as_ref()),
        None => (declared_scalar(right, registry)?, left.as_ref()),
    };
    if other_side_renaming(tested, &casts).is_some() {
        return None;
    }

    let TestedValue::Constant(value) = tested_value(tested) else {
        return None;
    };
    Some(ClassifiedExpr {
        confidence: grade(&source),
        pattern: PatternClass::P21CallerScalarUnequalsConstant(CallerScalarUnequalsConstant {
            value,
            source: source.into_owned(),
        }),
    })
}

/// `<declared single value> IN (<literals>)`, however negated, and the same test spelled
/// `= ANY (ARRAY[<literals>])`, which `PostgreSQL` reads as one membership.
///
/// Every element has to be a literal, since a column among them is a per-row value the
/// list cannot stand in for, and an element a cast renames reads as a different value.
fn scalar_in_constant_list(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let (tested, list, negated) = match expr {
        Expr::In {
            expr: tested,
            target: InTarget::List(list),
            negated,
            global: false,
        } => (tested.as_ref(), list.as_slice(), *negated),
        Expr::AnyOp {
            left: tested,
            compare_op: BinaryOperator::Eq,
            right,
            is_some: false,
        } => {
            let Expr::Array(array) = unwrap_cast_or_nested(right) else {
                return None;
            };
            (tested.as_ref(), array.elem.as_slice(), false)
        }
        _ => return None,
    };
    // `PostgreSQL` has no empty list, and the model has no gate to state one.
    if list.is_empty() {
        return None;
    }
    let (source, casts) = declared_scalar(tested, registry)?;
    // An element a cast renames, or that is no literal, is a value the list cannot stand
    // in for, so the whole list stays refused.
    if list
        .iter()
        .any(|element| other_side_renaming(element, &casts).is_some())
    {
        return None;
    }
    let values = list
        .iter()
        .map(string_literal)
        .collect::<Option<Vec<_>>>()?;
    Some(ClassifiedExpr {
        confidence: grade(&source),
        pattern: PatternClass::P22CallerScalarInConstantList(CallerScalarInConstantList {
            values,
            negated,
            source: source.into_owned(),
        }),
    })
}

/// `<NULLIF read> IS NULL`, the request leaving a value it may leave unset absent, and
/// `IS NOT NULL`, the request carrying it.
///
/// Only the wrapped read is an absence the request states, since [`nullif_read`] reads
/// both unset readings as `NULL`, while the bare read is `''` in one of them. A cast that
/// renames the read raises on the values it cannot spell, so it is refused with them.
fn absence_test(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    let (tested, negated) = match expr {
        Expr::IsNull(tested) => (tested, false),
        Expr::IsNotNull(tested) => (tested, true),
        _ => return None,
    };
    let (source, casts) = nullif_read(tested, registry)?;
    if casts.renaming(Some(&source.canonical_type())).is_some() {
        return None;
    }
    Some(ClassifiedExpr {
        pattern: PatternClass::P28RequestValueAbsent(RequestValueAbsent {
            source: source.clone(),
            negated,
        }),
        confidence: grade(source),
    })
}

/// Why every `IS NULL` and `IS NOT NULL` in `expr` that tests a declared single value
/// stays unclassified, where [`absence_test`] does not read it as the request leaving
/// the value absent or carrying it.
///
/// Answers for diagnosis, after recognition failed.
pub(crate) fn refused_absence_tests(expr: &Expr, registry: &FunctionRegistry) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        let (Expr::IsNull(tested) | Expr::IsNotNull(tested)) = node else {
            return core::ops::ControlFlow::<()>::Continue(());
        };
        if let Some(reason) = absence_refusal(tested, registry) {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        core::ops::ControlFlow::Continue(())
    });
    reasons
}

/// Why testing `tested` for `NULL` has no translation, or `None` when it is no declared
/// single value or [`absence_test`] reads it.
fn absence_refusal(tested: &Expr, registry: &FunctionRegistry) -> Option<String> {
    if let Some(EmptiedRead { key, path, casts }) = emptied_setting_read(tested, registry) {
        let source = registry
            .declared_source(&key, &path)
            .filter(|source| source.is_scalar())?;
        return if !path.is_empty() {
            Some(format!(
                "NULLIF hides a field of setting '{key}' holding '', which a request may \
                 carry, so testing it for NULL states nothing the request omits"
            ))
        } else if !source.may_be_unset() {
            Some(format!(
                "Setting '{key}' is declared set by every request, which may set it to '', \
                 so testing NULLIF of it for NULL tests no state the request can be in"
            ))
        } else {
            casts
                .renaming(Some(&source.canonical_type()))
                .map(|renamed| {
                    format!(
                        "Testing setting '{key}' for NULL through a cast to {renamed} raises \
                         on the values {renamed} cannot spell, which the model would admit"
                    )
                })
        };
    }
    let (source, _) = bare_declared_read(tested, registry)?;
    let key = source.setting_key();
    Some(if !source.path().is_empty() {
        format!("A field of setting '{key}' tested for NULL has no translation")
    } else if source.may_be_unset() {
        format!(
            "Setting '{key}' reads as '' rather than NULL once a transaction-local value \
             has ended, so testing it for NULL misses a request leaving it unset. Test \
             NULLIF(current_setting('{key}', true), '') instead"
        )
    } else {
        format!(
            "Setting '{key}' is declared set by every request, so testing it for NULL tests \
             no state the request can be in"
        )
    })
}

/// Why every read of a declared single value through `NULLIF(<read>, '')` in `expr`,
/// inline or through an accessor whose body is the wrap, is not the value the request
/// sends, where the wrap hides a `''` the request may send.
///
/// Answers for diagnosis, after recognition failed.
pub(crate) fn refused_emptied_reads(expr: &Expr, registry: &FunctionRegistry) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if let Some(reason) = emptied_read_refusal(node, registry) {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    reasons
}

/// Why `expr`, a read through `NULLIF(<read>, '')`, is not the value the request sends,
/// or `None` when it is no such read of a declared single value or the request never
/// sends the `''` the wrap hides. A call to an accessor normalizing such a read is one.
fn emptied_read_refusal(expr: &Expr, registry: &FunctionRegistry) -> Option<String> {
    let (key, path) = match emptied_setting_read(expr, registry) {
        Some(EmptiedRead { key, path, .. }) => (key, path),
        None => normalized_accessor_read(expr, registry)
            .filter(|read| read.skips_empty)
            .map(|read| (read.source.setting_key().to_string(), Vec::new()))?,
    };
    let source = registry
        .declared_source(&key, &path)
        .filter(|source| source.is_scalar() || source.is_caller())?;
    if !path.is_empty() {
        Some(format!(
            "NULLIF hides a field of setting '{key}' holding '', which a request may carry, \
             so the wrapped field is not the value the request sends"
        ))
    } else if !source.may_be_unset() {
        Some(format!(
            "Setting '{key}' is declared set by every request, which may set it to '', and \
             NULLIF reads that value as NULL, so the wrapped read is not the value the \
             request sends"
        ))
    } else {
        None
    }
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

/// A field taken out of the caller's value is indirection, which caps at B.
pub(super) fn grade(source: &DeclaredSource) -> ConfidenceLevel {
    if source.path().is_empty() {
        ConfidenceLevel::A
    } else {
        ConfidenceLevel::B
    }
}

/// The declared source `expr` reads, when it was declared as one single value and no cast
/// on the read renames it.
pub(super) fn declared_scalar<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(Cow<'r, DeclaredSource>, CastChain)> {
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
pub(crate) fn sole_projection(query: &Query) -> Option<&Expr> {
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
/// read, however the deployment spelled it, bare, through [`nullif_read`] or through
/// [`lowered_read`]. A set is read through [`set_read`], whose expander takes the parse
/// into `jsonb` as structure, and the caller through its own readers.
pub(super) fn declared_read<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(Cow<'r, DeclaredSource>, CastChain)> {
    match bare_declared_read(expr, registry).or_else(|| nullif_read(expr, registry)) {
        Some((source, casts)) => Some((Cow::Borrowed(source), casts)),
        None => lowered_read(expr, registry).map(|(source, casts)| (Cow::Owned(source), casts)),
    }
}

/// `lower(<read of a declared single value>)`, the read bare or through [`nullif_read`],
/// as the value of its own the caller sends in the value's place, and the casts around
/// the call, outermost first, written inline or as a call to an accessor whose whole body
/// is the call.
///
/// `lower` follows the database's collation, which CEL cannot read, so the model never
/// applies it and the caller sends what the database returns. The caller lowers the
/// value it carries, so a cast inside the call that renames the value is refused, and so
/// is a key a declared source already takes.
fn lowered_read(expr: &Expr, registry: &FunctionRegistry) -> Option<(DeclaredSource, CastChain)> {
    if let Some(read) = normalized_accessor_read(expr, registry) {
        if read.skips_empty && !read.source.may_be_unset() {
            return None;
        }
        let normalized = registry
            .sources()
            .normalized(read.source, read.normalization)?;
        return Some((normalized, read.casts));
    }
    let (casts, argument) = lowered_value(expr)?;
    let (source, inner) =
        bare_declared_read(argument, registry).or_else(|| nullif_read(argument, registry))?;
    if inner.renaming(Some(&source.canonical_type())).is_some() {
        return None;
    }
    let lowered = registry
        .sources()
        .normalized(source, RequestNormalization::Lower)?;
    Some((lowered, casts))
}

/// A call to an accessor whose whole body applies a normalization to a read of a whole
/// declared single value, bare or through `NULLIF(_, '')`.
pub(super) struct NormalizedAccessorRead<'r> {
    /// The declared single value the body reads.
    pub(super) source: &'r DeclaredSource,
    /// True where the body wraps the read in `NULLIF(_, '')`.
    pub(super) skips_empty: bool,
    /// The function the body applies to the read.
    normalization: RequestNormalization,
    /// Every cast around the call, outermost first.
    casts: CastChain,
}

/// The read `expr` makes through a call to an accessor whose whole body normalizes a
/// declared single value, under casts and a scalar subquery.
pub(super) fn normalized_accessor_read<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<NormalizedAccessorRead<'r>> {
    let AccessorRead { root, path, casts } = accessor_read(expr)?;
    let Expr::Function(function) = root else {
        return None;
    };
    if !path.is_empty() {
        return None;
    }
    let FunctionSemantic::SettingReader {
        key,
        skips_empty,
        normalization: Some(normalization),
    } = registry.get(&function.name.to_string())?
    else {
        return None;
    };
    let source = registry
        .declared_source(key, &[])
        .filter(|source| source.is_scalar())?;
    Some(NormalizedAccessorRead {
        source,
        skips_empty: *skips_empty,
        normalization: *normalization,
        casts,
    })
}

/// The value `pg_catalog.lower(<value>)` lowers, under casts and a scalar subquery, and
/// the casts around the call, outermost first.
pub(crate) fn lowered_value(expr: &Expr) -> Option<(CastChain, &Expr)> {
    let (mut casts, peeled) = CastChain::peeled(expr);
    let (inner_casts, argument) = match peeled {
        Expr::Subquery(query) => lowered_value(sole_projection(query)?)?,
        other => {
            let function = function_call(other)
                .filter(|function| builtin_function_name(function).as_deref() == Some("lower"))?;
            let FunctionArguments::List(list) = &function.args else {
                return None;
            };
            let [argument] = list.args.as_slice() else {
                return None;
            };
            (CastChain::default(), function_arg_expr(argument)?)
        }
    };
    casts.extend(inner_casts);
    Some((casts, argument))
}

/// As [`declared_read`], for a read no `NULLIF` wraps, which `PostgreSQL` reads as `''`
/// once a transaction-local value of a setting a request may leave unset has ended.
pub(super) fn bare_declared_read<'r>(
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

/// `NULLIF(<read of a whole declared single value>, '')`, of a setting a request may
/// leave unset, and the casts around and inside the wrap, outermost first, written inline
/// or as a call to an accessor whose whole body is the wrap.
///
/// `PostgreSQL` reads such a setting as `NULL` on a fresh connection and as `''` once a
/// transaction-local value has ended, and the wrap reads both as `NULL`. A request
/// leaving the setting unset omits its key, and one setting it never sends `''`, which
/// `PostgreSQL` cannot tell from the unset reading, so the wrapped read is the value the
/// request carries and is absent exactly where the key is. A setting every request sets
/// may hold `''`, which the wrap would hide, so its wrapped read is refused, and so is a
/// field of a document, whose own `''` the wrap would hide.
pub(super) fn nullif_read<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<(&'r DeclaredSource, CastChain)> {
    let EmptiedRead { key, path, casts } = emptied_setting_read(expr, registry)?;
    if !path.is_empty() {
        return None;
    }
    let source = registry
        .declared_source(&key, &[])
        .filter(|source| source.is_scalar() && source.may_be_unset())?;
    Some((source, casts))
}

/// A setting read through `NULLIF(_, '')`.
struct EmptiedRead {
    /// The `current_setting` key the wrap reads.
    key: String,
    /// The field path taken out of that key's value.
    path: Vec<String>,
    /// Every cast around and inside the wrap, outermost first.
    casts: CastChain,
}

/// The setting `expr` reads through `NULLIF(<read>, '')`, written inline or as a call to
/// an accessor whose whole body is the wrap.
fn emptied_setting_read(expr: &Expr, registry: &FunctionRegistry) -> Option<EmptiedRead> {
    if let Some((mut casts, wrapped)) = emptied_value(expr) {
        let AccessorRead {
            root,
            path,
            casts: inner,
        } = accessor_read(wrapped)?;
        casts.extend(inner);
        return Some(EmptiedRead {
            key: setting_key_read_by(root, registry)?,
            path,
            casts,
        });
    }
    let AccessorRead { root, path, casts } = accessor_read(expr)?;
    let (key, true) = setting_read_by(root, registry)? else {
        return None;
    };
    Some(EmptiedRead { key, path, casts })
}

/// The value `NULLIF(<value>, '')` wraps, under casts and a scalar subquery, and the
/// casts around the wrap, outermost first.
fn emptied_value(expr: &Expr) -> Option<(CastChain, &Expr)> {
    let (mut casts, peeled) = CastChain::peeled(expr);
    let (inner_casts, wrapped) = match peeled {
        Expr::Subquery(query) => emptied_value(sole_projection(query)?)?,
        other => {
            let function =
                function_call(other).filter(|function| empty_sentinel_nullif(function))?;
            (CastChain::default(), positional_function_arg(function, 0)?)
        }
    };
    casts.extend(inner_casts);
    Some((casts, wrapped))
}

/// The `current_setting` key a node reads bare, written inline or as a call to a function
/// whose whole body is that read. Both spellings reach one declaration, so they cannot
/// disagree.
pub(super) fn setting_key_read_by(root: &Expr, registry: &FunctionRegistry) -> Option<String> {
    let (key, false) = setting_read_by(root, registry)? else {
        return None;
    };
    Some(key)
}

/// The `current_setting` key a node reads, written inline or as a call to a function
/// whose whole body reads it, and whether that body wraps the read in `NULLIF(_, '')`. A
/// function applying a normalization to the read returns another value than the
/// setting's, which [`normalized_accessor_read`] reads.
fn setting_read_by(root: &Expr, registry: &FunctionRegistry) -> Option<(String, bool)> {
    if let Some(key) = current_setting_literal_key(root) {
        return Some((key, false));
    }
    let Expr::Function(function) = root else {
        return None;
    };
    match registry.get(&function.name.to_string())? {
        FunctionSemantic::SettingReader {
            key,
            skips_empty,
            normalization: None,
        } => Some((key.clone(), *skips_empty)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::function_registry::DeclaredSources;
    use crate::classifier::recognizers::is_current_user_expr;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use crate::parser::sql_parser::{SessionSetting, SettingValue};
    use crate::test_support::{caller, delimited_set, deployment, json_field, registry, scalar};
    use sqlparser::ast::DataType;

    /// The source a declared `app.mode` scalar reads, for an expected pattern.
    fn mode_source() -> DeclaredSource {
        DeclaredSources::of(&deployment([scalar("app.mode")]))
            .iter()
            .next()
            .expect("the declared setting")
            .clone()
    }

    /// A JSON setting whose `teams` field holds a JSON array of text.
    fn teams_claim() -> SessionSetting {
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

    /// `<>` against a literal is one value that must differ from the constant, either way
    /// round, and a text cast the value keeps its spelling under stays allowed.
    #[test]
    fn a_declared_value_differing_from_a_constant_is_read() {
        let registry = registry([scalar("app.mode")]);
        let read = |clause: &str| {
            recognize_session_attribute(&parse_expr(clause), &registry).map(|c| c.pattern)
        };
        let expected =
            PatternClass::P21CallerScalarUnequalsConstant(CallerScalarUnequalsConstant {
                value: "main".to_string(),
                source: mode_source(),
            });
        assert_eq!(
            read("current_setting('app.mode', true) <> 'main'"),
            Some(expected.clone())
        );
        // The constant on the left reads the same gate, and a text cast renames nothing.
        assert_eq!(
            read("'main' <> current_setting('app.mode', true)"),
            Some(expected.clone())
        );
        assert_eq!(
            read("current_setting('app.mode', true)::text <> 'main'"),
            Some(expected)
        );
    }

    /// `IN`, `NOT IN` and `= ANY (ARRAY[...])` against literals are one value in a named
    /// list, however negated, and the negation is kept.
    #[test]
    fn a_declared_value_in_a_constant_list_is_read() {
        let registry = registry([scalar("app.mode")]);
        let read = |clause: &str| {
            recognize_session_attribute(&parse_expr(clause), &registry).map(|c| c.pattern)
        };
        let list = |negated: bool| {
            PatternClass::P22CallerScalarInConstantList(CallerScalarInConstantList {
                values: vec!["main".to_string(), "dev".to_string()],
                negated,
                source: mode_source(),
            })
        };
        assert_eq!(
            read("current_setting('app.mode', true) IN ('main', 'dev')"),
            Some(list(false))
        );
        assert_eq!(
            read("current_setting('app.mode', true) NOT IN ('main', 'dev')"),
            Some(list(true))
        );
        // `= ANY (ARRAY[...])` is one membership, read the same way.
        assert_eq!(
            read("current_setting('app.mode', true) = ANY (ARRAY['main', 'dev'])"),
            Some(list(false))
        );
    }

    /// A list element that is no literal is a per-row value the list cannot stand in for,
    /// so the whole list stays refused.
    #[test]
    fn a_list_with_a_non_literal_element_is_refused() {
        let registry = registry([scalar("app.mode")]);
        for clause in [
            "current_setting('app.mode', true) IN ('main', other_mode)",
            "current_setting('app.mode', true) = ANY (ARRAY['main', other_mode])",
        ] {
            assert!(
                recognize_session_attribute(&parse_expr(clause), &registry).is_none(),
                "{clause} names a value the list does not hold"
            );
        }
    }

    /// `<>` against a row value is a gate with its own shape, not one value that must
    /// differ from a constant, so the setting side stays refused.
    #[test]
    fn an_inequality_against_a_row_value_is_refused() {
        let registry = registry([scalar("app.mode")]);
        assert!(
            recognize_session_attribute(
                &parse_expr("current_setting('app.mode', true) <> other_mode"),
                &registry
            )
            .is_none(),
            "a row value the value must differ from is no constant"
        );
    }

    /// `PostgreSQL` has no empty list and the model has no gate to state one, so an empty
    /// `= ANY` stays refused.
    #[test]
    fn an_empty_list_is_refused() {
        let registry = registry([scalar("app.mode")]);
        assert!(
            recognize_session_attribute(
                &parse_expr("current_setting('app.mode', true) = ANY (ARRAY[])"),
                &registry
            )
            .is_none(),
            "an empty list holds no element a value can match"
        );
    }

    /// `= ALL` and the non-equality quantifiers are no membership the request value
    /// passes, and a cast that renames the read reaches a different value, so each stays
    /// refused.
    #[test]
    fn a_list_the_request_value_cannot_pass_stays_refused() {
        let registry = registry([scalar("app.mode")]);
        for clause in [
            "current_setting('app.mode', true) = ALL (ARRAY['main', 'dev'])",
            "current_setting('app.mode', true) <> ANY (ARRAY['main', 'dev'])",
            "current_setting('app.mode', true)::integer IN ('7', '8')",
        ] {
            assert!(
                recognize_session_attribute(&parse_expr(clause), &registry).is_none(),
                "{clause} is no membership the request value passes"
            );
        }
    }

    /// A field the deployment declares reads the same list, grading at the field's B.
    #[test]
    fn a_field_value_in_a_constant_list_is_read() {
        let registry = registry([json_field(
            "request.jwt.claims",
            &["mode"],
            SettingValue::Scalar(DataType::Text),
        )]);
        let expr = parse_expr(
            "current_setting('request.jwt.claims')::jsonb ->> 'mode' IN ('main', 'dev')",
        );
        let classified = recognize_session_attribute(&expr, &registry)
            .expect("the declared field reads the list");
        assert!(matches!(
            classified.pattern,
            PatternClass::P22CallerScalarInConstantList(CallerScalarInConstantList {
                negated: false,
                ..
            })
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::B);
    }

    /// The two sources a fallback test reads, declared the way `Supabase` declares them.
    fn fallback_settings() -> [SessionSetting; 2] {
        [
            scalar("request.jwt.claim.role"),
            json_field(
                "request.jwt.claims",
                &["role"],
                SettingValue::Scalar(DataType::Text),
            ),
        ]
    }

    /// The source the step reads, so a test asserts the read order and the wrap.
    fn step_source(step: &FallbackStep) -> (&str, bool, bool) {
        (&step.setting_key, step.from_json_field, step.skips_empty)
    }

    /// The value a `coalesce` of the declared sources hands over, compared with a literal,
    /// is a request gate on that value, the sources in the order the read tries them.
    #[test]
    fn a_fallback_of_declared_sources_is_read() {
        let registry = registry(fallback_settings());
        let classified = recognize_session_attribute(
            &parse_expr("coalesce(current_setting('request.jwt.claim.role', true), current_setting('request.jwt.claims', true)::jsonb ->> 'role') = 'authenticated'"),
            &registry,
        )
        .expect("the coalesce reads the fallback");
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P23FallbackScalarEqualsConstant(
                    FallbackScalarEqualsConstant { value, first, rest }
                ) if value == "authenticated"
                    && rest.len() == 1
                    && step_source(first) == ("request.jwt.claim.role", false, false)
                    && step_source(&rest[0]) == ("request.jwt.claims", true, false)
            ),
            "the read keeps the sources in order, got {:?}",
            classified.pattern
        );
        assert_eq!(classified.confidence, ConfidenceLevel::B);
    }

    /// The same fallback gate in either operand order classifies alike, the read and the
    /// value the pattern stands for unchanged by which side the value stands on.
    #[test]
    fn the_fallback_test_reads_in_either_operand_order() {
        let registry = registry(fallback_settings());
        let value = "authenticated";
        let read = "coalesce(current_setting('request.jwt.claim.role', true), current_setting('request.jwt.claims', true)::jsonb ->> 'role')";
        let forward =
            recognize_session_attribute(&parse_expr(&format!("{read} = '{value}'")), &registry)
                .expect("the forward test reads the fallback");
        let reversed =
            recognize_session_attribute(&parse_expr(&format!("'{value}' = {read}")), &registry)
                .expect("the reversed test reads the fallback");
        assert_eq!(forward, reversed);
    }

    /// A `NULLIF` against the empty text wraps the source it sits on, whether that is the
    /// value or, for a field, the document it is taken from, and an outer cast that does
    /// not rename stands for the value the read hands over.
    #[test]
    fn a_nullif_wraps_the_source_it_sits_on() {
        let registry = registry(fallback_settings());
        let classified = recognize_session_attribute(
            &parse_expr("coalesce(nullif(current_setting('request.jwt.claim.role', true), ''), (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'))::text = 'authenticated'"),
            &registry,
        )
        .expect("the wrapped coalesce reads the fallback");
        assert!(
            matches!(
                &classified.pattern,
                PatternClass::P23FallbackScalarEqualsConstant(
                    FallbackScalarEqualsConstant { first, rest, .. }
                ) if rest.len() == 1
                    && step_source(first) == ("request.jwt.claim.role", false, true)
                    && step_source(&rest[0]) == ("request.jwt.claims", true, true)
            ),
            "the wrap follows the source it sits on, got {:?}",
            classified.pattern
        );
    }

    /// The same value differing from a constant, and one of a list of constants, spelled
    /// `IN` or `= ANY`, the `NOT IN` negating the list.
    #[test]
    fn the_fallback_value_is_read_by_the_other_tests_of_a_value() {
        let registry = registry(fallback_settings());
        let coalesce = "coalesce(current_setting('request.jwt.claim.role', true), current_setting('request.jwt.claims', true)::jsonb ->> 'role')";
        let unequal = recognize_session_attribute(
            &parse_expr(&format!("{coalesce} <> 'anonymous'")),
            &registry,
        )
        .expect("the coalesce differing from a constant reads");
        assert!(
            matches!(
                &unequal.pattern,
                PatternClass::P24FallbackScalarUnequalsConstant(FallbackScalarUnequalsConstant {
                    value, ..
                }) if value == "anonymous"
            ),
            "got {:?}",
            unequal.pattern
        );
        for (clause, negated) in [
            (
                format!("{coalesce} IN ('authenticated', 'anonymous')"),
                false,
            ),
            (
                format!("{coalesce} NOT IN ('authenticated', 'anonymous')"),
                true,
            ),
            (
                format!("{coalesce} = ANY (ARRAY['authenticated', 'anonymous'])"),
                false,
            ),
        ] {
            let classified = recognize_session_attribute(&parse_expr(&clause), &registry)
                .expect("the list test reads the fallback");
            assert!(
                matches!(
                    &classified.pattern,
                    PatternClass::P25FallbackScalarInConstantList(FallbackScalarInConstantList {
                        negated: spelled,
                        values,
                        ..
                    }) if *spelled == negated
                        && *values == vec!["authenticated".to_string(), "anonymous".to_string()]
                ),
                "`{clause}`: got {:?}",
                classified.pattern
            );
        }
    }

    /// A source the deployment does not declare, a column, a call or a literal among the
    /// sources leaves the read unclassified, as does a literal that renames a source or
    /// the tested side, and a column or a column element where a value is tested.
    #[test]
    fn a_part_the_read_cannot_stand_stays_unclassified() {
        let registry = registry([scalar("app.first"), scalar("app.second")]);
        let declared =
            "coalesce(current_setting('app.first', true), current_setting('app.second', true))";
        let refusals = [
            // A source the deployment does not declare.
            "coalesce(current_setting('app.first', true), current_setting('app.other', true)) = 'x'",
            // A column the fallback is compared with.
            &format!("{declared} = t.name"),
            // A column among the sources.
            "coalesce(t.name, current_setting('app.first', true)) = 'x'",
            // A call among the sources.
            "coalesce(other(), current_setting('app.first', true)) = 'x'",
            // A literal among the sources.
            "coalesce('x', current_setting('app.first', true)) = 'x'",
            // A cast that renames a source's value.
            "coalesce(current_setting('app.first', true)::integer, current_setting('app.second', true)::integer) = 1",
            // A cast on the literal that renames the value the read hands over.
            &format!("{declared} = '1'::integer"),
            // A column element of the list.
            &format!("{declared} IN (t.name)"),
            // A list element the tested side's casts rename.
            &format!("{declared} = ANY (ARRAY['x'::integer::text])"),
            // A document cast beyond the parse into jsonb the arrow needs.
            "coalesce(current_setting('app.first', true)::jsonb::text ->> 'f', current_setting('app.second', true)) = 'x'",
        ];
        for clause in refusals {
            assert!(
                recognize_session_attribute(&parse_expr(clause), &registry).is_none(),
                "`{clause}` stays unclassified"
            );
        }
    }

    /// The registry reading `auth.role` as the `Supabase` fallback across the two
    /// sources, the way a registry file spells it.
    fn fallback_registry(registry: &mut FunctionRegistry) {
        registry
            .load_from_json(
                r#"{ "auth.role": { "kind": "setting_fallback", "sources": [
                    { "key": "request.jwt.claim.role", "skips_empty": true },
                    { "key": "request.jwt.claims", "path": ["role"], "skips_empty": true }
                ] } }"#,
            )
            .expect("the registry parses");
    }

    /// A call the registry knows as a fallback reads the sources the registry names
    /// against the deployment, so one whose first source the deployment does not declare
    /// is not read as the fallback, and the comparison stays unclassified in either
    /// operand order.
    #[test]
    fn a_registered_fallback_whose_first_source_is_not_declared_is_not_read() {
        let mut registry = registry([json_field(
            "request.jwt.claims",
            &["role"],
            SettingValue::Scalar(DataType::Text),
        )]);
        fallback_registry(&mut registry);
        for clause in [
            "auth.role() = 'authenticated'",
            "'authenticated' = auth.role()",
        ] {
            assert!(
                recognize_session_attribute(&parse_expr(clause), &registry).is_none(),
                "`{clause}` stays unclassified, the first source is not declared"
            );
        }
    }

    /// The same refusal where the first source the deployment declares hands over and a
    /// later one the deployment does not, since every source the fallback names has to be
    /// declared.
    #[test]
    fn a_registered_fallback_whose_later_source_is_not_declared_is_not_read() {
        let mut registry = registry([scalar("request.jwt.claim.role")]);
        fallback_registry(&mut registry);
        assert!(
            recognize_session_attribute(&parse_expr("auth.role() = 'authenticated'"), &registry)
                .is_none(),
            "a later source the deployment does not declare"
        );
    }

    /// The source a declared `app.mode` scalar a request may leave unset reads.
    fn unset_mode_source() -> DeclaredSource {
        DeclaredSources::of(&deployment([scalar("app.mode").may_be_unset()]))
            .iter()
            .next()
            .expect("the declared setting")
            .clone()
    }

    /// `NULLIF(<read>, '')` of a setting a request may leave unset reads both unset
    /// readings as `NULL` and the value a request carries as itself, so it reads as the
    /// bare read wherever that one is, under casts and a scalar subquery alike.
    #[test]
    fn a_nullif_read_of_a_setting_a_request_may_leave_unset_is_the_value() {
        let registry = registry([scalar("app.mode").may_be_unset()]);
        let read = |clause: &str| {
            recognize_session_attribute(&parse_expr(clause), &registry).map(|c| c.pattern)
        };
        let equal = PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
            value: "main".to_string(),
            source: unset_mode_source(),
        });
        for clause in [
            "NULLIF(current_setting('app.mode', true), '') = 'main'",
            "NULLIF(current_setting('app.mode', true), '')::text = 'main'",
            "(SELECT NULLIF(current_setting('app.mode', true), '')) = 'main'",
            "'main' = (SELECT NULLIF(current_setting('app.mode', true)::text, '')::text)",
        ] {
            assert_eq!(read(clause), Some(equal.clone()), "{clause}");
        }
        assert_eq!(
            read("NULLIF(current_setting('app.mode', true), '') <> 'main'"),
            Some(PatternClass::P21CallerScalarUnequalsConstant(
                CallerScalarUnequalsConstant {
                    value: "main".to_string(),
                    source: unset_mode_source(),
                }
            ))
        );
        assert_eq!(
            read("mode = NULLIF(current_setting('app.mode', true), '')"),
            Some(PatternClass::P15RowValueEqualsCallerScalar(
                RowValueEqualsCallerScalar {
                    column: ColumnName::from_stored("mode"),
                    source: unset_mode_source(),
                }
            ))
        );
    }

    /// A setting every request sets has no unset reading, and `''` is then a value the
    /// wrap would read as `NULL`, so the wrapped read stays refused. So does a wrap
    /// against another sentinel, and one around a field of a document.
    #[test]
    fn a_nullif_read_the_bare_read_cannot_stand_for_is_refused() {
        let always = registry([scalar("app.mode")]);
        assert!(
            recognize_session_attribute(
                &parse_expr("NULLIF(current_setting('app.mode', true), '') = 'main'"),
                &always
            )
            .is_none(),
            "a setting every request sets"
        );
        let unset = registry([scalar("app.mode").may_be_unset()]);
        assert!(
            recognize_session_attribute(
                &parse_expr("NULLIF(current_setting('app.mode', true), 'none') = 'main'"),
                &unset
            )
            .is_none(),
            "another sentinel than the empty text"
        );
        let field = registry([json_field(
            "request.jwt.claims",
            &["mode"],
            SettingValue::Scalar(DataType::Text),
        )
        .may_be_unset()]);
        assert!(
            recognize_session_attribute(
                &parse_expr(
                    "NULLIF(current_setting('request.jwt.claims', true)::jsonb ->> 'mode', '') = 'main'"
                ),
                &field
            )
            .is_none(),
            "a field of a document"
        );
    }

    /// `IS NULL` on the wrapped read is the request leaving the value absent, and `IS
    /// NOT NULL` the request carrying it, under casts and a scalar subquery alike.
    #[test]
    fn an_absence_test_on_a_nullif_read_is_read() {
        let registry = registry([scalar("app.mode").may_be_unset()]);
        let read = |clause: &str| {
            recognize_session_attribute(&parse_expr(clause), &registry).map(|c| c.pattern)
        };
        let absent = |negated: bool| {
            PatternClass::P28RequestValueAbsent(RequestValueAbsent {
                source: unset_mode_source(),
                negated,
            })
        };
        assert_eq!(
            read("NULLIF(current_setting('app.mode', true), '') IS NULL"),
            Some(absent(false))
        );
        assert_eq!(
            read("(SELECT NULLIF(current_setting('app.mode', true), '')::text) IS NULL"),
            Some(absent(false))
        );
        assert_eq!(
            read("NULLIF(current_setting('app.mode', true), '') IS NOT NULL"),
            Some(absent(true))
        );
    }

    /// The bare read is `NULL` on a fresh connection and `''` once a transaction-local
    /// value has ended, so `IS NULL` on it answers both ways for one request, and a
    /// setting every request sets is never absent, nor is a field of a document. Each
    /// stays refused naming why, once however often the policy repeats it, and so does a
    /// cast that renames the wrapped read.
    #[test]
    fn an_absence_test_the_request_cannot_answer_is_refused() {
        let unset = registry([scalar("app.mode").may_be_unset()]);
        let always = registry([scalar("app.mode")]);
        let field = registry([json_field(
            "request.jwt.claims",
            &["mode"],
            SettingValue::Scalar(DataType::Text),
        )
        .may_be_unset()]);
        for (clause, registry, reason) in [
            (
                "current_setting('app.mode', true) IS NULL \
                 OR current_setting('app.mode', true) IS NULL",
                &unset,
                "Test NULLIF(current_setting('app.mode', true), '') instead",
            ),
            (
                "NULLIF(current_setting('request.jwt.claims', true)::jsonb ->> 'mode', '') IS NULL",
                &field,
                "NULLIF hides a field of setting 'request.jwt.claims'",
            ),
            (
                "current_setting('request.jwt.claims', true)::jsonb ->> 'mode' IS NULL",
                &field,
                "A field of setting 'request.jwt.claims' tested for NULL",
            ),
            (
                "current_setting('app.mode', true) IS NULL",
                &unset,
                "Test NULLIF(current_setting('app.mode', true), '') instead",
            ),
            (
                "current_setting('app.mode', true) IS NOT NULL",
                &unset,
                "Test NULLIF(current_setting('app.mode', true), '') instead",
            ),
            (
                "NULLIF(current_setting('app.mode', true), '')::integer IS NULL",
                &unset,
                "through a cast to integer",
            ),
            (
                "NULLIF(current_setting('app.mode', true), '') IS NULL",
                &always,
                "declared set by every request",
            ),
            (
                "current_setting('app.mode', true) IS NULL",
                &always,
                "declared set by every request",
            ),
        ] {
            assert_refused_naming(clause, registry, refused_absence_tests, reason);
        }
        assert_eq!(
            refused_absence_tests(
                &parse_expr("NULLIF(current_setting('app.mode', true), '') IS NULL"),
                &unset
            ),
            Vec::<String>::new(),
            "a test the request answers names nothing"
        );
    }

    /// The value `lower` makes of the one setting `setting` declares.
    fn lowered_source(setting: SessionSetting) -> DeclaredSource {
        let sources = DeclaredSources::of(&deployment([setting]));
        let declared = sources.iter().next().expect("the declared setting");
        sources
            .normalized(declared, RequestNormalization::Lower)
            .expect("a key no declared source takes")
    }

    /// `lower` of a declared single value is a value of its own, which the caller sends
    /// under a key of its own, read bare, through `NULLIF`, under a cast that renames
    /// nothing and inside a scalar subquery alike.
    #[test]
    fn a_lowered_declared_value_is_a_request_value_of_its_own() {
        let registry = registry([scalar("app.email").may_be_unset()]);
        let lowered = lowered_source(scalar("app.email").may_be_unset());
        assert_eq!(lowered.request_parameter(), "app_email_lower");
        assert_eq!(lowered.normalization(), Some(RequestNormalization::Lower));
        assert_eq!(lowered.setting_key(), "app.email");
        let read = |clause: &str| {
            recognize_session_attribute(&parse_expr(clause), &registry).map(|c| c.pattern)
        };
        let compared_with_row =
            PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar {
                column: ColumnName::from_stored("email"),
                source: lowered.clone(),
            });
        for clause in [
            "email = lower(NULLIF(current_setting('app.email', true), ''))",
            "lower(current_setting('app.email', true)) = email",
            "email = (SELECT lower(NULLIF(current_setting('app.email', true), '')))",
            "email = pg_catalog.lower(current_setting('app.email', true)::text)::text",
        ] {
            assert_eq!(read(clause), Some(compared_with_row.clone()), "{clause}");
        }
        assert_eq!(
            read("lower(current_setting('app.email', true)) = 'ann@example.com'"),
            Some(PatternClass::P17CallerScalarEqualsConstant(
                CallerScalarEqualsConstant {
                    value: "ann@example.com".to_string(),
                    source: lowered,
                }
            ))
        );
    }

    /// A cast inside the call that renames the value lowers a value the caller never
    /// sent, a cast outside it renames what `lower` returns, and a `lower` the schema
    /// defines is not `PostgreSQL`'s. Each stays refused, and so does `lower` of a set,
    /// of the caller, and of a value whose key a declared setting already takes.
    #[test]
    fn a_lowered_read_the_caller_cannot_send_is_refused() {
        let registry = registry([
            scalar("app.email"),
            scalar("app.alias"),
            scalar("app.alias_lower"),
            delimited_set("app.emails", ","),
            caller("app.user_id"),
        ]);
        for clause in [
            "email = lower(current_setting('app.email', true)::integer::text)",
            "id = lower(current_setting('app.email', true))::uuid",
            "email = app.lower(current_setting('app.email', true))",
            "email = upper(current_setting('app.email', true))",
            "email = lower(current_setting('app.alias', true))",
            "email = lower(current_setting('app.emails', true))",
            "email = lower(current_setting('app.user_id', true))",
        ] {
            assert!(
                recognize_session_attribute(&parse_expr(clause), &registry).is_none(),
                "`{clause}` stays refused"
            );
        }
    }

    /// A registry reading `app.mode` for a request that may leave it unset, with an
    /// accessor whose body returns the read through `NULLIF` and one returning it bare,
    /// and one returning `lower` of each.
    fn accessor_registry(mode: SessionSetting) -> FunctionRegistry {
        let mut registry = registry([mode]);
        for (name, skips_empty, normalization) in [
            ("app.wrapped_mode", true, None),
            ("app.bare_mode", false, None),
            ("app.lowered_mode", true, Some(RequestNormalization::Lower)),
            (
                "app.lowered_bare_mode",
                false,
                Some(RequestNormalization::Lower),
            ),
        ] {
            registry.register_if_absent(
                name,
                &FunctionSemantic::SettingReader {
                    key: "app.mode".to_string(),
                    skips_empty,
                    normalization,
                },
            );
        }
        registry
    }

    /// A call to an accessor whose body returns `lower` of a read is that lowered read,
    /// bare, inside a scalar subquery and under a cast that renames nothing, compared with
    /// a row value or a constant. A cast renaming what the call returns, `lower` of the
    /// call, and a test of the call for `NULL` stay refused as they are inline, and so
    /// does the wrapped call on a value every request sets.
    #[test]
    fn a_call_to_an_accessor_returning_a_lowered_read_is_that_lowered_read() {
        let unset = accessor_registry(scalar("app.mode").may_be_unset());
        let read = |clause: &str, registry: &FunctionRegistry| {
            recognize_session_attribute(&parse_expr(clause), registry).map(|c| c.pattern)
        };
        for (call, inline) in [
            (
                "mode = (SELECT app.lowered_mode())",
                "mode = lower(NULLIF(current_setting('app.mode', true), ''))",
            ),
            (
                "app.lowered_bare_mode() = mode",
                "lower(current_setting('app.mode', true)) = mode",
            ),
            (
                "app.lowered_mode()::text = 'main'",
                "lower(NULLIF(current_setting('app.mode', true), '')) = 'main'",
            ),
        ] {
            let expected = read(inline, &unset);
            assert!(expected.is_some(), "`{inline}` reads");
            assert_eq!(read(call, &unset), expected, "`{call}` reads as `{inline}`");
        }
        let always = accessor_registry(scalar("app.mode"));
        for (clause, registry) in [
            ("mode = lower(app.lowered_mode())", &unset),
            ("id = app.lowered_mode()::uuid", &unset),
            ("app.lowered_mode() IS NULL", &unset),
            ("mode = app.lowered_mode()", &always),
        ] {
            assert!(read(clause, registry).is_none(), "`{clause}` stays refused");
        }
    }

    /// A call to an accessor whose body returns `NULLIF(<read>, '')` is that read, so it
    /// reads as the value the request carries and its absence test as the request
    /// omitting it. The bare accessor keeps the bare read's refusal, and on a setting
    /// every request sets the wrapped one keeps the inline wrap's refusal.
    #[test]
    fn a_call_to_an_accessor_returning_a_nullif_read_is_that_read() {
        let unset = accessor_registry(scalar("app.mode").may_be_unset());
        let read = |clause: &str| {
            recognize_session_attribute(&parse_expr(clause), &unset).map(|c| c.pattern)
        };
        assert_eq!(
            read("(SELECT app.wrapped_mode()) = 'main'"),
            Some(PatternClass::P17CallerScalarEqualsConstant(
                CallerScalarEqualsConstant {
                    value: "main".to_string(),
                    source: unset_mode_source(),
                }
            ))
        );
        assert_eq!(
            read("app.wrapped_mode()::text IS NULL"),
            Some(PatternClass::P28RequestValueAbsent(RequestValueAbsent {
                source: unset_mode_source(),
                negated: false,
            }))
        );
        let always = accessor_registry(scalar("app.mode"));
        for (clause, registry, reason) in [
            (
                "app.bare_mode() IS NULL",
                &unset,
                "Test NULLIF(current_setting('app.mode', true), '') instead",
            ),
            (
                "app.wrapped_mode()::integer IS NULL",
                &unset,
                "through a cast to integer",
            ),
            (
                "app.wrapped_mode() IS NULL",
                &always,
                "declared set by every request",
            ),
        ] {
            assert_refused_naming(clause, registry, refused_absence_tests, reason);
        }
        assert!(
            recognize_session_attribute(&parse_expr("app.wrapped_mode() = 'main'"), &always)
                .is_none(),
            "a value every request sets may be '', which the wrap hides"
        );
    }

    /// A wrapped read of a value every request sets, or of a field, hides a `''` the
    /// request may send, so each is named once however often the clause repeats it,
    /// inline or through an accessor, the caller among them. A wrapped read the request
    /// answers, and a setting the deployment does not declare, name nothing.
    #[test]
    fn a_nullif_read_hiding_a_value_the_request_sends_names_why() {
        let always = accessor_registry(scalar("app.mode"));
        let field = registry([json_field(
            "request.jwt.claims",
            &["mode"],
            SettingValue::Scalar(DataType::Text),
        )
        .may_be_unset()]);
        let always_caller = registry([caller("app.user_id")]);
        for (clause, registry, reason) in [
            (
                "mode = NULLIF(current_setting('app.mode', true), '') \
                 OR mode = NULLIF(current_setting('app.mode', true), '')::text",
                &always,
                "Setting 'app.mode' is declared set by every request",
            ),
            (
                "mode = (SELECT app.wrapped_mode())",
                &always,
                "Setting 'app.mode' is declared set by every request",
            ),
            (
                "mode = (SELECT app.lowered_mode())",
                &always,
                "Setting 'app.mode' is declared set by every request",
            ),
            (
                "owner = NULLIF(current_setting('app.user_id', true), '')",
                &always_caller,
                "Setting 'app.user_id' is declared set by every request",
            ),
            (
                "mode = NULLIF(current_setting('request.jwt.claims', true)::jsonb ->> 'mode', '')",
                &field,
                "NULLIF hides a field of setting 'request.jwt.claims'",
            ),
        ] {
            assert_refused_naming(clause, registry, refused_emptied_reads, reason);
        }
        let unset = accessor_registry(scalar("app.mode").may_be_unset());
        for (clause, registry) in [
            ("mode = (SELECT app.wrapped_mode())", &unset),
            ("mode = (SELECT app.lowered_mode())", &unset),
            (
                "mode = NULLIF(current_setting('app.other', true), '')",
                &unset,
            ),
        ] {
            assert_eq!(
                refused_emptied_reads(&parse_expr(clause), registry),
                Vec::<String>::new(),
                "`{clause}` names nothing"
            );
        }
    }

    /// Asserts that `clause` stays unrecognized and that `diagnose` names exactly one
    /// reason, which contains `reason`.
    fn assert_refused_naming(
        clause: &str,
        registry: &FunctionRegistry,
        diagnose: fn(&Expr, &FunctionRegistry) -> Vec<String>,
        reason: &str,
    ) {
        let expr = parse_expr(clause);
        assert!(
            recognize_session_attribute(&expr, registry).is_none(),
            "`{clause}` stays refused"
        );
        let reasons = diagnose(&expr, registry);
        assert!(
            reasons.len() == 1 && reasons[0].contains(reason),
            "`{clause}` names why: {reasons:?}"
        );
    }
}
