//! Casts that can rename a value compared with a request value, a literal or the clock.
//!
//! The model compares the value a request sends with the row's value rendered as text,
//! while `PostgreSQL` compares whatever the casts made of both. The two agree only where
//! no cast renames either side, so every reader of a request value judges the casts it
//! peeled through [`CastChain::renaming`], and the row's side of the comparison takes no
//! declaration at all.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::ops::ControlFlow;

use sqlparser::ast::{BinaryOperator, Expr, InTarget};

use super::session::{declared_read, set_read, sole_projection};
use super::{
    accessor_read, caller_renaming_cast, caller_source, comparison_renaming_cast,
    is_coalesce_wrapped, positional_function_arg, reads_the_caller,
};
use crate::classifier::function_registry::FunctionRegistry;
use crate::parser::expr::{element_type, CastChain};

/// The cast on the row's side of a comparison that can rename the row's value.
///
/// A `COALESCE` compares its first argument, so a cast there renames the value too.
pub(super) fn row_renaming_cast(expr: &Expr) -> Option<String> {
    let (casts, peeled) = CastChain::peeled(expr);
    if let Some(cast) = casts.renaming(None) {
        return Some(cast.to_string());
    }
    let Expr::Function(function) = peeled else {
        return None;
    };
    if !is_coalesce_wrapped(peeled) {
        return None;
    }
    let (inner, _) = CastChain::peeled(positional_function_arg(function, 0)?);
    inner.renaming(None).map(str::to_string)
}

/// The type a comparison renames `other` into, when `other` is compared with a request
/// value whose casts are `request`.
///
/// A row value renames only through a cast of its own. A literal is also coerced into
/// whatever type the request value ends in, so `'07'` compared with an `integer` is `7`.
pub(super) fn other_side_renaming(other: &Expr, request: &CastChain) -> Option<String> {
    if let Some(cast) = row_renaming_cast(other) {
        return Some(cast);
    }
    let (_, peeled) = CastChain::peeled(other);
    match (peeled, request.outermost()) {
        (Expr::Value(_), Some(outermost)) if !request.yields_text() => Some(outermost.to_string()),
        _ => None,
    }
}

/// Why `expr` cannot translate for a cast that renames a value it compares with a request
/// value, one reason per renaming.
///
/// Answers for diagnosis before any recognizer runs. A recognizer refuses the same
/// spellings, and this names the cast so the refusal says what to change or declare.
pub(crate) fn renaming_casts(expr: &Expr, registry: &FunctionRegistry) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    let mut note = |reason: String| {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    };
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if let Some(request) = request_read(node, registry) {
            if let Some(cast) = &request.renaming {
                note(renaming_reason(
                    &request.subject,
                    cast,
                    request.declarable.as_deref(),
                ));
            }
        }
        for (other, request) in compared_operands(node, registry) {
            if let Some(cast) = other_side_renaming(other, &request.casts) {
                note(format!(
                    "{other} is compared with {} as {cast}, which can change its value in \
                     PostgreSQL while the model compares it as written",
                    request.subject
                ));
            }
        }
        ControlFlow::<()>::Continue(())
    });
    reasons
}

/// Why the comparison `expr` cannot translate for a cast that can change a literal, the
/// column or the clock it compares.
///
/// Asked of the clause's own comparison only. Inside a subquery such a conjunct stays SQL
/// that `PostgreSQL` evaluates with its casts, so it costs the shape no correctness.
pub(crate) fn compared_cast_reason(expr: &Expr) -> Option<String> {
    let (operand, cast) = comparison_renaming_cast(expr)?;
    Some(format!(
        "{operand} is cast to {cast}, which can change the value PostgreSQL compares while \
         the model compares it as written, so compare it uncast or as text"
    ))
}

/// Why reading `subject` through a cast to `cast` cannot translate, and what makes it hold
/// where `declarable` names the setting whose declared type would prove the cast.
pub(crate) fn renaming_reason(subject: &str, cast: &str, declarable: Option<&str>) -> String {
    let remedy = match declarable {
        Some(key) => format!(
            "declare {key} in the deployment as holding {} if every request sends it in that \
             type's canonical form, or compare it uncast",
            element_type(cast)
        ),
        None => "compare it uncast or as text".to_string(),
    };
    format!(
        "{subject} reaches the comparison through a cast to {cast}, which can change the value \
         PostgreSQL compares while the model compares the value as sent, so {remedy}"
    )
}

/// One read of a request value, as the diagnosis names it.
struct RequestRead {
    /// How the read is named in a reason.
    subject: String,
    /// The key a declaration of the read's canonical type goes on, absent for an accessor
    /// that takes no declaration.
    declarable: Option<String>,
    /// Every cast written around the read, outermost first.
    casts: CastChain,
    /// The first of them that can rename the value.
    renaming: Option<String>,
}

/// The request value `node` reads and the casts around it.
fn request_read(node: &Expr, registry: &FunctionRegistry) -> Option<RequestRead> {
    if reads_the_caller(node, registry) {
        return caller_read(node, CastChain::default(), registry);
    }
    // A one-element array holding the caller casts the caller with the array.
    let (array_casts, peeled) = CastChain::peeled(node);
    if let Expr::Array(array) = peeled {
        if let [only] = array.elem.as_slice() {
            if reads_the_caller(only, registry) {
                return caller_read(only, array_casts, registry);
            }
        }
    }
    let (source, casts) = declared_read(node, registry).or_else(|| set_read(node, registry))?;
    Some(RequestRead {
        subject: format!("current_setting('{}')", source.setting_key()),
        declarable: Some(source.setting_key().to_string()),
        renaming: casts
            .renaming(Some(&source.canonical_type()))
            .map(str::to_string),
        casts,
    })
}

/// The read of the caller `caller` makes, under the casts `outer` found around it.
fn caller_read(
    caller: &Expr,
    mut outer: CastChain,
    registry: &FunctionRegistry,
) -> Option<RequestRead> {
    let renaming = caller_renaming_cast(caller, &outer, registry);
    let read = accessor_read(caller)?;
    let declarable = caller_source(&read, registry).map(|source| source.setting_key().to_string());
    outer.extend(read.casts);
    Some(RequestRead {
        subject: format!("the caller's identity {}", read.root),
        declarable,
        casts: outer,
        renaming,
    })
}

/// The operands `node` compares with a request value, each beside that read.
fn compared_operands<'e>(
    node: &'e Expr,
    registry: &FunctionRegistry,
) -> Vec<(&'e Expr, RequestRead)> {
    let pairs: [(&Expr, &Expr); 2] = match node {
        Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Eq
                | BinaryOperator::AtArrow
                | BinaryOperator::ArrowAt
                | BinaryOperator::PGOverlap,
            right,
        }
        | Expr::IsNotDistinctFrom(left, right)
        | Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => [(left, right), (right, left)],
        Expr::In {
            expr: tested,
            target: InTarget::Subquery(subquery),
            negated: false,
            global: false,
        } => {
            return sole_projection(subquery)
                .and_then(|projected| request_read(projected, registry))
                .map(|read| vec![(tested.as_ref(), read)])
                .unwrap_or_default();
        }
        _ => return Vec::new(),
    };
    pairs
        .into_iter()
        .filter_map(|(other, request)| Some((other, request_read(request, registry)?)))
        .filter(|(other, _)| request_read(other, registry).is_none())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use crate::test_support::{caller, registry};

    /// `GLOBAL IN` is `ClickHouse` syntax that `PostgreSqlDialect` never parses, so the only
    /// way it reaches this matcher is a hand-built AST (the fuzzer's `Arbitrary` derive
    /// included), and the field has to be read, not wildcarded away.
    #[test]
    fn a_global_in_subquery_is_not_a_compared_operand() {
        let registry = registry([caller("app.user_id")]);
        let expr = parse_expr("id IN (SELECT current_setting('app.user_id', true))");
        assert!(
            !compared_operands(&expr, &registry).is_empty(),
            "sanity: the ordinary IN subquery reads the caller"
        );
        let Expr::In {
            expr: tested,
            target: target @ InTarget::Subquery(_),
            negated,
            ..
        } = &expr
        else {
            panic!("expected an IN subquery");
        };
        let global = Expr::In {
            expr: tested.clone(),
            target: target.clone(),
            negated: *negated,
            global: true,
        };
        assert!(
            compared_operands(&global, &registry).is_empty(),
            "a GLOBAL IN subquery must not be read as comparing a request value"
        );
    }
}
