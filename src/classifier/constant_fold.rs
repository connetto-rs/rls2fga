//! Comparisons between two constants, settled before classification.
//!
//! Where the deployment acts as one role, `current_user` reads as the role's name, so
//! `current_user = 'reader'` compares two literals and settles to a truth every request
//! shares. Folding it to `TRUE` or `FALSE` leaves a constant every recognizer already
//! reads.

use alloc::borrow::Cow;
use core::ops::ControlFlow;

use sqlparser::ast::{BinaryOperator, Expr, InTarget, Value, VisitMut, VisitorMut};

use crate::parser::expr::CastChain;

/// The longest text a `name` holds, `NAMEDATALEN` less its terminator.
const NAME_MAX_BYTES: usize = 63;

/// The text `expr` holds when it is a string literal under casts that keep it as written.
/// A `char(n)` or `varchar(n)` cast pads or truncates, and a `name` truncates past
/// [`NAME_MAX_BYTES`], so none of them keeps it.
fn text_constant(expr: &Expr) -> Option<&str> {
    let (casts, inner) = CastChain::peeled(expr);
    let Expr::Value(value) = inner else {
        return None;
    };
    let Value::SingleQuotedString(text) = &value.value else {
        return None;
    };
    let kept: &[&str] = if text.len() <= NAME_MAX_BYTES {
        &["name"]
    } else {
        &[]
    };
    casts
        .renaming_beyond(kept)
        .is_none()
        .then_some(text.as_str())
}

/// The truth of `expr` when it compares constants alone.
fn constant_truth(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            let equal = text_constant(left)? == text_constant(right)?;
            match op {
                BinaryOperator::Eq => Some(equal),
                BinaryOperator::NotEq => Some(!equal),
                _ => None,
            }
        }
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated,
            global: false,
        } => {
            let probe = text_constant(expr)?;
            let mut found = false;
            for item in list {
                found |= text_constant(item)? == probe;
            }
            Some(found != *negated)
        }
        _ => None,
    }
}

/// `expr` with every comparison between text constants replaced by its truth. Borrowed
/// where none occurs.
pub(crate) fn fold_constant_comparisons(expr: Cow<'_, Expr>) -> Cow<'_, Expr> {
    let found = sqlparser::ast::visit_expressions(expr.as_ref(), |node| {
        if constant_truth(node).is_some() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_break();
    if !found {
        return expr;
    }
    let mut folded = expr.into_owned();
    let _ = VisitMut::visit(&mut folded, &mut Fold);
    Cow::Owned(folded)
}

struct Fold;

impl VisitorMut for Fold {
    type Break = ();

    fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        if let Some(truth) = constant_truth(expr) {
            *expr = Expr::Value(Value::Boolean(truth).into());
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use alloc::string::{String, ToString};

    fn folded(sql: &str) -> String {
        fold_constant_comparisons(Cow::Owned(parse_expr(sql))).to_string()
    }

    /// A comparison between two literals, under the casts a lowered `current_user`
    /// carries, reads as its truth.
    #[test]
    fn a_comparison_between_constants_is_its_truth() {
        for (written, read) in [
            ("'reader' = 'reader'", "true"),
            ("'reader' = 'writer'", "false"),
            ("'reader' <> 'writer'", "true"),
            ("'reader'::TEXT = 'reader'", "true"),
            ("'reader'::name = 'reader'", "true"),
            ("'reader' IN ('writer', 'reader')", "true"),
            ("'reader' NOT IN ('writer', 'reader')", "false"),
            ("owner = 'x' OR 'reader' = 'writer'", "owner = 'x' OR false"),
        ] {
            assert_eq!(folded(written), read, "{written}");
        }
    }

    /// A column, a padding or truncating cast, a case-folding comparison or a list holding
    /// a non-constant is no comparison between constants.
    #[test]
    fn anything_but_two_text_constants_is_left_alone() {
        let long_name = format!("'{}'::name = 'x'", "x".repeat(NAME_MAX_BYTES + 1));
        for sql in [
            "owner = 'reader'",
            "'reader '::CHAR(7) = 'reader'",
            "'reader'::VARCHAR(3) = 'rea'",
            long_name.as_str(),
            "'reader' ILIKE 'READER'",
            "'reader' IN ('writer', owner)",
            "'1' < '2'",
        ] {
            assert_eq!(folded(sql), parse_expr(sql).to_string(), "{sql}");
        }
    }
}
