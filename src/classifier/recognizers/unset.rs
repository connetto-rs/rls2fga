//! Comparisons whose answer on an unset setting depends on which unset state `PostgreSQL`
//! is in.
//!
//! `current_setting(name, true)` on a setting the request left unset reads `NULL` on a
//! fresh connection and `''` once a transaction that set it has ended. A request leaving
//! a setting unset sends no value, so the model answers as the `NULL` reading does, which
//! admits least. Where the `''` reading admits rows, the model is the narrower of the two.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::ops::ControlFlow;

use sqlparser::ast::{BinaryOperator, Expr, InTarget, UnaryOperator};

use super::session::{declared_read, set_read, sole_projection};
use super::{accessor_read, caller_source, string_literal, unparenthesize};
use crate::classifier::function_registry::{DeclaredSource, FunctionRegistry};
use crate::parser::expr::unwrap_cast_or_nested;

/// Each comparison in `expr` that the `''` reading of a setting a request may leave unset
/// makes true for some row, beside that setting's declaration.
///
/// A value read compared with a row value or with `''` matches the rows holding `''`, and
/// a delimited set read under a negation is empty, so every element passes it. A JSON set
/// is not listed, since `''` is no JSON document and the read raises.
pub(crate) fn empty_readings<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Vec<(&'r DeclaredSource, String)> {
    let mut readings: Vec<(&DeclaredSource, String)> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        let mut record = |source: &'r DeclaredSource| {
            let reading = (source, node.to_string());
            if !readings.contains(&reading) {
                readings.push(reading);
            }
        };
        match node {
            Expr::BinaryOp { left, op, right } => {
                if let Some(comparison) = Comparison::of(op) {
                    compare(comparison, left, right, registry, &mut record);
                }
            }
            Expr::IsNotDistinctFrom(left, right) => {
                compare(Comparison::Equal, left, right, registry, &mut record);
            }
            Expr::IsDistinctFrom(left, right) => {
                compare(Comparison::Unequal, left, right, registry, &mut record);
            }
            Expr::AnyOp {
                left,
                compare_op: BinaryOperator::Eq,
                right,
                ..
            } => {
                if let Some(source) = unset_value(left, registry) {
                    // `x = ANY (ARRAY[...])` is the `IN` shape, so a literal list is judged
                    // by the empty reading, and a right side that is no list stays noted.
                    let holds = match unwrap_cast_or_nested(right) {
                        Expr::Array(array) => list_holds_for_empty(false, &array.elem),
                        _ => true,
                    };
                    if holds {
                        record(source);
                    }
                }
            }
            Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => {
                if let Some(source) = unset_value(left, registry) {
                    record(source);
                }
                if matches!(node, Expr::AllOp { .. }) {
                    if let Some(source) = unset_delimited_set(right, registry) {
                        record(source);
                    }
                }
            }
            Expr::In {
                expr: tested,
                target: InTarget::List(values),
                negated,
                global: false,
            } => {
                if let Some(source) = unset_value(tested, registry) {
                    if list_holds_for_empty(*negated, values) {
                        record(source);
                    }
                }
            }
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: negated,
            } => {
                if let Expr::AnyOp { right, .. } = unparenthesize(negated) {
                    if let Some(source) = unset_delimited_set(right, registry) {
                        record(source);
                    }
                }
            }
            Expr::In {
                target: InTarget::Subquery(subquery),
                negated: true,
                ..
            } => {
                if let Some(source) = sole_projection(subquery)
                    .and_then(|projected| unset_delimited_set(projected, registry))
                {
                    record(source);
                }
            }
            _ => {}
        }
        ControlFlow::<()>::Continue(())
    });
    readings
}

/// How two values are compared, the null-safe forms read as the plain ones since the
/// empty text is not `NULL`.
#[derive(Clone, Copy)]
enum Comparison {
    Equal,
    Unequal,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

impl Comparison {
    fn of(op: &BinaryOperator) -> Option<Self> {
        Some(match op {
            BinaryOperator::Eq => Self::Equal,
            BinaryOperator::NotEq => Self::Unequal,
            BinaryOperator::Lt => Self::Less,
            BinaryOperator::LtEq => Self::LessOrEqual,
            BinaryOperator::Gt => Self::Greater,
            BinaryOperator::GtEq => Self::GreaterOrEqual,
            _ => return None,
        })
    }

    /// The same comparison with its operands swapped.
    fn mirrored(self) -> Self {
        match self {
            Self::Less => Self::Greater,
            Self::LessOrEqual => Self::GreaterOrEqual,
            Self::Greater => Self::Less,
            Self::GreaterOrEqual => Self::LessOrEqual,
            Self::Equal | Self::Unequal => self,
        }
    }

    /// Whether `'' <op> literal` holds. The empty text sorts before every other text in
    /// every collation.
    fn holds_for_empty_against(self, literal: &str) -> bool {
        match self {
            Self::Equal | Self::GreaterOrEqual => literal.is_empty(),
            Self::Unequal | Self::Less => !literal.is_empty(),
            Self::LessOrEqual => true,
            Self::Greater => false,
        }
    }
}

/// Record the setting either side of `left <comparison> right` reads, when its empty
/// reading makes the comparison true for some row, always against a row value and against
/// a literal where `''` satisfies it.
fn compare<'r>(
    comparison: Comparison,
    left: &Expr,
    right: &Expr,
    registry: &'r FunctionRegistry,
    record: &mut impl FnMut(&'r DeclaredSource),
) {
    for (read, other, oriented) in [
        (left, right, comparison),
        (right, left, comparison.mirrored()),
    ] {
        let Some(source) = unset_value(read, registry) else {
            continue;
        };
        if string_literal(other).is_none_or(|literal| oriented.holds_for_empty_against(&literal)) {
            record(source);
        }
    }
}

/// The declaration of the single value `expr` reads, the caller or a scalar, when a
/// request may leave it unset.
fn unset_value<'r>(expr: &Expr, registry: &'r FunctionRegistry) -> Option<&'r DeclaredSource> {
    let caller = accessor_read(expr).and_then(|read| caller_source(&read, registry));
    caller
        .or_else(|| declared_read(expr, registry).map(|(source, _)| source))
        .filter(|source| source.may_be_unset())
}

/// Whether the `''` reading of the value tested against `values` passes the list test,
/// `false` where a non-literal element leaves the reading undecided.
fn list_holds_for_empty(negated: bool, values: &[Expr]) -> bool {
    let Some(literals) = values
        .iter()
        .map(string_literal)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let holds_empty = literals.iter().any(String::is_empty);
    if negated {
        !holds_empty
    } else {
        holds_empty
    }
}

/// The declaration of the delimited set `expr` reads, when a request may leave it unset.
fn unset_delimited_set<'r>(
    expr: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<&'r DeclaredSource> {
    set_read(expr, registry)
        .map(|(source, _)| source)
        .filter(|source| source.may_be_unset() && source.separator().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use crate::parser::sql_parser::{SessionSetting, SetPacking, SettingValue};
    use crate::test_support::{caller, delimited_set, json_field, registry, scalar};
    use sqlparser::ast::DataType;

    fn settings_read(expr: &str, settings: Vec<SessionSetting>) -> Vec<String> {
        let registry = registry(settings);
        empty_readings(&parse_expr(expr), &registry)
            .into_iter()
            .map(|(source, _)| source.setting_key().to_string())
            .collect()
    }

    /// The caller compared with a row value matches the rows holding `''` when the empty
    /// reading is in force, and only a setting a request may leave unset reaches it.
    #[test]
    fn a_caller_that_may_be_unset_matches_rows_holding_the_empty_text() {
        let owner = "owner = current_setting('app.user_id', true)";
        assert_eq!(
            settings_read(owner, vec![caller("app.user_id").may_be_unset()]),
            ["app.user_id"]
        );
        assert!(
            settings_read(owner, vec![caller("app.user_id")]).is_empty(),
            "a setting every request sets has no empty reading"
        );
    }

    /// A value compared with a non-empty literal is never `''`, while a row value or `''`
    /// itself can be.
    #[test]
    fn a_scalar_matches_the_empty_text_only_against_a_row_value_or_the_empty_literal() {
        let unset = || vec![scalar("app.tier").may_be_unset()];
        assert_eq!(
            settings_read("current_setting('app.tier', true) = 'gold'", unset()),
            Vec::<String>::new()
        );
        assert_eq!(
            settings_read("tier = current_setting('app.tier', true)", unset()),
            ["app.tier"]
        );
        assert_eq!(
            settings_read("current_setting('app.tier', true) = ''", unset()),
            ["app.tier"]
        );
    }

    /// `string_to_array('', ',')` is empty, so a negated membership in it holds for every
    /// row, and a positive one for none. `''` is no JSON document, so a JSON set raises.
    #[test]
    fn only_a_negated_delimited_set_admits_on_the_empty_reading() {
        let delimited = || vec![delimited_set("app.blocked", ",").may_be_unset()];
        let split = "string_to_array(current_setting('app.blocked', true), ',')";
        assert_eq!(
            settings_read(&format!("NOT (owner = ANY({split}))"), delimited()),
            ["app.blocked"]
        );
        assert_eq!(
            settings_read(&format!("owner <> ALL({split})"), delimited()),
            ["app.blocked"]
        );
        assert_eq!(
            settings_read(&format!("owner = ANY({split})"), delimited()),
            Vec::<String>::new()
        );
        assert_eq!(
            settings_read(
                &format!("owner NOT IN (SELECT unnest({split}))"),
                delimited()
            ),
            ["app.blocked"]
        );

        let json = vec![json_field(
            "request.jwt.claims",
            &["blocked"],
            SettingValue::Set {
                element: DataType::Text,
                packing: SetPacking::JsonArray,
            },
        )
        .may_be_unset()];
        assert_eq!(
            settings_read(
                "owner NOT IN (SELECT jsonb_array_elements_text(\
                 current_setting('request.jwt.claims', true)::jsonb -> 'blocked'))",
                json,
            ),
            Vec::<String>::new()
        );
    }

    /// Each comparison reads the empty text as `PostgreSQL` does, matching a row value and
    /// holding against a literal where `''` satisfies the operator, since `''` sorts before
    /// every other text.
    #[test]
    fn every_comparison_shape_reads_the_empty_text() {
        let unset = || vec![scalar("app.tier").may_be_unset()];
        for (expression, named) in [
            (
                "tier IS NOT DISTINCT FROM current_setting('app.tier', true)",
                true,
            ),
            (
                "current_setting('app.tier', true) IS NOT DISTINCT FROM 'gold'",
                false,
            ),
            (
                "current_setting('app.tier', true) IS DISTINCT FROM 'gold'",
                true,
            ),
            ("current_setting('app.tier', true) <> 'gold'", true),
            ("'gold' >= current_setting('app.tier', true)", true),
            ("current_setting('app.tier', true) < 'gold'", true),
            ("current_setting('app.tier', true) > 'gold'", false),
            ("'gold' > current_setting('app.tier', true)", true),
            ("'gold' <= current_setting('app.tier', true)", false),
            ("current_setting('app.tier', true) >= ''", true),
            ("current_setting('app.tier', true) = ANY(tiers)", true),
            ("current_setting('app.tier', true) <> ALL(tiers)", true),
        ] {
            let expected: Vec<String> = if named {
                vec!["app.tier".to_string()]
            } else {
                Vec::new()
            };
            assert_eq!(settings_read(expression, unset()), expected, "{expression}");
        }
    }
}
