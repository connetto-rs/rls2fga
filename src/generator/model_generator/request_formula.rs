//! A gate that reads only the request, reduced to one normal form.
//!
//! The gate has the same truth value for every row, so it is stated once per guarded type
//! rather than per row, and two spellings of one gate have to land on one statement. The
//! normal form flattens nested `AND`/`OR`, drops duplicate children, sorts them, folds
//! constants away and applies absorption, so reordered, repeated or subsumed arms reach
//! the same relation.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeMap;

use crate::classifier::function_registry::DeclaredSource;
use crate::classifier::patterns::{
    BoolOp, CallerScalarEqualsConstant, CallerScalarInConstantList, CallerScalarUnequalsConstant,
    Composite, ConstantBool, ConstantInCallerSet, PatternClass,
};
use crate::types::{ConditionParameterName, RequestAtom, RequestComparison};

/// One test of a request value against a constant the policy names, with the caller
/// contract it states.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GateAtom {
    /// Parameter the caller supplies its value as.
    pub(crate) request_parameter: ConditionParameterName,
    pub(crate) comparison: RequestComparison,
    /// The constant the policy names.
    pub(crate) value: String,
    /// Session setting the caller's value mirrors.
    pub(crate) setting_key: String,
    /// Separator the policy splits that setting on, for a set.
    pub(crate) separator: Option<String>,
}

impl GateAtom {
    /// `'value' = ANY(caller set)`.
    pub(crate) fn held_by_caller_set(test: &ConstantInCallerSet) -> Self {
        let ConstantInCallerSet {
            value,
            separator,
            source,
        } = test;
        Self {
            request_parameter: source.condition_parameter().clone(),
            comparison: RequestComparison::CallerSetHolds,
            value: value.clone(),
            setting_key: source.setting_key().to_string(),
            separator: separator.clone(),
        }
    }

    /// `caller value = 'value'`.
    pub(crate) fn equal_to_caller_value(test: &CallerScalarEqualsConstant) -> Self {
        Self::of(
            &test.source,
            RequestComparison::CallerValueEquals,
            &test.value,
        )
    }

    /// `caller value <> 'value'`.
    pub(crate) fn unequal_to_caller_value(test: &CallerScalarUnequalsConstant) -> Self {
        Self::of(
            &test.source,
            RequestComparison::CallerValueUnequals,
            &test.value,
        )
    }

    /// One constant test on the caller's single value.
    fn of(source: &DeclaredSource, comparison: RequestComparison, value: &str) -> Self {
        Self {
            request_parameter: source.condition_parameter().clone(),
            comparison,
            value: value.to_string(),
            setting_key: source.setting_key().to_string(),
            separator: None,
        }
    }

    /// The test as the recipe states it.
    pub(crate) fn request_atom(&self) -> RequestAtom {
        RequestAtom {
            request_parameter: self.request_parameter.to_string(),
            comparison: self.comparison,
            value: self.value.clone(),
        }
    }

    /// Exact structural identity, unambiguous whatever the constant holds.
    fn key(&self) -> String {
        format!(
            "{}:{:?}:{}:{}",
            self.request_parameter,
            self.comparison,
            self.value.len(),
            self.value
        )
    }
}

/// A gate over request values in normal form.
///
/// [`Self::Any`] and [`Self::All`] hold at least two children, sorted and distinct, none
/// of them a constant or a child of the same kind, and none subsumed by a sibling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RequestFormula {
    Const(bool),
    Atom(GateAtom),
    Any(Vec<RequestFormula>),
    All(Vec<RequestFormula>),
}

impl RequestFormula {
    /// The normal form of `pattern`, or `None` when it reads anything besides the
    /// request.
    pub(crate) fn of(pattern: &PatternClass) -> Option<Self> {
        match pattern {
            PatternClass::P10ConstantBool(ConstantBool { value }) => Some(Self::Const(*value)),
            PatternClass::P16ConstantInCallerSet(test) => {
                Some(Self::Atom(GateAtom::held_by_caller_set(test)))
            }
            PatternClass::P17CallerScalarEqualsConstant(test) => {
                Some(Self::Atom(GateAtom::equal_to_caller_value(test)))
            }
            PatternClass::P21CallerScalarUnequalsConstant(test) => {
                Some(Self::Atom(GateAtom::unequal_to_caller_value(test)))
            }
            PatternClass::P22CallerScalarInConstantList(test) => Some(Self::in_constant_list(test)),
            PatternClass::P8Composite(Composite { op, parts }) => {
                let children = parts
                    .iter()
                    .map(|part| Self::of(&part.pattern))
                    .collect::<Option<Vec<_>>>()?;
                Some(Self::join(*op, children))
            }
            _ => None,
        }
    }

    /// `caller value IN ('a', 'b')`, the `OR` of the constants' equality tests, or where
    /// negated the `AND` of their inequality tests, which denies on the unset reading.
    pub(crate) fn in_constant_list(test: &CallerScalarInConstantList) -> Self {
        let comparison = if test.negated {
            RequestComparison::CallerValueUnequals
        } else {
            RequestComparison::CallerValueEquals
        };
        let atoms = test
            .values
            .iter()
            .map(|value| GateAtom::of(&test.source, comparison, value))
            .map(Self::Atom)
            .collect();
        if test.negated {
            Self::join(BoolOp::And, atoms)
        } else {
            Self::join(BoolOp::Or, atoms)
        }
    }

    /// `children` joined by `op`, in normal form.
    pub(crate) fn join(op: BoolOp, children: Vec<Self>) -> Self {
        // The value that decides the join outright: `true` for `OR`, `false` for `AND`.
        let absorbing = op == BoolOp::Or;
        let mut flat = Vec::with_capacity(children.len());
        for child in children {
            match (op, child) {
                (_, Self::Const(value)) if value == absorbing => return Self::Const(absorbing),
                (_, Self::Const(_)) => {}
                (BoolOp::Or, Self::Any(grandchildren))
                | (BoolOp::And, Self::All(grandchildren)) => {
                    flat.extend(grandchildren);
                }
                (_, other) => flat.push(other),
            }
        }
        flat.sort();
        flat.dedup();
        if op == BoolOp::And && equates_one_value_to_two_constants(&flat) {
            return Self::Const(false);
        }
        let flat = without_absorbed(op, flat);
        match <[Self; 1]>::try_from(flat) {
            Ok([only]) => only,
            Err(flat) if flat.is_empty() => Self::Const(!absorbing),
            Err(flat) => match op {
                BoolOp::Or => Self::Any(flat),
                BoolOp::And => Self::All(flat),
            },
        }
    }

    /// Exact structural identity, which two formulas share only when they are equal.
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Const(value) => value.to_string(),
            Self::Atom(atom) => atom.key(),
            Self::Any(children) => format!("any({})", child_keys(children)),
            Self::All(children) => format!("all({})", child_keys(children)),
        }
    }
}

fn child_keys(children: &[RequestFormula]) -> String {
    children
        .iter()
        .map(RequestFormula::key)
        .collect::<Vec<_>>()
        .join(",")
}

/// One request value equal to two different constants, which no caller satisfies.
fn equates_one_value_to_two_constants(conjuncts: &[RequestFormula]) -> bool {
    let mut required: BTreeMap<&ConditionParameterName, &str> = BTreeMap::new();
    conjuncts.iter().any(|conjunct| match conjunct {
        RequestFormula::Atom(atom) if atom.comparison == RequestComparison::CallerValueEquals => {
            *required
                .entry(&atom.request_parameter)
                .or_insert(atom.value.as_str())
                != atom.value
        }
        _ => false,
    })
}

/// Drop every child a sibling subsumes: under `OR`, `a OR (a AND b)` is `a`, and under
/// `AND`, `a AND (a OR b)` is `a`.
fn without_absorbed(op: BoolOp, children: Vec<RequestFormula>) -> Vec<RequestFormula> {
    let subsumed: Vec<bool> = children
        .iter()
        .map(|child| {
            let own = terms(op, child);
            children.iter().any(|sibling| {
                let theirs = terms(op, sibling);
                theirs.len() < own.len() && theirs.iter().all(|term| own.contains(term))
            })
        })
        .collect();
    children
        .into_iter()
        .zip(subsumed)
        .filter_map(|(child, subsumed)| (!subsumed).then_some(child))
        .collect()
}

/// The terms `child` contributes to a join by `op`: its children when it is the dual
/// join, itself otherwise.
fn terms(op: BoolOp, child: &RequestFormula) -> Vec<&RequestFormula> {
    match (op, child) {
        (BoolOp::Or, RequestFormula::All(terms)) | (BoolOp::And, RequestFormula::Any(terms)) => {
            terms.iter().collect()
        }
        (_, other) => vec![other],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(value: &str) -> RequestFormula {
        RequestFormula::Atom(GateAtom {
            request_parameter: ConditionParameterName::derived("app_bot_list"),
            comparison: RequestComparison::CallerSetHolds,
            value: value.to_string(),
            setting_key: "app.bot_list".to_string(),
            separator: Some(",".to_string()),
        })
    }

    fn equals(value: &str) -> RequestFormula {
        RequestFormula::Atom(GateAtom {
            request_parameter: ConditionParameterName::derived("app_tier"),
            comparison: RequestComparison::CallerValueEquals,
            value: value.to_string(),
            setting_key: "app.tier".to_string(),
            separator: None,
        })
    }

    fn or(children: Vec<RequestFormula>) -> RequestFormula {
        RequestFormula::join(BoolOp::Or, children)
    }

    fn and(children: Vec<RequestFormula>) -> RequestFormula {
        RequestFormula::join(BoolOp::And, children)
    }

    #[test]
    fn order_nesting_and_repetition_reach_one_form() {
        let plain = or(vec![atom("t0:read"), atom("*")]);
        let respelled = or(vec![atom("*"), or(vec![atom("t0:read"), atom("*")])]);
        assert_eq!(plain, respelled);
        assert_eq!(plain.key(), respelled.key());
    }

    #[test]
    fn constants_decide_or_vanish() {
        assert_eq!(
            or(vec![atom("a"), RequestFormula::Const(true)]),
            RequestFormula::Const(true)
        );
        assert_eq!(or(vec![atom("a"), RequestFormula::Const(false)]), atom("a"));
        assert_eq!(
            and(vec![atom("a"), RequestFormula::Const(false)]),
            RequestFormula::Const(false)
        );
        assert_eq!(and(vec![atom("a"), RequestFormula::Const(true)]), atom("a"));
        assert_eq!(
            and(vec![
                RequestFormula::Const(true),
                RequestFormula::Const(true)
            ]),
            RequestFormula::Const(true)
        );
    }

    #[test]
    fn a_subsumed_arm_is_absorbed() {
        assert_eq!(
            or(vec![atom("a"), and(vec![atom("a"), atom("b")])]),
            atom("a")
        );
        assert_eq!(
            and(vec![atom("a"), or(vec![atom("a"), atom("b")])]),
            atom("a")
        );
        let kept = or(vec![atom("c"), and(vec![atom("a"), atom("b")])]);
        assert!(matches!(&kept, RequestFormula::Any(children) if children.len() == 2));
    }

    #[test]
    fn one_value_equal_to_two_constants_admits_nobody() {
        assert_eq!(
            and(vec![equals("gold"), equals("silver")]),
            RequestFormula::Const(false)
        );
        assert_eq!(and(vec![equals("gold"), equals("gold")]), equals("gold"));
        // A set can hold both, so the same pair over a set stays.
        assert!(matches!(
            and(vec![atom("gold"), atom("silver")]),
            RequestFormula::All(_)
        ));
    }

    #[test]
    fn keys_tell_apart_constants_that_fold_to_one_name() {
        assert_ne!(atom("t0:read").key(), atom("t0_read").key());
        assert_ne!(atom("a,b").key(), or(vec![atom("a"), atom("b")]).key());
    }

    /// One source for a formula test, declared the way the recognizers read it.
    fn declared_source() -> DeclaredSource {
        use crate::classifier::function_registry::DeclaredSources;
        use crate::test_support::{deployment, scalar};

        DeclaredSources::of(&deployment([scalar("app.mode")]))
            .iter()
            .next()
            .expect("the declared setting")
            .clone()
    }

    /// `IN` composes one equality test per constant, and `NOT IN` one inequality test per
    /// constant, so the two negations deny on the unset reading the `IN` admits.
    #[test]
    fn an_in_list_composes_one_test_per_constant() {
        let of_list = |negated: bool| {
            RequestFormula::in_constant_list(&CallerScalarInConstantList {
                values: vec!["main".to_string(), "dev".to_string()],
                negated,
                source: declared_source(),
            })
        };
        let in_list = of_list(false);
        let not_in_list = of_list(true);
        let children = |formula: &RequestFormula| match formula {
            RequestFormula::Any(children) | RequestFormula::All(children) => children.len(),
            _ => panic!("a two-constant list is a join: {formula:?}"),
        };
        assert_eq!(children(&in_list), 2);
        assert_eq!(children(&not_in_list), 2);
        // The positive list is an `OR` of `=` and the negated one an `AND` of `<>`.
        let comparisons = |formula: &RequestFormula| match formula {
            RequestFormula::Any(children) | RequestFormula::All(children) => children
                .iter()
                .map(|child| match child {
                    RequestFormula::Atom(atom) => atom.comparison,
                    _ => panic!("a list child is an atom: {child:?}"),
                })
                .collect::<Vec<_>>(),
            _ => panic!("a two-constant list is a join: {formula:?}"),
        };
        assert_eq!(
            comparisons(&in_list),
            vec![
                RequestComparison::CallerValueEquals,
                RequestComparison::CallerValueEquals
            ]
        );
        assert_eq!(
            comparisons(&not_in_list),
            vec![
                RequestComparison::CallerValueUnequals,
                RequestComparison::CallerValueUnequals
            ]
        );
    }

    /// `<>` is one inequality atom over the caller's value, the `=` mirror one equality
    /// atom, the two sharing the source's parameter and setting.
    #[test]
    fn an_unequal_test_composes_one_inequality_atom() {
        let unequal = RequestFormula::of(&PatternClass::P21CallerScalarUnequalsConstant(
            CallerScalarUnequalsConstant {
                value: "main".to_string(),
                source: declared_source(),
            },
        ))
        .expect("a declared value compared to a constant is a request formula");
        let equal = RequestFormula::of(&PatternClass::P17CallerScalarEqualsConstant(
            CallerScalarEqualsConstant {
                value: "main".to_string(),
                source: declared_source(),
            },
        ))
        .expect("a declared value compared to a constant is a request formula");
        let RequestFormula::Atom(unequal) = unequal else {
            panic!("one constant is one atom, not {unequal:?}")
        };
        let RequestFormula::Atom(equal) = equal else {
            panic!("one constant is one atom, not {equal:?}")
        };
        assert_eq!(unequal.comparison, RequestComparison::CallerValueUnequals);
        assert_eq!(equal.comparison, RequestComparison::CallerValueEquals);
        assert_eq!(unequal.value, equal.value);
        assert_eq!(unequal.request_parameter, equal.request_parameter);
        assert_eq!(unequal.setting_key, equal.setting_key);
    }
}
