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
    Composite, ConstantBool, ConstantInCallerSet, FallbackScalarEqualsConstant,
    FallbackScalarInConstantList, FallbackScalarUnequalsConstant, PatternClass,
};
use crate::types::{ConditionParameterName, FallbackStep, RequestAtom, RequestComparison};

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
    /// The settings the caller's value falls back across, one per setting in the order the
    /// policy reads them. Empty for one single read.
    pub(crate) fallback: Vec<FallbackStep>,
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
            fallback: vec![],
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
            fallback: vec![],
        }
    }

    /// The value a fallback read hands over equals a constant the policy names.
    pub(crate) fn fallback_equal_to_value(test: &FallbackScalarEqualsConstant) -> Self {
        Self::of_fallback(
            &test.first,
            &test.rest,
            RequestComparison::CallerValueEquals,
            &test.value,
        )
    }

    /// The value a fallback read hands over differs from a constant the policy names.
    pub(crate) fn fallback_unequal_to_value(test: &FallbackScalarUnequalsConstant) -> Self {
        Self::of_fallback(
            &test.first,
            &test.rest,
            RequestComparison::CallerValueUnequals,
            &test.value,
        )
    }

    /// One constant test on the value a fallback read hands over, whose sources the
    /// condition admits through in the order the read tries them.
    fn of_fallback(
        first: &FallbackStep,
        rest: &[FallbackStep],
        comparison: RequestComparison,
        value: &str,
    ) -> Self {
        let mut fallback = alloc::vec![first.clone()];
        fallback.extend(rest.iter().cloned());
        Self {
            request_parameter: ConditionParameterName::derived(&first.parameter),
            comparison,
            value: value.to_string(),
            setting_key: first.setting_key.clone(),
            separator: None,
            fallback,
        }
    }

    /// The test as the recipe states it.
    pub(crate) fn request_atom(&self) -> RequestAtom {
        RequestAtom {
            request_parameter: self.request_parameter.to_string(),
            comparison: self.comparison,
            value: self.value.clone(),
            fallback: self.fallback.clone(),
        }
    }

    /// Exact structural identity, unambiguous whatever the constant holds.
    fn key(&self) -> String {
        let fallback = self
            .fallback
            .iter()
            .map(|step| {
                format!(
                    "{}/{}/{}/{}/{}",
                    step.parameter,
                    step.from_json_field,
                    step.skips_empty,
                    step.may_be_unset,
                    step.setting_key
                )
            })
            .collect::<Vec<_>>()
            .join("|");
        format!(
            "{}:{:?}:{}:{}:{}",
            self.request_parameter,
            self.comparison,
            self.value.len(),
            self.value,
            fallback
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
            PatternClass::P23FallbackScalarEqualsConstant(test) => {
                Some(Self::Atom(GateAtom::of_fallback(
                    &test.first,
                    &test.rest,
                    RequestComparison::CallerValueEquals,
                    &test.value,
                )))
            }
            PatternClass::P24FallbackScalarUnequalsConstant(test) => {
                Some(Self::Atom(GateAtom::of_fallback(
                    &test.first,
                    &test.rest,
                    RequestComparison::CallerValueUnequals,
                    &test.value,
                )))
            }
            PatternClass::P25FallbackScalarInConstantList(test) => {
                Some(Self::fallback_in_constant_list(test))
            }
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

    /// The `OR` of the constants' equality tests on the value a fallback read hands over,
    /// or where negated the `AND` of their inequality tests, which denies on the unset
    /// reading.
    pub(crate) fn fallback_in_constant_list(test: &FallbackScalarInConstantList) -> Self {
        let comparison = if test.negated {
            RequestComparison::CallerValueUnequals
        } else {
            RequestComparison::CallerValueEquals
        };
        let atoms = test
            .values
            .iter()
            .map(|value| GateAtom::of_fallback(&test.first, &test.rest, comparison, value))
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
///
/// The value the atoms test is the parameter with the fallback chain, and two atoms with
/// different chains test different values, so they cannot contradict each other here.
fn equates_one_value_to_two_constants(conjuncts: &[RequestFormula]) -> bool {
    let mut required: BTreeMap<GateAtomKey, &str> = BTreeMap::new();
    conjuncts.iter().any(|conjunct| match conjunct {
        RequestFormula::Atom(atom) if atom.comparison == RequestComparison::CallerValueEquals => {
            let key = atom.value_key();
            *required.entry(key).or_insert(atom.value.as_str()) != atom.value
        }
        _ => false,
    })
}

/// Which value an atom tests, the parameter and the fallback chain it reads.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GateAtomKey {
    parameter: ConditionParameterName,
    fallback: Vec<FallbackStep>,
}

impl GateAtom {
    fn value_key(&self) -> GateAtomKey {
        GateAtomKey {
            parameter: self.request_parameter.clone(),
            fallback: self.fallback.clone(),
        }
    }
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
    use crate::classifier::patterns::{ClassifiedExpr, ConfidenceLevel};

    fn atom(value: &str) -> RequestFormula {
        RequestFormula::Atom(GateAtom {
            request_parameter: ConditionParameterName::derived("app_bot_list"),
            comparison: RequestComparison::CallerSetHolds,
            value: value.to_string(),
            setting_key: "app.bot_list".to_string(),
            separator: Some(",".to_string()),
            fallback: vec![],
        })
    }

    fn equals(value: &str) -> RequestFormula {
        RequestFormula::Atom(GateAtom {
            request_parameter: ConditionParameterName::derived("app_tier"),
            comparison: RequestComparison::CallerValueEquals,
            value: value.to_string(),
            setting_key: "app.tier".to_string(),
            separator: None,
            fallback: vec![],
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
        let source = declared_source();
        let of_list = |negated: bool| {
            RequestFormula::in_constant_list(&CallerScalarInConstantList {
                values: vec!["main".to_string(), "dev".to_string()],
                negated,
                source: source.clone(),
            })
        };
        // The positive list is an `OR` of `=` and the negated one an `AND` of `<>`.
        assert_eq!(
            of_list(false),
            or(vec![
                RequestFormula::Atom(GateAtom::of(
                    &source,
                    RequestComparison::CallerValueEquals,
                    "main"
                )),
                RequestFormula::Atom(GateAtom::of(
                    &source,
                    RequestComparison::CallerValueEquals,
                    "dev"
                ))
            ])
        );
        assert_eq!(
            of_list(true),
            and(vec![
                RequestFormula::Atom(GateAtom::of(
                    &source,
                    RequestComparison::CallerValueUnequals,
                    "main"
                )),
                RequestFormula::Atom(GateAtom::of(
                    &source,
                    RequestComparison::CallerValueUnequals,
                    "dev"
                ))
            ])
        );
    }

    /// `<>` is one inequality atom over the caller's value, the `=` mirror one equality
    /// atom, the two sharing the source's parameter and setting.
    #[test]
    fn an_unequal_test_composes_one_inequality_atom() {
        let source = declared_source();
        let unequal = PatternClass::P21CallerScalarUnequalsConstant(CallerScalarUnequalsConstant {
            value: "main".to_string(),
            source: source.clone(),
        });
        let equal = PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
            value: "main".to_string(),
            source: source.clone(),
        });
        assert_eq!(
            RequestFormula::of(&unequal),
            Some(RequestFormula::Atom(GateAtom::of(
                &source,
                RequestComparison::CallerValueUnequals,
                "main"
            )))
        );
        assert_eq!(
            RequestFormula::of(&equal),
            Some(RequestFormula::Atom(GateAtom::of(
                &source,
                RequestComparison::CallerValueEquals,
                "main"
            )))
        );
    }

    /// A list gate inside a composite reads through `of`, so a policy that joins it with
    /// another request gate keeps the list's tests beside the other gate's in one form.
    #[test]
    fn a_list_gate_joined_with_another_request_gate_reads_through_of() {
        let source = declared_source();
        let composite = PatternClass::P8Composite(Composite {
            op: BoolOp::Or,
            parts: vec![
                ClassifiedExpr {
                    pattern: PatternClass::P22CallerScalarInConstantList(
                        CallerScalarInConstantList {
                            values: vec!["main".to_string(), "dev".to_string()],
                            negated: false,
                            source: source.clone(),
                        },
                    ),
                    confidence: ConfidenceLevel::A,
                },
                ClassifiedExpr {
                    pattern: PatternClass::P21CallerScalarUnequalsConstant(
                        CallerScalarUnequalsConstant {
                            value: "staging".to_string(),
                            source: source.clone(),
                        },
                    ),
                    confidence: ConfidenceLevel::A,
                },
            ],
        });
        let formula = RequestFormula::of(&composite).expect("both parts read only the request");
        assert_eq!(
            formula,
            or(vec![
                or(vec![
                    RequestFormula::Atom(GateAtom::of(
                        &source,
                        RequestComparison::CallerValueEquals,
                        "main"
                    )),
                    RequestFormula::Atom(GateAtom::of(
                        &source,
                        RequestComparison::CallerValueEquals,
                        "dev"
                    ))
                ]),
                RequestFormula::Atom(GateAtom::of(
                    &source,
                    RequestComparison::CallerValueUnequals,
                    "staging"
                ))
            ])
        );
    }

    /// The two sources a fallback read walks, in the order the read tries them.
    fn fallback_steps() -> (FallbackStep, Vec<FallbackStep>) {
        (
            FallbackStep {
                setting_key: "request.jwt.claim.role".to_string(),
                parameter: "request_jwt_claim_role".to_string(),
                from_json_field: false,
                skips_empty: false,
                may_be_unset: true,
            },
            vec![FallbackStep {
                setting_key: "request.jwt.claims".to_string(),
                parameter: "request_jwt_claims_role".to_string(),
                from_json_field: true,
                skips_empty: false,
                may_be_unset: true,
            }],
        )
    }

    /// A fallback gate inside a composite reads through `of` like a single read, so a
    /// policy that joins it with another request gate keeps the fallback's tests beside
    /// the other gate's in one form, and `<>` and the `IN` list over one value compose
    /// like the single read's.
    #[test]
    fn a_fallback_gate_joined_with_another_request_gate_reads_through_of() {
        let source = declared_source();
        let (first, rest) = fallback_steps();
        let fallback_equal =
            PatternClass::P23FallbackScalarEqualsConstant(FallbackScalarEqualsConstant {
                value: "a".to_string(),
                first: first.clone(),
                rest: rest.clone(),
            });
        assert_eq!(
            RequestFormula::of(&fallback_equal),
            Some(RequestFormula::Atom(GateAtom::of_fallback(
                &first,
                &rest,
                RequestComparison::CallerValueEquals,
                "a"
            )))
        );
        let tier_equal = PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant {
            value: "b".to_string(),
            source: source.clone(),
        });
        assert_eq!(
            RequestFormula::of(&PatternClass::P8Composite(Composite {
                op: BoolOp::Or,
                parts: vec![
                    ClassifiedExpr {
                        pattern: fallback_equal,
                        confidence: ConfidenceLevel::B,
                    },
                    ClassifiedExpr {
                        pattern: tier_equal,
                        confidence: ConfidenceLevel::B,
                    },
                ],
            })),
            Some(or(vec![
                RequestFormula::Atom(GateAtom::of_fallback(
                    &first,
                    &rest,
                    RequestComparison::CallerValueEquals,
                    "a"
                )),
                RequestFormula::Atom(GateAtom::of(
                    &source,
                    RequestComparison::CallerValueEquals,
                    "b"
                ))
            ]))
        );
        assert_eq!(
            RequestFormula::of(&PatternClass::P8Composite(Composite {
                op: BoolOp::And,
                parts: vec![
                    ClassifiedExpr {
                        pattern: PatternClass::P24FallbackScalarUnequalsConstant(
                            FallbackScalarUnequalsConstant {
                                value: "a".to_string(),
                                first: first.clone(),
                                rest: rest.clone(),
                            }
                        ),
                        confidence: ConfidenceLevel::B,
                    },
                    ClassifiedExpr {
                        pattern: PatternClass::P25FallbackScalarInConstantList(
                            FallbackScalarInConstantList {
                                values: vec!["b".to_string(), "c".to_string()],
                                negated: false,
                                first: first.clone(),
                                rest: rest.clone(),
                            }
                        ),
                        confidence: ConfidenceLevel::B,
                    },
                ],
            })),
            Some(and(vec![
                RequestFormula::Atom(GateAtom::of_fallback(
                    &first,
                    &rest,
                    RequestComparison::CallerValueUnequals,
                    "a"
                )),
                or(vec![
                    RequestFormula::Atom(GateAtom::of_fallback(
                        &first,
                        &rest,
                        RequestComparison::CallerValueEquals,
                        "b"
                    )),
                    RequestFormula::Atom(GateAtom::of_fallback(
                        &first,
                        &rest,
                        RequestComparison::CallerValueEquals,
                        "c"
                    )),
                ])
            ]))
        );
    }
}
