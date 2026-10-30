//! Consumer-supplied classification for expressions this crate refuses.
//!
//! The crate falls closed on an expression it cannot recognize, which denies what
//! `PostgreSQL` grants. A consumer who knows what their own expression means can say so
//! by implementing [`PolicyOracle`] and calling [`consult_oracle`] between
//! [`Translator::classify`](crate::translator::Translator::classify) and the generators.
//!
//! Doing that by hand is possible, since every field involved is public, and it is a
//! trap. A refusal nests inside [`PatternClass::P5ParentInheritance`],
//! [`PatternClass::P7AbacAnd`], [`PatternClass::P8Composite`] and the base of
//! [`PatternClass::MembershipExclusion`], so a walk that knows
//! only the obvious one leaves the refusal in place and the model silently denies. An
//! enclosing pattern also keeps the grade its refused part dragged it to, so
//! `filter_policies_for_output` drops the whole clause even after the leaf is answered.
//! This module owns both problems.
//!
//! An oracle answers in one of three ways. [`OracleAnswer::Classified`] supplies a
//! translation, [`OracleAnswer::Denied`] says the expression grants nobody, and
//! [`OracleAnswer::Bailed`] leaves the refusal in place to be reported. Only the last is
//! a gap, and it is the default, so an oracle implementing nothing changes nothing.
//!
//! ```
//! use rls2fga::classifier::oracle::{consult_oracle, OracleAnswer, PolicyOracle, RefusedExpr};
//! use rls2fga::classifier::patterns::{ClassifiedExpr, ConstantBool, PatternClass};
//! use rls2fga::types::ConfidenceLevel;
//! use rls2fga::parser::sql_parser::parse_schema;
//! use rls2fga::translator::TranslatorBuilder;
//!
//! struct BitFlagIsPublic;
//!
//! impl PolicyOracle for BitFlagIsPublic {
//!     fn classify(&self, refused: &RefusedExpr<'_>) -> OracleAnswer {
//!         // `&` has no translation in this crate, but the deployment knows bit 4 marks
//!         // a row readable by anyone.
//!         if refused.sql_text().contains("flags & 4") {
//!             OracleAnswer::Classified(Box::new(ClassifiedExpr {
//!                 pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
//!                 confidence: ConfidenceLevel::A,
//!             }))
//!         } else {
//!             OracleAnswer::Bailed
//!         }
//!     }
//! }
//!
//! let db = parse_schema(
//!     "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, flags INT);\n\
//!      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
//!      CREATE POLICY docs_sel ON docs FOR SELECT\n\
//!        USING ((flags & 4) = 4 AND owner_id = current_user);\n",
//! )?;
//! let translator = TranslatorBuilder::new()
//!     .with_min_confidence(ConfidenceLevel::B)
//!     .build();
//!
//! let mut classified = translator.classify(&db);
//! let answered = consult_oracle(&mut classified, &BitFlagIsPublic);
//!
//! assert_eq!(answered.len(), 1);
//! assert_eq!(answered[0].sql_text(), "(flags & 4) = 4");
//! # Ok::<(), rls2fga::parser::sql_parser::SchemaError>(())
//! ```

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::classifier::patterns::{
    composite_confidence, AbacAnd, ArrayMembership, AttributeCondition, BooleanFlag,
    CallerScalarEqualsConstant, ClassifiedExpr, ClassifiedPolicy, Composite, ConfidenceLevel,
    ConstantBool, ConstantInCallerSet, DirectOwnership, ExistsMembership, ExpandedFunction,
    JsonbFieldOwnership, MembershipExclusion, MembershipInCallerSet, NumericThreshold,
    ParentInheritance, PatternClass, RoleNameInList, RowValueEqualsCallerScalar,
    RowValueInCallerSet, UnclassifiedExpr, UncorrelatedMembership,
};

/// Which clause of a policy an expression came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyClause {
    /// The `USING` clause, which filters the rows a command sees.
    Using,
    /// The `WITH CHECK` clause, which admits the rows a command writes.
    WithCheck,
}

impl PolicyClause {
    /// The clause as it is spelled in DDL.
    #[must_use]
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Using => "USING",
            Self::WithCheck => "WITH CHECK",
        }
    }
}

/// One expression the crate refused, offered to a [`PolicyOracle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedExpr<'a> {
    policy_name: &'a str,
    clause: PolicyClause,
    sql_text: &'a str,
    reason: &'a str,
}

impl<'a> RefusedExpr<'a> {
    /// Name of the policy the expression belongs to.
    #[must_use]
    pub fn policy_name(&self) -> &'a str {
        self.policy_name
    }

    /// Clause the expression came from.
    #[must_use]
    pub fn clause(&self) -> PolicyClause {
        self.clause
    }

    /// The expression as written, which is what an oracle matches on.
    #[must_use]
    pub fn sql_text(&self) -> &'a str {
        self.sql_text
    }

    /// Why this crate refused it.
    #[must_use]
    pub fn reason(&self) -> &'a str {
        self.reason
    }
}

/// What an oracle answers for a refused expression.
///
/// The three states are distinct on purpose. `Option` conflated the first two, so an
/// informed denial was reported as a translation gap.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum OracleAnswer {
    /// The oracle does not know this expression. The refusal stands and stays reported.
    Bailed,
    /// The oracle knows it and it grants nobody. A decision, not a gap.
    Denied,
    /// The oracle's own classification, whose grade still faces `min_confidence`.
    ///
    /// Boxed to keep this enum near the size of its two empty variants, since a
    /// classification carries every field the widest pattern needs.
    Classified(Box<ClassifiedExpr>),
}

/// Supplies a classification for an expression this crate refused.
///
/// The default bails on everything, so an oracle implementing nothing leaves the crate's
/// closed default exactly as it is.
pub trait PolicyOracle {
    /// Classify the refused expression, deny it deliberately, or bail.
    fn classify(&self, _refused: &RefusedExpr<'_>) -> OracleAnswer {
        OracleAnswer::Bailed
    }
}

/// What an oracle answered, so a report can attribute the classification to it.
#[derive(Debug, Clone, PartialEq)]
pub struct OracleSubstitution {
    policy_name: String,
    clause: PolicyClause,
    sql_text: String,
    reason: String,
    confidence: ConfidenceLevel,
}

impl OracleSubstitution {
    /// Name of the policy whose clause the oracle answered.
    #[must_use]
    pub fn policy_name(&self) -> &str {
        &self.policy_name
    }

    /// Clause the answered expression came from.
    #[must_use]
    pub fn clause(&self) -> PolicyClause {
        self.clause
    }

    /// The expression the oracle answered for.
    #[must_use]
    pub fn sql_text(&self) -> &str {
        &self.sql_text
    }

    /// Why this crate had refused it.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Grade the oracle claimed.
    #[must_use]
    pub fn confidence(&self) -> ConfidenceLevel {
        self.confidence
    }
}

/// Offer every refused expression in `policies` to `oracle` and apply what it answers.
///
/// Refusals are found wherever they nest, and every enclosing pattern is regraded
/// through [`composite_confidence`] so a clause is not dropped for a refusal that no
/// longer exists. Returns one entry per substitution, in the order they were applied.
pub fn consult_oracle<O>(policies: &mut [ClassifiedPolicy], oracle: &O) -> Vec<OracleSubstitution>
where
    O: PolicyOracle + ?Sized,
{
    let mut answered = Vec::new();
    for policy in policies {
        let name = policy.name().to_string();
        for (clause, expr) in [
            (PolicyClause::Using, policy.using_classification.as_mut()),
            (
                PolicyClause::WithCheck,
                policy.with_check_classification.as_mut(),
            ),
        ] {
            if let Some(expr) = expr {
                consult_expr(expr, &name, clause, oracle, &mut answered);
            }
        }
    }
    answered
}

/// Apply `oracle` to `expr` and everything nested in it, regrading on the way out.
///
/// Returns `true` when anything below `expr` changed, which is what tells the caller to
/// regrade in its turn.
fn consult_expr<O>(
    expr: &mut ClassifiedExpr,
    policy_name: &str,
    clause: PolicyClause,
    oracle: &O,
    answered: &mut Vec<OracleSubstitution>,
) -> bool
where
    O: PolicyOracle + ?Sized,
{
    if let PatternClass::Unknown(UnclassifiedExpr { sql_text, reason }) = &expr.pattern {
        let refused = RefusedExpr {
            policy_name,
            clause,
            sql_text,
            reason,
        };
        let supplied = match oracle.classify(&refused) {
            OracleAnswer::Bailed => return false,
            // A denial nobody doubts, so it passes any threshold and composes as the
            // false branch of whatever encloses it.
            OracleAnswer::Denied => ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: false }),
                confidence: ConfidenceLevel::A,
            },
            OracleAnswer::Classified(supplied) => *supplied,
        };
        answered.push(OracleSubstitution {
            policy_name: policy_name.to_string(),
            clause,
            sql_text: sql_text.clone(),
            reason: reason.clone(),
            confidence: supplied.confidence,
        });
        *expr = supplied;
        return true;
    }

    // Every variant holding a `ClassifiedExpr`. Matched exhaustively on purpose: a new
    // nesting variant must fail to compile here rather than hide a refusal from the
    // oracle. Each nesting arm yields the grade it now earns, so the recursion and the
    // regrade are one decision: a second match deciding the grade would keep the arms
    // compiler-checked while letting a new one silently hold the grade its refused part
    // dragged it to.
    let regraded = match &mut expr.pattern {
        PatternClass::P5ParentInheritance(ParentInheritance { inner_pattern, .. }) => {
            consult_expr(inner_pattern, policy_name, clause, oracle, answered)
                .then(|| composite_confidence([inner_pattern.as_ref()]))
        }
        PatternClass::P7AbacAnd(AbacAnd {
            relationship_part, ..
        }) => consult_expr(relationship_part, policy_name, clause, oracle, answered)
            .then(|| composite_confidence([relationship_part.as_ref()])),
        // The expansion is proven, so the grade stays the body's rather than being
        // capped as a composite.
        PatternClass::ExpandedFunction(ExpandedFunction { inner, .. }) => {
            consult_expr(inner, policy_name, clause, oracle, answered).then_some(inner.confidence)
        }
        PatternClass::P8Composite(Composite { parts, .. }) => {
            let mut any = false;
            for part in parts.iter_mut() {
                any |= consult_expr(part, policy_name, clause, oracle, answered);
            }
            any.then(|| composite_confidence(parts.iter()))
        }
        PatternClass::MembershipExclusion(MembershipExclusion { base, .. }) => {
            match base.as_deref_mut() {
                Some(base) => consult_expr(base, policy_name, clause, oracle, answered)
                    .then(|| crate::classifier::patterns::exclusion_confidence(Some(base))),
                None => None,
            }
        }
        // The declared request-scoped shapes nest no expression, so nothing inside them
        // can hold a refusal the oracle has not seen.
        PatternClass::P18MembershipInCallerSet(MembershipInCallerSet { .. })
        | PatternClass::P14RowValueInCallerSet(RowValueInCallerSet { .. })
        | PatternClass::P15RowValueEqualsCallerScalar(RowValueEqualsCallerScalar { .. })
        | PatternClass::P16ConstantInCallerSet(ConstantInCallerSet { .. })
        | PatternClass::P17CallerScalarEqualsConstant(CallerScalarEqualsConstant { .. })
        | PatternClass::P1NumericThreshold(NumericThreshold { .. })
        | PatternClass::P2RoleNameInList(RoleNameInList { .. })
        | PatternClass::P3DirectOwnership(DirectOwnership { .. })
        | PatternClass::P4ExistsMembership(ExistsMembership { .. })
        | PatternClass::P6BooleanFlag(BooleanFlag { .. })
        | PatternClass::P19IndirectMembership(_)
        | PatternClass::P9AttributeCondition(AttributeCondition { .. })
        | PatternClass::P10ConstantBool(ConstantBool { .. })
        | PatternClass::P11ArrayMembership(ArrayMembership { .. })
        | PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { .. })
        | PatternClass::P13UncorrelatedMembership(UncorrelatedMembership { .. })
        | PatternClass::Unknown(UnclassifiedExpr { .. }) => None,
    };

    match regraded {
        Some(confidence) => {
            expr.confidence = confidence;
            true
        }
        None => false,
    }
}
