#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArguments, InTarget, Select, SelectItem, TableFactor,
    UnaryOperator, Value,
};

use crate::classifier::function_registry::{
    FunctionRegistry, SessionAttribute, SessionAttributeKind,
};
use crate::classifier::patterns::*;
pub use crate::parser::expr::extract_column_name;
pub(crate) use crate::parser::expr::unwrap_cast_or_nested;
use crate::parser::expr::{extract_column_name_through_coalesce, is_coalesce_wrapped, CastChain};
use crate::parser::expr::{function_arg_expr, function_call, positional_function_arg};
use crate::parser::function_analyzer::current_setting_literal_key;
use crate::parser::function_analyzer::FunctionSemantic;
use crate::parser::names::{
    builtin_function_name, folded_function_name, is_current_user_keyword_name,
    is_public_flag_column_name, is_user_related_column_name, lookup_table, parse_target,
    stored_ident_name, stored_relation_name,
};
use crate::parser::sql_parser::{ColumnLike, DatabaseLike, ForeignKeyLike, TableLike};
use crate::types::ColumnName;

/// P7/P9 attribute-condition detection (non-user column comparisons, temporal guards).
mod attribute;
/// Casts that can rename a value compared with a request value.
mod casts;
/// Whether a residual answers every caller alike.
mod invariant;
/// Request-scoped values a deployment declared readable.
mod session;
/// P4/P5 membership and parent-inheritance recognizers (correlated EXISTS / IN subqueries).
mod subquery;

use attribute::attribute_literal;
pub use attribute::{
    attribute_literal_predicate, attribute_request_predicate, is_attribute_check,
    residual_predicate,
};
pub(crate) use attribute::{conjunct_reads_only_the_row, residual_predicate_reading};
pub(crate) use casts::{renaming_casts, renaming_reason};
pub(crate) use invariant::{residual_relations, MembershipScope};
pub use session::recognize_session_attribute;
pub(crate) use session::{
    caller_set, caller_set_in_subquery, row_valued_set, undeclared_set_reads,
};
pub(crate) use subquery::owner_key_of;
pub(crate) use subquery::projected_select;
pub use subquery::recognize_p19_indirect_membership;
pub(crate) use subquery::{
    diagnose_p4_membership_ambiguity, diagnose_p5_parent_inheritance_ambiguity,
};
pub use subquery::{recognize_p4, recognize_p4_in_subquery, recognize_p5};
pub(crate) use subquery::{resolve_membership_pairing, MembershipPairing};

/// Recognize P1: `role_fn(user, resource) >= N`, in either operand order.
pub fn recognize_p1<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    registry: &FunctionRegistry,
    command: PolicyCommand,
) -> Option<ClassifiedExpr> {
    if let Expr::BinaryOp { left, op, right } = expr {
        let (func_expr, threshold_expr, operator) = match op {
            BinaryOperator::GtEq => (left.as_ref(), right.as_ref(), ThresholdOperator::Gte),
            BinaryOperator::Gt => (left.as_ref(), right.as_ref(), ThresholdOperator::Gt),
            BinaryOperator::LtEq => (right.as_ref(), left.as_ref(), ThresholdOperator::Gte),
            BinaryOperator::Lt => (right.as_ref(), left.as_ref(), ThresholdOperator::Gt),
            _ => return None,
        };

        let func_name = extract_function_name(func_expr)?;
        if !registry.is_role_threshold(&func_name) {
            return None;
        }
        // Guard against resource attribute comparisons.
        if !function_has_current_user_arg(func_expr, registry) {
            return None;
        }

        let threshold = extract_integer_value(threshold_expr)?;

        return Some(ClassifiedExpr {
            pattern: PatternClass::P1NumericThreshold(NumericThreshold {
                resource_column: role_threshold_resource_column(func_expr, &func_name, registry),
                function_name: registry.resolved_name(&func_name),
                operator,
                threshold,
                command,
            }),
            confidence: ConfidenceLevel::A,
        });
    }
    None
}

/// Role name IN-list or `pg_has_role` built-in.
pub fn recognize_p2<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    if let Some((inner_expr, list)) = constant_in_list(expr) {
        if let Some(func_name) = extract_function_name(inner_expr) {
            if registry.is_role_threshold(&func_name) {
                if !function_has_current_user_arg(inner_expr, registry) {
                    return None;
                }

                let role_names = extract_role_names_from_in_list(list, true)?;
                if !role_names.is_empty() {
                    return Some(ClassifiedExpr {
                        pattern: PatternClass::P2RoleNameInList(RoleNameInList {
                            resource_column: role_threshold_resource_column(
                                inner_expr, &func_name, registry,
                            ),
                            function_name: registry.resolved_name(&func_name),
                            role_names,
                            privilege: RolePrivilege::Member,
                        }),
                        confidence: ConfidenceLevel::A,
                    });
                }
            }
        }
    }

    if let Some(c) = recognize_pg_has_role(expr, registry) {
        return Some(c);
    }

    recognize_role_accessor_comparison(expr, registry)
}

/// The column a role-threshold call passes as its resource.
///
/// The registry says which argument that is, so a call passing an expression rather than a
/// column answers `None` and the translation falls back to the schema.
fn role_threshold_resource_column(
    call: &Expr,
    function_name: &str,
    registry: &FunctionRegistry,
) -> Option<ColumnName> {
    let Some(FunctionSemantic::RoleThreshold {
        resource_param_index,
        ..
    }) = registry.get(function_name)
    else {
        return None;
    };
    let function = function_call(call)?;
    extract_column_name(positional_function_arg(function, *resource_param_index)?)
}

fn recognize_pg_has_role(expr: &Expr, registry: &FunctionRegistry) -> Option<ClassifiedExpr> {
    use sqlparser::ast::FunctionArguments;

    let Expr::Function(func) = expr else {
        return None;
    };
    if builtin_function_name(func).as_deref() != Some("pg_has_role") {
        return None;
    }
    let FunctionArguments::List(arg_list) = &func.args else {
        return None;
    };

    let args: Vec<&Expr> = arg_list.args.iter().filter_map(function_arg_expr).collect();

    // The implicit user of the two-argument form is `current_user`, not `session_user`:
    // probed under SET ROLE, where the two answer differently and the two-argument form
    // followed `current_user`.
    let (role_expr, privilege_expr) = match args.as_slice() {
        [user_expr, role_expr, privilege] if is_current_user_expr(user_expr, registry) => {
            (role_expr, privilege)
        }
        [role_expr, privilege] => (role_expr, privilege),
        _ => return None,
    };

    // The privilege decides which members the policy admits, so a privilege the crate cannot
    // read is refused rather than taken for plain membership. A dump deparses both literals
    // with casts, `'editor'::name` and `'MEMBER'::text`, which the reader peels.
    let privilege = RolePrivilege::parse(&string_literal(privilege_expr)?)?;
    let role_name = string_literal(role_expr)?;

    Some(ClassifiedExpr {
        pattern: PatternClass::P2RoleNameInList(RoleNameInList {
            resource_column: None,
            function_name: "pg_has_role".to_string(),
            role_names: vec![role_name],
            privilege,
        }),
        confidence: ConfidenceLevel::A,
    })
}

fn recognize_role_accessor_comparison(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let extract_role_func_name = |e: &Expr| -> Option<String> {
        let name = extract_function_name(e)?;
        if registry.is_role_accessor(&name) {
            Some(registry.resolved_name(&name))
        } else {
            None
        }
    };

    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    {
        let (func_name, literal_expr) = if let Some(name) = extract_role_func_name(left) {
            (name, right.as_ref())
        } else {
            let name = extract_role_func_name(right)?;
            (name, left.as_ref())
        };

        let role_name = string_literal(literal_expr)?;

        return Some(ClassifiedExpr {
            pattern: PatternClass::P2RoleNameInList(RoleNameInList {
                resource_column: None,
                function_name: func_name,
                role_names: vec![role_name],
                // A role accessor names the caller's role rather than asking about a kind of
                // membership in another one, so the widest kind is the faithful reading.
                privilege: RolePrivilege::Member,
            }),
            confidence: ConfidenceLevel::A,
        });
    }

    if let Some((inner, list)) = constant_in_list(expr) {
        let func_name = extract_role_func_name(inner)?;
        let role_names = extract_role_names_from_in_list(list, false)?;

        if role_names.is_empty() {
            return None;
        }

        return Some(ClassifiedExpr {
            pattern: PatternClass::P2RoleNameInList(RoleNameInList {
                resource_column: None,
                function_name: func_name,
                role_names,
                privilege: RolePrivilege::Member,
            }),
            confidence: ConfidenceLevel::A,
        });
    }

    None
}

/// Every element as a role literal, or `None` when any element is not one.
///
/// A non-literal element is a per-row grant the literals cannot stand in for, so
/// keeping only the literals would translate a subset of the policy and report it
/// as faithful.
fn extract_role_names_from_in_list(list: &[Expr], allow_numeric: bool) -> Option<Vec<String>> {
    list.iter()
        .map(|e| {
            // A dump deparses list elements with casts, which change no value here.
            if let Expr::Value(v) = unwrap_cast_or_nested(e) {
                return match &v.value {
                    Value::SingleQuotedString(s) => Some(s.clone()),
                    Value::Number(n, _) if allow_numeric => Some(n.clone()),
                    _ => None,
                };
            }
            None
        })
        .collect()
}

/// `x IN (a, b)` and its dumped spelling `x = ANY (ARRAY[a, b])`, one
/// expression with two spellings. Negated lists refuse elsewhere.
pub(super) fn constant_in_list(expr: &Expr) -> Option<(&Expr, &[Expr])> {
    match expr {
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated: false,
            global: false,
        } => Some((expr, list)),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            is_some: false,
        } => match unwrap_cast_or_nested(right) {
            Expr::Array(array) => Some((left, &array.elem)),
            _ => None,
        },
        _ => None,
    }
}

/// Direct ownership check.
pub fn recognize_p3<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let (left, right, null_safe) = match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => (left.as_ref(), right.as_ref(), false),
        Expr::IsNotDistinctFrom(left, right) => (left.as_ref(), right.as_ref(), true),
        _ => return None,
    };

    // Either operand may carry the accessor, and either may reach its column through a
    // COALESCE default, which `extract_column_name` alone does not see through.
    let (col_name, accessor_name, column_side, accessor_side) = if let (Some(col), Some(accessor)) =
        (extract_column_name(left), current_user_accessor_name(right))
    {
        (col, accessor, left, right)
    } else if let (Some(accessor), Some(col)) =
        (current_user_accessor_name(left), extract_column_name(right))
    {
        (col, accessor, right, left)
    } else if let (Some(col), Some(accessor)) = (
        extract_column_name_through_coalesce(left),
        current_user_accessor_name(right),
    ) {
        (col, accessor, left, right)
    } else if let (Some(accessor), Some(col)) = (
        current_user_accessor_name(left),
        extract_column_name_through_coalesce(right),
    ) {
        (col, accessor, right, left)
    } else {
        return None;
    };

    // Determine how we matched the accessor and assign confidence accordingly.
    let is_named = registry.is_current_user_accessor(&accessor_name)
        || reads_caller_setting_key(accessor_side, registry);
    let is_sql_keyword = is_sql_current_user_keyword_expr(accessor_side);

    // Guard against false positives like `owner_id = author_id`:
    // bare identifiers that are not SQL current-user keywords are columns/aliases,
    // not accessor expressions.
    if is_bare_identifier_expr(accessor_side) && !is_sql_keyword && !is_named {
        return None;
    }

    // Prevent false positives from user-defined function calls that only *look*
    // like SQL current-user keywords (e.g. `"current_user"()`, `x.current_user()`).
    if is_keyword_named_function_call_expr(accessor_side) && !is_sql_keyword && !is_named {
        return None;
    }

    // Strict policy: only SQL current-user keywords and accessors somebody named,
    // by function or by setting key, are eligible for P3.
    if !is_named && !is_sql_keyword {
        return None;
    }
    if null_safe && !is_sql_keyword {
        return None;
    }
    if caller_renaming_cast(accessor_side, &CastChain::default(), registry).is_some()
        || casts::row_renaming_cast(column_side).is_some()
    {
        return None;
    }

    let accessor_indirection =
        is_subquery_wrapped(accessor_side) || is_coalesce_wrapped(column_side);

    // Subquery- and COALESCE-wrapped accessors are accepted but capped at B due to added
    // indirection. This cap only applies after strict accessor validation above.
    if accessor_indirection {
        return Some(ClassifiedExpr {
            pattern: PatternClass::P3DirectOwnership(DirectOwnership { column: col_name }),
            confidence: ConfidenceLevel::B,
        });
    }

    // Registry-confirmed or SQL keyword without indirection: confidence A.
    Some(ClassifiedExpr {
        pattern: PatternClass::P3DirectOwnership(DirectOwnership { column: col_name }),
        confidence: ConfidenceLevel::A,
    })
}

/// Recognise "the caller is an element of an array column" in each spelling
/// `PostgreSQL` accepts: `caller = ANY (col)`, `col @> ARRAY[caller]`,
/// `ARRAY[caller] <@ col` and `ARRAY[caller] && col`.
///
/// Verified on `PostgreSQL` 18: the four agree on every row except an array holding
/// only NULL, where `= ANY` yields NULL and the others false. Both filter the row
/// out, so all four admit the same rows and translate alike.
pub fn recognize_array_patterns(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let column = array_membership_column(expr, registry)?;
    Some(ClassifiedExpr {
        pattern: PatternClass::P11ArrayMembership(ArrayMembership { column }),
        confidence: ConfidenceLevel::A,
    })
}

/// The array column whose elements the caller is tested against, if `expr` is one
/// of the four membership spellings.
///
/// The array side must resolve to a column: `= ANY (SELECT ...)` is membership
/// through a table, handled by the P4 recognizers, and treating its subquery as a
/// column would emit SQL naming a column that does not exist.
fn array_membership_column(expr: &Expr, registry: &FunctionRegistry) -> Option<ColumnName> {
    /// How the caller is written on its side of the operator.
    enum CallerForm {
        /// `= ANY` compares the caller itself.
        Direct,
        /// The containment and overlap spellings wrap it in a one-element array.
        Singleton,
    }

    let (form, caller_side, array_side) = match expr {
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => (CallerForm::Direct, left.as_ref(), right.as_ref()),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::AtArrow,
            right,
        } => (CallerForm::Singleton, right.as_ref(), left.as_ref()),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::ArrowAt,
            right,
        } => (CallerForm::Singleton, left.as_ref(), right.as_ref()),
        // `&&` is symmetric, so either side may hold the singleton.
        Expr::BinaryOp {
            left,
            op: BinaryOperator::PGOverlap,
            right,
        } => {
            if is_singleton_caller_element(left, registry) {
                (CallerForm::Singleton, left.as_ref(), right.as_ref())
            } else {
                (CallerForm::Singleton, right.as_ref(), left.as_ref())
            }
        }
        _ => return None,
    };

    let names_the_caller = match form {
        CallerForm::Direct => is_current_user_expr(caller_side, registry),
        CallerForm::Singleton => is_singleton_caller_element(caller_side, registry),
    };
    if !names_the_caller || casts::row_renaming_cast(array_side).is_some() {
        return None;
    }

    extract_column_name(unwrap_cast_or_nested(array_side))
}

/// Whether `expr` is a one-element array literal holding the caller, where a cast on the
/// array casts the caller too.
fn is_singleton_caller_element(expr: &Expr, registry: &FunctionRegistry) -> bool {
    let (array_casts, peeled) = CastChain::peeled(expr);
    let Expr::Array(array) = peeled else {
        return false;
    };
    let [only] = array.elem.as_slice() else {
        return false;
    };
    reads_the_caller(only, registry) && caller_renaming_cast(only, &array_casts, registry).is_none()
}

/// Recognise `data ->> 'owner' = caller`, the caller's identity stored in a jsonb
/// field, in either operand order and through casts.
///
/// Only a `->>` last hop qualifies: `->` yields `jsonb`, so `data -> 'owner'` compares
/// a JSON string (quotes included) rather than the text the caller is spelled with.
pub fn recognize_jsonb_field_ownership(
    expr: &Expr,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };

    let (row_side, caller_side) = if reads_the_caller(right, registry) {
        (left, right)
    } else if reads_the_caller(left, registry) {
        (right, left)
    } else {
        return None;
    };
    if !is_current_user_expr(caller_side, registry) || casts::row_renaming_cast(row_side).is_some()
    {
        return None;
    }
    let (column, path) = jsonb_text_path(row_side)?;

    Some(ClassifiedExpr {
        pattern: PatternClass::P12JsonbFieldOwnership(JsonbFieldOwnership { column, path }),
        confidence: ConfidenceLevel::A,
    })
}

/// The `(column, key chain)` of a jsonb text extraction, or `None` if `expr` is not one.
fn jsonb_text_path(expr: &Expr) -> Option<(ColumnName, Vec<String>)> {
    let (base, path) = json_text_path(expr)?;
    Some((extract_column_name(base)?, path))
}

/// Peel an arrow chain into the value it reads, the key chain, and whether the last hop
/// rendered text.
///
/// The one place an arrow chain is walked, so a rule about it cannot be applied by one
/// reader and dropped by another. The terminator is reported rather than fixed, because
/// the two readers need opposite ones: a value comparison needs `->>`, whose text form
/// is what a column holds, while expanding an array needs `->`, since `jsonb_array_elements_text`
/// takes jsonb and `PostgreSQL` refuses the text `->>` would hand it.
fn json_path(expr: &Expr) -> Option<(&Expr, Vec<String>, bool)> {
    let Expr::BinaryOp { left, op, right } = unwrap_cast_or_nested(expr) else {
        return None;
    };
    let rendered_text = match op {
        BinaryOperator::LongArrow => true,
        BinaryOperator::Arrow => false,
        _ => return None,
    };

    // A jsonb key is a string. An integer index addresses an array element, which names
    // no field, so a non-string key refuses the whole path.
    let mut path = vec![string_literal(right)?];
    let mut node = unwrap_cast_or_nested(left);
    // Walk the `->` hops leading up to the last one, innermost key last.
    while let Expr::BinaryOp {
        left: inner,
        op: BinaryOperator::Arrow,
        right: key,
    } = node
    {
        path.push(string_literal(key)?);
        node = unwrap_cast_or_nested(inner);
    }
    path.reverse();

    Some((node, path, rendered_text))
}

/// A chain ending in `->>`, whose value is text.
fn json_text_path(expr: &Expr) -> Option<(&Expr, Vec<String>)> {
    match json_path(expr)? {
        (node, path, true) => Some((node, path)),
        _ => None,
    }
}

/// A chain ending in `->`, whose value is still jsonb.
fn json_value_path(expr: &Expr) -> Option<(&Expr, Vec<String>)> {
    match json_path(expr)? {
        (node, path, false) => Some((node, path)),
        _ => None,
    }
}

pub(super) use crate::parser::expr::string_literal;

/// Constant boolean policy.
pub fn recognize_p10_constant_bool<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    _registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    constant_bool_value(expr).map(|value| ClassifiedExpr {
        pattern: PatternClass::P10ConstantBool(ConstantBool { value }),
        confidence: ConfidenceLevel::A,
    })
}

/// Boolean flag check.
pub fn recognize_p6<DB: DatabaseLike>(
    expr: &Expr,
    _db: &DB,
    registry: &FunctionRegistry,
) -> Option<ClassifiedExpr> {
    /// Pick confidence: A when the column is explicitly registered, B otherwise.
    ///
    /// Heuristic-only matches are capped at B because column names like `published`
    /// or `visible` commonly represent editorial state rather than access control;
    fn p6_confidence(col: &str, registry: &FunctionRegistry) -> ConfidenceLevel {
        if registry.is_confirmed_public_flag_column(col) {
            ConfidenceLevel::A
        } else {
            ConfidenceLevel::B
        }
    }

    if let Some((col_name, is_true)) = extract_boolean_column_equality(expr) {
        if is_true && is_public_flag_column_name(col_name.as_str()) {
            return Some(ClassifiedExpr {
                pattern: PatternClass::P6BooleanFlag(BooleanFlag {
                    column: col_name.clone(),
                    admits_null: false,
                }),
                confidence: p6_confidence(col_name.as_str(), registry),
            });
        }
        return None;
    }

    let (inner, admits_null) = match expr {
        Expr::IsTrue(inner) => (inner.as_ref(), false),
        Expr::IsNotFalse(inner) => (inner.as_ref(), true),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => (expr, false),
        _ => return None,
    };
    let col_name = extract_column_name(inner)?;
    if !is_public_flag_column_name(col_name.as_str()) {
        return None;
    }
    Some(ClassifiedExpr {
        pattern: PatternClass::P6BooleanFlag(BooleanFlag {
            column: col_name.clone(),
            admits_null,
        }),
        confidence: p6_confidence(col_name.as_str(), registry),
    })
}

/// Negated public-flag check: not expressible as static `OpenFGA` tuples.
pub fn is_negated_boolean_flag(expr: &Expr) -> Option<String> {
    if let Some((col_name, value)) = extract_boolean_column_equality(expr) {
        if !value && is_public_flag_column_name(col_name.as_str()) {
            return Some(col_name.to_string());
        }
        return None;
    }

    match expr {
        Expr::IsFalse(inner) | Expr::IsNotTrue(inner) => {
            let col_name = extract_column_name(inner)?;
            if is_public_flag_column_name(col_name.as_str()) {
                return Some(col_name.to_string());
            }
            None
        }
        _ => None,
    }
}

fn extract_boolean_column_equality(expr: &Expr) -> Option<(ColumnName, bool)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };

    if let (Some(col), Some(value)) = (extract_column_name(left), constant_bool_value(right)) {
        return Some((col, value));
    }
    if let (Some(value), Some(col)) = (constant_bool_value(left), extract_column_name(right)) {
        return Some((col, value));
    }

    None
}

pub(crate) fn constant_bool_value(expr: &Expr) -> Option<bool> {
    match unwrap_cast_or_nested(expr) {
        Expr::Value(v) => match &v.value {
            Value::Boolean(b) => Some(*b),
            _ => None,
        },
        // A negation is not a wrapper: it changes the answer, so it is read here.
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => constant_bool_value(inner).map(|value| !value),
        _ => None,
    }
}

/// Whether the clause filters every row out whatever the data holds.
///
/// A qual that is not true rejects the row, so a constant false admits nothing, an `AND`
/// admits nothing as soon as either side does, and an `OR` only when both do. Answered from
/// the expression rather than from its classification, since a pattern graded `no_access`
/// may equally be one the crate could not translate, which says nothing about the database.
pub(crate) fn is_constantly_false(expr: &Expr) -> bool {
    if constant_bool_value(expr) == Some(false) {
        return true;
    }
    match unparenthesize(expr) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => is_constantly_false(left) || is_constantly_false(right),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } => is_constantly_false(left) && is_constantly_false(right),
        _ => false,
    }
}

/// Function name called by `expr`, preserving qualification and quoting.
pub fn extract_function_name(expr: &Expr) -> Option<String> {
    function_call(expr).map(|function| function.name.to_string())
}

/// Normalized names of every function `expr` calls that does not identify the caller,
/// in source order, deduplicated.
///
/// Unlike [`extract_function_name`] this descends into operands and subqueries, so
/// it answers for diagnosis rather than recognition. Widening `extract_function_name`
/// instead would let P1 and P2 match a role function buried under an unrelated call.
/// The skip runs on the node so `is_current_user_expr` stays the only predicate that
/// decides what identifies the caller, keyword shape included. A constructor is not a
/// call either, so `ARRAY(subquery)` is left to [`subquery_set_constructors`].
pub(crate) fn called_function_names(expr: &Expr, registry: &FunctionRegistry) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if let Expr::Function(func) = node {
            if !is_current_user_expr(node, registry) && !takes_a_subquery(func) {
                let name = folded_function_name(func)
                    .unwrap_or_else(|| sql_traits::utils::last_str(&func.name).to_string());
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    names
}

/// Normalized names of every set constructor in `expr`, in source order, deduplicated.
///
/// `ARRAY(subquery)` parses as a function, so without this the blame names a registry
/// entry an operator cannot create.
pub(crate) fn subquery_set_constructors(expr: &Expr) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if let Expr::Function(func) = node {
            if takes_a_subquery(func) {
                let name = folded_function_name(func)
                    .unwrap_or_else(|| sql_traits::utils::last_str(&func.name).to_string());
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    names
}

/// Whether the node is a constructor spelled like a call. Under the `PostgreSQL` dialect
/// only `ARRAY(subquery)` parses this way, since a real call's arguments are a list, so
/// this never claims a user defined function that happens to be named `array`.
fn takes_a_subquery(func: &sqlparser::ast::Function) -> bool {
    matches!(func.args, FunctionArguments::Subquery(_))
}

/// Spellings of every operator in `expr` that no recognizer knows how to translate,
/// in source order, deduplicated.
///
/// A jsonb or array operator carries no function to blame, so without this the reason
/// names nothing at all. Comparison and boolean operators are omitted: a clause that
/// translates uses them too, so naming them would point at the wrong half.
pub(crate) fn unrecognized_operators(expr: &Expr) -> Vec<String> {
    let mut ops: Vec<String> = Vec::new();
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if let Expr::BinaryOp { op, .. } = node {
            if !operator_is_ordinary(op) {
                let spelling = op.to_string();
                if !ops.contains(&spelling) {
                    ops.push(spelling);
                }
            }
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    ops
}

/// Whether `op` is a comparison or boolean connective, which says nothing about why a
/// clause failed to translate.
fn operator_is_ordinary(op: &BinaryOperator) -> bool {
    matches!(
        op,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq
            | BinaryOperator::And
            | BinaryOperator::Or
    )
}

/// to a current-user expression.
///
/// Used by the P1/P2 recognizers to guard against false positives where a
/// role-threshold function is called with non-user arguments, e.g.
fn function_has_current_user_arg(expr: &Expr, registry: &FunctionRegistry) -> bool {
    use sqlparser::ast::FunctionArguments;
    let Expr::Function(func) = expr else {
        return false;
    };
    let FunctionArguments::List(arg_list) = &func.args else {
        return false;
    };
    arg_list
        .args
        .iter()
        .filter_map(function_arg_expr)
        .any(|e| is_current_user_expr(e, registry))
}

fn extract_integer_value(expr: &Expr) -> Option<i32> {
    match unwrap_cast_or_nested(expr) {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse().ok(),
            _ => None,
        },
        // A sign is not a wrapper: it decides the value, so both are read here.
        Expr::UnaryOp {
            op: UnaryOperator::Plus,
            expr: inner,
        } => extract_integer_value(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr: inner,
        } => extract_integer_value(inner).map(|value| -value),
        _ => None,
    }
}

/// Split a conjunction into its leaves, seeing through the parentheses `pg_dump`
/// writes around every conjunct it deparses.
fn flatten_and_predicates<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match unparenthesize(expr) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            flatten_and_predicates(left, out);
            flatten_and_predicates(right, out);
        }
        leaf => out.push(leaf),
    }
}

fn extract_qualified_column(expr: &Expr) -> Option<(Option<String>, ColumnName)> {
    match expr {
        Expr::Identifier(id) => Some((None, ColumnName::from_stored(stored_ident_name(id)))),
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [.., qualifier, last] => Some((
                Some(stored_ident_name(qualifier).into_owned()),
                ColumnName::from_stored(stored_ident_name(last)),
            )),
            _ => None,
        },
        _ => None,
    }
}

/// One read of a request value, with the node it bottoms out at, the field path taken out
/// of it, and the casts written around it.
///
/// One traversal, under parentheses, casts, a scalar subquery that is only its
/// projection, and an arrow chain, so the name, the setting key, the field path and the
/// casts an expression carries can never disagree about which read they describe.
pub(crate) struct AccessorRead<'e> {
    /// The accessor itself, a call, a keyword or a `current_setting`.
    pub(crate) root: &'e Expr,
    /// The field path taken out of the accessor's value, empty for the value itself.
    pub(crate) path: Vec<String>,
    /// Every cast between the accessor and the compared value, outermost first. The parse
    /// into `json` an arrow needs is structure and is left out.
    pub(crate) casts: CastChain,
}

/// The read `expr` makes, ending on `->>` or on no arrow at all.
pub(crate) fn accessor_read(expr: &Expr) -> Option<AccessorRead<'_>> {
    accessor_read_ending(expr, PathEnd::Text)
}

/// As [`accessor_read`], for a chain whose last hop is `->` and so is still jsonb.
/// Expanding a jsonb array needs that, since `->>` renders the array as text and
/// `PostgreSQL` refuses to expand text.
pub(crate) fn accessor_value_read(expr: &Expr) -> Option<AccessorRead<'_>> {
    accessor_read_ending(expr, PathEnd::JsonValue)
}

/// Which arrow the caller's read is allowed to end on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathEnd {
    /// `->>`, whose value is the text a column holds.
    Text,
    /// `->`, whose value is still jsonb.
    JsonValue,
}

fn accessor_read_ending(expr: &Expr, end: PathEnd) -> Option<AccessorRead<'_>> {
    let (mut casts, peeled) = CastChain::peeled(expr);
    let mut read = match peeled {
        // `(SELECT auth.uid())`, and only that: a subquery reading a table or carrying a
        // clause that can empty its result is a conjunct in disguise, and the pattern
        // keeps only a column name, so whatever it gates would vanish from the model.
        Expr::Subquery(query) => {
            let [SelectItem::UnnamedExpr(inner) | SelectItem::ExprWithAlias { expr: inner, .. }] =
                projected_select(query)?.projection.as_slice()
            else {
                return None;
            };
            accessor_read_ending(inner, end)?
        }
        other => {
            let hop = match end {
                PathEnd::Text => json_text_path(other),
                PathEnd::JsonValue => json_value_path(other),
            };
            match hop {
                // Every hop below the last is `->`, so the walk continues on that end.
                Some((base, mut path)) => {
                    let mut base = accessor_read_ending(base, PathEnd::JsonValue)?;
                    base.path.append(&mut path);
                    base.casts = base.casts.without_json_parse();
                    base
                }
                None => AccessorRead {
                    root: other,
                    path: Vec::new(),
                    casts: CastChain::default(),
                },
            }
        }
    };
    casts.extend(read.casts);
    read.casts = casts;
    Some(read)
}

/// The node an accessor expression bottoms out at, refusing a field taken out of it.
///
/// A field pulled out of the value is not the value: `sub` inside a token is an identity,
/// and so is `tenant`, and nothing in the expression says which of them the caller is.
/// Name a key holding the identity itself instead.
fn accessor_root(expr: &Expr) -> Option<&Expr> {
    accessor_read(expr)
        .filter(|read| read.path.is_empty())
        .map(|read| read.root)
}

fn current_user_accessor_name(expr: &Expr) -> Option<String> {
    match accessor_root(expr)? {
        Expr::Function(func) => Some(func.name.to_string()),
        Expr::Identifier(ident) => ident
            .quote_style
            .is_none()
            .then(|| ident.value.to_ascii_lowercase()),
        _ => None,
    }
}

/// Whether the accessor `expr` reads a `current_setting` key named as the caller.
fn reads_caller_setting_key(expr: &Expr, registry: &FunctionRegistry) -> bool {
    accessor_root(expr)
        .and_then(current_setting_literal_key)
        .is_some_and(|key| registry.names_caller_setting_key(&key))
}

/// The declared `CallerId` attribute `root` reads, when it is a `current_setting` key a
/// deployment declared as the caller.
fn caller_session_attribute<'r>(
    root: &Expr,
    registry: &'r FunctionRegistry,
) -> Option<&'r SessionAttribute> {
    let key = current_setting_literal_key(root)?;
    let attribute = registry.session_attribute(&key, &[])?;
    (attribute.kind() == SessionAttributeKind::CallerId).then_some(attribute)
}

/// The cast on `expr`'s read of the caller that can rename the caller, inside the casts
/// `outer` already found around it.
///
/// A cast is proven by the `identity_cast` of a declared caller key, or for an accessor
/// function by the type it returns, which a cast to that same type cannot change.
fn caller_renaming_cast(
    expr: &Expr,
    outer: &CastChain,
    registry: &FunctionRegistry,
) -> Option<String> {
    let read = accessor_read(expr)?;
    let declared = caller_session_attribute(read.root, registry)
        .and_then(SessionAttribute::identity_cast)
        .or_else(|| accessor_return_type(read.root, registry));
    outer
        .renaming(declared)
        .or_else(|| read.casts.renaming(declared))
        .map(str::to_string)
}

/// The type an accessor function the registry knows returns.
fn accessor_return_type<'r>(root: &Expr, registry: &'r FunctionRegistry) -> Option<&'r str> {
    let Expr::Function(function) = root else {
        return None;
    };
    match registry.get(&function.name.to_string())? {
        FunctionSemantic::CurrentUserAccessor { returns } => Some(returns.as_str()),
        _ => None,
    }
}

/// Returns `true` when `expr` (or its Cast/Nested wrapper) is a scalar subquery.
fn is_subquery_wrapped(expr: &Expr) -> bool {
    matches!(unwrap_cast_or_nested(expr), Expr::Subquery(_))
}

fn is_bare_identifier_expr(expr: &Expr) -> bool {
    matches!(
        unwrap_cast_or_nested(expr),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    )
}

/// Peel parentheses, which the parse has already resolved into tree shape and which
/// therefore say nothing about what an expression means. A cast is left in place: it
/// changes the value, and a leaf that reaches generated SQL has to keep it.
pub(crate) fn unparenthesize(mut expr: &Expr) -> &Expr {
    while let Expr::Nested(inner) = expr {
        expr = inner.as_ref();
    }
    expr
}
fn is_current_user_keyword(name: &str) -> bool {
    is_current_user_keyword_name(name)
}

fn is_sql_current_user_keyword_expr(expr: &Expr) -> bool {
    match accessor_root(expr) {
        Some(Expr::Identifier(ident)) => {
            ident.quote_style.is_none() && is_current_user_keyword(&ident.value)
        }
        Some(Expr::Function(func)) => {
            parse_target(&func.name.to_string()).is_some_and(|target| target.schema().is_none())
                && matches!(func.args, FunctionArguments::None)
                && folded_function_name(func)
                    .is_some_and(|name| is_current_user_keyword_name(&name))
        }
        _ => false,
    }
}

fn is_keyword_named_function_call_expr(expr: &Expr) -> bool {
    matches!(
        accessor_root(expr),
        Some(Expr::Function(func)) if folded_function_name(func)
            .is_some_and(|name| is_current_user_keyword_name(&name))
    )
}

/// `caller IS NOT NULL`, which says nothing a tuple does not already say.
///
/// A tuple exists only for a row that has an owner, and a caller with no identifier
/// matches none, so the check is already enforced by how tuples are produced. The same
/// test on a **row** column is a real filter and is not this: it decides which rows are
/// granted, so dropping it would grant rows the policy refuses.
pub fn is_redundant_caller_presence(expr: &Expr, registry: &FunctionRegistry) -> bool {
    match unparenthesize(expr) {
        Expr::IsNotNull(inner) => is_current_user_expr(inner, registry),
        _ => false,
    }
}

/// Whether `expr` is the caller, read so that the value compared is the value sent.
pub(crate) fn is_current_user_expr(expr: &Expr, registry: &FunctionRegistry) -> bool {
    reads_the_caller(expr, registry)
        && caller_renaming_cast(expr, &CastChain::default(), registry).is_none()
}

/// Whether `expr` reads the caller, whatever casts it is written under.
fn reads_the_caller(expr: &Expr, registry: &FunctionRegistry) -> bool {
    let Some(name) = current_user_accessor_name(expr) else {
        return false;
    };
    registry.is_current_user_accessor(&name)
        || reads_caller_setting_key(expr, registry)
        || (is_current_user_keyword(&name) && is_sql_current_user_keyword_expr(expr))
}

#[cfg(test)]
mod tests;
