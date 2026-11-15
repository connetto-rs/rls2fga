//! P26: the caller compared with an immutable function of one column of the row.

use sqlparser::ast::{FunctionArg, FunctionArgExpr, FunctionBehavior, Ident, ObjectName};

use super::*;
use crate::parser::names::stored_identifier;
use crate::parser::sql_parser::FunctionLike;

/// Recognise `f(owner) = caller` in either operand order, where every call `f(owner)` is
/// written with reaches only functions `PostgreSQL` declares `IMMUTABLE`.
///
/// An immutable function returns the same value for the same arguments wherever it runs,
/// so the tuple query computing it agrees with the policy on every row. A stable one may
/// answer differently in the caller's session, and a volatile one on every call.
pub fn recognize_owner_expression<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
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
        (left.as_ref(), right.as_ref())
    } else if reads_the_caller(left, registry) {
        (right.as_ref(), left.as_ref())
    } else {
        return None;
    };
    if !is_current_user_expr(caller_side, registry) {
        return None;
    }
    if !matches!(unparenthesize(row_side), Expr::Function(_)) {
        return None;
    }
    let mut column = None;
    let expression = immutable_row_expression(row_side, db, registry, &mut column)?;
    Some(ClassifiedExpr {
        pattern: PatternClass::P26OwnerExpression(OwnerExpression {
            column: column?,
            expression: expression.to_string(),
        }),
        confidence: ConfidenceLevel::B,
    })
}

/// `expr` as SQL over the bare row, or `None` where it is more than literals, one column of
/// the row, and calls of immutable functions over those.
///
/// Every call is rewritten to the schema of the functions it reaches, so the tuple query
/// reaches them whatever search path it runs under.
fn immutable_row_expression<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    column: &mut Option<ColumnName>,
) -> Option<Expr> {
    match expr {
        Expr::Nested(inner) => Some(Expr::Nested(Box::new(immutable_row_expression(
            inner, db, registry, column,
        )?))),
        Expr::Value(value) => matches!(
            value.value,
            Value::SingleQuotedString(_) | Value::Number(..) | Value::Boolean(_)
        )
        .then(|| expr.clone()),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
            if is_sql_current_user_keyword_expr(expr) {
                return None;
            }
            let read = extract_column_name(expr)?;
            if column.as_ref().is_some_and(|known| *known != read) {
                return None;
            }
            let quoted = Expr::Identifier(Ident::with_quote('"', read.as_str()));
            *column = Some(read);
            Some(quoted)
        }
        Expr::Function(function) => {
            if function.filter.is_some()
                || function.over.is_some()
                || function.null_treatment.is_some()
                || !function.within_group.is_empty()
                || !matches!(function.parameters, FunctionArguments::None)
                || registry.get(&function.name.to_string()).is_some()
            {
                return None;
            }
            let FunctionArguments::List(list) = &function.args else {
                return None;
            };
            if !list.clauses.is_empty() || list.duplicate_treatment.is_some() {
                return None;
            }
            let name = immutable_call_name(function, list.args.len(), db)?;
            let mut rewritten = function.clone();
            rewritten.name = name;
            let FunctionArguments::List(arguments) = &mut rewritten.args else {
                return None;
            };
            for argument in &mut arguments.args {
                let FunctionArg::Unnamed(FunctionArgExpr::Expr(value)) = argument else {
                    return None;
                };
                *value = immutable_row_expression(value, db, registry, column)?;
            }
            Some(Expr::Function(rewritten))
        }
        _ => None,
    }
}

/// `call`'s name qualified by the schema of every function it reaches with `arguments`
/// arguments, left unqualified where the schema leaves those functions on the search path.
///
/// `None` where the call reaches nothing the schema knows, reaches a function not declared
/// `IMMUTABLE`, or reaches functions of more than one schema, whose choice the search path
/// and the argument types would make.
fn immutable_call_name<DB: DatabaseLike>(
    call: &sqlparser::ast::Function,
    arguments: usize,
    db: &DB,
) -> Option<ObjectName> {
    let written_name = call.name.to_string();
    let written = parse_target(&written_name)?;
    let name = stored_identifier(written.name(), written.name_is_quoted());
    let written_schema = written
        .schema()
        .map(|schema| stored_identifier(schema, written.schema_is_quoted()));
    let mut reached: Vec<Option<String>> = Vec::new();
    for function in db.functions() {
        let declared = function.target_name();
        let declared_schema = declared
            .schema()
            .map(|schema| stored_identifier(schema, declared.schema_is_quoted()).into_owned());
        if function.stored_name() != name
            || written_schema
                .as_deref()
                .is_some_and(|schema| declared_schema.as_deref() != Some(schema))
            || !function.accepts_argument_count(arguments)
        {
            continue;
        }
        if function.volatility() != FunctionBehavior::Immutable {
            return None;
        }
        reached.push(declared_schema);
    }
    let (schema, rest) = reached.split_first()?;
    if rest.iter().any(|other| other != schema) {
        return None;
    }
    let name = Ident::with_quote('"', name);
    Some(ObjectName::from(match schema {
        Some(schema) => vec![Ident::with_quote('"', schema.as_str()), name],
        None => vec![name],
    }))
}
