//! P20, a column compared with the set a declared `SECURITY DEFINER` helper returns.
//!
//! The helper reads as its owner, so the rows it returns are facts the tuple loader reads
//! the same way. `sql-traits` answers what the body returns, and this module checks that
//! every key it returns names a row of one table, which is what lets the set become
//! relations on that table's type.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, InTarget, Query,
    SelectItem, Value,
};

use crate::classifier::expansion::call_matches_declared;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::*;
use crate::classifier::recognizers::projected_select;
use crate::generator::db_lookup::single_identity_column;
use crate::parser::expr::CastChain;
use crate::parser::names::{lookup_table, stored_ident_name, stored_relation_name, table_identity};
use crate::parser::sql_parser::{
    CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, GrantArm,
    HelperArm, HelperSet, LiteralSet, ParentArm, TableLike,
};
use crate::types::ColumnName;
use sql_traits::errors::{DeploymentError, HelperSetError, LookupError};

/// Why a call to a declared helper does not translate.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HelperRefusal {
    /// `sql-traits` cannot say what the helper returns.
    #[error("declared helper '{function}' does not translate, because {source}")]
    Unanswered {
        /// The helper the policy calls.
        function: String,
        /// Why the answer was refused.
        #[source]
        source: HelperSetError,
    },
    /// A helper the body calls was never declared.
    #[error(
        "declared helper '{function}' reads '{called}' through a parent arm, and '{called}' \
         is not declared"
    )]
    UndeclaredCallee {
        /// The helper whose body calls it.
        function: String,
        /// The helper called.
        called: String,
    },
    /// Several declarations take as many arguments as the call passes, so which one runs
    /// depends on argument types this reading does not infer.
    #[error(
        "more than one declaration of '{function}' takes this call's arguments, so which \
         body runs cannot be known"
    )]
    Overloaded {
        /// The helper.
        function: String,
    },
    /// The policy passes the helper something other than a literal.
    #[error("declared helper '{function}' is passed '{argument}', which is not a literal")]
    NonLiteralArgument {
        /// The helper.
        function: String,
        /// The argument as written.
        argument: String,
    },
    /// The deployment's settings cannot be described to `sql-traits`.
    #[error("the declared request settings cannot describe the caller, because {0}")]
    Deployment(#[from] DeploymentError),
    /// A table or column of the answer cannot be looked up.
    #[error(transparent)]
    Lookup(#[from] LookupError),
    /// A returned column keys no table's rows.
    #[error(
        "column '{column}' of '{table}' names no row of a table, since it is neither the \
         table's key nor a single-column foreign key to another table's key"
    )]
    NamesNoRows {
        /// The table.
        table: String,
        /// The column.
        column: String,
    },
    /// The compared column names other rows than the helper returns.
    #[error(
        "column '{column}' names rows of '{named}', while declared helper '{function}' \
         returns keys of '{level}'"
    )]
    OtherLevel {
        /// The compared column.
        column: String,
        /// The table its values name.
        named: String,
        /// The helper.
        function: String,
        /// The table the helper returns keys of.
        level: String,
    },
    /// A value the body keeps is no literal a relation can be named for.
    #[error("declared helper '{function}' keeps the value {value}, which no relation can name")]
    UnnamedValue {
        /// The helper.
        function: String,
        /// The value, as SQL spells it.
        value: String,
    },
}

/// Recognize `<column> = ANY (ARRAY(SELECT h(...)))`, `<column> = ANY (SELECT h(...))`
/// and `<column> IN (SELECT h(...))` for a declared helper `h`.
///
/// `None` where the expression has another shape or calls an undeclared function, so
/// today's handling stands.
pub(crate) fn recognize_declared_helper<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
) -> Option<ClassifiedExpr> {
    let (compared, query) = helper_set_operands(expr)?;
    let call = called_helper(query)?;
    let FunctionArguments::List(list) = &call.args else {
        return None;
    };
    let mut reached = db
        .functions()
        .filter(|declared| call_matches_declared(&call.name, *declared, db))
        .filter(|declared| declared.stored_argument_names(db).count() == list.args.len());
    let function = reached.next()?;
    if !registry.declares_helper(function) {
        return None;
    }
    let column = compared_column(compared, table)?;
    let guarded = lookup_table(db, table)?;

    let pattern = if reached.next().is_some() {
        Err(HelperRefusal::Overloaded {
            function: function.target_name().to_string(),
        })
    } else {
        declared_helper(function, &list.args, column, guarded, db, registry)
    };
    Some(match pattern {
        Ok(helper) => ClassifiedExpr {
            pattern: PatternClass::P20DeclaredHelper(helper),
            confidence: ConfidenceLevel::A,
        },
        Err(refusal) => ClassifiedExpr {
            pattern: PatternClass::Unknown(UnclassifiedExpr {
                sql_text: expr.to_string(),
                reason: refusal.to_string(),
            }),
            confidence: ConfidenceLevel::D,
        },
    })
}

/// The compared value and the query of the three spellings of set membership.
fn helper_set_operands(expr: &Expr) -> Option<(&Expr, &Query)> {
    match expr {
        Expr::Nested(inner) => helper_set_operands(inner),
        Expr::In {
            expr: compared,
            target: InTarget::Subquery(query),
            negated: false,
            global: false,
        } => Some((compared, query)),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match right.as_ref() {
            Expr::Subquery(query) => Some((left, query)),
            // Under the `PostgreSQL` dialect only the `ARRAY(subquery)` constructor parses
            // as a call taking a subquery.
            Expr::Function(array) => match &array.args {
                FunctionArguments::Subquery(query) => Some((left, query)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// The one call `SELECT h(...)` makes, reading no table and keeping its one row.
fn called_helper(query: &Query) -> Option<&sqlparser::ast::Function> {
    let select = projected_select(query)?;
    let [SelectItem::UnnamedExpr(Expr::Function(call))
    | SelectItem::ExprWithAlias {
        expr: Expr::Function(call),
        ..
    }] = select.projection.as_slice()
    else {
        return None;
    };
    let FunctionArguments::List(list) = &call.args else {
        return None;
    };
    let plain_call = call.over.is_none()
        && call.filter.is_none()
        && call.null_treatment.is_none()
        && call.within_group.is_empty()
        && matches!(call.parameters, FunctionArguments::None)
        && list.duplicate_treatment.is_none()
        && list.clauses.is_empty();
    plain_call.then_some(call)
}

/// The guarded table's column the set is compared with, uncast.
fn compared_column(expr: &Expr, table: &str) -> Option<ColumnName> {
    let column = match expr {
        Expr::Nested(inner) => return compared_column(inner, table),
        Expr::Identifier(column) => column,
        Expr::CompoundIdentifier(parts) => {
            let [qualifier, column] = parts.as_slice() else {
                return None;
            };
            if stored_ident_name(qualifier) != stored_relation_name(table) {
                return None;
            }
            column
        }
        _ => return None,
    };
    Some(ColumnName::from_stored(stored_ident_name(column)))
}

/// The pattern for one call of `function` compared with `column` of `guarded`.
fn declared_helper<DB: DatabaseLike>(
    function: &DB::Function,
    arguments: &[FunctionArg],
    column: ColumnName,
    guarded: &DB::Table,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<DeclaredHelper, HelperRefusal> {
    let name = function.target_name().to_string();
    let mut values = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value))) = argument else {
            return Err(HelperRefusal::NonLiteralArgument {
                function: name,
                argument: argument.to_string(),
            });
        };
        values.push(value.value.clone());
    }
    let deployment = registry.helper_deployment()?;
    let set = function
        .helper_set(&values, &deployment, db)
        .map_err(|source| HelperRefusal::Unanswered {
            function: name.clone(),
            source,
        })?;

    let guarded_column = guarded
        .columns(db)?
        .find(|candidate| candidate.stored_column_name() == column.as_str())
        .ok_or_else(|| HelperRefusal::NamesNoRows {
            table: table_identity(guarded).to_string(),
            column: column.to_string(),
        })?;
    let named = rows_named_by(guarded, guarded_column, db)?;
    let call = helper_call(function, &values, &set, &column, &named, db, registry)?;
    Ok(DeclaredHelper { column, call })
}

/// One call and what it returns, refused unless every arm returns keys of `level`, the
/// table whose rows `compared` names.
fn helper_call<DB: DatabaseLike>(
    function: &DB::Function,
    arguments: &[Value],
    set: &HelperSet<'_, DB>,
    compared: &ColumnName,
    level: &TableId,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<HelperCall, HelperRefusal> {
    let name = function.target_name().to_string();
    let mut arms = Vec::with_capacity(set.arms().len());
    for arm in set.arms() {
        let (returned, arm) = match arm {
            HelperArm::Grant(grant) => (
                rows_named_by(grant.table(), grant.column(), db)?,
                HelperSetArm::Grant(helper_grant(&name, grant, db)?),
            ),
            HelperArm::Parent(parent) => (
                table_identity(parent.table()),
                HelperSetArm::Parent(helper_parent(&name, parent, db, registry)?),
            ),
        };
        if returned != *level {
            return Err(HelperRefusal::OtherLevel {
                column: compared.to_string(),
                named: level.to_string(),
                function: name,
                level: returned.to_string(),
            });
        }
        arms.push(arm);
    }
    Ok(HelperCall {
        function: name,
        arguments: arguments.iter().map(ToString::to_string).collect(),
        level: level.clone(),
        arms,
    })
}

fn helper_parent<DB: DatabaseLike>(
    function: &str,
    parent: &ParentArm<'_, DB>,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<HelperParent, HelperRefusal> {
    let called = parent.function();
    if !registry.declares_helper(called) {
        return Err(HelperRefusal::UndeclaredCallee {
            function: function.to_string(),
            called: called.target_name().to_string(),
        });
    }
    let fk_column = ColumnName::from_stored(parent.foreign_key_column().stored_column_name());
    let referenced = rows_named_by(parent.table(), parent.foreign_key_column(), db)?;
    let call = helper_call(
        called,
        parent.arguments(),
        parent.set(),
        &fk_column,
        &referenced,
        db,
        registry,
    )?;
    Ok(HelperParent { fk_column, call })
}

fn helper_grant<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
    db: &DB,
) -> Result<HelperGrant, HelperRefusal> {
    let table = grant.table();
    let split = split_column(table, db)?;
    let rows = match (grant.restriction(), split) {
        (None, Some((column, domain))) => GrantRows::Roles {
            column,
            values: domain,
        },
        (None, None) => GrantRows::Matching { predicate: None },
        (Some(kept), Some((column, domain)))
            if kept.column().stored_column_name() == column.as_str() =>
        {
            let values = kept_literals(function, kept)?;
            GrantRows::Roles {
                column,
                values: domain
                    .into_iter()
                    .filter(|value| values.iter().any(|kept| same_literal(kept, value)))
                    .collect(),
            }
        }
        (Some(kept), _) => GrantRows::Matching {
            predicate: Some(AttributePredicate {
                column: ColumnName::from_stored(kept.column().stored_column_name()),
                test: AttributeTest::In(kept_literals(function, kept)?),
            }),
        },
    };
    Ok(HelperGrant {
        table: table_identity(table),
        object_column: ColumnName::from_stored(grant.column().stored_column_name()),
        user_column: ColumnName::from_stored(grant.caller_column().stored_column_name()),
        rows,
    })
}

fn kept_literals<DB: DatabaseLike>(
    function: &str,
    kept: &LiteralSet<'_, DB>,
) -> Result<Vec<AttributeLiteral>, HelperRefusal> {
    kept.values()
        .iter()
        .map(|value| {
            literal(value).ok_or_else(|| HelperRefusal::UnnamedValue {
                function: function.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

/// The table whose rows the values of `column` name, which are the rows its one
/// single-column foreign key references, else its own table's where it is that table's
/// key.
fn rows_named_by<DB: DatabaseLike>(
    table: &DB::Table,
    column: &DB::Column,
    db: &DB,
) -> Result<TableId, HelperRefusal> {
    let names_no_rows = || HelperRefusal::NamesNoRows {
        table: table_identity(table).to_string(),
        column: column.stored_column_name().into_owned(),
    };
    let mut single_column_keys = Vec::new();
    for foreign_key in table.foreign_keys(db)? {
        let mut host = foreign_key.host_columns(db)?;
        if host.next().is_some_and(|host| core::ptr::eq(host, column)) && host.next().is_none() {
            single_column_keys.push(foreign_key);
        }
    }
    match single_column_keys.as_slice() {
        [foreign_key] => {
            let referenced = table_identity(foreign_key.referenced_table(db)?);
            let names_key = foreign_key
                .referenced_columns(db)?
                .map(|column| ColumnName::from_stored(column.stored_column_name()))
                .eq(single_identity_column(&referenced, db));
            names_key.then_some(referenced).ok_or_else(names_no_rows)
        }
        [] => {
            let own = table_identity(table);
            let is_key = single_identity_column(&own, db)
                .is_some_and(|key| key.as_str() == column.stored_column_name());
            is_key.then_some(own).ok_or_else(names_no_rows)
        }
        _ => Err(names_no_rows()),
    }
}

/// The one column of `table` both `NOT NULL` and closed by a validated `CHECK` to
/// literals, with the literals in the order the check lists them.
///
/// A grant table's role column is that column, so every role is a relation and a grant
/// row one tuple. None where no column or several qualify.
fn split_column<DB: DatabaseLike>(
    table: &DB::Table,
    db: &DB,
) -> Result<Option<(ColumnName, Vec<AttributeLiteral>)>, HelperRefusal> {
    let mut found = None;
    for column in table.columns(db)? {
        if column.is_nullable(db)? {
            continue;
        }
        let name = column.stored_column_name();
        let mut domain = None;
        for check in column.check_constraints(db)? {
            if !check.is_validated(db)? {
                continue;
            }
            if let Some(values) = closed_domain(check.expression(db), &name) {
                domain = Some(values);
                break;
            }
        }
        let Some(domain) = domain else {
            continue;
        };
        if found.is_some() {
            return Ok(None);
        }
        found = Some((ColumnName::from_stored(name), domain));
    }
    Ok(found)
}

/// The literals `check` restricts `column` to, written `column IN (...)` or as
/// `PostgreSQL` dumps it, `column = ANY (ARRAY[...])`.
fn closed_domain(check: &Expr, column: &str) -> Option<Vec<AttributeLiteral>> {
    let (tested, listed): (&Expr, Vec<&Expr>) = match peeled_as_text(check)? {
        Expr::In {
            expr,
            target: InTarget::List(list),
            negated: false,
            global: false,
        } => (expr, list.iter().collect()),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match peeled_as_text(right)? {
            Expr::Array(array) => (left, array.elem.iter().collect()),
            _ => return None,
        },
        _ => return None,
    };
    let Expr::Identifier(tested) = peeled_as_text(tested)? else {
        return None;
    };
    if stored_ident_name(tested) != column {
        return None;
    }
    let mut values: Vec<AttributeLiteral> = Vec::with_capacity(listed.len());
    for element in listed {
        let Expr::Value(value) = peeled_as_text(element)? else {
            return None;
        };
        let value = literal(&value.value)?;
        if !values.iter().any(|held| same_literal(held, &value)) {
            values.push(value);
        }
    }
    (!values.is_empty()).then_some(values)
}

/// `expr` without the parentheses and casts around it, `None` where a cast can rename
/// the value, since only a cast rendering it as unbounded text changes nothing.
fn peeled_as_text(expr: &Expr) -> Option<&Expr> {
    let (casts, inner) = CastChain::peeled(expr);
    casts.renaming(None).is_none().then_some(inner)
}

fn literal(value: &Value) -> Option<AttributeLiteral> {
    match value {
        Value::SingleQuotedString(text) => Some(AttributeLiteral::Text(text.clone())),
        Value::DollarQuotedString(text) => Some(AttributeLiteral::Text(text.value.clone())),
        Value::Number(number, false) => Some(AttributeLiteral::Number(number.clone())),
        Value::Boolean(flag) => Some(AttributeLiteral::Boolean(*flag)),
        _ => None,
    }
}

/// Whether two literals compare equal, a number by value where it is an integer.
fn same_literal(left: &AttributeLiteral, right: &AttributeLiteral) -> bool {
    match (left, right) {
        (AttributeLiteral::Number(left), AttributeLiteral::Number(right)) => {
            left == right
                || matches!(
                    (left.parse::<i128>(), right.parse::<i128>()),
                    (Ok(left), Ok(right)) if left == right
                )
        }
        _ => left == right,
    }
}
