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
    SelectItem, UnaryOperator, Value,
};

use crate::classifier::expansion::call_matches_declared;
use crate::classifier::function_registry::{DeclaredSource, FunctionRegistry};
use crate::classifier::patterns::*;
use crate::classifier::recognizers::session::{declared_scalar, grade};
use crate::classifier::recognizers::{projected_select, unparenthesize};
use crate::generator::db_lookup::single_identity_column;
use crate::parser::expr::CastChain;
use crate::parser::names::{lookup_table, stored_ident_name, stored_relation_name, table_identity};
use crate::parser::sql_parser::{
    CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike, GrantArm,
    GrantedTo, HelperArm, HelperSet, LiteralSet, ParentArm, SettingContent, SettingValue,
    TableLike,
};
use crate::types::ColumnName;
use sql_traits::errors::{HelperSetError, LookupError};

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
    /// The registry was not read for a deployment, so nothing says which setting is the
    /// caller.
    #[error("declared helper '{function}' is read without a deployment naming the caller")]
    NoDeployment {
        /// The helper.
        function: String,
    },
    /// A table or column of the answer cannot be looked up.
    #[error(transparent)]
    Lookup(#[from] LookupError),
    /// A column keys no one table's rows.
    #[error(
        "column '{column}' of '{table}' names no row of one table, since it is not the \
         table's key, its foreign keys do not reference one table's key, and nothing it is \
         compared with covers a single table"
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
    /// An arm returns the same rows whoever calls, which no grantee of the compared
    /// column stands for.
    #[error(
        "declared helper '{function}' returns the rows of '{table}' it keeps to every \
         request alike, and no grantee stands for every caller"
    )]
    SameForEveryRequest {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
    },
    /// A request value is compared with arms whose rows depend on the request.
    #[error(
        "declared helper '{function}' is compared with the request's value \
         '{setting}', so only arms returning the same rows to every request read, and \
         one of its arms is a parent, a walk or keeps its rows by what the request \
         carries"
    )]
    RequestDependentValues {
        /// The helper.
        function: String,
        /// The setting compared with the set.
        setting: String,
    },
    /// An arm compared with a request value keeps its rows by the statement time.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' it compares with a \
         request value by the statement time, which no request-value gate carries"
    )]
    TimeBoundedRequestValues {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
    },
    /// An arm keeps its rows only while a caller setting reads a value, a condition
    /// no grant relation carries.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' only while a caller \
         setting is set, which no grant relation carries"
    )]
    CallerGated {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
    },
    /// An arm keeps the rows naming a grantee another helper returns.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' naming a grantee \
         '{grantees}' returns, which no grant relation reads yet"
    )]
    GranteeSet {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The helper returning the grantees.
        grantees: String,
    },
}

/// Recognize `<column> = ANY (ARRAY(SELECT h(...)))`, `<column> = ANY (SELECT h(...))`
/// and `<column> IN (SELECT h(...))` for a declared helper `h`, and the same spellings
/// comparing a declared request value in place of the column.
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
    let (pattern, confidence) =
        if let Some(helper) = helper_compared_with(compared, query, db, registry, table) {
            (
                helper.map(PatternClass::P20DeclaredHelper),
                ConfidenceLevel::A,
            )
        } else {
            let (source, _) = declared_scalar(compared, registry)?;
            let (function, arguments, overloaded) = declared_call(query, db, registry)?;
            let pattern = if overloaded {
                Err(HelperRefusal::Overloaded {
                    function: function.target_name().to_string(),
                })
            } else {
                request_value_in_helper_set(function, arguments, source, db, registry)
            };
            (
                pattern.map(PatternClass::P27RequestValueInHelperSet),
                grade(source),
            )
        };
    Some(match pattern {
        Ok(pattern) => ClassifiedExpr {
            pattern,
            confidence,
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

/// Recognize the rows a declared helper `h` does not return, written
/// `NOT (<column> = ANY (ARRAY(SELECT h(...))))`, `<column> <> ALL (ARRAY(SELECT h(...)))`
/// or `<column> NOT IN (SELECT h(...))`, as the helper whose set they exclude.
///
/// `None` where the expression has another shape or calls an undeclared function.
pub(crate) fn recognize_excluded_helper<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
) -> Option<Result<DeclaredHelper, HelperRefusal>> {
    let (compared, query) = excluded_set_operands(expr)?;
    helper_compared_with(compared, query, db, registry, table)
}

/// The helper `query` calls compared with `compared`, `None` where `query` calls no
/// declared helper or `compared` is no column of `table`.
fn helper_compared_with<DB: DatabaseLike>(
    compared: &Expr,
    query: &Query,
    db: &DB,
    registry: &FunctionRegistry,
    table: &str,
) -> Option<Result<DeclaredHelper, HelperRefusal>> {
    let (function, arguments, overloaded) = declared_call(query, db, registry)?;
    let column = compared_column(compared, table)?;
    let guarded = lookup_table(db, table)?;
    let guarded_column = guarded
        .columns(db)
        .ok()?
        .find(|candidate| candidate.stored_column_name() == column.as_str())?;

    Some(if overloaded {
        Err(HelperRefusal::Overloaded {
            function: function.target_name().to_string(),
        })
    } else {
        declared_helper(
            function,
            arguments,
            column,
            guarded,
            guarded_column,
            db,
            registry,
        )
    })
}

/// The declared helper `query` calls with its arguments, and whether another declaration
/// takes the same number of them. `None` where `query` calls no declared helper.
fn declared_call<'query, 'db, DB: DatabaseLike>(
    query: &'query Query,
    db: &'db DB,
    registry: &FunctionRegistry,
) -> Option<(&'db DB::Function, &'query [FunctionArg], bool)> {
    let (call, arguments) = called_helper(query)?;
    let mut reached = db
        .functions()
        .filter(|declared| call_matches_declared(&call.name, *declared, db))
        .filter(|declared| declared.stored_argument_names(db).count() == arguments.len());
    let function = reached.next()?;
    if !registry.declares_helper(function) {
        return None;
    }
    Some((function, arguments, reached.next().is_some()))
}

/// The compared value and the query of the three spellings of set membership, the
/// classifier having already taken the parentheses around the whole off.
fn helper_set_operands(expr: &Expr) -> Option<(&Expr, &Query)> {
    match expr {
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
        } => Some((left, set_query(right)?)),
        _ => None,
    }
}

/// The compared value and the query of the three spellings of set exclusion, which
/// `PostgreSQL` evaluates alike, `NULL` included.
fn excluded_set_operands(expr: &Expr) -> Option<(&Expr, &Query)> {
    match expr {
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr,
        } => helper_set_operands(unparenthesize(expr)),
        Expr::In {
            expr: compared,
            target: InTarget::Subquery(query),
            negated: true,
            global: false,
        } => Some((compared, query)),
        Expr::AllOp {
            left,
            compare_op: BinaryOperator::NotEq,
            right,
        } => Some((left, set_query(right)?)),
        _ => None,
    }
}

/// The query a quantified comparison reads its set from, `(SELECT ...)` or
/// `ARRAY(SELECT ...)`.
fn set_query(set: &Expr) -> Option<&Query> {
    match set {
        Expr::Subquery(query) => Some(query),
        // Under the `PostgreSQL` dialect only the `ARRAY(subquery)` constructor parses as
        // a call taking a subquery.
        Expr::Function(array) => match &array.args {
            FunctionArguments::Subquery(query) => Some(query),
            _ => None,
        },
        _ => None,
    }
}

/// The one call `SELECT h(...)` makes and its arguments, reading no table and keeping
/// its one row.
fn called_helper(query: &Query) -> Option<(&sqlparser::ast::Function, &[FunctionArg])> {
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
    plain_call.then_some((call, list.args.as_slice()))
}

/// The guarded table's column the set is compared with, uncast.
fn compared_column(expr: &Expr, table: &str) -> Option<ColumnName> {
    let column = match expr {
        Expr::Nested(inner) => return compared_column(inner, table),
        Expr::Identifier(column) => column,
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [qualifier, column] if stored_ident_name(qualifier) == stored_relation_name(table) => {
                column
            }
            _ => return None,
        },
        _ => return None,
    };
    Some(ColumnName::from_stored(stored_ident_name(column)))
}

/// The value an argument passes, a literal under any parentheses and casts that render
/// it as text, which is how `pg_dump` spells `'read'` (`'read'::text`).
fn argument_value(argument: &FunctionArg) -> Option<&Value> {
    let FunctionArg::Unnamed(FunctionArgExpr::Expr(argument)) = argument else {
        return None;
    };
    match peeled_as_text(argument)? {
        Expr::Value(value) => Some(&value.value),
        _ => None,
    }
}

/// The pattern for one call of `function` compared with `column` of `guarded`.
fn declared_helper<DB: DatabaseLike>(
    function: &DB::Function,
    arguments: &[FunctionArg],
    column: ColumnName,
    guarded: &DB::Table,
    guarded_column: &DB::Column,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<DeclaredHelper, HelperRefusal> {
    let (values, set) = answered_call(function, arguments, db, registry)?;
    // A column with no foreign key, and not its table's key, names the rows of the one
    // table the set covers, as membership in a set of that table's keys types it.
    let named = match rows_named_by(guarded, guarded_column, db)? {
        Some(named) => named,
        None => set
            .covered_table()
            .map(table_identity)
            .ok_or_else(|| names_no_rows(guarded, guarded_column))?,
    };
    let call = helper_call(function, &values, &set, &column, &named, db, registry)?;
    Ok(DeclaredHelper { column, call })
}

/// The pattern for one call of `function` the request's value `source` is compared with.
fn request_value_in_helper_set<DB: DatabaseLike>(
    function: &DB::Function,
    arguments: &[FunctionArg],
    source: &DeclaredSource,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<RequestValueInHelperSet, HelperRefusal> {
    let (values, set) = answered_call(function, arguments, db, registry)?;
    let name = registry.resolved_target_name(&function.target_name());
    let mut arms = Vec::with_capacity(set.arms().len());
    for arm in set.arms() {
        // Only an arm returning the same rows to every request is a fact the loader
        // can state once.
        let grant = match arm {
            HelperArm::Grant(grant)
                if matches!(grant.granted_to(), GrantedTo::Anyone) && grant.gate().is_none() =>
            {
                grant
            }
            _ => {
                return Err(HelperRefusal::RequestDependentValues {
                    function: name,
                    setting: source.setting_key().to_string(),
                })
            }
        };
        bounded_by_no_time(&name, grant)?;
        arms.push(HelperValues {
            table: table_identity(grant.table()),
            value_column: ColumnName::from_stored(grant.column().stored_column_name()),
            predicates: grant.restrictions().iter().map(restriction).collect(),
        });
    }
    Ok(RequestValueInHelperSet {
        source: source.clone(),
        function: name,
        arguments: values.iter().map(ToString::to_string).collect(),
        arms,
    })
}

/// Refuses an arm keeping rows by the statement time, which no gate comparing a row's
/// value with the request carries.
fn bounded_by_no_time<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
) -> Result<(), HelperRefusal> {
    if grant.time_bounds().is_empty() {
        return Ok(());
    }
    Err(HelperRefusal::TimeBoundedRequestValues {
        function: function.to_string(),
        table: table_identity(grant.table()).to_string(),
    })
}

/// The literal arguments of one call of `function` and the set it returns for them.
fn answered_call<'db, DB: DatabaseLike>(
    function: &'db DB::Function,
    arguments: &[FunctionArg],
    db: &'db DB,
    registry: &'db FunctionRegistry,
) -> Result<(Vec<Value>, HelperSet<'db, DB>), HelperRefusal> {
    let name = function.target_name().to_string();
    let mut values = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let value = argument_value(argument).ok_or_else(|| HelperRefusal::NonLiteralArgument {
            function: name.clone(),
            argument: argument.to_string(),
        })?;
        values.push(value.clone());
    }
    let deployment = registry
        .deployment()
        .ok_or_else(|| HelperRefusal::NoDeployment {
            function: name.clone(),
        })?;
    let set = function
        .helper_set(&values, deployment, db)
        .map_err(|source| HelperRefusal::Unanswered {
            function: name,
            source,
        })?;
    Ok((values, set))
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
    let name = registry.resolved_target_name(&function.target_name());
    let mut arms = Vec::with_capacity(set.arms().len());
    for arm in set.arms() {
        let (returned, arm) = match arm {
            HelperArm::Grant(grant) => (
                rows_named_by(grant.table(), grant.column(), db)?
                    .ok_or_else(|| names_no_rows(grant.table(), grant.column()))?,
                HelperSetArm::Grant(helper_grant(&name, grant, db)?),
            ),
            HelperArm::Parent(parent) => (
                table_identity(parent.table()),
                HelperSetArm::Parent(helper_parent(&name, parent, db, registry)?),
            ),
            HelperArm::Walk(walk) => (
                table_identity(walk.table()),
                HelperSetArm::Walk(HelperWalk {
                    fk_column: ColumnName::from_stored(walk.column().stored_column_name()),
                }),
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
    let fk_column = ColumnName::from_stored(parent.column().stored_column_name());
    // Without a foreign key the parent is the table the called set covers.
    let referenced = rows_named_by(parent.table(), parent.column(), db)?
        .unwrap_or_else(|| table_identity(parent.parent_table()));
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
    let refused_table = || table_identity(table).to_string();
    if grant.gate().is_some() {
        return Err(HelperRefusal::CallerGated {
            function: function.to_string(),
            table: refused_table(),
        });
    }
    let compared = match grant.granted_to() {
        GrantedTo::Request(compared) => compared,
        GrantedTo::Anyone => {
            return Err(HelperRefusal::SameForEveryRequest {
                function: function.to_string(),
                table: refused_table(),
            })
        }
        GrantedTo::Set(set) => {
            return Err(HelperRefusal::GranteeSet {
                function: function.to_string(),
                table: refused_table(),
                grantees: set.function().target_name().to_string(),
            })
        }
    };
    let column = ColumnName::from_stored(compared.column().stored_column_name());
    // `sql-traits` compares a column with the caller or with the elements of a whole
    // setting declared as a set.
    let grantee = match compared.setting().content() {
        SettingContent::Value(value @ SettingValue::Set { .. }) => {
            bounded_by_no_time(function, grant)?;
            HelperGrantee::RequestSet {
                value_column: column,
                source: DeclaredSource::whole(compared.setting(), value.clone()),
            }
        }
        _ => HelperGrantee::Caller {
            user_column: column,
        },
    };
    Ok(HelperGrant {
        table: table_identity(table),
        object_column: ColumnName::from_stored(grant.column().stored_column_name()),
        grantee,
        rows: grant_rows(table, grant.restrictions(), db)?,
    })
}

/// The rows `restrictions` keep of `table`, split by its role column where it has one.
fn grant_rows<DB: DatabaseLike>(
    table: &DB::Table,
    restrictions: &[LiteralSet<'_, DB>],
    db: &DB,
) -> Result<GrantRows, HelperRefusal> {
    let (role_column, mut roles) = split_column(table, db)?.unzip();
    let mut predicates = Vec::with_capacity(restrictions.len());
    for kept in restrictions {
        let kept = restriction(kept);
        match (&mut roles, &kept.test) {
            (Some(roles), AttributeTest::In(values))
                if role_column.as_ref() == Some(&kept.column) =>
            {
                roles.retain(|role| values.iter().any(|value| same_literal(value, role)));
            }
            _ => predicates.push(kept),
        }
    }
    Ok(match (role_column, roles) {
        (Some(column), Some(values)) => GrantRows::Roles {
            column,
            values,
            predicates,
        },
        _ => GrantRows::Matching { predicates },
    })
}

/// `<column> IN (<values>)`, the values one restriction keeps.
///
/// `sql-traits` keeps only the literal kinds [`literal`] reads, and a value it ever
/// kept otherwise is dropped, which narrows, since the relations load no row for an
/// empty list.
fn restriction<DB: DatabaseLike>(kept: &LiteralSet<'_, DB>) -> AttributePredicate {
    AttributePredicate {
        column: ColumnName::from_stored(kept.column().stored_column_name()),
        test: AttributeTest::In(kept.values().iter().filter_map(literal).collect()),
    }
}

/// The table whose rows the values of `column` name, which are the rows its one
/// single-column foreign key references, else its own table's where it is that table's
/// key, and `None` where it is neither.
fn rows_named_by<DB: DatabaseLike>(
    table: &DB::Table,
    column: &DB::Column,
    db: &DB,
) -> Result<Option<TableId>, HelperRefusal> {
    let mut referenced: Option<TableId> = None;
    for foreign_key in table.foreign_keys(db)? {
        let mut host = foreign_key.host_columns(db)?;
        if !(host.next().is_some_and(|host| core::ptr::eq(host, column)) && host.next().is_none()) {
            continue;
        }
        let parent = table_identity(foreign_key.referenced_table(db)?);
        let names_key = foreign_key
            .referenced_columns(db)?
            .map(|column| ColumnName::from_stored(column.stored_column_name()))
            .eq(single_identity_column(&parent, db));
        // Two keys referencing different tables leave the rows the value names open.
        if !names_key || referenced.as_ref().is_some_and(|held| *held != parent) {
            return Err(names_no_rows(table, column));
        }
        referenced = Some(parent);
    }
    if referenced.is_some() {
        return Ok(referenced);
    }
    let own = table_identity(table);
    let is_key = single_identity_column(&own, db)
        .is_some_and(|key| key.as_str() == column.stored_column_name());
    Ok(is_key.then_some(own))
}

fn names_no_rows<T: TableLike, C: ColumnLike>(table: &T, column: &C) -> HelperRefusal {
    HelperRefusal::NamesNoRows {
        table: table_identity(table).to_string(),
        column: column.stored_column_name().into_owned(),
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
    match peeled_as_text(tested)? {
        Expr::Identifier(tested) if stored_ident_name(tested) == column => {}
        _ => return None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use crate::parser::sql_parser::parse_schema;

    /// A registry nobody read for a deployment cannot say which setting is the caller, so
    /// a declared helper it meets is refused naming that, rather than answered against
    /// settings nobody declared.
    #[test]
    fn a_helper_read_without_a_deployment_is_refused() {
        let db = parse_schema(
            "CREATE TABLE projects (id UUID PRIMARY KEY);
             CREATE TABLE tasks (id UUID PRIMARY KEY, project_id UUID);
             CREATE FUNCTION projects_with(level TEXT) RETURNS SETOF UUID
                 LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
                 AS 'SELECT id FROM projects';",
        )
        .expect("the schema parses");
        let mut registry = FunctionRegistry::new();
        registry.declare_helpers(["projects_with"]);
        let expr = parse_expr("project_id IN (SELECT projects_with('read'))");

        let classified = recognize_declared_helper(&expr, &db, &registry, "tasks")
            .expect("the call is a declared helper's");
        assert_eq!(
            classified.pattern,
            PatternClass::Unknown(UnclassifiedExpr {
                sql_text: expr.to_string(),
                reason: "declared helper 'projects_with' is read without a deployment naming \
                         the caller"
                    .to_string(),
            })
        );
    }
}
