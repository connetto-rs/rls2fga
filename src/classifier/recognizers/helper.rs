//! P20, a column compared with the set a declared `SECURITY DEFINER` helper returns.
//!
//! The helper reads as its owner, so the rows it returns are facts the tuple loader reads
//! the same way. `sql-traits` answers what the body returns, and this module checks that
//! every key it returns names a row of one table, which is what lets the set become
//! relations on that table's type.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use sqlparser::ast::{
    BinaryOperator, DataType, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Ident,
    InTarget, ObjectName, Query, Select, SelectItem, TableAlias, TableFactor, TableFunctionArgs,
    TableWithJoins, UnaryOperator, Value,
};

use crate::classifier::expansion::call_matches_declared;
use crate::classifier::function_registry::{DeclaredSource, FunctionRegistry};
use crate::classifier::patterns::*;
use crate::classifier::recognizers::session::{declared_scalar, grade};
use crate::classifier::recognizers::subquery::{
    query_select, select_result_shaping_clause, set_limiting_clause,
};
use crate::classifier::recognizers::{projected_select, unparenthesize};
use crate::clock::{ClockOffset, ClockReading, ClockThreshold};
use crate::generator::db_lookup::{row_uniquely_keys, single_identity_column};
use crate::generator::model_bounds::MAX_CONDITIONS;
use crate::parser::expr::CastChain;
use crate::parser::names::{
    lookup_table, lookup_table_id, stored_ident_name, stored_relation_name, table_identity,
};
use crate::parser::sql_parser::{
    CallerGate, CheckConstraintLike, ColumnLike, DatabaseLike, ForeignKeyLike, FunctionLike,
    GrantArm, GrantedTo, HelperArm, HelperSet, ParentArm, Restriction, SettingContent,
    SettingPresence, SettingValue, TableLike, TimeBound, TimeComparison,
};
use crate::types::{ColumnName, TypeName};
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
    #[error("declared helper '{function}' calls '{called}', which is not declared")]
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
    /// A gate on a caller the deployment lets go unset keeps rows for a request no
    /// subject names apart from a caller's.
    #[error(
        "declared helper '{function}' tests whether setting '{setting}' holds a caller, \
         which the deployment lets a request leave unset, so no subject names such a request"
    )]
    GateOnUnsetCaller {
        /// The helper.
        function: String,
        /// The caller setting.
        setting: String,
    },
    /// A gate excludes a caller spelled otherwise than the identity a check sends.
    #[error(
        "declared helper '{function}' excludes the caller {value}, which is not spelled as \
         the identity a check sends"
    )]
    UnnamedCaller {
        /// The helper.
        function: String,
        /// The excluded value as written.
        value: String,
    },
    /// A gate excludes callers from rows admitting whoever presents a value of a set
    /// the request carries.
    #[error(
        "declared helper '{function}' excludes callers from rows a set the request \
         carries admits"
    )]
    ExcludedFromRequestSet {
        /// The helper.
        function: String,
    },
    /// A gate excludes callers from rows admitting whoever acts for a principal they name.
    #[error(
        "declared helper '{function}' excludes callers from rows naming the {kind} the \
         request acts for"
    )]
    ExcludedFromPrincipal {
        /// The helper.
        function: String,
        /// The type of the principal the rows name.
        kind: String,
    },
    /// An arm names a principal whose type no `OpenFGA` type name spells.
    #[error(
        "declared helper '{function}' keeps rows naming a principal of type '{kind}', \
         which no type name spells"
    )]
    UnspellablePrincipalType {
        /// The helper.
        function: String,
        /// The principal's type, as the deployment declares it.
        kind: String,
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
    /// An arm naming a set of grantees or everyone keeps its rows by the statement time.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' naming a set of grantees \
         or everyone by the statement time, which those grants do not carry"
    )]
    TimeBoundedGrantees {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
    },
    /// A grant arm bounds its rows against the clock more than once, while several of
    /// its rows can grant one caller one row, so no one tuple carries the bounds of the
    /// row that meets them all.
    #[error(
        "grant table '{table}' can hold several rows granting one caller the same row, \
         and several clock bounds cannot be compressed into one fact without mixing rows"
    )]
    MixedTimeBounds {
        /// The grant table.
        table: String,
    },
    /// Each bound keeping `NULL` doubles the ways a row meets the arm's bounds, each a
    /// condition of its own, and the arm needs more than an `OpenFGA` model admits.
    #[error(
        "grant table '{table}' keeps NULL in {bounds} clock bounds, which takes more than \
         the {MAX_CONDITIONS} conditions an OpenFGA model admits"
    )]
    TooManyNullBounds {
        /// The grant table.
        table: String,
        /// The bounds keeping `NULL`.
        bounds: usize,
    },
    /// A grant arm returns several columns, which no one relation names.
    #[error(
        "declared helper '{function}' returns {columns} columns of '{table}' from one arm, \
         while a relation names one"
    )]
    SeveralColumns {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// How many columns the arm returns.
        columns: usize,
    },
    /// A grant arm keeps only the rows whose columns pair with the rows another helper
    /// returns.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' only where they pair with \
         the rows '{cap}' returns, which no grant relation carries"
    )]
    Capped {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The helper returning the pairs.
        cap: String,
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
    let (name, arguments) = called_helper(query)?;
    let mut reached = db
        .functions()
        .filter(|declared| call_matches_declared(name, *declared, db))
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

/// The one call a set query reads and its arguments, `None` where the query reads
/// anything else or keeps fewer rows than the call returns.
fn called_helper(query: &Query) -> Option<(&ObjectName, &[FunctionArg])> {
    match projected_select(query) {
        Some(select) => projected_call(select),
        None => call_read_in_from(query),
    }
}

/// The call `SELECT h(...)` makes, reading no table and keeping its one row.
fn projected_call(select: &Select) -> Option<(&ObjectName, &[FunctionArg])> {
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
    plain_call.then_some((&call.name, list.args.as_slice()))
}

/// The call `SELECT c FROM h(...) a(c)` reads as its only relation, projecting the one
/// column a set-returning function of a base type returns and keeping every row.
///
/// The factor is spelled exhaustively so a field the parser adds to a `FROM` item is a
/// compile error here rather than a set admitted without a proof.
fn call_read_in_from(query: &Query) -> Option<(&ObjectName, &[FunctionArg])> {
    if set_limiting_clause(query).is_some() {
        return None;
    }
    let select = query_select(query)?;
    let [TableWithJoins { relation, joins }] = select.from.as_slice() else {
        return None;
    };
    if !joins.is_empty()
        || select.selection.is_some()
        || select_result_shaping_clause(select).is_some()
    {
        return None;
    }
    let TableFactor::Table {
        name,
        alias,
        args: Some(TableFunctionArgs {
            args,
            settings: None,
        }),
        version: None,
        sample: None,
        json_path: None,
        with_hints,
        with_ordinality: false,
        partitions,
        index_directives,
        inheritance: None,
    } = relation
    else {
        return None;
    };
    // Hints, partitions and index directives are other dialects' syntax, which a
    // PostgreSQL dump never carries, so any of them leaves the set unproven.
    let plain = with_hints.is_empty() && partitions.is_empty() && index_directives.is_empty();
    let [SelectItem::UnnamedExpr(projected)
    | SelectItem::ExprWithAlias {
        expr: projected, ..
    }] = select.projection.as_slice()
    else {
        return None;
    };
    let function = name.0.last()?.as_ident()?;
    let (relation, column) = returned_column(function, alias.as_ref())?;
    (plain && projects_column(unparenthesize(projected), relation, column))
        .then_some((name, args.as_slice()))
}

/// The relation name and the column name `PostgreSQL` gives the one column a function of
/// a base type returns, which is the alias's column where it lists one, else the alias,
/// else the function's own name.
fn returned_column<'a>(
    function: &'a Ident,
    alias: Option<&'a TableAlias>,
) -> Option<(&'a Ident, &'a Ident)> {
    let Some(alias) = alias else {
        return Some((function, function));
    };
    match alias.columns.as_slice() {
        [] => Some((&alias.name, &alias.name)),
        [column] if column.data_type.is_none() => Some((&alias.name, &column.name)),
        _ => None,
    }
}

/// Whether `projected` reads `column` of `relation`, bare or qualified by the relation.
fn projects_column(projected: &Expr, relation: &Ident, column: &Ident) -> bool {
    let same = |left: &Ident, right: &Ident| stored_ident_name(left) == stored_ident_name(right);
    match projected {
        Expr::Identifier(read) => same(read, column),
        Expr::CompoundIdentifier(parts) => matches!(
            parts.as_slice(),
            [qualifier, read] if same(qualifier, relation) && same(read, column)
        ),
        _ => false,
    }
}

/// The guarded table's column the set is compared with, uncast.
pub(super) fn compared_column(expr: &Expr, table: &str) -> Option<ColumnName> {
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
        let column = granted_column(&name, grant)?;
        arms.push(HelperValues {
            table: table_identity(grant.table()),
            value_column: ColumnName::from_stored(column.stored_column_name()),
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
/// table whose rows `compared` names, or of a table whose key references `level`'s.
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
    let arguments: Vec<String> = arguments.iter().map(ToString::to_string).collect();
    let mut arms = Vec::with_capacity(set.arms().len());
    for arm in set.arms() {
        let (returned, arm) = match arm {
            HelperArm::Grant(grant) => {
                let column = granted_column(&name, grant)?;
                (
                    rows_named_by(grant.table(), column, db)?
                        .ok_or_else(|| names_no_rows(grant.table(), column))?,
                    HelperSetArm::Grant(Box::new(helper_grant(&name, grant, db, registry)?)),
                )
            }
            HelperArm::Parent(parent) => (
                table_identity(parent.table()),
                HelperSetArm::Parent(helper_parent(&name, parent, db, registry)?),
            ),
            HelperArm::Walk(walk) => (
                table_identity(walk.table()),
                HelperSetArm::Walk(HelperWalk {
                    table: table_identity(walk.table()),
                    fk_column: ColumnName::from_stored(walk.column().stored_column_name()),
                    direction: walk.direction(),
                }),
            ),
        };
        if !keys_name_rows_of(&returned, level, db)? {
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
        arguments,
        level: level.clone(),
        arms,
    })
}

/// Whether every key of `table` is a key of `level`, its one-column key referencing
/// `level`'s through a chain of such keys, as an organization's key is a grantee's.
fn keys_name_rows_of<DB: DatabaseLike>(
    table: &TableId,
    level: &TableId,
    db: &DB,
) -> Result<bool, HelperRefusal> {
    let mut reached = table.clone();
    let mut visited = Vec::new();
    while reached != *level {
        if visited.contains(&reached) {
            return Ok(false);
        }
        let (Some(held), Some(key)) = (
            lookup_table_id(db, &reached),
            single_identity_column(&reached, db),
        ) else {
            return Ok(false);
        };
        let Some(key) = held
            .columns(db)?
            .find(|column| column.stored_column_name() == key.as_str())
        else {
            return Ok(false);
        };
        let Some(named) = rows_named_by(held, key, db)? else {
            return Ok(false);
        };
        visited.push(core::mem::replace(&mut reached, named));
    }
    Ok(true)
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
    Ok(HelperParent {
        table: table_identity(parent.table()),
        fk_column,
        call,
    })
}

fn helper_grant<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<HelperGrant, HelperRefusal> {
    let table = grant.table();
    let grantee = match grant.granted_to() {
        GrantedTo::Request(compared) => {
            let column = ColumnName::from_stored(compared.column().stored_column_name());
            // `sql-traits` compares a column with the caller, with another principal the
            // deployment declares, or with the elements of a whole setting declared as a
            // set.
            match compared.setting().content() {
                SettingContent::Value(value @ SettingValue::Set { .. }) => {
                    bounded_by_no_time(function, grant)?;
                    HelperGrantee::RequestSet {
                        value_column: column,
                        source: DeclaredSource::whole(compared.setting(), value.clone()),
                    }
                }
                SettingContent::Value(SettingValue::Principal { kind, .. }) => {
                    HelperGrantee::Principal {
                        principal_column: column,
                        principal_type: TypeName::try_from(kind.clone()).map_err(|_| {
                            HelperRefusal::UnspellablePrincipalType {
                                function: function.to_string(),
                                kind: kind.clone(),
                            }
                        })?,
                    }
                }
                _ => HelperGrantee::Caller {
                    user_column: column,
                },
            }
        }
        GrantedTo::Set(set) => {
            let called = set.function();
            if !registry.declares_helper(called) {
                return Err(HelperRefusal::UndeclaredCallee {
                    function: function.to_string(),
                    called: called.target_name().to_string(),
                });
            }
            let grantee_column = ColumnName::from_stored(set.column().stored_column_name());
            // Without a foreign key the grantees are rows of the table the set covers.
            let named = match rows_named_by(table, set.column(), db)? {
                Some(named) => named,
                None => set
                    .set()
                    .covered_table()
                    .map(table_identity)
                    .ok_or_else(|| names_no_rows(table, set.column()))?,
            };
            let call = helper_call(
                called,
                set.arguments(),
                set.set(),
                &grantee_column,
                &named,
                db,
                registry,
            )?;
            HelperGrantee::Set {
                grantee_column,
                call,
            }
        }
        GrantedTo::Anyone => HelperGrantee::Anyone,
    };
    if !grant.time_bounds().is_empty()
        && matches!(grantee, HelperGrantee::Set { .. } | HelperGrantee::Anyone)
    {
        return Err(HelperRefusal::TimeBoundedGrantees {
            function: function.to_string(),
            table: table_identity(table).to_string(),
        });
    }
    let excluded = match grant.gate() {
        None => Vec::new(),
        Some(gate) => excluded_callers(function, gate, &grantee)?,
    };
    let object_column = granted_column(function, grant)?;
    let grant = HelperGrant {
        table: table_identity(table),
        object_column: ColumnName::from_stored(object_column.stored_column_name()),
        grantee,
        excluded,
        rows: grant_rows(table, grant.restrictions(), db)?,
        time_bounds: grant.time_bounds().iter().map(time_bound).collect(),
    };
    if grant.time_bounds.len() > 1 && !row_uniquely_keys(&grant.table, &grant.tuple_key(), db) {
        return Err(HelperRefusal::MixedTimeBounds {
            table: grant.table.to_string(),
        });
    }
    let null_kept = grant
        .time_bounds
        .iter()
        .filter(|bound| bound.keeps_null)
        .count();
    // Each way a row meets the bounds is a condition, unless every bound is one met by
    // `NULL`, which leaves one way comparing nothing with the clock.
    let all_null = usize::from(null_kept == grant.time_bounds.len());
    let conditions = u32::try_from(null_kept)
        .ok()
        .and_then(|shift| 1_usize.checked_shl(shift))
        .map(|ways| ways - all_null);
    if conditions.is_none_or(|conditions| conditions > MAX_CONDITIONS) {
        return Err(HelperRefusal::TooManyNullBounds {
            table: grant.table.to_string(),
            bounds: null_kept,
        });
    }
    Ok(grant)
}

/// The bound as the comparison the request clock completes, `now()` read unshifted.
fn time_bound<DB: DatabaseLike>(bound: &TimeBound<'_, DB>) -> HelperTimeBound {
    let operator = match bound.comparison() {
        TimeComparison::Later => AttributeOperator::Gt,
        TimeComparison::LaterOrEqual => AttributeOperator::GtEq,
        TimeComparison::Earlier => AttributeOperator::Lt,
        TimeComparison::EarlierOrEqual => AttributeOperator::LtEq,
    };
    HelperTimeBound {
        comparison: AttributeRequestPredicate {
            column: ColumnName::from_stored(bound.column().stored_column_name()),
            operator,
            threshold: ClockThreshold {
                reading: ClockReading::Instant,
                offset: ClockOffset::ZERO,
            },
        },
        keeps_null: bound.keeps_null(),
    }
}

/// The rows `restrictions` keep of `table`, split by its role column where it has one.
fn grant_rows<DB: DatabaseLike>(
    table: &DB::Table,
    restrictions: &[Restriction<'_, DB>],
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

/// The callers a gate on the caller setting keeps no row for, as the identities their
/// checks send.
///
/// A check always names a caller, so `IS NOT NULL` and `<> ''` exclude nobody it can
/// send. That holds only where the deployment promises a caller on every request: a
/// request it lets leave the setting unset reads `NULL` or `''`, and no subject names
/// such a check apart from a caller's, unless the arm compares a column with the caller
/// and so keeps nothing for it anyway.
fn excluded_callers(
    function: &str,
    gate: &CallerGate<'_>,
    grantee: &HelperGrantee,
) -> Result<Vec<String>, HelperRefusal> {
    let setting = gate.setting();
    if setting.presence() == SettingPresence::MayBeUnset
        && !matches!(grantee, HelperGrantee::Caller { .. })
    {
        return Err(HelperRefusal::GateOnUnsetCaller {
            function: function.to_string(),
            setting: setting.name().to_string(),
        });
    }
    let data_type = match setting.content() {
        SettingContent::Value(SettingValue::Caller(data_type)) => Some(data_type),
        _ => None,
    };
    // `sql-traits` names each excluded value once.
    let mut excluded = Vec::with_capacity(gate.excluded().len());
    for value in gate.excluded() {
        let text = match value {
            Value::SingleQuotedString(text) => Some(text.as_str()),
            Value::DollarQuotedString(text) => Some(text.value.as_str()),
            _ => None,
        };
        // No check sends an empty caller, so `<> ''` excludes nobody.
        if text == Some("") {
            continue;
        }
        let identity = text
            .zip(data_type)
            .and_then(|(text, data_type)| caller_identity(text, data_type))
            .ok_or_else(|| HelperRefusal::UnnamedCaller {
                function: function.to_string(),
                value: value.to_string(),
            })?;
        excluded.push(identity);
    }
    if !excluded.is_empty() {
        match grantee {
            HelperGrantee::RequestSet { .. } => {
                return Err(HelperRefusal::ExcludedFromRequestSet {
                    function: function.to_string(),
                })
            }
            HelperGrantee::Principal { principal_type, .. } => {
                return Err(HelperRefusal::ExcludedFromPrincipal {
                    function: function.to_string(),
                    kind: principal_type.to_string(),
                })
            }
            HelperGrantee::Caller { .. } | HelperGrantee::Set { .. } | HelperGrantee::Anyone => {}
        }
    }
    Ok(excluded)
}

/// The identity a check sends for a caller spelled `text`, which the deployment
/// promises to send in the canonical text of `data_type`.
///
/// `None` where `text` is not that canonical text, since the cast `PostgreSQL` applies
/// is not read here, and for a type with no such reading.
fn caller_identity(text: &str, data_type: &DataType) -> Option<String> {
    let canonical = match data_type {
        DataType::Text | DataType::Varchar(None) | DataType::CharacterVarying(None) => true,
        DataType::Uuid => {
            text.len() == 36
                && text.char_indices().all(|(index, character)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        character == '-'
                    } else {
                        character.is_ascii_digit() || matches!(character, 'a'..='f')
                    }
                })
        }
        _ => false,
    };
    canonical.then(|| text.to_string())
}

/// The test one restriction puts on its column, `IN` its values, `IS NULL` or
/// `IS NOT NULL`.
///
/// `sql-traits` keeps only the literal kinds [`literal`] reads, and a value it ever
/// kept otherwise is dropped, which narrows, since the relations load no row for an
/// empty list.
fn restriction<DB: DatabaseLike>(kept: &Restriction<'_, DB>) -> AttributePredicate {
    let test = match kept {
        Restriction::In(set) => {
            AttributeTest::In(set.values().iter().filter_map(literal).collect())
        }
        Restriction::Null(_) => AttributeTest::IsNull,
        Restriction::NotNull(_) => AttributeTest::IsNotNull,
    };
    AttributePredicate {
        column: ColumnName::from_stored(kept.column().stored_column_name()),
        test,
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

/// The one column `grant` returns, refused where it returns several or where a cap
/// keeps only some of its rows, which no relation loaded from the arm carries.
fn granted_column<'db, DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'db, DB>,
) -> Result<&'db DB::Column, HelperRefusal> {
    let table = || table_identity(grant.table()).to_string();
    if let Some(cap) = grant.caps().first() {
        return Err(HelperRefusal::Capped {
            function: function.to_string(),
            table: table(),
            cap: cap.function().target_name().to_string(),
        });
    }
    match grant.columns() {
        [column] => Ok(column),
        columns => Err(HelperRefusal::SeveralColumns {
            function: function.to_string(),
            table: table(),
            columns: columns.len(),
        }),
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
