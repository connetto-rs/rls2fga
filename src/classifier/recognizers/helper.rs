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
use crate::generator::db_lookup::{
    column_kind, resolve_row_identity, row_uniquely_keys, single_identity_column,
};
use crate::generator::model_bounds::MAX_CONDITIONS;
use crate::parser::expr::CastChain;
use crate::parser::names::{
    lookup_table, lookup_table_id, stored_ident_name, stored_relation_name, table_identity,
};
use crate::parser::sql_parser::{
    CallerGate, CapLift, CapOperand, CheckConstraintLike, ColumnLike, DataTypeLike, DatabaseLike,
    ForeignKeyLike, FunctionLike, GrantArm, GrantedTo, HelperArm, HelperSet, JoinedRow, ParentArm,
    Restriction, RowCap, SettingComparison, SettingContent, SettingPresence, SettingValue,
    TableLike, TimeBound, TimeComparison,
};
use crate::types::{ColumnKind, ColumnName, RequestNormalization, TypeName};
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
    /// A gate on a caller the deployment lets go unset decides the arm in a way the request
    /// gate on whether the request carries a caller does not state.
    #[error(
        "declared helper '{function}' tests whether setting '{setting}' holds a caller, \
         which the deployment lets a request leave unset, {reason}"
    )]
    GateOnUnsetCaller {
        /// The helper.
        function: String,
        /// The caller setting.
        setting: String,
        /// Why the request carrying a caller does not decide the gate.
        reason: UnsetCallerGateRefusal,
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
    /// A gate excludes callers from rows admitting whoever presents a value the request
    /// carries.
    #[error(
        "declared helper '{function}' excludes callers from rows a value the request \
         carries admits"
    )]
    ExcludedFromRequestValue {
        /// The helper.
        function: String,
    },
    /// An arm compares a column with a value a request may leave unset, read without
    /// `NULLIF`, so the `''` an ended transaction-local value reads as keeps rows.
    #[error(
        "declared helper '{function}' compares a column with setting '{setting}' read \
         without NULLIF, which a request leaving it unset may read as '' and match rows \
         holding ''"
    )]
    UnsetReadAsEmpty {
        /// The helper.
        function: String,
        /// The setting compared with.
        setting: String,
    },
    /// An arm compares a column with a normalized value whose key a declared setting
    /// already takes, so the caller could not send both.
    #[error(
        "declared helper '{function}' compares a column with {normalization}({setting}), \
         whose key in the settings map a declared setting already takes"
    )]
    NormalizedKeyTaken {
        /// The helper.
        function: String,
        /// The setting normalized.
        setting: String,
        /// The function normalizing it.
        normalization: &'static str,
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
    /// An arm of a set compared with a request value keeps its rows by the statement
    /// time.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' it compares with a \
         request value by the statement time, which a set compared with a request value \
         does not carry"
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
    /// A grant arm compared with a request value keeps only the rows whose columns pair
    /// with the rows another helper returns.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' only where they pair with \
         the rows '{cap}' returns, which no request-value gate carries"
    )]
    Capped {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The helper returning the pairs.
        cap: String,
    },
    /// A cap returns some of its pairs through a parent or a walk, which no row keys.
    #[error(
        "declared helper '{function}' is capped by '{cap}', which returns pairs through a \
         parent or a walk, while a pair is read from the row returning it"
    )]
    CapByParentOrWalk {
        /// The capped helper.
        function: String,
        /// The helper returning the pairs.
        cap: String,
    },
    /// The rows returning a cap's pairs are capped in turn.
    #[error(
        "declared helper '{function}' is capped by '{cap}', whose own rows '{nested}' caps, \
         while a pair object carries no cap"
    )]
    CappedCap {
        /// The capped helper.
        function: String,
        /// The helper returning the pairs.
        cap: String,
        /// The helper capping the cap's rows.
        nested: String,
    },
    /// A cap is lifted by a read the request's absence does not decide.
    #[error(
        "declared helper '{function}' lifts its cap where setting '{setting}' reads NULL, \
         {reason}"
    )]
    Lift {
        /// The capped helper.
        function: String,
        /// The setting the lift reads.
        setting: String,
        /// Why its absence does not decide the lift.
        reason: LiftRefusal,
    },
    /// A cap operand is neither a column nor a literal the model spells.
    #[error(
        "declared helper '{function}' pairs '{operand}' with the rows '{cap}' returns, which \
         is no literal a pair is named by"
    )]
    CapOperand {
        /// The capped helper.
        function: String,
        /// The helper returning the pairs.
        cap: String,
        /// The operand as written.
        operand: String,
    },
    /// A cap reads more of a row than the level's row names, while several rows of the
    /// arm's table can name one returned row and no key holds each row as its own object.
    #[error(
        "declared helper '{function}' pairs column '{column}' of '{table}' with the rows \
         '{cap}' returns, while several rows of '{table}' can return one row and no key names \
         each of its rows"
    )]
    CapOnSeveralRows {
        /// The capped helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The paired column.
        column: String,
        /// The helper returning the pairs.
        cap: String,
    },
    /// A cap pairs literals with no column.
    #[error(
        "declared helper '{function}' pairs literals with the rows '{cap}' returns beside no \
         column of '{table}', so no pair names the row it returns"
    )]
    CapLiteralsBeside {
        /// The capped helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The helper returning the pairs.
        cap: String,
    },
    /// A cap pairs columns of two rows, the arm's own and a joined one or two joined ones,
    /// which no one table's rows link to the pair they name.
    #[error(
        "declared helper '{function}' pairs columns of '{first}' and of '{second}' with the \
         rows '{cap}' returns, which no one row holds"
    )]
    CapAcrossRows {
        /// The capped helper.
        function: String,
        /// The table of the first row read.
        first: String,
        /// The table of the other row read.
        second: String,
        /// The helper returning the pairs.
        cap: String,
    },
    /// A cap pairs columns whose types differ, or whose text spelling does not decide
    /// equality.
    #[error(
        "declared helper '{function}' pairs column '{column}' of '{table}' with column \
         '{paired}' of the rows '{cap}' returns, and the two are not of one type whose text \
         spelling decides equality, which names a pair"
    )]
    CapUnlikeTypes {
        /// The capped helper.
        function: String,
        /// The table of the arm's row or of the joined row the column belongs to.
        table: String,
        /// The paired column of that table.
        column: String,
        /// The helper returning the pairs.
        cap: String,
        /// The column of the cap's rows it pairs with.
        paired: String,
    },
    /// A grant arm read where no row link reaches it keeps only the rows naming a joined
    /// row that meets the join's conditions.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' only where they name a \
         row of '{joined}' meeting the join, which neither a request-value gate nor a cap's \
         pairs carry"
    )]
    Joined {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The table the arm joins.
        joined: String,
    },
    /// A grant arm read where no row link reaches it keeps only the rows no row of another
    /// table blocks.
    #[error(
        "declared helper '{function}' keeps the rows of '{table}' only where no row of \
         '{blocking}' blocks them, which neither a request-value gate nor a cap's pairs carry"
    )]
    AntiJoined {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The table whose rows block the arm's.
        blocking: String,
    },
    /// A grant arm joins or anti-joins the rows of a table through columns other than
    /// that table's key, so no one row is named by the arm's row.
    #[error(
        "declared helper '{function}' names the rows of '{other}' from the rows of '{table}' \
         through columns other than the key of '{other}', so no link names one row"
    )]
    JoinOffKey {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
        /// The joined or blocking table.
        other: String,
    },
    /// The rows a grant arm joins or anti-joins are bounded against the clock.
    #[error(
        "declared helper '{function}' bounds the rows of '{other}' it joins against the \
         clock, which no row link carries"
    )]
    JoinTimeBounds {
        /// The helper.
        function: String,
        /// The joined or blocking table.
        other: String,
    },
    /// A grant arm joining or anti-joining rows reads a table no key names one row of.
    #[error(
        "declared helper '{function}' joins the rows of '{table}', which no key names one \
         row of"
    )]
    JoinedTableUnkeyed {
        /// The helper.
        function: String,
        /// The table the arm reads.
        table: String,
    },
    /// A row blocking a grant arm's rows is told by a value no tuple spells, so a blocking
    /// row would go unwritten and the arm would keep the row it blocks.
    #[error(
        "declared helper '{function}' tells the rows of '{other}' that block its rows by a \
         value no tuple spells"
    )]
    UnspelledBlockingValue {
        /// The helper.
        function: String,
        /// The blocking table.
        other: String,
    },
}

/// Why the request leaving a setting absent does not decide a cap lifted where the setting
/// reads `NULL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LiftRefusal {
    /// `current_setting(name)` raises `42704` on a setting the request never set.
    #[error(
        "but reads it through current_setting without missing_ok, which raises 42704 where \
         a request never set it"
    )]
    RaisesWhenUnset,
    /// The read is `''` on a pooled connection whose earlier transaction set it.
    #[error(
        "but reads it without NULLIF(..., ''), so the '' a pooled connection reads for an \
         unset setting keeps the cap a request leaving it absent lifts"
    )]
    ReadBare,
    /// The deployment declares the setting no single value a request may leave unset.
    #[error("which the deployment does not declare as one value a request may leave unset")]
    NotMaybeUnset,
}

/// Why whether the request carries a caller it may leave unset does not decide a gate
/// on that caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UnsetCallerGateRefusal {
    /// `current_setting(name)` raises `42704` on a setting the request never set.
    #[error(
        "but reads it through current_setting without missing_ok, which raises 42704 where \
         a request never set it"
    )]
    RaisesWhenUnset,
    /// The read is `''` on a pooled connection whose earlier transaction set it.
    #[error(
        "but reads it without NULLIF(..., '') or <> '', so the '' a pooled connection reads \
         for an unset caller keeps the arm's rows, or raises where the read is cast"
    )]
    ReadBare,
    /// The gate sits on an arm returning the pairs of a cap, which no request gate reaches.
    #[error("but gates an arm of a cap, whose pairs no request gate reaches")]
    CapArm,
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
                request_value_in_helper_set(function, arguments, &source, db, registry)
            };
            (
                pattern.map(PatternClass::P27RequestValueInHelperSet),
                grade(&source),
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
        uncapped(&name, grant)?;
        unjoined(&name, grant)?;
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

/// Refuses an arm keeping rows by the statement time, which the gate stating a set
/// compared with a request value does not carry.
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
                    HelperSetArm::Grant(Box::new(helper_grant(
                        &name,
                        grant,
                        core::slice::from_ref(&column),
                        db,
                        registry,
                    )?)),
                )
            }
            HelperArm::Parent(parent) => (
                table_identity(parent.child_table()),
                HelperSetArm::Parent(helper_parent(&name, parent, db, registry)?),
            ),
            HelperArm::Walk(walk) => (
                table_identity(walk.tree()),
                HelperSetArm::Walk(HelperWalk {
                    edges: helper_edges::<DB>(walk.table(), walk.child(), walk.column()),
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
    let edges = helper_edges::<DB>(parent.table(), parent.key(), parent.column());
    // Without a foreign key the parent is the table the called set covers.
    let referenced = rows_named_by(parent.table(), parent.column(), db)?
        .unwrap_or_else(|| table_identity(parent.parent_table()));
    let call = helper_call(
        called,
        parent.arguments(),
        parent.set(),
        &edges.parent_column,
        &referenced,
        db,
        registry,
    )?;
    Ok(HelperParent { edges, call })
}

/// The edges the rows of `table` draw, each from the row `child` names to the one
/// `parent` names.
fn helper_edges<DB: DatabaseLike>(
    table: &DB::Table,
    child: &DB::Column,
    parent: &DB::Column,
) -> TreeEdges {
    TreeEdges {
        table: table_identity(table),
        child_column: ColumnName::from_stored(child.stored_column_name()),
        parent_column: ColumnName::from_stored(parent.stored_column_name()),
    }
}

/// The grant `grant` makes on the object `objects` name, the one row of the level for an
/// arm of a call and the pair for an arm of a cap.
fn helper_grant<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
    objects: &[&DB::Column],
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<HelperGrant, HelperRefusal> {
    let held = arm_joins(function, grant, db)?;
    let table = grant.table();
    let grantee = match grant.granted_to() {
        GrantedTo::Request(compared) => {
            let column = ColumnName::from_stored(compared.column().stored_column_name());
            // `sql-traits` compares a column with the caller, with another principal the
            // deployment declares, with a declared scalar, normalized or not, or with the
            // elements of a whole setting declared as a set.
            match compared.setting().content() {
                SettingContent::Value(value @ SettingValue::Set { .. }) => {
                    HelperGrantee::RequestValue {
                        value_column: column,
                        source: DeclaredSource::whole(compared.setting(), value.clone()),
                    }
                }
                SettingContent::Value(SettingValue::Scalar(_)) => HelperGrantee::RequestValue {
                    value_column: column,
                    source: compared_scalar(function, compared, registry)?,
                },
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
    let (carried_caller, excluded) = match grant.gate() {
        None => (None, Vec::new()),
        Some(gate) => (
            carried_caller(function, gate, &grantee, registry)?,
            excluded_callers(function, gate, &grantee)?,
        ),
    };
    let (caps, held) = match objects {
        [object] => {
            let caps = grant
                .caps()
                .iter()
                .map(|cap| helper_cap(function, grant, cap, db, registry))
                .collect::<Result<_, _>>()?;
            place_caps(function, grant, object, caps, held, db)?
        }
        // Only an arm of a cap returns several columns, and `helper_cap` refuses one
        // carrying caps of its own.
        _ => (Vec::new(), held),
    };
    let grant = HelperGrant {
        table: table_identity(table),
        object_columns: objects
            .iter()
            .map(|object| ColumnName::from_stored(object.stored_column_name()))
            .collect(),
        grantee,
        excluded,
        carried_caller,
        rows: grant_rows(table, grant.restrictions(), db)?,
        time_bounds: grant.time_bounds().iter().map(time_bound).collect(),
        caps,
        held,
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

/// The declared scalar a grant arm compares a column with, or the value of its own its
/// normalization makes of it, which the caller sends in the scalar's place.
///
/// A read without `NULLIF` of a scalar a request may leave unset reads `''` once a
/// transaction-local value has ended, and keeps the rows holding `''`, which a request
/// omitting the value never matches in the model, so it is refused.
fn compared_scalar<DB: DatabaseLike>(
    function: &str,
    compared: &SettingComparison<'_, DB>,
    registry: &FunctionRegistry,
) -> Result<DeclaredSource, HelperRefusal> {
    let setting = compared.setting().name();
    let source = registry
        .declared_source(setting, &[])
        .filter(|source| source.is_scalar())
        .ok_or_else(|| HelperRefusal::NoDeployment {
            function: function.to_string(),
        })?;
    if source.may_be_unset() && !compared.excludes_unset() {
        return Err(HelperRefusal::UnsetReadAsEmpty {
            function: function.to_string(),
            setting: setting.to_string(),
        });
    }
    let Some(normalization) = compared.normalization() else {
        return Ok(source.clone());
    };
    let normalization = match normalization {
        sql_traits::structs::RequestNormalization::Lower => RequestNormalization::Lower,
    };
    registry
        .sources()
        .normalized(source, normalization)
        .ok_or_else(|| HelperRefusal::NormalizedKeyTaken {
            function: function.to_string(),
            setting: setting.to_string(),
            normalization: normalization.function_name(),
        })
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

/// The caller `gate` keeps rows only for a request carrying, where the deployment lets a
/// request leave it unset and `grantee` compares no column with it.
///
/// No subject names a check without a caller apart from a caller's, so the gate is stated
/// on whether the request carries the caller under its `settings` key, which holds where
/// `PostgreSQL` reads neither `NULL` nor `''`. A gate keeping rows for `''`, or raising
/// where the setting was never set, is refused.
fn carried_caller(
    function: &str,
    gate: &CallerGate<'_>,
    grantee: &HelperGrantee,
    registry: &FunctionRegistry,
) -> Result<Option<DeclaredSource>, HelperRefusal> {
    let setting = gate.setting();
    if setting.presence() != SettingPresence::MayBeUnset
        || matches!(grantee, HelperGrantee::Caller { .. })
    {
        return Ok(None);
    }
    let refusal = |reason| HelperRefusal::GateOnUnsetCaller {
        function: function.to_string(),
        setting: setting.name().to_string(),
        reason,
    };
    if gate.raises_when_unset() {
        return Err(refusal(UnsetCallerGateRefusal::RaisesWhenUnset));
    }
    if !gate.excludes_unset() {
        return Err(refusal(UnsetCallerGateRefusal::ReadBare));
    }
    registry
        .sources()
        .caller(setting.name(), &[])
        .cloned()
        .map(Some)
        .ok_or_else(|| HelperRefusal::NoDeployment {
            function: function.to_string(),
        })
}

/// The callers a gate on the caller setting keeps no row for, as the identities their
/// checks send.
///
/// `IS NOT NULL` and `<> ''` exclude no caller a check names, and a request carrying no
/// caller is [`carried_caller`]'s to gate.
fn excluded_callers(
    function: &str,
    gate: &CallerGate<'_>,
    grantee: &HelperGrantee,
) -> Result<Vec<String>, HelperRefusal> {
    let setting = gate.setting();
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
            HelperGrantee::RequestValue { .. } => {
                return Err(HelperRefusal::ExcludedFromRequestValue {
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

/// The table whose rows the values of `column` name, which are the rows of the one table
/// whose key column its foreign keys pair it with, else its own table's where it is that
/// table's key, and `None` where it is neither.
///
/// A key of any width pairing `column` with the referenced table's key column makes every
/// value one row of that table. A single-column key referencing another column names rows
/// by something other than their key and refuses, while a wider one pairs `column` with
/// part of a key, which says nothing of `column` alone.
fn rows_named_by<DB: DatabaseLike>(
    table: &DB::Table,
    column: &DB::Column,
    db: &DB,
) -> Result<Option<TableId>, HelperRefusal> {
    let mut referenced: Option<TableId> = None;
    for foreign_key in table.foreign_keys(db)? {
        let Some(paired) = foreign_key
            .host_columns(db)?
            .zip(foreign_key.referenced_columns(db)?)
            .find_map(|(host, paired)| core::ptr::eq(host, column).then_some(paired))
        else {
            continue;
        };
        let parent = table_identity(foreign_key.referenced_table(db)?);
        let names_key = single_identity_column(&parent, db)
            .is_some_and(|key| key.as_str() == paired.stored_column_name());
        if !names_key {
            if foreign_key.is_composite(db)? {
                continue;
            }
            return Err(names_no_rows(table, column));
        }
        // Two keys referencing different tables leave the rows the value names open.
        if referenced.as_ref().is_some_and(|held| *held != parent) {
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

/// The one column `grant` returns, refused where it returns several, which no one relation
/// names.
fn granted_column<'db, DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'db, DB>,
) -> Result<&'db DB::Column, HelperRefusal> {
    match grant.columns() {
        [column] => Ok(column),
        columns => Err(HelperRefusal::SeveralColumns {
            function: function.to_string(),
            table: table_identity(grant.table()).to_string(),
            columns: columns.len(),
        }),
    }
}

/// Refuses an arm a cap keeps only some rows of, read where every row the arm's other
/// conditions keep is a value the request is compared with.
fn uncapped<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
) -> Result<(), HelperRefusal> {
    match grant.caps().first() {
        None => Ok(()),
        Some(cap) => Err(HelperRefusal::Capped {
            function: function.to_string(),
            table: table_identity(grant.table()).to_string(),
            cap: cap.function().target_name().to_string(),
        }),
    }
}

/// Refuses an arm keeping only the rows that name a joined row meeting the join, or that
/// no row of another table blocks, read where no link from the arm's own row reaches the
/// other table's row.
fn unjoined<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
) -> Result<(), HelperRefusal> {
    let table = || table_identity(grant.table()).to_string();
    if let Some(joined) = grant.joined_rows().first() {
        return Err(HelperRefusal::Joined {
            function: function.to_string(),
            table: table(),
            joined: table_identity(joined.table()).to_string(),
        });
    }
    match grant.anti_joins().first() {
        None => Ok(()),
        Some(anti_join) => Err(HelperRefusal::AntiJoined {
            function: function.to_string(),
            table: table(),
            blocking: table_identity(anti_join.table()).to_string(),
        }),
    }
}

/// The rows of `grant`'s table held by their key, with the rows each joins and the rows
/// that block it, each named by columns of the arm's own row, `None` where it names none,
/// and refused unless a key names one row of the arm's table and of each other table.
fn arm_joins<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
    db: &DB,
) -> Result<Option<HeldRows>, HelperRefusal> {
    if grant.joined_rows().is_empty() && grant.anti_joins().is_empty() {
        return Ok(None);
    }
    let table = table_identity(grant.table());
    let Some(identity) = resolve_row_identity(&table, db) else {
        return Err(HelperRefusal::JoinedTableUnkeyed {
            function: function.to_string(),
            table: table.to_string(),
        });
    };
    let joined = grant
        .joined_rows()
        .iter()
        .map(|joined| {
            helper_join(
                function,
                &table,
                joined.table(),
                joined.columns(),
                (joined.restrictions(), joined.time_bounds()),
                db,
            )
        })
        .collect::<Result<_, _>>()?;
    let blocked = grant
        .anti_joins()
        .iter()
        .map(|anti_join| {
            let columns: Vec<_> = anti_join
                .correlations()
                .iter()
                .map(|correlation| (correlation.arm_column(), correlation.blocking_column()))
                .collect();
            let blocked = helper_join(
                function,
                &table,
                anti_join.table(),
                &columns,
                (anti_join.restrictions(), anti_join.time_bounds()),
                db,
            )?;
            // A value the model cannot spell would leave a blocking row unwritten, and a
            // row nothing blocks is kept, so the arm would grant more than the body.
            if anti_join.restrictions().iter().any(|kept| match kept {
                Restriction::In(set) => set
                    .values()
                    .iter()
                    .any(|value| !matches!(value, Value::Null) && literal(value).is_none()),
                Restriction::Null(_) | Restriction::NotNull(_) => false,
            }) {
                return Err(HelperRefusal::UnspelledBlockingValue {
                    function: function.to_string(),
                    other: blocked.table.to_string(),
                });
            }
            Ok(blocked)
        })
        .collect::<Result<_, _>>()?;
    Ok(Some(HeldRows {
        identity,
        joined,
        blocked,
    }))
}

/// The row of `other` the arm's row names through `columns`, each an arm column beside the
/// column of `other` it equals, and what that row has to hold.
fn helper_join<DB: DatabaseLike>(
    function: &str,
    table: &TableId,
    other: &DB::Table,
    columns: &[(&DB::Column, &DB::Column)],
    (restrictions, time_bounds): (&[Restriction<'_, DB>], &[TimeBound<'_, DB>]),
    db: &DB,
) -> Result<HelperJoin, HelperRefusal> {
    let other = table_identity(other);
    if !time_bounds.is_empty() {
        return Err(HelperRefusal::JoinTimeBounds {
            function: function.to_string(),
            other: other.to_string(),
        });
    }
    let off_key = || HelperRefusal::JoinOffKey {
        function: function.to_string(),
        table: table.to_string(),
        other: other.to_string(),
    };
    let identity = resolve_row_identity(&other, db).ok_or_else(off_key)?;
    if identity.len() != columns.len() {
        return Err(off_key());
    }
    let columns = identity
        .iter()
        .map(|key| {
            columns
                .iter()
                .find(|(_, named)| named.stored_column_name() == key.as_str())
                .map(|(arm, _)| ColumnName::from_stored(arm.stored_column_name()))
                .ok_or_else(off_key)
        })
        .collect::<Result<_, _>>()?;
    Ok(HelperJoin {
        table: other,
        identity,
        columns,
        predicates: restrictions.iter().map(restriction).collect(),
    })
}

/// The cap `cap` puts on the rows `grant` returns, its pairs read from the cap's own arms,
/// linked from each held row until [`place_caps`] moves it to the level's row.
fn helper_cap<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
    cap: &RowCap<'_, DB>,
    db: &DB,
    registry: &FunctionRegistry,
) -> Result<HelperCap, HelperRefusal> {
    let called = cap.function();
    if !registry.declares_helper(called) {
        return Err(HelperRefusal::UndeclaredCallee {
            function: function.to_string(),
            called: called.target_name().to_string(),
        });
    }
    let name = registry.resolved_target_name(&called.target_name());
    let mut arms = Vec::with_capacity(cap.set().arms().len());
    let mut pairs = Vec::with_capacity(cap.set().arms().len());
    for arm in cap.set().arms() {
        let HelperArm::Grant(rows) = arm else {
            return Err(HelperRefusal::CapByParentOrWalk {
                function: function.to_string(),
                cap: name,
            });
        };
        unjoined(&name, rows)?;
        if let Some(nested) = rows.caps().first() {
            return Err(HelperRefusal::CappedCap {
                function: function.to_string(),
                cap: name,
                nested: nested.function().target_name().to_string(),
            });
        }
        let paired_arm = helper_grant(&name, rows, rows.columns(), db, registry)?;
        if let Some(caller) = &paired_arm.carried_caller {
            return Err(HelperRefusal::GateOnUnsetCaller {
                function: name,
                setting: caller.setting_key().to_string(),
                reason: UnsetCallerGateRefusal::CapArm,
            });
        }
        arms.push(paired_arm);
        pairs.push(rows);
    }
    let paired = PairedCap {
        function,
        cap: &name,
        grant,
        pairs: &pairs,
    };
    let link = paired.held_link(cap.operands(), db)?;
    let lift = cap
        .lift()
        .map(|lift| lifting_source(function, lift, registry))
        .transpose()?;
    Ok(HelperCap {
        arguments: cap.arguments().iter().map(ToString::to_string).collect(),
        function: name,
        arms,
        link,
        lift,
    })
}

/// The declared value whose absence lifts a cap, read only through `NULLIF(<read>, '')`
/// with `missing_ok`, which reads both states of an unset setting as `NULL`.
fn lifting_source(
    function: &str,
    lift: &CapLift<'_>,
    registry: &FunctionRegistry,
) -> Result<DeclaredSource, HelperRefusal> {
    let setting = lift.setting().name();
    let refusal = |reason: LiftRefusal| HelperRefusal::Lift {
        function: function.to_string(),
        setting: setting.to_string(),
        reason,
    };
    if lift.raises_when_unset() {
        return Err(refusal(LiftRefusal::RaisesWhenUnset));
    }
    if !lift.lifts_on_empty() {
        return Err(refusal(LiftRefusal::ReadBare));
    }
    registry
        .declared_source(setting, &[])
        .filter(|source| source.is_scalar() && source.may_be_unset())
        .cloned()
        .ok_or_else(|| refusal(LiftRefusal::NotMaybeUnset))
}

/// `caps` on the level's row where none needs more of a row than the level's row names and
/// no row is held for its joins, and on each held row otherwise, the arm's rows then held by
/// their key, refused where no key names each of them.
fn place_caps<DB: DatabaseLike>(
    function: &str,
    grant: &GrantArm<'_, DB>,
    object: &DB::Column,
    caps: Vec<HelperCap>,
    held: Option<HeldRows>,
    db: &DB,
) -> Result<(Vec<HelperCap>, Option<HeldRows>), HelperRefusal> {
    if held.is_some() || caps.is_empty() {
        return Ok((caps, held));
    }
    let table = table_identity(grant.table());
    let object = ColumnName::from_stored(object.stored_column_name());
    let keyed = row_uniquely_keys(&table, &[&object], db);
    let shapes: Option<Vec<LevelShape>> = caps
        .iter()
        .map(|cap| level_shape(&cap.link, &object, keyed))
        .collect();
    if let Some(shapes) = shapes {
        let caps = caps
            .into_iter()
            .zip(shapes)
            .map(|(cap, shape)| leveled(cap, shape))
            .collect();
        return Ok((caps, None));
    }
    let Some(identity) = resolve_row_identity(&table, db) else {
        let (column, cap) = caps
            .into_iter()
            .find(|cap| level_shape(&cap.link, &object, keyed).is_none())
            .map_or_else(Default::default, |cap| {
                (paired_column(&cap.link, &object), cap.function)
            });
        return Err(HelperRefusal::CapOnSeveralRows {
            function: function.to_string(),
            table: table.to_string(),
            column,
            cap,
        });
    };
    Ok((
        caps,
        Some(HeldRows {
            identity,
            joined: Vec::new(),
            blocked: Vec::new(),
        }),
    ))
}

/// How a cap linked from the held row reads on the level's row instead.
#[derive(Clone, Copy)]
enum LevelShape {
    /// Its columns name the pair on the arm's own row, which names one row of the level.
    Row,
    /// Its literals beside the column at this position, the level's row, name the pairs.
    Pair(usize),
}

/// How `link` reads on the level's row, `None` where it needs more of the arm's row than
/// `object` names: columns of the arm's own row name the pair where `object` keys the table
/// or every operand is `object`, and literals beside `object` alone name the pairs whose
/// column at its position holds the level's row.
fn level_shape(link: &CapLink, object: &ColumnName, keyed: bool) -> Option<LevelShape> {
    let CapLink::Held {
        reader: CapReader::Arm,
        columns,
        literals,
    } = link
    else {
        return None;
    };
    if literals.is_empty() {
        return (keyed || columns.iter().all(|(_, column)| column == object))
            .then_some(LevelShape::Row);
    }
    match columns.as_slice() {
        [(position, column)] if column == object => Some(LevelShape::Pair(*position)),
        _ => None,
    }
}

/// `cap` linked from the level's row as `shape` reads it.
fn leveled(cap: HelperCap, shape: LevelShape) -> HelperCap {
    let link = match (cap.link, shape) {
        (CapLink::Held { columns, .. }, LevelShape::Row) => CapLink::Row {
            columns: columns.into_iter().map(|(_, column)| column).collect(),
        },
        (CapLink::Held { literals, .. }, LevelShape::Pair(object)) => {
            CapLink::Pair { object, literals }
        }
        (link, _) => link,
    };
    HelperCap { link, ..cap }
}

/// The column `link` pairs beside `object`, or `object` itself where it pairs no other.
fn paired_column(link: &CapLink, object: &ColumnName) -> String {
    let CapLink::Held { columns, .. } = link else {
        return object.to_string();
    };
    columns
        .iter()
        .map(|(_, column)| column)
        .find(|column| *column != object)
        .unwrap_or(object)
        .to_string()
}

/// A column operand of a held row's cap.
struct HeldOperand<'a, 'db, DB: DatabaseLike> {
    /// Its position among the cap's operands.
    position: usize,
    /// The joined row it is read from beside that row's index, `None` for the held row.
    joined: Option<(usize, &'a JoinedRow<'db, DB>)>,
    /// The column read.
    column: &'db DB::Column,
    /// The held row's column holding the same value, `None` where no join equates one.
    own: Option<&'db DB::Column>,
}

/// A cap's operands beside the arms returning its pairs, for the refusals naming them.
struct PairedCap<'a, 'db, DB: DatabaseLike> {
    /// The helper whose arm the cap keeps.
    function: &'a str,
    /// The helper returning the pairs.
    cap: &'a str,
    /// The capped arm.
    grant: &'a GrantArm<'db, DB>,
    /// The cap's arms.
    pairs: &'a [&'a GrantArm<'db, DB>],
}

impl<DB: DatabaseLike> PairedCap<'_, '_, DB> {
    /// The row naming the pair each held row reaches through `operands`.
    ///
    /// That is the held row itself where every column operand is one of its columns or a
    /// joined row's column its join equates with one, and otherwise the one joined row every
    /// column operand is read from or equated with.
    fn held_link(
        &self,
        operands: &[CapOperand<'_, DB>],
        db: &DB,
    ) -> Result<CapLink, HelperRefusal> {
        let mut columns: Vec<HeldOperand<'_, '_, DB>> = Vec::with_capacity(operands.len());
        let mut literals = Vec::new();
        for (position, operand) in operands.iter().enumerate() {
            match operand {
                CapOperand::Column(column) => {
                    self.pairs_alike(self.grant.table(), column, position, db)?;
                    columns.push(HeldOperand {
                        position,
                        joined: None,
                        column,
                        own: Some(column),
                    });
                }
                CapOperand::Joined { row, column } => {
                    let joined = self.grant.joined_rows().get(*row).ok_or_else(|| {
                        HelperRefusal::CapOperand {
                            function: self.function.to_string(),
                            cap: self.cap.to_string(),
                            operand: column.column_name().to_string(),
                        }
                    })?;
                    self.pairs_alike(joined.table(), column, position, db)?;
                    let own = joined
                        .columns()
                        .iter()
                        .find(|(_, named)| same_column::<DB>(named, column))
                        .map(|(own, _)| *own);
                    if let Some(own) = own {
                        self.pairs_alike(self.grant.table(), own, position, db)?;
                    }
                    columns.push(HeldOperand {
                        position,
                        joined: Some((*row, joined)),
                        column,
                        own,
                    });
                }
                CapOperand::Value(value) => {
                    let value = literal(value).ok_or_else(|| HelperRefusal::CapOperand {
                        function: self.function.to_string(),
                        cap: self.cap.to_string(),
                        operand: value.to_string(),
                    })?;
                    literals.push((position, value));
                }
            }
        }
        if columns.is_empty() {
            return Err(HelperRefusal::CapLiteralsBeside {
                function: self.function.to_string(),
                table: table_identity(self.grant.table()).to_string(),
                cap: self.cap.to_string(),
            });
        }
        let reader = columns.iter().find_map(|operand| match operand {
            HeldOperand {
                joined: Some(joined),
                own: None,
                ..
            } => Some(*joined),
            _ => None,
        });
        let Some((read_row, reader)) = reader else {
            return Ok(CapLink::Held {
                reader: CapReader::Arm,
                columns: columns
                    .iter()
                    .filter_map(|operand| {
                        Some((
                            operand.position,
                            ColumnName::from_stored(operand.own?.stored_column_name()),
                        ))
                    })
                    .collect(),
                literals,
            });
        };
        let mut read = Vec::with_capacity(columns.len());
        for operand in columns {
            let column = if operand.joined.is_some_and(|(row, _)| row == read_row) {
                Some(operand.column)
            } else {
                operand.own.and_then(|own| {
                    reader
                        .columns()
                        .iter()
                        .find(|(equated, _)| same_column::<DB>(equated, own))
                        .map(|(_, named)| *named)
                })
            };
            let Some(column) = column else {
                let first = operand
                    .joined
                    .map_or_else(|| self.grant.table(), |(_, row)| row.table());
                return Err(HelperRefusal::CapAcrossRows {
                    function: self.function.to_string(),
                    first: table_identity(first).to_string(),
                    second: table_identity(reader.table()).to_string(),
                    cap: self.cap.to_string(),
                });
            };
            self.pairs_alike(reader.table(), column, operand.position, db)?;
            read.push((
                operand.position,
                ColumnName::from_stored(column.stored_column_name()),
            ));
        }
        Ok(CapLink::Held {
            reader: CapReader::Joined(read_row),
            columns: read,
            literals,
        })
    }

    /// Refuses `column` of `table` paired with the column at `position` of a cap arm,
    /// unless both are of one type whose text spelling decides equality, since a pair
    /// object is named by that spelling on either side.
    fn pairs_alike(
        &self,
        table: &DB::Table,
        column: &DB::Column,
        position: usize,
        db: &DB,
    ) -> Result<(), HelperRefusal> {
        let declared = column.data_type(db);
        let table = table_identity(table);
        for pairs in self.pairs {
            let Some(paired) = pairs.columns().get(position) else {
                continue;
            };
            let spelled = paired.data_type(db);
            let decides = matches!(
                column_kind(&table, &column.stored_column_name(), db),
                ColumnKind::Text
                    | ColumnKind::Bpchar
                    | ColumnKind::Uuid
                    | ColumnKind::Bool
                    | ColumnKind::Integer
                    | ColumnKind::Date
            );
            if !decides || declared.normalized_name(db) != spelled.normalized_name(db) {
                return Err(HelperRefusal::CapUnlikeTypes {
                    function: self.function.to_string(),
                    table: table.to_string(),
                    column: column.stored_column_name().into_owned(),
                    cap: self.cap.to_string(),
                    paired: paired.stored_column_name().into_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Whether `left` and `right`, columns of one table, are the same column.
fn same_column<DB: DatabaseLike>(left: &DB::Column, right: &DB::Column) -> bool {
    left.stored_column_name() == right.stored_column_name()
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
