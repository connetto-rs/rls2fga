//! A `LANGUAGE sql` body selecting what a PL/pgSQL function's output parameters hold.
//!
//! `SELECT id FROM authz.acting_installation()` reads the one row a call to a function
//! returning no set hands its `FROM`, so the projection is the value of that row's
//! columns, each the output parameter of the same name. `sql-traits` answers what each
//! output holds on every request the deployment admits, and refuses a body that may raise
//! on one of them, so a validator raising on half of an identity pair reads as the setting
//! reads it guards once the deployment declares the pair set together.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::ops::ControlFlow;

use sql_traits::errors::ReturnedValuesError;
use sql_traits::structs::{ReturnedOutput, ReturnedValue};
use sqlparser::ast::{
    visit_expressions, visit_expressions_mut, ArgMode, CaseWhen, CastKind, DataType, Expr,
    InTarget, SelectItem, SetExpr, Statement, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::classifier::recognizers::projected_call_select;
use crate::parser::function_analyzer::{
    current_setting_literal_key, normalize_setting_key, setting_read_of, BodySettingRead,
};
use crate::parser::names::{stored_ident_name, stored_identifier};
use crate::parser::sql_parser::{DatabaseLike, Deployment, FunctionLike};

/// Why a body selecting what a function returns reads as no declared setting.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub(crate) enum OutputReadRefusal {
    /// `sql-traits` cannot say what the called function's outputs hold.
    #[error("selects what '{function}' returns, whose outputs are not read ({source})")]
    Unreturned {
        /// The called function.
        function: String,
        /// Why `sql-traits` refuses it.
        #[source]
        source: ReturnedValuesError,
    },
    /// The output takes its value from one of several writes, depending on the path.
    #[error("selects '{output}' of '{function}', which several assignments give")]
    Several {
        /// The called function.
        function: String,
        /// The output parameter.
        output: String,
    },
    /// The output takes its value from a write other than an assignment of an expression.
    #[error("selects '{output}' of '{function}', which no assignment of an expression gives")]
    Unread {
        /// The called function.
        function: String,
        /// The output parameter.
        output: String,
    },
    /// The body's own `SET` clause sets a setting the outputs read, so the called function
    /// reads the body's value rather than the request's.
    #[error("sets '{setting}' itself, which '{function}' reads")]
    SetsRead {
        /// The called function.
        function: String,
        /// The setting.
        setting: String,
    },
    /// `CASE WHEN <tested> IS NOT NULL THEN <read> END` hands over `read` only where the
    /// request carries `tested`, which is `read` itself only where the two are set
    /// together.
    #[error(
        "returns '{read}' only where '{tested}' is carried, and the deployment does not \
         declare the two set together"
    )]
    NotSetTogether {
        /// The setting the `WHEN` tests.
        tested: String,
        /// The setting the `THEN` reads.
        read: String,
    },
}

/// The setting read the `LANGUAGE sql` body `body` of `function` returns by selecting
/// what a zero-argument PL/pgSQL function returns, read under `deployment`.
///
/// `None` where the body selects no such output, or where what it selects reads no setting.
pub(crate) fn projected_output_read<DB: DatabaseLike>(
    db: &DB,
    function: &DB::Function,
    body: &str,
    deployment: &Deployment,
) -> Option<Result<BodySettingRead, OutputReadRefusal>> {
    let ProjectedCall {
        mut projection,
        call,
        qualifier,
    } = projected_call(body)?;
    let called = called_function(db, function, &call)?;
    let name = called.target_name().to_string();
    let returned = match called.returned_values(db, deployment) {
        Ok(returned) => returned,
        Err(source) => {
            return Some(Err(OutputReadRefusal::Unreturned {
                function: name,
                source,
            }))
        }
    };
    let outputs = Outputs {
        function: &name,
        returned: &returned,
        types: output_types(db, called),
    };
    match outputs.substitute(&mut projection, &qualifier) {
        ControlFlow::Continue(()) => {}
        ControlFlow::Break(None) => return None,
        ControlFlow::Break(Some(refusal)) => return Some(Err(refusal)),
    }
    if let Some(setting) = setting_the_body_sets(function, &projection) {
        return Some(Err(OutputReadRefusal::SetsRead {
            function: name,
            setting,
        }));
    }
    if let Some(read) = setting_read_of(&projection) {
        return Some(Ok(read));
    }
    let (tested, read) = guarded_read(&projection)?;
    let tested = setting_read_of(tested).filter(|tested| tested.skips_empty)?;
    let read = setting_read_of(read).filter(|read| read.skips_empty)?;
    Some(if deployment.sets_together(&tested.key, &read.key) {
        Ok(read)
    } else {
        Err(OutputReadRefusal::NotSetTogether {
            tested: tested.key,
            read: read.key,
        })
    })
}

/// The one expression a body projects over the row a call in its `FROM` returns.
struct ProjectedCall {
    /// The projected expression.
    projection: Expr,
    /// The called function's name, each part as `PostgreSQL` stores it.
    call: Vec<String>,
    /// The name the projection reaches the call's columns by, as `PostgreSQL` stores it.
    qualifier: String,
}

/// The expression `body` projects over the one row of a call in its `FROM` passing no
/// argument, when it is one query projecting one expression and nothing narrows the row.
fn projected_call(body: &str) -> Option<ProjectedCall> {
    let mut statements = Parser::parse_sql(&PostgreSqlDialect {}, body).ok()?;
    let [Statement::Query(query)] = statements.as_mut_slice() else {
        return None;
    };
    let (select, name, qualifier) = projected_call_select(query)?;
    if !matches!(
        select.projection.as_slice(),
        [SelectItem::UnnamedExpr(_) | SelectItem::ExprWithAlias { .. }]
    ) {
        return None;
    }
    let call = name
        .0
        .iter()
        .map(|part| Some(stored_ident_name(part.as_ident()?).into_owned()))
        .collect::<Option<Vec<String>>>()?;
    let qualifier = stored_ident_name(qualifier).into_owned();
    let SetExpr::Select(select) = query.body.as_mut() else {
        return None;
    };
    let (SelectItem::UnnamedExpr(projection)
    | SelectItem::ExprWithAlias {
        expr: projection, ..
    }) = select.projection.pop()?
    else {
        return None;
    };
    Some(ProjectedCall {
        projection,
        call,
        qualifier,
    })
}

/// The one function `function`'s body reaches through the call named `call`, which
/// accepts no argument, as `PostgreSQL` resolves the call where the body runs.
fn called_function<'db, DB: DatabaseLike>(
    db: &'db DB,
    function: &DB::Function,
    call: &[String],
) -> Option<&'db DB::Function> {
    let (name, schema) = match call {
        [name] => (name, None),
        [schema, name] => (name, Some(schema)),
        _ => return None,
    };
    let mut matching = function
        .referenced_functions(db)
        .ok()?
        .into_iter()
        .filter(|candidate| {
            let target = candidate.target_name();
            candidate.accepts_argument_count(0)
                && stored_identifier(target.name(), target.name_is_quoted()) == name.as_str()
                && schema.is_none_or(|schema| {
                    target.schema().is_some_and(|written| {
                        stored_identifier(written, target.schema_is_quoted()) == schema.as_str()
                    })
                })
        });
    let called = matching.next()?;
    matching.next().is_none().then_some(called)
}

/// What a called function's outputs hold, with the type each converts its value to.
struct Outputs<'o> {
    /// The called function, as the refusals name it.
    function: &'o str,
    /// What each output holds when the function returns.
    returned: &'o [ReturnedValue],
    /// The type of each named output, by the name `PostgreSQL` stores.
    types: Vec<(String, DataType)>,
}

impl Outputs<'_> {
    /// Replace every reference in `projection` to a column of the call's row, which
    /// `qualifier` names, with what the output of that name holds.
    ///
    /// Breaks with `None` where the projection reads anything else, a subquery or a name
    /// no output answers among them, and with the refusal where an output holds no one
    /// expression.
    fn substitute(
        &self,
        projection: &mut Expr,
        qualifier: &str,
    ) -> ControlFlow<Option<OutputReadRefusal>> {
        let scoped = visit_expressions(projection, |expr| match expr {
            Expr::Subquery(_)
            | Expr::Exists { .. }
            | Expr::In {
                target: InTarget::Subquery(_),
                ..
            } => ControlFlow::Break(()),
            _ => ControlFlow::Continue(()),
        });
        if scoped.is_break() {
            return ControlFlow::Break(None);
        }
        visit_expressions_mut(projection, |expr| {
            let column = match expr {
                Expr::Identifier(column) => column,
                Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                    [table, column] if stored_ident_name(table) == qualifier => column,
                    _ => return ControlFlow::Break(None),
                },
                _ => return ControlFlow::Continue(()),
            };
            let output = {
                let name = stored_ident_name(column);
                self.returned.iter().find(|output| output.name() == name)
            };
            let Some(output) = output else {
                return ControlFlow::Break(None);
            };
            *expr = self.assigned_value(output)?;
            ControlFlow::Continue(())
        })
    }

    /// What `output` holds, converted to its declared type as `PL/pgSQL` converts every
    /// value it assigns.
    fn assigned_value(
        &self,
        output: &ReturnedValue,
    ) -> ControlFlow<Option<OutputReadRefusal>, Expr> {
        let held = match output.output() {
            ReturnedOutput::Expression(expression) => expression.as_ref().clone(),
            ReturnedOutput::Null => Expr::value(Value::Null),
            ReturnedOutput::Several => {
                return ControlFlow::Break(Some(OutputReadRefusal::Several {
                    function: self.function.to_string(),
                    output: output.name().to_string(),
                }))
            }
            ReturnedOutput::Unread => {
                return ControlFlow::Break(Some(OutputReadRefusal::Unread {
                    function: self.function.to_string(),
                    output: output.name().to_string(),
                }))
            }
        };
        let Some((_, data_type)) = self.types.iter().find(|(name, _)| name == output.name()) else {
            return ControlFlow::Break(None);
        };
        ControlFlow::Continue(Expr::Cast {
            kind: CastKind::DoubleColon,
            expr: Box::new(held),
            data_type: data_type.clone(),
            format: None,
        })
    }
}

/// The type of each named output parameter of `function`, by the name `PostgreSQL`
/// stores.
fn output_types<DB: DatabaseLike>(db: &DB, function: &DB::Function) -> Vec<(String, DataType)> {
    function
        .argument_modes()
        .zip(function.stored_argument_names(db))
        .zip(function.argument_type_names(db))
        .filter(|((mode, _), _)| matches!(mode, ArgMode::Out | ArgMode::InOut))
        .filter_map(|((_, name), type_name)| {
            let data_type = Parser::new(&PostgreSqlDialect {})
                .try_with_sql(&type_name)
                .and_then(|mut parser| parser.parse_data_type())
                .ok()?;
            Some((name?.into_owned(), data_type))
        })
        .collect()
}

/// A setting `expr` reads that the `SET` clause of `function` sets, which the function
/// then reads in place of the request's value.
fn setting_the_body_sets<F: FunctionLike>(function: &F, expr: &Expr) -> Option<String> {
    let configured: Vec<String> = function
        .configuration_parameters()
        .iter()
        .map(|parameter| normalize_setting_key(&parameter.name.to_string()))
        .collect();
    let mut set = None;
    let _ = visit_expressions(expr, |node| match current_setting_literal_key(node) {
        Some(key) if configured.contains(&key) => {
            set = Some(key);
            ControlFlow::Break(())
        }
        _ => ControlFlow::Continue(()),
    });
    set
}

/// The tested and the returned value of `CASE WHEN <tested> IS NOT NULL THEN <read> END`.
fn guarded_read(expr: &Expr) -> Option<(&Expr, &Expr)> {
    let Expr::Case {
        operand: None,
        conditions,
        else_result: None,
        ..
    } = expr
    else {
        return None;
    };
    let [CaseWhen {
        condition: Expr::IsNotNull(tested),
        result,
    }] = conditions.as_slice()
    else {
        return None;
    };
    Some((tested, result))
}
