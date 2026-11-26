//! A value compared with a scalar subquery selecting one column of one table, read as
//! membership in the rows the subquery selects once the schema proves it selects at most
//! one.
//!
//! A scalar subquery hands the comparison its one row, `NULL` where it selects none, and
//! fails the statement where it selects several. `x = (SELECT k FROM t WHERE p)` therefore
//! agrees with `x IN (SELECT k FROM t WHERE p)` exactly where at most one row of `t`
//! satisfies `p`, which a unique key of `t` that `p` pins to values no row decides proves.

use super::*;
use crate::parser::names::{lookup_table, stored_ident_name};
use crate::parser::sql_parser::{ConstraintDeferral, IndexLike, TableIndexLike};
use sql_traits::utils::normalize_postgres_type;

/// Why a comparison with a lookup is not read as membership in the rows it selects.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LookupRefusal {
    #[error(
        "The lookup compared with a value binds names in a WITH clause, so a name in its \
         FROM may be that binding rather than the table it looks like"
    )]
    BindsItsOwnNames,
    #[error(
        "The lookup compared with a value keeps only some of the rows its filter selects \
         through {clause}, which a membership in those rows does not read"
    )]
    Shaped { clause: &'static str },
    #[error(
        "The lookup reads '{table}', whose inheriting tables a scan of it reads too and may \
         repeat its keys, so it may select more than one row"
    )]
    Inherited { table: String },
    #[error(
        "The lookup may select more than one row of '{table}', since its filter pins no \
         unique key of it to values no row decides"
    )]
    NoKey { table: String },
    #[error(
        "The lookup may select more than one row of '{table}', since two alternatives of \
         its filter can both hold, and only one of them testing a value for NULL that the \
         other requires present keeps them apart"
    )]
    Overlapping { table: String },
    #[error(
        "The lookup selects '{column}' of type {column_type} and hands it over as \
         {returned}, a cast that may rename the value"
    )]
    Retyped {
        column: String,
        column_type: String,
        returned: String,
    },
}

/// `x = (SELECT k FROM t WHERE p)`, in either operand order, as `x IN (SELECT k FROM t
/// WHERE p)` where at most one row of `t` satisfies `p`, or why it may select more.
///
/// `returned` is the type a function returning the lookup's value declares, which the
/// selected column must already have.
///
/// `None` where `expr` compares no such subquery, so the blame the comparison already
/// earns stands.
///
/// The proof reads each alternative of `p` as pinning a unique key of `t` to values that
/// read no row of it, and any two alternatives as kept apart by one testing such a value
/// `IS NULL` where the other tests it `IS NOT NULL` or pins a column to it. Each such value
/// is read once per statement, since a volatile read could differ between the
/// alternatives. A request value or a row column is all the comparison translates to, so a
/// volatile read leaves the membership refused.
pub(crate) fn single_row_lookup<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    returned: Option<&str>,
) -> Option<Result<Expr, LookupRefusal>> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };
    let (value, query) = match (unparenthesize(left), unparenthesize(right)) {
        (_, Expr::Subquery(query)) if !matches!(unparenthesize(left), Expr::Subquery(_)) => {
            (left, query)
        }
        (Expr::Subquery(query), _) if !matches!(unparenthesize(right), Expr::Subquery(_)) => {
            (right, query)
        }
        _ => return None,
    };
    let lookup = Lookup::of(query, db)?;
    Some(
        lookup
            .keeps_type(returned, db)
            .and_then(|()| lookup.proves_one_row(db))
            .map(|()| Expr::In {
                expr: value.clone(),
                target: InTarget::Subquery(query.clone()),
                negated: false,
                global: false,
            }),
    )
}

/// The one table a lookup reads, the name its filter qualifies columns with, the column it
/// selects, and the filter.
struct Lookup<'q, 'db, DB: DatabaseLike> {
    table: &'db DB::Table,
    qualifier: String,
    selected: String,
    filter: Option<&'q Expr>,
    binds_names: bool,
    shaping: Option<&'static str>,
}

impl<'q, 'db, DB: DatabaseLike> Lookup<'q, 'db, DB> {
    /// The lookup `query` is, where it projects one column of the one table it reads under
    /// that table's own column names.
    fn of(query: &'q Query, db: &'db DB) -> Option<Self> {
        let select = query_select(query)?;
        let [TableWithJoins { relation, joins }] = select.from.as_slice() else {
            return None;
        };
        let TableFactor::Table {
            name,
            alias,
            args: None,
            ..
        } = relation
        else {
            return None;
        };
        if !joins.is_empty() {
            return None;
        }
        let table = lookup_table(db, &name.to_string())?;
        let qualifier = match alias {
            Some(TableAlias { columns, .. }) if !columns.is_empty() => return None,
            Some(TableAlias { name, .. }) => stored_ident_name(name).into_owned(),
            None => table.stored_table_name().into_owned(),
        };
        let [SelectItem::UnnamedExpr(projected)
        | SelectItem::ExprWithAlias {
            expr: projected, ..
        }] = select.projection.as_slice()
        else {
            return None;
        };
        let mut lookup = Self {
            table,
            qualifier,
            selected: String::new(),
            filter: select.selection.as_ref(),
            binds_names: query_binds_its_own_names(query),
            shaping: set_limiting_clause(query).or_else(|| select_result_shaping_clause(select)),
        };
        lookup.selected = lookup.column(projected, db)?;
        Some(lookup)
    }

    fn table_name(&self) -> String {
        self.table.stored_table_name().into_owned()
    }

    /// Whether handing the selected column over as `returned` keeps its value.
    fn keeps_type(&self, returned: Option<&str>, db: &DB) -> Result<(), LookupRefusal> {
        let Some(returned) = returned else {
            return Ok(());
        };
        let returned = normalize_postgres_type(returned);
        let column_type = self
            .table
            .columns(db)
            .into_iter()
            .flatten()
            .find(|column| column.stored_column_name() == self.selected)
            .map(|column| column.data_type(db).normalized_name(db).into_owned());
        if column_type.as_deref() == Some(returned.as_ref()) {
            return Ok(());
        }
        Err(LookupRefusal::Retyped {
            column: self.selected.clone(),
            column_type: column_type.unwrap_or_else(|| "unknown".to_string()),
            returned: returned.into_owned(),
        })
    }

    /// Whether the lookup selects at most one row.
    fn proves_one_row(&self, db: &DB) -> Result<(), LookupRefusal> {
        if self.binds_names {
            return Err(LookupRefusal::BindsItsOwnNames);
        }
        if let Some(clause) = self.shaping {
            return Err(LookupRefusal::Shaped { clause });
        }
        if self
            .table
            .inheritors(db)
            .into_iter()
            .flatten()
            .next()
            .is_some()
        {
            return Err(LookupRefusal::Inherited {
                table: self.table_name(),
            });
        }
        match self.filter {
            Some(filter) => self.selects_one_row(filter, db),
            None => Err(LookupRefusal::NoKey {
                table: self.table_name(),
            }),
        }
    }

    /// Whether at most one row satisfies `filter`, because its conjuncts pin a unique key
    /// or one of them is a disjunction whose alternatives each do and exclude one another.
    fn selects_one_row(&self, filter: &Expr, db: &DB) -> Result<(), LookupRefusal> {
        let conjuncts = split(filter, BinaryOperator::And);
        if self.pins_unique_key(&conjuncts, db) {
            return Ok(());
        }
        let mut refusal = None;
        for conjunct in &conjuncts {
            let alternatives = split(conjunct, BinaryOperator::Or);
            if alternatives.len() < 2 {
                continue;
            }
            let outcome = alternatives
                .iter()
                .try_for_each(|alternative| self.selects_one_row(alternative, db))
                .and_then(|()| self.exclusive(&alternatives, db));
            match outcome {
                Ok(()) => return Ok(()),
                Err(found) => {
                    refusal.get_or_insert(found);
                }
            }
        }
        Err(refusal.unwrap_or_else(|| LookupRefusal::NoKey {
            table: self.table_name(),
        }))
    }

    /// Whether the columns `conjuncts` pin cover a unique key checked at every statement,
    /// whose every entry is a plain column and whose rows no predicate limits.
    fn pins_unique_key(&self, conjuncts: &[&Expr], db: &DB) -> bool {
        let pinned: Vec<String> = conjuncts
            .iter()
            .flat_map(|conjunct| self.pins(conjunct, db))
            .map(|(column, _)| column)
            .collect();
        self.table
            .unique_indices(db)
            .into_iter()
            .flatten()
            .filter(|index| {
                index.deferral(db) == ConstraintDeferral::NotDeferrable
                    && index.predicate().is_none()
                    && index.is_simple(db) == Ok(true)
            })
            .any(|index| {
                let mut columns = index.columns(db).into_iter().flatten().peekable();
                columns.peek().is_some()
                    && columns.all(|column| {
                        pinned
                            .iter()
                            .any(|pinned| *pinned == column.stored_column_name())
                    })
            })
    }

    /// Whether every two of `alternatives` exclude one another.
    fn exclusive(&self, alternatives: &[&Expr], db: &DB) -> Result<(), LookupRefusal> {
        let facts: Vec<(Vec<&Expr>, Vec<&Expr>)> = alternatives
            .iter()
            .map(|alternative| self.nullness(alternative, db))
            .collect();
        let apart = |absent: &[&Expr], present: &[&Expr]| {
            absent.iter().any(|value| present.contains(value))
        };
        for (index, (absent, present)) in facts.iter().enumerate() {
            for (other_absent, other_present) in facts.iter().skip(index + 1) {
                if !apart(absent, other_present) && !apart(other_absent, present) {
                    return Err(LookupRefusal::Overlapping {
                        table: self.table_name(),
                    });
                }
            }
        }
        Ok(())
    }

    /// The values reading no row that `alternative` requires `NULL`, and those it requires
    /// present, through a test or by pinning a column to them.
    fn nullness<'e>(&self, alternative: &'e Expr, db: &DB) -> (Vec<&'e Expr>, Vec<&'e Expr>) {
        let mut absent = Vec::new();
        let mut present = Vec::new();
        for conjunct in split(alternative, BinaryOperator::And) {
            match conjunct {
                Expr::IsNull(value) if !self.reads_row(value, db) => {
                    absent.push(unparenthesize(value));
                }
                Expr::IsNotNull(value) if !self.reads_row(value, db) => {
                    present.push(unparenthesize(value));
                }
                _ => present.extend(self.pins(conjunct, db).into_iter().map(|(_, value)| value)),
            }
        }
        (absent, present)
    }

    /// Each column of the table `conjunct` sets equal to a value reading no row of it,
    /// with that value, row comparisons read element by element.
    fn pins<'e>(&self, conjunct: &'e Expr, db: &DB) -> Vec<(String, &'e Expr)> {
        let pairs: Vec<(&'e Expr, &'e Expr)> = match unparenthesize(conjunct) {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => match (unparenthesize(left), unparenthesize(right)) {
                (Expr::Tuple(lefts), Expr::Tuple(rights)) if lefts.len() == rights.len() => {
                    lefts.iter().zip(rights).collect()
                }
                (left, right) => vec![(left, right)],
            },
            _ => Vec::new(),
        };
        pairs
            .into_iter()
            .flat_map(|(left, right)| [(left, right), (right, left)])
            .filter_map(|(column, value)| {
                let column = self.column(column, db)?;
                (!self.reads_row(value, db)).then(|| (column, unparenthesize(value)))
            })
            .collect()
    }

    /// The column of the table `expr` names, bare or qualified with the lookup's name.
    fn column(&self, expr: &Expr, db: &DB) -> Option<String> {
        let ident = match unparenthesize(expr) {
            Expr::Identifier(ident) => ident,
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [qualifier, column] if stored_ident_name(qualifier) == self.qualifier => column,
                _ => return None,
            },
            _ => return None,
        };
        let name = stored_ident_name(ident);
        self.declares(&name, db).then(|| name.into_owned())
    }

    fn declares(&self, column: &str, db: &DB) -> bool {
        self.table
            .columns(db)
            .into_iter()
            .flatten()
            .any(|declared| declared.stored_column_name() == column)
    }

    /// Whether `expr` may read a row of the table, through a bare name it declares, the
    /// whole row, or a name qualified anywhere with the lookup's name or the table's.
    fn reads_row(&self, expr: &Expr, db: &DB) -> bool {
        let table_name = self.table.stored_table_name();
        let names_table = |ident: &Ident| {
            let name = stored_ident_name(ident);
            name == self.qualifier || name == table_name
        };
        sqlparser::ast::visit_expressions(expr, |node| {
            let reads = match node {
                Expr::Identifier(ident) => {
                    names_table(ident) || self.declares(&stored_ident_name(ident), db)
                }
                Expr::CompoundIdentifier(parts) => parts
                    .split_last()
                    .is_some_and(|(_, path)| path.iter().any(names_table)),
                _ => false,
            };
            if reads {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .is_break()
    }
}

/// The operands `expr` joins with `operator` at its top, through parentheses.
fn split(expr: &Expr, operator: BinaryOperator) -> Vec<&Expr> {
    match unparenthesize(expr) {
        Expr::BinaryOp { left, op, right } if *op == operator => {
            let mut operands = split(left, operator.clone());
            operands.extend(split(right, operator));
            operands
        }
        other => vec![other],
    }
}
