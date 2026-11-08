//! The casts a catalog answers around the date and time literals of a policy clause.
//!
//! `PostgreSQL` reads a literal compared with a column as the column's type when it creates
//! the policy, and stores it as that value cast to that type. Comparing the column with the
//! uncast value reads it as the same type again, so the clause means what it did.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;
use core::ops::ControlFlow;

use sql_traits::utils::scalar_family::ScalarFamily;
use sqlparser::ast::{
    helpers::attached_token::AttachedToken, BinaryOperator, DataType, Expr, GroupByExpr, Ident,
    InTarget, ObjectName, Query, Select, SelectFlavor, SetExpr, TableFactor, TableWithJoins,
    TimezoneInfo, Value, ValueWithSpan, Visit, VisitMut, Visitor, VisitorMut,
};

use crate::parser::expr::peel_noting_casts;
use crate::parser::sql_parser::{
    ColumnDefinition, ColumnDefinitionScope, ColumnLike, ColumnScope, DataTypeLike, DatabaseLike,
    IdentifierCase, TableLike,
};

/// The most fractional digits of a second `PostgreSQL` keeps.
const MAX_PRECISION: u64 = 6;

/// The date or timestamp type a comparison reads its operands as.
///
/// An operator takes its operands without a type modifier, so a column declared
/// `timestamp(0)` compares as `timestamp`, and a literal compared with it keeps its digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Temporal {
    Date,
    Timestamp { zone: bool },
}

impl Temporal {
    /// The type a cast reads its literal as, `None` when a precision rounds the literal.
    fn of_cast(data_type: &DataType) -> Option<Self> {
        match data_type {
            DataType::Date => Some(Self::Date),
            DataType::Timestamp(precision, zone)
                if precision.is_none_or(|digits| digits >= MAX_PRECISION) =>
            {
                Some(Self::Timestamp {
                    zone: matches!(zone, TimezoneInfo::WithTimeZone | TimezoneInfo::Tz),
                })
            }
            _ => None,
        }
    }

    fn of_column<DB: DatabaseLike>(column: &DB::Column, db: &DB) -> Option<Self> {
        match column.data_type(db).scalar_family(db)? {
            ScalarFamily::Date => Some(Self::Date),
            ScalarFamily::Timestamp => Some(Self::Timestamp { zone: false }),
            ScalarFamily::TimestampTz => Some(Self::Timestamp { zone: true }),
            _ => None,
        }
    }
}

/// `clause` on `table` with every quoted literal cast to the type of the column it is
/// compared with read uncast, as `PostgreSQL` reads it against that column.
///
/// A cast to another type or zone is kept, since `PostgreSQL` converts across those when
/// the query runs, and so is one whose precision rounds the literal.
pub(crate) fn without_column_type_casts<DB: DatabaseLike>(
    clause: &Expr,
    table: &DB::Table,
    db: &DB,
) -> Expr {
    if !holds_temporal_cast(clause) {
        return clause.clone();
    }
    let mut query = wrapping_query::<DB>(clause.clone(), table);
    let marked = match ColumnScope::from_query(&query, db, IdentifierCase::AsWritten) {
        Ok(scope) => {
            let mut finder = Finder {
                scope: &scope,
                selects: Vec::new(),
                marked: BTreeSet::new(),
            };
            let walk = Visit::visit(&query, &mut finder);
            debug_assert!(walk.is_continue(), "the search never breaks");
            finder.marked
        }
        Err(_) => return clause.clone(),
    };
    if marked.is_empty() {
        return clause.clone();
    }
    let walk = VisitMut::visit(&mut query, &mut Uncast { marked: &marked });
    debug_assert!(walk.is_continue(), "the rewrite never breaks");
    let mut rewritten = Expr::Value(Value::Null.with_empty_span());
    let walk = VisitMut::visit(
        &mut query,
        &mut Restore {
            target: &mut rewritten,
        },
    );
    debug_assert!(
        walk.is_break(),
        "the clause is the wrapper query's first expression"
    );
    rewritten
}

/// The type a quoted literal is cast to once, when it is a date or timestamp type.
fn cast_literal_type(expr: &Expr) -> Option<Temporal> {
    let mut casts = 0_usize;
    let mut outermost = None;
    let peeled = peel_noting_casts(expr, |data_type| {
        casts += 1;
        outermost.get_or_insert(data_type);
    });
    let Expr::Value(ValueWithSpan {
        value: Value::SingleQuotedString(_),
        ..
    }) = peeled
    else {
        return None;
    };
    if casts != 1 {
        return None;
    }
    Temporal::of_cast(outermost?)
}

fn holds_temporal_cast(clause: &Expr) -> bool {
    struct Holds;
    impl Visitor for Holds {
        type Break = ();

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            if cast_literal_type(expr).is_some() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
    }
    Visit::visit(clause, &mut Holds).is_break()
}

/// `SELECT FROM table WHERE clause`, the query whose scopes resolve the clause's columns.
fn wrapping_query<DB: DatabaseLike>(clause: Expr, table: &DB::Table) -> Query {
    let ident = |value: &str, quoted: bool| Ident {
        value: value.to_string(),
        quote_style: quoted.then_some('"'),
        span: sqlparser::tokenizer::Span::empty(),
    };
    let mut name = Vec::with_capacity(2);
    if let Some(schema) = table.table_schema() {
        name.push(ident(schema, table.table_schema_is_quoted()));
    }
    name.push(ident(table.table_name(), table.table_name_is_quoted()));
    let from = TableWithJoins {
        relation: TableFactor::Table {
            name: ObjectName::from(name),
            alias: None,
            args: None,
            with_hints: Vec::new(),
            version: None,
            with_ordinality: false,
            partitions: Vec::new(),
            json_path: None,
            sample: None,
            index_directives: Vec::new(),
            inheritance: None,
        },
        joins: Vec::new(),
    };
    let select = Select {
        select_token: AttachedToken::empty(),
        optimizer_hints: Vec::new(),
        distinct: None,
        select_modifiers: None,
        top: None,
        top_before_distinct: false,
        projection: Vec::new(),
        exclude: None,
        into: None,
        from: vec![from],
        lateral_views: Vec::new(),
        prewhere: None,
        selection: Some(clause),
        connect_by: Vec::new(),
        group_by: GroupByExpr::Expressions(Vec::new(), Vec::new()),
        cluster_by: Vec::new(),
        distribute_by: Vec::new(),
        sort_by: Vec::new(),
        having: None,
        named_window: Vec::new(),
        qualify: None,
        window_before_qualify: false,
        value_table_mode: None,
        flavor: SelectFlavor::Standard,
    };
    Query {
        with: None,
        body: Box::new(SetExpr::Select(Box::new(select))),
        order_by: None,
        limit_clause: None,
        fetch: None,
        locks: Vec::new(),
        for_clause: None,
        settings: None,
        format_clause: None,
        pipe_operators: Vec::new(),
    }
}

/// Finds the literals cast to the type of the column they are compared with.
struct Finder<'s, 'q, 'db, DB: DatabaseLike> {
    scope: &'s ColumnScope<'q, 'db, DB>,
    /// The scope of each select the walk is inside, innermost last.
    selects: Vec<Option<ColumnDefinitionScope<'s, 'q, 'db, DB>>>,
    marked: BTreeSet<*const Expr>,
}

impl<DB: DatabaseLike> Finder<'_, '_, '_, DB> {
    fn mark_against<'e>(&mut self, column: &Expr, literals: impl IntoIterator<Item = &'e Expr>) {
        let Some(column) = self.column_type(column) else {
            return;
        };
        for literal in literals {
            if cast_literal_type(literal) == Some(column) {
                self.marked.insert(core::ptr::from_ref(literal));
            }
        }
    }

    fn column_type(&self, reference: &Expr) -> Option<Temporal> {
        let reference = match reference {
            Expr::Nested(inner) => inner.as_ref(),
            other => other,
        };
        if !matches!(reference, Expr::Identifier(_) | Expr::CompoundIdentifier(_)) {
            return None;
        }
        let select = self.selects.last()?.as_ref()?;
        match select.resolve_column_definition(reference) {
            Ok(Some(ColumnDefinition::Base {
                column, database, ..
            })) => Temporal::of_column(column, database),
            _ => None,
        }
    }
}

impl<DB: DatabaseLike> Visitor for Finder<'_, '_, '_, DB> {
    type Break = ();

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        self.selects.push(self.scope.scope_for_select(select));
        ControlFlow::Continue(())
    }

    fn post_visit_select(&mut self, _select: &Select) -> ControlFlow<Self::Break> {
        self.selects.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        match expr {
            Expr::BinaryOp {
                left,
                op:
                    BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq
                    | BinaryOperator::Gt
                    | BinaryOperator::GtEq,
                right,
            }
            | Expr::IsDistinctFrom(left, right)
            | Expr::IsNotDistinctFrom(left, right) => {
                self.mark_against(left, [right.as_ref()]);
                self.mark_against(right, [left.as_ref()]);
            }
            Expr::Between {
                expr: subject,
                low,
                high,
                ..
            } => self.mark_against(subject, [low.as_ref(), high.as_ref()]),
            Expr::In {
                expr: subject,
                target: InTarget::List(list),
                ..
            } => self.mark_against(subject, list),
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

/// Replaces each marked cast with the literal it wraps.
struct Uncast<'m> {
    marked: &'m BTreeSet<*const Expr>,
}

impl VisitorMut for Uncast<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        if self.marked.contains(&core::ptr::from_ref(&*expr)) {
            *expr = peel_noting_casts(expr, |_| {}).clone();
        }
        ControlFlow::Continue(())
    }
}

/// Swaps `target` with the first expression a walk meets, which in the wrapper query is
/// its clause, and stops.
struct Restore<'t> {
    target: &'t mut Expr,
}

impl VisitorMut for Restore<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        core::mem::swap(self.target, expr);
        ControlFlow::Break(())
    }
}
