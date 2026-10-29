//! Whether a residual conjunct answers every caller alike.
//!
//! The loader answers once, as itself, so precomputing is safe only where the answer does
//! not depend on who asks.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::cmp::Ordering;
use core::ops::ControlFlow;
use sqlparser::ast::{
    BinaryOperator, Expr, Ident, InTarget, ObjectName, ObjectNamePart, Query, SelectItem, SetExpr,
    TableFactor, Value, Visit, VisitMut, Visitor, VisitorMut,
};

use super::attribute::{attribute_operator, ROW_PURE_FUNCTIONS};
use super::subquery::{
    query_binds_its_own_names, select_result_shaping_clause, set_limiting_clause,
};
use super::{unparenthesize, unwrap_cast_or_nested};
use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::readability::{table_readability, TableReadability};
use crate::generator::unrestricted::row_level_security_is_off;
use crate::parser::expr::function_call;
use crate::parser::names::{
    builtin_function_name, is_current_user_keyword_name, lookup_table, stored_ident_name,
    stored_relation_name, table_identity,
};
use crate::parser::sql_parser::{ColumnLike, DataTypeLike, DatabaseLike, TableLike};
use crate::types::TableId;

/// Aggregates whose value the rows decide without their order.
///
/// `array_agg` and `string_agg` are absent: they answer per row order.
const ORDER_FREE_AGGREGATES: &[&str] = &[
    "avg", "bool_and", "bool_or", "count", "every", "max", "min", "sum",
];

/// The scopes a membership subquery resolves its names through, the guarded table being
/// the one the generated query drops.
pub(crate) struct MembershipScope<'a> {
    /// The membership table, as the policy spells it.
    pub(crate) table: &'a str,
    /// The policy's alias for it, absent where it gave none.
    pub(crate) alias: Option<&'a str>,
    /// Its columns, as the schema stores them.
    pub(crate) columns: &'a [String],
    /// The guarded table the policy is attached to.
    pub(crate) guarded_table: &'a str,
}

/// The relations `conjunct` reads, proven to answer every caller alike, or [`None`] where
/// no such proof holds.
///
/// Empty where it reads none, which the caller still judges as before. Non-empty rewrites
/// each relation to the identity the catalog carries, so no `search_path` decides it. A
/// request-gated table reads alike only because the gate decides it, and the caller the
/// gate excludes sees it empty, so the residual must hold for no row then.
pub(crate) fn residual_relations<DB: DatabaseLike>(
    conjunct: &mut Expr,
    db: Option<&DB>,
    registry: &FunctionRegistry,
    scope: &MembershipScope<'_>,
    state: &ExpansionState,
) -> Option<Vec<TableId>> {
    let mut names = RelationNames::default();
    if Visit::visit(&*conjunct, &mut names).is_break() {
        return None;
    }
    if names.0.is_empty() {
        return Some(Vec::new());
    }
    let db = db?;
    let mut relations = BTreeSet::new();
    let mut columns = SessionColumns::default();
    if let Some(table) = lookup_table(db, scope.table) {
        columns.extend(table, db);
    }
    for name in &names.0 {
        let table = lookup_table(db, name)?;
        let identity = table_identity(table);
        if !row_level_security_is_off(table, db) {
            // Row security is on, so the caller and the loader read different rows unless the
            // table is request-gated. The caller the gate excludes sees it empty, so the
            // residual must hold for no row then, or the gate would hide rows it may read.
            if !matches!(
                table_readability(&identity, db, registry, state),
                TableReadability::RequestGated { .. }
            ) {
                return None;
            }
            if !residual_never_true_when_empty(conjunct, &identity, db) {
                return None;
            }
        }
        relations.insert(identity);
        columns.extend(table, db);
    }
    if answer_depends_on_the_asker(conjunct, registry, &columns) {
        return None;
    }
    if reaches_the_guarded_row(conjunct, db, scope) {
        return None;
    }
    if VisitMut::visit(conjunct, &mut QualifyRelations { db }).is_break() {
        return None;
    }
    Some(relations.into_iter().collect())
}

/// The columns whose type leaves part of a value to the evaluating session.
#[derive(Default)]
struct SessionColumns {
    /// Read against the session's zone and printed in its date style.
    temporal: BTreeSet<String>,
    /// Printed to a configured precision and summed in whatever order the rows arrive.
    inexact: BTreeSet<String>,
}

impl SessionColumns {
    fn extend<DB: DatabaseLike>(&mut self, table: &DB::Table, db: &DB) {
        for column in table.columns(db).into_iter().flatten() {
            let data_type = column.data_type(db).name(db);
            let name = || column.stored_column_name().into_owned();
            if type_is_temporal(&data_type) {
                self.temporal.insert(name());
            }
            if type_is_inexact(&data_type) {
                self.inexact.insert(name());
            }
        }
    }

    /// Whether `expr` names one of `family` anywhere.
    fn named_in(expr: &Expr, family: &BTreeSet<String>) -> bool {
        struct Named<'a>(&'a BTreeSet<String>);

        impl Visitor for Named<'_> {
            type Break = ();

            fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
                let named = match expr {
                    Expr::Identifier(ident) => Some(stored_ident_name(ident)),
                    Expr::CompoundIdentifier(parts) => parts.last().map(stored_ident_name),
                    _ => None,
                };
                if named.is_some_and(|name| self.0.contains(name.as_ref())) {
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            }
        }

        expr.visit(&mut Named(family)).is_break()
    }
}

/// Type families the session's zone or date style decides part of.
const TEMPORAL_TYPES: &[&str] = &["date", "interval", "time", "timestamp"];

/// Type families whose addition is not associative, so a sum answers per row order.
const INEXACT_TYPES: &[&str] = &["double", "float", "real"];

fn type_is_temporal(data_type: &str) -> bool {
    type_family_is(data_type, TEMPORAL_TYPES)
}

fn type_is_inexact(data_type: &str) -> bool {
    type_family_is(data_type, INEXACT_TYPES)
}

fn type_family_is(data_type: &str, families: &[&str]) -> bool {
    let lowered = data_type.to_ascii_lowercase();
    let terminal = lowered
        .rsplit('.')
        .next()
        .unwrap_or(&lowered)
        .trim_matches('"');
    families.iter().any(|family| terminal.starts_with(family))
}

/// Every relation named in a `FROM`, refusing non-plain tables and index directives.
///
/// A sample, a version, a derived table or a table function reads rows no flag was proven
/// about.
#[derive(Default)]
struct RelationNames(BTreeSet<String>);

impl Visitor for RelationNames {
    type Break = ();

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        let TableFactor::Table {
            name,
            args: None,
            version: None,
            sample: None,
            json_path: None,
            with_hints,
            partitions,
            index_directives,
            with_ordinality: false,
            ..
        } = factor
        else {
            return ControlFlow::Break(());
        };
        if !with_hints.is_empty() || !partitions.is_empty() || !index_directives.is_empty() {
            return ControlFlow::Break(());
        }
        self.0.insert(name.to_string());
        ControlFlow::Continue(())
    }
}

/// Whether anything in `conjunct` can answer one caller differently from another.
///
/// An allow-list throughout, so an unlisted expression or an unplaceable function refuses.
/// Types carry the rest: a cast or a column whose type the session decides part of refuses,
/// while two stored values compared against each other do not.
fn answer_depends_on_the_asker(
    conjunct: &Expr,
    registry: &FunctionRegistry,
    columns: &SessionColumns,
) -> bool {
    struct AskerDependence<'a> {
        registry: &'a FunctionRegistry,
        columns: &'a SessionColumns,
    }

    impl AskerDependence<'_> {
        fn spans_a_temporal_column_and_a_literal(&self, left: &Expr, right: &Expr) -> bool {
            let literal = |expr: &Expr| matches!(unwrap_cast_or_nested(expr), Expr::Value(_));
            let temporal = |expr: &Expr| SessionColumns::named_in(expr, &self.columns.temporal);
            (temporal(left) && literal(right)) || (temporal(right) && literal(left))
        }
    }

    impl Visitor for AskerDependence<'_> {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
            // A limit answers per evaluation, not per identity, and a binding resolves a
            // name against something the catalog never saw.
            if set_limiting_clause(query).is_some() || query_binds_its_own_names(query) {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            // A cast to a type the session decides part of, or over a column of one, reads
            // that setting however the value got there.
            if let Expr::Cast {
                expr: inner,
                data_type,
                ..
            } = expr
            {
                let rendered = data_type.to_string();
                if type_is_temporal(&rendered)
                    || type_is_inexact(&rendered)
                    || SessionColumns::named_in(inner, &self.columns.temporal)
                    || SessionColumns::named_in(inner, &self.columns.inexact)
                {
                    return ControlFlow::Break(());
                }
            }
            // A zone-less value beside a zoned column is completed by the session's zone.
            if let Some((left, right)) = comparison_operands(expr) {
                if self.spans_a_temporal_column_and_a_literal(left, right) {
                    return ControlFlow::Break(());
                }
            }
            // Neither a cast nor a parenthesis says who is asking.
            match unwrap_cast_or_nested(expr) {
                Expr::Identifier(ident) => {
                    if ident.quote_style.is_none() && is_current_user_keyword_name(&ident.value) {
                        return ControlFlow::Break(());
                    }
                }
                Expr::Value(value) => {
                    if matches!(value.value, Value::Placeholder(_)) {
                        return ControlFlow::Break(());
                    }
                }
                Expr::Function(func) => {
                    let named = builtin_function_name(func).filter(|name| {
                        ROW_PURE_FUNCTIONS.contains(&name.as_str())
                            || ORDER_FREE_AGGREGATES.contains(&name.as_str())
                    });
                    let Some(name) = named else {
                        return ControlFlow::Break(());
                    };
                    if func.over.is_some() || self.registry.get(&name).is_some() {
                        return ControlFlow::Break(());
                    }
                    // Adding inexact numbers is not associative, so a sum answers per row
                    // order and the loader's order need not be the caller's.
                    if matches!(name.as_str(), "avg" | "sum")
                        && SessionColumns::named_in(expr, &self.columns.inexact)
                    {
                        return ControlFlow::Break(());
                    }
                }
                Expr::CompoundIdentifier(_)
                | Expr::UnaryOp { .. }
                | Expr::BinaryOp { .. }
                | Expr::IsNull(_)
                | Expr::IsNotNull(_)
                | Expr::IsTrue(_)
                | Expr::IsNotTrue(_)
                | Expr::IsFalse(_)
                | Expr::IsNotFalse(_)
                | Expr::IsUnknown(_)
                | Expr::IsNotUnknown(_)
                | Expr::IsDistinctFrom(..)
                | Expr::IsNotDistinctFrom(..)
                | Expr::Between { .. }
                | Expr::In {
                    target: InTarget::List(_) | InTarget::Subquery(_),
                    ..
                }
                | Expr::AnyOp { .. }
                | Expr::AllOp { .. }
                | Expr::Like { .. }
                | Expr::ILike { .. }
                | Expr::Case { .. }
                | Expr::Tuple(_)
                | Expr::Exists { .. }
                | Expr::Subquery(_) => {}
                _ => return ControlFlow::Break(()),
            }
            ControlFlow::Continue(())
        }
    }

    conjunct
        .visit(&mut AskerDependence { registry, columns })
        .is_break()
}

/// The two sides of a comparison, absent where `expr` is not one.
fn comparison_operands(expr: &Expr) -> Option<(&Expr, &Expr)> {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            attribute_operator(op).map(|_| (left.as_ref(), right.as_ref()))
        }
        Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
            Some((left, right))
        }
        _ => None,
    }
}

/// Whether a nested query reaches the guarded row for any of its references.
///
/// The generated query scans the membership table alone and under no alias, so a name only
/// the guarded row supplies binds to nothing there. Resolution is by scope, never by
/// spelling, since a nested scan qualifies its own columns with its own table's name.
fn reaches_the_guarded_row<DB: DatabaseLike>(
    conjunct: &Expr,
    db: &DB,
    scope: &MembershipScope<'_>,
) -> bool {
    struct GuardedReference<'a, DB> {
        db: &'a DB,
        enclosing: &'a BTreeSet<String>,
        /// What each scope binds, the membership row outermost.
        scopes: Vec<QueryScope>,
    }

    impl<DB: DatabaseLike> GuardedReference<'_, DB> {
        /// Whether a qualifier resolves to a relation a scope both queries have binds.
        fn binds_relation(&self, name: &str) -> bool {
            self.scopes.iter().any(|scope| scope.names.contains(name))
        }
    }

    impl<DB: DatabaseLike> Visitor for GuardedReference<'_, DB> {
        type Break = ();

        fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
            match query_scope(query, self.db) {
                Some(scope) => self.scopes.push(scope),
                None => return ControlFlow::Break(()),
            }
            ControlFlow::Continue(())
        }

        fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
            self.scopes.pop();
            ControlFlow::Continue(())
        }

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            match expr {
                Expr::CompoundIdentifier(parts) => {
                    // The relation is the part before the column.
                    let Some(qualifier) = parts.len().checked_sub(2).and_then(|at| parts.get(at))
                    else {
                        return ControlFlow::Continue(());
                    };
                    let qualifier = stored_ident_name(qualifier);
                    if self.binds_relation(qualifier.as_ref()) {
                        return ControlFlow::Continue(());
                    }
                    if self.enclosing.contains(qualifier.as_ref()) {
                        return ControlFlow::Break(());
                    }
                }
                Expr::Identifier(ident) => {
                    let name = stored_ident_name(ident);
                    if !self
                        .scopes
                        .iter()
                        .any(|scope| scope.binds_column(name.as_ref()))
                    {
                        return ControlFlow::Break(());
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }

    // The alias is already stored, so parsing it again would split a dotted one.
    let mut enclosing: BTreeSet<String> = [scope.table, scope.guarded_table]
        .into_iter()
        .map(stored_relation_name)
        .collect();
    enclosing.extend(scope.alias.map(ToString::to_string));
    // The membership row is the outermost scope both queries have, so seeding it leaves no
    // level unresolved.
    let membership = QueryScope {
        names: BTreeSet::new(),
        columns: scope
            .columns
            .iter()
            .map(|column| (column.clone(), 1))
            .collect(),
    };
    conjunct
        .visit(&mut GuardedReference {
            db,
            enclosing: &enclosing,
            scopes: vec![membership],
        })
        .is_break()
}

/// What one query's own `FROM` binds, or [`None`] where one of its relations is not a
/// resolvable plain table.
struct QueryScope {
    /// The relation names and aliases a qualifier can resolve against here.
    names: BTreeSet<String>,
    /// How many of those relations carry each column name. A name two of them carry binds
    /// to neither, and `PostgreSQL` refuses the query rather than choosing.
    columns: BTreeMap<String, usize>,
}

impl QueryScope {
    fn binds_column(&self, name: &str) -> bool {
        self.columns.get(name) == Some(&1)
    }
}

fn query_scope<DB: DatabaseLike>(query: &Query, db: &DB) -> Option<QueryScope> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let mut scope = QueryScope {
        names: BTreeSet::new(),
        columns: BTreeMap::new(),
    };
    for item in &select.from {
        for factor in core::iter::once(&item.relation).chain(item.joins.iter().map(|j| &j.relation))
        {
            let TableFactor::Table { name, alias, .. } = factor else {
                return None;
            };
            let spelling = name.to_string();
            let table = lookup_table(db, &spelling)?;
            scope.names.insert(stored_relation_name(&spelling));
            if let Some(alias) = alias {
                scope
                    .names
                    .insert(stored_ident_name(&alias.name).into_owned());
            }
            for column in table.columns(db).into_iter().flatten() {
                *scope
                    .columns
                    .entry(column.stored_column_name().into_owned())
                    .or_default() += 1;
            }
        }
    }
    Some(scope)
}

/// Rewrite each relation reference to the identity the catalog carries, spelled as the
/// generated query spells the table it scans.
struct QualifyRelations<'db, DB> {
    db: &'db DB,
}

impl<DB: DatabaseLike> VisitorMut for QualifyRelations<'_, DB> {
    type Break = ();

    fn pre_visit_table_factor(&mut self, factor: &mut TableFactor) -> ControlFlow<()> {
        let TableFactor::Table { name, .. } = factor else {
            return ControlFlow::Break(());
        };
        let Some(table) = lookup_table(self.db, &name.to_string()) else {
            return ControlFlow::Break(());
        };
        let identity = table_identity(table);
        *name = ObjectName(vec![
            ObjectNamePart::Identifier(Ident::with_quote(
                '"',
                identity.schema().unwrap_or("public"),
            )),
            ObjectNamePart::Identifier(Ident::with_quote('"', identity.name())),
        ]);
        ControlFlow::Continue(())
    }
}

/// Whether `conjunct` is never true when `table` holds no row.
///
/// Each subquery over `table` is reduced to the value it takes on an empty table, and
/// [`never_true`] then has to prove the surrounding tree false or `NULL`. Anything the
/// evaluation cannot place is refused, which is the only outcome a wrong allow could not
/// forgive.
fn residual_never_true_when_empty<DB: DatabaseLike>(
    conjunct: &Expr,
    table: &TableId,
    db: &DB,
) -> bool {
    let mut substituted = conjunct.clone();
    let mut visitor = SubstituteEmpty {
        table,
        db,
        ok: true,
    };
    let _ = VisitMut::visit(&mut substituted, &mut visitor);
    visitor.ok && never_true(&substituted)
}

/// Reduces, in place, every subquery that reads `table` alone to the value it takes on an
/// empty table.
///
/// [`Self::ok`] turns false where a subquery joins `table` to another relation, reads a
/// relation that is not a plain table, or is not a projection the evaluation can place on
/// an empty table, which the caller reads as a refusal. A subquery that reads nothing of
/// `table` is left standing.
struct SubstituteEmpty<'a, DB> {
    table: &'a TableId,
    db: &'a DB,
    ok: bool,
}

/// A subquery the evaluation cannot place on an empty table.
struct Unplaceable;

impl<DB: DatabaseLike> SubstituteEmpty<'_, DB> {
    /// The value `query` takes when the table reads empty, `None` when it reads nothing of
    /// the table and stands as it is.
    fn placement(
        &self,
        query: &Query,
        value: impl FnOnce(&Query) -> Option<Expr>,
    ) -> Result<Option<Expr>, Unplaceable> {
        match subquery_over_table(query, self.table, self.db) {
            Some(false) => Ok(None),
            Some(true) => value(query).map(Some).ok_or(Unplaceable),
            None => Err(Unplaceable),
        }
    }
}

impl<DB: DatabaseLike> VisitorMut for SubstituteEmpty<'_, DB> {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        let placement = match expr {
            Expr::Exists { subquery, negated }
            | Expr::In {
                target: InTarget::Subquery(subquery),
                negated,
                ..
            } => {
                let negated = *negated;
                self.placement(subquery, |query| {
                    yields_no_row_when_empty(query).then(|| boolean_literal(negated))
                })
            }
            Expr::Subquery(query) => self.placement(query, scalar_empty_value),
            _ => Ok(None),
        };
        match placement {
            Ok(None) => {}
            Ok(Some(value)) => *expr = value,
            Err(Unplaceable) => {
                self.ok = false;
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }
}

/// Whether a subquery's FROM reads `table` alone.
///
/// `Some(true)` where the FROM is the single plain table `table`, `Some(false)` where it
/// reads nothing the caller's gate hides, and [`None`] where it joins `table` to another
/// relation or names a relation the evaluation cannot place.
fn subquery_over_table<DB: DatabaseLike>(query: &Query, table: &TableId, db: &DB) -> Option<bool> {
    let tables = from_tables(query, db)?;
    if !tables.contains(table) {
        return Some(false);
    }
    Some(tables.len() == 1)
}

/// The plain tables a query's FROM names, or [`None`] where one is not a plain table.
fn from_tables<DB: DatabaseLike>(query: &Query, db: &DB) -> Option<BTreeSet<TableId>> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let mut tables = BTreeSet::new();
    for item in &select.from {
        for factor in
            core::iter::once(&item.relation).chain(item.joins.iter().map(|join| &join.relation))
        {
            let TableFactor::Table {
                name,
                args: None,
                version: None,
                sample: None,
                json_path: None,
                with_hints,
                partitions,
                index_directives,
                with_ordinality: false,
                ..
            } = factor
            else {
                return None;
            };
            if !with_hints.is_empty() || !partitions.is_empty() || !index_directives.is_empty() {
                return None;
            }
            let table = lookup_table(db, &name.to_string())?;
            tables.insert(table_identity(table));
        }
    }
    Some(tables)
}

/// The value a scalar subquery over an empty table takes, or [`None`] where the evaluation
/// cannot place it.
///
/// A cast around the aggregate drops with it, since `NULL` and a numeric `0` survive it.
fn scalar_empty_value(query: &Query) -> Option<Expr> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    if select_result_shaping_clause(select).is_some() {
        return None;
    }
    let [SelectItem::UnnamedExpr(projection)] = select.projection.as_slice() else {
        return None;
    };
    if let Some(function) = function_call(projection) {
        match builtin_function_name(function).as_deref() {
            Some("count") => return Some(Expr::Value(Value::Number("0".into(), false).into())),
            Some(name) if ORDER_FREE_AGGREGATES.contains(&name) => {
                return Some(Expr::Value(Value::Null.into()));
            }
            _ => {}
        }
    }
    // Without an aggregate an empty table yields no row, which a scalar subquery reads as `NULL`.
    (!contains_aggregate(projection)).then(|| Expr::Value(Value::Null.into()))
}

/// Whether `query` yields no row when the table it reads is empty.
///
/// An aggregate or a `HAVING` can fold the empty table into one row, so
/// `EXISTS (SELECT count(*) FROM t)` holds on it.
fn yields_no_row_when_empty(query: &Query) -> bool {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return false;
    };
    select.having.is_none()
        && !contains_aggregate(&select.projection)
        && !contains_aggregate(&query.order_by)
}

/// Whether `node` calls an aggregate anywhere, which an aggregate-free check would pass.
fn contains_aggregate(node: &impl Visit) -> bool {
    struct Aggregates;

    impl Visitor for Aggregates {
        type Break = ();

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            if let Some(function) = function_call(expr) {
                if let Some(name) = builtin_function_name(function) {
                    if ORDER_FREE_AGGREGATES.contains(&name.as_str()) {
                        return ControlFlow::Break(());
                    }
                }
            }
            ControlFlow::Continue(())
        }
    }

    node.visit(&mut Aggregates).is_break()
}

fn boolean_literal(value: bool) -> Expr {
    Expr::Value(Value::Boolean(value).into())
}

/// A value the empty-set evaluation can place, or [`Self::Unknown`] where it cannot.
enum Abs {
    Null,
    Bool(bool),
    /// An integer literal, or the `0` of an empty `count`. Fractional and exponent
    /// literals stay unknown, so no comparison rests on a rounded value.
    Int(i128),
    Unknown,
}

/// Whether `expr` is provably never true, by the small evaluation the empty-set check allows.
///
/// A strict comparison is never true on a `NULL` operand or when two constants compare
/// false. A conjunct is already split from its siblings, so an `AND` never reaches here.
/// Anything else is unknown, which the caller reads as a refusal.
fn never_true(expr: &Expr) -> bool {
    match unwrap_cast_or_nested(expr) {
        Expr::BinaryOp { left, op, right } => {
            let Some(holds) = comparison(op) else {
                return false;
            };
            match (abstract_value(left), abstract_value(right)) {
                (Abs::Null, _) | (_, Abs::Null) => true,
                (Abs::Bool(left), Abs::Bool(right)) => !holds(left.cmp(&right)),
                (Abs::Int(left), Abs::Int(right)) => !holds(left.cmp(&right)),
                _ => false,
            }
        }
        Expr::Value(spanned) => matches!(&spanned.value, Value::Null | Value::Boolean(false)),
        _ => false,
    }
}

/// The constant `expr` names, or [`Abs::Unknown`] where it is a column or a value the
/// evaluation cannot place.
///
/// A cast keeps only a `NULL`, since casting a number can round it (`0.5::int` is `1`).
fn abstract_value(expr: &Expr) -> Abs {
    let Expr::Value(spanned) = unwrap_cast_or_nested(expr) else {
        return Abs::Unknown;
    };
    let uncast = matches!(unparenthesize(expr), Expr::Value(_));
    match &spanned.value {
        Value::Null => Abs::Null,
        Value::Boolean(value) if uncast => Abs::Bool(*value),
        Value::Number(number, _) if uncast => number.parse().map_or(Abs::Unknown, Abs::Int),
        _ => Abs::Unknown,
    }
}

/// What a comparison operator asks of the ordering of its two operands, or [`None`] for
/// an operator that is not a strict comparison.
fn comparison(op: &BinaryOperator) -> Option<fn(Ordering) -> bool> {
    Some(match op {
        BinaryOperator::Eq => Ordering::is_eq,
        BinaryOperator::NotEq => Ordering::is_ne,
        BinaryOperator::Lt => Ordering::is_lt,
        BinaryOperator::Gt => Ordering::is_gt,
        BinaryOperator::LtEq => Ordering::is_le,
        BinaryOperator::GtEq => Ordering::is_ge,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::sql_parser::parse_schema;
    use sqlparser::ast::Statement;
    use sqlparser::dialect::SQLiteDialect;
    use sqlparser::parser::Parser;

    #[test]
    fn sqlite_index_directives_are_not_plain_tables() {
        let db = parse_schema("CREATE TABLE t (id INT PRIMARY KEY);").unwrap();
        for (sql, plain) in [
            ("SELECT * FROM t", true),
            ("SELECT * FROM t INDEXED BY i", false),
            ("SELECT * FROM t NOT INDEXED", false),
        ] {
            let statements = Parser::parse_sql(&SQLiteDialect {}, sql).unwrap();
            let Statement::Query(query) = &statements[0] else {
                panic!("expected query");
            };
            assert_eq!(
                query.visit(&mut RelationNames::default()).is_continue(),
                plain,
                "{sql}"
            );
            assert_eq!(from_tables(query, &db).is_some(), plain, "{sql}");
        }
    }
}
