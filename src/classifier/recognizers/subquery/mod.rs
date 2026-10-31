use super::*;
use crate::classifier::expansion::ExpansionState;
use crate::classifier::function_registry::SessionAttribute;
use crate::parser::names::{lookup_table_id, resolve_table_id, table_identity};
use crate::parser::sql_parser::DataTypeLike;
use crate::types::{ColumnName, TableId};
use alloc::collections::BTreeSet;
use core::ops::ControlFlow;
use sqlparser::ast::{
    Distinct, GroupByExpr, Ident, JoinOperator, LimitClause, Query, SetExpr, TableInheritance,
    TableWithJoins, Visit, VisitMut, Visitor, VisitorMut,
};

mod indirect;
pub(crate) use indirect::owner_key_of;
pub use indirect::recognize_p19_indirect_membership;

/// Immutable visitor that gates `handle` on expressions outside nested subqueries.
struct TopLevelOnly<F> {
    depth: usize,
    descend: bool,
    handle: F,
}

impl<F: FnMut(&Expr) -> ControlFlow<()>> TopLevelOnly<F> {
    fn top_level(handle: F) -> Self {
        Self {
            depth: 0,
            descend: false,
            handle,
        }
    }
}

impl<F: FnMut(&Expr) -> ControlFlow<()>> Visitor for TopLevelOnly<F> {
    type Break = ();

    fn pre_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _: &Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if self.depth == 0 || self.descend {
            (self.handle)(expr)
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// As [`TopLevelOnly`], but for mutable traversal via [`VisitorMut`].
struct TopLevelOnlyMut<F> {
    depth: usize,
    descend: bool,
    handle: F,
}

impl<F: FnMut(&mut Expr) -> ControlFlow<()>> TopLevelOnlyMut<F> {
    fn new(descend: bool, handle: F) -> Self {
        Self {
            depth: 0,
            descend,
            handle,
        }
    }
}

impl<F: FnMut(&mut Expr) -> ControlFlow<()>> VisitorMut for TopLevelOnlyMut<F> {
    type Break = ();

    fn pre_visit_query(&mut self, _: &mut Query) -> ControlFlow<()> {
        self.depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _: &mut Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        if self.depth == 0 || self.descend {
            (self.handle)(expr)
        } else {
            ControlFlow::Continue(())
        }
    }
}

/// EXISTS membership check.
pub fn recognize_p4<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> Option<ClassifiedExpr> {
    classify_membership_select(
        readable_exists_select(expr)?,
        db,
        registry,
        outer_table,
        state,
    )
}

/// Parent inheritance via correlated EXISTS.
pub fn recognize_p5<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: PolicyCommand,
    state: &ExpansionState,
) -> Option<ClassifiedExpr> {
    let select = readable_exists_select(expr)?;
    let analysis = analyze_p5_parent_inheritance(select, db, outer_table)?;

    let mut matches = Vec::new();
    for candidate in analysis.candidates {
        let P5InheritanceCandidate {
            parent_table,
            parent_alias,
            fk_column,
            inner_predicates,
        } = candidate;
        // A join the rule never mentions still decides which rows the subquery returns,
        // so a filtering one has to be refused whether or not anything reads it.
        let rule = combine_predicates_with_and(inner_predicates);
        if !joins_drop_no_row(
            select,
            rule.as_ref(),
            &parent_table,
            parent_alias.as_deref(),
            db,
        ) {
            continue;
        }
        // No predicate of its own means the parent's own read rule is the whole
        // requirement: "you may do this over a parent row you can already see". P5 gates
        // on the parent's `can_select` regardless, so the inherited rule adds nothing.
        let inner_classified = match rule {
            Some(mut inner_expr) => {
                // Nested queries use parent alias from outer scope.
                strip_qualifier_from_expr_deep(
                    &mut inner_expr,
                    &parent_table,
                    parent_alias.as_deref(),
                );
                // What survives the strip reads a joined relation. Where the join makes
                // that reference equal to one of the parent's own columns for every row
                // the subquery returns, say so and carry on. Otherwise refuse: resolving
                // the bare name against the parent grants rows the database refuses.
                if predicate_references_other_table(&inner_expr, &parent_table, None)
                    && !rewrite_through_join(
                        &mut inner_expr,
                        select,
                        &parent_table,
                        parent_alias.as_deref(),
                        db,
                    )
                {
                    continue;
                }
                crate::classifier::policy_classifier::classify_expr_in_state(
                    &inner_expr,
                    db,
                    registry,
                    &parent_table,
                    command,
                    state,
                )
            }
            None => ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
                confidence: ConfidenceLevel::A,
            },
        };
        // Only accept relationship patterns, not attribute checks. A constant `TRUE` is
        // admitted because it is the bare delegation above, where the parent's gate is
        // the entire rule.
        if !p5_accepts_inner(&inner_classified.pattern) {
            continue;
        }
        let Some(parent_id) = resolve_table_id(db, &parent_table) else {
            continue;
        };
        // A bare delegation needs a gate behind it, and only a definite yes is one: an
        // unrestricted parent declares no relation for the walk to reach.
        if matches!(
            inner_classified.pattern,
            PatternClass::P10ConstantBool(ConstantBool { value: true })
        ) && !parent_enforces_row_security(db, &parent_id)
        {
            continue;
        }

        matches.push(ClassifiedExpr {
            confidence: inner_classified.confidence,
            pattern: PatternClass::P5ParentInheritance(ParentInheritance {
                parent_table: parent_id,
                fk_column,
                inner_pattern: Box::new(inner_classified),
            }),
        });
    }

    if matches.len() == 1 {
        return matches.into_iter().next();
    }
    None
}

/// Whether the parent positively enforces row security, which is what gives a bare
/// delegation a gate to walk to.
fn parent_enforces_row_security<DB: DatabaseLike>(db: &DB, parent: &TableId) -> bool {
    lookup_table_id(db, parent).is_some_and(|table| table.has_row_level_security(db) == Ok(true))
}

/// Whether an inherited parent rule is a relationship the P5 gate may carry.
/// Attribute checks are refused: they read the parent row rather than relate
/// the caller to it. A constant `TRUE` is the bare delegation, where the
/// parent's own gate is the entire rule.
fn p5_accepts_inner(pattern: &PatternClass) -> bool {
    match pattern {
        PatternClass::P1NumericThreshold(NumericThreshold { .. })
        | PatternClass::P2RoleNameInList(RoleNameInList { .. })
        | PatternClass::P3DirectOwnership(DirectOwnership { .. })
        | PatternClass::P4ExistsMembership(ExistsMembership { .. })
        | PatternClass::P5ParentInheritance(ParentInheritance { .. })
        | PatternClass::P7AbacAnd(AbacAnd { .. })
        | PatternClass::P8Composite(Composite { .. })
        | PatternClass::P10ConstantBool(ConstantBool { value: true }) => true,
        PatternClass::ExpandedFunction(ExpandedFunction { inner, .. }) => {
            p5_accepts_inner(&inner.pattern)
        }
        _ => false,
    }
}

/// Rewrite each reference to a joined relation into the parent's own column, where the
/// join makes the two equal for every row the subquery can return.
///
/// `SELECT o.id FROM orders o JOIN customers c ON o.customer_id = c.id WHERE c.id = $caller`
/// returns exactly the orders `WHERE o.customer_id = $caller` returns, so the second
/// spelling is the answer to the first. Two conditions make that an equality rather than
/// a resemblance, and both are required:
///
/// - The joined column is the joined table's whole primary key, so a parent row matches
///   at most one row of it and the substituted value is single.
/// - The parent's column is a declared foreign key to that table, so a parent row matches
///   at least one row of it and the join drops nothing. Without the key an orphan row
///   passes the rewritten filter and is dropped by the join, which is a wrong allow.
///
/// Returns false when any reference fails either condition, leaving `expr` untouched, so
/// the caller refuses rather than translating half a filter.
fn rewrite_through_join<DB: DatabaseLike>(
    expr: &mut Expr,
    select: &Select,
    parent_table: &str,
    parent_alias: Option<&str>,
    db: &DB,
) -> bool {
    let Some(equalities) = inner_join_equalities(select, Some(expr)) else {
        return false;
    };
    let sources = relation_sources(select);
    let Some(parent_meta) = lookup_table(db, parent_table) else {
        return false;
    };

    let mut rewrites: Vec<((String, String), Ident)> = Vec::new();
    for reference in foreign_references(expr, parent_table, parent_alias) {
        let (qualifier, column) = &reference;
        // The relation the qualifier names, so the parent's key to it can be read.
        let Some(source) = sources.iter().find(|source| {
            qualifier_matches_table(qualifier, &source.table_name, source.alias.as_deref())
        }) else {
            return false;
        };
        let Some(parent_column) = equalities.iter().find_map(|equality| {
            equality.parent_side(parent_table, parent_alias, qualifier, column.as_str())
        }) else {
            return false;
        };
        if !fk_targets_column(
            parent_meta,
            db,
            parent_column.as_str(),
            &source.table_name,
            column.as_str(),
        ) {
            return false;
        }
        rewrites.push((
            (qualifier.clone(), column.as_str().to_string()),
            Ident::new(parent_column.as_str()),
        ));
    }
    if rewrites.is_empty() {
        return false;
    }
    for ((qualifier, column), to) in rewrites {
        replace_compound_identifier(expr, (&qualifier, &column), &to);
    }
    // The comma spelling states its join in the rule, so the rewrite turns that half
    // into `x = x`. Dropping it is what makes the two spellings answer alike, and it
    // changes nothing: every shape reading a column already leaves its NULL rows out,
    // which is all `x = x` filters.
    let Some(remaining) = drop_self_equalities(expr) else {
        return false;
    };
    *expr = remaining;
    true
}

/// The rule without the `x = x` a rewrite leaves behind, or `None` when nothing else
/// remains: a subquery whose only condition was its join filters rows the bare parent
/// rule would grant, so it is not the same question.
fn drop_self_equalities(expr: &Expr) -> Option<Expr> {
    let mut predicates = Vec::new();
    flatten_and_predicates(expr, &mut predicates);
    let kept: Vec<Expr> = predicates
        .into_iter()
        .filter(|predicate| {
            !matches!(
                predicate,
                Expr::BinaryOp { left, op: BinaryOperator::Eq, right }
                    if matches!((left.as_ref(), right.as_ref()),
                        (Expr::Identifier(l), Expr::Identifier(r))
                            if stored_ident_name(l) == stored_ident_name(r))
            )
        })
        .cloned()
        .collect();
    combine_predicates_with_and(kept)
}

/// One equality an inner join states.
struct JoinEquality {
    left: (Option<String>, String),
    right: (Option<String>, String),
}

/// The qualifier and column of a reference to something other than the parent.
fn foreign_of<'s>(
    side: &'s (Option<String>, String),
    parent_table: &str,
    parent_alias: Option<&str>,
) -> Option<(&'s str, &'s str)> {
    let qualifier = side.0.as_deref()?;
    (!qualifier_matches_table(qualifier, parent_table, parent_alias))
        .then_some((qualifier, side.1.as_str()))
}

/// The parent's column `side` names. A bare name in this scope is the parent's own,
/// which is what every other reader here assumes and what the classifier's column gate
/// then verifies.
fn parent_of(
    side: &(Option<String>, String),
    parent_table: &str,
    parent_alias: Option<&str>,
) -> Option<ColumnName> {
    side.0
        .as_deref()
        .is_none_or(|found| qualifier_matches_table(found, parent_table, parent_alias))
        .then(|| ColumnName::from_stored(side.1.as_str()))
}

impl JoinEquality {
    /// The parent's column this equality ties `qualifier`.`column` to, if it does.
    fn parent_side(
        &self,
        parent_table: &str,
        parent_alias: Option<&str>,
        qualifier: &str,
        column: &str,
    ) -> Option<ColumnName> {
        let names = |side: &(Option<String>, String), q: &str, c: &str| {
            side.0
                .as_deref()
                .is_some_and(|found| qualifier_matches_table(found, q, None))
                && side.1 == c
        };
        if names(&self.left, qualifier, column) {
            return parent_of(&self.right, parent_table, parent_alias);
        }
        if names(&self.right, qualifier, column) {
            return parent_of(&self.left, parent_table, parent_alias);
        }
        None
    }

    /// The parent column and the foreign reference this equality ties together, when it
    /// ties exactly those two.
    fn link(
        &self,
        parent_table: &str,
        parent_alias: Option<&str>,
    ) -> Option<(ColumnName, &str, &str)> {
        if let (Some(parent), Some((qualifier, column))) = (
            parent_of(&self.left, parent_table, parent_alias),
            foreign_of(&self.right, parent_table, parent_alias),
        ) {
            return Some((parent, qualifier, column));
        }
        if let (Some(parent), Some((qualifier, column))) = (
            parent_of(&self.right, parent_table, parent_alias),
            foreign_of(&self.left, parent_table, parent_alias),
        ) {
            return Some((parent, qualifier, column));
        }
        None
    }
}

/// Whether every relation the select joins beside the parent leaves the parent's rows
/// alone: it drops none and duplicates none.
///
/// A join is a filter unless a declared key guarantees the match, so a parent row with
/// no partner is dropped by the database while a model that never saw the join grants
/// it. The key has to run from the parent to the joined column. A key the other way
/// says every joined row has a parent, which is not the same statement.
fn joins_drop_no_row<DB: DatabaseLike>(
    select: &Select,
    rule: Option<&Expr>,
    parent_table: &str,
    parent_alias: Option<&str>,
    db: &DB,
) -> bool {
    let joined: Vec<RelationSource> = relation_sources(select)
        .into_iter()
        .filter(|source| {
            // An unprovable pair counts as joined, and the key checks below then refuse.
            !written_tables_are_same(db, &source.table_name, parent_table).unwrap_or(false)
                && source
                    .alias
                    .as_deref()
                    .is_none_or(|alias| !qualifier_matches_table(alias, parent_table, parent_alias))
        })
        .collect();
    if joined.is_empty() {
        return true;
    }
    let Some(parent_meta) = lookup_table(db, parent_table) else {
        return false;
    };
    let Some(equalities) = inner_join_equalities(select, rule) else {
        return false;
    };

    joined.iter().all(|source| {
        equalities.iter().any(|equality| {
            let Some((parent_column, qualifier, column)) =
                equality.link(parent_table, parent_alias)
            else {
                return false;
            };
            qualifier_matches_table(qualifier, &source.table_name, source.alias.as_deref())
                && fk_targets_column(
                    parent_meta,
                    db,
                    parent_column.as_str(),
                    &source.table_name,
                    column,
                )
        })
    })
}

/// Every equality an inner join of the select states, plus every equality the rule
/// itself carries, which is where the comma-separated `FROM` spelling puts its join.
///
/// `None` when a join is not an inner one: an outer join admits rows whose right side is
/// absent, and a comparison against that absence is not the one the rewrite would write.
fn inner_join_equalities(select: &Select, rule: Option<&Expr>) -> Option<Vec<JoinEquality>> {
    let mut equalities = Vec::new();
    let mut predicates = Vec::new();
    for from in &select.from {
        for join in &from.joins {
            if !matches!(
                join.join_operator,
                JoinOperator::Join(_) | JoinOperator::Inner(_)
            ) {
                return None;
            }
            let condition = join_on_expr(&join.join_operator)?;
            flatten_and_predicates(condition, &mut predicates);
        }
    }
    if let Some(rule) = rule {
        flatten_and_predicates(rule, &mut predicates);
    }
    // An equality between two column references is a candidate join. Anything else is
    // part of the rule and is left to the classifier.
    for predicate in predicates {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = predicate
        else {
            continue;
        };
        let (Some(left), Some(right)) = (
            extract_qualified_column(left),
            extract_qualified_column(right),
        ) else {
            continue;
        };
        equalities.push(JoinEquality {
            left: (left.0, left.1.as_str().to_string()),
            right: (right.0, right.1.as_str().to_string()),
        });
    }
    Some(equalities)
}

/// Every `qualifier`.`column` the expression reads that the parent does not own,
/// deduplicated, and not descending into a nested subquery, whose references are its own.
fn foreign_references(
    expr: &Expr,
    parent_table: &str,
    parent_alias: Option<&str>,
) -> Vec<(String, ColumnName)> {
    let mut found: Vec<(String, ColumnName)> = Vec::new();
    let mut v = TopLevelOnly::top_level(|expr: &Expr| {
        if let Expr::CompoundIdentifier(parts) = expr {
            if let [.., qualifier, last] = parts.as_slice() {
                if !qualifier_matches_table(
                    stored_ident_name(qualifier).as_ref(),
                    parent_table,
                    parent_alias,
                ) {
                    let pair = (
                        stored_ident_name(qualifier).into_owned(),
                        ColumnName::from_stored(stored_ident_name(last)),
                    );
                    if !found.contains(&pair) {
                        found.push(pair);
                    }
                }
            }
        }
        ControlFlow::Continue(())
    });
    let _ = expr.visit(&mut v);
    found
}

/// Replace every `qualifier`.`column` reference with the bare identifier `to`.
///
/// Unlike `strip_qualifier`, rewrites at every nesting depth.
fn replace_compound_identifier(expr: &mut Expr, from: (&str, &str), to: &Ident) {
    struct Replacer<'a> {
        qualifier: &'a str,
        column: &'a str,
        to: &'a Ident,
    }

    impl VisitorMut for Replacer<'_> {
        type Break = ();

        fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
            if let Expr::CompoundIdentifier(parts) = &*expr {
                if let [.., qualifier, last] = parts.as_slice() {
                    if stored_ident_name(qualifier) == self.qualifier
                        && stored_ident_name(last) == self.column
                    {
                        *expr = Expr::Identifier(self.to.clone());
                    }
                }
            }
            ControlFlow::Continue(())
        }
    }

    let (qualifier, column) = from;
    let _ = expr.visit(&mut Replacer {
        qualifier,
        column,
        to,
    });
}

/// The single `Select` a query's body is, if it is one.
pub(super) fn query_select(query: &Query) -> Option<&Select> {
    match query.body.as_ref() {
        SetExpr::Select(select) => Some(select.as_ref()),
        _ => None,
    }
}

/// The clause by which a subquery shapes its rows beyond reading its FROM and WHERE, if
/// any.
///
/// Membership and parent inheritance read the subquery as a plain set of rows, so a clause
/// that drops rows from it lets the model grant rows the policy refuses. `TABLESAMPLE` is
/// named first because it thins the rows before any other clause sees them. `ONLY` leaves
/// out the rows of every table inheriting from the one it names, which a plain read
/// includes, while `t *` spells the plain read. `HAVING` is named ahead of the `GROUP BY` it
/// usually rides on because it is the clause doing the filtering. Plain `DISTINCT` drops
/// duplicate rows only, leaving the set itself intact.
pub(super) fn select_result_shaping_clause(select: &Select) -> Option<&'static str> {
    if any_named_source(select, &|factor| {
        matches!(
            factor,
            TableFactor::Table {
                sample: Some(_),
                ..
            }
        )
    }) {
        return Some("TABLESAMPLE");
    }
    if any_named_source(select, &|factor| {
        matches!(
            factor,
            TableFactor::Table {
                inheritance: Some(TableInheritance::Only { .. }),
                ..
            }
        )
    }) {
        return Some("ONLY");
    }
    if select.having.is_some() {
        return Some("HAVING");
    }
    if select.qualify.is_some() {
        return Some("QUALIFY");
    }
    let grouped = match &select.group_by {
        GroupByExpr::All(_) => true,
        GroupByExpr::Expressions(expressions, modifiers) => {
            !expressions.is_empty() || !modifiers.is_empty()
        }
    };
    if grouped {
        return Some("GROUP BY");
    }
    matches!(select.distinct, Some(Distinct::On(_))).then_some("DISTINCT ON")
}

/// True when `test` holds for any relation the `FROM` reads, nested joins included.
fn any_named_source(select: &Select, test: &dyn Fn(&TableFactor) -> bool) -> bool {
    select
        .from
        .iter()
        .any(|item| table_with_joins_has(item, test))
}

fn table_with_joins_has(item: &TableWithJoins, test: &dyn Fn(&TableFactor) -> bool) -> bool {
    core::iter::once(&item.relation)
        .chain(item.joins.iter().map(|join| &join.relation))
        .any(|factor| match factor {
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => table_with_joins_has(table_with_joins, test),
            _ => test(factor),
        })
}

/// True when a row count is a literal of at least one, so it cannot empty a result.
fn limit_keeps_a_row(rows: &Expr) -> bool {
    extract_integer_value(rows).is_some_and(|rows| rows >= 1)
}

/// The clause by which a query's row limit can leave `EXISTS` with nothing, if any.
///
/// `EXISTS` asks only whether one row survives, so a limit matters where it can empty a
/// non-empty result: a count that is not a literal of at least one, or an offset past the
/// first row.
fn exists_emptying_limit_clause(query: &Query) -> Option<&'static str> {
    match &query.limit_clause {
        None => {}
        Some(LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        }) => {
            if !limit_by.is_empty() || limit.as_ref().is_some_and(|rows| !limit_keeps_a_row(rows)) {
                return Some("LIMIT");
            }
            if offset
                .as_ref()
                .is_some_and(|offset| extract_integer_value(&offset.value) != Some(0))
            {
                return Some("OFFSET");
            }
        }
        Some(LimitClause::OffsetCommaLimit { .. }) => return Some("LIMIT"),
    }
    let fetch_keeps_a_row = query.fetch.as_ref().is_none_or(|fetch| {
        !fetch.percent && fetch.quantity.as_ref().is_none_or(limit_keeps_a_row)
    });
    (!fetch_keeps_a_row).then_some("FETCH")
}

/// The clause by which a query's row limit can drop a row from the set it reads, if any.
///
/// A plain set is not a set of one, so unlike `EXISTS` any limit refuses at all: which
/// rows survive turns on an order nothing here pins.
pub(super) fn set_limiting_clause(query: &Query) -> Option<&'static str> {
    if query.limit_clause.is_some() {
        return Some("LIMIT");
    }
    query.fetch.is_some().then_some("FETCH")
}

/// The `Select` a query projects when nothing narrows it, so its value is the projected
/// expression itself.
///
/// `PostgreSQL` empties a result with no `FROM` at all: `SELECT current_setting('k')
/// WHERE false`, `LIMIT 0`, `FETCH FIRST 0 ROWS` and `HAVING false` each return no row,
/// and a scalar subquery returning no row is NULL. `ORDER BY`, `DISTINCT` and a `WITH`
/// binding cannot drop the single row, so they are left alone.
pub(crate) fn projected_select(query: &Query) -> Option<&Select> {
    if set_limiting_clause(query).is_some() {
        return None;
    }
    let select = query_select(query)?;
    (select.from.is_empty()
        && select.selection.is_none()
        && select_result_shaping_clause(select).is_none())
    .then_some(select)
}

/// Why a subquery cannot be read as the plain set of rows in the table its `FROM` names.
#[derive(Clone, Copy)]
enum SubqueryRefusal {
    /// A clause thins the rows the subquery returns.
    Shaped(&'static str),
    /// A `WITH` clause binds names inside the subquery, so a name in its `FROM` may be
    /// that binding rather than the table it looks like.
    BindsItsOwnNames,
    /// A `FOR UPDATE` or `FOR SHARE` clause locks the rows it reads, which `PostgreSQL`
    /// also filters by the locked table's `UPDATE` policies.
    LocksItsRows,
}

impl SubqueryRefusal {
    /// Why the subquery cannot become a membership relation, for the operator.
    ///
    /// A shaped subquery returns a subset, which pre-computing recovers. A binding is not
    /// a subset at all: the rows may come from anywhere the `WITH` reads. A lock is a
    /// subset again, but of a set the reader's own update rights decide. All three want
    /// different advice.
    fn reason(self) -> String {
        match self {
            Self::Shaped(clause) => format!(
                "Subquery result is shaped by {clause}, so it admits fewer rows than a \
                 membership relation would grant, pre-compute the shaped set as its own table"
            ),
            Self::BindsItsOwnNames => String::from(
                "Subquery binds its own names in a WITH clause, so a table it reads may be \
                 that binding rather than the table of the same name, drop the WITH or read \
                 the tables directly",
            ),
            Self::LocksItsRows => String::from(
                "Subquery takes a row lock, so PostgreSQL filters it by the locked table's \
                 UPDATE policies as well and it finds fewer rows than a membership relation \
                 would grant, drop the lock from the policy",
            ),
        }
    }
}

/// The refusal a subquery's own name bindings earn, if it makes any.
///
/// Every binding is refused, referenced or not: a policy subquery that defines a `WITH` it
/// never reads is dead SQL, and deciding which bindings shadow a `FROM` name is the kind
/// of resolution whose failure direction is a grant.
pub(super) fn query_binds_its_own_names(query: &Query) -> bool {
    query.with.is_some()
}

/// The refusal a subquery's row locks earn, if it takes any.
///
/// Refused whatever the locked table's own policies say. Reading them here would mean
/// threading the schema through every extractor, and where the locked table has row level
/// security off the lock changes nothing, so this over-refuses that one shape in the safe
/// direction. The lock strength is deliberately not read: `PostgreSQL` filters all four
/// alike, and naming them would need a new arm the day `sqlparser` learns the two it still
/// refuses.
fn query_locks_its_rows(query: &Query) -> Option<SubqueryRefusal> {
    if query.locks.is_empty() {
        return None;
    }
    Some(SubqueryRefusal::LocksItsRows)
}

/// Everything about the query itself, rather than its `SELECT`, that stops the subquery
/// being read as the plain set of rows in the table its `FROM` names.
///
/// One composition point, so a further query-level refusal reaches both spellings at once.
fn query_level_refusal(query: &Query) -> Option<SubqueryRefusal> {
    query_binds_its_own_names(query)
        .then_some(SubqueryRefusal::BindsItsOwnNames)
        .or_else(|| query_locks_its_rows(query))
}

/// The `Select` an `EXISTS` tests, paired with the reason it cannot be read plainly.
fn exists_subquery_select(expr: &Expr) -> Option<(&Select, Option<SubqueryRefusal>)> {
    let Expr::Exists {
        subquery,
        negated: false,
    } = expr
    else {
        return None;
    };
    let select = query_select(subquery)?;
    let refusal = query_level_refusal(subquery)
        .or_else(|| exists_emptying_limit_clause(subquery).map(SubqueryRefusal::Shaped))
        .or_else(|| select_result_shaping_clause(select).map(SubqueryRefusal::Shaped));
    Some((select, refusal))
}

/// As [`exists_subquery_select`], for the callers that need the rows read plainly.
fn readable_exists_select(expr: &Expr) -> Option<&Select> {
    let (select, refusal) = exists_subquery_select(expr)?;
    refusal.is_none().then_some(select)
}

/// The `(tested value, subquery)` of `x IN (SELECT ...)` or `x = ANY (SELECT ...)`, paired
/// with the reason the set of tested values cannot be read plainly, if any.
///
/// Any row limit shapes that set here, `LIMIT 1` included: membership then tests one
/// arbitrary slice of the result rather than the whole of it, so reading it as full
/// membership grants rows the policy refuses. Ordering alone is irrelevant to a set
/// membership test.
fn membership_subquery_operands(expr: &Expr) -> Option<(&Expr, &Query, Option<SubqueryRefusal>)> {
    let (lhs, query) = match expr {
        Expr::In {
            expr: lhs,
            target: InTarget::Subquery(subquery),
            negated: false,
            global: false,
        } => (lhs.as_ref(), subquery.as_ref()),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match right.as_ref() {
            Expr::Subquery(subquery) => (left.as_ref(), subquery.as_ref()),
            _ => return None,
        },
        _ => return None,
    };

    if let Some(refusal) = query_level_refusal(query) {
        return Some((lhs, query, Some(refusal)));
    }
    let shaping = set_limiting_clause(query)
        .or_else(|| select_result_shaping_clause(query_select(query)?))
        .map(SubqueryRefusal::Shaped);
    Some((lhs, query, shaping))
}

/// As [`membership_subquery_operands`], for the callers that need the set read plainly.
fn readable_membership_subquery_operands(expr: &Expr) -> Option<(&Expr, &Query)> {
    let (lhs, query, refusal) = membership_subquery_operands(expr)?;
    refusal.is_none().then_some((lhs, query))
}

/// Membership and parent inheritance written as `x IN (SELECT y FROM t WHERE p)`, and the
/// `= ANY` spelling of the same, the caller-on-the-left form included.
///
/// Verified on `PostgreSQL` 18 to admit exactly the rows `EXISTS (SELECT 1 FROM t WHERE p
/// AND y = x)` admits, over rows covering a member, a non-member, no membership row at
/// all, a row whose key is NULL, a member beside a NULL key, and a member failing a
/// residual predicate: zero disagreements. The only difference is NULL against false,
/// which filters either way. So it is rewritten into that `EXISTS` and handed to the
/// recognizers in dispatch order, which keeps every refusal they already make.
pub fn recognize_p4_in_subquery<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: PolicyCommand,
    state: &ExpansionState,
) -> Option<ClassifiedExpr> {
    let rewritten = membership_exists_from_in_subquery(expr, registry, outer_table)?;
    recognize_p5(&rewritten, db, registry, outer_table, command, state)
        .or_else(|| recognize_p4(&rewritten, db, registry, outer_table, state))
}

/// `x IN (SELECT y FROM t WHERE p)` as `EXISTS (SELECT y FROM t WHERE p AND t.y = outer.x)`.
///
/// Both operands gain the qualifier the `IN` form leaves to scoping: the projection names
/// the subquery's own source, the tested value the guarded table. Without them a column
/// both tables spell alike reads as either, which drops the correlation and grants the
/// guarded table whole.
fn membership_exists_from_in_subquery(
    expr: &Expr,
    registry: &FunctionRegistry,
    outer_table: &str,
) -> Option<Expr> {
    let (tested, query) = readable_membership_subquery_operands(expr)?;
    let tested = if is_current_user_expr(tested, registry) {
        tested.clone()
    } else if matches!(tested, Expr::Identifier(_) | Expr::CompoundIdentifier(_)) {
        qualified_column(tested, outer_table)
    } else {
        return None;
    };

    let select = query_select(query)?;
    let projected = single_projected_column(select)?;
    let projected = match relation_sources(select).as_slice() {
        [source] => qualified_column(
            &projected,
            source.alias.as_deref().unwrap_or(&source.table_name),
        ),
        _ => projected,
    };

    let mut rewritten = query.clone();
    let SetExpr::Select(body) = rewritten.body.as_mut() else {
        return None;
    };
    let bound = Expr::BinaryOp {
        left: Box::new(projected),
        op: BinaryOperator::Eq,
        right: Box::new(tested),
    };
    body.selection = Some(match body.selection.take() {
        Some(existing) => Expr::BinaryOp {
            left: Box::new(existing),
            op: BinaryOperator::And,
            right: Box::new(bound),
        },
        None => bound,
    });
    Some(Expr::Exists {
        subquery: Box::new(rewritten),
        negated: false,
    })
}

/// `col` as `qualifier.col`, leaving anything already qualified alone.
///
/// The synthesized qualifier is quoted around the table's stored name, so its own stored
/// form is exactly that name whatever case the schema declared it in.
fn qualified_column(expr: &Expr, qualifier: &str) -> Expr {
    let Expr::Identifier(column) = expr else {
        return expr.clone();
    };
    Expr::CompoundIdentifier(vec![
        Ident::with_quote('"', stored_relation_name(qualifier)),
        column.clone(),
    ])
}

/// The one column a select projects, qualifier kept. `*`, several items, or anything that
/// is not a column reference yields `None`.
fn single_projected_column(select: &Select) -> Option<Expr> {
    let [item] = select.projection.as_slice() else {
        return None;
    };
    let (SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }) = item else {
        return None;
    };
    extract_column_name(expr).is_some().then(|| expr.clone())
}

fn classify_membership_select<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> Option<ClassifiedExpr> {
    match analyze_membership_select(select, db, registry, outer_table, state) {
        MembershipSelectAnalysis::Unique {
            join_table,
            columns:
                MembershipColumns {
                    pairs,
                    user_column,
                    member_match: MemberMatch::Caller,
                    extra_predicates,
                },
        } => Some(ClassifiedExpr {
            pattern: PatternClass::P4ExistsMembership(ExistsMembership {
                join_table: resolve_table_id(db, &join_table)?,
                pairs,
                user_column,
                extra_predicates,
            }),
            confidence: ConfidenceLevel::A,
        }),
        MembershipSelectAnalysis::Unique {
            join_table,
            columns:
                MembershipColumns {
                    pairs,
                    user_column,
                    member_match: MemberMatch::InCallerSet { source, separator },
                    extra_predicates,
                },
        } => Some(ClassifiedExpr {
            pattern: PatternClass::P18MembershipInCallerSet(MembershipInCallerSet {
                membership: ExistsMembership {
                    join_table: resolve_table_id(db, &join_table)?,
                    pairs,
                    user_column,
                    extra_predicates,
                },
                separator,
                source,
            }),
            confidence: ConfidenceLevel::A,
        }),
        MembershipSelectAnalysis::Uncorrelated {
            member_table,
            user_column,
            extra_predicates,
        } => Some(ClassifiedExpr {
            pattern: PatternClass::P13UncorrelatedMembership(UncorrelatedMembership {
                member_table: resolve_table_id(db, &member_table)?,
                user_column,
                extra_predicates,
            }),
            confidence: ConfidenceLevel::A,
        }),
        MembershipSelectAnalysis::AmbiguousMultiple
        | MembershipSelectAnalysis::AmbiguousNoUniqueJoin
        | MembershipSelectAnalysis::JoinsAnotherTable { .. }
        | MembershipSelectAnalysis::ScansEntityByOwnKey { .. }
        | MembershipSelectAnalysis::RescansGuardedTable
        | MembershipSelectAnalysis::UnkeyedPairing { .. }
        | MembershipSelectAnalysis::NoMatch => None,
    }
}

enum MembershipSelectAnalysis {
    Unique {
        join_table: String,
        columns: MembershipColumns,
    },
    AmbiguousMultiple,
    AmbiguousNoUniqueJoin,
    /// The subquery reads more than one table, so it carries conditions a single
    /// membership relation cannot express.
    JoinsAnotherTable {
        tables: Vec<String>,
    },
    /// The join column is the scanned table's own identity, so the subquery selects
    /// entities rather than membership rows.
    ScansEntityByOwnKey {
        join_table: String,
    },
    /// The subquery names no outer column at all, so it asks only whether the caller
    /// is a member of anything. Every row of the guarded table then passes together.
    Uncorrelated {
        member_table: String,
        user_column: ColumnName,
        extra_predicates: ResidualPredicates,
    },
    /// The equalities pair several columns, and the pairing names no single parent
    /// object per membership row.
    UnkeyedPairing {
        reason: String,
    },
    /// The subquery scans the guarded table itself, which `PostgreSQL` refuses to plan:
    /// reading it re-enters the policy being evaluated. Verified on `PostgreSQL` 18, which
    /// raises `infinite recursion detected in policy`.
    RescansGuardedTable,
    NoMatch,
}

fn analyze_membership_select<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> MembershipSelectAnalysis {
    if membership_sources_include_ambiguous_unresolvable_shape(select, db)
        && selection_references_current_user(select, registry)
    {
        return MembershipSelectAnalysis::AmbiguousNoUniqueJoin;
    }

    // Fail closed on self-joins: not expressible as static tuples.
    let all_sources = relation_sources(select);
    let unique_table_count = all_sources
        .iter()
        .map(|source| {
            resolve_table_id(db, &source.table_name)
                .map_or_else(|| source.table_name.clone(), |table| table.to_string())
        })
        .collect::<BTreeSet<_>>()
        .len();
    if unique_table_count != all_sources.len() {
        return MembershipSelectAnalysis::AmbiguousMultiple;
    }

    // Scanning the guarded table inside its own policy is a read PostgreSQL refuses to
    // plan, and the scan is a fresh one either way, so nothing in the subquery names the
    // guarded row. Inside a definer expansion whose reads provably bypass row level
    // security the scan is the owner's, which probe A shows never recurses, so the
    // membership routes below answer it.
    if !state.reading_as_owner()
        && all_sources.iter().any(|source| {
            // A source the schema cannot place may be the guarded table, so it refuses.
            written_tables_are_same(db, &source.table_name, outer_table).unwrap_or(true)
        })
    {
        return MembershipSelectAnalysis::RescansGuardedTable;
    }

    let MembershipMatches {
        mut matches,
        uncorrelated,
    } = membership_matches(select, &all_sources, db, registry, outer_table, state);
    if matches.len() > 1 {
        return MembershipSelectAnalysis::AmbiguousMultiple;
    }
    match matches.pop() {
        Some((join_table, mut columns)) => {
            let Some(join_table_id) = resolve_table_id(db, &join_table) else {
                return MembershipSelectAnalysis::UnkeyedPairing {
                    reason: format!("the membership table '{join_table}' does not resolve"),
                };
            };
            let Some(outer_table_id) = resolve_table_id(db, outer_table) else {
                return MembershipSelectAnalysis::UnkeyedPairing {
                    reason: format!("the guarded table '{outer_table}' does not resolve"),
                };
            };
            columns.pairs = match resolve_membership_pairing(
                columns.pairs,
                &join_table_id,
                &outer_table_id,
                db,
            ) {
                Ok((pairs, _)) => pairs,
                Err(reason) => return MembershipSelectAnalysis::UnkeyedPairing { reason },
            };
            // A membership row points at a parent. When the join column is the
            // scanned table's own identity, the rows are the entities themselves and
            // keying them by the child's identifier pairs unrelated rows.
            if let [pair] = columns.pairs.as_slice() {
                if scans_root_entity_by_its_key(db, &join_table, pair.join_column.as_str()) {
                    return MembershipSelectAnalysis::ScansEntityByOwnKey { join_table };
                }
            }
            // A third table in the subquery carries conditions that no single
            // membership relation can express, and keeping only the matching side
            // would drop them.
            let foreign: Vec<String> = all_sources
                .iter()
                .map(|source| source.table_name.clone())
                .filter(|name| {
                    // An unprovable pair counts as foreign, which refuses rather than
                    // dropping a third table's conditions.
                    !written_tables_are_same(db, name, &join_table).unwrap_or(false)
                })
                .collect();
            if !foreign.is_empty() {
                return MembershipSelectAnalysis::JoinsAnotherTable { tables: foreign };
            }
            MembershipSelectAnalysis::Unique {
                join_table,
                columns,
            }
        }
        None if selection_references_current_user(select, registry) => uncorrelated
            .and_then(|(source, predicates)| {
                analyze_uncorrelated_membership(
                    select,
                    db,
                    outer_table,
                    &source,
                    &predicates.selection,
                    registry,
                    state,
                )
            })
            .unwrap_or(MembershipSelectAnalysis::AmbiguousNoUniqueJoin),
        None => MembershipSelectAnalysis::NoMatch,
    }
}

/// Columns whose value the evaluating session's time zone decides.
pub(super) fn session_zoned_columns<DB: DatabaseLike>(table: &DB::Table, db: &DB) -> Vec<String> {
    table
        .columns(db)
        .into_iter()
        .flatten()
        .filter(|column| type_carries_a_zone(&column.data_type(db).name(db)))
        .map(|column| column.stored_column_name().into_owned())
        .collect()
}

/// A qualified or quoted spelling names the same type as the bare one.
fn type_carries_a_zone(data_type: &str) -> bool {
    let lowered = data_type.to_ascii_lowercase();
    let terminal = lowered
        .rsplit('.')
        .next()
        .unwrap_or(&lowered)
        .trim_matches('"');
    terminal.starts_with("timestamptz")
        || terminal.starts_with("timetz")
        || ((terminal.starts_with("timestamp") || terminal.starts_with("time"))
            && terminal.contains("with time zone"))
}

/// The subquery asks only whether the caller is a member of something, naming no column
/// of the guarded table.
///
/// Every refusal here matters, because the translation grants the whole table at once:
/// exactly one source with no joins, exactly one comparison against the caller, and
/// nothing reaching outside that one table. Anything else stays refused.
fn analyze_uncorrelated_membership<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    outer_table: &str,
    source: &RelationSource,
    predicates: &[AnalyzedMembershipPredicate<'_>],
    registry: &FunctionRegistry,
    state: &ExpansionState,
) -> Option<MembershipSelectAnalysis> {
    if select.from.iter().any(|item| !item.joins.is_empty()) {
        return None;
    }
    // Reading the guarded table itself is a self-reference, not a member source.
    if written_tables_are_same(db, &source.table_name, outer_table).unwrap_or(true) {
        return None;
    }
    let member = lookup_table(db, &source.table_name)?;
    let columns: Vec<String> = member
        .columns(db)
        .into_iter()
        .flatten()
        .map(|c| c.stored_column_name().into_owned())
        .collect();
    let session_zoned_columns = session_zoned_columns(member, db);

    select.selection.as_ref()?;

    let mut user_column: Option<ColumnName> = None;
    let mut extras: Vec<ResidualPredicate> = Vec::new();
    for analyzed in predicates {
        let predicate = analyzed.predicate;
        match &analyzed.analysis {
            MembershipEqAnalysis::UserColumn(column, MemberMatch::Caller)
                if user_column.is_none() =>
            {
                user_column = Some(column.clone());
                continue;
            }
            // A second caller comparison, a link to the outer row, or a join column
            // all mean this is not the shape. So does a column holding a grant rather
            // than a person, since granting the whole table to whoever appears in it
            // needs the rows to name people.
            //
            // That last case is a second line rather than the one that refuses today:
            // the caller reaches here only when the subquery references the caller, and
            // a declared set is not the caller, so the shape stops earlier. Kept so a
            // widening of that entry condition cannot turn grant keys into users, and
            // pinned by `an_uncorrelated_subquery_testing_a_declared_set_is_refused`.
            MembershipEqAnalysis::UserColumn(..)
            | MembershipEqAnalysis::FkCandidate { .. }
            | MembershipEqAnalysis::OuterCorrelation => return None,
            MembershipEqAnalysis::NotRelevant => {}
        }
        if predicate_references_other_table(predicate, &source.table_name, source.alias.as_deref())
        {
            return None;
        }
        let mut normalized = predicate.clone();
        strip_qualifier_from_expr(&mut normalized, &source.table_name, source.alias.as_deref());
        let relations = residual_relations(
            &mut normalized,
            Some(db),
            registry,
            &MembershipScope {
                table: &source.table_name,
                alias: source.alias.as_deref(),
                columns: &columns,
                guarded_table: outer_table,
            },
            state,
        )?;
        let residual = residual_predicate_reading(&normalized, relations);
        if residual.relations.is_empty()
            && residual.request.is_none()
            && !conjunct_reads_only_the_row(&normalized, &columns, &session_zoned_columns)
        {
            return None;
        }
        extras.push(residual);
    }

    Some(MembershipSelectAnalysis::Uncorrelated {
        member_table: source.table_name.clone(),
        user_column: user_column?,
        extra_predicates: ResidualPredicates::new(extras),
    })
}

/// How an accepted membership pairing names its parent.
pub(crate) enum MembershipPairing {
    /// One pair on a column that is not the guarded key, so the parent is decided from
    /// the join column alone.
    Single,
    /// The pairs are the host columns of one declared foreign key onto this
    /// table's full primary key.
    ForeignKey {
        /// The referenced table, as the schema spells it.
        parent_table: TableId,
    },
    /// The outer columns are the guarded table's own full primary key, so the
    /// parent is the guarded row itself.
    SelfKeyed,
}

/// The pairs ordered by the key that names the parent object, with the route that
/// accepted them, or the refusal reason.
///
/// Pairs name one parent object per membership row when their outer columns are the
/// guarded table's own primary key, when they are the host columns of one declared foreign
/// key onto a table's full primary key, or when one pair names a column of the join table.
/// The one resolver for classification and emission, so an oracle-supplied pattern is
/// validated by the same rules the recognizer applies.
pub(crate) fn resolve_membership_pairing<DB: DatabaseLike>(
    pairs: Vec<MembershipJoinPair>,
    join_table: &TableId,
    outer_table: &TableId,
    db: &DB,
) -> Result<(Vec<MembershipJoinPair>, MembershipPairing), String> {
    if pairs.is_empty() {
        return Err("the membership subquery correlates no column pair".to_string());
    }
    if pairs.len() == 1 {
        return Ok(match self_key_pair_order(&pairs, outer_table, db) {
            Some(ordered) => (ordered, MembershipPairing::SelfKeyed),
            None => (pairs, MembershipPairing::Single),
        });
    }
    if let Some(column) = first_duplicate_pair_column(&pairs) {
        return Err(format!(
            "the membership equalities pair '{column}' twice, which is not a key pairing"
        ));
    }
    match composite_fk_pair_order(&pairs, join_table, db) {
        FkPairing::One {
            ordered,
            parent_table,
        } => return Ok((ordered, MembershipPairing::ForeignKey { parent_table })),
        FkPairing::Several => {
            return Err(format!(
                "two foreign keys of '{join_table}' cover the joined columns, so the \
                 parent they name is ambiguous"
            ))
        }
        FkPairing::None => {}
    }
    if let Some(ordered) = self_key_pair_order(&pairs, outer_table, db) {
        return Ok((ordered, MembershipPairing::SelfKeyed));
    }
    Err(format!(
        "the {} membership equalities match neither a declared foreign key of \
         '{join_table}' nor the primary key of '{outer_table}', so no single parent \
         object is named",
        pairs.len()
    ))
}

/// A column either side of the pairing names twice, if any.
fn first_duplicate_pair_column(pairs: &[MembershipJoinPair]) -> Option<&ColumnName> {
    let mut join_seen = BTreeSet::new();
    let mut outer_seen = BTreeSet::new();
    for pair in pairs {
        if !join_seen.insert(pair.join_column.as_str()) {
            return Some(&pair.join_column);
        }
        if !outer_seen.insert(pair.outer_column.as_str()) {
            return Some(&pair.outer_column);
        }
    }
    None
}

/// How the declared foreign keys of the join table cover a pairing.
enum FkPairing {
    /// Exactly one covers it, and the pairs come back in its referenced key's order.
    One {
        ordered: Vec<MembershipJoinPair>,
        parent_table: TableId,
    },
    /// More than one covers it, so the parent is ambiguous.
    Several,
    /// None covers it.
    None,
}

/// The pairs reordered by the primary key of the table one declared foreign key
/// references, when the pairs' join columns are exactly that key's host columns.
///
/// The referenced columns must be the referenced table's full primary key, which is
/// how the parent's own rows name its objects, so the order threads through to one
/// spelling per object. Hosts and referenced columns pair positionally.
fn composite_fk_pair_order<DB: DatabaseLike>(
    pairs: &[MembershipJoinPair],
    join_table: &TableId,
    db: &DB,
) -> FkPairing {
    let Some(table) = lookup_table_id(db, join_table) else {
        return FkPairing::None;
    };
    let join_set: BTreeSet<&str> = pairs.iter().map(|pair| pair.join_column.as_str()).collect();
    let mut matched: Option<(Vec<MembershipJoinPair>, TableId)> = None;
    for fk in table.foreign_keys(db).into_iter().flatten() {
        let Ok(hosts) = fk.host_columns(db) else {
            continue;
        };
        let hosts: Vec<String> = hosts.map(|c| c.stored_column_name().into_owned()).collect();
        if hosts.len() != pairs.len()
            || hosts.iter().map(String::as_str).collect::<BTreeSet<_>>() != join_set
        {
            continue;
        }
        let (Ok(referenced_table), Ok(referenced)) =
            (fk.referenced_table(db), fk.referenced_columns(db))
        else {
            continue;
        };
        let referenced: Vec<String> = referenced
            .map(|c| c.stored_column_name().into_owned())
            .collect();
        let Ok(pk) = referenced_table.primary_key_columns(db) else {
            continue;
        };
        let pk: Vec<String> = pk.map(|c| c.stored_column_name().into_owned()).collect();
        if pk.is_empty()
            || pk.len() != referenced.len()
            || pk.iter().collect::<BTreeSet<_>>() != referenced.iter().collect::<BTreeSet<_>>()
        {
            continue;
        }
        let ordered: Option<Vec<MembershipJoinPair>> = pk
            .iter()
            .map(|pk_col| {
                let position = referenced.iter().position(|column| column == pk_col)?;
                let host = hosts.get(position)?.as_str();
                pairs
                    .iter()
                    .find(|pair| pair.join_column.as_str() == host)
                    .cloned()
            })
            .collect();
        let Some(ordered) = ordered else {
            continue;
        };
        if matched.is_some() {
            return FkPairing::Several;
        }
        matched = Some((ordered, table_identity(referenced_table)));
    }
    matched.map_or(FkPairing::None, |(ordered, parent_table)| FkPairing::One {
        ordered,
        parent_table,
    })
}

/// The pairs reordered by the guarded table's primary key, when the outer columns
/// are exactly that key. The parent is then the guarded row itself, named as its
/// own key names it.
fn self_key_pair_order<DB: DatabaseLike>(
    pairs: &[MembershipJoinPair],
    outer_table: &TableId,
    db: &DB,
) -> Option<Vec<MembershipJoinPair>> {
    let table = lookup_table_id(db, outer_table)?;
    let pk: Vec<String> = table
        .primary_key_columns(db)
        .ok()?
        .map(|c| c.stored_column_name().into_owned())
        .collect();
    if pk.len() != pairs.len() {
        return None;
    }
    pk.iter()
        .map(|pk_col| {
            pairs
                .iter()
                .find(|pair| pair.outer_column.as_str() == pk_col.as_str())
                .cloned()
        })
        .collect()
}

/// True when `column` is `table`'s own identity rather than a link to a parent:
/// the single-column primary key, and not itself a foreign key.
///
/// A dependent row keyed by its parent (`doc_owner(doc_id PRIMARY KEY REFERENCES
/// docs)`) is a membership row and stays translatable. A root entity scanned by its
fn scans_root_entity_by_its_key<DB: DatabaseLike>(db: &DB, table: &str, column: &str) -> bool {
    let Some(meta) = lookup_table(db, table) else {
        return false;
    };
    // Returning true refuses the policy, so an unreadable key cannot rule the scan out.
    let Ok(primary_key) = meta.primary_key_column(db) else {
        return true;
    };
    let is_primary_key = primary_key.is_some_and(|pk| pk.stored_column_name() == column);
    if !is_primary_key {
        return false;
    }
    !meta.foreign_keys(db).into_iter().flatten().any(|fk| {
        fk.host_column(db)
            .ok()
            .flatten()
            .is_some_and(|host| host.stored_column_name() == column)
    })
}

pub(crate) fn diagnose_p4_membership_ambiguity<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> Option<String> {
    fn diagnose_select<DB: DatabaseLike>(
        select: &Select,
        db: &DB,
        registry: &FunctionRegistry,
        outer_table: &str,
        state: &ExpansionState,
    ) -> Option<String> {
        match analyze_membership_select(select, db, registry, outer_table, state) {
            MembershipSelectAnalysis::AmbiguousMultiple => Some(
                "Ambiguous membership pattern: multiple candidate membership sources matched"
                    .to_string(),
            ),
            MembershipSelectAnalysis::AmbiguousNoUniqueJoin => Some(
                "Ambiguous membership pattern: could not infer a unique membership join"
                    .to_string(),
            ),
            MembershipSelectAnalysis::JoinsAnotherTable { tables } => Some(format!(
                "Membership subquery reads {} together, and a single OpenFGA relation cannot \
                 carry a condition on the joined table, so split the check or pre-compute a \
                 membership table",
                tables.join(" and ")
            )),
            MembershipSelectAnalysis::ScansEntityByOwnKey { join_table } => Some(format!(
                "Subquery selects '{join_table}' rows by their own primary key, so they are \
                 '{join_table}' entities rather than membership rows, and the foreign key \
                 from the policy's table to '{join_table}' should make the link parent \
                 inheritance"
            )),
            MembershipSelectAnalysis::RescansGuardedTable => Some(format!(
                "Subquery reads '{outer_table}', the table the policy guards, so PostgreSQL \
                 raises infinite recursion on every read and no reference in it names the \
                 guarded row, so drop the inner scan and correlate against '{outer_table}' \
                 directly"
            )),
            MembershipSelectAnalysis::UnkeyedPairing { reason } => Some(reason),
            MembershipSelectAnalysis::Unique { .. }
            | MembershipSelectAnalysis::Uncorrelated { .. }
            | MembershipSelectAnalysis::NoMatch => None,
        }
    }

    if let Expr::Exists { .. } = expr {
        let (select, refusal) = exists_subquery_select(expr)?;
        return match refusal {
            Some(refusal) => Some(refusal.reason()),
            None => diagnose_select(select, db, registry, outer_table, state),
        };
    }

    let (lhs, query, refusal) = membership_subquery_operands(expr)?;
    if let Some(refusal) = refusal {
        return Some(refusal.reason());
    }
    // A row-value IN pairs several columns at once. The EXISTS spelling of the same
    // policy translates through the pairing routes, so the reason names the
    // respelling rather than a projection problem.
    if matches!(unparenthesize(lhs), Expr::Tuple(_)) {
        return Some(
            "A row-value IN compares several columns at once, which has no translation. \
             Spell the policy as EXISTS with one equality per column, which translates \
             when the columns pair onto a key"
                .to_string(),
        );
    }
    if single_projected_column(query_select(query)?).is_none() {
        return Some(
            "Subquery selects an expression rather than a column, so nothing links it to the \
             guarded row, so project the correlating column instead"
                .to_string(),
        );
    }
    // Diagnose the rewrite the recognizer classifies, so the reason names the shape the
    // analyzer saw rather than the one the policy spells.
    let rewritten = membership_exists_from_in_subquery(expr, registry, outer_table)?;
    let Expr::Exists { subquery, .. } = &rewritten else {
        return None;
    };
    diagnose_select(query_select(subquery)?, db, registry, outer_table, state)
}

pub(crate) fn diagnose_p5_parent_inheritance_ambiguity<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: PolicyCommand,
    state: &ExpansionState,
) -> Option<String> {
    // The `IN (SELECT ...)` spelling reaches the recognizers rewritten, so the diagnosis
    // has to read the same expression they refused.
    let rewritten = membership_exists_from_in_subquery(expr, registry, outer_table);
    let expr = rewritten.as_ref().unwrap_or(expr);
    let select = readable_exists_select(expr)?;
    let analysis = analyze_p5_parent_inheritance(select, db, outer_table)?;

    if analysis.candidates.len() > 1 {
        return Some(
            "Ambiguous parent inheritance pattern: multiple candidate parent sources matched"
                .to_string(),
        );
    }
    if analysis.saw_conflicting_join {
        return Some(
            "Ambiguous parent inheritance pattern: conflicting outer FK join columns in EXISTS predicate"
                .to_string(),
        );
    }
    // The parent is unambiguous and its own rule is what failed, so say which rule and
    // why. Without this the operator reads "could not infer a unique membership join"
    // for a filter whose parent was inferred perfectly well.
    analysis.candidates.into_iter().find_map(|candidate| {
        let rule = combine_predicates_with_and(candidate.inner_predicates);
        // Only where the recognizer would otherwise have accepted, so a shape refused for
        // another reason keeps its own.
        let reached = joins_drop_no_row(
            select,
            rule.as_ref(),
            &candidate.parent_table,
            candidate.parent_alias.as_deref(),
            db,
        ) && !resolve_table_id(db, &candidate.parent_table)
            .is_some_and(|parent| parent_enforces_row_security(db, &parent));
        let Some(mut inner) = rule else {
            return reached.then(|| nothing_to_inherit(&candidate.parent_table));
        };
        strip_qualifier_from_expr_deep(
            &mut inner,
            &candidate.parent_table,
            candidate.parent_alias.as_deref(),
        );
        if predicate_references_other_table(&inner, &candidate.parent_table, None) {
            return Some(format!(
                "The rule inherited from '{}' reads another relation of the subquery, \
                 which one relation cannot carry",
                candidate.parent_table
            ));
        }
        match crate::classifier::policy_classifier::classify_expr_in_state(
            &inner,
            db,
            registry,
            &candidate.parent_table,
            command,
            state,
        )
        .pattern
        {
            PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => Some(format!(
                "The rule inherited from '{}' is not translatable: {reason}",
                candidate.parent_table
            )),
            PatternClass::P10ConstantBool(ConstantBool { value: true }) if reached => {
                Some(nothing_to_inherit(&candidate.parent_table))
            }
            _ => None,
        }
    })
}

/// Why a bare delegation to a parent that enforces nothing is refused.
fn nothing_to_inherit(parent_table: &str) -> String {
    format!(
        "The rule inherited from '{parent_table}' is that table's own read rule, and \
         '{parent_table}' enforces no row security, so there is nothing to inherit"
    )
}

#[derive(Debug, Clone)]
pub(super) struct P5InheritanceCandidate {
    pub(super) parent_table: String,
    /// Alias the subquery gave the parent table, if any. Predicates nested inside
    /// this subquery refer to the parent through it.
    pub(super) parent_alias: Option<String>,
    pub(super) fk_column: ColumnName,
    pub(super) inner_predicates: Vec<Expr>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct P5InheritanceAnalysis {
    pub(super) candidates: Vec<P5InheritanceCandidate>,
    pub(super) saw_conflicting_join: bool,
}

pub(super) fn analyze_p5_parent_inheritance<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    outer_table: &str,
) -> Option<P5InheritanceAnalysis> {
    let sources = relation_sources(select);
    if sources.is_empty() {
        return None;
    }

    let outer_table_meta = lookup_table(db, outer_table)?;
    let selection = select.selection.as_ref()?;

    let outer_cols: Vec<String> = outer_table_meta
        .columns(db)
        .into_iter()
        .flatten()
        .map(|c| c.stored_column_name().into_owned())
        .collect();
    let mut predicates = Vec::new();
    flatten_and_predicates(selection, &mut predicates);

    let mut analysis = P5InheritanceAnalysis::default();

    for source in sources {
        let Some(parent_table) = lookup_table(db, &source.table_name) else {
            continue;
        };
        let parent_cols: Vec<String> = parent_table
            .columns(db)
            .into_iter()
            .flatten()
            .map(|c| c.stored_column_name().into_owned())
            .collect();

        let mut fk_column: Option<ColumnName> = None;
        let mut inner_predicates = Vec::new();
        let mut invalid_join = false;

        for pred in &predicates {
            if let Some((outer_fk, _parent_col)) = extract_parent_join_columns(
                pred,
                outer_table,
                &outer_cols,
                &source.table_name,
                source.alias.as_deref(),
                &parent_cols,
            ) {
                if fk_column
                    .as_ref()
                    .is_none_or(|existing| existing == &outer_fk)
                {
                    fk_column = Some(outer_fk);
                    continue;
                }
                invalid_join = true;
                break;
            }
            inner_predicates.push((*pred).clone());
        }

        if invalid_join {
            analysis.saw_conflicting_join = true;
            continue;
        }
        let Some(fk_column) = fk_column else {
            continue;
        };
        // The policy states the join, so a declared key adds integrity rather than
        // meaning. It is still required wherever the subquery carries a rule of its own,
        // because then the shape competes with a membership lookup and the key is what
        // tells them apart. A bare correlation competes with nothing.
        if !inner_predicates.is_empty()
            && !table_has_fk_to_parent(outer_table_meta, db, fk_column.as_str(), &source.table_name)
        {
            continue;
        }

        analysis.candidates.push(P5InheritanceCandidate {
            parent_table: source.table_name,
            parent_alias: source.alias,
            fk_column,
            inner_predicates,
        });
    }

    Some(analysis)
}

pub(super) fn selection_references_current_user(
    select: &Select,
    registry: &FunctionRegistry,
) -> bool {
    let Some(selection) = select.selection.as_ref() else {
        return false;
    };
    let mut predicates = Vec::new();
    flatten_and_predicates(selection, &mut predicates);
    predicates.into_iter().any(|predicate| match predicate {
        Expr::BinaryOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => {
            is_current_user_expr(left, registry) || is_current_user_expr(right, registry)
        }
        _ => is_current_user_expr(predicate, registry),
    })
}
pub(super) fn table_factor_parts(tf: &TableFactor) -> Option<(String, Option<String>)> {
    if let TableFactor::Table { name, alias, .. } = tf {
        Some((
            name.to_string(),
            alias
                .as_ref()
                .map(|a| stored_ident_name(&a.name).into_owned()),
        ))
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct RelationSource {
    table_name: String,
    alias: Option<String>,
}

fn relation_sources(select: &Select) -> Vec<RelationSource> {
    let mut sources = Vec::new();
    for from in &select.from {
        if let Some(source) = relation_source_from_table_factor(&from.relation) {
            sources.push(source);
        }
        for join in &from.joins {
            if let Some(source) = relation_source_from_table_factor(&join.relation) {
                sources.push(source);
            }
        }
    }

    sources
}

fn relation_source_from_table_factor(tf: &TableFactor) -> Option<RelationSource> {
    let (table_name, alias) = table_factor_parts(tf)?;
    Some(RelationSource { table_name, alias })
}

fn membership_sources_include_ambiguous_unresolvable_shape<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
) -> bool {
    let mut relation_factor_count = 0usize;
    let mut has_non_plain_source = false;
    let mut has_unresolvable_source = false;

    for from in &select.from {
        relation_factor_count += 1;
        match &from.relation {
            TableFactor::Table { name, .. } => {
                if lookup_table(db, &name.to_string()).is_none() {
                    has_unresolvable_source = true;
                }
            }
            _ => has_non_plain_source = true,
        }
        for join in &from.joins {
            relation_factor_count += 1;
            match &join.relation {
                TableFactor::Table { name, .. } => {
                    if lookup_table(db, &name.to_string()).is_none() {
                        has_unresolvable_source = true;
                    }
                }
                _ => has_non_plain_source = true,
            }
        }
    }

    relation_factor_count > 1 && (has_non_plain_source || has_unresolvable_source)
}

struct MembershipMatches<'a> {
    matches: Vec<(String, MembershipColumns)>,
    uncorrelated: Option<(RelationSource, MembershipPredicateAnalyses<'a>)>,
}

fn membership_matches<'a, DB: DatabaseLike>(
    select: &'a Select,
    sources: &[RelationSource],
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> MembershipMatches<'a> {
    let mut matches = Vec::new();
    let mut uncorrelated = None;
    for source in sources {
        let Some(table) = lookup_table(db, &source.table_name) else {
            continue;
        };
        let col_names: Vec<String> = table
            .columns(db)
            .into_iter()
            .flatten()
            .map(|c| c.stored_column_name().into_owned())
            .collect();
        let predicates = analyze_membership_predicates(
            select,
            &source.table_name,
            source.alias.as_deref(),
            &col_names,
            registry,
        );

        let scope = MembershipScope {
            table: &source.table_name,
            alias: source.alias.as_deref(),
            columns: &col_names,
            guarded_table: outer_table,
        };
        if let Some(columns) = extract_membership_columns_with_analysis(
            select,
            &scope,
            Some(db),
            &predicates,
            registry,
            state,
        ) {
            matches.push((source.table_name.clone(), columns));
        }
        if sources.len() == 1 {
            uncorrelated = Some((source.clone(), predicates));
        }
    }
    MembershipMatches {
        matches,
        uncorrelated,
    }
}

pub(super) fn join_on_expr(op: &JoinOperator) -> Option<&Expr> {
    use sqlparser::ast::JoinConstraint;
    use sqlparser::ast::JoinOperator::{
        CrossJoin, FullOuter, Inner, Join, Left, LeftOuter, Right, RightOuter,
    };
    let (Join(c) | Inner(c) | Left(c) | LeftOuter(c) | Right(c) | RightOuter(c) | FullOuter(c)
    | CrossJoin(c)) = op
    else {
        return None;
    };
    if let JoinConstraint::On(expr) = c {
        Some(expr)
    } else {
        None
    }
}

/// How a membership row names who it admits.
///
/// The two are not interchangeable: a column holding the caller is a subject a tuple can
/// name, while a column holding a grant the caller carries is not a person at all, so
/// reading one as the other would declare grant keys to be users.
#[derive(Clone, PartialEq)]
pub(super) enum MemberMatch {
    /// The column holds the caller's own identity.
    Caller,
    /// The column holds a value the caller's declared set has to contain.
    InCallerSet {
        /// The declared source, carrying the parameter the caller supplies.
        source: SessionAttribute,
        /// Separator the policy splits the setting on.
        separator: Option<String>,
    },
}

/// The columns one membership subquery names, once the analysis has read every predicate.
struct MembershipColumns {
    /// The equalities linking the scanned table to the guarded table, as accumulated.
    /// [`resolve_membership_pairing`] is what orders them and refuses an unkeyed set.
    pairs: Vec<MembershipJoinPair>,
    /// Column of the scanned table naming who the row admits.
    user_column: ColumnName,
    member_match: MemberMatch,
    extra_predicates: ResidualPredicates,
}

/// A qualified or bare column reference, as the subquery spells it.
type ColumnRef = (Option<String>, ColumnName);

enum MembershipEqAnalysis {
    NotRelevant,
    UserColumn(ColumnName, MemberMatch),
    /// A correlation between a column of the scanned table and another reference, which
    /// reaches the guarded row directly or through the subquery's other equalities.
    FkCandidate {
        join_column: ColumnName,
        correlated: ColumnRef,
    },
    OuterCorrelation,
}

struct AnalyzedMembershipPredicate<'a> {
    predicate: &'a Expr,
    analysis: MembershipEqAnalysis,
}

struct MembershipPredicateAnalyses<'a> {
    selection: Vec<AnalyzedMembershipPredicate<'a>>,
    joins: Vec<AnalyzedMembershipPredicate<'a>>,
}

fn analyze_membership_predicates<'a>(
    select: &'a Select,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
    registry: &FunctionRegistry,
) -> MembershipPredicateAnalyses<'a> {
    let mut selection = Vec::new();
    if let Some(predicate) = &select.selection {
        flatten_and_predicates(predicate, &mut selection);
    }
    let selection = selection
        .into_iter()
        .map(|predicate| AnalyzedMembershipPredicate {
            predicate,
            analysis: analyze_membership_eq_predicate(
                predicate, join_table, join_alias, join_cols, registry,
            ),
        })
        .collect();

    let mut joins = Vec::new();
    for from_item in &select.from {
        for join in &from_item.joins {
            if let Some(predicate) = join_on_expr(&join.join_operator) {
                flatten_and_predicates(predicate, &mut joins);
            }
        }
    }
    let joins = joins
        .into_iter()
        .map(|predicate| AnalyzedMembershipPredicate {
            predicate,
            analysis: analyze_membership_eq_predicate(
                predicate, join_table, join_alias, join_cols, registry,
            ),
        })
        .collect();

    MembershipPredicateAnalyses { selection, joins }
}

fn analyze_membership_eq_predicate(
    predicate: &Expr,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
    registry: &FunctionRegistry,
) -> MembershipEqAnalysis {
    // The membership row holds a grant the caller may carry rather than the caller, in
    // either spelling of the set: `= ANY(string_to_array(...))` or `IN (SELECT unnest(...))`.
    let in_caller_set = match predicate {
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => Some((left, caller_set(right, registry))),
        Expr::In {
            expr,
            target: InTarget::Subquery(subquery),
            negated: false,
            global: false,
        } => Some((expr, caller_set_in_subquery(subquery, registry))),
        _ => None,
    };
    if let Some((tested, declared)) = in_caller_set {
        if let (Some((qualifier, column)), Some((source, separator))) =
            (extract_qualified_column(tested), declared)
        {
            if is_join_column_ref(
                qualifier.as_deref(),
                column.as_str(),
                join_table,
                join_alias,
                join_cols,
            ) {
                return MembershipEqAnalysis::UserColumn(
                    column,
                    MemberMatch::InCallerSet {
                        source: source.clone(),
                        separator,
                    },
                );
            }
        }
        return MembershipEqAnalysis::NotRelevant;
    }

    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = predicate
    else {
        return MembershipEqAnalysis::NotRelevant;
    };

    let left_col = extract_qualified_column(left);
    let right_col = extract_qualified_column(right);

    if let Some((qual, col)) = left_col.clone() {
        if is_join_column_ref(
            qual.as_deref(),
            col.as_str(),
            join_table,
            join_alias,
            join_cols,
        ) && is_current_user_expr(right, registry)
        {
            return MembershipEqAnalysis::UserColumn(col, MemberMatch::Caller);
        }
    }
    if let Some((qual, col)) = right_col.clone() {
        if is_join_column_ref(
            qual.as_deref(),
            col.as_str(),
            join_table,
            join_alias,
            join_cols,
        ) && is_current_user_expr(left, registry)
        {
            return MembershipEqAnalysis::UserColumn(col, MemberMatch::Caller);
        }
    }

    let (Some((left_qual, left_name)), Some((right_qual, right_name))) = (left_col, right_col)
    else {
        return MembershipEqAnalysis::NotRelevant;
    };

    let left_is_join = is_join_column_ref(
        left_qual.as_deref(),
        left_name.as_str(),
        join_table,
        join_alias,
        join_cols,
    );
    let right_is_join = is_join_column_ref(
        right_qual.as_deref(),
        right_name.as_str(),
        join_table,
        join_alias,
        join_cols,
    );

    if left_is_join && !right_is_join {
        return MembershipEqAnalysis::FkCandidate {
            join_column: left_name,
            correlated: (right_qual, right_name),
        };
    }
    if right_is_join && !left_is_join {
        return MembershipEqAnalysis::FkCandidate {
            join_column: right_name,
            correlated: (left_qual, left_name),
        };
    }
    if !left_is_join && !right_is_join {
        return MembershipEqAnalysis::OuterCorrelation;
    }

    MembershipEqAnalysis::NotRelevant
}

/// The guarded table's column this reference names.
///
/// `None` means the value compared is some other scan's, so a bridge keyed on it would
/// grant rows the correlation never admitted. A bare name is the guarded row's, since a
/// column of the scanned table would have been read as the join side.
fn guarded_row_column(reference: ColumnRef, outer_table: &str) -> Option<ColumnName> {
    let (qualifier, column) = reference;
    match qualifier {
        Some(qualifier) if !qualifier_matches_table(&qualifier, outer_table, None) => None,
        _ => Some(column),
    }
}

#[cfg(test)]
pub(super) fn extract_membership_columns(
    select: &Select,
    scope: &MembershipScope<'_>,
    registry: &FunctionRegistry,
) -> Option<(Vec<MembershipJoinPair>, ColumnName, ResidualPredicates)> {
    extract_membership_columns_with_db::<crate::parser::sql_parser::ParserDB>(
        select, scope, None, registry,
    )
    .map(|columns| (columns.pairs, columns.user_column, columns.extra_predicates))
}

#[cfg(test)]
fn extract_membership_columns_with_db<DB: DatabaseLike>(
    select: &Select,
    scope: &MembershipScope<'_>,
    db: Option<&DB>,
    registry: &FunctionRegistry,
) -> Option<MembershipColumns> {
    let predicates =
        analyze_membership_predicates(select, scope.table, scope.alias, scope.columns, registry);
    extract_membership_columns_with_analysis(
        select,
        scope,
        db,
        &predicates,
        registry,
        &ExpansionState::new(),
    )
}

fn extract_membership_columns_with_analysis<DB: DatabaseLike>(
    select: &Select,
    scope: &MembershipScope<'_>,
    db: Option<&DB>,
    analyzed_predicates: &MembershipPredicateAnalyses<'_>,
    registry: &FunctionRegistry,
    state: &ExpansionState,
) -> Option<MembershipColumns> {
    let MembershipScope {
        table: join_table,
        alias: join_alias,
        columns: join_cols,
        guarded_table: outer_table,
    } = *scope;
    let mut correlated: Vec<MembershipJoinPair> = Vec::new();
    let mut fk_col_is_explicit = false; // true only when found via an explicit `join_col = outer_col` predicate
    let mut user_col: Option<(ColumnName, MemberMatch)> = None;
    let mut extras: Vec<ResidualPredicate> = Vec::new();
    let unqualified_scope = db
        .map(|db| build_unqualified_membership_scope(select, db, join_table, join_cols))
        .unwrap_or_default();
    let session_zoned_columns = db
        .and_then(|db| lookup_table(db, join_table).map(|table| session_zoned_columns(table, db)))
        .unwrap_or_default();

    // JOIN predicates provide correlation but do not enter the generated filter.

    // Process WHERE predicates (with extras).
    for analyzed in &analyzed_predicates.selection {
        let pred = analyzed.predicate;
        match &analyzed.analysis {
            MembershipEqAnalysis::UserColumn(col, how) => {
                if !name_member(&mut user_col, col, how) {
                    return None;
                }
                continue;
            }
            MembershipEqAnalysis::FkCandidate {
                join_column,
                correlated: reference,
            } => {
                let pair = MembershipJoinPair {
                    join_column: join_column.clone(),
                    outer_column: guarded_row_column(reference.clone(), outer_table)?,
                };
                if !correlated.contains(&pair) {
                    correlated.push(pair);
                }
                fk_col_is_explicit = true;
                continue;
            }
            MembershipEqAnalysis::OuterCorrelation => {
                // Neither side is the membership row's, so PostgreSQL filters
                // through the guarded row per hit. The tuple query reads only
                // the membership table and cannot carry that filter.
                return None;
            }
            MembershipEqAnalysis::NotRelevant => {}
        }

        // Scope validation: reject predicates that reference columns from
        // tables other than the join table.  Such predicates require a JOIN
        // that the generated single-table tuple query cannot provide, so
        // they would produce semantically invalid SQL.
        if predicate_references_other_table(pred, join_table, join_alias) {
            return None;
        }
        if predicate_has_ambiguous_unqualified_column(pred, &unqualified_scope) {
            return None;
        }
        // Keep additional predicates for tuple filtering.
        // Strip join-table qualifiers at the AST level before rendering to SQL.
        // This handles double-quoted identifiers, dollar-quoted strings, and other
        // SQL literal forms that text-based rewriting would mangle.
        let mut normalized_pred = pred.clone();
        strip_qualifier_from_expr(&mut normalized_pred, join_table, join_alias);
        // The loader answers this query as itself, once, so a conjunct it cannot decide
        // from the row alone would answer a different question than the caller's check
        // does, unless every relation it reads answers everybody alike. A recognized
        // request value keeps its own route.
        let relations = residual_relations(&mut normalized_pred, db, registry, scope, state)?;
        let residual = residual_predicate_reading(&normalized_pred, relations);
        if residual.relations.is_empty()
            && residual.request.is_none()
            && !conjunct_reads_only_the_row(&normalized_pred, join_cols, &session_zoned_columns)
        {
            return None;
        }
        extras.push(residual);
    }

    // Also scan JOIN ON conditions for explicit FK correlation.
    // These are NOT added to extras because the generated tuple query does not include a JOIN.
    for analyzed in &analyzed_predicates.joins {
        if fk_col_is_explicit {
            break;
        }
        match &analyzed.analysis {
            MembershipEqAnalysis::UserColumn(col, how) => {
                if !name_member(&mut user_col, col, how) {
                    return None;
                }
            }
            MembershipEqAnalysis::FkCandidate {
                join_column,
                correlated: reference,
            } => {
                let pair = MembershipJoinPair {
                    join_column: join_column.clone(),
                    outer_column: guarded_row_column(reference.clone(), outer_table)?,
                };
                if !correlated.contains(&pair) {
                    correlated.push(pair);
                }
                fk_col_is_explicit = true;
            }
            MembershipEqAnalysis::OuterCorrelation | MembershipEqAnalysis::NotRelevant => {}
        }
    }

    let (user_column, member_match) = user_col?;
    if correlated.is_empty() {
        return None;
    }

    let extra_predicates = ResidualPredicates::new(extras);

    Some(MembershipColumns {
        pairs: correlated,
        user_column,
        member_match,
        extra_predicates,
    })
}

/// Record the column naming the member, or report that a different one already does.
///
/// A membership carries one member column. The same comparison written twice is one
/// condition, while a second column or a second way of matching the same column is a
/// condition the row would lose, leaving the grant resting on half the policy.
fn name_member(
    member: &mut Option<(ColumnName, MemberMatch)>,
    column: &ColumnName,
    how: &MemberMatch,
) -> bool {
    let (named, matched) = member.get_or_insert_with(|| (column.clone(), how.clone()));
    named == column && matched == how
}
fn is_join_column_ref(
    qualifier: Option<&str>,
    column: &str,
    join_table: &str,
    join_alias: Option<&str>,
    join_cols: &[String],
) -> bool {
    if !join_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        None => true,
        Some(q) => qualifier_matches_table(q, join_table, join_alias),
    }
}

/// Drop `join_table` or `join_alias` qualifiers, leaving bare identifiers that a
/// single-table query can host. Rewrites the AST, not the text, so quoted and
/// dollar-quoted forms survive.
pub(super) fn strip_qualifier_from_expr(
    expr: &mut Expr,
    join_table: &str,
    join_alias: Option<&str>,
) {
    strip_qualifier(expr, join_table, join_alias, false);
}

/// As [`strip_qualifier_from_expr`], but also rewriting references inside nested
/// subqueries.
///
/// Used when the qualifier names a table from an enclosing scope, so a nested
/// reference to it means the same table. A nested query that rebinds the same
/// alias to a different table would be rewritten too, which no realistic policy
/// does.
pub(super) fn strip_qualifier_from_expr_deep(
    expr: &mut Expr,
    join_table: &str,
    join_alias: Option<&str>,
) {
    strip_qualifier(expr, join_table, join_alias, true);
}

fn strip_qualifier(
    expr: &mut Expr,
    join_table: &str,
    join_alias: Option<&str>,
    descend_into_subqueries: bool,
) {
    let mut v = TopLevelOnlyMut::new(descend_into_subqueries, |expr: &mut Expr| {
        if let Expr::CompoundIdentifier(parts) = &*expr {
            if let [.., qualifier, last] = parts.as_slice() {
                if qualifier_matches_table(
                    stored_ident_name(qualifier).as_ref(),
                    join_table,
                    join_alias,
                ) {
                    *expr = Expr::Identifier(last.clone());
                }
            }
        }
        ControlFlow::Continue(())
    });
    let _ = expr.visit(&mut v);
}

pub(super) fn predicate_references_other_table(
    expr: &Expr,
    join_table: &str,
    join_alias: Option<&str>,
) -> bool {
    let mut v = TopLevelOnly::top_level(|expr: &Expr| {
        if let Expr::CompoundIdentifier(parts) = expr {
            if let [.., qualifier, _] = parts.as_slice() {
                if !qualifier_matches_table(
                    stored_ident_name(qualifier).as_ref(),
                    join_table,
                    join_alias,
                ) {
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    });
    expr.visit(&mut v).is_break()
}

#[derive(Debug, Default)]
struct UnqualifiedMembershipScope {
    enforce: bool,
    unknown_other_source: bool,
    join_columns: BTreeSet<String>,
    other_columns: BTreeSet<String>,
}

fn build_unqualified_membership_scope<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    join_table: &str,
    join_cols: &[String],
) -> UnqualifiedMembershipScope {
    let sources = relation_sources(select);
    if sources.len() <= 1 {
        return UnqualifiedMembershipScope::default();
    }

    let join_table_stored = stored_relation_name(join_table);
    let join_columns = join_cols.iter().map(ToString::to_string).collect();

    let mut scope = UnqualifiedMembershipScope {
        enforce: true,
        unknown_other_source: false,
        join_columns,
        other_columns: BTreeSet::new(),
    };

    for source in sources {
        if stored_relation_name(&source.table_name) == join_table_stored {
            continue;
        }

        let Some(table) = lookup_table(db, &source.table_name) else {
            scope.unknown_other_source = true;
            continue;
        };

        // An unreadable column list is as blind as an unresolvable table, and this scope
        // only ever adds a refusal, so both take the same flag.
        let Ok(columns) = table.columns(db) else {
            scope.unknown_other_source = true;
            continue;
        };
        for col in columns {
            scope
                .other_columns
                .insert(col.stored_column_name().into_owned());
        }
    }

    scope
}

fn predicate_has_ambiguous_unqualified_column(
    expr: &Expr,
    scope: &UnqualifiedMembershipScope,
) -> bool {
    if !scope.enforce {
        return false;
    }
    let mut v = TopLevelOnly::top_level(|expr: &Expr| {
        if let Expr::Identifier(ident) = expr {
            let col = stored_ident_name(ident).into_owned();
            let in_join = scope.join_columns.contains(&col);
            let in_other = scope.other_columns.contains(&col);
            if !in_join || in_other || scope.unknown_other_source {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    });
    expr.visit(&mut v).is_break()
}

/// Whether a column qualifier names this scan.
///
/// Every argument is a stored identifier, which is what makes plain equality
/// `PostgreSQL`'s own rule: an unquoted spelling folded on the way in, a quoted one kept
/// its case, and `"M"` therefore never answers for `m`. An alias replaces the table's own
/// name for its scope, so a qualifier spelling the hidden name refers to an enclosing
/// scope's table.
pub(super) fn qualifier_matches_table(
    qualifier: &str,
    table_name: &str,
    alias: Option<&str>,
) -> bool {
    match alias {
        Some(alias) => qualifier == alias,
        None => qualifier == stored_relation_name(table_name),
    }
}

/// Whether two written table spellings denote one table, `None` when the schema does not
/// say.
///
/// Each caller decides what an unprovable answer means, because the safe direction
/// differs: a self scan must refuse when it cannot be ruled out, and a foreign source
/// must refuse when it cannot be ruled in.
fn written_tables_are_same<DB: DatabaseLike>(db: &DB, left: &str, right: &str) -> Option<bool> {
    let left = resolve_table_id(db, left)?;
    let right = resolve_table_id(db, right)?;
    Some(left == right)
}

fn combine_predicates_with_and(predicates: Vec<Expr>) -> Option<Expr> {
    let mut iter = predicates.into_iter();
    let first = iter.next()?;
    Some(iter.fold(first, |acc, next| Expr::BinaryOp {
        left: Box::new(acc),
        op: BinaryOperator::And,
        right: Box::new(next),
    }))
}

pub(super) fn extract_parent_join_columns(
    predicate: &Expr,
    outer_table: &str,
    outer_cols: &[String],
    parent_table: &str,
    parent_alias: Option<&str>,
    parent_cols: &[String],
) -> Option<(ColumnName, ColumnName)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = predicate
    else {
        return None;
    };

    let left_col = extract_qualified_column(left)?;
    let right_col = extract_qualified_column(right)?;

    let left_is_parent = is_parent_column_ref(
        left_col.0.as_deref(),
        left_col.1.as_str(),
        parent_table,
        parent_alias,
        parent_cols,
        outer_cols,
    );
    let right_is_parent = is_parent_column_ref(
        right_col.0.as_deref(),
        right_col.1.as_str(),
        parent_table,
        parent_alias,
        parent_cols,
        outer_cols,
    );

    let left_is_outer = is_outer_column_ref(
        left_col.0.as_deref(),
        left_col.1.as_str(),
        outer_table,
        outer_cols,
        parent_cols,
    );
    let right_is_outer = is_outer_column_ref(
        right_col.0.as_deref(),
        right_col.1.as_str(),
        outer_table,
        outer_cols,
        parent_cols,
    );

    if left_is_parent && right_is_outer {
        return Some((right_col.1, left_col.1));
    }
    if right_is_parent && left_is_outer {
        return Some((left_col.1, right_col.1));
    }

    None
}

fn is_parent_column_ref(
    qualifier: Option<&str>,
    column: &str,
    parent_table: &str,
    parent_alias: Option<&str>,
    parent_cols: &[String],
    outer_cols: &[String],
) -> bool {
    if !parent_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        Some(q) => qualifier_matches_table(q, parent_table, parent_alias),
        None => !outer_cols.iter().any(|c| c == column),
    }
}

fn is_outer_column_ref(
    qualifier: Option<&str>,
    column: &str,
    outer_table: &str,
    outer_cols: &[String],
    parent_cols: &[String],
) -> bool {
    if !outer_cols.iter().any(|c| c == column) {
        return false;
    }

    match qualifier {
        Some(q) => qualifier_matches_table(q, outer_table, None),
        None => !parent_cols.iter().any(|c| c == column),
    }
}

/// Whether `column` of `parent` is a declared foreign key to `table`.`target`.
///
/// One check for both halves a rewrite through a join needs: a matching row always
/// exists, and there is at most one of it, since a foreign key can only target a
/// column the referenced table constrains as unique.
fn fk_targets_column<DB: DatabaseLike>(
    parent: &DB::Table,
    db: &DB,
    column: &str,
    table: &str,
    target: &str,
) -> bool {
    parent
        .foreign_keys(db)
        .into_iter()
        .flatten()
        .filter(|fk| {
            fk.host_column(db)
                .ok()
                .flatten()
                .is_some_and(|host| host.stored_column_name() == column)
        })
        .any(|fk| {
            let table_matches = fk.referenced_table(db).is_ok_and(|referenced| {
                qualifier_matches_table(referenced.stored_table_name().as_ref(), table, None)
            });
            table_matches
                && fk.referenced_column(db).is_ok_and(|referenced| {
                    referenced.is_some_and(|column| column.stored_column_name() == target)
                })
        })
}

fn table_has_fk_to_parent<DB: DatabaseLike>(
    outer_table: &DB::Table,
    db: &DB,
    fk_column: &str,
    parent_table_name: &str,
) -> bool {
    outer_table
        .foreign_keys(db)
        .into_iter()
        .flatten()
        .any(|fk| {
            let host_col_matches = fk
                .host_column(db)
                .ok()
                .flatten()
                .is_some_and(|col| col.stored_column_name() == fk_column);
            if !host_col_matches {
                return false;
            }

            fk.referenced_table(db).is_ok_and(|referenced| {
                qualifier_matches_table(
                    referenced.stored_table_name().as_ref(),
                    parent_table_name,
                    None,
                )
            })
        })
}
