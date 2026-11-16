//! P29, a row its own columns flag, named by a column of the guarded row or reached from it
//! up a recursive walk of edge tables.
//!
//! Only rows decide the test, never the caller, so the tuple loader reads the flag as the
//! policy does wherever nothing hides a row from the reader.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use core::ops::ControlFlow;
use sqlparser::ast::{
    BinaryOperator, Cte, Expr, Ident, JoinConstraint, JoinOperator, ObjectName, Query, Select,
    SelectItem, SetExpr, SetOperator, SetQuantifier, TableAlias, TableFactor, Visit, VisitMut,
    Visitor, VisitorMut,
};

use super::subquery::{
    query_binds_its_own_names, query_locks_its_rows, query_select, select_result_shaping_clause,
    set_limiting_clause,
};
use super::{attribute_literal_predicate, flatten_and_predicates, unparenthesize};
use crate::classifier::exclusion::table_guarded_by_rls;
use crate::classifier::expansion::{call_argument_column, ExpansionState};
use crate::classifier::patterns::*;
use crate::generator::db_lookup::{column_kind, single_identity_column};
use crate::parser::names::{
    resolve_table_id, stored_ident_name, stored_relation_name, table_has_column,
};
use crate::parser::sql_parser::DatabaseLike;
use crate::types::{ColumnName, TableId};

/// Why a test shaped as a row flag does not translate.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FlagRefusal {
    /// The reader sees only the rows its own policies admit.
    #[error(
        "the flag reads '{table}', which has row level security, so read as the caller it \
         finds only the rows the caller's own policies let through, and no tuple decides it"
    )]
    GuardedRead {
        /// The guarded table read.
        table: TableId,
    },
    /// The walk keeps a value beside the row it reaches.
    #[error(
        "the recursive walk '{walk}' keeps {columns} columns, and a column kept beside the row \
         it reaches, such as a depth counter, can stop the walk where OpenFGA follows every \
         parent"
    )]
    WalkKeepsColumns {
        /// The walk's name.
        walk: String,
        /// How many columns it keeps.
        columns: usize,
    },
    /// The walk never ends on a cycle of edges.
    #[error(
        "the recursive walk '{walk}' adds its steps with UNION ALL, which PostgreSQL repeats \
         without end around a cycle of edges where OpenFGA stops at the first repeat, so \
         write UNION"
    )]
    WalkRepeatsRows {
        /// The walk's name.
        walk: String,
    },
    /// Two compared keys are of different types.
    #[error(
        "the flag compares '{left}' with '{right}', whose declared types differ, so one \
         OpenFGA key cannot name both"
    )]
    KeyTypesDiffer {
        /// One key, as `table.column`.
        left: String,
        /// The other key, as `table.column`.
        right: String,
    },
}

/// The flag `expr` tests, `None` where it is not shaped as one.
///
/// `EXISTS (SELECT 1 FROM objects o WHERE o.id = objects.id AND o.archived)` tests the row a
/// column of the guarded row names. A `WITH RECURSIVE` walk inside the `EXISTS`, seeded with
/// that column and stepping up edge tables, tests every row the walk reaches.
pub(crate) fn recognize_flagged_row<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    table: &str,
    state: &ExpansionState,
) -> Option<Result<FlaggedRow, FlagRefusal>> {
    let Expr::Exists {
        subquery,
        negated: false,
    } = unparenthesize(expr)
    else {
        return None;
    };
    if !reads_every_row(subquery) {
        return None;
    }
    let guarded = resolve_table_id(db, table)?;
    let select = query_select(subquery)?;
    let (flagged, walk) = match &subquery.with {
        None => (flagged_select(select, db, &Anchor::Outer { table })?, None),
        Some(with) => {
            let [cte] = with.cte_tables.as_slice() else {
                return None;
            };
            if !with.recursive {
                return None;
            }
            let name = stored_ident_name(&cte.alias.name).into_owned();
            let column = match cte.alias.columns.as_slice() {
                [column] => stored_ident_name(&column.name).into_owned(),
                [] => return None,
                columns => {
                    return Some(Err(FlagRefusal::WalkKeepsColumns {
                        walk: name,
                        columns: columns.len(),
                    }))
                }
            };
            let anchor = Anchor::Walk {
                name: &name,
                column: &column,
            };
            let flagged = flagged_select(select, db, &anchor)?;
            let walk = match walk_of(cte, &name, &column, table, db)? {
                Ok(walk) => walk,
                Err(refusal) => return Some(Err(refusal)),
            };
            (flagged, Some(walk))
        }
    };
    let Flagged {
        table: flagged_table,
        key,
        seed,
        predicates,
    } = flagged;
    let (column, edges) = match walk {
        None => (seed?, Vec::new()),
        Some(Walk { seed, edges }) => (seed, edges),
    };
    if single_identity_column(&flagged_table, db).as_ref() != Some(&key) {
        return None;
    }
    if !state.reading_as_owner() {
        let read = core::iter::once(&flagged_table).chain(edges.iter().map(|edge| &edge.table));
        for table in read {
            if table_guarded_by_rls(db, table) {
                return Some(Err(FlagRefusal::GuardedRead {
                    table: table.clone(),
                }));
            }
        }
    }
    let key_kind = column_kind(&flagged_table, key.as_str(), db);
    let compared = core::iter::once((&guarded, &column)).chain(edges.iter().flat_map(|edge| {
        [
            (&edge.table, &edge.child_column),
            (&edge.table, &edge.parent_column),
        ]
    }));
    for (table, compared) in compared {
        if column_kind(table, compared.as_str(), db) != key_kind {
            return Some(Err(FlagRefusal::KeyTypesDiffer {
                left: format!("{table}.{compared}"),
                right: format!("{flagged_table}.{key}"),
            }));
        }
    }
    Some(Ok(FlaggedRow {
        column,
        table: flagged_table,
        key,
        predicates,
        edges,
    }))
}

/// What the flagged scan's key is compared with.
enum Anchor<'a> {
    /// A column of the guarded row, the policy's `table`.
    Outer { table: &'a str },
    /// The one column of the walk `name`.
    Walk { name: &'a str, column: &'a str },
}

/// The scan of the flagged table an `EXISTS` reads.
struct Flagged {
    table: TableId,
    /// The flagged table's column compared with the anchor.
    key: ColumnName,
    /// The guarded row's column the key is compared with, for an outer anchor.
    seed: Option<ColumnName>,
    predicates: Vec<AttributePredicate>,
}

/// The seed and steps of a walk.
struct Walk {
    seed: ColumnName,
    edges: Vec<FlagEdge>,
}

/// Whether nothing past `FROM` and `WHERE` decides which rows `query` returns.
fn reads_every_row(query: &Query) -> bool {
    set_limiting_clause(query).is_none() && query_locks_its_rows(query).is_none()
}

/// The table a plain `FROM` entry reads, with the name its columns are qualified by.
fn plain_table(factor: &TableFactor) -> Option<(&ObjectName, String)> {
    let table = super::invariant::plain_table(factor)?;
    Some((table.name, visible_name(table.name, table.alias)))
}

fn visible_name(name: &ObjectName, alias: Option<&TableAlias>) -> String {
    alias.map_or_else(
        || stored_relation_name(&name.to_string()),
        |alias| stored_ident_name(&alias.name).into_owned(),
    )
}

/// Whether `name` is one part spelling the binding `binding`.
fn names_binding(name: &ObjectName, binding: &str) -> bool {
    name.0.len() == 1 && stored_relation_name(&name.to_string()) == binding
}

/// The one expression `select` projects.
fn single_projection(select: &Select) -> Option<&Expr> {
    match select.projection.as_slice() {
        [SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }] => Some(expr),
        _ => None,
    }
}

/// `qualifier.column`, both stored.
fn qualified_column(expr: &Expr) -> Option<(String, String)> {
    let Expr::CompoundIdentifier(parts) = unparenthesize(expr) else {
        return None;
    };
    let [qualifier, column] = parts.as_slice() else {
        return None;
    };
    Some((
        stored_ident_name(qualifier).into_owned(),
        stored_ident_name(column).into_owned(),
    ))
}

/// The two sides of `left = right`.
fn equality(expr: &Expr) -> Option<(&Expr, &Expr)> {
    match unparenthesize(expr) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => Some((left, right)),
        _ => None,
    }
}

/// The scan of the flagged table `select` reads beside the anchor, with the key correlated to
/// it and the predicates on the flagged row.
fn flagged_select<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    anchor: &Anchor<'_>,
) -> Option<Flagged> {
    if select_result_shaping_clause(select).is_some() {
        return None;
    }
    let mut factors = Vec::new();
    let mut conjuncts = Vec::new();
    for item in &select.from {
        factors.push(&item.relation);
        for join in &item.joins {
            match &join.join_operator {
                JoinOperator::Join(JoinConstraint::On(on))
                | JoinOperator::Inner(JoinConstraint::On(on)) => {
                    flatten_and_predicates(on, &mut conjuncts);
                }
                JoinOperator::CrossJoin(JoinConstraint::None) => {}
                _ => return None,
            }
            factors.push(&join.relation);
        }
    }
    if let Some(selection) = &select.selection {
        flatten_and_predicates(selection, &mut conjuncts);
    }
    let mut flagged = None;
    let mut walk_visible = None;
    for factor in factors {
        let (name, visible) = plain_table(factor)?;
        match anchor {
            Anchor::Walk { name: walk, .. }
                if walk_visible.is_none() && names_binding(name, walk) =>
            {
                walk_visible = Some(visible);
            }
            _ if flagged.is_none() => {
                flagged = Some((resolve_table_id(db, &name.to_string())?, visible));
            }
            _ => return None,
        }
    }
    let (table, flagged_visible) = flagged?;
    let scope = Scope {
        db,
        flagged: &table,
        flagged_visible: &flagged_visible,
        anchor,
        walk_visible: walk_visible.as_deref(),
    };
    if matches!(anchor, Anchor::Walk { .. }) && scope.walk_visible.is_none() {
        return None;
    }
    let mut correlation = None;
    let mut predicates = Vec::new();
    for conjunct in conjuncts {
        if let Some(found) = scope.correlation(conjunct) {
            if correlation.replace(found).is_some() {
                return None;
            }
            continue;
        }
        predicates.push(scope.predicate(conjunct)?);
    }
    let (key, seed) = correlation?;
    if predicates.is_empty() {
        return None;
    }
    Some(Flagged {
        table,
        key,
        seed,
        predicates,
    })
}

/// The names one scan of the flagged table sees.
struct Scope<'s, DB> {
    db: &'s DB,
    flagged: &'s TableId,
    flagged_visible: &'s str,
    anchor: &'s Anchor<'s>,
    walk_visible: Option<&'s str>,
}

/// What one column reference in the flagged scan reads.
enum Reference {
    Flagged(ColumnName),
    /// The anchor, with the guarded row's column where the anchor is the outer row.
    Anchor(Option<ColumnName>),
}

impl<DB: DatabaseLike> Scope<'_, DB> {
    fn flagged_column(&self, column: &str) -> Option<ColumnName> {
        table_has_column(self.db, &self.flagged.to_string(), column)
            .then(|| ColumnName::from_stored(column.to_string()))
    }

    fn reference(&self, expr: &Expr) -> Option<Reference> {
        let expr = unparenthesize(expr);
        if let Expr::Identifier(ident) = expr {
            let column = stored_ident_name(ident);
            if let Anchor::Walk { column: walked, .. } = self.anchor {
                if column == *walked {
                    // Named by both scans, the column is ambiguous and PostgreSQL rejects it.
                    return self
                        .flagged_column(&column)
                        .is_none()
                        .then_some(Reference::Anchor(None));
                }
            }
            return self.flagged_column(&column).map(Reference::Flagged);
        }
        if let Some((qualifier, column)) = qualified_column(expr) {
            if qualifier == self.flagged_visible {
                return self.flagged_column(&column).map(Reference::Flagged);
            }
            if let (Anchor::Walk { column: walked, .. }, Some(walk)) =
                (self.anchor, self.walk_visible)
            {
                return (qualifier == walk && column == *walked).then_some(Reference::Anchor(None));
            }
        }
        match (self.anchor, expr) {
            (Anchor::Outer { table }, Expr::CompoundIdentifier(_)) => {
                call_argument_column(expr, table).map(|column| Reference::Anchor(Some(column)))
            }
            _ => None,
        }
    }

    /// The flagged key and the guarded column of `flagged.key = anchor`.
    fn correlation(&self, conjunct: &Expr) -> Option<(ColumnName, Option<ColumnName>)> {
        let (left, right) = equality(conjunct)?;
        match (self.reference(left)?, self.reference(right)?) {
            (Reference::Flagged(key), Reference::Anchor(seed))
            | (Reference::Anchor(seed), Reference::Flagged(key)) => Some((key, seed)),
            _ => None,
        }
    }

    /// `conjunct` as a test of the flagged row a tuple query decides.
    fn predicate(&self, conjunct: &Expr) -> Option<AttributePredicate> {
        if !self.reads_only_the_flagged_row(conjunct) {
            return None;
        }
        let mut bare = conjunct.clone();
        let _ = VisitMut::visit(&mut bare, &mut StripQualifiers);
        let bare = unparenthesize(&bare);
        let predicate = match bare {
            Expr::Identifier(ident) => boolean_true(ident),
            Expr::IsTrue(inner) => match unparenthesize(inner) {
                Expr::Identifier(ident) => boolean_true(ident),
                _ => return None,
            },
            other => attribute_literal_predicate(other)?,
        };
        decided_by_the_row(&predicate.test).then_some(predicate)
    }

    fn reads_only_the_flagged_row(&self, conjunct: &Expr) -> bool {
        struct OnlyFlagged<'v, 's, DB>(&'v Scope<'s, DB>);
        impl<DB: DatabaseLike> Visitor for OnlyFlagged<'_, '_, DB> {
            type Break = ();
            fn pre_visit_query(&mut self, _query: &Query) -> ControlFlow<()> {
                ControlFlow::Break(())
            }
            fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
                match expr {
                    Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
                        match self.0.reference(expr) {
                            Some(Reference::Flagged(_)) => ControlFlow::Continue(()),
                            _ => ControlFlow::Break(()),
                        }
                    }
                    Expr::Function(_) => ControlFlow::Break(()),
                    _ => ControlFlow::Continue(()),
                }
            }
        }
        conjunct.visit(&mut OnlyFlagged(self)).is_continue()
    }
}

/// `column = TRUE`, which a bare boolean column tests.
fn boolean_true(ident: &Ident) -> AttributePredicate {
    AttributePredicate {
        column: ColumnName::from_stored(stored_ident_name(ident).into_owned()),
        test: AttributeTest::Compare {
            operator: AttributeOperator::Eq,
            value: AttributeLiteral::Boolean(true),
        },
    }
}

/// Whether the row alone decides `test`, apart from the session's time zone and locale.
fn decided_by_the_row(test: &AttributeTest) -> bool {
    let plain = |literal: &AttributeLiteral| {
        matches!(
            literal,
            AttributeLiteral::Text(_)
                | AttributeLiteral::AsText(_)
                | AttributeLiteral::Number(_)
                | AttributeLiteral::Boolean(_)
        )
    };
    match test {
        AttributeTest::Compare { value, .. } => plain(value),
        AttributeTest::In(values) => values.iter().all(plain),
        AttributeTest::IsNull | AttributeTest::IsNotNull => true,
    }
}

/// Drops the qualifier of every `qualifier.column`, once each is known to name the flagged
/// scan.
struct StripQualifiers;

impl VisitorMut for StripQualifiers {
    type Break = ();
    fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        let column = match expr {
            Expr::CompoundIdentifier(parts) => parts.pop(),
            _ => None,
        };
        if let Some(column) = column {
            *expr = Expr::Identifier(column);
        }
        ControlFlow::Continue(())
    }
}

/// The seed and edges of the recursive `cte`, which binds `name` with the one `column`.
fn walk_of<DB: DatabaseLike>(
    cte: &Cte,
    name: &str,
    column: &str,
    table: &str,
    db: &DB,
) -> Option<Result<Walk, FlagRefusal>> {
    let query = &cte.query;
    if query_binds_its_own_names(query) || !reads_every_row(query) {
        return None;
    }
    let SetExpr::SetOperation {
        op: SetOperator::Union,
        set_quantifier,
        left,
        right,
    } = query.body.as_ref()
    else {
        return None;
    };
    let SetExpr::Select(seed) = left.as_ref() else {
        return None;
    };
    if !seed.from.is_empty()
        || seed.selection.is_some()
        || select_result_shaping_clause(seed).is_some()
    {
        return None;
    }
    let seed = call_argument_column(single_projection(seed)?, table)?;
    let SetExpr::Select(step) = right.as_ref() else {
        return None;
    };
    let edges = step_edges(step, name, column, db)?;
    match set_quantifier {
        SetQuantifier::Distinct | SetQuantifier::None => Some(Ok(Walk { seed, edges })),
        SetQuantifier::All => Some(Err(FlagRefusal::WalkRepeatsRows {
            walk: name.to_string(),
        })),
        _ => None,
    }
}

/// The edges one recursive step of the walk `name` follows, from its one `column`.
///
/// `FROM walk JOIN edge e ON e.child = walk.column` projecting `e.parent`, or `FROM walk
/// CROSS JOIN LATERAL (...) p` projecting `p.parent` over a `UNION` of such edge reads.
fn step_edges<DB: DatabaseLike>(
    step: &Select,
    name: &str,
    column: &str,
    db: &DB,
) -> Option<Vec<FlagEdge>> {
    if step.selection.is_some() || select_result_shaping_clause(step).is_some() {
        return None;
    }
    let [item] = step.from.as_slice() else {
        return None;
    };
    let (walk, walk_visible) = plain_table(&item.relation)?;
    if !names_binding(walk, name) {
        return None;
    }
    let [join] = item.joins.as_slice() else {
        return None;
    };
    let (qualifier, parent) = qualified_column(single_projection(step)?)?;
    let walk = WalkColumn {
        visible: &walk_visible,
        column,
    };
    match (&join.join_operator, &join.relation) {
        (
            JoinOperator::CrossJoin(JoinConstraint::None),
            TableFactor::Derived {
                lateral: true,
                subquery,
                alias: Some(alias),
                sample: None,
            },
        ) => {
            // A valid step names one column of the subquery, and each branch projects one.
            if qualifier != stored_ident_name(&alias.name) {
                return None;
            }
            lateral_edges(subquery, &walk, db)
        }
        (
            JoinOperator::Join(JoinConstraint::On(on))
            | JoinOperator::Inner(JoinConstraint::On(on)),
            relation,
        ) => {
            let (edge, edge_visible) = plain_table(relation)?;
            if qualifier != edge_visible {
                return None;
            }
            Some(vec![edge_of(db, edge, &edge_visible, on, &walk, parent)?])
        }
        _ => None,
    }
}

/// The walk's column as a step reads it.
struct WalkColumn<'a> {
    visible: &'a str,
    column: &'a str,
}

/// The edges a lateral `UNION` of edge reads follows, each branch projecting the parent.
fn lateral_edges<DB: DatabaseLike>(
    subquery: &Query,
    walk: &WalkColumn<'_>,
    db: &DB,
) -> Option<Vec<FlagEdge>> {
    if query_binds_its_own_names(subquery) || !reads_every_row(subquery) {
        return None;
    }
    let mut branches = Vec::new();
    union_branches(&subquery.body, &mut branches)?;
    let mut edges = Vec::with_capacity(branches.len());
    for branch in branches {
        if select_result_shaping_clause(branch).is_some() {
            return None;
        }
        let [item] = branch.from.as_slice() else {
            return None;
        };
        if !item.joins.is_empty() {
            return None;
        }
        let (edge, edge_visible) = plain_table(&item.relation)?;
        let (qualifier, parent) = qualified_column(single_projection(branch)?)?;
        if qualifier != edge_visible {
            return None;
        }
        let condition = branch.selection.as_ref()?;
        edges.push(edge_of(db, edge, &edge_visible, condition, walk, parent)?);
    }
    Some(edges)
}

/// The `Select` leaves of a `UNION`, either quantifier, since the walk's own `UNION` drops
/// what a step repeats.
fn union_branches<'q>(body: &'q SetExpr, out: &mut Vec<&'q Select>) -> Option<()> {
    match body {
        SetExpr::Select(select) => {
            out.push(select);
            Some(())
        }
        SetExpr::SetOperation {
            op: SetOperator::Union,
            set_quantifier: SetQuantifier::All | SetQuantifier::Distinct | SetQuantifier::None,
            left,
            right,
        } => {
            union_branches(left, out)?;
            union_branches(right, out)
        }
        _ => None,
    }
}

/// The edge `condition`, `edge.child = walk.column`, makes of the `edge` table read as
/// `edge_visible`, naming `parent` the parent.
fn edge_of<DB: DatabaseLike>(
    db: &DB,
    edge: &ObjectName,
    edge_visible: &str,
    condition: &Expr,
    walk: &WalkColumn<'_>,
    parent: String,
) -> Option<FlagEdge> {
    // An edge read under the walk's own name hides the walk inside the branch.
    if edge_visible == walk.visible {
        return None;
    }
    let (left, right) = equality(condition)?;
    let left = qualified_column(left)?;
    let right = qualified_column(right)?;
    let reads_walk =
        |(qualifier, column): &(String, String)| qualifier == walk.visible && column == walk.column;
    let child = if reads_walk(&right) && left.0 == edge_visible {
        left.1
    } else if reads_walk(&left) && right.0 == edge_visible {
        right.1
    } else {
        return None;
    };
    let table = resolve_table_id(db, &edge.to_string())?;
    let written = table.to_string();
    (table_has_column(db, &written, &child) && table_has_column(db, &written, &parent)).then(|| {
        FlagEdge {
            table,
            child_column: ColumnName::from_stored(child),
            parent_column: ColumnName::from_stored(parent),
        }
    })
}
