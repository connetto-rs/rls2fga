//! Statements reaching a table through a view that runs with its owner's rights.
//!
//! `PostgreSQL` checks the relations under such a view against its owner, so a role
//! granted the view reaches rows of the table its own policies refuse. An automatically
//! updatable view over one table writes that table's rows, and a statement through it
//! touches only the rows its condition admits. With a check option, the row a write
//! produces has to pass the condition too.
//!
//! Each such view is one more path to the table's rows, answered on a type of its own
//! whose objects are the table's rows under the table's key. Its rule is the view's
//! condition, read like a permissive policy whose `USING` judges the stored row and whose
//! `WITH CHECK` judges the produced one, and its privileges are those the acting role
//! holds on the view, carried over to the table's columns.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};
use core::ops::ControlFlow;

use sqlparser::ast::{Expr, Ident, Value, VisitMut, VisitorMut};

use crate::classifier::function_registry::FunctionRegistry;
use crate::classifier::patterns::{
    filter_policies_for_output, ClassifiedPolicy, PolicyMode, StoredClause,
};
use crate::classifier::policy_classifier::classify_expr;
use crate::parser::names::table_identity;
use crate::parser::sql_parser::{
    ActingRole, ColumnLike, ColumnPrivilege, DatabaseLike, Deployment, RowSecurity, RowStatement,
    RuleLike, TableLike, TablePrivileges, TriggerLike, ViewLike, WrittenRelation,
};
use crate::types::{ColumnName, ConfidenceLevel, Holding, PolicyCommand, TableId, TranslationNote};
use sql_traits::structs::PolicyTarget;

/// Why the model cannot follow what a view running with its owner's rights grants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PathRefusal {
    /// The view stores rows of its own.
    #[error("it is materialized")]
    Materialized,
    /// `PostgreSQL` does not pass a write on to one relation.
    #[error("it is not automatically updatable")]
    NotUpdatable,
    /// Its relation is no table this translation reads rows of.
    #[error("it reads a foreign table")]
    ForeignTable,
    /// Its relation is another view.
    #[error("it reads another view")]
    OverView,
    /// A trigger or a rule takes the write before the view passes it on.
    #[error("{0} takes a write to it")]
    Instead(String),
    /// The catalog does not record whose rights it runs with.
    #[error("its owner is not recorded")]
    UnknownOwner,
    /// The table's policies reach the owner, so they filter what the view passes on.
    #[error("the policies of '{0}' reach its owner")]
    OwnerFiltered(TableId),
    /// Reading the table reads the rows of tables inheriting from it.
    #[error("tables inherit from '{0}'")]
    InheritedRows(TableId),
    /// A lookup the answer depends on failed.
    #[error("{0}")]
    Lookup(String),
}

/// Where one acting role may run each command through a view, over the table's columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathHolding {
    /// Where it may read.
    pub(crate) select: Holding,
    /// Where it may insert.
    pub(crate) insert: Holding,
    /// Where it may update.
    pub(crate) update: Holding,
    /// Whether it may delete.
    pub(crate) delete: bool,
}

impl PathHolding {
    /// Whether the role holds no command at all.
    fn is_empty(&self) -> bool {
        self.select == Holding::Absent
            && self.insert == Holding::Absent
            && self.update == Holding::Absent
            && !self.delete
    }
}

/// One view running with its owner's rights through which an acting role reaches the rows
/// of one table.
#[derive(Debug, Clone)]
pub(crate) struct ViewPath {
    /// The view, as the catalog names it.
    pub(crate) view: TableId,
    /// The table its statements land on.
    pub(crate) table: TableId,
    /// What a row of the table passes to be a row of the view, over the table's own
    /// columns, `None` for a view admitting every row.
    pub(crate) condition: Option<Expr>,
    /// Whether the row a write produces has to pass the condition too.
    pub(crate) checked: bool,
    /// Per acting role holding a privilege on the view, where it holds each command.
    pub(crate) holdings: BTreeMap<String, PathHolding>,
}

impl ViewPath {
    /// The name the view's condition goes by where a note or a report names it.
    pub(crate) fn rule_name(&self) -> String {
        format!("view {}", self.view)
    }

    /// The view's condition as the permissive policy it acts as, once per acting role of
    /// `deployment`, read by `registry` and kept where it meets `min_confidence`.
    ///
    /// Its `USING` judges the stored row of a read, an update and a delete. Its `WITH
    /// CHECK` judges the row an insert or an update produces, and admits every row where
    /// the view has no check option, since nothing then constrains that row.
    pub(crate) fn policies<DB: DatabaseLike>(
        &self,
        db: &DB,
        registry: &FunctionRegistry,
        deployment: &Deployment,
        min_confidence: ConfidenceLevel,
    ) -> Vec<ClassifiedPolicy> {
        let every_row = Expr::value(Value::Boolean(true));
        let using = self.condition.clone().unwrap_or_else(|| every_row.clone());
        let check = match &self.condition {
            Some(condition) if self.checked => condition.clone(),
            _ => every_row,
        };
        let table = self.table.to_string();
        let mut registry = registry.clone();
        let mut policies = Vec::new();
        for role in deployment.acting_roles() {
            registry.set_acting_role(Some(role));
            let classify =
                |expr: &Expr| classify_expr(expr, db, &registry, &table, PolicyCommand::All);
            policies.push(ClassifiedPolicy {
                name: self.rule_name(),
                table: table.clone(),
                resolved_table: Some(self.table.clone()),
                command: PolicyCommand::All,
                mode: PolicyMode::Permissive,
                acting_role: Some(role.to_string()),
                using_classification: Some(classify(&using)),
                with_check_classification: Some(classify(&check)),
                using: Some(StoredClause::Read(using.clone())),
                with_check: Some(StoredClause::Read(check.clone())),
                using_filtered_at: None,
                with_check_filtered_at: None,
                using_targets: vec![
                    PolicyTarget::Select,
                    PolicyTarget::UpdateUsing,
                    PolicyTarget::Delete,
                ],
                with_check_targets: vec![PolicyTarget::Insert, PolicyTarget::UpdateCheck],
                illegal_clause: None,
            });
        }
        filter_policies_for_output(&policies, min_confidence)
    }
}

/// Every view running with its owner's rights through which an acting role of
/// `deployment` reaches the rows of a table, and a note per view and acting role whose
/// reach the model cannot follow.
///
/// A view running with its reader's rights applies the table's policies and privileges to
/// the reader, so it reaches nothing the table does not grant already.
pub(crate) fn discover<DB: DatabaseLike>(
    db: &DB,
    deployment: &Deployment,
) -> (Vec<ViewPath>, Vec<TranslationNote>) {
    let Ok(resolved) = deployment.resolve(db) else {
        return (Vec::new(), Vec::new());
    };
    let acting: Vec<(&str, &DB::Role)> = deployment
        .acting_roles()
        .zip(resolved.acting_roles())
        .collect();
    let mut paths = Vec::new();
    let mut notes = Vec::new();
    for view in db.views().filter(|view| !view.is_security_invoker()) {
        let identity = view_identity(view);
        let privileges: Vec<(&str, TablePrivileges<usize>)> = acting
            .iter()
            .filter_map(|(name, role)| {
                let held = view.privileges(ActingRole::Declared(*role), db).ok()?;
                holds_any(&held).then_some((*name, held))
            })
            .collect();
        if privileges.is_empty() {
            continue;
        }
        match view_path(view, &identity, &privileges, db) {
            Ok(Some(path)) => paths.push(path),
            Ok(None) => {}
            Err(refusal) => {
                notes.extend(privileges.iter().map(|(role, _)| {
                    TranslationNote::OwnerRightsViewRefused {
                        view: identity.clone(),
                        role: (*role).to_string(),
                        reason: refusal.to_string(),
                    }
                }));
            }
        }
    }
    for view in db.materialized_views() {
        let identity = view_identity(view);
        for (name, role) in &acting {
            if view
                .privileges(ActingRole::Declared(*role), db)
                .is_ok_and(|held| holds_any(&held))
            {
                notes.push(TranslationNote::OwnerRightsViewRefused {
                    view: identity.clone(),
                    role: (*name).to_string(),
                    reason: PathRefusal::Materialized.to_string(),
                });
            }
        }
    }
    (paths, notes)
}

/// `view` as the catalog names it.
fn view_identity<V: ViewLike>(view: &V) -> TableId {
    TableId::from_stored(
        view.stored_view_schema()
            .filter(|schema| schema != "public")
            .map(Into::into),
        view.stored_view_name().into(),
    )
}

/// Whether `privileges` hold any command reaching rows.
fn holds_any<C: PartialEq>(privileges: &TablePrivileges<C>) -> bool {
    privileges.select.on_any_column()
        || privileges.insert.on_any_column()
        || privileges.update.on_any_column()
        || privileges.delete
}

/// The path `view` opens to its table's rows for the roles holding `privileges` on it,
/// `None` where no command reaches the table through it.
fn view_path<'db, DB: DatabaseLike>(
    view: &'db DB::View,
    identity: &TableId,
    privileges: &[(&str, TablePrivileges<usize>)],
    db: &'db DB,
) -> Result<Option<ViewPath>, PathRefusal> {
    let lookup = |error: sql_traits::errors::LookupError| PathRefusal::Lookup(error.to_string());
    let Some(base) = view.updatable_base(db).map_err(lookup)? else {
        return Err(PathRefusal::NotUpdatable);
    };
    let condition = base.condition;
    let (table, columns, condition_columns) = match base.relation {
        WrittenRelation::ForeignTable { .. } => return Err(PathRefusal::ForeignTable),
        WrittenRelation::View { .. } => return Err(PathRefusal::OverView),
        WrittenRelation::Table {
            table,
            columns,
            condition_columns,
        } => (table, columns, condition_columns),
    };
    if let Some(trigger) = view.triggers(db).next() {
        return Err(PathRefusal::Instead(format!(
            "trigger '{}'",
            trigger.name()
        )));
    }
    let target = view.target_name();
    if let Some(rule) = db
        .rules()
        .find(|rule| rule.target_relation_name() == target && rule.is_instead())
    {
        return Err(PathRefusal::Instead(format!("rule '{}'", rule.name())));
    }
    let table_id = table_identity(table);
    let inherited = db.tables().any(|child| {
        child
            .inherits_from(db)
            .into_iter()
            .flatten()
            .any(|parent| table_identity(parent) == table_id)
    });
    if inherited {
        return Err(PathRefusal::InheritedRows(table_id));
    }
    let owner = view
        .owner(db)
        .map_err(lookup)?
        .and_then(|owner| db.role(owner))
        .ok_or(PathRefusal::UnknownOwner)?;
    for statement in [
        RowStatement::Select,
        RowStatement::Insert { returning: false },
        RowStatement::Update { reads: false },
        RowStatement::Delete { reads: false },
    ] {
        match table.row_security(statement, ActingRole::Declared(owner), db) {
            Ok(RowSecurity::Exempt(_)) => {}
            Ok(_) => return Err(PathRefusal::OwnerFiltered(table_id)),
            Err(error) => return Err(PathRefusal::Lookup(error.to_string())),
        }
    }
    let owner_holds = table
        .privileges(ActingRole::Declared(owner), db)
        .map_err(lookup)?;
    let every_column: BTreeSet<ColumnName> = table
        .columns(db)
        .map_err(lookup)?
        .map(|column| ColumnName::from_stored(column.stored_column_name()))
        .collect();
    let carried = |on_view: &ColumnPrivilege<usize>, on_table: &ColumnPrivilege<&DB::Column>| {
        let held: BTreeSet<ColumnName> = columns
            .iter()
            .enumerate()
            .filter_map(|(position, column)| {
                let column = (*column)?;
                (on_view.on_column(position) && on_table.on_column(column))
                    .then(|| ColumnName::from_stored(column.stored_column_name()))
            })
            .collect();
        if held.is_empty() {
            Holding::Absent
        } else if held == every_column {
            Holding::Table
        } else {
            Holding::Columns(held)
        }
    };
    let holdings: BTreeMap<String, PathHolding> = privileges
        .iter()
        .map(|(role, held)| {
            let holding = PathHolding {
                select: carried(&held.select, &owner_holds.select),
                insert: carried(&held.insert, &owner_holds.insert),
                update: carried(&held.update, &owner_holds.update),
                delete: held.delete && owner_holds.delete,
            };
            ((*role).to_string(), holding)
        })
        .filter(|(_, holding)| !holding.is_empty())
        .collect();
    if holdings.is_empty() {
        return Ok(None);
    }
    let condition = condition.map(|condition| {
        let mut rewritten = condition.clone();
        let _ = rewritten.visit(&mut BaseColumns {
            table: table.stored_table_name().to_string(),
            columns: condition_columns
                .iter()
                .map(|(index, column)| (*index, column.stored_column_name().to_string()))
                .collect(),
            index: 0,
        });
        rewritten
    });
    Ok(Some(ViewPath {
        view: identity.clone(),
        table: table_id,
        condition,
        checked: view.check_option().is_some(),
        holdings,
    }))
}

/// Rewrites each reference of a view's condition to its table's column, named through
/// the table so a relation a subquery reads cannot take it.
struct BaseColumns {
    /// The table's name as stored.
    table: String,
    /// The column each reference names, keyed by its index in the pre-order walk over
    /// every expression of the condition.
    columns: BTreeMap<usize, String>,
    /// The index of the next expression the walk meets.
    index: usize,
}

impl VisitorMut for BaseColumns {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        if let Some(column) = self.columns.get(&self.index) {
            *expr = Expr::CompoundIdentifier(vec![
                Ident::with_quote('"', self.table.clone()),
                Ident::with_quote('"', column.clone()),
            ]);
        }
        self.index += 1;
        ControlFlow::Continue(())
    }
}
