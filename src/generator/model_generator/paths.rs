//! Each view running with its owner's rights, answered as one more path to its table's rows.
//!
//! The path is a type of its own named after the view, whose objects are the table's rows
//! under the table's key and whose action relations are the view's condition gated on the
//! privileges each acting role holds on the view. A statement on the table passes where its
//! own policies or any path grants it.

use super::branches::{Asked, ASKED};
use super::*;

use crate::generator::view_paths::{PathHolding, ViewPath};
use crate::types::{ActingPrivileges, ActionAnswer, ActionRelations, Holding};

/// One view path and the policies its condition acts as, per acting role.
pub(crate) struct PlannedPath {
    /// The view and what it grants.
    pub(crate) path: ViewPath,
    /// Its condition as permissive policies, kept where they meet the threshold.
    pub(crate) policies: Vec<ClassifiedPolicy>,
}

/// Whether `holding` holds the command `asked` runs.
fn holds(asked: Asked, holding: &PathHolding) -> bool {
    match asked {
        Asked::Select => holding.select != Holding::Absent,
        Asked::Insert => holding.insert != Holding::Absent,
        Asked::Update => holding.update != Holding::Absent,
        Asked::Delete => holding.delete,
    }
}

/// What building a path type reads and records beside the type itself.
pub(super) struct PathBuild<'a, DB: DatabaseLike> {
    pub(super) notes: &'a mut Vec<TranslationNote>,
    pub(super) confidence_summary: &'a mut Vec<(String, ConfidenceLevel)>,
    pub(super) db: &'a DB,
    pub(super) settings: &'a GeneratorSettings,
    pub(super) table_types: &'a TableTypes,
    pub(super) condition_parameters: &'a ConditionParameterAllocator,
}

impl<DB: DatabaseLike> PathBuild<'_, DB> {
    /// Build `plan`, the path type `planned` answers on, for every acting role of
    /// `branches`, returning where each role holds each command there.
    pub(super) fn plan_path(
        &mut self,
        planned: &PlannedPath,
        plan: &mut TypePlan,
        other_types: &mut BTreeMap<TypeName, TypePlan>,
        branches: &mut [ActingBranch<'_, DB>],
    ) -> Vec<ActingPrivileges> {
        let path = &planned.path;
        let notes_before = self.notes.len();
        plan.names_rows_of(&path.table);
        for cp in &planned.policies {
            for (reason, targets) in unreadable_clause_targets(cp) {
                let note = TranslationNote::ExpressionRefused {
                    policy: cp.name().to_string(),
                    reason: reason.to_string(),
                };
                if !self.notes.contains(&note) {
                    self.notes.push(note);
                }
                mark_narrowed(plan, &targets);
            }
        }
        let mut per_target: BTreeMap<ActionTarget, Vec<UsersetExpr>> = BTreeMap::new();
        let mut held = Vec::new();
        for branch in branches.iter_mut() {
            let Some((role, _)) = branch.role else {
                continue;
            };
            let Some(holding) = path.holdings.get(role) else {
                continue;
            };
            held.push(ActingPrivileges {
                type_name: plan.type_name.clone(),
                role: role.to_string(),
                select: holding.select.clone(),
                insert: holding.insert.clone(),
                update: holding.update.clone(),
                delete: holding.delete,
            });
            let mut parts = BTreeMap::new();
            let mine: Vec<&ClassifiedPolicy> = planned
                .policies
                .iter()
                .filter(|cp| branch.classified(cp))
                .collect();
            {
                let mut build = TableBuild {
                    source_table: &path.table,
                    plan: &mut *plan,
                    other_types: &mut *other_types,
                    notes: &mut *self.notes,
                    readability: &mut branch.readability,
                    confidence_summary: &mut *self.confidence_summary,
                    db: self.db,
                    registry: &branch.registry,
                    settings: self.settings,
                    table_types: self.table_types,
                    condition_parameters: self.condition_parameters,
                };
                for cp in mine {
                    parts.extend(build.translate_one_policy(cp));
                }
            }
            let Some(walk) = acting_kind_walk(role, &path.table, self.db, plan, other_types) else {
                continue;
            };
            for asked in ASKED.into_iter().filter(|asked| holds(*asked, holding)) {
                for target in asked.targets() {
                    let bucket = match parts.get(target) {
                        Some(PolicyPart::Grant(expr)) => ModeBuckets {
                            permissive: vec![expr.clone()],
                            ..ModeBuckets::default()
                        },
                        _ => ModeBuckets::default(),
                    };
                    let answer = TargetAnswer::Gated(bucket);
                    if let Some(expr) = branch_expr(&answer, Some(walk.clone()), plan) {
                        per_target.entry(*target).or_default().push(expr);
                    }
                }
            }
        }
        for cp in &planned.policies {
            for (clause, confidence, targets) in clauses_lost_to_the_threshold(cp) {
                mark_narrowed(plan, &targets);
                let note = TranslationNote::ClauseBelowThreshold {
                    table: path.view.clone(),
                    policy: cp.name().to_string(),
                    mode: cp.mode().to_string(),
                    clause: clause.to_string(),
                    confidence,
                    commands: commands_fed_by(&targets),
                    relations: narrowed_by(&targets).into_iter().collect(),
                };
                if !self.notes.contains(&note) {
                    self.notes.push(note);
                }
            }
        }
        dedup_notes_added_since(self.notes, notes_before);
        let composed: BTreeMap<ActionTarget, UsersetExpr> = per_target
            .into_iter()
            .filter_map(|(target, branches)| combine_union(branches).map(|expr| (target, expr)))
            .collect();
        note_request_contracts(plan, self.notes);
        set_action_relations(plan, composed);
        plant_column_relations(plan, other_types, &held);
        fill_uncovered_actions_with_deny(plan);
        held
    }
}

/// Fold each path's answers into the answers of the table it reaches, as one more way a
/// statement on that table passes.
pub(super) fn fold_path_answers(
    entries: &mut Vec<ActionRelations>,
    types: &BTreeMap<TypeName, TypePlan>,
) {
    let path_of = |entry: &ActionRelations| {
        types
            .get(&entry.type_name)
            .and_then(|plan| plan.path_of.clone())
    };
    let (paths, mut own): (Vec<ActionRelations>, Vec<ActionRelations>) = entries
        .drain(..)
        .partition(|entry| path_of(entry).is_some());
    for path in paths {
        let Some(table) = path_of(&path) else {
            continue;
        };
        match own
            .iter_mut()
            .find(|entry| entry.type_name == table && entry.statement == path.statement)
        {
            Some(entry) => {
                let base = core::mem::replace(&mut entry.answer, ActionAnswer::Denied);
                entry.answer = ActionAnswer::any_of([base, path.answer]);
            }
            None => own.push(ActionRelations::new(
                table,
                path.statement,
                ActionAnswer::any_of([path.answer]),
            )),
        }
    }
    own.sort_by(|left, right| {
        left.type_name
            .as_str()
            .cmp(right.type_name.as_str())
            .then(left.statement.cmp(&right.statement))
    });
    *entries = own;
}
