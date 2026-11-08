//! Which relations answer one action, and which version of the row each judges.
//!
//! A statement is answered by relations the emitted model may or may not define, since a
//! policy writing one condition and a policy writing two produce different relations for
//! the same `UPDATE`. A consumer branching on which ones exist re-derives that mapping,
//! and a later revision emitting them under a further condition makes the branch judge a
//! replacement against one row version, which grants.
//!
//! Reading the relation names off the model is not enough either: nothing in the model
//! text says whether a relation judges the row as it is or as it will be, and a `WITH
//! CHECK` clause only means anything against the second.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::generator::model_generator::{relation_grants_nothing, SchemaPlan, TypePlan};
use crate::generator::unrestricted;
use crate::generator::well_known::{
    can_delete_relation, can_insert_relation, can_insert_returning_relation,
    can_select_for_update_relation, can_select_relation, can_update_check_relation,
    can_update_relation, can_update_using_relation, can_update_without_reading_check_relation,
    can_update_without_reading_relation,
};
use crate::parser::names::lookup_table_id;
use crate::parser::sql_parser::DatabaseLike;
use crate::types::{
    ActionAnswer, ActionJudgement, ActionRelations, ActionStatement, RelationName, RowVersion,
    TableId,
};

const EVERY_STATEMENT: [ActionStatement; 8] = [
    ActionStatement::Select,
    ActionStatement::Insert,
    ActionStatement::Update,
    ActionStatement::Delete,
    ActionStatement::SelectForUpdate,
    ActionStatement::InsertOnConflictUpdate,
    ActionStatement::InsertReturning,
    ActionStatement::UpdateWithoutWhere,
];

fn judge(relation: RelationName, version: RowVersion) -> ActionJudgement {
    ActionJudgement::new(relation, version)
}

/// The relation the type defines, or the one the model falls back to where it does not.
fn defined_or(plan: &TypePlan, wanted: RelationName, fallback: RelationName) -> RelationName {
    if plan.computed_relations.contains_key(&wanted) {
        wanted
    } else {
        fallback
    }
}

/// Whether this type answers the two `UPDATE` clauses apart, which it does exactly
/// where the policies gave them different rules. Asked once, since a second reading
/// could disagree with the first.
fn clauses_answered_apart(plan: &TypePlan) -> bool {
    plan.computed_relations
        .contains_key(&can_update_using_relation())
}

/// What a replacement has to satisfy: the two halves where the policy's clauses differ,
/// and the one relation twice where a lone `USING` is mirrored onto the result.
fn update_judgements(plan: &TypePlan) -> Vec<ActionJudgement> {
    if clauses_answered_apart(plan) {
        vec![
            judge(can_update_using_relation(), RowVersion::Existing),
            judge(can_update_check_relation(), RowVersion::Resulting),
        ]
    } else {
        vec![
            judge(can_update_relation(), RowVersion::Existing),
            judge(can_update_relation(), RowVersion::Resulting),
        ]
    }
}

/// A blind update applies both clauses without the read gate. The unread relation is
/// the `USING` half against the row as it is, and the unread check half, defined where
/// the clauses differ, judges the result.
fn blind_update_answer(plan: &TypePlan) -> ActionAnswer {
    let relation = can_update_without_reading_relation();
    if !plan.computed_relations.contains_key(&relation) {
        return ActionAnswer::Judged(update_judgements(plan));
    }
    ActionAnswer::Judged(vec![
        judge(relation.clone(), RowVersion::Existing),
        judge(
            defined_or(plan, can_update_without_reading_check_relation(), relation),
            RowVersion::Resulting,
        ),
    ])
}

fn answer(plan: &TypePlan, statement: ActionStatement) -> ActionAnswer {
    match statement {
        ActionStatement::Select => {
            ActionAnswer::Judged(vec![judge(can_select_relation(), RowVersion::Existing)])
        }
        ActionStatement::Insert => {
            ActionAnswer::Judged(vec![judge(can_insert_relation(), RowVersion::Resulting)])
        }
        ActionStatement::Update => ActionAnswer::Judged(update_judgements(plan)),
        ActionStatement::Delete => {
            ActionAnswer::Judged(vec![judge(can_delete_relation(), RowVersion::Existing)])
        }
        // The relation named for a locking read carries only what the UPDATE policies
        // add, so the read gate is named beside it rather than assumed.
        ActionStatement::SelectForUpdate => ActionAnswer::Judged(vec![
            judge(can_select_relation(), RowVersion::Existing),
            judge(
                defined_or(
                    plan,
                    can_select_for_update_relation(),
                    can_update_relation(),
                ),
                RowVersion::Existing,
            ),
        ]),
        // The inserted row is read back, then the conflicting row is read and updated, so
        // the readback and both update halves are named. Where PostgreSQL filters a row
        // failing an update half, an upsert raises instead, which a check answers alike.
        ActionStatement::InsertOnConflictUpdate => {
            let mut required = vec![judge(
                defined_or(plan, can_insert_returning_relation(), can_insert_relation()),
                RowVersion::Resulting,
            )];
            required.extend(update_judgements(plan));
            ActionAnswer::Judged(required)
        }
        // Absent exactly where nothing admits an insert, and the denial answers then.
        ActionStatement::InsertReturning => ActionAnswer::Judged(vec![judge(
            defined_or(plan, can_insert_returning_relation(), can_insert_relation()),
            RowVersion::Resulting,
        )]),
        ActionStatement::UpdateWithoutWhere => blind_update_answer(plan),
        _ => ActionAnswer::Denied,
    }
}

/// Whether the database filters none of this table's rows, by any route.
fn restricts_nothing<DB: DatabaseLike>(table: &TableId, db: &DB) -> bool {
    lookup_table_id(db, table)
        .is_some_and(|table| unrestricted::restricts_nothing_by_any_route(table, db))
}

/// Whether the model answers no to this statement for every row.
///
/// Reads [`relation_grants_nothing`], which is the simplifier's own walk, so the report
/// and the pruner cannot disagree about which relation is a denial.
fn answer_grants_nobody(plan: &TypePlan, answer: &ActionAnswer) -> bool {
    match answer {
        // Every judgement has to grant, so one that grants nobody refuses the statement.
        ActionAnswer::Judged(judges) => judges
            .iter()
            .any(|judge| relation_grants_nothing(plan, &judge.relation)),
        _ => false,
    }
}

/// One entry per type and statement the model answers, by type name then statement.
///
/// A type nothing keys on a row has no entry, since a consumer never names one of its
/// objects.
pub(crate) fn action_relations<DB: DatabaseLike>(
    plan: &SchemaPlan,
    db: &DB,
) -> Vec<ActionRelations> {
    let mut entries: Vec<ActionRelations> = Vec::new();
    for type_plan in &plan.types {
        let Some(table) = type_plan.source_table.as_ref() else {
            continue;
        };
        let restricted = type_plan
            .computed_relations
            .contains_key(&can_select_relation());
        if !restricted && !restricts_nothing(table, db) {
            continue;
        }
        let answers = if restricted {
            EVERY_STATEMENT.map(|statement| answer(type_plan, statement))
        } else {
            EVERY_STATEMENT.map(|_| ActionAnswer::Unrestricted)
        };
        entries.extend(
            EVERY_STATEMENT
                .into_iter()
                .zip(answers)
                .map(|(statement, answer)| {
                    let answer = if answer_grants_nobody(type_plan, &answer) {
                        ActionAnswer::Denied
                    } else {
                        answer
                    };
                    ActionRelations::new(type_plan.type_name.clone(), statement, answer)
                }),
        );
    }
    entries.sort_by(|left, right| {
        left.type_name
            .as_str()
            .cmp(right.type_name.as_str())
            .then(left.statement.cmp(&right.statement))
    });
    entries
}
