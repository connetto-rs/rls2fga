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

use crate::generator::model_generator::{
    relation_grants_every_actor, relation_grants_nothing, SchemaPlan, TypePlan,
};
use crate::generator::well_known::{
    CAN_DELETE_RELATION, CAN_INSERT_RELATION, CAN_INSERT_RETURNING_RELATION,
    CAN_SELECT_FOR_UPDATE_RELATION, CAN_SELECT_RELATION, CAN_UPDATE_CHECK_RELATION,
    CAN_UPDATE_RELATION, CAN_UPDATE_USING_RELATION, CAN_UPDATE_WITHOUT_READING_CHECK_RELATION,
    CAN_UPDATE_WITHOUT_READING_RELATION,
};
use crate::parser::sql_parser::Deployment;
use crate::types::{
    ActionAnswer, ActionJudgement, ActionRelations, ActionStatement, RelationName, RowVersion,
};

type Judgements = [Option<(&'static str, RowVersion)>; 3];

fn judge(relation: &'static str, version: RowVersion) -> (&'static str, RowVersion) {
    (relation, version)
}

/// The relation the type defines, or the one the model falls back to where it does not.
fn defined_or(plan: &TypePlan, wanted: &'static str, fallback: &'static str) -> &'static str {
    if plan.computed_relations.contains_key(wanted) {
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
        .contains_key(CAN_UPDATE_USING_RELATION)
}

/// What a replacement has to satisfy: the two halves where the policy's clauses differ,
/// and the one relation twice where a lone `USING` is mirrored onto the result.
fn update_judgements(plan: &TypePlan) -> [(&'static str, RowVersion); 2] {
    if clauses_answered_apart(plan) {
        [
            judge(CAN_UPDATE_USING_RELATION, RowVersion::Existing),
            judge(CAN_UPDATE_CHECK_RELATION, RowVersion::Resulting),
        ]
    } else {
        [
            judge(CAN_UPDATE_RELATION, RowVersion::Existing),
            judge(CAN_UPDATE_RELATION, RowVersion::Resulting),
        ]
    }
}

/// A blind update applies both clauses without the read gate. The unread relation is
/// the `USING` half against the row as it is, and the unread check half, defined where
/// the clauses differ, judges the result.
fn blind_update_judgements(plan: &TypePlan) -> [(&'static str, RowVersion); 2] {
    let relation = CAN_UPDATE_WITHOUT_READING_RELATION;
    [
        judge(relation, RowVersion::Existing),
        judge(
            defined_or(plan, CAN_UPDATE_WITHOUT_READING_CHECK_RELATION, relation),
            RowVersion::Resulting,
        ),
    ]
}

fn judgements(plan: &TypePlan) -> [(ActionStatement, Judgements); 8] {
    let [existing, resulting] = update_judgements(plan);
    let [unread, unread_check] = blind_update_judgements(plan);
    let returning = judge(
        defined_or(plan, CAN_INSERT_RETURNING_RELATION, CAN_INSERT_RELATION),
        RowVersion::Resulting,
    );
    [
        (
            ActionStatement::Select,
            [
                Some(judge(CAN_SELECT_RELATION, RowVersion::Existing)),
                None,
                None,
            ],
        ),
        (
            ActionStatement::Insert,
            [
                Some(judge(CAN_INSERT_RELATION, RowVersion::Resulting)),
                None,
                None,
            ],
        ),
        (
            ActionStatement::Update,
            [Some(existing), Some(resulting), None],
        ),
        (
            ActionStatement::Delete,
            [
                Some(judge(CAN_DELETE_RELATION, RowVersion::Existing)),
                None,
                None,
            ],
        ),
        (
            ActionStatement::SelectForUpdate,
            [
                Some(judge(CAN_SELECT_RELATION, RowVersion::Existing)),
                Some(judge(
                    defined_or(plan, CAN_SELECT_FOR_UPDATE_RELATION, CAN_UPDATE_RELATION),
                    RowVersion::Existing,
                )),
                None,
            ],
        ),
        (
            ActionStatement::InsertOnConflictUpdate,
            [Some(returning), Some(existing), Some(resulting)],
        ),
        (
            ActionStatement::InsertReturning,
            [Some(returning), None, None],
        ),
        (
            ActionStatement::UpdateWithoutWhere,
            [Some(unread), Some(unread_check), None],
        ),
    ]
}

fn answer(
    request_gate: Option<&TypePlan>,
    plan: &TypePlan,
    required: Judgements,
    deployment: Option<&Deployment>,
) -> ActionAnswer {
    if required.iter().flatten().any(|(relation, _)| {
        plan.computed_relations
            .get_key_value(*relation)
            .is_some_and(|(relation, _)| relation_grants_nothing(plan, relation))
    }) {
        return ActionAnswer::Denied;
    }
    if required.iter().flatten().all(|(relation, _)| {
        plan.computed_relations
            .get_key_value(*relation)
            .is_some_and(|(relation, _)| {
                relation_grants_every_actor(request_gate, plan, relation, deployment)
            })
    }) {
        return ActionAnswer::Unrestricted;
    }
    ActionAnswer::Judged(
        required
            .into_iter()
            .flatten()
            .map(|(relation, version)| {
                ActionJudgement::new(RelationName::canonicalized(relation), version)
            })
            .collect(),
    )
}

/// Permission answers for modeled tables with a read gate, ordered by type and statement.
pub(crate) fn action_relations(
    plan: &SchemaPlan,
    deployment: Option<&Deployment>,
) -> Vec<ActionRelations> {
    let request_gate = plan
        .types
        .iter()
        .find(|target| target.type_name == plan.well_known.request_gate);
    let mut entries: Vec<ActionRelations> = Vec::new();
    for type_plan in &plan.types {
        if type_plan.source_table.is_none() {
            continue;
        }
        if !type_plan
            .computed_relations
            .contains_key(CAN_SELECT_RELATION)
        {
            continue;
        }
        entries.extend(
            judgements(type_plan)
                .into_iter()
                .map(|(statement, required)| {
                    ActionRelations::new(
                        type_plan.type_name.clone(),
                        statement,
                        answer(request_gate, type_plan, required, deployment),
                    )
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
