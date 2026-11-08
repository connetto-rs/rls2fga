//! Passes that simplify a plan once every table's policies are translated.
//!
//! Each one runs over the whole plan rather than one table, because a relation minted for one
//! table may only become redundant, or unreachable, once another table's rules exist. Anything
//! order dependent belongs here rather than mid-loop: deciding a name while the loop is still
//! running is on the trap list twice.

use super::*;

/// The rule a `can_select` gate wraps, if this expression is such a gate.
pub(crate) fn select_gate_rule(expr: &UsersetExpr) -> Option<&UsersetExpr> {
    let UsersetExpr::Intersection(children) = expr else {
        return None;
    };
    let [rule, UsersetExpr::Computed(gate)] = children.as_slice() else {
        return None;
    };
    (*gate == can_select_relation()).then_some(rule)
}

/// Whether `rule` can only hold where `visible` holds, both read on `plan`. Unrecognized
/// shapes keep the gate. `path` holds the relations being expanded, so a cycle stops.
pub(crate) fn rule_implies(
    rule: &UsersetExpr,
    visible: &UsersetExpr,
    plan: &TypePlan,
    by_name: &BTreeMap<&TypeName, &TypePlan>,
    path: &mut Vec<(TypeName, RelationName)>,
) -> bool {
    if rule == visible {
        return true;
    }
    // A conjunct of the rule that implies the gate is enough, since the rule admits no more.
    if let UsersetExpr::Intersection(conjuncts) = rule {
        if conjuncts
            .iter()
            .any(|conjunct| rule_implies(conjunct, visible, plan, by_name, path))
        {
            return true;
        }
    }
    match visible {
        // Any branch that admits the rule admits it for the whole union.
        UsersetExpr::Union(branches) => branches
            .iter()
            .any(|branch| rule_implies(rule, branch, plan, by_name, path)),
        // Every conjunct has to admit it.
        UsersetExpr::Intersection(children) => children
            .iter()
            .all(|child| rule_implies(rule, child, plan, by_name, path)),
        // A named relation stands for its own definition. Levels of a role
        // hierarchy chain through here, and `path` keeps a cycle from looping.
        UsersetExpr::Computed(name) => {
            let Some(expr) = plan.computed_relations.get(name) else {
                return false;
            };
            if path
                .iter()
                .any(|(type_name, relation)| *type_name == plan.type_name && relation == name)
            {
                return false;
            }
            path.push((plan.type_name.clone(), name.clone()));
            let implied = rule_implies(rule, expr, plan, by_name, path);
            path.pop();
            implied
        }
        // Both sides walking one relation reach the same objects, so the question moves to
        // the type they reach: a role ladder answered through a pointer chains here.
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            let UsersetExpr::TupleToUserset {
                tupleset: walked,
                computed: held,
            } = rule
            else {
                return false;
            };
            if walked != tupleset {
                return false;
            }
            // A wildcard cannot be walked, so it is no evidence and the gate stays.
            let subjects = plan.direct_relations.get(tupleset).into_iter().flatten();
            let mut targets: Vec<&TypePlan> = Vec::new();
            for subject in subjects {
                match subject.resolved_type_name() {
                    Some(name) => match by_name.get(name) {
                        Some(target) => targets.push(target),
                        None => return false,
                    },
                    None => return false,
                }
            }
            !targets.is_empty()
                && targets.iter().all(|target| {
                    rule_implies(
                        &UsersetExpr::Computed(held.clone()),
                        &UsersetExpr::Computed(computed.clone()),
                        target,
                        by_name,
                        path,
                    )
                })
        }
        // An exclusion can remove the rule's own members, so it admits nothing.
        UsersetExpr::Exclusion { .. } => false,
    }
}

/// Require the row to be readable, which every per-row change does.
pub(crate) fn requires_read_access(expr: UsersetExpr) -> UsersetExpr {
    UsersetExpr::Intersection(vec![expr, UsersetExpr::Computed(can_select_relation())])
}

/// Drop a `can_select` gate the rule already implies.
pub(crate) fn simplify_redundant_select_gates(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    // A rule reaching its read through a pointer is answered on the type it points at, so
    // the whole plan is read while one type is rewritten.
    let snapshot: Vec<TypePlan> = all_types.values().cloned().collect();
    let by_name: BTreeMap<&TypeName, &TypePlan> = snapshot
        .iter()
        .map(|plan| (&plan.type_name, plan))
        .collect();
    for plan in all_types.values_mut() {
        let Some(read) = by_name.get(&plan.type_name).copied() else {
            continue;
        };
        let Some(visible) = read.computed_relations.get(&can_select_relation()) else {
            continue;
        };
        for (relation, expr) in &mut plan.computed_relations {
            if *relation == can_select_relation() {
                continue;
            }
            let Some(rule) = select_gate_rule(expr) else {
                continue;
            };
            if rule_implies(rule, visible, read, &by_name, &mut Vec::new()) {
                *expr = rule.clone();
            }
        }
    }
}

/// Drop the readback relation where it repeats `can_insert`, since a relation
/// that adds no requirement is noise.
pub(crate) fn drop_implied_insert_readback(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    for plan in all_types.values_mut() {
        let repeats = plan
            .computed_relations
            .get(&can_insert_returning_relation())
            .zip(plan.computed_relations.get(&can_insert_relation()))
            .is_some_and(|(readback, insert)| readback == insert);
        if repeats {
            plan.computed_relations
                .remove(&can_insert_returning_relation());
        }
    }
}

/// Inline a synthesized rule relation that is just another name for one relation on
/// the same type. Only generated holders are disposable.
pub(crate) fn inline_synthetic_rule_aliases(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    let mut aliases: BTreeMap<TypeName, BTreeMap<RelationName, RelationName>> = BTreeMap::new();
    for (type_name, plan) in all_types.iter() {
        for (relation, expr) in &plan.computed_relations {
            if !relation.as_str().starts_with(INHERITED_RELATION_PREFIX) {
                continue;
            }
            let UsersetExpr::Computed(target) = expr else {
                continue;
            };
            if plan.direct_relations.contains_key(target)
                || plan.computed_relations.contains_key(target)
            {
                aliases
                    .entry(type_name.clone())
                    .or_default()
                    .insert(relation.clone(), target.clone());
            }
        }
    }
    if aliases.is_empty() {
        return;
    }

    for plan in all_types.values_mut() {
        let TypePlan {
            type_name,
            direct_relations,
            computed_relations,
            ..
        } = plan;
        if let Some(dropped) = aliases.get(type_name.as_str()) {
            computed_relations.retain(|relation, _| !dropped.contains_key(relation));
        }
        let own = aliases.get(type_name.as_str());
        for expr in computed_relations.values_mut() {
            repoint_inlined_aliases(expr, direct_relations, own, &aliases);
        }
    }
}

/// Point every reference to an inlined alias at the relation it named.
pub(crate) fn repoint_inlined_aliases(
    expr: &mut UsersetExpr,
    direct_relations: &BTreeMap<RelationName, Vec<DirectSubject>>,
    own: Option<&BTreeMap<RelationName, RelationName>>,
    aliases: &BTreeMap<TypeName, BTreeMap<RelationName, RelationName>>,
) {
    match expr {
        UsersetExpr::Computed(name) => {
            if let Some(replacement) = own.and_then(|dropped| dropped.get(name)) {
                *name = replacement.clone();
            }
        }
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            // The walked relation is evaluated on the types the tupleset admits.
            let replacement = direct_relations
                .get(tupleset)
                .into_iter()
                .flatten()
                .filter_map(DirectSubject::resolved_type_name)
                .filter_map(|name| aliases.get(name))
                .find_map(|dropped| dropped.get(computed));
            if let Some(replacement) = replacement {
                *computed = replacement.clone();
            }
        }
        UsersetExpr::Union(children) | UsersetExpr::Intersection(children) => {
            for child in children {
                repoint_inlined_aliases(child, direct_relations, own, aliases);
            }
        }
        UsersetExpr::Exclusion { base, subtract } => {
            repoint_inlined_aliases(base, direct_relations, own, aliases);
            repoint_inlined_aliases(subtract, direct_relations, own, aliases);
        }
    }
}

/// Every `(type, relation)` some definition names, a denying one included.
///
/// Deliberately not [`grantable_relations`], which stops at a permission that grants
/// nothing. A relation only a denial names still has to stay declared, or the model
/// carries a reference to something it does not define.
pub(crate) fn referenced_relations(types: &[TypePlan]) -> BTreeSet<(TypeName, RelationName)> {
    let by_name: BTreeMap<&TypeName, &TypePlan> =
        types.iter().map(|plan| (&plan.type_name, plan)).collect();
    let mut reached: BTreeSet<(TypeName, RelationName)> = BTreeSet::new();
    for plan in types {
        for action in action_relations().chain(derived_action_relations()) {
            if let Some(expr) = plan.computed_relations.get(&action) {
                reach_userset(expr, plan, &by_name, &mut reached);
            }
        }
    }
    reached
}

/// Drop relations no permission names. They are declared, no tuple query feeds them,
/// and nothing can consult them, so the model advertises access it can never grant.
///
/// An operator hand-writing their own facts for such a relation will no longer find it
/// in the model, which is the point: it never did anything.
pub(crate) fn prune_unreferenced_relations(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    let types: Vec<TypePlan> = all_types.values().cloned().collect();
    let referenced = referenced_relations(&types);
    for plan in all_types.values_mut() {
        let owner = plan.type_name.clone();
        plan.direct_relations
            .retain(|name, _| referenced.contains(&(owner.clone(), name.clone())));
        plan.computed_relations.retain(|name, _| {
            generator_defines(name) || referenced.contains(&(owner.clone(), name.clone()))
        });
    }
}

/// Narrow every grants source to the ladder levels the model still declares.
///
/// A grants query names one relation per level, and a single row naming a pruned
/// relation poisons the whole write batch, so the source follows the pruning.
/// Owned by the plan rather than one renderer, so the tuple SQL, the bound
/// queries and the record descriptions all read the same levels.
pub(crate) fn narrow_grant_sources_to_declared(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    let declared: BTreeSet<(TypeName, RelationName)> = all_types
        .values()
        .flat_map(|plan| {
            plan.direct_relations
                .keys()
                .chain(plan.computed_relations.keys())
                .map(|relation| (plan.type_name.clone(), relation.clone()))
        })
        .collect();
    for plan in all_types.values_mut() {
        for source in &mut plan.table_tuple_sources {
            if let TupleSource::ExplicitGrants {
                owner_type,
                role_cases,
                ..
            } = source
            {
                role_cases.retain(|(_, grant_rel, _)| {
                    declared.contains(&(owner_type.clone(), grant_rel.clone()))
                });
            }
        }
        plan.table_tuple_sources.retain(|source| {
            !matches!(
                source,
                TupleSource::ExplicitGrants { role_cases, .. } if role_cases.is_empty()
            )
        });
    }
}

/// Whether a relation this type defines can never grant.
///
/// The relation-level door to [`grants_nothing`], so a caller holding a name rather than
/// an expression does not walk the plan itself. A relation the type does not define may
/// grant, since nothing here says it cannot.
pub(crate) fn relation_grants_nothing(plan: &TypePlan, relation: &RelationName) -> bool {
    plan.computed_relations
        .get(relation)
        .is_some_and(|expr| grants_nothing(expr, plan, &mut BTreeSet::new()))
}

/// Whether an expression can never grant. Only certainty is reported.
pub(crate) fn grants_nothing(
    expr: &UsersetExpr,
    plan: &TypePlan,
    seen: &mut BTreeSet<RelationName>,
) -> bool {
    match expr {
        UsersetExpr::Computed(name) if *name == deny_relation() => true,
        UsersetExpr::Computed(name) => {
            seen.insert(name.clone())
                && plan
                    .computed_relations
                    .get(name)
                    .is_some_and(|expr| grants_nothing(expr, plan, seen))
        }
        // One conjunct that never holds denies the whole intersection.
        UsersetExpr::Intersection(children) => children
            .iter()
            .any(|child| grants_nothing(child, plan, seen)),
        UsersetExpr::Union(children) => children
            .iter()
            .all(|child| grants_nothing(child, plan, seen)),
        // Subtracting from nothing still grants nothing, and how much a subtraction
        // removes is unknowable here.
        UsersetExpr::Exclusion { base, .. } => grants_nothing(base, plan, seen),
        UsersetExpr::TupleToUserset { .. } => false,
    }
}

pub(crate) fn reach_userset(
    expr: &UsersetExpr,
    plan: &TypePlan,
    by_name: &BTreeMap<&TypeName, &TypePlan>,
    reached: &mut BTreeSet<(TypeName, RelationName)>,
) {
    match expr {
        UsersetExpr::Computed(name) => {
            if !reached.insert((plan.type_name.clone(), name.clone())) {
                return;
            }
            if let Some(inner) = plan.computed_relations.get(name) {
                reach_userset(inner, plan, by_name, reached);
            }
        }
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            reached.insert((plan.type_name.clone(), tupleset.clone()));
            // The walked relation is evaluated on every type the tupleset admits.
            for target in plan
                .direct_relations
                .get(tupleset)
                .into_iter()
                .flatten()
                .filter_map(DirectSubject::resolved_type_name)
                .filter_map(|name| by_name.get(name))
            {
                if !reached.insert((target.type_name.clone(), computed.clone())) {
                    continue;
                }
                if let Some(inner) = target.computed_relations.get(computed) {
                    reach_userset(inner, target, by_name, reached);
                }
            }
        }
        UsersetExpr::Union(children) | UsersetExpr::Intersection(children) => {
            for child in children {
                reach_userset(child, plan, by_name, reached);
            }
        }
        // Both sides are consulted, so both keep their tuples.
        UsersetExpr::Exclusion { base, subtract } => {
            reach_userset(base, plan, by_name, reached);
            reach_userset(subtract, plan, by_name, reached);
        }
    }
}
