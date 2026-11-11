//! Passes that simplify a plan once every table's policies are translated.
//!
//! Each one runs over the whole plan rather than one table, because a relation minted for one
//! table may only become redundant, or unreachable, once another table's rules exist. Anything
//! order dependent belongs here rather than mid-loop: deciding a name while the loop is still
//! running is on the trap list twice.

use super::*;
use crate::generator::well_known::DENY_RELATION;
use crate::parser::sql_parser::Deployment;

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
/// carries a reference to something it does not define. A relation only locally answered
/// statements read is no root, since nothing asks about it.
pub(crate) fn referenced_relations(
    types: &[TypePlan],
    answered_locally: &BTreeMap<TypeName, BTreeSet<RelationName>>,
) -> BTreeSet<(TypeName, RelationName)> {
    let by_name: BTreeMap<&TypeName, &TypePlan> =
        types.iter().map(|plan| (&plan.type_name, plan)).collect();
    let mut reached: BTreeSet<(TypeName, RelationName)> = BTreeSet::new();
    for plan in types {
        let local = answered_locally.get(&plan.type_name);
        for action in action_relations().chain(derived_action_relations()) {
            if local.is_some_and(|local| local.contains(&action)) {
                continue;
            }
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
/// in the model, which is the point: it never did anything. The same holds for an action
/// relation only locally answered statements read, unless another relation reaches it.
pub(crate) fn prune_unreferenced_relations(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    answered_locally: &BTreeMap<TypeName, BTreeSet<RelationName>>,
) {
    let types: Vec<TypePlan> = all_types.values().cloned().collect();
    let referenced = referenced_relations(&types, answered_locally);
    for plan in all_types.values_mut() {
        let owner = plan.type_name.clone();
        let local = answered_locally.get(&owner);
        plan.direct_relations
            .retain(|name, _| referenced.contains(&(owner.clone(), name.clone())));
        plan.computed_relations.retain(|name, _| {
            referenced.contains(&(owner.clone(), name.clone()))
                || (generator_defines(name) && !local.is_some_and(|local| local.contains(name)))
        });
    }
    drop_unlinked_gate_entries(all_types);
}

/// Drop the constants on a gate object no surviving row links to.
///
/// A gate object is reached only through the link its rows carry, so once pruning removes
/// every such link, the constants written on it can never answer a check.
fn drop_unlinked_gate_entries(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    let mut linked: BTreeMap<TypeName, BTreeSet<String>> = BTreeMap::new();
    for plan in all_types.values() {
        for source in &plan.table_tuple_sources {
            if let TupleSource::PolicyScope {
                scope_relation,
                scope_type,
                scope_object,
                ..
            }
            | TupleSource::SingletonScope {
                scope_relation,
                scope_type,
                scope_object,
            } = source
            {
                if plan.direct_relations.contains_key(scope_relation) {
                    linked
                        .entry(scope_type.clone())
                        .or_default()
                        .insert(scope_object.clone());
                }
            }
        }
    }
    for plan in all_types.values_mut() {
        plan.table_tuple_sources.retain(|source| match source {
            TupleSource::ActingKind {
                gate_type,
                gate_object,
                ..
            }
            | TupleSource::RequestGateEntry {
                gate_type,
                gate_object,
                ..
            } => linked
                .get(gate_type)
                .is_some_and(|objects| objects.contains(gate_object)),
            _ => true,
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
        .is_some_and(|expr| grants_nothing(expr, plan))
}

/// Whether an expression can never grant. Only certainty is reported.
pub(crate) fn grants_nothing(expr: &UsersetExpr, plan: &TypePlan) -> bool {
    constant_expr(expr, plan, None, &mut Vec::new()) == Some(false)
}

/// Whether every deployment role passes without row or request-dependent data.
pub(crate) fn relation_grants_every_actor(
    request_gate: Option<&TypePlan>,
    owner: &TypePlan,
    relation: &RelationName,
    deployment: Option<&Deployment>,
) -> bool {
    let mut path = Vec::new();
    let mut grants = |role| {
        let context = ConstantContext {
            request_gate,
            owner,
            role,
        };
        constant_relation(owner, relation, Some(&context), &mut path) == Some(true)
    };
    match deployment {
        Some(deployment) => deployment.acting_roles().all(|role| grants(Some(role))),
        None => grants(None),
    }
}

struct ConstantContext<'a> {
    request_gate: Option<&'a TypePlan>,
    owner: &'a TypePlan,
    role: Option<&'a str>,
}

/// Resolve aliases with a type-qualified recursion path.
fn constant_relation<'a>(
    plan: &'a TypePlan,
    relation: &'a RelationName,
    context: Option<&ConstantContext<'a>>,
    path: &mut Vec<(&'a TypeName, &'a RelationName)>,
) -> Option<bool> {
    if relation.as_str() == DENY_RELATION {
        return Some(false);
    }
    let key = (&plan.type_name, relation);
    if path.contains(&key) {
        return None;
    }
    let Some(expr) = plan.computed_relations.get(relation) else {
        return context.and_then(|context| constant_leaf(plan, relation, context));
    };
    path.push(key);
    let value = constant_expr(expr, plan, context, path);
    path.pop();
    value
}

/// Fold only values independent of row contents and request conditions.
fn constant_expr<'a>(
    expr: &'a UsersetExpr,
    plan: &'a TypePlan,
    context: Option<&ConstantContext<'a>>,
    path: &mut Vec<(&'a TypeName, &'a RelationName)>,
) -> Option<bool> {
    match expr {
        UsersetExpr::Computed(name) => constant_relation(plan, name, context, path),
        UsersetExpr::Intersection(children) | UsersetExpr::Union(children) => {
            let intersection = matches!(expr, UsersetExpr::Intersection(_));
            let mut known = true;
            for child in children {
                match constant_expr(child, plan, context, path) {
                    Some(value) if value != intersection => return Some(value),
                    Some(_) => {}
                    None => known = false,
                }
            }
            known.then_some(intersection)
        }
        UsersetExpr::Exclusion { base, subtract } => {
            let base = constant_expr(base, plan, context, path);
            if base == Some(false) {
                return base;
            }
            match constant_expr(subtract, plan, context, path) {
                Some(true) => Some(false),
                Some(false) => base,
                None => None,
            }
        }
        UsersetExpr::TupleToUserset { tupleset, computed } => {
            let context = context?;
            let target = constant_scope(plan, tupleset, context)?;
            constant_relation(target, computed, Some(context), path)
        }
    }
}

/// The fixed request-gate object linked from every row of the owning table.
fn constant_scope<'a>(
    plan: &TypePlan,
    tupleset: &RelationName,
    context: &ConstantContext<'a>,
) -> Option<&'a TypePlan> {
    if plan.type_name != context.owner.type_name {
        return None;
    }
    let mut linked = false;
    for source in &plan.table_tuple_sources {
        match source {
            TupleSource::PolicyScope {
                scope_relation,
                scope_type,
                scope_object,
                ..
            }
            | TupleSource::SingletonScope {
                scope_relation,
                scope_type,
                scope_object,
            } if scope_relation == tupleset => {
                if *scope_type != context.owner.well_known.request_gate
                    || scope_object.as_str() != plan.type_name.as_str()
                {
                    return None;
                }
                linked = true;
            }
            _ => {}
        }
    }
    linked.then_some(context.request_gate).flatten()
}

/// Constant wildcard facts and acting-role facts are independent of row values.
fn constant_leaf(
    plan: &TypePlan,
    relation: &RelationName,
    context: &ConstantContext<'_>,
) -> Option<bool> {
    if plan.table_tuple_sources.iter().any(|source| {
        matches!(
            source,
            TupleSource::ConstantTrue { table, relation: held, .. }
                if held == relation && plan.source_table.as_ref() == Some(table)
        )
    }) {
        return Some(true);
    }
    if plan.type_name != context.owner.well_known.request_gate {
        return None;
    }
    let role = context.role?;
    let mut known = false;
    let mut conditional = false;
    for source in &context.owner.table_tuple_sources {
        match source {
            TupleSource::ActingKind {
                gate_type,
                gate_object,
                relation: held,
                pg_role,
            } if *gate_type == plan.type_name
                && gate_object.as_str() == context.owner.type_name.as_str()
                && held == relation =>
            {
                if pg_role == role {
                    return Some(true);
                }
                known = true;
            }
            TupleSource::RequestGateEntry {
                gate_type,
                gate_object,
                relation: held,
                ..
            } if *gate_type == plan.type_name
                && gate_object.as_str() == context.owner.type_name.as_str()
                && held == relation =>
            {
                conditional = true;
            }
            _ => {}
        }
    }
    (known && !conditional).then_some(false)
}

/// The relations a direct relation's userset subjects name, which a tuple of it reaches.
fn reach_direct_usersets(
    plan: &TypePlan,
    relation: &RelationName,
    reached: &mut BTreeSet<(TypeName, RelationName)>,
) {
    for subject in plan.direct_relations.get(relation).into_iter().flatten() {
        if let DirectSubject::Userset {
            type_name,
            relation,
        } = subject
        {
            reached.insert((type_name.clone(), relation.clone()));
        }
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
            reach_direct_usersets(plan, name, reached);
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
                reach_direct_usersets(target, computed, reached);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scoped_schema(scope_type: TypeName, scope_object: &str) -> SchemaPlan {
        let well_known = WellKnownTypes::default();
        let mut owner = TypePlan::new(TypeName::canonicalized("docs"));
        owner.add_source(TupleSource::SingletonScope {
            scope_relation: request_gate_link_relation(),
            scope_type,
            scope_object: scope_object.to_string(),
        });
        let gate = TypePlan::new(well_known.request_gate.clone());
        SchemaPlan {
            types: vec![owner, gate],
            notes: Vec::new(),
            confidence_summary: Vec::new(),
            conditions: BTreeMap::new(),
            clocks: Vec::new(),
            well_known,
            action_relations: Vec::new(),
        }
    }

    #[test]
    fn only_the_owners_fixed_gate_is_row_independent() {
        let gate_type = WellKnownTypes::default().request_gate;
        for (scope_type, scope_object, independent) in [
            (gate_type.clone(), "docs", true),
            (TypeName::canonicalized("other_gate"), "docs", false),
            (gate_type, "other", false),
        ] {
            let schema = scoped_schema(scope_type, scope_object);
            let owner = &schema.types[0];
            let context = ConstantContext {
                request_gate: Some(&schema.types[1]),
                owner,
                role: None,
            };
            assert_eq!(
                constant_scope(owner, &request_gate_link_relation(), &context).is_some(),
                independent,
                "{scope_object}",
            );
        }
    }

    #[test]
    fn a_foreign_scope_does_not_borrow_the_owners_gate() {
        let gate_type = WellKnownTypes::default().request_gate;
        let schema = scoped_schema(gate_type.clone(), "docs");
        let context = ConstantContext {
            request_gate: Some(&schema.types[1]),
            owner: &schema.types[0],
            role: None,
        };
        let mut foreign = TypePlan::new(TypeName::canonicalized("other"));
        foreign.add_source(TupleSource::SingletonScope {
            scope_relation: request_gate_link_relation(),
            scope_type: gate_type,
            scope_object: "other".to_string(),
        });
        assert!(constant_scope(&foreign, &request_gate_link_relation(), &context).is_none());
    }
}
