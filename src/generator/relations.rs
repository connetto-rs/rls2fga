//! Each relation of the emitted model, the shapes whose records fill it, and how one
//! row decides them.
//!
//! A consumer watching a change stream wants to answer the cheapest questions with
//! no round trip, by testing the changed row's records against its own subscriber
//! list. That is correct only for some relations, and being wrong in the permissive
//! direction is a wrong allow, so the analysis refuses to guess: anything it cannot
//! judge is reported as not decidable.
//!
//! The flag and the recipe leave one traversal. Derived apart they could disagree,
//! which is the divergence this surface exists to remove.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::types::{
    RecordDerivation, RecordDescription, RelationName, RelationShapes, RequestComparison,
    RequestPredicate, RowDecision, TypeName, ValueSource,
};
use alloc::collections::{BTreeMap, BTreeSet};

use crate::generator::db_lookup::resolve_row_identity;
use crate::generator::ir::TupleSource;
use crate::generator::model_generator::{
    relation_grants_nothing, SchemaPlan, TypePlan, UsersetExpr,
};
use crate::generator::tuple_generator::{rendered_source_key, RenderedSourceKey};
use crate::generator::well_known::WellKnownTypes;
use crate::parser::sql_parser::DatabaseLike;

/// Report every relation of the emitted model.
pub(crate) fn relation_shapes<'plan, DB: DatabaseLike>(
    plan: &'plan SchemaPlan,
    descriptions: &BTreeMap<RenderedSourceKey<'plan>, Option<RecordDescription>>,
    db: &DB,
) -> Vec<RelationShapes> {
    let sources = index_sources(plan, descriptions);

    let mut out = Vec::new();
    for type_plan in &plan.types {
        let mut names: BTreeSet<&RelationName> = BTreeSet::new();
        names.extend(type_plan.direct_relations.keys());
        names.extend(type_plan.computed_relations.keys());
        for relation in names {
            let mut visiting = BTreeSet::new();
            let decision = relation_decision(
                &type_plan.type_name,
                relation,
                plan,
                &sources,
                db,
                &mut visiting,
            );
            out.push(RelationShapes {
                type_name: type_plan.type_name.clone(),
                relation: relation.clone(),
                from_one_row: decision.is_some(),
                shapes: shapes_filling(&type_plan.type_name, relation, &sources),
                decision,
                grants_nobody: relation_grants_nothing(type_plan, relation),
            });
        }
    }
    out
}

fn index_sources<'plan, 'description>(
    plan: &'plan SchemaPlan,
    descriptions: &'description BTreeMap<RenderedSourceKey<'plan>, Option<RecordDescription>>,
) -> SourceIndex<'plan, 'description> {
    let mut index: SourceIndex<'plan, 'description> = BTreeMap::new();
    for type_plan in &plan.types {
        for source in &type_plan.table_tuple_sources {
            let key = rendered_source_key(
                source,
                &type_plan.type_name,
                type_plan.reads_only_its_own_rows,
            );
            let description = descriptions.get(&key).and_then(Option::as_ref);
            for target in source.feeds(&type_plan.type_name) {
                index.entry(target).or_default().push(IndexedSource {
                    source,
                    description,
                });
            }
        }
    }
    index
}

#[derive(Clone, Copy)]
struct IndexedSource<'plan, 'description> {
    source: &'plan TupleSource,
    description: Option<&'description RecordDescription>,
}

type SourceIndex<'plan, 'description> =
    BTreeMap<(TypeName, RelationName), Vec<IndexedSource<'plan, 'description>>>;

/// One shape per source. A source feeding the same relation from two type plans
/// describes it twice, and the key the renderer deduplicates queries on is what
/// says the two are the same. Scoping it by owner type would add nothing: a source
/// keying its objects on the owning type only ever reaches the bucket named after
/// that type.
fn shapes_filling(
    type_name: &TypeName,
    relation: &RelationName,
    sources: &SourceIndex<'_, '_>,
) -> Vec<RecordDescription> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for indexed in sources
        .get(&(type_name.clone(), relation.clone()))
        .into_iter()
        .flatten()
    {
        if !seen.insert(indexed.source.dedup_key()) {
            continue;
        }
        if let Some(description) = indexed.description {
            out.push(description.clone());
        }
    }
    out
}

fn find_type<'plan>(plan: &'plan SchemaPlan, type_name: &TypeName) -> Option<&'plan TypePlan> {
    plan.types
        .iter()
        .find(|candidate| candidate.type_name == *type_name)
}

fn relation_decision<DB: DatabaseLike>(
    type_name: &TypeName,
    relation: &RelationName,
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
    db: &DB,
    visiting: &mut BTreeSet<(String, RelationName)>,
) -> Option<RowDecision> {
    // A cycle is not something the analysis can judge, so it falls closed.
    if !visiting.insert((type_name.to_string(), relation.clone())) {
        return None;
    }
    let answer = match find_type(plan, type_name) {
        None => None,
        // A clause the database evaluates was lost here, so the emitted rule and the
        // database disagree and no row can settle the difference.
        Some(type_plan) if type_plan.narrowed_relations.contains(relation) => None,
        Some(type_plan) => match type_plan.computed_relations.get(relation) {
            Some(expr) => expr_decision(type_name, expr, plan, sources, db, visiting),
            // A relation with direct subjects is answered by the tuples loaded into
            // it, so the sources feeding it decide.
            None => leaf_decision(type_name, relation, sources, &plan.well_known, db),
        },
    };
    visiting.remove(&(type_name.to_string(), relation.clone()));
    answer
}

fn expr_decision<DB: DatabaseLike>(
    type_name: &TypeName,
    expr: &UsersetExpr,
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
    db: &DB,
    visiting: &mut BTreeSet<(String, RelationName)>,
) -> Option<RowDecision> {
    match expr {
        // A named relation stands for its own definition, so the recipe reaches
        // through it to the relations records actually fill.
        UsersetExpr::Computed(name) => {
            relation_decision(type_name, name, plan, sources, db, visiting)
        }
        // Every child has to decide, otherwise the composition does not either.
        UsersetExpr::Union(children) => {
            child_decisions(type_name, children, plan, sources, db, visiting).map(RowDecision::Any)
        }
        UsersetExpr::Intersection(children) => {
            child_decisions(type_name, children, plan, sources, db, visiting).map(RowDecision::All)
        }
        // A link to the object holding this type's request gates reaches a predicate over
        // the request alone, so the caller's context decides it for every row that yields
        // its link.
        UsersetExpr::TupleToUserset { tupleset, computed }
            if links_to_request_gates(type_name, tupleset, plan, sources) =>
        {
            let predicate =
                request_predicate(&plan.well_known.request_gate, computed, plan, sources)?;
            let shapes = shapes_filling(type_name, tupleset, sources);
            if shapes.is_empty() {
                return None;
            }
            Some(RowDecision::Request {
                relation: tupleset.clone(),
                shapes,
                // Every gate entry grants the typed wildcard of the user type.
                subject_type: plan.well_known.user.clone(),
                predicate,
            })
        }
        // Any other tuple-to-userset resolves on the object the tupleset reaches rather
        // than on this row, and an exclusion lets adding a record revoke access, so
        // neither is decidable from the row.
        UsersetExpr::TupleToUserset { .. } | UsersetExpr::Exclusion { .. } => None,
    }
}

/// Whether `tupleset` links this type's permission objects to its request gate.
fn links_to_request_gates(
    type_name: &TypeName,
    tupleset: &RelationName,
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
) -> bool {
    sources
        .get(&(type_name.clone(), tupleset.clone()))
        .is_some_and(|feeding| {
            !feeding.is_empty()
                && feeding.iter().all(|indexed| {
                    matches!(
                        indexed.source,
                        TupleSource::PolicyScope { scope_type, scope_object, .. }
                            | TupleSource::SingletonScope { scope_type, scope_object, .. }
                            if *scope_type == plan.well_known.request_gate
                                && scope_object.as_str() == type_name.as_str()
                    )
                })
        })
}

/// The predicate `relation` of the request-gate type states, or `None` when it is not
/// one the request alone decides. Gate relations are minted from a finite formula and
/// never refer back, so the walk ends.
fn request_predicate(
    gate_type: &TypeName,
    relation: &RelationName,
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
) -> Option<RequestPredicate> {
    let gate_plan = find_type(plan, gate_type)?;
    let members = |children: &[UsersetExpr]| {
        children
            .iter()
            .map(|child| match child {
                UsersetExpr::Computed(name) => request_predicate(gate_type, name, plan, sources),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
    };
    match gate_plan.computed_relations.get(relation) {
        Some(UsersetExpr::Computed(name)) => request_predicate(gate_type, name, plan, sources),
        Some(UsersetExpr::Union(children)) => members(children).map(RequestPredicate::Any),
        Some(UsersetExpr::Intersection(children)) => members(children).map(RequestPredicate::All),
        Some(UsersetExpr::TupleToUserset { .. } | UsersetExpr::Exclusion { .. }) => None,
        None => {
            let feeding = sources.get(&(gate_type.clone(), relation.clone()))?;
            // Every guarded type's gate object holds the same kind under this relation.
            let mut roles = feeding.iter().map(|indexed| match indexed.source {
                TupleSource::ActingKind { pg_role, .. } => Some(pg_role),
                _ => None,
            });
            if let Some(Some(role)) = roles.next() {
                return roles
                    .all(|other| other == Some(role))
                    .then(|| RequestPredicate::ActsAs { role: role.clone() });
            }
            let mut atoms = feeding.iter().map(|indexed| match indexed.source {
                TupleSource::RequestGateEntry { atom, .. } => Some(atom),
                _ => None,
            });
            let first = atoms.next()??;
            atoms
                .all(|atom| atom == Some(first))
                .then(|| RequestPredicate::Holds(first.request_atom()))
        }
    }
}

fn child_decisions<DB: DatabaseLike>(
    type_name: &TypeName,
    children: &[UsersetExpr],
    plan: &SchemaPlan,
    sources: &SourceIndex<'_, '_>,
    db: &DB,
    visiting: &mut BTreeSet<(String, RelationName)>,
) -> Option<Vec<RowDecision>> {
    children
        .iter()
        .map(|child| expr_decision(type_name, child, plan, sources, db, visiting))
        .collect()
}

/// Every source feeding `relation` must key its object on this row's identity and
/// name a user the row itself supplies. The shapes that pass are the ones
/// [`shapes_filling`] reports for it, deduplicated the same way.
fn leaf_decision<DB: DatabaseLike>(
    type_name: &TypeName,
    relation: &RelationName,
    sources: &SourceIndex<'_, '_>,
    well_known: &WellKnownTypes,
    db: &DB,
) -> Option<RowDecision> {
    let feeding = sources.get(&(type_name.clone(), relation.clone()))?;
    if feeding.is_empty() {
        return None;
    }

    let mut seen = BTreeSet::new();
    let distinct: Vec<_> = feeding
        .iter()
        .copied()
        .filter(|indexed| seen.insert(indexed.source.dedup_key()))
        .collect();
    if distinct
        .iter()
        .any(|indexed| matches!(indexed.source, TupleSource::SessionAttributeGate { .. }))
    {
        let [indexed] = distinct.as_slice() else {
            return None;
        };
        let TupleSource::SessionAttributeGate {
            row_parameter,
            request_parameter,
            comparison,
            ..
        } = indexed.source
        else {
            return None;
        };
        let description = indexed.description?.clone();
        return Some(RowDecision::RequestGated {
            relation: relation.clone(),
            shapes: vec![description],
            context_key: row_parameter.clone(),
            request_parameter: request_parameter.clone(),
            comparison: *comparison,
        });
    }

    if distinct
        .iter()
        .any(|indexed| matches!(indexed.source, TupleSource::CallerSetShareGate { .. }))
    {
        let [indexed] = distinct.as_slice() else {
            return None;
        };
        let TupleSource::CallerSetShareGate {
            row_parameter,
            request_parameter,
            temporal_context,
            ..
        } = indexed.source
        else {
            return None;
        };
        if !temporal_context.is_empty() {
            return None;
        }
        let description = indexed.description?.clone();
        return Some(RowDecision::RequestGated {
            relation: relation.clone(),
            shapes: vec![description],
            context_key: row_parameter.clone(),
            request_parameter: request_parameter.clone(),
            comparison: RequestComparison::CallerSetHolds,
        });
    }

    let mut unique = BTreeSet::new();
    let mut shapes = Vec::new();
    let mut kind = None;
    for indexed in feeding {
        let description = indexed.description?;
        let subject = row_subject(&description.derivation, type_name, &well_known.user, db)?;
        // One relation's shapes fill one kind of leaf, so a mix falls closed.
        if *kind.get_or_insert(subject) != subject {
            return None;
        }
        if unique.insert(indexed.source.dedup_key()) {
            shapes.push(description.clone());
        }
    }
    let relation = relation.clone();
    Some(match kind? {
        RowSubject::Named => RowDecision::Leaf { relation, shapes },
        RowSubject::Everyone => RowDecision::Everyone { relation, shapes },
    })
}

/// Whom one row's record grants, when the row alone settles it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RowSubject {
    /// The user the row names.
    Named,
    /// Every user, through the typed wildcard.
    Everyone,
}

fn row_subject<DB: DatabaseLike>(
    derivation: &RecordDerivation,
    type_name: &TypeName,
    user_type: &TypeName,
    db: &DB,
) -> Option<RowSubject> {
    let RecordDerivation::FromRow {
        table, template, ..
    } = derivation
    else {
        // A joining source reads a second table, so the row does not decide.
        return None;
    };
    // A conditional record grants only while its condition holds, which no row leaf says.
    if template.context.is_some() || template.object_type != *type_name {
        return None;
    }
    // A record keyed by a foreign column describes another object, which this row does not own.
    let object_columns: Option<Vec<&str>> = template
        .object_key
        .parts()
        .iter()
        .map(|part| match part {
            ValueSource::Column(column) => Some(column.as_str()),
            _ => None,
        })
        .collect();
    if object_columns? != resolve_row_identity(table, db)? {
        return None;
    }
    // A subject reached through another type's membership is not one the row settles.
    if template.subject_type != *user_type {
        return None;
    }
    if template.subject_key.is_wildcard() {
        return Some(RowSubject::Everyone);
    }
    (!matches!(template.subject_key.part(), ValueSource::Literal(_))).then_some(RowSubject::Named)
}
