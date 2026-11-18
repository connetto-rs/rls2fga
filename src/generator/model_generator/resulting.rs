//! The type judging the row a write produces.
//!
//! A `WITH CHECK` clause reads the new row's own columns directly, while every helper and
//! subquery it calls reads the statement's snapshot, which holds the stored rows and never
//! the row being written. Asking the stored type with the new row's facts added mixes the
//! two. An `UPDATE` keeps the old values granting beside the new ones, a row inserted with
//! a grant authorizes itself, and a lookup of the row's own table at its own key reads the
//! new values `PostgreSQL` cannot see.
//!
//! So each table a write judges gets a type of its own. Its relations read the new row's
//! own facts, which every check carries as contextual tuples, and reach everything else
//! through the stored row under the same key.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};

use super::{deny_expr, DirectSubject, TypePlan, UsersetExpr};
use crate::generator::relations::{feeding_once, index_sources};
use crate::generator::row_naming::row_key;
use crate::generator::tuple_generator::{describe_source, NameContext, UnboundedColumns};
use crate::parser::names::canonical_fga_type_name;
use crate::parser::sql_parser::DatabaseLike;
use crate::types::{
    stable_hex_suffix, ActionAnswer, ActionJudgement, ActionRelations, ObjectKey, RecordDerivation,
    RecordDescription, RecordTemplate, RelationName, ResultingRow, RowVersion, SubjectKey, TableId,
    TranslationNote, TypeName, ValueSource,
};

/// Where a direct relation of the stored type reads its facts from, for a row a write
/// produces.
#[derive(Clone)]
enum Reads {
    /// The new row's own columns, which the check carries.
    NewRow(Vec<RecordDescription>),
    /// The stored row under the same key.
    StoredRow,
}

/// A fact neither the new row states nor the stored row holds alone.
struct Unreadable;

/// Add the type judging each table's written rows, point every resulting judgement at it,
/// and return what a check about such a row names and carries.
pub(super) fn add_resulting_types<DB: DatabaseLike>(
    all_types: &mut BTreeMap<TypeName, TypePlan>,
    entries: &mut [ActionRelations],
    notes: &mut Vec<TranslationNote>,
    bounds: &UnboundedColumns,
    db: &DB,
) -> Vec<ResultingRow> {
    let mut judged: BTreeMap<TypeName, BTreeSet<RelationName>> = BTreeMap::new();
    for entry in entries.iter() {
        for judgement in judgements(&entry.answer) {
            if judgement.version == RowVersion::Resulting {
                judged
                    .entry(entry.type_name.clone())
                    .or_default()
                    .insert(judgement.relation.clone());
            }
        }
    }
    let placed = place_direct_relations(all_types, &judged, bounds, db);

    let mut rows = Vec::new();
    let mut renamed: BTreeMap<TypeName, TypeName> = BTreeMap::new();
    for (stored_type, mut relations) in judged {
        let Some(stored) = all_types.get(&stored_type).cloned() else {
            continue;
        };
        // A judged relation the stored type never defines is undefined on both types alike.
        relations.retain(|relation| stored.computed_relations.contains_key(relation));
        if relations.is_empty() {
            continue;
        }
        let (Some(table), Some(key)) = (stored.source_table.clone(), row_key(&stored, db)) else {
            continue;
        };
        let type_name = free_type_name(all_types, &stored_type);
        let reads = placed.get(&stored_type).cloned().unwrap_or_default();
        let mut build = Build {
            all_types,
            stored: &stored,
            resulting: TypePlan::new_with_well_known(type_name.clone(), &stored.well_known),
            stored_link: free_relation_name(&stored, "stored"),
            reads,
            mapped: BTreeSet::new(),
        };
        build.resulting.resulting_of = Some(stored_type.clone());
        build.resulting.direct_relations.insert(
            build.stored_link.clone(),
            vec![DirectSubject::Type(stored_type.clone())],
        );
        for relation in &relations {
            if build.map_judged(relation).is_err() {
                let denied = deny_expr(&mut build.resulting);
                build
                    .resulting
                    .computed_relations
                    .insert(relation.clone(), denied);
                notes.push(TranslationNote::ResultingRowFactUnreadable {
                    table: table.clone(),
                    relation: relation.clone(),
                });
            }
        }
        let shapes = build.shapes(&table, &key);
        let resulting = build.resulting;
        rows.push(ResultingRow::new(table, type_name.clone(), key, shapes));
        all_types.insert(type_name.clone(), resulting);
        renamed.insert(stored_type, type_name);
    }

    for entry in entries.iter_mut() {
        let Some(type_name) = renamed.get(&entry.type_name) else {
            continue;
        };
        for judgement in judgements_mut(&mut entry.answer) {
            if judgement.version == RowVersion::Resulting {
                judgement.type_name = type_name.clone();
            }
        }
    }
    rows
}

/// Where each direct relation of every judged type reads its facts from, `None` for one
/// a written row cannot read.
///
/// Every source is placed once, through the index the relation report uses, and the
/// result owns its descriptions so the types can be extended afterwards.
fn place_direct_relations<DB: DatabaseLike>(
    all_types: &BTreeMap<TypeName, TypePlan>,
    judged: &BTreeMap<TypeName, BTreeSet<RelationName>>,
    bounds: &UnboundedColumns,
    db: &DB,
) -> BTreeMap<TypeName, BTreeMap<RelationName, Option<Reads>>> {
    let sources = index_sources(all_types.values(), |owner, _| owner);
    let mut placed = BTreeMap::new();
    for stored_type in judged.keys() {
        let Some(stored) = all_types.get(stored_type) else {
            continue;
        };
        let (Some(table), Some(own_key)) = (
            stored.source_table.as_ref(),
            row_key(stored, db).as_ref().and_then(key_spelling),
        ) else {
            continue;
        };
        let relations = stored
            .direct_relations
            .keys()
            .map(|relation| {
                let mut own = Vec::new();
                let mut from_store = false;
                let mut readable = true;
                for indexed in feeding_once(stored_type, relation, &sources) {
                    let owner = indexed.description;
                    let description = describe_source(
                        indexed.source,
                        &owner.type_name,
                        owner.reads_only_its_own_rows,
                        &owner.well_known,
                        NameContext::new(bounds),
                        db,
                    );
                    match description.and_then(|description| {
                        place_source(description, table, stored_type, &own_key)
                    }) {
                        Some(Placed::NewRow(description)) => own.push(description),
                        Some(Placed::StoredRow) => from_store = true,
                        None => readable = false,
                    }
                }
                let reads = match (readable, own.is_empty(), from_store) {
                    (false, _, _) | (true, false, true) => None,
                    (true, _, false) => Some(Reads::NewRow(own)),
                    (true, true, true) => Some(Reads::StoredRow),
                };
                (relation.clone(), reads)
            })
            .collect();
        placed.insert(stored_type.clone(), relations);
    }
    placed
}

/// Where one source's records about a written row come from.
enum Placed {
    /// The new row's own columns state them.
    NewRow(RecordDescription),
    /// The store holds them whatever the written row holds.
    StoredRow,
}

/// Place one source feeding a direct relation of `stored_type`, `None` where a written row
/// cannot read it.
fn place_source(
    description: RecordDescription,
    table: &TableId,
    stored_type: &TypeName,
    own_key: &[String],
) -> Option<Placed> {
    match &description.derivation {
        RecordDerivation::FromRow {
            table: read,
            template,
            ..
        } if read == table
            && template.object_type == *stored_type
            && key_spelling(&template.object_key).as_deref() == Some(own_key) =>
        {
            Some(Placed::NewRow(description))
        }
        // SQL evaluates it over the row's own columns, which one row cannot.
        RecordDerivation::Joined { .. } | RecordDerivation::WholeShape { .. }
            if description.tables.contains(table) =>
        {
            None
        }
        // Another row, other tables or no row decide it.
        RecordDerivation::FromRow { .. }
        | RecordDerivation::Constant { .. }
        | RecordDerivation::Joined { .. }
        | RecordDerivation::WholeShape { .. } => Some(Placed::StoredRow),
        _ => None,
    }
}

/// The judgements an answer asks, through the rows answer of a column answer.
fn judgements(answer: &ActionAnswer) -> &[ActionJudgement] {
    match answer {
        ActionAnswer::Judged(judgements) => judgements,
        ActionAnswer::ByColumn(column) => judgements(&column.rows),
        _ => &[],
    }
}

fn judgements_mut(answer: &mut ActionAnswer) -> &mut [ActionJudgement] {
    match answer {
        ActionAnswer::Judged(judgements) => judgements,
        ActionAnswer::ByColumn(column) => judgements_mut(&mut column.rows),
        _ => &mut [],
    }
}

/// `<stored>_resulting`, or with the stored type's hash where a table already took it.
fn free_type_name(all_types: &BTreeMap<TypeName, TypePlan>, stored: &TypeName) -> TypeName {
    let base = format!("{stored}_resulting");
    let mut candidate = canonical_fga_type_name(&base);
    let mut attempt = 0_usize;
    while all_types.contains_key(&candidate) {
        attempt += 1;
        candidate = canonical_fga_type_name(&format!(
            "{base}_{}",
            stable_hex_suffix(&format!("{stored}:{attempt}"))
        ));
    }
    candidate
}

/// `base`, or with a hash where the stored type already defines it, since the resulting
/// type copies the stored type's relations under their own names.
fn free_relation_name(stored: &TypePlan, base: &str) -> RelationName {
    let mut candidate = RelationName::canonicalized(base);
    let mut attempt = 0_usize;
    while stored.direct_relations.contains_key(&candidate)
        || stored.computed_relations.contains_key(&candidate)
    {
        attempt += 1;
        candidate = RelationName::canonicalized(format!(
            "{base}_{}",
            stable_hex_suffix(&format!("{}:{attempt}", stored.type_name))
        ));
    }
    candidate
}

/// One resulting type under construction.
struct Build<'a> {
    all_types: &'a mut BTreeMap<TypeName, TypePlan>,
    /// The stored type as it was before any alias was added to it.
    stored: &'a TypePlan,
    resulting: TypePlan,
    /// The relation naming the stored row under the same key.
    stored_link: RelationName,
    /// Where each direct relation of the stored type reads its facts from.
    reads: BTreeMap<RelationName, Option<Reads>>,
    /// Computed relations already copied onto the resulting type.
    mapped: BTreeSet<RelationName>,
}

impl Build<'_> {
    /// Copy the judged `relation` onto the resulting type, leaving the model as it was when
    /// a fact it reads is unreadable.
    fn map_judged(&mut self, relation: &RelationName) -> Result<(), Unreadable> {
        let stored_relations: BTreeSet<RelationName> = self
            .all_types
            .get(&self.stored.type_name)
            .map_or_else(BTreeSet::new, |plan| {
                plan.computed_relations.keys().cloned().collect()
            });
        let computed = self.resulting.computed_relations.clone();
        let direct = self.resulting.direct_relations.clone();
        let mapped = self.mapped.clone();
        let outcome = self.map_relation(relation, &mut Vec::new());
        if outcome.is_err() {
            if let Some(plan) = self.all_types.get_mut(&self.stored.type_name) {
                plan.computed_relations
                    .retain(|name, _| stored_relations.contains(name));
            }
            self.resulting.computed_relations = computed;
            self.resulting.direct_relations = direct;
            self.mapped = mapped;
        }
        outcome
    }

    /// Copy `relation` onto the resulting type, reading each of its facts from where the
    /// database reads it for a written row.
    fn map_relation(
        &mut self,
        relation: &RelationName,
        visiting: &mut Vec<RelationName>,
    ) -> Result<(), Unreadable> {
        if self.mapped.contains(relation) {
            return Ok(());
        }
        // A rule reaching itself is a walk the stored side answers, never the new row.
        if visiting.contains(relation) {
            return Err(Unreadable);
        }
        let Some(expr) = self.stored.computed_relations.get(relation) else {
            return Err(Unreadable);
        };
        visiting.push(relation.clone());
        let mapped = self.map_expr(expr, visiting);
        visiting.pop();
        let mapped = mapped?;
        self.resulting
            .computed_relations
            .insert(relation.clone(), mapped);
        self.mapped.insert(relation.clone());
        Ok(())
    }

    fn map_expr(
        &mut self,
        expr: &UsersetExpr,
        visiting: &mut Vec<RelationName>,
    ) -> Result<UsersetExpr, Unreadable> {
        Ok(match expr {
            UsersetExpr::StoredRow(name) => self.via_stored(name.clone()),
            UsersetExpr::Computed(name) if self.stored.direct_relations.contains_key(name) => {
                if self.reads_new_row(name)? {
                    self.declare(name);
                    UsersetExpr::Computed(name.clone())
                } else {
                    self.via_stored(name.clone())
                }
            }
            UsersetExpr::Computed(name) => {
                self.map_relation(name, visiting)?;
                UsersetExpr::Computed(name.clone())
            }
            UsersetExpr::TupleToUserset { tupleset, computed } => {
                if !self.stored.direct_relations.contains_key(tupleset) {
                    return Err(Unreadable);
                }
                if self.reads_new_row(tupleset)? {
                    self.declare(tupleset);
                    expr.clone()
                } else {
                    let stored = self
                        .all_types
                        .get_mut(&self.stored.type_name)
                        .ok_or(Unreadable)?;
                    let alias =
                        stored.ensure_computed(format!("{computed}_via_{tupleset}"), expr.clone());
                    self.via_stored(alias)
                }
            }
            UsersetExpr::Union(children) => UsersetExpr::Union(self.map_all(children, visiting)?),
            UsersetExpr::Intersection(children) => {
                UsersetExpr::Intersection(self.map_all(children, visiting)?)
            }
            UsersetExpr::Exclusion { base, subtract } => UsersetExpr::Exclusion {
                base: Box::new(self.map_expr(base, visiting)?),
                subtract: Box::new(self.map_expr(subtract, visiting)?),
            },
        })
    }

    fn map_all(
        &mut self,
        children: &[UsersetExpr],
        visiting: &mut Vec<RelationName>,
    ) -> Result<Vec<UsersetExpr>, Unreadable> {
        children
            .iter()
            .map(|child| self.map_expr(child, visiting))
            .collect()
    }

    /// `relation` read on the stored row under the same key.
    fn via_stored(&self, relation: RelationName) -> UsersetExpr {
        UsersetExpr::TupleToUserset {
            tupleset: self.stored_link.clone(),
            computed: relation,
        }
    }

    /// Declare a direct relation the new row states, as the stored type declares it.
    fn declare(&mut self, relation: &RelationName) {
        if let Some(subjects) = self.stored.direct_relations.get(relation) {
            self.resulting
                .direct_relations
                .insert(relation.clone(), subjects.clone());
        }
    }

    /// Whether the new row's own columns state the direct `relation` (`true`) or the stored
    /// row holds it (`false`).
    fn reads_new_row(&self, relation: &RelationName) -> Result<bool, Unreadable> {
        match self.reads.get(relation) {
            Some(Some(Reads::NewRow(_))) => Ok(true),
            Some(Some(Reads::StoredRow)) => Ok(false),
            _ => Err(Unreadable),
        }
    }

    /// The records a check about a written row carries, the new row's own facts under the
    /// resulting type and the link to the stored row.
    fn shapes(&self, table: &TableId, key: &ObjectKey) -> Vec<RecordDescription> {
        let mut shapes: Vec<RecordDescription> = Vec::new();
        for relation in self.resulting.direct_relations.keys() {
            let Some(Some(Reads::NewRow(descriptions))) = self.reads.get(relation) else {
                continue;
            };
            for description in descriptions {
                let mut description = description.clone();
                if let RecordDerivation::FromRow { template, .. } = &mut description.derivation {
                    template.object_type = self.resulting.type_name.clone();
                }
                if !shapes.contains(&description) {
                    shapes.push(description);
                }
            }
        }
        if let Some((first, rest)) = key.parts().split_first() {
            shapes.push(RecordDescription {
                tables: vec![table.clone()],
                derivation: RecordDerivation::FromRow {
                    table: table.clone(),
                    template: Box::new(RecordTemplate {
                        object_type: self.resulting.type_name.clone(),
                        object_key: key.clone(),
                        relation: self.stored_link.clone(),
                        subject_type: self.stored.type_name.clone(),
                        subject_key: SubjectKey::composite_sources(first.clone(), rest.to_vec()),
                        context: None,
                    }),
                    guards: Vec::new(),
                },
            });
        }
        shapes
    }
}

/// How a key is spelled from columns and literals, in order, `None` for a part read any
/// other way.
fn key_spelling(key: &ObjectKey) -> Option<Vec<String>> {
    key.parts()
        .iter()
        .map(|part| match part {
            ValueSource::Column(read) => Some(format!("column:{}", read.as_str())),
            ValueSource::Literal(value) => Some(format!("literal:{value}")),
            _ => None,
        })
        .collect()
}
