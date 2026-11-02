//! Model and tuple equivalence under scoped direct-source renaming.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

pub(crate) type TupleRows = BTreeSet<(String, String, String)>;
type Types<'a> = BTreeMap<&'a str, &'a Value>;
type Renaming<'a> = BTreeMap<(&'a str, &'a str), &'a str>;

pub(crate) fn equivalent(
    left: &Value,
    left_rows: &TupleRows,
    right: &Value,
    right_rows: &TupleRows,
) -> bool {
    let Some((left_types, right_types)) = types(left).zip(types(right)) else {
        return false;
    };
    if !other_fields_equal(left, right, &["type_definitions"])
        || !left_types.keys().eq(right_types.keys())
        || left_rows.len() != right_rows.len()
    {
        return false;
    }
    let mut candidates = Vec::new();
    for (owner, left_type) in &left_types {
        let right_type = right_types[owner];
        let left_relations = relations(left_type);
        let right_relations = relations(right_type);
        if left_relations.map(Map::len) != right_relations.map(Map::len) {
            return false;
        }
        let Some(left_relations) = left_relations else {
            continue;
        };
        let Some(right_relations) = right_relations else {
            return false;
        };
        for (name, rule) in left_relations {
            if right_relations.contains_key(name) {
                continue;
            }
            if rule.as_object().is_none_or(|fields| fields.len() != 1)
                || !rule
                    .get("this")
                    .and_then(Value::as_object)
                    .is_some_and(Map::is_empty)
            {
                return false;
            }
            let choices: Vec<&str> = right_relations
                .iter()
                .filter(|(other, other_rule)| {
                    !left_relations.contains_key(*other)
                        && *other_rule == rule
                        && metadata(left_type, name) == metadata(right_type, other)
                })
                .map(|(other, _)| other.as_str())
                .collect();
            if choices.is_empty() {
                return false;
            }
            candidates.push(((*owner, name.as_str()), choices));
        }
    }
    let comparison = Comparison {
        left_types,
        right_types,
        left_rows,
        right_rows: right_rows
            .iter()
            .map(|(object, relation, subject)| {
                (
                    object.as_str(),
                    relation.as_str(),
                    Cow::Borrowed(subject.as_str()),
                )
            })
            .collect(),
    };
    comparison.search(&candidates, &mut Renaming::new())
}

struct Comparison<'a> {
    left_types: Types<'a>,
    right_types: Types<'a>,
    left_rows: &'a TupleRows,
    right_rows: BTreeSet<(&'a str, &'a str, Cow<'a, str>)>,
}

impl<'a> Comparison<'a> {
    fn search(
        &self,
        candidates: &[((&'a str, &'a str), Vec<&'a str>)],
        renaming: &mut Renaming<'a>,
    ) -> bool {
        let Some((key, choices)) = candidates.first() else {
            return self.models_equal(renaming) && self.rows_equal(renaming);
        };
        for choice in choices {
            if renaming
                .iter()
                .any(|((owner, _), image)| owner == &key.0 && image == choice)
            {
                continue;
            }
            renaming.insert(*key, choice);
            let matched = self.search(&candidates[1..], renaming);
            renaming.remove(key);
            if matched {
                return true;
            }
        }
        false
    }

    fn models_equal(&self, renaming: &Renaming<'_>) -> bool {
        self.left_types.iter().all(|(owner, left_type)| {
            let right_type = self.right_types[owner];
            if !other_fields_equal(left_type, right_type, &["relations", "metadata"])
                || !optional_fields_equal(
                    left_type.get("metadata"),
                    right_type.get("metadata"),
                    &["relations"],
                )
            {
                return false;
            }
            let entries_equal = |left: Option<&Map<String, Value>>,
                                 right: Option<&Map<String, Value>>,
                                 rewrites: bool| {
                match (left, right) {
                    (None, None) => true,
                    (Some(left), Some(right)) if left.len() == right.len() => {
                        left.iter().all(|(name, value)| {
                            right
                                .get(image(renaming, owner, name))
                                .is_some_and(|other| {
                                    if rewrites {
                                        self.rewrite_equal(value, other, owner, renaming)
                                    } else {
                                        value == other
                                    }
                                })
                        })
                    }
                    _ => false,
                }
            };
            entries_equal(relations(left_type), relations(right_type), true)
                && entries_equal(
                    metadata_relations(left_type),
                    metadata_relations(right_type),
                    false,
                )
        })
    }

    fn rewrite_equal(
        &self,
        left: &Value,
        right: &Value,
        owner: &str,
        renaming: &Renaming<'_>,
    ) -> bool {
        let Some((left_fields, right_fields)) = left.as_object().zip(right.as_object()) else {
            return false;
        };
        if left_fields.len() != 1 || !left_fields.keys().eq(right_fields.keys()) {
            return false;
        }
        let Some((kind, value)) = left_fields.iter().next() else {
            return false;
        };
        let other = &right_fields[kind];
        match kind.as_str() {
            "this" => value == other && value.as_object().is_some_and(Map::is_empty),
            "computedUserset" => reference_equal(value, other, owner, renaming),
            "tupleToUserset" => {
                if !other_fields_equal(value, other, &["tupleset", "computedUserset"]) {
                    return false;
                }
                let Some((tupleset, other_tupleset)) =
                    value.get("tupleset").zip(other.get("tupleset"))
                else {
                    return false;
                };
                if !reference_equal(tupleset, other_tupleset, owner, renaming) {
                    return false;
                }
                let Some((computed, other_computed)) = value
                    .get("computedUserset")
                    .zip(other.get("computedUserset"))
                else {
                    return false;
                };
                let Some(name) = tupleset.get("relation").and_then(Value::as_str) else {
                    return false;
                };
                let Some(targets) = self
                    .left_types
                    .get(owner)
                    .and_then(|definition| metadata(definition, name))
                    .and_then(|entry| entry.get("directly_related_user_types"))
                    .and_then(Value::as_array)
                else {
                    return computed == other_computed;
                };
                if targets.is_empty() {
                    return computed == other_computed;
                }
                targets.iter().all(|target| {
                    target
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|target_type| {
                            reference_equal(computed, other_computed, target_type, renaming)
                        })
                })
            }
            "union" | "intersection" => {
                if !other_fields_equal(value, other, &["child"]) {
                    return false;
                }
                let Some((children, other_children)) = value
                    .get("child")
                    .and_then(Value::as_array)
                    .zip(other.get("child").and_then(Value::as_array))
                else {
                    return false;
                };
                if children.len() != other_children.len() {
                    return false;
                }
                let mut used = vec![false; other_children.len()];
                children.iter().all(|child| {
                    let Some(index) =
                        other_children
                            .iter()
                            .enumerate()
                            .position(|(index, other_child)| {
                                !used[index]
                                    && self.rewrite_equal(child, other_child, owner, renaming)
                            })
                    else {
                        return false;
                    };
                    used[index] = true;
                    true
                })
            }
            "difference" => {
                other_fields_equal(value, other, &["base", "subtract"])
                    && ["base", "subtract"].into_iter().all(|field| {
                        value.get(field).zip(other.get(field)).is_some_and(
                            |(child, other_child)| {
                                self.rewrite_equal(child, other_child, owner, renaming)
                            },
                        )
                    })
            }
            _ => false,
        }
    }

    fn rows_equal(&self, renaming: &Renaming<'_>) -> bool {
        let mapped: BTreeSet<_> = self
            .left_rows
            .iter()
            .map(|(object, relation, subject)| {
                let owner = object.split_once(':').map_or("", |(owner, _)| owner);
                (
                    object.as_str(),
                    image(renaming, owner, relation),
                    mapped_subject(subject, renaming),
                )
            })
            .collect();
        mapped == self.right_rows
    }
}

fn types(model: &Value) -> Option<Types<'_>> {
    let mut types = BTreeMap::new();
    for definition in model.get("type_definitions")?.as_array()? {
        let name = definition.get("type")?.as_str()?;
        if types.insert(name, definition).is_some() {
            return None;
        }
    }
    Some(types)
}

fn relations(definition: &Value) -> Option<&Map<String, Value>> {
    definition.get("relations").and_then(Value::as_object)
}

fn metadata_relations(definition: &Value) -> Option<&Map<String, Value>> {
    definition.get("metadata")?.get("relations")?.as_object()
}

fn metadata<'a>(definition: &'a Value, relation: &str) -> Option<&'a Value> {
    metadata_relations(definition)?.get(relation)
}

fn image<'a>(renaming: &Renaming<'a>, owner: &str, name: &'a str) -> &'a str {
    renaming.get(&(owner, name)).copied().unwrap_or(name)
}

fn reference_equal(left: &Value, right: &Value, owner: &str, renaming: &Renaming<'_>) -> bool {
    other_fields_equal(left, right, &["relation"])
        && left
            .get("relation")
            .and_then(Value::as_str)
            .zip(right.get("relation").and_then(Value::as_str))
            .is_some_and(|(name, other)| image(renaming, owner, name) == other)
}

fn mapped_subject<'a>(subject: &'a str, renaming: &Renaming<'_>) -> Cow<'a, str> {
    let Some((object, relation)) = subject.rsplit_once('#') else {
        return Cow::Borrowed(subject);
    };
    let Some((owner, _)) = object.split_once(':') else {
        return Cow::Borrowed(subject);
    };
    let mapped = image(renaming, owner, relation);
    if mapped == relation {
        Cow::Borrowed(subject)
    } else {
        Cow::Owned(format!("{object}#{mapped}"))
    }
}

fn optional_fields_equal(left: Option<&Value>, right: Option<&Value>, excluded: &[&str]) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => other_fields_equal(left, right, excluded),
        _ => false,
    }
}

fn other_fields_equal(left: &Value, right: &Value, excluded: &[&str]) -> bool {
    let Some((left, right)) = left.as_object().zip(right.as_object()) else {
        return false;
    };
    left.iter()
        .filter(|(key, _)| !excluded.contains(&key.as_str()))
        .eq(right
            .iter()
            .filter(|(key, _)| !excluded.contains(&key.as_str())))
}
