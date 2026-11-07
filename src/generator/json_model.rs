#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeMap;

use serde::Serialize;

use crate::generator::model_generator::{
    ConditionParameter, DirectSubject, SchemaPlan, TypePlan, UsersetExpr, OPENFGA_SCHEMA_VERSION,
};
use crate::generator::well_known::LIST_PARAMETER_TYPE;
use crate::types::{ConditionName, RelationName, TypeName};

/// `OpenFGA` authorization model in the JSON form the API accepts.
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationModel {
    /// Currently `"1.1"`.
    pub schema_version: String,
    /// Types in emission order.
    pub type_definitions: Vec<TypeDefinition>,
    /// Conditions a relation reference may name, keyed by condition name. Omitted
    /// when the schema needs none, since `OpenFGA` accepts a model without the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<BTreeMap<ConditionName, Condition>>,
}

/// A `CEL` expression `OpenFGA` evaluates when a tuple naming it is consulted.
///
/// The parameters come from two places that merge at check time: the tuple carries
/// what the row knows, the request carries what only it knows.
#[derive(Debug, Clone, Serialize)]
pub struct Condition {
    /// Condition name, repeated inside the value as the API expects.
    pub name: ConditionName,
    /// The `CEL` expression, in terms of the parameter names.
    pub expression: String,
    /// Parameter name to its type.
    pub parameters: BTreeMap<String, ConditionParamType>,
}

/// A condition parameter's type, spelled the way the API names it.
#[derive(Debug, Clone, Serialize)]
pub struct ConditionParamType {
    /// For example `TYPE_NAME_TIMESTAMP`. A `CEL` parameter type, not a model type, so it
    /// carries no [`TypeName`].
    #[serde(rename = "type_name")]
    pub parameter_type: String,
    /// Element type of a list parameter, absent for a single value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_types: Option<Vec<ConditionParamType>>,
}

/// The API shape of a condition parameter type: a list names its element type as a
/// generic, a single value names none.
fn condition_param_type(kind: &ConditionParameter) -> ConditionParamType {
    match kind {
        ConditionParameter::Scalar(type_name) => ConditionParamType {
            parameter_type: (*type_name).to_string(),
            generic_types: None,
        },
        ConditionParameter::Clock(_) => ConditionParamType {
            parameter_type: crate::generator::well_known::TIMESTAMP_PARAMETER_TYPE.to_string(),
            generic_types: None,
        },
        ConditionParameter::ListOf(element) => ConditionParamType {
            parameter_type: LIST_PARAMETER_TYPE.to_string(),
            generic_types: Some(vec![ConditionParamType {
                parameter_type: (*element).to_string(),
                generic_types: None,
            }]),
        },
    }
}

/// One type and its relations.
#[derive(Debug, Clone, Serialize)]
pub struct TypeDefinition {
    /// Type identifier.
    #[serde(rename = "type")]
    pub type_name: TypeName,
    /// Relation name → userset rewrite rule. `None` for types with no relations (e.g. `user`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relations: Option<BTreeMap<RelationName, Userset>>,
    /// Allowed directly-related user types per relation. `None` for computed-only relations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TypeMetadata>,
}

/// Per-relation metadata declaring which types may be directly assigned.
#[derive(Debug, Clone, Serialize)]
pub struct TypeMetadata {
    /// Relation name to its assignable types.
    pub relations: BTreeMap<RelationName, RelationMetadata>,
}

/// Allowed directly-related types for a single relation.
#[derive(Debug, Clone, Serialize)]
pub struct RelationMetadata {
    /// Types accepted as subjects.
    pub directly_related_user_types: Vec<RelationReference>,
}

/// Reference to an allowed subject type, optionally as a public wildcard.
#[derive(Debug, Clone, Serialize)]
pub struct RelationReference {
    /// Type identifier.
    #[serde(rename = "type")]
    pub type_name: TypeName,
    /// If `Some`, this reference represents the public wildcard (`type:*`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<EmptyObject>,
    /// Condition every tuple through this reference must satisfy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionName>,
}

/// Marker struct serialized as `{}` for `OpenFGA`'s `this` and `wildcard` fields.
#[derive(Debug, Clone, Serialize)]
pub struct EmptyObject {}

/// A userset rewrite rule.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Userset {
    /// Direct assignment (`this: {}`).
    This {
        /// Serialized as `{}`.
        this: EmptyObject,
    },
    /// Reference to another relation on the same type.
    ComputedUserset {
        /// Relation to compute from.
        #[serde(rename = "computedUserset")]
        computed_userset: ObjectRelation,
    },
    /// Indirection through a tupleset relation to a computed userset on the target.
    TupleToUserset {
        /// The tupleset and target relation.
        #[serde(rename = "tupleToUserset")]
        tuple_to_userset: TupleToUsersetDef,
    },
    /// Union of child usersets (logical OR).
    Union {
        /// Children combined with OR.
        union: UnionDef,
    },
    /// Intersection of child usersets (logical AND).
    Intersection {
        /// Children combined with AND.
        intersection: IntersectionDef,
    },
    /// Base userset minus a subtracted one (logical AND NOT).
    Difference {
        /// The base and the userset removed from it.
        difference: DifferenceDef,
    },
}

/// Identifies a single relation by name.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectRelation {
    /// Relation name.
    pub relation: RelationName,
}

/// Follow `tupleset`, then evaluate `computed_userset` on each object reached.
#[derive(Debug, Clone, Serialize)]
pub struct TupleToUsersetDef {
    /// Relation whose tuples supply the intermediate objects.
    pub tupleset: ObjectRelation,
    /// Relation evaluated on each object reached.
    #[serde(rename = "computedUserset")]
    pub computed_userset: ObjectRelation,
}

/// A union of child userset rewrite rules.
#[derive(Debug, Clone, Serialize)]
pub struct UnionDef {
    /// Child usersets: access is granted if any child grants access.
    pub child: Vec<Userset>,
}

/// An intersection of child userset rewrite rules.
#[derive(Debug, Clone, Serialize)]
pub struct IntersectionDef {
    /// Child usersets: access is granted only if all children grant access.
    pub child: Vec<Userset>,
}

/// A userset minus another one.
#[derive(Debug, Clone, Serialize)]
pub struct DifferenceDef {
    /// Users granted before the subtraction.
    pub base: Box<Userset>,
    /// Users removed from `base`.
    pub subtract: Box<Userset>,
}

/// Render a JSON-serializable `AuthorizationModel` from a planned schema.
pub(crate) fn json_model_from_plan(plan: &SchemaPlan) -> AuthorizationModel {
    let type_definitions = plan.types.iter().map(type_plan_to_definition).collect();

    let conditions = (!plan.conditions.is_empty()).then(|| {
        plan.conditions
            .iter()
            .map(|(name, spec)| {
                (
                    name.clone(),
                    Condition {
                        name: name.clone(),
                        expression: spec.expression.clone(),
                        parameters: spec
                            .parameters
                            .iter()
                            .map(|(parameter, kind)| {
                                (parameter.clone(), condition_param_type(kind))
                            })
                            .collect(),
                    },
                )
            })
            .collect()
    });

    AuthorizationModel {
        schema_version: OPENFGA_SCHEMA_VERSION.to_string(),
        type_definitions,
        conditions,
    }
}

fn type_plan_to_definition(plan: &TypePlan) -> TypeDefinition {
    if plan.direct_relations.is_empty() && plan.computed_relations.is_empty() {
        return TypeDefinition {
            type_name: plan.type_name.clone(),
            relations: None,
            metadata: None,
        };
    }

    let mut relations = BTreeMap::new();
    let mut meta_relations = BTreeMap::new();

    for (name, subjects) in &plan.direct_relations {
        relations.insert(
            name.clone(),
            Userset::This {
                this: EmptyObject {},
            },
        );

        let refs = subjects
            .iter()
            .map(|subject| match subject {
                DirectSubject::Type(t) => RelationReference {
                    type_name: t.clone(),
                    wildcard: None,
                    condition: None,
                },
                DirectSubject::Wildcard(t) => RelationReference {
                    type_name: t.clone(),
                    wildcard: Some(EmptyObject {}),
                    condition: None,
                },
                DirectSubject::ConditionalWildcard {
                    type_name,
                    condition,
                } => RelationReference {
                    type_name: type_name.clone(),
                    wildcard: Some(EmptyObject {}),
                    condition: Some(condition.clone()),
                },
                DirectSubject::ConditionalType {
                    type_name,
                    condition,
                } => RelationReference {
                    type_name: type_name.clone(),
                    wildcard: None,
                    condition: Some(condition.clone()),
                },
            })
            .collect::<Vec<_>>();

        meta_relations.insert(
            name.clone(),
            RelationMetadata {
                directly_related_user_types: refs,
            },
        );
    }

    for (name, expr) in &plan.computed_relations {
        relations.insert(name.clone(), expr_to_userset(expr));
    }

    TypeDefinition {
        type_name: plan.type_name.clone(),
        relations: Some(relations),
        metadata: Some(TypeMetadata {
            relations: meta_relations,
        }),
    }
}

fn expr_to_userset(expr: &UsersetExpr) -> Userset {
    match expr {
        UsersetExpr::Computed(relation) => Userset::ComputedUserset {
            computed_userset: ObjectRelation {
                relation: relation.clone(),
            },
        },
        UsersetExpr::TupleToUserset { tupleset, computed } => Userset::TupleToUserset {
            tuple_to_userset: TupleToUsersetDef {
                tupleset: ObjectRelation {
                    relation: tupleset.clone(),
                },
                computed_userset: ObjectRelation {
                    relation: computed.clone(),
                },
            },
        },
        UsersetExpr::Union(children) => Userset::Union {
            union: UnionDef {
                child: children.iter().map(expr_to_userset).collect(),
            },
        },
        UsersetExpr::Intersection(children) => Userset::Intersection {
            intersection: IntersectionDef {
                child: children.iter().map(expr_to_userset).collect(),
            },
        },
        UsersetExpr::Exclusion { base, subtract } => Userset::Difference {
            difference: DifferenceDef {
                base: Box::new(expr_to_userset(base)),
                subtract: Box::new(expr_to_userset(subtract)),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::well_known::{member_relation, TEAM_TYPE};

    #[test]
    fn expr_to_userset_supports_intersection_nodes() {
        let expr = UsersetExpr::Intersection(vec![
            UsersetExpr::Computed(RelationName::canonicalized("owner")),
            UsersetExpr::TupleToUserset {
                tupleset: RelationName::canonicalized(TEAM_TYPE),
                computed: member_relation(),
            },
        ]);

        let userset = expr_to_userset(&expr);
        assert!(matches!(
            userset,
            Userset::Intersection {
                intersection: IntersectionDef { child }
            } if child.len() == 2
        ));
    }
}
