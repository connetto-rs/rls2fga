//! The `validate.rules` bounds the written model must satisfy, checked against the
//! JSON model the client writes.
//!
//! `OpenFGA` refuses a model that crosses one of these bounds at the write call, too
//! late. The check runs while the plan is built, so `PlanningError::ModelBoundExceeded`
//! names the bound before the model leaves.
//!
//! Relation and condition names are bounded by their own types, which refuse or clamp
//! anything past 50 characters, so only the names a deployment configures are checked
//! here. Server-configurable limits are not errors. The type count and the encoded size
//! stay on the outputs for a consumer to compare with its server.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::generator::model_generator::PlanningError;
use alloc::collections::BTreeMap;

use crate::generator::json_model::{AuthorizationModel, Condition, TypeDefinition};
use crate::types::ConditionName;

/// The number of pairs `AuthorizationModel.conditions` and
/// `WriteAuthorizationModelRequest.conditions` admit.
const MAX_CONDITIONS: usize = 25;

/// The number of pairs `Condition.parameters` admits.
const MAX_CONDITION_PARAMETERS: usize = 25;

/// The number of bytes a `Condition.expression` may carry.
const MAX_CONDITION_EXPRESSION_BYTES: usize = 512;

/// The number of characters a `TypeDefinition.type` or `RelationReference.type`
/// may carry.
const MAX_TYPE_NAME_CHARS: usize = 254;

/// The number of characters a `Condition.parameters` key may carry.
pub(crate) const MAX_PARAMETER_NAME_CHARS: usize = 50;

/// A `validate.rules` bound in `openfga/api` the written model must satisfy, read
/// from `openfga/v1/authzmodel.proto` and `openfga/v1/openfga_service.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelBound {
    /// `TypeDefinition.type`, one to 254 characters.
    TypeName,
    /// A `RelationReference.type`, one to 254 characters.
    ReferenceType,
    /// `AuthorizationModel.conditions`, at most 25 pairs.
    Conditions,
    /// A `Condition.expression`, at most 512 bytes.
    ConditionExpression,
    /// `Condition.parameters`, at most 25 pairs.
    ConditionParameters,
    /// A `Condition.parameters` key, one to 50 characters.
    ConditionParameterKey,
}

/// Check `model` against the bounds the `WriteAuthorizationModel` call enforces,
/// which `openfga/api` spells as `validate.rules` in `openfga/v1/authzmodel.proto`
/// and `openfga/v1/openfga_service.proto`.
///
/// # Errors
///
/// Returns the first bound the model crosses.
pub fn check(model: &AuthorizationModel) -> Result<(), PlanningError> {
    for definition in &model.type_definitions {
        check_type_definition(definition)?;
    }
    if let Some(conditions) = &model.conditions {
        check_conditions(conditions)
    } else {
        Ok(())
    }
}

fn check_type_definition(definition: &TypeDefinition) -> Result<(), PlanningError> {
    check_name(
        definition.type_name.as_str(),
        ModelBound::TypeName,
        MAX_TYPE_NAME_CHARS,
    )?;
    for relation in definition
        .metadata
        .iter()
        .flat_map(|metadata| metadata.relations.values())
    {
        for reference in &relation.directly_related_user_types {
            check_name(
                reference.type_name.as_str(),
                ModelBound::ReferenceType,
                MAX_TYPE_NAME_CHARS,
            )?;
        }
    }
    Ok(())
}

fn check_name(name: &str, bound: ModelBound, max_chars: usize) -> Result<(), PlanningError> {
    if name_within_pattern(name, max_chars) {
        Ok(())
    } else {
        Err(bound_error(bound, name.chars().count(), max_chars, name))
    }
}

fn check_conditions(conditions: &BTreeMap<ConditionName, Condition>) -> Result<(), PlanningError> {
    if let Some(past) = conditions.keys().nth(MAX_CONDITIONS) {
        return Err(bound_error(
            ModelBound::Conditions,
            conditions.len(),
            MAX_CONDITIONS,
            past.as_str(),
        ));
    }
    conditions.values().try_for_each(check_condition)
}

fn check_condition(condition: &Condition) -> Result<(), PlanningError> {
    let name = condition.name.as_str();
    if condition.expression.len() > MAX_CONDITION_EXPRESSION_BYTES {
        return Err(bound_error(
            ModelBound::ConditionExpression,
            condition.expression.len(),
            MAX_CONDITION_EXPRESSION_BYTES,
            name,
        ));
    }
    if condition.parameters.len() > MAX_CONDITION_PARAMETERS {
        return Err(bound_error(
            ModelBound::ConditionParameters,
            condition.parameters.len(),
            MAX_CONDITION_PARAMETERS,
            name,
        ));
    }
    for parameter in condition.parameters.keys() {
        check_name(
            parameter,
            ModelBound::ConditionParameterKey,
            MAX_PARAMETER_NAME_CHARS,
        )?;
    }
    Ok(())
}

/// The `OpenFGA` name pattern `^[^:#@\s]{1, $max_chars}$`, counted in characters.
fn name_within_pattern(name: &str, max_chars: usize) -> bool {
    !name.is_empty()
        && name.chars().count() <= max_chars
        && !name
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, ':' | '#' | '@'))
}

fn bound_error(bound: ModelBound, measured: usize, limit: usize, item: &str) -> PlanningError {
    PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        item: item.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    use crate::generator::json_model::{
        AuthorizationModel, Condition, ConditionParamType, EmptyObject, RelationMetadata,
        RelationReference, TypeDefinition, TypeMetadata, Userset,
    };
    use crate::types::{ConditionName, RelationName, TypeName};

    /// One type with one direct relation and no conditions.
    fn base_model() -> AuthorizationModel {
        AuthorizationModel {
            schema_version: "1.1".to_string(),
            type_definitions: vec![TypeDefinition {
                type_name: TypeName::canonicalized("docs"),
                relations: Some(BTreeMap::from([(
                    RelationName::canonicalized("can_select"),
                    Userset::This {
                        this: EmptyObject {},
                    },
                )])),
                metadata: None,
            }],
            conditions: None,
        }
    }

    fn with_conditions(conditions: impl IntoIterator<Item = Condition>) -> AuthorizationModel {
        let mut model = base_model();
        model.conditions = Some(
            conditions
                .into_iter()
                .map(|condition| (condition.name.clone(), condition))
                .collect(),
        );
        model
    }

    fn condition(name: &str, expression: &str, parameters: &[String]) -> Condition {
        Condition {
            name: ConditionName::canonicalized(name),
            expression: expression.to_string(),
            parameters: parameters
                .iter()
                .map(|key| {
                    (
                        key.clone(),
                        ConditionParamType {
                            parameter_type: "TYPE_NAME_STRING".to_string(),
                            generic_types: None,
                        },
                    )
                })
                .collect(),
        }
    }

    fn crossed(bound: ModelBound, measured: usize, limit: usize, item: &str) -> PlanningError {
        bound_error(bound, measured, limit, item)
    }

    #[test]
    fn a_model_at_every_bound_passes() {
        let parameters: Vec<String> = (0..25)
            .map(|index| format!("{}{index:02}", "p".repeat(48)))
            .collect();
        let mut model = with_conditions(
            (0..25).map(|index| condition(&format!("when_{index}"), &"e".repeat(512), &parameters)),
        );
        model.type_definitions[0].type_name =
            TypeName::try_from("a".repeat(254)).expect("the name is otherwise valid");
        check(&model).expect("every bound is met");
    }

    #[test]
    fn an_expression_over_five_hundred_twelve_bytes_refuses() {
        let model = with_conditions([condition("when_docs", &"e".repeat(513), &[])]);
        assert_eq!(
            check(&model),
            Err(crossed(
                ModelBound::ConditionExpression,
                513,
                512,
                "when_docs"
            ))
        );
    }

    #[test]
    fn twenty_six_conditions_refuse() {
        let model = with_conditions(
            (0..26).map(|index| condition(&format!("when_{index:02}"), "true", &[])),
        );
        assert_eq!(
            check(&model),
            Err(crossed(ModelBound::Conditions, 26, 25, "when_25"))
        );
    }

    #[test]
    fn twenty_six_condition_parameters_refuse() {
        let parameters: Vec<String> = (0..26).map(|index| format!("p{index}")).collect();
        let model = with_conditions([condition("when_docs", "true", &parameters)]);
        assert_eq!(
            check(&model),
            Err(crossed(
                ModelBound::ConditionParameters,
                26,
                25,
                "when_docs"
            ))
        );
    }

    #[test]
    fn a_parameter_name_over_fifty_characters_refuses() {
        let name = "p".repeat(51);
        let model = with_conditions([condition("when_docs", "true", core::slice::from_ref(&name))]);
        assert_eq!(
            check(&model),
            Err(crossed(ModelBound::ConditionParameterKey, 51, 50, &name))
        );
    }

    #[test]
    fn a_type_name_over_two_hundred_fifty_four_characters_refuses() {
        let name = "a".repeat(255);
        let mut model = base_model();
        model.type_definitions[0].type_name =
            TypeName::try_from(name.clone()).expect("the name is otherwise valid");
        assert_eq!(
            check(&model),
            Err(crossed(ModelBound::TypeName, 255, 254, &name))
        );
    }

    #[test]
    fn a_reference_type_over_two_hundred_fifty_four_characters_refuses() {
        let name = "a".repeat(255);
        let mut model = base_model();
        model.type_definitions[0].metadata = Some(TypeMetadata {
            relations: BTreeMap::from([(
                RelationName::canonicalized("can_select"),
                RelationMetadata {
                    directly_related_user_types: vec![RelationReference {
                        type_name: TypeName::try_from(name.clone())
                            .expect("the name is otherwise valid"),
                        wildcard: None,
                        condition: None,
                    }],
                },
            )]),
        });
        assert_eq!(
            check(&model),
            Err(crossed(ModelBound::ReferenceType, 255, 254, &name))
        );
    }
}
