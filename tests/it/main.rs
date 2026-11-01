mod support;

mod absent_column_tests;
mod action_relations_tests;
mod attribute_in_list_tests;
mod attribute_null_test_tests;
mod blocklist_exclusion_tests;
mod builtin_shadow_tests;
mod caller_cast_tests;
mod caller_roles_tests;
mod classifier_edge_case_tests;
mod classifier_indirect_membership_tests;
mod classifier_tests;
mod common_patterns_tests;
mod composite_key_membership_tests;
mod confidence_filtering_tests;
mod container_startup_tests;
mod declared_helper_parity_tests;
mod declared_helper_tests;
mod diagnostic_reach_tests;
#[cfg(feature = "client")]
mod dump_round_trip_tests;
mod duplication_guard_tests;
mod end_to_end_tests;
mod exact_support_tests;
mod footgun_clauses_tests;
mod footgun_inheritance_tests;
mod footgun_membership_tests;
mod footgun_model_shape_tests;
mod footgun_naming_tests;
mod footgun_quoted_identity_tests;
mod footgun_recursion_tests;
mod footgun_reporting_tests;
mod footgun_requests_tests;
mod footgun_residual_purity_tests;
mod footgun_roles_tests;
mod footgun_row_keys_tests;
mod footgun_spelling_tests;
mod footgun_subquery_shape_tests;
mod gated_membership_parity_tests;
mod generation_edge_case_tests;
mod generator_tests;
mod generic_catalog_tests;
mod indirect_membership_tests;
mod joined_inner_rule_tests;
mod membership_term_tests;
mod model_equivalence_tests;
#[cfg(feature = "client")]
mod openfga_client_tests;
#[cfg(feature = "client")]
mod openfga_integration_tests;
#[cfg(feature = "client")]
mod openfga_semantic_tests;
mod output_formatter_tests;
#[cfg(feature = "client")]
mod parity_runner_tests;
mod parser_tests;
mod pattern_generation_tests;
#[cfg(feature = "client")]
mod per_row_record_parity_tests;
mod per_row_witness_tests;
mod policy_composition_tests;
mod policy_oracle_tests;
mod policy_reads_tests;
mod relation_shapes_tests;
mod request_gate_parity_tests;
mod request_gate_recipe_parity_tests;
mod request_gate_tests;
mod row_naming_tests;
mod security_definer_tests;
mod table_privileges_tests;
mod translation_object_tests;
mod translator_builder_tests;
mod tuple_row_tests;
mod unrestricted_tables_tests;
mod web_examples_tests;
