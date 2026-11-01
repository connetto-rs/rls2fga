pub(crate) mod action_relations;
// `caller_roles` carries its own `//!` docs, so no outer doc here.
pub mod caller_roles;
/// Shared schema lookup helpers used by model/tuple generation.
pub(crate) mod db_lookup;
// `identity` carries its own `//!` docs, so no outer doc here.
pub(crate) mod identity;
// Private derivation modules carry their own module documentation.
pub(crate) mod describe;
/// Shared authorization intermediate representation (`TupleSource` and friends).
pub(crate) mod ir;
/// `OpenFGA` JSON authorization model structs and builder.
pub mod json_model;
/// The `validate.rules` bounds the written model must satisfy.
pub mod model_bounds;
/// `OpenFGA` DSL text model generation.
pub mod model_generator;
// `notes` carries its own `//!` docs, so no outer doc here.
pub(crate) mod notes;
pub(crate) mod relations;
/// Shared helpers for stable and valid role-based relation naming.
pub(crate) mod role_relations;
pub(crate) mod row_naming;
/// SQL queries that populate `OpenFGA` relationship tuples from live data.
pub mod tuple_generator;
pub mod well_known;
// `unrestricted` carries its own module documentation.
pub(crate) mod unrestricted;
