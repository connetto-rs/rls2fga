/// The casts a catalog answers around a policy's date and time literals.
pub(crate) mod column_type_casts;
/// SQL expression helpers used across classifier and generator code paths.
pub mod expr;
/// Heuristic analysis of SQL function bodies to infer their semantic role.
pub mod function_analyzer;
/// Identifier and table-name normalization helpers (schema-qualified names, quoted identifiers).
pub mod names;
/// Thin wrapper around `sql-traits` for schema parsing.
pub mod sql_parser;
