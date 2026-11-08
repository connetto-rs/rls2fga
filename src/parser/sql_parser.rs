pub use sql_traits::prelude::*;
use sqlparser::dialect::PostgreSqlDialect;

/// Why a SQL schema could not be turned into a [`ParserDB`].
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// The schema is invalid or references something it does not define.
    #[error("{0}")]
    Schema(#[from] sql_traits::errors::Error),
}

/// Parse SQL DDL into a [`ParserDB`].
///
/// References to objects the input never creates are read under
/// [`AccessResolution::OpenWorld`]. rls2fga models policies rather than
/// privileges, and roles are cluster objects a schema dump does not emit, so a
/// grant or a policy naming one must not refuse the schema.
///
/// # Errors
///
/// Returns [`SchemaError::Schema`] when the schema does not parse, and when it
/// describes something `PostgreSQL` would refuse: a foreign key whose target
/// table, target column or unique constraint is absent, or a policy on a table
/// the search path does not reach. Those refusals are what keeps the rest of the
/// pipeline total, since it resolves references eagerly.
pub fn parse_schema(sql: &str) -> Result<ParserDB, SchemaError> {
    Ok(schema_options().parse::<PostgreSqlDialect>(sql)?)
}

/// [`parse_schema`] for a schema created in a session whose `TimeZone` is `zone`.
///
/// `PostgreSQL` stores a policy's `timestamptz` literal as the instant it reads in the
/// creating session's `TimeZone`, so `'2026-01-01 12:00'` is 11:00 UTC when the
/// migration ran in `Europe/Rome`. A `SET TIME ZONE` in the script still takes over from
/// that statement on. [`parse_schema`] knows no zone, so such a literal before any
/// `SET TIME ZONE` has no value and its policy falls closed.
///
/// # Errors
///
/// Returns [`SchemaError::Schema`] for everything [`parse_schema`] refuses, and when
/// `zone` is not a time zone `PostgreSQL` accepts.
pub fn parse_schema_in_time_zone(sql: &str, zone: &str) -> Result<ParserDB, SchemaError> {
    Ok(schema_options()
        .with_session_time_zone(zone)?
        .parse::<PostgreSqlDialect>(sql)?)
}

fn schema_options() -> ParseOptions {
    ParseOptions::default().with_access_resolution(AccessResolution::OpenWorld)
}
