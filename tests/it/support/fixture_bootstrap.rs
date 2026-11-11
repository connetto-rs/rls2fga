//! External roles and schemas required by the fixture corpus.

use core::fmt::Write;
use diesel::{connection::SimpleConnection, PgConnection};

use super::deployment;

const AUTH_SCHEMA: &str = "CREATE SCHEMA IF NOT EXISTS auth;\n";
const FIXTURE_ROLES: [(&str, Option<&str>); 5] = [
    ("auditor", Some("schema_objects")),
    ("contractor", None),
    ("editors", None),
    ("app", None),
    ("editor", Some("pg_role_gate")),
];

/// Declare the deployment roles and fixture prerequisites in a fresh catalog.
pub(crate) fn declarations(fixture: &str) -> String {
    let mut declarations = deployment::ROLES.to_string();
    declarations.push_str(AUTH_SCHEMA);
    for (role, creator) in FIXTURE_ROLES {
        if creator != Some(fixture) {
            let _ = writeln!(declarations, "CREATE ROLE {role};");
        }
    }
    declarations
}

/// Prepare fixture prerequisites in a new database of a cluster holding the deployment roles.
pub(crate) fn prepare(connection: &mut PgConnection, fixture: &str) {
    for (role, creator) in FIXTURE_ROLES {
        let statement = if creator == Some(fixture) {
            format!("DROP ROLE IF EXISTS {role}")
        } else {
            format!(
                "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = \
                 '{role}') THEN CREATE ROLE {role}; END IF; END $$"
            )
        };
        connection
            .batch_execute(&statement)
            .expect("Failed to prepare a fixture role");
    }
    connection
        .batch_execute(AUTH_SCHEMA)
        .expect("Failed to create the auth schema");
    connection
        .batch_execute(deployment::DEFAULT_PRIVILEGES)
        .expect("Failed to grant the default table privileges");
}
