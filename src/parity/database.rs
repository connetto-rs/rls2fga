//! The row source a case's model is loaded from and its probes are named by.

use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec::Vec,
};
use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use diesel::{
    connection::SimpleConnection,
    pg::PgConnection,
    prelude::*,
    result::Error as DieselError,
    sql_types::{Jsonb, Text},
};
use serde_json::Value;
use sql_traits::parity::{identifier, Case};
use sqlparser::{ast::Statement, dialect::PostgreSqlDialect, parser::Parser};

use super::ParityError;

/// One row as `to_jsonb` prints it.
#[derive(QueryableByName)]
pub(super) struct JsonbRow {
    #[diesel(sql_type = Jsonb)]
    pub(super) row: Value,
}

diesel::table! {
    pg_roles (rolname) {
        rolname -> Text,
    }
}

#[diesel::declare_sql_function]
extern "SQL" {
    fn current_setting(name: Text) -> Text;
}

/// A fresh PostgreSQL 18 database holding one case's roles, `schema.sql` and `seed.sql`,
/// dropped with its roles on [`Database::cleanup`] or on drop.
pub struct Database {
    admin: PgConnection,
    connection: PgConnection,
    cleanup_sql: Vec<String>,
}

impl Database {
    /// Create an isolated database on the cluster `url` names and apply the case's
    /// schema and seed as the table owner.
    ///
    /// # Errors
    ///
    /// Returns a [`ParityError`] when the cluster is not PostgreSQL 18, already holds one of
    /// the case's roles, or refuses the schema or the seed.
    pub fn create(url: &str, case: &Case) -> Result<Self, ParityError> {
        let mut database_url = url::Url::parse(url)?;
        database_url
            .query_pairs_mut()
            .append_pair("connect_timeout", "10");
        let mut admin = PgConnection::establish(database_url.as_str())?;
        admin.batch_execute("SET statement_timeout = '30s'; SET lock_timeout = '5s'")?;
        let version: String =
            diesel::select(current_setting("server_version_num")).get_result(&mut admin)?;
        if version.parse::<u32>().ok().map(|number| number / 10_000) != Some(18) {
            return Err(ParityError::Version(version));
        }
        let mut roles = Vec::new();
        for statement in
            Parser::parse_sql(&PostgreSqlDialect {}, &case.schema).map_err(ParityError::Roles)?
        {
            if let Statement::CreateRole(role) = statement {
                roles.extend(
                    role.names
                        .into_iter()
                        .map(|name| name.to_string().trim_matches('"').to_owned()),
                );
            }
        }
        let occupied = pg_roles::table
            .filter(pg_roles::rolname.eq_any(&roles))
            .count()
            .get_result::<i64>(&mut admin)?;
        if occupied != 0 {
            return Err(ParityError::RolesExist);
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let name = format!("rlspar_{}_{nonce}", std::process::id());
        admin.batch_execute(&format!("CREATE DATABASE {}", identifier(&name)))?;
        database_url.set_path(&format!("/{name}"));
        let connection = match PgConnection::establish(database_url.as_str()) {
            Ok(connection) => connection,
            Err(error) => {
                admin
                    .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", identifier(&name)))?;
                return Err(error.into());
            }
        };
        let mut cleanup_sql = Vec::from([format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            identifier(&name)
        )]);
        cleanup_sql.extend(
            roles
                .iter()
                .map(|role| format!("DROP ROLE IF EXISTS {}", identifier(role))),
        );
        let mut database = Self {
            admin,
            connection,
            cleanup_sql,
        };
        database.connection.batch_execute(
            "SET statement_timeout = '30s'; SET lock_timeout = '5s'; SET TIME ZONE 'UTC'; \
             SET DateStyle = 'ISO, MDY'; SET bytea_output = 'hex'",
        )?;
        database
            .connection
            .batch_execute(&case.schema)
            .map_err(ParityError::Schema)?;
        database
            .connection
            .batch_execute(&case.seed)
            .map_err(ParityError::Seed)?;
        Ok(database)
    }

    /// The connection to the case's database, logged in as the table owner.
    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.connection
    }

    /// Read every row of `table`, spelled as SQL, as the owner without policy filtering.
    ///
    /// # Errors
    ///
    /// Returns the database's error when the read fails.
    pub fn rows(&mut self, table: &str) -> Result<Vec<Value>, DieselError> {
        // The case names the table at runtime, so no `table!` schema exists for it.
        Ok(
            diesel::sql_query(format!("SELECT to_jsonb(t) AS row FROM {table} t"))
                .load::<JsonbRow>(&mut self.connection)?
                .into_iter()
                .map(|row| row.row)
                .collect(),
        )
    }

    /// The row the table owner's `statement` returns, rolled back.
    ///
    /// # Errors
    ///
    /// Returns [`ParityError::Resulting`] when the statement fails.
    pub fn resulting(&mut self, statement: &str) -> Result<Option<Value>, ParityError> {
        self.connection.batch_execute("BEGIN")?;
        // The case's write is runtime fixture data.
        let rows = diesel::sql_query(statement).load::<JsonbRow>(&mut self.connection);
        self.connection.batch_execute("ROLLBACK")?;
        Ok(rows
            .map_err(|source| ParityError::Resulting {
                statement: statement.to_owned(),
                source,
            })?
            .into_iter()
            .next()
            .map(|row| row.row))
    }

    /// Remove only the database and roles created by this case.
    ///
    /// # Errors
    ///
    /// Returns the database's error when a drop fails, leaving the rest to the next call.
    pub fn cleanup(&mut self) -> Result<(), DieselError> {
        while let Some(statement) = self.cleanup_sql.first() {
            self.admin.batch_execute(statement)?;
            self.cleanup_sql.remove(0);
        }
        Ok(())
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            let _ = writeln!(std::io::stderr(), "Database cleanup failed {error}");
        }
    }
}
