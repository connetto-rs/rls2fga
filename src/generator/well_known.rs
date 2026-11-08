//! Type and relation names the generator reserves. The DSL, the JSON model and the
//! tuple SQL all read them from here so they cannot drift apart.
//!
//! A reserved relation is a function rather than a constant because
//! [`crate::types::RelationName`] is owned and an owned value cannot be a
//! `const`. That is the point: the names the generator uses most are relation names by
//! construction, so none of them can be handed to a place wanting a column or a type.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use crate::types::{RelationName, RolePrivilege, TypeName, TypeNameError};

/// Default subject type for a database user.
pub const USER_TYPE: &str = "user";

/// Default subject type for a team, minted by role threshold translation.
pub const TEAM_TYPE: &str = "team";

/// Default subject type for a `PostgreSQL` role named in a policy's `TO` clause.
pub const PG_ROLE_TYPE: &str = "pg_role";

/// Default subject type of the denial, which nothing is.
pub const NOBODY_TYPE: &str = "nobody";

/// Default type standing for the set of roles one policy's scope admits.
pub const PG_ROLE_SCOPE_TYPE: &str = "pg_role_scope";

/// Default type holding the gates that read only the request, one object per guarded
/// type.
pub const REQUEST_GATE_TYPE: &str = "request_gate";

/// Caller-chosen type names the generator treats as its own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WellKnownTypes {
    pub(crate) user: TypeName,
    pub(crate) team: TypeName,
    pub(crate) pg_role: TypeName,
    pub(crate) pg_role_scope: TypeName,
    pub(crate) request_gate: TypeName,
    pub(crate) nobody: TypeName,
}

impl WellKnownTypes {
    /// Validate the six configured type names and their shared namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when a name is invalid or two settings use one name.
    pub fn new(
        user: impl Into<String>,
        team: impl Into<String>,
        pg_role: impl Into<String>,
        pg_role_scope: impl Into<String>,
        request_gate: impl Into<String>,
        nobody: impl Into<String>,
    ) -> Result<Self, WellKnownTypesError> {
        let parse = |setting, name| {
            TypeName::try_from(name)
                .map_err(|source| WellKnownTypesError::InvalidTypeName { setting, source })
        };
        let names = Self {
            user: parse("user", user.into())?,
            team: parse("team", team.into())?,
            pg_role: parse("pg_role", pg_role.into())?,
            pg_role_scope: parse("pg_role_scope", pg_role_scope.into())?,
            request_gate: parse("request_gate", request_gate.into())?,
            nobody: parse("nobody", nobody.into())?,
        };

        let reserved = names.reserved();
        for (index, (first_setting, first_name)) in reserved.iter().enumerate() {
            for (second_setting, second_name) in reserved.iter().skip(index.saturating_add(1)) {
                if first_name == second_name {
                    return Err(WellKnownTypesError::DuplicateTypeName {
                        first_setting,
                        second_setting,
                        name: (*first_name).clone(),
                    });
                }
            }
        }

        Ok(names)
    }

    /// Type of database users.
    #[must_use]
    pub fn user(&self) -> &TypeName {
        &self.user
    }

    /// Type of teams.
    #[must_use]
    pub fn team(&self) -> &TypeName {
        &self.team
    }

    /// Type of database roles.
    #[must_use]
    pub fn pg_role(&self) -> &TypeName {
        &self.pg_role
    }

    /// Type of role-scope objects.
    #[must_use]
    pub fn pg_role_scope(&self) -> &TypeName {
        &self.pg_role_scope
    }

    /// Type of the objects holding the gates that read only the request.
    #[must_use]
    pub fn request_gate(&self) -> &TypeName {
        &self.request_gate
    }

    /// Type that cannot grant any caller.
    #[must_use]
    pub fn nobody(&self) -> &TypeName {
        &self.nobody
    }

    pub(crate) fn reserved(&self) -> [(&'static str, &TypeName); 6] {
        [
            ("user", &self.user),
            ("team", &self.team),
            ("pg_role", &self.pg_role),
            ("pg_role_scope", &self.pg_role_scope),
            ("request_gate", &self.request_gate),
            ("nobody", &self.nobody),
        ]
    }
}

/// Why configured well-known type names were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WellKnownTypesError {
    /// One setting carries an invalid name.
    #[error("well-known type setting `{setting}` is invalid: {source}")]
    InvalidTypeName {
        /// Setting being configured.
        setting: &'static str,
        /// Name validation failure.
        #[source]
        source: TypeNameError,
    },
    /// Two settings carry one type name.
    #[error("well-known type settings `{first_setting}` and `{second_setting}` both use `{name}`")]
    DuplicateTypeName {
        /// First setting.
        first_setting: &'static str,
        /// Second setting.
        second_setting: &'static str,
        /// Reused name.
        name: TypeName,
    },
}

impl Default for WellKnownTypes {
    fn default() -> Self {
        Self {
            user: TypeName::canonicalized(USER_TYPE),
            team: TypeName::canonicalized(TEAM_TYPE),
            pg_role: TypeName::canonicalized(PG_ROLE_TYPE),
            pg_role_scope: TypeName::canonicalized(PG_ROLE_SCOPE_TYPE),
            request_gate: TypeName::canonicalized(REQUEST_GATE_TYPE),
            nobody: TypeName::canonicalized(NOBODY_TYPE),
        }
    }
}

/// Relation linking a guarded row to the object holding its request gates.
#[must_use]
pub fn request_gate_link_relation() -> RelationName {
    RelationName::canonicalized("request_gate")
}

/// Relation on [`PG_ROLE_SCOPE_TYPE`] holding the roles a scope admits.
#[must_use]
pub fn scope_roles_relation() -> RelationName {
    RelationName::canonicalized("roles")
}

/// Relation that grants nobody, used wherever a policy must fail closed.
#[must_use]
pub fn deny_relation() -> RelationName {
    RelationName::canonicalized("no_access")
}

/// Relation that grants everyone, used wherever a policy is unconditionally open.
#[must_use]
pub fn public_relation() -> RelationName {
    RelationName::canonicalized("public_viewer")
}

/// Condition parameter the request supplies for a guard against statement time.
///
/// A choice, not a convention `OpenFGA` imposes, so the operator has to pass it in the
/// check context under exactly this name.
pub const REQUEST_TIME_PARAMETER: &str = "request_time";

/// `OpenFGA` name for a timestamp condition parameter.
pub const TIMESTAMP_PARAMETER_TYPE: &str = "TYPE_NAME_TIMESTAMP";

/// `OpenFGA` name for a string condition parameter.
pub const STRING_PARAMETER_TYPE: &str = "TYPE_NAME_STRING";

/// `OpenFGA` name for a list condition parameter, whose element type is a generic.
pub const LIST_PARAMETER_TYPE: &str = "TYPE_NAME_LIST";

/// Relation holding the users a membership row attaches to its parent object.
#[must_use]
pub fn member_relation() -> RelationName {
    RolePrivilege::Member.relation_name()
}

/// Base name for a relation holding a blocklist's excluded callers.
#[must_use]
pub fn blocked_relation() -> RelationName {
    RelationName::canonicalized("blocked")
}

/// Alias an unnested list element takes in generated SQL.
///
/// Deliberately not `member`: it is a column alias, not the [`member_relation`],
/// and one spelling for both made the two read as related.
pub(crate) const ARRAY_ELEMENT_ALIAS: &str = "element";

/// Relation holding the owning user of a row.
#[must_use]
pub fn owner_user_relation() -> RelationName {
    RelationName::canonicalized("owner_user")
}

/// Relation holding the owning team of a row.
#[must_use]
pub fn owner_team_relation() -> RelationName {
    RelationName::canonicalized("owner_team")
}

/// Object id of every holder, since exactly one stands for each member source.
pub const HOLDER_OBJECT_ID: &str = "all";

/// Identifier standing for every subject of a type.
///
/// The crate's own spelling for "everyone", never a value out of a row, so it is
/// the one identifier the encoding leaves alone. A row whose value is literally
/// `*` still encodes, or it would grant everybody.
pub use crate::types::identity::WILDCARD_SUBJECT_ID;

/// Action relation answering for a SQL `SELECT`.
#[must_use]
pub fn can_select_relation() -> RelationName {
    RelationName::canonicalized("can_select")
}

/// Action relation answering for a SQL `INSERT`.
#[must_use]
pub fn can_insert_relation() -> RelationName {
    RelationName::canonicalized("can_insert")
}

/// Action relation answering for a SQL `UPDATE`.
#[must_use]
pub fn can_update_relation() -> RelationName {
    RelationName::canonicalized("can_update")
}

/// Action relation answering for a SQL `DELETE`.
#[must_use]
pub fn can_delete_relation() -> RelationName {
    RelationName::canonicalized("can_delete")
}

/// The `USING` half of an `UPDATE`, which picks the rows the statement may touch.
#[must_use]
pub fn can_update_using_relation() -> RelationName {
    RelationName::canonicalized("can_update_using")
}

/// The `WITH CHECK` half of an `UPDATE`, which admits the new row.
#[must_use]
pub fn can_update_check_relation() -> RelationName {
    RelationName::canonicalized("can_update_check")
}

/// The `UPDATE` `USING` half without the read gate, which is what filters an update
/// that names no row, as `UPDATE t SET c = 1` does. Where the clauses differ the check
/// half is judged beside it against the result, never fused into it.
#[must_use]
pub fn can_update_without_reading_relation() -> RelationName {
    RelationName::canonicalized("can_update_without_reading")
}

/// The `UPDATE` `WITH CHECK` half without the read gate, which judges the row an update
/// naming no row writes. Defined only where it differs from the `USING` half.
#[must_use]
pub fn can_update_without_reading_check_relation() -> RelationName {
    RelationName::canonicalized("can_update_without_reading_check")
}

/// Inserting a row and reading it back, which returning a table column or naming
/// an `ON CONFLICT` target both do, so the `SELECT` policies apply to the new row.
#[must_use]
pub fn can_insert_returning_relation() -> RelationName {
    RelationName::canonicalized("can_insert_returning")
}

/// Reading a row under a locking clause (`FOR UPDATE`, `FOR NO KEY UPDATE`,
/// `FOR SHARE`, `FOR KEY SHARE`), which `PostgreSQL` filters by the `UPDATE`
/// policies' `USING` clause on top of the `SELECT` policies.
#[must_use]
pub fn can_select_for_update_relation() -> RelationName {
    RelationName::canonicalized("can_select_for_update")
}
