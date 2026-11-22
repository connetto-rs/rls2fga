//! Tuple loader omissions.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use crate::types::{ColumnName, TableId, TypeName};
use serde::Serialize;

/// Why a tuple query was not emitted, and the two comment lines that stand in its place in
/// the loader's script.
///
/// Separate from [`TranslationNote`](crate::types::TranslationNote) because it answers a different reader: someone
/// running the SQL, who needs to know what to do about the gap in their tuple set
/// rather than what the model says.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum SkippedTuples {
    /// A hybrid policy's attribute half, which no tuple can express.
    AttributeRuntimeEnforcement {
        /// Table the policy guards.
        table: TableId,
        /// Attribute the application has to enforce itself.
        attribute: String,
    },
    /// An attribute condition the row does not decide.
    StandaloneAttribute {
        /// Table the policy guards.
        table: TableId,
        /// Column the condition tests.
        column: ColumnName,
    },
    /// An expression nobody classified.
    UnclassifiedExpression {
        /// Table the policy guards.
        table: TableId,
        /// Why the expression stayed untranslated.
        reason: String,
    },
    /// Nothing identifies a row of the table.
    NoObjectIdentifier {
        /// Table whose rows nothing names.
        table: TableId,
        /// What the missing identity would have produced.
        what: String,
        /// Which identity the generator looked for.
        reason: String,
    },
    /// Nothing identifies a row, so the parent bridge cannot be built.
    NoBridge {
        /// Table the bridge starts from.
        table: TableId,
        /// Type the bridge points at.
        parent_type: TypeName,
        /// Which identity the generator looked for.
        reason: String,
    },
    /// Neither a user nor a team table holds the principals a grant table names.
    NoPrincipalTypeForGrants {
        /// Table holding the grants.
        grant_table: TableId,
    },
    /// The column joining a row to its parent is not in the schema.
    BridgeColumnMissing {
        /// Table the bridge starts from.
        table: TableId,
        /// Type the bridge points at.
        parent_type: TypeName,
        /// Column the policy joins on, which the schema does not declare.
        fk_col: ColumnName,
    },
    /// No table holds the user principals a role-threshold grant joins to.
    NoUserPrincipalTable {
        /// Table the grants govern.
        table: TableId,
    },
    /// No table holds the team principals a role-threshold grant joins to.
    NoTeamPrincipalTable {
        /// Table the grants govern.
        table: TableId,
    },
    /// No column carries the owner value a role-threshold policy compares, so no row can
    /// point at the owner judging it.
    NoOwnerColumn {
        /// Table the policy guards.
        table: TableId,
    },
}

/// Advice printed where the tuple query would have been.
pub(crate) const MISSING_OBJECT_IDENTIFIER_SQL: &str =
    "-- Tuple query not emitted because stable object IDs need a single-column primary key or a NOT NULL UNIQUE `id` column.";

impl SkippedTuples {
    /// The comment line naming what was skipped.
    #[must_use]
    pub fn comment(&self) -> String {
        match self {
            Self::AttributeRuntimeEnforcement { table, attribute } => format!(
                "-- TODO [Level C]: attribute condition '{attribute}' on {table} requires runtime enforcement"
            ),
            Self::StandaloneAttribute { table, .. } => format!(
                "-- TODO [Level D]: skipped tuple generation for {table} (unsupported pattern P9)"
            ),
            Self::UnclassifiedExpression { table, .. } => format!(
                "-- TODO [Level D]: skipped tuple generation for {table} (unsupported pattern Unknown)"
            ),
            Self::NoObjectIdentifier {
                table,
                what,
                reason,
            } => format!("-- TODO [Level D]: skipped {what} for {table} ({reason})"),
            Self::NoBridge {
                table,
                parent_type,
                reason,
            } => format!("-- TODO [Level D]: skipped {table} to {parent_type} bridge ({reason})"),
            Self::NoPrincipalTypeForGrants { grant_table } => format!(
                "-- TODO [Level C]: ExplicitGrants on '{grant_table}' could not resolve \
                 principal type (no user or team table identified). \
                 Review the grant table schema and register the principal tables."
            ),
            Self::BridgeColumnMissing {
                table,
                parent_type,
                fk_col,
            } => format!(
                "-- TODO [Level D]: skipped {table} to {parent_type} bridge \
                 (missing column '{fk_col}')"
            ),
            Self::NoUserPrincipalTable { table } => format!(
                "-- TODO [Level D]: skipped user ownership tuples for {table} (unresolved user principal table)"
            ),
            Self::NoTeamPrincipalTable { table } => format!(
                "-- TODO [Level D]: skipped team ownership tuples for {table} (unresolved team principal table)"
            ),
            Self::NoOwnerColumn { table } => format!(
                "-- TODO [Level D]: skipped the owner pointer for {table} (no column carries \
                 the owner the policy compares)"
            ),
        }
    }

    /// The body line saying what to do about it.
    #[must_use]
    pub fn body(&self) -> String {
        match self {
            Self::AttributeRuntimeEnforcement { attribute, .. } => format!(
                "-- No tuple can express the attribute filter '{attribute}', so application logic must enforce it."
            ),
            Self::StandaloneAttribute { column, .. } => format!(
                "-- Tuple query not emitted because attribute condition on '{column}' is not decided by the row, so no static tuple mapping exists."
            ),
            Self::UnclassifiedExpression { reason, .. } => format!(
                "-- Tuple query not emitted because classifier could not translate expression: {reason}."
            ),
            Self::NoObjectIdentifier { .. } => MISSING_OBJECT_IDENTIFIER_SQL.to_string(),
            Self::NoBridge { .. } | Self::BridgeColumnMissing { .. } => {
                "-- Bridge tuple not emitted because schema/FK mapping needs review.".to_string()
            }
            Self::NoPrincipalTypeForGrants { grant_table } => {
                format!("-- Unresolved: SELECT ... FROM {grant_table} og ...;")
            }
            Self::NoUserPrincipalTable { .. } => {
                "-- User ownership tuples not emitted because no role_threshold.user_table metadata or users table is present.".to_string()
            }
            Self::NoTeamPrincipalTable { .. } => {
                "-- Team ownership tuples not emitted because no role_threshold.team_table metadata or teams table is present.".to_string()
            }
            Self::NoOwnerColumn { .. } => {
                "-- Ownership tuples not emitted because owner mapping needs review.".to_string()
            }
        }
    }
}
