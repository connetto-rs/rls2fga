//! What a translation reports about itself.
//!
//! Every note is a typed cause. Its sentence is rendered here and never stored beside
//! it, so a note cannot say one thing while its kind says another, and
//! [`NoteSeverity`] answers the question a caller actually has: whether anything went
//! unhandled, whether their own threshold dropped it, or whether the model simply says
//! what the database says.

use crate::prelude::*;
use crate::{ColumnName, RelationName, TableId, TypeName};
use crate::{ConfidenceLevel, RolePrivilege};
use alloc::borrow::Cow;
use core::fmt;
use serde::{Deserialize, Serialize};

/// String serialization for one table identity.
mod table_id_as_str {
    use super::TableId;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &TableId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use alloc::string::ToString;
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<TableId, D::Error> {
        use serde::de::{Deserialize, Error};
        let s = alloc::string::String::deserialize(deserializer)?;
        super::parse_table_id_str(&s).map_err(D::Error::custom)
    }
}

/// String serialization for table identities.
mod table_id_vec_as_str {
    use super::TableId;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        values: &[TableId],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use alloc::string::ToString;
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for v in values {
            seq.serialize_element(&v.to_string())?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<alloc::vec::Vec<TableId>, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = alloc::vec::Vec<TableId>;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a sequence of table identifier strings")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = alloc::vec::Vec::new();
                while let Some(s) = seq.next_element::<alloc::string::String>()? {
                    out.push(super::parse_table_id_str(&s).map_err(A::Error::custom)?);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_seq(V)
    }
}

#[derive(Debug, thiserror::Error)]
enum TableIdParseError {
    #[error("empty table id component")]
    EmptyComponent,
    #[error("invalid table id slice in {input:?}")]
    InvalidSlice { input: String },
    #[error("trailing content after table id {input:?}")]
    TrailingContent { input: String },
    #[error("unexpected byte {byte:#04x} at position {position} in table id {input:?}")]
    UnexpectedByte {
        byte: u8,
        position: usize,
        input: String,
    },
    #[error("unterminated quoted identifier at {start}")]
    UnterminatedQuote { start: usize },
    #[error("malformed quoted identifier: {input:?}")]
    MalformedQuote { input: String },
}

fn parse_table_id_str(s: &str) -> Result<TableId, TableIdParseError> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let first_end = scan_part(bytes, &mut i)?;
    let first = s
        .get(..first_end)
        .ok_or_else(|| TableIdParseError::InvalidSlice {
            input: s.to_string(),
        })?;
    match bytes.get(i).copied() {
        Some(b'.') => {
            i += 1;
            let second_start = i;
            let second_end = scan_part(bytes, &mut i)?;
            if i != bytes.len() {
                return Err(TableIdParseError::TrailingContent {
                    input: s.to_string(),
                });
            }
            let name_part =
                s.get(second_start..second_end)
                    .ok_or_else(|| TableIdParseError::InvalidSlice {
                        input: s.to_string(),
                    })?;
            let schema = unescape_part(first)?;
            let name = unescape_part(name_part)?;
            Ok(TableId::from_stored(Some(schema), name))
        }
        None => {
            let name = unescape_part(first)?;
            Ok(TableId::from_stored(None, name))
        }
        Some(byte) => Err(TableIdParseError::UnexpectedByte {
            byte,
            position: i,
            input: s.to_string(),
        }),
    }
}

fn scan_part(bytes: &[u8], i: &mut usize) -> Result<usize, TableIdParseError> {
    match bytes.get(*i).copied() {
        None => Err(TableIdParseError::EmptyComponent),
        Some(b'"') => {
            let start = *i;
            *i += 1;
            loop {
                match bytes.get(*i).copied() {
                    None => return Err(TableIdParseError::UnterminatedQuote { start }),
                    Some(b'"') => {
                        *i += 1;
                        if bytes.get(*i).copied() == Some(b'"') {
                            *i += 1;
                        } else {
                            break;
                        }
                    }
                    Some(_) => *i += 1,
                }
            }
            Ok(*i)
        }
        Some(_) => {
            let start = *i;
            while matches!(bytes.get(*i).copied(), Some(b) if b != b'.') {
                *i += 1;
            }
            if *i == start {
                Err(TableIdParseError::EmptyComponent)
            } else {
                Ok(*i)
            }
        }
    }
}

fn unescape_part(s: &str) -> Result<String, TableIdParseError> {
    if let Some(inner) = s.strip_prefix('"') {
        let inner = inner
            .strip_suffix('"')
            .ok_or_else(|| TableIdParseError::MalformedQuote {
                input: s.to_string(),
            })?;
        Ok(inner.replace("\"\"", "\""))
    } else {
        Ok(String::from(s))
    }
}

/// How a note bears on what the model says compared with the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NoteSeverity {
    /// Nothing is missing. The model says what the database says.
    Faithful,
    /// The model is complete, but the operator has to supply or confirm something.
    ActionRequired,
    /// Translated in part, with the rest left to the caller to enforce.
    Partial,
    /// A clause the caller's own confidence threshold removed.
    BelowThreshold,
    /// A principal the database exempts from row level security entirely, so the model
    /// describes rules that do not reach them.
    Exempt,
    /// An expression nobody classified, so the model denies what the database may grant.
    Unhandled,
}

impl fmt::Display for NoteSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Faithful => "Faithful",
            Self::ActionRequired => "Action required",
            Self::Partial => "Partial",
            Self::BelowThreshold => "Below threshold",
            Self::Exempt => "Exempt",
            Self::Unhandled => "Unhandled",
        })
    }
}

impl NoteSeverity {
    /// Whether the model disagrees with the database about what the rules grant.
    ///
    /// [`NoteSeverity::Exempt`] is not a disagreement: the policies genuinely do not
    /// govern that principal, so the model is not wrong about them, it is saying the
    /// rules do not reach there. That belongs in the report rather than above the
    /// outputs beside a refused clause.
    ///
    /// Written as a refusal rather than a list, so a severity added later counts as a
    /// disagreement until someone decides otherwise.
    #[must_use]
    pub fn diverges_from_database(self) -> bool {
        !matches!(self, Self::Faithful | Self::ActionRequired | Self::Exempt)
    }
}

/// One thing a translation has to tell its caller about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TranslationNote {
    /// A function running as its owner cannot identify the caller.
    OwnerBoundFunction {
        /// Function the policies call.
        function: String,
    },
    /// A policy names something that is not one table in the schema.
    UnresolvedPolicyTable {
        /// Policy naming it.
        policy: String,
        /// The name as the policy spelled it.
        named: String,
    },
    /// A RESTRICTIVE clause guards on an attribute no relation can express.
    RestrictiveAttributeRefused {
        /// Policy carrying the clause.
        policy: String,
    },
    /// A barrier bound to roles binds everyone, since nothing can say who is bound.
    RestrictiveBarrierBindsEveryone {
        /// Policy carrying the barrier.
        policy: String,
        /// Roles it named.
        roles: Vec<String>,
    },
    /// Reading a table expands its policies, and a loop there raises `infinite
    /// recursion` rather than filtering.
    PolicyReadRecursion {
        /// Table whose commands the loop denies.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Commands it denies.
        commands: Vec<String>,
        /// Tables the loop runs through, in order.
        cycle: Vec<String>,
    },
    /// No permissive policy covers these commands, so the database denies them too.
    NoPermissivePolicy {
        /// Table with no covering policy.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Commands nothing covers.
        commands: Vec<String>,
    },
    /// Every policy covering these commands fell below the caller's threshold.
    CoveringPoliciesBelowThreshold {
        /// Table whose policies were dropped.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Commands left uncovered by the drop.
        commands: Vec<String>,
    },
    /// A clause the caller's own threshold dropped, naming what it cost.
    ///
    /// The machine readable channel for a threshold drop, in either mode. The report
    /// says the same thing in prose, and a program can only read it here.
    ClauseBelowThreshold {
        /// Table the policy guards.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Policy carrying the clause.
        policy: String,
        /// `PERMISSIVE` or `RESTRICTIVE`.
        mode: String,
        /// `USING` or `WITH CHECK`.
        clause: String,
        /// Grade the clause held when it was dropped.
        confidence: ConfidenceLevel,
        /// Commands the clause fed.
        commands: Vec<String>,
        /// Action relations it directly diverged from the database.
        relations: Vec<RelationName>,
    },
    /// A policy names a command without the clause that command needs.
    PolicyClauseAbsent {
        /// Policy missing the clause.
        policy: String,
        /// Commands it names.
        commands: String,
        /// Clause it does not store.
        clause: String,
    },
    /// The `TO` clause names a spelling `PostgreSQL` resolves when the policy is created.
    PolicyBoundToDdlTimeRole {
        /// Policy carrying the clause.
        policy: String,
        /// The spellings, as written.
        spellings: Vec<String>,
    },
    /// The policy stores a clause `PostgreSQL` refuses for its command.
    PolicyClauseIllegal {
        /// Policy carrying the clause.
        policy: String,
        /// `PostgreSQL`'s own refusal.
        rule: String,
    },
    /// Reads are denied, so these commands cannot name a row to change.
    ReadsDeniedSoWritesCannotName {
        /// Table whose reads are denied.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Commands a policy covers that the read gate closes anyway.
        commands: Vec<String>,
    },
    /// A policy's `TO` clause became a role scope relation.
    PolicyRoleScope {
        /// Policy carrying the clause.
        policy: String,
        /// Roles it names.
        roles: Vec<String>,
        /// Relation the scope became.
        relation: RelationName,
    },
    /// A role test in the expression became a role scope relation.
    RoleGateScope {
        /// Policy carrying the test.
        policy: String,
        /// Roles it admits.
        roles: Vec<String>,
        /// Relation the gate became.
        relation: RelationName,
        /// Relation on `pg_role` holding the kind of membership the policy asked about.
        held_by: String,
    },
    /// Reading the membership table needs a role, so the grant is scoped to it.
    MembershipReadScope {
        /// Policy holding the membership check.
        policy: String,
        /// Membership table only those roles may read.
        #[serde(with = "table_id_as_str")]
        join_table: TableId,
        /// Roles that may read it.
        roles: Vec<String>,
        /// Relation the scope became.
        relation: RelationName,
    },
    /// Two table spellings canonicalize to one type name.
    TypeNameCollision {
        /// Table whose type was renamed.
        #[serde(with = "table_id_as_str")]
        spelling: TableId,
        /// Table already holding the name.
        #[serde(with = "table_id_as_str")]
        prior: TableId,
        /// Name they both wanted.
        canonical: String,
        /// Name this one got instead.
        renamed: String,
    },
    /// The table has `INHERITS` children, so its tuple queries read `FROM ONLY` and
    /// child rows carry no tuples on this type.
    InheritanceParentReadsOwnRowsOnly {
        /// Inheritance parent whose type this is.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Its direct children, whose rows fall closed on this type.
        #[serde(with = "table_id_vec_as_str")]
        children: Vec<TableId>,
    },
    /// No single column names a row of the table, so every tuple query keyed on one is
    /// missing and each grant the model would carry falls closed.
    RowsCannotBeNamed {
        /// Table whose rows nothing can name.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Why no single column identifies a row.
        reason: String,
        /// The tuple queries left unemitted, as the loader's script names them.
        sources: Vec<String>,
    },
    /// The column linking a row to its parent object is not in the schema, so the bridge
    /// carrying the grant cannot be written and the grant falls closed.
    BridgeColumnMissing {
        /// Table the bridge would have read.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Type the bridge would have pointed at.
        parent_type: TypeName,
        /// Column the bridge would have read, absent from `table`.
        column: ColumnName,
    },
    /// The target caps an identifier, and this table's key can render a longer one, so
    /// a row past the cap emits no fact and the model denies it.
    ///
    /// Stated as a contract rather than a list: the translator never sees the data, so
    /// it can give the operator the exact number but not the rows. Only tables whose key
    /// type could reach the cap get this, so a `uuid` or integer key is silent.
    RowIdentifierBudget {
        /// Table whose key could render too long a name.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Characters the key may render, once encoded, before the row is left out.
        budget: usize,
    },
    /// A condition parameter the caller has to put in every check context.
    ///
    /// The model is complete without it, but a check that omits the key is refused by
    /// the service outright rather than denied, so the contract is part of using the
    /// model at all.
    CallerSuppliesConditionParameter {
        /// Parameter name every check context must use.
        parameter: String,
        /// The session setting it mirrors, when it mirrors one.
        setting_key: Option<String>,
        /// Separator the policy splits that setting on, for a list parameter.
        separator: Option<String>,
    },
    /// The membership table grants no reads, so no membership row is visible.
    MembershipTableGrantsNoReads {
        /// Policy holding the membership check.
        policy: String,
        /// Membership table nobody may read.
        #[serde(with = "table_id_as_str")]
        join_table: TableId,
    },
    /// Row level security on the membership table hides rows no relation can hide.
    MembershipTableGuarded {
        /// Policy holding the membership check.
        policy: String,
        /// Guarded membership table.
        #[serde(with = "table_id_as_str")]
        join_table: TableId,
    },
    /// A policy call was replaced by the named function's body.
    FunctionExpanded {
        /// Policy whose clause called the function.
        policy: String,
        /// The expanded function.
        function: String,
    },
    /// The membership check carries a predicate beyond the join.
    MembershipExtraPredicate {
        /// Policy holding the check.
        policy: String,
        /// The extra predicate, as written.
        predicate: String,
    },
    /// A residual the row does not decide was translated because every relation it reads
    /// shows every row to everybody, which the schema as translated is the proof of.
    MembershipResidualReadsUnrestrictedTables {
        /// Policy holding the check.
        policy: String,
        /// The residual, its relations spelled as the catalog carries them.
        predicate: String,
        /// The relations the proof rests on.
        #[serde(with = "table_id_vec_as_str")]
        tables: Vec<TableId>,
    },
    /// A nullable boolean predicate grants NULL rows that the generated tuples omit.
    NullableBooleanFlagNarrowed {
        /// Policy carrying `IS NOT FALSE`.
        policy: String,
        /// Nullable column whose NULL rows fall closed.
        column: ColumnName,
    },
    /// The parent-side rule could not be translated.
    ParentRuleUntranslated {
        /// Policy inheriting from the parent.
        policy: String,
        /// Parent table.
        #[serde(with = "table_id_as_str")]
        parent_table: TableId,
    },
    /// The attribute half of a hybrid policy is the caller's to enforce.
    AttributeNeedsRuntimeEnforcement {
        /// Policy carrying the hybrid clause.
        policy: String,
        /// Attribute condition left to the caller.
        attribute: String,
    },
    /// An attribute policy standing alone is not decided by the row.
    StandaloneAttributePolicy {
        /// Policy carrying the condition.
        policy: String,
        /// Column it guards on.
        column: ColumnName,
    },
    /// An expression nobody classified.
    ExpressionRefused {
        /// Policy carrying the expression.
        policy: String,
        /// Why it was refused.
        reason: String,
    },
    /// A role-threshold function the registry says nothing about.
    FunctionMissingMetadata {
        /// Policy calling it.
        policy: String,
        /// What kind of call it is, as the caller describes it.
        function_kind: String,
        /// Function called.
        function: String,
    },
    /// A role the database exempts from row level security everywhere.
    RoleBypassesPolicies {
        /// Role carrying `BYPASSRLS`.
        role: String,
    },
    /// A partition whose rows a direct read leaves unfiltered.
    ///
    /// `PostgreSQL` applies a parent's policies to rows reached through the parent, so a
    /// partition queried by name is filtered by its own policies alone, and a partition of
    /// a protected root has none. The model answers for the row, so it answers for the read
    /// through the root and not for this one.
    PartitionReadDirectlyIsUnfiltered {
        /// Partition a reader can name.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Root carrying the policies that a read through it applies.
        #[serde(with = "table_id_as_str")]
        root: TableId,
    },
    /// A table whose owner is exempt from its own policies, which is the default.
    TableOwnerBypassesPolicies {
        /// Table that does not force row level security on its owner.
        #[serde(with = "table_id_as_str")]
        table: TableId,
        /// Role that owns it, where the schema says so. A schema that never assigns
        /// ownership records none, and the note then cannot name the exempt principal.
        owner: Option<String>,
    },
}

impl TranslationNote {
    /// How this note bears on what the model says compared with the database.
    #[must_use]
    pub fn severity(&self) -> NoteSeverity {
        match self {
            Self::OwnerBoundFunction { .. }
            | Self::UnresolvedPolicyTable { .. }
            | Self::RestrictiveAttributeRefused { .. }
            | Self::RestrictiveBarrierBindsEveryone { .. }
            | Self::ParentRuleUntranslated { .. }
            | Self::StandaloneAttributePolicy { .. }
            | Self::ExpressionRefused { .. }
            | Self::FunctionMissingMetadata { .. }
            | Self::RowsCannotBeNamed { .. }
            | Self::BridgeColumnMissing { .. }
            | Self::PolicyBoundToDdlTimeRole { .. } => NoteSeverity::Unhandled,
            Self::RoleBypassesPolicies { .. }
            | Self::TableOwnerBypassesPolicies { .. }
            | Self::PartitionReadDirectlyIsUnfiltered { .. } => NoteSeverity::Exempt,
            Self::CoveringPoliciesBelowThreshold { .. } | Self::ClauseBelowThreshold { .. } => {
                NoteSeverity::BelowThreshold
            }
            Self::MembershipTableGuarded { .. }
            | Self::NullableBooleanFlagNarrowed { .. }
            | Self::AttributeNeedsRuntimeEnforcement { .. }
            | Self::InheritanceParentReadsOwnRowsOnly { .. } => NoteSeverity::Partial,
            Self::ReadsDeniedSoWritesCannotName { .. }
            | Self::PolicyRoleScope { .. }
            | Self::RoleGateScope { .. }
            | Self::CallerSuppliesConditionParameter { .. }
            | Self::RowIdentifierBudget { .. }
            | Self::MembershipReadScope { .. }
            | Self::TypeNameCollision { .. }
            | Self::PolicyClauseIllegal { .. } => NoteSeverity::ActionRequired,
            Self::PolicyReadRecursion { .. }
            | Self::NoPermissivePolicy { .. }
            | Self::PolicyClauseAbsent { .. }
            | Self::MembershipTableGrantsNoReads { .. }
            | Self::FunctionExpanded { .. }
            | Self::MembershipExtraPredicate { .. }
            | Self::MembershipResidualReadsUnrestrictedTables { .. } => NoteSeverity::Faithful,
        }
    }

    /// The policy, table or function the note is about.
    #[must_use]
    pub fn subject(&self) -> Cow<'_, str> {
        match self {
            Self::OwnerBoundFunction { function } => Cow::Borrowed(function),
            Self::CallerSuppliesConditionParameter { parameter, .. } => Cow::Borrowed(parameter),
            Self::TypeNameCollision { spelling, .. }
            | Self::PolicyReadRecursion {
                table: spelling, ..
            }
            | Self::NoPermissivePolicy {
                table: spelling, ..
            }
            | Self::CoveringPoliciesBelowThreshold {
                table: spelling, ..
            }
            | Self::TableOwnerBypassesPolicies {
                table: spelling, ..
            }
            | Self::PartitionReadDirectlyIsUnfiltered {
                table: spelling, ..
            }
            | Self::InheritanceParentReadsOwnRowsOnly {
                table: spelling, ..
            }
            | Self::RowsCannotBeNamed {
                table: spelling, ..
            }
            | Self::BridgeColumnMissing {
                table: spelling, ..
            }
            | Self::RowIdentifierBudget {
                table: spelling, ..
            }
            | Self::ReadsDeniedSoWritesCannotName {
                table: spelling, ..
            } => Cow::Owned(spelling.to_string()),
            Self::RoleBypassesPolicies { role } => Cow::Borrowed(role),
            Self::ClauseBelowThreshold { policy, .. }
            | Self::UnresolvedPolicyTable { policy, .. }
            | Self::RestrictiveAttributeRefused { policy }
            | Self::RestrictiveBarrierBindsEveryone { policy, .. }
            | Self::PolicyClauseAbsent { policy, .. }
            | Self::PolicyBoundToDdlTimeRole { policy, .. }
            | Self::PolicyClauseIllegal { policy, .. }
            | Self::PolicyRoleScope { policy, .. }
            | Self::RoleGateScope { policy, .. }
            | Self::MembershipReadScope { policy, .. }
            | Self::MembershipTableGrantsNoReads { policy, .. }
            | Self::FunctionExpanded { policy, .. }
            | Self::MembershipTableGuarded { policy, .. }
            | Self::MembershipExtraPredicate { policy, .. }
            | Self::MembershipResidualReadsUnrestrictedTables { policy, .. }
            | Self::NullableBooleanFlagNarrowed { policy, .. }
            | Self::ParentRuleUntranslated { policy, .. }
            | Self::AttributeNeedsRuntimeEnforcement { policy, .. }
            | Self::StandaloneAttributePolicy { policy, .. }
            | Self::ExpressionRefused { policy, .. }
            | Self::FunctionMissingMetadata { policy, .. } => Cow::Borrowed(policy),
        }
    }

    /// The sentence this note renders to.
    #[must_use]
    pub fn message(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for TranslationNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerBoundFunction { function } => write!(
                f,
                "Function '{function}' runs as its owner, so current_user names the owner for \
                 every caller and policies calling it are dropped"
            ),
            Self::CallerSuppliesConditionParameter {
                parameter,
                setting_key,
                separator,
            } => {
                write!(
                    f,
                    "Every check context must carry '{parameter}'. Omitting it makes the \
                     service refuse the check outright, where PostgreSQL would have hidden \
                     the row"
                )?;
                match (setting_key, separator) {
                    (Some(key), Some(separator)) => write!(
                        f,
                        ", so send exactly the elements string_to_array({key}, '{separator}') \
                         would produce, and an empty list where {key} is unset. Sending your \
                         own list instead grants a value holding '{separator}', which \
                         PostgreSQL cannot represent in {key} and therefore refuses"
                    ),
                    (Some(key), None) => write!(
                        f,
                        ", so send the value of {key} exactly as PostgreSQL renders it, and \
                         an empty string where {key} is unset"
                    ),
                    _ => write!(f, ""),
                }
            }
            Self::UnresolvedPolicyTable { policy, named } => write!(
                f,
                "Policy '{policy}' names '{named}', which does not resolve to one table in the \
                 schema, so qualify it with a schema to have the policy translated"
            ),
            Self::RestrictiveBarrierBindsEveryone { policy, roles } => write!(
                f,
                "RESTRICTIVE policy '{policy}' binds only {}, but no tuple can name a row of \
                 this table, so nothing can say who is bound and the barrier is applied to \
                 everyone. That denies more than RLS does",
                roles.join(", ")
            ),
            Self::RestrictiveAttributeRefused { policy } => write!(
                f,
                "RESTRICTIVE policy '{policy}' guards on an attribute the model cannot express, \
                 so the command is denied"
            ),
            Self::PolicyReadRecursion {
                table,
                commands,
                cycle,
            } => write!(
                f,
                "PostgreSQL raises infinite recursion on {} of '{table}', since the policies it \
                 expands loop ({}), so the model denies to match",
                commands.join(", "),
                render_read_loop(cycle)
            ),
            Self::NoPermissivePolicy { table, commands } => write!(
                f,
                "No permissive policy on '{table}' covers {}, so RLS denies {those} outright \
                 and the model mirrors that with no_access",
                commands.join(", "),
                those = if commands.len() == 1 { "it" } else { "them" }
            ),
            Self::CoveringPoliciesBelowThreshold { table, commands } => write!(
                f,
                "Every permissive policy on '{table}' covering {} fell below the confidence \
                 threshold, so the model denies what RLS grants",
                commands.join(", ")
            ),
            Self::ClauseBelowThreshold {
                table,
                policy,
                mode,
                clause,
                confidence,
                commands,
                relations,
            } => write!(
                f,
                "The {clause} clause of {mode} policy '{policy}' on '{table}' classified at \
                 confidence {confidence}, below the threshold, so the model no longer answers \
                 as the database does for {} through {}",
                commands.join(", "),
                relations.join(", ")
            ),
            Self::PolicyClauseAbsent {
                policy,
                commands,
                clause,
            } => write!(
                f,
                "Policy '{policy}' names {commands} without a {clause} clause, so PostgreSQL \
                 admits no row through it"
            ),
            Self::PolicyBoundToDdlTimeRole { spellings, .. } => write!(
                f,
                "The TO clause names ({}), which PostgreSQL resolves to whoever runs the \
                 CREATE POLICY, so a schema file cannot know the role. A permissive policy \
                 grants nobody here and a restrictive one binds everyone. Name the role \
                 explicitly.",
                spellings.join(", ")
            ),
            Self::PolicyClauseIllegal { rule, .. } => write!(
                f,
                "PostgreSQL refuses this policy outright ({rule}), so no database can hold \
                 it and the model ignores it. Fix the statement."
            ),
            Self::ReadsDeniedSoWritesCannotName { table, commands } => write!(
                f,
                "Reads of '{table}' are denied, so {} cannot name a row either. \
                 Add a SELECT policy the model can translate.",
                commands.join(", ")
            ),
            Self::PolicyRoleScope {
                policy,
                roles,
                relation,
            } => write!(
                f,
                "Policy '{policy}' is scoped TO ({}) through relation '{relation}', which reads \
                 pg_role '{}', so load that pg_role relation with each role's inheriting members",
                roles.join(", "),
                RolePrivilege::Usage.relation_name()
            ),
            Self::RoleGateScope {
                policy,
                roles,
                relation,
                held_by,
            } => write!(
                f,
                "Policy '{policy}' gates on ({}) through relation '{relation}', which reads \
                 pg_role '{held_by}', so load that pg_role relation with the roles' holders of \
                 that kind",
                roles.join(", ")
            ),
            Self::MembershipReadScope {
                join_table,
                roles,
                relation,
                ..
            } => write!(
                f,
                "Reading membership table '{join_table}' needs PostgreSQL role ({}), mapped to \
                 relation '{relation}', which reads pg_role '{}', so load that relation with \
                 each role's inheriting members",
                roles.join(", "),
                RolePrivilege::Usage.relation_name()
            ),
            Self::TypeNameCollision {
                spelling,
                prior,
                canonical,
                renamed,
            } => write!(
                f,
                "Type name collision: '{spelling}' and '{prior}' both canonicalize to \
                 '{canonical}'. Renamed to '{renamed}'. Update your OpenFGA model references \
                 accordingly."
            ),
            Self::InheritanceParentReadsOwnRowsOnly { table, children } => write!(
                f,
                "'{table}' has inheritance children ({}), so its tuple queries read FROM ONLY \
                 its own rows. Child rows are readable through '{table}' in PostgreSQL but \
                 carry no tuples here, so the model denies them.",
                children
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::RowsCannotBeNamed {
                table,
                reason,
                sources,
            } => write!(
                f,
                "No tuple can name a row of '{table}' ({reason}), so {} cannot be loaded and \
                 every grant on this type denies where PostgreSQL grants.",
                sources.join(", ")
            ),
            Self::BridgeColumnMissing {
                table,
                parent_type,
                column,
            } => write!(
                f,
                "'{table}' has no column '{column}' linking a row to '{parent_type}', so the \
                 bridge cannot be loaded and the grant it carries denies where PostgreSQL \
                 grants."
            ),
            Self::RowIdentifierBudget { table, budget } => write!(
                f,
                "A row of '{table}' is named by at most {budget} characters once encoded, \
                 and the generated query leaves a longer one out rather than shortening it, \
                 which would merge two rows into one object. Check whether any row exceeds \
                 it: the model denies those rows where PostgreSQL grants them."
            ),
            Self::FunctionExpanded { function, .. } => write!(
                f,
                "The call to '{function}' was replaced by the function's single SQL \
                 expression with the arguments substituted, so the translation is the \
                 body's"
            ),
            Self::MembershipTableGrantsNoReads { join_table, .. } => write!(
                f,
                "Membership table '{join_table}' grants no reads, so no membership row is \
                 visible and the command is denied"
            ),
            Self::MembershipTableGuarded { join_table, .. } => write!(
                f,
                "Row level security on membership table '{join_table}' decides which membership \
                 rows a user sees, which no relation can express. Load tuples only for the rows \
                 it exposes."
            ),
            Self::MembershipExtraPredicate { predicate, .. } => write!(
                f,
                "Membership policy carries extra predicate '{predicate}' that must be preserved \
                 in tuple SQL"
            ),
            Self::MembershipResidualReadsUnrestrictedTables {
                predicate, tables, ..
            } => {
                write!(
                    f,
                    "Residual '{predicate}' is decided by rows beyond the membership row, and \
                     translates because row level security is off on "
                )?;
                for (index, table) in tables.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "'{table}'")?;
                }
                write!(
                    f,
                    ". Enabling it on any of them makes the answer the loader's own, so \
                     translate again"
                )
            }
            Self::NullableBooleanFlagNarrowed { column, .. } => write!(
                f,
                "'{column} IS NOT FALSE' admits NULL rows, but generated tuples include only TRUE"
            ),
            Self::ParentRuleUntranslated { parent_table, .. } => write!(
                f,
                "Parent inheritance from '{parent_table}' could not translate the parent-side \
                 rule, so the command is denied"
            ),
            Self::AttributeNeedsRuntimeEnforcement { attribute, .. } => write!(
                f,
                "Attribute condition '{attribute}' still requires runtime enforcement"
            ),
            Self::StandaloneAttributePolicy { column, .. } => write!(
                f,
                "Standalone attribute policy on '{column}' mapped to no_access for safety"
            ),
            Self::ExpressionRefused { reason, .. } => write!(
                f,
                "Expression could not be safely translated ({reason}), so it maps to no_access"
            ),
            Self::FunctionMissingMetadata {
                function_kind,
                function,
                ..
            } => write!(
                f,
                "{function_kind} function '{function}' missing semantic metadata"
            ),
            Self::RoleBypassesPolicies { role } => write!(
                f,
                "Role '{role}' has BYPASSRLS, so every policy is skipped for it and the \
                 model answers for nobody connecting as that role"
            ),
            Self::PartitionReadDirectlyIsUnfiltered { table, root } => write!(
                f,
                "'{table}' is a partition of '{root}', which carries the policies, so a read \
                 naming '{table}' is filtered by nothing. The model answers for a read \
                 through '{root}'. ALTER TABLE '{table}' ENABLE ROW LEVEL SECURITY and give \
                 it the same policies, or revoke access to it"
            ),
            Self::TableOwnerBypassesPolicies { table, owner } => {
                let who = owner.as_ref().map_or_else(
                    || "the table's owner is".to_string(),
                    |owner| format!("its owner '{owner}' is"),
                );
                write!(
                    f,
                    "Row level security on '{table}' is not FORCEd, so {who} exempt from \
                     every policy on it. ALTER TABLE '{table}' FORCE ROW LEVEL SECURITY \
                     subjects them to it"
                )
            }
        }
    }
}

/// A loop in the policy read graph as `a reads b, b reads a`. A table reading itself is
/// a one-element loop.
fn render_read_loop(cycle: &[String]) -> String {
    let hops: Vec<String> = cycle
        .iter()
        .enumerate()
        .filter_map(|(index, table)| {
            let next = cycle.get(index + 1).or_else(|| cycle.first())?;
            Some(format!("{table} reads {next}"))
        })
        .collect();
    hops.join(", ")
}
