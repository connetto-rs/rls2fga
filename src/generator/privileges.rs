//! Who may run each command on a table at all, read from its `GRANT` and `REVOKE` statements.
//!
//! `PostgreSQL` refuses a role lacking the table privilege with `42501` before any policy runs.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use sqlparser::ast::{Action, Grantee, GranteeName, GranteesType};

use crate::generator::caller_roles::{CallerRoles, Settlement};
use crate::generator::unrestricted::row_level_security_is_off;
use crate::parser::names::{stored_ident_name, table_identity};
use crate::parser::sql_parser::{
    ColumnGrantLike, DatabaseLike, GrantLike, TableGrantLike, TableLike,
};
use crate::types::{PrivilegeHolders, TableId, TablePrivileges, TranslationNote};

/// A command row-level security governs, and the privilege `PostgreSQL` checks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TableCommand {
    Select,
    Insert,
    Update,
    Delete,
}

impl TableCommand {
    pub(crate) const ALL: [Self; 4] = [Self::Select, Self::Insert, Self::Update, Self::Delete];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
        }
    }

    /// Whether `action` grants this command on the whole table.
    fn granted_on_table(self, action: &Action) -> bool {
        matches!(
            (self, action),
            (Self::Select, Action::Select { columns: None })
                | (Self::Insert, Action::Insert { columns: None })
                | (Self::Update, Action::Update { columns: None })
                | (Self::Delete, Action::Delete)
        )
    }

    /// Whether `action` grants this command on a list of columns.
    fn granted_on_columns(self, action: &Action) -> bool {
        matches!(
            (self, action),
            (Self::Select, Action::Select { columns: Some(_) })
                | (Self::Insert, Action::Insert { columns: Some(_) })
                | (Self::Update, Action::Update { columns: Some(_) })
        )
    }
}

/// Each command beside its holders, in command order.
pub(crate) fn holders_by_command(
    privileges: &TablePrivileges,
) -> [(TableCommand, &PrivilegeHolders); 4] {
    [
        (TableCommand::Select, &privileges.select),
        (TableCommand::Insert, &privileges.insert),
        (TableCommand::Update, &privileges.update),
        (TableCommand::Delete, &privileges.delete),
    ]
}

/// `holders` settled against `callers`, and the holders whose memberships the schema cannot show.
///
/// Each holder settles alone, so an undeclared one narrows the gate rather than closing it.
fn settle_holders<DB: DatabaseLike>(
    holders: &PrivilegeHolders,
    callers: Option<&CallerRoles>,
    db: &DB,
) -> (PrivilegeHolders, BTreeSet<String>) {
    let (PrivilegeHolders::Roles(roles), Some(callers)) = (holders, callers) else {
        return (holders.clone(), BTreeSet::new());
    };
    let mut reaching = BTreeSet::new();
    let mut unsettled = BTreeSet::new();
    for role in roles {
        match callers.settle(core::slice::from_ref(role), db) {
            Settlement::Everyone => return (PrivilegeHolders::Everyone, BTreeSet::new()),
            Settlement::Callers(reached) => reaching.extend(reached),
            Settlement::Nobody => {}
            Settlement::Unsettled(undeclared) => unsettled.extend(undeclared),
        }
    }
    if reaching == *callers.roles() {
        return (PrivilegeHolders::Everyone, BTreeSet::new());
    }
    (
        PrivilegeHolders::Roles(reaching.into_iter().collect()),
        unsettled,
    )
}

/// One grantee as `PostgreSQL` resolves it.
enum Resolved {
    Public,
    Role(String),
    /// `CURRENT_USER`, `CURRENT_ROLE` or `SESSION_USER`, resolved when the `GRANT` runs.
    WhenGranted(String),
}

fn resolve_grantee(grantee: &Grantee) -> Resolved {
    if grantee.grantee_type == GranteesType::Public {
        return Resolved::Public;
    }
    let Some(GranteeName::ObjectName(name)) = &grantee.name else {
        return Resolved::Role(grantee.to_string());
    };
    let Some(ident) = name.0.last().and_then(|part| part.as_ident()) else {
        return Resolved::Role(name.to_string());
    };
    if ident.quote_style.is_none() {
        let upper = ident.value.to_ascii_uppercase();
        if upper == "PUBLIC" {
            return Resolved::Public;
        }
        if matches!(
            upper.as_str(),
            "CURRENT_USER" | "CURRENT_ROLE" | "SESSION_USER"
        ) {
            return Resolved::WhenGranted(upper);
        }
    }
    Resolved::Role(stored_ident_name(ident).into_owned())
}

/// What one command's grants add up to.
#[derive(Default)]
struct Held {
    public: bool,
    roles: BTreeSet<String>,
    public_on_columns: bool,
    roles_on_columns: BTreeSet<String>,
    when_granted: BTreeSet<String>,
}

impl Held {
    fn grant(&mut self, grantee: &Grantee, on_table: bool, on_columns: bool) {
        if !on_table && !on_columns {
            return;
        }
        match resolve_grantee(grantee) {
            Resolved::Public if on_table => self.public = true,
            Resolved::Public => self.public_on_columns = true,
            Resolved::Role(role) if on_table => {
                self.roles.insert(role);
            }
            Resolved::Role(role) => {
                self.roles_on_columns.insert(role);
            }
            Resolved::WhenGranted(spelling) => {
                self.when_granted.insert(spelling);
            }
        }
    }

    /// The holders, and what of the grants the model cannot carry.
    fn split(self, owner_unnamed: bool) -> (PrivilegeHolders, Gaps) {
        let mut on_columns_only = Vec::new();
        if !self.public {
            if self.public_on_columns {
                on_columns_only.push("PUBLIC".to_string());
            }
            on_columns_only.extend(self.roles_on_columns.difference(&self.roles).cloned());
        }
        let holders = if self.public {
            PrivilegeHolders::Everyone
        } else {
            PrivilegeHolders::Roles(self.roles.into_iter().collect())
        };
        (
            holders,
            Gaps {
                on_columns_only,
                when_granted: self.when_granted,
                owner_unnamed,
            },
        )
    }
}

/// What the model denies of one command where `PostgreSQL` may admit.
#[derive(Debug)]
struct Gaps {
    /// Holders of the command on some columns only, `PUBLIC` first where it is one.
    on_columns_only: Vec<String>,
    /// Grantee spellings resolved when the `GRANT` ran.
    when_granted: BTreeSet<String>,
    /// Whether an owner the schema does not name holds it under the table's rules.
    owner_unnamed: bool,
}

/// A table's privileges as read, and the gaps each command carries.
#[derive(Debug)]
pub(crate) struct ReadPrivileges {
    table: TableId,
    privileges: TablePrivileges,
    gaps: [Gaps; 4],
}

impl ReadPrivileges {
    /// Report the gaps of the commands a rule admits, since a command the rules deny narrows nothing.
    pub(crate) fn note_gaps(&self, admitted: &[TableCommand], notes: &mut Vec<TranslationNote>) {
        let reported = || {
            TableCommand::ALL
                .into_iter()
                .zip(&self.gaps)
                .filter(|(command, _)| admitted.contains(command))
        };
        if reported().any(|(_, gaps)| gaps.owner_unnamed) {
            notes.push(TranslationNote::TableOwnerUnnamed {
                table: self.table.clone(),
            });
        }
        for (command, gaps) in reported() {
            if !gaps.on_columns_only.is_empty() {
                notes.push(TranslationNote::ColumnPrivilegeOnly {
                    table: self.table.clone(),
                    command: command.as_str().to_string(),
                    roles: gaps.on_columns_only.clone(),
                });
            }
        }
        let commands: Vec<String> = reported()
            .filter(|(_, gaps)| !gaps.when_granted.is_empty())
            .map(|(command, _)| command.as_str().to_string())
            .collect();
        if !commands.is_empty() {
            let spellings: BTreeSet<&String> = reported()
                .flat_map(|(_, gaps)| &gaps.when_granted)
                .collect();
            notes.push(TranslationNote::TablePrivilegeGrantedToDdlTimeRole {
                table: self.table.clone(),
                commands,
                spellings: spellings.into_iter().cloned().collect(),
            });
        }
    }

    /// The holders settled against `callers`, noting for the commands a rule admits the
    /// holders whose memberships the schema cannot show.
    pub(crate) fn settled<DB: DatabaseLike>(
        &self,
        callers: Option<&CallerRoles>,
        db: &DB,
        admitted: &[TableCommand],
        notes: &mut Vec<TranslationNote>,
    ) -> TablePrivileges {
        let mut unsettled_commands = Vec::new();
        let mut unsettled_roles = BTreeSet::new();
        let [select, insert, update, delete] =
            holders_by_command(&self.privileges).map(|(command, holders)| {
                let (settled, unsettled) = settle_holders(holders, callers, db);
                if !unsettled.is_empty() && admitted.contains(&command) {
                    unsettled_commands.push(command.as_str().to_string());
                    unsettled_roles.extend(unsettled);
                }
                settled
            });
        if !unsettled_commands.is_empty() {
            notes.push(TranslationNote::TablePrivilegeRoleUnsettled {
                table: self.table.clone(),
                commands: unsettled_commands,
                roles: unsettled_roles.into_iter().collect(),
            });
        }
        TablePrivileges {
            select,
            insert,
            update,
            delete,
        }
    }
}

/// Whether the table's rules bind its owner, which forced or absent row-level security does.
fn rules_bind_owner<DB: DatabaseLike>(table: &DB::Table, db: &DB) -> bool {
    table.has_forced_row_level_security(db) == Ok(true) || row_level_security_is_off(table, db)
}

/// The table privileges of `table`, revokes already applied.
pub(crate) fn read_table_privileges<DB: DatabaseLike>(
    table: &DB::Table,
    db: &DB,
) -> ReadPrivileges {
    let identity = table_identity(table);
    let mut held: [Held; 4] = Default::default();

    for grant in db
        .table_grants()
        .filter(|grant| grant.applies_to_table(table, db))
    {
        let all = grant.is_all_privileges();
        for (command, held) in TableCommand::ALL.into_iter().zip(held.iter_mut()) {
            let on_table = all
                || grant
                    .privileges(db)
                    .any(|action| command.granted_on_table(action));
            let on_columns = !on_table
                && grant
                    .privileges(db)
                    .any(|action| command.granted_on_columns(action));
            for grantee in grant.grantees(db) {
                held.grant(grantee, on_table, on_columns);
            }
        }
    }
    // A column grant may sit in either store, so both are read for the column half, and
    // reading one twice changes no set.
    for grant in db.column_grants().filter(|grant| {
        grant
            .table(db)
            .is_some_and(|named| table_identity(named) == identity)
    }) {
        for (command, held) in TableCommand::ALL.into_iter().zip(held.iter_mut()) {
            let on_columns = grant
                .privileges(db)
                .any(|action| command.granted_on_columns(action));
            for grantee in grant.grantees(db) {
                held.grant(grantee, false, on_columns);
            }
        }
    }

    let mut owner_unnamed = [false; 4];
    if rules_bind_owner(table, db) {
        let entry: Vec<&Action> = table
            .owner_privileges(db)
            .map_or_else(|_| Vec::new(), Iterator::collect);
        let owner = table.owner(db).ok().flatten();
        for ((command, held), unnamed) in TableCommand::ALL
            .into_iter()
            .zip(held.iter_mut())
            .zip(owner_unnamed.iter_mut())
        {
            if !entry.iter().any(|action| command.granted_on_table(action)) {
                continue;
            }
            match owner {
                Some(name) => {
                    held.roles.insert(name.to_string());
                }
                None => *unnamed = true,
            }
        }
    }

    let [select, insert, update, delete] = held;
    let [select_owner, insert_owner, update_owner, delete_owner] = owner_unnamed;
    let (select, select_gaps) = select.split(select_owner);
    let (insert, insert_gaps) = insert.split(insert_owner);
    let (update, update_gaps) = update.split(update_owner);
    let (delete, delete_gaps) = delete.split(delete_owner);
    ReadPrivileges {
        table: identity,
        privileges: TablePrivileges {
            select,
            insert,
            update,
            delete,
        },
        gaps: [select_gaps, insert_gaps, update_gaps, delete_gaps],
    }
}
