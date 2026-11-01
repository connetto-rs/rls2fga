//! The database roles every caller runs as, and which of them a policy's `TO` roles reach.

#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
use alloc::collections::BTreeSet;

use crate::parser::sql_parser::{DatabaseLike, RoleMembershipLike};

/// The database roles a consumer runs every caller's transaction as, one per transaction.
///
/// Names are compared as `PostgreSQL` stores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerRoles(BTreeSet<String>);

/// [`CallerRoles`] was given no role, so no caller could run at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("caller roles need at least one role")]
pub struct NoCallerRoles;

/// Which caller roles a policy's `TO` roles reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Settlement {
    /// Every caller role, so the policy applies to every caller.
    Everyone,
    /// These caller roles and not all of them.
    Callers(Vec<String>),
    /// No caller role, so the policy applies to no caller.
    Nobody,
    /// Roles the schema never creates, whose memberships it cannot show.
    Unsettled(Vec<String>),
}

impl CallerRoles {
    /// The roles callers run as.
    ///
    /// # Errors
    ///
    /// [`NoCallerRoles`] when `roles` is empty.
    pub fn new<I, S>(roles: I) -> Result<Self, NoCallerRoles>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let roles: BTreeSet<String> = roles.into_iter().map(Into::into).collect();
        if roles.is_empty() {
            Err(NoCallerRoles)
        } else {
            Ok(Self(roles))
        }
    }

    /// Which caller roles have the privileges of any of `named`, the test `PostgreSQL`
    /// applies to a `TO` clause (`has_privs_of_role`).
    pub(crate) fn settle<DB: DatabaseLike>(&self, named: &[String], db: &DB) -> Settlement {
        let unsettled: BTreeSet<&String> = self
            .0
            .iter()
            .chain(named)
            .filter(|role| db.role(role).is_none())
            .collect();
        if !unsettled.is_empty() {
            return Settlement::Unsettled(unsettled.into_iter().cloned().collect());
        }
        let reaching: Vec<String> = self
            .0
            .iter()
            .filter(|caller| {
                let privileges = privileges_of(caller, db);
                named.iter().any(|role| privileges.contains(role.as_str()))
            })
            .cloned()
            .collect();
        if reaching.is_empty() {
            Settlement::Nobody
        } else if reaching.len() == self.0.len() {
            Settlement::Everyone
        } else {
            Settlement::Callers(reaching)
        }
    }

    /// The caller roles, as `PostgreSQL` stores their names.
    pub(crate) fn roles(&self) -> &BTreeSet<String> {
        &self.0
    }
}

/// `role` and every role whose privileges it uses without `SET ROLE`.
fn privileges_of<DB: DatabaseLike>(role: &str, db: &DB) -> BTreeSet<String> {
    let mut reached = BTreeSet::from([role.to_string()]);
    let mut frontier = vec![role.to_string()];
    while let Some(member) = frontier.pop() {
        for granted in db
            .role_memberships()
            .filter(|membership| {
                membership.inherit_option() && membership.stored_member_name() == member.as_str()
            })
            .map(|membership| membership.stored_role_name().into_owned())
        {
            if reached.insert(granted.clone()) {
                frontier.push(granted);
            }
        }
    }
    reached
}
