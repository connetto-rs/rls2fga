//! One branch of every action relation per role a request may act as.
//!
//! Which policies a row has to pass is `row_security`'s answer for one statement and one
//! acting role. Each gate it returns is the policies of one command judging one version of
//! the row, and those map one to one onto the targets the policies' clauses already feed:
//!
//! | Gate | Target |
//! | --- | --- |
//! | `SELECT` on the existing row | `Select` |
//! | `INSERT` on the inserted row | `Insert` |
//! | `UPDATE` on the existing row | `UpdateUsing` |
//! | `UPDATE` on the updated row | `UpdateCheck` |
//! | `DELETE` on the existing row | `Delete` |
//!
//! A statement reading the row also applies the `SELECT` gate, which the action relations
//! add as `can_select` beside the command's own target. A check runs as exactly one kind,
//! so the union over roles of each target, intersected across targets, answers the same
//! as the intersection of one role's targets.

use super::*;

use alloc::borrow::Cow;

use crate::types::ColumnCommand;
use sql_traits::errors::DeploymentError;
use sql_traits::structs::{
    ActingRole, ColumnPrivilege, GateTerm, RowSecurity, RowSecurityExemption, RowStatement,
    RowVersion, TablePrivileges,
};

/// What one policy's clause contributes to one target.
#[derive(Debug, Clone)]
pub(super) enum PolicyPart {
    /// The rows the clause admits.
    Grant(UsersetExpr),
    /// The rows a `NOT EXISTS` barrier removes.
    Subtract(UsersetExpr),
}

/// One role a request may act as, and what the classifier read for it.
pub(super) struct ActingBranch<'r, DB: DatabaseLike> {
    /// The role, `None` for a registry read for no deployment, which `PostgreSQL` reads
    /// as a caller holding no role.
    pub(super) role: Option<(&'r str, &'r DB::Role)>,
    /// The registry classifying for this role.
    pub(super) registry: Cow<'r, FunctionRegistry>,
    /// Which membership tables this role reads, answered once each.
    pub(super) readability: BTreeMap<TableId, TableReadability>,
}

impl<'r, DB: DatabaseLike> ActingBranch<'r, DB> {
    /// One branch per acting role of the deployment `registry` was read for, or one acting
    /// as no role where it was read for none.
    ///
    /// # Errors
    ///
    /// [`DeploymentError::UndeclaredRole`] naming the first role `db` does not declare.
    pub(super) fn every(
        registry: &'r FunctionRegistry,
        db: &'r DB,
    ) -> Result<Vec<Self>, DeploymentError> {
        let Some(deployment) = registry.deployment() else {
            return Ok(vec![Self::anonymous(registry)]);
        };
        let resolved = deployment.resolve(db)?;
        Ok(deployment
            .acting_roles()
            .zip(resolved.acting_roles())
            .map(|(name, role)| {
                let mut acting = registry.clone();
                acting.set_acting_role(Some(name));
                Self {
                    role: Some((name, role)),
                    registry: Cow::Owned(acting),
                    readability: BTreeMap::new(),
                }
            })
            .collect())
    }

    /// One branch acting as no role, for policies no catalog holds and for a registry read
    /// for no deployment.
    pub(super) fn anonymous(registry: &'r FunctionRegistry) -> Self {
        Self {
            role: None,
            registry: Cow::Borrowed(registry),
            readability: BTreeMap::new(),
        }
    }

    /// The role's name as a note spells it.
    pub(super) fn name(&self) -> &str {
        self.role.map_or("PUBLIC", |(name, _)| name)
    }

    /// Whether `policy` was classified for this branch. A branch acting as no role reads
    /// every policy, whichever role it was classified for.
    pub(super) fn classified(&self, policy: &ClassifiedPolicy) -> bool {
        self.role
            .is_none_or(|(name, _)| policy.acting_role() == Some(name))
    }

    fn acting_role(&self) -> ActingRole<'r, DB::Role> {
        match self.role {
            Some((_, role)) => ActingRole::Declared(role),
            None => ActingRole::Public,
        }
    }
}

/// How one target answers for one acting role.
#[derive(Debug)]
pub(super) enum TargetAnswer {
    /// Row security skips the role, so every row passes.
    Exempt,
    /// The rows the policies reaching the role admit.
    Gated(ModeBuckets),
    /// `PostgreSQL` raises, or the answer cannot be settled, so no row passes.
    Refused,
}

/// One statement asked of `row_security`. None reads the row, so each of its gates judges
/// the statement's own command.
#[derive(Debug, Clone, Copy)]
enum Asked {
    Select,
    Insert,
    Update,
    Delete,
}

/// The statements whose gates name every target once, beside the column command each needs.
const ASKED: [(Asked, Option<ColumnCommand>); 4] = [
    (Asked::Select, Some(ColumnCommand::Select)),
    (Asked::Insert, Some(ColumnCommand::Insert)),
    (Asked::Update, Some(ColumnCommand::Update)),
    (Asked::Delete, None),
];

impl Asked {
    /// The statement as `row_security` takes it.
    fn statement(self) -> RowStatement {
        match self {
            Self::Select => RowStatement::Select,
            Self::Insert => RowStatement::Insert { returning: false },
            Self::Update => RowStatement::Update { reads: false },
            Self::Delete => RowStatement::Delete { reads: false },
        }
    }

    /// Where this command is held.
    fn holding<C: ColumnLike>(self, privileges: &TablePrivileges<'_, C>) -> ColumnHolding {
        match self {
            Self::Select => column_holding(&privileges.select),
            Self::Insert => column_holding(&privileges.insert),
            Self::Update => column_holding(&privileges.update),
            Self::Delete if privileges.delete => ColumnHolding::Table,
            Self::Delete => ColumnHolding::Absent,
        }
    }

    /// The targets the statement's gates feed.
    fn targets(self) -> &'static [ActionTarget] {
        match self {
            Self::Select => &[ActionTarget::Select],
            Self::Insert => &[ActionTarget::Insert],
            Self::Update => &[ActionTarget::UpdateUsing, ActionTarget::UpdateCheck],
            Self::Delete => &[ActionTarget::Delete],
        }
    }

    /// The target the statement's gate on `row` feeds. Only an update judges two versions.
    fn target(self, row: RowVersion) -> ActionTarget {
        match self {
            Self::Select => ActionTarget::Select,
            Self::Insert => ActionTarget::Insert,
            Self::Update if row == RowVersion::Existing => ActionTarget::UpdateUsing,
            Self::Update => ActionTarget::UpdateCheck,
            Self::Delete => ActionTarget::Delete,
        }
    }
}

/// The SQL commands these targets feed, for a note.
fn commands_of(targets: &BTreeSet<ActionTarget>) -> Vec<String> {
    commands_fed_by(&targets.iter().copied().collect::<Vec<_>>())
}

/// Where a role holds one command on the table, as its privileges answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ColumnHolding {
    /// On the table, and so on every column.
    Table,
    /// On these columns only, never on the table.
    Columns(BTreeSet<ColumnName>),
    /// Nowhere.
    Absent,
}

/// One column privilege's holding.
fn column_holding<C: ColumnLike>(privilege: &ColumnPrivilege<'_, C>) -> ColumnHolding {
    match privilege {
        ColumnPrivilege::Table => ColumnHolding::Table,
        ColumnPrivilege::Columns(columns) if !columns.is_empty() => ColumnHolding::Columns(
            columns
                .iter()
                .map(|column| ColumnName::from_stored(column.stored_column_name()))
                .collect(),
        ),
        ColumnPrivilege::Columns(_) => ColumnHolding::Absent,
    }
}

/// Refuse the commands the role holds on no column, and return where it holds the ones
/// `PostgreSQL` grants on single columns.
pub(super) fn gate_on_privileges<DB: DatabaseLike>(
    answers: &mut BTreeMap<ActionTarget, TargetAnswer>,
    table: &DB::Table,
    branch: &ActingBranch<'_, DB>,
    db: &DB,
) -> BTreeMap<ColumnCommand, ColumnHolding> {
    let privileges = table.privileges(branch.acting_role(), db).ok();
    let mut held = BTreeMap::new();
    for (asked, command) in ASKED {
        let holding = privileges
            .as_ref()
            .map_or(ColumnHolding::Absent, |privileges| {
                asked.holding(privileges)
            });
        if holding == ColumnHolding::Absent {
            for target in asked.targets() {
                answers.insert(*target, TargetAnswer::Refused);
            }
        }
        if let Some(command) = command {
            held.insert(command, holding);
        }
    }
    held
}

/// Place one policy's part for one target in the bucket its mode makes it.
fn place(bucket: &mut ModeBuckets, mode: PolicyMode, part: PolicyPart) {
    match (mode, part) {
        (PolicyMode::Permissive, PolicyPart::Grant(expr)) => bucket.permissive.push(expr),
        (PolicyMode::Restrictive, PolicyPart::Grant(expr)) => bucket.restrictive.push(expr),
        (_, PolicyPart::Subtract(expr)) => bucket.subtractions.push(expr),
    }
}

/// Fill the bucket one gate's terms make, moving out the parts each policy's clause
/// produced. Every target has one gate, so a part is taken at most once.
///
/// A policy the gate applies whose clause produced nothing for the target was dropped,
/// which a permissive policy does by granting nothing and a restrictive one never does,
/// since its routing already turns a lost clause into a denial.
fn fill_bucket<P: PolicyLike>(
    bucket: &mut ModeBuckets,
    target: ActionTarget,
    permissive: &[GateTerm<'_, P>],
    restrictive: &[GateTerm<'_, P>],
    parts: &mut BTreeMap<String, BTreeMap<ActionTarget, PolicyPart>>,
) {
    for (mode, terms) in [
        (PolicyMode::Permissive, permissive),
        (PolicyMode::Restrictive, restrictive),
    ] {
        for term in terms {
            if let Some(part) = parts
                .get_mut(term.policy().name())
                .and_then(|targets| targets.remove(&target))
            {
                place(bucket, mode, part);
            }
        }
    }
}

/// Answer row-security targets and record the permissive policies reaching this role.
pub(super) fn answer_targets<'db, DB: DatabaseLike>(
    table: &'db DB::Table,
    source_table: &TableId,
    branch: &ActingBranch<'db, DB>,
    parts: &mut BTreeMap<String, BTreeMap<ActionTarget, PolicyPart>>,
    db: &'db DB,
    notes: &mut Vec<TranslationNote>,
    reached: &mut BTreeSet<&'db str>,
) -> BTreeMap<ActionTarget, TargetAnswer> {
    let mut answers = BTreeMap::new();
    let mut exempt = None;
    let mut recursion: BTreeMap<String, BTreeSet<ActionTarget>> = BTreeMap::new();
    let mut refused: BTreeMap<String, BTreeSet<ActionTarget>> = BTreeMap::new();
    for (asked, _) in ASKED {
        let targets = asked.targets();
        match table.row_security(asked.statement(), branch.acting_role(), db) {
            Ok(RowSecurity::Exempt(exemption)) => {
                exempt = Some(exemption);
                for target in targets {
                    answers.insert(*target, TargetAnswer::Exempt);
                }
            }
            Ok(RowSecurity::Gated(gates)) => {
                // A statement's gates feed only its own targets, so none is answered yet.
                let mut buckets: BTreeMap<ActionTarget, ModeBuckets> = BTreeMap::new();
                for gate in &gates {
                    reached.extend(gate.permissive().iter().map(|term| term.policy().name()));
                    let target = asked.target(gate.row());
                    let bucket = buckets.entry(target).or_default();
                    fill_bucket(bucket, target, gate.permissive(), gate.restrictive(), parts);
                }
                answers.extend(
                    buckets
                        .into_iter()
                        .map(|(target, bucket)| (target, TargetAnswer::Gated(bucket))),
                );
            }
            Ok(RowSecurity::InfiniteRecursion { relation }) => {
                recursion
                    .entry(relation)
                    .or_default()
                    .extend(targets.iter().copied());
                for target in targets {
                    answers.insert(*target, TargetAnswer::Refused);
                }
            }
            Err(error) => {
                refused
                    .entry(error.to_string())
                    .or_default()
                    .extend(targets.iter().copied());
                for target in targets {
                    answers.insert(*target, TargetAnswer::Refused);
                }
            }
        }
    }
    if let Some(exemption) = exempt.filter(|exemption| *exemption != RowSecurityExemption::Disabled)
    {
        notes.push(TranslationNote::ActingRoleExempt {
            table: source_table.clone(),
            role: branch.name().to_string(),
            reason: exemption.to_string(),
        });
    }
    for (relation, targets) in recursion {
        notes.push(TranslationNote::PolicyReadRecursion {
            table: source_table.clone(),
            role: branch.name().to_string(),
            commands: commands_of(&targets),
            relation,
        });
    }
    for (reason, targets) in refused {
        notes.push(TranslationNote::RowSecurityRefused {
            table: source_table.clone(),
            role: branch.name().to_string(),
            commands: commands_of(&targets),
            reason,
        });
    }
    answers
}

/// How each target answers for policies no catalog holds, such as a supplied read filter,
/// which `row_security` cannot be asked about. Each policy reaches every caller, combined
/// by its own mode.
pub(super) fn answer_supplied_policies<DB: DatabaseLike>(
    policies: &[&ClassifiedPolicy],
    branch: &ActingBranch<'_, DB>,
    mut parts: BTreeMap<String, BTreeMap<ActionTarget, PolicyPart>>,
) -> BTreeMap<ActionTarget, TargetAnswer> {
    let mut buckets: BTreeMap<ActionTarget, ModeBuckets> = BTreeMap::new();
    for policy in policies.iter().filter(|policy| branch.classified(policy)) {
        for (target, part) in parts.remove(policy.name()).into_iter().flatten() {
            place(buckets.entry(target).or_default(), policy.mode(), part);
        }
    }
    buckets
        .into_iter()
        .map(|(target, bucket)| (target, TargetAnswer::Gated(bucket)))
        .collect()
}

/// The rule one target answers for one role, `None` where no row passes.
///
/// `walk` joins the role's kind, and is `None` for a branch acting as no role, which no
/// kind tuple can name and no exemption reaches.
pub(super) fn branch_expr(
    answer: &TargetAnswer,
    walk: Option<UsersetExpr>,
    table_plan: &mut TypePlan,
) -> Option<UsersetExpr> {
    let rule = match answer {
        TargetAnswer::Refused => return None,
        // An exempt role reads every row its kind reaches.
        TargetAnswer::Exempt => return walk,
        TargetAnswer::Gated(bucket) if bucket.permissive.is_empty() => return None,
        TargetAnswer::Gated(bucket) => compose_action(table_plan, Some(bucket))?,
    };
    Some(match walk {
        Some(walk) => UsersetExpr::Intersection(vec![rule, walk]),
        None => rule,
    })
}
