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

use sql_traits::errors::DeploymentError;
use sql_traits::structs::{
    ActingRole, GateTerm, GatedCommand, RowSecurity, RowSecurityExemption, RowStatement, RowVersion,
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

/// The statements whose gates name every target once.
const STATEMENTS: [RowStatement; 4] = [
    RowStatement::Select,
    RowStatement::Insert { returning: false },
    RowStatement::Update { reads: false },
    RowStatement::Delete { reads: false },
];

/// The targets one statement's own gates feed.
fn statement_targets(statement: RowStatement) -> &'static [ActionTarget] {
    match statement {
        RowStatement::Select => &[ActionTarget::Select],
        RowStatement::Insert { .. } => &[ActionTarget::Insert],
        RowStatement::Update { .. } => &[ActionTarget::UpdateUsing, ActionTarget::UpdateCheck],
        _ => &[ActionTarget::Delete],
    }
}

/// The target a gate feeds.
fn gate_target(command: GatedCommand, row: RowVersion) -> Option<ActionTarget> {
    match (command, row) {
        (GatedCommand::Select, RowVersion::Existing) => Some(ActionTarget::Select),
        (GatedCommand::Insert, RowVersion::Inserted) => Some(ActionTarget::Insert),
        (GatedCommand::Update, RowVersion::Existing) => Some(ActionTarget::UpdateUsing),
        (GatedCommand::Update, RowVersion::Updated) => Some(ActionTarget::UpdateCheck),
        (GatedCommand::Delete, RowVersion::Existing) => Some(ActionTarget::Delete),
        _ => None,
    }
}

/// Why an exempt role skips the table, as a note says it.
fn exemption_reason(exemption: RowSecurityExemption) -> &'static str {
    match exemption {
        RowSecurityExemption::Disabled => "meets no row level security",
        RowSecurityExemption::Superuser => "is a superuser",
        RowSecurityExemption::BypassRls => "has BYPASSRLS",
        RowSecurityExemption::Owner => {
            "owns the table, or inherits from its owner, and the table does not FORCE row \
             level security"
        }
    }
}

/// The SQL commands these targets feed, for a note.
fn commands_of(targets: &BTreeSet<ActionTarget>) -> Vec<String> {
    commands_fed_by(&targets.iter().copied().collect::<Vec<_>>())
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
    let mut take = |term: &GateTerm<'_, P>| {
        parts
            .get_mut(term.policy().name())
            .and_then(|targets| targets.remove(&target))
    };
    for term in permissive {
        if let Some(PolicyPart::Grant(expr)) = take(term) {
            bucket.permissive.push(expr);
        }
    }
    for term in restrictive {
        match take(term) {
            Some(PolicyPart::Grant(expr)) => bucket.restrictive.push(expr),
            Some(PolicyPart::Subtract(expr)) => bucket.subtractions.push(expr),
            None => {}
        }
    }
}

/// How each target answers for `branch` on `table`, and the notes that answer raises.
/// Every permissive policy a gate applies to the branch's role joins `reached`.
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
    for statement in STATEMENTS {
        let targets = statement_targets(statement);
        match table.row_security(statement, branch.acting_role(), db) {
            Ok(RowSecurity::Exempt(exemption)) => {
                exempt = Some(exemption);
                for target in targets {
                    answers.insert(*target, TargetAnswer::Exempt);
                }
            }
            Ok(RowSecurity::Gated(gates)) => {
                for gate in &gates {
                    reached.extend(gate.permissive().iter().map(|term| term.policy().name()));
                    let Some(target) = gate_target(gate.command(), gate.row()) else {
                        continue;
                    };
                    let answer = answers
                        .entry(target)
                        .or_insert_with(|| TargetAnswer::Gated(ModeBuckets::default()));
                    if let TargetAnswer::Gated(bucket) = answer {
                        fill_bucket(bucket, target, gate.permissive(), gate.restrictive(), parts);
                    }
                }
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
            reason: exemption_reason(exemption).to_string(),
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
        let Some(targets) = parts.remove(policy.name()) else {
            continue;
        };
        for (target, part) in targets {
            let bucket = buckets.entry(target).or_default();
            match (policy.mode(), part) {
                (PolicyMode::Permissive, PolicyPart::Grant(expr)) => bucket.permissive.push(expr),
                (PolicyMode::Restrictive, PolicyPart::Grant(expr)) => {
                    bucket.restrictive.push(expr);
                }
                (_, PolicyPart::Subtract(expr)) => bucket.subtractions.push(expr),
            }
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
/// kind tuple can name.
pub(super) fn branch_expr(
    answer: &TargetAnswer,
    walk: Option<UsersetExpr>,
    table_plan: &mut TypePlan,
    all_rows: impl FnOnce(&mut TypePlan) -> UsersetExpr,
) -> Option<UsersetExpr> {
    let rule = match answer {
        TargetAnswer::Refused => return None,
        TargetAnswer::Exempt => None,
        TargetAnswer::Gated(bucket) => {
            if bucket.permissive.is_empty() {
                return None;
            }
            compose_action(table_plan, Some(bucket))
        }
    };
    match (rule, walk) {
        (Some(rule), Some(walk)) => Some(UsersetExpr::Intersection(vec![rule, walk])),
        (Some(rule), None) => Some(rule),
        (None, Some(walk)) => Some(walk),
        (None, None) => Some(all_rows(table_plan)),
    }
}
