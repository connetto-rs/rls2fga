//! Which relation a command reads, and how a policy's clauses reach it.
//!
//! One table pairs each action relation with its SQL command and the clause targets that command
//! needs, so a relation cannot be mapped to a command in a second place. The rest routes a
//! policy's `USING` and `WITH CHECK` to the targets they feed, composes the buckets that
//! collect, and fills what no policy covered with a denial.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ActionTarget {
    Select,
    Insert,
    UpdateUsing,
    UpdateCheck,
    Delete,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ModeBuckets {
    pub(crate) permissive: Vec<UsersetExpr>,
    pub(crate) restrictive: Vec<UsersetExpr>,
    pub(crate) subtractions: Vec<UsersetExpr>,
    /// Barriers that bind only the members of a role.
    pub(crate) role_limited: Vec<RoleLimitedRule>,
}

/// A RESTRICTIVE rule and the relation holding the roles it binds.
#[derive(Debug, Clone)]
pub(crate) struct RoleLimitedRule {
    pub(crate) policy: String,
    pub(crate) rule: UsersetExpr,
    pub(crate) scope_relation: RelationName,
}

/// The walk from a `TO`-clause scope to the users it admits.
///
/// `PostgreSQL` applies a `TO` clause with `has_privs_of_role` semantics, which is the
/// `usage` kind: an inheriting member is admitted, a `NOINHERIT` member or a
/// `WITH INHERIT FALSE` grant is not, while all three hold plain `MEMBER`. Probed on
/// 18.4 for the permissive scope and the restrictive barrier alike.
pub(crate) fn to_clause_scope_walk(scope_relation: &RelationName) -> UsersetExpr {
    UsersetExpr::TupleToUserset {
        tupleset: scope_relation.clone(),
        computed: RolePrivilege::Usage.relation_name(),
    }
}

pub(crate) fn scoped_policy_expr(expr: UsersetExpr, scope_relation: &RelationName) -> UsersetExpr {
    UsersetExpr::Intersection(vec![expr, to_clause_scope_walk(scope_relation)])
}

pub(crate) fn using_targets(command: PolicyCommand) -> Vec<ActionTarget> {
    match command {
        PolicyCommand::Select => vec![ActionTarget::Select],
        PolicyCommand::Insert => vec![],
        PolicyCommand::Update => vec![ActionTarget::UpdateUsing],
        PolicyCommand::Delete => vec![ActionTarget::Delete],
        PolicyCommand::All => vec![
            ActionTarget::Select,
            ActionTarget::UpdateUsing,
            ActionTarget::Delete,
        ],
    }
}

pub(crate) fn with_check_targets(command: PolicyCommand) -> Vec<ActionTarget> {
    match command {
        PolicyCommand::Insert => vec![ActionTarget::Insert],
        PolicyCommand::Update => vec![ActionTarget::UpdateCheck],
        PolicyCommand::Select | PolicyCommand::Delete => vec![],
        PolicyCommand::All => vec![ActionTarget::Insert, ActionTarget::UpdateCheck],
    }
}

/// Targets the `USING` feeds, the mirror included: a command that mirrors and stores
/// no `WITH CHECK` of its own has its check side answered by this clause too. The one
/// place that rule is spelled outside the translator itself.
pub(crate) fn using_targets_with_mirror(cp: &ClassifiedPolicy) -> Vec<ActionTarget> {
    let mut targets = using_targets(cp.command());
    if cp.with_check.is_none() && policy_uses_using_for_missing_with_check(cp.command()) {
        targets.extend(with_check_targets(cp.command()));
    }
    targets
}

/// Each clause the threshold dropped, the grade it held, and the targets it fed.
///
/// The single source for both halves of the disclosure: what the note says and what
/// the scar marks are the same targets, read once.
pub(crate) fn clauses_lost_to_the_threshold(
    cp: &ClassifiedPolicy,
) -> Vec<(&'static str, ConfidenceLevel, Vec<ActionTarget>)> {
    let mut lost = Vec::new();
    if let Some(confidence) = cp.using_filtered_at {
        lost.push(("USING", confidence, using_targets_with_mirror(cp)));
    }
    if let Some(confidence) = cp.with_check_filtered_at {
        lost.push(("WITH CHECK", confidence, with_check_targets(cp.command())));
    }
    lost
}

/// Each clause whose literal the catalog cannot read, why, and the targets it feeds.
pub(crate) fn unreadable_clause_targets(cp: &ClassifiedPolicy) -> Vec<(&str, Vec<ActionTarget>)> {
    let mut unreadable = Vec::new();
    if let Some(reason) = cp.using_unreadable() {
        unreadable.push((reason, using_targets_with_mirror(cp)));
    }
    if let Some(reason) = cp.with_check_unreadable() {
        unreadable.push((reason, with_check_targets(cp.command())));
    }
    unreadable
}

/// Every target this policy's stored clauses feed, for one dropped whole.
pub(crate) fn targets_a_policy_feeds(cp: &ClassifiedPolicy) -> Vec<ActionTarget> {
    let mut targets = Vec::new();
    if cp.using.is_some() {
        targets.extend(using_targets_with_mirror(cp));
    }
    if cp.with_check.is_some() {
        targets.extend(with_check_targets(cp.command()));
    }
    targets
}

/// Action relations that read this bucket, so losing it diverges them.
pub(crate) fn relations_fed_by(target: ActionTarget) -> Vec<RelationName> {
    match target {
        ActionTarget::Select => vec![can_select_relation()],
        ActionTarget::Insert => vec![can_insert_relation(), can_insert_returning_relation()],
        ActionTarget::UpdateUsing => vec![
            can_update_relation(),
            can_update_using_relation(),
            can_update_without_reading_relation(),
        ],
        ActionTarget::UpdateCheck => vec![can_update_relation(), can_update_check_relation()],
        ActionTarget::Delete => vec![can_delete_relation()],
    }
}

/// Relation names these targets diverge, deduplicated: the two UPDATE targets feed
/// `can_update` in common, so a policy losing both would otherwise name it twice. The
/// scar is a set, so the note has to be one too, or the two surfaces disagree about
/// what was lost.
pub(crate) fn narrowed_by(targets: &[ActionTarget]) -> BTreeSet<RelationName> {
    targets
        .iter()
        .flat_map(|target| relations_fed_by(*target))
        .collect()
}

/// Record that the rule these targets feed no longer answers as the database does.
pub(crate) fn mark_narrowed(plan: &mut TypePlan, targets: &[ActionTarget]) {
    plan.narrowed_relations.extend(narrowed_by(targets));
}

/// Whether a missing `WITH CHECK` reads the `USING` instead, which is what `PostgreSQL`
/// does for the commands that may store both. A bare `INSERT` policy cannot store a
/// `USING` at all, so it has no arm here.
pub(crate) fn policy_uses_using_for_missing_with_check(command: PolicyCommand) -> bool {
    matches!(command, PolicyCommand::All | PolicyCommand::Update)
}

/// Stand-in expression for a RESTRICTIVE clause dropped by confidence filtering:
/// `PostgreSQL` ANDs it onto the permissive union, so it must deny.
///
/// An explicit constant false rather than an unreadable expression, which is the same
/// substitution the oracle's `Denied` answer makes. It denies exactly as before, and
/// it keeps the caller's own threshold from being reported as a gap in the
/// translation: `ClauseBelowThreshold` says what happened, and `outputs` answers
/// instead of refusing.
pub(crate) fn dropped_restrictive_expr() -> ClassifiedExpr {
    ClassifiedExpr {
        pattern: PatternClass::P10ConstantBool(ConstantBool { value: false }),
        confidence: ConfidenceLevel::A,
    }
}

/// SQL commands these targets feed, in command order.
pub(crate) fn commands_fed_by(targets: &[ActionTarget]) -> Vec<String> {
    action_relation_commands()
        .into_iter()
        .filter(|(_, _, needed)| needed.iter().any(|target| targets.contains(target)))
        .map(|(_, command, _)| command.to_string())
        .collect()
}

/// Attribute guards this pattern discards, which widens whatever it guards.
pub(crate) fn dropped_attribute_guards(pattern: &PatternClass) -> Vec<&str> {
    match pattern {
        PatternClass::P7AbacAnd(AbacAnd { attribute_part, .. }) => vec![attribute_part.as_str()],
        PatternClass::P8Composite(Composite { parts, .. }) => parts
            .iter()
            .flat_map(|part| dropped_attribute_guards(&part.pattern))
            .collect(),
        PatternClass::ExpandedFunction(ExpandedFunction { inner, .. }) => {
            dropped_attribute_guards(&inner.pattern)
        }
        PatternClass::MembershipExclusion(MembershipExclusion { base, .. }) => base
            .as_ref()
            .map_or_else(Vec::new, |base| dropped_attribute_guards(&base.pattern)),
        _ => Vec::new(),
    }
}

pub(crate) fn for_each_policy_target_expr<F>(cp: &ClassifiedPolicy, mut f: F)
where
    F: FnMut(ActionTarget, &ClassifiedExpr),
{
    let restrictive = cp.mode() == PolicyMode::Restrictive;

    let dropped_using = (restrictive
        && (cp.using_filtered_at.is_some() || cp.using_unreadable().is_some()))
    .then(dropped_restrictive_expr);
    if let Some(using) = cp.using_classification.as_ref().or(dropped_using.as_ref()) {
        for target in using_targets(cp.command()) {
            f(target, using);
        }
    }

    // Mirror USING → WITH CHECK only when the SQL had no WITH CHECK at all, a dropped
    // barrier included. A filtered or unreadable check falls closed instead.
    let dropped_with_check = (restrictive
        && (cp.with_check_filtered_at.is_some() || cp.with_check_unreadable().is_some()))
    .then(dropped_restrictive_expr);
    let with_check_pattern = cp
        .with_check_classification
        .as_ref()
        .or(dropped_with_check.as_ref())
        .or_else(|| {
            if cp.with_check.is_none()
                && cp.with_check_filtered_at.is_none()
                && policy_uses_using_for_missing_with_check(cp.command())
            {
                cp.using_classification.as_ref().or(dropped_using.as_ref())
            } else {
                None
            }
        });

    if let Some(with_check) = with_check_pattern {
        for target in with_check_targets(cp.command()) {
            f(target, with_check);
        }
    }
}

/// Route one translated clause into its bucket.
///
/// A role scope narrows a PERMISSIVE grant, since the other permissive policies
/// still stand for everyone else. A RESTRICTIVE barrier instead binds only the
/// roles it names, which `compose_action` can express only once the base is known.
pub(crate) fn push_action_expr(
    action_buckets: &mut BTreeMap<ActionTarget, ModeBuckets>,
    target: ActionTarget,
    policy_name: &str,
    mode: PolicyMode,
    expr: UsersetExpr,
    scope_relation: Option<&RelationName>,
) {
    let bucket = action_buckets.entry(target).or_default();
    match (mode, scope_relation) {
        (PolicyMode::Permissive, Some(scope)) => {
            bucket.permissive.push(scoped_policy_expr(expr, scope));
        }
        (PolicyMode::Permissive, None) => bucket.permissive.push(expr),
        (PolicyMode::Restrictive, Some(scope)) => bucket.role_limited.push(RoleLimitedRule {
            policy: policy_name.to_string(),
            rule: expr,
            scope_relation: scope.clone(),
        }),
        (PolicyMode::Restrictive, None) => bucket.restrictive.push(expr),
    }
}

pub(crate) fn compose_action(
    table_plan: &mut TypePlan,
    bucket: Option<&ModeBuckets>,
) -> Option<UsersetExpr> {
    let bucket = bucket?;

    let permissive = combine_union(bucket.permissive.clone());
    let restrictive = combine_intersection(bucket.restrictive.clone());

    let Some(permissive) = permissive else {
        // Barriers alone grant nobody anything, whichever roles they bind.
        return (restrictive.is_some()
            || !bucket.subtractions.is_empty()
            || !bucket.role_limited.is_empty())
        .then(|| deny_expr(table_plan));
    };

    let mut expr = match restrictive {
        Some(restrictive) => UsersetExpr::Intersection(vec![permissive, restrictive]),
        None => permissive,
    };
    if let Some(subtract) = combine_union(bucket.subtractions.clone()) {
        expr = UsersetExpr::Exclusion {
            base: Box::new(expr),
            subtract: Box::new(subtract),
        };
    }

    // Members of the bound roles have to satisfy the barrier, everyone else is
    // untouched by it. Each barrier wraps the previous result, so a second one costs
    // one more relation rather than doubling the tree.
    for limited in &bucket.role_limited {
        let bound = UsersetExpr::Intersection(vec![expr.clone(), limited.rule.clone()]);
        let unbound = UsersetExpr::Exclusion {
            base: Box::new(expr),
            subtract: Box::new(to_clause_scope_walk(&limited.scope_relation)),
        };
        let name = table_plan.ensure_computed(
            role_limited_relation_name(&limited.policy),
            UsersetExpr::Union(vec![bound, unbound]),
        );
        expr = UsersetExpr::Computed(name);
    }

    Some(expr)
}

/// Prefix for relations synthesized to hold a parent-side rule.
pub(crate) const INHERITED_RELATION_PREFIX: &str = "inherited_";

/// Action relations, the SQL command each answers for, and the clause targets a
/// policy has to reach before any row passes that command.
///
/// A function rather than a `const`, since a [`RelationName`] is owned.
pub(crate) fn action_relation_commands(
) -> [(RelationName, &'static str, &'static [ActionTarget]); 4] {
    [
        (can_select_relation(), "SELECT", &[ActionTarget::Select]),
        (can_insert_relation(), "INSERT", &[ActionTarget::Insert]),
        (
            can_update_relation(),
            "UPDATE",
            &[ActionTarget::UpdateUsing, ActionTarget::UpdateCheck],
        ),
        (can_delete_relation(), "DELETE", &[ActionTarget::Delete]),
    ]
}

/// The action relations alone, in command order.
pub(crate) fn action_relations() -> impl Iterator<Item = RelationName> {
    action_relation_commands()
        .into_iter()
        .map(|(relation, _, _)| relation)
}

/// Relations a statement shape needs rather than a bare SQL command name.
pub(crate) fn derived_action_relations() -> [RelationName; 6] {
    [
        can_update_using_relation(),
        can_update_check_relation(),
        can_update_without_reading_relation(),
        can_insert_returning_relation(),
        can_upsert_relation(),
        can_select_for_update_relation(),
    ]
}

/// Action targets a policy's stored clauses reach, which is the routing
/// `for_each_policy_target_expr` performs once those clauses are classified.
pub(crate) fn policy_clause_targets<P: PolicyLike>(
    policy: &P,
    db: &P::DB,
) -> BTreeSet<ActionTarget> {
    recursion::declared_clause_targets(policy, db)
        .into_iter()
        .filter(|(clause, _)| clause.is_some())
        .flat_map(|(_, targets)| targets)
        .collect()
}

/// Whether barriers alone reached this target. A RESTRICTIVE policy narrows a grant and
/// there is none to narrow, so `compose_action` synthesizes a denial and the relation
/// exists without granting anybody.
fn barriers_alone(bucket: Option<&ModeBuckets>) -> bool {
    bucket.is_some_and(|bucket| {
        bucket.permissive.is_empty()
            && (!bucket.restrictive.is_empty()
                || !bucket.subtractions.is_empty()
                || !bucket.role_limited.is_empty())
    })
}

/// Commands a barrier refuses outright, so coverage is read off what grants rather than
/// off which relation exists. A command denies as soon as one of its targets does.
pub(crate) fn commands_denied_by_barriers_alone(
    action_buckets: &BTreeMap<ActionTarget, ModeBuckets>,
) -> Vec<&'static str> {
    action_relation_commands()
        .into_iter()
        .filter(|(_, _, targets)| {
            targets
                .iter()
                .any(|target| barriers_alone(action_buckets.get(target)))
        })
        .map(|(_, command, _)| command)
        .collect()
}

/// Commands the schema's permissive policies on one table cover, whatever their
/// confidence. The filtered policy set cannot answer this, and the answer decides
/// whether a denied command is a coverage gap in `PostgreSQL` or in the translation.
pub(crate) fn commands_a_permissive_policy_covers<P: PolicyLike>(
    declared: &[&P],
    db: &P::DB,
) -> BTreeSet<&'static str> {
    let mut commands = BTreeSet::new();
    for policy in declared {
        let reached = policy_clause_targets(*policy, db);
        commands.extend(
            action_relation_commands()
                .into_iter()
                .filter(|(_, _, needed)| needed.iter().all(|target| reached.contains(target)))
                .map(|(_, command, _)| command),
        );
    }
    commands
}

/// Permissive policies that name a command without storing the clause it reads,
/// as `(policy, commands, clause)`. `PostgreSQL` finds no qual for those, so the
/// policy admits nothing and the schema reads as if it covered them.
pub(crate) fn policies_missing_a_clause<P: PolicyLike>(
    declared: &[&P],
    db: &P::DB,
) -> Vec<(String, String, &'static str)> {
    let mut missing = Vec::new();
    for policy in declared {
        let command = policy_command(policy.command());
        // An illegal clause gets its own note, and an absent-clause line beside it
        // would send the operator hunting for a legal policy that never existed.
        let has_using = using_shape(*policy, db).is_some();
        let has_check = check_shape(*policy, db).is_some();
        if clause_illegal_for_command(command, has_using, has_check).is_some() {
            continue;
        }
        if has_using {
            continue;
        }
        let checks: BTreeSet<ActionTarget> = with_check_targets(command).into_iter().collect();
        let applies: BTreeSet<ActionTarget> = using_targets(command)
            .into_iter()
            .chain(checks.iter().copied())
            .collect();

        let mut needs_using = Vec::new();
        let mut needs_check = Vec::new();
        for (_, named, targets) in action_relation_commands() {
            if !targets.iter().any(|target| applies.contains(target)) {
                continue;
            }
            // A command every one of whose targets a WITH CHECK feeds, which is the
            // INSERT, survives a missing USING.
            if targets.iter().all(|target| checks.contains(target)) {
                needs_check.push(named);
            } else {
                needs_using.push(named);
            }
        }

        if !needs_using.is_empty() {
            missing.push((policy.name().to_string(), needs_using.join(", "), "USING"));
        }
        if !needs_check.is_empty() && !has_check {
            missing.push((
                policy.name().to_string(),
                needs_check.join(", "),
                "WITH CHECK",
            ));
        }
    }
    missing
}

/// Deny every action relation no policy produced, returning the denied commands.
pub(crate) fn fill_uncovered_actions_with_deny(table_plan: &mut TypePlan) -> Vec<&'static str> {
    let missing: Vec<(RelationName, &'static str)> = action_relation_commands()
        .into_iter()
        .filter(|(relation, _, _)| !table_plan.computed_relations.contains_key(relation))
        .map(|(relation, command, _)| (relation, command))
        .collect();
    if missing.is_empty() {
        return Vec::new();
    }
    let deny = deny_expr(table_plan);
    for (relation, _) in &missing {
        table_plan.set_computed(relation.clone(), deny.clone());
    }
    missing.into_iter().map(|(_, command)| command).collect()
}

/// Answer for `INSERT ... ON CONFLICT ... DO UPDATE`, which updates the conflicting
/// row and so needs the UPDATE policies too. Runs once the actions are final, and
/// is left out wherever it would add no requirement to `can_insert`.
pub(crate) fn define_upsert_relations(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    for plan in all_types.values_mut() {
        let Some(insert) = plan.computed_relations.get(&can_insert_relation()) else {
            continue;
        };
        let adds_nothing = grants_nothing(insert, plan, &mut BTreeSet::new())
            || plan
                .computed_relations
                .get(&can_update_relation())
                .is_some_and(|update| update == insert);
        if adds_nothing {
            continue;
        }
        plan.set_computed(
            can_upsert_relation(),
            UsersetExpr::Intersection(vec![
                UsersetExpr::Computed(can_insert_relation()),
                UsersetExpr::Computed(can_update_relation()),
            ]),
        );
    }
}

/// Answer for a locking read, which `PostgreSQL` filters by the `UPDATE` policies'
/// `USING` clause as well as the `SELECT` policies. That is the `USING` half where
/// the two `UPDATE` clauses differ, and `can_update` itself where they agree or
/// where nothing admits an update. Runs once the actions are final.
pub(crate) fn define_locking_read_relations(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    for plan in all_types.values_mut() {
        if !plan.computed_relations.contains_key(&can_update_relation()) {
            continue;
        }
        let answers = if plan
            .computed_relations
            .contains_key(&can_update_using_relation())
        {
            can_update_using_relation()
        } else {
            can_update_relation()
        };
        plan.set_computed(
            can_select_for_update_relation(),
            UsersetExpr::Computed(answers),
        );
    }
}

/// Every type carries `can_update_without_reading`, because an action relation nobody
/// defined reads as "the consumer decides". Where no rule admits an update it points at
/// `can_update`, which is already the denial.
pub(crate) fn define_blanket_update_relations(all_types: &mut BTreeMap<TypeName, TypePlan>) {
    for plan in all_types.values_mut() {
        if plan
            .computed_relations
            .contains_key(&can_update_without_reading_relation())
            || !plan.computed_relations.contains_key(&can_update_relation())
        {
            continue;
        }
        plan.set_computed(
            can_update_without_reading_relation(),
            UsersetExpr::Computed(can_update_relation()),
        );
    }
}
