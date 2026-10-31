use super::*;
use crate::types::AttributeLiteral;

/// Recognize membership reached through a closure table.
pub fn recognize_p19_indirect_membership<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    state: &ExpansionState,
) -> Option<ClassifiedExpr> {
    let rewritten = membership_exists_from_in_subquery(expr, registry, outer_table);
    let select = readable_exists_select(rewritten.as_ref().unwrap_or(expr))?;
    let sources = plain_relation_sources(select)?;

    let outer_id = resolve_table_id(db, outer_table)?;
    let outer_columns = table_column_names(db, lookup_table_id(db, &outer_id)?)?;

    let (link, far, mut far_select, link_conjuncts, joined_on) = match sources.as_slice() {
        [(_, source)] => {
            let link = p19_table(db, source)?;
            let (far_expr, far_conjunct) =
                p19_far_exists(select, &link, outer_table, &outer_columns, registry)?;
            let inner_select = readable_exists_select(&far_expr)?;
            let far_sources = plain_relation_sources(inner_select)?;
            let [(_, far_source)] = far_sources.as_slice() else {
                return None;
            };
            let far = p19_table(db, far_source)?;
            let mut link_conjuncts = Vec::new();
            flatten_and_predicates(select.selection.as_ref()?, &mut link_conjuncts);
            link_conjuncts.retain(|conjunct| !core::ptr::eq(*conjunct, far_conjunct));
            let far_select = inner_select.clone();
            (link, far, far_select, link_conjuncts, None)
        }
        [(first_factor, first), (second_factor, second)] => {
            let on = p19_join_on(select)?;
            let mut conjuncts = Vec::new();
            if let Some(selection) = select.selection.as_ref() {
                flatten_and_predicates(selection, &mut conjuncts);
            }
            flatten_and_predicates(on, &mut conjuncts);
            let first_table = p19_table(db, first)?;
            let second_table = p19_table(db, second)?;
            let first_is_link = p19_link_source(
                &first_table,
                &second_table,
                &conjuncts,
                outer_table,
                &outer_columns,
            )?;
            let (link, far, factor) = if first_is_link {
                (first_table, second_table, *second_factor)
            } else {
                (second_table, first_table, *first_factor)
            };
            let mut far_select = select.clone();
            far_select.from = vec![TableWithJoins {
                relation: factor.clone(),
                joins: vec![],
            }];
            (link, far, far_select, vec![], Some(on))
        }
        _ => return None,
    };

    // Reading the guarded table would recurse through its policy.
    let link_id = resolve_table_id(db, &link.name)?;
    let far_id = resolve_table_id(db, &far.name)?;
    if link_id == far_id {
        return None;
    }
    if !state.reading_as_owner()
        && (written_tables_are_same(db, &link.name, outer_table).unwrap_or(true)
            || written_tables_are_same(db, &far.name, outer_table).unwrap_or(true))
    {
        return None;
    }

    let mut link_pairs: Vec<MembershipJoinPair> = Vec::new();
    let mut link_residuals: Vec<&Expr> = Vec::new();
    let mut far_pairs: Vec<(ColumnName, ColumnName)> = Vec::new();
    let mut far_residual_conjuncts: Vec<Expr> = Vec::new();
    let mut far_conjuncts = Vec::new();
    if let Some(selection) = &far_select.selection {
        flatten_and_predicates(selection, &mut far_conjuncts);
    }
    if let Some(on) = joined_on {
        flatten_and_predicates(on, &mut far_conjuncts);
    }

    let conjuncts = link_conjuncts
        .into_iter()
        .map(|conjunct| (conjunct, None))
        .chain(
            far_conjuncts
                .into_iter()
                .map(|conjunct| (conjunct, Some(&far))),
        );
    for (conjunct, far_scope) in conjuncts {
        let role = p19_conjunct_role(conjunct, &link, far_scope, outer_table, &outer_columns)?;
        match role {
            P19Role::LinkPair(pair) if !link_pairs.contains(&pair) => link_pairs.push(pair),
            P19Role::LinkPair(_) => {}
            P19Role::FarPair {
                join_column,
                outer_column,
            } => {
                if let Some((join, outer)) = far_pairs
                    .iter()
                    .find(|(join, outer)| *join == join_column || *outer == outer_column)
                {
                    if *join != join_column || *outer != outer_column {
                        return None;
                    }
                } else {
                    far_pairs.push((join_column, outer_column));
                }
                far_residual_conjuncts.push(conjunct.clone());
            }
            P19Role::LinkResidual => link_residuals.push(conjunct),
            P19Role::FarResidual => {
                let mut stripped = conjunct.clone();
                strip_qualifier_from_expr(&mut stripped, &link.name, link.alias.as_deref());
                if p19_reads_link_deep(&stripped, &link) {
                    return None;
                }
                far_residual_conjuncts.push(stripped);
            }
        }
    }

    if link_pairs.is_empty() || far_pairs.is_empty() {
        return None;
    }
    if far_pairs
        .iter()
        .any(|(_, outer)| !link.columns.iter().any(|name| name == outer.as_str()))
    {
        return None;
    }

    // Both foreign keys must name the same owner key in the same positions.
    let link_owner_hosts: Vec<ColumnName> =
        far_pairs.iter().map(|(_, outer)| outer.clone()).collect();
    let (owner_id, owner_map) = owner_key_of(db, &link_id, &link_owner_hosts)?;
    let far_owner_hosts: Vec<ColumnName> = far_pairs.iter().map(|(join, _)| join.clone()).collect();
    let (far_owner_id, far_map) = owner_key_of(db, &far_id, &far_owner_hosts)?;
    if far_owner_id != owner_id
        || owner_map.len() != far_map.len()
        || owner_map
            .iter()
            .zip(&far_map)
            .any(|((link_key, link_host), (far_key, far_host))| {
                link_key != far_key
                    || !far_pairs.iter().any(|(join, outer)| {
                        join.as_str() == far_host && outer.as_str() == link_host
                    })
            })
    {
        return None;
    }

    let (link_pairs, pairing) =
        resolve_membership_pairing(link_pairs, &link_id, &outer_id, db).ok()?;
    if !match pairing {
        MembershipPairing::SelfKeyed => true,
        MembershipPairing::ForeignKey { parent_table } => parent_table == outer_id,
        MembershipPairing::Single => false,
    } {
        return None;
    }

    let link_table = lookup_table_id(db, &link_id)?;
    let link_zoned = session_zoned_columns(link_table, db);
    let link_scope = MembershipScope {
        table: &link.name,
        alias: link.alias.as_deref(),
        columns: &link.columns,
        guarded_table: outer_table,
    };
    let mut link_extras = Vec::new();
    for conjunct in &link_residuals {
        let mut normalized = (*conjunct).clone();
        strip_qualifier_from_expr(&mut normalized, &link.name, link.alias.as_deref());
        let relations =
            residual_relations(&mut normalized, Some(db), registry, &link_scope, state)?;
        let residual = residual_predicate_reading(&normalized, relations);
        // A request filter here would gate every member of the owner.
        if residual.request.is_some() {
            return None;
        }
        if residual.relations.is_empty()
            && residual.request.is_none()
            && !conjunct_reads_only_the_row(&normalized, &link.columns, &link_zoned)
        {
            return None;
        }
        link_extras.push(residual);
    }

    let (far_selection, in_lists) = split_far_in_lists(&far_residual_conjuncts);
    far_select.selection = combine_predicates_with_and(far_selection);
    let far_scope = MembershipScope {
        table: &far.name,
        alias: far.alias.as_deref(),
        columns: &far.columns,
        guarded_table: link.alias.as_deref().unwrap_or(&link.name),
    };
    let far_zoned = session_zoned_columns(lookup_table_id(db, &far_id)?, db);
    let predicates = analyze_membership_predicates(
        &far_select,
        &far.name,
        far.alias.as_deref(),
        &far.columns,
        registry,
    );
    let MembershipColumns {
        user_column,
        member_match,
        extra_predicates,
        ..
    } = extract_membership_columns_with_analysis(
        &far_select,
        &far_scope,
        Some(db),
        &predicates,
        registry,
        state,
    )?;
    if !matches!(member_match, MemberMatch::Caller) {
        return None;
    }

    // Tuple keys follow the owner's primary-key order.
    let owner_columns: Vec<ColumnName> = owner_map
        .into_iter()
        .map(|(_, host)| ColumnName::from_stored(host))
        .collect();
    let far_membership_pairs: Vec<MembershipJoinPair> = far_map
        .into_iter()
        .map(|(key, host)| MembershipJoinPair {
            join_column: ColumnName::from_stored(host),
            outer_column: ColumnName::from_stored(key),
        })
        .collect();
    let memberships: Vec<ExistsMembership> = far_variant_extras(
        extra_predicates.into_conjuncts(),
        &in_lists,
        &far_scope,
        db,
        registry,
        state,
        &far_zoned,
    )?
    .into_iter()
    .map(|extra_predicates| ExistsMembership {
        join_table: far_id.clone(),
        pairs: far_membership_pairs.clone(),
        user_column: user_column.clone(),
        extra_predicates,
    })
    .collect();

    Some(ClassifiedExpr {
        pattern: PatternClass::P19IndirectMembership(IndirectMembership {
            link_table: link_id,
            pairs: link_pairs,
            owner_table: owner_id,
            owner_columns,
            memberships,
            extra_predicates: ResidualPredicates::new(link_extras),
        }),
        confidence: ConfidenceLevel::B,
    })
}

fn table_column_names<DB: DatabaseLike>(db: &DB, table: &DB::Table) -> Option<Vec<String>> {
    let columns = table.columns(db).ok()?;
    Some(
        columns
            .map(|column| column.stored_column_name().into_owned())
            .collect(),
    )
}

fn primary_key_columns<DB: DatabaseLike>(db: &DB, table: &DB::Table) -> Option<Vec<String>> {
    let key = table.primary_key_columns(db).ok()?;
    Some(
        key.map(|column| column.stored_column_name().into_owned())
            .collect(),
    )
}

struct P19Table {
    name: String,
    alias: Option<String>,
    columns: Vec<String>,
}

fn p19_table<DB: DatabaseLike>(db: &DB, source: &RelationSource) -> Option<P19Table> {
    Some(P19Table {
        name: source.table_name.clone(),
        alias: source.alias.clone(),
        columns: table_column_names(db, lookup_table(db, &source.table_name)?)?,
    })
}

fn plain_relation_sources(select: &Select) -> Option<Vec<(&TableFactor, RelationSource)>> {
    let mut sources = Vec::new();
    for from in &select.from {
        sources.push((&from.relation, plain_relation_factor(&from.relation)?));
        for join in &from.joins {
            sources.push((&join.relation, plain_relation_factor(&join.relation)?));
        }
    }
    Some(sources)
}

fn plain_relation_factor(factor: &TableFactor) -> Option<RelationSource> {
    let TableFactor::Table {
        name: _,
        alias,
        args: None,
        with_hints,
        version: None,
        with_ordinality: false,
        partitions,
        json_path: None,
        sample: None,
        index_directives,
        inheritance: None | Some(TableInheritance::IncludeDescendants),
    } = factor
    else {
        return None;
    };
    if !with_hints.is_empty()
        || !partitions.is_empty()
        || !index_directives.is_empty()
        || alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
    {
        return None;
    }
    relation_source_from_table_factor(factor)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum P19Side {
    Link,
    Far,
    Guarded,
    Other,
}

fn p19_side(
    qualifier: Option<&str>,
    name: &str,
    link: &P19Table,
    far: Option<&P19Table>,
    outer_table: &str,
    outer_columns: &[String],
) -> P19Side {
    if let Some(qualifier) = qualifier {
        if qualifier_matches_table(qualifier, &link.name, link.alias.as_deref()) {
            return P19Side::Link;
        }
        if far
            .is_some_and(|far| qualifier_matches_table(qualifier, &far.name, far.alias.as_deref()))
        {
            return P19Side::Far;
        }
        if qualifier_matches_table(qualifier, outer_table, None) {
            return P19Side::Guarded;
        }
        return P19Side::Other;
    }
    let mut holders = 0;
    if link.columns.iter().any(|column| column == name) {
        holders += 1;
    }
    if far.is_some_and(|far| far.columns.iter().any(|column| column == name)) {
        holders += 1;
    }
    if outer_columns.iter().any(|column| column == name) {
        holders += 1;
    }
    match holders {
        1 => {
            if far.is_some_and(|far| far.columns.iter().any(|column| column == name)) {
                P19Side::Far
            } else if link.columns.iter().any(|column| column == name) {
                P19Side::Link
            } else {
                P19Side::Guarded
            }
        }
        _ => P19Side::Other,
    }
}

enum P19Role {
    LinkPair(MembershipJoinPair),
    FarPair {
        join_column: ColumnName,
        outer_column: ColumnName,
    },
    LinkResidual,
    FarResidual,
}

fn p19_conjunct_role(
    conjunct: &Expr,
    link: &P19Table,
    far: Option<&P19Table>,
    outer_table: &str,
    outer_columns: &[String],
) -> Option<P19Role> {
    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = unparenthesize(conjunct)
    {
        if let (Some((left_qual, left_col)), Some((right_qual, right_col))) = (
            extract_qualified_column(left).filter(|_| !is_sql_current_user_keyword_expr(left)),
            extract_qualified_column(right).filter(|_| !is_sql_current_user_keyword_expr(right)),
        ) {
            let sides = (
                p19_side(
                    left_qual.as_deref(),
                    left_col.as_str(),
                    link,
                    far,
                    outer_table,
                    outer_columns,
                ),
                p19_side(
                    right_qual.as_deref(),
                    right_col.as_str(),
                    link,
                    far,
                    outer_table,
                    outer_columns,
                ),
            );
            return match sides {
                (P19Side::Link, P19Side::Guarded) => Some(P19Role::LinkPair(MembershipJoinPair {
                    join_column: left_col,
                    outer_column: right_col,
                })),
                (P19Side::Guarded, P19Side::Link) => Some(P19Role::LinkPair(MembershipJoinPair {
                    join_column: right_col,
                    outer_column: left_col,
                })),
                (P19Side::Far, P19Side::Link) | (P19Side::Link, P19Side::Far) => {
                    let (join_column, outer_column) = match sides.0 {
                        P19Side::Far => (left_col, right_col),
                        _ => (right_col, left_col),
                    };
                    Some(P19Role::FarPair {
                        join_column,
                        outer_column,
                    })
                }
                (P19Side::Link, P19Side::Link) => Some(P19Role::LinkResidual),
                (P19Side::Far, P19Side::Far) => Some(P19Role::FarResidual),
                // Neither tuple source can carry a predicate spanning these scopes.
                _ => None,
            };
        }
    }
    let mut sides: BTreeSet<P19Side> = BTreeSet::new();
    let mut collect = TopLevelOnly::top_level(|expr: &Expr| {
        if is_sql_current_user_keyword_expr(expr) {
            return ControlFlow::Continue(());
        }
        let (qualifier, name) = match expr {
            Expr::CompoundIdentifier(parts) => match parts.as_slice() {
                [.., qualifier, last] => {
                    (Some(stored_ident_name(qualifier)), stored_ident_name(last))
                }
                _ => return ControlFlow::Continue(()),
            },
            Expr::Identifier(ident) => (None, stored_ident_name(ident)),
            _ => return ControlFlow::Continue(()),
        };
        sides.insert(p19_side(
            qualifier.as_deref(),
            &name,
            link,
            far,
            outer_table,
            outer_columns,
        ));
        ControlFlow::Continue(())
    });
    let _ = conjunct.visit(&mut collect);
    if sides.contains(&P19Side::Other) || sides.contains(&P19Side::Guarded) || sides.len() == 2 {
        return None;
    }
    if sides.contains(&P19Side::Far) {
        return Some(P19Role::FarResidual);
    }
    Some(P19Role::LinkResidual)
}

fn p19_far_exists<'a>(
    select: &'a Select,
    link: &P19Table,
    outer_table: &str,
    outer_columns: &[String],
    registry: &FunctionRegistry,
) -> Option<(Expr, &'a Expr)> {
    let mut conjuncts = Vec::new();
    flatten_and_predicates(select.selection.as_ref()?, &mut conjuncts);
    let mut found: Option<(Expr, &Expr)> = None;
    for conjunct in conjuncts {
        let candidate = if let Expr::Exists { negated: false, .. } = unparenthesize(conjunct) {
            Some(conjunct.clone())
        } else {
            let Some((tested, _, _)) = membership_subquery_operands(conjunct) else {
                continue;
            };
            let Some((qualifier, column)) = extract_qualified_column(tested) else {
                continue;
            };
            let is_link = p19_side(
                qualifier.as_deref(),
                column.as_str(),
                link,
                None,
                outer_table,
                outer_columns,
            ) == P19Side::Link;
            membership_exists_from_in_subquery(conjunct, registry, &link.name).filter(|_| is_link)
        };
        if let Some(candidate) = candidate {
            if found.is_some() {
                return None;
            }
            found = Some((candidate, conjunct));
        }
    }
    found
}

fn p19_join_on(select: &Select) -> Option<&Expr> {
    let join = select.from.iter().flat_map(|from| &from.joins).next()?;
    if matches!(
        join.join_operator,
        JoinOperator::Inner(_) | JoinOperator::Join(_)
    ) {
        join_on_expr(&join.join_operator)
    } else {
        None
    }
}

fn p19_link_source(
    first: &P19Table,
    second: &P19Table,
    conjuncts: &[&Expr],
    outer_table: &str,
    outer_columns: &[String],
) -> Option<bool> {
    let mut chosen = None;
    for (link, far, first_is_link) in [(first, second, true), (second, first, false)] {
        let mut has_link_pair = false;
        let mut valid = true;
        for conjunct in conjuncts {
            match p19_conjunct_role(conjunct, link, Some(far), outer_table, outer_columns) {
                Some(P19Role::LinkPair(_)) => has_link_pair = true,
                Some(_) => {}
                None => {
                    valid = false;
                    break;
                }
            }
        }
        if valid && has_link_pair && chosen.replace(first_is_link).is_some() {
            return None;
        }
    }
    chosen
}

// Far residuals cannot depend on the closure row.
fn p19_reads_link_deep(conjunct: &Expr, link: &P19Table) -> bool {
    let mut reader = P19LinkReader {
        name: link.name.as_str(),
        alias: link.alias.as_deref(),
    };
    conjunct.visit(&mut reader).is_break()
}

struct P19LinkReader<'a> {
    name: &'a str,
    alias: Option<&'a str>,
}

impl Visitor for P19LinkReader<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if let Expr::CompoundIdentifier(parts) = expr {
            if let [.., qualifier, _] = parts.as_slice() {
                if qualifier_matches_table(
                    stored_ident_name(qualifier).as_ref(),
                    self.name,
                    self.alias,
                ) {
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Resolve a foreign key to its owner's columns in primary-key order.
pub(crate) fn owner_key_of<DB: DatabaseLike>(
    db: &DB,
    table: &TableId,
    hosts: &[ColumnName],
) -> Option<(TableId, Vec<(String, String)>)> {
    let meta = lookup_table_id(db, table)?;
    let host_names: BTreeSet<&str> = hosts.iter().map(ColumnName::as_str).collect();
    let mut found: Option<(TableId, Vec<(String, String)>)> = None;
    for fk in meta.foreign_keys(db).into_iter().flatten() {
        let Ok(fk_hosts) = fk.host_columns(db) else {
            continue;
        };
        let fk_hosts: Vec<String> = fk_hosts
            .map(|column| column.stored_column_name().into_owned())
            .collect();
        if fk_hosts.len() != hosts.len()
            || fk_hosts.iter().map(String::as_str).collect::<BTreeSet<_>>() != host_names
        {
            continue;
        }
        let (Ok(referenced_table), Ok(referenced)) =
            (fk.referenced_table(db), fk.referenced_columns(db))
        else {
            continue;
        };
        let referenced: Vec<String> = referenced
            .map(|column| column.stored_column_name().into_owned())
            .collect();
        let Some(referenced_key) = primary_key_columns(db, referenced_table) else {
            continue;
        };
        if referenced_key.is_empty()
            || referenced_key.len() != referenced.len()
            || referenced_key.iter().collect::<BTreeSet<_>>()
                != referenced.iter().collect::<BTreeSet<_>>()
        {
            continue;
        }
        let mapping = referenced_key
            .iter()
            .map(|key_column| {
                let position = referenced.iter().position(|column| column == key_column)?;
                Some((key_column.clone(), fk_hosts.get(position)?.clone()))
            })
            .collect::<Option<Vec<_>>>();
        let Some(mapping) = mapping else {
            continue;
        };
        let entry = (table_identity(referenced_table), mapping);
        if found.as_ref().is_some_and(|found| found != &entry) {
            return None;
        }
        found = Some(entry);
    }
    found
}

fn split_far_in_lists(conjuncts: &[Expr]) -> (Vec<Expr>, Vec<(Expr, Vec<Expr>)>) {
    let mut rest = Vec::new();
    let mut in_lists = Vec::new();
    for conjunct in conjuncts {
        match far_in_list(conjunct) {
            Some(list) => in_lists.push(list),
            None => rest.push(conjunct.clone()),
        }
    }
    (rest, in_lists)
}

fn far_in_list(conjunct: &Expr) -> Option<(Expr, Vec<Expr>)> {
    let Expr::In {
        expr: column,
        target: InTarget::List(items),
        negated: false,
        global: false,
    } = unparenthesize(conjunct)
    else {
        return None;
    };
    match column.as_ref() {
        Expr::Identifier(_) => {}
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {}
        _ => return None,
    }
    let mut values: Vec<Expr> = Vec::new();
    let mut seen: Vec<AttributeLiteral> = Vec::new();
    for item in items {
        let value = attribute_literal(item)?;
        if !seen.iter().any(|seen| seen == &value) {
            seen.push(value);
            values.push(item.clone());
        }
    }
    (!values.is_empty()).then_some((column.as_ref().clone(), values))
}

fn far_variant_extras<DB: DatabaseLike>(
    base: Vec<ResidualPredicate>,
    in_lists: &[(Expr, Vec<Expr>)],
    scope: &MembershipScope<'_>,
    db: &DB,
    registry: &FunctionRegistry,
    state: &ExpansionState,
    zoned: &[String],
) -> Option<Vec<ResidualPredicates>> {
    if in_lists.is_empty() {
        return Some(vec![ResidualPredicates::new(base)]);
    }
    let mut groups: Vec<Vec<ResidualPredicate>> = Vec::new();
    for (column, items) in in_lists {
        let mut group = Vec::new();
        for item in items {
            let mut equality = Expr::BinaryOp {
                left: Box::new(column.clone()),
                op: BinaryOperator::Eq,
                right: Box::new(item.clone()),
            };
            strip_qualifier_from_expr(&mut equality, scope.table, scope.alias);
            let relations = residual_relations(&mut equality, Some(db), registry, scope, state)?;
            let residual = residual_predicate_reading(&equality, relations);
            if residual.relations.is_empty()
                && residual.request.is_none()
                && !conjunct_reads_only_the_row(&equality, scope.columns, zoned)
            {
                return None;
            }
            group.push(residual);
        }
        groups.push(group);
    }
    let mut variants: Vec<Vec<ResidualPredicate>> = vec![Vec::new()];
    for group in groups {
        let mut next = Vec::new();
        for prefix in &variants {
            for extra in &group {
                let mut branch = Vec::with_capacity(prefix.len() + 1);
                branch.extend_from_slice(prefix);
                branch.push(extra.clone());
                next.push(branch);
            }
        }
        variants = next;
    }
    Some(
        variants
            .into_iter()
            .map(|extras| {
                let mut conjuncts = base.clone();
                conjuncts.extend(extras);
                ResidualPredicates::new(conjuncts)
            })
            .collect(),
    )
}
