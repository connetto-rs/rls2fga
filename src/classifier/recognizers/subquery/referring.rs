use super::indirect::plain_relation_sources;
use super::*;

/// The guarded row admitted by some row of another table naming it by its key, read
/// through `EXISTS` or through the `IN` spellings' rewrite into it:
/// `id IN (SELECT i.organization_id FROM invitations i WHERE i.accepted_by_id IS NULL)`.
///
/// The subquery reads those rows under their own row security, so a referring row admits
/// the guarded row only where the caller can read it and it passes the subquery's rule.
/// A referring table enforcing no row security leaves no read to inherit, and a caller
/// column on it is a membership, which [`recognize_p4`] reads.
pub fn recognize_p31_referring_rows<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: PolicyCommand,
    state: &ExpansionState,
) -> Option<ClassifiedExpr> {
    let rewritten = membership_exists_from_in_subquery(expr, db, registry, outer_table);
    let select = readable_exists_select(rewritten.as_ref().unwrap_or(expr))?;
    let mut candidate = referring_rows_candidate(select, db, outer_table)?;
    if !parent_enforces_row_security(db, &candidate.referring_table) {
        return None;
    }
    let inner = candidate.take_rule(db, registry, command, state);
    if matches!(inner.pattern, PatternClass::Unknown(_)) {
        return None;
    }
    Some(ClassifiedExpr {
        confidence: inner.confidence,
        pattern: PatternClass::P31ReferringRows(ReferringRows {
            referring_table: candidate.referring_table,
            referring_columns: candidate.referring_columns,
            inner_pattern: Box::new(inner),
        }),
    })
}

/// Why the rule referring rows have to pass refuses, where the rows are otherwise read as
/// [`recognize_p31_referring_rows`] reads them.
pub(crate) fn diagnose_p31_referring_rows<DB: DatabaseLike>(
    expr: &Expr,
    db: &DB,
    registry: &FunctionRegistry,
    outer_table: &str,
    command: PolicyCommand,
    state: &ExpansionState,
) -> Option<String> {
    let rewritten = membership_exists_from_in_subquery(expr, db, registry, outer_table);
    let select = readable_exists_select(rewritten.as_ref().unwrap_or(expr))?;
    let mut candidate = referring_rows_candidate(select, db, outer_table)?;
    if !parent_enforces_row_security(db, &candidate.referring_table) {
        return None;
    }
    match candidate.take_rule(db, registry, command, state).pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => Some(format!(
            "The rule the rows of '{}' naming this row have to pass is not translatable: \
             {reason}",
            candidate.table_name
        )),
        _ => None,
    }
}

/// One table whose rows name the guarded row by its whole key.
struct ReferringRowsCandidate {
    referring_table: TableId,
    /// The spelling the subquery names the table by.
    table_name: String,
    alias: Option<String>,
    /// Columns of the referring table, in the order of the guarded key.
    referring_columns: Vec<ColumnName>,
    /// Every conjunct but the correlations.
    rule: Option<Expr>,
}

impl ReferringRowsCandidate {
    /// The rule classified on the referring table, refused where it reads another relation.
    fn take_rule<DB: DatabaseLike>(
        &mut self,
        db: &DB,
        registry: &FunctionRegistry,
        command: PolicyCommand,
        state: &ExpansionState,
    ) -> ClassifiedExpr {
        let Some(mut rule) = self.rule.take() else {
            return ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
                confidence: ConfidenceLevel::A,
            };
        };
        strip_qualifier_from_expr_deep(&mut rule, &self.table_name, self.alias.as_deref());
        if predicate_references_other_table(&rule, &self.table_name, self.alias.as_deref()) {
            return ClassifiedExpr {
                pattern: PatternClass::Unknown(UnclassifiedExpr {
                    sql_text: rule.to_string(),
                    reason: format!(
                        "it reads a relation other than '{}', which one referring row cannot \
                         carry",
                        self.table_name
                    ),
                }),
                confidence: ConfidenceLevel::D,
            };
        }
        crate::classifier::policy_classifier::classify_expr_in_state(
            &rule,
            db,
            registry,
            &self.table_name,
            command,
            state,
        )
    }
}

/// The one plain table `select` scans, where its correlations with `outer_table` pair a
/// column of it with each column of the guarded key.
///
/// A self reference is left alone: `PostgreSQL` refuses a policy reading its own table
/// under row security as infinite recursion.
fn referring_rows_candidate<DB: DatabaseLike>(
    select: &Select,
    db: &DB,
    outer_table: &str,
) -> Option<ReferringRowsCandidate> {
    let sources = plain_relation_sources(select)?;
    let Ok([(_, source)]) = <[_; 1]>::try_from(sources) else {
        return None;
    };
    let referring_table = resolve_table_id(db, &source.table_name)?;
    let guarded = resolve_table_id(db, outer_table)?;
    if referring_table == guarded {
        return None;
    }
    let outer_cols = stored_column_names(lookup_table(db, outer_table)?, db);
    let referring_cols = stored_column_names(lookup_table(db, &source.table_name)?, db);

    let mut predicates = Vec::new();
    flatten_and_predicates(select.selection.as_ref()?, &mut predicates);
    let mut pairs: Vec<(ColumnName, ColumnName)> = Vec::new();
    let mut rule = Vec::new();
    for predicate in predicates {
        match extract_parent_join_columns(
            predicate,
            outer_table,
            &outer_cols,
            &source.table_name,
            source.alias.as_deref(),
            &referring_cols,
        ) {
            Some((outer, referring))
                if !pairs
                    .iter()
                    .any(|pair| pair.0 == referring && pair.1 == outer) =>
            {
                pairs.push((referring, outer));
            }
            Some(_) => {}
            None => rule.push(predicate.clone()),
        }
    }
    let (pairs, key_len) = pairs_in_key_order(pairs, &resolve_row_identity(&guarded, db)?)?;
    if pairs.len() != key_len {
        return None;
    }
    Some(ReferringRowsCandidate {
        referring_table,
        table_name: source.table_name,
        alias: source.alias,
        referring_columns: pairs.into_iter().map(|(referring, _)| referring).collect(),
        rule: combine_predicates_with_and(rule),
    })
}
