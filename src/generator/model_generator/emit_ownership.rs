//! Emission for the patterns one column of the row decides.
//!
//! Ownership by a column, an array element or a jsonb field, the public flag, a constant, an
//! attribute guard, and the refusal a clause nobody classified earns.

use super::*;

/// A relation whose subjects are named by one column of the row, and the tuples that fill it.
///
/// P3, P11 and P12 are one shape: mint an ownership relation, declare it direct, and load it
/// from the row unless nothing names the row. Only the memo key, the name, and which
/// `TupleSource` reads the column differ, so the source arrives as a constructor.
pub(crate) fn emit_row_ownership<DB: DatabaseLike>(
    memo_key: &str,
    // What the relation is named after: a column, or a jsonb path joined into one name.
    name_source: &str,
    missing_what: &str,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    source: impl FnOnce(Vec<ColumnName>, RelationName) -> TupleSource,
) -> UsersetExpr {
    let ownership = table_plan.ownership_relation(memo_key, name_source);
    let relation = table_plan.ensure_direct(
        ownership,
        vec![DirectSubject::Type(table_plan.well_known.user.clone())],
    );
    let Some(identity_cols) = resolve_row_identity(ctx.source_table, ctx.db) else {
        skip_source_without_row_identity(table_plan, ctx.source_table, missing_what, ctx.db);
        return deny_expr(table_plan);
    };
    table_plan.add_source(source(identity_cols, relation.clone()));
    UsersetExpr::Computed(relation)
}

/// A column of the row naming the caller, which is P3 and a caller set the caller's
/// subjects complete.
pub(crate) fn emit_direct_ownership<DB: DatabaseLike>(
    column: &ColumnName,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    emit_row_ownership(
        column.as_str(),
        column.as_str(),
        "ownership tuples",
        ctx,
        table_plan,
        |identity_cols, relation| TupleSource::DirectOwnership {
            table: ctx.source_table.clone(),
            identity_cols,
            owner_col: column.clone(),
            relation,
        },
    )
}

/// Structural identity of a boolean flag gate: every P6 spelling loads `col = TRUE`.
fn flag_gate_key(column: &ColumnName) -> String {
    format!("flag:{}:{}", column.as_str().len(), column.as_str())
}

/// Structural identity of a literal attribute gate, never its display SQL.
///
/// `None` for a variant this build cannot name stably, which falls closed rather
/// than minting a gate whose key could collide with another predicate's.
fn attribute_gate_key(predicate: &AttributePredicate) -> Option<String> {
    let column = predicate.column.as_str();
    let test = match &predicate.test {
        AttributeTest::Compare { operator, value } => {
            format!("{}:{}", operator.gate_token(), literal_gate_key(value)?)
        }
        AttributeTest::In(values) => {
            let mut key = format!("in:{}:", values.len());
            for value in values {
                key.push_str(&literal_gate_key(value)?);
            }
            key
        }
    };
    Some(format!("attr:{}:{column}:{test}", column.len()))
}

/// One literal, length-prefixed so a list of them concatenates without ambiguity.
fn literal_gate_key(value: &AttributeLiteral) -> Option<String> {
    Some(match value {
        AttributeLiteral::Text(text) => format!("t{}:{text}", text.len()),
        AttributeLiteral::Number(number) => format!("n{}:{number}", number.len()),
        AttributeLiteral::Boolean(value) => format!("b:{value}"),
        _ => return None,
    })
}

/// The wildcard a boolean flag opens, gated by its own relation, and the tuples that
/// carry it.
pub(crate) fn emit_boolean_flag<DB: DatabaseLike>(
    boolean_flag: &BooleanFlag,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    let BooleanFlag { column, .. } = boolean_flag;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let Some(identity_cols) = resolve_row_identity(source_table, db) else {
        skip_source_without_row_identity(table_plan, source_table, "public-flag tuples", db);
        return deny_expr(table_plan);
    };
    let wildcard = vec![DirectSubject::Wildcard(table_plan.well_known.user.clone())];
    let relation = table_plan.gate_relation(
        &flag_gate_key(column),
        public_flag_relation_name(column.as_str()),
        wildcard,
    );
    table_plan.add_source(TupleSource::PublicFlag {
        table: source_table.clone(),
        identity_cols,
        flag_col: column.clone(),
        relation: relation.clone(),
    });
    UsersetExpr::Computed(relation)
}

/// Emit the wildcard only for rows whose strict-function arguments are present.
pub(crate) fn emit_row_presence_gate<DB: DatabaseLike>(
    columns: &[ColumnName],
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    let source_table = ctx.source_table;
    let Some(identity_cols) = resolve_row_identity(source_table, ctx.db) else {
        skip_source_without_row_identity(
            table_plan,
            source_table,
            "strict-function presence tuples",
            ctx.db,
        );
        return deny_expr(table_plan);
    };
    let relation = table_plan.ensure_direct(
        row_presence_relation_name(columns),
        vec![DirectSubject::Wildcard(table_plan.well_known.user.clone())],
    );
    table_plan.add_source(TupleSource::RowPresenceGate {
        table: source_table.clone(),
        identity_cols,
        relation: relation.clone(),
        columns: columns.to_vec(),
    });
    UsersetExpr::Computed(relation)
}

/// An attribute guard, as a wildcard the row decides or a condition the request completes.
pub(crate) fn emit_attribute_condition<DB: DatabaseLike>(
    attribute_condition: &AttributeCondition,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let AttributeCondition {
        column,
        predicate,
        request_predicate,
        ..
    } = attribute_condition;
    let policy_name = ctx.policy_name;
    let db = ctx.db;
    let source_table = ctx.source_table;
    let settings = ctx.settings;
    // A value only the request knows cannot be decided by a tuple, so the
    // guard becomes a condition the service evaluates per check, and the tuple
    // carries the row's own value as its context.
    if let Some(request) = request_predicate {
        if let Some(expr) = conditional_gate_expr(
            request,
            policy_name,
            source_table,
            table_plan,
            ctx.condition_parameters,
            db,
            &settings.request_time_parameter,
        ) {
            return expr;
        }
    }
    // A literal constant is decided by the row, so the guard generalises the
    // boolean flag: emit the wildcard and let the tuple query qualify rows.
    // The wildcard is only correct because the compared value is a literal.
    // A caller-derived one would grant everyone access to rows scoped to one
    // caller, so it arrives here as `None` and keeps falling closed.
    if let Some(predicate) = predicate {
        // A predicate whose key cannot be named stably falls through to the
        // standalone-attribute refusal below rather than minting a collidable gate.
        if let Some(key) = attribute_gate_key(predicate) {
            let Some(identity_cols) = resolve_row_identity(source_table, db) else {
                skip_source_without_row_identity(
                    table_plan,
                    source_table,
                    "attribute-gate tuples",
                    db,
                );
                return deny_expr(table_plan);
            };
            let wildcard = vec![DirectSubject::Wildcard(table_plan.well_known.user.clone())];
            let relation = table_plan.gate_relation(
                &key,
                attribute_gate_relation_name(predicate.column.as_str(), &key),
                wildcard,
            );
            table_plan.add_source(TupleSource::AttributeGate {
                table: source_table.clone(),
                identity_cols,
                predicate: predicate.clone(),
                relation: relation.clone(),
            });
            return UsersetExpr::Computed(relation);
        }
    }
    notes.push(TranslationNote::StandaloneAttributePolicy {
        policy: policy_name.to_string(),
        column: column.clone(),
    });
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::StandaloneAttribute {
            table: source_table.clone(),
            column: column.clone(),
        },
    });
    deny_expr(table_plan)
}

/// Everyone or nobody, which is what a constant clause grants.
pub(crate) fn emit_constant_bool<DB: DatabaseLike>(
    constant_bool: &ConstantBool,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
) -> UsersetExpr {
    let ConstantBool { value } = constant_bool;
    let db = ctx.db;
    let source_table = ctx.source_table;
    if *value {
        let Some(identity_cols) = resolve_row_identity(source_table, db) else {
            skip_source_without_row_identity(table_plan, source_table, "constant-TRUE tuples", db);
            return deny_expr(table_plan);
        };
        let relation = table_plan.ensure_direct(
            public_relation(),
            vec![DirectSubject::Wildcard(table_plan.well_known.user.clone())],
        );
        table_plan.add_source(TupleSource::ConstantTrue {
            table: source_table.clone(),
            identity_cols,
            relation: relation.clone(),
        });
        UsersetExpr::Computed(relation)
    } else {
        deny_expr(table_plan)
    }
}

/// A refusal: the clause is reported and the command falls closed.
pub(crate) fn emit_unclassified<DB: DatabaseLike>(
    unclassified: &UnclassifiedExpr,
    ctx: &PatternCtx<'_, DB>,
    table_plan: &mut TypePlan,
    notes: &mut Vec<TranslationNote>,
) -> UsersetExpr {
    let UnclassifiedExpr { reason, .. } = unclassified;
    let policy_name = ctx.policy_name;
    let source_table = ctx.source_table;
    notes.push(TranslationNote::ExpressionRefused {
        policy: policy_name.to_string(),
        reason: reason.clone(),
    });
    table_plan.add_source(TupleSource::Skipped {
        reason: SkippedTuples::UnclassifiedExpression {
            table: source_table.clone(),
            reason: reason.clone(),
        },
    });
    deny_expr(table_plan)
}
