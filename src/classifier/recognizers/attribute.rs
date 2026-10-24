use super::*;
use sqlparser::ast::{DataType, TimezoneInfo};

/// The guard as structure when the compared value is one only the request knows.
///
/// `expires_at > now()` is decided by the row and the clock together, so it becomes a
/// condition the authorization service evaluates per check rather than a tuple.
pub fn attribute_request_predicate(expr: &Expr) -> Option<AttributeRequestPredicate> {
    let Expr::BinaryOp { left, op, right } = unparenthesize(expr) else {
        return None;
    };
    let operator = attribute_operator(op)?;
    if let Some(column) = extract_column_name(left) {
        if let Some(side) = temporal_request_side(right) {
            if !is_user_related_column_name(column.as_str()) {
                return Some(AttributeRequestPredicate {
                    column,
                    operator,
                    request_value: RequestValue::StatementTimestamp,
                    offset: side.into_offset(),
                });
            }
        }
    }
    let column = extract_column_name(right)?;
    let offset = temporal_request_side(left)?.into_offset();
    if is_user_related_column_name(column.as_str()) {
        return None;
    }
    Some(AttributeRequestPredicate {
        column,
        operator: mirrored(operator),
        request_value: RequestValue::StatementTimestamp,
        offset,
    })
}

/// A request side of a temporal comparison: `now()` and its spellings, optionally shifted
/// by a fixed interval such as `now() - interval '30 days'`.
enum TemporalRequestSide {
    /// The bare request clock.
    Clock,
    /// The clock shifted by a fixed offset.
    Offset(TemporalOffset),
}

impl TemporalRequestSide {
    /// The offset the side carries, absent for the bare clock.
    fn into_offset(self) -> Option<TemporalOffset> {
        match self {
            Self::Clock => None,
            Self::Offset(offset) => Some(offset),
        }
    }
}

/// The clock a temporal comparison reads, or `None` when the side is neither the clock
/// nor the clock shifted by a fixed interval (a variable interval among them), so the
/// caller leaves the guard in SQL and the shape stays joined.
fn temporal_request_side(expr: &Expr) -> Option<TemporalRequestSide> {
    let expr = unwrap_cast_or_nested(expr);
    if is_well_known_temporal_function(expr) {
        return Some(TemporalRequestSide::Clock);
    }
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };
    let subtract = match op {
        BinaryOperator::Minus => true,
        BinaryOperator::Plus => false,
        _ => return None,
    };
    let left = unwrap_cast_or_nested(left);
    let right = unwrap_cast_or_nested(right);
    let interval = if is_well_known_temporal_function(left) {
        right
    } else if !subtract && is_well_known_temporal_function(right) {
        // Addition commutes here, while subtraction is one-sided because a timestamp
        // does not subtract from an interval.
        left
    } else {
        return None;
    };
    let Expr::Interval(interval) = interval else {
        return None;
    };
    let seconds = interval_seconds(interval)?;
    Some(TemporalRequestSide::Offset(TemporalOffset {
        cel_duration: cel_duration(seconds),
        subtract,
    }))
}

/// The fixed number of seconds a `PostgreSQL` interval spans, or `None` when it has no
/// fixed length (months and years) or a spelling this does not carry.
fn interval_seconds(interval: &sqlparser::ast::Interval) -> Option<i64> {
    // Only the string spelling, `interval '30 days'`, is carried, so the
    // field-qualified form `interval '30' day` falls back.
    if interval.leading_field.is_some() {
        return None;
    }
    let Expr::Value(value) = interval.value.as_ref() else {
        return None;
    };
    let Value::SingleQuotedString(text) = &value.value else {
        return None;
    };
    parse_interval_seconds(text)
}

/// Sum a `PostgreSQL` interval string of fixed-length units into seconds, rejecting a
/// month or year term and any spelling that does not parse.
fn parse_interval_seconds(text: &str) -> Option<i64> {
    let mut total: i64 = 0;
    let mut magnitude: Option<i64> = None;
    for token in text.split_whitespace() {
        if token.contains(':') {
            if magnitude.is_some() {
                return None;
            }
            total = total.checked_add(clock_seconds(token)?)?;
            continue;
        }
        if let Ok(number) = token.parse::<i64>() {
            if magnitude.replace(number).is_some() {
                return None;
            }
            continue;
        }
        let number = magnitude.take()?;
        total = total.checked_add(number.checked_mul(unit_seconds(token)?)?)?;
    }
    (magnitude.is_none() && total > 0).then_some(total)
}

/// Seconds in one fixed-length interval unit, or `None` for a variable-length unit.
fn unit_seconds(unit: &str) -> Option<i64> {
    Some(match unit.trim_end_matches('s') {
        "second" | "sec" => 1,
        "minute" | "min" => 60,
        "hour" | "hr" => 3_600,
        "day" => 86_400,
        "week" => 604_800,
        _ => return None,
    })
}

/// Seconds in a `HH:MM:SS` (or `HH:MM`) interval time part.
fn clock_seconds(token: &str) -> Option<i64> {
    let mut parts = token.split(':');
    let hours: i64 = parts.next()?.parse().ok()?;
    let minutes: i64 = parts.next()?.parse().ok()?;
    let seconds: i64 = match parts.next() {
        Some(value) => value.parse().ok()?,
        None => 0,
    };
    if parts.next().is_some()
        || hours < 0
        || !(0..60).contains(&minutes)
        || !(0..60).contains(&seconds)
    {
        return None;
    }
    Some(hours * 3_600 + minutes * 60 + seconds)
}

/// A fixed count of seconds as a CEL duration, using the coarsest whole unit.
fn cel_duration(seconds: i64) -> String {
    if seconds % 3_600 == 0 {
        format!("{}h", seconds / 3_600)
    } else if seconds % 60 == 0 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

/// The guard as structure, but only when the compared value is a literal constant.
///
/// [`is_attribute_check`] deliberately also accepts a well-known temporal function,
/// so `expires_at > now()` is an attribute guard too. That one is not decided by the
/// row: a tuple emitted for the rows qualifying today still grants access tomorrow.
/// So this returns `None` for it, and only a literal constant reaches the emission
/// that turns a guard into tuples.
pub fn attribute_literal_predicate(expr: &Expr) -> Option<AttributePredicate> {
    let Expr::BinaryOp { left, op, right } = unparenthesize(expr) else {
        return None;
    };
    let operator = attribute_operator(op)?;
    // The column may sit on either side, and the operator flips with it so the
    // predicate always reads column-first.
    if let Some(column) = extract_column_name(left) {
        if let Some(value) = attribute_literal(right) {
            if !is_user_related_column_name(column.as_str()) {
                return Some(AttributePredicate {
                    column,
                    operator,
                    value,
                });
            }
        }
    }
    let column = extract_column_name(right)?;
    let value = attribute_literal(left)?;
    if is_user_related_column_name(column.as_str()) {
        return None;
    }
    Some(AttributePredicate {
        column,
        operator: mirrored(operator),
        value,
    })
}

/// The residual conjunct paired with its structure, where a row image alone
/// decides it.
///
/// Anything else keeps only its SQL, and the shape carrying it keeps its
/// query, so an inexpressible residual costs coverage rather than
/// correctness. A bare column is the boolean test SQL makes of it, and a
/// comparison is taken only against a literal constant, so `expires_at >
/// now()` stays SQL: a row admitted today may not be admitted tomorrow, and
/// no change event fires when the clock moves.
pub fn residual_predicate(expr: &Expr) -> ResidualPredicate {
    ResidualPredicate {
        sql: expr.to_string(),
        guard: residual_guard(expr),
        request: attribute_request_predicate(expr),
        relations: Vec::new(),
    }
}

/// As [`residual_predicate`], carrying the relations the conjunct was proven to read.
pub(crate) fn residual_predicate_reading(
    expr: &Expr,
    relations: Vec<TableId>,
) -> ResidualPredicate {
    ResidualPredicate {
        relations,
        ..residual_predicate(expr)
    }
}

/// Functions whose value is decided by their arguments alone.
///
/// Nothing here reads the caller, the session or the clock, which is what makes it safe
/// for the tuple loader to answer on the caller's behalf. `to_char` is deliberately
/// absent: its output depends on `DateStyle` and `lc_time`.
pub(super) const ROW_PURE_FUNCTIONS: &[&str] = &[
    "abs",
    "btrim",
    "ceil",
    "ceiling",
    "char_length",
    "character_length",
    "coalesce",
    "concat",
    "concat_ws",
    "floor",
    "greatest",
    "least",
    "length",
    "lower",
    "ltrim",
    "nullif",
    "replace",
    "round",
    "rtrim",
    "split_part",
    "substr",
    "substring",
    "trim",
    "upper",
];

/// Whether the loader can decide `expr` from the membership row and policy text.
pub(crate) fn conjunct_reads_only_the_row(
    expr: &Expr,
    row_columns: &[String],
    session_zoned_columns: &[String],
) -> bool {
    let pure = |expr: &Expr| conjunct_reads_only_the_row(expr, row_columns, session_zoned_columns);
    match unparenthesize(expr) {
        Expr::Cast {
            expr: inner,
            data_type,
            ..
        } => !zoned_literal_uses_session(data_type, inner) && pure(inner),
        Expr::Identifier(ident) => row_columns.contains(&stored_ident_name(ident).into_owned()),
        Expr::Value(value) => !matches!(value.value, Value::Placeholder(_)),
        Expr::TypedString(typed) => {
            !zoned_literal_value_uses_session(&typed.data_type, &typed.value.value)
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::IsUnknown(inner)
        | Expr::IsNotUnknown(inner) => pure(inner),
        Expr::BinaryOp { left, op, right } => {
            !(attribute_operator(op).is_some()
                && comparison_uses_session_zone(left, right, session_zoned_columns))
                && pure(left)
                && pure(right)
        }
        Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
            !comparison_uses_session_zone(left, right, session_zoned_columns)
                && pure(left)
                && pure(right)
        }
        Expr::Between {
            expr: inner,
            low,
            high,
            ..
        } => {
            !(is_session_zoned_column(inner, session_zoned_columns)
                && (literal_uses_session_against_zoned_column(low)
                    || literal_uses_session_against_zoned_column(high)))
                && pure(inner)
                && pure(low)
                && pure(high)
        }
        Expr::In {
            expr: inner,
            target: InTarget::List(list),
            ..
        } => {
            !(is_session_zoned_column(inner, session_zoned_columns)
                && list.iter().any(literal_uses_session_against_zoned_column))
                && pure(inner)
                && list.iter().all(pure)
        }
        Expr::Like {
            expr: inner,
            pattern,
            ..
        }
        | Expr::ILike {
            expr: inner,
            pattern,
            ..
        } => pure(inner) && pure(pattern),
        Expr::Function(func) => {
            let named = builtin_function_name(func)
                .is_some_and(|name| ROW_PURE_FUNCTIONS.contains(&name.as_str()));
            if !named {
                return false;
            }
            let FunctionArguments::List(list) = &func.args else {
                return false;
            };
            list.args
                .iter()
                .all(|arg| function_arg_expr(arg).is_some_and(pure))
        }
        _ => false,
    }
}

fn comparison_uses_session_zone(
    left: &Expr,
    right: &Expr,
    session_zoned_columns: &[String],
) -> bool {
    (is_session_zoned_column(left, session_zoned_columns)
        && literal_uses_session_against_zoned_column(right))
        || (is_session_zoned_column(right, session_zoned_columns)
            && literal_uses_session_against_zoned_column(left))
}

fn is_session_zoned_column(expr: &Expr, session_zoned_columns: &[String]) -> bool {
    extract_column_name(expr).is_some_and(|column| {
        session_zoned_columns
            .iter()
            .any(|candidate| candidate == column.as_str())
    })
}

fn literal_uses_session_against_zoned_column(expr: &Expr) -> bool {
    match unparenthesize(expr) {
        Expr::Cast {
            expr: inner,
            data_type,
            ..
        } => match temporal_zone(data_type) {
            Some(true) => zoned_literal_uses_session(data_type, inner),
            Some(false) => string_literal_value(inner).is_some(),
            None => false,
        },
        Expr::TypedString(typed) => match temporal_zone(&typed.data_type) {
            Some(true) => zoned_literal_value_uses_session(&typed.data_type, &typed.value.value),
            Some(false) => sql_string_value(&typed.value.value).is_some(),
            None => false,
        },
        Expr::Value(value) => sql_string_value(&value.value).is_some_and(value_uses_session_zone),
        _ => false,
    }
}

fn zoned_literal_uses_session(data_type: &DataType, expr: &Expr) -> bool {
    temporal_zone(data_type) == Some(true)
        && string_literal_value(expr).is_some_and(value_uses_session_zone)
}

fn zoned_literal_value_uses_session(data_type: &DataType, value: &Value) -> bool {
    temporal_zone(data_type) == Some(true)
        && sql_string_value(value).is_some_and(value_uses_session_zone)
}

fn temporal_zone(data_type: &DataType) -> Option<bool> {
    match data_type {
        DataType::Timestamp(_, zone) | DataType::Time(_, zone) => Some(matches!(
            zone,
            TimezoneInfo::WithTimeZone | TimezoneInfo::Tz
        )),
        _ => None,
    }
}

fn string_literal_value(expr: &Expr) -> Option<&str> {
    match unwrap_cast_or_nested(expr) {
        Expr::TypedString(typed) => sql_string_value(&typed.value.value),
        Expr::Value(value) => sql_string_value(&value.value),
        _ => None,
    }
}

fn sql_string_value(value: &Value) -> Option<&str> {
    match value {
        Value::SingleQuotedString(value)
        | Value::EscapedStringLiteral(value)
        | Value::UnicodeStringLiteral(value)
        | Value::NationalStringLiteral(value) => Some(value),
        Value::DollarQuotedString(value) => Some(&value.value),
        _ => None,
    }
}

fn value_uses_session_zone(value: &str) -> bool {
    let value = value.trim();
    if value.eq_ignore_ascii_case("infinity") || value.eq_ignore_ascii_case("-infinity") {
        return false;
    }
    !has_explicit_utc_offset(value)
}

fn has_explicit_utc_offset(value: &str) -> bool {
    if value.ends_with('Z') || value.ends_with('z') {
        return true;
    }
    let Some(sign) = value.rfind(['+', '-']) else {
        return false;
    };
    if !value[..sign].contains(':') {
        return false;
    }
    let offset = &value[sign + 1..];
    if !offset.contains(':') {
        return !offset.is_empty()
            && offset.len() <= 6
            && offset.bytes().all(|byte| byte.is_ascii_digit());
    }
    let mut parts = offset.split(':');
    let Some(hours) = parts.next() else {
        return false;
    };
    if hours.is_empty() || hours.len() > 2 || !hours.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Some(minutes) = parts.next() else {
        return false;
    };
    if minutes.len() != 2 || !minutes.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match parts.next() {
        Some(seconds) => {
            seconds.len() == 2
                && seconds.bytes().all(|byte| byte.is_ascii_digit())
                && parts.next().is_none()
        }
        None => true,
    }
}

fn residual_guard(expr: &Expr) -> Option<ResidualGuard> {
    let inner = unparenthesize(expr);
    if let Expr::IsNotNull(operand) = inner {
        return extract_column_name(operand).map(ResidualGuard::NotNull);
    }
    if let Some(column) = extract_column_name(inner) {
        return Some(ResidualGuard::IsTrue(column));
    }
    attribute_literal_predicate(inner).map(ResidualGuard::Compare)
}

pub(super) fn attribute_operator(op: &BinaryOperator) -> Option<AttributeOperator> {
    match op {
        BinaryOperator::Eq => Some(AttributeOperator::Eq),
        BinaryOperator::NotEq => Some(AttributeOperator::NotEq),
        BinaryOperator::Gt => Some(AttributeOperator::Gt),
        BinaryOperator::GtEq => Some(AttributeOperator::GtEq),
        BinaryOperator::Lt => Some(AttributeOperator::Lt),
        BinaryOperator::LtEq => Some(AttributeOperator::LtEq),
        _ => None,
    }
}

/// The operator reading the other way round, for `3 <= priority`.
fn mirrored(operator: AttributeOperator) -> AttributeOperator {
    match operator {
        AttributeOperator::Eq => AttributeOperator::Eq,
        AttributeOperator::NotEq => AttributeOperator::NotEq,
        AttributeOperator::Gt => AttributeOperator::Lt,
        AttributeOperator::GtEq => AttributeOperator::LtEq,
        AttributeOperator::Lt => AttributeOperator::Gt,
        AttributeOperator::LtEq => AttributeOperator::GtEq,
        _ => operator,
    }
}

/// A literal constant, and nothing a function or the clock supplies.
fn attribute_literal(expr: &Expr) -> Option<AttributeLiteral> {
    let Expr::Value(value) = unwrap_cast_or_nested(expr) else {
        return None;
    };
    match &value.value {
        Value::SingleQuotedString(text) => Some(AttributeLiteral::Text(text.clone())),
        Value::Number(number, _) => Some(AttributeLiteral::Number(number.clone())),
        Value::Boolean(flag) => Some(AttributeLiteral::Boolean(*flag)),
        _ => None,
    }
}

/// The non-user column one operand names when the other is a literal or temporal value,
/// trying `left` as the column first.
fn attribute_beside_value(left: &Expr, right: &Expr) -> Option<ColumnName> {
    [(left, right), (right, left)]
        .into_iter()
        .find_map(|(column, value)| {
            extract_column_name(column).filter(|col| {
                is_literal_or_temporal(value) && !is_user_related_column_name(col.as_str())
            })
        })
}

/// Column name compared in a non-user attribute guard, if `expr` is one.
pub fn is_attribute_check(expr: &Expr) -> Option<ColumnName> {
    // A dump parenthesizes every conjunct, and the parentheses are not part
    // of the shape.
    let expr = unparenthesize(expr);
    if let Expr::BinaryOp { left, op, right } = expr {
        if matches!(
            op,
            BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::GtEq
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::Lt
        ) {
            if let Some(col) = attribute_beside_value(left, right) {
                return Some(col);
            }
        }
    }
    if let Some((col_expr, list)) = constant_in_list(unparenthesize(expr)) {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(col.as_str())
                && !list.is_empty()
                && list.iter().all(is_literal_value)
            {
                return Some(col);
            }
        }
    }
    // `col IS NOT DISTINCT FROM value` / `col IS DISTINCT FROM value`
    if let Expr::IsNotDistinctFrom(left, right) | Expr::IsDistinctFrom(left, right) = expr {
        if let Some(col) = attribute_beside_value(left, right) {
            return Some(col);
        }
    }
    // `col BETWEEN low AND high` (non-negated, both bounds literal or temporal).
    if let Expr::Between {
        expr: col_expr,
        low,
        high,
        negated: false,
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(col.as_str())
                && is_literal_or_temporal(low)
                && is_literal_or_temporal(high)
            {
                return Some(col);
            }
        }
    }
    // `col IS NULL` / `col IS NOT NULL`
    if let Expr::IsNull(col_expr) | Expr::IsNotNull(col_expr) = expr {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(col.as_str()) {
                return Some(col);
            }
        }
    }
    // `col LIKE pattern` / `col ILIKE pattern` (non-negated)
    if let Expr::Like {
        negated: false,
        expr: col_expr,
        ..
    }
    | Expr::ILike {
        negated: false,
        expr: col_expr,
        ..
    } = expr
    {
        if let Some(col) = extract_column_name(col_expr) {
            if !is_user_related_column_name(col.as_str()) {
                return Some(col);
            }
        }
    }
    if let Some(guard) = is_document_attribute_check(expr) {
        return Some(guard);
    }
    None
}

/// A jsonb field or array column compared against a literal, described for the operator.
///
/// Same job as the column forms above: the value is not the caller, so no tuple can
/// carry it. Recognising it keeps `owner_id = caller AND data ->> 'k' = 'v'` behaving
/// like `owner_id = caller AND status = 'v'` instead of collapsing to a denial.
fn is_document_attribute_check(expr: &Expr) -> Option<ColumnName> {
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };

    // `data ->> 'status' = 'published'`, in either operand order.
    if matches!(
        op,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::GtEq
            | BinaryOperator::LtEq
            | BinaryOperator::Gt
            | BinaryOperator::Lt
    ) {
        for (path_side, value_side) in [(left, right), (right, left)] {
            if is_literal_or_temporal(value_side) {
                if let Some(guard) = describe_jsonb_path_guard(path_side) {
                    return Some(guard);
                }
            }
        }
    }

    // Containment and overlap against a literal document or array literal.
    if matches!(
        op,
        BinaryOperator::AtArrow | BinaryOperator::ArrowAt | BinaryOperator::PGOverlap
    ) {
        for (column_side, other_side) in [(left, right), (right, left)] {
            if !is_literal_container(other_side) && extract_column_name(other_side).is_none() {
                continue;
            }
            if let Some(col) = extract_column_name(unwrap_cast_or_nested(column_side)) {
                if !is_user_related_column_name(col.as_str()) {
                    return Some(col);
                }
            }
        }
    }
    None
}

/// `data -> meta ->> status` for a jsonb text extraction whose field is not user
/// related, matching the refusal `is_attribute_check` already makes for such a column.
fn describe_jsonb_path_guard(expr: &Expr) -> Option<ColumnName> {
    let (column, path) = jsonb_text_path(expr)?;
    if is_user_related_column_name(path.last()?) {
        return None;
    }
    Some(ColumnName::from_stored(format!(
        "{column} ->> {}",
        path.join(" -> ")
    )))
}

/// A literal, or an array literal whose every element is a literal.
///
/// A caller expression is a function call, so it never qualifies, which keeps
/// `ARRAY[current_user] && editors` out of the attribute path and in the relationship
/// one regardless of the order the two are tried in.
fn is_literal_container(expr: &Expr) -> bool {
    match unwrap_cast_or_nested(expr) {
        Expr::Array(array) => array.elem.iter().all(is_literal_value),
        other => is_literal_value(other),
    }
}

fn is_literal_value(expr: &Expr) -> bool {
    match unwrap_cast_or_nested(expr) {
        Expr::Value(_) => true,
        // A sign or a negation is not a wrapper, so it is read here rather than peeled.
        Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus | UnaryOperator::Not,
            expr: inner,
        } => is_literal_value(inner),
        _ => false,
    }
}

/// Returns `true` when the expression is a literal value, a well-known temporal function
/// call (`now()`, `current_timestamp`), or such a function shifted by a fixed interval
/// (`now() - interval '30 days'`). Used in `is_attribute_check` so `valid_until > now()`
/// and its grace-period spellings are recognised as attribute conditions rather than
/// falling through to Unknown.
fn is_literal_or_temporal(expr: &Expr) -> bool {
    is_literal_value(expr) || temporal_request_side(expr).is_some()
}

/// (within a statement) date/time value.
fn is_well_known_temporal_function(expr: &Expr) -> bool {
    let Expr::Function(func) = unwrap_cast_or_nested(expr) else {
        return false;
    };
    let name = builtin_function_name(func);
    matches!(
        name.as_deref(),
        Some(
            "now"
                | "current_timestamp"
                | "current_date"
                | "current_time"
                | "clock_timestamp"
                | "statement_timestamp"
                | "transaction_timestamp"
                | "localtime"
                | "localtimestamp"
        )
    )
}
