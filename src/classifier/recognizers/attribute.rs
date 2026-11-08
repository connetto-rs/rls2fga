use super::*;
use crate::clock::{ClockOffset, ClockReading, ClockThreshold};
use crate::parser::expr::{cast_type_name, element_type, peel_noting_casts};
use crate::parser::sql_parser::DataTypeLike;
use crate::types::TemporalKind;
use sql_traits::utils::scalar_family::ScalarFamily;
use sql_values::{parse_interval_typmod, IntervalError, IntervalFields, IntervalTypmod};
use sqlparser::ast::{self, DataType, DateTimeField, Interval, TimezoneInfo, ValueWithSpan};

/// The guard as structure when the compared value is one only the request knows.
///
/// `expires_at > now()` is decided by the row and the clock together, so it becomes a
/// condition the authorization service evaluates per check rather than a tuple.
pub fn attribute_request_predicate(expr: &Expr) -> Option<AttributeRequestPredicate> {
    if comparison_renaming_cast(expr).is_some() {
        return None;
    }
    let Expr::BinaryOp { left, op, right } = unparenthesize(expr) else {
        return None;
    };
    let operator = attribute_operator(op)?;
    if let Some(column) = extract_column_name(left) {
        if let Some(threshold) = temporal_request_side(right) {
            return Some(AttributeRequestPredicate {
                column,
                operator,
                threshold,
            });
        }
    }
    let column = extract_column_name(right)?;
    let threshold = temporal_request_side(left)?;
    Some(AttributeRequestPredicate {
        column,
        operator: mirrored(operator),
        threshold,
    })
}

/// The threshold a temporal comparison reads, or `None` when the side is not the clock
/// or the clock shifted by an interval the threshold can follow, so the caller leaves
/// the guard in SQL and the shape stays joined.
fn temporal_request_side(expr: &Expr) -> Option<ClockThreshold> {
    clock_threshold(&clock_shift(expr)?).ok()
}

/// Why each `column op clock`, or `BETWEEN` bounded so, within `expr` falls closed, for
/// every clock or shift no threshold follows.
pub(crate) fn clock_refusals(expr: &Expr) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    let _ = ast::visit_expressions(expr, |node| {
        if let Some(refusal) = clock_refusal(node) {
            reasons.push(refusal.to_string());
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    reasons
}

/// Why one `column op clock` or `BETWEEN` bounded so falls closed.
fn clock_refusal(expr: &Expr) -> Option<ClockRefusal> {
    let bounds: [&Expr; 2] = match unparenthesize(expr) {
        Expr::BinaryOp { left, op, right } => {
            attribute_operator(op)?;
            if extract_column_name(left).is_some() {
                [right, right]
            } else {
                extract_column_name(right)?;
                [left, left]
            }
        }
        Expr::Between {
            expr,
            low,
            high,
            negated: false,
        } => {
            extract_column_name(expr)?;
            [low, high]
        }
        _ => return None,
    };
    bounds
        .into_iter()
        .find_map(|bound| clock_threshold(&clock_shift(bound)?).err())
}

/// The request clock as written, bare or shifted by an interval.
struct ClockShift<'e> {
    /// `now()` or one of its spellings, with any cast written around it.
    clock: &'e Expr,
    /// What the clock function reads.
    function: ClockFunction,
    /// The interval added or subtracted, a literal or a value cast to an interval type.
    interval: Option<&'e Expr>,
    /// `true` for `clock - interval`.
    subtract: bool,
}

/// The clock or the clock shifted by an interval, whatever the interval's length.
fn clock_shift(expr: &Expr) -> Option<ClockShift<'_>> {
    let expr = unwrap_cast_or_nested(expr);
    if let Some(function) = clock_function(expr) {
        return Some(ClockShift {
            clock: expr,
            function,
            interval: None,
            subtract: false,
        });
    }
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };
    let subtract = match op {
        BinaryOperator::Minus => true,
        BinaryOperator::Plus => false,
        _ => return None,
    };
    let (clock, function, interval) = if let Some(function) = clock_function(left) {
        (left, function, right)
    } else if let (false, Some(function)) = (subtract, clock_function(right)) {
        // Addition commutes here, while subtraction is one-sided because a timestamp
        // does not subtract from an interval.
        (right, function, left)
    } else {
        return None;
    };
    let mut outermost_cast = None;
    let peeled = peel_noting_casts(interval, |data_type| {
        outermost_cast.get_or_insert(data_type);
    });
    let is_interval = matches!(peeled, Expr::Interval(_))
        || matches!(outermost_cast, Some(DataType::Interval { .. }));
    is_interval.then_some(ClockShift {
        clock,
        function,
        interval: Some(interval),
        subtract,
    })
}

/// Why a clock reading or the interval shifting it has no threshold.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClockRefusal {
    /// `localtime` or `current_time`, a time of day.
    #[error(
        "{clock} is a time of day, which no timestamp condition parameter carries and \
         PostgreSQL does not compare with a timestamptz"
    )]
    TimeOfDay {
        /// The clock as written.
        clock: String,
    },
    /// `current_date` or `localtimestamp` cast before an interval shifts it, which turns
    /// the zoneless shift into one on the zone's calendar.
    #[error(
        "{clock} casts the local clock before shifting it, which this does not follow, so \
         it has no threshold"
    )]
    CastLocalClock {
        /// The clock as written.
        clock: String,
    },
    /// The interval is not written as a quoted string.
    #[error("{interval} is not a quoted string, so it has no fixed CEL duration")]
    NotAString {
        /// The interval as written.
        interval: String,
    },
    /// A cast to an interval type whose operand is itself cast, so `PostgreSQL` reads the
    /// text as that other type first and only then applies the interval's fields.
    #[error(
        "{interval} casts through another type before the interval, which this does not \
         follow, so it has no fixed CEL duration"
    )]
    CastChain {
        /// The interval as written.
        interval: String,
    },
    /// An interval literal cast again, which `PostgreSQL` rescales to the target's fields.
    #[error(
        "{interval} casts the interval again, which this does not follow, so it has no \
         fixed CEL duration"
    )]
    Recast {
        /// The interval as written.
        interval: String,
    },
    /// The field qualifier is one `PostgreSQL` does not accept on an interval literal.
    #[error("PostgreSQL does not read the field qualifier of {interval}")]
    UnreadableQualifier {
        /// The interval as written.
        interval: String,
    },
    /// `interval_in` refuses the text.
    #[error("PostgreSQL does not read '{text}' as an interval ({source})")]
    Unreadable {
        /// The quoted text.
        text: String,
        /// The error `PostgreSQL` raises.
        #[source]
        source: IntervalError,
    },
    /// `infinity` or `-infinity`.
    #[error("{interval} has no finite length, so it has no CEL duration")]
    Infinite {
        /// The interval as written.
        interval: String,
    },
    /// An interval `interval_um` refuses to negate for the subtraction.
    #[error("PostgreSQL raises interval out of range subtracting {interval}")]
    Unnegatable {
        /// The interval as written.
        interval: String,
    },
    /// A fixed shift of the instant beyond the nanosecond count a CEL duration holds.
    #[error("{interval} is longer than a CEL duration holds")]
    TooLong {
        /// The interval as written.
        interval: String,
    },
}

/// The microseconds a CEL duration holds, a Go `time.Duration` of nanoseconds.
const CEL_DURATION_MAX_MICROSECONDS: u64 = i64::MAX.unsigned_abs() / 1_000;

/// What `shift`'s clock reads, or why no threshold follows it. A local clock cast before
/// an interval shifts it is refused, since the cast moves the shift onto the zone's
/// calendar.
fn clock_reading(shift: &ClockShift<'_>) -> Result<ClockReading, ClockRefusal> {
    let clock = || shift.clock.to_string();
    let ClockFunction::Reading(reading) = shift.function else {
        return Err(ClockRefusal::TimeOfDay { clock: clock() });
    };
    let mut cast = false;
    peel_noting_casts(shift.clock, |_| cast = true);
    if cast && shift.interval.is_some() && reading != ClockReading::Instant {
        return Err(ClockRefusal::CastLocalClock { clock: clock() });
    }
    Ok(reading)
}

/// The threshold `shift` reads, or why it has none.
fn clock_threshold(shift: &ClockShift<'_>) -> Result<ClockThreshold, ClockRefusal> {
    let reading = clock_reading(shift)?;
    let Some(interval) = shift.interval else {
        return Ok(ClockThreshold {
            reading,
            offset: ClockOffset::ZERO,
        });
    };
    let written = || interval.to_string();
    let value = interval_value(interval)?;
    if !value.is_finite() {
        return Err(ClockRefusal::Infinite {
            interval: written(),
        });
    }
    let value = if shift.subtract {
        value.checked_neg().map_err(|_| ClockRefusal::Unnegatable {
            interval: written(),
        })?
    } else {
        value
    };
    let offset = ClockOffset::from(value);
    // Only the instant shifted by a fixed length rides the clock as a CEL duration.
    if reading == ClockReading::Instant
        && offset.is_fixed()
        && offset.microseconds.unsigned_abs() > CEL_DURATION_MAX_MICROSECONDS
    {
        return Err(ClockRefusal::TooLong {
            interval: written(),
        });
    }
    Ok(ClockThreshold { reading, offset })
}

/// The interval as `PostgreSQL` stores it, from `interval '…'` or from a quoted string
/// cast once to an interval type, which `PostgreSQL` reads alike.
fn interval_value(written: &Expr) -> Result<sql_values::PgInterval, ClockRefusal> {
    let mut casts: Vec<&DataType> = Vec::new();
    let peeled = peel_noting_casts(written, |data_type| casts.push(data_type));
    let interval = || written.to_string();
    let (text, typmod) = match (peeled, casts.as_slice()) {
        (Expr::Interval(literal), casts) => {
            // Only the unqualified type leaves an interval as it is.
            let identity = |cast: &&DataType| {
                matches!(
                    cast,
                    DataType::Interval {
                        fields: None,
                        precision: None,
                    }
                )
            };
            if !casts.iter().all(identity) {
                return Err(ClockRefusal::Recast {
                    interval: interval(),
                });
            }
            (literal.value.as_ref(), literal_typmod(literal))
        }
        (operand, [DataType::Interval { fields, precision }]) => {
            (operand, cast_typmod(fields.as_ref(), *precision))
        }
        _ => {
            return Err(ClockRefusal::CastChain {
                interval: interval(),
            })
        }
    };
    let text = quoted_text(text).ok_or_else(|| ClockRefusal::NotAString {
        interval: interval(),
    })?;
    let typmod = typmod.ok_or_else(|| ClockRefusal::UnreadableQualifier {
        interval: interval(),
    })?;
    parse_interval_typmod(text, typmod).map_err(|source| ClockRefusal::Unreadable {
        text: text.to_string(),
        source,
    })
}

/// The text of a single- or dollar-quoted string, the spellings `PostgreSQL` reads as an
/// interval's input.
fn quoted_text(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Value(ValueWithSpan {
            value: Value::SingleQuotedString(text),
            ..
        }) => Some(text),
        Expr::Value(ValueWithSpan {
            value: Value::DollarQuotedString(quoted),
            ..
        }) => Some(&quoted.value),
        _ => None,
    }
}

/// The type modifier a literal's field qualifier such as `day to second(3)` sets, or
/// `None` for a qualifier `PostgreSQL`'s grammar does not accept on an interval literal.
fn literal_typmod(interval: &Interval) -> Option<IntervalTypmod> {
    let fields = match (&interval.leading_field, &interval.last_field) {
        (None, None) => None,
        (Some(DateTimeField::Year), None) => Some(IntervalFields::Year),
        (Some(DateTimeField::Month), None) => Some(IntervalFields::Month),
        (Some(DateTimeField::Day), None) => Some(IntervalFields::Day),
        (Some(DateTimeField::Hour), None) => Some(IntervalFields::Hour),
        (Some(DateTimeField::Minute), None) => Some(IntervalFields::Minute),
        (Some(DateTimeField::Second), None) => Some(IntervalFields::Second),
        (Some(DateTimeField::Year), Some(DateTimeField::Month)) => {
            Some(IntervalFields::YearToMonth)
        }
        (Some(DateTimeField::Day), Some(DateTimeField::Hour)) => Some(IntervalFields::DayToHour),
        (Some(DateTimeField::Day), Some(DateTimeField::Minute)) => {
            Some(IntervalFields::DayToMinute)
        }
        (Some(DateTimeField::Day), Some(DateTimeField::Second)) => {
            Some(IntervalFields::DayToSecond)
        }
        (Some(DateTimeField::Hour), Some(DateTimeField::Minute)) => {
            Some(IntervalFields::HourToMinute)
        }
        (Some(DateTimeField::Hour), Some(DateTimeField::Second)) => {
            Some(IntervalFields::HourToSecond)
        }
        (Some(DateTimeField::Minute), Some(DateTimeField::Second)) => {
            Some(IntervalFields::MinuteToSecond)
        }
        _ => return None,
    };
    // `second(p)` alone puts its precision first, `… to second(p)` last.
    let precision = match (
        interval.leading_precision,
        interval.fractional_seconds_precision,
    ) {
        (None, None) => None,
        (Some(precision), None) if fields == Some(IntervalFields::Second) => Some(precision),
        (None, Some(precision)) if interval.last_field == Some(DateTimeField::Second) => {
            Some(precision)
        }
        _ => return None,
    };
    interval_typmod(fields, precision)
}

/// The type modifier of the interval type a value is cast to, as in
/// `'90'::interval minute`, or `None` for a precision after fields not ending in `SECOND`.
fn cast_typmod(
    fields: Option<&ast::IntervalFields>,
    precision: Option<u64>,
) -> Option<IntervalTypmod> {
    let fields = fields.map(|fields| match fields {
        ast::IntervalFields::Year => IntervalFields::Year,
        ast::IntervalFields::Month => IntervalFields::Month,
        ast::IntervalFields::Day => IntervalFields::Day,
        ast::IntervalFields::Hour => IntervalFields::Hour,
        ast::IntervalFields::Minute => IntervalFields::Minute,
        ast::IntervalFields::Second => IntervalFields::Second,
        ast::IntervalFields::YearToMonth => IntervalFields::YearToMonth,
        ast::IntervalFields::DayToHour => IntervalFields::DayToHour,
        ast::IntervalFields::DayToMinute => IntervalFields::DayToMinute,
        ast::IntervalFields::DayToSecond => IntervalFields::DayToSecond,
        ast::IntervalFields::HourToMinute => IntervalFields::HourToMinute,
        ast::IntervalFields::HourToSecond => IntervalFields::HourToSecond,
        ast::IntervalFields::MinuteToSecond => IntervalFields::MinuteToSecond,
    });
    interval_typmod(fields, precision)
}

/// The type modifier of `fields` and `precision`, clamping a precision above six to six
/// as `PostgreSQL` does.
fn interval_typmod(
    fields: Option<IntervalFields>,
    precision: Option<u64>,
) -> Option<IntervalTypmod> {
    IntervalTypmod::new(
        fields,
        precision.map(|precision| u8::try_from(precision).unwrap_or(u8::MAX)),
    )
}

/// The guard as structure, but only when every compared value is a literal constant
/// or the guard tests the column for NULL.
///
/// [`is_attribute_check`] deliberately also accepts a well-known temporal function,
/// so `expires_at > now()` is an attribute guard too. That one is not decided by the
/// row: a tuple emitted for the rows qualifying today still grants access tomorrow.
/// So this returns `None` for it, and only a literal constant reaches the emission
/// that turns a guard into tuples.
pub fn attribute_literal_predicate(expr: &Expr) -> Option<AttributePredicate> {
    let expr = unparenthesize(expr);
    if comparison_renaming_cast(expr).is_some() {
        return None;
    }
    if let Some((column, list)) = constant_in_list(expr) {
        let as_text = column_cast_to_text(column) || list_compares_as_text(expr, list);
        return literal_list_predicate(column, list, as_text);
    }
    let null_test = match expr {
        Expr::IsNull(operand) => Some((operand, AttributeTest::IsNull)),
        Expr::IsNotNull(operand) => Some((operand, AttributeTest::IsNotNull)),
        _ => None,
    };
    if let Some((operand, test)) = null_test {
        let column = extract_column_name(operand)?;
        return Some(AttributePredicate { column, test });
    }
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };
    let operator = attribute_operator(op)?;
    // The column may sit on either side, and the operator flips with it so the
    // predicate always reads column-first.
    if let Some(column) = extract_column_name(left) {
        if let Some(value) = attribute_literal(right) {
            let as_text = column_cast_to_text(left) || literal_cast_to_text(right);
            return Some(AttributePredicate {
                column,
                test: AttributeTest::Compare {
                    operator,
                    value: compared_as_text(value, as_text),
                },
            });
        }
    }
    let column = extract_column_name(right)?;
    let value = attribute_literal(left)?;
    let as_text = column_cast_to_text(right) || literal_cast_to_text(left);
    Some(AttributePredicate {
        column,
        test: AttributeTest::Compare {
            operator: mirrored(operator),
            value: compared_as_text(value, as_text),
        },
    })
}

/// The literal as compared with its column, marked [`AttributeLiteral::AsText`] where it
/// ends in a blank and compares as `text`.
///
/// `PostgreSQL` compares a `char(n)` column with an untyped, `varchar` or `char` value as
/// `char(n)`, ignoring trailing blanks on both sides, and with a `text` value as `text`,
/// where the value's trailing blanks count. A literal without one compares the same either
/// way, and so does a column of any other type, so only this literal needs the mark.
fn compared_as_text(value: AttributeLiteral, as_text: bool) -> AttributeLiteral {
    match value {
        AttributeLiteral::Text(text) if as_text && text.ends_with(' ') => {
            AttributeLiteral::AsText(text)
        }
        other => other,
    }
}

/// Whether a column operand is cast to an unbounded text type, which compares it as `text`.
fn column_cast_to_text(column: &Expr) -> bool {
    CastChain::peeled(column).0.casts_to_text()
}

/// Whether a literal operand is cast to `text` itself. A `varchar` literal still compares
/// with a `char(n)` column as `char(n)`.
fn literal_cast_to_text(literal: &Expr) -> bool {
    CastChain::peeled(literal).0.outermost() == Some("text")
}

/// Whether the values of a list compare with an uncast column as `text`.
///
/// An `IN` list of several values takes the column's type whatever the values are cast
/// to, and a list of one is the equality it spells. `= ANY (ARRAY[...])` takes the array's
/// type, which is `text[]` when the array or an item is cast to `text` or nothing is cast,
/// and otherwise the `varchar` or `char(n)` a string literal here is cast to, which a
/// `char(n)` column compares as `char(n)`.
fn list_compares_as_text(expr: &Expr, list: &[Expr]) -> bool {
    let Expr::AnyOp { right, .. } = expr else {
        return matches!(list, [only] if literal_cast_to_text(only));
    };
    if let Some(array_type) = CastChain::peeled(right).0.outermost() {
        return element_type(array_type) == "text";
    }
    let mut typed = false;
    for item in list {
        match CastChain::peeled(item).0.outermost() {
            Some("text") => return true,
            Some(_) => typed = true,
            None => {}
        }
    }
    !typed
}

/// The list item a list of several values compares, without the `text` and unbounded
/// `varchar` casts its column's type overrides.
pub(super) fn listed_value(item: &Expr) -> &Expr {
    let (casts, inner) = CastChain::peeled(item);
    if casts.renaming(None).is_none() {
        inner
    } else {
        item
    }
}

/// A literal list in one spelling per set of values: sorted, without repeats, and a
/// single value as the equality it means, so every spelling of one guard mints one gate.
fn literal_list_predicate(
    column: &Expr,
    list: &[Expr],
    as_text: bool,
) -> Option<AttributePredicate> {
    let column = extract_column_name(column)?;
    let mut values = list
        .iter()
        .map(|item| attribute_literal(item).map(|value| compared_as_text(value, as_text)))
        .collect::<Option<Vec<_>>>()?;
    values.sort();
    values.dedup();
    let test = match <[AttributeLiteral; 1]>::try_from(values) {
        Ok([value]) => AttributeTest::Compare {
            operator: AttributeOperator::Eq,
            value,
        },
        Err(values) if !values.is_empty() => AttributeTest::In(values),
        Err(_) => return None,
    };
    Some(AttributePredicate { column, test })
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
    zoned: &[String],
    relations: Vec<TableId>,
) -> ResidualPredicate {
    let residual = ResidualPredicate {
        relations,
        ..residual_predicate(expr)
    };
    match local_literal_comparison(expr, zoned) {
        Some(Ok(request)) => ResidualPredicate {
            guard: None,
            request: Some(request),
            ..residual
        },
        _ => residual,
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
    let reads_session = |column: &Expr, value: &Expr| {
        if is_session_zoned_column(column, session_zoned_columns) {
            literal_uses_session_against_zoned_column(value)
        } else {
            // An instant meets a zoneless column only after the column is converted in
            // the session zone.
            bare_column(column).is_some()
                && temporal_literal(value)
                    .is_some_and(|(kind, _)| kind == TemporalKind::TimestampTz)
        }
    };
    reads_session(left, right) || reads_session(right, left)
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

/// Whether a date or time type carries a zone, `None` for any other type.
fn temporal_zone(data_type: &DataType) -> Option<bool> {
    match data_type {
        DataType::Timestamp(_, zone) | DataType::Time(_, zone) => Some(matches!(
            zone,
            TimezoneInfo::WithTimeZone | TimezoneInfo::Tz
        )),
        DataType::Date => Some(false),
        _ => None,
    }
}

/// Why a local literal compared with a `timestamptz` column becomes no threshold.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalLiteralRefusal {
    /// A comparison a threshold condition cannot carry, such as `IS DISTINCT FROM`, which
    /// admits a `NULL` row.
    #[error(
        "{comparison} compares {column} with a local time PostgreSQL converts in the session \
         TimeZone, which only an ordering or an equality carries as a threshold"
    )]
    NotAnOrdering {
        /// The comparison as written.
        comparison: String,
        /// The column it compares.
        column: ColumnName,
    },
    /// A literal whose value cannot be computed here.
    #[error("'{text}' as a {pg_type} has no value rls2fga computes ({source})")]
    Unreadable {
        /// The literal's text.
        text: String,
        /// The type the literal is cast to.
        pg_type: sql_values::PgType,
        /// Why the cast has no value.
        #[source]
        source: sql_values::CastError,
    },
}

/// `column op literal` where `column` is one of `zoned` and the literal a `date` or
/// `timestamp`, which `PostgreSQL` converts to an instant in the session `TimeZone` of each
/// query, as the request predicate comparing the row with that instant, or why there is
/// none.
///
/// `None` where no such literal meets such a column, which every other reading judges.
pub(crate) fn local_literal_comparison(
    expr: &Expr,
    zoned: &[String],
) -> Option<Result<AttributeRequestPredicate, LocalLiteralRefusal>> {
    let expr = unparenthesize(expr);
    let zoned_column = |column: &Expr| {
        let column = bare_column(column)?;
        zoned
            .iter()
            .any(|name| name == column.as_str())
            .then_some(column)
    };
    match expr {
        Expr::BinaryOp { left, op, right } => {
            let operator = attribute_operator(op)?;
            [
                (left.as_ref(), right.as_ref(), operator),
                (right.as_ref(), left.as_ref(), mirrored(operator)),
            ]
            .into_iter()
            .find_map(|(column, value, operator)| {
                let column = zoned_column(column)?;
                Some(
                    local_literal(value)?.map(|local| AttributeRequestPredicate {
                        column,
                        operator,
                        threshold: ClockThreshold {
                            reading: ClockReading::FixedLocal(local),
                            offset: ClockOffset::ZERO,
                        },
                    }),
                )
            })
        }
        Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => [
            (left.as_ref(), right.as_ref()),
            (right.as_ref(), left.as_ref()),
        ]
        .into_iter()
        .find_map(|(column, value)| {
            let column = zoned_column(column)?;
            let refusal = match local_literal(value)? {
                Err(unreadable) => unreadable,
                Ok(_) => LocalLiteralRefusal::NotAnOrdering {
                    comparison: expr.to_string(),
                    column,
                },
            };
            Some(Err(refusal))
        }),
        _ => None,
    }
}

/// `column BETWEEN low AND high` as `column >= low AND column <= high`, and `column IN
/// (a, b)` as `column = a OR column = b`, where `column` is a date or time column and a bound
/// or a value a date or time literal, so each comparison is judged on its own.
/// `PostgreSQL` stores such a `BETWEEN` as the two comparisons.
pub(crate) fn temporal_literal_comparisons(expr: &Expr, columns: &TemporalColumns) -> Option<Expr> {
    let compared = |column: &Expr, op: BinaryOperator, value: &Expr| Expr::BinaryOp {
        left: Box::new(column.clone()),
        op,
        right: Box::new(value.clone()),
    };
    let temporal_column =
        |column: &Expr| bare_column(column).is_some_and(|name| columns.kind(&name).is_some());
    match unparenthesize(expr) {
        Expr::Between {
            expr: column,
            negated: false,
            low,
            high,
        } if temporal_column(column)
            && (temporal_literal(low).is_some() || temporal_literal(high).is_some()) =>
        {
            Some(Expr::BinaryOp {
                left: Box::new(compared(column, BinaryOperator::GtEq, low)),
                op: BinaryOperator::And,
                right: Box::new(compared(column, BinaryOperator::LtEq, high)),
            })
        }
        Expr::In {
            expr: column,
            target: InTarget::List(list),
            negated: false,
            ..
        } if temporal_column(column)
            && list.iter().any(|value| temporal_literal(value).is_some()) =>
        {
            list.iter()
                .map(|value| compared(column, BinaryOperator::Eq, value))
                .reduce(|left, right| Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOperator::Or,
                    right: Box::new(right),
                })
        }
        _ => None,
    }
}

/// The date and time columns of one table, with the type each compares as.
#[derive(Debug, Clone, Default)]
pub(crate) struct TemporalColumns(Vec<(String, TemporalKind)>);

impl TemporalColumns {
    /// `table`'s `date`, `timestamp` and `timestamptz` columns, as the schema stores
    /// their names.
    pub(crate) fn of<DB: DatabaseLike>(table: &DB::Table, db: &DB) -> Self {
        Self(
            table
                .columns(db)
                .into_iter()
                .flatten()
                .filter_map(|column| {
                    let kind = match column.data_type(db).scalar_family(db)? {
                        ScalarFamily::Date => TemporalKind::Date,
                        ScalarFamily::Timestamp => TemporalKind::Timestamp,
                        ScalarFamily::TimestampTz => TemporalKind::TimestampTz,
                        _ => return None,
                    };
                    Some((column.stored_column_name().into_owned(), kind))
                })
                .collect(),
        )
    }

    fn kind(&self, column: &ColumnName) -> Option<TemporalKind> {
        self.0
            .iter()
            .find(|(name, _)| name == column.as_str())
            .map(|(_, kind)| *kind)
    }
}

/// Why a date or time literal of another type than its column's becomes no guard.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TemporalLiteralRefusal {
    /// An instant compared with a `date` or `timestamp` column.
    #[error(
        "{comparison}: PostgreSQL converts {column} to a timestamptz in the session TimeZone \
         to compare it with an instant, so the same row compares differently in each zone"
    )]
    ZonelessAgainstInstant {
        /// The comparison as written.
        comparison: String,
        /// The column it converts.
        column: ColumnName,
    },
}

/// `column op literal` where `column` is a date or time column and the literal one of
/// another type, or one a precision rounds, which `PostgreSQL` compares the same in every
/// session. The literal stays typed as the policy stores it, so the tuple query compares
/// as the policy does.
///
/// `None` for a `date` or `timestamp` compared with a `timestamptz` column, which the
/// session zone converts and [`local_literal_comparison`] judges, and wherever no such
/// literal meets such a column. An instant compared with a zoneless column is refused.
pub(crate) fn temporal_literal_comparison(
    expr: &Expr,
    columns: &TemporalColumns,
) -> Option<Result<AttributePredicate, TemporalLiteralRefusal>> {
    let expr = unparenthesize(expr);
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };
    let operator = attribute_operator(op)?;
    [
        (left.as_ref(), right.as_ref(), operator),
        (right.as_ref(), left.as_ref(), mirrored(operator)),
    ]
    .into_iter()
    .find_map(|(column, value, operator)| {
        let column = bare_column(column)?;
        let column_kind = columns.kind(&column)?;
        let (kind, text) = temporal_literal(value)?;
        let zoned_column = column_kind == TemporalKind::TimestampTz;
        let zoned_literal = kind == TemporalKind::TimestampTz;
        if zoned_column && !zoned_literal && local_literal(value).is_some() {
            return None;
        }
        if zoned_literal && !zoned_column {
            return Some(Err(TemporalLiteralRefusal::ZonelessAgainstInstant {
                comparison: expr.to_string(),
                column,
            }));
        }
        Some(Ok(AttributePredicate {
            column,
            test: AttributeTest::Compare {
                operator,
                value: AttributeLiteral::Temporal { kind, text },
            },
        }))
    })
}

/// The type and printed value of a quoted literal cast once to `date`, `timestamp` or
/// `timestamptz`, a precision applied as `PostgreSQL` applies it. `None` for any other
/// literal, and for one the cast has no value for, which every other reading refuses.
fn temporal_literal(expr: &Expr) -> Option<(TemporalKind, String)> {
    use sql_values::CastTarget;
    let (text, data_type) = cast_once(expr)?;
    let (target, kind) = match cast_target(data_type)? {
        target @ CastTarget::Date => (target, TemporalKind::Date),
        target @ CastTarget::Timestamp(_) => (target, TemporalKind::Timestamp),
        target @ CastTarget::TimestampTz(_) => (target, TemporalKind::TimestampTz),
        _ => return None,
    };
    let value = sql_values::cast_literal(sql_values::Literal::Quoted(text), target).ok()?;
    Some((kind, value.to_string()))
}

/// The quoted text and the type of a literal cast exactly once, in either spelling a cast
/// takes, `'…'::date` or `DATE '…'`.
fn cast_once(expr: &Expr) -> Option<(&str, &DataType)> {
    let mut casts = 0_usize;
    let mut outermost = None;
    let peeled = peel_noting_casts(expr, |data_type| {
        casts += 1;
        outermost.get_or_insert(data_type);
    });
    match (peeled, casts, outermost) {
        (Expr::Value(value), 1, Some(data_type)) => {
            Some((sql_string_value(&value.value)?, data_type))
        }
        (Expr::TypedString(typed), 0, None) => {
            Some((sql_string_value(&typed.value.value)?, &typed.data_type))
        }
        _ => None,
    }
}

/// The column `expr` names with nothing around it, since a cast on the column compares
/// something else.
fn bare_column(expr: &Expr) -> Option<ColumnName> {
    match unparenthesize(expr) {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => extract_column_name(expr),
        _ => None,
    }
}

/// The local time a quoted literal cast once to `date` or `timestamp` names, a date as its
/// midnight, or why it has none. `None` for any other literal, and for an infinity, which
/// every zone converts alike.
fn local_literal(expr: &Expr) -> Option<Result<sql_values::PgTimestamp, LocalLiteralRefusal>> {
    use sql_values::{CastError, CastTarget, CastValue, PgTime, PgTimestamp};
    let (text, data_type) = cast_once(expr)?;
    let target = cast_target(data_type)
        .filter(|target| matches!(target, CastTarget::Date | CastTarget::Timestamp(_)))?;
    let read = || -> Result<Option<PgTimestamp>, CastError> {
        Ok(
            match sql_values::cast_literal(sql_values::Literal::Quoted(text), target)? {
                CastValue::Date(date) if date.is_finite() => Some(
                    PgTimestamp::new(date, PgTime::MIDNIGHT)
                        .ok_or(CastError::DateOutOfRangeForTimestamp)?,
                ),
                CastValue::Timestamp(local) if local.is_finite() => Some(local),
                _ => None,
            },
        )
    };
    read()
        .map_err(|source| LocalLiteralRefusal::Unreadable {
            text: text.to_string(),
            pg_type: target.pg_type(),
            source,
        })
        .transpose()
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

/// A literal constant, and nothing a function or the clock supplies, read through casts
/// that keep its value or as the value a cast `sql-values` computes makes of it.
pub(super) fn attribute_literal(expr: &Expr) -> Option<AttributeLiteral> {
    let (casts, peeled) = CastChain::peeled(expr);
    let Expr::Value(value) = peeled else {
        return None;
    };
    if casts.renaming(None).is_some() {
        return folded_literal(expr);
    }
    match &value.value {
        Value::SingleQuotedString(text) => Some(AttributeLiteral::Text(text.clone())),
        Value::Number(number, _) => Some(AttributeLiteral::Number(number.clone())),
        Value::Boolean(flag) => Some(AttributeLiteral::Boolean(*flag)),
        _ => None,
    }
}

/// The value `PostgreSQL` makes of a literal through its chain of casts, applied innermost
/// first, as the literal that compares like it, or `None` where any cast in the chain is
/// one `sql-values` does not compute.
///
/// A date or time result is not folded, since how it compares with a zoned column depends
/// on the session's `TimeZone`, and `char(n)` reads without the blank padding its cast to
/// `text` drops.
fn folded_literal(expr: &Expr) -> Option<AttributeLiteral> {
    let mut targets = Vec::new();
    let peeled = peel_noting_casts(expr, |data_type| targets.push(data_type));
    let Expr::Value(ValueWithSpan { value, .. }) = peeled else {
        return None;
    };
    let literal = match value {
        Value::SingleQuotedString(text) => sql_values::Literal::Quoted(text),
        Value::DollarQuotedString(quoted) => sql_values::Literal::Quoted(&quoted.value),
        Value::Number(number, _) => sql_values::Literal::Number(number),
        _ => return None,
    };
    let mut targets = targets.into_iter().rev();
    let first = sql_values::cast_literal(literal, cast_target(targets.next()?)?).ok()?;
    let folded = targets.try_fold(first, |value, data_type| {
        sql_values::cast_value(value, cast_target(data_type)?).ok()
    })?;
    match folded {
        sql_values::CastValue::Boolean(flag) => Some(AttributeLiteral::Boolean(flag)),
        number @ (sql_values::CastValue::Smallint(_)
        | sql_values::CastValue::Integer(_)
        | sql_values::CastValue::Bigint(_)) => Some(AttributeLiteral::Number(number.to_string())),
        sql_values::CastValue::Numeric(number) => {
            // `NaN` and the infinities print as words no bare SQL number spells.
            let printed = number.to_string();
            printed
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
                .then_some(AttributeLiteral::Number(printed))
        }
        sql_values::CastValue::Text(text) => Some(AttributeLiteral::Text(text)),
        sql_values::CastValue::Bpchar(text) => {
            Some(AttributeLiteral::Text(text.as_text().to_string()))
        }
        sql_values::CastValue::Date(_)
        | sql_values::CastValue::Timestamp(_)
        | sql_values::CastValue::TimestampTz(_) => None,
    }
}

/// The cast `sql-values` computes for a cast to `data_type`, or `None` for a type it does
/// not model or a modifier `PostgreSQL` refuses.
fn cast_target(data_type: &DataType) -> Option<sql_values::CastTarget> {
    use sql_values::{CastTarget, CharLength, NumericTypmod};
    let length = |length: &Option<ast::CharacterLength>| match length {
        None => Some(None),
        Some(ast::CharacterLength::IntegerLength { length, unit: None }) => {
            CharLength::new(usize::try_from(*length).ok()?).map(Some)
        }
        Some(_) => None,
    };
    Some(match data_type {
        DataType::Bool | DataType::Boolean => CastTarget::Boolean,
        DataType::SmallInt(None) | DataType::Int2(None) => CastTarget::Smallint,
        DataType::Int(None) | DataType::Integer(None) | DataType::Int4(None) => CastTarget::Integer,
        DataType::BigInt(None) | DataType::Int8(None) => CastTarget::Bigint,
        DataType::Numeric(info) | DataType::Decimal(info) | DataType::Dec(info) => {
            CastTarget::Numeric(match info {
                ast::ExactNumberInfo::None => None,
                ast::ExactNumberInfo::Precision(precision) => {
                    Some(NumericTypmod::new(u16::try_from(*precision).ok()?, 0)?)
                }
                ast::ExactNumberInfo::PrecisionAndScale(precision, scale) => {
                    Some(NumericTypmod::new(
                        u16::try_from(*precision).ok()?,
                        i16::try_from(*scale).ok()?,
                    )?)
                }
            })
        }
        DataType::Text => CastTarget::Text,
        DataType::Varchar(chars)
        | DataType::CharacterVarying(chars)
        | DataType::CharVarying(chars) => CastTarget::Varchar(length(chars)?),
        DataType::Char(chars) | DataType::Character(chars) => {
            // A bare `char` is `char(1)`.
            CastTarget::Bpchar(Some(length(chars)?.or_else(|| CharLength::new(1))?))
        }
        // An unbounded `bpchar` keeps the value's own blanks.
        DataType::Custom(_, modifiers) if bpchar_name(data_type) => {
            CastTarget::Bpchar(match modifiers.as_slice() {
                [] => None,
                [ast::TypeModifier::Number(length, false)] => {
                    Some(CharLength::new(length.parse().ok()?)?)
                }
                _ => return None,
            })
        }
        DataType::Date => CastTarget::Date,
        DataType::Timestamp(precision, _) => {
            // A precision above six is six, as `PostgreSQL` clamps it.
            let precision = precision.map(|precision| u8::try_from(precision).unwrap_or(u8::MAX));
            if temporal_zone(data_type) == Some(true) {
                CastTarget::TimestampTz(precision)
            } else {
                CastTarget::Timestamp(precision)
            }
        }
        _ => return None,
    })
}

/// Whether `data_type` spells `bpchar`, bare or in `pg_catalog`, the name `PostgreSQL` gives
/// `char(n)` when it prints a literal compared with such a column.
fn bpchar_name(data_type: &DataType) -> bool {
    let name = cast_type_name(data_type);
    name.split('(').next() == Some("bpchar")
}

/// The column one operand names when the other is a literal or temporal value, trying
/// `left` as the column first.
fn attribute_beside_value(left: &Expr, right: &Expr) -> Option<ColumnName> {
    [(left, right), (right, left)]
        .into_iter()
        .find_map(|(column, value)| {
            extract_column_name(column).filter(|_| is_literal_or_temporal(value))
        })
}

/// Column name compared in an attribute guard, if `expr` is one.
pub fn is_attribute_check(expr: &Expr) -> Option<ColumnName> {
    // A dump parenthesizes every conjunct, and the parentheses are not part
    // of the shape.
    let expr = unparenthesize(expr);
    if comparison_renaming_cast(expr).is_some() {
        return None;
    }
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
            if !list.is_empty() && list.iter().all(is_literal_value) {
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
            if is_literal_or_temporal(low) && is_literal_or_temporal(high) {
                return Some(col);
            }
        }
    }
    // `col IS NULL` / `col IS NOT NULL`
    if let Expr::IsNull(col_expr) | Expr::IsNotNull(col_expr) = expr {
        if let Some(col) = extract_column_name(col_expr) {
            return Some(col);
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
            return Some(col);
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
                return Some(col);
            }
        }
    }
    None
}

/// `data -> meta ->> status` for a jsonb text extraction.
fn describe_jsonb_path_guard(expr: &Expr) -> Option<ColumnName> {
    let (column, path) = jsonb_text_path(expr)?;
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
/// (`now() - interval '36 hours'`). Used in `is_attribute_check` so `valid_until > now()`
/// and its grace-period spellings are recognised as attribute conditions rather than
/// falling through to Unknown.
fn is_literal_or_temporal(expr: &Expr) -> bool {
    is_literal_value(expr) || temporal_request_side(expr).is_some()
}

/// The spellings of the request clock's own type, a cast to which leaves the clock as it
/// is.
const CLOCK_TYPE: &[&str] = &["timestamptz", "timestamp with time zone"];

/// The operand of the comparison `expr` that `PostgreSQL` compares through a cast able to
/// change its value, with that cast, when the comparison sets a column against literals
/// or the request clock.
///
/// The tuple SQL and the request clock read each operand as written, so such a cast
/// makes the model compare something else. A cast that renders text, or the clock cast
/// to its own type, changes nothing.
pub(crate) fn comparison_renaming_cast(expr: &Expr) -> Option<(&Expr, String)> {
    match unparenthesize(expr) {
        Expr::BinaryOp { left, op, right } if attribute_operator(op).is_some() => {
            renaming_beside(left, [right.as_ref()])
                .or_else(|| renaming_beside(right, [left.as_ref()]))
        }
        Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
            renaming_beside(left, [right.as_ref()])
                .or_else(|| renaming_beside(right, [left.as_ref()]))
        }
        Expr::Between {
            expr: column,
            low,
            high,
            negated: false,
        } => renaming_beside(column, [low.as_ref(), high.as_ref()]),
        other => {
            let (column, list) = constant_in_list(other)?;
            renaming_beside(column, list)
        }
    }
}

/// The renaming cast among `column` and the `values` it is compared with, when `column`
/// names a column and every value is a literal or the clock.
fn renaming_beside<'e>(
    column: &'e Expr,
    values: impl IntoIterator<Item = &'e Expr, IntoIter: Clone>,
) -> Option<(&'e Expr, String)> {
    let values = values.into_iter();
    if extract_column_name(column).is_none()
        || !values
            .clone()
            .all(|value| is_literal_value(value) || is_clock_shaped(value))
    {
        return None;
    }
    core::iter::once(column)
        .chain(values)
        .find_map(operand_renaming_cast)
}

/// Whether `expr` is the clock, or the clock shifted by any interval, whatever its casts.
fn is_clock_shaped(expr: &Expr) -> bool {
    let expr = unwrap_cast_or_nested(expr);
    is_well_known_temporal_function(expr) || shifted_clock(expr).is_some()
}

/// The clock operand of `now() ± interval`, read the way [`clock_shift`] reads it: the
/// left operand, or the right one of an addition.
fn shifted_clock(expr: &Expr) -> Option<&Expr> {
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };
    match op {
        BinaryOperator::Minus | BinaryOperator::Plus if is_well_known_temporal_function(left) => {
            Some(left)
        }
        BinaryOperator::Plus if is_well_known_temporal_function(right) => Some(right),
        _ => None,
    }
}

/// The cast around `operand` that can change its value, with the operand it wraps: any
/// cast but text on a literal or a column, any but `timestamptz` on the clock or on a
/// shifted clock.
fn operand_renaming_cast(operand: &Expr) -> Option<(&Expr, String)> {
    let (casts, peeled) = CastChain::peeled(operand);
    if !is_clock_shaped(peeled) {
        let cast = casts.renaming(None)?;
        return folded_literal(operand)
            .is_none()
            .then(|| (operand, cast.to_string()));
    }
    if let Some(cast) = casts.renaming_beyond(CLOCK_TYPE) {
        return Some((operand, cast.to_string()));
    }
    shifted_clock(peeled).and_then(operand_renaming_cast)
}

/// Whether `expr` reads the statement's clock, through any cast around it.
fn is_well_known_temporal_function(expr: &Expr) -> bool {
    clock_function(expr).is_some()
}

/// A function reading the statement's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClockFunction {
    /// A reading a timestamp threshold can carry.
    Reading(ClockReading),
    /// `localtime` and `current_time`, a time of day.
    TimeOfDay,
}

/// The clock function `expr` calls, through any cast around it.
fn clock_function(expr: &Expr) -> Option<ClockFunction> {
    let Expr::Function(func) = unwrap_cast_or_nested(expr) else {
        return None;
    };
    Some(match builtin_function_name(func).as_deref()? {
        "now"
        | "current_timestamp"
        | "clock_timestamp"
        | "statement_timestamp"
        | "transaction_timestamp" => ClockFunction::Reading(ClockReading::Instant),
        "localtimestamp" => ClockFunction::Reading(ClockReading::LocalTimestamp),
        "current_date" => ClockFunction::Reading(ClockReading::LocalDate),
        "localtime" | "current_time" => ClockFunction::TimeOfDay,
        _ => return None,
    })
}
