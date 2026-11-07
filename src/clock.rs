#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;

use sql_values::{
    DateTimeError, PgInterval, PgTime, PgTimeZone, PgTimestamp, PgTimestampTz, ShiftError,
};

use crate::types::ConditionParameterName;

/// The request clock as a guard reads it, shifted by an interval, which the request
/// supplies rather than the row.
///
/// `PostgreSQL` adds an interval's months and days on the calendar of the session
/// `TimeZone`, and `current_date` and `localtimestamp` read the clock in that zone, so
/// only an instant shifted by microseconds alone has one value in every zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockThreshold {
    /// What the guard reads off the clock.
    pub reading: ClockReading,
    /// The interval added to the reading.
    pub offset: ClockOffset,
}

/// What a guard reads off the statement's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClockReading {
    /// `now()` and its spellings, the instant itself.
    Instant,
    /// `localtimestamp`, the instant's wall clock in the session `TimeZone`.
    LocalTimestamp,
    /// `current_date`, the instant's date in the session `TimeZone`.
    LocalDate,
}

/// An interval added to a clock reading, negated where the guard subtracts it.
///
/// Equal field by field. `PgInterval` equates a month with thirty days, which shift a
/// clock to different instants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockOffset {
    /// Months, added on the zone's calendar.
    pub months: i32,
    /// Days, added on the zone's calendar.
    pub days: i32,
    /// Microseconds, added after the months and days.
    pub microseconds: i64,
}

impl ClockOffset {
    /// No shift at all.
    pub const ZERO: Self = Self {
        months: 0,
        days: 0,
        microseconds: 0,
    };

    /// Whether the offset has one length in every time zone, counting no months or days.
    #[must_use]
    pub const fn is_fixed(self) -> bool {
        self.months == 0 && self.days == 0
    }

    /// The offset as the interval `PostgreSQL` adds.
    #[must_use]
    pub const fn interval(self) -> PgInterval {
        PgInterval {
            months: self.months,
            days: self.days,
            microseconds: self.microseconds,
        }
    }
}

impl From<PgInterval> for ClockOffset {
    fn from(interval: PgInterval) -> Self {
        Self {
            months: interval.months,
            days: interval.days,
            microseconds: interval.microseconds,
        }
    }
}

impl ClockThreshold {
    /// The bare instant, `now()`.
    pub const INSTANT: Self = Self {
        reading: ClockReading::Instant,
        offset: ClockOffset::ZERO,
    };

    /// The instant `PostgreSQL` compares a `timestamptz` column with when the statement
    /// runs at `request_time` with `zone` as its `TimeZone`.
    ///
    /// An instant is shifted as `timestamptz + interval` shifts it. A local reading is
    /// shifted as `timestamp + interval` shifts the zoneless clock, then read back in
    /// `zone`, as the comparison with the column reads it.
    ///
    /// ```
    /// use rls2fga::clock::{ClockOffset, ClockReading, ClockThreshold};
    /// use sql_values::{InputContext, PgTimeZone, PgTimestampTz};
    ///
    /// let rome = PgTimeZone::parse("Europe/Rome").unwrap();
    /// let at = PgTimestampTz::parse("2026-03-29 12:00+02", InputContext::new()).unwrap();
    /// let day_before = ClockThreshold {
    ///     reading: ClockReading::Instant,
    ///     offset: ClockOffset { months: 0, days: -1, microseconds: 0 },
    /// };
    /// // Twenty three hours back, across the spring change.
    /// assert_eq!(day_before.at(at, &rome).unwrap().to_string(), "2026-03-28 11:00:00+00");
    /// ```
    ///
    /// # Errors
    ///
    /// The error `PostgreSQL` raises computing the threshold, such as `timestamp out of
    /// range`.
    pub fn at(
        self,
        request_time: PgTimestampTz,
        zone: &PgTimeZone,
    ) -> Result<PgTimestampTz, ClockError> {
        let interval = self.offset.interval();
        let local = |clock: PgTimestamp| -> Result<PgTimestampTz, ClockError> {
            Ok(interval.add_to_timestamp(clock)?.to_timestamptz(zone)?)
        };
        match self.reading {
            ClockReading::Instant => Ok(interval.add_to_timestamptz(request_time, zone)?),
            ClockReading::LocalTimestamp => local(request_time.to_timestamp(zone)?),
            ClockReading::LocalDate => local(
                PgTimestamp::new(request_time.to_date(zone)?, PgTime::MIDNIGHT)
                    .ok_or(DateTimeError::TimestampOutOfRange)?,
            ),
        }
    }

    /// What a parameter holding this threshold appends to the clock parameter's name,
    /// nothing for the bare instant: `_current_date_minus_1_day`, with each term's sign
    /// written where it changes and the microseconds as the CEL duration of their
    /// magnitude.
    pub(crate) fn name_suffix(self) -> String {
        let mut name = String::from(match self.reading {
            ClockReading::Instant => "",
            ClockReading::LocalTimestamp => "_localtimestamp",
            ClockReading::LocalDate => "_current_date",
        });
        let ClockOffset {
            months,
            days,
            microseconds,
        } = self.offset;
        let terms = [
            (i64::from(months), months_words(months.unsigned_abs())),
            (i64::from(days), counted(days.unsigned_abs(), "day")),
            (microseconds, cel_duration(microseconds.unsigned_abs())),
        ];
        let mut negative = None;
        for (value, words) in terms {
            if value == 0 {
                continue;
            }
            if negative != Some(value < 0) {
                name.push_str(if value < 0 { "_minus" } else { "_plus" });
                negative = Some(value < 0);
            }
            name.push('_');
            name.push_str(&words);
        }
        name
    }
}

/// A month count as `PostgreSQL` prints it, in years and months: `1_year_2_mons`.
fn months_words(months: u32) -> String {
    let (years, months) = (months / 12, months % 12);
    match (years, months) {
        (0, months) => counted(months, "mon"),
        (years, 0) => counted(years, "year"),
        (years, months) => format!("{}_{}", counted(years, "year"), counted(months, "mon")),
    }
}

/// `count` of `unit`, plural but for one.
fn counted(count: u32, unit: &str) -> String {
    if count == 1 {
        format!("1_{unit}")
    } else {
        format!("{count}_{unit}s")
    }
}

/// A positive count of microseconds as a CEL duration, in the coarsest unit holding it
/// exactly.
pub(crate) fn cel_duration(microseconds: u64) -> String {
    let (size, unit) = [
        (3_600_000_000, "h"),
        (60_000_000, "m"),
        (1_000_000, "s"),
        (1_000, "ms"),
    ]
    .into_iter()
    .find(|&(size, _)| microseconds.is_multiple_of(size))
    .unwrap_or((1, "us"));
    format!("{}{unit}", microseconds / size)
}

/// Why a threshold has no value the checker can supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    /// Shifting the clock fails as it does in `PostgreSQL`.
    #[error(transparent)]
    Shift(#[from] ShiftError),
    /// Reading the clock in the zone, or back out of it, fails as it does in `PostgreSQL`.
    #[error(transparent)]
    DateTime(#[from] DateTimeError),
    /// The threshold lies outside the years 1 to 9999 a CEL timestamp holds.
    #[error("{0} lies outside the years 1 to 9999 a CEL timestamp holds")]
    OutsideCelRange(PgTimestampTz),
}

/// A condition parameter the model declares for one clock threshold, which the checker
/// computes and supplies at every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockParameter {
    name: ConditionParameterName,
    threshold: ClockThreshold,
}

impl ClockParameter {
    pub(crate) fn new(name: ConditionParameterName, threshold: ClockThreshold) -> Self {
        Self { name, threshold }
    }

    /// The key the check context carries the threshold under.
    #[must_use]
    pub fn name(&self) -> &ConditionParameterName {
        &self.name
    }

    /// The threshold the parameter holds.
    #[must_use]
    pub fn threshold(&self) -> &ClockThreshold {
        &self.threshold
    }

    /// The parameter's context value at `request_time` in `zone`, an RFC 3339 instant in
    /// `UTC` as a CEL `timestamp` reads it.
    ///
    /// # Errors
    ///
    /// The [`ClockError`] computing the threshold, or
    /// [`ClockError::OutsideCelRange`] where CEL has no timestamp for it.
    pub fn value(
        &self,
        request_time: PgTimestampTz,
        zone: &PgTimeZone,
    ) -> Result<String, ClockError> {
        let at = self.threshold.at(request_time, zone)?;
        rfc3339(at).ok_or(ClockError::OutsideCelRange(at))
    }
}

/// Why a check context could not be computed, naming the parameter that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the threshold `{parameter}` has no value: {source}")]
pub struct ClockContextError {
    pub(crate) parameter: ConditionParameterName,
    #[source]
    pub(crate) source: ClockError,
}

impl ClockContextError {
    /// The parameter whose threshold failed.
    #[must_use]
    pub fn parameter(&self) -> &ConditionParameterName {
        &self.parameter
    }

    /// Why it failed.
    #[must_use]
    pub fn error(&self) -> ClockError {
        self.source
    }
}

/// `at` as `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`, or `None` outside the years 1 to 9999.
fn rfc3339(at: PgTimestampTz) -> Option<String> {
    // `2026-03-28 11:00:00.5+00`, with ` BC` after a year before 1, five digits after
    // 9999, and `infinity` for either infinity.
    let text = at.to_string();
    let utc = text.strip_suffix("+00")?;
    let (date, clock) = utc.split_once(' ')?;
    (date.len() == 10).then(|| format!("{date}T{clock}Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_spans_the_years_cel_holds() {
        let render =
            |micros: i64| rfc3339(PgTimestampTz::from_pg_micros(micros).expect("a stored instant"));
        // 0001-01-01 00:00:00+00 and 9999-12-31 23:59:59.999999+00.
        let first = -63_082_281_600_000_000;
        let last = 252_455_615_999_999_999;
        assert_eq!(render(first).as_deref(), Some("0001-01-01T00:00:00Z"));
        assert_eq!(render(first - 1), None);
        assert_eq!(render(last).as_deref(), Some("9999-12-31T23:59:59.999999Z"));
        assert_eq!(render(last + 1), None);
        assert_eq!(render(500_000).as_deref(), Some("2000-01-01T00:00:00.5Z"));
        assert_eq!(rfc3339(PgTimestampTz::INFINITY), None);
        assert_eq!(rfc3339(PgTimestampTz::NEG_INFINITY), None);
    }
}
