use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Duration(i64);

impl Timestamp {
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    #[must_use]
    pub const fn as_unix_seconds(self) -> i64 {
        self.0
    }

    #[must_use]
    pub const fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.0))
    }

    #[must_use]
    pub const fn since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    #[must_use]
    pub const fn is_after(self, deadline: Self) -> bool {
        self.0 > deadline.0
    }
}

#[must_use]
#[allow(
    clippy::integer_division,
    reason = "the proleptic Gregorian calendar conversion is exact integer arithmetic"
)]
pub fn rfc3339(at: Timestamp) -> String {
    let seconds = at.as_unix_seconds();
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);

    let hour = rest / 3_600;
    let minute = (rest % 3_600) / 60;
    let second = rest % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[allow(
    clippy::integer_division,
    reason = "the proleptic Gregorian calendar conversion is exact integer arithmetic"
)]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * shifted_month + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    })
    .unwrap_or(1);
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

impl Duration {
    #[must_use]
    pub const fn from_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    #[must_use]
    pub const fn as_seconds(self) -> i64 {
        self.0
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, Timestamp};

    #[test]
    fn expiry_boundary_is_inclusive() {
        let deadline = Timestamp::from_unix_seconds(1_000);

        assert!(!Timestamp::from_unix_seconds(1_000).is_after(deadline));
        assert!(Timestamp::from_unix_seconds(1_001).is_after(deadline));
        assert!(!Timestamp::from_unix_seconds(999).is_after(deadline));
    }

    #[test]
    fn add_saturates_instead_of_panicking() {
        let far = Timestamp::from_unix_seconds(i64::MAX);
        assert_eq!(far.saturating_add(Duration::from_seconds(60)), far);
    }

    #[test]
    fn since_measures_elapsed_time() {
        let t0 = Timestamp::from_unix_seconds(100);
        let t1 = Timestamp::from_unix_seconds(160);
        assert_eq!(t1.since(t0), Duration::from_seconds(60));
        assert_eq!(t0.since(t1), Duration::from_seconds(-60));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod rfc3339_tests {
    use super::{Timestamp, rfc3339};

    #[test]
    fn the_epoch_renders_as_the_start_of_1970() {
        assert_eq!(
            rfc3339(Timestamp::from_unix_seconds(0)),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn a_leap_day_is_rendered_as_the_twenty_ninth_of_february() {
        assert_eq!(
            rfc3339(Timestamp::from_unix_seconds(1_709_164_800)),
            "2024-02-29T00:00:00Z"
        );
    }

    #[test]
    fn the_day_after_a_non_leap_february_is_the_first_of_march() {
        assert_eq!(
            rfc3339(Timestamp::from_unix_seconds(1_677_628_800)),
            "2023-03-01T00:00:00Z"
        );
    }

    #[test]
    fn the_rfc7644_example_timestamp_round_trips() {
        assert_eq!(
            rfc3339(Timestamp::from_unix_seconds(1_305_261_754)),
            "2011-05-13T04:42:34Z"
        );
    }

    #[test]
    fn a_moment_before_the_epoch_does_not_wrap_into_the_future() {
        assert_eq!(
            rfc3339(Timestamp::from_unix_seconds(-1)),
            "1969-12-31T23:59:59Z"
        );
    }

    #[test]
    fn rendered_timestamps_sort_the_same_way_the_instants_do() {
        let mut moments = [1_305_261_754_i64, 0, 1_709_164_800, 946_684_800];
        moments.sort_unstable();
        let rendered: Vec<String> = moments
            .iter()
            .map(|s| rfc3339(Timestamp::from_unix_seconds(*s)))
            .collect();
        let mut sorted = rendered.clone();
        sorted.sort();
        assert_eq!(
            rendered, sorted,
            "SCIM filters compare meta.lastModified as a string, so the two orders must agree"
        );
    }
}
