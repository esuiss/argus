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
