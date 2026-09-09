use core::fmt;

macro_rules! define_epoch {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*

        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(u64);

        impl $name {
            pub const ZERO: Self = Self(0);

            #[must_use]
            pub const fn from_raw(value: u64) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_raw(self) -> u64 {
                self.0
            }

            #[must_use]
            pub const fn next(self) -> Self {
                Self(self.0.saturating_add(1))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_epoch! {
    SessionEpoch
}

define_epoch! {
    AuthzEpoch
}

define_epoch! {
    KeyEpoch
}

impl SessionEpoch {
    #[must_use]
    pub const fn is_token_revoked(self, token: Self) -> bool {
        token.0 < self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthzEpoch, KeyEpoch, SessionEpoch};

    #[test]
    fn epochs_start_at_zero() {
        assert_eq!(SessionEpoch::default(), SessionEpoch::ZERO);
        assert_eq!(AuthzEpoch::default().as_raw(), 0);
        assert_eq!(KeyEpoch::ZERO.as_raw(), 0);
    }

    #[test]
    fn next_is_monotonic() {
        let a = SessionEpoch::ZERO;
        let b = a.next();
        assert!(b > a);
        assert_eq!(b.as_raw(), 1);
    }

    #[test]
    fn next_saturates_instead_of_wrapping() {
        let max = SessionEpoch::from_raw(u64::MAX);
        assert_eq!(max.next(), max);
    }

    #[test]
    fn older_token_epoch_is_revoked() {
        let current = SessionEpoch::from_raw(5);
        assert!(current.is_token_revoked(SessionEpoch::from_raw(0)));
        assert!(current.is_token_revoked(SessionEpoch::from_raw(4)));
    }

    #[test]
    fn equal_or_newer_token_epoch_is_live() {
        let current = SessionEpoch::from_raw(5);
        assert!(!current.is_token_revoked(SessionEpoch::from_raw(5)));

        assert!(!current.is_token_revoked(SessionEpoch::from_raw(6)));
    }

    #[test]
    fn debug_shows_the_value() {
        assert_eq!(
            format!("{:?}", SessionEpoch::from_raw(7)),
            "SessionEpoch(7)"
        );
        assert_eq!(format!("{:?}", AuthzEpoch::from_raw(7)), "AuthzEpoch(7)");
    }
}
