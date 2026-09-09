use core::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Aal {
    One,
    Two,
    Three,
}

impl Aal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::One => "aal1",
            Self::Two => "aal2",
            Self::Three => "aal3",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "aal1" => Some(Self::One),
            "aal2" => Some(Self::Two),
            "aal3" => Some(Self::Three),
            _ => None,
        }
    }

    #[must_use]
    pub fn satisfies(self, required: Self) -> bool {
        matches!(self.cmp(&required), Ordering::Equal | Ordering::Greater)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::Aal;

    #[test]
    fn the_ordering_is_the_schema_contract() {
        assert!(Aal::One < Aal::Two);
        assert!(Aal::Two < Aal::Three);
        assert!(Aal::One < Aal::Three);
    }

    #[test]
    fn a_stronger_level_satisfies_a_weaker_requirement() {
        assert!(Aal::Three.satisfies(Aal::One));
        assert!(Aal::Three.satisfies(Aal::Two));
        assert!(Aal::Two.satisfies(Aal::One));
    }

    #[test]
    fn an_equal_level_satisfies_the_requirement() {
        for level in [Aal::One, Aal::Two, Aal::Three] {
            assert!(level.satisfies(level));
        }
    }

    #[test]
    fn a_weaker_level_never_satisfies_a_stronger_requirement() {
        assert!(!Aal::One.satisfies(Aal::Two));
        assert!(!Aal::One.satisfies(Aal::Three));
        assert!(!Aal::Two.satisfies(Aal::Three));
    }

    #[test]
    fn the_wire_names_match_the_schema_enum_labels() {
        assert_eq!(Aal::One.as_str(), "aal1");
        assert_eq!(Aal::Two.as_str(), "aal2");
        assert_eq!(Aal::Three.as_str(), "aal3");
        for level in [Aal::One, Aal::Two, Aal::Three] {
            assert_eq!(Aal::parse(level.as_str()), Some(level));
        }
    }

    #[test]
    fn an_unknown_label_is_not_guessed_at() {
        for bad in ["", "aal0", "aal4", "AAL2", "two"] {
            assert!(Aal::parse(bad).is_none(), "accepted {bad}");
        }
    }
}
