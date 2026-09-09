pub const MIN_LENGTH: usize = 8;
pub const RECOMMENDED_LENGTH: usize = 15;
pub const MAX_LENGTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("the password is shorter than the minimum accepted length")]
    TooShort,

    #[error("the password is longer than the maximum accepted length")]
    TooLong,

    #[error("the password appears in a known breach corpus")]
    Breached,
}

pub trait BreachCorpus {
    fn contains(&self, password: &str) -> bool;
}

pub struct NoBreachCorpus;

impl BreachCorpus for NoBreachCorpus {
    fn contains(&self, _password: &str) -> bool {
        false
    }
}

pub fn check(password: &str, corpus: &impl BreachCorpus) -> Result<(), PolicyError> {
    let length = password.chars().count();

    if length < MIN_LENGTH {
        return Err(PolicyError::TooShort);
    }

    if length > MAX_LENGTH {
        return Err(PolicyError::TooLong);
    }

    if corpus.contains(password) {
        return Err(PolicyError::Breached);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        BreachCorpus, MAX_LENGTH, MIN_LENGTH, NoBreachCorpus, PolicyError, RECOMMENDED_LENGTH,
        check,
    };

    struct Leaked(&'static str);

    impl BreachCorpus for Leaked {
        fn contains(&self, password: &str) -> bool {
            password == self.0
        }
    }

    #[test]
    fn the_limits_follow_nist_800_63_4() {
        assert_eq!(MIN_LENGTH, 8);
        const { assert!(RECOMMENDED_LENGTH >= 15) };
        const { assert!(MAX_LENGTH >= 64, "NIST requires at least 64 to be accepted") };
    }

    #[test]
    fn a_long_passphrase_is_accepted() {
        assert_eq!(
            check("correct horse battery staple", &NoBreachCorpus),
            Ok(())
        );
    }

    #[test]
    fn there_are_no_composition_rules() {
        for password in [
            "aaaaaaaaaaaaaaaa",
            "12345678901234567890",
            "all lower case words here",
            "ALL UPPER CASE WORDS HERE",
        ] {
            assert_eq!(
                check(password, &NoBreachCorpus),
                Ok(()),
                "composition rule leaked in for {password:?}"
            );
        }
    }

    #[test]
    fn spaces_and_unicode_count_as_characters() {
        assert_eq!(check("        ", &NoBreachCorpus), Ok(()));
        assert_eq!(check("パスワードですよ", &NoBreachCorpus), Ok(()));
        assert_eq!(check("🔐🔐🔐🔐🔐🔐🔐🔐", &NoBreachCorpus), Ok(()));
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        let eight_emoji = "🔐".repeat(8);
        assert!(
            eight_emoji.len() > MIN_LENGTH,
            "byte length would pass anyway"
        );
        assert_eq!(check(&eight_emoji, &NoBreachCorpus), Ok(()));

        let seven_emoji = "🔐".repeat(7);
        assert_eq!(
            check(&seven_emoji, &NoBreachCorpus).unwrap_err(),
            PolicyError::TooShort,
            "a 28-byte but 7-character password must be refused"
        );
    }

    #[test]
    fn the_boundaries_are_exact() {
        assert_eq!(
            check(&"a".repeat(MIN_LENGTH - 1), &NoBreachCorpus).unwrap_err(),
            PolicyError::TooShort
        );
        assert_eq!(check(&"a".repeat(MIN_LENGTH), &NoBreachCorpus), Ok(()));
        assert_eq!(check(&"a".repeat(MAX_LENGTH), &NoBreachCorpus), Ok(()));
        assert_eq!(
            check(&"a".repeat(MAX_LENGTH + 1), &NoBreachCorpus).unwrap_err(),
            PolicyError::TooLong
        );
    }

    #[test]
    fn a_breached_password_is_refused() {
        let corpus = Leaked("correct horse battery staple");
        assert_eq!(
            check("correct horse battery staple", &corpus).unwrap_err(),
            PolicyError::Breached
        );
        assert_eq!(check("some other passphrase", &corpus), Ok(()));
    }

    #[test]
    fn length_is_checked_before_the_corpus_is_consulted() {
        struct Everything;
        impl BreachCorpus for Everything {
            fn contains(&self, _password: &str) -> bool {
                true
            }
        }
        assert_eq!(
            check("short", &Everything).unwrap_err(),
            PolicyError::TooShort,
            "a short password must not be sent to an external corpus"
        );
    }
}
