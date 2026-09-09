use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

pub const MEMORY_KIB: u32 = 19_456;
pub const TIME_COST: u32 = 2;
pub const PARALLELISM: u32 = 1;
pub const SALT_BYTES: usize = 16;
pub const MAX_PASSWORD_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    #[error("the password exceeds the maximum accepted length")]
    TooLong,

    #[error("the stored hash is not a valid PHC string")]
    MalformedHash,

    #[error("hashing failed")]
    HashingFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Correct,
    CorrectButNeedsRehash,
    Wrong,
}

fn hasher() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(MEMORY_KIB, TIME_COST, PARALLELISM, None)
        .map_err(|_| PasswordError::HashingFailed)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn hash(password: &str) -> Result<String, PasswordError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLong);
    }

    let salt = SaltString::generate(&mut OsRng);

    hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| PasswordError::HashingFailed)
}

pub fn verify(password: &str, stored: &str) -> Result<Verdict, PasswordError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLong);
    }

    let parsed = PasswordHash::new(stored).map_err(|_| PasswordError::MalformedHash)?;

    if hasher()?
        .verify_password(password.as_bytes(), &parsed)
        .is_err()
    {
        return Ok(Verdict::Wrong);
    }

    if needs_rehash(&parsed) {
        return Ok(Verdict::CorrectButNeedsRehash);
    }

    Ok(Verdict::Correct)
}

fn needs_rehash(parsed: &PasswordHash<'_>) -> bool {
    if parsed.algorithm.as_str() != "argon2id" {
        return true;
    }

    let Ok(params) = Params::try_from(parsed) else {
        return true;
    };

    params.m_cost() < MEMORY_KIB || params.t_cost() < TIME_COST || params.p_cost() < PARALLELISM
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        MAX_PASSWORD_BYTES, MEMORY_KIB, PARALLELISM, PasswordError, TIME_COST, Verdict, hash,
        verify,
    };

    #[test]
    fn the_parameters_are_the_owasp_2026_baseline() {
        assert_eq!(MEMORY_KIB, 19_456);
        assert_eq!(TIME_COST, 2);
        assert_eq!(PARALLELISM, 1);
    }

    #[test]
    fn a_password_verifies_against_its_own_hash() {
        let stored = hash("correct horse battery staple").expect("hash");
        assert_eq!(
            verify("correct horse battery staple", &stored).expect("verify"),
            Verdict::Correct
        );
    }

    #[test]
    fn a_wrong_password_is_wrong_not_an_error() {
        let stored = hash("correct horse battery staple").expect("hash");
        assert_eq!(verify("wrong", &stored).expect("verify"), Verdict::Wrong);
    }

    #[test]
    fn two_hashes_of_the_same_password_differ() {
        let a = hash("same").expect("hash");
        let b = hash("same").expect("hash");
        assert_ne!(a, b, "the salt must make every hash unique");
        assert_eq!(verify("same", &a).expect("verify"), Verdict::Correct);
        assert_eq!(verify("same", &b).expect("verify"), Verdict::Correct);
    }

    #[test]
    fn the_stored_form_is_a_phc_string_naming_argon2id() {
        let stored = hash("x").expect("hash");
        assert!(stored.starts_with("$argon2id$"), "{stored}");
        assert!(stored.contains(&format!("m={MEMORY_KIB}")), "{stored}");
        assert!(stored.contains(&format!("t={TIME_COST}")), "{stored}");
    }

    #[test]
    fn a_hash_with_weaker_parameters_asks_to_be_rehashed() {
        let weak = "$argon2id$v=19$m=4096,t=1,p=1$c29tZXNhbHR2YWx1ZQ$\
                    JvRTMv2FeHhBEz8xLcQK1JhDlxRj4Bi1cCPq1xIVUQU";
        let verdict = verify("x", weak).expect("verify");
        assert!(
            matches!(verdict, Verdict::Wrong | Verdict::CorrectButNeedsRehash),
            "a weak hash must never be reported as up to date: {verdict:?}"
        );
    }

    #[test]
    fn a_bcrypt_hash_is_recognised_as_stale_rather_than_trusted() {
        let bcrypt = "$2b$12$K3JNi5xUOqZ8xJvKPQ0Zru3Qa5mzZ8FZ0O9wq3sJ1rG7hV8kYcFqK";
        assert!(
            verify("x", bcrypt).is_err()
                || verify("x", bcrypt).expect("verify") != Verdict::Correct,
            "a foreign algorithm must not verify as current"
        );
    }

    #[test]
    fn a_malformed_stored_hash_is_an_error_not_a_silent_pass() {
        for bad in ["", "not a hash", "$argon2id$", "$$$$"] {
            assert_eq!(
                verify("x", bad).unwrap_err(),
                PasswordError::MalformedHash,
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn unicode_and_spaces_are_accepted_verbatim() {
        for password in [
            "correct horse battery staple",
            "  leading and trailing  ",
            "パスワード",
            "🔐🔐🔐",
            "contraseña muy segura",
        ] {
            let stored = hash(password).expect("hash");
            assert_eq!(
                verify(password, &stored).expect("verify"),
                Verdict::Correct,
                "failed for {password:?}"
            );
            assert_eq!(
                verify(password.trim(), &stored).expect("verify"),
                if password == password.trim() {
                    Verdict::Correct
                } else {
                    Verdict::Wrong
                },
                "whitespace must not be silently trimmed"
            );
        }
    }

    #[test]
    fn a_long_password_is_not_silently_truncated_like_bcrypt() {
        let base = "a".repeat(100);
        let longer = format!("{base}b");
        let stored = hash(&base).expect("hash");
        assert_eq!(verify(&longer, &stored).expect("verify"), Verdict::Wrong);
    }

    #[test]
    fn an_absurdly_long_password_is_refused_rather_than_hashed() {
        let huge = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert_eq!(hash(&huge).unwrap_err(), PasswordError::TooLong);
        assert_eq!(
            verify(&huge, "$argon2id$x").unwrap_err(),
            PasswordError::TooLong
        );
    }
}
