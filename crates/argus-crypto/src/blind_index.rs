use aws_lc_rs::hmac;

pub const KEY_BYTES: usize = 32;
pub const INDEX_BYTES: usize = 32;

#[derive(Clone)]
pub struct BlindIndexKey {
    key: hmac::Key,
}

impl core::fmt::Debug for BlindIndexKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BlindIndexKey(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlindIndexError {
    #[error("a blind index key must be at least 32 bytes")]
    KeyTooShort,
}

impl BlindIndexKey {
    pub fn new(secret: &[u8]) -> Result<Self, BlindIndexError> {
        if secret.len() < KEY_BYTES {
            return Err(BlindIndexError::KeyTooShort);
        }
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        })
    }

    #[must_use]
    pub fn compute(&self, value: &str) -> [u8; INDEX_BYTES] {
        let normalised = value.trim().to_lowercase();
        let tag = hmac::sign(&self.key, normalised.as_bytes());

        let mut out = [0u8; INDEX_BYTES];
        out.copy_from_slice(tag.as_ref());
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{BlindIndexError, BlindIndexKey, KEY_BYTES};

    fn key(fill: u8) -> BlindIndexKey {
        BlindIndexKey::new(&[fill; KEY_BYTES]).expect("key")
    }

    #[test]
    fn the_same_value_always_yields_the_same_index() {
        let k = key(1);
        assert_eq!(k.compute("user@example.com"), k.compute("user@example.com"));
    }

    #[test]
    fn different_values_yield_different_indexes() {
        let k = key(1);
        assert_ne!(k.compute("a@example.com"), k.compute("b@example.com"));
    }

    #[test]
    fn a_different_key_yields_a_different_index_for_the_same_value() {
        assert_ne!(
            key(1).compute("user@example.com"),
            key(2).compute("user@example.com"),
            "without this an offline dictionary of emails would transfer between tenants"
        );
    }

    #[test]
    fn the_index_is_not_a_plain_hash_of_the_value() {
        use crate::AwsLcSha256;
        use argus_core::pkce::Sha256 as _;

        let plain = AwsLcSha256.sha256(b"user@example.com");
        assert_ne!(
            key(1).compute("user@example.com"),
            plain,
            "an unkeyed digest of an email is reversible with a wordlist"
        );
    }

    #[test]
    fn lookup_is_case_and_whitespace_insensitive() {
        let k = key(1);
        let canonical = k.compute("user@example.com");
        for variant in [
            "USER@EXAMPLE.COM",
            "  user@example.com  ",
            "User@Example.Com",
        ] {
            assert_eq!(k.compute(variant), canonical, "failed for {variant:?}");
        }
    }

    #[test]
    fn a_short_key_is_refused() {
        assert_eq!(
            BlindIndexKey::new(&[0u8; KEY_BYTES - 1]).unwrap_err(),
            BlindIndexError::KeyTooShort
        );
        assert!(BlindIndexKey::new(&[0u8; KEY_BYTES]).is_ok());
    }

    #[test]
    fn the_key_never_appears_in_debug_output() {
        let shown = format!("{:?}", key(0xAB));
        assert!(!shown.contains("ab"), "leaked: {shown}");
        assert!(shown.contains("redacted"));
    }
}
