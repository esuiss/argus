use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

use crate::CryptoError;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = NONCE_LEN;
pub const TAG_BYTES: usize = 16;
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;

pub struct SealingKey {
    key: LessSafeKey,
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKey(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl SealingKey {
    pub fn new(material: &[u8]) -> Result<Self, CryptoError> {
        if material.len() != KEY_BYTES {
            return Err(CryptoError::InvalidKeyMaterial);
        }

        let unbound =
            UnboundKey::new(&AES_256_GCM, material).map_err(|_| CryptoError::InvalidKeyMaterial)?;

        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    pub fn seal(&self, plaintext: &[u8], associated: &[u8]) -> Result<Sealed, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(CryptoError::InvalidKeyMaterial);
        }

        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::Signing)?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buffer = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(associated), &mut buffer)
            .map_err(|_| CryptoError::Signing)?;

        Ok(Sealed {
            nonce: nonce_bytes,
            ciphertext: buffer,
        })
    }

    pub fn open(&self, sealed: &Sealed, associated: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.ciphertext.len() < TAG_BYTES {
            return Err(CryptoError::BadSignature);
        }

        let nonce = Nonce::assume_unique_for_key(sealed.nonce);
        let mut buffer = sealed.ciphertext.clone();

        let opened = self
            .key
            .open_in_place(nonce, Aad::from(associated), &mut buffer)
            .map_err(|_| CryptoError::BadSignature)?;

        Ok(opened.to_vec())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::{KEY_BYTES, Sealed, SealingKey};

    fn key(fill: u8) -> SealingKey {
        SealingKey::new(&[fill; KEY_BYTES]).expect("key")
    }

    #[test]
    fn a_secret_round_trips_through_the_key_that_sealed_it() {
        let sealing = key(7);
        let sealed = sealing
            .seal(b"upstream refresh token", b"tenant:a")
            .expect("seal");

        assert_eq!(
            sealing.open(&sealed, b"tenant:a").expect("open"),
            b"upstream refresh token"
        );
    }

    #[test]
    fn the_ciphertext_never_contains_the_plaintext() {
        let sealing = key(7);
        let sealed = sealing.seal(b"hunter2", b"tenant:a").expect("seal");

        assert!(
            !sealed
                .ciphertext
                .windows(7)
                .any(|window| window == b"hunter2"),
            "a secret at rest must not be readable by anyone who can read the table"
        );
    }

    #[test]
    fn another_key_cannot_open_what_this_one_sealed() {
        let sealed = key(7).seal(b"secret", b"tenant:a").expect("seal");
        assert!(key(9).open(&sealed, b"tenant:a").is_err());
    }

    #[test]
    fn a_secret_sealed_for_one_tenant_does_not_open_for_another() {
        let sealing = key(7);
        let sealed = sealing.seal(b"secret", b"tenant:a").expect("seal");

        assert!(
            sealing.open(&sealed, b"tenant:b").is_err(),
            "binding the tenant into the associated data is what stops a row being moved sideways"
        );
    }

    #[test]
    fn a_flipped_byte_in_the_ciphertext_is_detected() {
        let sealing = key(7);
        let mut sealed = sealing.seal(b"secret", b"tenant:a").expect("seal");
        sealed.ciphertext[0] ^= 0x01;

        assert!(sealing.open(&sealed, b"tenant:a").is_err());
    }

    #[test]
    fn a_flipped_byte_in_the_nonce_is_detected() {
        let sealing = key(7);
        let mut sealed = sealing.seal(b"secret", b"tenant:a").expect("seal");
        sealed.nonce[0] ^= 0x01;

        assert!(sealing.open(&sealed, b"tenant:a").is_err());
    }

    #[test]
    fn two_sealings_of_one_secret_differ() {
        let sealing = key(7);
        let first = sealing.seal(b"secret", b"tenant:a").expect("seal");
        let second = sealing.seal(b"secret", b"tenant:a").expect("seal");

        assert_ne!(
            first.nonce, second.nonce,
            "a repeated nonce under one key is what breaks this mode outright"
        );
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(SealingKey::new(&[0_u8; 16]).is_err());
        assert!(SealingKey::new(&[]).is_err());
    }

    #[test]
    fn a_truncated_ciphertext_is_refused_rather_than_read() {
        let sealing = key(7);
        let sealed = sealing.seal(b"secret", b"tenant:a").expect("seal");

        let truncated = Sealed {
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext[..4].to_vec(),
        };

        assert!(sealing.open(&truncated, b"tenant:a").is_err());
    }

    #[test]
    fn the_key_never_prints_its_material() {
        let rendered = format!("{:?}", key(7));
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains('7'));
    }
}
