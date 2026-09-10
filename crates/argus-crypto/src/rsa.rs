use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair, PublicKeyComponents};
use aws_lc_rs::signature::{
    KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, UnparsedPublicKey,
};

use crate::CryptoError;

pub const MIN_MODULUS_BITS: usize = 2048;

pub struct RsaSigningKey {
    kid: String,
    key: KeyPair,
}

impl core::fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaSigningKey")
            .field("kid", &self.kid)
            .field("modulus_bits", &(self.key.public_modulus_len() * 8))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicComponents {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl RsaSigningKey {
    pub fn from_pkcs8(kid: impl Into<String>, pkcs8: &[u8]) -> Result<Self, CryptoError> {
        let key = KeyPair::from_pkcs8(pkcs8).map_err(|_| CryptoError::InvalidKeyMaterial)?;

        if key.public_modulus_len().saturating_mul(8) < MIN_MODULUS_BITS {
            return Err(CryptoError::InvalidKeyMaterial);
        }

        Ok(Self {
            kid: kid.into(),
            key,
        })
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        self.key.public_modulus_len().saturating_mul(8)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut signature = vec![0_u8; self.key.public_modulus_len()];

        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| CryptoError::Signing)?;

        Ok(signature)
    }

    pub fn public_components(&self) -> Result<RsaPublicComponents, CryptoError> {
        let components: PublicKeyComponents<Vec<u8>> =
            PublicKeyComponents::from(self.key.public_key());

        Ok(RsaPublicComponents {
            n: components.n,
            e: components.e,
        })
    }

    pub fn verifying_key(&self) -> Result<RsaVerifyingKey, CryptoError> {
        Ok(RsaVerifyingKey {
            spki: self.key.public_key().as_ref().to_vec(),
        })
    }
}

pub struct RsaVerifyingKey {
    spki: Vec<u8>,
}

impl core::fmt::Debug for RsaVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RsaVerifyingKey")
    }
}

impl RsaVerifyingKey {
    #[must_use]
    pub fn from_der(spki: Vec<u8>) -> Self {
        Self { spki }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.spki)
            .verify(message, signature)
            .map_err(|_| CryptoError::BadSignature)
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
    use super::{MIN_MODULUS_BITS, RsaSigningKey};

    fn key() -> RsaSigningKey {
        let pkcs8 = include_bytes!("../tests/fixtures/rsa-2048.pkcs8");
        RsaSigningKey::from_pkcs8("rsa-1", pkcs8).expect("key")
    }

    #[test]
    fn a_signature_this_key_makes_verifies_against_its_own_public_key() {
        let signing = key();
        let signature = signing.sign(b"the payload").expect("sign");

        signing
            .verifying_key()
            .expect("public key")
            .verify(b"the payload", &signature)
            .expect("verify");
    }

    #[test]
    fn a_signature_does_not_verify_over_different_bytes() {
        let signing = key();
        let signature = signing.sign(b"the payload").expect("sign");

        assert!(
            signing
                .verifying_key()
                .expect("public key")
                .verify(b"another payload", &signature)
                .is_err()
        );
    }

    #[test]
    fn the_key_carries_a_modulus_large_enough_for_the_profile() {
        assert!(key().modulus_bits() >= MIN_MODULUS_BITS);
    }

    #[test]
    fn a_key_that_is_not_pkcs8_is_refused() {
        assert!(RsaSigningKey::from_pkcs8("x", b"not a key").is_err());
    }

    #[test]
    fn the_public_components_are_the_ones_a_jwks_publishes() {
        let components = key().public_components().expect("components");
        assert_eq!(components.n.len(), 256, "a 2048 bit modulus is 256 bytes");
        assert!(!components.e.is_empty());
    }

    #[test]
    fn the_key_never_prints_its_private_material() {
        let rendered = format!("{:?}", key());
        assert!(rendered.contains("rsa-1"));
        assert!(rendered.contains("2048"));
    }
}
