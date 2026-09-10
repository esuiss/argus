pub mod blind_index;
pub mod password;
pub mod sealing;

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};

use argus_core::pkce::Sha256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("failed to generate a signing key")]
    KeyGeneration,

    #[error("invalid PKCS#8 key material")]
    InvalidKeyMaterial,

    #[error("signing failed")]
    Signing,

    #[error("signature verification failed")]
    BadSignature,

    #[error("malformed public key point")]
    MalformedPublicKey,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AwsLcSha256;

impl Sha256 for AwsLcSha256 {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        let d = digest::digest(&digest::SHA256, input);
        let mut out = [0u8; 32];

        out.copy_from_slice(d.as_ref());
        out
    }
}

pub struct SigningKey {
    pair: EcdsaKeyPair,
    kid: String,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey(kid={:?}, alg=ES256)", self.kid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyComponents {
    pub kid: String,

    pub x: [u8; 32],

    pub y: [u8; 32],
}

impl PublicKeyComponents {
    #[must_use]
    pub const fn curve(&self) -> &'static str {
        "P-256"
    }

    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        "ES256"
    }
}

impl SigningKey {
    pub fn generate(kid: impl Into<String>) -> Result<(Self, Vec<u8>), CryptoError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| CryptoError::KeyGeneration)?;
        let bytes = pkcs8.as_ref().to_vec();
        let key = Self::from_pkcs8(kid, &bytes)?;
        Ok((key, bytes))
    }

    pub fn from_pkcs8(kid: impl Into<String>, pkcs8: &[u8]) -> Result<Self, CryptoError> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self {
            pair,
            kid: kid.into(),
        })
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let rng = SystemRandom::new();
        let sig = self
            .pair
            .sign(&rng, message)
            .map_err(|_| CryptoError::Signing)?;
        Ok(sig.as_ref().to_vec())
    }

    pub fn public_components(&self) -> Result<PublicKeyComponents, CryptoError> {
        let point = self.pair.public_key().as_ref();
        let (tag, rest) = point.split_first().ok_or(CryptoError::MalformedPublicKey)?;
        if *tag != 0x04 || rest.len() != 64 {
            return Err(CryptoError::MalformedPublicKey);
        }
        let (x_bytes, y_bytes) = rest.split_at(32);

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(x_bytes);
        y.copy_from_slice(y_bytes);

        Ok(PublicKeyComponents {
            kid: self.kid.clone(),
            x,
            y,
        })
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            point: self.pair.public_key().as_ref().to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    point: Vec<u8>,
}

impl VerifyingKey {
    #[must_use]
    pub fn from_components(x: &[u8; 32], y: &[u8; 32]) -> Self {
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        Self { point }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.point)
            .verify(message, signature)
            .map_err(|_| CryptoError::BadSignature)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{AwsLcSha256, CryptoError, SigningKey, VerifyingKey};
    use argus_core::pkce::{CodeChallenge, CodeChallengeMethod, Sha256 as _};
    use core::fmt::Write as _;

    #[test]
    fn rfc7636_appendix_b_verifies_with_real_sha256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge_b64 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let challenge = CodeChallenge::parse(CodeChallengeMethod::S256, challenge_b64)
            .expect("valid challenge");

        challenge
            .verify(verifier, &AwsLcSha256)
            .expect("RFC 7636 Appendix B vector must verify");
    }

    #[test]
    fn sha256_known_answer() {
        let d = AwsLcSha256.sha256(b"");
        let mut hex = String::new();
        for b in d {
            let _ = write!(hex, "{b:02x}");
        }
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (key, _pkcs8) = SigningKey::generate("k1").expect("key generation");
        let msg = b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhYmMifQ";

        let sig = key.sign(msg).expect("signing");
        key.verifying_key().verify(msg, &sig).expect("verification");
    }

    #[test]
    fn tampered_message_fails_verification() {
        let (key, _) = SigningKey::generate("k1").expect("key generation");
        let sig = key.sign(b"original").expect("signing");

        assert_eq!(
            key.verifying_key().verify(b"tampered", &sig).unwrap_err(),
            CryptoError::BadSignature
        );
    }

    #[test]
    fn another_key_cannot_verify() {
        let (a, _) = SigningKey::generate("a").expect("key generation");
        let (b, _) = SigningKey::generate("b").expect("key generation");
        let sig = a.sign(b"msg").expect("signing");

        assert_eq!(
            b.verifying_key().verify(b"msg", &sig).unwrap_err(),
            CryptoError::BadSignature
        );
    }

    #[test]
    fn key_survives_a_pkcs8_round_trip() {
        let (original, pkcs8) = SigningKey::generate("k1").expect("key generation");
        let restored = SigningKey::from_pkcs8("k1", &pkcs8).expect("restore");

        let sig = restored.sign(b"msg").expect("signing");
        original
            .verifying_key()
            .verify(b"msg", &sig)
            .expect("same key");
    }

    #[test]
    fn public_components_round_trip_through_jwk_coordinates() {
        let (key, _) = SigningKey::generate("k1").expect("key generation");
        let c = key.public_components().expect("components");

        assert_eq!(c.kid, "k1");
        assert_eq!(c.curve(), "P-256");
        assert_eq!(c.algorithm(), "ES256");

        let sig = key.sign(b"msg").expect("signing");
        VerifyingKey::from_components(&c.x, &c.y)
            .verify(b"msg", &sig)
            .expect("reconstructed key verifies");
    }

    #[test]
    fn invalid_pkcs8_is_rejected() {
        assert_eq!(
            SigningKey::from_pkcs8("k", b"not a key").unwrap_err(),
            CryptoError::InvalidKeyMaterial
        );
    }

    #[test]
    fn debug_reveals_only_the_kid() {
        let (key, pkcs8) = SigningKey::generate("kid-42").expect("key generation");
        let shown = format!("{key:?}");

        assert!(shown.contains("kid-42"), "got: {shown}");
        let mut hex = String::new();
        for b in &pkcs8 {
            let _ = write!(hex, "{b:02x}");
        }
        assert!(!shown.contains(&hex));
    }
}
