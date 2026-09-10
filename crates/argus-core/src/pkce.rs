use base64ct::{Base64UrlUnpadded, Encoding as _};
use subtle::ConstantTimeEq as _;

use crate::error::PkceError;

const VERIFIER_MIN_LEN: usize = 43;

const VERIFIER_MAX_LEN: usize = 128;

pub trait Sha256 {
    fn sha256(&self, input: &[u8]) -> [u8; 32];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeChallengeMethod {
    S256,
}

impl CodeChallengeMethod {
    pub fn parse(value: &str) -> Result<Self, PkceError> {
        match value {
            "S256" => Ok(Self::S256),
            other => Err(PkceError::UnsupportedMethod {
                method: other.to_owned(),
            }),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CodeChallenge {
    method: CodeChallengeMethod,

    digest: [u8; 32],
}

impl CodeChallenge {
    pub fn parse(method: CodeChallengeMethod, raw: &str) -> Result<Self, PkceError> {
        let mut digest = [0u8; 32];
        let decoded = Base64UrlUnpadded::decode(raw, &mut digest)
            .map_err(|_| PkceError::MalformedChallenge)?;

        if decoded.len() != 32 {
            return Err(PkceError::ChallengeWrongLength { len: decoded.len() });
        }

        Ok(Self { method, digest })
    }

    #[must_use]
    pub const fn method(&self) -> CodeChallengeMethod {
        self.method
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    // RFC 7636 §4.6. §8 §5254: RFC sabit zamanı ZORUNLU KILMIYOR, "ama maliyeti
    // sıfır olduğundan yine de yapın". Elle yazılmış bir karşılaştırma derleyici
    // tarafından kaldırılabilir; `subtle` tam olarak bunu engellemek için var
    // (Cargo.toml, subtle gerekçesi).
    pub fn verify(&self, verifier: &str, hasher: &impl Sha256) -> Result<(), PkceError> {
        validate_verifier_syntax(verifier)?;

        let CodeChallengeMethod::S256 = self.method;
        let actual = hasher.sha256(verifier.as_bytes());

        if actual.ct_eq(&self.digest).into() {
            Ok(())
        } else {
            Err(PkceError::VerifierMismatch)
        }
    }
}

impl core::fmt::Debug for CodeChallenge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CodeChallenge({}, {:02x}{:02x}…)",
            self.method.as_str(),
            self.digest[0],
            self.digest[1]
        )
    }
}

fn validate_verifier_syntax(verifier: &str) -> Result<(), PkceError> {
    let len = verifier.len();
    if !(VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&len) {
        return Err(PkceError::VerifierWrongLength { len });
    }

    if !verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(PkceError::VerifierInvalidChar);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CodeChallenge, CodeChallengeMethod, Sha256};
    use crate::error::PkceError;

    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    const RFC_DIGEST: [u8; 32] = [
        19, 211, 30, 150, 26, 26, 216, 236, 47, 22, 177, 12, 76, 152, 46, 8, 118, 168, 120, 173,
        109, 241, 68, 86, 110, 225, 137, 74, 203, 112, 249, 195,
    ];

    struct FakeSha256;

    impl Sha256 for FakeSha256 {
        fn sha256(&self, input: &[u8]) -> [u8; 32] {
            if input == RFC_VERIFIER.as_bytes() {
                RFC_DIGEST
            } else {
                [0xFF; 32]
            }
        }
    }

    fn challenge() -> CodeChallenge {
        CodeChallenge::parse(CodeChallengeMethod::S256, RFC_CHALLENGE).unwrap()
    }

    #[test]
    fn rfc7636_appendix_b_vector_verifies() {
        assert!(challenge().verify(RFC_VERIFIER, &FakeSha256).is_ok());
    }

    #[test]
    fn wrong_verifier_is_rejected() {
        let other = "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge().verify(other, &FakeSha256).unwrap_err(),
            PkceError::VerifierMismatch
        );
    }

    #[test]
    fn plain_method_is_not_representable() {
        assert_eq!(
            CodeChallengeMethod::parse("plain").unwrap_err(),
            PkceError::UnsupportedMethod {
                method: "plain".to_owned()
            }
        );
        assert_eq!(
            CodeChallengeMethod::parse("S256").unwrap(),
            CodeChallengeMethod::S256
        );
    }

    #[test]
    fn verifier_length_bounds_are_enforced() {
        let short = "a".repeat(42);
        let long = "a".repeat(129);
        for (v, len) in [(short, 42), (long, 129)] {
            assert_eq!(
                challenge().verify(&v, &FakeSha256).unwrap_err(),
                PkceError::VerifierWrongLength { len }
            );
        }

        for n in [43, 128] {
            let v = "a".repeat(n);
            assert_eq!(
                challenge().verify(&v, &FakeSha256).unwrap_err(),
                PkceError::VerifierMismatch,
                "length {n} should pass syntax and fail on digest"
            );
        }
    }

    #[test]
    fn verifier_charset_is_enforced() {
        let bad = format!("{}+/", "a".repeat(41));
        assert_eq!(
            challenge().verify(&bad, &FakeSha256).unwrap_err(),
            PkceError::VerifierInvalidChar
        );
    }

    #[test]
    fn challenge_must_decode_to_32_bytes() {
        assert_eq!(
            CodeChallenge::parse(CodeChallengeMethod::S256, "c2hvcnQ").unwrap_err(),
            PkceError::ChallengeWrongLength { len: 5 }
        );
        assert_eq!(
            CodeChallenge::parse(CodeChallengeMethod::S256, "not base64!").unwrap_err(),
            PkceError::MalformedChallenge
        );
    }

    #[test]
    fn debug_does_not_print_the_whole_digest() {
        let shown = format!("{:?}", challenge());
        assert!(
            shown.starts_with("CodeChallenge(S256, 13d3"),
            "got: {shown}"
        );
        assert!(!shown.contains("cb70f9c3"));
    }
}
