//! PKCE — RFC 7636.
//!
//! OAuth 2.1'de **her akışta zorunludur**; `plain` metodu Argus'ta hiç
//! implemente edilmez (§4: *"PKCE her yerde, implicit ve ROPC yok"*).
//!
//! # Neden hash fonksiyonu dışarıdan veriliyor
//!
//! `argus-core` kripto bağımlılığı taşımaz. Bunun sebebi üslup değil §10: formel
//! doğrulamanın girebileceği tek katman burasıdır ve o katmanın bağımlılık yüzeyi
//! ne kadar küçükse o kadar iyidir. SHA-256'yı [`Sha256`] üzerinden çağıran taraf
//! sağlar; `argus-crypto` bunu `aws-lc-rs` ile uygular.
//!
//! # Sabit zamanlı karşılaştırma
//!
//! RFC 7636 §4.6 bunu **zorunlu kılmaz** — yalnızca eşitlik ister. §8'deki analiz:
//! `code_verifier` en az 256 bit entropi taşıdığı için bayt bayt sızıntı pratikte
//! sömürülemez. Yine de maliyeti sıfır olduğundan yapılıyor.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use subtle::ConstantTimeEq as _;

use crate::error::PkceError;

/// `code_verifier` için RFC 7636 §4.1 uzunluk sınırları.
const VERIFIER_MIN_LEN: usize = 43;
/// RFC 7636 §4.1 üst sınır.
const VERIFIER_MAX_LEN: usize = 128;

/// SHA-256 sağlayıcısı.
///
/// `argus-core`'un kripto bağımlılığı olmasın diye tanımlanmıştır; üretimde
/// `argus-crypto` uygular.
pub trait Sha256 {
    /// Girdinin SHA-256 özetini döndürür.
    fn sha256(&self, input: &[u8]) -> [u8; 32];
}

/// `code_challenge_method`.
///
/// `plain` **kasten yok**. RFC 7636 onu tanımlar ama OAuth 2.1 ve RFC 9700 `S256`
/// zorunlu kılar; `plain`'i tip düzeyinde temsil etmemek, onu yanlışlıkla kabul
/// eden bir kod yolunun yazılmasını imkânsız kılar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeChallengeMethod {
    /// `BASE64URL(SHA256(ASCII(code_verifier)))`
    S256,
}

impl CodeChallengeMethod {
    /// Yetkilendirme isteğindeki `code_challenge_method` parametresini çözer.
    ///
    /// # Errors
    ///
    /// `plain` dahil, `S256` dışındaki her değer için
    /// [`PkceError::UnsupportedMethod`] döner.
    pub fn parse(value: &str) -> Result<Self, PkceError> {
        match value {
            "S256" => Ok(Self::S256),
            other => Err(PkceError::UnsupportedMethod {
                method: other.to_owned(),
            }),
        }
    }

    /// Protokoldeki dizge karşılığı.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

/// Yetkilendirme isteğiyle gelen `code_challenge`.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeChallenge {
    method: CodeChallengeMethod,
    /// Çözülmüş özet. Ham dizge saklanmaz: karşılaştırma bayt üzerinden yapılır,
    /// böylece kodlama farkları (padding, hizalama) eşitlik sonucunu etkilemez.
    digest: [u8; 32],
}

impl CodeChallenge {
    /// İstekten gelen `code_challenge` değerini çözer ve doğrular.
    ///
    /// # Errors
    ///
    /// - [`PkceError::MalformedChallenge`] — geçerli BASE64URL değil.
    /// - [`PkceError::ChallengeWrongLength`] — çözüldüğünde 32 bayt değil.
    ///   `S256` için başka bir uzunluk mümkün değildir; kabul etmek, hash
    ///   dışı bir değerin sunulmasına izin vermek olurdu.
    pub fn parse(method: CodeChallengeMethod, raw: &str) -> Result<Self, PkceError> {
        let mut digest = [0u8; 32];
        let decoded = Base64UrlUnpadded::decode(raw, &mut digest)
            .map_err(|_| PkceError::MalformedChallenge)?;

        if decoded.len() != 32 {
            return Err(PkceError::ChallengeWrongLength { len: decoded.len() });
        }

        Ok(Self { method, digest })
    }

    /// Kullanılan metot.
    #[must_use]
    pub const fn method(&self) -> CodeChallengeMethod {
        self.method
    }

    /// Token isteğinde sunulan `code_verifier`'ı doğrular.
    ///
    /// Karşılaştırma sabit zamanlıdır (bkz. modül notu).
    ///
    /// # Errors
    ///
    /// - [`PkceError::VerifierWrongLength`] / [`PkceError::VerifierInvalidChar`] —
    ///   verifier RFC 7636 §4.1'e uymuyor. Bunlar eşleşme denemesinden **önce**
    ///   kontrol edilir: biçimsiz bir verifier hiçbir zaman doğru olamaz ve
    ///   hash'lemeye gerek yoktur.
    /// - [`PkceError::VerifierMismatch`] — biçim doğru ama özet tutmuyor.
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
        // Özet bir sır değil (istekte açık gider) ama tam hâlini log'a basmanın
        // da faydası yok; kimlik tipleriyle aynı kısaltma uygulanıyor.
        write!(
            f,
            "CodeChallenge({}, {:02x}{:02x}…)",
            self.method.as_str(),
            self.digest[0],
            self.digest[1]
        )
    }
}

/// RFC 7636 §4.1: `code_verifier = 43*128unreserved`,
/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`.
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

    /// RFC 7636 Ek B test vektörü.
    ///
    /// `argus-core` kripto taşımadığı için gerçek SHA-256 burada koşmaz; RFC'nin
    /// verdiği ara değer (verifier'ın SHA-256 özeti) sabit olarak veriliyor.
    /// Gerçek hash'in doğruluğu `argus-crypto`'nun known-answer testlerinin işidir.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    /// RFC 7636 Ek B'deki sekizli dizisi.
    const RFC_DIGEST: [u8; 32] = [
        19, 211, 30, 150, 26, 26, 216, 236, 47, 22, 177, 12, 76, 152, 46, 8, 118, 168, 120, 173,
        109, 241, 68, 86, 110, 225, 137, 74, 203, 112, 249, 195,
    ];

    /// Sabit özet döndüren sahte hash: yalnızca RFC verifier'ı için doğru cevabı
    /// verir, başka her girdi için farklı bir değer üretir.
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
        // Doğru uzunlukta ve doğru karakter setinde ama farklı bir verifier.
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
        // Sınırlar dahil.
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
        // `+` ve `/` unreserved değil — base64 (standart) alfabesinden gelen
        // bir verifier'ın sessizce kabul edilmemesi gerekiyor.
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
