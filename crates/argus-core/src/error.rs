//! Çekirdek hata tipleri.
//!
//! Her hata **neyin** yanlış olduğunu taşır, ham girdiyi değil: hata metni log'a ve
//! çoğu zaman kullanıcıya gider, dolayısıyla içine denetlenmemiş veri konmaz.

use thiserror::Error;

/// Kimlik tiplerinin doğrulama hataları.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// `client_id` boş.
    #[error("client_id must not be empty")]
    ClientIdEmpty,

    /// `client_id` azami uzunluğu aştı.
    ///
    /// Sınır RFC 6749'dan değil, Argus'un kendi tercihinden gelir: `client_id`
    /// indekslenen ve token'da taşınan bir alandır, sınırsız bırakılmaz.
    #[error("client_id is {len} bytes, maximum is {max}")]
    ClientIdTooLong {
        /// Verilen değerin bayt uzunluğu.
        len: usize,
        /// İzin verilen azami bayt uzunluğu.
        max: usize,
    },

    /// `client_id` yazdırılamayan karakter içeriyor.
    ///
    /// RFC 6749 Ek A `client_id`'yi `*VSCHAR` olarak tanımlar: yalnızca görünür
    /// ASCII (0x20–0x7E). Bu; kontrol karakterlerini, satır sonlarını ve ASCII
    /// dışı her şeyi dışarıda bırakır.
    #[error("client_id contains a non-printable character (RFC 6749 App. A: *VSCHAR)")]
    ClientIdInvalidChar,
}

/// `redirect_uri` kayıt hataları.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RedirectUriError {
    /// Ayrıştırılamadı veya göreli. RFC 6749 §3.1.2 mutlak URI ister.
    #[error("redirect_uri must be an absolute URI (RFC 6749 §3.1.2)")]
    NotAbsolute,

    /// Fragment içeriyor. RFC 6749 §3.1.2 fragment'i yasaklar.
    #[error("redirect_uri must not contain a fragment (RFC 6749 §3.1.2)")]
    HasFragment,

    /// `*` içeriyor.
    ///
    /// Ayrı bir hata olması bilinçli: sessizce "eşleşmedi" dönseydik operatör
    /// wildcard'ın desteklendiğini ama kaydının hatalı olduğunu sanabilirdi.
    /// Argus wildcard'ı desteklemez ve desteklemeyecektir (§1 #24).
    #[error("redirect_uri wildcards are not supported; register each URI exactly")]
    WildcardNotSupported,
}

/// PKCE hataları (RFC 7636).
///
/// Bunların hiçbiri istemciye ayrıntısıyla dönmez: token endpoint'i hepsini tek bir
/// `invalid_grant` altında toplar. Ayrım denetim kaydı ve operatör içindir —
/// istemciye "verifier'ın uzunluğu yanlıştı" demek, saldırgana hangi adımda
/// olduğunu söylemektir.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PkceError {
    /// `code_challenge_method` desteklenmiyor. `plain` dahil.
    #[error("unsupported code_challenge_method: {method}")]
    UnsupportedMethod {
        /// İstekte gelen değer.
        method: String,
    },

    /// `code_challenge` geçerli BASE64URL değil.
    #[error("code_challenge is not valid BASE64URL")]
    MalformedChallenge,

    /// `code_challenge` çözüldüğünde 32 bayt değil.
    #[error("code_challenge decodes to {len} bytes, S256 requires 32")]
    ChallengeWrongLength {
        /// Çözülen bayt sayısı.
        len: usize,
    },

    /// `code_verifier` uzunluğu RFC 7636 §4.1 sınırları dışında (43-128).
    #[error("code_verifier is {len} bytes, RFC 7636 §4.1 requires 43..=128")]
    VerifierWrongLength {
        /// Verilen uzunluk.
        len: usize,
    },

    /// `code_verifier` unreserved olmayan karakter içeriyor.
    #[error("code_verifier contains a character outside the unreserved set")]
    VerifierInvalidChar,

    /// Verifier biçimsel olarak doğru ama özet tutmuyor.
    #[error("code_verifier does not match code_challenge")]
    VerifierMismatch,
}
