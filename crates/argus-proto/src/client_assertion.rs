//! `private_key_jwt` istemci assertion'ı — `RFC` 7523 §2.2.
//!
//! # Neden iki adım
//!
//! Assertion'ın imzasını doğrulamak için istemcinin açık anahtarı gerekiyor;
//! hangi istemci olduğunu ise assertion'ın **içindeki** `sub` söylüyor. Yani
//! doğrulanmamış bir veriden yola çıkıp anahtar aramak zorundayız.
//!
//! Bu tehlikeli görünür ama değildir — yeter ki sıra doğru olsun:
//! [`parse`] yalnızca **arama anahtarı** üretir ve hiçbir güven ifade etmez;
//! güven [`verify`]'ın döndürdüğü [`AssertionClaims`] ile başlar ve o tip ancak
//! imza tutarsa kurulur. Tek adımlı bir API bu ayrımı gizler ve çağıranın
//! `parse` çıktısına güvenmesini kolaylaştırırdı.
//!
//! # `alg` beyaz listesi
//!
//! Yalnızca `ES256`. `none` elbette, ama simetrik `HS*` de reddedilir: `HS256`
//! kabul eden bir doğrulayıcıda saldırgan, sunucunun **açık** anahtarını `HMAC`
//! sırrı gibi kullanarak assertion üretebilir — algoritma karıştırma saldırısının
//! klasik biçimi.

use argus_core::client_auth::{AssertionClaims, ClientKey};
use argus_core::time::Timestamp;
use argus_crypto::VerifyingKey;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;

/// `client_assertion_type` — `RFC` 7523 §2.2'de bu değer SABİTTİR.
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Assertion ayrıştırma ve doğrulama hataları.
///
/// Hepsi istemciye `invalid_client` olarak döner; ayrım denetim kaydı içindir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssertionError {
    /// Kompakt `JWS` biçimi bozuk.
    #[error("the client assertion is malformed")]
    Malformed,
    /// `alg` beyaz listede değil.
    #[error("the client assertion algorithm is not accepted")]
    DisallowedAlgorithm,
    /// Zorunlu bir claim eksik.
    #[error("the client assertion is missing a required claim")]
    MissingClaim,
    /// İmza tutmuyor ya da eşleşen anahtar yok.
    #[error("the client assertion signature does not verify")]
    BadSignature,
}

/// Doğrulanmamış assertion — yalnızca **arama** için.
///
/// ⚠️ Bu tipteki hiçbir alan bir güven ifadesi değildir. `client_id`, anahtarı
/// bulmak için kullanılır; kimliği [`verify`] kanıtlar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedAssertion {
    /// `sub` claim'i — hangi istemcinin anahtarlarının aranacağı.
    pub client_id: String,
    /// `JWS` başlığındaki `kid`; yoksa tüm anahtarlar denenir.
    pub kid: Option<String>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// `aud` hem tek dizge hem dizi olabilir (`RFC` 7519 §4.1.3).
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<i64>,
    jti: Option<String>,
}

fn split(assertion: &str) -> Result<(&str, &str, &str), AssertionError> {
    let mut parts = assertion.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AssertionError::Malformed);
    };
    Ok((h, c, s))
}

fn decode<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, AssertionError> {
    let bytes = Base64UrlUnpadded::decode_vec(segment).map_err(|_| AssertionError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| AssertionError::Malformed)
}

/// Assertion'dan **arama anahtarını** çıkarır. Hiçbir şeyi doğrulamaz.
///
/// `alg` yine de burada kontrol edilir: beyaz listede olmayan bir algoritma için
/// anahtar aramaya hiç girmemek gerekir.
///
/// # Errors
///
/// Biçim bozuksa, `alg` kabul edilmiyorsa ya da `sub` yoksa.
pub fn parse(assertion: &str) -> Result<UnverifiedAssertion, AssertionError> {
    let (h, c, _) = split(assertion)?;
    let header: Header = decode(h)?;
    if header.alg != "ES256" {
        return Err(AssertionError::DisallowedAlgorithm);
    }
    let claims: Claims = decode(c)?;
    let client_id = claims.sub.ok_or(AssertionError::MissingClaim)?;
    Ok(UnverifiedAssertion {
        client_id,
        kid: header.kid,
    })
}

/// Assertion'ı kayıtlı anahtarlara karşı doğrular.
///
/// `kid` verilmişse yalnızca o anahtar denenir; verilmemişse hepsi denenir —
/// istemcinin `kid` yazmaması `RFC` 7515 §4.1.4'e göre meşrudur ve rotasyon
/// sırasında birden fazla anahtar geçerlidir.
///
/// Claim **kuralları** burada uygulanmaz; onlar
/// `argus_core::client_auth::validate_assertion`'ın işidir. Bu fonksiyon
/// yalnızca "bu baytları bu istemcinin özel anahtarı imzaladı" sorusunu yanıtlar.
///
/// # Errors
///
/// Biçim bozuksa, `alg` kabul edilmiyorsa, zorunlu claim eksikse ya da hiçbir
/// kayıtlı anahtar imzayı doğrulayamıyorsa.
pub fn verify(assertion: &str, keys: &[ClientKey]) -> Result<AssertionClaims, AssertionError> {
    let (h, c, sig_b64) = split(assertion)?;
    let header: Header = decode(h)?;
    if header.alg != "ES256" {
        return Err(AssertionError::DisallowedAlgorithm);
    }

    let signature =
        Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| AssertionError::Malformed)?;
    let signing_input = format!("{h}.{c}");

    // `kid` varsa arama daraltılır. Daraltmamak bir güvenlik açığı değil ama
    // rotasyon sırasında gereksiz imza doğrulaması demektir.
    let candidates = header.kid.as_ref().map_or_else(
        || keys.iter().collect::<Vec<_>>(),
        |kid| keys.iter().filter(|k| &k.kid == kid).collect::<Vec<_>>(),
    );

    let verified = candidates.iter().any(|k| {
        VerifyingKey::from_components(&k.x, &k.y)
            .verify(signing_input.as_bytes(), &signature)
            .is_ok()
    });

    if !verified {
        return Err(AssertionError::BadSignature);
    }

    let claims: Claims = decode(c)?;
    let (Some(iss), Some(sub), Some(aud), Some(exp), Some(jti)) =
        (claims.iss, claims.sub, claims.aud, claims.exp, claims.jti)
    else {
        // `jti` dahil hepsi ZORUNLU: `jti` olmadan tekrar tespiti imkânsızdır
        // ve `RFC` 7523 §3 onu zorunlu sayar.
        return Err(AssertionError::MissingClaim);
    };

    Ok(AssertionClaims {
        issuer: iss,
        subject: sub,
        audience: match aud {
            Audience::One(a) => vec![a],
            Audience::Many(a) => a,
        },
        expires_at: Timestamp::from_unix_seconds(exp),
        jti,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{AssertionError, ClientKey, parse, verify};
    use argus_crypto::SigningKey;
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    fn key_pair(kid: &str) -> (SigningKey, ClientKey) {
        let (signing, _) = SigningKey::generate(kid).expect("key");
        let c = signing.public_components().expect("components");
        (
            signing,
            ClientKey {
                kid: kid.to_owned(),
                x: c.x,
                y: c.y,
            },
        )
    }

    fn assertion(signing: &SigningKey, header: &str, payload: &str) -> String {
        let input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(header.as_bytes()),
            Base64UrlUnpadded::encode_string(payload.as_bytes())
        );
        let sig = signing.sign(input.as_bytes()).expect("sign");
        format!("{input}.{}", Base64UrlUnpadded::encode_string(&sig))
    }

    fn good_payload() -> String {
        r#"{"iss":"acme-web","sub":"acme-web","aud":"https://argus.test","exp":1000300,"jti":"a1"}"#
            .to_owned()
    }

    fn good_header(kid: &str) -> String {
        format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#)
    }

    #[test]
    fn a_genuine_assertion_verifies_and_yields_its_claims() {
        let (signing, public) = key_pair("k1");
        let a = assertion(&signing, &good_header("k1"), &good_payload());

        let claims = verify(&a, &[public]).expect("verifies");
        assert_eq!(claims.issuer, "acme-web");
        assert_eq!(claims.subject, "acme-web");
        assert_eq!(claims.audience, ["https://argus.test"]);
        assert_eq!(claims.jti, "a1");
        assert_eq!(claims.expires_at.as_unix_seconds(), 1_000_300);
    }

    /// Arama, doğrulanmamış `sub`'a dayanır ama hiçbir güven ifade etmez.
    #[test]
    fn parse_extracts_the_lookup_key_without_verifying() {
        let (signing, _) = key_pair("k1");
        let a = assertion(&signing, &good_header("k1"), &good_payload());

        let u = parse(&a).expect("parses");
        assert_eq!(u.client_id, "acme-web");
        assert_eq!(u.kid.as_deref(), Some("k1"));

        // İmzayı bozmak `parse`'ı ETKİLEMEZ — bu kasıtlı: `parse` imza hakkında
        // hiçbir şey söylemez.
        let tampered = format!("{a}x");
        assert!(parse(&tampered).is_ok());
        // Ama `verify` reddeder.
        let (_, public) = key_pair("k1");
        assert!(verify(&tampered, &[public]).is_err());
    }

    /// BAŞKA bir anahtarla imzalanmış assertion kabul edilmemeli.
    #[test]
    fn an_assertion_signed_by_another_key_is_rejected() {
        let (attacker, _) = key_pair("k1");
        let (_, registered) = key_pair("k1");
        let a = assertion(&attacker, &good_header("k1"), &good_payload());

        assert_eq!(
            verify(&a, &[registered]).unwrap_err(),
            AssertionError::BadSignature
        );
    }

    /// Rotasyon penceresinde iki anahtar birden geçerlidir.
    #[test]
    fn any_registered_key_may_verify_during_rotation() {
        let (old_signing, old_public) = key_pair("old");
        let (_, new_public) = key_pair("new");
        let a = assertion(&old_signing, &good_header("old"), &good_payload());

        assert!(verify(&a, &[old_public, new_public]).is_ok());
    }

    /// `kid` yazmamak meşrudur (`RFC` 7515 §4.1.4); tüm anahtarlar denenir.
    #[test]
    fn a_missing_kid_falls_back_to_trying_every_key() {
        let (signing, public) = key_pair("k1");
        let (_, other) = key_pair("k2");
        let a = assertion(&signing, r#"{"alg":"ES256","typ":"JWT"}"#, &good_payload());

        assert!(parse(&a).expect("parse").kid.is_none());
        assert!(verify(&a, &[other, public]).is_ok());
    }

    /// Yanlış `kid` gösteren bir assertion, o `kid`'e ait olmayan bir anahtarla
    /// doğrulanmamalı — daraltma bir kısayol, bir atlatma yolu değil.
    #[test]
    fn a_kid_that_matches_no_registered_key_fails() {
        let (signing, public) = key_pair("k1");
        let a = assertion(&signing, &good_header("nope"), &good_payload());

        assert_eq!(
            verify(&a, &[public]).unwrap_err(),
            AssertionError::BadSignature
        );
    }

    /// Algoritma karıştırma: `none` ve simetrik `alg` reddedilmeli.
    #[test]
    fn only_es256_is_accepted() {
        let (signing, public) = key_pair("k1");
        for alg in ["none", "HS256", "RS256", "ES384", "EdDSA"] {
            let header = format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"k1"}}"#);
            let a = assertion(&signing, &header, &good_payload());
            assert_eq!(
                verify(&a, core::slice::from_ref(&public)).unwrap_err(),
                AssertionError::DisallowedAlgorithm,
                "must reject alg={alg}"
            );
            assert_eq!(parse(&a).unwrap_err(), AssertionError::DisallowedAlgorithm);
        }
    }

    /// `jti` olmadan tekrar tespiti imkânsızdır; eksikse assertion reddedilir.
    #[test]
    fn every_required_claim_is_mandatory() {
        let (signing, public) = key_pair("k1");
        for payload in [
            r#"{"sub":"acme-web","aud":"https://argus.test","exp":1000300,"jti":"a1"}"#,
            r#"{"iss":"acme-web","aud":"https://argus.test","exp":1000300,"jti":"a1"}"#,
            r#"{"iss":"acme-web","sub":"acme-web","exp":1000300,"jti":"a1"}"#,
            r#"{"iss":"acme-web","sub":"acme-web","aud":"https://argus.test","jti":"a1"}"#,
            r#"{"iss":"acme-web","sub":"acme-web","aud":"https://argus.test","exp":1000300}"#,
        ] {
            let a = assertion(&signing, &good_header("k1"), payload);
            assert_eq!(
                verify(&a, core::slice::from_ref(&public)).unwrap_err(),
                AssertionError::MissingClaim,
                "must reject {payload}"
            );
        }
    }

    /// `aud` hem tek dizge hem dizi olabilir (`RFC` 7519 §4.1.3).
    #[test]
    fn the_audience_may_be_a_string_or_an_array() {
        let (signing, public) = key_pair("k1");
        let payload = r#"{"iss":"acme-web","sub":"acme-web","aud":["https://a.test","https://argus.test"],"exp":1000300,"jti":"a1"}"#;
        let a = assertion(&signing, &good_header("k1"), payload);

        let claims = verify(&a, &[public]).expect("verifies");
        assert_eq!(claims.audience, ["https://a.test", "https://argus.test"]);
    }

    #[test]
    fn malformed_assertions_are_rejected() {
        let (_, public) = key_pair("k1");
        for bad in ["", "a", "a.b", "a.b.c.d", "!!!.???.###"] {
            assert!(verify(bad, core::slice::from_ref(&public)).is_err());
            assert!(parse(bad).is_err());
        }
    }
}
