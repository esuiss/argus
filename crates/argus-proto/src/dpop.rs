//! `DPoP` kanıtının ayrıştırılması ve imza doğrulaması — RFC 9449.
//!
//! `argus-core::dpop` claim kurallarını uygular ama imzaya bakmaz (orada kripto
//! yok). Bu modül eksik yarıyı tamamlar: kanıtı ayrıştırır, gömülü `JWK` ile
//! imzasını doğrular ve ancak ondan sonra `VerifiedProof` kurar.
//!
//! # `jkt` — bağlamayı kuran değer
//!
//! `RFC` 7638 `JWK` thumbprint'i: anahtarın kanonik `JSON` gösteriminin
//! SHA-256'sı. Access token'a `cnf.jkt` olarak yazılır. Kaynak sunucu, sunulan
//! kanıtın anahtarının thumbprint'ini hesaplayıp token'daki değerle karşılaştırır;
//! tutmuyorsa token o istemciye ait değildir.

use argus_core::dpop::VerifiedProof;
use argus_core::pkce::Sha256 as _;
use argus_core::time::Timestamp;
use argus_crypto::{AwsLcSha256, VerifyingKey};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;

/// `DPoP` ayrıştırma hataları.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpopParseError {
    /// Kanıt üç parçalı bir `JWS` değil.
    #[error("malformed DPoP proof")]
    Malformed,
    /// `typ` başlığı `dpop+jwt` değil.
    ///
    /// RFC 9449 §4.2 bunu zorunlu kılar; kontrol etmemek, başka amaçla üretilmiş
    /// bir `JWT`'nin kanıt olarak kabul edilmesine yol açardı.
    #[error("DPoP proof has the wrong typ header")]
    WrongType,
    /// `alg` izinli değil.
    #[error("DPoP proof algorithm is not allowed")]
    DisallowedAlgorithm,
    /// Gömülü `JWK` eksik veya desteklenmeyen bir eğri.
    #[error("DPoP proof has a missing or unsupported jwk")]
    BadKey,
    /// İmza doğrulanamadı.
    #[error("DPoP proof signature is invalid")]
    BadSignature,
}

#[derive(Deserialize)]
struct ProofHeader {
    alg: String,
    typ: String,
    jwk: ProofJwk,
}

#[derive(Deserialize)]
struct ProofJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct ProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
}

/// `RFC` 7638 `JWK` thumbprint'i.
///
/// Kanonik gösterim: alanlar **sözlük sırasında**, boşluksuz, yalnızca zorunlu
/// alanlar. Sıra veya boşluk değişirse thumbprint değişir ve bağlama kopar —
/// bu yüzden dizge elle kuruluyor, `serde_json` nesne sırasına güvenilmiyor.
#[must_use]
pub fn jwk_thumbprint(crv: &str, x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = AwsLcSha256.sha256(canonical.as_bytes());
    Base64UrlUnpadded::encode_string(&digest)
}

/// Bir `DPoP` kanıtını ayrıştırır ve imzasını doğrular.
///
/// İmza doğrulanmadan [`VerifiedProof`] kurulmaz; claim kurallarını
/// `argus_core::dpop::validate` uygular.
///
/// # Errors
///
/// Biçim bozuksa, `typ`/`alg` yanlışsa veya imza tutmuyorsa.
pub fn parse_and_verify(proof: &str) -> Result<VerifiedProof, DpopParseError> {
    let mut parts = proof.split('.');
    let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopParseError::Malformed);
    };

    let header_bytes =
        Base64UrlUnpadded::decode_vec(header_b64).map_err(|_| DpopParseError::Malformed)?;
    let header: ProofHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| DpopParseError::Malformed)?;

    // RFC 9449 §4.2: `typ` DAİMA `dpop+jwt`. Bu kontrol, başka amaçla üretilmiş
    // bir `JWT`'nin kanıt yerine geçmesini engeller.
    if header.typ != "dpop+jwt" {
        return Err(DpopParseError::WrongType);
    }
    if header.alg != "ES256" {
        return Err(DpopParseError::DisallowedAlgorithm);
    }
    if header.jwk.kty != "EC" || header.jwk.crv != "P-256" {
        return Err(DpopParseError::BadKey);
    }

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let dx =
        Base64UrlUnpadded::decode(&header.jwk.x, &mut x).map_err(|_| DpopParseError::BadKey)?;
    let dy =
        Base64UrlUnpadded::decode(&header.jwk.y, &mut y).map_err(|_| DpopParseError::BadKey)?;
    if dx.len() != 32 || dy.len() != 32 {
        return Err(DpopParseError::BadKey);
    }

    let signature =
        Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| DpopParseError::Malformed)?;
    let signing_input = format!("{header_b64}.{claims_b64}");
    VerifyingKey::from_components(&x, &y)
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| DpopParseError::BadSignature)?;

    let claim_bytes =
        Base64UrlUnpadded::decode_vec(claims_b64).map_err(|_| DpopParseError::Malformed)?;
    let claims: ProofClaims =
        serde_json::from_slice(&claim_bytes).map_err(|_| DpopParseError::Malformed)?;

    Ok(VerifiedProof::new(
        claims.jti,
        claims.htm,
        claims.htu,
        Timestamp::from_unix_seconds(claims.iat),
        claims.ath,
        jwk_thumbprint(&header.jwk.crv, &header.jwk.x, &header.jwk.y),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{DpopParseError, jwk_thumbprint, parse_and_verify};
    use argus_crypto::SigningKey;
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    /// Test için gerçek bir `DPoP` kanıtı üretir.
    fn make_proof(key: &SigningKey, htm: &str, htu: &str, iat: i64) -> String {
        let c = key.public_components().expect("components");
        let x = Base64UrlUnpadded::encode_string(&c.x);
        let y = Base64UrlUnpadded::encode_string(&c.y);
        let header = format!(
            r#"{{"alg":"ES256","typ":"dpop+jwt","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#
        );
        let claims = format!(r#"{{"jti":"j1","htm":"{htm}","htu":"{htu}","iat":{iat}}}"#);
        let input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(header.as_bytes()),
            Base64UrlUnpadded::encode_string(claims.as_bytes())
        );
        let sig = key.sign(input.as_bytes()).expect("sign");
        format!("{input}.{}", Base64UrlUnpadded::encode_string(&sig))
    }

    #[test]
    fn a_genuine_proof_verifies_and_carries_its_thumbprint() {
        let (key, _) = SigningKey::generate("k").expect("key");
        let proof = make_proof(&key, "POST", "https://a.test/token", 1_000);

        let verified = parse_and_verify(&proof).expect("verify");
        assert_eq!(verified.htm, "POST");
        assert_eq!(verified.htu, "https://a.test/token");
        assert_eq!(verified.iat.as_unix_seconds(), 1_000);
        assert!(!verified.jkt.is_empty());
    }

    /// Thumbprint anahtarın kimliğidir: farklı anahtar, farklı thumbprint.
    #[test]
    fn thumbprints_differ_per_key() {
        let (a, _) = SigningKey::generate("a").expect("key");
        let (b, _) = SigningKey::generate("b").expect("key");
        let pa = parse_and_verify(&make_proof(&a, "POST", "https://a.test/t", 1)).expect("a");
        let pb = parse_and_verify(&make_proof(&b, "POST", "https://a.test/t", 1)).expect("b");
        assert_ne!(pa.jkt, pb.jkt);
    }

    /// Aynı anahtar daima aynı thumbprint'i verir — kanonik gösterim sabit.
    #[test]
    fn thumbprint_is_stable() {
        let a = jwk_thumbprint("P-256", "eG9v", "d2h5");
        let b = jwk_thumbprint("P-256", "eG9v", "d2h5");
        assert_eq!(a, b);
        assert_ne!(a, jwk_thumbprint("P-256", "eG9v", "ZGlmZg"));
    }

    /// İmzayı bozan bir değişiklik yakalanmalı.
    #[test]
    fn tampered_claims_fail_verification() {
        let (key, _) = SigningKey::generate("k").expect("key");
        let proof = make_proof(&key, "POST", "https://a.test/token", 1_000);
        let parts: Vec<&str> = proof.split('.').collect();
        let evil = Base64UrlUnpadded::encode_string(
            br#"{"jti":"j1","htm":"POST","htu":"https://evil.test/x","iat":1000}"#,
        );
        let forged = format!("{}.{evil}.{}", parts[0], parts[2]);
        assert_eq!(
            parse_and_verify(&forged).unwrap_err(),
            DpopParseError::BadSignature
        );
    }

    /// RFC 9449 §4.2: `typ` kontrol edilmezse başka amaçla üretilmiş bir `JWT`
    /// kanıt yerine geçebilir.
    #[test]
    fn a_jwt_with_the_wrong_typ_is_rejected() {
        let (key, _) = SigningKey::generate("k").expect("key");
        let c = key.public_components().expect("components");
        let x = Base64UrlUnpadded::encode_string(&c.x);
        let y = Base64UrlUnpadded::encode_string(&c.y);
        let header = format!(
            r#"{{"alg":"ES256","typ":"JWT","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#
        );
        let input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(header.as_bytes()),
            Base64UrlUnpadded::encode_string(br#"{"jti":"j","htm":"POST","htu":"u","iat":1}"#)
        );
        let sig = key.sign(input.as_bytes()).expect("sign");
        let proof = format!("{input}.{}", Base64UrlUnpadded::encode_string(&sig));

        assert_eq!(
            parse_and_verify(&proof).unwrap_err(),
            DpopParseError::WrongType
        );
    }

    #[test]
    fn malformed_proofs_are_rejected() {
        for bad in ["", "a.b", "a.b.c.d", "not-a-proof"] {
            assert!(parse_and_verify(bad).is_err(), "accepted: {bad}");
        }
    }
}
