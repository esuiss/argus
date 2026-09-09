//! JWS ile imzalanmış JWT üretimi ve doğrulaması — RFC 7515, RFC 7519.

use argus_crypto::{CryptoError, SigningKey, VerifyingKey};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};

/// JWS başlığı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsHeader {
    /// İmza algoritması.
    ///
    /// ⚠️ `none` **hiç desteklenmiyor** ve `alg` doğrulamada beyaz listeye karşı
    /// kontrol edilir. Alg karışıklığı (`alg` confusion) JWT'nin en klasik
    /// atlatma sınıfıdır.
    pub alg: String,
    /// İmzalayan anahtarın kimliği.
    pub kid: String,
    /// Token tipi.
    pub typ: String,
}

/// Access token claim'leri.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Issuer — kiracının metadata'sındakiyle **birebir** aynı olmalı.
    pub iss: String,
    /// Özne.
    pub sub: String,
    /// Hedef kaynak(lar). RFC 8707 `resource` buraya yansır.
    pub aud: String,
    /// Sona erme (saniye).
    pub exp: i64,
    /// Veriliş (saniye).
    pub iat: i64,
    /// Token kimliği — tekrar tespiti için.
    pub jti: String,
    /// Verilen kapsam.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// §1 #18: oturum geçersizleme sayacı token'ın İÇİNDE taşınır; doğrulamada
    /// node cache'indeki değerle karşılaştırılır ve ağ turu gerekmez.
    pub sess: u64,

    /// `RFC` 9449 §6: token'ı istemcinin anahtarına bağlayan doğrulama.
    ///
    /// Yoksa token bearer'dır ve **sahip olan herkes** kullanabilir. Varsa,
    /// kaynak sunucu sunulan `DPoP` kanıtının thumbprint'ini buradakiyle
    /// karşılaştırır; token'ı çalmak yetmez, anahtarı da çalmak gerekir.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

/// `RFC` 7800 doğrulama claim'i.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// `JWK` thumbprint (`RFC` 7638).
    pub jkt: String,
}

/// JWT hataları.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    /// Serileştirme başarısız.
    #[error("failed to serialise the token")]
    Serialisation,
    /// İmzalama başarısız.
    #[error("failed to sign the token")]
    Signing,
    /// Token üç parçalı değil.
    #[error("malformed token")]
    Malformed,
    /// İmza doğrulanamadı.
    #[error("signature verification failed")]
    BadSignature,
    /// `alg` beyaz listede değil.
    #[error("algorithm not allowed")]
    DisallowedAlgorithm,
}

/// Claim'leri imzalayıp kompakt JWS üretir.
///
/// # Errors
///
/// Serileştirme veya imzalama başarısız olursa.
pub fn sign(claims: &AccessTokenClaims, key: &SigningKey) -> Result<String, JwtError> {
    let header = JwsHeader {
        alg: "ES256".to_owned(),
        kid: key.kid().to_owned(),
        typ: "at+jwt".to_owned(),
    };

    let h = serde_json::to_vec(&header).map_err(|_| JwtError::Serialisation)?;
    let c = serde_json::to_vec(claims).map_err(|_| JwtError::Serialisation)?;

    let signing_input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(&h),
        Base64UrlUnpadded::encode_string(&c)
    );

    let sig = key
        .sign(signing_input.as_bytes())
        .map_err(|_: CryptoError| JwtError::Signing)?;

    Ok(format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&sig)
    ))
}

/// Kompakt JWS'i doğrular ve claim'leri döner.
///
/// # Errors
///
/// Biçim bozuksa, `alg` izinli değilse veya imza tutmuyorsa.
pub fn verify(token: &str, key: &VerifyingKey) -> Result<AccessTokenClaims, JwtError> {
    let mut parts = token.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };

    let header_bytes = Base64UrlUnpadded::decode_vec(h).map_err(|_| JwtError::Malformed)?;
    let header: JwsHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;

    // Beyaz liste: `none` ve diğer her şey reddedilir.
    if header.alg != "ES256" {
        return Err(JwtError::DisallowedAlgorithm);
    }

    let sig = Base64UrlUnpadded::decode_vec(s).map_err(|_| JwtError::Malformed)?;
    let signing_input = format!("{h}.{c}");
    key.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| JwtError::BadSignature)?;

    let claim_bytes = Base64UrlUnpadded::decode_vec(c).map_err(|_| JwtError::Malformed)?;
    serde_json::from_slice(&claim_bytes).map_err(|_| JwtError::Malformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{AccessTokenClaims, JwtError, sign, verify};
    use argus_crypto::SigningKey;
    use base64ct::Encoding as _;

    fn claims() -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "https://acme.argus.test".to_owned(),
            sub: "user-1".to_owned(),
            aud: "https://api.acme.test".to_owned(),
            exp: 1_000_300,
            iat: 1_000_000,
            jti: "jti-1".to_owned(),
            scope: Some("openid".to_owned()),
            sess: 7,
            cnf: None,
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign(&claims(), &key).expect("sign");
        assert_eq!(
            verify(&token, &key.verifying_key()).expect("verify"),
            claims()
        );
    }

    #[test]
    fn header_carries_the_kid_so_rotation_can_work() {
        let (key, _) = SigningKey::generate("kid-9").expect("key");
        let token = sign(&claims(), &key).expect("sign");
        let header = token.split('.').next().expect("header");
        let bytes = base64ct::Base64UrlUnpadded::decode_vec(header).expect("b64");
        let json = String::from_utf8(bytes).expect("utf8");
        assert!(json.contains("\"kid\":\"kid-9\""), "got: {json}");
        assert!(json.contains("\"alg\":\"ES256\""));
    }

    #[test]
    fn another_key_cannot_verify() {
        let (a, _) = SigningKey::generate("a").expect("key");
        let (b, _) = SigningKey::generate("b").expect("key");
        let token = sign(&claims(), &a).expect("sign");
        assert_eq!(
            verify(&token, &b.verifying_key()).unwrap_err(),
            JwtError::BadSignature
        );
    }

    #[test]
    fn tampered_payload_fails() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign(&claims(), &key).expect("sign");
        let mut parts: Vec<&str> = token.split('.').collect();
        let evil = base64ct::Base64UrlUnpadded::encode_string(
            br#"{"iss":"https://evil.test","sub":"admin","aud":"a","exp":9,"iat":1,"jti":"x","sess":0}"#,
        );
        parts[1] = &evil;
        let forged = parts.join(".");
        assert_eq!(
            verify(&forged, &key.verifying_key()).unwrap_err(),
            JwtError::BadSignature
        );
    }

    /// `alg: none` klasik atlatmadır; beyaz liste onu reddetmeli.
    #[test]
    fn alg_none_is_rejected() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign(&claims(), &key).expect("sign");
        let parts: Vec<&str> = token.split('.').collect();
        let header = base64ct::Base64UrlUnpadded::encode_string(
            br#"{"alg":"none","kid":"k1","typ":"at+jwt"}"#,
        );
        let forged = format!("{header}.{}.", parts[1]);
        assert_eq!(
            verify(&forged, &key.verifying_key()).unwrap_err(),
            JwtError::DisallowedAlgorithm
        );
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let vk = key.verifying_key();
        for bad in ["", "a.b", "a.b.c.d", "not-a-token"] {
            assert!(verify(bad, &vk).is_err(), "accepted: {bad}");
        }
    }
}
