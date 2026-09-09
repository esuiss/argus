use argus_crypto::{SigningKey, VerifyingKey};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};

use crate::jwt::JwtError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,

    pub sub: String,

    pub aud: String,

    pub exp: i64,

    pub iat: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
}

#[must_use]
pub fn at_hash(access_token: &str, hasher: &impl argus_core::pkce::Sha256) -> String {
    let digest = hasher.sha256(access_token.as_bytes());

    Base64UrlUnpadded::encode_string(digest.get(..16).unwrap_or(&digest))
}

pub fn sign_id_token(claims: &IdTokenClaims, key: &SigningKey) -> Result<String, JwtError> {
    let header = format!(
        r#"{{"alg":"ES256","kid":"{}","typ":"JWT"}}"#,
        key.kid().replace('"', "")
    );
    let payload = serde_json::to_vec(claims).map_err(|_| JwtError::Serialisation)?;

    let signing_input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(header.as_bytes()),
        Base64UrlUnpadded::encode_string(&payload)
    );

    let sig = key
        .sign(signing_input.as_bytes())
        .map_err(|_| JwtError::Signing)?;

    Ok(format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&sig)
    ))
}

pub fn verify_id_token(token: &str, key: &VerifyingKey) -> Result<IdTokenClaims, JwtError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };

    let header_bytes =
        Base64UrlUnpadded::decode_vec(header_b64).map_err(|_| JwtError::Malformed)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;
    if header.get("alg").and_then(serde_json::Value::as_str) != Some("ES256") {
        return Err(JwtError::DisallowedAlgorithm);
    }

    let sig = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| JwtError::Malformed)?;
    key.verify(format!("{header_b64}.{claims_b64}").as_bytes(), &sig)
        .map_err(|_| JwtError::BadSignature)?;

    let claim_bytes = Base64UrlUnpadded::decode_vec(claims_b64).map_err(|_| JwtError::Malformed)?;
    serde_json::from_slice(&claim_bytes).map_err(|_| JwtError::Malformed)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{IdTokenClaims, at_hash, sign_id_token, verify_id_token};
    use crate::jwt::JwtError;
    use argus_crypto::{AwsLcSha256, SigningKey};
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    fn claims() -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://acme.argus.test".to_owned(),
            sub: "user-1".to_owned(),
            aud: "acme-web".to_owned(),
            exp: 1_000_600,
            iat: 1_000_000,
            nonce: Some("n-abc".to_owned()),
            auth_time: Some(999_990),
            at_hash: Some("hash".to_owned()),
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign_id_token(&claims(), &key).expect("sign");
        assert_eq!(
            verify_id_token(&token, &key.verifying_key()).expect("verify"),
            claims()
        );
    }

    #[test]
    fn audience_is_the_client() {
        assert_eq!(claims().aud, "acme-web");
    }

    #[test]
    fn typ_is_jwt_not_at_jwt() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign_id_token(&claims(), &key).expect("sign");
        let header =
            Base64UrlUnpadded::decode_vec(token.split('.').next().expect("h")).expect("b64");
        let json = String::from_utf8(header).expect("utf8");
        assert!(json.contains(r#""typ":"JWT""#), "got: {json}");
        assert!(!json.contains("at+jwt"));
    }

    #[test]
    fn nonce_is_echoed_exactly() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign_id_token(&claims(), &key).expect("sign");
        let back = verify_id_token(&token, &key.verifying_key()).expect("verify");
        assert_eq!(back.nonce.as_deref(), Some("n-abc"));
    }

    #[test]
    fn another_key_cannot_verify() {
        let (a, _) = SigningKey::generate("a").expect("key");
        let (b, _) = SigningKey::generate("b").expect("key");
        let token = sign_id_token(&claims(), &a).expect("sign");
        assert_eq!(
            verify_id_token(&token, &b.verifying_key()).unwrap_err(),
            JwtError::BadSignature
        );
    }

    #[test]
    fn at_hash_is_the_left_half_of_the_digest() {
        let token = "an-access-token";
        let h = at_hash(token, &AwsLcSha256);
        let decoded = Base64UrlUnpadded::decode_vec(&h).expect("b64");
        assert_eq!(decoded.len(), 16, "must be half of a 256-bit digest");

        assert_ne!(h, at_hash("another-token", &AwsLcSha256));
    }

    #[test]
    fn at_hash_is_stable() {
        assert_eq!(at_hash("t", &AwsLcSha256), at_hash("t", &AwsLcSha256));
    }
}
