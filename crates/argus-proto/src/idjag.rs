use argus_crypto::{SigningKey, VerifyingKey};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};

use crate::jwt::JwtError;

pub const TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const GRANT_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
pub const HEADER_TYP: &str = "oauth-id-jag+jwt";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdJagClaims {
    pub iss: String,

    pub sub: String,

    pub aud: String,

    pub client_id: String,

    pub jti: String,

    pub exp: i64,

    pub iat: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

pub fn sign_id_jag(claims: &IdJagClaims, key: &SigningKey) -> Result<String, JwtError> {
    let header = format!(
        r#"{{"alg":"ES256","kid":"{}","typ":"{HEADER_TYP}"}}"#,
        key.kid().replace('"', "")
    );
    let payload = serde_json::to_vec(claims).map_err(|_| JwtError::Serialisation)?;

    let signing_input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(header.as_bytes()),
        Base64UrlUnpadded::encode_string(&payload)
    );

    let signature = key
        .sign(signing_input.as_bytes())
        .map_err(|_| JwtError::Signing)?;

    Ok(format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&signature)
    ))
}

pub fn verify_id_jag(token: &str, key: &VerifyingKey) -> Result<IdJagClaims, JwtError> {
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

    if header.get("typ").and_then(serde_json::Value::as_str) != Some(HEADER_TYP) {
        return Err(JwtError::DisallowedAlgorithm);
    }

    let signature = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| JwtError::Malformed)?;
    key.verify(format!("{header_b64}.{claims_b64}").as_bytes(), &signature)
        .map_err(|_| JwtError::BadSignature)?;

    let claim_bytes = Base64UrlUnpadded::decode_vec(claims_b64).map_err(|_| JwtError::Malformed)?;
    serde_json::from_slice(&claim_bytes).map_err(|_| JwtError::Malformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{HEADER_TYP, IdJagClaims, sign_id_jag, verify_id_jag};
    use crate::jwt::JwtError;
    use argus_crypto::SigningKey;
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    fn claims() -> IdJagClaims {
        IdJagClaims {
            iss: "https://acme.idp.example".to_owned(),
            sub: "U019488227".to_owned(),
            aud: "https://auth.chat.example/".to_owned(),
            client_id: "f53f191f9311af35".to_owned(),
            jti: "9e43f81b64a33f20116179".to_owned(),
            exp: 1_311_281_970,
            iat: 1_311_280_970,
            resource: Some("https://mcp.chat.example/".to_owned()),
            scope: Some("chat.read chat.history".to_owned()),
            email: Some("user@example.com".to_owned()),
        }
    }

    #[test]
    fn a_signed_grant_round_trips() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign_id_jag(&claims(), &key).expect("sign");
        assert_eq!(
            verify_id_jag(&token, &key.verifying_key()).expect("verify"),
            claims()
        );
    }

    #[test]
    fn the_typ_header_is_the_one_the_draft_mandates() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign_id_jag(&claims(), &key).expect("sign");
        let head = token.split('.').next().expect("header");
        let decoded = Base64UrlUnpadded::decode_vec(head).expect("decode");
        let header: serde_json::Value = serde_json::from_slice(&decoded).expect("json");
        assert_eq!(
            header.get("typ").and_then(serde_json::Value::as_str),
            Some(HEADER_TYP)
        );
        assert_eq!(
            header.get("kid").and_then(serde_json::Value::as_str),
            Some("k1")
        );
    }

    #[test]
    fn a_token_with_another_typ_is_refused() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let access = crate::jwt::sign(
            &crate::jwt::AccessTokenClaims {
                iss: "https://acme.idp.example".to_owned(),
                sub: "U019488227".to_owned(),
                aud: crate::jwt::Audience::One("x".to_owned()),
                exp: 1,
                iat: 0,
                jti: "j".to_owned(),
                scope: None,
                sess: 0,
                cnf: None,
            },
            &key,
        )
        .expect("sign");

        assert_eq!(
            verify_id_jag(&access, &key.verifying_key()).unwrap_err(),
            JwtError::DisallowedAlgorithm
        );
    }

    #[test]
    fn another_key_cannot_verify() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let (other, _) = SigningKey::generate("k2").expect("key");
        let token = sign_id_jag(&claims(), &key).expect("sign");
        assert_eq!(
            verify_id_jag(&token, &other.verifying_key()).unwrap_err(),
            JwtError::BadSignature
        );
    }

    #[test]
    fn the_wire_shape_matches_the_specs_example() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let token = sign_id_jag(&claims(), &key).expect("sign");
        let payload = token.split('.').nth(1).expect("payload");
        let decoded = Base64UrlUnpadded::decode_vec(payload).expect("decode");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("json");

        for member in [
            "jti",
            "iss",
            "sub",
            "email",
            "aud",
            "resource",
            "client_id",
            "exp",
            "iat",
            "scope",
        ] {
            assert!(value.get(member).is_some(), "{member} missing");
        }
    }

    #[test]
    fn optional_members_are_omitted_when_absent() {
        let (key, _) = SigningKey::generate("k1").expect("key");
        let bare = IdJagClaims {
            resource: None,
            scope: None,
            email: None,
            ..claims()
        };
        let token = sign_id_jag(&bare, &key).expect("sign");
        let payload = token.split('.').nth(1).expect("payload");
        let decoded = Base64UrlUnpadded::decode_vec(payload).expect("decode");
        let text = String::from_utf8(decoded).expect("utf8");
        assert!(!text.contains("resource"));
        assert!(!text.contains("scope"));
        assert!(!text.contains("email"));
    }
}
