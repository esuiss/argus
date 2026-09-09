use argus_crypto::{CryptoError, SigningKey, VerifyingKey};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsHeader {
    pub alg: String,

    pub kid: String,

    pub typ: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    #[must_use]
    pub fn of(values: &[String]) -> Self {
        match values {
            [only] => Self::One(only.clone()),
            many => Self::Many(many.to_vec()),
        }
    }

    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(one) => one == value,
            Self::Many(many) => many.iter().any(|a| a == value),
        }
    }

    #[must_use]
    pub fn values(&self) -> Vec<&str> {
        match self {
            Self::One(one) => vec![one.as_str()],
            Self::Many(many) => many.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,

    pub sub: String,

    pub aud: Audience,

    pub exp: i64,

    pub iat: i64,

    pub jti: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    pub sess: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    pub jkt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    #[error("failed to serialise the token")]
    Serialisation,

    #[error("failed to sign the token")]
    Signing,

    #[error("malformed token")]
    Malformed,

    #[error("signature verification failed")]
    BadSignature,

    #[error("algorithm not allowed")]
    DisallowedAlgorithm,
}

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
    use super::{AccessTokenClaims, Audience, JwtError, sign, verify};
    use argus_crypto::SigningKey;
    use base64ct::Encoding as _;

    fn claims() -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "https://acme.argus.test".to_owned(),
            sub: "user-1".to_owned(),
            aud: Audience::One("https://api.acme.test".to_owned()),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod audience_tests {
    use super::Audience;

    #[test]
    fn a_single_audience_stays_a_bare_string_on_the_wire() {
        let json = serde_json::to_string(&Audience::of(&["https://a.test".to_owned()])).unwrap();
        assert_eq!(json, r#""https://a.test""#);
    }

    #[test]
    fn several_audiences_become_an_array() {
        let json = serde_json::to_string(&Audience::of(&[
            "https://a.test".to_owned(),
            "https://b.test".to_owned(),
        ]))
        .unwrap();
        assert_eq!(json, r#"["https://a.test","https://b.test"]"#);
    }

    #[test]
    fn both_wire_forms_round_trip() {
        for json in [
            r#""https://a.test""#,
            r#"["https://a.test","https://b.test"]"#,
        ] {
            let parsed: Audience = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        }
    }

    #[test]
    fn membership_is_exact() {
        let aud = Audience::of(&["https://a.test".to_owned(), "https://b.test".to_owned()]);
        assert!(aud.contains("https://a.test"));
        assert!(aud.contains("https://b.test"));
        assert!(!aud.contains("https://a.test.evil"));
        assert!(!aud.contains("a.test"));
    }

    #[test]
    fn an_empty_list_is_an_empty_array_not_a_string() {
        let json = serde_json::to_string(&Audience::of(&[])).unwrap();
        assert_eq!(json, "[]");
    }
}
