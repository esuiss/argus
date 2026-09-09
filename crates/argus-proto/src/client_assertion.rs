use argus_core::client_auth::{AssertionClaims, ClientKey};
use argus_core::time::Timestamp;
use argus_crypto::VerifyingKey;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;

pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssertionError {
    #[error("the client assertion is malformed")]
    Malformed,

    #[error("the client assertion algorithm is not accepted")]
    DisallowedAlgorithm,

    #[error("the client assertion is missing a required claim")]
    MissingClaim,

    #[error("the client assertion signature does not verify")]
    BadSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedAssertion {
    pub client_id: String,

    pub kid: Option<String>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

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

pub fn verify(assertion: &str, keys: &[ClientKey]) -> Result<AssertionClaims, AssertionError> {
    let (h, c, sig_b64) = split(assertion)?;
    let header: Header = decode(h)?;
    if header.alg != "ES256" {
        return Err(AssertionError::DisallowedAlgorithm);
    }

    let signature =
        Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| AssertionError::Malformed)?;
    let signing_input = format!("{h}.{c}");

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

    #[test]
    fn parse_extracts_the_lookup_key_without_verifying() {
        let (signing, _) = key_pair("k1");
        let a = assertion(&signing, &good_header("k1"), &good_payload());

        let u = parse(&a).expect("parses");
        assert_eq!(u.client_id, "acme-web");
        assert_eq!(u.kid.as_deref(), Some("k1"));

        let tampered = format!("{a}x");
        assert!(parse(&tampered).is_ok());

        let (_, public) = key_pair("k1");
        assert!(verify(&tampered, &[public]).is_err());
    }

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

    #[test]
    fn any_registered_key_may_verify_during_rotation() {
        let (old_signing, old_public) = key_pair("old");
        let (_, new_public) = key_pair("new");
        let a = assertion(&old_signing, &good_header("old"), &good_payload());

        assert!(verify(&a, &[old_public, new_public]).is_ok());
    }

    #[test]
    fn a_missing_kid_falls_back_to_trying_every_key() {
        let (signing, public) = key_pair("k1");
        let (_, other) = key_pair("k2");
        let a = assertion(&signing, r#"{"alg":"ES256","typ":"JWT"}"#, &good_payload());

        assert!(parse(&a).expect("parse").kid.is_none());
        assert!(verify(&a, &[other, public]).is_ok());
    }

    #[test]
    fn a_kid_that_matches_no_registered_key_fails() {
        let (signing, public) = key_pair("k1");
        let a = assertion(&signing, &good_header("nope"), &good_payload());

        assert_eq!(
            verify(&a, &[public]).unwrap_err(),
            AssertionError::BadSignature
        );
    }

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
