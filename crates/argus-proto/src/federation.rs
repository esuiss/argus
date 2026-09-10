use argus_crypto::{CryptoError, SigningKey, VerifyingKey};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ENTITY_STATEMENT_TYPE: &str = "entity-statement+jwt";
pub const TRUST_MARK_TYPE: &str = "trust-mark+jwt";
pub const RESOLVE_RESPONSE_TYPE: &str = "resolve-response+jwt";
pub const EXPLICIT_REGISTRATION_RESPONSE_TYPE: &str = "explicit-registration-response+jwt";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationHeader {
    pub alg: String,
    pub kid: String,
    pub typ: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatementJwtError {
    #[error("the statement could not be serialised")]
    Serialisation,

    #[error("the statement could not be signed")]
    Signing,

    #[error("the statement is not a well formed JWS")]
    Malformed,

    #[error("the statement declares the algorithm {alg}, which is not accepted")]
    DisallowedAlgorithm { alg: String },

    #[error("the statement declares the type {typ}, which is not the one expected")]
    WrongType { typ: String },

    #[error("no published key with the identifier {kid} could verify the statement")]
    NoSuchKey { kid: String },

    #[error("the signature does not verify")]
    BadSignature,

    #[error("a published key is not an EC P-256 key this server can use")]
    UnusableKey,
}

pub fn sign(claims: &Value, key: &SigningKey, typ: &str) -> Result<String, StatementJwtError> {
    let header = FederationHeader {
        alg: "ES256".to_owned(),
        kid: key.kid().to_owned(),
        typ: typ.to_owned(),
    };

    let head = serde_json::to_vec(&header).map_err(|_| StatementJwtError::Serialisation)?;
    let body = serde_json::to_vec(claims).map_err(|_| StatementJwtError::Serialisation)?;

    let signing_input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(&head),
        Base64UrlUnpadded::encode_string(&body)
    );

    let signature = key
        .sign(signing_input.as_bytes())
        .map_err(|_: CryptoError| StatementJwtError::Signing)?;

    Ok(format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&signature)
    ))
}

pub fn keys_from_jwks(jwks: &Value) -> Result<Vec<(String, VerifyingKey)>, StatementJwtError> {
    let list = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(StatementJwtError::UnusableKey)?;

    let mut out = Vec::with_capacity(list.len());

    for entry in list {
        if entry.get("kty").and_then(Value::as_str) != Some("EC") {
            continue;
        }
        if entry.get("crv").and_then(Value::as_str) != Some("P-256") {
            continue;
        }
        if let Some(usage) = entry.get("use").and_then(Value::as_str)
            && usage != "sig"
        {
            continue;
        }

        let Some(kid) = entry.get("kid").and_then(Value::as_str) else {
            continue;
        };

        let (Some(x), Some(y)) = (
            entry.get("x").and_then(Value::as_str),
            entry.get("y").and_then(Value::as_str),
        ) else {
            continue;
        };

        let x = Base64UrlUnpadded::decode_vec(x).map_err(|_| StatementJwtError::UnusableKey)?;
        let y = Base64UrlUnpadded::decode_vec(y).map_err(|_| StatementJwtError::UnusableKey)?;

        let x: [u8; 32] = x.try_into().map_err(|_| StatementJwtError::UnusableKey)?;
        let y: [u8; 32] = y.try_into().map_err(|_| StatementJwtError::UnusableKey)?;

        out.push((kid.to_owned(), VerifyingKey::from_components(&x, &y)));
    }

    if out.is_empty() {
        return Err(StatementJwtError::UnusableKey);
    }

    Ok(out)
}

pub fn verify(token: &str, jwks: &Value, expected_type: &str) -> Result<Value, StatementJwtError> {
    let mut parts = token.split('.');
    let (Some(head), Some(body), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(StatementJwtError::Malformed);
    };

    let head_bytes =
        Base64UrlUnpadded::decode_vec(head).map_err(|_| StatementJwtError::Malformed)?;
    let header: FederationHeader =
        serde_json::from_slice(&head_bytes).map_err(|_| StatementJwtError::Malformed)?;

    if header.alg != "ES256" {
        return Err(StatementJwtError::DisallowedAlgorithm { alg: header.alg });
    }

    if header.typ != expected_type {
        return Err(StatementJwtError::WrongType { typ: header.typ });
    }

    let keys = keys_from_jwks(jwks)?;

    let key = keys
        .iter()
        .find(|(kid, _)| *kid == header.kid)
        .map(|(_, key)| key)
        .ok_or_else(|| StatementJwtError::NoSuchKey {
            kid: header.kid.clone(),
        })?;

    let raw_signature =
        Base64UrlUnpadded::decode_vec(signature).map_err(|_| StatementJwtError::Malformed)?;

    let signing_input = format!("{head}.{body}");

    key.verify(signing_input.as_bytes(), &raw_signature)
        .map_err(|_| StatementJwtError::BadSignature)?;

    let body_bytes =
        Base64UrlUnpadded::decode_vec(body).map_err(|_| StatementJwtError::Malformed)?;

    serde_json::from_slice(&body_bytes).map_err(|_| StatementJwtError::Malformed)
}

#[must_use]
pub fn jwks_of(keys: &[&SigningKey]) -> Value {
    let mut published = Vec::with_capacity(keys.len());

    for key in keys {
        let Ok(components) = key.public_components() else {
            continue;
        };

        published.push(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": key.kid(),
            "x": Base64UrlUnpadded::encode_string(&components.x),
            "y": Base64UrlUnpadded::encode_string(&components.y)
        }));
    }

    serde_json::json!({ "keys": published })
}
