use argus_crypto::{CryptoError, SigningKey, VerifyingKey};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::{Map, Value};

use crate::jcs::{TextFault, canonicalize, canonicalize_text};

pub const SIGNATURE_FIELD: &str = "signature";
pub const MAX_CARD_BYTES: usize = 256 * 1024;

pub const SECURITY_SCHEME_TYPES: [&str; 5] =
    ["apiKey", "http", "oauth2", "openIdConnect", "mutualTls"];

pub const ACCEPTED_OAUTH_FLOWS: [&str; 3] =
    ["authorizationCode", "clientCredentials", "deviceCode"];

pub const FORBIDDEN_OAUTH_FLOWS: [&str; 2] = ["implicit", "password"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CardFault {
    #[error("the agent card is not a JSON object")]
    NotAnObject,

    #[error("the agent card carries no {field}")]
    Missing { field: &'static str },

    #[error("the field {field} is not of the shape the protocol requires")]
    WrongShape { field: &'static str },

    #[error("the agent card is larger than this server will sign")]
    TooLarge,

    #[error("the security scheme {name} declares the type {kind}")]
    UnknownSecurityScheme { name: String, kind: String },

    #[error("the security scheme {name} offers the {flow} flow, which OAuth 2.1 removed")]
    ForbiddenFlow { name: String, flow: String },

    #[error("the security scheme {name} offers no flow this server will vouch for")]
    NoAcceptableFlow { name: String },

    #[error("the skill {skill} names the security scheme {scheme}, which the card never declares")]
    UndeclaredScheme { skill: String, scheme: String },

    #[error("the agent card could not be canonicalized: {0}")]
    Canonical(#[from] TextFault),

    #[error("the agent card could not be signed")]
    Signing,

    #[error("the signature block is not a detached JWS this server understands")]
    MalformedSignature,

    #[error("the signature declares the algorithm {alg}, which is not accepted")]
    DisallowedAlgorithm { alg: String },

    #[error("the signature does not verify against the key it names")]
    BadSignature,

    #[error("the signature names the key {kid}, which is not one this issuer publishes")]
    NoSuchKey { kid: String },
}

pub fn check(card: &Value) -> Result<(), CardFault> {
    let object = card.as_object().ok_or(CardFault::NotAnObject)?;

    for field in ["id", "name"] {
        let present = object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());

        if !present {
            return Err(CardFault::Missing {
                field: if field == "id" { "id" } else { "name" },
            });
        }
    }

    let interfaces =
        object
            .get("interfaces")
            .and_then(Value::as_array)
            .ok_or(CardFault::Missing {
                field: "interfaces",
            })?;

    if interfaces.is_empty() {
        return Err(CardFault::Missing {
            field: "interfaces",
        });
    }

    let mut declared: Vec<String> = Vec::new();

    if let Some(schemes) = object.get("securitySchemes") {
        let schemes = schemes.as_object().ok_or(CardFault::WrongShape {
            field: "securitySchemes",
        })?;

        for (name, scheme) in schemes {
            declared.push(name.clone());

            let kind = scheme
                .get("type")
                .and_then(Value::as_str)
                .ok_or(CardFault::WrongShape {
                    field: "securitySchemes",
                })?;

            if !SECURITY_SCHEME_TYPES.contains(&kind) {
                return Err(CardFault::UnknownSecurityScheme {
                    name: name.clone(),
                    kind: kind.to_owned(),
                });
            }

            if kind == "oauth2" {
                check_flows(name, scheme)?;
            }
        }
    }

    if let Some(security) = object.get("security") {
        check_security(security, &declared, "card")?;
    }

    if let Some(skills) = object.get("skills").and_then(Value::as_array) {
        for skill in skills {
            let name = skill
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
                .to_owned();

            if let Some(security) = skill.get("security") {
                check_security(security, &declared, &name)?;
            }
        }
    }

    Ok(())
}

fn check_flows(name: &str, scheme: &Value) -> Result<(), CardFault> {
    let flows = scheme
        .get("flows")
        .and_then(Value::as_object)
        .ok_or(CardFault::WrongShape {
            field: "securitySchemes",
        })?;

    for flow in flows.keys() {
        if FORBIDDEN_OAUTH_FLOWS.contains(&flow.as_str()) {
            return Err(CardFault::ForbiddenFlow {
                name: name.to_owned(),
                flow: flow.clone(),
            });
        }
    }

    let acceptable = flows
        .keys()
        .any(|flow| ACCEPTED_OAUTH_FLOWS.contains(&flow.as_str()));

    if !acceptable {
        return Err(CardFault::NoAcceptableFlow {
            name: name.to_owned(),
        });
    }

    Ok(())
}

fn check_security(security: &Value, declared: &[String], where_: &str) -> Result<(), CardFault> {
    let entries = security
        .as_array()
        .ok_or(CardFault::WrongShape { field: "security" })?;

    for entry in entries {
        let requirement = entry
            .as_object()
            .ok_or(CardFault::WrongShape { field: "security" })?;

        for scheme in requirement.keys() {
            if !declared.iter().any(|name| name == scheme) {
                return Err(CardFault::UndeclaredScheme {
                    skill: where_.to_owned(),
                    scheme: scheme.clone(),
                });
            }
        }
    }

    Ok(())
}

#[must_use]
pub fn without_signature(card: &Value) -> Value {
    let Some(object) = card.as_object() else {
        return card.clone();
    };

    let mut stripped = object.clone();
    stripped.remove(SIGNATURE_FIELD);
    Value::Object(stripped)
}

pub fn payload(card: &Value) -> Result<String, CardFault> {
    let stripped = without_signature(card);
    let rendered = serde_json::to_string(&stripped).map_err(|_| CardFault::NotAnObject)?;

    if rendered.len() > MAX_CARD_BYTES {
        return Err(CardFault::TooLarge);
    }

    Ok(canonicalize_text(&rendered)?)
}

pub fn payload_from_text(raw: &str) -> Result<String, CardFault> {
    if raw.len() > MAX_CARD_BYTES {
        return Err(CardFault::TooLarge);
    }

    let parsed: Value = serde_json::from_str(raw).map_err(|_| CardFault::NotAnObject)?;
    let stripped = without_signature(&parsed);

    let rendered = serde_json::to_string(&stripped).map_err(|_| CardFault::NotAnObject)?;
    Ok(canonicalize_text(&rendered)?)
}

pub fn sign(card: &Value, key: &SigningKey, issuer: &str) -> Result<Value, CardFault> {
    check(card)?;

    let body = payload(card)?;

    let protected = serde_json::json!({
        "alg": "ES256",
        "kid": key.kid(),
        "typ": "JOSE",
        "iss": issuer
    });

    let protected_form = canonicalize(&protected).map_err(|_| CardFault::Signing)?;
    let protected_encoded = Base64UrlUnpadded::encode_string(protected_form.as_bytes());
    let payload_encoded = Base64UrlUnpadded::encode_string(body.as_bytes());

    let signing_input = format!("{protected_encoded}.{payload_encoded}");

    let signature = key
        .sign(signing_input.as_bytes())
        .map_err(|_: CryptoError| CardFault::Signing)?;

    let mut signed = card.as_object().ok_or(CardFault::NotAnObject)?.clone();

    let mut block = Map::new();
    block.insert("protected".to_owned(), Value::String(protected_encoded));
    block.insert(
        "signature".to_owned(),
        Value::String(Base64UrlUnpadded::encode_string(&signature)),
    );

    signed.insert(SIGNATURE_FIELD.to_owned(), Value::Object(block));

    Ok(Value::Object(signed))
}

pub struct PublishedKey {
    pub kid: String,
    pub key: VerifyingKey,
}

pub fn verify(card: &Value, keys: &[PublishedKey]) -> Result<String, CardFault> {
    let block = card
        .get(SIGNATURE_FIELD)
        .and_then(Value::as_object)
        .ok_or(CardFault::MalformedSignature)?;

    let protected_encoded = block
        .get("protected")
        .and_then(Value::as_str)
        .ok_or(CardFault::MalformedSignature)?;

    let signature_encoded = block
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(CardFault::MalformedSignature)?;

    let protected_bytes = Base64UrlUnpadded::decode_vec(protected_encoded)
        .map_err(|_| CardFault::MalformedSignature)?;

    let protected: Value =
        serde_json::from_slice(&protected_bytes).map_err(|_| CardFault::MalformedSignature)?;

    let alg = protected
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(CardFault::MalformedSignature)?;

    if alg != "ES256" {
        return Err(CardFault::DisallowedAlgorithm {
            alg: alg.to_owned(),
        });
    }

    let kid = protected
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(CardFault::MalformedSignature)?;

    let published = keys
        .iter()
        .find(|candidate| candidate.kid == kid)
        .ok_or_else(|| CardFault::NoSuchKey {
            kid: kid.to_owned(),
        })?;

    let body = payload(card)?;
    let payload_encoded = Base64UrlUnpadded::encode_string(body.as_bytes());
    let signing_input = format!("{protected_encoded}.{payload_encoded}");

    let raw_signature = Base64UrlUnpadded::decode_vec(signature_encoded)
        .map_err(|_| CardFault::MalformedSignature)?;

    published
        .key
        .verify(signing_input.as_bytes(), &raw_signature)
        .map_err(|_| CardFault::BadSignature)?;

    Ok(protected
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned())
}
