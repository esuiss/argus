use std::collections::BTreeMap;

use serde_json::Value;

use crate::time::{Duration, Timestamp};

pub const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-federation";
pub const ENTITY_STATEMENT_TYPE: &str = "entity-statement+jwt";
pub const MAX_CLOCK_SKEW: Duration = Duration::from_seconds(60);
pub const MAX_AUTHORITY_HINTS: usize = 8;
pub const MAX_TRUST_MARKS: usize = 32;

pub const ENTITY_TYPE_FEDERATION: &str = "federation_entity";
pub const ENTITY_TYPE_OPENID_PROVIDER: &str = "openid_provider";
pub const ENTITY_TYPE_RELYING_PARTY: &str = "openid_relying_party";
pub const ENTITY_TYPE_AUTHORIZATION_SERVER: &str = "oauth_authorization_server";
pub const ENTITY_TYPE_RESOURCE: &str = "oauth_resource";
pub const ENTITY_TYPE_CLIENT: &str = "oauth_client";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Leaf,
    Intermediate,
    TrustAnchor,
}

impl Role {
    #[must_use]
    pub const fn serves_subordinates(self) -> bool {
        matches!(self, Self::Intermediate | Self::TrustAnchor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatementFault {
    #[error("the statement is not a JSON object")]
    NotAnObject,

    #[error("the statement carries no {claim}")]
    Missing { claim: &'static str },

    #[error("the claim {claim} is not of the shape the specification requires")]
    WrongShape { claim: &'static str },

    #[error("an entity identifier must be an https URL with no query and no fragment")]
    NotAnEntityIdentifier,

    #[error("an entity configuration must be issued by the entity it describes")]
    NotSelfIssued,

    #[error("a subordinate statement must not be issued by its own subject")]
    SelfIssuedSubordinate,

    #[error("the statement expires before it was issued")]
    ExpiresBeforeIssued,

    #[error("the statement is not yet valid")]
    NotYetValid,

    #[error("the statement has expired")]
    Expired,

    #[error("the statement carries no federation signing key")]
    NoKeys,

    #[error("the statement carries a critical claim this server does not understand: {claim}")]
    UnknownCritical { claim: String },

    #[error("an entity configuration may not carry {claim}")]
    ConfigurationOnly { claim: &'static str },

    #[error("a subordinate statement may not carry {claim}")]
    SubordinateOnly { claim: &'static str },

    #[error("the statement names more authorities than this server will follow")]
    TooManyAuthorities,

    #[error("the statement carries more trust marks than this server will read")]
    TooManyTrustMarks,

    #[error("a leaf entity must not publish the {endpoint} endpoint")]
    LeafServesSubordinates { endpoint: &'static str },

    #[error("an entity that serves subordinates must publish the {endpoint} endpoint")]
    MissingSubordinateEndpoint { endpoint: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityIdentifier(String);

impl EntityIdentifier {
    pub fn parse(raw: &str) -> Result<Self, StatementFault> {
        let Some(rest) = raw.strip_prefix("https://") else {
            return Err(StatementFault::NotAnEntityIdentifier);
        };

        if rest.is_empty() || raw.contains('?') || raw.contains('#') {
            return Err(StatementFault::NotAnEntityIdentifier);
        }

        let host = rest.split('/').next().unwrap_or_default();
        if host.is_empty() || host.contains('@') || host.contains(' ') {
            return Err(StatementFault::NotAnEntityIdentifier);
        }

        Ok(Self(raw.trim_end_matches('/').to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn well_known(&self) -> String {
        format!("{}{WELL_KNOWN_SUFFIX}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustMark {
    pub trust_mark_type: String,
    pub trust_mark: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Constraints {
    pub max_path_length: Option<u32>,
    pub naming_allowed: Vec<String>,
    pub naming_excluded: Vec<String>,
    pub allowed_entity_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntityStatement {
    pub issuer: EntityIdentifier,
    pub subject: EntityIdentifier,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub keys: Value,
    pub metadata: BTreeMap<String, Value>,
    pub metadata_policy: Option<Value>,
    pub authority_hints: Vec<EntityIdentifier>,
    pub trust_marks: Vec<TrustMark>,
    pub constraints: Constraints,
    pub source_endpoint: Option<String>,
}

impl EntityStatement {
    #[must_use]
    pub fn is_configuration(&self) -> bool {
        self.issuer == self.subject
    }

    #[must_use]
    pub fn entity_type(&self, name: &str) -> Option<&Value> {
        self.metadata.get(name)
    }

    #[must_use]
    pub fn federation_endpoint(&self, name: &str) -> Option<&str> {
        self.metadata
            .get(ENTITY_TYPE_FEDERATION)?
            .get(name)?
            .as_str()
    }
}

fn required_string(
    body: &serde_json::Map<String, Value>,
    claim: &'static str,
) -> Result<String, StatementFault> {
    body.get(claim)
        .ok_or(StatementFault::Missing { claim })?
        .as_str()
        .map(str::to_owned)
        .ok_or(StatementFault::WrongShape { claim })
}

fn required_time(
    body: &serde_json::Map<String, Value>,
    claim: &'static str,
) -> Result<Timestamp, StatementFault> {
    let seconds = body
        .get(claim)
        .ok_or(StatementFault::Missing { claim })?
        .as_i64()
        .ok_or(StatementFault::WrongShape { claim })?;

    Ok(Timestamp::from_unix_seconds(seconds))
}

const UNDERSTOOD_CRITICAL: [&str; 0] = [];

#[allow(
    clippy::too_many_lines,
    reason = "the statement checklist reads as one ordered list of the specification's rules"
)]
pub fn parse(body: &Value) -> Result<EntityStatement, StatementFault> {
    let object = body.as_object().ok_or(StatementFault::NotAnObject)?;

    let issuer = EntityIdentifier::parse(&required_string(object, "iss")?)?;
    let subject = EntityIdentifier::parse(&required_string(object, "sub")?)?;
    let issued_at = required_time(object, "iat")?;
    let expires_at = required_time(object, "exp")?;

    if expires_at <= issued_at {
        return Err(StatementFault::ExpiresBeforeIssued);
    }

    if let Some(critical) = object.get("crit") {
        let names = critical
            .as_array()
            .ok_or(StatementFault::WrongShape { claim: "crit" })?;

        for name in names {
            let name = name
                .as_str()
                .ok_or(StatementFault::WrongShape { claim: "crit" })?;

            if !UNDERSTOOD_CRITICAL.contains(&name) {
                return Err(StatementFault::UnknownCritical {
                    claim: name.to_owned(),
                });
            }
        }
    }

    let keys = object
        .get("jwks")
        .cloned()
        .ok_or(StatementFault::Missing { claim: "jwks" })?;

    if keys
        .get("keys")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        return Err(StatementFault::NoKeys);
    }

    let metadata = match object.get("metadata") {
        None => BTreeMap::new(),
        Some(value) => value
            .as_object()
            .ok_or(StatementFault::WrongShape { claim: "metadata" })?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    };

    let is_configuration = issuer == subject;

    if is_configuration {
        for claim in ["metadata_policy", "constraints", "source_endpoint"] {
            if object.contains_key(claim) {
                return Err(StatementFault::ConfigurationOnly {
                    claim: match claim {
                        "metadata_policy" => "metadata_policy",
                        "constraints" => "constraints",
                        _ => "source_endpoint",
                    },
                });
            }
        }
    } else {
        for claim in ["authority_hints", "trust_mark_issuers", "trust_mark_owners"] {
            if object.contains_key(claim) {
                return Err(StatementFault::SubordinateOnly {
                    claim: match claim {
                        "authority_hints" => "authority_hints",
                        "trust_mark_issuers" => "trust_mark_issuers",
                        _ => "trust_mark_owners",
                    },
                });
            }
        }
    }

    let mut authority_hints = Vec::new();
    if let Some(hints) = object.get("authority_hints") {
        let list = hints.as_array().ok_or(StatementFault::WrongShape {
            claim: "authority_hints",
        })?;

        if list.len() > MAX_AUTHORITY_HINTS {
            return Err(StatementFault::TooManyAuthorities);
        }

        for hint in list {
            let raw = hint.as_str().ok_or(StatementFault::WrongShape {
                claim: "authority_hints",
            })?;
            authority_hints.push(EntityIdentifier::parse(raw)?);
        }
    }

    let mut trust_marks = Vec::new();
    if let Some(marks) = object.get("trust_marks") {
        let list = marks.as_array().ok_or(StatementFault::WrongShape {
            claim: "trust_marks",
        })?;

        if list.len() > MAX_TRUST_MARKS {
            return Err(StatementFault::TooManyTrustMarks);
        }

        for mark in list {
            let kind = mark.get("trust_mark_type").and_then(Value::as_str).ok_or(
                StatementFault::WrongShape {
                    claim: "trust_marks",
                },
            )?;

            let jwt = mark.get("trust_mark").and_then(Value::as_str).ok_or(
                StatementFault::WrongShape {
                    claim: "trust_marks",
                },
            )?;

            trust_marks.push(TrustMark {
                trust_mark_type: kind.to_owned(),
                trust_mark: jwt.to_owned(),
            });
        }
    }

    let constraints = match object.get("constraints") {
        None => Constraints::default(),
        Some(value) => parse_constraints(value)?,
    };

    Ok(EntityStatement {
        issuer,
        subject,
        issued_at,
        expires_at,
        keys,
        metadata,
        metadata_policy: object.get("metadata_policy").cloned(),
        authority_hints,
        trust_marks,
        constraints,
        source_endpoint: object
            .get("source_endpoint")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn parse_constraints(value: &Value) -> Result<Constraints, StatementFault> {
    let object = value.as_object().ok_or(StatementFault::WrongShape {
        claim: "constraints",
    })?;

    let max_path_length = match object.get("max_path_length") {
        None => None,
        Some(raw) => Some(
            raw.as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(StatementFault::WrongShape {
                    claim: "constraints",
                })?,
        ),
    };

    let strings = |name: &str| -> Result<Vec<String>, StatementFault> {
        match object.get("naming_constraints").and_then(|n| n.get(name)) {
            None => Ok(Vec::new()),
            Some(list) => list
                .as_array()
                .ok_or(StatementFault::WrongShape {
                    claim: "constraints",
                })?
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or(StatementFault::WrongShape {
                            claim: "constraints",
                        })
                })
                .collect(),
        }
    };

    let allowed_entity_types = match object.get("allowed_entity_types") {
        None => None,
        Some(list) => Some(
            list.as_array()
                .ok_or(StatementFault::WrongShape {
                    claim: "constraints",
                })?
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or(StatementFault::WrongShape {
                            claim: "constraints",
                        })
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };

    Ok(Constraints {
        max_path_length,
        naming_allowed: strings("permitted")?,
        naming_excluded: strings("excluded")?,
        allowed_entity_types,
    })
}

pub fn check_freshness(statement: &EntityStatement, now: Timestamp) -> Result<(), StatementFault> {
    if now.saturating_add(MAX_CLOCK_SKEW) < statement.issued_at {
        return Err(StatementFault::NotYetValid);
    }

    if statement.expires_at.saturating_add(MAX_CLOCK_SKEW) <= now {
        return Err(StatementFault::Expired);
    }

    Ok(())
}

pub fn check_configuration(
    statement: &EntityStatement,
    expected: &EntityIdentifier,
) -> Result<(), StatementFault> {
    if statement.issuer != statement.subject || &statement.subject != expected {
        return Err(StatementFault::NotSelfIssued);
    }
    Ok(())
}

pub fn check_subordinate(
    statement: &EntityStatement,
    expected_issuer: &EntityIdentifier,
    expected_subject: &EntityIdentifier,
) -> Result<(), StatementFault> {
    if statement.issuer == statement.subject {
        return Err(StatementFault::SelfIssuedSubordinate);
    }

    if &statement.issuer != expected_issuer || &statement.subject != expected_subject {
        return Err(StatementFault::NotSelfIssued);
    }

    Ok(())
}

pub fn check_role(statement: &EntityStatement, role: Role) -> Result<(), StatementFault> {
    let fetch = statement.federation_endpoint("federation_fetch_endpoint");
    let list = statement.federation_endpoint("federation_list_endpoint");

    if role.serves_subordinates() {
        if fetch.is_none() {
            return Err(StatementFault::MissingSubordinateEndpoint {
                endpoint: "federation_fetch_endpoint",
            });
        }
        if list.is_none() {
            return Err(StatementFault::MissingSubordinateEndpoint {
                endpoint: "federation_list_endpoint",
            });
        }
    } else {
        if fetch.is_some() {
            return Err(StatementFault::LeafServesSubordinates {
                endpoint: "federation_fetch_endpoint",
            });
        }
        if list.is_some() {
            return Err(StatementFault::LeafServesSubordinates {
                endpoint: "federation_list_endpoint",
            });
        }
    }

    Ok(())
}

#[must_use]
pub fn naming_permits(subject: &EntityIdentifier, constraints: &Constraints) -> bool {
    let under = |prefix: &String| {
        let prefix = prefix.trim_end_matches('/');
        subject.as_str() == prefix
            || subject
                .as_str()
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    };

    if constraints.naming_excluded.iter().any(under) {
        return false;
    }

    if constraints.naming_allowed.is_empty() {
        return true;
    }

    constraints.naming_allowed.iter().any(under)
}
