use serde_json::{Map, Value};

use crate::aal::Aal;
use crate::time::Timestamp;

// draft-liu-oauth-chain-delegation. Zincir uzunluğu sınırlı, yoksa doğrulama
// maliyeti saldırganın kontrolündeki bir sayıyla ölçeklenir.
pub const MAX_HOPS: usize = 5;
// draft-mcguinness-oauth-actor-profile: bir uygulama en az 4 seviye `act`
// yuvalaması desteklemeli. Kanonik aktör (iss, sub) çiftidir, tek başına sub
// değil.
pub const MIN_SUPPORTED_ACTOR_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRecord {
    pub delegator_id: String,
    pub delegatee_id: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub scope: Vec<String>,
    pub floor: Option<Aal>,
    pub as_signature: String,
    pub delegator_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationFault {
    #[error("the chain carries no record")]
    Empty,

    #[error("the chain is {actual} hops long and this server accepts {allowed}")]
    TooLong { allowed: usize, actual: usize },

    #[error("hop {index} is delegated by {found}, which is not the party hop {previous} handed to")]
    Unlinked {
        index: usize,
        previous: usize,
        found: String,
    },

    #[error("hop {index} widens the scope it was given: {scope}")]
    ScopeWidened { index: usize, scope: String },

    #[error("hop {index} outlives the delegation it came from")]
    ExpiryExtended { index: usize },

    #[error("hop {index} claims to have been issued before the delegation it came from")]
    IssuedBeforeItsParent { index: usize },

    #[error("hop {index} lowers the assurance floor it was given")]
    FloorRelaxed { index: usize },

    #[error("{party} appears twice in the chain")]
    Cycle { party: String },

    #[error("hop {index} carries no {which} signature")]
    Unsigned { index: usize, which: &'static str },

    #[error("the chain has expired")]
    Expired,

    #[error("the chain is not yet valid")]
    NotYetValid,

    #[error("the declared depth {declared} does not match the {actual} records present")]
    DepthMismatch { declared: usize, actual: usize },

    #[error("the declared depth {declared} exceeds the declared maximum {maximum}")]
    DepthAboveMaximum { declared: usize, maximum: usize },

    #[error("the subject of the token is not the party the chain starts from")]
    SubjectNotTheDelegator,

    #[error("the outermost actor is not the party the chain ends at")]
    ActorNotTheDelegatee,

    #[error("a delegation record is not a JSON object")]
    NotAnObject,

    #[error("a delegation record carries no {field}")]
    MissingField { field: &'static str },
}

fn scope_set(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_owned).collect()
}

#[must_use]
pub fn contains_scope(parent: &[String], child: &[String]) -> bool {
    child.iter().all(|value| parent.contains(value))
}

pub fn check(
    chain: &[DelegationRecord],
    declared_depth: usize,
    declared_maximum: usize,
    now: Timestamp,
) -> Result<(), DelegationFault> {
    let Some(first) = chain.first() else {
        return Err(DelegationFault::Empty);
    };

    if chain.len() > MAX_HOPS {
        return Err(DelegationFault::TooLong {
            allowed: MAX_HOPS,
            actual: chain.len(),
        });
    }

    if declared_depth != chain.len() {
        return Err(DelegationFault::DepthMismatch {
            declared: declared_depth,
            actual: chain.len(),
        });
    }

    if declared_depth > declared_maximum {
        return Err(DelegationFault::DepthAboveMaximum {
            declared: declared_depth,
            maximum: declared_maximum,
        });
    }

    let mut seen: Vec<&str> = vec![first.delegator_id.as_str()];

    for (index, record) in chain.iter().enumerate() {
        if record.as_signature.is_empty() {
            return Err(DelegationFault::Unsigned {
                index,
                which: "authorization server",
            });
        }

        if record.delegator_signature.is_empty() {
            return Err(DelegationFault::Unsigned {
                index,
                which: "delegator",
            });
        }

        if seen.contains(&record.delegatee_id.as_str()) {
            return Err(DelegationFault::Cycle {
                party: record.delegatee_id.clone(),
            });
        }
        seen.push(record.delegatee_id.as_str());

        if record
            .expires_at
            .saturating_add(crate::time::Duration::from_seconds(0))
            <= now
        {
            return Err(DelegationFault::Expired);
        }

        if now < record.issued_at {
            return Err(DelegationFault::NotYetValid);
        }

        let Some(previous) = index.checked_sub(1).and_then(|i| chain.get(i)) else {
            continue;
        };

        if record.delegator_id != previous.delegatee_id {
            return Err(DelegationFault::Unlinked {
                index,
                previous: index.saturating_sub(1),
                found: record.delegator_id.clone(),
            });
        }

        if !contains_scope(&previous.scope, &record.scope) {
            return Err(DelegationFault::ScopeWidened {
                index,
                scope: record.scope.join(" "),
            });
        }

        if record.expires_at > previous.expires_at {
            return Err(DelegationFault::ExpiryExtended { index });
        }

        if record.issued_at < previous.issued_at {
            return Err(DelegationFault::IssuedBeforeItsParent { index });
        }

        if let Some(parent_floor) = previous.floor {
            match record.floor {
                None => return Err(DelegationFault::FloorRelaxed { index }),
                Some(child_floor) if child_floor < parent_floor => {
                    return Err(DelegationFault::FloorRelaxed { index });
                }
                Some(_) => {}
            }
        }
    }

    Ok(())
}

pub fn check_against_token(
    chain: &[DelegationRecord],
    subject: &str,
    outermost_actor: &str,
) -> Result<(), DelegationFault> {
    let Some(first) = chain.first() else {
        return Err(DelegationFault::Empty);
    };

    let last = chain.last().ok_or(DelegationFault::Empty)?;

    if first.delegator_id != subject {
        return Err(DelegationFault::SubjectNotTheDelegator);
    }

    if last.delegatee_id != outermost_actor {
        return Err(DelegationFault::ActorNotTheDelegatee);
    }

    Ok(())
}

#[must_use]
pub fn effective_scope(chain: &[DelegationRecord]) -> Vec<String> {
    chain
        .last()
        .map(|record| record.scope.clone())
        .unwrap_or_default()
}

#[must_use]
pub fn effective_expiry(chain: &[DelegationRecord]) -> Option<Timestamp> {
    chain.iter().map(|record| record.expires_at).min()
}

#[must_use]
pub fn effective_floor(chain: &[DelegationRecord]) -> Option<Aal> {
    chain.iter().filter_map(|record| record.floor).max()
}

#[must_use]
pub fn signing_input(record: &DelegationRecord) -> Value {
    let mut body = Map::new();
    body.insert(
        "delegator_id".to_owned(),
        Value::String(record.delegator_id.clone()),
    );
    body.insert(
        "delegatee_id".to_owned(),
        Value::String(record.delegatee_id.clone()),
    );
    body.insert(
        "iat".to_owned(),
        Value::from(record.issued_at.as_unix_seconds()),
    );
    body.insert(
        "exp".to_owned(),
        Value::from(record.expires_at.as_unix_seconds()),
    );
    body.insert("scope".to_owned(), Value::String(record.scope.join(" ")));

    if let Some(floor) = record.floor {
        body.insert(
            "acr_floor".to_owned(),
            Value::String(floor.as_str().to_owned()),
        );
    }

    Value::Object(body)
}

pub fn parse_record(raw: &Value) -> Result<DelegationRecord, DelegationFault> {
    let object = raw.as_object().ok_or(DelegationFault::NotAnObject)?;

    let text = |field: &'static str| -> Result<String, DelegationFault> {
        object
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(DelegationFault::MissingField { field })
    };

    let time = |field: &'static str| -> Result<Timestamp, DelegationFault> {
        object
            .get(field)
            .and_then(Value::as_i64)
            .map(Timestamp::from_unix_seconds)
            .ok_or(DelegationFault::MissingField { field })
    };

    let floor = match object.get("acr_floor").and_then(Value::as_str) {
        None => None,
        Some(raw) => Aal::parse(raw),
    };

    Ok(DelegationRecord {
        delegator_id: text("delegator_id")?,
        delegatee_id: text("delegatee_id")?,
        issued_at: time("iat")?,
        expires_at: time("exp")?,
        scope: object
            .get("scope")
            .and_then(Value::as_str)
            .map(scope_set)
            .unwrap_or_default(),
        floor,
        as_signature: text("as_signature")?,
        delegator_signature: text("delegator_signature")?,
    })
}

pub fn parse_chain(raw: &Value) -> Result<Vec<DelegationRecord>, DelegationFault> {
    let list = raw.as_array().ok_or(DelegationFault::NotAnObject)?;

    if list.len() > MAX_HOPS {
        return Err(DelegationFault::TooLong {
            allowed: MAX_HOPS,
            actual: list.len(),
        });
    }

    list.iter().map(parse_record).collect()
}

#[must_use]
pub fn actor_depth(act: &Value) -> usize {
    let mut depth = 0_usize;
    let mut current = act;

    while current.is_object() {
        depth = depth.saturating_add(1);
        match current.get("act") {
            None => break,
            Some(inner) => current = inner,
        }
    }

    depth
}

#[must_use]
pub fn canonical_actor(act: &Value) -> Option<(String, String)> {
    let issuer = act.get("iss")?.as_str()?.to_owned();
    let subject = act.get("sub")?.as_str()?.to_owned();
    Some((issuer, subject))
}

#[must_use]
pub fn outermost_actor(act: &Value) -> Option<String> {
    act.get("sub").and_then(Value::as_str).map(str::to_owned)
}
