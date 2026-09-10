use serde_json::{Map, Value};

use crate::scim::ResourceType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    FeedAdd,
    FeedRemove,
    CreateNotice,
    CreateFull,
    PatchNotice,
    PatchFull,
    PutNotice,
    PutFull,
    Delete,
    Activate,
    Deactivate,
    AsyncResponse,
}

impl EventKind {
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::FeedAdd => "urn:ietf:params:scim:event:feed:add",
            Self::FeedRemove => "urn:ietf:params:scim:event:feed:remove",
            Self::CreateNotice => "urn:ietf:params:scim:event:prov:create:notice",
            Self::CreateFull => "urn:ietf:params:scim:event:prov:create:full",
            Self::PatchNotice => "urn:ietf:params:scim:event:prov:patch:notice",
            Self::PatchFull => "urn:ietf:params:scim:event:prov:patch:full",
            Self::PutNotice => "urn:ietf:params:scim:event:prov:put:notice",
            Self::PutFull => "urn:ietf:params:scim:event:prov:put:full",
            Self::Delete => "urn:ietf:params:scim:event:prov:delete",
            Self::Activate => "urn:ietf:params:scim:event:prov:activate",
            Self::Deactivate => "urn:ietf:params:scim:event:prov:deactivate",
            Self::AsyncResponse => "urn:ietf:params:scim:event:misc:asyncresp",
        }
    }

    #[must_use]
    pub const fn carries_full_payload(self) -> bool {
        matches!(self, Self::CreateFull | Self::PatchFull | Self::PutFull)
    }

    #[must_use]
    pub const fn carries_attribute_names(self) -> bool {
        matches!(
            self,
            Self::CreateNotice | Self::PatchNotice | Self::PutNotice
        )
    }
}

#[must_use]
pub fn all_event_uris() -> Vec<&'static str> {
    Vec::from([
        EventKind::FeedAdd.uri(),
        EventKind::FeedRemove.uri(),
        EventKind::CreateNotice.uri(),
        EventKind::PatchNotice.uri(),
        EventKind::PutNotice.uri(),
        EventKind::Delete.uri(),
        EventKind::Activate.uri(),
        EventKind::Deactivate.uri(),
    ])
}

pub const NEVER_RETURNED: [&str; 3] = ["password", "phc", "secret"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventFault {
    #[error("this event carries a full payload and cannot carry an attribute list")]
    BothPayloadAndAttributes,

    #[error("this event carries neither a payload nor an attribute list")]
    NeitherPayloadNorAttributes,

    #[error("the subject identifier must be a SCIM resource path")]
    SubjectNotAResourcePath,
}

#[must_use]
pub fn resource_uri(kind: ResourceType, id: &str) -> String {
    let plural = match kind {
        ResourceType::User => "Users",
        ResourceType::Group => "Groups",
    };
    format!("/{plural}/{id}")
}

#[must_use]
pub fn changed_attributes(before: &Value, after: &Value) -> Vec<String> {
    let empty = Map::new();
    let before = before.as_object().unwrap_or(&empty);
    let after = after.as_object().unwrap_or(&empty);

    let mut names: Vec<String> = Vec::new();

    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort_unstable();
    keys.dedup();

    for key in keys {
        if matches!(key.as_str(), "meta" | "schemas" | "id") {
            continue;
        }

        let old = before.get(key);
        let new = after.get(key);

        if old == new {
            continue;
        }

        match (old, new) {
            (Some(Value::Object(old)), Some(Value::Object(new))) => {
                let mut sub: Vec<&String> = old.keys().chain(new.keys()).collect();
                sub.sort_unstable();
                sub.dedup();
                for name in sub {
                    if old.get(name) != new.get(name) {
                        names.push(format!("{key}.{name}"));
                    }
                }
            }
            _ => names.push(key.clone()),
        }
    }

    names
}

#[must_use]
pub fn redact(payload: &Value) -> Value {
    let Some(object) = payload.as_object() else {
        return payload.clone();
    };

    let mut out = Map::new();
    for (key, value) in object {
        if NEVER_RETURNED
            .iter()
            .any(|never| key.eq_ignore_ascii_case(never))
        {
            continue;
        }
        out.insert(key.clone(), redact(value));
    }
    Value::Object(out)
}

pub struct Event {
    pub kind: EventKind,
    pub subject_uri: String,
    pub external_id: Option<String>,
    pub attributes: Vec<String>,
    pub payload: Option<Value>,
}

pub fn claims(
    event: &Event,
    issuer: &str,
    audience: &str,
    jti: &str,
    txn: &str,
    issued_at: i64,
) -> Result<Value, EventFault> {
    if !event.subject_uri.starts_with('/') {
        return Err(EventFault::SubjectNotAResourcePath);
    }

    let mut detail = Map::new();

    match (event.kind.carries_full_payload(), event.payload.as_ref()) {
        (true, Some(payload)) => {
            if !event.attributes.is_empty() {
                return Err(EventFault::BothPayloadAndAttributes);
            }
            detail.insert("data".to_owned(), redact(payload));
        }
        (true, None) => return Err(EventFault::NeitherPayloadNorAttributes),
        (false, _) => {
            if event.kind.carries_attribute_names() {
                if event.attributes.is_empty() {
                    return Err(EventFault::NeitherPayloadNorAttributes);
                }
                if event.payload.is_some() {
                    return Err(EventFault::BothPayloadAndAttributes);
                }
                detail.insert(
                    "attributes".to_owned(),
                    Value::Array(
                        event
                            .attributes
                            .iter()
                            .map(|name| Value::String(name.clone()))
                            .collect(),
                    ),
                );
            }
        }
    }

    let mut subject = Map::new();
    subject.insert("format".to_owned(), Value::String("scim".to_owned()));
    subject.insert("uri".to_owned(), Value::String(event.subject_uri.clone()));
    if let Some(external) = event.external_id.as_ref() {
        subject.insert("externalId".to_owned(), Value::String(external.clone()));
    }

    let mut events = Map::new();
    events.insert(event.kind.uri().to_owned(), Value::Object(detail));

    let mut body = Map::new();
    body.insert("iss".to_owned(), Value::String(issuer.to_owned()));
    body.insert("aud".to_owned(), Value::String(audience.to_owned()));
    body.insert("jti".to_owned(), Value::String(jti.to_owned()));
    body.insert("iat".to_owned(), Value::from(issued_at));
    body.insert("txn".to_owned(), Value::String(txn.to_owned()));
    body.insert("sub_id".to_owned(), Value::Object(subject));
    body.insert("events".to_owned(), Value::Object(events));

    Ok(Value::Object(body))
}
