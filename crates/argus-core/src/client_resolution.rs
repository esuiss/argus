use serde_json::Value;

use crate::time::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Unverified,
    Registered,
    Federated,
    FederatedWithTrustMark,
}

impl TrustLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Registered => "registered",
            Self::Federated => "federated",
            Self::FederatedWithTrustMark => "federated_with_trust_mark",
        }
    }

    #[must_use]
    pub const fn may_skip_consent(self) -> bool {
        matches!(self, Self::FederatedWithTrustMark)
    }

    #[must_use]
    pub const fn must_warn_the_user(self) -> bool {
        matches!(self, Self::Unverified)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSource {
    LocalRegistration,
    ClientIdMetadataDocument,
    Federation,
}

impl TrustSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalRegistration => "dcr",
            Self::ClientIdMetadataDocument => "cimd",
            Self::Federation => "federation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIdShape {
    HttpsUrl,
    Opaque,
}

#[must_use]
pub fn shape_of(client_id: &str) -> ClientIdShape {
    if client_id.starts_with("https://") || client_id.starts_with("http://") {
        ClientIdShape::HttpsUrl
    } else {
        ClientIdShape::Opaque
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPaths {
    pub local_registration: bool,
    pub client_id_metadata_document: bool,
    pub federation: bool,
}

impl Default for TenantPaths {
    fn default() -> Self {
        Self {
            local_registration: true,
            client_id_metadata_document: false,
            federation: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    Federation,
    ClientIdMetadataDocument,
    LocalRegistration,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionFault {
    #[error("no resolution path is enabled for this tenant")]
    NoPathEnabled,

    #[error("a client identifier in URL form is never resolved from the local registry")]
    UrlWouldFallBackToLocal,

    #[error("the client identifier could not be resolved by any enabled path")]
    Unresolvable,

    #[error("the resolved metadata does not carry {parameter}")]
    MissingParameter { parameter: &'static str },

    #[error("a scope this client's trust level may not request: {scope}")]
    ScopeAboveTrustLevel { scope: String },
}

pub fn order(shape: ClientIdShape, paths: &TenantPaths) -> Result<Vec<Attempt>, ResolutionFault> {
    let mut out = Vec::with_capacity(3);

    match shape {
        ClientIdShape::HttpsUrl => {
            if paths.federation {
                out.push(Attempt::Federation);
            }
            if paths.client_id_metadata_document {
                out.push(Attempt::ClientIdMetadataDocument);
            }

            if out.is_empty() {
                return if paths.local_registration {
                    Err(ResolutionFault::UrlWouldFallBackToLocal)
                } else {
                    Err(ResolutionFault::NoPathEnabled)
                };
            }
        }

        ClientIdShape::Opaque => {
            if !paths.local_registration {
                return Err(ResolutionFault::NoPathEnabled);
            }
            out.push(Attempt::LocalRegistration);
        }
    }

    Ok(out)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedClient {
    pub client_id: String,
    pub metadata: Value,
    pub source: TrustSource,
    pub trust_level: TrustLevel,
    pub expires_at: Option<Timestamp>,
    pub policy_applied: bool,
    pub trust_anchor: Option<String>,
}

impl ResolvedClient {
    #[must_use]
    pub fn redirect_uris(&self) -> Vec<String> {
        self.metadata
            .get("redirect_uris")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn is_fresh(&self, now: Timestamp) -> bool {
        self.expires_at.is_none_or(|deadline| now < deadline)
    }
}

pub const SENSITIVE_SCOPES: [&str; 4] = ["scim", "admin", "offline_access", "urn:argus:vault:read"];

pub fn check_scopes(client: &ResolvedClient, requested: &str) -> Result<(), ResolutionFault> {
    if client.trust_level > TrustLevel::Unverified {
        return Ok(());
    }

    for scope in requested.split_whitespace() {
        if SENSITIVE_SCOPES.contains(&scope) {
            return Err(ResolutionFault::ScopeAboveTrustLevel {
                scope: scope.to_owned(),
            });
        }
    }

    Ok(())
}

#[must_use]
pub fn requires_consent(client: &ResolvedClient) -> bool {
    !client.trust_level.may_skip_consent()
}

#[must_use]
pub fn from_federation(
    client_id: &str,
    metadata: Value,
    trust_anchor: &str,
    expires_at: Timestamp,
    carries_trust_mark: bool,
) -> ResolvedClient {
    ResolvedClient {
        client_id: client_id.to_owned(),
        metadata,
        source: TrustSource::Federation,
        trust_level: if carries_trust_mark {
            TrustLevel::FederatedWithTrustMark
        } else {
            TrustLevel::Federated
        },
        expires_at: Some(expires_at),
        policy_applied: true,
        trust_anchor: Some(trust_anchor.to_owned()),
    }
}

#[must_use]
pub fn from_metadata_document(
    client_id: &str,
    metadata: Value,
    expires_at: Option<Timestamp>,
) -> ResolvedClient {
    ResolvedClient {
        client_id: client_id.to_owned(),
        metadata,
        source: TrustSource::ClientIdMetadataDocument,
        trust_level: TrustLevel::Unverified,
        expires_at,
        policy_applied: false,
        trust_anchor: None,
    }
}

#[must_use]
pub fn from_local_registration(client_id: &str, metadata: Value) -> ResolvedClient {
    ResolvedClient {
        client_id: client_id.to_owned(),
        metadata,
        source: TrustSource::LocalRegistration,
        trust_level: TrustLevel::Registered,
        expires_at: None,
        policy_applied: false,
        trust_anchor: None,
    }
}
