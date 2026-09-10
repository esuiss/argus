use std::collections::HashMap;
use std::sync::Mutex;

use argus_core::authorize::RegisteredClient;
use argus_core::client_auth::{ClientAuthMethod, ClientKey};
use argus_core::client_resolution::{ResolvedClient, TrustLevel, from_federation};
use argus_core::federation::statement::{ENTITY_TYPE_RELYING_PARTY, EntityIdentifier};
use argus_core::id::ClientId;
use argus_core::redirect_uri::RedirectUri;
use argus_core::time::Timestamp;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::Value;

use super::fetch::Resolver;
use super::resolver::{Federation, ResolveFault};

pub const MAX_CACHE_SECONDS: i64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FederatedClientFault {
    #[error("the client identifier is not an entity identifier")]
    NotAnEntity,

    #[error("the trust chain could not be resolved: {0}")]
    Chain(#[from] ResolveFault),

    #[error("the resolved metadata registers no redirect_uri")]
    NoRedirectUri,

    #[error("the resolved metadata registers a redirect_uri this server refuses")]
    UnusableRedirectUri,

    #[error("a federated client must authenticate with asymmetric cryptography")]
    SymmetricAuthentication,

    #[error("the resolved metadata publishes no usable signing key")]
    NoSigningKey,
}

pub struct FederationRuntime<R> {
    federation: Federation<R>,
    cache: Mutex<HashMap<String, (RegisteredClient, ResolvedClient, i64)>>,
}

impl<R> core::fmt::Debug for FederationRuntime<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FederationRuntime")
    }
}

impl<R: Resolver> FederationRuntime<R> {
    #[must_use]
    pub fn new(federation: Federation<R>) -> Self {
        Self {
            federation,
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn trust_anchors(&self) -> &[EntityIdentifier] {
        &self.federation.trust_anchors
    }

    pub async fn resolve(
        &self,
        client_id: &str,
        now: Timestamp,
    ) -> Result<(RegisteredClient, ResolvedClient), FederatedClientFault> {
        if let Some(hit) = self.cached(client_id, now) {
            return Ok(hit);
        }

        let entity =
            EntityIdentifier::parse(client_id).map_err(|_| FederatedClientFault::NotAnEntity)?;

        let resolved = self
            .federation
            .resolve(&entity, ENTITY_TYPE_RELYING_PARTY, now)
            .await?;

        let carries_trust_mark = false;

        let registered = to_registered_client(client_id, &resolved.metadata)?;

        let described = from_federation(
            client_id,
            resolved.metadata.clone(),
            resolved.trust_anchor.as_str(),
            resolved.expires_at,
            carries_trust_mark,
        );

        let ceiling = now
            .as_unix_seconds()
            .saturating_add(MAX_CACHE_SECONDS)
            .min(resolved.expires_at.as_unix_seconds());

        if ceiling > now.as_unix_seconds()
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.insert(
                client_id.to_owned(),
                (registered.clone(), described.clone(), ceiling),
            );
        }

        Ok((registered, described))
    }

    fn cached(&self, key: &str, now: Timestamp) -> Option<(RegisteredClient, ResolvedClient)> {
        let mut cache = self.cache.lock().ok()?;
        let (registered, described, expires) = cache.get(key)?;

        if *expires <= now.as_unix_seconds() {
            cache.remove(key);
            return None;
        }

        Some((registered.clone(), described.clone()))
    }
}

pub fn to_registered_client(
    client_id: &str,
    metadata: &Value,
) -> Result<RegisteredClient, FederatedClientFault> {
    let id = ClientId::new(client_id).map_err(|_| FederatedClientFault::NotAnEntity)?;

    let raw_uris = metadata
        .get("redirect_uris")
        .and_then(Value::as_array)
        .ok_or(FederatedClientFault::NoRedirectUri)?;

    if raw_uris.is_empty() {
        return Err(FederatedClientFault::NoRedirectUri);
    }

    let mut redirect_uris = Vec::with_capacity(raw_uris.len());
    for raw in raw_uris {
        let text = raw
            .as_str()
            .ok_or(FederatedClientFault::UnusableRedirectUri)?;
        let uri = RedirectUri::register(text.to_owned())
            .map_err(|_| FederatedClientFault::UnusableRedirectUri)?;
        redirect_uris.push(uri);
    }

    let method = metadata
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("private_key_jwt");

    if method != "private_key_jwt" && method != "none" {
        return Err(FederatedClientFault::SymmetricAuthentication);
    }

    let keys = signing_keys(metadata);

    if method == "private_key_jwt" && keys.is_empty() {
        return Err(FederatedClientFault::NoSigningKey);
    }

    Ok(RegisteredClient {
        client_id: id,
        redirect_uris,
        auth_method: if method == "none" {
            ClientAuthMethod::None
        } else {
            ClientAuthMethod::PrivateKeyJwt
        },
        keys,
    })
}

fn signing_keys(metadata: &Value) -> Vec<ClientKey> {
    let Some(list) = metadata
        .get("jwks")
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    let mut out = Vec::new();

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

        let (Some(kid), Some(x), Some(y)) = (
            entry.get("kid").and_then(Value::as_str),
            entry.get("x").and_then(Value::as_str),
            entry.get("y").and_then(Value::as_str),
        ) else {
            continue;
        };

        let (Ok(x), Ok(y)) = (
            Base64UrlUnpadded::decode_vec(x),
            Base64UrlUnpadded::decode_vec(y),
        ) else {
            continue;
        };

        let (Ok(x), Ok(y)) = (<[u8; 32]>::try_from(x), <[u8; 32]>::try_from(y)) else {
            continue;
        };

        out.push(ClientKey {
            kid: kid.to_owned(),
            x,
            y,
        });
    }

    out
}

#[must_use]
pub const fn trust_level_of(resolved: &ResolvedClient) -> TrustLevel {
    resolved.trust_level
}
