use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use argus_core::authorize::RegisteredClient;
use argus_core::cimd::ClientIdUrl;
use argus_core::client_auth::{ClientAuthMethod, ClientKey};
use argus_core::id::ClientId;
use argus_core::redirect_uri::RedirectUri;
use argus_core::time::Timestamp;
use argus_proto::cimd::ClientIdMetadataDocument;
use base64ct::{Base64UrlUnpadded, Encoding as _};

use crate::cimd_fetch::{FetchError, Resolver, fetch};

pub const DEFAULT_CACHE_SECONDS: u64 = 300;
pub const MAX_CACHE_SECONDS: u64 = 86_400;

pub struct CimdRuntime {
    tls: Arc<rustls::ClientConfig>,
    allow_loopback: bool,
    cache: Mutex<HashMap<String, (RegisteredClient, i64)>>,
}

impl core::fmt::Debug for CimdRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CimdRuntime")
    }
}

impl CimdRuntime {
    #[must_use]
    pub fn new(tls: Arc<rustls::ClientConfig>) -> Self {
        Self {
            tls,
            allow_loopback: false,
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn allowing_loopback(mut self) -> Self {
        self.allow_loopback = true;
        self
    }

    pub async fn resolve(
        &self,
        url: &ClientIdUrl,
        resolver: &impl Resolver,
        now: Timestamp,
    ) -> Result<RegisteredClient, FetchError> {
        if let Some(hit) = self.cached(url.as_str(), now) {
            return Ok(hit);
        }

        let fetched = fetch(url, resolver, &self.tls, self.allow_loopback).await?;
        let client = to_registered_client(url, &fetched.document)?;

        let lifetime = fetched
            .max_age
            .unwrap_or(DEFAULT_CACHE_SECONDS)
            .min(MAX_CACHE_SECONDS);

        if lifetime > 0
            && let Ok(mut cache) = self.cache.lock()
        {
            let expires = now
                .as_unix_seconds()
                .saturating_add(i64::try_from(lifetime).unwrap_or(i64::MAX));
            cache.insert(url.as_str().to_owned(), (client.clone(), expires));
        }

        Ok(client)
    }

    fn cached(&self, key: &str, now: Timestamp) -> Option<RegisteredClient> {
        let mut cache = self.cache.lock().ok()?;
        let (client, expires) = cache.get(key)?;
        if *expires <= now.as_unix_seconds() {
            cache.remove(key);
            return None;
        }
        Some(client.clone())
    }
}

fn to_registered_client(
    url: &ClientIdUrl,
    document: &ClientIdMetadataDocument,
) -> Result<RegisteredClient, FetchError> {
    let client_id =
        ClientId::new(url.as_str()).map_err(|_| argus_proto::cimd::DocumentError::Malformed)?;

    let mut redirect_uris = Vec::with_capacity(document.redirect_uris.len());
    for raw in &document.redirect_uris {
        let uri = RedirectUri::register(raw.clone())
            .map_err(|_| argus_proto::cimd::DocumentError::DisallowedUrlScheme)?;
        redirect_uris.push(uri);
    }

    if redirect_uris.is_empty() {
        return Err(argus_proto::cimd::DocumentError::NoRedirectUris.into());
    }

    let auth_method = match document.token_endpoint_auth_method.as_deref() {
        Some("private_key_jwt") => ClientAuthMethod::PrivateKeyJwt,
        _ => ClientAuthMethod::None,
    };

    Ok(RegisteredClient {
        client_id,
        redirect_uris,
        auth_method,
        keys: inline_keys(document.jwks.as_ref()),
    })
}

fn inline_keys(jwks: Option<&serde_json::Value>) -> Vec<ClientKey> {
    let Some(keys) = jwks
        .and_then(|j| j.get("keys"))
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for key in keys {
        if key.get("kty").and_then(serde_json::Value::as_str) != Some("EC")
            || key.get("crv").and_then(serde_json::Value::as_str) != Some("P-256")
        {
            continue;
        }
        let (Some(x), Some(y), Some(kid)) = (
            key.get("x").and_then(serde_json::Value::as_str),
            key.get("y").and_then(serde_json::Value::as_str),
            key.get("kid").and_then(serde_json::Value::as_str),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{inline_keys, to_registered_client};
    use argus_core::cimd::ClientIdUrl;
    use argus_core::client_auth::ClientAuthMethod;
    use argus_proto::cimd::parse_and_validate;

    const URL: &str = "https://example.com/client.json";

    fn build(extra: &str) -> Result<argus_core::authorize::RegisteredClient, super::FetchError> {
        let url = ClientIdUrl::parse(URL).expect("url");
        let body = format!(
            r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"]{extra}}}"#
        );
        let doc = parse_and_validate(&body, &url).expect("document");
        to_registered_client(&url, &doc)
    }

    #[test]
    fn the_client_id_becomes_the_url_itself() {
        let client = build("").expect("client");
        assert_eq!(client.client_id.as_str(), URL);
        assert_eq!(client.auth_method, ClientAuthMethod::None);
    }

    #[test]
    fn private_key_jwt_is_carried_over() {
        let client = build(r#","token_endpoint_auth_method":"private_key_jwt""#).expect("client");
        assert_eq!(client.auth_method, ClientAuthMethod::PrivateKeyJwt);
    }

    #[test]
    fn a_redirect_uri_the_core_rules_refuse_kills_the_document() {
        let url = ClientIdUrl::parse(URL).expect("url");
        let body = format!(
            r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["http://evil.example.com/cb"]}}"#
        );
        let doc = parse_and_validate(&body, &url).expect("document");
        assert!(to_registered_client(&url, &doc).is_err());
    }

    #[test]
    fn loopback_redirect_uris_are_still_allowed() {
        let url = ClientIdUrl::parse(URL).expect("url");
        let body = format!(
            r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["http://127.0.0.1:3000/callback"]}}"#
        );
        let doc = parse_and_validate(&body, &url).expect("document");
        let client = to_registered_client(&url, &doc).expect("client");
        assert_eq!(client.redirect_uris.len(), 1);
    }

    #[test]
    fn only_p256_keys_with_a_kid_are_taken() {
        let jwks = serde_json::json!({"keys":[
            {"kty":"EC","crv":"P-256","kid":"good","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            {"kty":"RSA","kid":"wrong-kty","n":"x","e":"AQAB"},
            {"kty":"EC","crv":"P-384","kid":"wrong-crv","x":"a","y":"b"},
            {"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
        ]});
        let keys = inline_keys(Some(&jwks));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.first().expect("key").kid, "good");
    }

    #[test]
    fn a_document_without_a_jwks_has_no_keys() {
        assert!(inline_keys(None).is_empty());
        assert!(inline_keys(Some(&serde_json::json!({}))).is_empty());
    }
}
