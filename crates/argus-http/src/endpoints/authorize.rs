use argus_core::authorize::{AuthorizeOutcome, AuthorizeRequest, RegisteredClient, validate};
use argus_core::authz_code::{AuthorizationCode, DEFAULT_CODE_LIFETIME};
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::pkce::Sha256;
use argus_core::time::Timestamp;
use serde::Deserialize;

use crate::store::{ClientStore, CodeIssuer, StoreError};

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,

    pub client_id: String,

    pub redirect_uri: Option<String>,

    pub state: Option<String>,

    pub code_challenge: Option<String>,

    pub code_challenge_method: Option<String>,

    pub scope: Option<String>,

    pub nonce: Option<String>,

    #[serde(skip)]
    pub resource: Vec<String>,
}

pub trait UserAuthenticator {
    fn current_user(&self, tenant: TenantId) -> Option<UserId>;
}

#[derive(Debug, Clone, Copy)]
pub struct DevAuthenticator {
    pub user: UserId,
}

impl UserAuthenticator for DevAuthenticator {
    fn current_user(&self, _tenant: TenantId) -> Option<UserId> {
        Some(self.user)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeResponse {
    Redirect(String),

    ShowError(&'static str),

    NeedsAuthentication,
}

pub struct AuthorizeContext<'a, S, I, U, H> {
    pub tenant: TenantId,

    pub issuer: &'a str,

    pub clients: &'a S,

    pub codes: &'a I,

    pub auth: &'a U,

    pub hasher: &'a H,

    pub now: Timestamp,

    pub new_code: &'a str,

    pub registered_resources: &'a [argus_core::resource::ResourceUri],
}

impl<S, I, U, H> Clone for AuthorizeContext<'_, S, I, U, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S, I, U, H> Copy for AuthorizeContext<'_, S, I, U, H> {}

pub async fn handle<S, I, U, H>(
    ctx: &AuthorizeContext<'_, S, I, U, H>,
    query: &AuthorizeQuery,
) -> Result<AuthorizeResponse, StoreError>
where
    S: ClientStore + Sync,
    I: CodeIssuer + Sync,
    U: UserAuthenticator + Sync,
    H: Sha256,
{
    let AuthorizeContext {
        tenant,
        issuer,
        clients,
        codes,
        auth,
        hasher,
        now,
        new_code,
        registered_resources,
    } = *ctx;

    let client_id = ClientId::new(query.client_id.clone()).ok();
    let registered: Option<RegisteredClient> = match client_id.as_ref() {
        Some(id) => clients.find(tenant, id).await?,
        None => None,
    };

    let request = AuthorizeRequest {
        response_type: query.response_type.clone(),
        client_id: query.client_id.clone(),
        redirect_uri: query.redirect_uri.clone(),
        state: query.state.clone(),
        code_challenge: query.code_challenge.clone(),
        code_challenge_method: query.code_challenge_method.clone(),
        scope: query.scope.clone(),
        nonce: query.nonce.clone(),
        resources: query.resource.clone(),
    };

    match validate(&request, registered.as_ref(), registered_resources) {
        AuthorizeOutcome::Fatal(_) => Ok(AuthorizeResponse::ShowError(
            "the redirect_uri is not registered for this client",
        )),

        AuthorizeOutcome::RedirectError {
            redirect_uri,
            error,
            state,
        } => {
            let mut url = format!("{}?error={}", redirect_uri.as_str(), error.as_str());
            append_state(&mut url, state.as_deref());
            append_iss(&mut url, issuer);
            Ok(AuthorizeResponse::Redirect(url))
        }

        AuthorizeOutcome::Proceed {
            redirect_uri,
            challenge,
            state,
            scope,
            nonce,
            resources,
        } => {
            let Some(user) = auth.current_user(tenant) else {
                return Ok(AuthorizeResponse::NeedsAuthentication);
            };

            let Some(client) = client_id else {
                return Ok(AuthorizeResponse::ShowError("invalid client_id"));
            };

            let Ok(record) = AuthorizationCode::new(
                tenant,
                client,
                user,
                redirect_uri.clone(),
                challenge,
                now,
                DEFAULT_CODE_LIFETIME,
            ) else {
                return Ok(AuthorizeResponse::ShowError(
                    "authorization code lifetime is misconfigured",
                ));
            };

            let hash = hasher.sha256(new_code.as_bytes());

            codes
                .issue(
                    tenant,
                    &hash,
                    &record
                        .with_oidc(nonce, scope)
                        .with_resources(resources)
                        .to_stored(),
                )
                .await?;

            let mut url = format!("{}?code={new_code}", redirect_uri.as_str());
            append_state(&mut url, state.as_deref());

            append_iss(&mut url, issuer);
            Ok(AuthorizeResponse::Redirect(url))
        }
    }
}

fn append_state(url: &mut String, state: Option<&str>) {
    if let Some(s) = state {
        url.push_str("&state=");
        url.push_str(&urlencode(s));
    }
}

fn append_iss(url: &mut String, issuer: &str) {
    url.push_str("&iss=");
    url.push_str(&urlencode(issuer));
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(hex_digit(b >> 4)));
            out.push(char::from(hex_digit(b & 0x0F)));
        }
    }
    out
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + (nibble - 10),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{AuthorizeResponse, urlencode};

    #[test]
    fn state_separators_are_encoded() {
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencode("x#frag"), "x%23frag");
        assert_eq!(urlencode("safe-._~"), "safe-._~");
    }

    #[test]
    fn show_error_is_not_a_redirect() {
        let r = AuthorizeResponse::ShowError("nope");
        assert!(!matches!(r, AuthorizeResponse::Redirect(_)));
    }
}

#[must_use]
pub fn repeated_query_values(raw: Option<&str>, key: &str) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| percent_decode_value(v))
        .collect()
}

fn percent_decode_value(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'+') => {
                out.push(b' ');
                i += 1;
            }
            Some(b'%') if i + 2 < bytes.len() => {
                let hex = value.get(i + 1..i + 3).unwrap_or_default();
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            Some(b) => {
                out.push(*b);
                i += 1;
            }
            None => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod repeated_tests {
    use super::repeated_query_values;

    #[test]
    fn several_occurrences_are_all_collected() {
        let raw = "client_id=a&resource=https%3A%2F%2Fa.test&resource=https%3A%2F%2Fb.test";
        assert_eq!(
            repeated_query_values(Some(raw), "resource"),
            ["https://a.test", "https://b.test"]
        );
    }

    #[test]
    fn a_single_occurrence_still_yields_one_value() {
        assert_eq!(
            repeated_query_values(Some("resource=https%3A%2F%2Fa.test"), "resource"),
            ["https://a.test"]
        );
    }

    #[test]
    fn an_absent_key_yields_nothing() {
        assert!(repeated_query_values(Some("client_id=a"), "resource").is_empty());
        assert!(repeated_query_values(None, "resource").is_empty());
    }

    #[test]
    fn a_key_that_merely_starts_the_same_is_not_matched() {
        assert!(repeated_query_values(Some("resources=a&resource_x=b"), "resource").is_empty());
    }
}
