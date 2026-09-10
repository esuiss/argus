use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argus_core::client_auth::{
    ClientAuthMethod, MAX_ASSERTION_LIFETIME, PresentedCredential, authenticate, validate_assertion,
};
use argus_core::id::ClientId;
use argus_core::par::{
    IDENTIFIER_BYTES, ParFault, Profile, PushedRequest, check_authorize_entry, check_push,
    check_redemption, identifier_of, lifetime, request_uri_for,
};
use argus_core::time::{Duration, Timestamp};
use argus_store::PostgresStore;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::json;

pub struct ParState {
    pub store: PostgresStore,
    // §18: kiracı istekten çözülür, duruma sabitlenmez.
    pub tenants: Arc<crate::tenancy::TenantRegistry>,
    pub profile: Profile,
    pub issuer: String,
    pub endpoint: String,
}

type Shared = Arc<ParState>;
type Refusal = Box<Response>;

fn now() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Timestamp::from_unix_seconds(seconds)
}

fn error(status: u16, code: &str, detail: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = (
        status,
        Json(json!({ "error": code, "error_description": detail })),
    )
        .into_response();

    if let Ok(value) = "no-store".parse() {
        response
            .headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, value);
    }

    response
}

#[must_use]
pub fn new_identifier() -> String {
    let raw = uuid::Uuid::new_v4();
    let mut material = [0_u8; IDENTIFIER_BYTES];
    let bytes = raw.as_bytes();

    for (index, slot) in material.iter_mut().enumerate() {
        *slot =
            bytes.get(index % bytes.len()).copied().unwrap_or(0) ^ u8::try_from(index).unwrap_or(0);
    }

    Base64UrlUnpadded::encode_string(&material)
}

#[must_use]
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (decode(key), decode(value)))
        .collect()
}

fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes.get(index) {
            Some(b'+') => {
                out.push(b' ');
                index = index.saturating_add(1);
            }
            Some(b'%') if index + 2 < bytes.len() => {
                let hex = value.get(index + 1..index + 3).unwrap_or_default();
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index = index.saturating_add(3);
                } else {
                    out.push(b'%');
                    index = index.saturating_add(1);
                }
            }
            Some(byte) => {
                out.push(*byte);
                index = index.saturating_add(1);
            }
            None => break,
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

pub async fn push(
    state: &ParState,
    tenant: &crate::tenancy::Tenant,
    parameters: &[(String, String)],
    authenticated: &ClientId,
    requested_lifetime: Option<Duration>,
) -> Result<(String, Duration), Refusal> {
    if let Err(fault) = check_push(parameters, authenticated) {
        return Err(Box::new(error(400, "invalid_request", &fault.to_string())));
    }

    let window = lifetime(requested_lifetime);
    let identifier = new_identifier();
    let at = now();

    state
        .store
        .push_request(
            tenant.id(),
            &identifier,
            authenticated,
            parameters,
            at.saturating_add(window),
        )
        .await
        .map_err(|_| {
            error(
                503,
                "temporarily_unavailable",
                "the request could not be stored",
            )
        })?;

    Ok((request_uri_for(&identifier), window))
}

pub async fn redeem(
    state: &ParState,
    tenant: &crate::tenancy::Tenant,
    request_uri: &str,
    presenting: &ClientId,
) -> Result<PushedRequest, ParFault> {
    let identifier = identifier_of(request_uri).ok_or(ParFault::UnknownRequestUri)?;

    let request = state
        .store
        .consume_request(tenant.id(), identifier)
        .await
        .map_err(|_| ParFault::UnknownRequestUri)?;

    check_redemption(&request, presenting, now())?;

    Ok(request)
}

pub fn entry_check(state: &ParState, request_uri: Option<&str>) -> Result<(), ParFault> {
    check_authorize_entry(state.profile, request_uri)
}

#[allow(
    clippy::too_many_lines,
    reason = "client authentication reads as one ordered list of the checks it performs"
)]
pub async fn authenticate_pusher(
    state: &ParState,
    tenant: &crate::tenancy::Tenant,
    parameters: &[(String, String)],
) -> Result<ClientId, Refusal> {
    use crate::store::{ClientStore as _, JtiPurpose, ReplayStore as _};

    let value = |name: &str| {
        parameters
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };

    let Some(raw_client) = value("client_id") else {
        return Err(Box::new(error(
            400,
            "invalid_request",
            "the request carries no client_id",
        )));
    };

    let Ok(client) = ClientId::new(raw_client) else {
        return Err(Box::new(error(
            400,
            "invalid_request",
            "the client_id is not usable",
        )));
    };

    let registered = state
        .store
        .find(tenant.id(), &client)
        .await
        .map_err(|_| {
            error(
                503,
                "temporarily_unavailable",
                "the client could not be read",
            )
        })?
        .ok_or_else(|| Box::new(error(401, "invalid_client", "the client is not registered")))?;

    if state.profile.forbid_public_clients && registered.auth_method == ClientAuthMethod::None {
        return Err(Box::new(error(
            401,
            "invalid_client",
            "this profile accepts confidential clients only",
        )));
    }

    let presented = match value("client_assertion") {
        None => PresentedCredential::None,
        Some(raw) => {
            let claims =
                argus_proto::client_assertion::verify(&raw, &registered.keys).map_err(|_| {
                    Box::new(error(
                        401,
                        "invalid_client",
                        "the client assertion is not valid",
                    ))
                })?;

            let at = now();

            let outcome = state
                .store
                .consume_jti(
                    tenant.id(),
                    JtiPurpose::ClientAssertion,
                    &claims.jti,
                    at.saturating_add(MAX_ASSERTION_LIFETIME),
                )
                .await
                .map_err(|_| {
                    error(
                        503,
                        "temporarily_unavailable",
                        "the assertion could not be checked",
                    )
                })?;

            if outcome != crate::store::JtiOutcome::Fresh {
                return Err(Box::new(error(
                    401,
                    "invalid_client",
                    "the client assertion was replayed",
                )));
            }

            validate_assertion(
                &claims,
                &client,
                &[state.issuer.as_str(), state.endpoint.as_str()],
                at,
                &AlwaysFresh,
            )
            .map_err(|_| {
                error(
                    401,
                    "invalid_client",
                    "the client assertion is not acceptable",
                )
            })?;

            PresentedCredential::VerifiedAssertion {
                client_id: client.clone(),
            }
        }
    };

    authenticate(
        &client,
        registered.auth_method,
        &presented,
        None,
        |secret| {
            use argus_core::pkce::Sha256 as _;
            argus_crypto::AwsLcSha256.sha256(secret.as_bytes())
        },
    )
    .map_err(|_| {
        Box::new(error(
            401,
            "invalid_client",
            "the client did not authenticate",
        ))
    })?;

    Ok(client)
}

struct AlwaysFresh;

impl argus_core::dpop::ReplayGuard for AlwaysFresh {
    fn seen(&self, _jti: &str) -> bool {
        false
    }
}

async fn par_handler(State(state): State<Shared>, headers: HeaderMap, body: String) -> Response {
    let tenant = match crate::tenancy::resolve(&state.tenants, &headers) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };

    let parameters = parse_form(&body);

    let client = match authenticate_pusher(&state, &tenant, &parameters).await {
        Ok(client) => client,
        Err(response) => return *response,
    };

    match push(&state, &tenant, &parameters, &client, None).await {
        Ok((request_uri, window)) => {
            let mut response = (
                StatusCode::CREATED,
                Json(json!({
                    "request_uri": request_uri,
                    "expires_in": window.as_seconds()
                })),
            )
                .into_response();

            if let Ok(value) = "no-store".parse() {
                response
                    .headers_mut()
                    .insert(axum::http::header::CACHE_CONTROL, value);
            }

            response
        }
        Err(response) => *response,
    }
}

pub fn build(state: Shared) -> Router {
    Router::new()
        .route("/par", post(par_handler))
        .with_state(state)
}

#[must_use]
pub fn query_from(
    pushed: &PushedRequest,
    fallback: &crate::endpoints::authorize::AuthorizeQuery,
) -> crate::endpoints::authorize::AuthorizeQuery {
    let one = |name: &str| pushed.parameter(name).map(str::to_owned);

    crate::endpoints::authorize::AuthorizeQuery {
        response_type: one("response_type").unwrap_or_else(|| fallback.response_type.clone()),
        client_id: pushed.client.as_str().to_owned(),
        redirect_uri: one("redirect_uri"),
        state: one("state"),
        code_challenge: one("code_challenge"),
        code_challenge_method: one("code_challenge_method"),
        scope: one("scope"),
        nonce: one("nonce"),
        resource: pushed
            .all("resource")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        consented: fallback.consented,
    }
}
