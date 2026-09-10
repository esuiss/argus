use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argus_core::client_resolution::TrustLevel;
use argus_core::delegation::parse_chain;
use argus_core::id::{TenantId, UserId};
use argus_core::time::{Duration, Timestamp};
use argus_core::vault::{
    Lease, READ_SCOPE, Requester, SecretRecord, VaultFault, associated_data, lease_lifetime,
    may_lease, may_redeem, may_release_raw,
};
use argus_crypto::sealing::SealingKey;
use argus_crypto::{SigningKey, VerifyingKey};
use argus_proto::agent_card::{CardFault, PublishedKey, sign as sign_card};
use argus_proto::federation::ENTITY_STATEMENT_TYPE;
use argus_proto::jwt::AccessTokenClaims;
use argus_store::PostgresStore;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::federation::publish::{DEFAULT_CONFIGURATION_LIFETIME, FederationIdentity};

pub const AGENT_CARD_SCOPE: &str = "urn:argus:agent-card:sign";

pub struct DifferentiationState {
    pub tenant_id: TenantId,
    pub issuer: String,
    pub published_keys: Vec<Arc<SigningKey>>,
    pub federation: Option<FederationIdentity>,
    pub provider_metadata: Value,
    pub agent_card_key: Option<Arc<SigningKey>>,
    pub vault: Option<VaultRuntime>,
}

pub struct VaultRuntime {
    pub store: PostgresStore,
    pub sealing: SealingKey,
}

impl core::fmt::Debug for VaultRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VaultRuntime")
    }
}

type Shared = Arc<DifferentiationState>;
type Refusal = Box<Response>;

fn now() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Timestamp::from_unix_seconds(seconds)
}

fn problem(status: u16, detail: &str) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    (code, Json(json!({ "error": detail }))).into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

fn authorize(
    state: &DifferentiationState,
    headers: &HeaderMap,
) -> Result<AccessTokenClaims, Refusal> {
    let Some(token) = bearer(headers) else {
        return Err(Box::new(problem(401, "an access token is required")));
    };

    let keys: Vec<VerifyingKey> = state
        .published_keys
        .iter()
        .map(|key| key.verifying_key())
        .collect();

    let claims = keys
        .iter()
        .find_map(|key| argus_proto::jwt::verify(token, key).ok())
        .ok_or_else(|| Box::new(problem(401, "the access token is not valid")))?;

    if claims.iss != state.issuer {
        return Err(Box::new(problem(
            401,
            "the access token was issued elsewhere",
        )));
    }

    if claims.exp <= now().as_unix_seconds() {
        return Err(Box::new(problem(401, "the access token has expired")));
    }

    Ok(claims)
}

fn holds(claims: &AccessTokenClaims, scope: &str) -> bool {
    claims
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .any(|granted| granted == scope)
}

async fn entity_configuration(State(state): State<Shared>) -> Response {
    let Some(identity) = state.federation.as_ref() else {
        return problem(404, "this server is not configured as a federation entity");
    };

    match identity.entity_configuration(
        &state.provider_metadata,
        now(),
        DEFAULT_CONFIGURATION_LIFETIME,
    ) {
        Ok(token) => (
            [(
                axum::http::header::CONTENT_TYPE,
                format!("application/{ENTITY_STATEMENT_TYPE}"),
            )],
            token,
        )
            .into_response(),
        Err(e) => problem(500, &e.to_string()),
    }
}

async fn federation_keys(State(state): State<Shared>) -> Response {
    let Some(identity) = state.federation.as_ref() else {
        return problem(404, "this server is not configured as a federation entity");
    };

    Json(identity.jwks()).into_response()
}

async fn sign_agent_card(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(card): Json<Value>,
) -> Response {
    let claims = match authorize(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return *response,
    };

    if !holds(&claims, AGENT_CARD_SCOPE) {
        return problem(403, "the access token does not carry the agent card scope");
    }

    let Some(key) = state.agent_card_key.as_ref() else {
        return problem(404, "this server does not sign agent cards");
    };

    match sign_card(&card, key, &state.issuer) {
        Ok(signed) => Json(signed).into_response(),
        Err(CardFault::Signing) => problem(500, "the card could not be signed"),
        Err(fault) => problem(400, &fault.to_string()),
    }
}

async fn agent_card_keys(State(state): State<Shared>) -> Response {
    let Some(key) = state.agent_card_key.as_ref() else {
        return problem(404, "this server does not sign agent cards");
    };

    Json(argus_proto::federation::jwks_of(&[key.as_ref()])).into_response()
}

#[must_use]
pub fn agent_card_verification_keys(state: &DifferentiationState) -> Vec<PublishedKey> {
    state
        .agent_card_key
        .iter()
        .map(|key| PublishedKey {
            kid: key.kid().to_owned(),
            key: key.verifying_key(),
        })
        .collect()
}

#[derive(Debug, serde::Deserialize)]
pub struct LeaseRequest {
    pub secret_id: String,
    pub audience: String,
    #[serde(default)]
    pub lifetime_seconds: Option<i64>,
    #[serde(default)]
    pub delegation_chain: Option<Value>,
}

fn requester_of(claims: &AccessTokenClaims, request: &LeaseRequest) -> Result<Requester, Refusal> {
    let delegation = match request.delegation_chain.as_ref() {
        None => Vec::new(),
        Some(raw) => parse_chain(raw).map_err(|e| Box::new(problem(400, &e.to_string())))?,
    };

    let subject = uuid::Uuid::parse_str(&claims.sub)
        .ok()
        .map(UserId::from_uuid);

    Ok(Requester {
        subject,
        audience: request.audience.clone(),
        granted_scope: claims
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        trust_level: TrustLevel::Registered,
        delegation,
    })
}

fn vault_status(fault: &VaultFault) -> u16 {
    match fault {
        VaultFault::NoSuchSecret | VaultFault::NoSuchLease => 404,
        VaultFault::Revoked | VaultFault::Expired | VaultFault::LeaseExpired => 410,
        VaultFault::MissingVaultScope
        | VaultFault::MissingSecretScope { .. }
        | VaultFault::TrustLevelTooLow
        | VaultFault::DelegationNarrowed
        | VaultFault::NotTheOwner
        | VaultFault::NoSubject
        | VaultFault::LeaseNotYours => 403,
        _ => 400,
    }
}

async fn take_lease(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<LeaseRequest>,
) -> Response {
    let claims = match authorize(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return *response,
    };

    if !holds(&claims, READ_SCOPE) {
        return problem(403, "the access token does not carry the vault scope");
    }

    let Some(vault) = state.vault.as_ref() else {
        return problem(404, "this server runs no vault");
    };

    let requester = match requester_of(&claims, &request) {
        Ok(requester) => requester,
        Err(response) => return *response,
    };

    let Ok(stored) = vault
        .store
        .load_secret(state.tenant_id, &request.secret_id)
        .await
    else {
        return problem(404, "the secret does not exist");
    };

    let at = now();

    if let Err(fault) = may_lease(&stored.record, &requester, at) {
        return problem(vault_status(&fault), &fault.to_string());
    }

    let lifetime = lease_lifetime(
        &stored.record,
        request.lifetime_seconds.map(Duration::from_seconds),
        at,
    );

    let holder = holder_of(&claims);

    match vault
        .store
        .issue_lease(
            state.tenant_id,
            &request.secret_id,
            &holder,
            at.saturating_add(lifetime),
        )
        .await
    {
        Ok(lease) => Json(json!({
            "lease_id": lease.lease_id,
            "secret_id": lease.secret_id,
            "expires_in": lifetime.as_seconds(),
            "single_use": true
        }))
        .into_response(),
        Err(_) => problem(500, "the lease could not be issued"),
    }
}

fn holder_of(claims: &AccessTokenClaims) -> String {
    format!("{}#{}", claims.sub, claims.jti)
}

#[derive(Debug, serde::Deserialize)]
pub struct RedeemRequest {
    pub lease_id: String,
}

async fn redeem_lease(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<RedeemRequest>,
) -> Response {
    let claims = match authorize(&state, &headers) {
        Ok(claims) => claims,
        Err(response) => return *response,
    };

    if !holds(&claims, READ_SCOPE) {
        return problem(403, "the access token does not carry the vault scope");
    }

    let Some(vault) = state.vault.as_ref() else {
        return problem(404, "this server runs no vault");
    };

    let at = now();
    let holder = holder_of(&claims);

    let lease: Lease = match vault
        .store
        .spend_lease(state.tenant_id, &request.lease_id)
        .await
    {
        Ok(lease) => lease,
        Err(_) => return problem(404, "the lease does not exist or was already used"),
    };

    if let Err(fault) = may_redeem(&lease, &holder, at) {
        return problem(vault_status(&fault), &fault.to_string());
    }

    let Ok(stored) = vault
        .store
        .load_secret(state.tenant_id, &lease.secret_id)
        .await
    else {
        return problem(404, "the secret does not exist");
    };

    if let Err(fault) = may_release_raw(&stored.record) {
        return problem(vault_status(&fault), &fault.to_string());
    }

    let context = associated_data(state.tenant_id, &stored.record.secret_id);

    match vault.sealing.open(&stored.sealed, &context) {
        Ok(plaintext) => match String::from_utf8(plaintext) {
            Ok(secret) => release(&stored.record, &secret),
            Err(_) => problem(500, "the secret is not text"),
        },
        Err(_) => problem(500, "the secret could not be opened"),
    }
}

fn release(record: &SecretRecord, secret: &str) -> Response {
    let mut response = Json(json!({
        "secret_id": record.secret_id,
        "kind": record.kind.as_str(),
        "audience": record.audience,
        "secret": secret
    }))
    .into_response();

    if let Ok(value) = "no-store".parse() {
        response
            .headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, value);
    }

    response
}

pub fn build(state: Shared) -> Router {
    Router::new()
        .route("/.well-known/openid-federation", get(entity_configuration))
        .route("/federation/jwks", get(federation_keys))
        .route("/agent-cards/sign", post(sign_agent_card))
        .route("/agent-cards/jwks", get(agent_card_keys))
        .route("/vault/lease", post(take_lease))
        .route("/vault/redeem", post(redeem_lease))
        .with_state(state)
}

#[must_use]
pub fn metadata_value(metadata: &argus_proto::AuthorizationServerMetadata) -> Value {
    serde_json::to_value(metadata).unwrap_or(Value::Null)
}

pub fn decode_base64(raw: &str) -> Result<Vec<u8>, base64ct::Error> {
    use base64ct::{Base64, Encoding as _};
    Base64::decode_vec(raw)
}
