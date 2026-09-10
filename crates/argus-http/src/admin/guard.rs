use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argus_core::admin::manifest::{RouteRequirement, Surface};
use argus_core::authz::grant::GrantPolicy;
use argus_core::authz::model::{EntityRef, Model, SubjectRef};
use argus_core::authz::{CheckRequest, check};
use argus_core::id::TenantId;
use argus_crypto::{SigningKey, VerifyingKey};
use argus_proto::jwt::AccessTokenClaims;
use argus_store::PostgresStore;
use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

pub struct AdminState {
    pub tenant_id: TenantId,
    pub issuer: String,
    pub store: PostgresStore,
    pub published_keys: Vec<Arc<SigningKey>>,
    pub model: Model,
    pub policy: GrantPolicy,
}

pub type Shared = Arc<AdminState>;

pub const PLATFORM_OBJECT: &str = "control-plane";

pub type Refusal = Box<Response>;

#[derive(Debug, Clone)]
pub struct Caller {
    pub subject: String,
    pub surface: Surface,
}

pub(super) fn problem(status: u16, error: &str, description: &str) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    (
        code,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

pub(super) fn hidden() -> Response {
    problem(404, "not_found", "no such resource")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn now_signed() -> i64 {
    i64::try_from(now()).unwrap_or(i64::MAX)
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

fn audience_matches(claims: &AccessTokenClaims, issuer: &str, surface: Surface) -> bool {
    let expected = format!("{issuer}{}", surface.audience_suffix());
    claims.aud.contains(&expected)
}

fn verify(state: &AdminState, headers: &HeaderMap) -> Result<AccessTokenClaims, Refusal> {
    let Some(token) = bearer(headers) else {
        return Err(Box::new(problem(
            401,
            "unauthorized",
            "an access token is required",
        )));
    };

    let keys: Vec<VerifyingKey> = state
        .published_keys
        .iter()
        .map(|key| key.verifying_key())
        .collect();

    let claims = keys
        .iter()
        .find_map(|key| argus_proto::jwt::verify(token, key).ok())
        .ok_or_else(|| {
            Box::new(problem(
                401,
                "unauthorized",
                "the access token is not valid",
            ))
        })?;

    if claims.iss != state.issuer {
        return Err(Box::new(problem(
            401,
            "unauthorized",
            "the access token was issued elsewhere",
        )));
    }

    if claims.exp <= now_signed() {
        return Err(Box::new(problem(
            401,
            "unauthorized",
            "the access token has expired",
        )));
    }

    Ok(claims)
}

pub(super) async fn admit(
    state: &AdminState,
    headers: &HeaderMap,
    requirement: &RouteRequirement,
) -> Result<Caller, Refusal> {
    let claims = verify(state, headers)?;

    if !audience_matches(&claims, &state.issuer, requirement.surface) {
        return Err(Box::new(hidden()));
    }

    let object_id = match requirement.surface {
        Surface::Tenant => state.tenant_id.as_uuid().to_string(),
        Surface::Platform => PLATFORM_OBJECT.to_owned(),
    };

    let object = EntityRef::new(requirement.object_kind, &object_id).map_err(|_| {
        Box::new(problem(
            500,
            "server_error",
            "the object is not addressable",
        ))
    })?;

    let subject = SubjectRef::direct(EntityRef::new("user", &claims.sub).map_err(|_| {
        Box::new(problem(
            401,
            "unauthorized",
            "the subject is not addressable",
        ))
    })?);

    let index = state
        .store
        .authz_index(state.tenant_id)
        .await
        .map_err(|_| {
            Box::new(problem(
                503,
                "unavailable",
                "the relation graph is unreadable",
            ))
        })?;

    let decision = check(
        &state.model,
        &index,
        &CheckRequest {
            object,
            relation: requirement.relation.to_owned(),
            subject: subject.clone(),
        },
    )
    .map_err(|e| Box::new(problem(400, "invalid_request", &e.to_string())))?;

    if !decision.allowed {
        return Err(Box::new(hidden()));
    }

    Ok(Caller {
        subject: claims.sub,
        surface: requirement.surface,
    })
}

pub(super) enum Idempotency {
    Run(Option<String>),
    Replay(Response),
}

pub(super) async fn open_idempotency(
    state: &AdminState,
    headers: &HeaderMap,
    surface: Surface,
    body: &Value,
) -> Result<Idempotency, Refusal> {
    let Some(raw) = headers.get("idempotency-key") else {
        return Ok(Idempotency::Run(None));
    };

    let raw = raw.to_str().unwrap_or_default();
    let key = argus_core::admin::IdempotencyKey::new(raw)
        .map_err(|e| Box::new(problem(400, "invalid_request", &e.to_string())))?;

    let fingerprint = fingerprint_of(body);
    let name = match surface {
        Surface::Platform => "platform",
        Surface::Tenant => "tenant",
    };

    let existing = state
        .store
        .idempotency_record(state.tenant_id, name, key.as_str())
        .await
        .map_err(|_| Box::new(problem(503, "unavailable", "the key store is unreadable")))?;

    let record = existing.as_ref().map(|(record, _)| record);
    match argus_core::admin::idempotency::decide(record, &fingerprint, now()) {
        argus_core::admin::IdempotencyOutcome::Execute => {}

        argus_core::admin::IdempotencyOutcome::Replay => {
            let stored = existing.and_then(|(_, response)| response);
            let response = stored.map_or_else(
                || problem(200, "ok", "this request was already applied"),
                |stored| {
                    let code = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
                    (code, Json(stored.body)).into_response()
                },
            );
            return Ok(Idempotency::Replay(response));
        }

        argus_core::admin::IdempotencyOutcome::PayloadMismatch => {
            return Err(Box::new(problem(
                422,
                "idempotency_key_reused",
                "this key was used for a different payload",
            )));
        }

        argus_core::admin::IdempotencyOutcome::InFlight => {
            return Err(Box::new(problem(
                409,
                "request_in_flight",
                "a request with this key is still running",
            )));
        }
    }

    let claimed = state
        .store
        .idempotency_begin(state.tenant_id, name, key.as_str(), &fingerprint)
        .await
        .map_err(|_| Box::new(problem(503, "unavailable", "the key store is unwritable")))?;

    if !claimed {
        return Err(Box::new(problem(
            409,
            "request_in_flight",
            "a request with this key is still running",
        )));
    }

    Ok(Idempotency::Run(Some(key.as_str().to_owned())))
}

pub(super) async fn close_idempotency(
    state: &AdminState,
    key: Option<&str>,
    surface: Surface,
    status: u16,
    body: &Value,
) {
    let Some(key) = key else {
        return;
    };
    let name = match surface {
        Surface::Platform => "platform",
        Surface::Tenant => "tenant",
    };
    let succeeded = (200..300).contains(&status);
    let _ = state
        .store
        .idempotency_finish(state.tenant_id, name, key, succeeded, status, body)
        .await;
}

fn fingerprint_of(body: &Value) -> [u8; 32] {
    use argus_core::pkce::Sha256 as _;
    let canonical = argus_proto::jcs::canonicalize(body).unwrap_or_default();
    argus_crypto::AwsLcSha256.sha256(canonical.as_bytes())
}
