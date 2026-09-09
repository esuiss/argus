use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argus_core::time::Timestamp;
use argus_crypto::AwsLcSha256;
use argus_proto::{OAuthError, OAuthErrorCode};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};

use crate::endpoints::authorize::{
    AuthorizeContext, AuthorizeQuery, AuthorizeResponse, UserAuthenticator,
    handle as authorize_handle,
};
use crate::endpoints::discovery;
use crate::endpoints::token::{Binding, TokenForm, handle};
use crate::endpoints::userinfo::{self, UserInfoRequest};
use crate::replay::{PrecheckedReplay, consume};
use crate::state::AppState;
use crate::store::{
    AuditSink, ClientStore, CodeIssuer, CodeStore, JtiPurpose, RefreshStore, ReplayStore,
};

fn now() -> Timestamp {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Timestamp::from_unix_seconds(secs)
}

fn oauth_response(err: &OAuthError) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = (status, Json(err)).into_response();

    if err.error == OAuthErrorCode::InvalidClient
        && let Ok(value) = "Basic realm=\"argus\"".parse()
    {
        response.headers_mut().insert("WWW-Authenticate", value);
    }

    if let Ok(value) = "no-store".parse() {
        response.headers_mut().insert("Cache-Control", value);
    }
    response
}

type SharedState<C, R, A, S, U, P> = Arc<AppState<C, R, A, S, U, P>>;

async fn metadata_handler<C, R, A, S, U, P>(
    State(state): State<SharedState<C, R, A, S, U, P>>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
{
    Json(discovery::metadata(&state.tenant)).into_response()
}

async fn jwks_handler<C, R, A, S, U, P>(
    State(state): State<SharedState<C, R, A, S, U, P>>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
{
    discovery::jwks(&state.tenant).map_or_else(
        |_| oauth_response(&OAuthError::new(OAuthErrorCode::ServerError)),
        |set| Json(set).into_response(),
    )
}

async fn dpop_binding<P>(
    replay_store: &P,
    tenant: argus_core::id::TenantId,
    headers: &HeaderMap,
    htu: &str,
    now: Timestamp,
) -> Result<Binding, OAuthError>
where
    P: ReplayStore + Sync,
{
    let Some(raw) = headers.get("DPoP") else {
        return Ok(None);
    };
    let Ok(proof_str) = raw.to_str() else {
        return Err(OAuthError::new(OAuthErrorCode::InvalidRequest));
    };

    let proof = argus_proto::dpop::parse_and_verify(proof_str)
        .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    let replay = consume(
        replay_store,
        tenant,
        JtiPurpose::DpopProof,
        &proof.jti,
        now,
        argus_core::dpop::DEFAULT_PROOF_WINDOW,
    )
    .await
    .map_err(|_| OAuthError::new(OAuthErrorCode::TemporarilyUnavailable))?;

    argus_core::dpop::validate(
        &proof,
        &argus_core::dpop::RequestBinding {
            method: "POST".to_owned(),
            uri: htu.to_owned(),
        },
        None,
        now,
        argus_core::dpop::DEFAULT_PROOF_WINDOW,
        &replay,
    )
    .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    Ok(Some(proof.jkt))
}

async fn token_handler<C, R, A, S, U, P>(
    State(state): State<SharedState<C, R, A, S, U, P>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
{
    let at = now();
    let binding = match dpop_binding(
        &state.replay,
        state.tenant_id(),
        &headers,
        &state.tenant.metadata.token_endpoint,
        at,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return oauth_response(&e),
    };

    match handle(&state, &form, at, &AwsLcSha256, binding).await {
        Ok(response) => {
            let mut r = Json(response).into_response();
            if let Ok(value) = "no-store".parse() {
                r.headers_mut().insert("Cache-Control", value);
            }
            r
        }
        Err(err) => oauth_response(&err),
    }
}

fn form_field(body: &str, name: &str) -> Option<String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| percent_decode(v))
}

fn percent_decode(value: &str) -> String {
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

async fn userinfo_handler<C, R, A, S, U, P>(
    State(state): State<SharedState<C, R, A, S, U, P>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
{
    let authorization = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let dpop_header = headers.get("DPoP").and_then(|v| v.to_str().ok());

    let form_access_token = form_field(&body, "access_token");
    let uri = state
        .tenant
        .metadata
        .userinfo_endpoint
        .clone()
        .unwrap_or_else(|| format!("{}/userinfo", state.tenant.metadata.issuer));

    let at = now();

    let proof = match dpop_header.map(argus_proto::dpop::parse_and_verify) {
        Some(Ok(proof)) => Some(proof),
        Some(Err(_)) => return userinfo_refusal(userinfo::UserInfoError::InvalidProof),
        None => None,
    };

    let replay = match &proof {
        Some(proof) => match consume(
            &state.replay,
            state.tenant_id(),
            JtiPurpose::DpopProof,
            &proof.jti,
            at,
            argus_core::dpop::DEFAULT_PROOF_WINDOW,
        )
        .await
        {
            Ok(guard) => guard,
            Err(_) => {
                return oauth_response(&OAuthError::new(OAuthErrorCode::TemporarilyUnavailable));
            }
        },
        None => PrecheckedReplay::fresh(),
    };

    let request = UserInfoRequest {
        authorization,
        form_access_token: form_access_token.as_deref(),
        dpop_proof: proof.as_ref(),

        method: "GET",
        uri: &uri,
    };

    match userinfo::handle(&state.tenant, &request, at, &replay) {
        Ok(info) => {
            let mut r = Json(info).into_response();

            if let Ok(value) = "no-store".parse() {
                r.headers_mut().insert("Cache-Control", value);
            }
            r
        }
        Err(err) => userinfo_refusal(err),
    }
}

fn userinfo_refusal(err: userinfo::UserInfoError) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::UNAUTHORIZED);
    let mut r = (status, Json(err.body())).into_response();
    if let Ok(value) = err.challenge().parse() {
        r.headers_mut().insert("WWW-Authenticate", value);
    }
    if let Ok(value) = "no-store".parse() {
        r.headers_mut().insert("Cache-Control", value);
    }
    r
}

async fn authorize_handler<C, R, A, S, U, P>(
    State(state): State<SharedState<C, R, A, S, U, P>>,
    Query(query): Query<AuthorizeQuery>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
{
    let code = uuid::Uuid::new_v4().simple().to_string();
    let ctx = AuthorizeContext {
        tenant: state.tenant_id(),
        issuer: &state.tenant.metadata.issuer,
        clients: &state.clients,
        codes: &state.codes,
        auth: &state.authenticator,
        hasher: &AwsLcSha256,
        now: now(),
        new_code: &code,
    };
    let outcome = authorize_handle(&ctx, &query).await;

    match outcome {
        Ok(AuthorizeResponse::Redirect(url)) => axum::response::Redirect::to(&url).into_response(),
        Ok(AuthorizeResponse::ShowError(message)) => {
            (StatusCode::BAD_REQUEST, message.to_owned()).into_response()
        }
        Ok(AuthorizeResponse::NeedsAuthentication) => (
            StatusCode::UNAUTHORIZED,
            "authentication required (phase 3)".to_owned(),
        )
            .into_response(),
        Err(_) => oauth_response(&OAuthError::new(OAuthErrorCode::TemporarilyUnavailable)),
    }
}

pub fn build<C, R, A, S, U, P>(state: SharedState<C, R, A, S, U, P>) -> Router
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata_handler::<C, R, A, S, U, P>),
        )
        .route(
            "/.well-known/openid-configuration",
            get(metadata_handler::<C, R, A, S, U, P>),
        )
        .route(
            "/.well-known/jwks.json",
            get(jwks_handler::<C, R, A, S, U, P>),
        )
        .route("/authorize", get(authorize_handler::<C, R, A, S, U, P>))
        .route("/token", post(token_handler::<C, R, A, S, U, P>))
        .route(
            "/userinfo",
            get(userinfo_handler::<C, R, A, S, U, P>).post(userinfo_handler::<C, R, A, S, U, P>),
        )
        .with_state(state)
}
