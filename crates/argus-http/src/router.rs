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
    AuthorizeContext, AuthorizeQuery, AuthorizeResponse, handle as authorize_handle,
};
use crate::endpoints::discovery;
use crate::endpoints::token::{Binding, TokenForm, handle};
use crate::endpoints::userinfo::{self, UserInfoRequest};
use crate::replay::{PrecheckedReplay, consume};
use crate::state::AppState;
use crate::store::{
    AuditSink, AuthnStore, BackchannelStore, ClientStore, CodeIssuer, CodeStore, ConnectionStore,
    IssuerStore, JtiPurpose, RefreshStore, ReplayStore, ResourceStore, SessionStore,
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

type SharedState<C, R, A, S, U, P, X> = Arc<AppState<C, R, A, S, U, P, X>>;

async fn metadata_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
{
    Json(discovery::metadata(&state.tenant)).into_response()
}

async fn jwks_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
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

async fn token_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
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

async fn backchannel_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
    Form(form): Form<crate::endpoints::backchannel::BackchannelForm>,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
{
    use crate::endpoints::backchannel::{
        BackchannelContext, DevBackchannelResolver, request as backchannel_request,
    };

    let at = now();

    let Some(raw_client) = form.client_id.clone() else {
        return oauth_response(&OAuthError::new(OAuthErrorCode::InvalidClient));
    };

    let resolved = match resolve_client(&state, &raw_client, at).await {
        Ok(Some(client)) => client,
        Ok(None) => return oauth_response(&OAuthError::new(OAuthErrorCode::InvalidClient)),
        Err(response) => return *response,
    };

    let auth_req_id = uuid::Uuid::new_v4().simple().to_string();

    let ctx = BackchannelContext {
        tenant: state.tenant_id(),
        client: &resolved.client_id,
        store: &state.codes,
        hasher: &AwsLcSha256,
        users: &DevBackchannelResolver {
            user: argus_core::id::UserId::from_uuid(uuid::Uuid::from_u128(1)),
        },
        now: at,
        auth_req_id: &auth_req_id,
        resources: Vec::new(),
    };

    match backchannel_request(&ctx, &form).await {
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

fn consent_page(
    client_host: &str,
    redirect_host: &str,
    scope: Option<&str>,
    raw_query: Option<&str>,
) -> Response {
    let query = raw_query.unwrap_or_default();
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Authorize</title>\
         <h1>Authorize this application?</h1>\
         <p>Client identifier host: <strong>{}</strong></p>\
         <p>You will be returned to: <strong>{}</strong></p>\
         <p>Requested scope: <strong>{}</strong></p>\
         <form method=\"get\" action=\"/authorize\">\
         {}<button type=\"submit\" name=\"consented\" value=\"true\">Approve</button>\
         </form>",
        escape(client_host),
        escape(redirect_host),
        escape(scope.unwrap_or("(none)")),
        hidden_fields(query),
    );

    let mut response = (StatusCode::OK, body).into_response();
    if let Ok(value) = "text/html; charset=utf-8".parse() {
        response.headers_mut().insert("Content-Type", value);
    }
    if let Ok(value) = "no-store".parse() {
        response.headers_mut().insert("Cache-Control", value);
    }
    response
}

fn hidden_fields(query: &str) -> String {
    use core::fmt::Write as _;

    let mut out = String::new();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == "consented" {
            continue;
        }
        let _ = write!(
            out,
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escape(key),
            escape(&percent_decode(value))
        );
    }
    out
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn login_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
    Form(form): Form<crate::endpoints::authn::PasswordLoginForm>,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
{
    use crate::endpoints::authn::{LoginOutcome, LoginResponse, password_login, session_cookie};

    let at = now();
    let (outcome, secret) = password_login(
        &state.codes,
        state.tenant_id(),
        &form,
        &AwsLcSha256,
        &state.tenant.blind_index,
        at,
    )
    .await;

    let mut response = match outcome {
        LoginOutcome::Established { .. } => {
            let Some(secret) = secret else {
                return oauth_response(&OAuthError::new(OAuthErrorCode::ServerError));
            };
            let secure = state.tenant.metadata.issuer.starts_with("https://");
            let mut r = Json(LoginResponse {
                authenticated: true,
            })
            .into_response();
            if let Ok(value) = session_cookie(&secret, secure).parse() {
                r.headers_mut().insert("Set-Cookie", value);
            }
            r
        }
        LoginOutcome::Refused => (
            StatusCode::UNAUTHORIZED,
            Json(LoginResponse {
                authenticated: false,
            }),
        )
            .into_response(),
        LoginOutcome::Unavailable => {
            return oauth_response(&OAuthError::new(OAuthErrorCode::TemporarilyUnavailable));
        }
    };

    if let Ok(value) = "no-store".parse() {
        response.headers_mut().insert("Cache-Control", value);
    }
    response
}

async fn resolve_subject<C, R, A, S, U, P, X>(
    state: &AppState<C, R, A, S, U, P, X>,
    headers: &HeaderMap,
    now: Timestamp,
) -> Option<argus_core::id::UserId>
where
    C: CodeStore + SessionStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    use argus_core::pkce::Sha256 as _;

    let cookies = headers.get("Cookie").and_then(|v| v.to_str().ok());
    let secret = crate::endpoints::authn::session_from_cookies(cookies)?;
    let hash = AwsLcSha256.sha256(secret.as_bytes());

    state
        .codes
        .load_session(state.tenant_id(), &hash, now)
        .await
        .ok()
        .map(|session| session.subject)
}

async fn resolve_client<C, R, A, S, U, P, X>(
    state: &AppState<C, R, A, S, U, P, X>,
    client_id: &str,
    now: Timestamp,
) -> Result<Option<argus_core::authorize::RegisteredClient>, Box<Response>>
where
    C: CodeStore + CodeIssuer + BackchannelStore + SessionStore + AuthnStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    S: ClientStore + Send + Sync,
{
    if argus_core::cimd::looks_like_a_url(client_id) {
        let Some(cimd) = state.cimd.as_ref() else {
            return Ok(None);
        };
        let Ok(url) = argus_core::cimd::ClientIdUrl::parse(client_id) else {
            return Ok(None);
        };
        return Ok(cimd
            .resolve(&url, &crate::cimd_fetch::SystemResolver, now)
            .await
            .ok());
    }

    let Ok(id) = argus_core::id::ClientId::new(client_id) else {
        return Ok(None);
    };

    match state.clients.find(state.tenant_id(), &id).await {
        Ok(found) => Ok(found),
        Err(_) => Err(Box::new(oauth_response(&OAuthError::new(
            OAuthErrorCode::TemporarilyUnavailable,
        )))),
    }
}

async fn prm_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
{
    prm_response(&state, &format!("/{path}")).await
}

async fn prm_root_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
{
    prm_response(&state, "").await
}

async fn prm_response<C, R, A, S, U, P, X>(
    state: &AppState<C, R, A, S, U, P, X>,
    suffix: &str,
) -> Response
where
    C: CodeStore + CodeIssuer + BackchannelStore + SessionStore + AuthnStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    X: ResourceStore + Send + Sync,
{
    let Ok(resources) = state.resources.list_resources(state.tenant_id()).await else {
        return oauth_response(&OAuthError::new(OAuthErrorCode::TemporarilyUnavailable));
    };

    let wanted = format!("/.well-known/oauth-protected-resource{suffix}");

    let found = resources
        .into_iter()
        .find(|r| argus_proto::well_known_path(r.uri.as_str()).is_some_and(|p| p == wanted));

    let Some(resource) = found else {
        if suffix.is_empty() {
            let own = argus_proto::ProtectedResourceMetadata::new(
                &state.tenant.metadata.issuer,
                &state.tenant.metadata.issuer,
            )
            .with_scopes(Some("openid"));
            let mut r = Json(own).into_response();
            if let Ok(value) = "public, max-age=3600".parse() {
                r.headers_mut().insert("Cache-Control", value);
            }
            return r;
        }
        return (StatusCode::NOT_FOUND, "no such protected resource").into_response();
    };

    let metadata = argus_proto::ProtectedResourceMetadata::new(
        resource.uri.as_str(),
        &state.tenant.metadata.issuer,
    )
    .with_name(resource.name)
    .with_scopes(resource.scopes.as_deref());

    let mut r = Json(metadata).into_response();
    if let Ok(value) = "public, max-age=3600".parse() {
        r.headers_mut().insert("Cache-Control", value);
    }
    r
}

async fn userinfo_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
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
        Some(Err(_)) => {
            return userinfo_refusal(
                userinfo::UserInfoError::InvalidProof,
                &state.tenant.metadata.issuer,
            );
        }
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
        Err(err) => userinfo_refusal(err, &state.tenant.metadata.issuer),
    }
}

fn userinfo_refusal(err: userinfo::UserInfoError, issuer: &str) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::UNAUTHORIZED);
    let mut r = (status, Json(err.body())).into_response();
    let challenge = format!(
        r#"{}, resource_metadata="{issuer}/.well-known/oauth-protected-resource""#,
        err.challenge()
    );
    if let Ok(value) = challenge.parse() {
        r.headers_mut().insert("WWW-Authenticate", value);
    }
    if let Ok(value) = "no-store".parse() {
        r.headers_mut().insert("Cache-Control", value);
    }
    r
}

async fn authorize_handler<C, R, A, S, U, P, X>(
    State(state): State<SharedState<C, R, A, S, U, P, X>>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
{
    let at = now();
    let mut query = query;
    query.resource =
        crate::endpoints::authorize::repeated_query_values(raw_query.as_deref(), "resource");

    let code = uuid::Uuid::new_v4().simple().to_string();
    let registered_resources = match state.resources.list_resources(state.tenant_id()).await {
        Ok(list) => list.into_iter().map(|r| r.uri).collect::<Vec<_>>(),
        Err(_) => {
            return oauth_response(&OAuthError::new(OAuthErrorCode::TemporarilyUnavailable));
        }
    };

    let subject = resolve_subject(&state, &headers, at).await;

    let resolved = match resolve_client(&state, &query.client_id, at).await {
        Ok(client) => client,
        Err(response) => return *response,
    };

    let ctx = AuthorizeContext {
        tenant: state.tenant_id(),
        issuer: &state.tenant.metadata.issuer,
        client: resolved.as_ref(),
        codes: &state.codes,
        subject,
        hasher: &AwsLcSha256,
        now: at,
        new_code: &code,
        registered_resources: &registered_resources,
        requires_consent: argus_core::cimd::looks_like_a_url(&query.client_id),
    };
    let outcome = authorize_handle(&ctx, &query).await;

    match outcome {
        Ok(AuthorizeResponse::Redirect(url)) => axum::response::Redirect::to(&url).into_response(),
        Ok(AuthorizeResponse::ShowError(message)) => {
            (StatusCode::BAD_REQUEST, message.to_owned()).into_response()
        }
        Ok(AuthorizeResponse::NeedsConsent {
            client_host,
            redirect_host,
            scope,
        }) => consent_page(
            &client_host,
            &redirect_host,
            scope.as_deref(),
            raw_query.as_deref(),
        ),
        Ok(AuthorizeResponse::NeedsAuthentication) => (
            StatusCode::UNAUTHORIZED,
            "authentication required (phase 3)".to_owned(),
        )
            .into_response(),
        Err(_) => oauth_response(&OAuthError::new(OAuthErrorCode::TemporarilyUnavailable)),
    }
}

pub fn build<C, R, A, S, U, P, X>(state: SharedState<C, R, A, S, U, P, X>) -> Router
where
    C: CodeStore
        + CodeIssuer
        + BackchannelStore
        + SessionStore
        + AuthnStore
        + Send
        + Sync
        + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: Send + Sync + 'static,
    P: ReplayStore + Send + Sync + 'static,
    X: ResourceStore + ConnectionStore + IssuerStore + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata_handler::<C, R, A, S, U, P, X>),
        )
        .route(
            "/.well-known/openid-configuration",
            get(metadata_handler::<C, R, A, S, U, P, X>),
        )
        .route(
            "/.well-known/jwks.json",
            get(jwks_handler::<C, R, A, S, U, P, X>),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(prm_root_handler::<C, R, A, S, U, P, X>),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*path}",
            get(prm_handler::<C, R, A, S, U, P, X>),
        )
        .route("/authorize", get(authorize_handler::<C, R, A, S, U, P, X>))
        .route("/token", post(token_handler::<C, R, A, S, U, P, X>))
        .route("/login", post(login_handler::<C, R, A, S, U, P, X>))
        .route(
            "/bc-authorize",
            post(backchannel_handler::<C, R, A, S, U, P, X>),
        )
        .route(
            "/userinfo",
            get(userinfo_handler::<C, R, A, S, U, P, X>)
                .post(userinfo_handler::<C, R, A, S, U, P, X>),
        )
        .with_state(state)
}
