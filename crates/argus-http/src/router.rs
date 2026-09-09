//! Axum router.
//!
//! # Buradaki her şey ince
//!
//! Handler'lar ayrıştırır, saf karar fonksiyonunu çağırır ve sonucu `HTTP`'ye
//! çevirir. Karar mantığı yoktur; olsaydı `argus-core`'un yanlış yerinde olurdu.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argus_core::time::Timestamp;
use argus_crypto::AwsLcSha256;
use argus_proto::{OAuthError, OAuthErrorCode};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};

use crate::endpoints::authorize::{
    AuthorizeContext, AuthorizeQuery, AuthorizeResponse, UserAuthenticator,
    handle as authorize_handle,
};
use crate::endpoints::discovery;
use crate::endpoints::token::{TokenForm, handle};
use crate::state::AppState;
use crate::store::{AuditSink, ClientStore, CodeIssuer, CodeStore, RefreshStore};

/// Duvar saatini okur.
///
/// **Tek okuma noktası budur.** `argus-core` saate bakmaz (bkz. `argus_core::time`);
/// zaman buradan girer ve karar fonksiyonlarına parametre olarak geçer.
fn now() -> Timestamp {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Timestamp::from_unix_seconds(secs)
}

/// [`OAuthError`]'ı `HTTP` yanıtına çevirir.
fn oauth_response(err: &OAuthError) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = (status, Json(err)).into_response();

    // RFC 6749 §5.2: `invalid_client` 401 ile birlikte `WWW-Authenticate` taşır.
    if err.error == OAuthErrorCode::InvalidClient
        && let Ok(value) = "Basic realm=\"argus\"".parse()
    {
        response.headers_mut().insert("WWW-Authenticate", value);
    }

    // §14 §12994: yanıtın cache'lenmemesi gerekiyor; token yanıtı sırdır.
    if let Ok(value) = "no-store".parse() {
        response.headers_mut().insert("Cache-Control", value);
    }
    response
}

type SharedState<C, R, A, S, U> = Arc<AppState<C, R, A, S, U>>;

async fn metadata_handler<C, R, A, S, U>(
    State(state): State<SharedState<C, R, A, S, U>>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
{
    Json(discovery::metadata(&state.tenant)).into_response()
}

async fn jwks_handler<C, R, A, S, U>(State(state): State<SharedState<C, R, A, S, U>>) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
{
    discovery::jwks(&state.tenant).map_or_else(
        |_| oauth_response(&OAuthError::new(OAuthErrorCode::ServerError)),
        |set| Json(set).into_response(),
    )
}

async fn token_handler<C, R, A, S, U>(
    State(state): State<SharedState<C, R, A, S, U>>,
    Form(form): Form<TokenForm>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
{
    match handle(&state, &form, now(), &AwsLcSha256).await {
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

/// `GET /authorize`.
///
/// `redirect_uri` doğrulanamadığında **yönlendirme yapılmaz**: açık yönlendirici
/// olmamak için tek güvenli davranış hata göstermektir.
async fn authorize_handler<C, R, A, S, U>(
    State(state): State<SharedState<C, R, A, S, U>>,
    Query(query): Query<AuthorizeQuery>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
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

/// Router'ı kurar.
///
/// # Discovery iki yoldan da yayınlanır
///
/// §18: iki spec aynı issuer için farklı well-known URL üretiyor ve istemcilerin
/// hangisini deneyeceği belirsiz. İkisini birden sunmak maliyetsiz ve interop
/// kırılmasını önlüyor.
pub fn build<C, R, A, S, U>(state: SharedState<C, R, A, S, U>) -> Router
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata_handler::<C, R, A, S, U>),
        )
        .route(
            "/.well-known/openid-configuration",
            get(metadata_handler::<C, R, A, S, U>),
        )
        .route("/.well-known/jwks.json", get(jwks_handler::<C, R, A, S, U>))
        // RFC 6749 §3.2: token endpoint'i **yalnızca** POST kabul eder.
        .route("/authorize", get(authorize_handler::<C, R, A, S, U>))
        .route("/token", post(token_handler::<C, R, A, S, U>))
        .with_state(state)
}
