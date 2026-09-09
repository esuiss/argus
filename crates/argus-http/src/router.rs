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
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};

use crate::endpoints::discovery;
use crate::endpoints::token::{TokenForm, handle};
use crate::state::AppState;
use crate::store::{AuditSink, CodeStore, RefreshStore};

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

type SharedState<C, R, A> = Arc<AppState<C, R, A>>;

async fn metadata_handler<C, R, A>(State(state): State<SharedState<C, R, A>>) -> Response
where
    C: CodeStore + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
{
    Json(discovery::metadata(&state.tenant)).into_response()
}

async fn jwks_handler<C, R, A>(State(state): State<SharedState<C, R, A>>) -> Response
where
    C: CodeStore + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
{
    discovery::jwks(&state.tenant).map_or_else(
        |_| oauth_response(&OAuthError::new(OAuthErrorCode::ServerError)),
        |set| Json(set).into_response(),
    )
}

async fn token_handler<C, R, A>(
    State(state): State<SharedState<C, R, A>>,
    Form(form): Form<TokenForm>,
) -> Response
where
    C: CodeStore + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
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

/// Router'ı kurar.
///
/// # Discovery iki yoldan da yayınlanır
///
/// §18: iki spec aynı issuer için farklı well-known URL üretiyor ve istemcilerin
/// hangisini deneyeceği belirsiz. İkisini birden sunmak maliyetsiz ve interop
/// kırılmasını önlüyor.
pub fn build<C, R, A>(state: SharedState<C, R, A>) -> Router
where
    C: CodeStore + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata_handler::<C, R, A>),
        )
        .route(
            "/.well-known/openid-configuration",
            get(metadata_handler::<C, R, A>),
        )
        .route("/.well-known/jwks.json", get(jwks_handler::<C, R, A>))
        // RFC 6749 §3.2: token endpoint'i **yalnızca** POST kabul eder.
        .route("/token", post(token_handler::<C, R, A>))
        .with_state(state)
}
