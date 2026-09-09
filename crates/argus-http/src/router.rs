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

/// ⚠️ Tekrar kaydı **henüz yok**.
///
/// Hem `DPoP` kanıtlarının hem `private_key_jwt` assertion'larının `jti`'si buna
/// sorulur. `RFC` 9449 §11.1 ve `RFC` 7523 §3 tekrar korumasını istiyor ve bu
/// tip şu an her `jti`'yi yeni sayıyor. Tek node'da bile eksik; çok node'lu dağıtımda paylaşımlı bir
/// kayıt (Redis/Postgres) şart. §6 §4.4 bunu Bloom/cuckoo filtrenin **tek meşru
/// kullanım alanı** olarak işaretliyor: yanlış pozitifin bedeli tek bir isteğin
/// reddi, kullanıcı çıkışı değil.
struct NoReplayRecord;

impl argus_core::dpop::ReplayGuard for NoReplayRecord {
    fn seen(&self, _jti: &str) -> bool {
        false
    }
}

/// `DPoP` başlığını doğrular ve bağlamayı çıkarır.
///
/// Kanıt varsa **doğrulanmadan** kullanılmaz: imza, `typ`, `alg`, metot ve URI
/// eşleşmesi ve tekrar kontrolü geçmeden bağlama kurulmaz. Geçersiz bir kanıt
/// sessizce yok sayılmaz — `invalid_dpop_proof` ile reddedilir, aksi hâlde
/// saldırgan bozuk kanıt göndererek token'ı bearer'a düşürebilirdi.
fn dpop_binding(headers: &HeaderMap, htu: &str, now: Timestamp) -> Result<Binding, OAuthError> {
    let Some(raw) = headers.get("DPoP") else {
        return Ok(None);
    };
    let Ok(proof_str) = raw.to_str() else {
        return Err(OAuthError::new(OAuthErrorCode::InvalidRequest));
    };

    let proof = argus_proto::dpop::parse_and_verify(proof_str)
        .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    argus_core::dpop::validate(
        &proof,
        &argus_core::dpop::RequestBinding {
            method: "POST".to_owned(),
            uri: htu.to_owned(),
        },
        None,
        now,
        argus_core::dpop::DEFAULT_PROOF_WINDOW,
        &NoReplayRecord,
    )
    .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    Ok(Some(proof.jkt))
}

async fn token_handler<C, R, A, S, U>(
    State(state): State<SharedState<C, R, A, S, U>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
{
    let at = now();
    let binding = match dpop_binding(&headers, &state.tenant.metadata.token_endpoint, at) {
        Ok(b) => b,
        Err(e) => return oauth_response(&e),
    };

    match handle(&state, &form, at, &AwsLcSha256, binding, &NoReplayRecord).await {
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

/// Form-encoded gövdeden bir alanı çıkarır.
///
/// Tam bir form ayrıştırıcısı değil ve olmamalı: burada tek bir alan aranıyor
/// ve gövde kimliği doğrulanmamış veridir. Küçük yüzey, küçük risk.
fn form_field(body: &str, name: &str) -> Option<String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| percent_decode(v))
}

/// Form değeri için minimal yüzde çözümlemesi.
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

/// `GET`/`POST /userinfo` — OIDC Core §5.3.
///
/// # Neden iki metot birden
///
/// §5.3.1 `GET` **ve** `POST`'u zorunlu tutuyor. Yalnızca birini sunmak,
/// uyumluluk paketinin `UserInfo` adımını düşürür.
///
/// # `WWW-Authenticate` neden her ret yolunda var
///
/// `RFC` 6750 §3: 401 dönen bir kaynak sunucu istemciye **nasıl** kimlik
/// doğrulayacağını söylemek zorundadır. Başlıksız 401, istemciyi kör bir yeniden
/// denemeye iter.
async fn userinfo_handler<C, R, A, S, U>(
    State(state): State<SharedState<C, R, A, S, U>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    C: CodeStore + CodeIssuer + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    A: AuditSink + Send + Sync + 'static,
    S: ClientStore + Send + Sync + 'static,
    U: UserAuthenticator + Send + Sync + 'static,
{
    let authorization = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let dpop = headers.get("DPoP").and_then(|v| v.to_str().ok());
    // `RFC` 6750 §2.2: yalnızca form-encoded gövde. `GET`'te gövde boştur ve
    // ayrıştırma hiçbir şey bulmaz.
    let form_access_token = form_field(&body, "access_token");
    let uri = state
        .tenant
        .metadata
        .userinfo_endpoint
        .clone()
        .unwrap_or_else(|| format!("{}/userinfo", state.tenant.metadata.issuer));

    let request = UserInfoRequest {
        authorization,
        form_access_token: form_access_token.as_deref(),
        dpop,
        // `htm` daima `GET`: her iki metot da aynı `htu`ya bağlanır ve
        // `POST` yolunda gövde yok. İstemcinin hangi metodu kullandığını
        // kanıta yansıtmak, `GET` için üretilmiş kanıtın `POST`'ta
        // reddedilmesine yol açardı.
        method: "GET",
        uri: &uri,
    };

    match userinfo::handle(&state.tenant, &request, now(), &NoReplayRecord) {
        Ok(info) => {
            let mut r = Json(info).into_response();
            // Kimlik yanıtı cache'lenmemeli: §5.3.4 ve token yanıtıyla aynı gerekçe.
            if let Ok(value) = "no-store".parse() {
                r.headers_mut().insert("Cache-Control", value);
            }
            r
        }
        Err(err) => {
            let status =
                StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::UNAUTHORIZED);
            let mut r = (status, Json(err.body())).into_response();
            if let Ok(value) = err.challenge().parse() {
                r.headers_mut().insert("WWW-Authenticate", value);
            }
            if let Ok(value) = "no-store".parse() {
                r.headers_mut().insert("Cache-Control", value);
            }
            r
        }
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
        // OIDC Core §5.3.1: `GET` ve `POST` ikisi de zorunlu.
        .route(
            "/userinfo",
            get(userinfo_handler::<C, R, A, S, U>).post(userinfo_handler::<C, R, A, S, U>),
        )
        .with_state(state)
}
