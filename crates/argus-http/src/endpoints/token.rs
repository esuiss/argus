//! Token endpoint'i — RFC 6749 §3.2.
//!
//! Bu dosya karar vermez. Her grant için sırayla: isteği ayrıştır →
//! `argus-core`'un saf fonksiyonunu çağır → dönen etkileri **tamamen** uygula →
//! token üret.

use argus_core::authz_code::{AuthorizationCode, Decision, TokenRequest, redeem};
use argus_core::effect::Effect;
use argus_core::id::ClientId;
use argus_core::pkce::Sha256;
use argus_core::refresh::{
    DEFAULT_FAMILY_LIFETIME, DEFAULT_TOKEN_LIFETIME, RefreshDecision, RefreshRequest, RefreshState,
    RefreshToken, rotate,
};
use argus_core::time::{Duration, Timestamp};
use argus_proto::jwt::{AccessTokenClaims, sign};
use argus_proto::{OAuthError, OAuthErrorCode, TokenResponse};
use serde::Deserialize;

use crate::effects::{EffectContext, Rotation, apply};
use crate::state::AppState;
use crate::store::{AuditSink, CodeStore, RefreshStore, StoreError};

/// Access token varsayılan ömrü.
///
/// ⚠️ **§1 §10.1 AÇIK KARAR.** Bu değer bir yer tutucudur, karar değildir: iptal
/// ve bayatlık sözleşmesi (uzun ömürlü + sinyal güdümlü mü, kısa ömürlü mü)
/// kapatılmadan buraya bir sayı yazmak, kapatılmamış bir kararı sessizce
/// kapatmak olurdu. Beş dakika, §19 §7.2'nin degraded mode analiziyle tutarlı
/// olan **muhafazakâr** taraftır.
pub const PLACEHOLDER_ACCESS_TOKEN_LIFETIME: Duration = Duration::from_seconds(300);

/// `POST /token` gövdesi (form-encoded).
///
/// RFC 6749 §4.1.3 `application/x-www-form-urlencoded` **zorunlu** kılar;
/// §14 §12925: JSON-only parser yaygın bir hatadır ve 415 dönersen istemci
/// bağlanamaz.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenForm {
    /// Grant tipi.
    pub grant_type: String,
    /// `authorization_code` akışında kod.
    pub code: Option<String>,
    /// `authorization_code` akışında yönlendirme adresi.
    pub redirect_uri: Option<String>,
    /// PKCE verifier.
    pub code_verifier: Option<String>,
    /// İstemci kimliği.
    pub client_id: Option<String>,
    /// `refresh_token` akışında token.
    pub refresh_token: Option<String>,
}

/// Sır değerlerinden depo anahtarı üretir.
///
/// Ham kod/token **hiçbir zaman** saklanmaz; depo yalnızca hash'i görür.
fn hash(hasher: &impl Sha256, secret: &str) -> [u8; 32] {
    hasher.sha256(secret.as_bytes())
}

/// Depo hatasını istemci yanıtına çevirir.
///
/// §19 §7.1'in kuralı: kesinti sırasında **asla `invalid_grant`** dönülmez.
/// `invalid_grant` istemciye "yeniden yetkilendir" dedirtir ve geçici bir arızayı
/// kalıcı bir çıkışa çevirir. Doğru cevap `503`'tür.
const fn store_error_to_oauth(e: &StoreError) -> OAuthError {
    match e {
        StoreError::NotFound => OAuthError::new(OAuthErrorCode::InvalidGrant),
        StoreError::Unavailable => OAuthError::new(OAuthErrorCode::TemporarilyUnavailable),
    }
}

/// Token isteğini işler.
///
/// # Errors
///
/// Grant geçersizse, istemci doğrulanamazsa veya depo erişilemezse.
pub async fn handle<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    form: &TokenForm,
    now: Timestamp,
    hasher: &H,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    match form.grant_type.as_str() {
        "authorization_code" => authorization_code(state, form, now, hasher).await,
        "refresh_token" => refresh_token(state, form, now, hasher).await,
        // OAuth 2.1: `password` ve `implicit` yok. Bilinmeyen grant da buraya düşer.
        _ => Err(OAuthError::with_description(
            OAuthErrorCode::UnsupportedGrantType,
            "only authorization_code and refresh_token are supported",
        )),
    }
}

fn client_of(form: &TokenForm) -> Result<ClientId, OAuthError> {
    let raw = form
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidClient))?;
    ClientId::new(raw).map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))
}

async fn authorization_code<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    form: &TokenForm,
    now: Timestamp,
    hasher: &H,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    let client = client_of(form)?;
    let code = form
        .code
        .as_deref()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;
    let redirect_uri = form
        .redirect_uri
        .clone()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;
    let code_verifier = form
        .code_verifier
        .clone()
        // PKCE OAuth 2.1'de ZORUNLU: eksikse istek geçersizdir.
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    let tenant = state.tenant_id();
    let code_hash = hash(hasher, code);

    let stored = state
        .codes
        .load(tenant, &code_hash)
        .await
        .map_err(|e| store_error_to_oauth(&e))?;
    let record = AuthorizationCode::from_stored(stored);

    let decision = redeem(
        &record,
        &TokenRequest {
            client: client.clone(),
            redirect_uri,
            code_verifier,
            tenant,
        },
        now,
        hasher,
    );

    let (grant, effects) = match decision {
        Decision::Grant { grant, effects } => (grant, effects),
        Decision::Deny { reason, effects } => {
            // Ret yolunda da etkiler uygulanır: kodun tüketilmesi ve — tekrar
            // kullanımda — zincirin düşürülmesi tam olarak burada olur.
            apply_effects(state, &effects, &code_hash, None, now).await?;
            return Err(OAuthError::new(match reason.oauth_error_code() {
                "invalid_grant" => OAuthErrorCode::InvalidGrant,
                _ => OAuthErrorCode::InvalidRequest,
            }));
        }
    };

    apply_effects(state, &effects, &code_hash, None, now).await?;
    issue(state, &grant.subject, &grant.client, now, hasher, None)
}

async fn refresh_token<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    form: &TokenForm,
    now: Timestamp,
    hasher: &H,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    let client = client_of(form)?;
    let presented = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    let tenant = state.tenant_id();
    let old_hash = hash(hasher, presented);

    let stored = state
        .refresh
        .load(tenant, &old_hash)
        .await
        .map_err(|e| store_error_to_oauth(&e))?;

    let decision = rotate(
        &stored,
        &RefreshRequest {
            client: client.clone(),
            tenant,
        },
        now,
        DEFAULT_FAMILY_LIFETIME,
    );

    match decision {
        RefreshDecision::Deny { reason, effects } => {
            let rotation = Rotation {
                old_hash: &old_hash,
                new_hash: &old_hash,
                new_token: &stored,
                family: stored.family,
            };
            apply_effects(state, &effects, &old_hash, Some(rotation), now).await?;
            let _ = reason;
            Err(OAuthError::new(OAuthErrorCode::InvalidGrant))
        }
        RefreshDecision::Rotate { grant, effects } => {
            let new_secret = new_secret();
            let new_hash = hash(hasher, &new_secret);
            let new_token = RefreshToken {
                tenant: grant.tenant,
                client: grant.client.clone(),
                subject: grant.subject,
                family: grant.family,
                generation: grant.next_generation,
                family_started_at: stored.family_started_at,
                expires_at: now.saturating_add(DEFAULT_TOKEN_LIFETIME),
                state: RefreshState::Active,
            };

            let rotation = Rotation {
                old_hash: &old_hash,
                new_hash: &new_hash,
                new_token: &new_token,
                family: grant.family,
            };
            apply_effects(state, &effects, &old_hash, Some(rotation), now).await?;

            issue(
                state,
                &grant.subject,
                &grant.client,
                now,
                hasher,
                Some(new_secret),
            )
        }
    }
}

async fn apply_effects<C, R, A, S, U>(
    state: &AppState<C, R, A, S, U>,
    effects: &[Effect],
    code_hash: &[u8; 32],
    rotation: Option<Rotation<'_>>,
    now: Timestamp,
) -> Result<(), OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    let ctx = EffectContext {
        tenant: state.tenant_id(),
        code_hash: Some(code_hash),
        rotation,
        now,
    };
    apply(effects, &ctx, &state.codes, &state.refresh, &state.audit)
        .await
        .map_err(|e| store_error_to_oauth(&e))
}

/// Kriptografik olarak rastgele bir sır üretir.
fn new_secret() -> String {
    // UUIDv4 122 bit entropi taşır; RFC 6749 §10.10'un istediği tahmin edilemezlik
    // için yeterli. Depoda yalnızca hash'i durur.
    uuid::Uuid::new_v4().simple().to_string()
}

fn issue<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    subject: &argus_core::id::UserId,
    client: &ClientId,
    now: Timestamp,
    _hasher: &H,
    refresh: Option<String>,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    let exp = now.saturating_add(PLACEHOLDER_ACCESS_TOKEN_LIFETIME);
    let claims = AccessTokenClaims {
        iss: state.tenant.metadata.issuer.clone(),
        sub: subject.as_uuid().simple().to_string(),
        aud: client.as_str().to_owned(),
        exp: exp.as_unix_seconds(),
        iat: now.as_unix_seconds(),
        jti: uuid::Uuid::new_v4().simple().to_string(),
        scope: None,
        sess: 0,
    };

    let access_token = sign(&claims, &state.tenant.active_key)
        .map_err(|_| OAuthError::new(OAuthErrorCode::ServerError))?;

    Ok(TokenResponse {
        access_token,
        // §1 §4.1: bearer varsayılan değildir. DPoP bağlama gelene kadar
        // `Bearer` dönülüyor ve bu bir eksiklik olarak işaretli.
        token_type: "Bearer".to_owned(),
        expires_in: PLACEHOLDER_ACCESS_TOKEN_LIFETIME.as_seconds(),
        refresh_token: refresh,
        scope: None,
    })
}
