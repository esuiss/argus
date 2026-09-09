//! Token endpoint'i — RFC 6749 §3.2.
//!
//! Bu dosya karar vermez. Her grant için sırayla: isteği ayrıştır →
//! `argus-core`'un saf fonksiyonunu çağır → dönen etkileri **tamamen** uygula →
//! token üret.

use argus_core::authz_code::{AuthorizationCode, Decision, TokenRequest, redeem};
use argus_core::client_auth::{PresentedCredential, authenticate, validate_assertion};
use argus_core::dpop::ReplayGuard;
use argus_core::effect::Effect;
use argus_core::id::ClientId;
use argus_core::pkce::Sha256;
use argus_core::refresh::{
    DEFAULT_FAMILY_LIFETIME, DEFAULT_TOKEN_LIFETIME, RefreshDecision, RefreshRequest, RefreshState,
    RefreshToken, rotate,
};
use argus_core::time::{Duration, Timestamp};
use argus_proto::jwt::{AccessTokenClaims, Confirmation, sign};
use argus_proto::oidc::{IdTokenClaims, at_hash, sign_id_token};
use argus_proto::{OAuthError, OAuthErrorCode, TokenResponse};
use serde::Deserialize;

use crate::effects::{EffectContext, Rotation, apply};
use crate::state::AppState;
use crate::store::{AuditSink, ClientStore, CodeStore, RefreshStore, StoreError};

/// Access token varsayılan ömrü.
///
/// ⚠️ **§1 §10.1 AÇIK KARAR.** Bu değer bir yer tutucudur, karar değildir: iptal
/// ve bayatlık sözleşmesi (uzun ömürlü + sinyal güdümlü mü, kısa ömürlü mü)
/// kapatılmadan buraya bir sayı yazmak, kapatılmamış bir kararı sessizce
/// kapatmak olurdu. Beş dakika, §19 §7.2'nin degraded mode analiziyle tutarlı
/// olan **muhafazakâr** taraftır.
pub const PLACEHOLDER_ACCESS_TOKEN_LIFETIME: Duration = Duration::from_seconds(300);

/// `id_token` ömrü.
///
/// Access token'dan bağımsızdır: `id_token` bir **kimlik doğrulama anının**
/// kaydıdır, erişim yetkisi değil. İstemci onu aldığı anda doğrular ve claim'leri
/// kendi oturumuna kopyalar; uzun tutmak, çalınmış bir iddianın çok sonra
/// sunulabilmesi demektir.
pub const ID_TOKEN_LIFETIME: Duration = Duration::from_seconds(300);

/// `openid` kapsamı istendi mi.
///
/// Kapsam boşlukla ayrılmış bir listedir (RFC 6749 §3.3); `contains` ile
/// aramak `openid-connect` gibi bir değeri yanlışlıkla eşleştirirdi.
fn wants_openid(scope: Option<&str>) -> bool {
    scope.is_some_and(|s| s.split(' ').any(|v| v == "openid"))
}

/// `DPoP` bağlaması: kanıt doğrulandıysa thumbprint, aksi hâlde yok.
///
/// ⚠️ §1 §4.1: **bearer varsayılan değildir.** `None` dönmesi bir eksikliktir,
/// tercih değil: istemci `DPoP` başlığı göndermediyse token bearer olur ve onu
/// çalan herkes kullanabilir.
pub type Binding = Option<String>;

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

    /// `RFC` 7523 §2.2: `private_key_jwt` assertion'ının tipi.
    ///
    /// Sabit bir `URN`'dir; farklı bir değer, istemcinin desteklenmeyen bir
    /// mekanizma denediğini gösterir ve sessizce yok sayılmamalıdır.
    pub client_assertion_type: Option<String>,

    /// `RFC` 7523 §2.2: assertion'ın kendisi (kompakt `JWS`).
    pub client_assertion: Option<String>,
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
/// # Sıra önemli: önce istemci, sonra grant
///
/// İstemci kimlik doğrulaması grant kontrolünden **önce** yapılır. Tersi olsaydı,
/// kimliği doğrulanmamış bir çağıran grant kontrolünün yan etkilerini
/// tetikleyebilirdi — kodun tüketilmesi, refresh zincirinin düşürülmesi. Yani
/// kimlik doğrulamasız bir istek, başkasının oturumunu sonlandırabilirdi.
///
/// # Errors
///
/// İstemci doğrulanamazsa, grant geçersizse veya depo erişilemezse.
pub async fn handle<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    form: &TokenForm,
    now: Timestamp,
    hasher: &H,
    binding: Binding,
    assertion_replay: &impl ReplayGuard,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    S: ClientStore + Send + Sync,
    H: Sha256,
{
    let client = authenticate_client(state, form, now, hasher, assertion_replay).await?;

    match form.grant_type.as_str() {
        "authorization_code" => {
            authorization_code(state, form, &client, now, hasher, binding).await
        }
        "refresh_token" => refresh_token(state, form, &client, now, hasher, binding).await,
        // OAuth 2.1: `password` ve `implicit` yok. Bilinmeyen grant da buraya düşer.
        _ => Err(OAuthError::with_description(
            OAuthErrorCode::UnsupportedGrantType,
            "only authorization_code and refresh_token are supported",
        )),
    }
}

/// İstemciyi tanımlar ve **kayıtlı yöntemine göre** doğrular.
///
/// # `client_id` neden assertion'dan da okunabiliyor
///
/// `RFC` 7523 §2.2: `private_key_jwt` kullanan istemci `client_id` form alanını
/// göndermek zorunda değildir; kimlik assertion'ın `sub`'ındadır. İkisi birden
/// gelirse **uyuşmak zorundadır** — uyuşmazlığı yok saymak, bir istemcinin
/// başkasının kimliğiyle token istemesine kapı açar.
async fn authenticate_client<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    form: &TokenForm,
    now: Timestamp,
    hasher: &H,
    replay: &impl ReplayGuard,
) -> Result<ClientId, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    S: ClientStore + Send + Sync,
    H: Sha256,
{
    let tenant = state.tenant_id();

    // Assertion varsa kimliği ondan gelir; yoksa form alanından.
    let claimed = match form.client_assertion.as_deref() {
        Some(raw) => {
            // Tip alanı sabittir. Farklı bir değer, desteklenmeyen bir mekanizma
            // denendiğini gösterir ve SESSİZCE yok sayılmamalı: yok sayılırsa
            // istekler kimlik doğrulamasız bir yola düşerdi.
            if form.client_assertion_type.as_deref() != Some(argus_proto::ASSERTION_TYPE) {
                return Err(OAuthError::with_description(
                    OAuthErrorCode::InvalidRequest,
                    "client_assertion_type must be the JWT bearer assertion type",
                ));
            }
            let unverified = argus_proto::client_assertion::parse(raw)
                .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

            if let Some(from_form) = form.client_id.as_deref()
                && from_form != unverified.client_id
            {
                return Err(OAuthError::new(OAuthErrorCode::InvalidClient));
            }
            unverified.client_id
        }
        None => form
            .client_id
            .clone()
            .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidClient))?,
    };

    let client =
        ClientId::new(claimed).map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

    // Kayıt olmadan kimlik doğrulaması yapılamaz: hangi yöntemin beklendiğini
    // yalnızca kayıt söyler.
    let registered = state
        .clients
        .find(tenant, &client)
        .await
        .map_err(|e| store_error_to_oauth(&e))?
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidClient))?;

    let presented = match form.client_assertion.as_deref() {
        Some(raw) => {
            // İmza doğrulaması burada; `VerifiedAssertion` ancak bundan sonra
            // kurulabilir.
            let claims = argus_proto::client_assertion::verify(raw, &registered.keys)
                .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

            // `aud`: hem issuer hem token endpoint kabul ediliyor. `RFC` 7523 §3
            // yetkilendirme sunucusunu işaret etmeyi ister, OIDC Core §9 token
            // endpoint `URL`'ini örnekler; ikisi de yaygın ve reddetmek gerçek
            // istemcileri kırar. İkisi de bu sunucuyu gösterdiği için cross-AS
            // replay koruması kaybolmuyor.
            validate_assertion(
                &claims,
                &client,
                &[
                    state.tenant.metadata.issuer.as_str(),
                    state.tenant.metadata.token_endpoint.as_str(),
                ],
                now,
                replay,
            )
            .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

            PresentedCredential::VerifiedAssertion {
                client_id: client.clone(),
            }
        }
        None => PresentedCredential::None,
    };

    // Kayıtlı yöntemle sunulan yöntem burada karşılaştırılıyor. `private_key_jwt`
    // ile kayıtlı bir istemci kimlik bilgisi sunmadan geçemez.
    authenticate(
        &client,
        registered.auth_method,
        &presented,
        None,
        |secret| hasher.sha256(secret.as_bytes()),
    )
    .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

    Ok(client)
}

async fn authorization_code<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    form: &TokenForm,
    client: &ClientId,
    now: Timestamp,
    hasher: &H,
    binding: Binding,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
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
    issue(
        state,
        &IssueRequest {
            subject: &grant.subject,
            client: &grant.client,
            refresh: None,
            binding,
            // OIDC alanları yetkilendirme isteğinden geliyor; token isteği onları
            // taşımaz ve istemcinin göndermesine güvenilemez.
            nonce: grant.nonce.as_deref(),
            scope: grant.scope.as_deref(),
        },
        now,
        hasher,
    )
}

async fn refresh_token<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    form: &TokenForm,
    client: &ClientId,
    now: Timestamp,
    hasher: &H,
    binding: Binding,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
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

            // `id_token` YOK. OIDC Core §12.1 refresh yanıtının `id_token`
            // taşımasını gerektirmiyor ("it might not contain an id_token") ve
            // `refresh_tokens` tablosunda kapsam saklanmıyor: `openid`
            // istenip istenmediğini bilmeden kimlik iddiası üretmek uydurmak
            // olurdu. Kapsam kalıcılığı geldiğinde burası da üretebilir.
            issue(
                state,
                &IssueRequest {
                    subject: &grant.subject,
                    client: &grant.client,
                    refresh: Some(new_secret),
                    binding,
                    nonce: None,
                    scope: None,
                },
                now,
                hasher,
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

/// [`issue`] girdisi.
///
/// Yedi konumsal argüman yerine yapı: `nonce` ile `refresh` gibi aynı tipteki
/// alanların sessizce yer değiştirmesi derleyicinin yakalayamayacağı bir hata
/// olurdu.
struct IssueRequest<'a> {
    /// Token'ın öznesi.
    subject: &'a argus_core::id::UserId,
    /// Token'ın verildiği istemci.
    client: &'a ClientId,
    /// Yanıta konacak refresh token — üretildiyse.
    refresh: Option<String>,
    /// `DPoP` bağlaması.
    binding: Binding,
    /// Yetkilendirme isteğindeki `nonce`.
    nonce: Option<&'a str>,
    /// Verilen kapsam.
    scope: Option<&'a str>,
}

fn issue<C, R, A, S, U, H>(
    state: &AppState<C, R, A, S, U>,
    request: &IssueRequest<'_>,
    now: Timestamp,
    hasher: &H,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    let subject = request.subject.as_uuid().simple().to_string();
    let exp = now.saturating_add(PLACEHOLDER_ACCESS_TOKEN_LIFETIME);
    let claims = AccessTokenClaims {
        iss: state.tenant.metadata.issuer.clone(),
        sub: subject.clone(),
        aud: request.client.as_str().to_owned(),
        exp: exp.as_unix_seconds(),
        iat: now.as_unix_seconds(),
        jti: uuid::Uuid::new_v4().simple().to_string(),
        scope: request.scope.map(str::to_owned),
        sess: 0,
        // `RFC` 9449 §6: token'ı istemcinin anahtarına bağlar.
        cnf: request.binding.clone().map(|jkt| Confirmation { jkt }),
    };

    let bound = claims.cnf.is_some();

    let access_token = sign(&claims, &state.tenant.active_key)
        .map_err(|_| OAuthError::new(OAuthErrorCode::ServerError))?;

    // OIDC Core §3.1.3.3: kimlik iddiası YALNIZCA `openid` istendiğinde.
    let id_token = if wants_openid(request.scope) {
        let id_claims = IdTokenClaims {
            iss: state.tenant.metadata.issuer.clone(),
            sub: subject,
            // `aud` istemcinin kendisi — access token'daki gibi kaynak sunucu
            // değil. Karıştırmak, bir istemcinin başkasına verilmiş kimlik
            // iddiasını kabul etmesine yol açar.
            aud: request.client.as_str().to_owned(),
            exp: now.saturating_add(ID_TOKEN_LIFETIME).as_unix_seconds(),
            iat: now.as_unix_seconds(),
            nonce: request.nonce.map(str::to_owned),
            // ⚠️ `auth_time` YOK: kullanıcının ne zaman doğrulandığı henüz
            // kaydedilmiyor (kimlik doğrulama Faz 3). Kodun veriliş anını
            // yazmak, doğrulanmamış bir şeyi iddia etmek olurdu.
            auth_time: None,
            // §3.1.3.6: `id_token` ile access token'ın AYNI yanıttan geldiğini
            // kanıtlar; birinin başka bir yanıttan yapıştırılmasını engeller.
            at_hash: Some(at_hash(&access_token, hasher)),
        };
        Some(
            sign_id_token(&id_claims, &state.tenant.active_key)
                .map_err(|_| OAuthError::new(OAuthErrorCode::ServerError))?,
        )
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,
        // `RFC` 9449 §5: bağlı token'ın tipi `DPoP`'tur. İstemci `Bearer`
        // görürse token'ı `Authorization: Bearer` ile gönderir ve bağlama
        // sessizce devre dışı kalırdı.
        token_type: if bound {
            "DPoP".to_owned()
        } else {
            "Bearer".to_owned()
        },
        expires_in: PLACEHOLDER_ACCESS_TOKEN_LIFETIME.as_seconds(),
        refresh_token: request.refresh.clone(),
        scope: request.scope.map(str::to_owned),
        id_token,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::wants_openid;

    /// Kapsam boşlukla ayrılmış bir listedir; alt dize araması yanlış eşleşir.
    #[test]
    fn openid_is_matched_as_a_whole_value() {
        assert!(wants_openid(Some("openid")));
        assert!(wants_openid(Some("profile openid email")));
        assert!(wants_openid(Some("openid profile")));
    }

    #[test]
    fn a_scope_that_merely_contains_openid_does_not_count() {
        assert!(!wants_openid(Some("openid-connect")));
        assert!(!wants_openid(Some("not-openid")));
        assert!(!wants_openid(Some("myopenid")));
    }

    /// Kapsam yoksa kimlik iddiası da yok.
    #[test]
    fn absent_scope_never_asks_for_an_id_token() {
        assert!(!wants_openid(None));
        assert!(!wants_openid(Some("")));
    }
}
