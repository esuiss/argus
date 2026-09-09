//! Yetkilendirme endpoint'i — RFC 6749 §4.1.1.
//!
//! # ⚠️ Kullanıcı kimlik doğrulaması burada GEÇİCİDİR
//!
//! Gerçek kimlik doğrulama (`WebAuthn`, `Argon2`, kurtarma durum makinesi) **Faz
//! 3**'ün işi. Ama `/authorize` bir kullanıcıyı doğrulamadan kod üretemez ve
//! Faz 1'in çıkış kriteri (`OIDF` conformance) çalışan bir akış istiyor. Belgedeki
//! faz planında bu boşluk var: kimlik doğrulama Faz 3'te ama Faz 1 ve 2 uçtan
//! uca çalışmalı.
//!
//! Çözüm, boşluğu **görünür** kılmak: [`DevAuthenticator`] açıkça geliştirme
//! amaçlıdır, üretim yapılandırmasında kapalıdır ve Faz 3 onu değiştirecektir.
//! Sessizce "şimdilik herkesi kabul et" yazmak, sonradan kimsenin fark etmediği
//! bir kimlik doğrulama atlatması bırakırdı.

use argus_core::authorize::{AuthorizeOutcome, AuthorizeRequest, RegisteredClient, validate};
use argus_core::authz_code::{AuthorizationCode, DEFAULT_CODE_LIFETIME};
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::pkce::Sha256;
use argus_core::time::Timestamp;
use serde::Deserialize;

use crate::store::{ClientStore, CodeIssuer, StoreError};

/// `GET /authorize` sorgu parametreleri.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeQuery {
    /// `response_type`.
    pub response_type: String,
    /// `client_id`.
    pub client_id: String,
    /// `redirect_uri`.
    pub redirect_uri: Option<String>,
    /// `state`.
    pub state: Option<String>,
    /// `code_challenge`.
    pub code_challenge: Option<String>,
    /// `code_challenge_method`.
    pub code_challenge_method: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
}

/// Kullanıcı kimlik doğrulama sınırı.
///
/// Faz 3 bunu `WebAuthn` ve parola akışlarıyla uygulayacak.
pub trait UserAuthenticator {
    /// İsteğin sahibi olan kullanıcıyı döndürür; oturum yoksa `None`.
    fn current_user(&self, tenant: TenantId) -> Option<UserId>;
}

/// ⚠️ **Geliştirme amaçlı** kimlik doğrulayıcı.
///
/// Sabit bir kullanıcı döndürür. Üretimde kullanılmaz; Faz 3 gerçek olanı
/// getirecek. Adı ve bu not, yanlışlıkla üretime sızmasını zorlaştırmak içindir.
#[derive(Debug, Clone, Copy)]
pub struct DevAuthenticator {
    /// Her istekte döndürülecek kullanıcı.
    pub user: UserId,
}

impl UserAuthenticator for DevAuthenticator {
    fn current_user(&self, _tenant: TenantId) -> Option<UserId> {
        Some(self.user)
    }
}

/// Yetkilendirme sonucunun `HTTP` karşılığı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeResponse {
    /// İstemciye yönlendir.
    Redirect(String),
    /// **Yönlendirme yapılmaz** — kullanıcıya hata gösterilir.
    ///
    /// `redirect_uri` doğrulanamadığında tek güvenli davranış budur: aksi hâlde
    /// sunucu açık yönlendiriciye dönerdi.
    ShowError(&'static str),
    /// Kullanıcı henüz giriş yapmamış.
    NeedsAuthentication,
}

/// [`handle`] için gereken bağlam.
///
/// Dokuz konumsal argüman yerine yapı: aynı tipteki iki referansın (`clients`
/// ve `codes` gibi) sessizce yer değiştirmesi, derleyicinin yakalayamayacağı
/// bir hata olurdu.
pub struct AuthorizeContext<'a, S, I, U, H> {
    /// Çözülmüş kiracı.
    pub tenant: TenantId,
    /// Kiracının issuer'ı — `RFC` 9207 `iss` parametresine yazılır.
    pub issuer: &'a str,
    /// İstemci kaydı deposu.
    pub clients: &'a S,
    /// Kod yazma sınırı.
    pub codes: &'a I,
    /// Kullanıcı kimlik doğrulayıcı.
    pub auth: &'a U,
    /// Hash sağlayıcı.
    pub hasher: &'a H,
    /// Şimdi.
    pub now: Timestamp,
    /// Üretilmiş kod değeri; yalnızca hash'i saklanır.
    pub new_code: &'a str,
}

impl<S, I, U, H> Clone for AuthorizeContext<'_, S, I, U, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S, I, U, H> Copy for AuthorizeContext<'_, S, I, U, H> {}

/// Yetkilendirme isteğini işler.
///
/// # Errors
///
/// Depo erişilemezse.
pub async fn handle<S, I, U, H>(
    ctx: &AuthorizeContext<'_, S, I, U, H>,
    query: &AuthorizeQuery,
) -> Result<AuthorizeResponse, StoreError>
where
    S: ClientStore + Sync,
    I: CodeIssuer + Sync,
    U: UserAuthenticator + Sync,
    H: Sha256,
{
    let AuthorizeContext {
        tenant,
        issuer,
        clients,
        codes,
        auth,
        hasher,
        now,
        new_code,
    } = *ctx;

    let client_id = ClientId::new(query.client_id.clone()).ok();
    let registered: Option<RegisteredClient> = match client_id.as_ref() {
        Some(id) => clients.find(tenant, id).await?,
        None => None,
    };

    let request = AuthorizeRequest {
        response_type: query.response_type.clone(),
        client_id: query.client_id.clone(),
        redirect_uri: query.redirect_uri.clone(),
        state: query.state.clone(),
        code_challenge: query.code_challenge.clone(),
        code_challenge_method: query.code_challenge_method.clone(),
        scope: query.scope.clone(),
    };

    match validate(&request, registered.as_ref()) {
        AuthorizeOutcome::Fatal(_) => Ok(AuthorizeResponse::ShowError(
            "the redirect_uri is not registered for this client",
        )),

        AuthorizeOutcome::RedirectError {
            redirect_uri,
            error,
            state,
        } => {
            let mut url = format!("{}?error={}", redirect_uri.as_str(), error.as_str());
            append_state(&mut url, state.as_deref());
            append_iss(&mut url, issuer);
            Ok(AuthorizeResponse::Redirect(url))
        }

        AuthorizeOutcome::Proceed {
            redirect_uri,
            challenge,
            state,
            ..
        } => {
            let Some(user) = auth.current_user(tenant) else {
                return Ok(AuthorizeResponse::NeedsAuthentication);
            };

            // `client_id` burada kesinlikle geçerli: `validate` bilinmeyen
            // istemcide `Fatal` döndürüyor ve o dal yukarıda ele alındı.
            let Some(client) = client_id else {
                return Ok(AuthorizeResponse::ShowError("invalid client_id"));
            };

            let Ok(record) = AuthorizationCode::new(
                tenant,
                client,
                user,
                redirect_uri.clone(),
                challenge,
                now,
                DEFAULT_CODE_LIFETIME,
            ) else {
                return Ok(AuthorizeResponse::ShowError(
                    "authorization code lifetime is misconfigured",
                ));
            };

            // Kodun kendisi saklanmaz; yalnızca hash'i.
            let hash = hasher.sha256(new_code.as_bytes());
            codes.issue(tenant, &hash, &record.to_stored()).await?;

            let mut url = format!("{}?code={new_code}", redirect_uri.as_str());
            append_state(&mut url, state.as_deref());
            // RFC 9207: mix-up savunması. §1 #8 gün-1 kararı.
            append_iss(&mut url, issuer);
            Ok(AuthorizeResponse::Redirect(url))
        }
    }
}

fn append_state(url: &mut String, state: Option<&str>) {
    if let Some(s) = state {
        url.push_str("&state=");
        url.push_str(&urlencode(s));
    }
}

fn append_iss(url: &mut String, issuer: &str) {
    url.push_str("&iss=");
    url.push_str(&urlencode(issuer));
}

/// Sorgu değeri için minimal yüzde kodlaması.
///
/// Yalnızca `unreserved` karakterler olduğu gibi geçer; geri kalanı kodlanır.
/// Bu, `state` içindeki bir `&` veya `#` karakterinin yönlendirme adresine
/// parametre enjekte etmesini engeller.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(hex_digit(b >> 4)));
            out.push(char::from(hex_digit(b & 0x0F)));
        }
    }
    out
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + (nibble - 10),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{AuthorizeResponse, urlencode};

    /// `state` içindeki ayırıcılar kodlanmalı, yoksa saldırgan yönlendirme
    /// adresine kendi parametresini enjekte edebilir.
    #[test]
    fn state_separators_are_encoded() {
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencode("x#frag"), "x%23frag");
        assert_eq!(urlencode("safe-._~"), "safe-._~");
    }

    #[test]
    fn show_error_is_not_a_redirect() {
        let r = AuthorizeResponse::ShowError("nope");
        assert!(!matches!(r, AuthorizeResponse::Redirect(_)));
    }
}
