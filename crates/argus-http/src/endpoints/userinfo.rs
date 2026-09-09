//! `UserInfo` endpoint'i — OIDC Core §5.3.
//!
//! # Bu dosya bir kaynak sunucudur
//!
//! Argus'un korunan ilk kaynağı burasıdır: token **üretmez**, token **tüketir**.
//! Ayrım önemli, çünkü kaynak sunucu tarafında kuralların yönü tersine döner —
//! token endpoint'i sırrı doğrular ve iddia üretir; burası iddiayı doğrular ve
//! yalnızca doğrulanabilir olanı döndürür.
//!
//! # `DPoP` bağlaması burada zorunlu hâle gelir
//!
//! `RFC` 9449 §7.1: token `cnf.jkt` taşıyorsa, onu sunan istek **aynı anahtarla**
//! imzalanmış bir kanıt taşımak zorundadır. Bunu kaynak sunucuda uygulamamak,
//! bağlamayı tamamen anlamsız kılar: token endpoint'inde token'ı anahtara
//! bağlayıp sonra herkesin bearer gibi kullanmasına izin vermek, çalınmış bir
//! token'ı hâlâ kullanılabilir bırakır.
//!
//! Kanıt ayrıca `ath` taşımalıdır (§4.3): `htm`/`htu` isteği bağlar ama hangi
//! token'a ait olduğunu söylemez. `ath` olmadan, bir kaynak için üretilmiş kanıt
//! başka bir token'la eşleştirilebilirdi.

use argus_core::dpop::{DEFAULT_PROOF_WINDOW, ReplayGuard, RequestBinding};
use argus_core::time::Timestamp;
use argus_crypto::{AwsLcSha256, VerifyingKey};
use argus_proto::jwt::AccessTokenClaims;
use argus_proto::{OAuthError, OAuthErrorCode, UserInfo};
use base64ct::{Base64UrlUnpadded, Encoding as _};

use crate::state::TenantContext;

/// `UserInfo` isteğinin reddedilme sebebi.
///
/// `RFC` 6750 §3.1 ile `RFC` 9449 §7.1 farklı `WWW-Authenticate` şemaları ister;
/// bu yüzden sebep tipli tutuluyor, düz bir `OAuthError`'a çevrilmiyor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserInfoError {
    /// `Authorization` başlığı yok ya da tanınmayan bir şema taşıyor.
    ///
    /// `RFC` 6750 §3.1: bu durumda **401** ve `error` **yazılmaz** — istemciye
    /// "kimlik doğrula" denir, "token'ın bozuk" denmez.
    MissingCredentials,
    /// Token doğrulanamadı: imza, biçim, `iss` ya da süre.
    InvalidToken,
    /// Token `DPoP` bağlı ama istek geçerli bir kanıt taşımıyor.
    MissingProof,
    /// Kanıt geçerli ama token'a ya da isteğe ait değil.
    InvalidProof,
}

impl UserInfoError {
    /// `HTTP` durum kodu.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        // Hepsi 401: 403 "kimliğin doğru ama yetkin yok" demektir ve buradaki
        // hiçbir sebep o anlama gelmiyor.
        401
    }

    /// `WWW-Authenticate` başlığının değeri.
    #[must_use]
    pub const fn challenge(self) -> &'static str {
        match self {
            Self::MissingCredentials => "Bearer",
            Self::InvalidToken => {
                r#"Bearer error="invalid_token", error_description="the access token is not valid""#
            }
            Self::MissingProof => {
                r#"DPoP error="invalid_token", error_description="a DPoP proof is required for this token", algs="ES256""#
            }
            Self::InvalidProof => {
                r#"DPoP error="invalid_token", error_description="the DPoP proof does not match this token or request", algs="ES256""#
            }
        }
    }

    /// Gövdeye yazılacak hata.
    #[must_use]
    pub const fn body(self) -> OAuthError {
        OAuthError::new(OAuthErrorCode::InvalidToken)
    }
}

/// `Authorization` başlığından token'ı ve şemasını çıkarır.
///
/// Şema `RFC` 7235 §2.1 gereği harf büyüklüğüne duyarsızdır; `bearer` gönderen
/// istemciler var ve onları reddetmek uyum hatası olur.
fn credentials(raw: &str) -> Option<(Scheme, &str)> {
    let (scheme, token) = raw.split_once(' ')?;
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        Some((Scheme::Bearer, token))
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Some((Scheme::Dpop, token))
    } else {
        None
    }
}

/// Sunulan kimlik bilgisinin şeması.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// `Authorization: Bearer`.
    Bearer,
    /// `Authorization: DPoP`.
    Dpop,
}

/// `RFC` 9449 §4.3: `ath` = access token'ın SHA-256'sı, BASE64URL.
///
/// `at_hash`'ten farklı olarak **tam** digest kullanılır; yarısı değil.
fn access_token_hash(access_token: &str) -> String {
    use argus_core::pkce::Sha256 as _;
    Base64UrlUnpadded::encode_string(&AwsLcSha256.sha256(access_token.as_bytes()))
}

/// Token'ı yayınlanmış anahtarların **herhangi biriyle** doğrular.
///
/// Rotasyon penceresinde eski anahtarla imzalanmış token'lar hâlâ dolaşımdadır;
/// yalnızca aktif anahtarı denemek §1 §9'un "rotasyonda 0 adet 401" kriterini
/// ihlal ederdi.
fn verify_with_published_keys(
    tenant: &TenantContext,
    token: &str,
) -> Result<AccessTokenClaims, UserInfoError> {
    let keys: Vec<VerifyingKey> = tenant
        .published_keys
        .iter()
        .map(|k| k.verifying_key())
        .collect();

    keys.iter()
        .find_map(|key| argus_proto::jwt::verify(token, key).ok())
        .ok_or(UserInfoError::InvalidToken)
}

/// İsteğin `UserInfo` bileşenleri.
pub struct UserInfoRequest<'a> {
    /// `Authorization` başlığının ham değeri.
    pub authorization: Option<&'a str>,
    /// Gövdedeki `access_token` form parametresi.
    ///
    /// `RFC` 6750 §2.2 ve OIDC Core §5.3.1: istemci token'ı form gövdesinde de
    /// gönderebilir. Yalnızca başlığı okumak, bu yolu kullanan istemcileri kırar
    /// (`oidcc-userinfo-post-body`).
    ///
    /// ⚠️ Başlıkla **birlikte** gelemez: `RFC` 6750 §2 birden fazla yöntemle
    /// token sunmayı yasaklar. İkisi birden geldiğinde hangisinin geçerli
    /// olduğunu seçmek, sunucular arasında farklı davranış üretir.
    pub form_access_token: Option<&'a str>,
    /// `DPoP` başlığının ham değeri.
    pub dpop: Option<&'a str>,
    /// Kanıtın bağlanacağı `HTTP` metodu.
    pub method: &'a str,
    /// Kanıtın bağlanacağı `URI` (query ve fragment hariç).
    pub uri: &'a str,
}

/// `UserInfo` isteğini karşılar.
///
/// # Errors
///
/// Kimlik bilgisi yoksa, token doğrulanamazsa ya da `DPoP` bağlaması tutmazsa.
pub fn handle(
    tenant: &TenantContext,
    request: &UserInfoRequest<'_>,
    now: Timestamp,
    replay: &impl ReplayGuard,
) -> Result<UserInfo, UserInfoError> {
    let (scheme, token) = match (request.authorization, request.form_access_token) {
        // `RFC` 6750 §2: "Clients MUST NOT use more than one method to transmit
        // the token in each request."
        (Some(_), Some(_)) => return Err(UserInfoError::InvalidToken),
        (Some(header), None) => credentials(header).ok_or(UserInfoError::MissingCredentials)?,
        // Gövde yolunda şema yoktur; `DPoP` bağlı bir token bu yolla
        // sunulamaz — kanıtın bağlanacağı bir şema bilgisi yok. Aşağıdaki
        // `cnf` kontrolü bunu zaten reddedecek.
        (None, Some(body)) if !body.trim().is_empty() => (Scheme::Bearer, body.trim()),
        _ => return Err(UserInfoError::MissingCredentials),
    };

    let claims = verify_with_published_keys(tenant, token)?;

    // Issuer eşleşmeli: başka bir kiracının anahtarı bu kiracının anahtar
    // setinde olmasa da, ileride paylaşılan bir sette olabilir.
    if claims.iss != tenant.metadata.issuer {
        return Err(UserInfoError::InvalidToken);
    }

    // İmza geçerli olsa bile süresi dolmuş token kabul edilmez.
    if claims.exp <= now.as_unix_seconds() {
        return Err(UserInfoError::InvalidToken);
    }

    match claims.cnf.as_ref() {
        // Bağlı token: kanıt ZORUNLU ve şema `DPoP` olmalı.
        Some(confirmation) => {
            if scheme != Scheme::Dpop {
                return Err(UserInfoError::MissingProof);
            }
            let Some(proof_header) = request.dpop else {
                return Err(UserInfoError::MissingProof);
            };

            let proof = argus_proto::dpop::parse_and_verify(proof_header)
                .map_err(|_| UserInfoError::InvalidProof)?;

            // Bağlamanın TAMAMI bu karşılaştırmada: kanıtı imzalayan anahtarın
            // thumbprint'i token'daki `jkt` ile aynı olmalı.
            if proof.jkt != confirmation.jkt {
                return Err(UserInfoError::InvalidProof);
            }

            argus_core::dpop::validate(
                &proof,
                &RequestBinding {
                    method: request.method.to_owned(),
                    uri: request.uri.to_owned(),
                },
                Some(&access_token_hash(token)),
                now,
                DEFAULT_PROOF_WINDOW,
                replay,
            )
            .map_err(|_| UserInfoError::InvalidProof)?;
        }
        // Bağsız token: `DPoP` şemasıyla sunulması bir çelişkidir.
        None => {
            if scheme == Scheme::Dpop {
                return Err(UserInfoError::InvalidToken);
            }
        }
    }

    Ok(UserInfo { sub: claims.sub })
}
