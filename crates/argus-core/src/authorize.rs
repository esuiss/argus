//! Yetkilendirme isteği doğrulaması — RFC 6749 §4.1.1.
//!
//! # En kritik kural: ne zaman yönlendirilir, ne zaman yönlendirilmez
//!
//! Hata yanıtı normalde `redirect_uri`'ye yönlendirilerek verilir. Ama
//! `redirect_uri`'nin **kendisi** doğrulanamadıysa oraya yönlendirmek, sunucuyu
//! bir **açık yönlendiriciye** çevirir: saldırgan kendi adresini yazar, kurbanı
//! Argus üzerinden kendi sitesine taşır ve bunu meşru bir kimlik sağlayıcı
//! alan adı altında yapar. RFC 9700 bunu açıkça yasaklar.
//!
//! Bu yüzden sonuç üç değerlidir ve ayrım tip düzeyindedir:
//!
//! | Sonuç | Ne yapılır |
//! |---|---|
//! | [`AuthorizeOutcome::Fatal`] | **Yönlendirme YOK.** Hata sayfası gösterilir |
//! | [`AuthorizeOutcome::RedirectError`] | `redirect_uri` doğrulandı; hata oraya yönlendirilir |
//! | [`AuthorizeOutcome::Proceed`] | Kullanıcı kimlik doğrulamasına geçilir |

use crate::id::ClientId;
use crate::pkce::{CodeChallenge, CodeChallengeMethod};
use crate::redirect_uri::RedirectUri;

/// Yetkilendirme endpoint'ine gelen istek.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    /// `response_type` — yalnızca `code` desteklenir.
    pub response_type: String,
    /// `client_id`.
    pub client_id: String,
    /// `redirect_uri`.
    pub redirect_uri: Option<String>,
    /// `state` — istemciye geri verilir.
    pub state: Option<String>,
    /// `code_challenge`.
    pub code_challenge: Option<String>,
    /// `code_challenge_method`.
    pub code_challenge_method: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
}

/// Kayıtlı istemcinin yetkilendirme için gereken bilgisi.
#[derive(Debug, Clone)]
pub struct RegisteredClient {
    /// Kimlik.
    pub client_id: ClientId,
    /// Kayıtlı yönlendirme adresleri.
    pub redirect_uris: Vec<RedirectUri>,
}

/// Yönlendirilemeyecek hatalar.
///
/// Bunların **hiçbiri** `redirect_uri`'ye yönlendirilmez.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizeFatal {
    /// `client_id` eksik veya biçimsiz.
    #[error("client_id is missing or malformed")]
    UnknownClient,

    /// `redirect_uri` verilmedi ve istemcinin tek bir kayıtlı adresi yok.
    ///
    /// RFC 6749 §3.1.2.3 tek kayıtlı adres varsa atlanmasına izin verir; birden
    /// fazlaysa istek belirsizdir ve tahmin edilemez.
    #[error("redirect_uri is required when the client has multiple registered URIs")]
    AmbiguousRedirectUri,

    /// Sunulan `redirect_uri` kayıtlı değil.
    ///
    /// **Asıl açık yönlendirici koruması burasıdır.**
    #[error("redirect_uri is not registered for this client")]
    UnregisteredRedirectUri,
}

/// Yönlendirilerek verilebilecek hatalar (RFC 6749 §4.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeError {
    /// `response_type` desteklenmiyor.
    UnsupportedResponseType,
    /// Zorunlu parametre eksik veya geçersiz.
    InvalidRequest,
}

impl AuthorizeError {
    /// Yönlendirme sorgusuna yazılacak `error` değeri.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidRequest => "invalid_request",
        }
    }
}

/// Doğrulamanın sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// **Yönlendirme yapılmaz.** Kullanıcıya hata gösterilir.
    Fatal(AuthorizeFatal),

    /// `redirect_uri` doğrulandı; hata oraya yönlendirilebilir.
    RedirectError {
        /// Doğrulanmış adres.
        redirect_uri: RedirectUri,
        /// Hata kodu.
        error: AuthorizeError,
        /// İstemcinin `state` değeri, aynen geri verilir.
        state: Option<String>,
    },

    /// İstek geçerli; kullanıcı kimlik doğrulamasına geçilebilir.
    Proceed {
        /// Doğrulanmış adres.
        redirect_uri: RedirectUri,
        /// Doğrulanmış PKCE challenge.
        challenge: CodeChallenge,
        /// İstemcinin `state` değeri.
        state: Option<String>,
        /// İstenen kapsam.
        scope: Option<String>,
    },
}

/// Yetkilendirme isteğini doğrular.
///
/// Saf fonksiyon. Kullanıcıyı doğrulamaz, kod üretmez — yalnızca isteğin
/// geçerliliğine ve nereye yanıt verilebileceğine karar verir.
///
/// # Sıra neden bu
///
/// `redirect_uri` **her şeyden önce** doğrulanır. Diğer hataları yönlendirerek
/// verebilmek için önce nereye yönlendirileceğinin güvenli olduğu bilinmelidir.
#[must_use]
pub fn validate(request: &AuthorizeRequest, client: Option<&RegisteredClient>) -> AuthorizeOutcome {
    // 1. İstemci tanınmıyorsa hiçbir şey yapılamaz: kayıtlı adres listesi de yok,
    //    dolayısıyla güvenli bir yönlendirme hedefi de yok.
    let Some(client) = client else {
        return AuthorizeOutcome::Fatal(AuthorizeFatal::UnknownClient);
    };

    // 2. Yönlendirme hedefini çöz ve DOĞRULA.
    let redirect_uri = match request.redirect_uri.as_deref() {
        Some(presented) => {
            let matched = client
                .redirect_uris
                .iter()
                .find(|registered| registered.match_presented(presented).is_some());
            match matched {
                Some(uri) => uri.clone(),
                None => {
                    return AuthorizeOutcome::Fatal(AuthorizeFatal::UnregisteredRedirectUri);
                }
            }
        }
        None => {
            // RFC 6749 §3.1.2.3: tek kayıtlı adres varsa atlanabilir.
            match client.redirect_uris.as_slice() {
                [only] => only.clone(),
                _ => return AuthorizeOutcome::Fatal(AuthorizeFatal::AmbiguousRedirectUri),
            }
        }
    };

    let state = request.state.clone();
    let redirect_error = |error| AuthorizeOutcome::RedirectError {
        redirect_uri: redirect_uri.clone(),
        error,
        state: state.clone(),
    };

    // 3. Buradan sonrası yönlendirilebilir.
    // OAuth 2.1: yalnızca `code`. `token` ve `id_token` (implicit) yok.
    if request.response_type != "code" {
        return redirect_error(AuthorizeError::UnsupportedResponseType);
    }

    // PKCE zorunlu (OAuth 2.1, RFC 9700).
    let (Some(challenge_value), Some(method_value)) = (
        request.code_challenge.as_deref(),
        request.code_challenge_method.as_deref(),
    ) else {
        return redirect_error(AuthorizeError::InvalidRequest);
    };

    let Ok(method) = CodeChallengeMethod::parse(method_value) else {
        return redirect_error(AuthorizeError::InvalidRequest);
    };

    let Ok(challenge) = CodeChallenge::parse(method, challenge_value) else {
        return redirect_error(AuthorizeError::InvalidRequest);
    };

    AuthorizeOutcome::Proceed {
        redirect_uri,
        challenge,
        state,
        scope: request.scope.clone(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        AuthorizeError, AuthorizeFatal, AuthorizeOutcome, AuthorizeRequest, RegisteredClient,
        validate,
    };
    use crate::id::ClientId;
    use crate::redirect_uri::RedirectUri;

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn uri(s: &str) -> RedirectUri {
        RedirectUri::register(s).expect("uri")
    }

    fn client() -> RegisteredClient {
        RegisteredClient {
            client_id: ClientId::new("acme-web").expect("client"),
            redirect_uris: vec![uri("https://app.example.com/cb")],
        }
    }

    fn request() -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: "code".to_owned(),
            client_id: "acme-web".to_owned(),
            redirect_uri: Some("https://app.example.com/cb".to_owned()),
            state: Some("xyz".to_owned()),
            code_challenge: Some(CHALLENGE.to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: None,
        }
    }

    #[test]
    fn a_valid_request_proceeds() {
        assert!(matches!(
            validate(&request(), Some(&client())),
            AuthorizeOutcome::Proceed { .. }
        ));
    }

    /// Bilinmeyen istemcide yönlendirilebilecek güvenli bir hedef yoktur.
    #[test]
    fn unknown_client_is_fatal() {
        assert_eq!(
            validate(&request(), None),
            AuthorizeOutcome::Fatal(AuthorizeFatal::UnknownClient)
        );
    }

    /// **Açık yönlendirici koruması.** Kayıtsız bir adrese hata yönlendirmesi
    /// yapmak, saldırganın kurbanı Argus üzerinden kendi sitesine taşımasıdır.
    #[test]
    fn unregistered_redirect_uri_is_fatal_and_never_redirects() {
        let mut r = request();
        r.redirect_uri = Some("https://evil.test/steal".to_owned());

        let outcome = validate(&r, Some(&client()));
        assert_eq!(
            outcome,
            AuthorizeOutcome::Fatal(AuthorizeFatal::UnregisteredRedirectUri)
        );
        assert!(
            !matches!(outcome, AuthorizeOutcome::RedirectError { .. }),
            "an unregistered URI must never become a redirect target"
        );
    }

    /// Yakın ama farklı adresler de reddedilir (authentik CVE-2024-52289 sınıfı).
    #[test]
    fn near_miss_redirect_uris_are_rejected() {
        for evil in [
            "https://app.example.com/cb/extra",
            "https://app0example.com/cb",
            "https://app.example.com.evil.test/cb",
        ] {
            let mut r = request();
            r.redirect_uri = Some(evil.to_owned());
            assert_eq!(
                validate(&r, Some(&client())),
                AuthorizeOutcome::Fatal(AuthorizeFatal::UnregisteredRedirectUri),
                "accepted: {evil}"
            );
        }
    }

    /// RFC 6749 §3.1.2.3: tek kayıtlı adres varsa `redirect_uri` atlanabilir.
    #[test]
    fn redirect_uri_may_be_omitted_when_exactly_one_is_registered() {
        let mut r = request();
        r.redirect_uri = None;
        assert!(matches!(
            validate(&r, Some(&client())),
            AuthorizeOutcome::Proceed { .. }
        ));
    }

    /// Birden fazla adres varsa atlamak belirsizdir; tahmin edilmez.
    #[test]
    fn omitting_redirect_uri_is_fatal_when_several_are_registered() {
        let c = RegisteredClient {
            redirect_uris: vec![
                uri("https://app.example.com/cb"),
                uri("https://app.example.com/cb2"),
            ],
            ..client()
        };
        let mut r = request();
        r.redirect_uri = None;
        assert_eq!(
            validate(&r, Some(&c)),
            AuthorizeOutcome::Fatal(AuthorizeFatal::AmbiguousRedirectUri)
        );
    }

    /// OAuth 2.1 implicit akışı kaldırdı.
    #[test]
    fn implicit_response_types_are_rejected_by_redirect() {
        for rt in ["token", "id_token", "code token"] {
            let mut r = request();
            r.response_type = rt.to_owned();
            match validate(&r, Some(&client())) {
                AuthorizeOutcome::RedirectError { error, state, .. } => {
                    assert_eq!(error, AuthorizeError::UnsupportedResponseType);
                    assert_eq!(state.as_deref(), Some("xyz"), "state must be echoed back");
                }
                other => panic!("expected a redirect error for {rt}, got {other:?}"),
            }
        }
    }

    /// PKCE zorunlu; eksikse veya `plain` ise istek geçersiz.
    #[test]
    fn pkce_is_mandatory_and_only_s256_is_accepted() {
        let cases = [
            (None, Some("S256")),
            (Some(CHALLENGE), None),
            (Some(CHALLENGE), Some("plain")),
            (Some("not-base64!"), Some("S256")),
        ];

        for (challenge, method) in cases {
            let mut r = request();
            r.code_challenge = challenge.map(ToOwned::to_owned);
            r.code_challenge_method = method.map(ToOwned::to_owned);

            match validate(&r, Some(&client())) {
                AuthorizeOutcome::RedirectError { error, .. } => {
                    assert_eq!(error, AuthorizeError::InvalidRequest);
                }
                other => {
                    panic!("expected invalid_request for {challenge:?}/{method:?}, got {other:?}")
                }
            }
        }
    }

    /// Loopback istisnası burada da geçerli (§1 #24 / RFC 8252 §7.3).
    #[test]
    fn loopback_port_variance_is_accepted() {
        let c = RegisteredClient {
            redirect_uris: vec![uri("http://127.0.0.1/callback")],
            ..client()
        };
        let mut r = request();
        r.redirect_uri = Some("http://127.0.0.1:51234/callback".to_owned());
        assert!(matches!(
            validate(&r, Some(&c)),
            AuthorizeOutcome::Proceed { .. }
        ));
    }
}
