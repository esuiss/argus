//! Authorization Server Metadata — RFC 8414 ve OIDC Discovery.

use serde::{Deserialize, Serialize};

/// `/.well-known/oauth-authorization-server` ve
/// `/.well-known/openid-configuration` gövdesi.
///
/// # Neden tek tip iki endpoint'e hizmet ediyor
///
/// §18: *"İki spec aynı issuer için FARKLI URL üretir. Path-based issuer
/// kullanacaksanız her ikisini de servis etmek zorundasınız."* Argus subdomain
/// tabanlı issuer seçtiği için (§1 #8) bu tuzağa düşmüyor, ama her iki yolu da
/// aynı gövdeyle yayınlıyor — istemcilerin hangisini deneyeceği belirsiz.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Issuer. Token'ların `iss` claim'iyle **birebir** aynı olmalı.
    pub issuer: String,
    /// Yetkilendirme endpoint'i.
    pub authorization_endpoint: String,
    /// Token endpoint'i.
    pub token_endpoint: String,
    /// `JWKS` URI.
    pub jwks_uri: String,

    /// Desteklenen yanıt tipleri.
    ///
    /// **Yalnızca `code`.** OAuth 2.1 implicit akışı kaldırdı; `token` ve
    /// `id_token` yanıt tipleri hiç desteklenmez (§4).
    pub response_types_supported: Vec<String>,

    /// Desteklenen grant tipleri.
    ///
    /// `password` (`ROPC`) **yok**: OAuth 2.1 onu kaldırdı ve kullanıcı parolasını
    /// istemciye vermek Argus'un tehdit modelinde kabul edilemez.
    pub grant_types_supported: Vec<String>,

    /// PKCE metotları.
    ///
    /// **Yalnızca `S256`.** `plain` `argus-core`'da tip düzeyinde temsil
    /// edilemiyor, dolayısıyla burada da ilan edilmez.
    pub code_challenge_methods_supported: Vec<String>,

    /// Token endpoint istemci kimlik doğrulama yöntemleri.
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// `id_token` imzalama algoritmaları.
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// `DPoP` imzalama algoritmaları (RFC 9449 §5.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    /// Desteklenen kapsamlar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// RFC 9207: yetkilendirme yanıtında `iss` döndürülüyor mu.
    ///
    /// **Daima `true`.** Mix-up saldırısı savunması ve §1 #8'in gün-1 kararı.
    pub authorization_response_iss_parameter_supported: bool,
}

impl AuthorizationServerMetadata {
    /// Bir issuer için Argus'un varsayılan metadata'sını üretir.
    ///
    /// Endpoint yolları issuer'a göre türetilir; issuer sondaki `/` olmadan
    /// verilmelidir.
    #[must_use]
    pub fn for_issuer(issuer: &str) -> Self {
        let issuer = issuer.trim_end_matches('/');
        Self {
            issuer: issuer.to_owned(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            response_types_supported: vec!["code".to_owned()],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
            ],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            token_endpoint_auth_methods_supported: vec![
                "private_key_jwt".to_owned(),
                "none".to_owned(),
            ],
            id_token_signing_alg_values_supported: vec!["ES256".to_owned()],
            dpop_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
            scopes_supported: Some(vec!["openid".to_owned()]),
            authorization_response_iss_parameter_supported: true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::AuthorizationServerMetadata;

    fn meta() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata::for_issuer("https://acme.argus.test")
    }

    /// OAuth 2.1: implicit akış YOK.
    #[test]
    fn only_the_code_response_type_is_advertised() {
        assert_eq!(meta().response_types_supported, ["code"]);
    }

    /// OAuth 2.1: ROPC (`password` grant) YOK.
    #[test]
    fn password_grant_is_not_advertised() {
        assert!(
            !meta()
                .grant_types_supported
                .contains(&"password".to_owned())
        );
    }

    /// `plain` PKCE `argus-core`'da temsil edilemiyor; burada da ilan edilmez.
    #[test]
    fn only_s256_pkce_is_advertised() {
        assert_eq!(meta().code_challenge_methods_supported, ["S256"]);
    }

    /// RFC 9207 mix-up savunması gün-1'de açık (§1 #8).
    #[test]
    fn iss_parameter_is_always_advertised() {
        assert!(meta().authorization_response_iss_parameter_supported);
    }

    /// Issuer, token'ların `iss` claim'iyle birebir eşleşmeli; sondaki `/`
    /// sessizce fark üretmemeli.
    #[test]
    fn trailing_slash_is_normalised() {
        let a = AuthorizationServerMetadata::for_issuer("https://acme.argus.test/");
        assert_eq!(a.issuer, "https://acme.argus.test");
        assert_eq!(a.token_endpoint, "https://acme.argus.test/token");
    }

    #[test]
    fn round_trips_through_json() {
        let json = serde_json::to_string(&meta()).unwrap();
        let back: AuthorizationServerMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta(), back);
    }
}
