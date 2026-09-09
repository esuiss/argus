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

    /// `UserInfo` endpoint'i — OIDC Discovery §3'te `RECOMMENDED`.
    ///
    /// İlan edilmezse istemciler `id_token` dışında talep alamayacaklarını
    /// varsayar; ilan edilip çalışmazsa daha kötüsü olur. Bkz. §5.3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

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
    ///
    /// **`client_secret_*` YOK.** §12529: *"Paylaşılan secret yok — confidential
    /// client yolu `private_key_jwt` + yayımlanmış JWKS"*. Simetrik bir sır iki
    /// tarafta birden durur ve sızıntının hangi taraftan olduğu anlaşılamaz.
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// `private_key_jwt` assertion'larının imza algoritmaları.
    ///
    /// `RFC` 7523 kullanan bir istemcinin hangi algoritmayla imzalayacağını
    /// bilmesi gerekir; ilan edilmezse istemci tahmin eder ve `RS256` üretir.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// `id_token` imzalama algoritmaları.
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// Desteklenen özne tipleri — OIDC Discovery §3'te **zorunlu**.
    ///
    /// `public`: `sub` tüm istemciler için aynıdır. `pairwise` (istemci başına
    /// farklı `sub`) ilan EDİLMİYOR, çünkü uygulanmadı; ilan edip `public`
    /// davranmak, istemcileri sağlanmayan bir gizlilik garantisine güvendirirdi.
    pub subject_types_supported: Vec<String>,

    /// `UserInfo` yanıtının imzalama algoritmaları.
    ///
    /// `none`: yanıt düz `JSON` döner. `TLS` altında OIDC Core §5.3.2 bunu
    /// kabul eder; imzalı `JWT` yanıtı henüz yok ve olmayan bir şey ilan
    /// edilmez.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    /// Döndürülebilecek talepler — OIDC Discovery §3'te `RECOMMENDED`.
    ///
    /// Liste kısa çünkü `profile`/`email` talepleri §1 #17 gereği kullanıcı
    /// başına `DEK` ile şifreli ve rıza kaydı henüz yok.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,

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
            userinfo_endpoint: Some(format!("{issuer}/userinfo")),
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
            token_endpoint_auth_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
            id_token_signing_alg_values_supported: vec!["ES256".to_owned()],
            subject_types_supported: vec!["public".to_owned()],
            userinfo_signing_alg_values_supported: Some(vec!["none".to_owned()]),
            claims_supported: Some(vec![
                "sub".to_owned(),
                "iss".to_owned(),
                "aud".to_owned(),
                "exp".to_owned(),
                "iat".to_owned(),
                "nonce".to_owned(),
                "auth_time".to_owned(),
                "at_hash".to_owned(),
            ]),
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

    /// Paylaşılan sır yolu ilan EDİLMEMELİ (§12529); ilan etmek, uygulanmayan
    /// bir yolu istemcilere önermek olurdu.
    #[test]
    fn no_shared_secret_client_auth_is_advertised() {
        let m = meta();
        for method in [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
        ] {
            assert!(
                !m.token_endpoint_auth_methods_supported
                    .contains(&method.to_owned()),
                "must not advertise {method}"
            );
        }
    }

    /// `private_key_jwt` ilan ediliyorsa imza algoritması da ilan edilmeli,
    /// yoksa istemci tahmin eder.
    #[test]
    fn the_assertion_signing_algorithm_is_advertised() {
        let m = meta();
        assert!(
            m.token_endpoint_auth_methods_supported
                .contains(&"private_key_jwt".to_owned())
        );
        assert_eq!(
            m.token_endpoint_auth_signing_alg_values_supported
                .as_deref(),
            Some(["ES256".to_owned()].as_slice())
        );
    }

    /// OIDC Discovery §3 `subject_types_supported`'ı zorunlu tutar; eksikse
    /// uyumluluk paketi metadata adımında düşer.
    #[test]
    fn subject_types_are_advertised() {
        assert_eq!(meta().subject_types_supported, ["public"]);
    }

    /// Uygulanmamış bir gizlilik garantisi ilan edilmemeli.
    #[test]
    fn pairwise_subjects_are_not_claimed() {
        assert!(
            !meta()
                .subject_types_supported
                .contains(&"pairwise".to_owned())
        );
    }

    /// `id_token` üretiliyorsa `UserInfo` de bulunabilir olmalı; ikisi OIDC
    /// Core'un aynı sözleşmesinin parçası.
    #[test]
    fn userinfo_endpoint_is_derived_from_the_issuer() {
        assert_eq!(
            meta().userinfo_endpoint.as_deref(),
            Some("https://acme.argus.test/userinfo")
        );
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
