use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,

    pub authorization_endpoint: String,

    pub token_endpoint: String,

    pub jwks_uri: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

    pub response_types_supported: Vec<String>,

    pub grant_types_supported: Vec<String>,

    pub code_challenge_methods_supported: Vec<String>,

    pub token_endpoint_auth_methods_supported: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    pub id_token_signing_alg_values_supported: Vec<String>,

    pub subject_types_supported: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    pub authorization_response_iss_parameter_supported: bool,

    pub client_id_metadata_document_supported: bool,
}

impl AuthorizationServerMetadata {
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
            client_id_metadata_document_supported: true,
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

    #[test]
    fn only_the_code_response_type_is_advertised() {
        assert_eq!(meta().response_types_supported, ["code"]);
    }

    #[test]
    fn password_grant_is_not_advertised() {
        assert!(
            !meta()
                .grant_types_supported
                .contains(&"password".to_owned())
        );
    }

    #[test]
    fn only_s256_pkce_is_advertised() {
        assert_eq!(meta().code_challenge_methods_supported, ["S256"]);
    }

    #[test]
    fn iss_parameter_is_always_advertised() {
        assert!(meta().authorization_response_iss_parameter_supported);
    }

    #[test]
    fn cimd_support_is_advertised() {
        assert!(meta().client_id_metadata_document_supported);
        let json = serde_json::to_string(&meta()).unwrap();
        assert!(json.contains(r#""client_id_metadata_document_supported":true"#));
    }

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

    #[test]
    fn subject_types_are_advertised() {
        assert_eq!(meta().subject_types_supported, ["public"]);
    }

    #[test]
    fn pairwise_subjects_are_not_claimed() {
        assert!(
            !meta()
                .subject_types_supported
                .contains(&"pairwise".to_owned())
        );
    }

    #[test]
    fn userinfo_endpoint_is_derived_from_the_issuer() {
        assert_eq!(
            meta().userinfo_endpoint.as_deref(),
            Some("https://acme.argus.test/userinfo")
        );
    }

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
