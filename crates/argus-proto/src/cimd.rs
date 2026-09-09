use argus_core::cimd::ClientIdUrl;
use serde::{Deserialize, Serialize};

pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdMetadataDocument {
    pub client_id: String,

    pub client_name: String,

    pub redirect_uris: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocumentError {
    #[error("the document is not valid JSON or is missing a required member")]
    Malformed,

    #[error("client_id does not match the URL the document was fetched from")]
    ClientIdMismatch,

    #[error("the document declares no redirect_uris")]
    NoRedirectUris,

    #[error("client_name must not be empty")]
    NoClientName,

    #[error("symmetric client authentication is not possible with CIMD")]
    SymmetricAuthMethod,

    #[error("the document carries secret material, which CIMD forbids")]
    CarriesSecretMaterial,

    #[error("a URL in the document uses a scheme this server will not fetch or render")]
    DisallowedUrlScheme,
}

const FORBIDDEN_MEMBERS: &[&str] = &[
    "client_secret",
    "client_secret_expires_at",
    "registration_access_token",
    "registration_client_uri",
];

const SYMMETRIC_AUTH_METHODS: &[&str] = &[
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
];

pub fn parse_and_validate(
    body: &str,
    fetched_from: &ClientIdUrl,
) -> Result<ClientIdMetadataDocument, DocumentError> {
    let raw: serde_json::Value =
        serde_json::from_str(body).map_err(|_| DocumentError::Malformed)?;

    let Some(object) = raw.as_object() else {
        return Err(DocumentError::Malformed);
    };

    for member in FORBIDDEN_MEMBERS {
        if object.contains_key(*member) {
            return Err(DocumentError::CarriesSecretMaterial);
        }
    }

    if let Some(jwks) = object.get("jwks")
        && contains_private_key_material(jwks)
    {
        return Err(DocumentError::CarriesSecretMaterial);
    }

    let document: ClientIdMetadataDocument =
        serde_json::from_value(raw.clone()).map_err(|_| DocumentError::Malformed)?;

    if !fetched_from.matches(&document.client_id) {
        return Err(DocumentError::ClientIdMismatch);
    }

    if document.client_name.trim().is_empty() {
        return Err(DocumentError::NoClientName);
    }

    if document.redirect_uris.is_empty() {
        return Err(DocumentError::NoRedirectUris);
    }

    if let Some(method) = document.token_endpoint_auth_method.as_deref()
        && SYMMETRIC_AUTH_METHODS.contains(&method)
    {
        return Err(DocumentError::SymmetricAuthMethod);
    }

    for url in [
        document.jwks_uri.as_deref(),
        document.logo_uri.as_deref(),
        document.policy_uri.as_deref(),
        document.tos_uri.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !url.starts_with("https://") {
            return Err(DocumentError::DisallowedUrlScheme);
        }
    }

    Ok(document)
}

fn contains_private_key_material(jwks: &serde_json::Value) -> bool {
    let Some(keys) = jwks.get("keys").and_then(serde_json::Value::as_array) else {
        return false;
    };
    keys.iter().any(|key| {
        ["d", "p", "q", "dp", "dq", "qi", "k"]
            .iter()
            .any(|member| key.get(*member).is_some())
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{DocumentError, MAX_DOCUMENT_BYTES, parse_and_validate};
    use argus_core::cimd::ClientIdUrl;

    const URL: &str = "https://example.com/client.json";

    fn url() -> ClientIdUrl {
        ClientIdUrl::parse(URL).expect("url")
    }

    fn good() -> String {
        format!(
            r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"]}}"#
        )
    }

    #[test]
    fn a_minimal_valid_document_is_accepted() {
        let doc = parse_and_validate(&good(), &url()).expect("valid");
        assert_eq!(doc.client_id, URL);
        assert_eq!(doc.client_name, "Demo");
        assert_eq!(doc.redirect_uris, ["https://example.com/cb"]);
    }

    #[test]
    fn client_id_must_match_the_fetched_url_exactly() {
        for other in [
            "https://example.com/client",
            "https://example.com:443/client.json",
            "https://EXAMPLE.com/client.json",
            "https://evil.test/client.json",
        ] {
            let body = format!(
                r#"{{"client_id":"{other}","client_name":"Demo","redirect_uris":["https://example.com/cb"]}}"#
            );
            assert_eq!(
                parse_and_validate(&body, &url()).unwrap_err(),
                DocumentError::ClientIdMismatch,
                "accepted {other}"
            );
        }
    }

    #[test]
    fn mcp_requires_client_name_and_redirect_uris() {
        let no_name = format!(
            r#"{{"client_id":"{URL}","client_name":"","redirect_uris":["https://example.com/cb"]}}"#
        );
        assert_eq!(
            parse_and_validate(&no_name, &url()).unwrap_err(),
            DocumentError::NoClientName
        );

        let no_uris = format!(r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":[]}}"#);
        assert_eq!(
            parse_and_validate(&no_uris, &url()).unwrap_err(),
            DocumentError::NoRedirectUris
        );

        let missing = format!(r#"{{"client_id":"{URL}","client_name":"Demo"}}"#);
        assert_eq!(
            parse_and_validate(&missing, &url()).unwrap_err(),
            DocumentError::Malformed
        );
    }

    #[test]
    fn symmetric_client_authentication_is_refused() {
        for method in [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
        ] {
            let body = format!(
                r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"{method}"}}"#
            );
            assert_eq!(
                parse_and_validate(&body, &url()).unwrap_err(),
                DocumentError::SymmetricAuthMethod,
                "accepted {method}"
            );
        }
    }

    #[test]
    fn private_key_jwt_and_none_are_accepted() {
        for method in ["private_key_jwt", "none"] {
            let body = format!(
                r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"{method}"}}"#
            );
            assert!(
                parse_and_validate(&body, &url()).is_ok(),
                "rejected {method}"
            );
        }
    }

    #[test]
    fn secret_members_are_refused() {
        for member in [
            r#""client_secret":"s""#,
            r#""client_secret_expires_at":0"#,
            r#""registration_access_token":"t""#,
            r#""registration_client_uri":"https://example.com/r""#,
        ] {
            let body = format!(
                r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"],{member}}}"#
            );
            assert_eq!(
                parse_and_validate(&body, &url()).unwrap_err(),
                DocumentError::CarriesSecretMaterial,
                "accepted {member}"
            );
        }
    }

    #[test]
    fn a_jwks_carrying_a_private_component_is_refused() {
        let body = format!(
            r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"],"jwks":{{"keys":[{{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"SECRET"}}]}}}}"#
        );
        assert_eq!(
            parse_and_validate(&body, &url()).unwrap_err(),
            DocumentError::CarriesSecretMaterial
        );
    }

    #[test]
    fn a_public_jwks_is_accepted() {
        let body = format!(
            r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"],"jwks":{{"keys":[{{"kty":"EC","crv":"P-256","x":"a","y":"b"}}]}}}}"#
        );
        assert!(parse_and_validate(&body, &url()).is_ok());
    }

    #[test]
    fn document_urls_must_be_https() {
        for field in ["jwks_uri", "logo_uri", "policy_uri", "tos_uri"] {
            for value in [
                "http://example.com/x",
                "javascript:alert(1)",
                "file:///etc/passwd",
                "data:text/html,x",
            ] {
                let body = format!(
                    r#"{{"client_id":"{URL}","client_name":"Demo","redirect_uris":["https://example.com/cb"],"{field}":"{value}"}}"#
                );
                assert_eq!(
                    parse_and_validate(&body, &url()).unwrap_err(),
                    DocumentError::DisallowedUrlScheme,
                    "accepted {field}={value}"
                );
            }
        }
    }

    #[test]
    fn malformed_json_is_refused() {
        for body in ["", "not json", "[]", "\"a string\"", "{"] {
            assert_eq!(
                parse_and_validate(body, &url()).unwrap_err(),
                DocumentError::Malformed,
                "accepted {body:?}"
            );
        }
    }

    #[test]
    fn the_read_limit_is_the_five_kilobytes_the_draft_recommends() {
        assert_eq!(MAX_DOCUMENT_BYTES, 5120);
    }
}
