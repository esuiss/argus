use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,

    pub authorization_servers: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    pub bearer_methods_supported: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    pub dpop_bound_access_tokens_required: bool,

    pub tls_client_certificate_bound_access_tokens: bool,
}

impl ProtectedResourceMetadata {
    #[must_use]
    pub fn new(resource: &str, issuer: &str) -> Self {
        Self {
            resource: resource.to_owned(),
            authorization_servers: vec![issuer.to_owned()],
            jwks_uri: None,
            scopes_supported: None,
            bearer_methods_supported: vec!["header".to_owned()],
            resource_name: None,
            dpop_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
            dpop_bound_access_tokens_required: false,
            tls_client_certificate_bound_access_tokens: false,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: Option<String>) -> Self {
        self.resource_name = name;
        self
    }

    #[must_use]
    pub fn with_scopes(mut self, scopes: Option<&str>) -> Self {
        self.scopes_supported = scopes.map(|s| {
            s.split(' ')
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect()
        });
        self
    }
}

#[must_use]
pub fn well_known_path(resource: &str) -> Option<String> {
    let rest = resource
        .strip_prefix("https://")
        .or_else(|| resource.strip_prefix("http://"))?;

    let path_start = rest.find('/').unwrap_or(rest.len());
    let path = rest.get(path_start..).unwrap_or_default();
    let path = path.split('?').next().unwrap_or_default();
    let path = path.trim_end_matches('/');

    Some(format!("/.well-known/oauth-protected-resource{path}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{ProtectedResourceMetadata, well_known_path};

    #[test]
    fn the_well_known_string_goes_between_the_host_and_the_path() {
        assert_eq!(
            well_known_path("https://mcp.example.com").as_deref(),
            Some("/.well-known/oauth-protected-resource")
        );
        assert_eq!(
            well_known_path("https://mcp.example.com/mcp").as_deref(),
            Some("/.well-known/oauth-protected-resource/mcp")
        );
        assert_eq!(
            well_known_path("https://example.com/public/mcp").as_deref(),
            Some("/.well-known/oauth-protected-resource/public/mcp")
        );
    }

    #[test]
    fn a_terminating_slash_is_removed_before_appending() {
        assert_eq!(
            well_known_path("https://mcp.example.com/").as_deref(),
            Some("/.well-known/oauth-protected-resource")
        );
        assert_eq!(
            well_known_path("https://mcp.example.com/mcp/").as_deref(),
            Some("/.well-known/oauth-protected-resource/mcp")
        );
    }

    #[test]
    fn a_port_does_not_leak_into_the_path() {
        assert_eq!(
            well_known_path("https://mcp.example.com:8443/mcp").as_deref(),
            Some("/.well-known/oauth-protected-resource/mcp")
        );
    }

    #[test]
    fn a_non_http_identifier_has_no_well_known_path() {
        assert!(well_known_path("urn:example:mcp").is_none());
    }

    #[test]
    fn mcp_requires_at_least_one_authorization_server() {
        let m = ProtectedResourceMetadata::new("https://mcp.example.com", "https://idp.test");
        assert_eq!(m.authorization_servers, ["https://idp.test"]);
        assert!(!m.authorization_servers.is_empty());
    }

    #[test]
    fn mcp_forbids_the_query_bearer_method() {
        let m = ProtectedResourceMetadata::new("https://mcp.example.com", "https://idp.test");
        assert_eq!(m.bearer_methods_supported, ["header"]);
        assert!(!m.bearer_methods_supported.contains(&"query".to_owned()));
    }

    #[test]
    fn scopes_are_split_on_spaces_and_omitted_when_absent() {
        let m = ProtectedResourceMetadata::new("https://mcp.example.com", "https://idp.test")
            .with_scopes(Some("read write"));
        assert_eq!(
            m.scopes_supported.as_deref(),
            Some(["read".to_owned(), "write".to_owned()].as_slice())
        );

        let bare = ProtectedResourceMetadata::new("https://mcp.example.com", "https://idp.test");
        let json = serde_json::to_string(&bare).unwrap();
        assert!(!json.contains("scopes_supported"));
    }

    #[test]
    fn the_resource_field_is_always_present() {
        let m = ProtectedResourceMetadata::new("https://mcp.example.com/mcp", "https://idp.test");
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains(r#""resource":"https://mcp.example.com/mcp""#));
    }
}
