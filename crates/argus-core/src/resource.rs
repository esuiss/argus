use core::fmt;

use url::Url;

use crate::error::ResourceUriError;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ResourceUri {
    canonical: String,
}

impl ResourceUri {
    pub fn parse(raw: &str) -> Result<Self, ResourceUriError> {
        if raw.is_empty() {
            return Err(ResourceUriError::NotAbsolute);
        }

        let parsed = Url::parse(raw).map_err(|_| ResourceUriError::NotAbsolute)?;

        if !parsed.has_host() {
            return Err(ResourceUriError::NotAbsolute);
        }

        if parsed.fragment().is_some() {
            return Err(ResourceUriError::HasFragment);
        }

        let scheme = parsed.scheme();
        if scheme != "https" && scheme != "http" {
            return Err(ResourceUriError::DisallowedScheme {
                scheme: scheme.to_owned(),
            });
        }

        let mut canonical = String::with_capacity(raw.len());
        canonical.push_str(scheme);
        canonical.push_str("://");
        canonical.push_str(parsed.host_str().unwrap_or_default());
        if let Some(port) = parsed.port() {
            canonical.push(':');
            canonical.push_str(&port.to_string());
        }

        let path = parsed.path().trim_end_matches('/');
        canonical.push_str(path);

        if let Some(query) = parsed.query() {
            canonical.push('?');
            canonical.push_str(query);
        }

        Ok(Self { canonical })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl fmt::Debug for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResourceUri({})", self.canonical)
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::ResourceUri;
    use crate::error::ResourceUriError;

    fn canonical(raw: &str) -> String {
        ResourceUri::parse(raw).expect("valid").as_str().to_owned()
    }

    #[test]
    fn valid_mcp_identifiers_are_accepted() {
        for raw in [
            "https://mcp.example.com/mcp",
            "https://mcp.example.com",
            "https://mcp.example.com:8443",
            "https://mcp.example.com/server/mcp",
        ] {
            assert!(ResourceUri::parse(raw).is_ok(), "rejected {raw}");
        }
    }

    #[test]
    fn a_fragment_is_refused() {
        assert_eq!(
            ResourceUri::parse("https://mcp.example.com#fragment").unwrap_err(),
            ResourceUriError::HasFragment
        );
    }

    #[test]
    fn a_bare_host_is_refused() {
        assert_eq!(
            ResourceUri::parse("mcp.example.com").unwrap_err(),
            ResourceUriError::NotAbsolute
        );
        assert_eq!(
            ResourceUri::parse("").unwrap_err(),
            ResourceUriError::NotAbsolute
        );
    }

    #[test]
    fn non_http_schemes_are_refused() {
        for raw in ["ftp://x.test/mcp", "urn:example:mcp", "file:///etc/passwd"] {
            assert!(ResourceUri::parse(raw).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn a_trailing_slash_is_removed() {
        assert_eq!(
            canonical("https://mcp.example.com/mcp/"),
            "https://mcp.example.com/mcp"
        );
        assert_eq!(
            canonical("https://mcp.example.com/"),
            "https://mcp.example.com"
        );
    }

    #[test]
    fn scheme_and_host_are_lowercased_but_the_path_is_not() {
        assert_eq!(
            canonical("HTTPS://MCP.Example.COM/MCP"),
            "https://mcp.example.com/MCP"
        );
    }

    #[test]
    fn the_default_port_is_not_written_out() {
        assert_eq!(
            canonical("https://mcp.example.com:443/mcp"),
            "https://mcp.example.com/mcp"
        );
        assert_eq!(
            canonical("https://mcp.example.com:8443/mcp"),
            "https://mcp.example.com:8443/mcp"
        );
    }

    #[test]
    fn a_query_is_preserved() {
        assert_eq!(
            canonical("https://mcp.example.com/mcp?tenant=a"),
            "https://mcp.example.com/mcp?tenant=a"
        );
    }

    #[test]
    fn equivalent_spellings_canonicalise_to_the_same_value() {
        let forms = [
            "https://mcp.example.com/mcp",
            "https://mcp.example.com/mcp/",
            "HTTPS://MCP.EXAMPLE.COM/mcp",
            "https://mcp.example.com:443/mcp",
        ];
        let first = canonical(forms[0]);
        for form in forms {
            assert_eq!(canonical(form), first, "{form} did not canonicalise");
        }
    }
}
