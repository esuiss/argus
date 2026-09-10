use core::fmt;

use url::Url;

use crate::error::ClientIdUrlError;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientIdUrl {
    raw: String,
    parsed: Url,
}

impl ClientIdUrl {
    pub fn parse(raw: &str) -> Result<Self, ClientIdUrlError> {
        let parsed = Url::parse(raw).map_err(|_| ClientIdUrlError::NotAUrl)?;

        if parsed.scheme() != "https" {
            return Err(ClientIdUrlError::NotHttps);
        }

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ClientIdUrlError::HasUserinfo);
        }

        if parsed.fragment().is_some() {
            return Err(ClientIdUrlError::HasFragment);
        }

        if raw_path(raw).split('/').any(|s| s == "." || s == "..") {
            return Err(ClientIdUrlError::DottedPathSegment);
        }

        let path = parsed.path();
        if path.is_empty() || path == "/" {
            return Err(ClientIdUrlError::NoPath);
        }

        match parsed.host() {
            Some(url::Host::Domain(name)) => {
                if name.eq_ignore_ascii_case("localhost") {
                    return Err(ClientIdUrlError::NotRoutable);
                }
            }
            Some(_) => return Err(ClientIdUrlError::NotRoutable),
            None => return Err(ClientIdUrlError::NotAUrl),
        }

        Ok(Self {
            raw: raw.to_owned(),
            parsed,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub fn host(&self) -> &str {
        self.parsed.host_str().unwrap_or_default()
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.parsed.port().unwrap_or(443)
    }

    #[must_use]
    pub fn request_target(&self) -> String {
        match self.parsed.query() {
            Some(query) => format!("{}?{}", self.parsed.path(), query),
            None => self.parsed.path().to_owned(),
        }
    }

    #[must_use]
    pub fn matches(&self, other: &str) -> bool {
        self.raw == other
    }
}

impl fmt::Debug for ClientIdUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientIdUrl({})", self.raw)
    }
}

impl fmt::Display for ClientIdUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

fn raw_path(raw: &str) -> &str {
    let rest = raw.strip_prefix("https://").unwrap_or(raw);
    let after_authority = rest
        .find('/')
        .map_or("", |i| rest.get(i..).unwrap_or_default());
    after_authority.split(['?', '#']).next().unwrap_or_default()
}

#[must_use]
// §14: CIMD, dinamik istemci kaydının (RFC 7591) yerini alır — client_id bir
// URL'dir ve metadata oradan çekilir. OIDF conformance'ın DCR isteyen planı bu
// yüzden geçilemiyor; mimari onu bilinçli olarak değiştirdi.
pub fn looks_like_a_url(client_id: &str) -> bool {
    client_id.starts_with("https://") || client_id.starts_with("http://")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{ClientIdUrl, looks_like_a_url};
    use crate::error::ClientIdUrlError;

    #[test]
    fn a_well_formed_identifier_is_accepted() {
        for raw in [
            "https://example.com/client.json",
            "https://example.com/client",
            "https://example.com:8443/client",
            "https://sub.example.com/apps/mcp/client",
        ] {
            assert!(ClientIdUrl::parse(raw).is_ok(), "rejected {raw}");
        }
    }

    #[test]
    fn https_is_mandatory() {
        assert_eq!(
            ClientIdUrl::parse("http://example.com/client").unwrap_err(),
            ClientIdUrlError::NotHttps
        );
    }

    #[test]
    fn a_path_component_is_mandatory() {
        assert_eq!(
            ClientIdUrl::parse("https://example.com").unwrap_err(),
            ClientIdUrlError::NoPath
        );
        assert_eq!(
            ClientIdUrl::parse("https://example.com/").unwrap_err(),
            ClientIdUrlError::NoPath
        );
    }

    #[test]
    fn userinfo_is_refused() {
        for raw in [
            "https://user@example.com/client",
            "https://user:pass@example.com/client",
        ] {
            assert_eq!(
                ClientIdUrl::parse(raw).unwrap_err(),
                ClientIdUrlError::HasUserinfo,
                "accepted {raw}"
            );
        }
    }

    #[test]
    fn a_fragment_is_refused() {
        assert_eq!(
            ClientIdUrl::parse("https://example.com/client#x").unwrap_err(),
            ClientIdUrlError::HasFragment
        );
    }

    #[test]
    fn dotted_path_segments_are_refused() {
        for raw in [
            "https://example.com/./client",
            "https://example.com/a/../client",
            "https://example.com/..",
        ] {
            assert_eq!(
                ClientIdUrl::parse(raw).unwrap_err(),
                ClientIdUrlError::DottedPathSegment,
                "accepted {raw}"
            );
        }
    }

    #[test]
    fn localhost_and_bare_addresses_cannot_be_client_identifiers() {
        for raw in [
            "https://localhost/client",
            "https://127.0.0.1/client",
            "https://[::1]/client",
            "https://192.168.1.5/client",
        ] {
            assert_eq!(
                ClientIdUrl::parse(raw).unwrap_err(),
                ClientIdUrlError::NotRoutable,
                "accepted {raw}"
            );
        }
    }

    #[test]
    fn comparison_is_simple_string_equality_with_no_port_normalisation() {
        let id = ClientIdUrl::parse("https://example.com/client").expect("url");
        assert!(id.matches("https://example.com/client"));
        assert!(!id.matches("https://example.com:443/client"));
        assert!(!id.matches("https://example.com/client/"));
        assert!(!id.matches("HTTPS://EXAMPLE.COM/client"));
    }

    #[test]
    fn the_request_target_keeps_the_query() {
        let id = ClientIdUrl::parse("https://example.com/client?v=2").expect("url");
        assert_eq!(id.request_target(), "/client?v=2");
        assert_eq!(id.host(), "example.com");
        assert_eq!(id.port(), 443);
    }

    #[test]
    fn an_explicit_port_is_carried_through() {
        let id = ClientIdUrl::parse("https://example.com:8443/client").expect("url");
        assert_eq!(id.port(), 8443);
    }

    #[test]
    fn only_url_shaped_client_ids_trigger_the_cimd_path() {
        assert!(looks_like_a_url("https://example.com/client"));
        assert!(looks_like_a_url("http://example.com/client"));
        assert!(!looks_like_a_url("demo-client"));
        assert!(!looks_like_a_url("urn:example:client"));
    }
}
