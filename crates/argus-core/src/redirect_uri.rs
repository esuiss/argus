use core::fmt;

use url::{Host, Url};

use crate::error::RedirectUriError;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RedirectUri {
    parsed: Url,

    raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectUriMatch {
    Exact,

    LoopbackPortIgnored,
}

impl RedirectUri {
    pub fn register(raw: impl Into<String>) -> Result<Self, RedirectUriError> {
        let raw = raw.into();

        if raw.contains('*') {
            return Err(RedirectUriError::WildcardNotSupported);
        }

        let parsed = Url::parse(&raw).map_err(|_| RedirectUriError::NotAbsolute)?;

        if parsed.fragment().is_some() {
            return Err(RedirectUriError::HasFragment);
        }

        let scheme = parsed.scheme().to_owned();
        match scheme.as_str() {
            "https" => {}
            "http" => {
                let loopback = match parsed.host() {
                    Some(Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(Host::Ipv6(ip)) => ip.is_loopback(),
                    Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
                    None => false,
                };
                if !loopback {
                    return Err(RedirectUriError::InsecureHttpHost);
                }
            }
            other if other.contains('.') => {}
            other => {
                return Err(RedirectUriError::DisallowedScheme {
                    scheme: other.to_owned(),
                });
            }
        }

        Ok(Self { parsed, raw })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub fn is_loopback(&self) -> bool {
        if self.parsed.scheme() != "http" {
            return false;
        }
        match self.parsed.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),

            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        }
    }

    #[must_use]
    // §1 #24: eşleştirme YALNIZCA exact string. Regex ve wildcard implemente
    // edilmez. Tek istisna loopback'te port'un yok sayılmasıdır (RFC 8252
    // §7.3) ve o istisna aşağıda, exact karşılaştırma başarısız olduktan sonra
    // başlar.
    pub fn match_presented(&self, presented: &str) -> Option<RedirectUriMatch> {
        if self.raw == presented {
            return Some(RedirectUriMatch::Exact);
        }

        if !self.is_loopback() {
            return None;
        }

        // Port'u yok saymak için URL'yi ayrıştırmak zorunlu; elle ayrıştırma
        // tam olarak authentik CVE-2024-52289'un sınıfıdır (Cargo.toml, url
        // bağımlılığının gerekçesi).
        let other = Url::parse(presented).ok()?;
        if other.fragment().is_some() {
            return None;
        }

        let same_scheme = self.parsed.scheme() == other.scheme();
        let same_host = self.parsed.host() == other.host();
        let same_path = self.parsed.path() == other.path();
        let same_query = self.parsed.query() == other.query();

        let other_is_loopback = match other.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        };

        if same_scheme && same_host && same_path && same_query && other_is_loopback {
            Some(RedirectUriMatch::LoopbackPortIgnored)
        } else {
            None
        }
    }
}

impl fmt::Debug for RedirectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedirectUri({:?})", self.raw)
    }
}

impl fmt::Display for RedirectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{RedirectUri, RedirectUriMatch};
    use crate::error::RedirectUriError;

    fn reg(s: &str) -> RedirectUri {
        RedirectUri::register(s).unwrap()
    }

    #[test]
    fn exact_match_wins() {
        let uri = reg("https://app.example.com/cb");
        assert_eq!(
            uri.match_presented("https://app.example.com/cb"),
            Some(RedirectUriMatch::Exact)
        );
    }

    #[test]
    fn regex_dot_does_not_match_arbitrary_character() {
        let uri = reg("https://app.example.com/cb");
        assert_eq!(uri.match_presented("https://app0example.com/cb"), None);
    }

    #[test]
    fn no_prefix_or_suffix_matching() {
        let uri = reg("https://app.example.com/cb");
        for evil in [
            "https://app.example.com/cb/extra",
            "https://app.example.com/cb?x=1",
            "https://app.example.com.evil.test/cb",
            "https://evil.test/https://app.example.com/cb",
            "https://app.example.com:8443/cb",
        ] {
            assert_eq!(uri.match_presented(evil), None, "matched: {evil}");
        }
    }

    #[test]
    fn wildcard_is_rejected_at_registration() {
        assert_eq!(
            RedirectUri::register("https://*.example.com/cb").unwrap_err(),
            RedirectUriError::WildcardNotSupported
        );
    }

    #[test]
    fn fragment_is_rejected_at_registration() {
        assert_eq!(
            RedirectUri::register("https://app.example.com/cb#frag").unwrap_err(),
            RedirectUriError::HasFragment
        );
    }

    #[test]
    fn relative_uri_is_rejected() {
        assert_eq!(
            RedirectUri::register("/cb").unwrap_err(),
            RedirectUriError::NotAbsolute
        );
    }

    #[test]
    fn loopback_ipv4_ignores_port() {
        let uri = reg("http://127.0.0.1/callback");
        assert_eq!(
            uri.match_presented("http://127.0.0.1:3118/callback"),
            Some(RedirectUriMatch::LoopbackPortIgnored)
        );
    }

    #[test]
    fn loopback_ipv6_ignores_port() {
        let uri = reg("http://[::1]/callback");
        assert_eq!(
            uri.match_presented("http://[::1]:51234/callback"),
            Some(RedirectUriMatch::LoopbackPortIgnored)
        );
    }

    #[test]
    fn localhost_ignores_port() {
        let uri = reg("http://localhost/callback");
        assert_eq!(
            uri.match_presented("http://localhost:8080/callback"),
            Some(RedirectUriMatch::LoopbackPortIgnored)
        );
    }

    #[test]
    fn loopback_relaxation_does_not_cross_scheme_host_or_path() {
        let uri = reg("http://127.0.0.1/callback");
        for evil in [
            "https://127.0.0.1:3118/callback",
            "http://127.0.0.2:3118/callback",
            "http://127.0.0.1:3118/other",
            "http://evil.test:3118/callback",
            "http://127.0.0.1:3118/callback?x=1",
        ] {
            assert_eq!(uri.match_presented(evil), None, "matched: {evil}");
        }
    }

    #[test]
    fn https_loopback_gets_no_relaxation() {
        let uri = reg("https://127.0.0.1/callback");
        assert!(!uri.is_loopback());
        assert_eq!(uri.match_presented("https://127.0.0.1:3118/callback"), None);
    }

    #[test]
    fn non_loopback_never_gets_port_relaxation() {
        let uri = reg("https://app.example.com/cb");
        assert!(!uri.is_loopback());
        assert_eq!(uri.match_presented("https://app.example.com:9999/cb"), None);
    }
}
