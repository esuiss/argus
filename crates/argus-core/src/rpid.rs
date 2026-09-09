use url::Url;

use crate::error::RpIdError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RpId {
    value: String,
}

impl RpId {
    pub fn register(raw: &str) -> Result<Self, RpIdError> {
        let lowered = raw.to_ascii_lowercase();

        if lowered.is_empty() {
            return Err(RpIdError::Empty);
        }

        if lowered.contains([':', '/', '?', '#']) {
            return Err(RpIdError::NotABareDomain);
        }

        if lowered.parse::<core::net::IpAddr>().is_ok() {
            return Err(RpIdError::NotABareDomain);
        }

        if !lowered.contains('.') && lowered != "localhost" {
            return Err(RpIdError::NotABareDomain);
        }

        if lowered.starts_with('.') || lowered.ends_with('.') || lowered.contains("..") {
            return Err(RpIdError::NotABareDomain);
        }

        Ok(Self { value: lowered })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn accepts_origin(&self, origin: &str) -> Result<bool, RpIdError> {
        let parsed = Url::parse(origin).map_err(|_| RpIdError::MalformedOrigin)?;

        let scheme = parsed.scheme();
        let host = parsed.host_str().ok_or(RpIdError::MalformedOrigin)?;
        let host = host.to_ascii_lowercase();

        let loopback = host == "localhost"
            || host
                .parse::<core::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());

        if scheme != "https" && !(scheme == "http" && loopback) {
            return Err(RpIdError::InsecureOrigin);
        }

        Ok(is_registrable_suffix(&host, &self.value))
    }
}

fn is_registrable_suffix(effective_domain: &str, rp_id: &str) -> bool {
    if effective_domain == rp_id {
        return true;
    }

    let Some(remainder) = effective_domain.strip_suffix(rp_id) else {
        return false;
    };

    if !remainder.ends_with('.') {
        return false;
    }

    rp_id.contains('.')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::RpId;
    use crate::error::RpIdError;

    fn rp(raw: &str) -> RpId {
        RpId::register(raw).expect("rp id")
    }

    #[test]
    fn an_origin_matching_its_own_effective_domain_is_accepted() {
        assert!(
            rp("login.example.com")
                .accepts_origin("https://login.example.com")
                .expect("origin")
        );
    }

    #[test]
    fn a_registrable_suffix_of_the_origin_is_accepted() {
        assert!(
            rp("example.com")
                .accepts_origin("https://login.example.com")
                .expect("origin")
        );
        assert!(
            rp("example.com")
                .accepts_origin("https://a.b.example.com")
                .expect("origin")
        );
    }

    #[test]
    fn a_single_label_public_suffix_is_refused_at_registration() {
        assert_eq!(
            RpId::register("com").unwrap_err(),
            RpIdError::NotABareDomain,
            "com must never become an RP ID; eTLD+1 is the floor"
        );
    }

    #[test]
    fn a_multi_label_public_suffix_is_not_caught_without_the_public_suffix_list() {
        let accepted = rp("co.uk")
            .accepts_origin("https://example.co.uk")
            .expect("origin");
        assert!(
            accepted,
            "documented limitation: co.uk passes the dot rule. The browser refuses \
             a public-suffix RP ID on its side, and the RP ID is tenant configuration \
             rather than attacker input, so this is a configuration check that wants \
             the Public Suffix List, not a runtime boundary."
        );
    }

    #[test]
    fn a_sibling_domain_is_refused() {
        assert!(
            !rp("example.com")
                .accepts_origin("https://example.com.evil.test")
                .expect("origin")
        );
        assert!(
            !rp("example.com")
                .accepts_origin("https://notexample.com")
                .expect("origin")
        );
        assert!(
            !rp("example.com")
                .accepts_origin("https://evil-example.com")
                .expect("origin")
        );
    }

    #[test]
    fn an_rp_id_more_specific_than_the_origin_is_refused() {
        assert!(
            !rp("login.example.com")
                .accepts_origin("https://example.com")
                .expect("origin"),
            "an RP ID must be the origin domain or a suffix of it, never a subdomain"
        );
    }

    #[test]
    fn a_plaintext_origin_is_refused_unless_it_is_loopback() {
        assert_eq!(
            rp("example.com")
                .accepts_origin("http://example.com")
                .unwrap_err(),
            RpIdError::InsecureOrigin
        );
        assert!(
            rp("localhost")
                .accepts_origin("http://localhost:3000")
                .expect("loopback is allowed for development")
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(
            rp("Example.COM")
                .accepts_origin("https://LOGIN.EXAMPLE.com")
                .expect("origin")
        );
    }

    #[test]
    fn an_rp_id_must_be_a_bare_domain() {
        for bad in [
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "",
            ".example.com",
            "example..com",
            "127.0.0.1",
            "::1",
            "singlelabel",
        ] {
            assert!(RpId::register(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_port_on_the_origin_does_not_affect_the_match() {
        assert!(
            rp("example.com")
                .accepts_origin("https://login.example.com:8443")
                .expect("origin")
        );
    }

    #[test]
    fn a_malformed_origin_is_an_error_not_a_silent_refusal() {
        assert_eq!(
            rp("example.com").accepts_origin("not a url").unwrap_err(),
            RpIdError::MalformedOrigin
        );
    }
}
