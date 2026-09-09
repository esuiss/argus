use crate::client_auth::ClientKey;
use crate::id::ClientId;
use crate::time::{Duration, Timestamp};

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const MAX_ASSERTION_LIFETIME: Duration = Duration::from_seconds(600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuer {
    pub issuer: String,
    pub keys: Vec<ClientKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedGrant {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub client_id: String,
    pub jti: String,
    pub expires_at: Timestamp,
    pub issued_at: Timestamp,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("the assertion issuer is not trusted by this tenant")]
    UntrustedIssuer,

    #[error("the assertion is not addressed to this authorization server")]
    AudienceMismatch,

    #[error("the assertion names a different client than the one authenticated")]
    ClientDiscontinuity,

    #[error("the assertion has expired")]
    Expired,

    #[error("the assertion lifetime exceeds the accepted maximum")]
    LifetimeTooLong,

    #[error("the assertion has already been redeemed")]
    Replayed,

    #[error("the assertion names a resource this server does not host")]
    UnknownResource,
}

impl GrantError {
    #[must_use]
    pub const fn oauth_error_code(self) -> &'static str {
        match self {
            Self::UnknownResource => "invalid_target",
            _ => "invalid_grant",
        }
    }
}

pub fn validate(
    grant: &PresentedGrant,
    authenticated_client: &ClientId,
    our_issuer: &str,
    trusted: &[TrustedIssuer],
    known_resources: &[String],
    now: Timestamp,
    already_seen: bool,
) -> Result<(), GrantError> {
    if already_seen {
        return Err(GrantError::Replayed);
    }

    if !trusted.iter().any(|t| t.issuer == grant.issuer) {
        return Err(GrantError::UntrustedIssuer);
    }

    if grant.audience != our_issuer {
        return Err(GrantError::AudienceMismatch);
    }

    if grant.client_id != authenticated_client.as_str() {
        return Err(GrantError::ClientDiscontinuity);
    }

    if grant.expires_at.as_unix_seconds() <= now.as_unix_seconds() {
        return Err(GrantError::Expired);
    }

    if grant.expires_at.since(grant.issued_at).as_seconds() > MAX_ASSERTION_LIFETIME.as_seconds() {
        return Err(GrantError::LifetimeTooLong);
    }

    if let Some(resource) = grant.resource.as_deref()
        && !known_resources.iter().any(|r| r == resource)
    {
        return Err(GrantError::UnknownResource);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{GrantError, PresentedGrant, TrustedIssuer, validate};
    use crate::id::ClientId;
    use crate::time::Timestamp;

    const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);
    const US: &str = "https://auth.chat.example";
    const IDP: &str = "https://acme.idp.example";
    const MCP: &str = "https://mcp.chat.example";

    fn client() -> ClientId {
        ClientId::new("f53f191f9311af35").expect("client")
    }

    fn trusted() -> Vec<TrustedIssuer> {
        vec![TrustedIssuer {
            issuer: IDP.to_owned(),
            keys: Vec::new(),
        }]
    }

    fn grant() -> PresentedGrant {
        PresentedGrant {
            issuer: IDP.to_owned(),
            subject: "U019488227".to_owned(),
            audience: US.to_owned(),
            client_id: "f53f191f9311af35".to_owned(),
            jti: "9e43f81b".to_owned(),
            expires_at: Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 300),
            issued_at: NOW,
            resource: Some(MCP.to_owned()),
            scope: Some("chat.read".to_owned()),
        }
    }

    fn known() -> Vec<String> {
        vec![MCP.to_owned()]
    }

    fn check(g: &PresentedGrant, seen: bool) -> Result<(), GrantError> {
        validate(g, &client(), US, &trusted(), &known(), NOW, seen)
    }

    #[test]
    fn a_well_formed_grant_from_a_trusted_issuer_passes() {
        assert_eq!(check(&grant(), false), Ok(()));
    }

    #[test]
    fn an_unknown_issuer_is_refused() {
        let mut g = grant();
        g.issuer = "https://evil.idp.example".to_owned();
        assert_eq!(check(&g, false).unwrap_err(), GrantError::UntrustedIssuer);
    }

    #[test]
    fn a_grant_addressed_elsewhere_is_refused() {
        let mut g = grant();
        g.audience = "https://auth.other.example".to_owned();
        assert_eq!(check(&g, false).unwrap_err(), GrantError::AudienceMismatch);
    }

    #[test]
    fn client_continuity_is_enforced() {
        let mut g = grant();
        g.client_id = "someone-else".to_owned();
        assert_eq!(
            check(&g, false).unwrap_err(),
            GrantError::ClientDiscontinuity
        );
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let mut g = grant();
        g.expires_at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() - 1);
        assert_eq!(check(&g, false).unwrap_err(), GrantError::Expired);
    }

    #[test]
    fn an_over_long_grant_is_refused() {
        let mut g = grant();
        g.expires_at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 86_400);
        assert_eq!(check(&g, false).unwrap_err(), GrantError::LifetimeTooLong);
    }

    #[test]
    fn a_replayed_jti_is_refused_before_anything_else() {
        let mut g = grant();
        g.issuer = "https://evil.idp.example".to_owned();
        assert_eq!(check(&g, true).unwrap_err(), GrantError::Replayed);
    }

    #[test]
    fn a_resource_this_server_does_not_host_is_invalid_target() {
        let mut g = grant();
        g.resource = Some("https://mcp.elsewhere.example".to_owned());
        assert_eq!(check(&g, false).unwrap_err(), GrantError::UnknownResource);
        assert_eq!(
            GrantError::UnknownResource.oauth_error_code(),
            "invalid_target"
        );
    }

    #[test]
    fn a_grant_without_a_resource_is_accepted() {
        let mut g = grant();
        g.resource = None;
        assert_eq!(check(&g, false), Ok(()));
    }
}
