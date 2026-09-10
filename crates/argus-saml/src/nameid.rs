use argus_core::id::{TenantId, UserId};

pub const FORMAT_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
pub const FORMAT_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
pub const FORMAT_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
pub const FORMAT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameIdFormat {
    Persistent,
    Transient,
    Email,
}

impl NameIdFormat {
    #[must_use]
    pub const fn as_uri(self) -> &'static str {
        match self {
            Self::Persistent => FORMAT_PERSISTENT,
            Self::Transient => FORMAT_TRANSIENT,
            Self::Email => FORMAT_EMAIL,
        }
    }

    #[must_use]
    pub fn parse(uri: &str) -> Option<Self> {
        match uri {
            FORMAT_PERSISTENT | FORMAT_UNSPECIFIED => Some(Self::Persistent),
            FORMAT_TRANSIENT => Some(Self::Transient),
            FORMAT_EMAIL => Some(Self::Email),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameIdFault {
    #[error("the service provider asked for a name identifier format this server does not issue")]
    UnsupportedFormat,

    #[error("an email name identifier was asked for but the account carries no verified address")]
    NoVerifiedEmail,
}

pub trait PairwiseIdentifier {
    fn pairwise(&self, tenant: TenantId, audience: &str, user: UserId) -> String;
}

pub struct NameId {
    pub format: NameIdFormat,
    pub value: String,
}

pub fn issue(
    requested: Option<&str>,
    tenant: TenantId,
    audience: &str,
    user: UserId,
    verified_email: Option<&str>,
    transient_handle: &str,
    pairwise: &impl PairwiseIdentifier,
) -> Result<NameId, NameIdFault> {
    let format = match requested {
        None => NameIdFormat::Persistent,
        Some(uri) => NameIdFormat::parse(uri).ok_or(NameIdFault::UnsupportedFormat)?,
    };

    let value = match format {
        NameIdFormat::Persistent => pairwise.pairwise(tenant, audience, user),
        NameIdFormat::Transient => transient_handle.to_owned(),
        NameIdFormat::Email => verified_email
            .ok_or(NameIdFault::NoVerifiedEmail)?
            .to_owned(),
    };

    Ok(NameId { format, value })
}
