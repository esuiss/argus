use crate::client_resolution::TrustLevel;
use crate::delegation::{DelegationRecord, contains_scope, effective_scope};
use crate::id::{TenantId, UserId};
use crate::time::{Duration, Timestamp};

pub const READ_SCOPE: &str = "urn:argus:vault:read";
pub const MAX_LEASE: Duration = Duration::from_seconds(300);
pub const DEFAULT_LEASE: Duration = Duration::from_seconds(60);
pub const MIN_TRUST_LEVEL: TrustLevel = TrustLevel::Registered;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    BearerToken,
    ApiKey,
    BasicPassword,
    UpstreamRefreshToken,
}

impl SecretKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BearerToken => "bearer",
            Self::ApiKey => "api_key",
            Self::BasicPassword => "basic",
            Self::UpstreamRefreshToken => "upstream_refresh_token",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "bearer" => Some(Self::BearerToken),
            "api_key" => Some(Self::ApiKey),
            "basic" => Some(Self::BasicPassword),
            "upstream_refresh_token" => Some(Self::UpstreamRefreshToken),
            _ => None,
        }
    }

    #[must_use]
    pub const fn may_be_released_raw(self) -> bool {
        !matches!(self, Self::UpstreamRefreshToken)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    pub tenant: TenantId,
    pub secret_id: String,
    pub owner: Option<UserId>,
    pub audience: String,
    pub kind: SecretKind,
    pub required_scope: String,
    pub expires_at: Option<Timestamp>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requester {
    pub subject: Option<UserId>,
    pub audience: String,
    pub granted_scope: Vec<String>,
    pub trust_level: TrustLevel,
    pub delegation: Vec<DelegationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultFault {
    #[error("the secret does not exist")]
    NoSuchSecret,

    #[error("the secret has been revoked")]
    Revoked,

    #[error("the secret has expired")]
    Expired,

    #[error("the caller does not hold the scope the vault requires")]
    MissingVaultScope,

    #[error("the caller does not hold {scope}, which this secret requires")]
    MissingSecretScope { scope: String },

    #[error("the token was issued for {presented} and the secret belongs to {expected}")]
    WrongAudience { presented: String, expected: String },

    #[error("the secret belongs to another person")]
    NotTheOwner,

    #[error("a secret with an owner cannot be read by a token with no subject")]
    NoSubject,

    #[error("a client at this trust level may not read the vault")]
    TrustLevelTooLow,

    #[error("the delegation chain no longer carries the scope the vault requires")]
    DelegationNarrowed,

    #[error("this kind of secret is never released in the clear")]
    NotReleasable,

    #[error("the lease does not exist")]
    NoSuchLease,

    #[error("the lease has already been used")]
    LeaseSpent,

    #[error("the lease has expired")]
    LeaseExpired,

    #[error("the lease was issued to another caller")]
    LeaseNotYours,
}

pub fn may_lease(
    secret: &SecretRecord,
    requester: &Requester,
    now: Timestamp,
) -> Result<(), VaultFault> {
    if secret.revoked {
        return Err(VaultFault::Revoked);
    }

    if secret.expires_at.is_some_and(|deadline| deadline <= now) {
        return Err(VaultFault::Expired);
    }

    if requester.trust_level < MIN_TRUST_LEVEL {
        return Err(VaultFault::TrustLevelTooLow);
    }

    if !requester
        .granted_scope
        .iter()
        .any(|scope| scope == READ_SCOPE)
    {
        return Err(VaultFault::MissingVaultScope);
    }

    if !secret.required_scope.is_empty()
        && !requester.granted_scope.contains(&secret.required_scope)
    {
        return Err(VaultFault::MissingSecretScope {
            scope: secret.required_scope.clone(),
        });
    }

    if requester.audience != secret.audience {
        return Err(VaultFault::WrongAudience {
            presented: requester.audience.clone(),
            expected: secret.audience.clone(),
        });
    }

    match (secret.owner, requester.subject) {
        (Some(_), None) => return Err(VaultFault::NoSubject),
        (Some(owner), Some(subject)) if owner != subject => {
            return Err(VaultFault::NotTheOwner);
        }
        _ => {}
    }

    if !requester.delegation.is_empty() {
        let narrowed = effective_scope(&requester.delegation);
        if !contains_scope(&narrowed, &[READ_SCOPE.to_owned()]) {
            return Err(VaultFault::DelegationNarrowed);
        }
    }

    Ok(())
}

#[must_use]
pub fn lease_lifetime(
    secret: &SecretRecord,
    requested: Option<Duration>,
    now: Timestamp,
) -> Duration {
    let asked = requested.unwrap_or(DEFAULT_LEASE);

    let bounded = if asked.as_seconds() <= 0 || asked.as_seconds() > MAX_LEASE.as_seconds() {
        MAX_LEASE
    } else {
        asked
    };

    match secret.expires_at {
        None => bounded,
        Some(deadline) => {
            let remaining = deadline.since(now);
            if remaining.as_seconds() < bounded.as_seconds() {
                remaining
            } else {
                bounded
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub lease_id: String,
    pub secret_id: String,
    pub holder: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub spent: bool,
}

pub fn may_redeem(lease: &Lease, holder: &str, now: Timestamp) -> Result<(), VaultFault> {
    if lease.spent {
        return Err(VaultFault::LeaseSpent);
    }

    if lease.expires_at <= now {
        return Err(VaultFault::LeaseExpired);
    }

    if lease.holder != holder {
        return Err(VaultFault::LeaseNotYours);
    }

    Ok(())
}

pub fn may_release_raw(secret: &SecretRecord) -> Result<(), VaultFault> {
    if secret.kind.may_be_released_raw() {
        Ok(())
    } else {
        Err(VaultFault::NotReleasable)
    }
}

#[must_use]
pub fn associated_data(tenant: TenantId, secret_id: &str) -> Vec<u8> {
    format!("argus-vault:{}:{secret_id}", tenant.as_uuid().simple()).into_bytes()
}
