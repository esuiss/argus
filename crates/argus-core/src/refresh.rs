use core::fmt;

use uuid::Uuid;

use crate::effect::Effect;
use crate::id::{ClientId, TenantId, UserId};
use crate::time::{Duration, Timestamp};

// OAuth 2.1 §4.14.2: refresh token rotasyonu ve yeniden kullanım tespiti.
// Aile ömrü tek tek token'ların ömründen uzundur; yeniden kullanım görülürse
// iptal edilen tek token değil TÜM ailedir.
pub const DEFAULT_FAMILY_LIFETIME: Duration = Duration::from_seconds(30 * 24 * 60 * 60);

pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_seconds(14 * 24 * 60 * 60);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FamilyId(Uuid);

impl FamilyId {
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for FamilyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = Uuid::encode_buffer();
        let full = self.0.as_simple().encode_lower(&mut buf);
        let prefix = full.get(..8).unwrap_or(full);
        write!(f, "FamilyId({prefix}…)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshState {
    Active,

    Rotated { at: Timestamp },

    Revoked { at: Timestamp },
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub tenant: TenantId,

    pub client: ClientId,

    pub subject: UserId,

    pub family: FamilyId,

    pub generation: u32,

    pub family_started_at: Timestamp,

    pub expires_at: Timestamp,

    pub state: RefreshState,
}

#[derive(Debug, Clone)]
pub struct RefreshRequest {
    pub client: ClientId,

    pub tenant: TenantId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedGrant {
    pub subject: UserId,

    pub client: ClientId,

    pub tenant: TenantId,

    pub family: FamilyId,

    pub next_generation: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDenial {
    Expired,

    FamilyExpired,

    ClientMismatch,

    TenantMismatch,

    Revoked,

    Reused {
        rotated_at: Timestamp,

        generation: u32,
    },
}

impl RefreshDenial {
    #[must_use]
    pub const fn oauth_error_code(&self) -> &'static str {
        "invalid_grant"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDecision {
    Rotate {
        grant: RotatedGrant,

        effects: Vec<Effect>,
    },

    Deny {
        reason: RefreshDenial,

        effects: Vec<Effect>,
    },
}

#[must_use]
pub fn rotate(
    token: &RefreshToken,
    request: &RefreshRequest,
    now: Timestamp,
    family_lifetime: Duration,
) -> RefreshDecision {
    if let RefreshState::Rotated { at } = token.state {
        return RefreshDecision::Deny {
            reason: RefreshDenial::Reused {
                rotated_at: at,
                generation: token.generation,
            },
            effects: vec![
                Effect::RevokeRefreshFamily,
                Effect::RecordAudit("oauth.refresh_token.reuse_detected"),
            ],
        };
    }

    if matches!(token.state, RefreshState::Revoked { .. }) {
        return RefreshDecision::Deny {
            reason: RefreshDenial::Revoked,
            effects: vec![Effect::RecordAudit("oauth.refresh_token.revoked_presented")],
        };
    }

    let deny = |reason: RefreshDenial, audit: &'static str| RefreshDecision::Deny {
        reason,
        effects: vec![Effect::RecordAudit(audit)],
    };

    if token.tenant != request.tenant {
        return deny(
            RefreshDenial::TenantMismatch,
            "oauth.refresh_token.tenant_mismatch",
        );
    }

    if token.client != request.client {
        return deny(
            RefreshDenial::ClientMismatch,
            "oauth.refresh_token.client_mismatch",
        );
    }

    if now.is_after(token.family_started_at.saturating_add(family_lifetime)) {
        return deny(
            RefreshDenial::FamilyExpired,
            "oauth.refresh_token.family_expired",
        );
    }

    if now.is_after(token.expires_at) {
        return deny(RefreshDenial::Expired, "oauth.refresh_token.expired");
    }

    RefreshDecision::Rotate {
        grant: RotatedGrant {
            subject: token.subject,
            client: token.client.clone(),
            tenant: token.tenant,
            family: token.family,

            next_generation: token.generation.saturating_add(1),
        },
        effects: vec![
            Effect::RotateRefreshToken,
            Effect::RecordAudit("oauth.refresh_token.rotated"),
        ],
    }
}
