use crate::effect::Effect;
use crate::error::PkceError;
use crate::id::{ClientId, TenantId, UserId};
use crate::pkce::{CodeChallenge, Sha256};
use crate::redirect_uri::RedirectUri;
use crate::resource::ResourceUri;
use crate::time::{Duration, Timestamp};

pub const MAX_CODE_LIFETIME: Duration = Duration::from_seconds(600);

pub const DEFAULT_CODE_LIFETIME: Duration = Duration::from_seconds(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeState {
    Issued,

    Redeemed { at: Timestamp },
}

#[derive(Debug, Clone)]
pub struct StoredCode {
    pub tenant: TenantId,

    pub client: ClientId,

    pub subject: UserId,

    pub redirect_uri: RedirectUri,

    pub challenge: CodeChallenge,

    pub issued_at: Timestamp,

    pub expires_at: Timestamp,

    pub state: CodeState,

    pub nonce: Option<String>,

    pub scope: Option<String>,

    pub resources: Vec<ResourceUri>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    tenant: TenantId,
    client: ClientId,
    subject: UserId,
    redirect_uri: RedirectUri,
    challenge: CodeChallenge,
    issued_at: Timestamp,
    expires_at: Timestamp,
    state: CodeState,
    nonce: Option<String>,
    scope: Option<String>,
    resources: Vec<ResourceUri>,
}

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub client: ClientId,

    pub redirect_uri: String,

    pub code_verifier: String,

    pub tenant: TenantId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub subject: UserId,

    pub client: ClientId,

    pub tenant: TenantId,

    pub nonce: Option<String>,

    pub scope: Option<String>,

    pub resources: Vec<ResourceUri>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    Expired,

    ClientMismatch,

    TenantMismatch,

    RedirectUriMismatch,

    Pkce(PkceError),

    Replayed { first_redeemed_at: Timestamp },
}

impl DenialReason {
    #[must_use]
    pub const fn oauth_error_code(&self) -> &'static str {
        "invalid_grant"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Grant {
        grant: Grant,

        effects: Vec<Effect>,
    },

    Deny {
        reason: DenialReason,

        effects: Vec<Effect>,
    },
}

impl AuthorizationCode {
    pub fn new(
        tenant: TenantId,
        client: ClientId,
        subject: UserId,
        redirect_uri: RedirectUri,
        challenge: CodeChallenge,
        issued_at: Timestamp,
        lifetime: Duration,
    ) -> Result<Self, CodeLifetimeError> {
        if lifetime.as_seconds() <= 0 {
            return Err(CodeLifetimeError::NotPositive {
                seconds: lifetime.as_seconds(),
            });
        }
        if lifetime.as_seconds() > MAX_CODE_LIFETIME.as_seconds() {
            return Err(CodeLifetimeError::TooLong {
                seconds: lifetime.as_seconds(),
                max: MAX_CODE_LIFETIME.as_seconds(),
            });
        }

        Ok(Self {
            tenant,
            client,
            subject,
            redirect_uri,
            challenge,
            issued_at,
            expires_at: issued_at.saturating_add(lifetime),
            state: CodeState::Issued,
            nonce: None,
            scope: None,
            resources: Vec::new(),
        })
    }

    #[must_use]
    pub fn from_stored(stored: StoredCode) -> Self {
        Self {
            tenant: stored.tenant,
            client: stored.client,
            subject: stored.subject,
            redirect_uri: stored.redirect_uri,
            challenge: stored.challenge,
            issued_at: stored.issued_at,
            expires_at: stored.expires_at,
            state: stored.state,
            nonce: stored.nonce,
            scope: stored.scope,
            resources: stored.resources,
        }
    }

    #[must_use]
    pub fn with_oidc(mut self, nonce: Option<String>, scope: Option<String>) -> Self {
        self.nonce = nonce;
        self.scope = scope;
        self
    }

    #[must_use]
    pub fn with_resources(mut self, resources: Vec<ResourceUri>) -> Self {
        self.resources = resources;
        self
    }

    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    #[must_use]
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    #[must_use]
    pub const fn state(&self) -> CodeState {
        self.state
    }

    #[must_use]
    pub fn to_stored(&self) -> StoredCode {
        StoredCode {
            tenant: self.tenant,
            client: self.client.clone(),
            subject: self.subject,
            redirect_uri: self.redirect_uri.clone(),
            challenge: self.challenge.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            state: self.state,
            nonce: self.nonce.clone(),
            scope: self.scope.clone(),
            resources: self.resources.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodeLifetimeError {
    #[error("authorization code lifetime must be positive, got {seconds}s")]
    NotPositive { seconds: i64 },

    #[error("authorization code lifetime {seconds}s exceeds the {max}s maximum (RFC 6749 §4.1.2)")]
    TooLong { seconds: i64, max: i64 },
}

#[must_use]
pub fn redeem(
    code: &AuthorizationCode,
    request: &TokenRequest,
    now: Timestamp,
    hasher: &impl Sha256,
) -> Decision {
    if let CodeState::Redeemed { at } = code.state {
        return Decision::Deny {
            reason: DenialReason::Replayed {
                first_redeemed_at: at,
            },

            effects: vec![
                Effect::RevokeTokensIssuedForCode,
                Effect::RecordAudit("oauth.authorization_code.replayed"),
            ],
        };
    }

    let deny = |reason: DenialReason, audit: &'static str| Decision::Deny {
        reason,

        effects: vec![Effect::ConsumeCode, Effect::RecordAudit(audit)],
    };

    if code.tenant != request.tenant {
        return deny(
            DenialReason::TenantMismatch,
            "oauth.authorization_code.tenant_mismatch",
        );
    }

    if code.client != request.client {
        return deny(
            DenialReason::ClientMismatch,
            "oauth.authorization_code.client_mismatch",
        );
    }

    if code
        .redirect_uri
        .match_presented(&request.redirect_uri)
        .is_none()
    {
        return deny(
            DenialReason::RedirectUriMismatch,
            "oauth.authorization_code.redirect_uri_mismatch",
        );
    }

    if now.is_after(code.expires_at) {
        return deny(DenialReason::Expired, "oauth.authorization_code.expired");
    }

    if let Err(e) = code.challenge.verify(&request.code_verifier, hasher) {
        return deny(
            DenialReason::Pkce(e),
            "oauth.authorization_code.pkce_failed",
        );
    }

    Decision::Grant {
        grant: Grant {
            subject: code.subject,
            client: code.client.clone(),
            tenant: code.tenant,
            nonce: code.nonce.clone(),
            scope: code.scope.clone(),
            resources: code.resources.clone(),
        },
        effects: vec![
            Effect::ConsumeCode,
            Effect::RecordAudit("oauth.authorization_code.redeemed"),
        ],
    }
}
