pub mod list;
pub mod routes;

use std::sync::Arc;

use argus_core::id::TenantId;
use argus_core::time::Timestamp;
use argus_crypto::{SigningKey, VerifyingKey};
use argus_proto::jwt::AccessTokenClaims;

pub const REQUIRED_SCOPE: &str = "scim";

pub trait EventSink: Send + Sync {
    fn publish(&self, token: &str);
}

pub struct EventPublisher {
    pub key: Arc<SigningKey>,
    pub audience: String,
    pub sink: Arc<dyn EventSink>,
}

impl EventPublisher {
    pub fn emit(&self, event: &argus_core::scim_event::Event, issuer: &str, now: Timestamp) {
        let jti = uuid::Uuid::new_v4().to_string();
        let txn = uuid::Uuid::new_v4().to_string();

        let Ok(claims) = argus_core::scim_event::claims(
            event,
            issuer,
            &self.audience,
            &jti,
            &txn,
            now.as_unix_seconds(),
        ) else {
            return;
        };

        if let Ok(token) = argus_proto::jwt::sign_security_event(&claims, &self.key) {
            self.sink.publish(&token);
        }
    }
}

pub struct ScimState<S> {
    pub store: S,
    pub tenant_id: TenantId,
    pub issuer: String,
    pub base: String,
    pub published_keys: Vec<Arc<SigningKey>>,
    pub events: Option<EventPublisher>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    MissingCredentials,
    InvalidToken,
    InsufficientScope,
}

impl AuthFailure {
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::MissingCredentials | Self::InvalidToken => 401,
            Self::InsufficientScope => 403,
        }
    }

    #[must_use]
    pub const fn challenge(self) -> &'static str {
        match self {
            Self::MissingCredentials => "Bearer",
            Self::InvalidToken => {
                r#"Bearer error="invalid_token", error_description="the access token is not valid""#
            }
            Self::InsufficientScope => r#"Bearer error="insufficient_scope", scope="scim""#,
        }
    }

    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::MissingCredentials => "an access token is required",
            Self::InvalidToken => "the access token is not valid",
            Self::InsufficientScope => "the access token does not carry the scim scope",
        }
    }
}

impl<S> ScimState<S> {
    pub fn authorize(
        &self,
        authorization: Option<&str>,
        now: Timestamp,
    ) -> Result<AccessTokenClaims, AuthFailure> {
        let raw = authorization.ok_or(AuthFailure::MissingCredentials)?;

        let (scheme, token) = raw.split_once(' ').ok_or(AuthFailure::MissingCredentials)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(AuthFailure::MissingCredentials);
        }
        let token = token.trim();
        if token.is_empty() {
            return Err(AuthFailure::MissingCredentials);
        }

        let keys: Vec<VerifyingKey> = self
            .published_keys
            .iter()
            .map(|key| key.verifying_key())
            .collect();

        let claims = keys
            .iter()
            .find_map(|key| argus_proto::jwt::verify(token, key).ok())
            .ok_or(AuthFailure::InvalidToken)?;

        if claims.iss != self.issuer {
            return Err(AuthFailure::InvalidToken);
        }

        if claims.exp <= now.as_unix_seconds() {
            return Err(AuthFailure::InvalidToken);
        }

        if !claims.aud.contains(&self.issuer) {
            return Err(AuthFailure::InvalidToken);
        }

        let granted = claims
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .any(|scope| scope == REQUIRED_SCOPE);

        if !granted {
            return Err(AuthFailure::InsufficientScope);
        }

        Ok(claims)
    }
}
