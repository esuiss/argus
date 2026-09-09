use argus_core::ciba::{
    BackchannelRequest, BackchannelState, DEFAULT_POLL_INTERVAL, DEFAULT_REQUEST_LIFETIME,
};
use argus_core::id::{TenantId, UserId};
use argus_core::pkce::Sha256;
use argus_core::resource::ResourceUri;
use argus_core::time::Timestamp;
use argus_proto::{OAuthError, OAuthErrorCode};
use serde::{Deserialize, Serialize};

use crate::store::{BackchannelStore, StoreError};

#[derive(Debug, Clone, Deserialize)]
pub struct BackchannelForm {
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
    pub binding_message: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackchannelResponse {
    pub auth_req_id: String,
    pub expires_in: i64,
    pub interval: i64,
}

pub const MAX_BINDING_MESSAGE: usize = 64;

pub trait BackchannelUserResolver {
    fn resolve(&self, tenant: TenantId, login_hint: Option<&str>) -> Option<UserId>;
}

#[derive(Debug, Clone, Copy)]
pub struct DevBackchannelResolver {
    pub user: UserId,
}

impl BackchannelUserResolver for DevBackchannelResolver {
    fn resolve(&self, _tenant: TenantId, login_hint: Option<&str>) -> Option<UserId> {
        login_hint.map(|_| self.user)
    }
}

pub struct BackchannelContext<'a, B, H, U> {
    pub tenant: TenantId,
    pub client: &'a argus_core::id::ClientId,
    pub store: &'a B,
    pub hasher: &'a H,
    pub users: &'a U,
    pub now: Timestamp,
    pub auth_req_id: &'a str,
    pub resources: Vec<ResourceUri>,
}

pub async fn request<B, H, U>(
    ctx: &BackchannelContext<'_, B, H, U>,
    form: &BackchannelForm,
) -> Result<BackchannelResponse, OAuthError>
where
    B: BackchannelStore + Sync,
    H: Sha256,
    U: BackchannelUserResolver + Sync,
{
    if form.login_hint.as_deref().is_none_or(str::is_empty) {
        return Err(OAuthError::with_description(
            OAuthErrorCode::InvalidRequest,
            "login_hint is required; this server does not accept id_token_hint or login_hint_token",
        ));
    }

    if form
        .binding_message
        .as_deref()
        .is_some_and(|m| m.chars().count() > MAX_BINDING_MESSAGE)
    {
        return Err(OAuthError::with_description(
            OAuthErrorCode::InvalidRequest,
            "binding_message is too long to be shown on a constrained device",
        ));
    }

    let Some(subject) = ctx.users.resolve(ctx.tenant, form.login_hint.as_deref()) else {
        return Err(OAuthError::with_description(
            OAuthErrorCode::InvalidGrant,
            "unknown user",
        ));
    };

    let record = BackchannelRequest {
        tenant: ctx.tenant,
        client: ctx.client.clone(),
        subject,
        scope: form.scope.clone(),
        resources: ctx.resources.clone(),
        state: BackchannelState::Pending,
        issued_at: ctx.now,
        expires_at: ctx.now.saturating_add(DEFAULT_REQUEST_LIFETIME),
        interval: DEFAULT_POLL_INTERVAL,
        last_polled_at: None,
    };

    let hash = ctx.hasher.sha256(ctx.auth_req_id.as_bytes());

    ctx.store
        .create_backchannel(ctx.tenant, &hash, &record)
        .await
        .map_err(|e| match e {
            StoreError::NotFound => OAuthError::new(OAuthErrorCode::InvalidGrant),
            StoreError::Unavailable => OAuthError::new(OAuthErrorCode::TemporarilyUnavailable),
        })?;

    Ok(BackchannelResponse {
        auth_req_id: ctx.auth_req_id.to_owned(),
        expires_in: DEFAULT_REQUEST_LIFETIME.as_seconds(),
        interval: DEFAULT_POLL_INTERVAL.as_seconds(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{BackchannelForm, MAX_BINDING_MESSAGE};

    fn form() -> BackchannelForm {
        BackchannelForm {
            client_id: Some("acme-web".to_owned()),
            scope: Some("openid".to_owned()),
            login_hint: Some("user@example.com".to_owned()),
            binding_message: None,
            client_assertion_type: None,
            client_assertion: None,
        }
    }

    #[test]
    fn the_binding_message_ceiling_fits_a_constrained_display() {
        assert_eq!(MAX_BINDING_MESSAGE, 64);
        let long = "x".repeat(MAX_BINDING_MESSAGE + 1);
        assert!(long.chars().count() > MAX_BINDING_MESSAGE);
    }

    #[test]
    fn a_login_hint_is_what_identifies_the_user() {
        assert!(form().login_hint.is_some());
    }
}
