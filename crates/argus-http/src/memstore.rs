use std::collections::HashMap;
use std::sync::Mutex;

use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::id::{TenantId, UserId};
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::Timestamp;

use argus_core::authorize::RegisteredClient;
use argus_core::id::ClientId;

use crate::store::{
    AuditSink, AuthnSession, AuthnStore, BackchannelStore, ClientStore, CodeIssuer, CodeStore,
    ConnectionStore, IssuerStore, JtiOutcome, JtiPurpose, ProtectedResource, RefreshStore,
    ReplayStore, ResourceStore, SessionStore, StoreError,
};

#[derive(Debug, Default)]
pub struct MemoryCodeStore {
    codes: Mutex<HashMap<[u8; 32], StoredCode>>,
    backchannel: Mutex<HashMap<[u8; 32], argus_core::ciba::BackchannelRequest>>,
    sessions: Mutex<HashMap<[u8; 32], AuthnSession>>,
}

impl MemoryCodeStore {
    pub fn insert(&self, hash: [u8; 32], code: StoredCode) -> Result<(), StoreError> {
        self.codes
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(hash, code);
        Ok(())
    }
}

impl CodeIssuer for MemoryCodeStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn issue(
        &self,
        _t: TenantId,
        code_hash: &[u8; 32],
        code: &StoredCode,
    ) -> Result<(), StoreError> {
        self.codes
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(*code_hash, code.clone());
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryClientStore {
    clients: Mutex<HashMap<String, RegisteredClient>>,
}

impl MemoryClientStore {
    pub fn insert(&self, client: RegisteredClient) -> Result<(), StoreError> {
        self.clients
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(client.client_id.as_str().to_owned(), client);
        Ok(())
    }
}

impl ClientStore for MemoryClientStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn find(
        &self,
        _t: TenantId,
        client_id: &ClientId,
    ) -> Result<Option<RegisteredClient>, StoreError> {
        Ok(self
            .clients
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get(client_id.as_str())
            .cloned())
    }
}

impl CodeStore for MemoryCodeStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn load(&self, _t: TenantId, hash: &[u8; 32]) -> Result<StoredCode, StoreError> {
        self.codes
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get(hash)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn consume(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut codes = self.codes.lock().map_err(|_| StoreError::Unavailable)?;
        if let Some(c) = codes.get_mut(hash) {
            c.state = CodeState::Redeemed { at };
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke_tokens_issued_for_code(
        &self,
        _t: TenantId,
        _hash: &[u8; 32],
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryRefreshStore {
    tokens: Mutex<HashMap<[u8; 32], RefreshToken>>,
}

impl MemoryRefreshStore {
    pub fn insert(&self, hash: [u8; 32], token: RefreshToken) -> Result<(), StoreError> {
        self.tokens
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(hash, token);
        Ok(())
    }
}

impl RefreshStore for MemoryRefreshStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn load(&self, _t: TenantId, hash: &[u8; 32]) -> Result<RefreshToken, StoreError> {
        self.tokens
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get(hash)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn rotate(
        &self,
        _t: TenantId,
        old: &[u8; 32],
        new: &[u8; 32],
        new_token: &RefreshToken,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tokens = self.tokens.lock().map_err(|_| StoreError::Unavailable)?;
        if let Some(t) = tokens.get_mut(old) {
            t.state = RefreshState::Rotated { at };
        }
        tokens.insert(*new, new_token.clone());
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke_family(
        &self,
        _t: TenantId,
        family: FamilyId,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tokens = self.tokens.lock().map_err(|_| StoreError::Unavailable)?;
        for t in tokens.values_mut() {
            if t.family == family {
                t.state = RefreshState::Revoked { at };
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    events: Mutex<Vec<(String, i64)>>,
}

impl MemoryAuditSink {
    pub fn events(&self) -> Result<Vec<(String, i64)>, StoreError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .clone())
    }
}

impl AuditSink for MemoryAuditSink {
    #[allow(clippy::unused_async_trait_impl)]
    async fn record(
        &self,
        _t: TenantId,
        event_type: &str,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        self.events
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .push((event_type.to_owned(), at.as_unix_seconds()));
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    seen: Mutex<HashMap<(TenantId, &'static str, String), i64>>,
}

impl ReplayStore for MemoryReplayStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn consume_jti(
        &self,
        tenant: TenantId,
        purpose: JtiPurpose,
        jti: &str,
        expires_at: Timestamp,
    ) -> Result<JtiOutcome, StoreError> {
        let mut seen = self.seen.lock().map_err(|_| StoreError::Unavailable)?;
        let key = (tenant, purpose.as_str(), jti.to_owned());
        if seen.contains_key(&key) {
            return Ok(JtiOutcome::Replayed);
        }
        seen.insert(key, expires_at.as_unix_seconds());
        Ok(JtiOutcome::Fresh)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn purge_expired_jtis(
        &self,
        _tenant: TenantId,
        now: Timestamp,
    ) -> Result<u64, StoreError> {
        let mut seen = self.seen.lock().map_err(|_| StoreError::Unavailable)?;
        let before = seen.len();
        seen.retain(|_, expires| *expires > now.as_unix_seconds());
        Ok((before - seen.len()) as u64)
    }
}

#[derive(Debug, Default)]
pub struct MemoryResourceStore {
    resources: Mutex<Vec<ProtectedResource>>,
    connections: Mutex<Vec<argus_core::exchange::CrossAppConnection>>,
    issuers: Mutex<Vec<argus_core::jag_consume::TrustedIssuer>>,
}

impl MemoryResourceStore {
    pub fn insert(&self, resource: ProtectedResource) -> Result<(), StoreError> {
        self.resources
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .push(resource);
        Ok(())
    }
}

impl ResourceStore for MemoryResourceStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn find_resource(
        &self,
        _tenant: TenantId,
        uri: &argus_core::resource::ResourceUri,
    ) -> Result<Option<ProtectedResource>, StoreError> {
        Ok(self
            .resources
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .iter()
            .find(|r| &r.uri == uri)
            .cloned())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn list_resources(
        &self,
        _tenant: TenantId,
    ) -> Result<Vec<ProtectedResource>, StoreError> {
        Ok(self
            .resources
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .clone())
    }
}

impl MemoryResourceStore {
    pub fn connect(
        &self,
        connection: argus_core::exchange::CrossAppConnection,
    ) -> Result<(), StoreError> {
        self.connections
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .push(connection);
        Ok(())
    }
}

impl ConnectionStore for MemoryResourceStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn find_connection(
        &self,
        _tenant: TenantId,
        client: &ClientId,
        resource_as_issuer: &str,
    ) -> Result<Option<argus_core::exchange::CrossAppConnection>, StoreError> {
        Ok(self
            .connections
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .iter()
            .find(|c| &c.requesting_client == client && c.resource_as_issuer == resource_as_issuer)
            .cloned())
    }
}

impl BackchannelStore for MemoryCodeStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn create_backchannel(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        request: &argus_core::ciba::BackchannelRequest,
    ) -> Result<(), StoreError> {
        self.backchannel
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(*hash, request.clone());
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn load_backchannel(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
    ) -> Result<argus_core::ciba::BackchannelRequest, StoreError> {
        self.backchannel
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get(hash)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn record_backchannel_poll(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError> {
        if let Some(record) = self
            .backchannel
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get_mut(hash)
        {
            record.last_polled_at = Some(at);
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn consume_backchannel(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        _at: Timestamp,
    ) -> Result<bool, StoreError> {
        let mut guard = self
            .backchannel
            .lock()
            .map_err(|_| StoreError::Unavailable)?;
        let Some(record) = guard.get_mut(hash) else {
            return Ok(false);
        };
        if record.state != argus_core::ciba::BackchannelState::Approved {
            return Ok(false);
        }
        record.state = argus_core::ciba::BackchannelState::Consumed;
        Ok(true)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn decide_backchannel(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        approved: bool,
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        if let Some(record) = self
            .backchannel
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get_mut(hash)
        {
            record.state = if approved {
                argus_core::ciba::BackchannelState::Approved
            } else {
                argus_core::ciba::BackchannelState::Denied
            };
        }
        Ok(())
    }
}

impl MemoryResourceStore {
    pub fn trust(&self, issuer: argus_core::jag_consume::TrustedIssuer) -> Result<(), StoreError> {
        self.issuers
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .push(issuer);
        Ok(())
    }
}

impl IssuerStore for MemoryResourceStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn trusted_issuers(
        &self,
        _tenant: TenantId,
    ) -> Result<Vec<argus_core::jag_consume::TrustedIssuer>, StoreError> {
        Ok(self
            .issuers
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .clone())
    }
}

impl SessionStore for MemoryCodeStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn create_session(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        session: &AuthnSession,
    ) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(*hash, session.clone());
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn load_session(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        now: Timestamp,
    ) -> Result<AuthnSession, StoreError> {
        let guard = self.sessions.lock().map_err(|_| StoreError::Unavailable)?;
        let session = guard.get(hash).ok_or(StoreError::NotFound)?;
        if session.expires_at.as_unix_seconds() <= now.as_unix_seconds() {
            return Err(StoreError::NotFound);
        }
        Ok(session.clone())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke_session(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .remove(hash);
        Ok(())
    }
}

impl AuthnStore for MemoryCodeStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn find_user_by_blind_index(
        &self,
        _t: TenantId,
        _index: &[u8; 32],
    ) -> Result<Option<UserId>, StoreError> {
        Ok(None)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn create_user(
        &self,
        _t: TenantId,
        _u: UserId,
        _i: &[u8; 32],
        _e: &[u8],
    ) -> Result<(), StoreError> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn password_of(&self, _t: TenantId, _u: UserId) -> Result<Option<String>, StoreError> {
        Ok(None)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn set_password(&self, _t: TenantId, _u: UserId, _p: &str) -> Result<(), StoreError> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn required_aal(
        &self,
        _t: TenantId,
        _u: UserId,
    ) -> Result<argus_core::aal::Aal, StoreError> {
        Ok(argus_core::aal::Aal::One)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn webauthn_credentials(
        &self,
        _t: TenantId,
        _u: UserId,
    ) -> Result<Vec<String>, StoreError> {
        Ok(Vec::new())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn store_webauthn_credential(
        &self,
        _t: TenantId,
        _u: UserId,
        _c: &[u8],
        _r: &str,
        _s: &str,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn user_for_credential(
        &self,
        _t: TenantId,
        _c: &[u8],
    ) -> Result<Option<UserId>, StoreError> {
        Ok(None)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn advance_sign_count(
        &self,
        _t: TenantId,
        _c: &[u8],
        _n: i64,
        _at: Timestamp,
    ) -> Result<bool, StoreError> {
        Ok(true)
    }
}
