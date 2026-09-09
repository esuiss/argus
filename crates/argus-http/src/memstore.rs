use std::collections::HashMap;
use std::sync::Mutex;

use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::id::TenantId;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::Timestamp;

use argus_core::authorize::RegisteredClient;
use argus_core::id::ClientId;

use crate::store::{AuditSink, ClientStore, CodeIssuer, CodeStore, RefreshStore, StoreError};

#[derive(Debug, Default)]
pub struct MemoryCodeStore {
    codes: Mutex<HashMap<[u8; 32], StoredCode>>,
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
