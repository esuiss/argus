//! Bellek içi depo — **yalnızca geliştirme ve test için**.
//!
//! ⚠️ **Üretimde kullanılmaz.** Süreç yeniden başladığında her şey kaybolur:
//! bekleyen authorization code'lar, refresh zincirleri ve — en kötüsü — denetim
//! kayıtları. §1 #23 denetim olayının iş değişikliğiyle **aynı transaction'da**
//! kalıcılaşmasını istiyor; bellek bunu sağlayamaz.
//!
//! Var olma sebebi, sunucunun `PostgreSQL` olmadan ayağa kalkıp uçtan uca
//! denenebilmesi.

use std::collections::HashMap;
use std::sync::Mutex;

use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::id::TenantId;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::Timestamp;

use crate::store::{AuditSink, CodeStore, RefreshStore, StoreError};

/// Bellek içi authorization code deposu.
#[derive(Debug, Default)]
pub struct MemoryCodeStore {
    codes: Mutex<HashMap<[u8; 32], StoredCode>>,
}

impl MemoryCodeStore {
    /// Yeni bir kod kaydı ekler.
    ///
    /// # Errors
    ///
    /// Kilit zehirlenmişse (başka bir thread panikleyerek çıkmışsa).
    pub fn insert(&self, hash: [u8; 32], code: StoredCode) -> Result<(), StoreError> {
        self.codes
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(hash, code);
        Ok(())
    }
}

impl CodeStore for MemoryCodeStore {
    // Bellek erişimi senkron; `async` imzası trait\'in `impl Future + Send`
    // sözleşmesi için. `PostgreSQL` sürümü gerçekten bekleyecek.
    #[allow(clippy::unused_async_trait_impl)]
    async fn load(&self, _t: TenantId, hash: &[u8; 32]) -> Result<StoredCode, StoreError> {
        self.codes
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get(hash)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    // Bellek erişimi senkron; `async` imzası trait\'in `impl Future + Send`
    // sözleşmesi için. `PostgreSQL` sürümü gerçekten bekleyecek.
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

    // Bellek erişimi senkron; `async` imzası trait\'in `impl Future + Send`
    // sözleşmesi için. `PostgreSQL` sürümü gerçekten bekleyecek.
    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke_tokens_issued_for_code(
        &self,
        _t: TenantId,
        _hash: &[u8; 32],
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        // Bellek içi sürümde koddan türeyen token izi tutulmuyor; PostgreSQL
        // sürümü bunu `audit_outbox` ve refresh zinciriyle bağlayacak.
        Ok(())
    }
}

/// Bellek içi refresh token deposu.
#[derive(Debug, Default)]
pub struct MemoryRefreshStore {
    tokens: Mutex<HashMap<[u8; 32], RefreshToken>>,
}

impl MemoryRefreshStore {
    /// Yeni bir token kaydı ekler.
    ///
    /// # Errors
    ///
    /// Kilit zehirlenmişse.
    pub fn insert(&self, hash: [u8; 32], token: RefreshToken) -> Result<(), StoreError> {
        self.tokens
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(hash, token);
        Ok(())
    }
}

impl RefreshStore for MemoryRefreshStore {
    // Bellek erişimi senkron; `async` imzası trait\'in `impl Future + Send`
    // sözleşmesi için. `PostgreSQL` sürümü gerçekten bekleyecek.
    #[allow(clippy::unused_async_trait_impl)]
    async fn load(&self, _t: TenantId, hash: &[u8; 32]) -> Result<RefreshToken, StoreError> {
        self.tokens
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get(hash)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    // Bellek erişimi senkron; `async` imzası trait\'in `impl Future + Send`
    // sözleşmesi için. `PostgreSQL` sürümü gerçekten bekleyecek.
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

    // Bellek erişimi senkron; `async` imzası trait\'in `impl Future + Send`
    // sözleşmesi için. `PostgreSQL` sürümü gerçekten bekleyecek.
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

/// Bellek içi denetim kaydı.
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    events: Mutex<Vec<(String, i64)>>,
}

impl MemoryAuditSink {
    /// Kaydedilmiş olayları verir.
    ///
    /// # Errors
    ///
    /// Kilit zehirlenmişse.
    pub fn events(&self) -> Result<Vec<(String, i64)>, StoreError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .clone())
    }
}

impl AuditSink for MemoryAuditSink {
    // Bellek erişimi senkron; `async` imzası trait\'in `impl Future + Send`
    // sözleşmesi için. `PostgreSQL` sürümü gerçekten bekleyecek.
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
