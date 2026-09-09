use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::StoredCode;
use argus_core::id::ClientId;
use argus_core::id::TenantId;
use argus_core::refresh::{FamilyId, RefreshToken};
use core::future::Future;

use argus_core::time::Timestamp;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("record not found")]
    NotFound,

    #[error("storage backend unavailable")]
    Unavailable,
}

pub trait CodeStore {
    fn load(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
    ) -> impl Future<Output = Result<StoredCode, StoreError>> + Send;

    fn consume(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn revoke_tokens_issued_for_code(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

pub trait ClientStore {
    fn find(
        &self,
        tenant: TenantId,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<RegisteredClient>, StoreError>> + Send;
}

pub trait CodeIssuer {
    fn issue(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        code: &StoredCode,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

pub trait RefreshStore {
    fn load(
        &self,
        tenant: TenantId,
        token_hash: &[u8; 32],
    ) -> impl Future<Output = Result<RefreshToken, StoreError>> + Send;

    fn rotate(
        &self,
        tenant: TenantId,
        old_hash: &[u8; 32],
        new_hash: &[u8; 32],
        new_token: &RefreshToken,
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn revoke_family(
        &self,
        tenant: TenantId,
        family: FamilyId,
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

pub trait AuditSink {
    fn record(
        &self,
        tenant: TenantId,
        event_type: &str,
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}
