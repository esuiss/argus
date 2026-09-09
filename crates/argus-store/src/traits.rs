use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::StoredCode;
use argus_core::ciba::BackchannelRequest;
use argus_core::exchange::CrossAppConnection;
use argus_core::id::ClientId;
use argus_core::id::TenantId;
use argus_core::jag_consume::TrustedIssuer;
use argus_core::refresh::{FamilyId, RefreshToken};
use argus_core::resource::ResourceUri;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiPurpose {
    DpopProof,
    ClientAssertion,
}

impl JtiPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DpopProof => "dpop_proof",
            Self::ClientAssertion => "client_assertion",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiOutcome {
    Fresh,
    Replayed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResource {
    pub uri: ResourceUri,
    pub name: Option<String>,
    pub scopes: Option<String>,
}

pub trait ResourceStore {
    fn find_resource(
        &self,
        tenant: TenantId,
        uri: &ResourceUri,
    ) -> impl Future<Output = Result<Option<ProtectedResource>, StoreError>> + Send;

    fn list_resources(
        &self,
        tenant: TenantId,
    ) -> impl Future<Output = Result<Vec<ProtectedResource>, StoreError>> + Send;
}

pub trait BackchannelStore {
    fn create_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        request: &BackchannelRequest,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn load_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
    ) -> impl Future<Output = Result<BackchannelRequest, StoreError>> + Send;

    fn record_backchannel_poll(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn consume_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        at: Timestamp,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn decide_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        approved: bool,
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

pub trait IssuerStore {
    fn trusted_issuers(
        &self,
        tenant: TenantId,
    ) -> impl Future<Output = Result<Vec<TrustedIssuer>, StoreError>> + Send;
}

pub trait ConnectionStore {
    fn find_connection(
        &self,
        tenant: TenantId,
        client: &ClientId,
        resource_as_issuer: &str,
    ) -> impl Future<Output = Result<Option<CrossAppConnection>, StoreError>> + Send;
}

pub trait ReplayStore {
    fn consume_jti(
        &self,
        tenant: TenantId,
        purpose: JtiPurpose,
        jti: &str,
        expires_at: Timestamp,
    ) -> impl Future<Output = Result<JtiOutcome, StoreError>> + Send;

    fn purge_expired_jtis(
        &self,
        tenant: TenantId,
        now: Timestamp,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

pub trait AuditSink {
    fn record(
        &self,
        tenant: TenantId,
        event_type: &str,
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}
