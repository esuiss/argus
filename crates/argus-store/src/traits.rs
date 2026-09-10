use argus_core::aal::Aal;
use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::StoredCode;
use argus_core::ciba::BackchannelRequest;
use argus_core::exchange::CrossAppConnection;
use argus_core::id::ClientId;
use argus_core::id::TenantId;
use argus_core::id::UserId;
use argus_core::jag_consume::TrustedIssuer;
use argus_core::recovery::RecoveryAttempt;
use argus_core::refresh::{FamilyId, RefreshToken};
use argus_core::resource::ResourceUri;
use argus_core::scim::ScimRecord;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnSession {
    pub subject: UserId,
    pub achieved: Aal,
    pub authenticated_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyPurpose {
    Registration,
    Authentication,
}

impl CeremonyPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Authentication => "authentication",
        }
    }
}

pub trait AuthnStore {
    fn find_user_by_blind_index(
        &self,
        tenant: TenantId,
        blind_index: &[u8; 32],
    ) -> impl Future<Output = Result<Option<UserId>, StoreError>> + Send;

    fn create_user(
        &self,
        tenant: TenantId,
        user: UserId,
        blind_index: &[u8; 32],
        email_ciphertext: &[u8],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn password_of(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;

    fn set_password(
        &self,
        tenant: TenantId,
        user: UserId,
        phc: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn required_aal(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> impl Future<Output = Result<Aal, StoreError>> + Send;

    fn webauthn_credentials(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send;

    fn store_webauthn_credential(
        &self,
        tenant: TenantId,
        user: UserId,
        credential_id: &[u8],
        rp_id: &str,
        serialised: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn user_for_credential(
        &self,
        tenant: TenantId,
        credential_id: &[u8],
    ) -> impl Future<Output = Result<Option<UserId>, StoreError>> + Send;

    fn advance_sign_count(
        &self,
        tenant: TenantId,
        credential_id: &[u8],
        counter: i64,
        at: Timestamp,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

#[derive(Debug, Clone, Copy)]
pub struct PendingCeremony<'a> {
    pub user: Option<UserId>,
    pub purpose: CeremonyPurpose,
    pub state: &'a str,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}

pub trait CeremonyStore {
    fn store_ceremony(
        &self,
        tenant: TenantId,
        ceremony_hash: &[u8; 32],
        ceremony: &PendingCeremony<'_>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn take_ceremony(
        &self,
        tenant: TenantId,
        ceremony_hash: &[u8; 32],
        purpose: CeremonyPurpose,
        now: Timestamp,
    ) -> impl Future<Output = Result<(Option<UserId>, String), StoreError>> + Send;
}

pub trait RecoveryStore {
    fn open_recovery(
        &self,
        tenant: TenantId,
        attempt_id: uuid::Uuid,
        attempt: &RecoveryAttempt,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn load_recovery(
        &self,
        tenant: TenantId,
        attempt_id: uuid::Uuid,
    ) -> impl Future<Output = Result<RecoveryAttempt, StoreError>> + Send;

    fn advance_recovery(
        &self,
        tenant: TenantId,
        attempt_id: uuid::Uuid,
        attempt: &RecoveryAttempt,
        at: Timestamp,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

pub trait SessionStore {
    fn create_session(
        &self,
        tenant: TenantId,
        session_hash: &[u8; 32],
        session: &AuthnSession,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn load_session(
        &self,
        tenant: TenantId,
        session_hash: &[u8; 32],
        now: Timestamp,
    ) -> impl Future<Output = Result<AuthnSession, StoreError>> + Send;

    fn revoke_session(
        &self,
        tenant: TenantId,
        session_hash: &[u8; 32],
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimConflict {
    UserNameTaken,
    ExternalIdTaken,
    UnknownMember(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScimStoreError {
    #[error("record not found")]
    NotFound,

    #[error("storage backend unavailable")]
    Unavailable,

    #[error("the resource conflicts with one that already exists")]
    Conflict(ScimConflict),
}

impl From<StoreError> for ScimStoreError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::NotFound,
            StoreError::Unavailable => Self::Unavailable,
        }
    }
}

pub trait ScimStore {
    fn create_user(
        &self,
        tenant: TenantId,
        payload: &serde_json::Value,
        now: Timestamp,
    ) -> impl Future<Output = Result<ScimRecord, ScimStoreError>> + Send;

    fn get_user(
        &self,
        tenant: TenantId,
        id: &str,
    ) -> impl Future<Output = Result<ScimRecord, ScimStoreError>> + Send;

    fn replace_user(
        &self,
        tenant: TenantId,
        id: &str,
        payload: &serde_json::Value,
        now: Timestamp,
    ) -> impl Future<Output = Result<ScimRecord, ScimStoreError>> + Send;

    fn delete_user(
        &self,
        tenant: TenantId,
        id: &str,
    ) -> impl Future<Output = Result<(), ScimStoreError>> + Send;

    fn scan_users(
        &self,
        tenant: TenantId,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<ScimRecord>, ScimStoreError>> + Send;

    fn create_group(
        &self,
        tenant: TenantId,
        payload: &serde_json::Value,
        now: Timestamp,
    ) -> impl Future<Output = Result<ScimRecord, ScimStoreError>> + Send;

    fn get_group(
        &self,
        tenant: TenantId,
        id: &str,
    ) -> impl Future<Output = Result<ScimRecord, ScimStoreError>> + Send;

    fn replace_group(
        &self,
        tenant: TenantId,
        id: &str,
        payload: &serde_json::Value,
        now: Timestamp,
    ) -> impl Future<Output = Result<ScimRecord, ScimStoreError>> + Send;

    fn delete_group(
        &self,
        tenant: TenantId,
        id: &str,
    ) -> impl Future<Output = Result<(), ScimStoreError>> + Send;

    fn scan_groups(
        &self,
        tenant: TenantId,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<ScimRecord>, ScimStoreError>> + Send;
}
