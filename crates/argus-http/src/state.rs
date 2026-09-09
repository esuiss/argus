use std::sync::Arc;

use argus_crypto::SigningKey;
use argus_proto::AuthorizationServerMetadata;

use crate::store::{AuditSink, CodeStore, RefreshStore};

pub struct TenantContext {
    pub metadata: AuthorizationServerMetadata,

    pub active_key: Arc<SigningKey>,

    pub published_keys: Vec<Arc<SigningKey>>,
}

pub struct AppState<C, R, A, S = (), U = (), P = (), X = ()>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    pub tenant: TenantContext,

    pub codes: C,

    pub refresh: R,

    pub audit: A,

    pub tenant_id: argus_core::id::TenantId,

    pub clients: S,

    pub authenticator: U,
    pub replay: P,
    pub resources: X,
}

impl<C, R, A, S, U, P, X> AppState<C, R, A, S, U, P, X>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    #[must_use]
    pub const fn tenant_id(&self) -> argus_core::id::TenantId {
        self.tenant_id
    }
}
