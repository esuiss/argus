use std::sync::Arc;

use argus_crypto::SigningKey;
use argus_proto::AuthorizationServerMetadata;

use crate::store::{AuditSink, CodeStore, RefreshStore};

pub struct TenantContext {
    pub metadata: AuthorizationServerMetadata,

    pub active_key: Arc<SigningKey>,

    pub published_keys: Vec<Arc<SigningKey>>,
    pub rsa_keys: Vec<Arc<argus_crypto::rsa::RsaSigningKey>>,
    pub blind_index: argus_crypto::blind_index::BlindIndexKey,
    pub relying_party: Option<Arc<argus_proto::webauthn::RelyingParty>>,
}

pub struct AppState<C, R, A, S = (), U = (), P = (), X = ()>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    // §18: host'tan kiracıya çözümleme. Göç sırasında `tenant` ile birlikte
    // duruyor; taşınan her handler kayıt defterinden çözer.
    pub tenants: Arc<crate::tenancy::TenantRegistry>,

    pub codes: C,

    pub refresh: R,

    pub audit: A,

    pub clients: S,

    pub authenticator: U,
    pub replay: P,
    pub resources: X,
    pub cimd: Option<crate::cimd_client::CimdRuntime>,
    pub federation: Option<
        crate::federation::client::FederationRuntime<crate::federation::fetch::SystemResolver>,
    >,
    pub federation_identity: Option<crate::federation::publish::FederationIdentity>,
    pub pushed_requests: Option<Arc<crate::par::ParState>>,
}

impl<C, R, A, S, U, P, X> AppState<C, R, A, S, U, P, X>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    #[must_use]
    pub fn tenants(&self) -> &crate::tenancy::TenantRegistry {
        &self.tenants
    }
}
