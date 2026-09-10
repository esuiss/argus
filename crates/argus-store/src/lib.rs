#![forbid(unsafe_code)]

pub mod directory;
pub mod par;
pub mod postgres;
pub mod schema;
pub mod scim;
pub mod traits;
pub mod vault;

pub use postgres::PostgresStore;
pub use schema::{EXPECTED_MIGRATIONS, SchemaError};
pub use traits::{
    AuditSink, BackchannelStore, ClientStore, CodeIssuer, CodeStore, ConnectionStore, JtiOutcome,
    JtiPurpose, ProtectedResource, RefreshStore, ReplayStore, ResourceStore, ScimConflict,
    ScimStore, ScimStoreError, StoreError,
};
