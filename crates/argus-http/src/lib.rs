#![forbid(unsafe_code)]

pub mod cimd_client;
pub mod cimd_fetch;
pub mod differentiation;
pub mod effects;
pub mod endpoints;
pub mod federation;
pub mod memstore;
pub mod par;
pub mod replay;
pub mod router;
pub mod saml;
pub mod scim;
pub mod state;
pub use argus_store::traits as store;

pub use router::build;
pub use state::AppState;
