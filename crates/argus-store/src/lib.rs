//! `argus-store` — PostgreSQL depolama katmanı.
//!
//! Karar mantığı yoktur; `argus-core` karar verir, burası kalıcılaştırır.

// `Cargo.toml` zaten `unsafe_code = "forbid"` uyguluyor. Attribute ayrıca
// yazılıyor çünkü kaynak dosyayı okuyan araçlar (cargo-geiger) lint tablosunu
// görmüyor.
#![forbid(unsafe_code)]

pub mod postgres;
pub mod traits;

pub use postgres::PostgresStore;
pub use traits::{AuditSink, ClientStore, CodeIssuer, CodeStore, RefreshStore, StoreError};
