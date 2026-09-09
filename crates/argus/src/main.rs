//! Argus sunucusu.
//!
//! # Bu dosyanın işi
//!
//! Yalnızca **bağlama**: konfigürasyonu okur, anahtarı yükler, durumu kurar,
//! dinlemeye başlar. İş mantığı yok — olsaydı `argus-core`'un yanlış yerinde
//! olurdu.
//!
//! # Başlatma sırası
//!
//! §11 §8591: init → serve. Önce konfigürasyon, `TLS`, anahtar materyali ve port
//! bind edilir; sertleştirme (`Landlock`/seccomp) ondan **sonra** uygulanır, çünkü
//! kısıtlar bir kez konduktan sonra dosya ve soket açılamaz. Sertleştirme
//! `argus-sandbox` ile gelecek.

// `Cargo.toml` zaten `unsafe_code = "forbid"` uyguluyor. Attribute ayrıca
// yazılıyor çünkü kaynak dosyayı okuyan araçlar (cargo-geiger) lint tablosunu
// görmüyor — Faz 0 çıkış kriteri o araçla ifade edilmiş.
#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use argus_core::id::TenantId;
use argus_crypto::SigningKey;
use argus_http::memstore::{MemoryAuditSink, MemoryCodeStore, MemoryRefreshStore};
use argus_http::state::{AppState, TenantContext};
use argus_proto::AuthorizationServerMetadata;
use uuid::Uuid;

/// Ortamdan okunan konfigürasyon.
struct Config {
    issuer: String,
    bind: String,
}

impl Config {
    fn from_env() -> Self {
        Self {
            issuer: env::var("ARGUS_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_owned()),
            bind: env::var("ARGUS_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned()),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = Config::from_env();

    // §1 #4: imzalama anahtarı kiracı başınadır. §1 #25: özel anahtar DB'nin
    // dışındadır. Şu an her başlatmada yeni bir anahtar üretiliyor — bu yalnızca
    // geliştirme içindir ve üretimde pluggable backend'den (dosya/KMS/PKCS#11)
    // yüklenecek. Yeniden başlatmada anahtar değişirse dolaşımdaki token'lar
    // doğrulanamaz.
    let Ok((key, _pkcs8)) = SigningKey::generate("dev-key-1") else {
        eprintln!("argus: failed to generate a signing key");
        return ExitCode::FAILURE;
    };
    let key = Arc::new(key);

    let state = Arc::new(AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer(&config.issuer),
            active_key: Arc::clone(&key),
            published_keys: vec![key],
        },
        codes: MemoryCodeStore::default(),
        refresh: MemoryRefreshStore::default(),
        audit: MemoryAuditSink::default(),
        tenant_id: TenantId::from_uuid(Uuid::nil()),
    });

    let app = argus_http::build(state);

    let Ok(listener) = tokio::net::TcpListener::bind(&config.bind).await else {
        eprintln!("argus: cannot bind {}", config.bind);
        return ExitCode::FAILURE;
    };

    eprintln!(
        "argus: listening on {} (issuer {})",
        config.bind, config.issuer
    );
    eprintln!("argus: WARNING — in-memory store, keys regenerated on restart; development only");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
    {
        eprintln!("argus: server error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// `SIGINT`'te düzgün kapanır.
///
/// Yarıda kesilen bir token isteği, istemcide belirsiz bir duruma yol açar:
/// token verildi mi verilmedi mi bilinmez. Graceful shutdown bunu önler.
async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("argus: shutting down");
}
