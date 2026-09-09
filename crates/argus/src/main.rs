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

use argus_core::authorize::RegisteredClient;
use argus_core::id::TenantId;
use argus_core::id::{ClientId, UserId};
use argus_core::redirect_uri::RedirectUri;
use argus_crypto::SigningKey;
use argus_http::endpoints::authorize::DevAuthenticator;
use argus_http::memstore::{
    MemoryAuditSink, MemoryClientStore, MemoryCodeStore, MemoryRefreshStore,
};
use argus_http::state::{AppState, TenantContext};
use argus_proto::AuthorizationServerMetadata;
use uuid::Uuid;

/// Ortamdan okunan konfigürasyon.
struct Config {
    issuer: String,
    bind: String,
    /// Ayarlıysa `PostgreSQL` kullanılır; değilse bellek içi depo.
    database_url: Option<String>,
}

impl Config {
    fn from_env() -> Self {
        Self {
            issuer: env::var("ARGUS_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_owned()),
            bind: env::var("ARGUS_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned()),
            database_url: env::var("ARGUS_DATABASE_URL").ok(),
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

    // ⚠️ Geliştirme kaydı: gerçek istemci yönetimi admin API ile gelecek.
    let clients = MemoryClientStore::default();
    let Ok(demo_client) = ClientId::new("demo-client") else {
        eprintln!("argus: invalid demo client_id");
        return ExitCode::FAILURE;
    };
    let Ok(demo_redirect) = RedirectUri::register("http://127.0.0.1/callback") else {
        eprintln!("argus: invalid demo redirect_uri");
        return ExitCode::FAILURE;
    };
    if clients
        .insert(RegisteredClient {
            client_id: demo_client,
            redirect_uris: vec![demo_redirect],
        })
        .is_err()
    {
        eprintln!("argus: failed to seed the demo client");
        return ExitCode::FAILURE;
    }

    if let Some(url) = config.database_url.clone() {
        return serve_with_postgres(&config, &url, key).await;
    }

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
        clients,
        // ⚠️ Faz 1 geçici kimlik doğrulayıcısı. Faz 3 bunu WebAuthn ve parola
        // akışlarıyla değiştirecek; adı bilerek "Dev".
        authenticator: DevAuthenticator {
            user: UserId::from_uuid(Uuid::from_u128(1)),
        },
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
    eprintln!(
        "argus: WARNING - in-memory store, keys regenerated on restart, DevAuthenticator active"
    );
    eprintln!("argus: WARNING - development configuration, not for production");

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

/// `PostgreSQL` destekli sunucu.
///
/// Depo, `AppState`'in beş genel parametresinden dördünü birden karşılıyor:
/// `PostgresStore` kod, refresh, denetim ve istemci arayüzlerinin hepsini
/// uyguluyor. Bu bir kolaylık değil, kararın sonucu — §1 #23 denetim kaydının
/// iş değişikliğiyle **aynı transaction'da** olmasını istiyor ve bu ancak aynı
/// havuz üzerinden mümkün.
async fn serve_with_postgres(
    config: &Config,
    url: &str,
    key: Arc<argus_crypto::SigningKey>,
) -> ExitCode {
    let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(url)
        .await
    else {
        eprintln!("argus: cannot connect to the database");
        return ExitCode::FAILURE;
    };

    let store = argus_store::PostgresStore::new(pool);

    let state = Arc::new(AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer(&config.issuer),
            active_key: Arc::clone(&key),
            published_keys: vec![key],
        },
        codes: store.clone(),
        refresh: store.clone(),
        audit: store.clone(),
        tenant_id: TenantId::from_uuid(Uuid::nil()),
        clients: store,
        // ⚠️ Faz 1 geçici kimlik doğrulayıcısı; Faz 3 değiştirecek.
        authenticator: DevAuthenticator {
            user: UserId::from_uuid(Uuid::from_u128(1)),
        },
    });

    let app = argus_http::build(state);

    let Ok(listener) = tokio::net::TcpListener::bind(&config.bind).await else {
        eprintln!("argus: cannot bind {}", config.bind);
        return ExitCode::FAILURE;
    };

    eprintln!(
        "argus: listening on {} (issuer {}, PostgreSQL)",
        config.bind, config.issuer
    );
    eprintln!("argus: WARNING - DevAuthenticator active, development only");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
    {
        eprintln!("argus: server error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
