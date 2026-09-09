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
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
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
    /// İmzalama anahtarlarının bulunduğu dizin.
    ///
    /// §1 #25: özel anahtar **veritabanının dışındadır** ve backend
    /// pluggable'dır. Dosya sistemi en basit backend'dir; `KMS`/`PKCS#11`
    /// aynı sınırın arkasına girer.
    key_dir: Option<String>,
    /// Aktif anahtarın `kid`'i. Belirtilmezse sıradaki son anahtar aktiftir.
    active_kid: Option<String>,
}

impl Config {
    fn from_env() -> Self {
        Self {
            issuer: env::var("ARGUS_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_owned()),
            bind: env::var("ARGUS_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned()),
            database_url: env::var("ARGUS_DATABASE_URL").ok(),
            key_dir: env::var("ARGUS_SIGNING_KEY_DIR").ok(),
            active_kid: env::var("ARGUS_ACTIVE_KID").ok(),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // Anahtar üretimi sunucuyu ayağa kaldırmadan yapılabilmeli: rotasyon bir
    // dosya eklemekten ibaret olmalı ve bunun için sunucuyu durdurmak
    // gerekmemeli.
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("keygen") {
        return keygen(args.get(1..).unwrap_or_default());
    }

    let config = Config::from_env();

    // §1 #4: imzalama anahtarı kiracı başınadır. §1 #25: özel anahtar DB'nin
    // DIŞINDADIR.
    let keys = match load_keys(&config) {
        Ok(k) => k,
        Err(message) => {
            eprintln!("argus: {message}");
            return ExitCode::FAILURE;
        }
    };

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
            // Public client: sır yok, PKCE zorunlu (OAuth 2.1).
            auth_method: argus_core::client_auth::ClientAuthMethod::None,
            keys: Vec::new(),
        })
        .is_err()
    {
        eprintln!("argus: failed to seed the demo client");
        return ExitCode::FAILURE;
    }

    if let Some(url) = config.database_url.clone() {
        return serve_with_postgres(&config, &url, &keys).await;
    }

    let state = Arc::new(AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer(&config.issuer),
            active_key: Arc::clone(&keys.active),
            published_keys: keys.published.clone(),
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
    eprintln!("argus: WARNING - in-memory store, DevAuthenticator active");
    warn_if_keys_are_ephemeral(&config);
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

/// `argus keygen <kid> <dizin>` — yeni bir imzalama anahtarı yazar.
///
/// # Neden ayrı bir komut, neden `openssl` değil
///
/// `aws-lc-rs`, `PKCS#8` içinde açık anahtarın da bulunmasını bekler; `openssl
/// genpkey`'in varsayılan çıktısı bunu içermez ve yüklenirken reddedilir.
/// Operatörü bu ayrıntıyla uğraştırmak, rotasyonun hiç yapılmamasına yol açar.
///
/// Dosya `0600` ile yazılır ve **üzerine yazmaz**: var olan bir `kid`'i
/// ezmek, o anahtarla imzalanmış dolaşımdaki tüm token'ları doğrulanamaz kılar.
fn keygen(args: &[String]) -> ExitCode {
    let (Some(kid), Some(dir)) = (args.first(), args.get(1)) else {
        eprintln!("usage: argus keygen <kid> <directory>");
        return ExitCode::FAILURE;
    };

    if kid.is_empty() || kid.contains(['/', '\\', '.']) {
        eprintln!("argus: kid must not be empty or contain path separators or dots");
        return ExitCode::FAILURE;
    }

    let path = Path::new(dir).join(format!("{kid}.pkcs8"));
    if path.exists() {
        eprintln!(
            "argus: {} already exists; refusing to overwrite",
            path.display()
        );
        return ExitCode::FAILURE;
    }

    let Ok((_, pkcs8)) = SigningKey::generate(kid.clone()) else {
        eprintln!("argus: failed to generate a signing key");
        return ExitCode::FAILURE;
    };

    // Önce izinlerle birlikte oluştur, SONRA yaz: önce yazıp sonra `chmod`
    // yapmak, aradaki pencerede özel anahtarı herkese okunur bırakır.
    let opened = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path);

    let Ok(mut file) = opened else {
        eprintln!("argus: cannot create {}", path.display());
        return ExitCode::FAILURE;
    };

    if file.write_all(&pkcs8).is_err() {
        eprintln!("argus: cannot write {}", path.display());
        return ExitCode::FAILURE;
    }

    println!("{}", path.display());
    ExitCode::SUCCESS
}

/// Yayınlanan anahtar seti.
///
/// # Neden aktif ve yayınlanan AYRI
///
/// §1 §9'un çıkış kriteri *"anahtar rotasyonunda 0 adet 401"*. Bunun tek yolu,
/// yeni anahtarla imzalarken **eski anahtarı yayınlamaya devam etmektir**:
/// dolaşımdaki token'lar hâlâ eskiyle imzalıdır ve RP'lerin `JWKS` cache'i
/// hemen tazelenmez. Tek anahtarlı bir model bu kriteri sağlayamaz.
struct KeySet {
    /// Yeni token'ları imzalayan anahtar.
    active: Arc<SigningKey>,
    /// `JWKS`'te yayınlanan tüm anahtarlar; `active` de içindedir.
    published: Vec<Arc<SigningKey>>,
}

/// Anahtarları yükler.
///
/// `ARGUS_SIGNING_KEY_DIR` ayarlıysa dizindeki `*.pkcs8` dosyaları okunur ve
/// dosya adının uzantısız hâli `kid` olur. Ayarlı değilse **geliştirme için**
/// tek seferlik bir anahtar üretilir.
///
/// # Neden dizin
///
/// Rotasyon bir dosya eklemekten ibaret olmalı. Anahtarı koda ya da veritabanına
/// gömmek, rotasyonu bir dağıtım ya da şema işine çevirir ve o da rotasyonun
/// hiç yapılmamasına yol açar.
fn load_keys(config: &Config) -> Result<KeySet, String> {
    let Some(dir) = config.key_dir.as_deref() else {
        let (key, _pkcs8) =
            SigningKey::generate("dev-key-1").map_err(|_| "failed to generate a signing key")?;
        let key = Arc::new(key);
        return Ok(KeySet {
            active: Arc::clone(&key),
            published: vec![key],
        });
    };

    let entries = std::fs::read_dir(dir).map_err(|_| format!("cannot read key directory {dir}"))?;

    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("pkcs8") {
            continue;
        }
        let Some(kid) = path.file_stem().and_then(OsStr::to_str) else {
            continue;
        };
        found.push((kid.to_owned(), path));
    }

    // Sıralama belirleyici olmalı: aktif anahtar `ARGUS_ACTIVE_KID` ile
    // seçilmezse "sıradaki son" olur ve dizin okuma sırası platforma göre
    // değişir. Belirsiz bir aktif anahtar, yeniden başlatmada sessizce
    // değişen bir imzalayan demektir.
    found.sort_by(|a, b| a.0.cmp(&b.0));

    if found.is_empty() {
        return Err(format!("no *.pkcs8 signing keys in {dir}"));
    }

    let mut published = Vec::with_capacity(found.len());
    for (kid, path) in &found {
        let bytes = std::fs::read(path).map_err(|_| format!("cannot read key {kid}"))?;
        let key = SigningKey::from_pkcs8(kid.clone(), &bytes)
            .map_err(|_| format!("key {kid} is not a valid PKCS#8 P-256 private key"))?;
        published.push(Arc::new(key));
    }

    let active = match config.active_kid.as_deref() {
        Some(wanted) => published
            .iter()
            .find(|k| k.kid() == wanted)
            .ok_or_else(|| format!("ARGUS_ACTIVE_KID={wanted} is not present in {dir}"))?,
        // Belirtilmezse sıradaki son. Rotasyon "yeni anahtarı ekle" ile
        // başlar ve `ARGUS_ACTIVE_KID` ile kontrollü şekilde devreye alınır.
        None => published.last().ok_or("no keys")?,
    };

    Ok(KeySet {
        active: Arc::clone(active),
        published: published.clone(),
    })
}

/// Anahtarlar geçiciyse uyarır.
///
/// Her başlatmada yeni anahtar üretmek, yeniden başlatmada dolaşımdaki TÜM
/// token'ları doğrulanamaz kılar — §1 §9'un "0 adet 401" kriterinin tam tersi.
/// Sessizce yapmak, sorunu ancak üretimde fark ettirir.
fn warn_if_keys_are_ephemeral(config: &Config) {
    if config.key_dir.is_none() {
        eprintln!(
            "argus: WARNING - no ARGUS_SIGNING_KEY_DIR; a throwaway key is generated at \
             every start and every previously issued token becomes unverifiable on restart"
        );
    }
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
async fn serve_with_postgres(config: &Config, url: &str, keys: &KeySet) -> ExitCode {
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
            active_key: Arc::clone(&keys.active),
            published_keys: keys.published.clone(),
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
    warn_if_keys_are_ephemeral(config);

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
    {
        eprintln!("argus: server error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
