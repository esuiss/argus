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
    MemoryAuditSink, MemoryClientStore, MemoryCodeStore, MemoryRefreshStore, MemoryReplayStore,
};
use argus_http::state::{AppState, TenantContext};
use argus_proto::AuthorizationServerMetadata;
use uuid::Uuid;

struct Config {
    issuer: String,
    bind: String,

    database_url: Option<String>,

    key_dir: Option<String>,

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
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("keygen") {
        return keygen(args.get(1..).unwrap_or_default());
    }

    let config = Config::from_env();

    let keys = match load_keys(&config) {
        Ok(k) => k,
        Err(message) => {
            eprintln!("argus: {message}");
            return ExitCode::FAILURE;
        }
    };

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

        authenticator: DevAuthenticator {
            user: UserId::from_uuid(Uuid::from_u128(1)),
        },
        replay: MemoryReplayStore::default(),
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

struct KeySet {
    active: Arc<SigningKey>,

    published: Vec<Arc<SigningKey>>,
}

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

        None => published.last().ok_or("no keys")?,
    };

    Ok(KeySet {
        active: Arc::clone(active),
        published: published.clone(),
    })
}

fn warn_if_keys_are_ephemeral(config: &Config) {
    if config.key_dir.is_none() {
        eprintln!(
            "argus: WARNING - no ARGUS_SIGNING_KEY_DIR; a throwaway key is generated at \
             every start and every previously issued token becomes unverifiable on restart"
        );
    }
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("argus: shutting down");
}

async fn serve_with_postgres(config: &Config, url: &str, keys: &KeySet) -> ExitCode {
    let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(url)
        .await
    else {
        eprintln!("argus: cannot connect to the database");
        return ExitCode::FAILURE;
    };

    if let Err(e) = argus_store::schema::validate(&pool).await {
        eprintln!("argus: schema validation failed: {e}");
        eprintln!("argus: run the migration job before starting the server");
        return ExitCode::FAILURE;
    }

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
        clients: store.clone(),

        authenticator: DevAuthenticator {
            user: UserId::from_uuid(Uuid::from_u128(1)),
        },
        replay: store,
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
