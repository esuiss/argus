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
    MemoryResourceStore,
};
use argus_http::state::{AppState, TenantContext};
use argus_proto::AuthorizationServerMetadata;
use uuid::Uuid;

struct Config {
    issuer: String,
    bind: String,

    database_url: Option<String>,

    key_dir: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    production: bool,

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
            tls_cert: env::var("ARGUS_TLS_CERT").ok(),
            tls_key: env::var("ARGUS_TLS_KEY").ok(),
            production: env::var("ARGUS_ENV").is_ok_and(|v| v == "production"),
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
        resources: MemoryResourceStore::default(),
        cimd: Some(cimd_runtime()),
    });

    let app = argus_http::build(state);

    eprintln!("argus: WARNING - in-memory store, DevAuthenticator active");
    warn_if_keys_are_ephemeral(&config);
    eprintln!("argus: WARNING - development configuration, not for production");

    serve(app, &config, "in-memory").await
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

async fn serve(app: axum::Router, config: &Config, store_kind: &str) -> ExitCode {
    let tls = match tls_config(config) {
        Ok(tls) => tls,
        Err(message) => {
            eprintln!("argus: {message}");
            return ExitCode::FAILURE;
        }
    };

    let Ok(listener) = tokio::net::TcpListener::bind(&config.bind).await else {
        eprintln!("argus: cannot bind {}", config.bind);
        return ExitCode::FAILURE;
    };

    let scheme = if tls.is_some() { "https" } else { "http" };
    eprintln!(
        "argus: listening on {} over {scheme} (issuer {}, {store_kind})",
        config.bind, config.issuer
    );

    if let Some(tls) = tls {
        return serve_tls(listener, app, tls).await;
    }

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
    {
        eprintln!("argus: server error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn cimd_runtime() -> argus_http::cimd_client::CimdRuntime {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    argus_http::cimd_client::CimdRuntime::new(std::sync::Arc::new(client_config))
}

fn tls_config(config: &Config) -> Result<Option<Arc<rustls::ServerConfig>>, String> {
    let (cert_path, key_path) = match (config.tls_cert.as_deref(), config.tls_key.as_deref()) {
        (Some(c), Some(k)) => (c, k),
        (None, None) => {
            if config.production {
                return Err(
                    "ARGUS_ENV=production requires ARGUS_TLS_CERT and ARGUS_TLS_KEY; \
                     refusing to serve an identity provider over plaintext"
                        .to_owned(),
                );
            }
            eprintln!(
                "argus: WARNING - no TLS; every token and authorization code crosses \
                 the network in plaintext (MCP AS-M4 requires HTTPS)"
            );
            return Ok(None);
        }
        _ => {
            return Err("ARGUS_TLS_CERT and ARGUS_TLS_KEY must be set together".to_owned());
        }
    };

    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("the certificate and key do not match: {e}"))?;

    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Some(Arc::new(server_config)))
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|_| format!("cannot read {path}"))?;
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut data.as_slice()).collect();
    let certs = certs.map_err(|_| format!("{path} is not a valid PEM certificate chain"))?;
    if certs.is_empty() {
        return Err(format!("{path} contains no certificates"));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|_| format!("cannot read {path}"))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|_| format!("{path} is not a valid PEM private key"))?
        .ok_or_else(|| format!("{path} contains no private key"))
}

async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: Arc<rustls::ServerConfig>,
) -> ExitCode {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let mut stop = Box::pin(shutdown());

    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            () = &mut stop => break,
        };

        let Ok((stream, _peer)) = accepted else {
            continue;
        };

        let acceptor = acceptor.clone();
        let service = hyper_util::service::TowerToHyperService::new(app.clone());

        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
        });
    }

    ExitCode::SUCCESS
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
        replay: store.clone(),
        resources: store,
        cimd: Some(cimd_runtime()),
    });

    let app = argus_http::build(state);

    eprintln!("argus: WARNING - DevAuthenticator active, development only");
    warn_if_keys_are_ephemeral(config);

    serve(app, config, "PostgreSQL").await
}
