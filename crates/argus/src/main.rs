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
use argus_core::id::ClientId;
use argus_core::id::TenantId;
use argus_core::redirect_uri::RedirectUri;
use argus_crypto::SigningKey;
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

    scim_event_audience: Option<String>,

    saml_key: Option<String>,
    saml_cert: Option<String>,
    saml_entity_id: Option<String>,
    saml_sp_dir: Option<String>,

    ldap_bind: Option<String>,
    ldap_base_dn: Option<String>,
    ldap_cert: Option<String>,
    ldap_key: Option<String>,
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
            scim_event_audience: env::var("ARGUS_SCIM_EVENT_AUDIENCE").ok(),
            saml_key: env::var("ARGUS_SAML_KEY").ok(),
            saml_cert: env::var("ARGUS_SAML_CERT").ok(),
            saml_entity_id: env::var("ARGUS_SAML_ENTITY_ID").ok(),
            saml_sp_dir: env::var("ARGUS_SAML_SP_DIR").ok(),
            ldap_bind: env::var("ARGUS_LDAP_BIND").ok(),
            ldap_base_dn: env::var("ARGUS_LDAP_BASE_DN").ok(),
            ldap_cert: env::var("ARGUS_LDAP_CERT").ok(),
            ldap_key: env::var("ARGUS_LDAP_KEY").ok(),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("keygen") {
        return keygen(args.get(1..).unwrap_or_default());
    }

    if args.first().map(String::as_str) == Some("ldap") {
        return serve_ldap().await;
    }

    if args.first().map(String::as_str) == Some("token") {
        return mint_token(args.get(1..).unwrap_or_default());
    }

    let config = Config::from_env();

    let blind_index = match load_blind_index(&config) {
        Ok(key) => key,
        Err(message) => {
            eprintln!("argus: {message}");
            return ExitCode::FAILURE;
        }
    };

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
        return serve_with_postgres(&config, &url, &keys, &blind_index).await;
    }

    let state = Arc::new(AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer(&config.issuer),
            active_key: Arc::clone(&keys.active),
            published_keys: keys.published.clone(),
            blind_index: blind_index.clone(),
            relying_party: relying_party(&config),
        },
        codes: MemoryCodeStore::default(),
        refresh: MemoryRefreshStore::default(),
        audit: MemoryAuditSink::default(),
        tenant_id: TenantId::from_uuid(Uuid::nil()),
        clients,

        authenticator: (),
        replay: MemoryReplayStore::default(),
        resources: MemoryResourceStore::default(),
        cimd: Some(cimd_runtime(&config)),
    });

    let app = argus_http::build(state);

    eprintln!("argus: WARNING - in-memory store, DevAuthenticator active");
    warn_if_keys_are_ephemeral(&config);
    eprintln!("argus: WARNING - development configuration, not for production");

    serve(app, &config, "in-memory").await
}

struct StorePasswords {
    entries: std::collections::HashMap<String, String>,
}

impl argus_ldap::session::PasswordCheck for StorePasswords {
    fn verify(&self, dn: &str, password: &[u8]) -> bool {
        let Ok(parsed) = argus_core::ldap::Dn::parse(dn) else {
            return false;
        };
        let Some(uid) = parsed.first_value("uid") else {
            return false;
        };
        let Some(stored) = self.entries.get(&uid.to_lowercase()) else {
            return false;
        };
        let Ok(candidate) = core::str::from_utf8(password) else {
            return false;
        };
        matches!(
            argus_crypto::password::verify(candidate, stored),
            Ok(argus_crypto::password::Verdict::Correct
                | argus_crypto::password::Verdict::CorrectButNeedsRehash)
        )
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the gateway start-up sequence reads as one list of preconditions"
)]
async fn serve_ldap() -> ExitCode {
    let config = Config::from_env();

    let Some(bind) = config.ldap_bind.clone() else {
        eprintln!("argus: set ARGUS_LDAP_BIND to the address the directory listens on");
        return ExitCode::FAILURE;
    };

    let base_text = config
        .ldap_base_dn
        .clone()
        .unwrap_or_else(|| "dc=idm,dc=example,dc=com".to_owned());

    let Ok(base) = argus_core::ldap::Dn::parse(&base_text) else {
        eprintln!("argus: ARGUS_LDAP_BASE_DN is not a distinguished name");
        return ExitCode::FAILURE;
    };

    let Some(url) = config.database_url.clone() else {
        eprintln!("argus: the directory gateway reads from the database; set ARGUS_DATABASE_URL");
        return ExitCode::FAILURE;
    };

    let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
    else {
        eprintln!("argus: cannot connect to the database");
        return ExitCode::FAILURE;
    };

    if let Err(e) = argus_store::schema::validate(&pool).await {
        eprintln!("argus: schema validation failed: {e}");
        return ExitCode::FAILURE;
    }

    let tenant = TenantId::from_uuid(Uuid::nil());

    let (people, groups, passwords) = match argus_store::directory::load(&pool, tenant).await {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("argus: cannot read the directory: {e}");
            return ExitCode::FAILURE;
        }
    };

    let directory = argus_ldap::directory::Directory {
        base,
        base_text,
        vendor_version: env!("CARGO_PKG_VERSION").to_owned(),
        start_tls_offered: false,
        people,
        groups,
    };

    eprintln!(
        "argus: directory gateway with {} people and {} groups",
        directory.people.len(),
        directory.groups.len()
    );

    let service = Arc::new(argus_ldap::server::Service {
        directory,
        passwords: StorePasswords { entries: passwords },
    });

    let tls = match (config.ldap_cert.as_deref(), config.ldap_key.as_deref()) {
        (Some(cert), Some(key)) => {
            let certs = match load_certs(cert) {
                Ok(certs) => certs,
                Err(message) => {
                    eprintln!("argus: {message}");
                    return ExitCode::FAILURE;
                }
            };
            let key = match load_key(key) {
                Ok(key) => key,
                Err(message) => {
                    eprintln!("argus: {message}");
                    return ExitCode::FAILURE;
                }
            };
            match rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
            {
                Ok(server) => Some(Arc::new(server)),
                Err(e) => {
                    eprintln!("argus: the certificate and key do not match: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        (None, None) => None,
        _ => {
            eprintln!("argus: ARGUS_LDAP_CERT and ARGUS_LDAP_KEY must be set together");
            return ExitCode::FAILURE;
        }
    };

    if tls.is_none() && config.production {
        eprintln!("argus: ARGUS_ENV=production requires ARGUS_LDAP_CERT and ARGUS_LDAP_KEY");
        return ExitCode::FAILURE;
    }

    let Ok(listener) = tokio::net::TcpListener::bind(&bind).await else {
        eprintln!("argus: cannot listen on {bind}");
        return ExitCode::FAILURE;
    };

    if tls.is_some() {
        eprintln!("argus: LDAPS on {bind}");
    } else {
        eprintln!("argus: LDAP on {bind}");
        eprintln!("argus: WARNING - no TLS; this listener refuses every password bind");
    }

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let service = Arc::clone(&service);
        let tls = tls.clone();

        tokio::spawn(async move {
            match tls {
                None => {
                    let mut stream = stream;
                    let _ = argus_ldap::server::serve(
                        &mut stream,
                        &service,
                        argus_ldap::session::Confidentiality::Plaintext,
                    )
                    .await;
                }
                Some(config) => {
                    let acceptor = tokio_rustls::TlsAcceptor::from(config);
                    if let Ok(mut protected) = acceptor.accept(stream).await {
                        let _ = argus_ldap::server::serve(
                            &mut protected,
                            &service,
                            argus_ldap::session::Confidentiality::Protected,
                        )
                        .await;
                    }
                }
            }
        });
    }
}

fn mint_token(args: &[String]) -> ExitCode {
    let Some(scope) = args.first() else {
        eprintln!("usage: argus token <scope> [lifetime-seconds]");
        eprintln!("mints an access token from the configured signing key for bootstrap use");
        return ExitCode::FAILURE;
    };

    let config = Config::from_env();

    if config.key_dir.is_none() {
        eprintln!(
            "argus: set ARGUS_SIGNING_KEY_DIR; an ephemeral key would mint a token \
                   nothing can verify"
        );
        return ExitCode::FAILURE;
    }

    let keys = match load_keys(&config) {
        Ok(keys) => keys,
        Err(message) => {
            eprintln!("argus: {message}");
            return ExitCode::FAILURE;
        }
    };

    let lifetime: i64 = args
        .get(1)
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(3_600);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));

    let claims = argus_proto::jwt::AccessTokenClaims {
        iss: config.issuer.clone(),
        sub: format!("bootstrap:{scope}"),
        aud: argus_proto::Audience::One(config.issuer.clone()),
        exp: now.saturating_add(lifetime),
        iat: now,
        jti: Uuid::new_v4().to_string(),
        scope: Some(scope.clone()),
        sess: 0,
        cnf: None,
    };

    match argus_proto::jwt::sign(&claims, &keys.active) {
        Ok(token) => {
            eprintln!(
                "argus: WARNING - this token carries {scope} for {lifetime} seconds and is not \
                 tied to any person; treat it as a credential"
            );
            println!("{token}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("argus: cannot sign: {e}");
            ExitCode::FAILURE
        }
    }
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

fn relying_party(config: &Config) -> Option<Arc<argus_proto::webauthn::RelyingParty>> {
    let host = config
        .issuer
        .strip_prefix("https://")
        .or_else(|| config.issuer.strip_prefix("http://"))?
        .split(['/', ':'])
        .next()?;

    let rp_id = env::var("ARGUS_WEBAUTHN_RP_ID").unwrap_or_else(|_| host.to_owned());
    let rp_id = argus_core::rpid::RpId::register(&rp_id).ok()?;

    argus_proto::webauthn::RelyingParty::new(&rp_id, &config.issuer, "Argus")
        .ok()
        .map(Arc::new)
}

fn load_blind_index(config: &Config) -> Result<argus_crypto::blind_index::BlindIndexKey, String> {
    let Ok(raw) = env::var("ARGUS_BLIND_INDEX_KEY") else {
        if config.production {
            return Err(
                "ARGUS_ENV=production requires ARGUS_BLIND_INDEX_KEY; without a stable \
                 key every lookup index changes on restart and no account is findable"
                    .to_owned(),
            );
        }
        eprintln!(
            "argus: WARNING - no ARGUS_BLIND_INDEX_KEY; a throwaway key is used and \
             existing accounts become unfindable on restart"
        );
        let mut key = [0u8; 32];
        if aws_lc_rs::rand::fill(&mut key).is_err() {
            return Err("cannot generate a blind index key".to_owned());
        }
        return argus_crypto::blind_index::BlindIndexKey::new(&key)
            .map_err(|_| "cannot build a blind index key".to_owned());
    };

    let bytes = raw.as_bytes();
    argus_crypto::blind_index::BlindIndexKey::new(bytes)
        .map_err(|_| "ARGUS_BLIND_INDEX_KEY must be at least 32 bytes".to_owned())
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

fn cimd_runtime(config: &Config) -> argus_http::cimd_client::CimdRuntime {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let runtime = argus_http::cimd_client::CimdRuntime::new(std::sync::Arc::new(client_config));

    if config.production {
        return runtime;
    }

    if env::var("ARGUS_CIMD_ALLOW_LOOPBACK").is_ok_and(|v| v == "1") {
        eprintln!(
            "argus: WARNING - CIMD documents may be fetched from loopback; \
             this exception is refused under ARGUS_ENV=production"
        );
        return runtime.allowing_loopback();
    }

    runtime
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

struct MetadataRegistry {
    providers: Vec<argus_saml::metadata::ServiceProvider>,
}

impl argus_http::saml::ServiceProviderRegistry for MetadataRegistry {
    fn find(&self, entity_id: &str) -> Option<argus_saml::metadata::ServiceProvider> {
        self.providers
            .iter()
            .find(|provider| provider.entity_id == entity_id)
            .cloned()
    }
}

struct NoSamlSubject;

impl argus_http::saml::Subject for NoSamlSubject {
    fn resolve(
        &self,
        _session: Option<&str>,
    ) -> Option<(argus_core::id::UserId, Option<String>, bool)> {
        None
    }
}

struct HmacPairwise {
    key: argus_crypto::blind_index::BlindIndexKey,
}

impl argus_saml::nameid::PairwiseIdentifier for HmacPairwise {
    fn pairwise(&self, tenant: TenantId, audience: &str, user: argus_core::id::UserId) -> String {
        let digest = self.key.compute(&format!(
            "saml-pairwise:{}:{}:{}",
            tenant.as_uuid().simple(),
            audience,
            user.as_uuid().simple()
        ));

        argus_core::hex::encode(&digest)
    }
}

fn saml_router(
    config: &Config,
    blind_index: &argus_crypto::blind_index::BlindIndexKey,
    tenant_id: TenantId,
) -> Option<axum::Router> {
    let key_path = config.saml_key.as_ref()?;
    let cert_path = config.saml_cert.as_ref()?;

    let key = std::fs::read(key_path).ok()?;
    let certificate_pem = std::fs::read_to_string(cert_path).ok()?;

    let certificate_base64: String = certificate_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    let signer = argus_saml::signature::BergshamraSigner::from_rsa_private_pem(&key).ok()?;

    let mut providers = Vec::new();
    if let Some(dir) = config.saml_sp_dir.as_ref()
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            let Ok(document) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            match argus_saml::metadata::parse_service_provider(&document) {
                Ok(provider) => {
                    eprintln!("argus: saml peer {}", provider.entity_id);
                    providers.push(provider);
                }
                Err(e) => eprintln!("argus: skipping {}: {e}", entry.path().display()),
            }
        }
    }

    if providers.is_empty() {
        eprintln!("argus: WARNING - SAML is configured but no service provider metadata loaded");
    }

    let entity_id = config
        .saml_entity_id
        .clone()
        .unwrap_or_else(|| config.issuer.clone());

    Some(argus_http::saml::build(Arc::new(
        argus_http::saml::SamlState {
            signer,
            registry: MetadataRegistry { providers },
            subjects: NoSamlSubject,
            tenant_id,
            entity_id,
            sso_location: format!("{}/saml/sso", config.issuer),
            certificate_base64,
            pairwise: Box::new(HmacPairwise {
                key: blind_index.clone(),
            }),
            session_lifetime: argus_core::time::Duration::from_seconds(28_800),
        },
    )))
}

struct StderrEventSink;

impl argus_http::scim::EventSink for StderrEventSink {
    fn publish(&self, token: &str) {
        eprintln!("argus: scim.event {token}");
    }
}

async fn serve_with_postgres(
    config: &Config,
    url: &str,
    keys: &KeySet,
    blind_index: &argus_crypto::blind_index::BlindIndexKey,
) -> ExitCode {
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

    let tenant_id = TenantId::from_uuid(Uuid::nil());

    let scim = Arc::new(argus_http::scim::ScimState {
        store: store.clone(),
        tenant_id,
        issuer: config.issuer.clone(),
        base: config.issuer.clone(),
        published_keys: keys.published.clone(),
        events: config.scim_event_audience.as_ref().map(|audience| {
            argus_http::scim::EventPublisher {
                key: Arc::clone(&keys.active),
                audience: audience.clone(),
                sink: Arc::new(StderrEventSink),
            }
        }),
    });

    let state = Arc::new(AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer(&config.issuer),
            active_key: Arc::clone(&keys.active),
            published_keys: keys.published.clone(),
            blind_index: blind_index.clone(),
            relying_party: relying_party(config),
        },
        codes: store.clone(),
        refresh: store.clone(),
        audit: store.clone(),
        tenant_id,
        clients: store.clone(),

        authenticator: (),
        replay: store.clone(),
        resources: store,
        cimd: Some(cimd_runtime(config)),
    });

    let mut app = argus_http::build(state).merge(argus_http::scim::routes::build(scim));

    if let Some(saml) = saml_router(config, blind_index, tenant_id) {
        app = app.merge(saml);
        eprintln!("argus: SAML identity provider at /saml/metadata and /saml/sso");
    }

    eprintln!("argus: WARNING - DevAuthenticator active, development only");
    warn_if_keys_are_ephemeral(config);

    serve(app, config, "PostgreSQL").await
}
