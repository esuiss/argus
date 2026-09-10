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

#[allow(clippy::struct_excessive_bools)]
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

    federation_entity_id: Option<String>,
    federation_key_dir: Option<String>,
    federation_trust_anchors: Option<String>,
    agent_card_key_dir: Option<String>,
    vault_key: Option<String>,
    fapi_profile: bool,
    federation_role_anchor: bool,
    rsa_key_dir: Option<String>,

    platform_database_url: Option<String>,

    // Issuer'ın seçilmiş mi yoksa varsayılan mı olduğu. §9.5 #2 tahmin edilmiş
    // bir issuer'la üretimde başlamayı reddediyor: Keycloak'ın kendi uyarısı,
    // URL'i yönlendirebilen bir saldırganın kendi seçtiği issuer'dan token
    // alacağıdır.
    issuer_was_set: bool,

    admin_bind: Option<String>,
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
            federation_entity_id: env::var("ARGUS_FEDERATION_ENTITY_ID").ok(),
            federation_key_dir: env::var("ARGUS_FEDERATION_KEY_DIR").ok(),
            federation_trust_anchors: env::var("ARGUS_FEDERATION_TRUST_ANCHORS").ok(),
            agent_card_key_dir: env::var("ARGUS_AGENT_CARD_KEY_DIR").ok(),
            vault_key: env::var("ARGUS_VAULT_KEY").ok(),
            fapi_profile: env::var("ARGUS_FAPI_PROFILE").is_ok_and(|v| v == "1"),
            federation_role_anchor: env::var("ARGUS_FEDERATION_ROLE")
                .is_ok_and(|v| v == "trust_anchor"),
            rsa_key_dir: env::var("ARGUS_RSA_KEY_DIR").ok(),
            platform_database_url: env::var("ARGUS_PLATFORM_DATABASE_URL").ok(),
            issuer_was_set: env::var("ARGUS_ISSUER").is_ok(),
            admin_bind: env::var("ARGUS_ADMIN_BIND").ok(),
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
            rsa_keys: Vec::new(),
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
        federation: None,
        federation_identity: None,
        pushed_requests: None,
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

fn keygen_rsa(args: &[String]) -> ExitCode {
    let (Some(kid), Some(dir)) = (args.first(), args.get(1)) else {
        eprintln!("usage: argus keygen --rsa <kid> <directory>");
        return ExitCode::FAILURE;
    };

    if kid.is_empty() || kid.contains(['/', '\\', '.']) {
        eprintln!("argus: kid must not be empty or contain path separators or dots");
        return ExitCode::FAILURE;
    }

    let path = Path::new(dir).join(format!("{kid}.pkcs8"));
    if path.exists() {
        eprintln!("argus: {} already exists", path.display());
        return ExitCode::FAILURE;
    }

    let Ok(pair) = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048) else {
        eprintln!("argus: could not generate an RSA key");
        return ExitCode::FAILURE;
    };

    let document: aws_lc_rs::encoding::Pkcs8V1Der<'static> = {
        use aws_lc_rs::encoding::AsDer as _;
        let Ok(document) = pair.as_der() else {
            eprintln!("argus: could not serialise the RSA key");
            return ExitCode::FAILURE;
        };
        document
    };

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            if file.write_all(document.as_ref()).is_err() {
                eprintln!("argus: could not write {}", path.display());
                return ExitCode::FAILURE;
            }
            println!("{}", path.display());
            eprintln!(
                "argus: RS256 is offered for compatibility only; identity tokens are signed \
                 with ES256 unless a client asks for RS256"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("argus: could not create {}: {e}", path.display());
            ExitCode::FAILURE
        }
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
    if args.first().map(String::as_str) == Some("--rsa") {
        return keygen_rsa(args.get(1..).unwrap_or_default());
    }

    let (Some(kid), Some(dir)) = (args.first(), args.get(1)) else {
        eprintln!("usage: argus keygen <kid> <directory>");
        eprintln!("       argus keygen --rsa <kid> <directory>");
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

    // §9.5 #2: güvensiz üretim konfigürasyonunda uyarmak yerine REDDET.
    // Keycloak'ın kendi listesinde bunlar öneri olarak kalıyor ve tam da
    // üstlerindeki her şeyi sessizce işe yaramaz hâle getirenler bunlar.
    if config.production {
        if !config.issuer_was_set {
            eprintln!(
                "argus: ARGUS_ENV=production requires ARGUS_ISSUER; a guessed issuer lets                  an attacker who can steer the URL have tokens minted under one they chose"
            );
            return ExitCode::FAILURE;
        }

        if config.admin_bind.is_none() {
            eprintln!(
                "argus: ARGUS_ENV=production requires ARGUS_ADMIN_BIND; the administrative                  surface does not share an address with the public one"
            );
            return ExitCode::FAILURE;
        }
    }

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

fn tls_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Ok(path) = env::var("ARGUS_EXTRA_CA") {
        match load_certs(&path) {
            Ok(extra) => {
                let mut added = 0_usize;
                for certificate in extra {
                    if roots.add(certificate).is_ok() {
                        added = added.saturating_add(1);
                    }
                }
                eprintln!(
                    "argus: {added} extra certificate authority root(s) trusted for outbound calls"
                );
            }
            Err(message) => eprintln!("argus: {message}"),
        }
    }

    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
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

fn load_rsa_key_dir(dir: &str) -> Vec<Arc<argus_crypto::rsa::RsaSigningKey>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut keys = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("pkcs8") {
            continue;
        }

        let (Some(kid), Ok(material)) = (
            path.file_stem().and_then(OsStr::to_str),
            std::fs::read(&path),
        ) else {
            continue;
        };

        match argus_crypto::rsa::RsaSigningKey::from_pkcs8(kid, &material) {
            Ok(key) => keys.push(Arc::new(key)),
            Err(e) => eprintln!("argus: skipping {}: {e}", path.display()),
        }
    }

    keys.sort_by(|left, right| left.kid().cmp(right.kid()));
    keys
}

fn load_key_dir(dir: &str) -> Vec<Arc<argus_crypto::SigningKey>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut keys = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("pkcs8") {
            continue;
        }

        let Some(kid) = path.file_stem().and_then(OsStr::to_str) else {
            continue;
        };

        let Ok(material) = std::fs::read(&path) else {
            continue;
        };

        if let Ok(key) = argus_crypto::SigningKey::from_pkcs8(kid, &material) {
            keys.push(Arc::new(key));
        }
    }

    keys.sort_by(|left, right| left.kid().cmp(right.kid()));
    keys
}

fn federation_identity(
    config: &Config,
) -> Option<argus_http::federation::publish::FederationIdentity> {
    let entity_id = config.federation_entity_id.clone()?;
    let dir = config.federation_key_dir.as_ref()?;

    let entity = match argus_core::federation::statement::EntityIdentifier::parse(&entity_id) {
        Ok(entity) => entity,
        Err(e) => {
            eprintln!("argus: ARGUS_FEDERATION_ENTITY_ID is not a usable entity identifier: {e}");
            return None;
        }
    };
    let keys = load_key_dir(dir);

    if keys.is_empty() {
        eprintln!("argus: no federation signing key found in {dir}");
        return None;
    }

    let role = if config.federation_role_anchor {
        argus_core::federation::statement::Role::TrustAnchor
    } else {
        argus_core::federation::statement::Role::Leaf
    };

    let authority_hints = if role == argus_core::federation::statement::Role::TrustAnchor {
        Vec::new()
    } else {
        trust_anchors(config)
    };

    Some(argus_http::federation::publish::FederationIdentity {
        entity,
        role,
        signing_keys: keys,
        authority_hints,
        organization_name: None,
        trust_marks: Vec::new(),
    })
}

fn trust_anchors(config: &Config) -> Vec<argus_core::federation::statement::EntityIdentifier> {
    config
        .federation_trust_anchors
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .filter_map(|raw| argus_core::federation::statement::EntityIdentifier::parse(raw).ok())
        .collect()
}

fn federation_reach(config: &Config) -> argus_http::federation::fetch::Reach {
    if config.production {
        return argus_http::federation::fetch::Reach::public_only();
    }

    let private = env::var("ARGUS_FEDERATION_ALLOW_PRIVATE").is_ok_and(|value| value == "1");

    if private {
        eprintln!(
            "argus: WARNING - federation peers may be fetched from private address ranges; \
             this exception is refused under ARGUS_ENV=production"
        );
    }

    argus_http::federation::fetch::Reach {
        loopback: true,
        private,
    }
}

fn federation_resolver_runtime(
    config: &Config,
) -> Option<argus_http::differentiation::ResolverRuntime> {
    let anchors = trust_anchors(config);

    if anchors.is_empty() {
        return None;
    }

    Some(argus_http::differentiation::ResolverRuntime::new(
        argus_http::federation::resolver::Federation {
            resolver: argus_http::federation::fetch::SystemResolver,
            tls: tls_client_config(),
            trust_anchors: anchors,
            reach: federation_reach(config),
        },
    ))
}

fn federation_runtime(
    config: &Config,
    tls: Arc<rustls::ClientConfig>,
) -> Option<
    argus_http::federation::client::FederationRuntime<
        argus_http::federation::fetch::SystemResolver,
    >,
> {
    let anchors = trust_anchors(config);

    if anchors.is_empty() {
        return None;
    }

    Some(argus_http::federation::client::FederationRuntime::new(
        argus_http::federation::resolver::Federation {
            resolver: argus_http::federation::fetch::SystemResolver,
            tls,
            trust_anchors: anchors,
            reach: federation_reach(config),
        },
    ))
}

fn vault_runtime(
    config: &Config,
    store: &argus_store::PostgresStore,
) -> Option<argus_http::differentiation::VaultRuntime> {
    let raw = config.vault_key.as_ref()?;
    let material = decode_key_material(raw)?;

    match argus_crypto::sealing::SealingKey::new(&material) {
        Ok(sealing) => Some(argus_http::differentiation::VaultRuntime {
            store: store.clone(),
            sealing,
        }),
        Err(e) => {
            eprintln!("argus: ARGUS_VAULT_KEY is not usable: {e}");
            None
        }
    }
}

fn decode_key_material(raw: &str) -> Option<Vec<u8>> {
    if let Ok(decoded) = argus_http::differentiation::decode_base64(raw.trim())
        && decoded.len() == argus_crypto::sealing::KEY_BYTES
    {
        return Some(decoded);
    }

    eprintln!("argus: ARGUS_VAULT_KEY must be 32 base64 encoded bytes");
    None
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

#[allow(
    clippy::too_many_lines,
    reason = "the start-up sequence reads as one ordered list of what the server offers"
)]
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

    let mut store = argus_store::PostgresStore::new(pool);

    // §24 #21. Kontrol düzlemi ayrı bir veritabanı aslıdır, dolayısıyla onu
    // yapılandırmayan bir dağıtım kiracı kaydına ulaşmayı reddetmekle kalmaz,
    // hiç ULAŞAMAZ.
    if let Some(url) = config.platform_database_url.as_deref() {
        let Ok(control) = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(url)
            .await
        else {
            eprintln!("argus: cannot connect to the control plane database");
            return ExitCode::FAILURE;
        };
        store = store.with_control_plane(control);
        eprintln!("argus: control plane at /admin/platform");
    }

    let tenant_id = TenantId::from_uuid(Uuid::nil());

    let rsa_keys = config
        .rsa_key_dir
        .as_deref()
        .map(load_rsa_key_dir)
        .unwrap_or_default();

    if !rsa_keys.is_empty() {
        eprintln!(
            "argus: RS256 available for identity tokens with {} key(s)",
            rsa_keys.len()
        );
    }

    let published_metadata = {
        let mut metadata = AuthorizationServerMetadata::for_issuer(&config.issuer);
        metadata.require_pushed_authorization_requests = config.fapi_profile;
        if !rsa_keys.is_empty() {
            metadata
                .id_token_signing_alg_values_supported
                .push("RS256".to_owned());
        }
        metadata
    };

    let profile = if config.fapi_profile {
        argus_core::par::Profile::financial_grade()
    } else {
        argus_core::par::Profile::permissive()
    };

    let pushed_requests = Arc::new(argus_http::par::ParState {
        store: store.clone(),
        tenant_id,
        profile,
        issuer: config.issuer.clone(),
        endpoint: format!("{}/par", config.issuer),
    });

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

    let federation = federation_identity(config);

    let state = Arc::new(AppState {
        tenant: TenantContext {
            metadata: published_metadata.clone(),
            active_key: Arc::clone(&keys.active),
            published_keys: keys.published.clone(),
            rsa_keys: rsa_keys.clone(),
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
        resources: store.clone(),
        cimd: Some(cimd_runtime(config)),
        federation: federation_runtime(config, tls_client_config()),
        federation_identity: federation.clone(),
        pushed_requests: Some(Arc::clone(&pushed_requests)),
    });

    let mut app = argus_http::build(state).merge(argus_http::scim::routes::build(scim));

    if let Some(saml) = saml_router(config, blind_index, tenant_id) {
        app = app.merge(saml);
        eprintln!("argus: SAML identity provider at /saml/metadata and /saml/sso");
    }

    let differentiation = Arc::new(argus_http::differentiation::DifferentiationState {
        tenant_id,
        store: Some(store.clone()),
        issuer: config.issuer.clone(),
        published_keys: keys.published.clone(),
        federation: federation.clone(),
        provider_metadata: argus_http::differentiation::metadata_value(&published_metadata),
        agent_card_key: config
            .agent_card_key_dir
            .as_deref()
            .and_then(|dir| load_key_dir(dir).into_iter().next()),
        vault: vault_runtime(config, &store),
        resolver: federation_resolver_runtime(config),
    });

    if differentiation.federation.is_some() {
        eprintln!("argus: federation entity configuration at /.well-known/openid-federation");
    }
    if differentiation.agent_card_key.is_some() {
        eprintln!("argus: agent card signing at /agent-cards/sign");
    }
    if differentiation.vault.is_some() {
        eprintln!("argus: credential vault at /vault/lease and /vault/redeem");
    }

    app = app
        .merge(argus_http::differentiation::build(differentiation))
        .merge(argus_http::par::build(Arc::clone(&pushed_requests)));

    // §24. Router izin manifestosundan üretilir; mount etmek, tam olarak birinin
    // izin bildirdiği route'ları mount etmek demektir.
    let admin = argus_http::admin::build(Arc::new(argus_http::admin::AdminState {
        tenant_id,
        issuer: config.issuer.clone(),
        store: store.clone(),
        published_keys: keys.published.clone(),
        model: argus_core::admin::model(),
        policy: argus_core::admin::policy(),
    }));

    // §9.5 #2 ve §24 #34: verildiğinde kendi adresinde, böylece yönetim yüzeyi
    // genel yüzeyin ulaşamadığı bir yerden erişilebilir. Keycloak bunu öneri
    // olarak bırakıyor ve stored XSS bulgularının tamamı düşük yetkili bir
    // yöneticinin daha yüksek yetkili birinin tarayıcısına ulaşmasıdır.
    if let Some(bind) = config.admin_bind.as_deref() {
        let Ok(listener) = tokio::net::TcpListener::bind(bind).await else {
            eprintln!("argus: cannot bind {bind}");
            return ExitCode::FAILURE;
        };
        eprintln!("argus: administrative API on {bind}");
        let admin = admin.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, admin).await;
        });
    } else {
        eprintln!("argus: administrative API at /admin, on the main listener");
        app = app.merge(admin);
    }

    if config.fapi_profile {
        eprintln!(
            "argus: financial grade profile: authorization requests must be pushed, \
             tokens must be sender constrained, public clients are refused"
        );
    }

    eprintln!("argus: WARNING - DevAuthenticator active, development only");
    warn_if_keys_are_ephemeral(config);

    serve(app, config, "PostgreSQL").await
}
