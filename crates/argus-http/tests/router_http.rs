#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl
)]

use std::sync::{Arc, Mutex};

use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::StoredCode;
use argus_core::client_auth::ClientAuthMethod;
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::redirect_uri::RedirectUri;
use argus_core::refresh::{FamilyId, RefreshToken};
use argus_core::time::Timestamp;
use argus_crypto::SigningKey;
use argus_http::memstore::{MemoryReplayStore, MemoryResourceStore};
use argus_http::state::{AppState, TenantContext};
use argus_http::store::{
    AuditSink, AuthnStore, BackchannelStore, CeremonyStore, ClientStore, CodeIssuer, CodeStore,
    RecoveryStore, RefreshStore, SessionStore, StoreError,
};
use argus_proto::AuthorizationServerMetadata;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

type PendingState = (Option<UserId>, String);

#[derive(Default)]
struct Codes {
    issued: Mutex<Option<StoredCode>>,
    sessions: Mutex<std::collections::HashMap<[u8; 32], argus_http::store::AuthnSession>>,
    ceremonies: Mutex<std::collections::HashMap<[u8; 32], PendingState>>,
    recoveries: Mutex<std::collections::HashMap<uuid::Uuid, argus_core::recovery::RecoveryAttempt>>,
}

impl CodeIssuer for Codes {
    async fn issue(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
        code: &StoredCode,
    ) -> Result<(), StoreError> {
        *self.issued.lock().expect("lock") = Some(code.clone());
        Ok(())
    }
}

impl CodeStore for Codes {
    async fn load(&self, _t: TenantId, _h: &[u8; 32]) -> Result<StoredCode, StoreError> {
        Err(StoreError::NotFound)
    }
    async fn consume(&self, _t: TenantId, _h: &[u8; 32], _at: Timestamp) -> Result<(), StoreError> {
        Ok(())
    }
    async fn revoke_tokens_issued_for_code(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

struct Refresh;

impl RefreshStore for Refresh {
    async fn load(&self, _t: TenantId, _h: &[u8; 32]) -> Result<RefreshToken, StoreError> {
        Err(StoreError::NotFound)
    }
    async fn rotate(
        &self,
        _t: TenantId,
        _o: &[u8; 32],
        _n: &[u8; 32],
        _new: &RefreshToken,
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        Ok(())
    }
    async fn revoke_family(
        &self,
        _t: TenantId,
        _f: FamilyId,
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

struct Audit;

impl AuditSink for Audit {
    async fn record(&self, _t: TenantId, _e: &str, _at: Timestamp) -> Result<(), StoreError> {
        Ok(())
    }
}

struct Clients;

impl ClientStore for Clients {
    async fn find(
        &self,
        _t: TenantId,
        client_id: &ClientId,
    ) -> Result<Option<RegisteredClient>, StoreError> {
        if client_id.as_str() != "demo-client" {
            return Ok(None);
        }
        Ok(Some(RegisteredClient {
            client_id: client_id.clone(),
            redirect_uris: vec![RedirectUri::register("https://app.example.com/cb").expect("uri")],
            auth_method: ClientAuthMethod::None,
            keys: Vec::new(),
        }))
    }
}

const SESSION_SECRET: &str = "test-session-secret";

fn session_cookie_header() -> String {
    format!("Cookie: argus_session={SESSION_SECRET}\r\n")
}

async fn serve() -> String {
    let (key, _) = SigningKey::generate("k1").expect("key");
    let key = Arc::new(key);

    let state = Arc::new(AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer("http://argus.test"),
            active_key: Arc::clone(&key),
            published_keys: vec![key],
            blind_index: test_blind_index(),
            relying_party: None,
        },
        codes: Codes::default(),
        refresh: Refresh,
        audit: Audit,
        tenant_id: TenantId::from_uuid(Uuid::nil()),
        clients: Clients,
        authenticator: (),
        replay: MemoryReplayStore::default(),
        resources: MemoryResourceStore::default(),
        cimd: None,
        federation: None,
        federation_identity: None,
        pushed_requests: None,
    });

    {
        use argus_core::pkce::Sha256 as _;
        let hash = argus_crypto::AwsLcSha256.sha256(SESSION_SECRET.as_bytes());
        state
            .codes
            .create_session(
                TenantId::from_uuid(Uuid::nil()),
                &hash,
                &argus_http::store::AuthnSession {
                    subject: UserId::from_uuid(Uuid::from_u128(1)),
                    achieved: argus_core::aal::Aal::One,
                    authenticated_at: Timestamp::from_unix_seconds(0),
                    expires_at: Timestamp::from_unix_seconds(4_000_000_000),
                },
            )
            .await
            .expect("session");
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let app = argus_http::build(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

async fn raw(addr: &str, request: &str) -> String {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(request.as_bytes()).await.expect("write");
    let mut out = Vec::new();

    s.read_to_end(&mut out).await.expect("read");
    String::from_utf8_lossy(&out).into_owned()
}

async fn get(addr: &str, path: &str, headers: &str) -> String {
    raw(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n{headers}\r\n"),
    )
    .await
}

fn status(response: &str) -> &str {
    response.lines().next().unwrap_or("").trim()
}

#[tokio::test]
async fn both_well_known_paths_serve_the_same_metadata() {
    let addr = serve().await;
    let a = get(&addr, "/.well-known/openid-configuration", "").await;
    let b = get(&addr, "/.well-known/oauth-authorization-server", "").await;

    assert!(status(&a).contains("200"), "{a}");
    assert!(status(&b).contains("200"), "{b}");
    let body = |r: &str| r.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned();
    assert_eq!(body(&a), body(&b));
    assert!(body(&a).contains("\"userinfo_endpoint\""));
}

#[tokio::test]
async fn the_token_endpoint_refuses_get() {
    let addr = serve().await;
    let r = get(&addr, "/token", "").await;
    assert!(status(&r).contains("405"), "{r}");
}

#[tokio::test]
async fn userinfo_accepts_both_get_and_post() {
    let addr = serve().await;

    let g = get(&addr, "/userinfo", "").await;
    let p = raw(
        &addr,
        "POST /userinfo HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    )
    .await;

    assert!(status(&g).contains("401"), "{g}");
    assert!(status(&p).contains("401"), "{p}");
}

#[tokio::test]
async fn an_unauthenticated_userinfo_request_carries_a_challenge() {
    let addr = serve().await;
    let r = get(&addr, "/userinfo", "").await;

    assert!(status(&r).contains("401"), "{r}");
    assert!(
        r.to_lowercase().contains("www-authenticate: bearer"),
        "no challenge in: {r}"
    );

    assert!(r.to_lowercase().contains("cache-control: no-store"), "{r}");
}

#[tokio::test]
async fn an_invalid_token_is_named_in_the_challenge() {
    let addr = serve().await;
    let r = get(
        &addr,
        "/userinfo",
        "Authorization: Bearer not.a.real.jwt\r\n",
    )
    .await;

    assert!(status(&r).contains("401"), "{r}");
    assert!(r.contains(r#"error="invalid_token""#), "{r}");
}

#[tokio::test]
async fn an_unregistered_redirect_uri_never_redirects() {
    let addr = serve().await;
    let r = get(
        &addr,
        "/authorize?response_type=code&client_id=demo-client&redirect_uri=https%3A%2F%2Fevil.test%2Fcb\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        "",
    )
    .await;

    assert!(status(&r).contains("400"), "{r}");
    assert!(
        !r.to_lowercase().contains("location:"),
        "must not redirect: {r}"
    );
}

#[tokio::test]
async fn a_valid_authorize_request_redirects_with_iss_and_encoded_state() {
    let addr = serve().await;
    let r = get(
        &addr,
        "/authorize?response_type=code&client_id=demo-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &state=a%26b&scope=openid&nonce=n1\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        &session_cookie_header(),
    )
    .await;

    assert!(status(&r).contains("303"), "{r}");
    let location = r
        .lines()
        .find(|l| l.to_lowercase().starts_with("location:"))
        .expect("location header");
    assert!(
        location.contains("iss=http%3A%2F%2Fargus.test"),
        "{location}"
    );
    assert!(location.contains("code="), "{location}");

    assert!(location.contains("state=a%26b"), "{location}");
}

#[tokio::test]
async fn a_malformed_dpop_header_fails_the_token_request() {
    let addr = serve().await;
    let body = "grant_type=authorization_code&code=x&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
                &code_verifier=v&client_id=demo-client";
    let r = raw(
        &addr,
        &format!(
            "POST /token HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nDPoP: garbage\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;

    assert!(status(&r).contains("400"), "{r}");
    assert!(r.contains("invalid_request"), "{r}");
}

#[tokio::test]
async fn the_published_jwks_contains_no_private_material() {
    let addr = serve().await;
    let r = get(&addr, "/.well-known/jwks.json", "").await;

    assert!(status(&r).contains("200"), "{r}");
    assert!(!r.contains("\"d\""), "private component leaked: {r}");
    assert!(r.contains("\"kty\":\"EC\""), "{r}");
}
impl BackchannelStore for Codes {
    #[allow(clippy::unused_async_trait_impl)]
    async fn create_backchannel(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
        _r: &argus_core::ciba::BackchannelRequest,
    ) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn load_backchannel(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
    ) -> Result<argus_core::ciba::BackchannelRequest, StoreError> {
        Err(StoreError::Unavailable)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn record_backchannel_poll(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn consume_backchannel(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
        _at: Timestamp,
    ) -> Result<bool, StoreError> {
        Err(StoreError::Unavailable)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn decide_backchannel(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
        _approved: bool,
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }
}

#[tokio::test]
async fn a_cimd_client_sees_the_redirect_host_before_being_sent_there() {
    let addr = serve().await;
    let r = get(
        &addr,
        "/authorize?response_type=code&client_id=https%3A%2F%2Fexample.com%2Fclient.json\
         &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        "",
    )
    .await;

    assert!(status(&r).contains("400"), "{r}");
}

#[tokio::test]
async fn the_consent_page_escapes_what_it_shows() {
    let addr = serve().await;
    let r = get(
        &addr,
        "/authorize?response_type=code&client_id=demo-client\
         &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=%3Cscript%3E\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        "",
    )
    .await;

    assert!(
        !r.contains("<script>"),
        "unescaped markup reached the page: {r}"
    );
}

impl SessionStore for Codes {
    #[allow(clippy::unused_async_trait_impl)]
    async fn create_session(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        session: &argus_http::store::AuthnSession,
    ) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(*hash, session.clone());
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn load_session(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        now: Timestamp,
    ) -> Result<argus_http::store::AuthnSession, StoreError> {
        let guard = self.sessions.lock().map_err(|_| StoreError::Unavailable)?;
        let session = guard.get(hash).ok_or(StoreError::NotFound)?;
        if session.expires_at.as_unix_seconds() <= now.as_unix_seconds() {
            return Err(StoreError::NotFound);
        }
        Ok(session.clone())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke_session(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .remove(hash);
        Ok(())
    }
}

impl AuthnStore for Codes {
    #[allow(clippy::unused_async_trait_impl)]
    async fn find_user_by_blind_index(
        &self,
        _t: TenantId,
        _index: &[u8; 32],
    ) -> Result<Option<UserId>, StoreError> {
        Ok(None)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn create_user(
        &self,
        _t: TenantId,
        _u: UserId,
        _i: &[u8; 32],
        _e: &[u8],
    ) -> Result<(), StoreError> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn password_of(&self, _t: TenantId, _u: UserId) -> Result<Option<String>, StoreError> {
        Ok(None)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn set_password(&self, _t: TenantId, _u: UserId, _p: &str) -> Result<(), StoreError> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn required_aal(
        &self,
        _t: TenantId,
        _u: UserId,
    ) -> Result<argus_core::aal::Aal, StoreError> {
        Ok(argus_core::aal::Aal::One)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn webauthn_credentials(
        &self,
        _t: TenantId,
        _u: UserId,
    ) -> Result<Vec<String>, StoreError> {
        Ok(Vec::new())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn store_webauthn_credential(
        &self,
        _t: TenantId,
        _u: UserId,
        _c: &[u8],
        _r: &str,
        _s: &str,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn user_for_credential(
        &self,
        _t: TenantId,
        _c: &[u8],
    ) -> Result<Option<UserId>, StoreError> {
        Ok(None)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn advance_sign_count(
        &self,
        _t: TenantId,
        _c: &[u8],
        _n: i64,
        _at: Timestamp,
    ) -> Result<bool, StoreError> {
        Ok(true)
    }
}

#[tokio::test]
async fn an_authorize_request_without_a_session_is_not_authenticated() {
    let addr = serve().await;
    let r = get(
        &addr,
        "/authorize?response_type=code&client_id=demo-client\
         &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        "",
    )
    .await;

    assert!(
        status(&r).contains("401"),
        "an unauthenticated authorize request must not mint a code: {r}"
    );
    assert!(!r.to_lowercase().contains("location:"), "{r}");
}

#[tokio::test]
async fn a_forged_session_cookie_does_not_authenticate() {
    let addr = serve().await;
    let r = get(
        &addr,
        "/authorize?response_type=code&client_id=demo-client\
         &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        "Cookie: argus_session=not-the-real-one\r\n",
    )
    .await;

    assert!(status(&r).contains("401"), "{r}");
}

fn test_blind_index() -> argus_crypto::blind_index::BlindIndexKey {
    argus_crypto::blind_index::BlindIndexKey::new(&[7u8; 32]).expect("key")
}

impl CeremonyStore for Codes {
    #[allow(clippy::unused_async_trait_impl)]
    async fn store_ceremony(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        ceremony: &argus_http::store::PendingCeremony<'_>,
    ) -> Result<(), StoreError> {
        self.ceremonies
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(*hash, (ceremony.user, ceremony.state.to_owned()));
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn take_ceremony(
        &self,
        _t: TenantId,
        hash: &[u8; 32],
        _purpose: argus_http::store::CeremonyPurpose,
        _now: Timestamp,
    ) -> Result<(Option<UserId>, String), StoreError> {
        self.ceremonies
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .remove(hash)
            .ok_or(StoreError::NotFound)
    }
}

impl RecoveryStore for Codes {
    #[allow(clippy::unused_async_trait_impl)]
    async fn open_recovery(
        &self,
        _t: TenantId,
        attempt_id: uuid::Uuid,
        attempt: &argus_core::recovery::RecoveryAttempt,
    ) -> Result<(), StoreError> {
        self.recoveries
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .insert(attempt_id, attempt.clone());
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn load_recovery(
        &self,
        _t: TenantId,
        attempt_id: uuid::Uuid,
    ) -> Result<argus_core::recovery::RecoveryAttempt, StoreError> {
        self.recoveries
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .get(&attempt_id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn advance_recovery(
        &self,
        _t: TenantId,
        attempt_id: uuid::Uuid,
        attempt: &argus_core::recovery::RecoveryAttempt,
        _at: Timestamp,
    ) -> Result<bool, StoreError> {
        let mut guard = self
            .recoveries
            .lock()
            .map_err(|_| StoreError::Unavailable)?;
        if !guard.contains_key(&attempt_id) {
            return Ok(false);
        }
        guard.insert(attempt_id, attempt.clone());
        Ok(true)
    }
}
