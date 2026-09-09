#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl
)]

use std::sync::{Arc, Mutex};

use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::client_auth::ClientAuthMethod;
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::pkce::{CodeChallenge, CodeChallengeMethod, Sha256};
use argus_core::redirect_uri::RedirectUri;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::{Duration, Timestamp};
use argus_crypto::{AwsLcSha256, SigningKey};
use argus_http::endpoints::token::{TokenForm, handle};
use argus_http::memstore::{MemoryReplayStore, MemoryResourceStore};
use argus_http::state::{AppState, TenantContext};
use argus_http::store::{AuditSink, ClientStore, CodeStore, RefreshStore, StoreError};
use argus_proto::{AuthorizationServerMetadata, OAuthErrorCode};
use base64ct::Encoding as _;
use uuid::Uuid;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);

fn tenant() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0a))
}

fn client() -> ClientId {
    ClientId::new("acme-web").expect("client")
}

#[derive(Default)]
struct MemCodes {
    record: Mutex<Option<StoredCode>>,
    consumed: Mutex<bool>,
    revoked_for_code: Mutex<bool>,
}

impl CodeStore for MemCodes {
    async fn load(&self, _t: TenantId, _h: &[u8; 32]) -> Result<StoredCode, StoreError> {
        self.record
            .lock()
            .expect("lock")
            .clone()
            .ok_or(StoreError::NotFound)
    }
    async fn consume(&self, _t: TenantId, _h: &[u8; 32], _at: Timestamp) -> Result<(), StoreError> {
        *self.consumed.lock().expect("lock") = true;
        Ok(())
    }
    async fn revoke_tokens_issued_for_code(
        &self,
        _t: TenantId,
        _h: &[u8; 32],
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        *self.revoked_for_code.lock().expect("lock") = true;
        Ok(())
    }
}

#[derive(Default)]
struct MemRefresh {
    record: Mutex<Option<RefreshToken>>,
    rotated: Mutex<bool>,
    family_revoked: Mutex<bool>,
}

impl RefreshStore for MemRefresh {
    async fn load(&self, _t: TenantId, _h: &[u8; 32]) -> Result<RefreshToken, StoreError> {
        self.record
            .lock()
            .expect("lock")
            .clone()
            .ok_or(StoreError::NotFound)
    }
    async fn rotate(
        &self,
        _t: TenantId,
        _o: &[u8; 32],
        _n: &[u8; 32],
        _new: &RefreshToken,
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        *self.rotated.lock().expect("lock") = true;
        Ok(())
    }
    async fn revoke_family(
        &self,
        _t: TenantId,
        _f: FamilyId,
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        *self.family_revoked.lock().expect("lock") = true;
        Ok(())
    }
}

#[derive(Default)]
struct MemAudit {
    events: Mutex<Vec<String>>,
}

impl AuditSink for MemAudit {
    async fn record(
        &self,
        _t: TenantId,
        event_type: &str,
        _at: Timestamp,
    ) -> Result<(), StoreError> {
        self.events
            .lock()
            .expect("lock")
            .push(event_type.to_owned());
        Ok(())
    }
}

struct Clients {
    method: ClientAuthMethod,
    keys: Vec<argus_core::client_auth::ClientKey>,
}

impl Default for Clients {
    fn default() -> Self {
        Self {
            method: ClientAuthMethod::None,
            keys: Vec::new(),
        }
    }
}

impl ClientStore for Clients {
    async fn find(
        &self,
        _t: TenantId,
        client_id: &ClientId,
    ) -> Result<Option<RegisteredClient>, StoreError> {
        if client_id != &client() {
            return Ok(None);
        }
        Ok(Some(RegisteredClient {
            client_id: client_id.clone(),
            redirect_uris: vec![RedirectUri::register("https://app.example.com/cb").expect("uri")],
            auth_method: self.method,
            keys: self.keys.clone(),
        }))
    }
}

type TestState =
    AppState<MemCodes, MemRefresh, MemAudit, Clients, (), MemoryReplayStore, MemoryResourceStore>;

async fn token(
    s: &TestState,
    form: &TokenForm,
    binding: Option<String>,
) -> Result<argus_proto::TokenResponse, argus_proto::OAuthError> {
    handle(s, form, NOW, &AwsLcSha256, binding).await
}

fn state() -> TestState {
    let (key, _) = SigningKey::generate("k1").expect("key");
    let key = Arc::new(key);
    AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer("https://acme.argus.test"),
            active_key: Arc::clone(&key),
            published_keys: vec![key],
        },
        codes: MemCodes::default(),
        refresh: MemRefresh::default(),
        audit: MemAudit::default(),
        tenant_id: tenant(),
        clients: Clients::default(),
        authenticator: (),
        replay: MemoryReplayStore::default(),
        resources: MemoryResourceStore::default(),
    }
}

fn stored_code(code_state: CodeState) -> StoredCode {
    StoredCode {
        tenant: tenant(),
        client: client(),
        subject: UserId::from_uuid(Uuid::from_u128(0xa1)),
        redirect_uri: RedirectUri::register("https://app.example.com/cb").expect("uri"),
        challenge: CodeChallenge::parse(CodeChallengeMethod::S256, CHALLENGE).expect("challenge"),
        issued_at: NOW,
        expires_at: NOW.saturating_add(Duration::from_seconds(60)),
        state: code_state,
        nonce: None,
        scope: None,
        resources: Vec::new(),
    }
}

fn code_form() -> TokenForm {
    TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("the-code".to_owned()),
        redirect_uri: Some("https://app.example.com/cb".to_owned()),
        code_verifier: Some(VERIFIER.to_owned()),
        client_id: Some("acme-web".to_owned()),
        refresh_token: None,
        client_assertion_type: None,
        client_assertion: None,
    }
}

#[tokio::test]
async fn authorization_code_yields_a_verifiable_access_token() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let resp = token(&s, &code_form(), None).await.expect("token issued");

    let claims = argus_proto::jwt::verify(&resp.access_token, &s.tenant.active_key.verifying_key())
        .expect("token verifies against the published key");

    assert_eq!(claims.iss, "https://acme.argus.test");
    assert!(claims.aud.contains("acme-web"));
    assert_eq!(claims.exp, NOW.as_unix_seconds() + resp.expires_in);
    assert!(
        *s.codes.consumed.lock().expect("lock"),
        "code must be consumed"
    );
    assert!(
        s.audit
            .events
            .lock()
            .expect("lock")
            .contains(&"oauth.authorization_code.redeemed".to_owned())
    );
}

#[tokio::test]
async fn wrong_pkce_verifier_is_rejected_and_burns_the_code() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let form = TokenForm {
        code_verifier: Some("z".repeat(43)),
        ..code_form()
    };

    let err = token(&s, &form, None).await.expect_err("must be denied");
    assert_eq!(err.error, OAuthErrorCode::InvalidGrant);
    assert!(
        *s.codes.consumed.lock().expect("lock"),
        "a denied attempt must still burn the code"
    );
}

#[tokio::test]
async fn replayed_code_triggers_revocation_of_derived_tokens() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Redeemed {
        at: Timestamp::from_unix_seconds(999_999),
    }));

    let err = token(&s, &code_form(), None)
        .await
        .expect_err("replay must be denied");
    assert_eq!(err.error, OAuthErrorCode::InvalidGrant);
    assert!(
        *s.codes.revoked_for_code.lock().expect("lock"),
        "replay must revoke tokens issued for the code"
    );
    assert!(
        s.audit
            .events
            .lock()
            .expect("lock")
            .contains(&"oauth.authorization_code.replayed".to_owned())
    );
}

fn stored_refresh(rs: RefreshState) -> RefreshToken {
    RefreshToken {
        tenant: tenant(),
        client: client(),
        subject: UserId::from_uuid(Uuid::from_u128(0xa1)),
        family: FamilyId::from_uuid(Uuid::from_u128(0xf1)),
        generation: 0,
        family_started_at: NOW,
        expires_at: NOW.saturating_add(Duration::from_seconds(3600)),
        state: rs,
    }
}

fn refresh_form() -> TokenForm {
    TokenForm {
        grant_type: "refresh_token".to_owned(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        client_id: Some("acme-web".to_owned()),
        refresh_token: Some("the-refresh".to_owned()),
        client_assertion_type: None,
        client_assertion: None,
    }
}

#[tokio::test]
async fn refresh_rotates_and_returns_a_new_token() {
    let s = state();
    *s.refresh.record.lock().expect("lock") = Some(stored_refresh(RefreshState::Active));

    let resp = token(&s, &refresh_form(), None).await.expect("rotation");

    assert!(
        *s.refresh.rotated.lock().expect("lock"),
        "store must be told to rotate"
    );
    let new = resp.refresh_token.expect("a new refresh token is returned");
    assert_ne!(new, "the-refresh", "the returned token must be a new one");
    assert!(
        s.audit
            .events
            .lock()
            .expect("lock")
            .contains(&"oauth.refresh_token.rotated".to_owned())
    );
}

#[tokio::test]
async fn reusing_a_rotated_refresh_token_brings_the_family_down() {
    let s = state();
    *s.refresh.record.lock().expect("lock") = Some(stored_refresh(RefreshState::Rotated {
        at: Timestamp::from_unix_seconds(999_999),
    }));

    let err = token(&s, &refresh_form(), None)
        .await
        .expect_err("reuse must be denied");
    assert_eq!(err.error, OAuthErrorCode::InvalidGrant);
    assert!(
        *s.refresh.family_revoked.lock().expect("lock"),
        "reuse must revoke the whole family"
    );
}

#[tokio::test]
async fn unsupported_grant_types_are_rejected() {
    let s = state();
    for gt in ["password", "implicit", "client_credentials", "nonsense"] {
        let form = TokenForm {
            grant_type: gt.to_owned(),
            ..code_form()
        };
        let err = token(&s, &form, None).await.expect_err("must be rejected");
        assert_eq!(
            err.error,
            OAuthErrorCode::UnsupportedGrantType,
            "grant: {gt}"
        );
    }
}

#[tokio::test]
async fn storage_outage_returns_503_not_invalid_grant() {
    struct DeadCodes;
    impl CodeStore for DeadCodes {
        async fn load(&self, _: TenantId, _: &[u8; 32]) -> Result<StoredCode, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn consume(&self, _: TenantId, _: &[u8; 32], _: Timestamp) -> Result<(), StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn revoke_tokens_issued_for_code(
            &self,
            _: TenantId,
            _: &[u8; 32],
            _: Timestamp,
        ) -> Result<(), StoreError> {
            Err(StoreError::Unavailable)
        }
    }

    let (key, _) = SigningKey::generate("k1").expect("key");
    let key = Arc::new(key);
    let s = AppState {
        tenant: TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer("https://acme.argus.test"),
            active_key: Arc::clone(&key),
            published_keys: vec![key],
        },
        codes: DeadCodes,
        refresh: MemRefresh::default(),
        audit: MemAudit::default(),
        tenant_id: tenant(),
        clients: Clients::default(),
        authenticator: (),
        replay: MemoryReplayStore::default(),
        resources: MemoryResourceStore::default(),
    };

    let err = handle(&s, &code_form(), NOW, &AwsLcSha256, None)
        .await
        .expect_err("outage");
    assert_eq!(err.error, OAuthErrorCode::TemporarilyUnavailable);
    assert_eq!(err.http_status(), 503);
}

#[test]
fn the_flow_uses_real_sha256() {
    let digest = AwsLcSha256.sha256(VERIFIER.as_bytes());
    let expected = base64ct::Base64UrlUnpadded::decode_vec(CHALLENGE).expect("b64");
    assert_eq!(digest.as_slice(), expected.as_slice());
}

#[tokio::test]
async fn dpop_binding_changes_the_token_type_and_adds_cnf() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let resp = token(&s, &code_form(), Some("thumbprint-abc".to_owned()))
        .await
        .expect("token issued");

    assert_eq!(resp.token_type, "DPoP");

    let claims = argus_proto::jwt::verify(&resp.access_token, &s.tenant.active_key.verifying_key())
        .expect("verify");
    assert_eq!(
        claims.cnf.expect("cnf must be present").jkt,
        "thumbprint-abc"
    );
}

#[tokio::test]
async fn without_dpop_the_token_stays_bearer() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let resp = token(&s, &code_form(), None).await.expect("token issued");

    assert_eq!(resp.token_type, "Bearer");
    let claims = argus_proto::jwt::verify(&resp.access_token, &s.tenant.active_key.verifying_key())
        .expect("verify");
    assert!(claims.cnf.is_none());
}

fn openid_code() -> StoredCode {
    StoredCode {
        nonce: Some("n-0S6_WzA2Mj".to_owned()),
        scope: Some("openid profile".to_owned()),
        ..stored_code(CodeState::Issued)
    }
}

#[tokio::test]
async fn openid_scope_produces_a_verifiable_id_token() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(openid_code());

    let resp = token(&s, &code_form(), None).await.expect("token issued");

    let raw = resp.id_token.as_deref().expect("id_token must be present");
    let claims = argus_proto::oidc::verify_id_token(raw, &s.tenant.active_key.verifying_key())
        .expect("id_token verifies against the published key");

    assert_eq!(claims.iss, "https://acme.argus.test");

    assert!(claims.aud.contains("acme-web"));
    assert!(claims.exp > claims.iat);
}

#[tokio::test]
async fn the_nonce_is_echoed_byte_for_byte() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(openid_code());

    let resp = token(&s, &code_form(), None).await.expect("token issued");

    let claims = argus_proto::oidc::verify_id_token(
        resp.id_token.as_deref().expect("id_token"),
        &s.tenant.active_key.verifying_key(),
    )
    .expect("verify");

    assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
}

#[tokio::test]
async fn at_hash_binds_the_id_token_to_this_access_token() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(openid_code());

    let resp = token(&s, &code_form(), None).await.expect("token issued");

    let claims = argus_proto::oidc::verify_id_token(
        resp.id_token.as_deref().expect("id_token"),
        &s.tenant.active_key.verifying_key(),
    )
    .expect("verify");

    let expected = argus_proto::oidc::at_hash(&resp.access_token, &AwsLcSha256);
    assert_eq!(claims.at_hash.as_deref(), Some(expected.as_str()));

    let other = argus_proto::oidc::at_hash("some-other-token", &AwsLcSha256);
    assert_ne!(claims.at_hash.as_deref(), Some(other.as_str()));
}

#[tokio::test]
async fn a_plain_oauth_request_gets_no_id_token() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(StoredCode {
        scope: Some("profile email".to_owned()),
        ..stored_code(CodeState::Issued)
    });

    let resp = token(&s, &code_form(), None).await.expect("token issued");

    assert!(resp.id_token.is_none());
}

#[tokio::test]
async fn openid_without_a_nonce_still_succeeds() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(StoredCode {
        nonce: None,
        scope: Some("openid".to_owned()),
        ..stored_code(CodeState::Issued)
    });

    let resp = token(&s, &code_form(), None)
        .await
        .expect("token must be issued without a nonce");

    let claims = argus_proto::oidc::verify_id_token(
        resp.id_token.as_deref().expect("id_token"),
        &s.tenant.active_key.verifying_key(),
    )
    .expect("verify");

    assert!(claims.nonce.is_none());
}

#[tokio::test]
async fn refresh_does_not_fabricate_an_id_token() {
    let s = state();
    *s.refresh.record.lock().expect("lock") = Some(stored_refresh(RefreshState::Active));

    let resp = token(&s, &refresh_form(), None).await.expect("rotated");

    assert!(resp.id_token.is_none());
}

use argus_core::client_auth::ClientKey;

fn client_key(kid: &str) -> (SigningKey, ClientKey) {
    let (signing, _) = SigningKey::generate(kid).expect("key");
    let c = signing.public_components().expect("components");
    (
        signing,
        ClientKey {
            kid: kid.to_owned(),
            x: c.x,
            y: c.y,
        },
    )
}

fn assertion_for(signing: &SigningKey, kid: &str, payload: &str) -> String {
    let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
    let input = format!(
        "{}.{}",
        base64ct::Base64UrlUnpadded::encode_string(header.as_bytes()),
        base64ct::Base64UrlUnpadded::encode_string(payload.as_bytes())
    );
    let sig = signing.sign(input.as_bytes()).expect("sign");
    format!(
        "{input}.{}",
        base64ct::Base64UrlUnpadded::encode_string(&sig)
    )
}

fn assertion_payload(aud: &str, exp_offset: i64, jti: &str) -> String {
    format!(
        r#"{{"iss":"acme-web","sub":"acme-web","aud":"{aud}","exp":{},"jti":"{jti}"}}"#,
        NOW.as_unix_seconds() + exp_offset
    )
}

fn confidential_state(keys: Vec<ClientKey>) -> TestState {
    let mut s = state();
    s.clients = Clients {
        method: ClientAuthMethod::PrivateKeyJwt,
        keys,
    };
    s
}

fn assertion_form(assertion: String) -> TokenForm {
    TokenForm {
        client_assertion_type: Some(argus_proto::ASSERTION_TYPE.to_owned()),
        client_assertion: Some(assertion),
        ..code_form()
    }
}

#[tokio::test]
async fn a_valid_private_key_jwt_authenticates_the_client() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test", 120, "j1"),
    );
    token(&s, &assertion_form(a), None)
        .await
        .expect("token issued");
}

#[tokio::test]
async fn a_confidential_client_cannot_authenticate_with_nothing() {
    let (_, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let err = token(&s, &code_form(), None)
        .await
        .expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
    assert_eq!(err.http_status(), 401);

    assert!(
        !*s.codes.consumed.lock().expect("lock"),
        "an unauthenticated request must not burn the code"
    );
}

#[tokio::test]
async fn an_assertion_signed_by_an_unregistered_key_is_refused() {
    let (attacker, _) = client_key("k1");
    let (_, registered) = client_key("k1");
    let s = confidential_state(vec![registered]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &attacker,
        "k1",
        &assertion_payload("https://acme.argus.test", 120, "j1"),
    );
    let err = token(&s, &assertion_form(a), None)
        .await
        .expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn an_assertion_addressed_to_another_server_is_refused() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://other-idp.test", 120, "j1"),
    );
    let err = token(&s, &assertion_form(a), None)
        .await
        .expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn the_token_endpoint_url_is_also_an_accepted_audience() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test/token", 120, "j1"),
    );
    assert!(token(&s, &assertion_form(a), None).await.is_ok());
}

#[tokio::test]
async fn an_expired_assertion_is_refused() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test", -1, "j1"),
    );
    let err = token(&s, &assertion_form(a), None)
        .await
        .expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn an_assertion_that_lives_too_long_is_refused() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test", 86_400, "j1"),
    );
    let err = token(&s, &assertion_form(a), None)
        .await
        .expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn an_assertion_claiming_another_client_is_refused() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let payload = format!(
        r#"{{"iss":"acme-web","sub":"other-app","aud":"https://acme.argus.test","exp":{},"jti":"j1"}}"#,
        NOW.as_unix_seconds() + 120
    );
    let a = assertion_for(&signing, "k1", &payload);
    let err = token(&s, &assertion_form(a), None)
        .await
        .expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn a_contradictory_client_id_is_refused() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test", 120, "j1"),
    );
    let form = TokenForm {
        client_id: Some("someone-else".to_owned()),
        ..assertion_form(a)
    };
    let err = token(&s, &form, None).await.expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn a_wrong_assertion_type_is_not_silently_ignored() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test", 120, "j1"),
    );
    let form = TokenForm {
        client_assertion_type: Some("urn:something:else".to_owned()),
        ..assertion_form(a)
    };
    let err = token(&s, &form, None).await.expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidRequest);
}

#[tokio::test]
async fn a_public_client_may_not_present_an_assertion() {
    let (signing, _) = client_key("k1");
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test", 120, "j1"),
    );
    let err = token(&s, &assertion_form(a), None)
        .await
        .expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn an_unregistered_client_is_refused() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let form = TokenForm {
        client_id: Some("ghost".to_owned()),
        ..code_form()
    };
    let err = token(&s, &form, None).await.expect_err("must be refused");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn a_replayed_assertion_is_refused() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);

    let a = assertion_for(
        &signing,
        "k1",
        &assertion_payload("https://acme.argus.test", 120, "j-once"),
    );

    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));
    token(&s, &assertion_form(a.clone()), None)
        .await
        .expect("first use succeeds");

    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));
    let err = token(&s, &assertion_form(a), None)
        .await
        .expect_err("the same jti must not be accepted twice");
    assert_eq!(err.error, OAuthErrorCode::InvalidClient);
}

#[tokio::test]
async fn a_different_jti_from_the_same_client_is_accepted() {
    let (signing, public) = client_key("k1");
    let s = confidential_state(vec![public]);

    for jti in ["j-1", "j-2"] {
        *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));
        let a = assertion_for(
            &signing,
            "k1",
            &assertion_payload("https://acme.argus.test", 120, jti),
        );
        token(&s, &assertion_form(a), None)
            .await
            .unwrap_or_else(|e| panic!("jti {jti} must be accepted: {e:?}"));
    }
}
