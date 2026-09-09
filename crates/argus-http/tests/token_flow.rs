//! Token endpoint'inin uçtan uca akışı.
//!
//! Katmanların gerçekten birleştiğini kanıtlar: `argus-core`'un kararı,
//! `argus-http`'nin etki uygulaması, `argus-crypto`'nun imzası ve
//! `argus-proto`'nun tel formatı tek bir istekte buluşuyor.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    // Sahte depolar bellek içi ve senkron; `async` imzası trait sözleşmesi için.
    clippy::unused_async_trait_impl
)]

use std::sync::{Arc, Mutex};

use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::pkce::{CodeChallenge, CodeChallengeMethod, Sha256};
use argus_core::redirect_uri::RedirectUri;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::{Duration, Timestamp};
use argus_crypto::{AwsLcSha256, SigningKey};
use argus_http::endpoints::token::{TokenForm, handle};
use argus_http::state::{AppState, TenantContext};
use argus_http::store::{AuditSink, CodeStore, RefreshStore, StoreError};
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

// --- Bellek içi depolar ---------------------------------------------------

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

// --- Kurulum --------------------------------------------------------------

fn state() -> AppState<MemCodes, MemRefresh, MemAudit> {
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
        clients: (),
        authenticator: (),
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
    }
}

// --- Authorization code ---------------------------------------------------

#[tokio::test]
async fn authorization_code_yields_a_verifiable_access_token() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let resp = handle(&s, &code_form(), NOW, &AwsLcSha256)
        .await
        .expect("token issued");

    // Token gerçekten bu sunucunun yayınladığı anahtarla doğrulanabilmeli.
    let claims = argus_proto::jwt::verify(&resp.access_token, &s.tenant.active_key.verifying_key())
        .expect("token verifies against the published key");

    assert_eq!(claims.iss, "https://acme.argus.test");
    assert_eq!(claims.aud, "acme-web");
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

/// PKCE yanlışsa token verilmez ve kod yine de tüketilir — saldırgan aynı kodu
/// farklı verifier'larla deneyemesin.
#[tokio::test]
async fn wrong_pkce_verifier_is_rejected_and_burns_the_code() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Issued));

    let form = TokenForm {
        code_verifier: Some("z".repeat(43)),
        ..code_form()
    };

    let err = handle(&s, &form, NOW, &AwsLcSha256)
        .await
        .expect_err("must be denied");
    assert_eq!(err.error, OAuthErrorCode::InvalidGrant);
    assert!(
        *s.codes.consumed.lock().expect("lock"),
        "a denied attempt must still burn the code"
    );
}

/// RFC 9700 §4.1.1: tekrar kullanılan kod, o koddan türeyen her şeyi düşürür.
#[tokio::test]
async fn replayed_code_triggers_revocation_of_derived_tokens() {
    let s = state();
    *s.codes.record.lock().expect("lock") = Some(stored_code(CodeState::Redeemed {
        at: Timestamp::from_unix_seconds(999_999),
    }));

    let err = handle(&s, &code_form(), NOW, &AwsLcSha256)
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

// --- Refresh --------------------------------------------------------------

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
    }
}

#[tokio::test]
async fn refresh_rotates_and_returns_a_new_token() {
    let s = state();
    *s.refresh.record.lock().expect("lock") = Some(stored_refresh(RefreshState::Active));

    let resp = handle(&s, &refresh_form(), NOW, &AwsLcSha256)
        .await
        .expect("rotation");

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

/// RFC 9700 §4.14.2: döndürülmüş bir token yeniden sunulduğunda zincir düşer.
#[tokio::test]
async fn reusing_a_rotated_refresh_token_brings_the_family_down() {
    let s = state();
    *s.refresh.record.lock().expect("lock") = Some(stored_refresh(RefreshState::Rotated {
        at: Timestamp::from_unix_seconds(999_999),
    }));

    let err = handle(&s, &refresh_form(), NOW, &AwsLcSha256)
        .await
        .expect_err("reuse must be denied");
    assert_eq!(err.error, OAuthErrorCode::InvalidGrant);
    assert!(
        *s.refresh.family_revoked.lock().expect("lock"),
        "reuse must revoke the whole family"
    );
}

// --- Grant tipi ve arıza davranışı ----------------------------------------

/// OAuth 2.1 `password` ve implicit'i kaldırdı; desteklenmedikleri net olmalı.
#[tokio::test]
async fn unsupported_grant_types_are_rejected() {
    let s = state();
    for gt in ["password", "implicit", "client_credentials", "nonsense"] {
        let form = TokenForm {
            grant_type: gt.to_owned(),
            ..code_form()
        };
        let err = handle(&s, &form, NOW, &AwsLcSha256)
            .await
            .expect_err("must be rejected");
        assert_eq!(
            err.error,
            OAuthErrorCode::UnsupportedGrantType,
            "grant: {gt}"
        );
    }
}

/// §19 §7.1: depo erişilemezken `invalid_grant` DÖNÜLMEZ. `invalid_grant`
/// istemciye "yeniden yetkilendir" dedirtir ve geçici bir arızayı kalıcı bir
/// çıkışa çevirir. Doğru cevap 503'tür.
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
        clients: (),
        authenticator: (),
    };

    let err = handle(&s, &code_form(), NOW, &AwsLcSha256)
        .await
        .expect_err("outage");
    assert_eq!(err.error, OAuthErrorCode::TemporarilyUnavailable);
    assert_eq!(err.http_status(), 503);
}

/// Akışın sahte hash değil GERÇEK SHA-256 kullandığının kanıtı: RFC 7636 Ek B
/// vektörü uçtan uca yolda da tutmalı.
#[test]
fn the_flow_uses_real_sha256() {
    let digest = AwsLcSha256.sha256(VERIFIER.as_bytes());
    let expected = base64ct::Base64UrlUnpadded::decode_vec(CHALLENGE).expect("b64");
    assert_eq!(digest.as_slice(), expected.as_slice());
}
