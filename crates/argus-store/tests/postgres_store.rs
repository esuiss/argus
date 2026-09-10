#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::client_auth::ClientAuthMethod;
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::pkce::{CodeChallenge, CodeChallengeMethod};
use argus_core::redirect_uri::RedirectUri;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::{Duration, Timestamp};
use argus_store::PostgresStore;
use argus_store::traits::{
    ClientStore, CodeIssuer, CodeStore, JtiOutcome, JtiPurpose, RefreshStore, ReplayStore,
    StoreError,
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const NOW: Timestamp = Timestamp::from_unix_seconds(1_700_000_000);

fn fresh_tenant() -> TenantId {
    TenantId::from_uuid(Uuid::new_v4())
}

fn user() -> UserId {
    UserId::from_uuid(Uuid::from_u128(0xa1))
}

fn client_of(tenant: TenantId) -> ClientId {
    ClientId::new(format!("c{}", &tenant.as_uuid().simple().to_string()[..8])).expect("client")
}

async fn store() -> Option<PostgresStore> {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    Some(PostgresStore::new(pool))
}

async fn seed(tenant: TenantId) {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");

    let slug = format!("t{}", &tenant.as_uuid().simple().to_string()[..8]);
    let mut tx = pool.begin().await.expect("begin");

    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("scope");

    sqlx::query("INSERT INTO tenants (tenant_id, slug, issuer_host) VALUES ($1, $2, $3)")
        .bind(tenant.as_uuid())
        .bind(&slug)
        .bind(format!("{slug}.test"))
        .execute(&mut *tx)
        .await
        .expect("tenant");

    sqlx::query(
        "INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id) \
         VALUES ($1, $2, '\\x01', 'k')",
    )
    .bind(tenant.as_uuid())
    .bind(user().as_uuid())
    .execute(&mut *tx)
    .await
    .expect("user key");

    sqlx::query("INSERT INTO users (tenant_id, user_id) VALUES ($1, $2)")
        .bind(tenant.as_uuid())
        .bind(user().as_uuid())
        .execute(&mut *tx)
        .await
        .expect("user");

    sqlx::query(
        "INSERT INTO clients (tenant_id, client_id, client_type) VALUES ($1, $2, 'public')",
    )
    .bind(tenant.as_uuid())
    .bind(client_of(tenant).as_str())
    .execute(&mut *tx)
    .await
    .expect("client");

    sqlx::query(
        "INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri) \
         VALUES ($1, $2, 'https://app.example.com/cb')",
    )
    .bind(tenant.as_uuid())
    .bind(client_of(tenant).as_str())
    .execute(&mut *tx)
    .await
    .expect("redirect uri");

    tx.commit().await.expect("commit");
}

fn stored_code(tenant: TenantId) -> StoredCode {
    StoredCode {
        tenant,
        client: client_of(tenant),
        subject: user(),
        redirect_uri: RedirectUri::register("https://app.example.com/cb").expect("uri"),
        challenge: CodeChallenge::parse(CodeChallengeMethod::S256, CHALLENGE).expect("challenge"),
        issued_at: NOW,
        expires_at: NOW.saturating_add(Duration::from_seconds(60)),
        state: CodeState::Issued,
        nonce: None,
        scope: None,
        resources: Vec::new(),
    }
}

fn refresh(tenant: TenantId, family: FamilyId, generation: u32) -> RefreshToken {
    RefreshToken {
        tenant,
        client: client_of(tenant),
        subject: user(),
        family,
        generation,
        family_started_at: NOW,
        expires_at: NOW.saturating_add(Duration::from_seconds(86_400)),
        state: RefreshState::Active,
    }
}

#[tokio::test]
async fn authorization_code_round_trips_through_the_database() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let hash = [7u8; 32];
    s.issue(t, &hash, &stored_code(t)).await.expect("issue");

    let loaded = CodeStore::load(&s, t, &hash).await.expect("load");
    assert_eq!(loaded.client, client_of(t));
    assert_eq!(loaded.subject, user());
    assert_eq!(loaded.state, CodeState::Issued);

    assert_eq!(loaded.challenge.digest(), stored_code(t).challenge.digest());
    assert_eq!(loaded.redirect_uri.as_str(), "https://app.example.com/cb");
}

#[tokio::test]
async fn consuming_a_code_is_idempotent_and_one_way() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let hash = [8u8; 32];
    s.issue(t, &hash, &stored_code(t)).await.expect("issue");

    let at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 5);
    s.consume(t, &hash, at).await.expect("consume");

    let loaded = CodeStore::load(&s, t, &hash).await.expect("load");
    assert_eq!(loaded.state, CodeState::Redeemed { at });

    let later = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 99);
    s.consume(t, &hash, later).await.expect("consume 2");
    assert_eq!(
        CodeStore::load(&s, t, &hash).await.expect("load").state,
        CodeState::Redeemed { at }
    );
}

#[tokio::test]
async fn missing_code_is_not_found_not_unavailable() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    assert_eq!(
        CodeStore::load(&s, t, &[0u8; 32]).await.unwrap_err(),
        StoreError::NotFound
    );
}

#[tokio::test]
async fn refresh_rotation_closes_the_old_and_opens_the_new() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let family = FamilyId::from_uuid(Uuid::from_u128(0xf1));
    let old = [1u8; 32];
    let new = [2u8; 32];

    s.rotate(t, &old, &old, &refresh(t, family, 0), NOW)
        .await
        .expect("seed token");

    let at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 10);
    s.rotate(t, &old, &new, &refresh(t, family, 1), at)
        .await
        .expect("rotate");

    let previous = RefreshStore::load(&s, t, &old).await.expect("load old");
    assert_eq!(previous.state, RefreshState::Rotated { at });

    let current = RefreshStore::load(&s, t, &new).await.expect("load new");
    assert_eq!(current.state, RefreshState::Active);
    assert_eq!(current.generation, 1);

    assert_eq!(current.family, family);

    assert_eq!(current.family_started_at, NOW);
}

#[tokio::test]
async fn revoking_a_family_takes_every_generation_down() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let family = FamilyId::from_uuid(Uuid::from_u128(0xf2));
    let other_family = FamilyId::from_uuid(Uuid::from_u128(0xf3));

    let hashes: [[u8; 32]; 3] = [[10u8; 32], [11u8; 32], [12u8; 32]];
    for (i, h) in hashes.iter().enumerate() {
        s.rotate(
            t,
            h,
            h,
            &refresh(t, family, u32::try_from(i).unwrap_or(0)),
            NOW,
        )
        .await
        .expect("seed");
    }

    let untouched = [13u8; 32];
    s.rotate(t, &untouched, &untouched, &refresh(t, other_family, 0), NOW)
        .await
        .expect("seed other");

    let at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 20);
    s.revoke_family(t, family, at).await.expect("revoke");

    for h in &hashes {
        assert_eq!(
            RefreshStore::load(&s, t, h).await.expect("load").state,
            RefreshState::Revoked { at },
            "every generation in the family must be revoked"
        );
    }

    assert_eq!(
        RefreshStore::load(&s, t, &untouched)
            .await
            .expect("load")
            .state,
        RefreshState::Active
    );
}

#[tokio::test]
async fn client_lookup_returns_registered_redirect_uris() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let found = s
        .find(t, &client_of(t))
        .await
        .expect("query")
        .expect("client exists");
    assert_eq!(found.client_id, client_of(t));
    assert_eq!(found.redirect_uris.len(), 1);
    assert_eq!(
        found.redirect_uris.first().expect("uri").as_str(),
        "https://app.example.com/cb"
    );

    let unknown = ClientId::new("nope").expect("client id");
    assert!(s.find(t, &unknown).await.expect("query").is_none());
}

#[tokio::test]
async fn oidc_claims_survive_the_round_trip() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let hash = [21u8; 32];
    let code = StoredCode {
        nonce: Some("n-0S6_WzA2Mj".to_owned()),
        scope: Some("openid profile".to_owned()),
        ..stored_code(t)
    };
    s.issue(t, &hash, &code).await.expect("issue");

    let loaded = CodeStore::load(&s, t, &hash).await.expect("load");

    assert_eq!(loaded.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    assert_eq!(loaded.scope.as_deref(), Some("openid profile"));
}

#[tokio::test]
async fn a_plain_oauth_code_stores_no_oidc_claims() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let hash = [22u8; 32];
    s.issue(t, &hash, &stored_code(t)).await.expect("issue");

    let loaded = CodeStore::load(&s, t, &hash).await.expect("load");
    assert!(loaded.nonce.is_none());
    assert!(loaded.scope.is_none());
}

#[tokio::test]
async fn an_oversized_nonce_is_refused_by_the_schema() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let code = StoredCode {
        nonce: Some("n".repeat(256)),
        ..stored_code(t)
    };
    assert!(
        s.issue(t, &[23u8; 32], &code).await.is_err(),
        "the schema must reject a nonce longer than 255 characters"
    );

    let at_limit = StoredCode {
        nonce: Some("n".repeat(255)),
        ..stored_code(t)
    };
    s.issue(t, &[24u8; 32], &at_limit)
        .await
        .expect("255 characters must be accepted");
}

#[tokio::test]
async fn a_confidential_client_carries_its_method_and_keys() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");

    let mut tx = pool.begin().await.expect("begin");

    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(t.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("scope");

    sqlx::query(
        "UPDATE clients SET client_type = 'confidential', auth_method = 'private_key_jwt' \
         WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind(t.as_uuid())
    .bind(client_of(t).as_str())
    .execute(&mut *tx)
    .await
    .expect("promote client");

    for (kid, fill) in [("k1", 0x11u8), ("k2", 0x33u8)] {
        sqlx::query(
            "INSERT INTO client_keys (tenant_id, client_id, kid, x, y) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(t.as_uuid())
        .bind(client_of(t).as_str())
        .bind(kid)
        .bind(vec![fill; 32])
        .bind(vec![fill.wrapping_add(1); 32])
        .execute(&mut *tx)
        .await
        .expect("key");
    }

    tx.commit().await.expect("commit");

    let found = s
        .find(t, &client_of(t))
        .await
        .expect("query")
        .expect("client exists");

    assert_eq!(found.auth_method, ClientAuthMethod::PrivateKeyJwt);

    assert_eq!(found.keys.len(), 2);
    let kids: Vec<&str> = found.keys.iter().map(|k| k.kid.as_str()).collect();
    assert_eq!(kids, ["k1", "k2"]);
    assert_eq!(found.keys.first().expect("key").x, [0x11u8; 32]);
    assert_eq!(found.keys.first().expect("key").y, [0x12u8; 32]);
}

#[tokio::test]
async fn a_public_client_defaults_to_no_authentication() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let found = s
        .find(t, &client_of(t))
        .await
        .expect("query")
        .expect("client exists");

    assert_eq!(found.auth_method, ClientAuthMethod::None);
    assert!(found.keys.is_empty());
}

#[tokio::test]
async fn a_jti_is_accepted_once_and_only_once() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let expiry = NOW.saturating_add(Duration::from_seconds(60));
    assert_eq!(
        s.consume_jti(t, JtiPurpose::DpopProof, "j1", expiry)
            .await
            .expect("first"),
        JtiOutcome::Fresh
    );
    assert_eq!(
        s.consume_jti(t, JtiPurpose::DpopProof, "j1", expiry)
            .await
            .expect("second"),
        JtiOutcome::Replayed
    );
}

#[tokio::test]
async fn the_same_jti_under_a_different_purpose_is_not_a_replay() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let expiry = NOW.saturating_add(Duration::from_seconds(60));
    assert_eq!(
        s.consume_jti(t, JtiPurpose::DpopProof, "shared", expiry)
            .await
            .expect("dpop"),
        JtiOutcome::Fresh
    );
    assert_eq!(
        s.consume_jti(t, JtiPurpose::ClientAssertion, "shared", expiry)
            .await
            .expect("assertion"),
        JtiOutcome::Fresh
    );
}

#[tokio::test]
async fn one_tenant_cannot_burn_another_tenants_jti() {
    let Some(s) = store().await else {
        return;
    };
    let a = fresh_tenant();
    let b = fresh_tenant();
    seed(a).await;
    seed(b).await;

    let expiry = NOW.saturating_add(Duration::from_seconds(60));
    assert_eq!(
        s.consume_jti(a, JtiPurpose::DpopProof, "same", expiry)
            .await
            .expect("a"),
        JtiOutcome::Fresh
    );
    assert_eq!(
        s.consume_jti(b, JtiPurpose::DpopProof, "same", expiry)
            .await
            .expect("b"),
        JtiOutcome::Fresh
    );
}

#[tokio::test]
async fn purging_removes_only_expired_records() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let past = Timestamp::from_unix_seconds(NOW.as_unix_seconds() - 10);
    let future = NOW.saturating_add(Duration::from_seconds(600));
    s.consume_jti(t, JtiPurpose::DpopProof, "stale", past)
        .await
        .expect("stale");
    s.consume_jti(t, JtiPurpose::DpopProof, "live", future)
        .await
        .expect("live");

    let removed = s.purge_expired_jtis(t, NOW).await.expect("purge");
    assert!(removed >= 1, "the expired record must be removed");

    assert_eq!(
        s.consume_jti(t, JtiPurpose::DpopProof, "stale", future)
            .await
            .expect("reuse after purge"),
        JtiOutcome::Fresh,
        "an expired jti may be used again once purged"
    );
    assert_eq!(
        s.consume_jti(t, JtiPurpose::DpopProof, "live", future)
            .await
            .expect("still live"),
        JtiOutcome::Replayed
    );
}
