#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::aal::Aal;
use argus_core::id::{TenantId, UserId};
use argus_core::time::{Duration, Timestamp};
use argus_crypto::blind_index::BlindIndexKey;
use argus_store::PostgresStore;
use argus_store::traits::{AuthnSession, AuthnStore, SessionStore, StoreError};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const NOW: Timestamp = Timestamp::from_unix_seconds(1_700_000_000);

async fn store() -> Option<PostgresStore> {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    Some(PostgresStore::new(pool))
}

fn fresh_tenant() -> TenantId {
    TenantId::from_uuid(Uuid::new_v4())
}

fn key() -> BlindIndexKey {
    BlindIndexKey::new(&[9u8; 32]).expect("key")
}

async fn seed_tenant(tenant: TenantId) {
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

    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn a_user_created_with_a_blind_index_is_found_by_it() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let user = UserId::from_uuid(Uuid::new_v4());
    let index = key().compute("Person@Example.COM");

    s.create_user(t, user, &index, b"ciphertext")
        .await
        .expect("the lookup path must work against the real database");

    assert_eq!(
        s.find_user_by_blind_index(t, &index)
            .await
            .expect("query must not error"),
        Some(user)
    );
}

#[tokio::test]
async fn the_lookup_is_case_and_whitespace_insensitive_end_to_end() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let user = UserId::from_uuid(Uuid::new_v4());
    s.create_user(t, user, &key().compute("person@example.com"), b"c")
        .await
        .expect("create");

    for spelling in ["PERSON@EXAMPLE.COM", "  person@example.com  "] {
        assert_eq!(
            s.find_user_by_blind_index(t, &key().compute(spelling))
                .await
                .expect("query"),
            Some(user),
            "failed for {spelling:?}"
        );
    }
}

#[tokio::test]
async fn an_unknown_identifier_is_none_rather_than_an_error() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    assert_eq!(
        s.find_user_by_blind_index(t, &key().compute("nobody@example.com"))
            .await
            .expect("an unknown identifier must not be an error"),
        None,
        "an error here would turn every failed login into a 503"
    );
}

#[tokio::test]
async fn one_tenant_cannot_find_another_tenants_user() {
    let Some(s) = store().await else {
        return;
    };
    let a = fresh_tenant();
    let b = fresh_tenant();
    seed_tenant(a).await;
    seed_tenant(b).await;

    let index = key().compute("shared@example.com");
    s.create_user(a, UserId::from_uuid(Uuid::new_v4()), &index, b"c")
        .await
        .expect("create");

    assert_eq!(
        s.find_user_by_blind_index(b, &index).await.expect("query"),
        None
    );
}

#[tokio::test]
async fn a_password_round_trips_and_the_required_level_defaults_to_aal1() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let user = UserId::from_uuid(Uuid::new_v4());
    s.create_user(t, user, &key().compute("p@example.com"), b"c")
        .await
        .expect("create");

    assert_eq!(s.password_of(t, user).await.expect("query"), None);

    let phc = argus_crypto::password::hash("a real passphrase").expect("hash");
    s.set_password(t, user, &phc).await.expect("set");

    assert_eq!(s.password_of(t, user).await.expect("query"), Some(phc));
    assert_eq!(s.required_aal(t, user).await.expect("query"), Aal::One);
}

#[tokio::test]
async fn a_session_round_trips_and_expires() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let user = UserId::from_uuid(Uuid::new_v4());
    s.create_user(t, user, &key().compute("s@example.com"), b"c")
        .await
        .expect("create");

    let hash = [3u8; 32];
    let session = AuthnSession {
        subject: user,
        achieved: Aal::One,
        authenticated_at: NOW,
        expires_at: NOW.saturating_add(Duration::from_seconds(600)),
    };
    s.create_session(t, &hash, &session).await.expect("create");

    assert_eq!(
        s.load_session(t, &hash, NOW).await.expect("load").subject,
        user
    );

    let later = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 601);
    assert_eq!(
        s.load_session(t, &hash, later).await.unwrap_err(),
        StoreError::NotFound
    );
}

#[tokio::test]
async fn a_revoked_session_stops_loading() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let user = UserId::from_uuid(Uuid::new_v4());
    s.create_user(t, user, &key().compute("r@example.com"), b"c")
        .await
        .expect("create");

    let hash = [4u8; 32];
    s.create_session(
        t,
        &hash,
        &AuthnSession {
            subject: user,
            achieved: Aal::One,
            authenticated_at: NOW,
            expires_at: NOW.saturating_add(Duration::from_seconds(600)),
        },
    )
    .await
    .expect("create");

    s.revoke_session(t, &hash, NOW).await.expect("revoke");

    assert_eq!(
        s.load_session(t, &hash, NOW).await.unwrap_err(),
        StoreError::NotFound
    );
}

#[tokio::test]
async fn a_recovery_attempt_round_trips_and_the_schema_refuses_weak_evidence() {
    use argus_core::recovery::{RecoveryAttempt, RecoveryState};
    use argus_store::traits::RecoveryStore;

    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let user = UserId::from_uuid(Uuid::new_v4());
    s.create_user(t, user, &key().compute("rec@example.com"), b"c")
        .await
        .expect("create");

    let attempt_id = Uuid::new_v4();
    let opened = RecoveryAttempt {
        subject: user,
        state: RecoveryState::Requested,
        required: Aal::Two,
        achieved: None,
        evidence_consumed: false,
        cooldown_until: None,
        grace_until: None,
    };
    s.open_recovery(t, attempt_id, &opened).await.expect("open");

    let loaded = s.load_recovery(t, attempt_id).await.expect("load");
    assert_eq!(loaded.state, RecoveryState::Requested);
    assert_eq!(loaded.required, Aal::Two);
    assert!(!loaded.evidence_consumed);

    let weak = RecoveryAttempt {
        state: RecoveryState::RebindOpen,
        achieved: Some(Aal::One),
        evidence_consumed: true,
        ..loaded.clone()
    };
    assert!(
        s.advance_recovery(t, attempt_id, &weak, NOW).await.is_err(),
        "the schema must refuse recovery weaker than the account it recovers"
    );

    let strong = RecoveryAttempt {
        state: RecoveryState::CoolingDown,
        achieved: Some(Aal::Two),
        evidence_consumed: true,
        cooldown_until: Some(NOW.saturating_add(Duration::from_seconds(86_400))),
        ..loaded
    };
    assert!(
        s.advance_recovery(t, attempt_id, &strong, NOW)
            .await
            .expect("advance"),
        "sufficient evidence must be accepted"
    );

    let after = s.load_recovery(t, attempt_id).await.expect("load");
    assert_eq!(after.state, RecoveryState::CoolingDown);
    assert_eq!(after.achieved, Some(Aal::Two));
    assert!(after.evidence_consumed);
}

#[tokio::test]
async fn an_unknown_recovery_attempt_is_not_found() {
    use argus_store::traits::RecoveryStore;

    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    assert_eq!(
        s.load_recovery(t, Uuid::new_v4()).await.unwrap_err(),
        StoreError::NotFound
    );
}
