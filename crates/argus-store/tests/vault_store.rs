#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::id::{TenantId, UserId};
use argus_core::time::Timestamp;
use argus_core::vault::{SecretKind, SecretRecord, associated_data};
use argus_crypto::sealing::SealingKey;
use argus_store::PostgresStore;
use argus_store::traits::StoreError;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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

async fn seed_tenant(tenant: TenantId) -> Uuid {
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

    let user: Uuid =
        sqlx::query_scalar("INSERT INTO users (tenant_id) VALUES ($1) RETURNING user_id")
            .bind(tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("user");

    sqlx::query(
        "INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id) VALUES ($1, $2, '\\x01', 'k')",
    )
    .bind(tenant.as_uuid())
    .bind(user)
    .execute(&mut *tx)
    .await
    .expect("user key");

    tx.commit().await.expect("commit");
    user
}

fn key() -> SealingKey {
    SealingKey::new(&[3_u8; 32]).expect("key")
}

fn record(tenant: TenantId, owner: Option<UserId>) -> SecretRecord {
    SecretRecord {
        tenant,
        secret_id: "books-api".to_owned(),
        owner,
        audience: "https://books.example.test".to_owned(),
        kind: SecretKind::ApiKey,
        required_scope: "books.write".to_owned(),
        expires_at: None,
        revoked: false,
    }
}

#[tokio::test]
async fn a_sealed_secret_round_trips_through_the_database() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    let owner = UserId::from_uuid(seed_tenant(t).await);

    let sealing = key();
    let sealed = sealing
        .seal(b"downstream-api-key", &associated_data(t, "books-api"))
        .expect("seal");

    s.put_secret(t, &record(t, Some(owner)), &sealed)
        .await
        .expect("store");

    let loaded = s.load_secret(t, "books-api").await.expect("load");

    assert_eq!(loaded.record.audience, "https://books.example.test");
    assert_eq!(loaded.record.kind, SecretKind::ApiKey);
    assert_eq!(loaded.record.owner, Some(owner));

    let opened = sealing
        .open(&loaded.sealed, &associated_data(t, "books-api"))
        .expect("open");

    assert_eq!(opened, b"downstream-api-key");
}

#[tokio::test]
async fn the_plaintext_never_reaches_the_table() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let sealed = key()
        .seal(b"hunter2-in-the-vault", &associated_data(t, "books-api"))
        .expect("seal");

    s.put_secret(t, &record(t, None), &sealed)
        .await
        .expect("store");

    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");

    let hits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM vault_secrets WHERE position('hunter2-in-the-vault' in encode(ciphertext, 'escape')) > 0",
    )
    .fetch_one(&pool)
    .await
    .expect("query");

    assert_eq!(
        hits, 0,
        "anyone with a database backup would otherwise hold every downstream credential"
    );
}

#[tokio::test]
async fn a_secret_sealed_for_one_tenant_does_not_open_under_another_tenants_context() {
    let Some(s) = store().await else {
        return;
    };
    let first = fresh_tenant();
    let second = fresh_tenant();
    seed_tenant(first).await;
    seed_tenant(second).await;

    let sealing = key();
    let sealed = sealing
        .seal(b"secret", &associated_data(first, "books-api"))
        .expect("seal");

    s.put_secret(first, &record(first, None), &sealed)
        .await
        .expect("store");

    let loaded = s.load_secret(first, "books-api").await.expect("load");

    assert!(
        sealing
            .open(&loaded.sealed, &associated_data(second, "books-api"))
            .is_err(),
        "moving a row between tenants must not move the credential with it"
    );
}

#[tokio::test]
async fn another_tenant_cannot_read_the_secret_at_all() {
    let Some(s) = store().await else {
        return;
    };
    let first = fresh_tenant();
    let second = fresh_tenant();
    seed_tenant(first).await;
    seed_tenant(second).await;

    let sealed = key()
        .seal(b"secret", &associated_data(first, "books-api"))
        .expect("seal");
    s.put_secret(first, &record(first, None), &sealed)
        .await
        .expect("store");

    assert_eq!(
        s.load_secret(second, "books-api").await.unwrap_err(),
        StoreError::NotFound
    );
}

#[tokio::test]
async fn rotating_a_secret_replaces_the_ciphertext_and_clears_the_revocation() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let sealing = key();
    let first = sealing
        .seal(b"old", &associated_data(t, "books-api"))
        .expect("seal");
    s.put_secret(t, &record(t, None), &first)
        .await
        .expect("store");
    s.revoke_secret(t, "books-api").await.expect("revoke");

    assert!(
        s.load_secret(t, "books-api")
            .await
            .expect("load")
            .record
            .revoked
    );

    let second = sealing
        .seal(b"new", &associated_data(t, "books-api"))
        .expect("seal");
    s.put_secret(t, &record(t, None), &second)
        .await
        .expect("rotate");

    let loaded = s.load_secret(t, "books-api").await.expect("load");
    assert!(!loaded.record.revoked);
    assert_eq!(
        sealing
            .open(&loaded.sealed, &associated_data(t, "books-api"))
            .expect("open"),
        b"new"
    );
}

#[tokio::test]
async fn revoking_a_secret_that_does_not_exist_is_reported_as_not_found() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    assert_eq!(
        s.revoke_secret(t, "no-such-secret").await.unwrap_err(),
        StoreError::NotFound
    );
}

#[tokio::test]
async fn a_lease_can_be_spent_exactly_once() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let sealed = key()
        .seal(b"secret", &associated_data(t, "books-api"))
        .expect("seal");
    s.put_secret(t, &record(t, None), &sealed)
        .await
        .expect("store");

    let lease = s
        .issue_lease(
            t,
            "books-api",
            "agent:worker",
            Timestamp::from_unix_seconds(chrono::Utc::now().timestamp() + 60),
        )
        .await
        .expect("issue");

    s.spend_lease(t, &lease.lease_id)
        .await
        .expect("first redemption");

    assert_eq!(
        s.spend_lease(t, &lease.lease_id).await.unwrap_err(),
        StoreError::NotFound,
        "single use has to be enforced by the write itself, not by a read beforehand"
    );
}

#[tokio::test]
async fn the_schema_refuses_a_lease_that_outlives_the_ceiling() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let sealed = key()
        .seal(b"secret", &associated_data(t, "books-api"))
        .expect("seal");
    s.put_secret(t, &record(t, None), &sealed)
        .await
        .expect("store");

    let result = s
        .issue_lease(
            t,
            "books-api",
            "agent:worker",
            Timestamp::from_unix_seconds(chrono::Utc::now().timestamp() + 86_400),
        )
        .await;

    assert!(
        result.is_err(),
        "the five minute ceiling belongs in the schema so a bug in the service cannot exceed it"
    );
}

#[tokio::test]
async fn deleting_the_owner_takes_their_secrets_with_them() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    let owner = seed_tenant(t).await;

    let sealed = key()
        .seal(b"secret", &associated_data(t, "books-api"))
        .expect("seal");
    s.put_secret(t, &record(t, Some(UserId::from_uuid(owner))), &sealed)
        .await
        .expect("store");

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
    sqlx::query("DELETE FROM users WHERE tenant_id = $1 AND user_id = $2")
        .bind(t.as_uuid())
        .bind(owner)
        .execute(&mut *tx)
        .await
        .expect("delete");
    tx.commit().await.expect("commit");

    assert_eq!(
        s.load_secret(t, "books-api").await.unwrap_err(),
        StoreError::NotFound,
        "deprovisioning a person must not leave their downstream credentials behind"
    );
}

#[tokio::test]
async fn spent_and_expired_leases_are_purged() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let sealed = key()
        .seal(b"secret", &associated_data(t, "books-api"))
        .expect("seal");
    s.put_secret(t, &record(t, None), &sealed)
        .await
        .expect("store");

    let lease = s
        .issue_lease(
            t,
            "books-api",
            "agent:worker",
            Timestamp::from_unix_seconds(chrono::Utc::now().timestamp() + 60),
        )
        .await
        .expect("issue");

    s.spend_lease(t, &lease.lease_id).await.expect("spend");

    let purged = s
        .purge_spent_leases(
            t,
            Timestamp::from_unix_seconds(chrono::Utc::now().timestamp()),
        )
        .await
        .expect("purge");

    assert!(purged >= 1);
}

#[tokio::test]
async fn a_lease_can_be_spent_in_the_same_second_it_was_issued() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let sealed = key()
        .seal(b"secret", &associated_data(t, "books-api"))
        .expect("seal");
    s.put_secret(t, &record(t, None), &sealed)
        .await
        .expect("store");

    let lease = s
        .issue_lease(
            t,
            "books-api",
            "agent:worker",
            Timestamp::from_unix_seconds(chrono::Utc::now().timestamp() + 60),
        )
        .await
        .expect("issue");

    s.spend_lease(t, &lease.lease_id).await.expect(
        "an agent redeems immediately; a whole-second timestamp written by the application \
         can land before the sub-second issue time the database recorded",
    );
}
