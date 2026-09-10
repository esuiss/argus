#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::audit::merkle::verify_inclusion;
use argus_core::id::TenantId;
use argus_crypto::AwsLcSha256;
use argus_store::PostgresStore;
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

async fn seed(tenant: TenantId, events: usize) -> Vec<Uuid> {
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

    let mut ids = Vec::with_capacity(events);
    for i in 0..events {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO audit_events \
               (tenant_id, occurred_at, event_id, event_type, outcome, actor_kind) \
             VALUES ($1, now() + ($2 || ' seconds')::interval, $3, 'token.issued', 'success', 'client')",
        )
        .bind(tenant.as_uuid())
        .bind(format!("-{}", 1000 - i))
        .bind(id)
        .execute(&mut *tx)
        .await
        .expect("event");
        ids.push(id);
    }

    tx.commit().await.expect("commit");
    ids
}

#[tokio::test]
async fn every_checkpointed_event_proves_itself_against_the_published_root() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    let ids = seed(tenant, 9).await;

    let checkpoint = store
        .checkpoint_audit(tenant, &AwsLcSha256)
        .await
        .expect("checkpoint")
        .expect("something to fold");

    assert_eq!(checkpoint.tree_size, 9);

    for id in &ids {
        let (index, leaf, published, proof) = store
            .audit_proof(tenant, id, &AwsLcSha256)
            .await
            .expect("proof");

        assert!(
            verify_inclusion(
                &AwsLcSha256,
                &leaf,
                usize::try_from(index).expect("index"),
                usize::try_from(published.tree_size).expect("size"),
                &proof,
                &published.root
            ),
            "event {id} did not verify against the published root"
        );

        assert!(
            proof.len() <= 4,
            "{} hashes for a tree of nine",
            proof.len()
        );
    }
}

#[tokio::test]
async fn a_proof_does_not_verify_against_a_root_from_a_different_log() {
    let Some(store) = store().await else {
        return;
    };
    let mine = TenantId::from_uuid(Uuid::new_v4());
    let theirs = TenantId::from_uuid(Uuid::new_v4());
    let ids = seed(mine, 5).await;
    seed(theirs, 5).await;

    store
        .checkpoint_audit(mine, &AwsLcSha256)
        .await
        .expect("checkpoint");
    let other = store
        .checkpoint_audit(theirs, &AwsLcSha256)
        .await
        .expect("checkpoint")
        .expect("something to fold");

    let id = ids.first().expect("an event");
    let (index, leaf, published, proof) = store
        .audit_proof(mine, id, &AwsLcSha256)
        .await
        .expect("proof");

    assert_ne!(published.root, other.root, "two logs, two roots");

    assert!(
        !verify_inclusion(
            &AwsLcSha256,
            &leaf,
            usize::try_from(index).expect("index"),
            usize::try_from(other.tree_size).expect("size"),
            &proof,
            &other.root
        ),
        "a proof must not verify against another tenant's root"
    );
}

#[tokio::test]
async fn an_event_that_has_not_been_folded_in_yet_has_no_proof() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    let first = seed(tenant, 3).await;

    store
        .checkpoint_audit(tenant, &AwsLcSha256)
        .await
        .expect("checkpoint");

    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("scope");
    let late = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_events \
           (tenant_id, occurred_at, event_id, event_type, outcome, actor_kind) \
         VALUES ($1, now(), $2, 'token.issued', 'success', 'client')",
    )
    .bind(tenant.as_uuid())
    .bind(late)
    .execute(&mut *tx)
    .await
    .expect("event");
    tx.commit().await.expect("commit");

    assert!(
        store
            .audit_proof(tenant, &late, &AwsLcSha256)
            .await
            .is_err(),
        "issuing a proof that cannot verify is worse than saying there is none"
    );

    assert!(
        store
            .audit_proof(tenant, first.first().expect("event"), &AwsLcSha256)
            .await
            .is_ok(),
        "the events the checkpoint does cover still prove"
    );
}

#[tokio::test]
async fn a_second_checkpoint_extends_the_first_rather_than_replacing_it() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, 4).await;

    let first = store
        .checkpoint_audit(tenant, &AwsLcSha256)
        .await
        .expect("checkpoint")
        .expect("something to fold");
    assert_eq!(first.tree_size, 4);

    seed_more(tenant, 3).await;

    let second = store
        .checkpoint_audit(tenant, &AwsLcSha256)
        .await
        .expect("checkpoint")
        .expect("something to fold");
    assert_eq!(second.tree_size, 7);
    assert_ne!(first.root, second.root);

    assert!(
        store
            .checkpoint_audit(tenant, &AwsLcSha256)
            .await
            .expect("checkpoint")
            .is_none()
    );
}

async fn seed_more(tenant: TenantId, events: usize) {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("scope");
    for i in 0..events {
        sqlx::query(
            "INSERT INTO audit_events \
               (tenant_id, occurred_at, event_id, event_type, outcome, actor_kind) \
             VALUES ($1, now() + ($2 || ' seconds')::interval, $3, 'token.issued', 'success', 'client')",
        )
        .bind(tenant.as_uuid())
        .bind(format!("-{}", 500 - i))
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .expect("event");
    }
    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn a_leaf_cannot_be_changed_once_it_is_written() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, 2).await;
    store
        .checkpoint_audit(tenant, &AwsLcSha256)
        .await
        .expect("checkpoint");

    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("scope");

    let outcome = sqlx::query("UPDATE audit_leaves SET leaf_hash = $2 WHERE tenant_id = $1")
        .bind(tenant.as_uuid())
        .bind(vec![0_u8; 32])
        .execute(&mut *tx)
        .await;

    assert!(outcome.is_err(), "a leaf must not be rewritable");
}
