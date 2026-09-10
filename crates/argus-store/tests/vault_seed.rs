#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[tokio::test]
async fn seed_the_probe_secrets_this_workspace_uses_for_live_checks() {
    let Ok(url) = std::env::var("ARGUS_TEST_DATABASE_URL") else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");

    let store = argus_store::PostgresStore::new(pool);
    let tenant = argus_core::id::TenantId::from_uuid(uuid::Uuid::nil());

    let material: Vec<u8> = (0_u8..32).collect();
    let sealing = argus_crypto::sealing::SealingKey::new(&material).expect("key");

    for (secret_id, kind, plaintext) in [
        (
            "books-api",
            argus_core::vault::SecretKind::ApiKey,
            &b"sk-live-downstream-books-key"[..],
        ),
        (
            "upstream-oidc",
            argus_core::vault::SecretKind::UpstreamRefreshToken,
            &b"rt-upstream-never-released"[..],
        ),
    ] {
        let record = argus_core::vault::SecretRecord {
            tenant,
            secret_id: secret_id.to_owned(),
            owner: None,
            audience: "https://books.example.test".to_owned(),
            kind,
            required_scope: "books.write".to_owned(),
            expires_at: None,
            revoked: false,
        };

        let sealed = sealing
            .seal(
                plaintext,
                &argus_core::vault::associated_data(tenant, secret_id),
            )
            .expect("seal");

        store
            .put_secret(tenant, &record, &sealed)
            .await
            .expect("store");
    }
}
