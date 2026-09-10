#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use argus_core::id::{ClientId, TenantId};
use argus_core::par::{ParFault, Profile};
use argus_core::time::Duration;
use argus_crypto::SigningKey;
use argus_http::par::{ParState, authenticate_pusher, parse_form, push, redeem};
use argus_store::PostgresStore;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const ISSUER: &str = "https://idp.argus.test";

fn endpoint() -> String {
    format!("{ISSUER}/par")
}

async fn pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").ok()?;
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()
}

fn client_id_for(tenant: TenantId) -> String {
    format!("acme-{}", &tenant.as_uuid().simple().to_string()[..12])
}

async fn seed(tenant: TenantId, confidential: bool, key: Option<&SigningKey>) {
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

    let (kind, method) = if confidential {
        ("confidential", "private_key_jwt")
    } else {
        ("public", "none")
    };

    sqlx::query(
        "INSERT INTO clients (tenant_id, client_id, client_type, auth_method) VALUES ($1, $2, $3, $4)",
    )
    .bind(tenant.as_uuid())
    .bind(client_id_for(tenant))
    .bind(kind)
    .bind(method)
    .execute(&mut *tx)
    .await
    .expect("client");

    sqlx::query(
        "INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri) VALUES ($1, $2, $3)",
    )
    .bind(tenant.as_uuid())
    .bind(client_id_for(tenant))
    .bind("https://app.example.test/cb")
    .execute(&mut *tx)
    .await
    .expect("redirect uri");

    if let Some(key) = key {
        let components = key.public_components().expect("components");
        sqlx::query(
            "INSERT INTO client_keys (tenant_id, client_id, kid, x, y) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant.as_uuid())
        .bind(client_id_for(tenant))
        .bind(key.kid())
        .bind(components.x.as_slice())
        .bind(components.y.as_slice())
        .execute(&mut *tx)
        .await
        .expect("client key");
    }

    tx.commit().await.expect("commit");
}

fn state(store: PostgresStore, tenant: TenantId, profile: Profile) -> Arc<ParState> {
    Arc::new(ParState {
        store,
        tenant_id: tenant,
        profile,
        issuer: ISSUER.to_owned(),
        endpoint: endpoint(),
    })
}

fn client(tenant: TenantId) -> ClientId {
    ClientId::new(client_id_for(tenant)).expect("client")
}

fn assertion(key: &SigningKey, audience: &str, jti: &str, client_id: &str) -> String {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("clock");

    let header = serde_json::json!({ "alg": "ES256", "kid": key.kid(), "typ": "JWT" });
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": jti,
        "iat": now,
        "exp": now + 120
    });

    let head =
        Base64UrlUnpadded::encode_string(serde_json::to_string(&header).expect("json").as_bytes());
    let body =
        Base64UrlUnpadded::encode_string(serde_json::to_string(&claims).expect("json").as_bytes());

    let input = format!("{head}.{body}");
    let signature = key.sign(input.as_bytes()).expect("sign");

    format!("{input}.{}", Base64UrlUnpadded::encode_string(&signature))
}

fn parameters(tenant: TenantId, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out = vec![
        ("client_id".to_owned(), client_id_for(tenant)),
        ("response_type".to_owned(), "code".to_owned()),
        (
            "redirect_uri".to_owned(),
            "https://app.example.test/cb".to_owned(),
        ),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
        ("scope".to_owned(), "openid".to_owned()),
    ];

    out.extend(
        extra
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    );
    out
}

#[tokio::test]
async fn a_pushed_request_is_redeemed_once_and_carries_its_parameters() {
    let Some(pool) = pool().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, true, None).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    let (request_uri, window) = push(
        &state,
        &parameters(tenant, &[("resource", "https://a.test")]),
        &client(tenant),
        None,
    )
    .await
    .expect("push");

    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    assert_eq!(window, Duration::from_seconds(90));

    let redeemed = redeem(&state, &request_uri, &client(tenant))
        .await
        .expect("redeem");

    assert_eq!(redeemed.parameter("scope"), Some("openid"));
    assert_eq!(
        redeemed.parameter("redirect_uri"),
        Some("https://app.example.test/cb")
    );
    assert_eq!(redeemed.all("resource"), ["https://a.test"]);

    assert_eq!(
        redeem(&state, &request_uri, &client(tenant))
            .await
            .unwrap_err(),
        ParFault::UnknownRequestUri,
        "a request_uri that can be presented twice is an authorization request an attacker can replay"
    );
}

#[tokio::test]
async fn a_request_uri_cannot_be_presented_by_another_client() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, true, None).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    let (request_uri, _) = push(&state, &parameters(tenant, &[]), &client(tenant), None)
        .await
        .expect("push");

    let stranger = ClientId::new("someone-else").expect("client");

    assert_eq!(
        redeem(&state, &request_uri, &stranger).await.unwrap_err(),
        ParFault::NotYours,
        "handing a request_uri to another client would let it borrow this one's registration"
    );
}

#[tokio::test]
async fn a_request_uri_this_server_never_issued_is_refused() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, true, None).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    for candidate in [
        "urn:ietf:params:oauth:request_uri:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "https://attacker.test/request.jwt",
        "urn:ietf:params:oauth:request_uri:",
    ] {
        assert_eq!(
            redeem(&state, candidate, &client(tenant))
                .await
                .unwrap_err(),
            ParFault::UnknownRequestUri,
            "for {candidate}"
        );
    }
}

#[tokio::test]
async fn a_push_that_declares_another_client_is_refused() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, true, None).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    let mut body = parameters(tenant, &[]);
    body[0] = ("client_id".to_owned(), "someone-else".to_owned());

    assert!(
        push(&state, &body, &client(tenant), None).await.is_err(),
        "the authenticated client is the only one that may push on its own behalf"
    );
}

#[tokio::test]
async fn a_confidential_client_authenticates_with_its_assertion() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    let (key, _) = SigningKey::generate("client-1").expect("key");
    seed(tenant, true, Some(&key)).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    let body = parameters(
        tenant,
        &[
            (
                "client_assertion",
                &assertion(&key, &endpoint(), "jti-1", &client_id_for(tenant)),
            ),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
        ],
    );

    let authenticated = authenticate_pusher(&state, &body)
        .await
        .expect("the client presented a valid assertion");

    assert_eq!(authenticated.as_str(), client_id_for(tenant));
}

#[tokio::test]
async fn a_confidential_client_that_presents_no_assertion_is_refused() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    let (key, _) = SigningKey::generate("client-1").expect("key");
    seed(tenant, true, Some(&key)).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    assert!(
        authenticate_pusher(&state, &parameters(tenant, &[]))
            .await
            .is_err(),
        "anyone able to push without authenticating can craft an authorization request for any client"
    );
}

#[tokio::test]
async fn an_assertion_signed_by_a_key_the_client_never_registered_is_refused() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    let (registered, _) = SigningKey::generate("client-1").expect("key");
    let (stranger, _) = SigningKey::generate("client-1").expect("key");
    seed(tenant, true, Some(&registered)).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    let body = parameters(
        tenant,
        &[(
            "client_assertion",
            &assertion(&stranger, &endpoint(), "jti-2", &client_id_for(tenant)),
        )],
    );

    assert!(authenticate_pusher(&state, &body).await.is_err());
}

#[tokio::test]
async fn an_assertion_minted_for_another_audience_is_refused() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    let (key, _) = SigningKey::generate("client-1").expect("key");
    seed(tenant, true, Some(&key)).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    let body = parameters(
        tenant,
        &[(
            "client_assertion",
            &assertion(
                &key,
                "https://another-idp.test/token",
                "jti-3",
                &client_id_for(tenant),
            ),
        )],
    );

    assert!(
        authenticate_pusher(&state, &body).await.is_err(),
        "an assertion accepted for any audience is one that can be relayed to this server"
    );
}

#[tokio::test]
async fn an_assertion_is_refused_the_second_time_it_is_presented() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    let (key, _) = SigningKey::generate("client-1").expect("key");
    seed(tenant, true, Some(&key)).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    let body = parameters(
        tenant,
        &[(
            "client_assertion",
            &assertion(&key, &endpoint(), "jti-replay", &client_id_for(tenant)),
        )],
    );

    authenticate_pusher(&state, &body).await.expect("first use");

    assert!(
        authenticate_pusher(&state, &body).await.is_err(),
        "a replayable assertion is a bearer credential wearing a signature"
    );
}

#[tokio::test]
async fn the_financial_grade_profile_refuses_a_public_client() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, false, None).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::financial_grade());

    assert!(
        authenticate_pusher(&state, &parameters(tenant, &[]))
            .await
            .is_err(),
        "the profile is for third party access and says confidential clients only"
    );
}

#[tokio::test]
async fn the_permissive_profile_still_accepts_a_public_client() {
    let Some(pool) = pool().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant, false, None).await;

    let state = state(PostgresStore::new(pool), tenant, Profile::permissive());

    authenticate_pusher(&state, &parameters(tenant, &[]))
        .await
        .expect("ordinary deployments still work");
}

#[tokio::test]
async fn a_request_pushed_by_one_tenant_is_invisible_to_another() {
    let Some(pool) = pool().await else {
        return;
    };
    let first = TenantId::from_uuid(Uuid::new_v4());
    let second = TenantId::from_uuid(Uuid::new_v4());
    seed(first, true, None).await;
    seed(second, true, None).await;

    let store = PostgresStore::new(pool);
    let one = state(store.clone(), first, Profile::financial_grade());
    let other = state(store, second, Profile::financial_grade());

    let (request_uri, _) = push(&one, &parameters(first, &[]), &client(first), None)
        .await
        .expect("push");

    assert_eq!(
        redeem(&other, &request_uri, &client(first))
            .await
            .unwrap_err(),
        ParFault::UnknownRequestUri
    );
}

#[test]
fn a_form_body_is_read_with_repeated_parameters_intact() {
    let parsed = parse_form(
        "client_id=acme-web&resource=https%3A%2F%2Fa.test&resource=https%3A%2F%2Fb.test",
    );

    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[1].1, "https://a.test");
    assert_eq!(parsed[2].1, "https://b.test");
}

#[test]
fn a_plus_in_a_form_body_decodes_to_a_space() {
    let parsed = parse_form("scope=openid+profile");
    assert_eq!(parsed[0].1, "openid profile");
}
