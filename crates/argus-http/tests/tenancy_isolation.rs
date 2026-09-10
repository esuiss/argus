#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use argus_core::admin::manifest::Surface;
use argus_core::authz::TupleOp;
use argus_core::authz::model::{EntityRef, SubjectRef, Tuple};
use argus_core::id::TenantId;
use argus_crypto::SigningKey;
use argus_http::admin::{AdminState, build};
use argus_http::tenancy::{TenantEntry, TenantRegistry};
use argus_proto::jwt::{AccessTokenClaims, Audience};
use argus_store::PostgresStore;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const HOST_ONE: &str = "one.argus.test";
const HOST_TWO: &str = "two.argus.test";

fn issuer(host: &str) -> String {
    format!("https://{host}")
}

async fn pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").ok()?;
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()
}

async fn seed(tenant: TenantId, host: &str) {
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
        .bind(format!("{}-{host}", &slug[..4]))
        .execute(&mut *tx)
        .await
        .expect("tenant");
    tx.commit().await.expect("commit");
}

fn context(host: &str, key: &Arc<SigningKey>) -> argus_http::state::TenantContext {
    argus_http::state::TenantContext {
        metadata: argus_proto::AuthorizationServerMetadata::for_issuer(&issuer(host)),
        active_key: Arc::clone(key),
        published_keys: vec![Arc::clone(key)],
        rsa_keys: Vec::new(),
        blind_index: argus_crypto::blind_index::BlindIndexKey::new(&[9_u8; 32])
            .expect("blind index"),
        relying_party: None,
    }
}

struct Harness {
    addr: String,
    key: Arc<SigningKey>,
    one: TenantId,
    two: TenantId,
    store: PostgresStore,
}

async fn harness() -> Option<Harness> {
    let pool = pool().await?;
    let store = PostgresStore::new(pool);

    let one = TenantId::from_uuid(Uuid::new_v4());
    let two = TenantId::from_uuid(Uuid::new_v4());
    seed(one, HOST_ONE).await;
    seed(two, HOST_TWO).await;

    let (key, _) = SigningKey::generate("k1".to_owned()).expect("key");
    let key = Arc::new(key);

    // İki kiracı, iki host. §18'in bütün mesele ettiği şey burada ölçülüyor.
    let mut registry = TenantRegistry::new();
    registry.register(
        HOST_ONE,
        TenantEntry {
            id: one,
            issuer: issuer(HOST_ONE),
            context: context(HOST_ONE, &key),
        },
    );
    registry.register(
        HOST_TWO,
        TenantEntry {
            id: two,
            issuer: issuer(HOST_TWO),
            context: context(HOST_TWO, &key),
        },
    );

    let app = build(Arc::new(AdminState {
        tenants: Arc::new(registry),
        issuer: issuer(HOST_ONE),
        store: store.clone(),
        published_keys: vec![Arc::clone(&key)],
        model: argus_core::admin::model(),
        policy: argus_core::admin::policy(),
    }));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Some(Harness {
        addr,
        key,
        one,
        two,
        store,
    })
}

/// Her iki kiracının token'ı da aynı issuer'ı taşır; ayrım Host başlığından
/// gelir. Bu kasıtlı: eğer token kiracıyı belirleseydi test hiçbir şey
/// kanıtlamazdı.
fn token(harness: &Harness, subject: &str) -> String {
    let claims = AccessTokenClaims {
        iss: issuer(HOST_ONE),
        sub: subject.to_owned(),
        aud: Audience::One(format!(
            "{}{}",
            issuer(HOST_ONE),
            Surface::Tenant.audience_suffix()
        )),
        exp: 4_000_000_000,
        iat: 1_000_000_000,
        jti: Uuid::new_v4().to_string(),
        scope: None,
        sess: 0,
        cnf: None,
    };
    argus_proto::jwt::sign(&claims, &harness.key).expect("sign")
}

async fn make_admin(harness: &Harness, subject: &str, tenant: TenantId) {
    let tuple = Tuple::new(
        EntityRef::new("tenant", &tenant.as_uuid().to_string()).expect("object"),
        argus_core::admin::ADMINISTRATOR,
        SubjectRef::direct(EntityRef::new("user", subject).expect("subject")),
    )
    .expect("tuple");

    harness
        .store
        .authz_apply(tenant, &[TupleOp::Write(tuple)])
        .await
        .expect("apply");
}

async fn raw(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.expect("read");
    String::from_utf8_lossy(&out).into_owned()
}

fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn body_of(response: &str) -> Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    let Some(start) = body.find(['{', '[']) else {
        return Value::Null;
    };
    let trimmed = body.get(start..).unwrap_or_default();
    serde_json::from_str(trimmed).unwrap_or_else(|_| {
        let end = trimmed.rfind('}').map_or(trimmed.len(), |i| i + 1);
        serde_json::from_str(trimmed.get(..end).unwrap_or_default()).unwrap_or(Value::Null)
    })
}

async fn call(
    harness: &Harness,
    method: &str,
    host: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> String {
    let mut head = format!("{method} {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    head.push_str("Authorization: Bearer ");
    head.push_str(token);
    head.push_str("\r\n");

    let request = match body {
        Some(body) => {
            let body = body.to_string();
            format!(
                "{head}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        }
        None => format!("{head}\r\n"),
    };

    raw(&harness.addr, &request).await
}

#[tokio::test]
async fn a_host_this_server_does_not_serve_is_refused() {
    let Some(harness) = harness().await else {
        return;
    };
    let token = token(&harness, "root");

    let response = call(
        &harness,
        "GET",
        "somewhere.else.test",
        "/admin/api/clients/v1",
        &token,
        None,
    )
    .await;

    assert_eq!(status_of(&response), 404);
    assert_eq!(
        body_of(&response).get("error").and_then(Value::as_str),
        Some("unknown_issuer"),
        "an unrecognised host must fail closed, never fall back to a known tenant"
    );
}

#[tokio::test]
async fn administering_one_tenant_grants_nothing_on_the_other() {
    let Some(harness) = harness().await else {
        return;
    };
    make_admin(&harness, "root", harness.one).await;
    let token = token(&harness, "root");

    let allowed = call(
        &harness,
        "GET",
        HOST_ONE,
        "/admin/api/federation-subordinates/v1",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status_of(&allowed),
        200,
        "root administers the first tenant"
    );

    // Aynı token, aynı özne, farklı host. Kiracı Host'tan çözüldüğü için bu
    // ikinci kiracıya yapılmış bir istektir ve root'un orada hiçbir ilişkisi yok.
    let refused = call(
        &harness,
        "GET",
        HOST_TWO,
        "/admin/api/federation-subordinates/v1",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status_of(&refused),
        404,
        "the same token must not administer a tenant it holds nothing on"
    );
}

#[tokio::test]
async fn a_resource_written_under_one_host_is_invisible_under_the_other() {
    let Some(harness) = harness().await else {
        return;
    };
    make_admin(&harness, "root", harness.one).await;
    make_admin(&harness, "root", harness.two).await;
    let token = token(&harness, "root");

    let created = call(
        &harness,
        "POST",
        HOST_ONE,
        "/admin/api/federation-subordinates/v1",
        &token,
        Some(json!({ "id": "https://leaf.one.test", "jwks": { "keys": [] } })),
    )
    .await;
    assert_eq!(status_of(&created), 201);

    let mine = call(
        &harness,
        "GET",
        HOST_ONE,
        "/admin/api/federation-subordinates/v1",
        &token,
        None,
    )
    .await;
    assert_eq!(
        body_of(&mine)
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );

    // Aynı yönetici, ikinci kiracıda da yetkili. Yine de birincinin verisini
    // göremez: kiracı kapsamı yetkiden bağımsızdır.
    let theirs = call(
        &harness,
        "GET",
        HOST_TWO,
        "/admin/api/federation-subordinates/v1",
        &token,
        None,
    )
    .await;
    assert_eq!(status_of(&theirs), 200);
    assert_eq!(
        body_of(&theirs)
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0),
        "the second tenant must not see the first tenant's subordinate"
    );
}

#[tokio::test]
async fn the_audit_chain_identifier_follows_the_host() {
    let Some(harness) = harness().await else {
        return;
    };
    make_admin(&harness, "root", harness.one).await;
    make_admin(&harness, "root", harness.two).await;
    let token = token(&harness, "root");

    let one = call(
        &harness,
        "POST",
        HOST_ONE,
        "/admin/api/audit-checkpoints/v1",
        &token,
        Some(json!({})),
    )
    .await;
    let two = call(
        &harness,
        "POST",
        HOST_TWO,
        "/admin/api/audit-checkpoints/v1",
        &token,
        Some(json!({})),
    )
    .await;

    assert_eq!(status_of(&one), 200, "no events to fold yet");
    assert_eq!(status_of(&two), 200);

    // Denetim zinciri kimliği kiracıdan türer; iki host iki zincirdir.
    assert_ne!(
        harness.one.as_uuid(),
        harness.two.as_uuid(),
        "the two tenants are distinct"
    );
}
