#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use argus_core::admin::manifest::{MANIFEST, Surface};
use argus_core::authz::TupleOp;
use argus_core::authz::model::{EntityRef, SubjectRef, Tuple};
use argus_core::id::TenantId;
use argus_crypto::SigningKey;
use argus_http::admin::{AdminState, PLATFORM_OBJECT, build, unimplemented};
use argus_proto::jwt::{AccessTokenClaims, Audience};
use argus_store::PostgresStore;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const ISSUER: &str = "https://as.test";

async fn store() -> Option<PostgresStore> {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;

    let store = PostgresStore::new(pool);

    let Some(control) = std::env::var("ARGUS_TEST_PLATFORM_DATABASE_URL").ok() else {
        return Some(store);
    };
    let control = PgPoolOptions::new()
        .max_connections(2)
        .connect(&control)
        .await
        .ok()?;

    Some(store.with_control_plane(control))
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
    tx.commit().await.expect("commit");
}

struct Harness {
    addr: String,
    key: Arc<SigningKey>,
    tenant: TenantId,
    store: PostgresStore,
}

async fn harness() -> Option<Harness> {
    let store = store().await?;
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant).await;

    let (key, _) = SigningKey::generate("k1".to_owned()).expect("key");
    let key = Arc::new(key);

    let app = build(Arc::new(AdminState {
        tenants: std::sync::Arc::new(argus_http::tenancy::TenantRegistry::single(
            "as.test",
            argus_http::tenancy::TenantEntry {
                id: tenant,
                issuer: ISSUER.to_owned(),
                context: test_context(),
            },
        )),
        issuer: ISSUER.to_owned(),
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
        tenant,
        store,
    })
}

fn token(harness: &Harness, subject: &str, surface: Surface) -> String {
    let claims = AccessTokenClaims {
        iss: ISSUER.to_owned(),
        sub: subject.to_owned(),
        aud: Audience::One(format!("{ISSUER}{}", surface.audience_suffix())),
        exp: 4_000_000_000,
        iat: 1_000_000_000,
        jti: Uuid::new_v4().to_string(),
        scope: None,
        sess: 0,
        cnf: None,
    };
    argus_proto::jwt::sign(&claims, &harness.key).expect("sign")
}

async fn make_admin(harness: &Harness, subject: &str, kind: &str, id: &str) {
    let tuple = Tuple::new(
        EntityRef::new(kind, id).expect("object"),
        argus_core::admin::ADMINISTRATOR,
        SubjectRef::direct(EntityRef::new("user", subject).expect("subject")),
    )
    .expect("tuple");

    harness
        .store
        .authz_apply(harness.tenant, &[TupleOp::Write(tuple)])
        .await
        .expect("apply");
}

fn named(harness: &Harness, name: &str) -> String {
    format!(
        "{name}-{}",
        harness
            .tenant
            .as_uuid()
            .simple()
            .to_string()
            .get(..8)
            .unwrap_or("x")
    )
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

fn header_of(response: &str, name: &str) -> Option<String> {
    response.split("\r\n\r\n").next()?.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

struct Call<'a> {
    method: &'a str,
    uri: &'a str,
    token: Option<&'a str>,
    body: Option<Value>,
    idempotency: Option<&'a str>,
}

async fn send(harness: &Harness, call: Call<'_>) -> String {
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: as.test\r\nConnection: close\r\n",
        call.method, call.uri
    );
    if let Some(token) = call.token {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    if let Some(key) = call.idempotency {
        head.push_str("Idempotency-Key: ");
        head.push_str(key);
        head.push_str("\r\n");
    }

    let request = match call.body {
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

async fn call(
    harness: &Harness,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> String {
    send(
        harness,
        Call {
            method,
            uri,
            token,
            body,
            idempotency: None,
        },
    )
    .await
}

#[test]
fn every_route_the_manifest_declares_has_a_handler() {
    assert_eq!(
        unimplemented(),
        Vec::<(&str, &str)>::new(),
        "these manifest entries have no handler"
    );
}

#[tokio::test]
async fn a_request_with_no_token_is_refused() {
    let Some(harness) = harness().await else {
        return;
    };
    let response = call(&harness, "GET", "/admin/api/clients/v1", None, None).await;
    assert_eq!(status_of(&response), 401);
}

#[tokio::test]
async fn a_caller_without_the_relation_is_told_the_resource_is_not_there() {
    let Some(harness) = harness().await else {
        return;
    };
    let token = token(&harness, "nobody", Surface::Tenant);
    let response = call(&harness, "GET", "/admin/api/clients/v1", Some(&token), None).await;

    assert_eq!(status_of(&response), 404);
    assert_eq!(
        body_of(&response).get("error").and_then(Value::as_str),
        Some("not_found"),
        "the body must not distinguish forbidden from absent"
    );
}

#[tokio::test]
async fn no_route_serves_a_caller_that_holds_nothing() {
    let Some(harness) = harness().await else {
        return;
    };

    for entry in MANIFEST {
        let token = token(&harness, "nobody", entry.surface);
        let uri = entry.path.replace("{id}", "some-id");
        let body = entry.mutating.then(|| json!({}));

        let response = call(&harness, entry.method, &uri, Some(&token), body).await;

        assert_eq!(
            status_of(&response),
            404,
            "{} {} served a caller holding no relation",
            entry.method,
            entry.path
        );
    }
}

#[tokio::test]
async fn a_tenant_token_cannot_reach_the_platform_surface() {
    let Some(harness) = harness().await else {
        return;
    };
    if !harness.store.serves_control_plane() {
        return;
    }
    make_admin(&harness, "root", "platform", PLATFORM_OBJECT).await;

    let wrong = token(&harness, "root", Surface::Tenant);
    let response = call(
        &harness,
        "GET",
        "/admin/platform/tenants/v1",
        Some(&wrong),
        None,
    )
    .await;
    assert_eq!(status_of(&response), 404);

    let right = token(&harness, "root", Surface::Platform);
    let response = call(
        &harness,
        "GET",
        "/admin/platform/tenants/v1",
        Some(&right),
        None,
    )
    .await;
    assert_eq!(status_of(&response), 200);
}

#[tokio::test]
async fn a_deployment_with_no_control_plane_connection_does_not_carry_its_routes() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = TenantId::from_uuid(Uuid::new_v4());
    seed(tenant).await;
    let (key, _) = SigningKey::generate("k1".to_owned()).expect("key");
    let key = Arc::new(key);

    let tenant_only = PostgresStore::new(
        PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("ARGUS_TEST_DATABASE_URL").expect("url"))
            .await
            .expect("pool"),
    );
    assert!(!tenant_only.serves_control_plane());

    let app = build(Arc::new(AdminState {
        tenants: std::sync::Arc::new(argus_http::tenancy::TenantRegistry::single(
            "as.test",
            argus_http::tenancy::TenantEntry {
                id: tenant,
                issuer: ISSUER.to_owned(),
                context: test_context(),
            },
        )),
        issuer: ISSUER.to_owned(),
        store: tenant_only,
        published_keys: vec![Arc::clone(&key)],
        model: argus_core::admin::model(),
        policy: argus_core::admin::policy(),
    }));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let harness = Harness {
        addr,
        key,
        tenant,
        store,
    };
    make_admin(&harness, "root", "platform", PLATFORM_OBJECT).await;
    let token = token(&harness, "root", Surface::Platform);

    let response = call(
        &harness,
        "GET",
        "/admin/platform/tenants/v1",
        Some(&token),
        None,
    )
    .await;

    assert_eq!(
        status_of(&response),
        404,
        "the control plane route must not exist in a tenant-serving process"
    );
}

#[tokio::test]
async fn an_administrator_can_enrol_a_federation_subordinate() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    let response = call(
        &harness,
        "POST",
        "/admin/api/federation-subordinates/v1",
        Some(&token),
        Some(json!({ "id": "https://leaf.test", "jwks": { "keys": [] } })),
    )
    .await;

    assert_eq!(status_of(&response), 201);
    let body = body_of(&response);
    assert_eq!(
        body.get("id").and_then(Value::as_str),
        Some("https://leaf.test")
    );
    assert!(body.get("jwks").is_some());

    let response = call(
        &harness,
        "GET",
        "/admin/api/federation-subordinates/v1",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status_of(&response), 200);
    assert_eq!(
        body_of(&response)
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
}

#[tokio::test]
async fn creating_a_client_returns_the_whole_resource_and_put_upserts_it() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    let response = call(
        &harness,
        "POST",
        "/admin/api/clients/v1",
        Some(&token),
        Some(json!({
            "clientId": named(&harness, "app-one"),
            "clientType": "public",
            "redirectUris": ["https://app.test/cb"]
        })),
    )
    .await;

    assert_eq!(status_of(&response), 201);
    assert_eq!(
        body_of(&response)
            .get("redirectUris")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "§24 #7: one request has to be enough to create the whole resource"
    );

    let response = call(
        &harness,
        "PUT",
        &format!("/admin/api/clients/v1/{}", named(&harness, "app-one")),
        Some(&token),
        Some(json!({ "clientType": "public", "redirectUris": [] })),
    )
    .await;
    assert_eq!(status_of(&response), 200);

    let response = call(
        &harness,
        "PUT",
        &format!("/admin/api/clients/v1/{}", named(&harness, "app-two")),
        Some(&token),
        Some(json!({ "clientType": "public" })),
    )
    .await;
    assert_eq!(status_of(&response), 201);
}

#[tokio::test]
async fn a_patch_cannot_move_the_client_id() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    call(
        &harness,
        "POST",
        "/admin/api/clients/v1",
        Some(&token),
        Some(json!({ "clientId": named(&harness, "fixed").as_str(), "clientType": "public" })),
    )
    .await;

    let response = call(
        &harness,
        "PATCH",
        &format!("/admin/api/clients/v1/{}", named(&harness, "fixed")),
        Some(&token),
        Some(json!({ "clientId": "moved" })),
    )
    .await;

    assert_eq!(status_of(&response), 400);
    assert_eq!(
        body_of(&response).get("error").and_then(Value::as_str),
        Some("invalid_request")
    );
}

#[tokio::test]
async fn a_filter_naming_an_unknown_field_is_refused_rather_than_ignored() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    let response = call(
        &harness,
        "GET",
        "/admin/api/clients/v1?q=secret%20eq%20%22x%22",
        Some(&token),
        None,
    )
    .await;

    assert_eq!(status_of(&response), 400);
    assert_eq!(
        body_of(&response).get("error").and_then(Value::as_str),
        Some("invalid_query")
    );
}

#[tokio::test]
async fn a_listing_names_its_next_page_in_a_link_header() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    for i in 0..5 {
        call(
            &harness,
            "POST",
            "/admin/api/clients/v1",
            Some(&token),
            Some(
                json!({ "clientId": named(&harness, &format!("c{i:02}")), "clientType": "public" }),
            ),
        )
        .await;
    }

    let response = call(
        &harness,
        "GET",
        "/admin/api/clients/v1?limit=2",
        Some(&token),
        None,
    )
    .await;

    assert_eq!(status_of(&response), 200);
    assert_eq!(
        body_of(&response)
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    let link = header_of(&response, "link").unwrap_or_default();
    assert!(link.contains("rel=\"next\""), "no next link: {link}");
}

#[tokio::test]
async fn the_same_idempotency_key_with_a_different_payload_is_refused() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    let post = async |body: Value| {
        send(
            &harness,
            Call {
                method: "POST",
                uri: "/admin/api/clients/v1",
                token: Some(&token),
                body: Some(body),
                idempotency: Some("same-key"),
            },
        )
        .await
    };

    let first =
        post(json!({ "clientId": named(&harness, "idem-one").as_str(), "clientType": "public" }))
            .await;
    assert_eq!(status_of(&first), 201, "{first}");

    let replay =
        post(json!({ "clientId": named(&harness, "idem-one").as_str(), "clientType": "public" }))
            .await;
    assert_eq!(
        status_of(&replay),
        201,
        "the same payload replays its stored result"
    );

    let different =
        post(json!({ "clientId": named(&harness, "idem-two").as_str(), "clientType": "public" }))
            .await;
    assert_eq!(
        status_of(&different),
        422,
        "§24 #33: key reuse with another payload is its own failure"
    );
}

#[tokio::test]
async fn a_bulk_job_is_accepted_and_reports_its_own_partial_failure() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    let response = call(
        &harness,
        "POST",
        "/admin/api/jobs/v1",
        Some(&token),
        Some(json!({
            "clients": [
                { "clientId": named(&harness, "bulk-one").as_str(), "clientType": "public" },
                { "clientType": "public" }
            ]
        })),
    )
    .await;

    assert_eq!(status_of(&response), 202);
    let body = body_of(&response);
    let id = body.get("id").and_then(Value::as_str).expect("job id");

    let response = call(
        &harness,
        "GET",
        &format!("/admin/api/jobs/v1/{id}"),
        Some(&token),
        None,
    )
    .await;

    assert_eq!(status_of(&response), 200);
    assert_eq!(
        body_of(&response)
            .get("metadata")
            .and_then(|m| m.get("state"))
            .and_then(Value::as_str),
        Some("partially_succeeded"),
        "one item carried no clientId"
    );
}

#[tokio::test]
async fn the_specification_is_generated_from_the_same_table_as_the_router() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    let response = call(&harness, "GET", "/admin/api/openapi/v1", Some(&token), None).await;
    assert_eq!(status_of(&response), 200);

    let document = body_of(&response);
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .expect("paths");

    for entry in MANIFEST {
        let operations = paths
            .get(entry.path)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{} is missing from the document", entry.path));
        assert!(
            operations.contains_key(&entry.method.to_lowercase()),
            "{} {} is missing from the document",
            entry.method,
            entry.path
        );
    }
}

#[tokio::test]
async fn an_audit_event_proves_itself_through_the_api() {
    let Some(harness) = harness().await else {
        return;
    };
    let subject = harness.tenant.as_uuid().to_string();
    make_admin(&harness, "root", "tenant", &subject).await;
    let token = token(&harness, "root", Surface::Tenant);

    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(harness.tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("scope");

    let event = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_events \
           (tenant_id, occurred_at, event_id, event_type, outcome, actor_kind) \
         VALUES ($1, now() - interval '60 seconds', $2, 'token.issued', 'success', 'client')",
    )
    .bind(harness.tenant.as_uuid())
    .bind(event)
    .execute(&mut *tx)
    .await
    .expect("event");
    tx.commit().await.expect("commit");

    let response = call(
        &harness,
        "GET",
        &format!("/admin/api/audit-proofs/v1/{event}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status_of(&response), 404);

    let response = call(
        &harness,
        "POST",
        "/admin/api/audit-checkpoints/v1",
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status_of(&response), 201);
    let published = body_of(&response);
    let root = published
        .get("root")
        .and_then(Value::as_str)
        .expect("a published root");

    let response = call(
        &harness,
        "GET",
        &format!("/admin/api/audit-proofs/v1/{event}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status_of(&response), 200);

    let proof = body_of(&response);
    assert_eq!(proof.get("root").and_then(Value::as_str), Some(root));
    assert!(proof.get("path").and_then(Value::as_array).is_some());
    assert!(
        proof
            .get("chain_uid")
            .and_then(Value::as_str)
            .is_some_and(|uid| uid.starts_with(argus_core::audit::CHAIN_UID_PREFIX)),
        "the OCSF chain identifier must name this log"
    );
}

fn test_context() -> argus_http::state::TenantContext {
    let (key, _) = argus_crypto::SigningKey::generate("t1".to_owned()).expect("key");
    let key = std::sync::Arc::new(key);
    argus_http::state::TenantContext {
        metadata: argus_proto::AuthorizationServerMetadata::for_issuer("https://as.test"),
        active_key: std::sync::Arc::clone(&key),
        published_keys: vec![key],
        rsa_keys: Vec::new(),
        blind_index: argus_crypto::blind_index::BlindIndexKey::new(&[7_u8; 32])
            .expect("blind index"),
        relying_party: None,
    }
}
