#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use argus_core::id::TenantId;
use argus_core::time::{Duration, Timestamp};
use argus_crypto::SigningKey;
use argus_http::scim::{EventPublisher, EventSink, ScimState};
use argus_proto::jwt::AccessTokenClaims;
use argus_store::PostgresStore;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const ISSUER: &str = "https://argus.test";

fn now() -> Timestamp {
    Timestamp::from_unix_seconds(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0)),
    )
}

fn token(key: &SigningKey, scope: &str, audience: &str) -> String {
    let claims = AccessTokenClaims {
        iss: ISSUER.to_owned(),
        sub: "provisioner".to_owned(),
        aud: argus_proto::Audience::One(audience.to_owned()),
        exp: now()
            .saturating_add(Duration::from_seconds(300))
            .as_unix_seconds(),
        iat: now().as_unix_seconds(),
        jti: Uuid::new_v4().to_string(),
        scope: Some(scope.to_owned()),
        sess: 0,
        cnf: None,
    };
    argus_proto::jwt::sign(&claims, key).expect("sign")
}

#[derive(Default)]
struct CapturedEvents(std::sync::Mutex<Vec<String>>);

impl EventSink for CapturedEvents {
    fn publish(&self, token: &str) {
        self.0.lock().expect("lock").push(token.to_owned());
    }
}

struct Harness {
    addr: String,
    authorization: String,
    tenant: TenantId,
    key: Arc<SigningKey>,
    events: Arc<CapturedEvents>,
}

fn event_claims(token: &str) -> Value {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let payload = token.split('.').nth(1).expect("payload");
    let bytes = Base64UrlUnpadded::decode_vec(payload).expect("base64");
    serde_json::from_slice(&bytes).expect("json")
}

fn event_header(token: &str) -> Value {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let header = token.split('.').next().expect("header");
    let bytes = Base64UrlUnpadded::decode_vec(header).expect("base64");
    serde_json::from_slice(&bytes).expect("json")
}

impl Harness {
    fn published(&self) -> Vec<Value> {
        self.events
            .0
            .lock()
            .expect("lock")
            .iter()
            .map(|token| event_claims(token))
            .collect()
    }

    fn raw_events(&self) -> Vec<String> {
        self.events.0.lock().expect("lock").clone()
    }
}

async fn harness() -> Option<Harness> {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .ok()?;

    let tenant = TenantId::from_uuid(Uuid::new_v4());
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

    let (key, _) = SigningKey::generate("scim").expect("key");
    let key = Arc::new(key);

    let events = Arc::new(CapturedEvents::default());

    let state = Arc::new(ScimState {
        store: PostgresStore::new(pool),
        tenants: std::sync::Arc::new(argus_http::tenancy::TenantRegistry::single(
            "as.test",
            argus_http::tenancy::TenantEntry {
                id: tenant,
                theme: argus_core::theme::Theme::default(),
                client_themes: std::collections::BTreeMap::new(),
                issuer: ISSUER.to_owned(),
                context: test_context(),
            },
        )),
        issuer: ISSUER.to_owned(),
        base: ISSUER.to_owned(),
        published_keys: vec![Arc::clone(&key)],
        events: Some(EventPublisher {
            key: Arc::clone(&key),
            audience: "https://receiver.test".to_owned(),
            sink: Arc::clone(&events) as Arc<dyn EventSink>,
        }),
    });

    let authorization = format!("Authorization: Bearer {}\r\n", token(&key, "scim", ISSUER));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let app = argus_http::scim::routes::build(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Some(Harness {
        addr,
        authorization,
        tenant,
        key,
        events,
    })
}

async fn raw(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.expect("read");
    String::from_utf8_lossy(&out).into_owned()
}

fn status(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn json_body(response: &str) -> Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    let start = body.find(['{', '[']).unwrap_or(0);
    let trimmed = &body[start..];
    serde_json::from_str(trimmed).unwrap_or_else(|_| {
        let end = trimmed.rfind('}').map_or(trimmed.len(), |i| i + 1);
        serde_json::from_str(&trimmed[..end]).unwrap_or(Value::Null)
    })
}

impl Harness {
    async fn get(&self, path: &str) -> String {
        raw(
            &self.addr,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n{}\r\n",
                self.authorization
            ),
        )
        .await
    }

    async fn get_unauthenticated(&self, path: &str) -> String {
        raw(
            &self.addr,
            &format!("GET {path} HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n\r\n"),
        )
        .await
    }

    async fn send(&self, method: &str, path: &str, body: &Value) -> String {
        let body = serde_json::to_string(body).expect("json");
        raw(
            &self.addr,
            &format!(
                "{method} {path} HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n\
                 Content-Type: application/scim+json\r\nContent-Length: {}\r\n{}\r\n{body}",
                body.len(),
                self.authorization
            ),
        )
        .await
    }

    async fn delete(&self, path: &str) -> String {
        raw(
            &self.addr,
            &format!(
                "DELETE {path} HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n{}\r\n",
                self.authorization
            ),
        )
        .await
    }

    async fn create_user(&self, name: &str) -> Value {
        let response = self
            .send(
                "POST",
                "/scim/v2/Users",
                &json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": name
                }),
            )
            .await;
        assert_eq!(status(&response), 201, "{response}");
        json_body(&response)
    }
}

#[tokio::test]
async fn the_discovery_documents_are_served_without_a_token() {
    let Some(h) = harness().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };

    for path in [
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/ResourceTypes",
        "/scim/v2/Schemas",
    ] {
        let response = h.get_unauthenticated(path).await;
        assert_eq!(
            status(&response),
            200,
            "a client discovers what the server supports before it has a token: {path}"
        );
    }
}

#[tokio::test]
async fn the_service_provider_config_reports_what_this_server_actually_does() {
    let Some(h) = harness().await else {
        return;
    };
    let body = json_body(&h.get("/scim/v2/ServiceProviderConfig").await);
    assert_eq!(body["patch"]["supported"], true);
    assert_eq!(body["filter"]["supported"], true);
    assert_eq!(body["bulk"]["supported"], false);
    assert_eq!(body["etag"]["supported"], false);
    assert_eq!(body["authenticationSchemes"][0]["type"], "oauthbearertoken");
}

#[tokio::test]
async fn a_named_schema_is_retrievable_by_its_urn() {
    let Some(h) = harness().await else {
        return;
    };
    let response = h
        .get("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User")
        .await;
    assert_eq!(status(&response), 200);
    assert_eq!(
        json_body(&response)["id"],
        "urn:ietf:params:scim:schemas:core:2.0:User"
    );
}

#[tokio::test]
async fn a_request_without_a_token_is_refused_with_a_challenge() {
    let Some(h) = harness().await else {
        return;
    };
    let response = h.get_unauthenticated("/scim/v2/Users").await;
    assert_eq!(status(&response), 401);
    assert!(
        response.to_lowercase().contains("www-authenticate: bearer"),
        "{response}"
    );
}

#[tokio::test]
async fn a_token_without_the_scim_scope_is_refused_as_forbidden() {
    let Some(h) = harness().await else {
        return;
    };
    let weak = token(&h.key, "openid profile", ISSUER);
    let response = raw(
        &h.addr,
        &format!(
            "GET /scim/v2/Users HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n\
             Authorization: Bearer {weak}\r\n\r\n"
        ),
    )
    .await;

    assert_eq!(
        status(&response),
        403,
        "a valid token for another purpose must not provision users: {response}"
    );
    assert!(response.contains("insufficient_scope"));
}

#[tokio::test]
async fn a_token_minted_for_another_audience_is_refused() {
    let Some(h) = harness().await else {
        return;
    };
    let foreign = token(&h.key, "scim", "https://someone-else.test");
    let response = raw(
        &h.addr,
        &format!(
            "GET /scim/v2/Users HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n\
             Authorization: Bearer {foreign}\r\n\r\n"
        ),
    )
    .await;

    assert_eq!(status(&response), 401, "{response}");
}

#[tokio::test]
async fn a_token_signed_by_a_key_this_server_does_not_publish_is_refused() {
    let Some(h) = harness().await else {
        return;
    };
    let (stranger, _) = SigningKey::generate("stranger").expect("key");
    let forged = token(&stranger, "scim", ISSUER);
    let response = raw(
        &h.addr,
        &format!(
            "GET /scim/v2/Users HTTP/1.1\r\nHost: argus.test\r\nConnection: close\r\n\
             Authorization: Bearer {forged}\r\n\r\n"
        ),
    )
    .await;

    assert_eq!(status(&response), 401, "{response}");
}

#[tokio::test]
async fn creating_a_user_answers_with_the_location_of_the_new_resource() {
    let Some(h) = harness().await else {
        return;
    };
    let response = h
        .send(
            "POST",
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "bjensen@example.com",
                "name": { "givenName": "Barbara", "familyName": "Jensen" }
            }),
        )
        .await;

    assert_eq!(status(&response), 201, "{response}");
    assert!(response.to_lowercase().contains("location:"), "{response}");
    assert!(
        response.contains("application/scim+json"),
        "SCIM clients dispatch on the media type: {response}"
    );

    let body = json_body(&response);
    assert!(!body["id"].as_str().unwrap_or_default().is_empty());
    assert_eq!(body["meta"]["resourceType"], "User");
    assert_eq!(
        body["meta"]["location"],
        format!("{ISSUER}/scim/v2/Users/{}", body["id"].as_str().unwrap())
    );
    assert_eq!(body["active"], true);
}

#[tokio::test]
async fn a_create_that_carries_an_identifier_is_refused_for_mutability() {
    let Some(h) = harness().await else {
        return;
    };
    let response = h
        .send(
            "POST",
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": "an-identifier-the-client-picked",
                "userName": "sneaky"
            }),
        )
        .await;

    assert_eq!(status(&response), 400, "{response}");
    assert_eq!(json_body(&response)["scimType"], "mutability");
}

#[tokio::test]
async fn a_duplicate_user_name_is_reported_as_a_uniqueness_conflict() {
    let Some(h) = harness().await else {
        return;
    };
    h.create_user("duplicate").await;

    let response = h
        .send(
            "POST",
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "duplicate"
            }),
        )
        .await;

    assert_eq!(status(&response), 409, "{response}");
    let body = json_body(&response);
    assert_eq!(body["scimType"], "uniqueness");
    assert_eq!(
        body["status"], "409",
        "RFC 7644 carries the status as a string inside the body as well"
    );
}

#[tokio::test]
async fn a_resource_that_does_not_exist_answers_with_a_scim_error_body() {
    let Some(h) = harness().await else {
        return;
    };
    let response = h.get(&format!("/scim/v2/Users/{}", Uuid::new_v4())).await;

    assert_eq!(status(&response), 404);
    let body = json_body(&response);
    assert_eq!(body["status"], "404");
    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
}

#[tokio::test]
async fn a_listing_is_filtered_by_the_scim_filter_grammar() {
    let Some(h) = harness().await else {
        return;
    };
    h.create_user("alpha@example.com").await;
    h.create_user("beta@example.com").await;

    let response = h
        .get("/scim/v2/Users?filter=userName%20eq%20%22alpha%40example.com%22")
        .await;

    assert_eq!(status(&response), 200, "{response}");
    let body = json_body(&response);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["userName"], "alpha@example.com");
}

#[tokio::test]
async fn a_filter_the_grammar_rejects_is_reported_as_an_invalid_filter() {
    let Some(h) = harness().await else {
        return;
    };
    let response = h.get("/scim/v2/Users?filter=userName%20eq").await;

    assert_eq!(status(&response), 400, "{response}");
    assert_eq!(json_body(&response)["scimType"], "invalidFilter");
}

#[tokio::test]
async fn index_pagination_reports_the_full_total_and_returns_one_page() {
    let Some(h) = harness().await else {
        return;
    };
    for index in 0..5 {
        h.create_user(&format!("page{index}")).await;
    }

    let body = json_body(&h.get("/scim/v2/Users?startIndex=2&count=2").await);
    assert_eq!(body["totalResults"], 5);
    assert_eq!(body["itemsPerPage"], 2);
    assert_eq!(body["startIndex"], 2);
    assert_eq!(body["Resources"].as_array().expect("array").len(), 2);
}

#[tokio::test]
async fn a_count_of_zero_returns_the_total_and_no_resources() {
    let Some(h) = harness().await else {
        return;
    };
    h.create_user("counted").await;

    let body = json_body(&h.get("/scim/v2/Users?count=0").await);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"].as_array().expect("array").len(), 0);
}

#[tokio::test]
async fn cursor_pagination_walks_every_resource_exactly_once() {
    let Some(h) = harness().await else {
        return;
    };
    let mut expected = Vec::new();
    for index in 0..5 {
        expected.push(
            h.create_user(&format!("walk{index}")).await["id"]
                .as_str()
                .expect("id")
                .to_owned(),
        );
    }

    let mut seen = Vec::new();
    let mut cursor = String::new();

    for _ in 0..10 {
        let path = format!("/scim/v2/Users?count=2&cursor={cursor}");
        let body = json_body(&h.get(&path).await);

        for resource in body["Resources"].as_array().expect("array") {
            seen.push(resource["id"].as_str().expect("id").to_owned());
        }

        match body["nextCursor"].as_str() {
            Some(next) => cursor = next.to_owned(),
            None => break,
        }
    }

    assert_eq!(
        seen, expected,
        "a cursor walk must visit every resource once, in order"
    );
}

#[tokio::test]
async fn sorting_orders_the_page_by_the_named_attribute() {
    let Some(h) = harness().await else {
        return;
    };
    for name in ["charlie", "alpha", "bravo"] {
        h.create_user(name).await;
    }

    let body = json_body(&h.get("/scim/v2/Users?sortBy=userName").await);
    let names: Vec<&str> = body["Resources"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|r| r["userName"].as_str())
        .collect();
    assert_eq!(names, ["alpha", "bravo", "charlie"]);

    let body = json_body(
        &h.get("/scim/v2/Users?sortBy=userName&sortOrder=descending")
            .await,
    );
    let names: Vec<&str> = body["Resources"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|r| r["userName"].as_str())
        .collect();
    assert_eq!(names, ["charlie", "bravo", "alpha"]);
}

#[tokio::test]
async fn a_projection_returns_only_what_was_asked_for() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("projected").await;
    let id = created["id"].as_str().expect("id");

    let body = json_body(
        &h.get(&format!("/scim/v2/Users/{id}?attributes=userName"))
            .await,
    );
    assert!(body.get("userName").is_some());
    assert!(body.get("id").is_some());
    assert!(
        body.get("active").is_none(),
        "an attribute that was not asked for must not be returned: {body}"
    );
}

#[tokio::test]
async fn a_search_by_post_accepts_the_same_query_in_the_body() {
    let Some(h) = harness().await else {
        return;
    };
    h.create_user("searchable").await;

    let response = h
        .send(
            "POST",
            "/scim/v2/Users/.search",
            &json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
                "filter": "userName eq \"searchable\"",
                "count": 10
            }),
        )
        .await;

    assert_eq!(status(&response), 200, "{response}");
    let body = json_body(&response);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["userName"], "searchable");
}

#[tokio::test]
async fn a_replace_overwrites_the_resource() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("original").await;
    let id = created["id"].as_str().expect("id");

    let response = h
        .send(
            "PUT",
            &format!("/scim/v2/Users/{id}"),
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "renamed",
                "active": false
            }),
        )
        .await;

    assert_eq!(status(&response), 200, "{response}");
    let body = json_body(&response);
    assert_eq!(body["userName"], "renamed");
    assert_eq!(body["active"], false);
    assert_eq!(body["id"], id);
}

#[tokio::test]
async fn a_patch_that_deactivates_a_user_is_the_deprovisioning_path_entra_uses() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("leaving").await;
    let id = created["id"].as_str().expect("id");

    let response = h
        .send(
            "PATCH",
            &format!("/scim/v2/Users/{id}"),
            &json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{ "op": "replace", "path": "active", "value": false }]
            }),
        )
        .await;

    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(json_body(&response)["active"], false);

    let read = json_body(&h.get(&format!("/scim/v2/Users/{id}")).await);
    assert_eq!(read["active"], false, "the change has to survive the write");
}

#[tokio::test]
async fn a_patch_body_that_does_not_declare_the_patch_schema_is_refused() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("strict").await;
    let id = created["id"].as_str().expect("id");

    let response = h
        .send(
            "PATCH",
            &format!("/scim/v2/Users/{id}"),
            &json!({ "Operations": [{ "op": "replace", "path": "active", "value": false }] }),
        )
        .await;

    assert_eq!(status(&response), 400, "{response}");
    assert_eq!(json_body(&response)["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn a_patch_whose_filter_matches_nothing_reports_no_target() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("untargeted").await;
    let id = created["id"].as_str().expect("id");

    let response = h
        .send(
            "PATCH",
            &format!("/scim/v2/Users/{id}"),
            &json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{
                    "op": "replace",
                    "path": "emails[type eq \"work\"].value",
                    "value": "nobody@example.com"
                }]
            }),
        )
        .await;

    assert_eq!(status(&response), 400, "{response}");
    assert_eq!(json_body(&response)["scimType"], "noTarget");
}

#[tokio::test]
async fn deleting_a_user_answers_with_no_content_and_the_resource_is_gone() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("temporary").await;
    let id = created["id"].as_str().expect("id");

    let response = h.delete(&format!("/scim/v2/Users/{id}")).await;
    assert_eq!(status(&response), 204, "{response}");

    assert_eq!(status(&h.get(&format!("/scim/v2/Users/{id}")).await), 404);
    assert_eq!(
        status(&h.delete(&format!("/scim/v2/Users/{id}")).await),
        404,
        "a second delete must not report success"
    );
}

#[tokio::test]
async fn a_group_is_created_with_members_and_read_back_with_them() {
    let Some(h) = harness().await else {
        return;
    };
    let alice = h.create_user("alice").await;
    let alice_id = alice["id"].as_str().expect("id");

    let response = h
        .send(
            "POST",
            "/scim/v2/Groups",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Tour Guides",
                "members": [{ "value": alice_id }]
            }),
        )
        .await;

    assert_eq!(status(&response), 201, "{response}");
    let body = json_body(&response);
    assert_eq!(body["displayName"], "Tour Guides");
    assert_eq!(body["members"][0]["value"], alice_id);
    assert_eq!(body["meta"]["resourceType"], "Group");
}

#[tokio::test]
async fn adding_a_member_by_patch_is_the_path_okta_uses() {
    let Some(h) = harness().await else {
        return;
    };
    let alice = h.create_user("member-alice").await;
    let alice_id = alice["id"].as_str().expect("id").to_owned();

    let group = json_body(
        &h.send(
            "POST",
            "/scim/v2/Groups",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Growing"
            }),
        )
        .await,
    );
    let group_id = group["id"].as_str().expect("id");

    let response = h
        .send(
            "PATCH",
            &format!("/scim/v2/Groups/{group_id}"),
            &json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{
                    "op": "add",
                    "path": "members",
                    "value": [{ "value": alice_id }]
                }]
            }),
        )
        .await;

    assert_eq!(status(&response), 200, "{response}");
    let body = json_body(&response);
    assert_eq!(body["members"][0]["value"], alice_id);
}

#[tokio::test]
async fn a_group_naming_a_member_that_does_not_exist_is_refused() {
    let Some(h) = harness().await else {
        return;
    };
    let response = h
        .send(
            "POST",
            "/scim/v2/Groups",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Phantoms",
                "members": [{ "value": Uuid::new_v4().to_string() }]
            }),
        )
        .await;

    assert_eq!(status(&response), 400, "{response}");
    assert_eq!(json_body(&response)["scimType"], "invalidValue");
}

#[tokio::test]
async fn a_group_listing_is_filtered_by_display_name() {
    let Some(h) = harness().await else {
        return;
    };
    for name in ["Engineering", "Marketing"] {
        h.send(
            "POST",
            "/scim/v2/Groups",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": name
            }),
        )
        .await;
    }

    let body = json_body(
        &h.get("/scim/v2/Groups?filter=displayName%20eq%20%22Engineering%22")
            .await,
    );
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["displayName"], "Engineering");
}

#[tokio::test]
async fn one_tenants_provisioning_never_appears_in_another() {
    let Some(first) = harness().await else {
        return;
    };
    let Some(second) = harness().await else {
        return;
    };

    first.create_user("only-in-the-first").await;

    let body = json_body(&second.get("/scim/v2/Users").await);
    assert_eq!(
        body["totalResults"], 0,
        "the second tenant must see nothing the first provisioned"
    );
    assert_ne!(first.tenant, second.tenant);
}

#[tokio::test]
async fn creating_a_user_publishes_a_signed_notice_event() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("announced").await;
    let id = created["id"].as_str().expect("id");

    let tokens = h.raw_events();
    assert_eq!(tokens.len(), 1, "one state change, one event");

    assert_eq!(
        event_header(&tokens[0])["typ"],
        "secevent+jwt",
        "a receiver distinguishes a SET from an access token by the header type"
    );

    let claims = event_claims(&tokens[0]);
    assert_eq!(claims["sub_id"]["format"], "scim");
    assert_eq!(claims["sub_id"]["uri"], format!("/Users/{id}"));
    assert!(claims.get("sub").is_none());
    assert!(claims["txn"].as_str().is_some());

    let detail = &claims["events"]["urn:ietf:params:scim:event:prov:create:notice"];
    let attributes: Vec<&str> = detail["attributes"]
        .as_array()
        .expect("attributes")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(attributes.contains(&"userName"));
    assert!(detail.get("data").is_none());
}

#[tokio::test]
async fn deactivating_a_user_publishes_a_deactivate_event_not_a_patch_event() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("suspended").await;
    let id = created["id"].as_str().expect("id");

    h.send(
        "PATCH",
        &format!("/scim/v2/Users/{id}"),
        &json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "path": "active", "value": false }]
        }),
    )
    .await;

    let events = h.published();
    let last = events.last().expect("an event");
    assert!(
        last["events"]
            .get("urn:ietf:params:scim:event:prov:deactivate")
            .is_some(),
        "a receiver acts on deactivation differently from an ordinary attribute change: {last}"
    );
}

#[tokio::test]
async fn deleting_a_user_publishes_a_delete_event_with_no_payload() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("removed").await;
    let id = created["id"].as_str().expect("id");

    h.delete(&format!("/scim/v2/Users/{id}")).await;

    let events = h.published();
    let last = events.last().expect("an event");
    let detail = &last["events"]["urn:ietf:params:scim:event:prov:delete"];
    assert_eq!(*detail, json!({}));
    assert_eq!(last["sub_id"]["uri"], format!("/Users/{id}"));
}

#[tokio::test]
async fn a_write_that_changes_nothing_publishes_nothing() {
    let Some(h) = harness().await else {
        return;
    };
    let created = h.create_user("unchanged").await;
    let id = created["id"].as_str().expect("id");
    let before = h.raw_events().len();

    h.send(
        "PUT",
        &format!("/scim/v2/Users/{id}"),
        &json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "unchanged",
            "active": true
        }),
    )
    .await;

    assert_eq!(
        h.raw_events().len(),
        before,
        "a receiver that refetches on every event must not be woken by a write that changed nothing"
    );
}

#[tokio::test]
async fn a_rejected_request_publishes_nothing() {
    let Some(h) = harness().await else {
        return;
    };
    h.create_user("first-holder").await;
    let before = h.raw_events().len();

    let response = h
        .send(
            "POST",
            "/scim/v2/Users",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "first-holder"
            }),
        )
        .await;
    assert_eq!(status(&response), 409);

    assert_eq!(
        h.raw_events().len(),
        before,
        "an event announces a change that happened, not one that was refused"
    );
}

#[tokio::test]
async fn the_config_advertises_exactly_the_events_the_server_emits() {
    let Some(h) = harness().await else {
        return;
    };
    let config = json_body(&h.get("/scim/v2/ServiceProviderConfig").await);
    let advertised: Vec<&str> = config["securityEvents"]["eventUris"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let created = h.create_user("advertised").await;
    let id = created["id"].as_str().expect("id");
    h.delete(&format!("/scim/v2/Users/{id}")).await;

    for event in h.published() {
        for uri in event["events"].as_object().expect("events").keys() {
            assert!(
                advertised.contains(&uri.as_str()),
                "{uri} was emitted but the configuration never announced it"
            );
        }
    }
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
