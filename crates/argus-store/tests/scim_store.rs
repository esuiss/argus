#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::id::TenantId;
use argus_core::time::Timestamp;
use argus_store::PostgresStore;
use argus_store::traits::{ScimConflict, ScimStore, ScimStoreError};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const NOW: Timestamp = Timestamp::from_unix_seconds(1_700_000_000);
const LATER: Timestamp = Timestamp::from_unix_seconds(1_700_000_600);

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

async fn scoped_pool(tenant: TenantId) -> sqlx::PgPool {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let tenant = tenant.as_uuid().to_string();
            Box::pin(async move {
                sqlx::query("SELECT set_config('argus.tenant_id', $1, false)")
                    .bind(tenant)
                    .execute(conn)
                    .await
                    .map(|_| ())
            })
        })
        .connect(&url)
        .await
        .expect("pool")
}

fn user(name: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": name,
        "active": true
    })
}

fn group(name: &str, members: &[&str]) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": name,
        "members": members.iter().map(|id| json!({ "value": id })).collect::<Vec<_>>()
    })
}

#[tokio::test]
async fn a_created_user_is_read_back_with_the_identifier_the_server_assigned() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let created = s
        .create_user(t, &user("bjensen"), NOW)
        .await
        .expect("create");

    assert!(!created.id.is_empty());
    assert_eq!(created.payload["userName"], "bjensen");

    let read = s.get_user(t, &created.id).await.expect("read back");
    assert_eq!(read.id, created.id);
    assert_eq!(read.seq, created.seq);
}

#[tokio::test]
async fn a_provisioned_user_becomes_a_real_platform_user() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let created = s
        .create_user(t, &user("linked"), NOW)
        .await
        .expect("create");

    let pool = scoped_pool(t).await;

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE tenant_id = $1 AND user_id = $2)",
    )
    .bind(t.as_uuid())
    .bind(Uuid::parse_str(&created.id).expect("uuid"))
    .fetch_one(&pool)
    .await
    .expect("query");

    assert!(
        exists,
        "SCIM provisioning must create the identity that authentication will later use, not a parallel directory"
    );
}

#[tokio::test]
async fn a_second_user_with_the_same_user_name_is_a_uniqueness_conflict() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    s.create_user(t, &user("taken"), NOW).await.expect("first");

    assert_eq!(
        s.create_user(t, &user("taken"), NOW).await.unwrap_err(),
        ScimStoreError::Conflict(ScimConflict::UserNameTaken)
    );
}

#[tokio::test]
async fn user_names_collide_without_regard_to_case() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    s.create_user(t, &user("BJensen"), NOW)
        .await
        .expect("first");

    assert_eq!(
        s.create_user(t, &user("bjensen"), NOW).await.unwrap_err(),
        ScimStoreError::Conflict(ScimConflict::UserNameTaken),
        "userName is declared caseExact false with server uniqueness"
    );
}

#[tokio::test]
async fn the_same_user_name_is_free_in_another_tenant() {
    let Some(s) = store().await else {
        return;
    };
    let first = fresh_tenant();
    let second = fresh_tenant();
    seed_tenant(first).await;
    seed_tenant(second).await;

    s.create_user(first, &user("shared"), NOW)
        .await
        .expect("first tenant");
    s.create_user(second, &user("shared"), NOW)
        .await
        .expect("uniqueness is scoped to the tenant, not the installation");
}

#[tokio::test]
async fn a_user_from_another_tenant_is_invisible() {
    let Some(s) = store().await else {
        return;
    };
    let first = fresh_tenant();
    let second = fresh_tenant();
    seed_tenant(first).await;
    seed_tenant(second).await;

    let created = s
        .create_user(first, &user("hidden"), NOW)
        .await
        .expect("create");

    assert_eq!(
        s.get_user(second, &created.id).await.unwrap_err(),
        ScimStoreError::NotFound
    );
    assert!(
        s.scan_users(second, None, 100)
            .await
            .expect("scan")
            .is_empty(),
        "every SCIM query carries the tenant as a predicate"
    );
}

#[tokio::test]
async fn row_level_security_hides_other_tenants_even_without_a_tenant_predicate() {
    let Some(s) = store().await else {
        return;
    };
    let first = fresh_tenant();
    let second = fresh_tenant();
    seed_tenant(first).await;
    seed_tenant(second).await;

    s.create_user(first, &user("mine"), NOW)
        .await
        .expect("mine");
    s.create_user(second, &user("theirs"), NOW)
        .await
        .expect("theirs");

    let pool = scoped_pool(first).await;

    let visible: Vec<String> = sqlx::query_scalar("SELECT user_name FROM scim_users")
        .fetch_all(&pool)
        .await
        .expect("an unfiltered read is exactly what the policy has to answer");

    assert_eq!(
        visible,
        ["mine"],
        "a query that forgets the tenant predicate must still be confined by the policy"
    );

    let groups: i64 = sqlx::query_scalar("SELECT count(*) FROM scim_groups")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(groups, 0);

    let members: i64 = sqlx::query_scalar("SELECT count(*) FROM scim_group_members")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(members, 0);
}

#[tokio::test]
async fn a_replace_updates_the_payload_and_moves_the_modification_time() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let created = s
        .create_user(t, &user("before"), NOW)
        .await
        .expect("create");

    let replaced = s
        .replace_user(
            t,
            &created.id,
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "after",
                "active": false
            }),
            LATER,
        )
        .await
        .expect("replace");

    assert_eq!(replaced.payload["userName"], "after");
    assert_eq!(replaced.payload["active"], false);
    assert_eq!(replaced.created_at, created.created_at);
    assert!(replaced.last_modified > created.last_modified);
}

#[tokio::test]
async fn a_replace_does_not_move_the_resource_in_the_pagination_order() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let first = s.create_user(t, &user("one"), NOW).await.expect("one");
    let second = s.create_user(t, &user("two"), NOW).await.expect("two");

    let touched = s
        .replace_user(t, &first.id, &user("one-renamed"), LATER)
        .await
        .expect("replace");

    assert_eq!(
        touched.seq, first.seq,
        "a cursor is a position in creation order; letting an update move a row would skip records mid-page"
    );
    assert!(touched.seq < second.seq);
}

#[tokio::test]
async fn deleting_a_user_removes_the_platform_identity_too() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let created = s.create_user(t, &user("gone"), NOW).await.expect("create");
    s.delete_user(t, &created.id).await.expect("delete");

    assert_eq!(
        s.get_user(t, &created.id).await.unwrap_err(),
        ScimStoreError::NotFound
    );

    let pool = scoped_pool(t).await;

    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1 AND user_id = $2")
            .bind(t.as_uuid())
            .bind(Uuid::parse_str(&created.id).expect("uuid"))
            .fetch_one(&pool)
            .await
            .expect("query");

    assert_eq!(remaining, 0, "deprovisioning must not leave a usable login");
}

#[tokio::test]
async fn deleting_a_user_that_does_not_exist_is_reported_as_not_found() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    assert_eq!(
        s.delete_user(t, &Uuid::new_v4().to_string())
            .await
            .unwrap_err(),
        ScimStoreError::NotFound
    );
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_not_found_rather_than_an_error() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    assert_eq!(
        s.get_user(t, "'; DROP TABLE scim_users; --")
            .await
            .unwrap_err(),
        ScimStoreError::NotFound
    );
}

#[tokio::test]
async fn the_scan_returns_resources_in_creation_order_and_pages_by_cursor() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let mut created = Vec::new();
    for index in 0..5 {
        created.push(
            s.create_user(t, &user(&format!("user{index}")), NOW)
                .await
                .expect("create"),
        );
    }

    let first = s.scan_users(t, None, 2).await.expect("page one");
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].id, created[0].id);
    assert_eq!(first[1].id, created[1].id);

    let second = s
        .scan_users(t, Some(first[1].seq), 2)
        .await
        .expect("page two");
    assert_eq!(second[0].id, created[2].id);
    assert_eq!(second[1].id, created[3].id);

    let third = s
        .scan_users(t, Some(second[1].seq), 2)
        .await
        .expect("page three");
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].id, created[4].id);
}

#[tokio::test]
async fn a_group_carries_the_members_it_was_created_with() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let alice = s.create_user(t, &user("alice"), NOW).await.expect("alice");
    let bob = s.create_user(t, &user("bob"), NOW).await.expect("bob");

    let created = s
        .create_group(t, &group("Tour Guides", &[&alice.id, &bob.id]), NOW)
        .await
        .expect("create group");

    let members = created.payload["members"].as_array().expect("members");
    assert_eq!(members.len(), 2);

    let values: Vec<&str> = members.iter().filter_map(|m| m["value"].as_str()).collect();
    assert!(values.contains(&alice.id.as_str()));
    assert!(values.contains(&bob.id.as_str()));

    assert!(
        members.iter().any(|m| m["display"] == "alice"),
        "membership is resolved against the real user, so the display name cannot go stale"
    );
}

#[tokio::test]
async fn a_member_that_does_not_exist_is_refused() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let stranger = Uuid::new_v4().to_string();
    let error = s
        .create_group(t, &group("Ghosts", &[&stranger]), NOW)
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            ScimStoreError::Conflict(ScimConflict::UnknownMember(_))
        ),
        "got {error:?}"
    );
}

#[tokio::test]
async fn a_member_belonging_to_another_tenant_cannot_be_added() {
    let Some(s) = store().await else {
        return;
    };
    let first = fresh_tenant();
    let second = fresh_tenant();
    seed_tenant(first).await;
    seed_tenant(second).await;

    let outsider = s
        .create_user(second, &user("outsider"), NOW)
        .await
        .expect("create");

    let error = s
        .create_group(first, &group("Locals", &[&outsider.id]), NOW)
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            ScimStoreError::Conflict(ScimConflict::UnknownMember(_))
        ),
        "a cross-tenant membership would leak an identity across the isolation boundary; got {error:?}"
    );
}

#[tokio::test]
async fn deleting_a_user_withdraws_that_user_from_every_group() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let alice = s.create_user(t, &user("alice"), NOW).await.expect("alice");
    let bob = s.create_user(t, &user("bob"), NOW).await.expect("bob");

    let created = s
        .create_group(t, &group("Everyone", &[&alice.id, &bob.id]), NOW)
        .await
        .expect("group");

    s.delete_user(t, &alice.id).await.expect("delete alice");

    let read = s.get_group(t, &created.id).await.expect("read group");
    let members = read.payload["members"].as_array().expect("members");

    assert_eq!(
        members.len(),
        1,
        "a deprovisioned user must not remain a member of any group"
    );
    assert_eq!(members[0]["value"], bob.id);
}

#[tokio::test]
async fn replacing_a_group_replaces_its_membership_wholesale() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let alice = s.create_user(t, &user("alice"), NOW).await.expect("alice");
    let bob = s.create_user(t, &user("bob"), NOW).await.expect("bob");

    let created = s
        .create_group(t, &group("Rotating", &[&alice.id]), NOW)
        .await
        .expect("group");

    let replaced = s
        .replace_group(t, &created.id, &group("Rotating", &[&bob.id]), LATER)
        .await
        .expect("replace");

    let members = replaced.payload["members"].as_array().expect("members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["value"], bob.id);
}

#[tokio::test]
async fn a_group_cannot_contain_itself() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let created = s
        .create_group(t, &group("Loop", &[]), NOW)
        .await
        .expect("group");

    let error = s
        .replace_group(t, &created.id, &group("Loop", &[&created.id]), LATER)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ScimStoreError::Conflict(ScimConflict::UnknownMember(_))
    ));
}

#[tokio::test]
async fn a_group_may_contain_another_group() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let inner = s
        .create_group(t, &group("Inner", &[]), NOW)
        .await
        .expect("inner");
    let outer = s
        .create_group(t, &group("Outer", &[&inner.id]), NOW)
        .await
        .expect("outer");

    let members = outer.payload["members"].as_array().expect("members");
    assert_eq!(members[0]["type"], "Group");
    assert_eq!(members[0]["display"], "Inner");
}

#[tokio::test]
async fn deleting_a_group_leaves_its_members_alone() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let alice = s.create_user(t, &user("alice"), NOW).await.expect("alice");
    let created = s
        .create_group(t, &group("Temporary", &[&alice.id]), NOW)
        .await
        .expect("group");

    s.delete_group(t, &created.id).await.expect("delete");

    s.get_user(t, &alice.id)
        .await
        .expect("removing a group must not deprovision the people in it");
}

#[tokio::test]
async fn an_external_id_collides_within_a_tenant() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "first",
        "externalId": "hr-1"
    });
    s.create_user(t, &body, NOW).await.expect("first");

    let clashing = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "second",
        "externalId": "hr-1"
    });

    assert_eq!(
        s.create_user(t, &clashing, NOW).await.unwrap_err(),
        ScimStoreError::Conflict(ScimConflict::ExternalIdTaken)
    );
}

#[tokio::test]
async fn several_users_may_leave_the_external_id_unset() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed_tenant(t).await;

    s.create_user(t, &user("one"), NOW).await.expect("one");
    s.create_user(t, &user("two"), NOW)
        .await
        .expect("a partial unique index must not treat two absent external ids as a collision");
}
