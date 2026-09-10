#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::authz::model::{EntityRef, SubjectRef, Tuple};
use argus_core::authz::{CheckRequest, TupleOp, check};
use argus_core::authz::{Model, Rewrite, TypeDef};
use argus_core::id::TenantId;
use argus_store::PostgresStore;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn fresh_tenant() -> TenantId {
    TenantId::from_uuid(Uuid::new_v4())
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

    tx.commit().await.expect("commit");
}

fn e(kind: &str, id: &str) -> EntityRef {
    EntityRef::new(kind, id).expect("entity")
}

fn membership(object: &str, member: &str) -> Tuple {
    Tuple::new(
        e("group", object),
        "member",
        SubjectRef::direct(e("user", member)),
    )
    .expect("tuple")
}

fn group_model() -> Model {
    Model::new()
        .with("user", TypeDef::new())
        .with("group", TypeDef::new().with("member", Rewrite::This))
}

#[tokio::test]
async fn a_written_tuple_is_readable_and_decides_a_check() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = fresh_tenant();
    seed(tenant).await;

    let revision = store
        .authz_apply(tenant, &[TupleOp::Write(membership("eng", "alice"))])
        .await
        .expect("apply");
    assert!(revision > 0);

    let index = store.authz_index(tenant).await.expect("index");
    let decision = check(
        &group_model(),
        &index,
        &CheckRequest {
            object: e("group", "eng"),
            relation: "member".to_owned(),
            subject: SubjectRef::direct(e("user", "alice")),
        },
    )
    .expect("check");

    assert!(decision.allowed);
    assert_eq!(decision.evaluated_at, u64::try_from(revision).unwrap());
}

#[tokio::test]
async fn a_decision_taken_at_an_older_revision_stays_reproducible() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = fresh_tenant();
    seed(tenant).await;

    let granted = store
        .authz_apply(tenant, &[TupleOp::Write(membership("eng", "alice"))])
        .await
        .expect("grant");

    let revoked = store
        .authz_apply(tenant, &[TupleOp::Delete(membership("eng", "alice"))])
        .await
        .expect("revoke");
    assert!(revoked > granted);

    let now = store.authz_index(tenant).await.expect("now");
    let then = store.authz_index_at(tenant, granted).await.expect("then");

    let request = CheckRequest {
        object: e("group", "eng"),
        relation: "member".to_owned(),
        subject: SubjectRef::direct(e("user", "alice")),
    };

    assert!(
        !check(&group_model(), &now, &request).expect("now").allowed,
        "the tuple was revoked"
    );
    assert!(
        check(&group_model(), &then, &request)
            .expect("then")
            .allowed,
        "a read at the revision that granted it must still see it"
    );
}

#[tokio::test]
async fn a_revoked_tuple_is_tombstoned_rather_than_deleted() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = fresh_tenant();
    seed(tenant).await;

    store
        .authz_apply(tenant, &[TupleOp::Write(membership("eng", "alice"))])
        .await
        .expect("grant");
    store
        .authz_apply(tenant, &[TupleOp::Delete(membership("eng", "alice"))])
        .await
        .expect("revoke");

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

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM authz_tuples WHERE tenant_id = $1")
        .bind(tenant.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .expect("count");

    assert_eq!(rows, 1, "the row must survive its revocation");
}

#[tokio::test]
async fn one_tenants_tuples_are_invisible_to_another() {
    let Some(store) = store().await else {
        return;
    };
    let mine = fresh_tenant();
    let theirs = fresh_tenant();
    seed(mine).await;
    seed(theirs).await;

    store
        .authz_apply(mine, &[TupleOp::Write(membership("eng", "alice"))])
        .await
        .expect("apply");

    let index = store.authz_index(theirs).await.expect("index");
    assert!(
        index.is_empty(),
        "a tenant must not see another tenant's relation graph"
    );
}

#[tokio::test]
async fn the_row_level_policy_and_not_the_query_is_what_hides_another_tenant() {
    let Some(store) = store().await else {
        return;
    };
    let mine = fresh_tenant();
    let theirs = fresh_tenant();
    seed(mine).await;
    seed(theirs).await;

    store
        .authz_apply(mine, &[TupleOp::Write(membership("eng", "alice"))])
        .await
        .expect("apply");

    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(theirs.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .expect("scope");

    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM authz_tuples")
        .fetch_one(&mut *tx)
        .await
        .expect("count");

    assert_eq!(
        visible, 0,
        "scoped to another tenant, an unfiltered read must return nothing"
    );
}

#[tokio::test]
async fn a_batch_larger_than_the_ceiling_is_refused_before_any_row_lands() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = fresh_tenant();
    seed(tenant).await;

    let ops: Vec<TupleOp> = (0..1001)
        .map(|i| TupleOp::Write(membership("eng", &format!("u{i}"))))
        .collect();

    assert!(store.authz_apply(tenant, &ops).await.is_err());
    assert_eq!(
        store.authz_revision(tenant).await.expect("revision"),
        0,
        "a refused batch must not consume a revision"
    );
}
