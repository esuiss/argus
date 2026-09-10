use argus_core::admin::idempotency::{Record, RecordState};
use argus_core::admin::job::{ItemResult, Job, JobState};
use argus_core::id::TenantId;
use serde_json::Value;
use sqlx::Row as _;

use crate::postgres::PostgresStore;
use crate::traits::StoreError;

fn state_of(raw: &str) -> Option<RecordState> {
    match raw {
        "in_flight" => Some(RecordState::InFlight),
        "succeeded" => Some(RecordState::Succeeded),
        "failed" => Some(RecordState::Failed),
        _ => None,
    }
}

pub struct StoredResponse {
    pub status: u16,
    pub body: Value,
}

impl PostgresStore {
    pub async fn idempotency_record(
        &self,
        tenant: TenantId,
        surface: &str,
        key: &str,
    ) -> Result<Option<(Record, Option<StoredResponse>)>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT fingerprint, state, status_code, body, \
                    extract(epoch FROM stored_at)::bigint AS stored_at \
               FROM admin_idempotency \
              WHERE tenant_id = $1 AND surface = $2 AND key = $3",
        )
        .bind(tenant.as_uuid())
        .bind(surface)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let raw: Vec<u8> = row
            .try_get("fingerprint")
            .map_err(|_| StoreError::Unavailable)?;
        let fingerprint: [u8; 32] = raw.try_into().map_err(|_| StoreError::Unavailable)?;

        let name: String = row.try_get("state").map_err(|_| StoreError::Unavailable)?;
        let state = state_of(&name).ok_or(StoreError::Unavailable)?;

        let stored_at: i64 = row
            .try_get("stored_at")
            .map_err(|_| StoreError::Unavailable)?;

        let response = match (
            row.try_get::<Option<i32>, _>("status_code").ok().flatten(),
            row.try_get::<Option<Value>, _>("body").ok().flatten(),
        ) {
            (Some(status), body) => u16::try_from(status).ok().map(|status| StoredResponse {
                status,
                body: body.unwrap_or(Value::Null),
            }),
            _ => None,
        };

        Ok(Some((
            Record {
                fingerprint,
                state,
                stored_at: u64::try_from(stored_at).unwrap_or(0),
            },
            response,
        )))
    }

    pub async fn idempotency_begin(
        &self,
        tenant: TenantId,
        surface: &str,
        key: &str,
        fingerprint: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let inserted = sqlx::query(
            "INSERT INTO admin_idempotency (tenant_id, surface, key, fingerprint, state) \
             VALUES ($1, $2, $3, $4, 'in_flight') \
             ON CONFLICT (tenant_id, surface, key) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(surface)
        .bind(key)
        .bind(fingerprint.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(inserted.rows_affected() == 1)
    }

    pub async fn idempotency_finish(
        &self,
        tenant: TenantId,
        surface: &str,
        key: &str,
        succeeded: bool,
        status: u16,
        body: &Value,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "UPDATE admin_idempotency \
                SET state = $4, status_code = $5, body = $6 \
              WHERE tenant_id = $1 AND surface = $2 AND key = $3",
        )
        .bind(tenant.as_uuid())
        .bind(surface)
        .bind(key)
        .bind(if succeeded { "succeeded" } else { "failed" })
        .bind(i32::from(status))
        .bind(body)
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn create_job(
        &self,
        tenant: TenantId,
        kind: &str,
        total: usize,
    ) -> Result<String, StoreError> {
        let total = i32::try_from(total).map_err(|_| StoreError::Unavailable)?;
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "INSERT INTO admin_jobs (tenant_id, kind, total) VALUES ($1, $2, $3) \
             RETURNING job_id",
        )
        .bind(tenant.as_uuid())
        .bind(kind)
        .bind(total)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        let id: uuid::Uuid = row.try_get("job_id").map_err(|_| StoreError::Unavailable)?;
        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(id.to_string())
    }

    pub async fn save_job(&self, tenant: TenantId, job: &Job) -> Result<(), StoreError> {
        let id = uuid::Uuid::parse_str(&job.id).map_err(|_| StoreError::NotFound)?;
        let failures: Vec<Value> = job
            .failures
            .iter()
            .map(|f| {
                serde_json::json!({
                    "index": f.index,
                    "code": f.code,
                    "message": f.message,
                })
            })
            .collect();

        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "UPDATE admin_jobs \
                SET state = $3, completed = $4, failures = $5, \
                    finished_at = CASE WHEN $3 IN ('succeeded', 'partially_succeeded', 'failed') \
                                       THEN now() ELSE NULL END \
              WHERE tenant_id = $1 AND job_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .bind(job.state.as_str())
        .bind(i32::try_from(job.completed).unwrap_or(i32::MAX))
        .bind(Value::Array(failures))
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn load_job(&self, tenant: TenantId, id: &str) -> Result<Job, StoreError> {
        let id = uuid::Uuid::parse_str(id).map_err(|_| StoreError::NotFound)?;
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT job_id, state, total, completed, failures, \
                    extract(epoch FROM created_at)::bigint AS created_at \
               FROM admin_jobs WHERE tenant_id = $1 AND job_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        let row = row.ok_or(StoreError::NotFound)?;

        let state: String = row.try_get("state").map_err(|_| StoreError::Unavailable)?;
        let total: i32 = row.try_get("total").map_err(|_| StoreError::Unavailable)?;
        let completed: i32 = row
            .try_get("completed")
            .map_err(|_| StoreError::Unavailable)?;
        let failures: Value = row
            .try_get("failures")
            .map_err(|_| StoreError::Unavailable)?;
        let created_at: i64 = row
            .try_get("created_at")
            .map_err(|_| StoreError::Unavailable)?;

        let state = match state.as_str() {
            "pending" => JobState::Pending,
            "running" => JobState::Running,
            "succeeded" => JobState::Succeeded,
            "partially_succeeded" => JobState::PartiallySucceeded,
            "failed" => JobState::Failed,
            _ => return Err(StoreError::Unavailable),
        };

        let failures = failures
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some(ItemResult {
                            index: usize::try_from(item.get("index")?.as_u64()?).ok()?,
                            code: item.get("code")?.as_str()?.to_owned(),
                            message: item.get("message")?.as_str()?.to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Job {
            id: id.to_string(),
            state,
            total: usize::try_from(total).unwrap_or(0),
            completed: usize::try_from(completed).unwrap_or(0),
            failures,
            created_at: u64::try_from(created_at).unwrap_or(0),
        })
    }
}

pub struct AdminClient {
    pub client_id: String,
    pub client_type: String,
    pub auth_method: String,
    pub redirect_uris: Vec<String>,
}

impl core::fmt::Debug for AdminClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdminClient")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl PostgresStore {
    pub async fn list_clients(
        &self,
        tenant: TenantId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdminClient>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT client_id, client_type, auth_method \
               FROM clients \
              WHERE tenant_id = $1 AND ($2::text IS NULL OR client_id > $2) \
              ORDER BY client_id \
              LIMIT $3",
        )
        .bind(tenant.as_uuid())
        .bind(after)
        .bind(i64::try_from(limit).unwrap_or(50))
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let client_id: String = row
                .try_get("client_id")
                .map_err(|_| StoreError::Unavailable)?;
            let uris = sqlx::query(
                "SELECT redirect_uri FROM client_redirect_uris \
                  WHERE tenant_id = $1 AND client_id = $2 ORDER BY redirect_uri",
            )
            .bind(tenant.as_uuid())
            .bind(&client_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| StoreError::Unavailable)?;

            out.push(AdminClient {
                client_type: row
                    .try_get("client_type")
                    .map_err(|_| StoreError::Unavailable)?,
                auth_method: row
                    .try_get("auth_method")
                    .map_err(|_| StoreError::Unavailable)?,
                redirect_uris: uris
                    .iter()
                    .filter_map(|r| r.try_get::<String, _>("redirect_uri").ok())
                    .collect(),
                client_id,
            });
        }

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(out)
    }

    pub async fn describe_client(
        &self,
        tenant: TenantId,
        client_id: &str,
    ) -> Result<Option<AdminClient>, StoreError> {
        let found = self.list_clients_named(tenant, client_id).await?;
        Ok(found)
    }

    async fn list_clients_named(
        &self,
        tenant: TenantId,
        client_id: &str,
    ) -> Result<Option<AdminClient>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT client_id, client_type, auth_method FROM clients \
              WHERE tenant_id = $1 AND client_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        let Some(row) = row else {
            tx.commit().await.map_err(|_| StoreError::Unavailable)?;
            return Ok(None);
        };

        let uris = sqlx::query(
            "SELECT redirect_uri FROM client_redirect_uris \
              WHERE tenant_id = $1 AND client_id = $2 ORDER BY redirect_uri",
        )
        .bind(tenant.as_uuid())
        .bind(client_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        Ok(Some(AdminClient {
            client_id: row
                .try_get("client_id")
                .map_err(|_| StoreError::Unavailable)?,
            client_type: row
                .try_get("client_type")
                .map_err(|_| StoreError::Unavailable)?,
            auth_method: row
                .try_get("auth_method")
                .map_err(|_| StoreError::Unavailable)?,
            redirect_uris: uris
                .iter()
                .filter_map(|r| r.try_get::<String, _>("redirect_uri").ok())
                .collect(),
        }))
    }

    pub async fn upsert_client(
        &self,
        tenant: TenantId,
        client: &AdminClient,
    ) -> Result<bool, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let existed = sqlx::query("SELECT 1 FROM clients WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant.as_uuid())
            .bind(&client.client_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| StoreError::Unavailable)?
            .is_some();

        sqlx::query(
            "INSERT INTO clients (tenant_id, client_id, client_type, auth_method) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, client_id) DO UPDATE SET \
               client_type = EXCLUDED.client_type, \
               auth_method = EXCLUDED.auth_method, \
               updated_at = now()",
        )
        .bind(tenant.as_uuid())
        .bind(&client.client_id)
        .bind(&client.client_type)
        .bind(&client.auth_method)
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::NotFound)?;

        sqlx::query("DELETE FROM client_redirect_uris WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant.as_uuid())
            .bind(&client.client_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| StoreError::Unavailable)?;

        for uri in &client.redirect_uris {
            sqlx::query(
                "INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri) \
                 VALUES ($1, $2, $3)",
            )
            .bind(tenant.as_uuid())
            .bind(&client.client_id)
            .bind(uri)
            .execute(&mut *tx)
            .await
            .map_err(|_| StoreError::NotFound)?;
        }

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(!existed)
    }

    pub async fn delete_client(&self, tenant: TenantId, client_id: &str) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let affected = sqlx::query("DELETE FROM clients WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant.as_uuid())
            .bind(client_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| StoreError::Unavailable)?;

        if affected.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }
}

pub struct TenantRecord {
    pub tenant_id: String,
    pub slug: String,
    pub issuer_host: String,
}

impl core::fmt::Debug for TenantRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TenantRecord")
            .field("slug", &self.slug)
            .finish_non_exhaustive()
    }
}

impl PostgresStore {
    pub async fn list_tenants(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<TenantRecord>, StoreError> {
        let mut tx = self.platform().await?;

        let rows = sqlx::query(
            "SELECT tenant_id, slug, issuer_host FROM tenants \
              WHERE $1::text IS NULL OR slug > $1 \
              ORDER BY slug LIMIT $2",
        )
        .bind(after)
        .bind(i64::try_from(limit).unwrap_or(50))
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        rows.iter()
            .map(|row| {
                Ok(TenantRecord {
                    tenant_id: row
                        .try_get::<uuid::Uuid, _>("tenant_id")
                        .map_err(|_| StoreError::Unavailable)?
                        .to_string(),
                    slug: row.try_get("slug").map_err(|_| StoreError::Unavailable)?,
                    issuer_host: row
                        .try_get("issuer_host")
                        .map_err(|_| StoreError::Unavailable)?,
                })
            })
            .collect()
    }

    pub async fn find_tenant(&self, slug: &str) -> Result<Option<TenantRecord>, StoreError> {
        let found = self.list_tenants(None, 1000).await?;
        Ok(found.into_iter().find(|record| record.slug == slug))
    }

    pub async fn create_tenant(
        &self,
        slug: &str,
        issuer_host: &str,
    ) -> Result<TenantRecord, StoreError> {
        let mut tx = self.platform().await?;

        let row = sqlx::query(
            "INSERT INTO tenants (slug, issuer_host) VALUES ($1, $2) RETURNING tenant_id",
        )
        .bind(slug)
        .bind(issuer_host)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| StoreError::NotFound)?;

        let id: uuid::Uuid = row
            .try_get("tenant_id")
            .map_err(|_| StoreError::Unavailable)?;
        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        Ok(TenantRecord {
            tenant_id: id.to_string(),
            slug: slug.to_owned(),
            issuer_host: issuer_host.to_owned(),
        })
    }
}
