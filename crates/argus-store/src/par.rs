use argus_core::id::{ClientId, TenantId};
use argus_core::par::PushedRequest;
use argus_core::time::Timestamp;
use serde_json::Value;
use sqlx::Row as _;

use crate::postgres::PostgresStore;
use crate::traits::StoreError;

fn to_pairs(raw: &Value) -> Vec<(String, String)> {
    raw.as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let key = item.get(0)?.as_str()?.to_owned();
                    let value = item.get(1)?.as_str()?.to_owned();
                    Some((key, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn from_pairs(pairs: &[(String, String)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(key, value)| {
                Value::Array(vec![
                    Value::String(key.clone()),
                    Value::String(value.clone()),
                ])
            })
            .collect(),
    )
}

impl PostgresStore {
    pub async fn push_request(
        &self,
        tenant: TenantId,
        request_id: &str,
        client: &ClientId,
        parameters: &[(String, String)],
        expires_at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO pushed_requests (tenant_id, request_id, client_id, parameters, expires_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant.as_uuid())
        .bind(request_id)
        .bind(client.as_str())
        .bind(from_pairs(parameters))
        .bind(
            chrono::DateTime::from_timestamp(expires_at.as_unix_seconds(), 0)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH),
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn consume_request(
        &self,
        tenant: TenantId,
        request_id: &str,
    ) -> Result<PushedRequest, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "UPDATE pushed_requests SET consumed_at = greatest(now(), issued_at) \
              WHERE tenant_id = $1 AND request_id = $2 AND consumed_at IS NULL \
              RETURNING client_id, parameters, issued_at, expires_at",
        )
        .bind(tenant.as_uuid())
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::NotFound)?;

        let client_id: String = row
            .try_get("client_id")
            .map_err(|_| StoreError::Unavailable)?;
        let parameters: Value = row
            .try_get("parameters")
            .map_err(|_| StoreError::Unavailable)?;
        let issued_at: chrono::DateTime<chrono::Utc> = row
            .try_get("issued_at")
            .map_err(|_| StoreError::Unavailable)?;
        let expires_at: chrono::DateTime<chrono::Utc> = row
            .try_get("expires_at")
            .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        Ok(PushedRequest {
            client: ClientId::new(client_id).map_err(|_| StoreError::Unavailable)?,
            parameters: to_pairs(&parameters),
            issued_at: Timestamp::from_unix_seconds(issued_at.timestamp()),
            expires_at: Timestamp::from_unix_seconds(expires_at.timestamp()),
            consumed: false,
        })
    }

    pub async fn purge_pushed_requests(
        &self,
        tenant: TenantId,
        now: Timestamp,
    ) -> Result<u64, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let affected = sqlx::query(
            "DELETE FROM pushed_requests \
              WHERE tenant_id = $1 AND (consumed_at IS NOT NULL OR expires_at <= $2)",
        )
        .bind(tenant.as_uuid())
        .bind(
            chrono::DateTime::from_timestamp(now.as_unix_seconds(), 0)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH),
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .rows_affected();

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(affected)
    }
}
