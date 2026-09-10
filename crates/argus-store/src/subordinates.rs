use argus_core::id::TenantId;
use serde_json::Value;
use sqlx::Row as _;

use crate::postgres::PostgresStore;
use crate::traits::StoreError;

pub struct Subordinate {
    pub subject: String,
    pub jwks: Value,
    pub metadata_policy: Option<Value>,
    pub constraints: Option<Value>,
}

impl core::fmt::Debug for Subordinate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Subordinate")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl PostgresStore {
    pub async fn enrol_subordinate(
        &self,
        tenant: TenantId,
        subordinate: &Subordinate,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO federation_subordinates \
               (tenant_id, subject, jwks, metadata_policy, constraints) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant_id, subject) DO UPDATE SET \
               jwks = EXCLUDED.jwks, \
               metadata_policy = EXCLUDED.metadata_policy, \
               constraints = EXCLUDED.constraints, \
               withdrawn_at = NULL",
        )
        .bind(tenant.as_uuid())
        .bind(&subordinate.subject)
        .bind(&subordinate.jwks)
        .bind(subordinate.metadata_policy.as_ref())
        .bind(subordinate.constraints.as_ref())
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn withdraw_subordinate(
        &self,
        tenant: TenantId,
        subject: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let affected = sqlx::query(
            "UPDATE federation_subordinates SET withdrawn_at = now() \
              WHERE tenant_id = $1 AND subject = $2 AND withdrawn_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(subject)
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .rows_affected();

        if affected == 0 {
            return Err(StoreError::NotFound);
        }

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn list_subordinates(&self, tenant: TenantId) -> Result<Vec<String>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT subject FROM federation_subordinates \
              WHERE tenant_id = $1 AND withdrawn_at IS NULL ORDER BY subject",
        )
        .bind(tenant.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(
                row.try_get("subject")
                    .map_err(|_| StoreError::Unavailable)?,
            );
        }

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(out)
    }

    pub async fn find_subordinate(
        &self,
        tenant: TenantId,
        subject: &str,
    ) -> Result<Subordinate, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT subject, jwks, metadata_policy, constraints \
               FROM federation_subordinates \
              WHERE tenant_id = $1 AND subject = $2 AND withdrawn_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::NotFound)?;

        let subordinate = Subordinate {
            subject: row
                .try_get("subject")
                .map_err(|_| StoreError::Unavailable)?,
            jwks: row.try_get("jwks").map_err(|_| StoreError::Unavailable)?,
            metadata_policy: row
                .try_get("metadata_policy")
                .map_err(|_| StoreError::Unavailable)?,
            constraints: row
                .try_get("constraints")
                .map_err(|_| StoreError::Unavailable)?,
        };

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(subordinate)
    }
}
