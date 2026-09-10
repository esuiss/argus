use argus_core::id::{TenantId, UserId};
use argus_core::time::Timestamp;
use argus_core::vault::{Lease, SecretKind, SecretRecord};
use argus_crypto::sealing::{NONCE_BYTES, Sealed};
use sqlx::{Row as _, postgres::PgRow};
use uuid::Uuid;

use crate::postgres::PostgresStore;
use crate::traits::StoreError;

pub struct StoredSecret {
    pub record: SecretRecord,
    pub sealed: Sealed,
}

impl core::fmt::Debug for StoredSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredSecret")
            .field("secret_id", &self.record.secret_id)
            .field("audience", &self.record.audience)
            .field("kind", &self.record.kind.as_str())
            .field("sealed", &"<redacted>")
            .finish()
    }
}

fn to_secret(row: &PgRow, tenant: TenantId) -> Result<StoredSecret, StoreError> {
    let secret_id: String = row
        .try_get("secret_id")
        .map_err(|_| StoreError::Unavailable)?;
    let owner: Option<Uuid> = row
        .try_get("owner_user_id")
        .map_err(|_| StoreError::Unavailable)?;
    let audience: String = row
        .try_get("audience")
        .map_err(|_| StoreError::Unavailable)?;
    let kind: String = row.try_get("kind").map_err(|_| StoreError::Unavailable)?;
    let required_scope: String = row
        .try_get("required_scope")
        .map_err(|_| StoreError::Unavailable)?;
    let nonce: Vec<u8> = row.try_get("nonce").map_err(|_| StoreError::Unavailable)?;
    let ciphertext: Vec<u8> = row
        .try_get("ciphertext")
        .map_err(|_| StoreError::Unavailable)?;
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = row
        .try_get("expires_at")
        .map_err(|_| StoreError::Unavailable)?;
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> = row
        .try_get("revoked_at")
        .map_err(|_| StoreError::Unavailable)?;

    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| StoreError::Unavailable)?;

    Ok(StoredSecret {
        record: SecretRecord {
            tenant,
            secret_id,
            owner: owner.map(UserId::from_uuid),
            audience,
            kind: SecretKind::parse(&kind).ok_or(StoreError::Unavailable)?,
            required_scope,
            expires_at: expires_at.map(|at| Timestamp::from_unix_seconds(at.timestamp())),
            revoked: revoked_at.is_some(),
        },
        sealed: Sealed { nonce, ciphertext },
    })
}

impl PostgresStore {
    pub async fn put_secret(
        &self,
        tenant: TenantId,
        record: &SecretRecord,
        sealed: &Sealed,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO vault_secrets \
               (tenant_id, secret_id, owner_user_id, audience, kind, required_scope, nonce, ciphertext, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (tenant_id, secret_id) DO UPDATE SET \
               owner_user_id = EXCLUDED.owner_user_id, \
               audience = EXCLUDED.audience, \
               kind = EXCLUDED.kind, \
               required_scope = EXCLUDED.required_scope, \
               nonce = EXCLUDED.nonce, \
               ciphertext = EXCLUDED.ciphertext, \
               expires_at = EXCLUDED.expires_at, \
               rotated_at = now(), \
               revoked_at = NULL",
        )
        .bind(tenant.as_uuid())
        .bind(&record.secret_id)
        .bind(record.owner.map(UserId::as_uuid))
        .bind(&record.audience)
        .bind(record.kind.as_str())
        .bind(&record.required_scope)
        .bind(sealed.nonce.as_slice())
        .bind(sealed.ciphertext.as_slice())
        .bind(record.expires_at.map(|at| {
            chrono::DateTime::from_timestamp(at.as_unix_seconds(), 0)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        }))
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn load_secret(
        &self,
        tenant: TenantId,
        secret_id: &str,
    ) -> Result<StoredSecret, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT secret_id, owner_user_id, audience, kind, required_scope, nonce, ciphertext, \
                    expires_at, revoked_at \
               FROM vault_secrets WHERE tenant_id = $1 AND secret_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(secret_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::NotFound)?;

        let secret = to_secret(&row, tenant)?;
        tx.commit().await.map_err(|_| StoreError::Unavailable)?;
        Ok(secret)
    }

    pub async fn revoke_secret(&self, tenant: TenantId, secret_id: &str) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let affected = sqlx::query(
            "UPDATE vault_secrets SET revoked_at = now() \
              WHERE tenant_id = $1 AND secret_id = $2 AND revoked_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(secret_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .rows_affected();

        if affected == 0 {
            return Err(StoreError::NotFound);
        }

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn issue_lease(
        &self,
        tenant: TenantId,
        secret_id: &str,
        holder: &str,
        expires_at: Timestamp,
    ) -> Result<Lease, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "INSERT INTO vault_leases (tenant_id, secret_id, holder, expires_at) \
             VALUES ($1, $2, $3, $4) RETURNING lease_id, issued_at, expires_at",
        )
        .bind(tenant.as_uuid())
        .bind(secret_id)
        .bind(holder)
        .bind(
            chrono::DateTime::from_timestamp(expires_at.as_unix_seconds(), 0)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        let lease_id: Uuid = row
            .try_get("lease_id")
            .map_err(|_| StoreError::Unavailable)?;
        let issued_at: chrono::DateTime<chrono::Utc> = row
            .try_get("issued_at")
            .map_err(|_| StoreError::Unavailable)?;
        let expires: chrono::DateTime<chrono::Utc> = row
            .try_get("expires_at")
            .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        Ok(Lease {
            lease_id: lease_id.to_string(),
            secret_id: secret_id.to_owned(),
            holder: holder.to_owned(),
            issued_at: Timestamp::from_unix_seconds(issued_at.timestamp()),
            expires_at: Timestamp::from_unix_seconds(expires.timestamp()),
            spent: false,
        })
    }

    pub async fn spend_lease(&self, tenant: TenantId, lease_id: &str) -> Result<Lease, StoreError> {
        let lease_id = Uuid::parse_str(lease_id).map_err(|_| StoreError::NotFound)?;

        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "UPDATE vault_leases SET spent_at = greatest(now(), issued_at) \
              WHERE tenant_id = $1 AND lease_id = $2 AND spent_at IS NULL \
              RETURNING lease_id, secret_id, holder, issued_at, expires_at",
        )
        .bind(tenant.as_uuid())
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::NotFound)?;

        let secret_id: String = row
            .try_get("secret_id")
            .map_err(|_| StoreError::Unavailable)?;
        let holder: String = row.try_get("holder").map_err(|_| StoreError::Unavailable)?;
        let issued_at: chrono::DateTime<chrono::Utc> = row
            .try_get("issued_at")
            .map_err(|_| StoreError::Unavailable)?;
        let expires_at: chrono::DateTime<chrono::Utc> = row
            .try_get("expires_at")
            .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        Ok(Lease {
            lease_id: lease_id.to_string(),
            secret_id,
            holder,
            issued_at: Timestamp::from_unix_seconds(issued_at.timestamp()),
            expires_at: Timestamp::from_unix_seconds(expires_at.timestamp()),
            spent: false,
        })
    }

    pub async fn purge_spent_leases(
        &self,
        tenant: TenantId,
        now: Timestamp,
    ) -> Result<u64, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let affected = sqlx::query(
            "DELETE FROM vault_leases WHERE tenant_id = $1 AND (spent_at IS NOT NULL OR expires_at <= $2)",
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
