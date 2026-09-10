use argus_core::id::TenantId;
use argus_core::scim::ScimRecord;
use argus_core::time::Timestamp;
use serde_json::{Map, Value};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::postgres::PostgresStore;
use crate::traits::{ScimConflict, ScimStore, ScimStoreError};

fn classify(error: &sqlx::Error) -> ScimStoreError {
    match error {
        sqlx::Error::RowNotFound => ScimStoreError::NotFound,
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some("23505") => match db.constraint() {
                Some("scim_users_user_name_key") => {
                    ScimStoreError::Conflict(ScimConflict::UserNameTaken)
                }
                Some("scim_users_external_id_key" | "scim_groups_external_id_key") => {
                    ScimStoreError::Conflict(ScimConflict::ExternalIdTaken)
                }
                _ => ScimStoreError::Unavailable,
            },
            Some("23503") => ScimStoreError::Conflict(ScimConflict::UnknownMember(String::new())),
            _ => ScimStoreError::Unavailable,
        },
        _ => ScimStoreError::Unavailable,
    }
}

fn to_dt(at: Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(at.as_unix_seconds(), 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
}

fn from_dt(at: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp::from_unix_seconds(at.timestamp())
}

fn seq_of(row: &sqlx::postgres::PgRow) -> Result<u64, ScimStoreError> {
    let raw: i64 = row.try_get("create_seq").map_err(|e| classify(&e))?;
    u64::try_from(raw).map_err(|_| ScimStoreError::Unavailable)
}

fn record_of(row: &sqlx::postgres::PgRow, id_column: &str) -> Result<ScimRecord, ScimStoreError> {
    let id: Uuid = row.try_get(id_column).map_err(|e| classify(&e))?;
    let payload: Value = row.try_get("payload").map_err(|e| classify(&e))?;
    let created: chrono::DateTime<chrono::Utc> =
        row.try_get("created_at").map_err(|e| classify(&e))?;
    let modified: chrono::DateTime<chrono::Utc> =
        row.try_get("last_modified").map_err(|e| classify(&e))?;

    Ok(ScimRecord {
        id: id.to_string(),
        payload,
        created_at: from_dt(created),
        last_modified: from_dt(modified),
        seq: seq_of(row)?,
    })
}

fn parse_id(id: &str) -> Result<Uuid, ScimStoreError> {
    Uuid::parse_str(id).map_err(|_| ScimStoreError::NotFound)
}

fn strip_members(payload: &Value) -> Value {
    let mut object = payload.as_object().cloned().unwrap_or_else(Map::new);
    object.remove("members");
    Value::Object(object)
}

async fn attach_members(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    records: &mut [ScimRecord],
) -> Result<(), ScimStoreError> {
    if records.is_empty() {
        return Ok(());
    }

    let ids: Vec<Uuid> = records
        .iter()
        .filter_map(|record| Uuid::parse_str(&record.id).ok())
        .collect();

    let rows = sqlx::query(
        "SELECT m.group_id, m.member_id, \
                CASE WHEN m.member_user_id IS NULL THEN 'Group' ELSE 'User' END AS member_type, \
                coalesce(u.user_name, g.display_name) AS display \
           FROM scim_group_members m \
           LEFT JOIN scim_users  u ON u.tenant_id = m.tenant_id AND u.user_id  = m.member_user_id \
           LEFT JOIN scim_groups g ON g.tenant_id = m.tenant_id AND g.group_id = m.member_group_id \
          WHERE m.tenant_id = $1 AND m.group_id = ANY($2) \
          ORDER BY m.member_id",
    )
    .bind(tenant.as_uuid())
    .bind(&ids)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| classify(&e))?;

    for record in records.iter_mut() {
        let mut members: Vec<Value> = Vec::new();
        for row in &rows {
            let group_id: Uuid = row.try_get("group_id").map_err(|e| classify(&e))?;
            if group_id.to_string() != record.id {
                continue;
            }
            let member_id: Uuid = row.try_get("member_id").map_err(|e| classify(&e))?;
            let member_type: String = row.try_get("member_type").map_err(|e| classify(&e))?;
            let display: Option<String> = row.try_get("display").map_err(|e| classify(&e))?;

            let mut member = Map::new();
            member.insert("value".to_owned(), Value::String(member_id.to_string()));
            member.insert("type".to_owned(), Value::String(member_type));
            if let Some(display) = display {
                member.insert("display".to_owned(), Value::String(display));
            }
            members.push(Value::Object(member));
        }

        if let Some(object) = record.payload.as_object_mut() {
            object.insert("members".to_owned(), Value::Array(members));
        }
    }

    Ok(())
}

async fn replace_members(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    group: Uuid,
    payload: &Value,
) -> Result<(), ScimStoreError> {
    sqlx::query("DELETE FROM scim_group_members WHERE tenant_id = $1 AND group_id = $2")
        .bind(tenant.as_uuid())
        .bind(group)
        .execute(&mut **tx)
        .await
        .map_err(|e| classify(&e))?;

    for raw in argus_core::scim::member_ids(payload) {
        let member = Uuid::parse_str(&raw)
            .map_err(|_| ScimStoreError::Conflict(ScimConflict::UnknownMember(raw.clone())))?;

        if member == group {
            return Err(ScimStoreError::Conflict(ScimConflict::UnknownMember(raw)));
        }

        let is_user: bool = sqlx::query(
            "SELECT EXISTS (SELECT 1 FROM scim_users WHERE tenant_id = $1 AND user_id = $2)",
        )
        .bind(tenant.as_uuid())
        .bind(member)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| classify(&e))?
        .try_get(0)
        .map_err(|e| classify(&e))?;

        let statement = if is_user {
            "INSERT INTO scim_group_members (tenant_id, group_id, member_user_id) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
        } else {
            "INSERT INTO scim_group_members (tenant_id, group_id, member_group_id) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
        };

        sqlx::query(statement)
            .bind(tenant.as_uuid())
            .bind(group)
            .bind(member)
            .execute(&mut **tx)
            .await
            .map_err(|_| ScimStoreError::Conflict(ScimConflict::UnknownMember(raw)))?;
    }

    Ok(())
}

fn text_of(payload: &Value, attribute: &str) -> Option<String> {
    payload
        .get(attribute)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

impl ScimStore for PostgresStore {
    async fn create_user(
        &self,
        tenant: TenantId,
        payload: &Value,
        now: Timestamp,
    ) -> Result<ScimRecord, ScimStoreError> {
        let user_name = text_of(payload, "userName").ok_or(ScimStoreError::Unavailable)?;
        let external_id = text_of(payload, "externalId");
        let active = payload
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let mut tx = self.scim_scoped(tenant).await?;

        let id: Uuid = sqlx::query("INSERT INTO users (tenant_id) VALUES ($1) RETURNING user_id")
            .bind(tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| classify(&e))?
            .try_get("user_id")
            .map_err(|e| classify(&e))?;

        sqlx::query(
            "INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id) \
             VALUES ($1, $2, $3, 'bootstrap')",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .bind([0u8; 1].as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|e| classify(&e))?;

        let row = sqlx::query(
            "INSERT INTO scim_users \
               (tenant_id, user_id, user_name, external_id, active, payload, created_at, last_modified) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
             RETURNING user_id, payload, created_at, last_modified, create_seq",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .bind(&user_name)
        .bind(external_id.as_deref())
        .bind(active)
        .bind(payload)
        .bind(to_dt(now))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify(&e))?;

        let record = record_of(&row, "user_id")?;
        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(record)
    }

    async fn get_user(&self, tenant: TenantId, id: &str) -> Result<ScimRecord, ScimStoreError> {
        let id = parse_id(id)?;
        let mut tx = self.scim_scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT user_id, payload, created_at, last_modified, create_seq \
               FROM scim_users WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify(&e))?
        .ok_or(ScimStoreError::NotFound)?;

        let record = record_of(&row, "user_id")?;
        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(record)
    }

    async fn replace_user(
        &self,
        tenant: TenantId,
        id: &str,
        payload: &Value,
        now: Timestamp,
    ) -> Result<ScimRecord, ScimStoreError> {
        let id = parse_id(id)?;
        let user_name = text_of(payload, "userName").ok_or(ScimStoreError::Unavailable)?;
        let external_id = text_of(payload, "externalId");
        let active = payload
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let mut tx = self.scim_scoped(tenant).await?;

        let row = sqlx::query(
            "UPDATE scim_users \
                SET user_name = $3, external_id = $4, active = $5, payload = $6, last_modified = $7 \
              WHERE tenant_id = $1 AND user_id = $2 \
              RETURNING user_id, payload, created_at, last_modified, create_seq",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .bind(&user_name)
        .bind(external_id.as_deref())
        .bind(active)
        .bind(payload)
        .bind(to_dt(now))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify(&e))?
        .ok_or(ScimStoreError::NotFound)?;

        let record = record_of(&row, "user_id")?;
        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(record)
    }

    async fn delete_user(&self, tenant: TenantId, id: &str) -> Result<(), ScimStoreError> {
        let id = parse_id(id)?;
        let mut tx = self.scim_scoped(tenant).await?;

        let affected = sqlx::query("DELETE FROM users WHERE tenant_id = $1 AND user_id = $2")
            .bind(tenant.as_uuid())
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| classify(&e))?
            .rows_affected();

        sqlx::query("DELETE FROM user_keys WHERE tenant_id = $1 AND user_id = $2")
            .bind(tenant.as_uuid())
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| classify(&e))?;

        if affected == 0 {
            return Err(ScimStoreError::NotFound);
        }

        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(())
    }

    async fn scan_users(
        &self,
        tenant: TenantId,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<ScimRecord>, ScimStoreError> {
        let after = i64::try_from(after.unwrap_or(0)).unwrap_or(0);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);

        let mut tx = self.scim_scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT user_id, payload, created_at, last_modified, create_seq \
               FROM scim_users \
              WHERE tenant_id = $1 AND create_seq > $2 \
              ORDER BY create_seq LIMIT $3",
        )
        .bind(tenant.as_uuid())
        .bind(after)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| classify(&e))?;

        let mut records = Vec::with_capacity(rows.len());
        for row in &rows {
            records.push(record_of(row, "user_id")?);
        }

        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(records)
    }

    async fn create_group(
        &self,
        tenant: TenantId,
        payload: &Value,
        now: Timestamp,
    ) -> Result<ScimRecord, ScimStoreError> {
        let display_name = text_of(payload, "displayName").ok_or(ScimStoreError::Unavailable)?;
        let external_id = text_of(payload, "externalId");
        let stored = strip_members(payload);

        let mut tx = self.scim_scoped(tenant).await?;

        let row = sqlx::query(
            "INSERT INTO scim_groups \
               (tenant_id, display_name, external_id, payload, created_at, last_modified) \
             VALUES ($1, $2, $3, $4, $5, $5) \
             RETURNING group_id, payload, created_at, last_modified, create_seq",
        )
        .bind(tenant.as_uuid())
        .bind(&display_name)
        .bind(external_id.as_deref())
        .bind(&stored)
        .bind(to_dt(now))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify(&e))?;

        let id: Uuid = row.try_get("group_id").map_err(|e| classify(&e))?;
        replace_members(&mut tx, tenant, id, payload).await?;

        let mut record = record_of(&row, "group_id")?;
        attach_members(&mut tx, tenant, core::slice::from_mut(&mut record)).await?;

        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(record)
    }

    async fn get_group(&self, tenant: TenantId, id: &str) -> Result<ScimRecord, ScimStoreError> {
        let id = parse_id(id)?;
        let mut tx = self.scim_scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT group_id, payload, created_at, last_modified, create_seq \
               FROM scim_groups WHERE tenant_id = $1 AND group_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify(&e))?
        .ok_or(ScimStoreError::NotFound)?;

        let mut record = record_of(&row, "group_id")?;
        attach_members(&mut tx, tenant, core::slice::from_mut(&mut record)).await?;

        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(record)
    }

    async fn replace_group(
        &self,
        tenant: TenantId,
        id: &str,
        payload: &Value,
        now: Timestamp,
    ) -> Result<ScimRecord, ScimStoreError> {
        let id = parse_id(id)?;
        let display_name = text_of(payload, "displayName").ok_or(ScimStoreError::Unavailable)?;
        let external_id = text_of(payload, "externalId");
        let stored = strip_members(payload);

        let mut tx = self.scim_scoped(tenant).await?;

        let row = sqlx::query(
            "UPDATE scim_groups \
                SET display_name = $3, external_id = $4, payload = $5, last_modified = $6 \
              WHERE tenant_id = $1 AND group_id = $2 \
              RETURNING group_id, payload, created_at, last_modified, create_seq",
        )
        .bind(tenant.as_uuid())
        .bind(id)
        .bind(&display_name)
        .bind(external_id.as_deref())
        .bind(&stored)
        .bind(to_dt(now))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| classify(&e))?
        .ok_or(ScimStoreError::NotFound)?;

        replace_members(&mut tx, tenant, id, payload).await?;

        let mut record = record_of(&row, "group_id")?;
        attach_members(&mut tx, tenant, core::slice::from_mut(&mut record)).await?;

        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(record)
    }

    async fn delete_group(&self, tenant: TenantId, id: &str) -> Result<(), ScimStoreError> {
        let id = parse_id(id)?;
        let mut tx = self.scim_scoped(tenant).await?;

        let affected =
            sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1 AND group_id = $2")
                .bind(tenant.as_uuid())
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|e| classify(&e))?
                .rows_affected();

        if affected == 0 {
            return Err(ScimStoreError::NotFound);
        }

        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(())
    }

    async fn scan_groups(
        &self,
        tenant: TenantId,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<ScimRecord>, ScimStoreError> {
        let after = i64::try_from(after.unwrap_or(0)).unwrap_or(0);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);

        let mut tx = self.scim_scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT group_id, payload, created_at, last_modified, create_seq \
               FROM scim_groups \
              WHERE tenant_id = $1 AND create_seq > $2 \
              ORDER BY create_seq LIMIT $3",
        )
        .bind(tenant.as_uuid())
        .bind(after)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| classify(&e))?;

        let mut records = Vec::with_capacity(rows.len());
        for row in &rows {
            records.push(record_of(row, "group_id")?);
        }

        attach_members(&mut tx, tenant, &mut records).await?;

        tx.commit().await.map_err(|e| classify(&e))?;
        Ok(records)
    }
}
