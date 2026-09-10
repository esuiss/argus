use argus_core::audit::merkle::{inclusion_proof, leaf_hash, root};
use argus_core::audit::record::Checkpoint;
use argus_core::id::TenantId;
use argus_core::pkce::Sha256;
use serde_json::{Value, json};
use sqlx::Row as _;

use crate::postgres::PostgresStore;
use crate::traits::StoreError;

// Bir checkpoint en fazla bu kadar yeni olayı kapsar. §9.3'ün ölçümü olay
// başına değil batch başına tek imza; batch yine de sınırlı olmalı ki tek bir
// katlama sınırsız sayıda satır okumasın.
pub const MAX_BATCH: i64 = 10_000;

struct AuditEvent {
    event_id: uuid::Uuid,
    occurred_at: i64,
    event_type: String,
    outcome: String,
    actor_kind: String,
    actor_id: Option<uuid::Uuid>,
    target_kind: Option<String>,
    target_id: Option<String>,
}

// Olayın hash'lendiği kanonik biçim. Saklanan satırı değil ANLAMINI temsil
// eder: sonradan bir sütun eklemek daha önce verilmiş her kanıtı
// geçersizleştirmemeli.
fn canonical(event: &AuditEvent) -> Value {
    json!({
        "event_id": event.event_id.to_string(),
        "occurred_at": event.occurred_at,
        "event_type": event.event_type,
        "outcome": event.outcome,
        "actor_kind": event.actor_kind,
        "actor_id": event.actor_id.map(|id| id.to_string()),
        "target_kind": event.target_kind,
        "target_id": event.target_id,
    })
}

impl PostgresStore {
    // Ağaçta olmayan her olayı katlar ve yeni bir checkpoint yayınlar.
    // Katlanacak bir şey yoksa None döner.
    pub async fn checkpoint_audit<H: Sha256>(
        &self,
        tenant: TenantId,
        hasher: &H,
    ) -> Result<Option<Checkpoint>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        // Bir sonraki boş indeks. audit_leaves append-only olduğu için bu aynı
        // zamanda mevcut ağaç boyutudur.
        let size: i64 = sqlx::query_scalar(
            "SELECT coalesce(max(leaf_index) + 1, 0) FROM audit_leaves WHERE tenant_id = $1",
        )
        .bind(tenant.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        // `checkpoint_at` DEĞİL: audit_events append-only ve argus_app'in onda
        // UPDATE yetkisi yok (§25 K7), ki doğrusu budur. Bir olayın ağaçta olup
        // olmadığı ağaç hakkında bir olgudur, o yüzden cevabı ağaç verir.
        let pending = sqlx::query(
            "SELECT e.event_id, e.occurred_at, e.event_type, e.outcome, e.actor_kind, \
                    e.actor_id, e.target_kind, e.target_id \
               FROM audit_events e \
              WHERE e.tenant_id = $1 \
                AND NOT EXISTS ( \
                  SELECT 1 FROM audit_leaves l \
                   WHERE l.tenant_id = e.tenant_id AND l.event_id = e.event_id) \
              ORDER BY e.occurred_at, e.event_id \
              LIMIT $2",
        )
        .bind(tenant.as_uuid())
        .bind(MAX_BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        if pending.is_empty() {
            tx.commit().await.map_err(|_| StoreError::Unavailable)?;
            return Ok(None);
        }

        for (next, row) in (size..).zip(pending.iter()) {
            let event_id: uuid::Uuid = row
                .try_get("event_id")
                .map_err(|_| StoreError::Unavailable)?;
            let occurred: chrono::DateTime<chrono::Utc> = row
                .try_get("occurred_at")
                .map_err(|_| StoreError::Unavailable)?;
            let event_type: String = row
                .try_get("event_type")
                .map_err(|_| StoreError::Unavailable)?;
            let outcome: String = row
                .try_get("outcome")
                .map_err(|_| StoreError::Unavailable)?;
            let actor_kind: String = row
                .try_get("actor_kind")
                .map_err(|_| StoreError::Unavailable)?;
            let actor_id: Option<uuid::Uuid> = row.try_get("actor_id").ok().flatten();
            let target_kind: Option<String> = row.try_get("target_kind").ok().flatten();
            let target_id: Option<String> = row.try_get("target_id").ok().flatten();

            let document = canonical(&AuditEvent {
                event_id,
                occurred_at: occurred.timestamp(),
                event_type,
                outcome,
                actor_kind,
                actor_id,
                target_kind,
                target_id,
            });

            let canonical = argus_proto_jcs(&document)?;
            let hash = leaf_hash(hasher, canonical.as_bytes());

            sqlx::query(
                "INSERT INTO audit_leaves (tenant_id, leaf_index, leaf_hash, event_id) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(tenant.as_uuid())
            .bind(next)
            .bind(hash.as_slice())
            .bind(event_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        }

        let leaves = read_leaves(&mut tx, tenant).await?;
        let computed = root(hasher, &leaves);
        let tree_size = i64::try_from(leaves.len()).map_err(|_| StoreError::Unavailable)?;

        sqlx::query(
            "INSERT INTO audit_checkpoints (tenant_id, tree_size, root) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id, tree_size) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(tree_size)
        .bind(computed.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        Ok(Some(Checkpoint {
            tree_size: u64::try_from(tree_size).unwrap_or(0),
            root: computed,
            issued_at: 0,
        }))
    }

    // Tek bir olayın yayınlanmış ağaçta olduğunun kanıtı; henüz katlanmadıysa
    // NotFound.
    pub async fn audit_proof<H: Sha256>(
        &self,
        tenant: TenantId,
        event_id: &uuid::Uuid,
        hasher: &H,
    ) -> Result<(u64, [u8; 32], Checkpoint, Vec<[u8; 32]>), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT leaf_index, leaf_hash FROM audit_leaves \
              WHERE tenant_id = $1 AND event_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::NotFound)?;

        let index: i64 = row
            .try_get("leaf_index")
            .map_err(|_| StoreError::Unavailable)?;
        let raw: Vec<u8> = row
            .try_get("leaf_hash")
            .map_err(|_| StoreError::Unavailable)?;
        let leaf: [u8; 32] = raw.try_into().map_err(|_| StoreError::Unavailable)?;

        let checkpoint = sqlx::query(
            "SELECT tree_size, root, extract(epoch FROM issued_at)::bigint AS issued_at \
               FROM audit_checkpoints \
              WHERE tenant_id = $1 ORDER BY tree_size DESC LIMIT 1",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?
        .ok_or(StoreError::NotFound)?;

        let tree_size: i64 = checkpoint
            .try_get("tree_size")
            .map_err(|_| StoreError::Unavailable)?;
        let root_raw: Vec<u8> = checkpoint
            .try_get("root")
            .map_err(|_| StoreError::Unavailable)?;
        let root_hash: [u8; 32] = root_raw.try_into().map_err(|_| StoreError::Unavailable)?;
        let issued_at: i64 = checkpoint
            .try_get("issued_at")
            .map_err(|_| StoreError::Unavailable)?;

        let leaves = read_leaves(&mut tx, tenant).await?;
        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        let wanted = usize::try_from(index).map_err(|_| StoreError::Unavailable)?;
        let covered = usize::try_from(tree_size).map_err(|_| StoreError::Unavailable)?;

        // En yeni checkpoint'ten sonra eklenen bir yaprak henüz onun içinde
        // değildir; doğrulanamayacak bir kanıt vermektense bunu söylemek
        // daha iyidir.
        if wanted >= covered {
            return Err(StoreError::NotFound);
        }

        let within = leaves.get(..covered).ok_or(StoreError::Unavailable)?;
        let proof = inclusion_proof(hasher, within, wanted).ok_or(StoreError::Unavailable)?;

        Ok((
            u64::try_from(index).unwrap_or(0),
            leaf,
            Checkpoint {
                tree_size: u64::try_from(tree_size).unwrap_or(0),
                root: root_hash,
                issued_at,
            },
            proof,
        ))
    }
}

async fn read_leaves(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: TenantId,
) -> Result<Vec<[u8; 32]>, StoreError> {
    let rows =
        sqlx::query("SELECT leaf_hash FROM audit_leaves WHERE tenant_id = $1 ORDER BY leaf_index")
            .bind(tenant.as_uuid())
            .fetch_all(&mut **tx)
            .await
            .map_err(|_| StoreError::Unavailable)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let raw: Vec<u8> = row
            .try_get("leaf_hash")
            .map_err(|_| StoreError::Unavailable)?;
        out.push(raw.try_into().map_err(|_| StoreError::Unavailable)?);
    }
    Ok(out)
}

fn argus_proto_jcs(value: &Value) -> Result<String, StoreError> {
    argus_proto::jcs::canonicalize(value).map_err(|_| StoreError::Unavailable)
}
