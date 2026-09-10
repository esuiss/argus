use argus_core::authz::index::TupleIndex;
use argus_core::authz::model::{EntityRef, SubjectRef, Tuple};
use argus_core::authz::{GrantRefusal, TupleOp};
use argus_core::id::TenantId;
use sqlx::Row as _;

use crate::postgres::PostgresStore;
use crate::traits::StoreError;

/// §20 §7.4 uses the largest bigint as "not deleted", so a live row needs no
/// NULL handling in a range predicate.
const NEVER_DELETED: i64 = i64::MAX;

fn row_to_tuple(
    object_type: &str,
    object_id: &str,
    relation: &str,
    subject_type: &str,
    subject_id: &str,
    subject_relation: &str,
) -> Option<Tuple> {
    let object = EntityRef::new(object_type, object_id).ok()?;
    let subject_entity = EntityRef::new(subject_type, subject_id).ok()?;

    let subject = if subject_relation.is_empty() {
        SubjectRef::direct(subject_entity)
    } else {
        SubjectRef::userset(subject_entity, subject_relation).ok()?
    };

    Tuple::new(object, relation, subject).ok()
}

impl PostgresStore {
    /// The revision the tenant is currently at. A tenant that has never had a
    /// tuple written sits at zero, which is a valid revision to read at.
    pub async fn authz_revision(&self, tenant: TenantId) -> Result<i64, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query("SELECT revision FROM authz_revisions WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        Ok(row
            .and_then(|r| r.try_get::<i64, _>("revision").ok())
            .unwrap_or(0))
    }

    /// Every tuple alive at `revision`. F1 of §20 §7.7 loads the tenant's
    /// graph and resolves in process; a materialized index is a later stage
    /// and must be differentially tested against this one.
    pub async fn authz_index_at(
        &self,
        tenant: TenantId,
        revision: i64,
    ) -> Result<TupleIndex, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT object_type, object_id, relation, \
                    subject_type, subject_id, subject_relation \
               FROM authz_tuples \
              WHERE tenant_id = $1 \
                AND created_rev <= $2 \
                AND deleted_rev > $2",
        )
        .bind(tenant.as_uuid())
        .bind(revision)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        let mut index = TupleIndex::new();

        for row in rows {
            let (Ok(object_type), Ok(object_id), Ok(relation)) = (
                row.try_get::<String, _>("object_type"),
                row.try_get::<String, _>("object_id"),
                row.try_get::<String, _>("relation"),
            ) else {
                return Err(StoreError::Unavailable);
            };
            let (Ok(subject_type), Ok(subject_id), Ok(subject_relation)) = (
                row.try_get::<String, _>("subject_type"),
                row.try_get::<String, _>("subject_id"),
                row.try_get::<String, _>("subject_relation"),
            ) else {
                return Err(StoreError::Unavailable);
            };

            let Some(tuple) = row_to_tuple(
                &object_type,
                &object_id,
                &relation,
                &subject_type,
                &subject_id,
                &subject_relation,
            ) else {
                // A stored row the model layer cannot represent is a schema
                // violation, not a tuple to skip quietly.
                return Err(StoreError::Unavailable);
            };

            index.insert(tuple);
        }

        index.set_revision(u64::try_from(revision).unwrap_or(0));
        Ok(index)
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn authz_index(&self, tenant: TenantId) -> Result<TupleIndex, StoreError> {
        let revision = self.authz_revision(tenant).await?;
        self.authz_index_at(tenant, revision).await
    }

    /// Applies a batch and returns the revision it produced. The revision bump
    /// and the rows land in one transaction, so a reader at revision R never
    /// sees half a batch.
    pub async fn authz_apply(
        &self,
        tenant: TenantId,
        ops: &[TupleOp],
    ) -> Result<i64, AuthzWriteError> {
        // argus-core enforces this too; the store repeats it because it is the
        // last place before the rows land.
        if ops.len() > argus_core::authz::MAX_TUPLES_PER_WRITE {
            return Err(AuthzWriteError::TooManyTuples {
                allowed: argus_core::authz::MAX_TUPLES_PER_WRITE,
                actual: ops.len(),
            });
        }

        let mut tx = self.scoped(tenant).await.map_err(AuthzWriteError::Store)?;

        // The row lock serialises concurrent batches for this tenant, so two
        // writers cannot be handed the same revision.
        let row = sqlx::query(
            "INSERT INTO authz_revisions (tenant_id, revision) VALUES ($1, 1) \
             ON CONFLICT (tenant_id) DO UPDATE \
               SET revision = authz_revisions.revision + 1, updated_at = now() \
             RETURNING revision",
        )
        .bind(tenant.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AuthzWriteError::Store(StoreError::Unavailable))?;

        let revision: i64 = row
            .try_get("revision")
            .map_err(|_| AuthzWriteError::Store(StoreError::Unavailable))?;

        for op in ops {
            let tuple = op.tuple();
            let subject_relation = tuple.subject.relation().unwrap_or_default();

            match op {
                TupleOp::Write(_) => {
                    sqlx::query(
                        "INSERT INTO authz_tuples \
                           (tenant_id, object_type, object_id, relation, \
                            subject_type, subject_id, subject_relation, created_rev) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                         ON CONFLICT (tenant_id, object_type, object_id, relation, \
                                      subject_type, subject_id, subject_relation, created_rev) \
                         DO NOTHING",
                    )
                    .bind(tenant.as_uuid())
                    .bind(tuple.object.kind())
                    .bind(tuple.object.id())
                    .bind(&tuple.relation)
                    .bind(tuple.subject.entity().kind())
                    .bind(tuple.subject.entity().id())
                    .bind(subject_relation)
                    .bind(revision)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| AuthzWriteError::Store(StoreError::Unavailable))?;
                }

                TupleOp::Delete(_) => {
                    // Tombstoned, never removed: a decision taken at an older
                    // revision has to stay reproducible.
                    sqlx::query(
                        "UPDATE authz_tuples SET deleted_rev = $8 \
                          WHERE tenant_id = $1 AND object_type = $2 AND object_id = $3 \
                            AND relation = $4 AND subject_type = $5 AND subject_id = $6 \
                            AND subject_relation = $7 AND deleted_rev = $9",
                    )
                    .bind(tenant.as_uuid())
                    .bind(tuple.object.kind())
                    .bind(tuple.object.id())
                    .bind(&tuple.relation)
                    .bind(tuple.subject.entity().kind())
                    .bind(tuple.subject.entity().id())
                    .bind(subject_relation)
                    .bind(revision)
                    .bind(NEVER_DELETED)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| AuthzWriteError::Store(StoreError::Unavailable))?;
                }
            }
        }

        tx.commit()
            .await
            .map_err(|_| AuthzWriteError::Store(StoreError::Unavailable))?;
        Ok(revision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthzWriteError {
    #[error("a write of {actual} tuples exceeds the {allowed} this server accepts")]
    TooManyTuples { allowed: usize, actual: usize },

    #[error(transparent)]
    Refused(#[from] GrantRefusal),

    #[error(transparent)]
    Store(#[from] StoreError),
}
