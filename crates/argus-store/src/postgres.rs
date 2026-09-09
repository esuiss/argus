//! PostgreSQL uygulaması.
//!
//! # Kiracı kapsamı her sorguda kurulur
//!
//! §18: RLS politikaları `argus_current_tenant()`'ı okur ve o değer
//! transaction-yerel bir `GUC`'tan gelir. Bu yüzden **her** işlem bir
//! transaction açar ve ilk iş olarak `SET LOCAL` yapar. Havuzdan alınan bir
//! bağlantı asla önceki isteğin kapsamını taşımaz; `SET LOCAL` `COMMIT`'te
//! kendiliğinden temizlenir.
//!
//! Kapsamı kurmayı unutmak **fail-closed**'dur: `argus_current_tenant()` `NULL`
//! döner, politikalar hiçbir satır göstermez.
//!
//! # Derleme zamanı sorgu doğrulaması kullanılmıyor
//!
//! `sqlx::query!` makrosu derleme sırasında canlı bir veritabanı ister ve
//! derlemeyi ortama bağımlı kılar. Sorgular çalışma zamanında bağlanıyor;
//! doğruluğu gerçek `PostgreSQL`'e karşı koşan testler kanıtlıyor.

use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::pkce::{CodeChallenge, CodeChallengeMethod};
use argus_core::redirect_uri::RedirectUri;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::Timestamp;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sqlx::{PgPool, Postgres, Row as _, Transaction};

use crate::traits::{AuditSink, ClientStore, CodeIssuer, CodeStore, RefreshStore, StoreError};

/// `PostgreSQL` destekli depo.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

/// `sqlx` hatasını depo hatasına çevirir.
///
/// ⚠️ Ayrım önemli: `RowNotFound` bir **istek** hatasıdır (`invalid_grant`),
/// geri kalan her şey bir **altyapı** hatasıdır ve §19 §7.1 gereği `503`'e
/// dönüşür. İkisini birleştirmek, geçici bir veritabanı arızasını kullanıcıya
/// "yeniden yetkilendir" olarak gösterirdi.
fn map_err(e: &sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        _ => StoreError::Unavailable,
    }
}

impl PostgresStore {
    /// Havuzdan depo kurar.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Kiracı kapsamı kurulmuş bir transaction açar.
    async fn scoped(&self, tenant: TenantId) -> Result<Transaction<'_, Postgres>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(|e| map_err(&e))?;
        // `true` = SET LOCAL: COMMIT'te temizlenir.
        sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| map_err(&e))?;
        Ok(tx)
    }
}

/// Unix saniyesini `chrono` zamanına çevirir.
fn to_dt(ts: Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(ts.as_unix_seconds(), 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
}

/// `chrono` zamanını Unix saniyesine çevirir.
fn from_dt(dt: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp::from_unix_seconds(dt.timestamp())
}

impl ClientStore for PostgresStore {
    async fn find(
        &self,
        tenant: TenantId,
        client_id: &ClientId,
    ) -> Result<Option<RegisteredClient>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let exists = sqlx::query("SELECT 1 FROM clients WHERE tenant_id = $1 AND client_id = $2")
            .bind(tenant.as_uuid())
            .bind(client_id.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map_err(&e))?;

        if exists.is_none() {
            return Ok(None);
        }

        let rows = sqlx::query(
            "SELECT redirect_uri FROM client_redirect_uris \
             WHERE tenant_id = $1 AND client_id = $2 ORDER BY redirect_uri",
        )
        .bind(tenant.as_uuid())
        .bind(client_id.as_str())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let mut redirect_uris = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: String = row.try_get("redirect_uri").map_err(|e| map_err(&e))?;
            // Şema `client_redirect_uris` üzerinde wildcard/fragment/mutlaklık
            // kısıtlarını zaten zorluyor; yine de burada tekrar doğrulanıyor.
            // Veri katmanına uygulama dışından da yazılabilir.
            if let Ok(uri) = RedirectUri::register(raw) {
                redirect_uris.push(uri);
            }
        }

        Ok(Some(RegisteredClient {
            client_id: client_id.clone(),
            redirect_uris,
        }))
    }
}

impl CodeIssuer for PostgresStore {
    async fn issue(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        code: &StoredCode,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO authorization_codes \
             (tenant_id, code_hash, client_id, user_id, redirect_uri, \
              challenge_digest, challenge_method, issued_at, expires_at, state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'issued')",
        )
        .bind(tenant.as_uuid())
        .bind(&code_hash[..])
        .bind(code.client.as_str())
        .bind(code.subject.as_uuid())
        .bind(code.redirect_uri.as_str())
        .bind(&code.challenge.digest()[..])
        .bind(code.challenge.method().as_str())
        .bind(to_dt(code.issued_at))
        .bind(to_dt(code.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }
}

impl CodeStore for PostgresStore {
    async fn load(&self, tenant: TenantId, code_hash: &[u8; 32]) -> Result<StoredCode, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT client_id, user_id, redirect_uri, challenge_digest, \
                    issued_at, expires_at, state, redeemed_at \
             FROM authorization_codes WHERE tenant_id = $1 AND code_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(&code_hash[..])
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let client_raw: String = row.try_get("client_id").map_err(|e| map_err(&e))?;
        let user: uuid::Uuid = row.try_get("user_id").map_err(|e| map_err(&e))?;
        let redirect_raw: String = row.try_get("redirect_uri").map_err(|e| map_err(&e))?;
        let digest: Vec<u8> = row.try_get("challenge_digest").map_err(|e| map_err(&e))?;
        let issued: chrono::DateTime<chrono::Utc> =
            row.try_get("issued_at").map_err(|e| map_err(&e))?;
        let expires: chrono::DateTime<chrono::Utc> =
            row.try_get("expires_at").map_err(|e| map_err(&e))?;
        let state_raw: String = row.try_get("state").map_err(|e| map_err(&e))?;
        let redeemed: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("redeemed_at").map_err(|e| map_err(&e))?;

        let challenge = CodeChallenge::parse(
            CodeChallengeMethod::S256,
            &Base64UrlUnpadded::encode_string(&digest),
        )
        .map_err(|_| StoreError::Unavailable)?;

        let state = match (state_raw.as_str(), redeemed) {
            ("redeemed", Some(at)) => CodeState::Redeemed { at: from_dt(at) },
            _ => CodeState::Issued,
        };

        Ok(StoredCode {
            tenant,
            client: ClientId::new(client_raw).map_err(|_| StoreError::Unavailable)?,
            subject: UserId::from_uuid(user),
            redirect_uri: RedirectUri::register(redirect_raw)
                .map_err(|_| StoreError::Unavailable)?,
            challenge,
            issued_at: from_dt(issued),
            expires_at: from_dt(expires),
            state,
        })
    }

    async fn consume(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        // `WHERE state = 'issued'`: iki eşzamanlı istek aynı kodu tüketemez.
        // Yarışı kaybeden 0 satır günceller ve çağıran bunu tekrar kullanım
        // olarak görür — tam olarak istenen davranış.
        sqlx::query(
            "UPDATE authorization_codes SET state = 'redeemed', redeemed_at = $3 \
             WHERE tenant_id = $1 AND code_hash = $2 AND state = 'issued'",
        )
        .bind(tenant.as_uuid())
        .bind(&code_hash[..])
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn revoke_tokens_issued_for_code(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        // RFC 9700 §4.1.1: koddan türeyen her şey düşer. Kodun sahibi olan
        // kullanıcı+istemci çiftinin, kod verildikten SONRA başlayan refresh
        // zincirleri iptal edilir.
        sqlx::query(
            "UPDATE refresh_tokens r SET state = 'revoked', revoked_at = $3 \
             WHERE r.tenant_id = $1 AND r.state <> 'revoked' AND EXISTS ( \
               SELECT 1 FROM authorization_codes c \
                WHERE c.tenant_id = r.tenant_id AND c.code_hash = $2 \
                  AND c.client_id = r.client_id AND c.user_id = r.user_id \
                  AND r.family_started_at >= c.issued_at )",
        )
        .bind(tenant.as_uuid())
        .bind(&code_hash[..])
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }
}

impl RefreshStore for PostgresStore {
    async fn load(
        &self,
        tenant: TenantId,
        token_hash: &[u8; 32],
    ) -> Result<RefreshToken, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT client_id, user_id, family_id, generation, family_started_at, \
                    expires_at, state, rotated_at, revoked_at \
             FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(&token_hash[..])
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let client_raw: String = row.try_get("client_id").map_err(|e| map_err(&e))?;
        let user: uuid::Uuid = row.try_get("user_id").map_err(|e| map_err(&e))?;
        let family: uuid::Uuid = row.try_get("family_id").map_err(|e| map_err(&e))?;
        let generation: i32 = row.try_get("generation").map_err(|e| map_err(&e))?;
        let started: chrono::DateTime<chrono::Utc> =
            row.try_get("family_started_at").map_err(|e| map_err(&e))?;
        let expires: chrono::DateTime<chrono::Utc> =
            row.try_get("expires_at").map_err(|e| map_err(&e))?;
        let state_raw: String = row.try_get("state").map_err(|e| map_err(&e))?;
        let rotated: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("rotated_at").map_err(|e| map_err(&e))?;
        let revoked: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("revoked_at").map_err(|e| map_err(&e))?;

        let state = match (state_raw.as_str(), rotated, revoked) {
            ("rotated", Some(at), _) => RefreshState::Rotated { at: from_dt(at) },
            ("revoked", _, Some(at)) => RefreshState::Revoked { at: from_dt(at) },
            _ => RefreshState::Active,
        };

        Ok(RefreshToken {
            tenant,
            client: ClientId::new(client_raw).map_err(|_| StoreError::Unavailable)?,
            subject: UserId::from_uuid(user),
            family: FamilyId::from_uuid(family),
            generation: u32::try_from(generation).unwrap_or(0),
            family_started_at: from_dt(started),
            expires_at: from_dt(expires),
            state,
        })
    }

    async fn rotate(
        &self,
        tenant: TenantId,
        old_hash: &[u8; 32],
        new_hash: &[u8; 32],
        new_token: &RefreshToken,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        // İkisi AYNI transaction'da: eskisinin kapanması ile yenisinin
        // yazılması arasında bir pencere kalırsa, o pencerede çöken bir süreç
        // ya iki geçerli token ya da hiç token bırakır.
        sqlx::query(
            "UPDATE refresh_tokens SET state = 'rotated', rotated_at = $3 \
             WHERE tenant_id = $1 AND token_hash = $2 AND state = 'active'",
        )
        .bind(tenant.as_uuid())
        .bind(&old_hash[..])
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        sqlx::query(
            "INSERT INTO refresh_tokens \
             (tenant_id, token_hash, client_id, user_id, family_id, generation, \
              family_started_at, expires_at, state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')",
        )
        .bind(tenant.as_uuid())
        .bind(&new_hash[..])
        .bind(new_token.client.as_str())
        .bind(new_token.subject.as_uuid())
        .bind(new_token.family.as_uuid())
        .bind(i32::try_from(new_token.generation).unwrap_or(i32::MAX))
        .bind(to_dt(new_token.family_started_at))
        .bind(to_dt(new_token.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn revoke_family(
        &self,
        tenant: TenantId,
        family: FamilyId,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        // Tek sorgu: yeniden kullanım tespit edildiğinde gecikme, saldırganın
        // penceresidir. `refresh_tokens_family` indeksi bunu destekliyor.
        sqlx::query(
            "UPDATE refresh_tokens SET state = 'revoked', revoked_at = $3 \
             WHERE tenant_id = $1 AND family_id = $2 AND state <> 'revoked'",
        )
        .bind(tenant.as_uuid())
        .bind(family.as_uuid())
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }
}

impl AuditSink for PostgresStore {
    async fn record(
        &self,
        tenant: TenantId,
        event_type: &str,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        // §1 #23: olay ve outbox satırı AYNI transaction'da. Ayrı bir kuyruğa
        // yazmak, süreç çöktüğünde iş değişikliğini kalıcı ama denetim kaydını
        // kayıp bırakırdı.
        let row = sqlx::query(
            "INSERT INTO audit_events \
             (tenant_id, occurred_at, event_type, outcome, actor_kind) \
             VALUES ($1, $2, $3, 'success', 'system') \
             RETURNING event_id, occurred_at",
        )
        .bind(tenant.as_uuid())
        .bind(to_dt(at))
        .bind(event_type)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        let event_id: uuid::Uuid = row.try_get("event_id").map_err(|e| map_err(&e))?;
        let occurred: chrono::DateTime<chrono::Utc> =
            row.try_get("occurred_at").map_err(|e| map_err(&e))?;

        sqlx::query(
            "INSERT INTO audit_outbox (tenant_id, occurred_at, event_id) VALUES ($1, $2, $3)",
        )
        .bind(tenant.as_uuid())
        .bind(occurred)
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }
}
