use argus_core::aal::Aal;
use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::ciba::{BackchannelRequest, BackchannelState};
use argus_core::client_auth::{ClientAuthMethod, ClientKey};
use argus_core::exchange::CrossAppConnection;
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::jag_consume::TrustedIssuer;
use argus_core::pkce::{CodeChallenge, CodeChallengeMethod};
use argus_core::recovery::{RecoveryAttempt, RecoveryState};
use argus_core::redirect_uri::RedirectUri;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::resource::ResourceUri;
use argus_core::time::Timestamp;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sqlx::{PgPool, Postgres, Row as _, Transaction};

use crate::traits::{
    AuditSink, AuthnSession, AuthnStore, BackchannelStore, CeremonyPurpose, CeremonyStore,
    ClientStore, CodeIssuer, CodeStore, ConnectionStore, IssuerStore, JtiOutcome, JtiPurpose,
    PendingCeremony, ProtectedResource, RecoveryStore, RefreshStore, ReplayStore, ResourceStore,
    SessionStore, StoreError,
};

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
    /// Present only in a process that serves the control plane. §24 #21.
    platform_pool: Option<PgPool>,
}

fn map_err(e: &sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        _ => StoreError::Unavailable,
    }
}

impl PostgresStore {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self {
            pool,
            platform_pool: None,
        }
    }

    pub(crate) async fn scim_scoped(
        &self,
        tenant: TenantId,
    ) -> Result<Transaction<'_, Postgres>, crate::traits::ScimStoreError> {
        Ok(self.scoped(tenant).await?)
    }

    pub(crate) async fn scoped(
        &self,
        tenant: TenantId,
    ) -> Result<Transaction<'_, Postgres>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(|e| map_err(&e))?;

        sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
            .bind(tenant.as_uuid().to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| map_err(&e))?;
        Ok(tx)
    }

    /// A transaction on the control plane role. §24 #21: this reaches the
    /// tenant registry and nothing else, which migration 0022 asserts at the
    /// end of itself rather than leaving to convention.
    ///
    /// It runs on its own connection, with its own login. A process that
    /// serves tenant traffic and one that serves the control plane are then
    /// different database principals, so the separation §24 #19 asks for is a
    /// boundary rather than a convention: a tenant-serving process cannot
    /// reach the registry even if its own code asked it to.
    pub(crate) async fn platform(&self) -> Result<Transaction<'_, Postgres>, StoreError> {
        let pool = self.platform_pool.as_ref().ok_or(StoreError::NotFound)?;
        let mut tx = pool.begin().await.map_err(|e| map_err(&e))?;

        sqlx::query("SET LOCAL ROLE argus_platform")
            .execute(&mut *tx)
            .await
            .map_err(|e| map_err(&e))?;

        Ok(tx)
    }

    #[must_use]
    pub const fn serves_control_plane(&self) -> bool {
        self.platform_pool.is_some()
    }

    #[must_use]
    pub fn with_control_plane(mut self, pool: PgPool) -> Self {
        self.platform_pool = Some(pool);
        self
    }
}

fn to_dt(ts: Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(ts.as_unix_seconds(), 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
}

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

        let registration =
            sqlx::query("SELECT auth_method FROM clients WHERE tenant_id = $1 AND client_id = $2")
                .bind(tenant.as_uuid())
                .bind(client_id.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| map_err(&e))?;

        let Some(registration) = registration else {
            return Ok(None);
        };

        let raw_method: String = registration
            .try_get("auth_method")
            .map_err(|e| map_err(&e))?;

        let auth_method = match raw_method.as_str() {
            "none" => ClientAuthMethod::None,
            "private_key_jwt" => ClientAuthMethod::PrivateKeyJwt,
            _ => return Err(StoreError::Unavailable),
        };

        let rows = sqlx::query(
            "SELECT redirect_uri FROM client_redirect_uris \
             WHERE tenant_id = $1 AND client_id = $2 ORDER BY redirect_uri",
        )
        .bind(tenant.as_uuid())
        .bind(client_id.as_str())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        let key_rows = sqlx::query(
            "SELECT kid, x, y FROM client_keys \
             WHERE tenant_id = $1 AND client_id = $2 ORDER BY kid",
        )
        .bind(tenant.as_uuid())
        .bind(client_id.as_str())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let mut keys = Vec::with_capacity(key_rows.len());
        for row in key_rows {
            let kid: String = row.try_get("kid").map_err(|e| map_err(&e))?;
            let x: Vec<u8> = row.try_get("x").map_err(|e| map_err(&e))?;
            let y: Vec<u8> = row.try_get("y").map_err(|e| map_err(&e))?;

            let (Ok(x), Ok(y)) = (<[u8; 32]>::try_from(x), <[u8; 32]>::try_from(y)) else {
                return Err(StoreError::Unavailable);
            };
            keys.push(ClientKey { kid, x, y });
        }

        let mut redirect_uris = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: String = row.try_get("redirect_uri").map_err(|e| map_err(&e))?;

            if let Ok(uri) = RedirectUri::register(raw) {
                redirect_uris.push(uri);
            }
        }

        Ok(Some(RegisteredClient {
            client_id: client_id.clone(),
            redirect_uris,
            auth_method,
            keys,
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
              challenge_digest, challenge_method, issued_at, expires_at, state, \
              nonce, scope, resources) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'issued', $10, $11, $12)",
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
        .bind(code.nonce.as_deref())
        .bind(code.scope.as_deref())
        .bind(if code.resources.is_empty() {
            None
        } else {
            Some(
                code.resources
                    .iter()
                    .map(argus_core::resource::ResourceUri::as_str)
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        })
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
                    issued_at, expires_at, state, redeemed_at, nonce, scope, resources \
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
        let nonce: Option<String> = row.try_get("nonce").map_err(|e| map_err(&e))?;
        let scope: Option<String> = row.try_get("scope").map_err(|e| map_err(&e))?;
        let raw_resources: Option<String> = row.try_get("resources").map_err(|e| map_err(&e))?;
        let mut resources = Vec::new();
        for value in raw_resources.as_deref().unwrap_or_default().split(' ') {
            if value.is_empty() {
                continue;
            }
            resources.push(ResourceUri::parse(value).map_err(|_| StoreError::Unavailable)?);
        }

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
            nonce,
            scope,
            resources,
        })
    }

    async fn consume(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

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

impl ResourceStore for PostgresStore {
    async fn find_resource(
        &self,
        tenant: TenantId,
        uri: &ResourceUri,
    ) -> Result<Option<ProtectedResource>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT resource_uri, resource_name, scopes FROM protected_resources \
             WHERE tenant_id = $1 AND resource_uri = $2",
        )
        .bind(tenant.as_uuid())
        .bind(uri.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(resource_from_row(&row)?))
    }

    async fn list_resources(&self, tenant: TenantId) -> Result<Vec<ProtectedResource>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT resource_uri, resource_name, scopes FROM protected_resources \
             WHERE tenant_id = $1 ORDER BY resource_uri",
        )
        .bind(tenant.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(resource_from_row(row)?);
        }
        Ok(out)
    }
}

fn resource_from_row(row: &sqlx::postgres::PgRow) -> Result<ProtectedResource, StoreError> {
    let raw: String = row.try_get("resource_uri").map_err(|e| map_err(&e))?;
    let name: Option<String> = row.try_get("resource_name").map_err(|e| map_err(&e))?;
    let scopes: Option<String> = row.try_get("scopes").map_err(|e| map_err(&e))?;

    let uri = ResourceUri::parse(&raw).map_err(|_| StoreError::Unavailable)?;
    Ok(ProtectedResource { uri, name, scopes })
}

impl BackchannelStore for PostgresStore {
    async fn create_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        request: &BackchannelRequest,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO backchannel_requests \
             (tenant_id, auth_req_hash, client_id, user_id, scope, resources, \
              state, issued_at, expires_at, poll_interval) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)",
        )
        .bind(tenant.as_uuid())
        .bind(auth_req_hash.as_slice())
        .bind(request.client.as_str())
        .bind(request.subject.as_uuid())
        .bind(request.scope.as_deref())
        .bind(join_resources(&request.resources))
        .bind(to_dt(request.issued_at))
        .bind(to_dt(request.expires_at))
        .bind(i32::try_from(request.interval.as_seconds()).unwrap_or(5))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn load_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
    ) -> Result<BackchannelRequest, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT client_id, user_id, scope, resources, state, issued_at, \
                    expires_at, poll_interval, last_polled_at \
             FROM backchannel_requests WHERE tenant_id = $1 AND auth_req_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(auth_req_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?
        .ok_or(StoreError::NotFound)?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let client_id: String = row.try_get("client_id").map_err(|e| map_err(&e))?;
        let user_id: uuid::Uuid = row.try_get("user_id").map_err(|e| map_err(&e))?;
        let scope: Option<String> = row.try_get("scope").map_err(|e| map_err(&e))?;
        let raw_resources: Option<String> = row.try_get("resources").map_err(|e| map_err(&e))?;
        let raw_state: String = row.try_get("state").map_err(|e| map_err(&e))?;
        let issued: chrono::DateTime<chrono::Utc> =
            row.try_get("issued_at").map_err(|e| map_err(&e))?;
        let expires: chrono::DateTime<chrono::Utc> =
            row.try_get("expires_at").map_err(|e| map_err(&e))?;
        let interval: i32 = row.try_get("poll_interval").map_err(|e| map_err(&e))?;
        let last_polled: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("last_polled_at").map_err(|e| map_err(&e))?;

        let state = match raw_state.as_str() {
            "pending" => BackchannelState::Pending,
            "approved" => BackchannelState::Approved,
            "denied" => BackchannelState::Denied,
            "consumed" => BackchannelState::Consumed,
            _ => return Err(StoreError::Unavailable),
        };

        let mut resources = Vec::new();
        for value in raw_resources.as_deref().unwrap_or_default().split(' ') {
            if value.is_empty() {
                continue;
            }
            resources.push(ResourceUri::parse(value).map_err(|_| StoreError::Unavailable)?);
        }

        Ok(BackchannelRequest {
            tenant,
            client: ClientId::new(client_id).map_err(|_| StoreError::Unavailable)?,
            subject: UserId::from_uuid(user_id),
            scope,
            resources,
            state,
            issued_at: from_dt(issued),
            expires_at: from_dt(expires),
            interval: argus_core::time::Duration::from_seconds(i64::from(interval)),
            last_polled_at: last_polled.map(from_dt),
        })
    }

    async fn record_backchannel_poll(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "UPDATE backchannel_requests SET last_polled_at = $3 \
             WHERE tenant_id = $1 AND auth_req_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(auth_req_hash.as_slice())
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn consume_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<bool, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let result = sqlx::query(
            "UPDATE backchannel_requests SET state = 'consumed', decided_at = $3 \
             WHERE tenant_id = $1 AND auth_req_hash = $2 AND state = 'approved'",
        )
        .bind(tenant.as_uuid())
        .bind(auth_req_hash.as_slice())
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;
        Ok(result.rows_affected() == 1)
    }

    async fn decide_backchannel(
        &self,
        tenant: TenantId,
        auth_req_hash: &[u8; 32],
        approved: bool,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "UPDATE backchannel_requests SET state = $3, decided_at = $4 \
             WHERE tenant_id = $1 AND auth_req_hash = $2 AND state = 'pending'",
        )
        .bind(tenant.as_uuid())
        .bind(auth_req_hash.as_slice())
        .bind(if approved { "approved" } else { "denied" })
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }
}

fn join_resources(resources: &[ResourceUri]) -> Option<String> {
    if resources.is_empty() {
        return None;
    }
    Some(
        resources
            .iter()
            .map(ResourceUri::as_str)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

impl AuthnStore for PostgresStore {
    async fn find_user_by_blind_index(
        &self,
        tenant: TenantId,
        blind_index: &[u8; 32],
    ) -> Result<Option<UserId>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT user_id FROM users \
             WHERE tenant_id = $1 AND email_blind_index = $2",
        )
        .bind(tenant.as_uuid())
        .bind(blind_index.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let Some(row) = row else {
            return Ok(None);
        };
        let id: uuid::Uuid = row.try_get("user_id").map_err(|e| map_err(&e))?;
        Ok(Some(UserId::from_uuid(id)))
    }

    async fn create_user(
        &self,
        tenant: TenantId,
        user: UserId,
        blind_index: &[u8; 32],
        email_ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id) \
             VALUES ($1, $2, $3, 'bootstrap')",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .bind([0u8; 1].as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        sqlx::query(
            "INSERT INTO users (tenant_id, user_id, email_ciphertext, email_blind_index) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .bind(email_ciphertext)
        .bind(blind_index.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn password_of(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<String>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT phc FROM password_credentials WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(row.try_get("phc").map_err(|e| map_err(&e))?))
    }

    async fn set_password(
        &self,
        tenant: TenantId,
        user: UserId,
        phc: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO password_credentials (tenant_id, user_id, phc) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id, user_id) DO UPDATE SET phc = $3, updated_at = now()",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .bind(phc)
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn required_aal(&self, tenant: TenantId, user: UserId) -> Result<Aal, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT required_aal::text FROM users WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?
        .ok_or(StoreError::NotFound)?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let raw: String = row.try_get("required_aal").map_err(|e| map_err(&e))?;
        Aal::parse(&raw).ok_or(StoreError::Unavailable)
    }

    async fn webauthn_credentials(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<String>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT public_key FROM webauthn_credentials \
             WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let raw: Vec<u8> = row.try_get("public_key").map_err(|e| map_err(&e))?;
            out.push(String::from_utf8(raw).map_err(|_| StoreError::Unavailable)?);
        }
        Ok(out)
    }

    async fn store_webauthn_credential(
        &self,
        tenant: TenantId,
        user: UserId,
        credential_id: &[u8],
        rp_id: &str,
        serialised: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO webauthn_credentials \
             (tenant_id, credential_id, user_id, rp_id, public_key) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant.as_uuid())
        .bind(credential_id)
        .bind(user.as_uuid())
        .bind(rp_id)
        .bind(serialised.as_bytes())
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn user_for_credential(
        &self,
        tenant: TenantId,
        credential_id: &[u8],
    ) -> Result<Option<UserId>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT user_id FROM webauthn_credentials \
             WHERE tenant_id = $1 AND credential_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(credential_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let Some(row) = row else {
            return Ok(None);
        };
        let id: uuid::Uuid = row.try_get("user_id").map_err(|e| map_err(&e))?;
        Ok(Some(UserId::from_uuid(id)))
    }

    async fn advance_sign_count(
        &self,
        tenant: TenantId,
        credential_id: &[u8],
        counter: i64,
        at: Timestamp,
    ) -> Result<bool, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let result = sqlx::query(
            "UPDATE webauthn_credentials SET sign_count = $3, last_used_at = $4 \
             WHERE tenant_id = $1 AND credential_id = $2 \
               AND ($3 = 0 OR $3 > sign_count)",
        )
        .bind(tenant.as_uuid())
        .bind(credential_id)
        .bind(counter)
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;
        Ok(result.rows_affected() == 1)
    }
}

impl CeremonyStore for PostgresStore {
    async fn store_ceremony(
        &self,
        tenant: TenantId,
        ceremony_hash: &[u8; 32],
        ceremony: &PendingCeremony<'_>,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO webauthn_ceremonies \
             (tenant_id, ceremony_hash, user_id, purpose, state, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant.as_uuid())
        .bind(ceremony_hash.as_slice())
        .bind(ceremony.user.map(UserId::as_uuid))
        .bind(ceremony.purpose.as_str())
        .bind(ceremony.state)
        .bind(to_dt(ceremony.issued_at))
        .bind(to_dt(ceremony.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn take_ceremony(
        &self,
        tenant: TenantId,
        ceremony_hash: &[u8; 32],
        purpose: CeremonyPurpose,
        now: Timestamp,
    ) -> Result<(Option<UserId>, String), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "DELETE FROM webauthn_ceremonies \
             WHERE tenant_id = $1 AND ceremony_hash = $2 AND purpose = $3 AND expires_at > $4 \
             RETURNING user_id, state",
        )
        .bind(tenant.as_uuid())
        .bind(ceremony_hash.as_slice())
        .bind(purpose.as_str())
        .bind(to_dt(now))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?
        .ok_or(StoreError::NotFound)?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let user: Option<uuid::Uuid> = row.try_get("user_id").map_err(|e| map_err(&e))?;
        let state: String = row.try_get("state").map_err(|e| map_err(&e))?;
        Ok((user.map(UserId::from_uuid), state))
    }
}

impl RecoveryStore for PostgresStore {
    async fn open_recovery(
        &self,
        tenant: TenantId,
        attempt_id: uuid::Uuid,
        attempt: &RecoveryAttempt,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO recovery_attempts \
             (tenant_id, attempt_id, user_id, state, required_aal) \
             VALUES ($1, $2, $3, $4, $5::aal)",
        )
        .bind(tenant.as_uuid())
        .bind(attempt_id)
        .bind(attempt.subject.as_uuid())
        .bind(attempt.state.as_str())
        .bind(attempt.required.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn load_recovery(
        &self,
        tenant: TenantId,
        attempt_id: uuid::Uuid,
    ) -> Result<RecoveryAttempt, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT user_id, state, achieved_aal::text, required_aal::text, \
                    evidence_consumed, cooldown_until, grace_until \
             FROM recovery_attempts WHERE tenant_id = $1 AND attempt_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(attempt_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?
        .ok_or(StoreError::NotFound)?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let user: uuid::Uuid = row.try_get("user_id").map_err(|e| map_err(&e))?;
        let raw_state: String = row.try_get("state").map_err(|e| map_err(&e))?;
        let achieved: Option<String> = row.try_get("achieved_aal").map_err(|e| map_err(&e))?;
        let required: Option<String> = row.try_get("required_aal").map_err(|e| map_err(&e))?;
        let consumed: bool = row.try_get("evidence_consumed").map_err(|e| map_err(&e))?;
        let cooldown: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("cooldown_until").map_err(|e| map_err(&e))?;
        let grace: Option<chrono::DateTime<chrono::Utc>> =
            row.try_get("grace_until").map_err(|e| map_err(&e))?;

        let state = match raw_state.as_str() {
            "requested" => RecoveryState::Requested,
            "evidence_met" => RecoveryState::EvidenceMet,
            "cooling_down" => RecoveryState::CoolingDown,
            "rebind_open" => RecoveryState::RebindOpen,
            "grace_period" => RecoveryState::GracePeriod,
            "closed" => RecoveryState::Closed,
            "denied" => RecoveryState::Denied,
            "throttled" => RecoveryState::Throttled,
            "locked" => RecoveryState::Locked,
            _ => return Err(StoreError::Unavailable),
        };

        Ok(RecoveryAttempt {
            subject: UserId::from_uuid(user),
            state,
            required: required.as_deref().and_then(Aal::parse).unwrap_or(Aal::One),
            achieved: achieved.as_deref().and_then(Aal::parse),
            evidence_consumed: consumed,
            cooldown_until: cooldown.map(from_dt),
            grace_until: grace.map(from_dt),
        })
    }

    async fn advance_recovery(
        &self,
        tenant: TenantId,
        attempt_id: uuid::Uuid,
        attempt: &RecoveryAttempt,
        at: Timestamp,
    ) -> Result<bool, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let result = sqlx::query(
            "UPDATE recovery_attempts SET state = $3, achieved_aal = $4::aal, \
                    evidence_consumed = $5, cooldown_until = $6, grace_until = $7, \
                    state_changed_at = $8 \
             WHERE tenant_id = $1 AND attempt_id = $2 AND evidence_consumed = false \
             OR (tenant_id = $1 AND attempt_id = $2 AND $5 = evidence_consumed)",
        )
        .bind(tenant.as_uuid())
        .bind(attempt_id)
        .bind(attempt.state.as_str())
        .bind(attempt.achieved.map(Aal::as_str))
        .bind(attempt.evidence_consumed)
        .bind(attempt.cooldown_until.map(to_dt))
        .bind(attempt.grace_until.map(to_dt))
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;
        Ok(result.rows_affected() == 1)
    }
}

impl SessionStore for PostgresStore {
    async fn create_session(
        &self,
        tenant: TenantId,
        session_hash: &[u8; 32],
        session: &AuthnSession,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO authn_sessions \
             (tenant_id, session_hash, user_id, achieved_aal, authenticated_at, expires_at) \
             VALUES ($1, $2, $3, $4::aal, $5, $6)",
        )
        .bind(tenant.as_uuid())
        .bind(session_hash.as_slice())
        .bind(session.subject.as_uuid())
        .bind(session.achieved.as_str())
        .bind(to_dt(session.authenticated_at))
        .bind(to_dt(session.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }

    async fn load_session(
        &self,
        tenant: TenantId,
        session_hash: &[u8; 32],
        now: Timestamp,
    ) -> Result<AuthnSession, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT user_id, achieved_aal::text, authenticated_at, expires_at \
             FROM authn_sessions \
             WHERE tenant_id = $1 AND session_hash = $2 \
               AND revoked_at IS NULL AND expires_at > $3",
        )
        .bind(tenant.as_uuid())
        .bind(session_hash.as_slice())
        .bind(to_dt(now))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?
        .ok_or(StoreError::NotFound)?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let user: uuid::Uuid = row.try_get("user_id").map_err(|e| map_err(&e))?;
        let raw_aal: String = row.try_get("achieved_aal").map_err(|e| map_err(&e))?;
        let authenticated: chrono::DateTime<chrono::Utc> =
            row.try_get("authenticated_at").map_err(|e| map_err(&e))?;
        let expires: chrono::DateTime<chrono::Utc> =
            row.try_get("expires_at").map_err(|e| map_err(&e))?;

        Ok(AuthnSession {
            subject: UserId::from_uuid(user),
            achieved: Aal::parse(&raw_aal).ok_or(StoreError::Unavailable)?,
            authenticated_at: from_dt(authenticated),
            expires_at: from_dt(expires),
        })
    }

    async fn revoke_session(
        &self,
        tenant: TenantId,
        session_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "UPDATE authn_sessions SET revoked_at = $3 \
             WHERE tenant_id = $1 AND session_hash = $2 AND revoked_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(session_hash.as_slice())
        .bind(to_dt(at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))
    }
}

impl IssuerStore for PostgresStore {
    async fn trusted_issuers(&self, tenant: TenantId) -> Result<Vec<TrustedIssuer>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT i.issuer, k.kid, k.x, k.y FROM trusted_issuers i \
             LEFT JOIN trusted_issuer_keys k \
               ON k.tenant_id = i.tenant_id AND k.issuer = i.issuer \
             WHERE i.tenant_id = $1 ORDER BY i.issuer, k.kid",
        )
        .bind(tenant.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let mut out: Vec<TrustedIssuer> = Vec::new();
        for row in &rows {
            let issuer: String = row.try_get("issuer").map_err(|e| map_err(&e))?;
            let kid: Option<String> = row.try_get("kid").map_err(|e| map_err(&e))?;

            if !out.iter().any(|i| i.issuer == issuer) {
                out.push(TrustedIssuer {
                    issuer: issuer.clone(),
                    keys: Vec::new(),
                });
            }

            let Some(kid) = kid else {
                continue;
            };
            let x: Vec<u8> = row.try_get("x").map_err(|e| map_err(&e))?;
            let y: Vec<u8> = row.try_get("y").map_err(|e| map_err(&e))?;
            let (Ok(x), Ok(y)) = (<[u8; 32]>::try_from(x), <[u8; 32]>::try_from(y)) else {
                return Err(StoreError::Unavailable);
            };

            if let Some(entry) = out.iter_mut().find(|i| i.issuer == issuer) {
                entry.keys.push(ClientKey { kid, x, y });
            }
        }

        Ok(out)
    }
}

impl ConnectionStore for PostgresStore {
    async fn find_connection(
        &self,
        tenant: TenantId,
        client: &ClientId,
        resource_as_issuer: &str,
    ) -> Result<Option<CrossAppConnection>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let row = sqlx::query(
            "SELECT resource_uri, allowed_scopes FROM cross_app_connections \
             WHERE tenant_id = $1 AND requesting_client_id = $2 AND resource_as_issuer = $3",
        )
        .bind(tenant.as_uuid())
        .bind(client.as_str())
        .bind(resource_as_issuer)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let raw_resource: Option<String> = row.try_get("resource_uri").map_err(|e| map_err(&e))?;
        let allowed: String = row.try_get("allowed_scopes").map_err(|e| map_err(&e))?;

        let resource = match raw_resource {
            Some(raw) => Some(ResourceUri::parse(&raw).map_err(|_| StoreError::Unavailable)?),
            None => None,
        };

        Ok(Some(CrossAppConnection {
            requesting_client: client.clone(),
            resource_as_issuer: resource_as_issuer.to_owned(),
            resource,
            allowed_scopes: allowed
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        }))
    }
}

impl ReplayStore for PostgresStore {
    async fn consume_jti(
        &self,
        tenant: TenantId,
        purpose: JtiPurpose,
        jti: &str,
        expires_at: Timestamp,
    ) -> Result<JtiOutcome, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let result = sqlx::query(
            "INSERT INTO consumed_jtis (tenant_id, purpose, jti, expires_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(purpose.as_str())
        .bind(jti)
        .bind(to_dt(expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;

        if result.rows_affected() == 0 {
            Ok(JtiOutcome::Replayed)
        } else {
            Ok(JtiOutcome::Fresh)
        }
    }

    async fn purge_expired_jtis(
        &self,
        tenant: TenantId,
        now: Timestamp,
    ) -> Result<u64, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let result = sqlx::query("DELETE FROM consumed_jtis WHERE expires_at <= $1")
            .bind(to_dt(now))
            .execute(&mut *tx)
            .await
            .map_err(|e| map_err(&e))?;

        tx.commit().await.map_err(|e| map_err(&e))?;
        Ok(result.rows_affected())
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
