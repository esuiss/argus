use argus_core::id::TenantId;
use argus_core::theme::{Link, Theme};
use serde_json::Value;
use sqlx::Row as _;

use crate::postgres::PostgresStore;
use crate::traits::StoreError;

// §1 K29: tema veritabanında saklanır ama istek başına buradan OKUNMAZ.
// Başlangıçta kayıt defterine yüklenir; render başına yapılan iş bir map
// aramasıdır. Değişiklikten sonra yönetim ucu o kiracının girdisini tazeler.

/// Kiracının varsayılan teması. §1 K29: istemciye özel tema bunun üstüne biner.
pub const TENANT_DEFAULT: &str = "";

fn strings_of(value: &Value) -> std::collections::BTreeMap<String, String> {
    value
        .as_object()
        .map(|members| {
            members
                .iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn links_of(value: &Value) -> Vec<Link> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(Link {
                        label: item.get("label")?.as_str()?.to_owned(),
                        url: item.get("url")?.as_str()?.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn row_to_theme(row: &sqlx::postgres::PgRow) -> Result<(String, Theme), StoreError> {
    let client_id: String = row
        .try_get("client_id")
        .map_err(|_| StoreError::Unavailable)?;

    Ok((
        client_id,
        Theme {
            name: row.try_get("name").map_err(|_| StoreError::Unavailable)?,
            logo_url: row.try_get("logo_url").ok().flatten(),
            primary_colour: row.try_get("primary_colour").ok().flatten(),
            background_colour: row.try_get("background_colour").ok().flatten(),
            shell: row.try_get("shell").ok().flatten(),
            strings: row
                .try_get::<Value, _>("strings")
                .map(|v| strings_of(&v))
                .unwrap_or_default(),
            footer_links: row
                .try_get::<Value, _>("footer_links")
                .map(|v| links_of(&v))
                .unwrap_or_default(),
        },
    ))
}

impl PostgresStore {
    /// Bir kiracının bütün temaları: varsayılan ve istemciye özel olanlar.
    /// Kayıt defteri bunu başlangıçta ve tazelemede çağırır.
    pub async fn themes_of(&self, tenant: TenantId) -> Result<Vec<(String, Theme)>, StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let rows = sqlx::query(
            "SELECT client_id, name, logo_url, primary_colour, background_colour, \
                    shell, strings, footer_links \
               FROM themes WHERE tenant_id = $1 ORDER BY client_id",
        )
        .bind(tenant.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)?;

        rows.iter().map(row_to_theme).collect()
    }

    /// Temayı yazar. §1 K28: kabuk saklanmadan önce çağıran tarafından
    /// doğrulanır; reddedilen bir tema hiç saklanmaz.
    pub async fn save_theme(
        &self,
        tenant: TenantId,
        client_id: &str,
        theme: &Theme,
    ) -> Result<(), StoreError> {
        let strings = serde_json::to_value(&theme.strings).unwrap_or(Value::Null);
        let links = Value::Array(
            theme
                .footer_links
                .iter()
                .map(|l| serde_json::json!({ "label": l.label, "url": l.url }))
                .collect(),
        );

        let mut tx = self.scoped(tenant).await?;

        sqlx::query(
            "INSERT INTO themes \
               (tenant_id, client_id, name, logo_url, primary_colour, \
                background_colour, shell, strings, footer_links) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (tenant_id, client_id) DO UPDATE SET \
               name = EXCLUDED.name, \
               logo_url = EXCLUDED.logo_url, \
               primary_colour = EXCLUDED.primary_colour, \
               background_colour = EXCLUDED.background_colour, \
               shell = EXCLUDED.shell, \
               strings = EXCLUDED.strings, \
               footer_links = EXCLUDED.footer_links, \
               updated_at = now()",
        )
        .bind(tenant.as_uuid())
        .bind(client_id)
        .bind(&theme.name)
        .bind(theme.logo_url.as_ref())
        .bind(theme.primary_colour.as_ref())
        .bind(theme.background_colour.as_ref())
        .bind(theme.shell.as_ref())
        .bind(strings)
        .bind(links)
        .execute(&mut *tx)
        .await
        // Şema son kapıdır: https olmayan bir logo ya da onaltılık olmayan bir
        // renk buraya kadar gelirse CHECK reddeder.
        .map_err(|_| StoreError::NotFound)?;

        tx.commit().await.map_err(|_| StoreError::Unavailable)
    }

    pub async fn delete_theme(&self, tenant: TenantId, client_id: &str) -> Result<(), StoreError> {
        let mut tx = self.scoped(tenant).await?;

        let affected = sqlx::query("DELETE FROM themes WHERE tenant_id = $1 AND client_id = $2")
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
