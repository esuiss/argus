use std::collections::HashMap;

use argus_core::id::TenantId;
use argus_core::ldap::{Group, Person};
use serde_json::Value;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use crate::traits::StoreError;

type Loaded = (Vec<Person>, Vec<Group>, HashMap<String, String>);

fn text(payload: &Value, attribute: &str) -> Option<String> {
    payload
        .get(attribute)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn primary_email(payload: &Value) -> Option<String> {
    let emails = payload.get("emails")?.as_array()?;

    emails
        .iter()
        .find(|entry| entry.get("primary").and_then(Value::as_bool) == Some(true))
        .or_else(|| emails.first())
        .and_then(|entry| entry.get("value"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[allow(
    clippy::too_many_lines,
    reason = "the directory is read in one transaction so every projection sees one snapshot"
)]
pub async fn load(pool: &PgPool, tenant: TenantId) -> Result<Loaded, StoreError> {
    let mut tx = pool.begin().await.map_err(|_| StoreError::Unavailable)?;

    sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")
        .bind(tenant.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| StoreError::Unavailable)?;

    let user_rows = sqlx::query(
        "SELECT user_id, user_name, active, payload FROM scim_users WHERE tenant_id = $1 \
         ORDER BY create_seq",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| StoreError::Unavailable)?;

    let group_rows = sqlx::query(
        "SELECT group_id, display_name, payload FROM scim_groups WHERE tenant_id = $1 \
         ORDER BY create_seq",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| StoreError::Unavailable)?;

    let member_rows = sqlx::query(
        "SELECT g.display_name AS group_name, u.user_name AS member_name \
           FROM scim_group_members m \
           JOIN scim_groups g ON g.tenant_id = m.tenant_id AND g.group_id = m.group_id \
           JOIN scim_users  u ON u.tenant_id = m.tenant_id AND u.user_id = m.member_user_id \
          WHERE m.tenant_id = $1 AND m.member_user_id IS NOT NULL",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| StoreError::Unavailable)?;

    let nested_rows = sqlx::query(
        "SELECT parent.display_name AS group_name, child.display_name AS member_name \
           FROM scim_group_members m \
           JOIN scim_groups parent ON parent.tenant_id = m.tenant_id AND parent.group_id = m.group_id \
           JOIN scim_groups child  ON child.tenant_id = m.tenant_id AND child.group_id = m.member_group_id \
          WHERE m.tenant_id = $1 AND m.member_group_id IS NOT NULL",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| StoreError::Unavailable)?;

    let credential_rows = sqlx::query(
        "SELECT c.user_id, c.phc FROM password_credentials c \
           JOIN scim_users u ON u.tenant_id = c.tenant_id AND u.user_id = c.user_id \
          WHERE c.tenant_id = $1",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| StoreError::Unavailable)?;

    tx.commit().await.map_err(|_| StoreError::Unavailable)?;

    let mut membership: HashMap<String, Vec<String>> = HashMap::new();
    let mut reverse: HashMap<String, Vec<String>> = HashMap::new();

    for row in &member_rows {
        let group: String = row
            .try_get("group_name")
            .map_err(|_| StoreError::Unavailable)?;
        let member: String = row
            .try_get("member_name")
            .map_err(|_| StoreError::Unavailable)?;
        membership
            .entry(group.clone())
            .or_default()
            .push(member.clone());
        reverse.entry(member).or_default().push(group);
    }

    let mut nested: HashMap<String, Vec<String>> = HashMap::new();
    for row in &nested_rows {
        let group: String = row
            .try_get("group_name")
            .map_err(|_| StoreError::Unavailable)?;
        let member: String = row
            .try_get("member_name")
            .map_err(|_| StoreError::Unavailable)?;
        nested.entry(group).or_default().push(member);
    }

    let mut identifiers: HashMap<Uuid, String> = HashMap::new();
    let mut people = Vec::with_capacity(user_rows.len());

    for row in &user_rows {
        let user_id: Uuid = row
            .try_get("user_id")
            .map_err(|_| StoreError::Unavailable)?;
        let user_name: String = row
            .try_get("user_name")
            .map_err(|_| StoreError::Unavailable)?;
        let active: bool = row.try_get("active").map_err(|_| StoreError::Unavailable)?;
        let payload: Value = row
            .try_get("payload")
            .map_err(|_| StoreError::Unavailable)?;

        let display_name = text(&payload, "displayName").unwrap_or_else(|| user_name.clone());
        let family = payload
            .get("name")
            .and_then(|name| name.get("familyName"))
            .and_then(Value::as_str)
            .unwrap_or(&user_name)
            .to_owned();
        let given = payload
            .get("name")
            .and_then(|name| name.get("givenName"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();

        identifiers.insert(user_id, user_name.clone());

        people.push(Person {
            uuid: *user_id.as_bytes(),
            uid: user_name.clone(),
            display_name,
            surname: family,
            given_name: given,
            mail: primary_email(&payload),
            active,
            groups: reverse.remove(&user_name).unwrap_or_default(),
        });
    }

    let mut groups = Vec::with_capacity(group_rows.len());
    for row in &group_rows {
        let group_id: Uuid = row
            .try_get("group_id")
            .map_err(|_| StoreError::Unavailable)?;
        let display_name: String = row
            .try_get("display_name")
            .map_err(|_| StoreError::Unavailable)?;
        let payload: Value = row
            .try_get("payload")
            .map_err(|_| StoreError::Unavailable)?;

        groups.push(Group {
            uuid: *group_id.as_bytes(),
            name: display_name.clone(),
            description: text(&payload, "description"),
            member_uids: membership.remove(&display_name).unwrap_or_default(),
            member_groups: nested.remove(&display_name).unwrap_or_default(),
        });
    }

    let mut passwords = HashMap::new();
    for row in &credential_rows {
        let user_id: Uuid = row
            .try_get("user_id")
            .map_err(|_| StoreError::Unavailable)?;
        let phc: String = row.try_get("phc").map_err(|_| StoreError::Unavailable)?;

        if let Some(uid) = identifiers.get(&user_id) {
            passwords.insert(uid.to_lowercase(), phc);
        }
    }

    Ok((people, groups, passwords))
}
