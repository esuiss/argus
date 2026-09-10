use sqlx::{PgPool, Row as _};

pub const EXPECTED_MIGRATIONS: &[&str] = &[
    "0001_baseline",
    "0002_audit",
    "0003_oauth_grants",
    "0004_oidc_code_claims",
    "0005_client_authentication",
    "0006_redirect_uri_scheme",
    "0007_consumed_jtis",
    "0008_schema_migrations",
    "0009_protected_resources",
    "0010_code_resources",
    "0011_cross_app_connections",
    "0012_backchannel_requests",
    "0013_trusted_issuers",
    "0014_authentication",
    "0015_sessions_and_ceremonies",
    "0016_scim",
    "0017_vault",
    "0018_pushed_requests",
    "0019_federation_subordinates",
    "0020_authz_tuples",
    "0021_admin_api",
    "0022_platform_role",
    "0023_audit_checkpoints",
    "0024_themes",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("the schema ledger is unreachable; the database may not be migrated at all")]
    LedgerUnreadable,

    #[error("the database is missing migrations: {missing}")]
    Missing { missing: String },

    #[error("the database has migrations this build does not know about: {unknown}")]
    Unknown { unknown: String },
}

pub async fn validate(pool: &PgPool) -> Result<(), SchemaError> {
    let rows = sqlx::query("SELECT name FROM argus_meta.schema_migrations")
        .fetch_all(pool)
        .await
        .map_err(|_| SchemaError::LedgerUnreadable)?;

    let mut applied: Vec<String> = Vec::with_capacity(rows.len());
    for row in rows {
        applied.push(
            row.try_get("name")
                .map_err(|_| SchemaError::LedgerUnreadable)?,
        );
    }

    compare(&applied)
}

pub fn compare(applied: &[String]) -> Result<(), SchemaError> {
    let missing: Vec<&str> = EXPECTED_MIGRATIONS
        .iter()
        .copied()
        .filter(|expected| !applied.iter().any(|a| a == expected))
        .collect();

    if !missing.is_empty() {
        return Err(SchemaError::Missing {
            missing: missing.join(", "),
        });
    }

    let unknown: Vec<&str> = applied
        .iter()
        .map(String::as_str)
        .filter(|a| !EXPECTED_MIGRATIONS.contains(a))
        .collect();

    if !unknown.is_empty() {
        return Err(SchemaError::Unknown {
            unknown: unknown.join(", "),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{EXPECTED_MIGRATIONS, SchemaError, compare};

    fn all() -> Vec<String> {
        EXPECTED_MIGRATIONS
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    #[test]
    fn an_exactly_migrated_database_passes() {
        assert_eq!(compare(&all()), Ok(()));
    }

    #[test]
    fn order_does_not_matter() {
        let mut applied = all();
        applied.reverse();
        assert_eq!(compare(&applied), Ok(()));
    }

    #[test]
    fn a_missing_migration_is_named() {
        let applied: Vec<String> = all()
            .into_iter()
            .filter(|m| m != "0007_consumed_jtis")
            .collect();
        assert_eq!(
            compare(&applied),
            Err(SchemaError::Missing {
                missing: "0007_consumed_jtis".to_owned()
            })
        );
    }

    #[test]
    fn every_missing_migration_is_reported_not_just_the_first() {
        let applied: Vec<String> = all()
            .into_iter()
            .filter(|m| m != "0006_redirect_uri_scheme" && m != "0007_consumed_jtis")
            .collect();
        let Err(SchemaError::Missing { missing }) = compare(&applied) else {
            panic!("must report missing migrations");
        };
        assert!(missing.contains("0006_redirect_uri_scheme"));
        assert!(missing.contains("0007_consumed_jtis"));
    }

    #[test]
    fn an_empty_database_is_refused() {
        assert!(matches!(compare(&[]), Err(SchemaError::Missing { .. })));
    }

    #[test]
    fn a_newer_database_than_this_build_is_refused() {
        let mut applied = all();
        applied.push("0009_from_the_future".to_owned());
        assert_eq!(
            compare(&applied),
            Err(SchemaError::Unknown {
                unknown: "0009_from_the_future".to_owned()
            })
        );
    }
}
