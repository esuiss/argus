#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_store::EXPECTED_MIGRATIONS;
use sqlx::postgres::PgPoolOptions;

#[test]
fn the_expected_list_matches_the_migrations_on_disk() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");

    let mut on_disk: Vec<String> = std::fs::read_dir(dir)
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("sql") {
                return None;
            }
            path.file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .map(str::to_owned)
        })
        .collect();
    on_disk.sort();

    let expected: Vec<String> = EXPECTED_MIGRATIONS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        on_disk, expected,
        "EXPECTED_MIGRATIONS has drifted from the migrations directory"
    );
}

#[test]
fn every_migration_is_registered_in_the_ledger() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/0008_schema_migrations.sql"
    );
    let sql = std::fs::read_to_string(path).expect("ledger migration");

    for name in EXPECTED_MIGRATIONS {
        assert!(
            sql.contains(&format!("('{name}')")),
            "{name} is not inserted into argus_meta.schema_migrations"
        );
    }
}

#[tokio::test]
async fn a_fully_migrated_database_validates() {
    let Ok(url) = std::env::var("ARGUS_TEST_DATABASE_URL") else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let Ok(pool) = PgPoolOptions::new().max_connections(1).connect(&url).await else {
        return;
    };

    argus_store::schema::validate(&pool)
        .await
        .expect("a migrated database must validate");
}
