//! `PostgresStore`'un gerçek `PostgreSQL`'e karşı davranışı.
//!
//! # Neden gerçek veritabanı
//!
//! Bu katmanın işi SQL yazmak. Sahte bir depoyla test etmek, tam olarak test
//! edilmesi gereken şeyi (sorguların doğruluğu, `RLS`'in devrede olması,
//! transaction sınırları) atlamak olurdu. Faz 0'da `FORCE ROW LEVEL SECURITY`
//! ile ilgili iki gerçek açık ancak canlı veritabanına karşı koşunca çıkmıştı.
//!
//! `ARGUS_TEST_DATABASE_URL` ayarlı değilse testler **atlanır**, başarısız
//! olmaz: veritabanı olmayan bir makinede derleme kapısını kırmak istemiyoruz.
//! Kurulum: `./.claude/skills/dogrula/rls-test.sh` kabı ayakta bırakmaz;
//! elle `docker run --name argus-db ... -e POSTGRES_DB=argus_db -p 55432:5432`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::authz_code::{CodeState, StoredCode};
use argus_core::id::{ClientId, TenantId, UserId};
use argus_core::pkce::{CodeChallenge, CodeChallengeMethod};
use argus_core::redirect_uri::RedirectUri;
use argus_core::refresh::{FamilyId, RefreshState, RefreshToken};
use argus_core::time::{Duration, Timestamp};
use argus_store::PostgresStore;
use argus_store::traits::{ClientStore, CodeIssuer, CodeStore, RefreshStore, StoreError};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const NOW: Timestamp = Timestamp::from_unix_seconds(1_700_000_000);

/// Her teste KENDİ kiracısı verilir.
///
/// Testler paralel koşuyor; ortak bir kiracıyı silip yeniden yazmak birbirlerinin
/// verisini yok ederdi. Ayrı kiracılar hem bunu çözüyor hem de kiracı kapsamının
/// gerçekten işlediğini kanıtlıyor.
fn fresh_tenant() -> TenantId {
    TenantId::from_uuid(Uuid::new_v4())
}

fn user() -> UserId {
    UserId::from_uuid(Uuid::from_u128(0xa1))
}

/// `client_id` GLOBAL benzersizdir (§1 #5), bu yüzden kiracıya bağlanıyor.
fn client_of(tenant: TenantId) -> ClientId {
    ClientId::new(format!("c{}", &tenant.as_uuid().simple().to_string()[..8])).expect("client")
}

/// Veritabanı yoksa `None` döner ve test atlanır.
async fn store() -> Option<PostgresStore> {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    Some(PostgresStore::new(pool))
}

/// Verilen kiracı için istemci ve kullanıcı kurar.
async fn seed(tenant: TenantId) {
    let url = std::env::var("ARGUS_TEST_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("pool");

    let slug = format!("t{}", &tenant.as_uuid().simple().to_string()[..8]);
    sqlx::query("INSERT INTO tenants (tenant_id, slug, issuer_host) VALUES ($1, $2, $3)")
        .bind(tenant.as_uuid())
        .bind(&slug)
        .bind(format!("{slug}.test"))
        .execute(&pool)
        .await
        .expect("tenant");

    sqlx::query(
        "INSERT INTO user_keys (tenant_id, user_id, dek_wrapped, kek_id) \
         VALUES ($1, $2, '\\x01', 'k')",
    )
    .bind(tenant.as_uuid())
    .bind(user().as_uuid())
    .execute(&pool)
    .await
    .expect("user key");

    sqlx::query("INSERT INTO users (tenant_id, user_id) VALUES ($1, $2)")
        .bind(tenant.as_uuid())
        .bind(user().as_uuid())
        .execute(&pool)
        .await
        .expect("user");

    // `client_id` GLOBAL benzersiz (§1 #5), bu yüzden kiracıya özgü olmalı.
    sqlx::query(
        "INSERT INTO clients (tenant_id, client_id, client_type) VALUES ($1, $2, 'public')",
    )
    .bind(tenant.as_uuid())
    .bind(client_of(tenant).as_str())
    .execute(&pool)
    .await
    .expect("client");

    sqlx::query(
        "INSERT INTO client_redirect_uris (tenant_id, client_id, redirect_uri) \
         VALUES ($1, $2, 'https://app.example.com/cb')",
    )
    .bind(tenant.as_uuid())
    .bind(client_of(tenant).as_str())
    .execute(&pool)
    .await
    .expect("redirect uri");
}

fn stored_code(tenant: TenantId) -> StoredCode {
    StoredCode {
        tenant,
        client: client_of(tenant),
        subject: user(),
        redirect_uri: RedirectUri::register("https://app.example.com/cb").expect("uri"),
        challenge: CodeChallenge::parse(CodeChallengeMethod::S256, CHALLENGE).expect("challenge"),
        issued_at: NOW,
        expires_at: NOW.saturating_add(Duration::from_seconds(60)),
        state: CodeState::Issued,
    }
}

fn refresh(tenant: TenantId, family: FamilyId, generation: u32) -> RefreshToken {
    RefreshToken {
        tenant,
        client: client_of(tenant),
        subject: user(),
        family,
        generation,
        family_started_at: NOW,
        expires_at: NOW.saturating_add(Duration::from_seconds(86_400)),
        state: RefreshState::Active,
    }
}

#[tokio::test]
async fn authorization_code_round_trips_through_the_database() {
    let Some(s) = store().await else {
        eprintln!("skipped: ARGUS_TEST_DATABASE_URL is not set");
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let hash = [7u8; 32];
    s.issue(t, &hash, &stored_code(t)).await.expect("issue");

    let loaded = CodeStore::load(&s, t, &hash).await.expect("load");
    assert_eq!(loaded.client, client_of(t));
    assert_eq!(loaded.subject, user());
    assert_eq!(loaded.state, CodeState::Issued);
    // PKCE challenge kaydedilip geri okunabilmeli, yoksa doğrulama çalışmaz.
    assert_eq!(loaded.challenge.digest(), stored_code(t).challenge.digest());
    assert_eq!(loaded.redirect_uri.as_str(), "https://app.example.com/cb");
}

/// Tüketim tek yönlüdür ve `WHERE state = 'issued'` sayesinde iki eşzamanlı
/// istek aynı kodu tüketemez.
#[tokio::test]
async fn consuming_a_code_is_idempotent_and_one_way() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let hash = [8u8; 32];
    s.issue(t, &hash, &stored_code(t)).await.expect("issue");

    let at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 5);
    s.consume(t, &hash, at).await.expect("consume");

    let loaded = CodeStore::load(&s, t, &hash).await.expect("load");
    assert_eq!(loaded.state, CodeState::Redeemed { at });

    // İkinci tüketim durumu DEĞİŞTİRMEZ: ilk tüketimin zamanı korunur, yoksa
    // denetim kaydı yanlış anı gösterirdi.
    let later = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 99);
    s.consume(t, &hash, later).await.expect("consume 2");
    assert_eq!(
        CodeStore::load(&s, t, &hash).await.expect("load").state,
        CodeState::Redeemed { at }
    );
}

#[tokio::test]
async fn missing_code_is_not_found_not_unavailable() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    // Ayrım kritik: `NotFound` istemciye `invalid_grant`, `Unavailable` ise
    // 503 olur (§19 §7.1).
    assert_eq!(
        CodeStore::load(&s, t, &[0u8; 32]).await.unwrap_err(),
        StoreError::NotFound
    );
}

#[tokio::test]
async fn refresh_rotation_closes_the_old_and_opens_the_new() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let family = FamilyId::from_uuid(Uuid::from_u128(0xf1));
    let old = [1u8; 32];
    let new = [2u8; 32];

    // İlk token'ı doğrudan yazmak için rotate kullanılıyor: eski hash yoksa
    // UPDATE 0 satır etkiler, INSERT yine de çalışır.
    s.rotate(t, &old, &old, &refresh(t, family, 0), NOW)
        .await
        .expect("seed token");

    let at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 10);
    s.rotate(t, &old, &new, &refresh(t, family, 1), at)
        .await
        .expect("rotate");

    let previous = RefreshStore::load(&s, t, &old).await.expect("load old");
    assert_eq!(previous.state, RefreshState::Rotated { at });

    let current = RefreshStore::load(&s, t, &new).await.expect("load new");
    assert_eq!(current.state, RefreshState::Active);
    assert_eq!(current.generation, 1);
    // Zincir korunmalı: tespit ancak `family_id` aynı kalırsa mümkün.
    assert_eq!(current.family, family);
    // Mutlak ömür rotasyonla YENİLENMEZ.
    assert_eq!(current.family_started_at, NOW);
}

/// RFC 9700 §4.14.2: yeniden kullanım tespit edildiğinde zincirin TAMAMI düşer.
#[tokio::test]
async fn revoking_a_family_takes_every_generation_down() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let family = FamilyId::from_uuid(Uuid::from_u128(0xf2));
    let other_family = FamilyId::from_uuid(Uuid::from_u128(0xf3));

    let hashes: [[u8; 32]; 3] = [[10u8; 32], [11u8; 32], [12u8; 32]];
    for (i, h) in hashes.iter().enumerate() {
        s.rotate(
            t,
            h,
            h,
            &refresh(t, family, u32::try_from(i).unwrap_or(0)),
            NOW,
        )
        .await
        .expect("seed");
    }

    let untouched = [13u8; 32];
    s.rotate(t, &untouched, &untouched, &refresh(t, other_family, 0), NOW)
        .await
        .expect("seed other");

    let at = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 20);
    s.revoke_family(t, family, at).await.expect("revoke");

    for h in &hashes {
        assert_eq!(
            RefreshStore::load(&s, t, h).await.expect("load").state,
            RefreshState::Revoked { at },
            "every generation in the family must be revoked"
        );
    }

    // Başka bir zincire dokunulmamalı.
    assert_eq!(
        RefreshStore::load(&s, t, &untouched)
            .await
            .expect("load")
            .state,
        RefreshState::Active
    );
}

#[tokio::test]
async fn client_lookup_returns_registered_redirect_uris() {
    let Some(s) = store().await else {
        return;
    };
    let t = fresh_tenant();
    seed(t).await;

    let found = s
        .find(t, &client_of(t))
        .await
        .expect("query")
        .expect("client exists");
    assert_eq!(found.client_id, client_of(t));
    assert_eq!(found.redirect_uris.len(), 1);
    assert_eq!(
        found.redirect_uris.first().expect("uri").as_str(),
        "https://app.example.com/cb"
    );

    // Bilinmeyen istemci bir HATA değil: yetkilendirme akışında bu normal bir
    // durumdur ve `Fatal(UnknownClient)` sonucunu doğurur.
    let unknown = ClientId::new("nope").expect("client id");
    assert!(s.find(t, &unknown).await.expect("query").is_none());
}
