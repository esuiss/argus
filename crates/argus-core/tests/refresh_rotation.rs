//! Refresh token rotasyonu ve yeniden kullanım tespitinin kuralları.

// Testlerde `expect`/`panic` serbest: fikstür kurulumu başarısız olursa testin
// durması DOĞRU davranıştır. Üretim kodunda bu lint'ler `deny` olarak kalır.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::effect::Effect;
use argus_core::refresh::{
    DEFAULT_FAMILY_LIFETIME, DEFAULT_TOKEN_LIFETIME, FamilyId, RefreshDecision, RefreshDenial,
    RefreshRequest, RefreshState, RefreshToken, rotate,
};
use argus_core::time::Duration;
use argus_core::{ClientId, TenantId, Timestamp, UserId};
use uuid::Uuid;

const STARTED: Timestamp = Timestamp::from_unix_seconds(1_000_000);

fn tenant_a() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0a))
}

fn tenant_b() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0b))
}

fn subject() -> UserId {
    UserId::from_uuid(Uuid::from_u128(0xa1))
}

fn client_a() -> ClientId {
    ClientId::new("acme-web").expect("valid client_id")
}

fn client_b() -> ClientId {
    ClientId::new("other-app").expect("valid client_id")
}

fn family() -> FamilyId {
    FamilyId::from_uuid(Uuid::from_u128(0xf1))
}

fn token(state: RefreshState, generation: u32) -> RefreshToken {
    RefreshToken {
        tenant: tenant_a(),
        client: client_a(),
        subject: subject(),
        family: family(),
        generation,
        family_started_at: STARTED,
        expires_at: STARTED.saturating_add(DEFAULT_TOKEN_LIFETIME),
        state,
    }
}

fn active() -> RefreshToken {
    token(RefreshState::Active, 0)
}

fn request() -> RefreshRequest {
    RefreshRequest {
        client: client_a(),
        tenant: tenant_a(),
    }
}

fn go(t: &RefreshToken, now: Timestamp) -> RefreshDecision {
    rotate(t, &request(), now, DEFAULT_FAMILY_LIFETIME)
}

fn reason(d: &RefreshDecision) -> &RefreshDenial {
    match d {
        RefreshDecision::Deny { reason, .. } => reason,
        RefreshDecision::Rotate { .. } => panic!("expected a denial, got a rotation"),
    }
}

fn effects(d: &RefreshDecision) -> &[Effect] {
    match d {
        RefreshDecision::Deny { effects, .. } | RefreshDecision::Rotate { effects, .. } => effects,
    }
}

// --- Mutlu yol ------------------------------------------------------------

#[test]
fn active_token_rotates_within_the_same_family() {
    let d = go(&active(), STARTED);

    match &d {
        RefreshDecision::Rotate { grant, .. } => {
            // Zincir DEĞİŞMEZ: tespit ancak zincir kimliği korunursa mümkün.
            assert_eq!(grant.family, family());
            assert_eq!(grant.next_generation, 1);
            assert_eq!(grant.subject, subject());
            assert_eq!(grant.tenant, tenant_a());
        }
        RefreshDecision::Deny { reason, .. } => panic!("expected rotation, denied: {reason:?}"),
    }

    assert!(effects(&d).contains(&Effect::RotateRefreshToken));
}

#[test]
fn generation_increments_along_the_chain() {
    for generation in [0_u32, 1, 7] {
        let d = go(&token(RefreshState::Active, generation), STARTED);
        match d {
            RefreshDecision::Rotate { grant, .. } => {
                assert_eq!(grant.next_generation, generation + 1);
            }
            RefreshDecision::Deny { reason, .. } => {
                panic!("denied at generation {generation}: {reason:?}")
            }
        }
    }
}

// --- Yeniden kullanım: en önemli kural ------------------------------------

/// RFC 9700 §4.14.2: döndürülmüş bir token ikinci kez sunulduğunda sunucu, meşru
/// istemci ile saldırganı ayırt EDEMEZ. Tek güvenli davranış zinciri düşürmektir.
#[test]
fn reusing_a_rotated_token_revokes_the_whole_family() {
    let rotated_at = Timestamp::from_unix_seconds(1_000_500);
    let t = token(RefreshState::Rotated { at: rotated_at }, 3);

    let d = go(&t, Timestamp::from_unix_seconds(1_000_600));

    assert_eq!(
        reason(&d),
        &RefreshDenial::Reused {
            rotated_at,
            generation: 3
        }
    );
    assert!(
        effects(&d).contains(&Effect::RevokeRefreshFamily),
        "reuse must bring the family down, got {:?}",
        effects(&d)
    );
}

/// Süresi dolmuş bir token'ın yeniden sunulması da güvenlik olayıdır. "Zaten
/// süresi dolmuştu" diyerek zincir iptalini atlamak, saldırganın çaldığı token'ı
/// bekletmesini ödüllendirirdi.
#[test]
fn reuse_of_an_expired_rotated_token_still_revokes_the_family() {
    let t = token(
        RefreshState::Rotated {
            at: Timestamp::from_unix_seconds(1_000_500),
        },
        1,
    );

    // Token ömrünün çok ötesinde sunuluyor.
    let far_future = STARTED.saturating_add(Duration::from_seconds(365 * 24 * 60 * 60));
    let d = go(&t, far_future);

    assert!(matches!(reason(&d), RefreshDenial::Reused { .. }));
    assert!(effects(&d).contains(&Effect::RevokeRefreshFamily));
}

/// Zaten iptal edilmiş bir token sunulduğunda zincir tekrar düşürülmez — çoktan
/// düşmüştür — ama denemenin kaydı tutulur.
#[test]
fn presenting_a_revoked_token_is_recorded_but_does_not_re_revoke() {
    let t = token(
        RefreshState::Revoked {
            at: Timestamp::from_unix_seconds(1_000_400),
        },
        2,
    );

    let d = go(&t, Timestamp::from_unix_seconds(1_000_900));

    assert_eq!(reason(&d), &RefreshDenial::Revoked);
    assert!(!effects(&d).contains(&Effect::RevokeRefreshFamily));
    assert!(
        effects(&d)
            .iter()
            .any(|e| matches!(e, Effect::RecordAudit(_)))
    );
}

// --- Bağlama --------------------------------------------------------------

#[test]
fn token_is_bound_to_its_client() {
    let req = RefreshRequest {
        client: client_b(),
        tenant: tenant_a(),
    };
    let d = rotate(&active(), &req, STARTED, DEFAULT_FAMILY_LIFETIME);
    assert_eq!(reason(&d), &RefreshDenial::ClientMismatch);
}

#[test]
fn token_is_bound_to_its_tenant() {
    let req = RefreshRequest {
        client: client_a(),
        tenant: tenant_b(),
    };
    let d = rotate(&active(), &req, STARTED, DEFAULT_FAMILY_LIFETIME);
    assert_eq!(reason(&d), &RefreshDenial::TenantMismatch);
}

// --- Ömür -----------------------------------------------------------------

#[test]
fn token_expiry_is_enforced() {
    let t = active();
    let after = Timestamp::from_unix_seconds(t.expires_at.as_unix_seconds() + 1);
    // Zincir ömrü token ömründen uzun olmalı ki test gerçekten TOKEN süresini ölçsün,
    // zincir süresini değil.
    let long_family = Duration::from_seconds(100 * 365 * 24 * 60 * 60);
    let d = rotate(&t, &request(), after, long_family);
    assert_eq!(reason(&d), &RefreshDenial::Expired);
}

/// Rotasyon tek başına sonsuz erişim üretir; mutlak zincir ömrü bunu keser.
/// Sınır zincirin İLK token'ından sayılır ve rotasyonla yenilenmez.
#[test]
fn absolute_family_lifetime_caps_endless_rotation() {
    // Zincir çoktan ilerlemiş, token'ın kendisi hâlâ taze — ama zincir yaşlı.
    let mut t = token(RefreshState::Active, 99);
    let past_family_deadline = STARTED.saturating_add(DEFAULT_FAMILY_LIFETIME);
    t.expires_at = past_family_deadline.saturating_add(Duration::from_seconds(60 * 60));

    let d = go(
        &t,
        Timestamp::from_unix_seconds(past_family_deadline.as_unix_seconds() + 1),
    );

    assert_eq!(reason(&d), &RefreshDenial::FamilyExpired);
}

#[test]
fn rotation_is_allowed_at_the_exact_family_deadline() {
    let deadline = STARTED.saturating_add(DEFAULT_FAMILY_LIFETIME);
    let mut t = active();
    t.expires_at = deadline.saturating_add(Duration::from_seconds(60));

    assert!(matches!(go(&t, deadline), RefreshDecision::Rotate { .. }));
}

// --- Değişmezler ----------------------------------------------------------

#[test]
fn every_decision_requests_an_audit_record() {
    let wrong_client = RefreshRequest {
        client: client_b(),
        tenant: tenant_a(),
    };

    let decisions = [
        go(&active(), STARTED),
        rotate(&active(), &wrong_client, STARTED, DEFAULT_FAMILY_LIFETIME),
        go(&token(RefreshState::Rotated { at: STARTED }, 0), STARTED),
    ];

    for d in &decisions {
        assert!(
            effects(d)
                .iter()
                .any(|e| matches!(e, Effect::RecordAudit(_))),
            "decision without an audit effect: {d:?}"
        );
    }
}

#[test]
fn all_denials_surface_as_invalid_grant() {
    let wrong_client = RefreshRequest {
        client: client_b(),
        tenant: tenant_a(),
    };

    let denials = [
        rotate(&active(), &wrong_client, STARTED, DEFAULT_FAMILY_LIFETIME),
        go(&token(RefreshState::Rotated { at: STARTED }, 0), STARTED),
        go(&token(RefreshState::Revoked { at: STARTED }, 0), STARTED),
    ];

    for d in &denials {
        assert_eq!(reason(d).oauth_error_code(), "invalid_grant");
    }
}
