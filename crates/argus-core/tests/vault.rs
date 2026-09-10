#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::client_resolution::TrustLevel;
use argus_core::delegation::DelegationRecord;
use argus_core::id::{TenantId, UserId};
use argus_core::time::{Duration, Timestamp};
use argus_core::vault::{
    DEFAULT_LEASE, Lease, MAX_LEASE, READ_SCOPE, Requester, SecretKind, SecretRecord, VaultFault,
    associated_data, lease_lifetime, may_lease, may_redeem, may_release_raw,
};
use uuid::Uuid;

const NOW: Timestamp = Timestamp::from_unix_seconds(1_800_000_000);
const AUDIENCE: &str = "https://books.example.test";

fn tenant() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(1))
}

fn barbara() -> UserId {
    UserId::from_uuid(Uuid::from_u128(7))
}

fn secret() -> SecretRecord {
    SecretRecord {
        tenant: tenant(),
        secret_id: "books-api".to_owned(),
        owner: Some(barbara()),
        audience: AUDIENCE.to_owned(),
        kind: SecretKind::ApiKey,
        required_scope: "books.write".to_owned(),
        expires_at: None,
        revoked: false,
    }
}

fn requester() -> Requester {
    Requester {
        subject: Some(barbara()),
        audience: AUDIENCE.to_owned(),
        granted_scope: vec![READ_SCOPE.to_owned(), "books.write".to_owned()],
        trust_level: TrustLevel::Registered,
        delegation: Vec::new(),
    }
}

fn hop(delegator: &str, delegatee: &str, scope: &[&str]) -> DelegationRecord {
    DelegationRecord {
        delegator_id: delegator.to_owned(),
        delegatee_id: delegatee.to_owned(),
        issued_at: NOW,
        expires_at: Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 3_600),
        scope: scope.iter().map(|s| (*s).to_owned()).collect(),
        floor: None,
        as_signature: "a".to_owned(),
        delegator_signature: "b".to_owned(),
    }
}

#[test]
fn the_owner_holding_both_scopes_may_take_a_lease() {
    may_lease(&secret(), &requester(), NOW).expect("this is the case the vault exists for");
}

#[test]
fn a_caller_without_the_vault_scope_is_refused() {
    let mut caller = requester();
    caller.granted_scope = vec!["books.write".to_owned()];

    assert_eq!(
        may_lease(&secret(), &caller, NOW).unwrap_err(),
        VaultFault::MissingVaultScope
    );
}

#[test]
fn a_caller_without_the_scope_the_secret_demands_is_refused() {
    let mut caller = requester();
    caller.granted_scope = vec![READ_SCOPE.to_owned()];

    assert!(
        matches!(
            may_lease(&secret(), &caller, NOW).unwrap_err(),
            VaultFault::MissingSecretScope { .. }
        ),
        "the vault scope opens the door; the secret's own scope decides which shelf"
    );
}

#[test]
fn a_token_minted_for_another_resource_cannot_reach_this_secret() {
    let mut caller = requester();
    caller.audience = "https://other.example.test".to_owned();

    assert!(
        matches!(
            may_lease(&secret(), &caller, NOW).unwrap_err(),
            VaultFault::WrongAudience { .. }
        ),
        "without this the vault becomes a confused deputy for every resource at once"
    );
}

#[test]
fn another_person_cannot_read_a_secret_that_belongs_to_someone() {
    let mut caller = requester();
    caller.subject = Some(UserId::from_uuid(Uuid::from_u128(8)));

    assert_eq!(
        may_lease(&secret(), &caller, NOW).unwrap_err(),
        VaultFault::NotTheOwner
    );
}

#[test]
fn a_token_with_no_subject_cannot_read_a_secret_that_has_an_owner() {
    let mut caller = requester();
    caller.subject = None;

    assert_eq!(
        may_lease(&secret(), &caller, NOW).unwrap_err(),
        VaultFault::NoSubject
    );
}

#[test]
fn a_tenant_wide_secret_has_no_owner_to_match() {
    let mut record = secret();
    record.owner = None;

    let mut caller = requester();
    caller.subject = None;

    may_lease(&record, &caller, NOW).expect("a service account reads the tenant's own credential");
}

#[test]
fn an_unverified_client_may_never_read_the_vault() {
    let mut caller = requester();
    caller.trust_level = TrustLevel::Unverified;

    assert_eq!(
        may_lease(&secret(), &caller, NOW).unwrap_err(),
        VaultFault::TrustLevelTooLow
    );
}

#[test]
fn a_revoked_or_expired_secret_is_refused() {
    let mut revoked = secret();
    revoked.revoked = true;
    assert_eq!(
        may_lease(&revoked, &requester(), NOW).unwrap_err(),
        VaultFault::Revoked
    );

    let mut stale = secret();
    stale.expires_at = Some(Timestamp::from_unix_seconds(NOW.as_unix_seconds() - 1));
    assert_eq!(
        may_lease(&stale, &requester(), NOW).unwrap_err(),
        VaultFault::Expired
    );
}

#[test]
fn a_delegated_agent_that_lost_the_vault_scope_along_the_way_is_refused() {
    let mut caller = requester();
    caller.delegation = vec![
        hop(
            "user:barbara",
            "agent:orchestrator",
            &[READ_SCOPE, "books.write"],
        ),
        hop("agent:orchestrator", "agent:worker", &["books.write"]),
    ];

    assert_eq!(
        may_lease(&secret(), &caller, NOW).unwrap_err(),
        VaultFault::DelegationNarrowed,
        "the token may still carry the scope, but the chain is what the agent actually holds"
    );
}

#[test]
fn a_delegated_agent_that_kept_the_vault_scope_is_allowed() {
    let mut caller = requester();
    caller.delegation = vec![
        hop(
            "user:barbara",
            "agent:orchestrator",
            &[READ_SCOPE, "books.write"],
        ),
        hop("agent:orchestrator", "agent:worker", &[READ_SCOPE]),
    ];

    may_lease(&secret(), &caller, NOW).expect("the chain still carries it");
}

#[test]
fn an_upstream_refresh_token_is_never_released_in_the_clear() {
    let mut record = secret();
    record.kind = SecretKind::UpstreamRefreshToken;

    may_lease(&record, &requester(), NOW).expect("leasing it is fine");

    assert_eq!(
        may_release_raw(&record).unwrap_err(),
        VaultFault::NotReleasable,
        "the point of holding the long lived credential is that the agent never sees it"
    );
}

#[test]
fn the_other_kinds_may_be_released() {
    for kind in [
        SecretKind::BearerToken,
        SecretKind::ApiKey,
        SecretKind::BasicPassword,
    ] {
        let mut record = secret();
        record.kind = kind;
        may_release_raw(&record)
            .unwrap_or_else(|e| panic!("{} must be releasable: {e}", kind.as_str()));
    }
}

#[test]
fn a_lease_is_bounded_by_the_server_ceiling_whatever_was_asked_for() {
    assert_eq!(lease_lifetime(&secret(), None, NOW), DEFAULT_LEASE);
    assert_eq!(
        lease_lifetime(&secret(), Some(Duration::from_seconds(30)), NOW),
        Duration::from_seconds(30)
    );
    assert_eq!(
        lease_lifetime(&secret(), Some(Duration::from_seconds(86_400)), NOW),
        MAX_LEASE,
        "a caller must not be able to hold a credential open for a day"
    );
    assert_eq!(
        lease_lifetime(&secret(), Some(Duration::from_seconds(0)), NOW),
        MAX_LEASE
    );
}

#[test]
fn a_lease_never_outlives_the_secret_it_points_at() {
    let mut record = secret();
    record.expires_at = Some(Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 20));

    assert_eq!(
        lease_lifetime(&record, Some(Duration::from_seconds(300)), NOW),
        Duration::from_seconds(20)
    );
}

fn lease(spent: bool, offset: i64) -> Lease {
    Lease {
        lease_id: "lease-1".to_owned(),
        secret_id: "books-api".to_owned(),
        holder: "agent:worker".to_owned(),
        issued_at: NOW,
        expires_at: Timestamp::from_unix_seconds(NOW.as_unix_seconds() + offset),
        spent,
    }
}

#[test]
fn a_fresh_lease_redeems_once() {
    may_redeem(&lease(false, 60), "agent:worker", NOW).expect("redeem");
}

#[test]
fn a_lease_that_was_already_used_cannot_be_used_again() {
    assert_eq!(
        may_redeem(&lease(true, 60), "agent:worker", NOW).unwrap_err(),
        VaultFault::LeaseSpent,
        "a replayable lease is a long lived credential wearing a short lived name"
    );
}

#[test]
fn an_expired_lease_cannot_be_redeemed() {
    assert_eq!(
        may_redeem(&lease(false, -1), "agent:worker", NOW).unwrap_err(),
        VaultFault::LeaseExpired
    );
}

#[test]
fn a_lease_cannot_be_redeemed_by_somebody_else() {
    assert_eq!(
        may_redeem(&lease(false, 60), "agent:other", NOW).unwrap_err(),
        VaultFault::LeaseNotYours
    );
}

#[test]
fn the_sealing_context_binds_both_the_tenant_and_the_secret() {
    let one = associated_data(tenant(), "books-api");
    let other_tenant = associated_data(TenantId::from_uuid(Uuid::from_u128(2)), "books-api");
    let other_secret = associated_data(tenant(), "payroll-api");

    assert_ne!(one, other_tenant);
    assert_ne!(one, other_secret);
    assert_eq!(one, associated_data(tenant(), "books-api"));
}

#[test]
fn a_secret_kind_round_trips_through_its_wire_name() {
    for kind in [
        SecretKind::BearerToken,
        SecretKind::ApiKey,
        SecretKind::BasicPassword,
        SecretKind::UpstreamRefreshToken,
    ] {
        assert_eq!(SecretKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(SecretKind::parse("magic"), None);
}
