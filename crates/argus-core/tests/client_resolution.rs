#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::client_resolution::{
    Attempt, ClientIdShape, ResolutionFault, TenantPaths, TrustLevel, TrustSource, check_scopes,
    from_federation, from_local_registration, from_metadata_document, order, requires_consent,
    shape_of,
};
use argus_core::time::Timestamp;
use serde_json::json;

const NOW: Timestamp = Timestamp::from_unix_seconds(1_800_000_000);

fn everything() -> TenantPaths {
    TenantPaths {
        local_registration: true,
        client_id_metadata_document: true,
        federation: true,
    }
}

#[test]
fn a_url_shaped_identifier_tries_federation_before_a_metadata_document() {
    let attempts = order(ClientIdShape::HttpsUrl, &everything()).expect("order");
    assert_eq!(
        attempts,
        [Attempt::Federation, Attempt::ClientIdMetadataDocument],
        "federation carries a signature chain and a metadata document carries only a domain name; \
         trying the weaker one first would let it win"
    );
}

#[test]
fn a_url_shaped_identifier_never_falls_back_to_the_local_registry() {
    let attempts = order(ClientIdShape::HttpsUrl, &everything()).expect("order");
    assert!(
        !attempts.contains(&Attempt::LocalRegistration),
        "a client that registers the literal string https://victim.test locally would otherwise \
         answer for the real one"
    );

    let only_local = TenantPaths {
        local_registration: true,
        client_id_metadata_document: false,
        federation: false,
    };

    assert_eq!(
        order(ClientIdShape::HttpsUrl, &only_local).unwrap_err(),
        ResolutionFault::UrlWouldFallBackToLocal
    );
}

#[test]
fn an_opaque_identifier_only_ever_reads_the_local_registry() {
    let attempts = order(ClientIdShape::Opaque, &everything()).expect("order");
    assert_eq!(attempts, [Attempt::LocalRegistration]);
}

#[test]
fn a_tenant_with_no_path_enabled_resolves_nothing() {
    let none = TenantPaths {
        local_registration: false,
        client_id_metadata_document: false,
        federation: false,
    };

    assert_eq!(
        order(ClientIdShape::Opaque, &none).unwrap_err(),
        ResolutionFault::NoPathEnabled
    );
    assert_eq!(
        order(ClientIdShape::HttpsUrl, &none).unwrap_err(),
        ResolutionFault::NoPathEnabled
    );
}

#[test]
fn a_tenant_that_enables_only_federation_skips_the_metadata_document() {
    let paths = TenantPaths {
        local_registration: true,
        client_id_metadata_document: false,
        federation: true,
    };

    assert_eq!(
        order(ClientIdShape::HttpsUrl, &paths).expect("order"),
        [Attempt::Federation]
    );
}

#[test]
fn the_shape_of_an_identifier_is_decided_by_its_scheme() {
    assert_eq!(
        shape_of("https://app.example.test/client.json"),
        ClientIdShape::HttpsUrl
    );
    assert_eq!(
        shape_of("http://app.example.test/client.json"),
        ClientIdShape::HttpsUrl
    );
    assert_eq!(shape_of("demo-client"), ClientIdShape::Opaque);
    assert_eq!(shape_of("urn:example:client"), ClientIdShape::Opaque);
}

#[test]
fn the_default_tenant_opens_only_the_local_registry() {
    let paths = TenantPaths::default();
    assert!(paths.local_registration);
    assert!(
        !paths.federation && !paths.client_id_metadata_document,
        "a tenant that never asked for federation must not make outbound calls on every authorize"
    );
}

#[test]
fn trust_levels_are_ordered_from_weakest_to_strongest() {
    assert!(TrustLevel::Unverified < TrustLevel::Registered);
    assert!(TrustLevel::Registered < TrustLevel::Federated);
    assert!(TrustLevel::Federated < TrustLevel::FederatedWithTrustMark);
}

#[test]
fn only_a_client_carrying_a_trust_mark_may_skip_consent() {
    assert!(TrustLevel::FederatedWithTrustMark.may_skip_consent());
    assert!(!TrustLevel::Federated.may_skip_consent());
    assert!(!TrustLevel::Registered.may_skip_consent());
    assert!(!TrustLevel::Unverified.may_skip_consent());
}

#[test]
fn only_an_unverified_client_makes_the_user_see_a_warning() {
    assert!(TrustLevel::Unverified.must_warn_the_user());
    assert!(!TrustLevel::Registered.must_warn_the_user());
}

#[test]
fn a_metadata_document_client_is_unverified_and_a_federated_one_is_not() {
    let weak = from_metadata_document(
        "https://app.example.test/client.json",
        json!({ "client_name": "App" }),
        None,
    );
    assert_eq!(weak.trust_level, TrustLevel::Unverified);
    assert_eq!(weak.source, TrustSource::ClientIdMetadataDocument);
    assert!(!weak.policy_applied);

    let strong = from_federation(
        "https://rp.example.test",
        json!({ "client_name": "RP" }),
        "https://anchor.federation.test",
        NOW,
        false,
    );
    assert_eq!(strong.trust_level, TrustLevel::Federated);
    assert!(strong.policy_applied);
    assert_eq!(
        strong.trust_anchor.as_deref(),
        Some("https://anchor.federation.test")
    );
}

#[test]
fn a_trust_mark_raises_the_level_a_federated_client_reaches() {
    let marked = from_federation(
        "https://rp.example.test",
        json!({}),
        "https://anchor.federation.test",
        NOW,
        true,
    );
    assert_eq!(marked.trust_level, TrustLevel::FederatedWithTrustMark);
    assert!(!requires_consent(&marked));
}

#[test]
fn an_unverified_client_cannot_ask_for_a_sensitive_scope() {
    let weak = from_metadata_document("https://app.example.test/client.json", json!({}), None);

    assert!(check_scopes(&weak, "openid profile").is_ok());

    assert!(matches!(
        check_scopes(&weak, "openid scim").unwrap_err(),
        ResolutionFault::ScopeAboveTrustLevel { .. }
    ));
    assert!(matches!(
        check_scopes(&weak, "admin").unwrap_err(),
        ResolutionFault::ScopeAboveTrustLevel { .. }
    ));
}

#[test]
fn a_registered_client_may_ask_for_a_sensitive_scope() {
    let registered = from_local_registration("demo-client", json!({}));
    check_scopes(&registered, "openid scim offline_access").expect("registered clients are known");
}

#[test]
fn every_client_below_a_trust_mark_still_sees_a_consent_screen() {
    for client in [
        from_metadata_document("https://a.test/c.json", json!({}), None),
        from_local_registration("demo", json!({})),
        from_federation("https://rp.test", json!({}), "https://a.test", NOW, false),
    ] {
        assert!(requires_consent(&client));
    }
}

#[test]
fn a_federated_client_goes_stale_when_its_chain_does() {
    let client = from_federation(
        "https://rp.example.test",
        json!({}),
        "https://anchor.federation.test",
        NOW,
        false,
    );

    assert!(client.is_fresh(Timestamp::from_unix_seconds(NOW.as_unix_seconds() - 1)));
    assert!(
        !client.is_fresh(NOW),
        "a resolved client cached past its chain would outlive the authority that vouched for it"
    );
}

#[test]
fn a_locally_registered_client_never_goes_stale_on_its_own() {
    let client = from_local_registration("demo-client", json!({}));
    assert!(client.expires_at.is_none());
    assert!(client.is_fresh(Timestamp::from_unix_seconds(i64::MAX)));
}

#[test]
fn the_redirect_uris_come_from_the_resolved_metadata_whatever_the_path_was() {
    let client = from_federation(
        "https://rp.example.test",
        json!({ "redirect_uris": ["https://rp.example.test/cb"] }),
        "https://anchor.federation.test",
        NOW,
        false,
    );

    assert_eq!(client.redirect_uris(), ["https://rp.example.test/cb"]);
    assert!(
        from_local_registration("demo", json!({}))
            .redirect_uris()
            .is_empty()
    );
}
