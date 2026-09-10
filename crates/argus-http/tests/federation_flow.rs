#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use argus_core::federation::statement::{EntityIdentifier, Role};
use argus_core::time::{Duration, Timestamp};
use argus_crypto::SigningKey;
use argus_http::federation::publish::FederationIdentity;
use argus_http::federation::resolver::{ResolveFault, decode_without_checking, resolve_offline};
use argus_proto::federation::{ENTITY_STATEMENT_TYPE, jwks_of, sign, verify};
use serde_json::{Value, json};

const NOW: Timestamp = Timestamp::from_unix_seconds(1_800_000_000);
const ANCHOR: &str = "https://anchor.federation.test";
const MIDDLE: &str = "https://intermediate.federation.test";
const RP: &str = "https://rp.example.test";

fn entity(raw: &str) -> EntityIdentifier {
    EntityIdentifier::parse(raw).expect("entity")
}

fn key(kid: &str) -> Arc<SigningKey> {
    let (key, _) = SigningKey::generate(kid).expect("key");
    Arc::new(key)
}

fn identity(raw: &str, role: Role, hints: &[&str], key: &Arc<SigningKey>) -> FederationIdentity {
    FederationIdentity {
        entity: entity(raw),
        role,
        signing_keys: vec![Arc::clone(key)],
        authority_hints: hints.iter().map(|hint| entity(hint)).collect(),
        organization_name: Some("Federation Member".to_owned()),
        trust_marks: Vec::new(),
    }
}

fn rp_configuration(rp_key: &Arc<SigningKey>, metadata: &Value, hints: &[&str]) -> String {
    let borrowed: Vec<&SigningKey> = vec![rp_key.as_ref()];

    let claims = json!({
        "iss": RP,
        "sub": RP,
        "iat": NOW.as_unix_seconds() - 60,
        "exp": NOW.as_unix_seconds() + 3_600,
        "jwks": jwks_of(&borrowed),
        "authority_hints": hints,
        "metadata": { "openid_relying_party": metadata.clone() }
    });

    sign(&claims, rp_key, ENTITY_STATEMENT_TYPE).expect("sign")
}

fn anchors() -> Vec<EntityIdentifier> {
    vec![entity(ANCHOR)]
}

#[test]
fn a_chain_this_server_builds_verifies_and_resolves() {
    let anchor_key = key("anchor-1");
    let rp_key = key("rp-1");

    let anchor = identity(ANCHOR, Role::TrustAnchor, &[], &anchor_key);

    let leaf = rp_configuration(
        &rp_key,
        &json!({
            "client_name": "Example RP",
            "redirect_uris": [format!("{RP}/callback")],
            "grant_types": ["authorization_code", "client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic"
        }),
        &[ANCHOR],
    );

    let rp_jwks = decode_without_checking(&leaf).expect("decode").keys;

    let subordinate = anchor
        .subordinate_statement(
            &entity(RP),
            &rp_jwks,
            Some(&json!({
                "openid_relying_party": {
                    "grant_types": { "subset_of": ["authorization_code"] },
                    "token_endpoint_auth_method": { "value": "private_key_jwt" }
                }
            })),
            None,
            NOW,
            Duration::from_seconds(3_600),
        )
        .expect("subordinate");

    let anchor_configuration = anchor
        .entity_configuration(
            &json!({ "issuer": ANCHOR }),
            NOW,
            Duration::from_seconds(86_400),
        )
        .expect("configuration");

    let chain = vec![leaf, subordinate, anchor_configuration];

    let resolved = resolve_offline(&chain, &anchors(), "openid_relying_party", NOW)
        .expect("the chain this server built has to resolve");

    assert_eq!(resolved.subject.as_str(), RP);
    assert_eq!(resolved.trust_anchor.as_str(), ANCHOR);
    assert_eq!(resolved.metadata["client_name"], "Example RP");
    assert_eq!(
        resolved.metadata["grant_types"],
        json!(["authorization_code"]),
        "the policy the anchor set has to survive the round trip through signed statements"
    );
    assert_eq!(
        resolved.metadata["token_endpoint_auth_method"],
        "private_key_jwt"
    );
}

#[test]
fn a_three_link_chain_through_an_intermediate_resolves() {
    let anchor_key = key("anchor-1");
    let middle_key = key("middle-1");
    let rp_key = key("rp-1");

    let anchor = identity(ANCHOR, Role::TrustAnchor, &[], &anchor_key);
    let middle = identity(MIDDLE, Role::Intermediate, &[ANCHOR], &middle_key);

    let leaf = rp_configuration(
        &rp_key,
        &json!({ "client_name": "Example RP", "grant_types": ["authorization_code", "implicit"] }),
        &[MIDDLE],
    );

    let rp_jwks = decode_without_checking(&leaf).expect("decode").keys;

    let middle_about_rp = middle
        .subordinate_statement(
            &entity(RP),
            &rp_jwks,
            Some(&json!({
                "openid_relying_party": { "grant_types": { "subset_of": ["authorization_code"] } }
            })),
            None,
            NOW,
            Duration::from_seconds(3_600),
        )
        .expect("middle statement");

    let middle_configuration = middle
        .entity_configuration(&json!({}), NOW, Duration::from_seconds(86_400))
        .expect("middle configuration");

    let middle_jwks = decode_without_checking(&middle_configuration)
        .expect("decode")
        .keys;

    let anchor_about_middle = anchor
        .subordinate_statement(
            &entity(MIDDLE),
            &middle_jwks,
            Some(&json!({
                "openid_relying_party": {
                    "grant_types": { "subset_of": ["authorization_code", "refresh_token"] }
                }
            })),
            None,
            NOW,
            Duration::from_seconds(3_600),
        )
        .expect("anchor statement");

    let anchor_configuration = anchor
        .entity_configuration(&json!({}), NOW, Duration::from_seconds(86_400))
        .expect("anchor configuration");

    let chain = vec![
        leaf,
        middle_about_rp,
        anchor_about_middle,
        anchor_configuration,
    ];

    let resolved =
        resolve_offline(&chain, &anchors(), "openid_relying_party", NOW).expect("resolve");

    assert_eq!(resolved.path_length, 2);
    assert_eq!(
        resolved.metadata["grant_types"],
        json!(["authorization_code"])
    );
}

#[test]
fn a_statement_signed_by_a_key_the_superior_never_published_is_refused() {
    let anchor_key = key("anchor-1");
    let stranger = key("stranger-1");
    let rp_key = key("rp-1");

    let anchor = identity(ANCHOR, Role::TrustAnchor, &[], &anchor_key);
    let leaf = rp_configuration(&rp_key, &json!({ "client_name": "RP" }), &[ANCHOR]);
    let rp_jwks = decode_without_checking(&leaf).expect("decode").keys;

    let forged = {
        let claims = json!({
            "iss": ANCHOR,
            "sub": RP,
            "iat": NOW.as_unix_seconds(),
            "exp": NOW.as_unix_seconds() + 3_600,
            "jwks": rp_jwks
        });
        sign(&claims, &stranger, ENTITY_STATEMENT_TYPE).expect("sign")
    };

    let anchor_configuration = anchor
        .entity_configuration(&json!({}), NOW, Duration::from_seconds(86_400))
        .expect("configuration");

    let chain = vec![leaf, forged, anchor_configuration];

    assert!(
        resolve_offline(&chain, &anchors(), "openid_relying_party", NOW).is_err(),
        "anyone able to mint statements in the anchor's name owns the whole federation"
    );
}

#[test]
fn a_leaf_that_swaps_its_keys_after_the_superior_attested_them_is_refused() {
    let anchor_key = key("anchor-1");
    let honest_rp = key("rp-1");
    let attacker_rp = key("rp-1");

    let anchor = identity(ANCHOR, Role::TrustAnchor, &[], &anchor_key);

    let honest_leaf = rp_configuration(&honest_rp, &json!({ "client_name": "RP" }), &[ANCHOR]);
    let attested_jwks = decode_without_checking(&honest_leaf).expect("decode").keys;

    let subordinate = anchor
        .subordinate_statement(
            &entity(RP),
            &attested_jwks,
            None,
            None,
            NOW,
            Duration::from_seconds(3_600),
        )
        .expect("subordinate");

    let swapped_leaf = rp_configuration(
        &attacker_rp,
        &json!({ "client_name": "Impostor" }),
        &[ANCHOR],
    );

    let anchor_configuration = anchor
        .entity_configuration(&json!({}), NOW, Duration::from_seconds(86_400))
        .expect("configuration");

    let chain = vec![swapped_leaf, subordinate, anchor_configuration];

    assert!(
        resolve_offline(&chain, &anchors(), "openid_relying_party", NOW).is_err(),
        "the leaf's keys are the ones its superior signed for, not the ones it claims for itself"
    );
}

#[test]
fn a_chain_ending_at_an_unconfigured_anchor_is_refused_before_any_signature_work() {
    let stranger_key = key("stranger-1");
    let rp_key = key("rp-1");

    let stranger = identity(
        "https://stranger.federation.test",
        Role::TrustAnchor,
        &[],
        &stranger_key,
    );

    let leaf = rp_configuration(&rp_key, &json!({ "client_name": "RP" }), &[]);
    let rp_jwks = decode_without_checking(&leaf).expect("decode").keys;

    let subordinate = stranger
        .subordinate_statement(
            &entity(RP),
            &rp_jwks,
            None,
            None,
            NOW,
            Duration::from_seconds(3_600),
        )
        .expect("subordinate");

    let configuration = stranger
        .entity_configuration(&json!({}), NOW, Duration::from_seconds(86_400))
        .expect("configuration");

    let chain = vec![leaf, subordinate, configuration];

    assert!(matches!(
        resolve_offline(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ResolveFault::Chain(argus_core::federation::chain::ChainFault::NoTrustAnchor)
    ));
}

#[test]
fn a_statement_carrying_the_wrong_media_type_in_its_header_is_refused() {
    let anchor_key = key("anchor-1");

    let claims = json!({
        "iss": ANCHOR, "sub": ANCHOR,
        "iat": NOW.as_unix_seconds(), "exp": NOW.as_unix_seconds() + 60,
        "jwks": jwks_of(&[anchor_key.as_ref()])
    });

    let token = sign(&claims, &anchor_key, "at+jwt").expect("sign");
    let jwks = jwks_of(&[anchor_key.as_ref()]);

    assert!(
        verify(&token, &jwks, ENTITY_STATEMENT_TYPE).is_err(),
        "a token minted for another purpose must not double as an entity statement"
    );
}

#[test]
fn the_entity_configuration_this_server_publishes_verifies_against_its_own_keys() {
    let signing = key("fed-1");
    let identity = identity(ANCHOR, Role::TrustAnchor, &[], &signing);

    let token = identity
        .entity_configuration(
            &json!({ "issuer": ANCHOR, "authorization_endpoint": format!("{ANCHOR}/authorize") }),
            NOW,
            Duration::from_seconds(86_400),
        )
        .expect("configuration");

    let body = verify(&token, &identity.jwks(), ENTITY_STATEMENT_TYPE).expect("verify");

    assert_eq!(body["iss"], ANCHOR);
    assert_eq!(body["sub"], ANCHOR);
    assert_eq!(
        body["metadata"]["openid_provider"]["issuer"], ANCHOR,
        "the provider metadata has to travel inside the signed statement"
    );
}

#[test]
fn a_trust_anchor_publishes_the_endpoints_its_role_requires_and_a_leaf_does_not() {
    let signing = key("fed-1");

    let anchor = identity(ANCHOR, Role::TrustAnchor, &[], &signing)
        .entity_configuration(&json!({}), NOW, Duration::from_seconds(60))
        .expect("anchor");
    let anchor_body = verify(
        &anchor,
        &jwks_of(&[signing.as_ref()]),
        ENTITY_STATEMENT_TYPE,
    )
    .expect("verify");

    let federation = &anchor_body["metadata"]["federation_entity"];
    assert!(federation.get("federation_fetch_endpoint").is_some());
    assert!(federation.get("federation_list_endpoint").is_some());

    let leaf = identity(RP, Role::Leaf, &[ANCHOR], &signing)
        .entity_configuration(&json!({}), NOW, Duration::from_seconds(60))
        .expect("leaf");
    let leaf_body =
        verify(&leaf, &jwks_of(&[signing.as_ref()]), ENTITY_STATEMENT_TYPE).expect("verify");

    let federation = &leaf_body["metadata"]["federation_entity"];
    assert!(
        federation.get("federation_fetch_endpoint").is_none(),
        "a leaf publishing the fetch endpoint is a specification violation, not extra caution"
    );
    assert!(federation.get("federation_list_endpoint").is_none());
}

#[test]
fn a_leaf_cannot_issue_a_statement_about_anybody_else() {
    let signing = key("fed-1");
    let leaf = identity(RP, Role::Leaf, &[ANCHOR], &signing);

    assert!(
        leaf.subordinate_statement(
            &entity("https://victim.example.test"),
            &jwks_of(&[signing.as_ref()]),
            None,
            None,
            NOW,
            Duration::from_seconds(60),
        )
        .is_err(),
        "a leaf that can vouch for others is an authority it was never configured to be"
    );
}

#[test]
fn an_empty_chain_and_an_over_long_chain_are_both_refused() {
    assert!(resolve_offline(&[], &anchors(), "openid_relying_party", NOW).is_err());

    let filler: Vec<String> = (0..32).map(|index| format!("token-{index}")).collect();
    assert!(matches!(
        resolve_offline(&filler, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ResolveFault::Chain(argus_core::federation::chain::ChainFault::TooLong)
    ));
}

#[test]
fn the_published_provider_metadata_declares_how_clients_may_register() {
    let signing = key("fed-1");
    let identity = identity(ANCHOR, Role::Leaf, &[ANCHOR], &signing);

    let token = identity
        .entity_configuration(
            &json!({ "issuer": ANCHOR }),
            NOW,
            Duration::from_seconds(3_600),
        )
        .expect("configuration");

    let body = verify(&token, &identity.jwks(), ENTITY_STATEMENT_TYPE).expect("verify");

    assert_eq!(
        body["metadata"]["openid_provider"]["client_registration_types_supported"],
        json!(["automatic"]),
        "the federation profile makes this parameter required; without it a relying party \
         cannot tell whether it may register at all"
    );
    assert_eq!(body["metadata"]["openid_provider"]["issuer"], ANCHOR);
}
