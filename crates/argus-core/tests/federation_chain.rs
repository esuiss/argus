#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::federation::chain::{ChainFault, MAX_CHAIN_LENGTH, resolve};
use argus_core::federation::statement::{
    EntityIdentifier, EntityStatement, Role, StatementFault, check_role, parse,
};
use argus_core::time::Timestamp;
use serde_json::{Value, json};

const NOW: Timestamp = Timestamp::from_unix_seconds(1_800_000_000);
const LEAF: &str = "https://rp.example.test";
const MIDDLE: &str = "https://intermediate.federation.test";
const ANCHOR: &str = "https://anchor.federation.test";

fn keys() -> Value {
    json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": "aa", "y": "bb", "kid": "f1" }] })
}

fn configuration(entity: &str, extra: &Value) -> EntityStatement {
    let mut body = json!({
        "iss": entity,
        "sub": entity,
        "iat": NOW.as_unix_seconds() - 60,
        "exp": NOW.as_unix_seconds() + 3_600,
        "jwks": keys()
    });

    merge_into(&mut body, extra);
    parse(&body).expect("configuration")
}

fn subordinate(issuer: &str, subject: &str, extra: &Value) -> EntityStatement {
    let mut body = json!({
        "iss": issuer,
        "sub": subject,
        "iat": NOW.as_unix_seconds() - 60,
        "exp": NOW.as_unix_seconds() + 3_600,
        "jwks": keys()
    });

    merge_into(&mut body, extra);
    parse(&body).expect("subordinate")
}

fn merge_into(target: &mut Value, extra: &Value) {
    let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) else {
        return;
    };
    for (key, value) in extra {
        target.insert(key.clone(), value.clone());
    }
}

fn rp_metadata() -> Value {
    json!({
        "metadata": {
            "openid_relying_party": {
                "client_name": "Example RP",
                "redirect_uris": ["https://rp.example.test/callback"],
                "grant_types": ["authorization_code", "client_credentials"],
                "token_endpoint_auth_method": "client_secret_basic"
            }
        },
        "authority_hints": [ANCHOR]
    })
}

fn anchors() -> Vec<EntityIdentifier> {
    vec![EntityIdentifier::parse(ANCHOR).expect("anchor")]
}

#[test]
fn the_shortest_chain_is_leaf_then_subordinate_statement_then_anchor() {
    let chain = [
        configuration(LEAF, &rp_metadata()),
        subordinate(ANCHOR, LEAF, &json!({})),
        configuration(ANCHOR, &json!({})),
    ];

    let resolved = resolve(&chain, &anchors(), "openid_relying_party", NOW).expect("resolve");

    assert_eq!(resolved.subject.as_str(), LEAF);
    assert_eq!(resolved.trust_anchor.as_str(), ANCHOR);
    assert_eq!(resolved.metadata["client_name"], "Example RP");
    assert_eq!(resolved.path_length, 1);
}

#[test]
fn a_chain_with_no_subordinate_statement_is_refused() {
    let chain = [
        configuration(LEAF, &rp_metadata()),
        configuration(ANCHOR, &json!({})),
    ];

    assert_eq!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::NoTrustAnchor,
        "without a statement the anchor issued about the leaf, the anchor never vouched for it;          two self-issued configurations standing side by side prove nothing"
    );
}

#[test]
fn a_chain_ending_at_an_anchor_this_server_does_not_trust_is_refused() {
    let chain = [
        configuration(LEAF, &rp_metadata()),
        configuration("https://stranger.federation.test", &json!({})),
    ];

    assert_eq!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::NoTrustAnchor,
        "a chain that terminates anywhere it likes is not a trust chain"
    );
}

#[test]
fn the_chain_expires_when_its_earliest_statement_does() {
    let short = subordinate(ANCHOR, LEAF, &json!({ "exp": NOW.as_unix_seconds() + 300 }));

    let chain = [
        configuration(LEAF, &rp_metadata()),
        short,
        configuration(ANCHOR, &json!({})),
    ];

    let resolved = resolve(&chain, &anchors(), "openid_relying_party", NOW).expect("resolve");

    assert_eq!(
        resolved.expires_at.as_unix_seconds(),
        NOW.as_unix_seconds() + 300,
        "caching to the longest lifetime would keep a withdrawn subordinate alive"
    );
}

#[test]
fn a_policy_in_the_middle_narrows_the_leaf_metadata() {
    let statement = subordinate(
        ANCHOR,
        LEAF,
        &json!({
            "metadata_policy": {
                "openid_relying_party": {
                    "grant_types": { "subset_of": ["authorization_code"] },
                    "token_endpoint_auth_method": { "value": "private_key_jwt" }
                }
            }
        }),
    );

    let chain = [
        configuration(LEAF, &rp_metadata()),
        statement,
        configuration(ANCHOR, &json!({})),
    ];

    let resolved = resolve(&chain, &anchors(), "openid_relying_party", NOW).expect("resolve");

    assert_eq!(
        resolved.metadata["grant_types"],
        json!(["authorization_code"])
    );
    assert_eq!(
        resolved.metadata["token_endpoint_auth_method"], "private_key_jwt",
        "the client cannot choose a weaker authentication method than its authority allows"
    );
}

#[test]
fn a_three_link_chain_folds_both_policies() {
    let anchor_statement = subordinate(
        ANCHOR,
        MIDDLE,
        &json!({
            "metadata_policy": {
                "openid_relying_party": {
                    "grant_types": { "subset_of": ["authorization_code", "refresh_token"] }
                }
            }
        }),
    );

    let middle_statement = subordinate(
        MIDDLE,
        LEAF,
        &json!({
            "metadata_policy": {
                "openid_relying_party": {
                    "grant_types": { "subset_of": ["authorization_code"] }
                }
            }
        }),
    );

    let leaf = configuration(
        LEAF,
        &json!({
            "metadata": {
                "openid_relying_party": {
                    "grant_types": ["authorization_code", "refresh_token", "client_credentials"]
                }
            },
            "authority_hints": [MIDDLE]
        }),
    );

    let chain = [
        leaf,
        middle_statement,
        anchor_statement,
        configuration(ANCHOR, &json!({})),
    ];

    let resolved = resolve(&chain, &anchors(), "openid_relying_party", NOW).expect("resolve");

    assert_eq!(
        resolved.metadata["grant_types"],
        json!(["authorization_code"])
    );
    assert_eq!(resolved.path_length, 2);
}

#[test]
fn a_chain_that_revisits_an_entity_is_refused_rather_than_walked_forever() {
    let chain = [
        configuration(LEAF, &rp_metadata()),
        subordinate(ANCHOR, LEAF, &json!({})),
        configuration(ANCHOR, &json!({})),
    ];

    let looped = [
        chain[0].clone(),
        subordinate(MIDDLE, LEAF, &json!({})),
        subordinate(MIDDLE, MIDDLE, &json!({})),
        configuration(ANCHOR, &json!({})),
    ];

    let error = resolve(&looped, &anchors(), "openid_relying_party", NOW).unwrap_err();
    assert!(
        matches!(error, ChainFault::Cycle { .. } | ChainFault::Statement(_)),
        "got {error:?}"
    );
}

#[test]
fn a_chain_longer_than_the_ceiling_is_refused() {
    let mut chain = vec![configuration(LEAF, &rp_metadata())];
    for index in 0..MAX_CHAIN_LENGTH {
        chain.push(subordinate(
            &format!("https://hop{index}.federation.test"),
            LEAF,
            &json!({}),
        ));
    }
    chain.push(configuration(ANCHOR, &json!({})));

    assert_eq!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::TooLong
    );
}

#[test]
fn a_max_path_length_constraint_is_enforced() {
    let anchor_statement = subordinate(
        ANCHOR,
        MIDDLE,
        &json!({ "constraints": { "max_path_length": 1 } }),
    );

    let chain = [
        configuration(
            LEAF,
            &json!({
                "metadata": { "openid_relying_party": { "client_name": "x" } },
                "authority_hints": [MIDDLE]
            }),
        ),
        subordinate(MIDDLE, LEAF, &json!({})),
        anchor_statement,
        configuration(ANCHOR, &json!({})),
    ];

    assert!(matches!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::PathTooLong { .. }
    ));
}

#[test]
fn a_naming_constraint_excludes_a_subject_outside_the_permitted_prefix() {
    let statement = subordinate(
        ANCHOR,
        LEAF,
        &json!({
            "constraints": {
                "naming_constraints": { "permitted": ["https://members.federation.test"] }
            }
        }),
    );

    let chain = [
        configuration(LEAF, &rp_metadata()),
        statement,
        configuration(ANCHOR, &json!({})),
    ];

    assert!(matches!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::NameNotPermitted { .. }
    ));
}

#[test]
fn a_naming_constraint_that_permits_the_subject_lets_the_chain_through() {
    let subject = "https://members.federation.test/rp";
    let statement = subordinate(
        ANCHOR,
        subject,
        &json!({
            "constraints": {
                "naming_constraints": { "permitted": ["https://members.federation.test"] }
            }
        }),
    );

    let chain = [
        configuration(
            subject,
            &json!({
                "metadata": { "openid_relying_party": { "client_name": "member" } },
                "authority_hints": [ANCHOR]
            }),
        ),
        statement,
        configuration(ANCHOR, &json!({})),
    ];

    resolve(&chain, &anchors(), "openid_relying_party", NOW).expect("permitted");
}

#[test]
fn a_prefix_that_merely_shares_leading_text_is_not_under_the_permitted_name() {
    let subject = "https://members.federation.test.attacker.example";
    let statement = subordinate(
        ANCHOR,
        subject,
        &json!({
            "constraints": {
                "naming_constraints": { "permitted": ["https://members.federation.test"] }
            }
        }),
    );

    let chain = [
        configuration(
            subject,
            &json!({
                "metadata": { "openid_relying_party": { "client_name": "impostor" } },
                "authority_hints": [ANCHOR]
            }),
        ),
        statement,
        configuration(ANCHOR, &json!({})),
    ];

    assert!(
        matches!(
            resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
            ChainFault::NameNotPermitted { .. }
        ),
        "a naming constraint compared as a plain prefix would admit any attacker-registered suffix"
    );
}

#[test]
fn an_expired_statement_anywhere_in_the_chain_refuses_the_whole_chain() {
    let stale = subordinate(
        ANCHOR,
        LEAF,
        &json!({
            "iat": NOW.as_unix_seconds() - 7_200,
            "exp": NOW.as_unix_seconds() - 3_600
        }),
    );

    let chain = [
        configuration(LEAF, &rp_metadata()),
        stale,
        configuration(ANCHOR, &json!({})),
    ];

    assert_eq!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::Statement(StatementFault::Expired)
    );
}

#[test]
fn a_statement_from_the_future_beyond_the_tolerated_skew_is_refused() {
    let ahead = subordinate(
        ANCHOR,
        LEAF,
        &json!({
            "iat": NOW.as_unix_seconds() + 600,
            "exp": NOW.as_unix_seconds() + 7_200
        }),
    );

    let chain = [
        configuration(LEAF, &rp_metadata()),
        ahead,
        configuration(ANCHOR, &json!({})),
    ];

    assert_eq!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::Statement(StatementFault::NotYetValid)
    );
}

#[test]
fn a_subject_that_publishes_no_metadata_for_the_type_asked_for_is_refused() {
    let chain = [
        configuration(
            LEAF,
            &json!({
                "metadata": { "openid_provider": { "issuer": LEAF } },
                "authority_hints": [ANCHOR]
            }),
        ),
        subordinate(ANCHOR, LEAF, &json!({})),
        configuration(ANCHOR, &json!({})),
    ];

    assert!(matches!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::NoSuchEntityType { .. }
    ));
}

#[test]
fn an_allowed_entity_type_constraint_is_enforced() {
    let statement = subordinate(
        ANCHOR,
        LEAF,
        &json!({ "constraints": { "allowed_entity_types": ["openid_provider"] } }),
    );

    let chain = [
        configuration(LEAF, &rp_metadata()),
        statement,
        configuration(ANCHOR, &json!({})),
    ];

    assert!(matches!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::EntityTypeNotAllowed { .. }
    ));
}

#[test]
fn an_empty_chain_is_refused() {
    assert_eq!(
        resolve(&[], &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::Empty
    );
}

#[test]
fn a_leaf_that_is_not_self_issued_is_refused() {
    let chain = [
        subordinate(ANCHOR, LEAF, &json!({})),
        subordinate(ANCHOR, LEAF, &json!({})),
        configuration(ANCHOR, &json!({})),
    ];

    assert!(matches!(
        resolve(&chain, &anchors(), "openid_relying_party", NOW).unwrap_err(),
        ChainFault::Statement(StatementFault::NotSelfIssued)
    ));
}

#[test]
fn an_entity_configuration_may_not_carry_a_subordinate_only_claim() {
    let body = json!({
        "iss": LEAF, "sub": LEAF,
        "iat": NOW.as_unix_seconds(), "exp": NOW.as_unix_seconds() + 60,
        "jwks": keys(),
        "metadata_policy": { "openid_relying_party": {} }
    });

    assert!(matches!(
        parse(&body).unwrap_err(),
        StatementFault::ConfigurationOnly { .. }
    ));
}

#[test]
fn a_subordinate_statement_may_not_carry_authority_hints() {
    let body = json!({
        "iss": ANCHOR, "sub": LEAF,
        "iat": NOW.as_unix_seconds(), "exp": NOW.as_unix_seconds() + 60,
        "jwks": keys(),
        "authority_hints": [ANCHOR]
    });

    assert!(matches!(
        parse(&body).unwrap_err(),
        StatementFault::SubordinateOnly { .. }
    ));
}

#[test]
fn a_critical_claim_this_server_does_not_understand_refuses_the_statement() {
    let body = json!({
        "iss": LEAF, "sub": LEAF,
        "iat": NOW.as_unix_seconds(), "exp": NOW.as_unix_seconds() + 60,
        "jwks": keys(),
        "crit": ["some_future_extension"]
    });

    assert!(
        matches!(
            parse(&body).unwrap_err(),
            StatementFault::UnknownCritical { .. }
        ),
        "ignoring a critical claim is how a restriction becomes invisible"
    );
}

#[test]
fn a_statement_with_no_signing_key_is_refused() {
    let body = json!({
        "iss": LEAF, "sub": LEAF,
        "iat": NOW.as_unix_seconds(), "exp": NOW.as_unix_seconds() + 60,
        "jwks": { "keys": [] }
    });

    assert_eq!(parse(&body).unwrap_err(), StatementFault::NoKeys);
}

#[test]
fn an_entity_identifier_must_be_an_https_url_without_query_or_fragment() {
    assert!(EntityIdentifier::parse("https://rp.example.test").is_ok());
    assert!(EntityIdentifier::parse("https://rp.example.test/tenant/a").is_ok());

    for bad in [
        "http://rp.example.test",
        "https://rp.example.test?a=b",
        "https://rp.example.test#frag",
        "rp.example.test",
        "https://",
        "https://user@rp.example.test",
    ] {
        assert!(
            EntityIdentifier::parse(bad).is_err(),
            "{bad} must not be an entity identifier"
        );
    }
}

#[test]
fn the_well_known_path_is_appended_to_the_identifier_rather_than_replacing_its_path() {
    let entity = EntityIdentifier::parse("https://idp.example.test/tenant/acme").expect("id");
    assert_eq!(
        entity.well_known(),
        "https://idp.example.test/tenant/acme/.well-known/openid-federation",
        "path-suffix semantics are what make one host serve many tenants"
    );
}

#[test]
fn a_trailing_slash_does_not_make_two_names_of_one_entity() {
    let bare = EntityIdentifier::parse("https://rp.example.test").expect("id");
    let slashed = EntityIdentifier::parse("https://rp.example.test/").expect("id");
    assert_eq!(bare, slashed);
}

#[test]
fn a_leaf_must_not_publish_the_endpoints_only_an_authority_serves() {
    let leaf = configuration(
        LEAF,
        &json!({
            "metadata": {
                "federation_entity": {
                    "federation_fetch_endpoint": "https://rp.example.test/fetch"
                }
            }
        }),
    );

    assert!(
        matches!(
            check_role(&leaf, Role::Leaf).unwrap_err(),
            StatementFault::LeafServesSubordinates { .. }
        ),
        "opening every endpoint just in case is a specification violation, not caution"
    );
}

#[test]
fn an_authority_must_publish_both_endpoints_it_is_required_to_serve() {
    let partial = configuration(
        ANCHOR,
        &json!({
            "metadata": {
                "federation_entity": {
                    "federation_fetch_endpoint": "https://anchor.federation.test/fetch"
                }
            }
        }),
    );

    assert!(matches!(
        check_role(&partial, Role::TrustAnchor).unwrap_err(),
        StatementFault::MissingSubordinateEndpoint {
            endpoint: "federation_list_endpoint"
        }
    ));

    let complete = configuration(
        ANCHOR,
        &json!({
            "metadata": {
                "federation_entity": {
                    "federation_fetch_endpoint": "https://anchor.federation.test/fetch",
                    "federation_list_endpoint": "https://anchor.federation.test/list"
                }
            }
        }),
    );

    check_role(&complete, Role::TrustAnchor).expect("complete authority");
}

#[test]
fn a_leaf_publishing_no_authority_endpoints_passes_its_role_check() {
    check_role(&configuration(LEAF, &rp_metadata()), Role::Leaf).expect("leaf");
}
