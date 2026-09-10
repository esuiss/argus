#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_crypto::SigningKey;
use argus_proto::agent_card::{CardFault, PublishedKey, check, payload, sign, verify};
use serde_json::{Value, json};

const ISSUER: &str = "https://idp.argus.test";

fn key(kid: &str) -> SigningKey {
    let (key, _) = SigningKey::generate(kid).expect("key");
    key
}

fn published(key: &SigningKey) -> Vec<PublishedKey> {
    vec![PublishedKey {
        kid: key.kid().to_owned(),
        key: key.verifying_key(),
    }]
}

fn card() -> Value {
    json!({
        "id": "urn:agent:invoice-bot",
        "name": "Invoice Bot",
        "description": "Reconciles invoices",
        "interfaces": [
            { "transport": "JSONRPC", "url": "https://agent.example.test/a2a" }
        ],
        "securitySchemes": {
            "argus": {
                "type": "openIdConnect",
                "openIdConnectUrl": "https://idp.argus.test/.well-known/openid-configuration"
            },
            "argus-oauth": {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": { "tokenUrl": "https://idp.argus.test/token", "scopes": {} }
                }
            }
        },
        "security": [{ "argus": [] }],
        "skills": [
            { "id": "reconcile", "name": "Reconcile", "security": [{ "argus-oauth": ["invoice.write"] }] }
        ]
    })
}

#[test]
fn a_well_formed_card_passes_the_structural_checks() {
    check(&card()).expect("this card is what the protocol describes");
}

#[test]
fn a_card_without_an_identifier_or_a_name_is_refused() {
    for field in ["id", "name"] {
        let mut body = card();
        body.as_object_mut().expect("object").remove(field);

        assert!(
            matches!(check(&body).unwrap_err(), CardFault::Missing { .. }),
            "{field} is required"
        );
    }
}

#[test]
fn a_card_with_no_interface_is_refused() {
    let mut body = card();
    body["interfaces"] = json!([]);

    assert!(matches!(
        check(&body).unwrap_err(),
        CardFault::Missing {
            field: "interfaces"
        }
    ));
}

#[test]
fn a_security_scheme_of_a_type_the_protocol_does_not_define_is_refused() {
    let mut body = card();
    body["securitySchemes"]["argus"]["type"] = json!("magic");

    assert!(matches!(
        check(&body).unwrap_err(),
        CardFault::UnknownSecurityScheme { .. }
    ));
}

#[test]
fn a_card_offering_the_implicit_flow_is_refused() {
    let mut body = card();
    body["securitySchemes"]["argus-oauth"]["flows"] = json!({
        "implicit": { "authorizationUrl": "https://idp.argus.test/authorize", "scopes": {} }
    });

    assert!(
        matches!(check(&body).unwrap_err(), CardFault::ForbiddenFlow { flow, .. } if flow == "implicit"),
        "signing a card that advertises a flow OAuth 2.1 removed would vouch for the removal being undone"
    );
}

#[test]
fn a_card_offering_the_password_flow_is_refused() {
    let mut body = card();
    body["securitySchemes"]["argus-oauth"]["flows"] = json!({
        "password": { "tokenUrl": "https://idp.argus.test/token", "scopes": {} }
    });

    assert!(matches!(
        check(&body).unwrap_err(),
        CardFault::ForbiddenFlow { .. }
    ));
}

#[test]
fn the_three_flows_the_protocol_keeps_are_all_accepted() {
    for flow in ["authorizationCode", "clientCredentials", "deviceCode"] {
        let mut body = card();
        body["securitySchemes"]["argus-oauth"]["flows"] =
            json!({ flow: { "tokenUrl": "https://idp.argus.test/token", "scopes": {} } });

        check(&body).unwrap_or_else(|e| panic!("{flow} must be accepted: {e}"));
    }
}

#[test]
fn a_card_whose_oauth_scheme_offers_no_usable_flow_is_refused() {
    let mut body = card();
    body["securitySchemes"]["argus-oauth"]["flows"] = json!({});

    assert!(matches!(
        check(&body).unwrap_err(),
        CardFault::NoAcceptableFlow { .. }
    ));
}

#[test]
fn a_skill_naming_a_scheme_the_card_never_declared_is_refused() {
    let mut body = card();
    body["skills"][0]["security"] = json!([{ "not-declared": [] }]);

    assert!(
        matches!(
            check(&body).unwrap_err(),
            CardFault::UndeclaredScheme { .. }
        ),
        "a dangling scheme name sends the caller looking for an authentication method that does not exist"
    );
}

#[test]
fn a_card_this_server_signs_verifies_against_the_key_it_named() {
    let signing = key("agent-card-1");
    let signed = sign(&card(), &signing, ISSUER).expect("sign");

    let issuer = verify(&signed, &published(&signing)).expect("verify");
    assert_eq!(issuer, ISSUER);
}

#[test]
fn the_signature_block_is_added_without_disturbing_the_rest_of_the_card() {
    let signing = key("agent-card-1");
    let signed = sign(&card(), &signing, ISSUER).expect("sign");

    assert_eq!(signed["id"], card()["id"]);
    assert_eq!(signed["interfaces"], card()["interfaces"]);
    assert!(signed["signature"]["protected"].as_str().is_some());
    assert!(signed["signature"]["signature"].as_str().is_some());
}

#[test]
fn the_signed_payload_never_covers_the_signature_block_itself() {
    let signing = key("agent-card-1");
    let signed = sign(&card(), &signing, ISSUER).expect("sign");

    assert_eq!(
        payload(&card()).expect("unsigned"),
        payload(&signed).expect("signed"),
        "the canonical payload has to be the same before and after the block is attached"
    );
}

#[test]
fn changing_any_field_after_signing_breaks_the_signature() {
    let signing = key("agent-card-1");
    let mut signed = sign(&card(), &signing, ISSUER).expect("sign");

    signed["interfaces"][0]["url"] = json!("https://attacker.test/a2a");

    assert!(
        matches!(
            verify(&signed, &published(&signing)).unwrap_err(),
            CardFault::BadSignature
        ),
        "the endpoint a caller is sent to is exactly what the signature has to cover"
    );
}

#[test]
fn adding_a_field_after_signing_breaks_the_signature() {
    let signing = key("agent-card-1");
    let mut signed = sign(&card(), &signing, ISSUER).expect("sign");

    signed
        .as_object_mut()
        .expect("object")
        .insert("extraSkill".to_owned(), json!({ "id": "exfiltrate" }));

    assert!(matches!(
        verify(&signed, &published(&signing)).unwrap_err(),
        CardFault::BadSignature
    ));
}

#[test]
fn reordering_the_fields_of_a_signed_card_does_not_break_the_signature() {
    let signing = key("agent-card-1");
    let signed = sign(&card(), &signing, ISSUER).expect("sign");

    let text = serde_json::to_string(&signed).expect("json");
    let reparsed: Value = serde_json::from_str(&text).expect("json");

    verify(&reparsed, &published(&signing))
        .expect("canonicalization is what makes a card survive being reserialised");
}

#[test]
fn a_card_signed_by_another_key_does_not_verify() {
    let signing = key("agent-card-1");
    let stranger = key("agent-card-1");

    let signed = sign(&card(), &signing, ISSUER).expect("sign");

    assert!(matches!(
        verify(&signed, &published(&stranger)).unwrap_err(),
        CardFault::BadSignature
    ));
}

#[test]
fn a_card_naming_a_key_the_issuer_does_not_publish_is_refused() {
    let signing = key("agent-card-1");
    let other = key("agent-card-2");

    let signed = sign(&card(), &signing, ISSUER).expect("sign");

    assert!(matches!(
        verify(&signed, &published(&other)).unwrap_err(),
        CardFault::NoSuchKey { .. }
    ));
}

#[test]
fn a_card_with_no_signature_block_is_refused_rather_than_treated_as_unsigned_but_fine() {
    assert!(matches!(
        verify(&card(), &published(&key("agent-card-1"))).unwrap_err(),
        CardFault::MalformedSignature
    ));
}

#[test]
fn a_signature_declaring_an_algorithm_this_server_does_not_accept_is_refused() {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    let signing = key("agent-card-1");
    let mut signed = sign(&card(), &signing, ISSUER).expect("sign");

    let forged = json!({ "alg": "none", "kid": signing.kid(), "typ": "JOSE", "iss": ISSUER });
    let encoded =
        Base64UrlUnpadded::encode_string(serde_json::to_string(&forged).expect("json").as_bytes());
    signed["signature"]["protected"] = json!(encoded);

    assert!(matches!(
        verify(&signed, &published(&signing)).unwrap_err(),
        CardFault::DisallowedAlgorithm { .. }
    ));
}

#[test]
fn a_card_that_fails_the_structural_checks_is_never_signed() {
    let signing = key("agent-card-1");
    let mut body = card();
    body["securitySchemes"]["argus-oauth"]["flows"] = json!({ "implicit": {} });

    assert!(
        sign(&body, &signing, ISSUER).is_err(),
        "signing is a statement that the card is sound; it cannot come before the checks"
    );
}
