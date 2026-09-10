#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_saml::request::{
    AssertionConsumerService, ConsumerServiceFault, RequestFault, parse, resolve_consumer_service,
};
use argus_saml::xml::XmlFault;

const ACS: &str = "https://sp.example.com/acs";
const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

fn request(extra: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z" Destination="https://idp.argus.test/sso"{extra}><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>"#
    )
}

fn registered() -> Vec<AssertionConsumerService> {
    vec![
        AssertionConsumerService {
            index: 0,
            binding: POST.to_owned(),
            location: ACS.to_owned(),
            is_default: true,
        },
        AssertionConsumerService {
            index: 1,
            binding: REDIRECT.to_owned(),
            location: "https://sp.example.com/acs-redirect".to_owned(),
            is_default: false,
        },
    ]
}

#[test]
fn a_well_formed_request_is_read_completely() {
    let parsed = parse(&request("")).expect("parse");
    assert_eq!(parsed.id, "_req-1");
    assert_eq!(parsed.issuer, "https://sp.example.com/metadata");
    assert_eq!(
        parsed.destination.as_deref(),
        Some("https://idp.argus.test/sso")
    );
    assert!(!parsed.force_authn);
    assert!(!parsed.is_passive);
}

#[test]
fn force_authn_and_is_passive_are_read_only_when_they_say_true() {
    let parsed = parse(&request(r#" ForceAuthn="true" IsPassive="true""#)).expect("parse");
    assert!(parsed.force_authn);
    assert!(parsed.is_passive);

    let parsed = parse(&request(r#" ForceAuthn="1" IsPassive="TRUE""#)).expect("parse");
    assert!(
        !parsed.force_authn,
        "xsd:boolean in a SAML request is 'true' or 'false'; guessing at other spellings would silently weaken a reauthentication demand"
    );
    assert!(!parsed.is_passive);
}

#[test]
fn a_request_without_an_issuer_is_refused() {
    let body = r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z"/>"#;
    assert_eq!(
        parse(body).unwrap_err(),
        RequestFault::Missing {
            attribute: "Issuer"
        }
    );
}

#[test]
fn a_request_with_an_empty_issuer_is_refused() {
    let body = r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z"><saml:Issuer>   </saml:Issuer></samlp:AuthnRequest>"#;
    assert_eq!(
        parse(body).unwrap_err(),
        RequestFault::Missing {
            attribute: "Issuer"
        }
    );
}

#[test]
fn a_saml_one_one_request_is_refused() {
    let body = request("").replace(r#"Version="2.0""#, r#"Version="1.1""#);
    assert_eq!(
        parse(&body).unwrap_err(),
        RequestFault::WrongVersion {
            version: "1.1".to_owned()
        }
    );
}

#[test]
fn an_issuer_element_from_the_wrong_namespace_is_not_an_issuer() {
    let body = request("").replace(
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
        "xmlns:saml=\"urn:example:not-saml\"",
    );
    assert_eq!(
        parse(&body).unwrap_err(),
        RequestFault::Missing {
            attribute: "Issuer"
        }
    );
}

#[test]
fn an_element_that_merely_looks_like_an_authn_request_is_refused() {
    let body = r#"<?xml version="1.0"?><AuthnRequest ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z"/>"#;
    assert_eq!(parse(body).unwrap_err(), RequestFault::NotAnAuthnRequest);
}

#[test]
fn a_request_carrying_a_doctype_never_reaches_the_parser_logic() {
    let body = request("").replace(
        r#"<?xml version="1.0"?>"#,
        r#"<?xml version="1.0"?><!DOCTYPE samlp:AuthnRequest [<!ENTITY x SYSTEM "file:///etc/passwd">]>"#,
    );
    assert_eq!(
        parse(&body).unwrap_err(),
        RequestFault::Xml(XmlFault::DoctypePresent)
    );
}

#[test]
fn a_request_naming_both_a_location_and_an_index_is_refused_as_ambiguous() {
    let body = request(
        r#" AssertionConsumerServiceURL="https://sp.example.com/acs" AssertionConsumerServiceIndex="1""#,
    );
    assert_eq!(
        parse(&body).unwrap_err(),
        RequestFault::AmbiguousConsumerService
    );
}

#[test]
fn a_requested_location_must_be_one_the_peer_registered() {
    let parsed = parse(&request(&format!(
        r#" AssertionConsumerServiceURL="{ACS}""#
    )))
    .expect("parse");

    assert_eq!(
        resolve_consumer_service(&parsed, &registered())
            .expect("registered")
            .location,
        ACS
    );
}

#[test]
fn an_unregistered_location_is_refused_rather_than_honoured() {
    let parsed = parse(&request(
        r#" AssertionConsumerServiceURL="https://attacker.test/collect""#,
    ))
    .expect("parse");

    assert_eq!(
        resolve_consumer_service(&parsed, &registered()).unwrap_err(),
        ConsumerServiceFault::LocationNotRegistered,
        "honouring an unregistered location would post the assertion straight to the attacker"
    );
}

#[test]
fn a_location_that_merely_starts_with_a_registered_one_is_not_accepted() {
    let parsed = parse(&request(&format!(
        r#" AssertionConsumerServiceURL="{ACS}.attacker.test""#
    )))
    .expect("parse");

    assert_eq!(
        resolve_consumer_service(&parsed, &registered()).unwrap_err(),
        ConsumerServiceFault::LocationNotRegistered
    );
}

#[test]
fn a_binding_that_contradicts_the_registered_endpoint_is_refused() {
    let parsed = parse(&request(&format!(
        r#" AssertionConsumerServiceURL="{ACS}" ProtocolBinding="{REDIRECT}""#
    )))
    .expect("parse");

    assert_eq!(
        resolve_consumer_service(&parsed, &registered()).unwrap_err(),
        ConsumerServiceFault::BindingMismatch
    );
}

#[test]
fn an_index_resolves_to_the_registered_endpoint_that_carries_it() {
    let parsed = parse(&request(r#" AssertionConsumerServiceIndex="1""#)).expect("parse");
    let endpoints = registered();
    let found = resolve_consumer_service(&parsed, &endpoints).expect("resolved");
    assert_eq!(found.location, "https://sp.example.com/acs-redirect");
}

#[test]
fn an_unregistered_index_is_refused() {
    let parsed = parse(&request(r#" AssertionConsumerServiceIndex="7""#)).expect("parse");
    assert_eq!(
        resolve_consumer_service(&parsed, &registered()).unwrap_err(),
        ConsumerServiceFault::IndexNotRegistered
    );
}

#[test]
fn a_request_that_names_neither_falls_back_to_the_registered_default() {
    let parsed = parse(&request("")).expect("parse");
    let endpoints = registered();
    let found = resolve_consumer_service(&parsed, &endpoints).expect("resolved");
    assert!(found.is_default);
    assert_eq!(found.location, ACS);
}

#[test]
fn a_peer_with_no_registered_endpoint_gets_no_assertion() {
    let parsed = parse(&request("")).expect("parse");
    assert_eq!(
        resolve_consumer_service(&parsed, &[]).unwrap_err(),
        ConsumerServiceFault::NoneRegistered
    );
}

#[test]
fn a_name_id_policy_is_read_from_the_request() {
    let body = request("").replace(
        "</samlp:AuthnRequest>",
        r#"<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>"#,
    );
    let parsed = parse(&body).expect("parse");
    assert_eq!(
        parsed.name_id_format.as_deref(),
        Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    );
}

#[test]
fn a_request_repeating_one_identifier_is_refused() {
    let body = request("").replace(
        "</samlp:AuthnRequest>",
        r#"<samlp:Scoping ID="_req-1"/></samlp:AuthnRequest>"#,
    );
    assert_eq!(
        parse(&body).unwrap_err(),
        RequestFault::Xml(XmlFault::DuplicateId {
            id: "_req-1".to_owned()
        })
    );
}
