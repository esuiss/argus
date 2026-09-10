#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_saml::metadata::{
    IdentityProvider, MetadataFault, identity_provider, parse_service_provider,
};
use argus_saml::request::{parse as parse_request, resolve_consumer_service};
use argus_saml::xml::XmlFault;

fn certificate() -> String {
    include_str!("fixtures/idp-cert.pem")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

fn sp_metadata(extra: &str, endpoints: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.example.com/metadata"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"{extra}><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>{endpoints}</md:SPSSODescriptor></md:EntityDescriptor>"#,
        certificate()
    )
}

const ACS_POST: &str = r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0" isDefault="true"/>"#;

#[test]
fn a_service_providers_endpoints_and_key_are_read_from_its_metadata() {
    let parsed = parse_service_provider(&sp_metadata("", ACS_POST)).expect("parse");

    assert_eq!(parsed.entity_id, "https://sp.example.com/metadata");
    assert_eq!(parsed.consumer_services.len(), 1);
    assert_eq!(
        parsed.consumer_services[0].location,
        "https://sp.example.com/acs"
    );
    assert!(parsed.consumer_services[0].is_default);
    assert_eq!(parsed.signing_certificates.len(), 1);
}

#[test]
fn the_endpoints_read_from_metadata_are_what_a_request_is_checked_against() {
    let parsed = parse_service_provider(&sp_metadata("", ACS_POST)).expect("parse");

    let request = parse_request(
        r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-09-10T00:00:00Z" AssertionConsumerServiceURL="https://attacker.test/collect"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>"#,
    )
    .expect("parse request");

    assert!(
        resolve_consumer_service(&request, &parsed.consumer_services).is_err(),
        "the metadata is the only source of truth for where an assertion may be posted"
    );
}

#[test]
fn an_encryption_only_key_is_not_taken_as_a_signing_key() {
    let metadata = sp_metadata("", ACS_POST).replace(r#"use="signing""#, r#"use="encryption""#);
    assert_eq!(
        parse_service_provider(&metadata).unwrap_err(),
        MetadataFault::NoSigningCertificate
    );
}

#[test]
fn a_key_with_no_use_attribute_serves_for_signing() {
    let metadata = sp_metadata("", ACS_POST).replace(r#" use="signing""#, "");
    let parsed = parse_service_provider(&metadata).expect("parse");
    assert_eq!(parsed.signing_certificates.len(), 1);
}

#[test]
fn a_service_provider_with_no_endpoint_is_refused() {
    assert_eq!(
        parse_service_provider(&sp_metadata("", "")).unwrap_err(),
        MetadataFault::NoConsumerService
    );
}

#[test]
fn an_endpoint_using_a_binding_this_server_does_not_speak_is_refused() {
    let artifact = r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://sp.example.com/artifact" index="0"/>"#;
    assert!(matches!(
        parse_service_provider(&sp_metadata("", artifact)).unwrap_err(),
        MetadataFault::UnsupportedBinding { .. }
    ));
}

#[test]
fn a_certificate_that_is_not_base64_is_refused_rather_than_silently_dropped() {
    let metadata = sp_metadata("", ACS_POST).replace(&certificate(), "not base64 at all !!!");
    assert_eq!(
        parse_service_provider(&metadata).unwrap_err(),
        MetadataFault::CertificateNotBase64
    );
}

#[test]
fn metadata_carrying_a_doctype_is_refused() {
    let metadata = sp_metadata("", ACS_POST).replace(
        r#"<?xml version="1.0"?>"#,
        r#"<?xml version="1.0"?><!DOCTYPE md:EntityDescriptor [<!ENTITY x SYSTEM "http://attacker.test/">]>"#,
    );
    assert_eq!(
        parse_service_provider(&metadata).unwrap_err(),
        MetadataFault::Xml(XmlFault::DoctypePresent)
    );
}

#[test]
fn an_identity_provider_metadata_document_this_server_publishes_parses_as_xml() {
    let document = identity_provider(&IdentityProvider {
        entity_id: "https://idp.argus.test",
        sso_post_location: "https://idp.argus.test/saml/sso",
        sso_redirect_location: "https://idp.argus.test/saml/sso",
        signing_certificate_base64: &certificate(),
    });

    argus_saml::xml::parse(&document).expect("what this server publishes must parse");
    assert!(document.contains("IDPSSODescriptor"));
    assert!(document.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
    assert!(document.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"));
    assert!(document.contains(&certificate()));
}

#[test]
fn the_published_metadata_lists_only_name_identifier_formats_this_server_issues() {
    let document = identity_provider(&IdentityProvider {
        entity_id: "https://idp.argus.test",
        sso_post_location: "https://idp.argus.test/saml/sso",
        sso_redirect_location: "https://idp.argus.test/saml/sso",
        signing_certificate_base64: &certificate(),
    });

    assert!(document.contains("nameid-format:persistent"));
    assert!(document.contains("nameid-format:transient"));
    assert!(document.contains("nameid-format:emailAddress"));
    assert!(
        !document.contains("nameid-format:kerberos"),
        "advertising a format this server cannot issue makes a peer's request fail at the worst moment"
    );
}

#[test]
fn an_entity_id_carrying_markup_cannot_break_out_of_the_published_document() {
    let document = identity_provider(&IdentityProvider {
        entity_id: r#"https://evil.test" foo="bar"#,
        sso_post_location: "https://idp.argus.test/saml/sso",
        sso_redirect_location: "https://idp.argus.test/saml/sso",
        signing_certificate_base64: &certificate(),
    });

    let parsed = argus_saml::xml::parse(&document).expect("still well formed");
    let root = parsed.document_element().expect("root");
    assert_eq!(
        parsed.get_attribute(root, "entityID"),
        Some(r#"https://evil.test" foo="bar"#)
    );
    assert!(parsed.get_attribute(root, "foo").is_none());
}
