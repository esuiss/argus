#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::must_use_candidate,
    dead_code
)]

use argus_core::time::{Duration, Timestamp};
use argus_saml::nameid::{NameId, NameIdFormat};
use argus_saml::response::{
    ATTRIBUTE_NAME_FORMAT_URI, AUTHN_CONTEXT_PASSWORD_PROTECTED, AssertionRequest, Attribute,
    template,
};
use argus_saml::signature::{BergshamraSigner, BergshamraVerifier, XmlSigner, XmlVerifier};

const NOW: Timestamp = Timestamp::from_unix_seconds(1_700_000_000);

pub(crate) fn idp_key() -> &'static [u8] {
    include_bytes!("fixtures/idp-key.pem")
}

pub(crate) fn idp_cert_pem() -> &'static str {
    include_str!("fixtures/idp-cert.pem")
}

pub(crate) fn foreign_cert_pem() -> &'static str {
    include_str!("fixtures/foreign-cert.pem")
}

pub(crate) fn der_of(pem: &str) -> Vec<u8> {
    use base64ct::{Base64, Encoding as _};
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    Base64::decode_vec(&body).expect("certificate is base64")
}

pub(crate) fn base64_of(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

pub(crate) fn signed_response() -> String {
    let name_id = NameId {
        format: NameIdFormat::Persistent,
        value: "b7d3f1a0-persistent".to_owned(),
    };

    let attributes = [Attribute {
        name: "urn:oid:0.9.2342.19200300.100.1.3".to_owned(),
        name_format: ATTRIBUTE_NAME_FORMAT_URI.to_owned(),
        values: Vec::from(["bjensen@example.com".to_owned()]),
    }];

    let certificate = base64_of(idp_cert_pem());

    let request = AssertionRequest {
        issuer: "https://idp.argus.test",
        audience: "https://sp.example.com/metadata",
        recipient: "https://sp.example.com/acs",
        in_response_to: Some("_request-1"),
        name_id: &name_id,
        session_index: "_session-1",
        authn_context: AUTHN_CONTEXT_PASSWORD_PROTECTED,
        attributes: &attributes,
        response_id: "_response-1",
        assertion_id: "_assertion-1",
        certificate_base64: &certificate,
        now: NOW,
        lifetime: Duration::from_seconds(300),
        session_expiry: NOW.saturating_add(Duration::from_seconds(28_800)),
    };

    let unsigned = template(&request).expect("template");
    BergshamraSigner::from_rsa_private_pem(idp_key())
        .expect("signer")
        .sign(&unsigned)
        .expect("sign")
}

pub(crate) fn verify(
    document: &str,
) -> Result<Vec<argus_saml::signature::VerifiedFragment>, argus_saml::signature::SignatureFault> {
    BergshamraVerifier.verify(document, &[der_of(idp_cert_pem())])
}

#[test]
fn a_response_this_server_signs_verifies_against_its_own_certificate() {
    let document = signed_response();
    let fragments = verify(&document).expect("the signature this server produced must verify");

    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].reference_uri(), "#_assertion-1");
}

#[test]
fn the_verified_fragment_is_the_assertion_and_not_the_whole_response() {
    let document = signed_response();
    let fragments = verify(&document).expect("verify");
    let assertion = fragments[0].xml();

    assert!(assertion.contains("Assertion"));
    assert!(
        !assertion.contains("samlp:Response"),
        "business logic must receive the signed node alone, never the envelope: {assertion}"
    );
    assert!(assertion.contains("b7d3f1a0-persistent"));
    assert!(assertion.contains("bjensen@example.com"));
}

#[test]
fn the_verified_fragment_stands_on_its_own_as_a_document() {
    let document = signed_response();
    let fragments = verify(&document).expect("verify");

    fragments[0]
        .document()
        .expect("exclusive canonicalization must carry the namespaces the subtree uses");
}

#[test]
fn a_certificate_this_server_does_not_trust_does_not_verify() {
    let document = signed_response();
    let result = BergshamraVerifier.verify(&document, &[der_of(foreign_cert_pem())]);
    assert!(
        result.is_err(),
        "a signature verified against an untrusted key would let anyone mint assertions"
    );
}

#[test]
fn a_response_with_no_trusted_key_at_all_does_not_verify() {
    let document = signed_response();
    assert!(BergshamraVerifier.verify(&document, &[]).is_err());
}

#[test]
fn a_single_flipped_byte_in_the_assertion_breaks_the_signature() {
    let document = signed_response().replace("bjensen@example.com", "attacker@example.com");
    assert!(
        verify(&document).is_err(),
        "the digest must cover the attribute values the relying party will trust"
    );
}

#[test]
fn changing_the_audience_breaks_the_signature() {
    let document = signed_response().replace(
        "https://sp.example.com/metadata",
        "https://other.example.com/metadata",
    );
    assert!(verify(&document).is_err());
}

#[test]
fn an_unsigned_response_is_refused_rather_than_accepted_as_unprotected() {
    let document = signed_response();
    let start = document.find("<ds:Signature").expect("signature");
    let end = document.find("</ds:Signature>").expect("close") + "</ds:Signature>".len();
    let stripped = format!("{}{}", &document[..start], &document[end..]);

    assert!(verify(&stripped).is_err());
}
