#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod signed_response;

use argus_saml::signature::{BergshamraVerifier, SignatureFault, XmlVerifier};
use signed_response::{der_of, idp_cert_pem, signed_response};

const VICTIM: &str = "b7d3f1a0-persistent";
const ATTACKER: &str = "administrator";

fn verify(document: &str) -> Result<Vec<argus_saml::signature::VerifiedFragment>, SignatureFault> {
    BergshamraVerifier.verify(document, &[der_of(idp_cert_pem())])
}

fn assertion_of(document: &str) -> (usize, usize) {
    let start = document.find("<saml:Assertion").expect("assertion start");
    let end =
        document.find("</saml:Assertion>").expect("assertion end") + "</saml:Assertion>".len();
    (start, end)
}

fn genuine_assertion(document: &str) -> String {
    let (start, end) = assertion_of(document);
    document[start..end].to_owned()
}

fn forged_assertion(id: &str) -> String {
    format!(
        r#"<saml:Assertion ID="{id}" Version="2.0" IssueInstant="2023-11-14T22:13:20Z">\
<saml:Issuer>https://idp.argus.test</saml:Issuer>\
<saml:Subject>\
<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{ATTACKER}</saml:NameID>\
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">\
<saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="https://sp.example.com/acs"/>\
</saml:SubjectConfirmation>\
</saml:Subject>\
<saml:Conditions NotBefore="2023-11-14T22:13:20Z" NotOnOrAfter="2099-01-01T00:00:00Z">\
<saml:AudienceRestriction><saml:Audience>https://sp.example.com/metadata</saml:Audience></saml:AudienceRestriction>\
</saml:Conditions>\
<saml:AuthnStatement AuthnInstant="2023-11-14T22:13:20Z" SessionIndex="_evil">\
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>\
</saml:AuthnStatement>\
</saml:Assertion>"#
    )
    .replace("\\\n", "")
}

fn survives(name: &str, document: &str) {
    match verify(document) {
        Err(_) => {}
        Ok(fragments) => {
            assert!(
                !fragments.is_empty(),
                "{name}: verification succeeded but handed back nothing to act on"
            );
            for fragment in &fragments {
                assert!(
                    !fragment.xml().contains(ATTACKER),
                    "{name}: the forged subject reached business logic\n{}",
                    fragment.xml()
                );
                assert!(
                    fragment.xml().contains(VICTIM),
                    "{name}: the fragment handed back is not the signed assertion\n{}",
                    fragment.xml()
                );
            }
        }
    }
}

#[test]
fn xsw1_the_signed_response_is_wrapped_inside_a_forged_response() {
    let genuine = signed_response();
    let body = genuine
        .strip_prefix(r#"<?xml version="1.0" encoding="UTF-8"?>"#)
        .expect("declaration");

    let attacked = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil-response" Version="2.0" IssueInstant="2023-11-14T22:13:20Z">{body}{}</samlp:Response>"#,
        forged_assertion("_evil-assertion")
    );

    survives("XSW1", &attacked);
}

#[test]
fn xsw2_the_signed_response_is_placed_beside_a_forged_one() {
    let genuine = signed_response();
    let body = genuine
        .strip_prefix(r#"<?xml version="1.0" encoding="UTF-8"?>"#)
        .expect("declaration");

    let attacked = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil-response" Version="2.0" IssueInstant="2023-11-14T22:13:20Z">{}{body}</samlp:Response>"#,
        forged_assertion("_evil-assertion")
    );

    survives("XSW2", &attacked);
}

#[test]
fn xsw3_a_forged_assertion_is_added_as_a_sibling_of_the_signed_one() {
    let genuine = signed_response();
    let (start, _) = assertion_of(&genuine);
    let attacked = format!(
        "{}{}{}",
        &genuine[..start],
        forged_assertion("_evil-assertion"),
        &genuine[start..]
    );

    survives("XSW3", &attacked);
}

#[test]
fn xsw4_a_forged_assertion_becomes_the_parent_of_the_signed_one() {
    let genuine = signed_response();
    let signed = genuine_assertion(&genuine);
    let forged = forged_assertion("_evil-assertion");
    let wrapper = forged.replace("</saml:Assertion>", &format!("{signed}</saml:Assertion>"));

    let attacked = genuine.replace(&signed, &wrapper);
    survives("XSW4", &attacked);
}

#[test]
fn xsw5_the_forged_assertion_takes_the_identifier_of_the_signed_one() {
    let genuine = signed_response();
    let (start, _) = assertion_of(&genuine);
    let attacked = format!(
        "{}{}{}",
        &genuine[..start],
        forged_assertion("_assertion-1"),
        &genuine[start..]
    );

    match verify(&attacked) {
        Err(SignatureFault::Xml(argus_saml::xml::XmlFault::DuplicateId { id })) => {
            assert_eq!(id, "_assertion-1");
        }
        Err(_) => {}
        Ok(fragments) => panic!(
            "two elements share one identifier, so which one the signature covers is undefined: {fragments:?}"
        ),
    }
}

#[test]
fn xsw6_the_signed_assertion_is_hidden_inside_the_signature_of_a_forged_one() {
    let genuine = signed_response();
    let signed = genuine_assertion(&genuine);

    let signature_start = signed.find("<ds:Signature").expect("signature");
    let signature_end = signed.find("</ds:Signature>").expect("close") + "</ds:Signature>".len();
    let signature = &signed[signature_start..signature_end];

    let forged = forged_assertion("_evil-assertion");
    let carrier = forged.replace(
        "<saml:Subject>",
        &format!(
            "{}<saml:Subject>",
            signature.replace(
                "</ds:Signature>",
                &format!("<ds:Object>{signed}</ds:Object></ds:Signature>")
            )
        ),
    );

    let attacked = genuine.replace(&signed, &carrier);
    survives("XSW6", &attacked);
}

#[test]
fn xsw7_the_signed_assertion_is_buried_in_an_extensions_element() {
    let genuine = signed_response();
    let signed = genuine_assertion(&genuine);
    let forged = forged_assertion("_evil-assertion");

    let attacked = genuine.replace(
        &signed,
        &format!("<samlp:Extensions>{signed}</samlp:Extensions>{forged}"),
    );

    survives("XSW7", &attacked);
}

#[test]
fn xsw8_the_signed_assertion_is_moved_into_the_signature_object() {
    let genuine = signed_response();
    let signed = genuine_assertion(&genuine);

    let signature_start = signed.find("<ds:Signature").expect("signature");
    let signature_end = signed.find("</ds:Signature>").expect("close") + "</ds:Signature>".len();
    let signature = signed[signature_start..signature_end].to_owned();

    let stripped = format!("{}{}", &signed[..signature_start], &signed[signature_end..]);

    let relocated = signature.replace(
        "</ds:Signature>",
        &format!("<ds:Object>{stripped}</ds:Object></ds:Signature>"),
    );

    let forged = forged_assertion("_evil-assertion");
    let carrier = forged.replace("<saml:Subject>", &format!("{relocated}<saml:Subject>"));

    let attacked = genuine.replace(&signed, &carrier);
    survives("XSW8", &attacked);
}

#[test]
fn attribute_pollution_cannot_change_which_attributes_resolve() {
    let genuine = signed_response();

    let attacked = genuine.replace(
        r#"<saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3""#,
        r#"<saml:Attribute xmlns:evil="urn:oasis:names:tc:SAML:2.0:assertion" evil:Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" Name="urn:oid:0.9.2342.19200300.100.1.3""#,
    );

    match verify(&attacked) {
        Err(_) => {}
        Ok(fragments) => {
            assert!(
                !fragments[0].xml().contains("1.3.6.1.4.1.5923.1.1.1.6"),
                "a second Name attribute in another prefix must not survive into the verified bytes"
            );
        }
    }
}

#[test]
fn namespace_confusion_cannot_hide_the_signature_from_this_verifier() {
    let genuine = signed_response();

    let attacked = genuine.replace(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ds2="http://www.w3.org/2000/09/xmldsig#">"#,
    );

    survives("namespace confusion", &attacked);

    let renamespaced = genuine.replace(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#IGNORED">"#,
    );

    assert!(
        verify(&renamespaced).is_err(),
        "a signature element outside the XMLDSig namespace is not a signature"
    );
}

#[test]
fn void_canonicalization_hard_fails_instead_of_hashing_nothing() {
    let genuine = signed_response();

    for uri in [
        "unresolvable.xml",
        "../../etc/passwd",
        "https://attacker.test/payload.xml",
        "cid:attachment",
        "",
        "#",
    ] {
        let attacked = genuine.replace(r##"URI="#_assertion-1""##, &format!(r#"URI="{uri}""#));

        let result = verify(&attacked);
        assert!(
            result.is_err(),
            "a reference to {uri:?} must fail closed rather than canonicalize to the empty string"
        );
    }
}

#[test]
fn a_reference_that_resolves_to_nothing_is_not_treated_as_an_empty_document() {
    let genuine = signed_response();
    let attacked = genuine.replace(r##"URI="#_assertion-1""##, r##"URI="#_no_such_element""##);

    assert!(
        verify(&attacked).is_err(),
        "a same-document reference with no target must fail, not hash the empty node set"
    );
}

#[test]
fn a_document_carrying_a_doctype_is_refused_before_any_signature_work() {
    let genuine = signed_response();
    let attacked = genuine.replace(
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#,
    );

    assert!(matches!(
        verify(&attacked),
        Err(SignatureFault::Xml(
            argus_saml::xml::XmlFault::DoctypePresent
        ))
    ));
}

#[test]
fn a_billion_laughs_document_is_refused_at_the_parser() {
    let attacked = concat!(
        r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">"#,
        r#"<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">"#,
        r#"<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">"#,
        r#"]><lolz>&lol2;</lolz>"#
    );

    assert!(matches!(
        argus_saml::xml::parse(attacked),
        Err(argus_saml::xml::XmlFault::DoctypePresent)
    ));
}

#[test]
fn the_corpus_is_not_passing_only_because_every_variant_is_refused() {
    let genuine = signed_response();
    let (start, _) = assertion_of(&genuine);
    let attacked = format!(
        "{}{}{}",
        &genuine[..start],
        forged_assertion("_evil-assertion"),
        &genuine[start..]
    );

    let fragments = verify(&attacked).expect(
        "XSW3 is a well-formed document with a genuine signature; it has to verify, and the \
         defence has to be that only the signed node is handed on",
    );

    assert_eq!(fragments.len(), 1);
    assert!(fragments[0].xml().contains(VICTIM));
    assert!(!fragments[0].xml().contains(ATTACKER));
    assert!(
        attacked.contains(ATTACKER),
        "the forged assertion really is in the document that was verified"
    );
}
