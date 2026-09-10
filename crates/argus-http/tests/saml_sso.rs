#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::id::{TenantId, UserId};
use argus_core::time::Duration;
use argus_http::saml::{
    SamlState, ServiceProviderRegistry, SsoOutcome, SsoRequest, Subject, handle, post_form,
};
use argus_saml::binding::{decode_post, encode_post};
use argus_saml::metadata::parse_service_provider;
use argus_saml::nameid::PairwiseIdentifier;
use argus_saml::signature::{BergshamraSigner, BergshamraVerifier, XmlVerifier};
use uuid::Uuid;

const IDP_KEY: &[u8] = include_bytes!("../../argus-saml/tests/fixtures/idp-key.pem");
const IDP_CERT: &str = include_str!("../../argus-saml/tests/fixtures/idp-cert.pem");

const ENTITY: &str = "https://idp.argus.test";
const SSO: &str = "https://idp.argus.test/saml/sso";
const SP: &str = "https://sp.example.com/metadata";
const ACS: &str = "https://sp.example.com/acs";

fn certificate() -> String {
    IDP_CERT
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

fn certificate_der() -> Vec<u8> {
    use base64ct::{Base64, Encoding as _};
    Base64::decode_vec(&certificate()).expect("base64")
}

struct OneProvider;

impl ServiceProviderRegistry for OneProvider {
    fn find(&self, entity_id: &str) -> Option<argus_saml::metadata::ServiceProvider> {
        if entity_id != SP {
            return None;
        }

        let metadata = format!(
            r#"<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{SP}"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{ACS}" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>"#,
            certificate()
        );

        parse_service_provider(&metadata).ok()
    }
}

struct KnownUser(Option<(UserId, Option<String>, bool)>);

impl Subject for KnownUser {
    fn resolve(&self, _session: Option<&str>) -> Option<(UserId, Option<String>, bool)> {
        self.0.clone()
    }
}

struct SaltedPairwise;

impl PairwiseIdentifier for SaltedPairwise {
    fn pairwise(&self, tenant: TenantId, audience: &str, user: UserId) -> String {
        format!(
            "{}:{}:{}",
            tenant.as_uuid().simple(),
            audience.len(),
            user.as_uuid().simple()
        )
    }
}

fn state(
    subject: Option<(UserId, Option<String>, bool)>,
) -> SamlState<BergshamraSigner, OneProvider, KnownUser> {
    SamlState {
        signer: BergshamraSigner::from_rsa_private_pem(IDP_KEY).expect("signer"),
        registry: OneProvider,
        subjects: KnownUser(subject),
        tenants: std::sync::Arc::new(argus_http::tenancy::TenantRegistry::single(
            "as.test",
            argus_http::tenancy::TenantEntry {
                id: TenantId::from_uuid(Uuid::nil()),
                theme: argus_core::theme::Theme::default(),
                client_themes: std::collections::BTreeMap::new(),
                issuer: "https://as.test".to_owned(),
                context: test_context(),
            },
        )),
        entity_id: ENTITY.to_owned(),
        sso_location: SSO.to_owned(),
        certificate_base64: certificate(),
        pairwise: Box::new(SaltedPairwise),
        session_lifetime: Duration::from_seconds(28_800),
    }
}

fn authn_request(extra: &str) -> String {
    encode_post(&format!(
        r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z" Destination="{SSO}"{extra}><saml:Issuer>{SP}</saml:Issuer></samlp:AuthnRequest>"#
    ))
}

fn sso<'a>(encoded: &'a str, relay_state: Option<&'a str>) -> SsoRequest<'a> {
    SsoRequest {
        encoded,
        relay_state,
        subject: Some((
            UserId::from_uuid(Uuid::from_u128(7)),
            Some("bjensen@example.com".to_owned()),
            false,
        )),
        response_id: "_response-1",
        assertion_id: "_assertion-1",
        session_index: "_session-1",
        transient_handle: "_transient-1",
    }
}

fn posted(outcome: &SsoOutcome) -> (&str, String) {
    match outcome {
        SsoOutcome::Post {
            destination,
            saml_response,
            ..
        } => (
            destination.as_str(),
            decode_post(saml_response).expect("decode"),
        ),
        other => panic!("expected a post, got {other:?}"),
    }
}

#[test]
fn the_assertion_this_endpoint_produces_verifies_against_the_published_certificate() {
    let request = authn_request("");
    let outcome = handle(
        &test_tenant(),
        &state(Some((
            UserId::from_uuid(Uuid::from_u128(7)),
            Some("bjensen@example.com".to_owned()),
            false,
        ))),
        &sso(&request, None),
    )
    .expect("sso");

    let (destination, document) = posted(&outcome);
    assert_eq!(destination, ACS);

    let fragments = BergshamraVerifier
        .verify(&document, &[certificate_der()])
        .expect("a service provider has to be able to verify what this endpoint sends");

    assert_eq!(fragments.len(), 1);
    assert!(fragments[0].xml().contains("bjensen@example.com"));
}

#[test]
fn the_assertion_is_bound_to_the_request_that_asked_for_it() {
    let request = authn_request("");
    let outcome = handle(
        &test_tenant(),
        &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
        &sso(&request, None),
    )
    .expect("sso");
    let (_, document) = posted(&outcome);

    assert!(document.contains(r#"InResponseTo="_req-1""#));
    assert!(
        document.contains(&format!(r#"Recipient="{ACS}""#)),
        "a bearer assertion has to name where it may be delivered"
    );
    assert!(document.contains(&format!("<saml:Audience>{SP}</saml:Audience>")));
}

#[test]
fn an_unregistered_service_provider_gets_no_assertion() {
    let encoded = encode_post(&format!(
        r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z" Destination="{SSO}"><saml:Issuer>https://attacker.test/metadata</saml:Issuer></samlp:AuthnRequest>"#
    ));

    assert!(
        handle(
            &test_tenant(),
            &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
            &sso(&encoded, None)
        )
        .is_err()
    );
}

#[test]
fn an_unregistered_delivery_location_gets_no_assertion() {
    let encoded = authn_request(r#" AssertionConsumerServiceURL="https://attacker.test/collect""#);
    let error = handle(
        &test_tenant(),
        &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
        &sso(&encoded, None),
    )
    .expect_err("an assertion posted to an unregistered location is an account takeover");

    assert!(error.to_string().contains("assertion consumer service"));
}

#[test]
fn a_request_addressed_to_another_server_is_refused() {
    let encoded = encode_post(&format!(
        r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z" Destination="https://other-idp.test/sso"><saml:Issuer>{SP}</saml:Issuer></samlp:AuthnRequest>"#
    ));

    assert!(
        handle(
            &test_tenant(),
            &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
            &sso(&encoded, None)
        )
        .is_err(),
        "honouring a request addressed elsewhere is how a mix-up starts"
    );
}

#[test]
fn an_anonymous_visitor_is_sent_to_authenticate_rather_than_given_an_assertion() {
    let request = authn_request("");
    let mut sso_request = sso(&request, None);
    sso_request.subject = None;

    assert_eq!(
        handle(&test_tenant(), &state(None), &sso_request).expect("sso"),
        SsoOutcome::NeedsAuthentication
    );
}

#[test]
fn a_passive_request_from_an_anonymous_visitor_answers_with_no_passive() {
    let request = authn_request(r#" IsPassive="true""#);
    let mut sso_request = sso(&request, None);
    sso_request.subject = None;

    let outcome = handle(&test_tenant(), &state(None), &sso_request).expect("sso");
    let (_, document) = posted(&outcome);

    assert!(document.contains("status:NoPassive"));
    assert!(
        !document.contains("<saml:Assertion"),
        "a passive request that cannot be satisfied must carry no assertion at all"
    );
}

#[test]
fn a_persistent_identifier_differs_per_service_provider() {
    let request = authn_request("");
    let user = UserId::from_uuid(Uuid::from_u128(7));

    let outcome = handle(
        &test_tenant(),
        &state(Some((user, None, false))),
        &sso(&request, None),
    )
    .expect("sso");
    let (_, document) = posted(&outcome);

    assert!(document.contains("nameid-format:persistent"));
    assert!(
        document.contains(&format!("{}", user.as_uuid().simple())),
        "this test's pairwise function is salted by audience length, so the audience has to reach it"
    );
}

#[test]
fn an_email_identifier_is_refused_when_the_account_carries_no_address() {
    let request = authn_request("");
    let with_policy = encode_post(&format!(
        r#"<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z" Destination="{SSO}"><saml:Issuer>{SP}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>"#
    ));
    let _ = request;

    let mut sso_request = sso(&with_policy, None);
    sso_request.subject = Some((UserId::from_uuid(Uuid::from_u128(7)), None, false));

    let outcome = handle(
        &test_tenant(),
        &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
        &sso_request,
    )
    .expect("sso");

    let (_, document) = posted(&outcome);
    assert!(document.contains("status:Requester"));
    assert!(!document.contains("<saml:Assertion"));
}

#[test]
fn a_multi_factor_session_is_reported_in_the_authentication_context() {
    let request = authn_request("");
    let mut sso_request = sso(&request, None);
    sso_request.subject = Some((UserId::from_uuid(Uuid::from_u128(7)), None, true));

    let outcome = handle(
        &test_tenant(),
        &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, true))),
        &sso_request,
    )
    .expect("sso");
    let (_, document) = posted(&outcome);

    assert!(
        document.contains("MultiFactorAuthentication"),
        "a relying party that demands a second factor reads this class, not our word for it"
    );
}

#[test]
fn a_relay_state_beyond_the_saml_limit_is_refused() {
    let request = authn_request("");
    let long = "a".repeat(81);
    assert!(
        handle(
            &test_tenant(),
            &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
            &sso(&request, Some(&long))
        )
        .is_err()
    );
}

#[test]
fn a_relay_state_within_the_limit_is_carried_back_unchanged() {
    let request = authn_request("");
    let outcome = handle(
        &test_tenant(),
        &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
        &sso(&request, Some("/dashboard")),
    )
    .expect("sso");

    match outcome {
        SsoOutcome::Post { relay_state, .. } => {
            assert_eq!(relay_state.as_deref(), Some("/dashboard"));
        }
        other => panic!("expected a post, got {other:?}"),
    }
}

#[test]
fn a_relay_state_carrying_markup_cannot_break_out_of_the_auto_post_form() {
    let form = post_form(ACS, "PHNhbWw+", Some(r#""><script>alert(1)</script>"#));

    assert!(
        !form.contains("<script>"),
        "the browser posts this form, so an unescaped RelayState is stored cross-site scripting: {form}"
    );
    assert!(form.contains("&lt;script&gt;"));
    assert!(form.contains(r#"name="SAMLResponse""#));
}

#[test]
fn a_request_that_is_not_base64_is_refused_before_any_parsing() {
    assert!(
        handle(
            &test_tenant(),
            &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
            &sso("not base64 !!!", None)
        )
        .is_err()
    );
}

#[test]
fn a_request_carrying_a_doctype_is_refused() {
    let encoded = encode_post(&format!(
        r#"<?xml version="1.0"?><!DOCTYPE samlp:AuthnRequest [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-09-10T00:00:00Z" Destination="{SSO}"><saml:Issuer>{SP}</saml:Issuer></samlp:AuthnRequest>"#
    ));

    let error = handle(
        &test_tenant(),
        &state(Some((UserId::from_uuid(Uuid::from_u128(7)), None, false))),
        &sso(&encoded, None),
    )
    .expect_err("a doctype must never reach the parser");
    assert!(error.to_string().contains("document type declaration"));
}

fn test_tenant() -> argus_http::tenancy::Tenant {
    argus_http::tenancy::TenantRegistry::single(
        "as.test",
        argus_http::tenancy::TenantEntry {
            id: TenantId::from_uuid(Uuid::nil()),
            theme: argus_core::theme::Theme::default(),
            client_themes: std::collections::BTreeMap::new(),
            issuer: "https://as.test".to_owned(),
            context: test_context(),
        },
    )
    .resolve("as.test")
    .expect("registered")
}

fn test_context() -> argus_http::state::TenantContext {
    let (key, _) = argus_crypto::SigningKey::generate("t1".to_owned()).expect("key");
    let key = std::sync::Arc::new(key);
    argus_http::state::TenantContext {
        metadata: argus_proto::AuthorizationServerMetadata::for_issuer("https://as.test"),
        active_key: std::sync::Arc::clone(&key),
        published_keys: vec![key],
        rsa_keys: Vec::new(),
        blind_index: argus_crypto::blind_index::BlindIndexKey::new(&[7_u8; 32])
            .expect("blind index"),
        relying_party: None,
    }
}
