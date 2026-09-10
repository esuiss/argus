#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::id::ClientId;
use argus_core::par::{
    DEFAULT_LIFETIME, MAX_LIFETIME, MIN_LIFETIME, ParFault, Profile, PushedRequest,
    check_authorize_entry, check_push, check_redemption, identifier_of, lifetime, request_uri_for,
};
use argus_core::time::{Duration, Timestamp};

const NOW: Timestamp = Timestamp::from_unix_seconds(1_800_000_000);

fn client(raw: &str) -> ClientId {
    ClientId::new(raw).expect("client")
}

fn parameters(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn pushed(consumed: bool, offset: i64) -> PushedRequest {
    PushedRequest {
        client: client("demo-client"),
        parameters: parameters(&[
            ("client_id", "demo-client"),
            ("response_type", "code"),
            ("redirect_uri", "https://app.test/cb"),
            ("scope", "openid"),
            ("resource", "https://a.test"),
            ("resource", "https://b.test"),
        ]),
        issued_at: NOW,
        expires_at: Timestamp::from_unix_seconds(NOW.as_unix_seconds() + offset),
        consumed,
    }
}

#[test]
fn a_request_uri_carries_the_registered_urn_prefix() {
    let uri = request_uri_for("abc123");
    assert_eq!(uri, "urn:ietf:params:oauth:request_uri:abc123");
    assert_eq!(identifier_of(&uri), Some("abc123"));
}

#[test]
fn something_that_is_not_a_request_uri_is_not_read_as_one() {
    for raw in [
        "https://attacker.test/request.jwt",
        "urn:ietf:params:oauth:request_uri:",
        "urn:ietf:params:oauth:request_uri:../../etc/passwd",
        "urn:ietf:params:oauth:request_uri:a b",
        "abc123",
    ] {
        assert!(
            identifier_of(raw).is_none(),
            "{raw} must not be accepted as a request_uri this server issued"
        );
    }
}

#[test]
fn a_request_uri_identifier_cannot_carry_a_path() {
    assert!(identifier_of("urn:ietf:params:oauth:request_uri:a/b").is_none());
    assert!(identifier_of("urn:ietf:params:oauth:request_uri:a%2Fb").is_none());
}

#[test]
fn a_pushed_request_may_not_carry_a_request_uri_of_its_own() {
    let body = parameters(&[
        ("client_id", "demo-client"),
        ("request_uri", "urn:ietf:params:oauth:request_uri:x"),
    ]);

    assert_eq!(
        check_push(&body, &client("demo-client")).unwrap_err(),
        ParFault::RequestUriInPushedRequest,
        "chaining pushed requests would let one client stack another's parameters"
    );
}

#[test]
fn a_pushed_request_declaring_another_client_is_refused() {
    let body = parameters(&[("client_id", "someone-else")]);

    assert_eq!(
        check_push(&body, &client("demo-client")).unwrap_err(),
        ParFault::ClientMismatch,
        "the authenticated client is the only one that may push on its own behalf"
    );
}

#[test]
fn a_pushed_request_with_no_client_id_is_refused() {
    assert_eq!(
        check_push(&parameters(&[("scope", "openid")]), &client("demo-client")).unwrap_err(),
        ParFault::MissingClientId
    );
}

#[test]
fn a_matching_pushed_request_is_accepted() {
    check_push(
        &parameters(&[("client_id", "demo-client"), ("scope", "openid")]),
        &client("demo-client"),
    )
    .expect("this is the ordinary case");
}

#[test]
fn a_fresh_request_uri_is_redeemed_by_the_client_that_pushed_it() {
    check_redemption(&pushed(false, 90), &client("demo-client"), NOW).expect("redeem");
}

#[test]
fn a_request_uri_is_single_use() {
    assert_eq!(
        check_redemption(&pushed(true, 90), &client("demo-client"), NOW).unwrap_err(),
        ParFault::AlreadyUsed,
        "a replayable request_uri is an authorization request an attacker can resubmit"
    );
}

#[test]
fn an_expired_request_uri_is_refused() {
    assert_eq!(
        check_redemption(&pushed(false, -1), &client("demo-client"), NOW).unwrap_err(),
        ParFault::Expired
    );
}

#[test]
fn a_request_uri_pushed_by_one_client_cannot_be_presented_by_another() {
    assert_eq!(
        check_redemption(&pushed(false, 90), &client("other-client"), NOW).unwrap_err(),
        ParFault::NotYours,
        "without this a client could hand its request_uri to another and borrow its identity"
    );
}

#[test]
fn the_lifetime_is_clamped_to_the_window_the_specification_allows() {
    assert_eq!(lifetime(None), DEFAULT_LIFETIME);
    assert_eq!(
        lifetime(Some(Duration::from_seconds(60))),
        Duration::from_seconds(60)
    );
    assert_eq!(lifetime(Some(Duration::from_seconds(1))), MIN_LIFETIME);
    assert_eq!(lifetime(Some(Duration::from_seconds(86_400))), MAX_LIFETIME);
    assert_eq!(lifetime(Some(Duration::from_seconds(-5))), MIN_LIFETIME);
}

#[test]
fn repeated_parameters_survive_the_push() {
    let request = pushed(false, 90);
    assert_eq!(
        request.all("resource"),
        ["https://a.test", "https://b.test"],
        "resource indicators repeat, and flattening them would silently drop one"
    );
    assert_eq!(request.parameter("scope"), Some("openid"));
    assert_eq!(request.parameter("nonce"), None);
}

#[test]
fn the_permissive_profile_lets_an_ordinary_authorize_request_through() {
    check_authorize_entry(Profile::permissive(), None).expect("ordinary deployments still work");
}

#[test]
fn the_financial_grade_profile_refuses_an_authorize_request_that_was_not_pushed() {
    assert_eq!(
        check_authorize_entry(Profile::financial_grade(), None).unwrap_err(),
        ParFault::PushRequired,
        "the profile says the server shall reject authorization requests sent without a push"
    );

    check_authorize_entry(
        Profile::financial_grade(),
        Some("urn:ietf:params:oauth:request_uri:x"),
    )
    .expect("a pushed request is what the profile asks for");
}

#[test]
fn the_financial_grade_profile_also_demands_the_other_two_constraints() {
    let profile = Profile::financial_grade();
    assert!(profile.require_sender_constrained_tokens);
    assert!(profile.forbid_public_clients);

    let permissive = Profile::permissive();
    assert!(!permissive.require_sender_constrained_tokens);
    assert!(!permissive.forbid_public_clients);
}

#[test]
fn the_default_profile_is_the_permissive_one() {
    assert_eq!(Profile::default(), Profile::permissive());
}
