#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::scim::ResourceType;
use argus_core::scim_event::{
    Event, EventFault, EventKind, all_event_uris, changed_attributes, claims, redact, resource_uri,
};
use serde_json::{Value, json};

fn notice() -> Event {
    Event {
        kind: EventKind::PatchNotice,
        subject_uri: "/Users/2b2f880af".to_owned(),
        external_id: Some("hr-1".to_owned()),
        attributes: Vec::from(["userName".to_owned(), "name.familyName".to_owned()]),
        payload: None,
    }
}

#[test]
fn the_subject_is_carried_in_sub_id_and_never_in_sub() {
    let token = claims(
        &notice(),
        "https://idp.test",
        "https://rp.test",
        "j1",
        "t1",
        100,
    )
    .unwrap();

    assert_eq!(token["sub_id"]["format"], "scim");
    assert_eq!(token["sub_id"]["uri"], "/Users/2b2f880af");
    assert_eq!(token["sub_id"]["externalId"], "hr-1");
    assert!(
        token.get("sub").is_none(),
        "RFC 9967 2.1 forbids sub so a SET is never mistaken for an authorization token"
    );
}

#[test]
fn the_transaction_identifier_is_a_token_level_claim_beside_jti() {
    let token = claims(
        &notice(),
        "https://idp.test",
        "https://rp.test",
        "j1",
        "t1",
        100,
    )
    .unwrap();
    assert_eq!(token["txn"], "t1");
    assert_eq!(token["jti"], "j1");
    assert_eq!(token["iat"], 100);
    assert_eq!(token["iss"], "https://idp.test");
    assert_eq!(token["aud"], "https://rp.test");
}

#[test]
fn a_notice_event_names_the_changed_attributes_and_carries_no_data() {
    let token = claims(
        &notice(),
        "https://idp.test",
        "https://rp.test",
        "j1",
        "t1",
        100,
    )
    .unwrap();
    let detail = &token["events"]["urn:ietf:params:scim:event:prov:patch:notice"];

    assert_eq!(detail["attributes"][0], "userName");
    assert_eq!(detail["attributes"][1], "name.familyName");
    assert!(
        detail.get("data").is_none(),
        "a notice must send the receiver back for the resource rather than putting it on the wire"
    );
}

#[test]
fn a_full_event_carries_data_and_no_attribute_list() {
    let event = Event {
        kind: EventKind::CreateFull,
        subject_uri: "/Users/1".to_owned(),
        external_id: None,
        attributes: Vec::new(),
        payload: Some(json!({ "userName": "bjensen" })),
    };
    let token = claims(
        &event,
        "https://idp.test",
        "https://rp.test",
        "j1",
        "t1",
        100,
    )
    .unwrap();
    let detail = &token["events"]["urn:ietf:params:scim:event:prov:create:full"];

    assert_eq!(detail["data"]["userName"], "bjensen");
    assert!(detail.get("attributes").is_none());
}

#[test]
fn an_event_may_not_carry_both_a_payload_and_an_attribute_list() {
    let event = Event {
        kind: EventKind::CreateFull,
        subject_uri: "/Users/1".to_owned(),
        external_id: None,
        attributes: Vec::from(["userName".to_owned()]),
        payload: Some(json!({ "userName": "bjensen" })),
    };
    assert_eq!(
        claims(
            &event,
            "https://idp.test",
            "https://rp.test",
            "j1",
            "t1",
            100
        )
        .unwrap_err(),
        EventFault::BothPayloadAndAttributes
    );
}

#[test]
fn an_event_must_carry_one_of_the_two() {
    let event = Event {
        kind: EventKind::PutNotice,
        subject_uri: "/Users/1".to_owned(),
        external_id: None,
        attributes: Vec::new(),
        payload: None,
    };
    assert_eq!(
        claims(
            &event,
            "https://idp.test",
            "https://rp.test",
            "j1",
            "t1",
            100
        )
        .unwrap_err(),
        EventFault::NeitherPayloadNorAttributes
    );
}

#[test]
fn a_delete_event_carries_no_payload_at_all() {
    let event = Event {
        kind: EventKind::Delete,
        subject_uri: "/Users/1".to_owned(),
        external_id: None,
        attributes: Vec::new(),
        payload: None,
    };
    let token = claims(
        &event,
        "https://idp.test",
        "https://rp.test",
        "j1",
        "t1",
        100,
    )
    .unwrap();
    let detail = &token["events"]["urn:ietf:params:scim:event:prov:delete"];

    assert_eq!(*detail, json!({}));
}

#[test]
fn the_subject_must_be_a_scim_resource_path() {
    let event = Event {
        subject_uri: "2b2f880af".to_owned(),
        ..notice()
    };
    assert_eq!(
        claims(
            &event,
            "https://idp.test",
            "https://rp.test",
            "j1",
            "t1",
            100
        )
        .unwrap_err(),
        EventFault::SubjectNotAResourcePath
    );
}

#[test]
fn a_value_that_is_never_returned_is_stripped_before_it_reaches_a_token() {
    let payload = json!({
        "userName": "bjensen",
        "password": "hunter2",
        "name": { "givenName": "Barbara", "secret": "x" }
    });

    let stripped = redact(&payload);
    assert_eq!(stripped["userName"], "bjensen");
    assert!(
        stripped.get("password").is_none(),
        "the RFC's own example lists password among the changed attributes of a full create"
    );
    assert!(stripped["name"].get("secret").is_none());
    assert_eq!(stripped["name"]["givenName"], "Barbara");
}

#[test]
fn a_full_event_cannot_smuggle_a_credential_through_the_payload() {
    let event = Event {
        kind: EventKind::CreateFull,
        subject_uri: "/Users/1".to_owned(),
        external_id: None,
        attributes: Vec::new(),
        payload: Some(json!({ "userName": "bjensen", "password": "hunter2" })),
    };
    let token = claims(
        &event,
        "https://idp.test",
        "https://rp.test",
        "j1",
        "t1",
        100,
    )
    .unwrap();
    let serialised = serde_json::to_string(&token).unwrap();

    assert!(
        !serialised.contains("hunter2"),
        "a credential must never leave the server inside an event: {serialised}"
    );
}

#[test]
fn the_advertised_event_uris_are_the_ones_this_server_can_actually_emit() {
    let advertised = all_event_uris();

    assert!(advertised.contains(&"urn:ietf:params:scim:event:prov:create:notice"));
    assert!(advertised.contains(&"urn:ietf:params:scim:event:prov:delete"));
    assert!(
        !advertised.contains(&"urn:ietf:params:scim:event:prov:create:full"),
        "full payload events put the whole user record on the wire and are not enabled yet"
    );
    assert!(!advertised.contains(&"urn:ietf:params:scim:event:misc:asyncresp"));
}

#[test]
fn every_advertised_uri_is_from_the_iana_registry() {
    let registry = [
        "urn:ietf:params:scim:event:feed:add",
        "urn:ietf:params:scim:event:feed:remove",
        "urn:ietf:params:scim:event:prov:create:notice",
        "urn:ietf:params:scim:event:prov:create:full",
        "urn:ietf:params:scim:event:prov:patch:notice",
        "urn:ietf:params:scim:event:prov:patch:full",
        "urn:ietf:params:scim:event:prov:put:notice",
        "urn:ietf:params:scim:event:prov:put:full",
        "urn:ietf:params:scim:event:prov:delete",
        "urn:ietf:params:scim:event:prov:activate",
        "urn:ietf:params:scim:event:prov:deactivate",
        "urn:ietf:params:scim:event:misc:asyncresp",
    ];

    for uri in all_event_uris() {
        assert!(registry.contains(&uri), "{uri} is not a registered event");
    }
}

#[test]
fn the_changed_attributes_use_the_patch_path_form() {
    let before = json!({
        "userName": "bjensen",
        "name": { "givenName": "Barbara", "familyName": "Jensen" },
        "active": true
    });
    let after = json!({
        "userName": "bjensen",
        "name": { "givenName": "Barbara", "familyName": "Smith" },
        "active": false
    });

    assert_eq!(
        changed_attributes(&before, &after),
        ["active", "name.familyName"]
    );
}

#[test]
fn an_added_attribute_is_reported_as_changed() {
    let before = json!({ "userName": "bjensen" });
    let after = json!({ "userName": "bjensen", "displayName": "Barbara" });
    assert_eq!(changed_attributes(&before, &after), ["displayName"]);
}

#[test]
fn a_removed_attribute_is_reported_as_changed() {
    let before = json!({ "userName": "bjensen", "displayName": "Barbara" });
    let after = json!({ "userName": "bjensen" });
    assert_eq!(changed_attributes(&before, &after), ["displayName"]);
}

#[test]
fn the_server_managed_attributes_are_not_reported_as_changes() {
    let before = json!({ "id": "1", "meta": { "lastModified": "a" }, "userName": "x" });
    let after = json!({ "id": "1", "meta": { "lastModified": "b" }, "userName": "x" });

    assert!(
        changed_attributes(&before, &after).is_empty(),
        "every write moves lastModified; reporting it would make every event look like a change"
    );
}

#[test]
fn a_write_that_changes_nothing_produces_no_attribute_list() {
    let same = json!({ "userName": "bjensen", "active": true });
    assert!(changed_attributes(&same, &same).is_empty());
}

#[test]
fn the_subject_path_matches_the_endpoint_the_receiver_will_call_back() {
    assert_eq!(resource_uri(ResourceType::User, "abc"), "/Users/abc");
    assert_eq!(resource_uri(ResourceType::Group, "abc"), "/Groups/abc");
}

#[test]
fn a_serialised_event_token_round_trips_as_json() {
    let token = claims(
        &notice(),
        "https://idp.test",
        "https://rp.test",
        "j1",
        "t1",
        100,
    )
    .unwrap();
    let text = serde_json::to_string(&token).unwrap();
    let back: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(back, token);
}
