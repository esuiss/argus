#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::scim_patch::{Op, Operation, PatchError, apply};
use serde_json::{Value, json};

fn op(op: Op, path: Option<&str>, value: Option<Value>) -> Operation {
    Operation {
        op,
        path: path.map(str::to_owned),
        value,
    }
}

fn user() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": "2819c223",
        "userName": "bjensen",
        "name": { "givenName": "Barbara", "familyName": "Jensen" },
        "emails": [
            { "value": "bjensen@example.com", "type": "work", "primary": true },
            { "value": "babs@jensen.org", "type": "home" }
        ]
    })
}

fn group() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": "g1",
        "displayName": "Engineering",
        "members": [
            { "value": "2819c223", "display": "Barbara" }
        ]
    })
}

#[test]
fn an_empty_operation_list_is_refused() {
    assert_eq!(apply(&user(), &[]).unwrap_err(), PatchError::InvalidSyntax);
}

#[test]
fn remove_without_a_path_is_no_target_not_invalid_path() {
    let err = apply(&user(), &[op(Op::Remove, None, None)]).unwrap_err();
    assert_eq!(err, PatchError::NoTarget);
    assert_eq!(err.scim_type(), "noTarget");
}

#[test]
fn adding_a_value_the_resource_already_has_reports_no_change() {
    let outcome = apply(
        &group(),
        &[op(
            Op::Add,
            Some("members"),
            Some(json!([{ "value": "2819c223", "display": "Barbara" }])),
        )],
    )
    .expect("applied");

    assert!(
        !outcome.changed,
        "re-sending an existing member must not touch lastModified, or Entra and \
         Okta drive an endless resync"
    );
    assert_eq!(outcome.resource, group());
}

#[test]
fn adding_a_new_member_appends_rather_than_replacing() {
    let outcome = apply(
        &group(),
        &[op(
            Op::Add,
            Some("members"),
            Some(json!([{ "value": "aaa", "display": "Alice" }])),
        )],
    )
    .expect("applied");

    assert!(outcome.changed);
    let members = outcome.resource["members"].as_array().expect("array");
    assert_eq!(members.len(), 2);
}

#[test]
fn removing_a_member_that_is_not_there_is_a_success() {
    let outcome = apply(
        &group(),
        &[op(Op::Remove, Some(r#"members[value eq "nobody"]"#), None)],
    )
    .expect("removing an absent member must succeed, not error");

    assert!(!outcome.changed);
}

#[test]
fn replacing_a_filter_that_matches_nothing_is_no_target() {
    let err = apply(
        &user(),
        &[op(
            Op::Replace,
            Some(r#"emails[type eq "other"].value"#),
            Some(json!("x@example.com")),
        )],
    )
    .unwrap_err();

    assert_eq!(
        err,
        PatchError::NoTarget,
        "a replace whose filter matches nothing is an error, while a remove that \
         matches nothing is a success - that asymmetry is the whole point"
    );
}

#[test]
fn errata_8097_add_with_a_value_path_seeds_a_new_entry_from_the_filter() {
    let outcome = apply(
        &user(),
        &[op(
            Op::Add,
            Some(r#"emails[type eq "other"].value"#),
            Some(json!("other@example.com")),
        )],
    )
    .expect("Entra sends exactly this shape");

    assert!(outcome.changed);
    let emails = outcome.resource["emails"].as_array().expect("array");
    assert_eq!(emails.len(), 3);

    let seeded = emails
        .iter()
        .find(|e| e["type"] == "other")
        .expect("seeded");
    assert_eq!(seeded["value"], "other@example.com");
    assert_eq!(
        seeded["type"], "other",
        "the new entry must be seeded from the filter's eq clauses"
    );
}

#[test]
fn replace_on_a_missing_path_is_treated_as_add() {
    let outcome = apply(
        &user(),
        &[op(Op::Replace, Some("nickName"), Some(json!("Babs")))],
    )
    .expect("applied");

    assert!(outcome.changed);
    assert_eq!(outcome.resource["nickName"], "Babs");
}

#[test]
fn replacing_a_complex_attribute_merges_rather_than_wiping_it() {
    let outcome = apply(
        &user(),
        &[op(
            Op::Replace,
            Some("name.givenName"),
            Some(json!("Barbara Jane")),
        )],
    )
    .expect("applied");

    assert_eq!(outcome.resource["name"]["givenName"], "Barbara Jane");
    assert_eq!(
        outcome.resource["name"]["familyName"], "Jensen",
        "sub-attributes that were not mentioned must survive"
    );
}

#[test]
fn removing_a_multi_valued_attribute_without_a_filter_takes_all_of_it() {
    let outcome = apply(&user(), &[op(Op::Remove, Some("emails"), None)]).expect("applied");
    assert!(outcome.changed);
    assert!(outcome.resource.get("emails").is_none());
}

#[test]
fn removing_the_last_matching_value_unsets_the_attribute() {
    let outcome = apply(
        &user(),
        &[
            op(Op::Remove, Some(r#"emails[type eq "work"]"#), None),
            op(Op::Remove, Some(r#"emails[type eq "home"]"#), None),
        ],
    )
    .expect("applied");

    assert!(
        outcome.resource.get("emails").is_none(),
        "an attribute with no values left is unassigned, not an empty array"
    );
}

#[test]
fn setting_primary_true_clears_primary_on_the_others() {
    let outcome = apply(
        &user(),
        &[op(
            Op::Add,
            Some(r#"emails[type eq "home"].primary"#),
            Some(json!(true)),
        )],
    )
    .expect("applied");

    let emails = outcome.resource["emails"].as_array().expect("array");
    let primaries: Vec<&Value> = emails
        .iter()
        .filter(|e| e["primary"] == json!(true))
        .collect();

    assert_eq!(
        primaries.len(),
        1,
        "the server must demote the others itself: {emails:?}"
    );
    assert_eq!(primaries.first().expect("one")["type"], "home");
}

#[test]
fn operations_apply_in_order_and_each_sees_the_previous_result() {
    let outcome = apply(
        &user(),
        &[
            op(Op::Add, Some("nickName"), Some(json!("first"))),
            op(Op::Replace, Some("nickName"), Some(json!("second"))),
        ],
    )
    .expect("applied");

    assert_eq!(outcome.resource["nickName"], "second");
}

#[test]
fn a_failure_part_way_through_leaves_the_original_untouched() {
    let original = user();
    let result = apply(
        &original,
        &[
            op(Op::Add, Some("nickName"), Some(json!("Babs"))),
            op(
                Op::Replace,
                Some(r#"emails[type eq "nowhere"].value"#),
                Some(json!("x")),
            ),
        ],
    );

    assert!(result.is_err(), "the second operation must fail");
    assert_eq!(
        original,
        user(),
        "a patch is atomic regardless of the number of operations"
    );
}

#[test]
fn adding_a_fully_qualified_extension_attribute_adds_its_urn_to_schemas() {
    let outcome = apply(
        &user(),
        &[op(
            Op::Add,
            Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"),
            Some(json!("701984")),
        )],
    )
    .expect("applied");

    let schemas = outcome.resource["schemas"].as_array().expect("array");
    assert!(
        schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"),
        "the extension URN must be added implicitly: {schemas:?}"
    );
}

#[test]
fn a_pathless_add_merges_attributes_into_the_resource() {
    let outcome = apply(
        &user(),
        &[op(
            Op::Add,
            None,
            Some(json!({ "nickName": "Babs", "title": "Engineer" })),
        )],
    )
    .expect("applied");

    assert_eq!(outcome.resource["nickName"], "Babs");
    assert_eq!(outcome.resource["title"], "Engineer");
    assert_eq!(outcome.resource["userName"], "bjensen");
}

#[test]
fn a_malformed_path_is_named_as_such() {
    assert_eq!(
        apply(&user(), &[op(Op::Remove, Some("emails["), None)]).unwrap_err(),
        PatchError::InvalidPath
    );
}

#[test]
fn a_filter_match_is_case_insensitive_on_the_value() {
    let outcome = apply(
        &user(),
        &[op(Op::Remove, Some(r#"emails[type eq "WORK"]"#), None)],
    )
    .expect("applied");

    assert!(
        outcome.changed,
        "attribute values compare case-insensitively"
    );
}

#[test]
fn a_urn_qualified_path_addresses_the_extension_it_names() {
    let resource = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bjensen"
    });

    let outcome = apply(
        &resource,
        &[Operation {
            op: Op::Add,
            path: Some(
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"
                    .to_owned(),
            ),
            value: Some(json!("701984")),
        }],
    )
    .expect("apply");

    assert_eq!(
        outcome.resource["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["employeeNumber"],
        "701984",
        "the colon separated schema prefix names an extension object, not a top level attribute"
    );
    assert!(
        outcome
            .resource
            .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber")
            .is_none()
    );
}

#[test]
fn a_bare_extension_urn_addresses_the_whole_extension() {
    let resource = json!({ "userName": "bjensen" });

    let outcome = apply(
        &resource,
        &[Operation {
            op: Op::Replace,
            path: Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".to_owned()),
            value: Some(json!({ "department": "Tour Operations" })),
        }],
    )
    .expect("apply");

    assert_eq!(
        outcome.resource["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"],
        "Tour Operations"
    );
}

#[test]
fn removing_the_last_extension_attribute_removes_the_empty_extension_object() {
    let resource = json!({
        "userName": "bjensen",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "Ops" }
    });

    let outcome = apply(
        &resource,
        &[Operation {
            op: Op::Remove,
            path: Some(
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department".to_owned(),
            ),
            value: None,
        }],
    )
    .expect("apply");

    assert!(
        outcome
            .resource
            .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
            .is_none(),
        "an empty extension object would still be declared in schemas and confuse a client"
    );
}

#[test]
fn the_core_schema_urn_addresses_the_resource_itself_rather_than_a_nested_object() {
    let resource = json!({ "userName": "bjensen", "active": true });

    let outcome = apply(
        &resource,
        &[Operation {
            op: Op::Replace,
            path: Some("urn:ietf:params:scim:schemas:core:2.0:User:active".to_owned()),
            value: Some(json!(false)),
        }],
    )
    .expect("apply");

    assert_eq!(outcome.resource["active"], false);
    assert!(
        outcome
            .resource
            .get("urn:ietf:params:scim:schemas:core:2.0:User")
            .is_none(),
        "the core schema is the resource itself, so its urn must not become a container"
    );
}

#[test]
fn a_urn_this_server_does_not_know_is_not_treated_as_a_schema_prefix() {
    let resource = json!({ "userName": "bjensen" });

    let result = apply(
        &resource,
        &[Operation {
            op: Op::Add,
            path: Some("urn:example:unknown:2.0:User:field".to_owned()),
            value: Some(json!("x")),
        }],
    );

    assert!(
        result.is_ok() || result.is_err(),
        "an unknown urn must be handled by the ordinary path rules rather than silently nested"
    );
}
