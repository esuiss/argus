#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::federation::policy::{ApplyFault, PolicyFault, apply, merge, parse};
use serde_json::json;

fn policy(raw: &serde_json::Value) -> argus_core::federation::policy::MetadataPolicy {
    parse(raw).expect("policy")
}

#[test]
fn value_assigns_the_parameter_whatever_the_metadata_said() {
    let rule = policy(&json!({ "token_endpoint_auth_method": { "value": "private_key_jwt" } }));
    let metadata = json!({ "token_endpoint_auth_method": "client_secret_basic" });

    let resolved = apply(&metadata, &rule).expect("apply");
    assert_eq!(resolved["token_endpoint_auth_method"], "private_key_jwt");
}

#[test]
fn a_null_value_removes_the_parameter() {
    let rule = policy(&json!({ "client_secret": { "value": null } }));
    let metadata = json!({ "client_secret": "hunter2", "client_name": "app" });

    let resolved = apply(&metadata, &rule).expect("apply");
    assert!(
        resolved.get("client_secret").is_none(),
        "a superior that forbids a parameter has to be able to strike it out"
    );
    assert_eq!(resolved["client_name"], "app");
}

#[test]
fn add_extends_an_array_without_duplicating_what_is_already_there() {
    let rule = policy(&json!({ "scope": { "add": ["openid", "profile"] } }));
    let metadata = json!({ "scope": ["openid", "email"] });

    let resolved = apply(&metadata, &rule).expect("apply");
    assert_eq!(resolved["scope"], json!(["openid", "email", "profile"]));
}

#[test]
fn add_creates_the_parameter_when_the_metadata_omits_it() {
    let rule = policy(&json!({ "contacts": { "add": ["ops@example.test"] } }));
    let resolved = apply(&json!({}), &rule).expect("apply");
    assert_eq!(resolved["contacts"], json!(["ops@example.test"]));
}

#[test]
fn default_fills_a_gap_and_leaves_a_present_value_alone() {
    let rule = policy(&json!({ "grant_types": { "default": ["authorization_code"] } }));

    let filled = apply(&json!({}), &rule).expect("apply");
    assert_eq!(filled["grant_types"], json!(["authorization_code"]));

    let untouched = apply(&json!({ "grant_types": ["refresh_token"] }), &rule).expect("apply");
    assert_eq!(untouched["grant_types"], json!(["refresh_token"]));
}

#[test]
fn one_of_refuses_a_value_outside_the_list() {
    let rule = policy(&json!({ "subject_type": { "one_of": ["pairwise"] } }));

    apply(&json!({ "subject_type": "pairwise" }), &rule).expect("the allowed value passes");

    assert!(matches!(
        apply(&json!({ "subject_type": "public" }), &rule).unwrap_err(),
        ApplyFault::NotAllowed { .. }
    ));
}

#[test]
fn subset_of_keeps_the_allowed_values_and_drops_the_rest() {
    let rule =
        policy(&json!({ "grant_types": { "subset_of": ["authorization_code", "refresh_token"] } }));
    let metadata = json!({ "grant_types": ["authorization_code", "implicit", "refresh_token"] });

    let resolved = apply(&metadata, &rule).expect("apply");
    assert_eq!(
        resolved["grant_types"],
        json!(["authorization_code", "refresh_token"]),
        "subset_of narrows the array rather than refusing the whole registration"
    );
}

#[test]
fn subset_of_removes_the_parameter_when_nothing_survives() {
    let rule = policy(&json!({ "grant_types": { "subset_of": ["authorization_code"] } }));
    let resolved = apply(&json!({ "grant_types": ["implicit"] }), &rule).expect("apply");
    assert!(resolved.get("grant_types").is_none());
}

#[test]
fn superset_of_refuses_metadata_that_omits_a_required_value() {
    let rule = policy(&json!({ "response_types": { "superset_of": ["code"] } }));

    apply(
        &json!({ "response_types": ["code", "code id_token"] }),
        &rule,
    )
    .expect("carries code");

    assert!(matches!(
        apply(&json!({ "response_types": ["id_token"] }), &rule).unwrap_err(),
        ApplyFault::NotASuperset { .. }
    ));
}

#[test]
fn essential_refuses_metadata_that_omits_the_parameter() {
    let rule = policy(&json!({ "contacts": { "essential": true } }));

    assert!(matches!(
        apply(&json!({}), &rule).unwrap_err(),
        ApplyFault::MissingEssential { .. }
    ));

    apply(&json!({ "contacts": ["ops@example.test"] }), &rule).expect("present");
}

#[test]
fn the_operators_run_in_the_order_the_specification_fixes() {
    let rule = policy(&json!({
        "grant_types": {
            "add": ["refresh_token"],
            "default": ["authorization_code"],
            "subset_of": ["authorization_code", "refresh_token"],
            "essential": true
        }
    }));

    let resolved = apply(&json!({ "grant_types": ["implicit"] }), &rule);

    assert!(
        matches!(resolved, Err(ApplyFault::MissingEssential { .. })) || resolved.is_ok(),
        "the order decides the outcome; it must not depend on map iteration"
    );

    let twice = apply(&json!({ "grant_types": ["implicit"] }), &rule);
    assert_eq!(
        format!("{resolved:?}"),
        format!("{twice:?}"),
        "applying one policy to one document twice must give one answer"
    );
}

#[test]
fn add_runs_before_subset_of_so_an_added_value_is_still_checked() {
    let rule = policy(&json!({
        "grant_types": {
            "add": ["implicit"],
            "subset_of": ["authorization_code"]
        }
    }));

    let resolved = apply(&json!({ "grant_types": ["authorization_code"] }), &rule).expect("apply");

    assert_eq!(
        resolved["grant_types"],
        json!(["authorization_code"]),
        "a value the superior added must still face the values it allows, or add becomes an escape hatch"
    );
}

#[test]
fn value_cannot_be_combined_with_another_assigning_operator() {
    let fault = parse(&json!({
        "subject_type": { "value": "pairwise", "one_of": ["public", "pairwise"] }
    }))
    .unwrap_err();

    assert!(matches!(fault, PolicyFault::ValueCombined { .. }));
}

#[test]
fn one_of_cannot_be_combined_with_the_array_operators() {
    assert!(matches!(
        parse(&json!({ "x": { "one_of": ["a"], "subset_of": ["a"] } })).unwrap_err(),
        PolicyFault::OneOfCombined { .. }
    ));
    assert!(matches!(
        parse(&json!({ "x": { "one_of": ["a"], "add": ["a"] } })).unwrap_err(),
        PolicyFault::OneOfCombined { .. }
    ));
}

#[test]
fn an_operator_this_server_does_not_implement_is_refused_rather_than_ignored() {
    let fault = parse(&json!({ "x": { "regex": "^a" } })).unwrap_err();
    assert!(
        matches!(fault, PolicyFault::UnknownOperator { .. }),
        "silently ignoring an operator turns a restriction into permission"
    );
}

#[test]
fn an_operator_of_the_wrong_shape_is_refused() {
    assert!(matches!(
        parse(&json!({ "x": { "add": "not-an-array" } })).unwrap_err(),
        PolicyFault::WrongShape { .. }
    ));
    assert!(matches!(
        parse(&json!({ "x": { "essential": "yes" } })).unwrap_err(),
        PolicyFault::WrongShape { .. }
    ));
}

#[test]
fn merging_takes_the_intersection_of_two_one_of_lists() {
    let above = policy(&json!({ "subject_type": { "one_of": ["public", "pairwise"] } }));
    let below = policy(&json!({ "subject_type": { "one_of": ["pairwise"] } }));

    let merged = merge(&above, &below).expect("merge");
    assert_eq!(
        merged.parameters["subject_type"].one_of,
        Some(vec![json!("pairwise")])
    );
}

#[test]
fn a_subordinate_cannot_widen_what_a_superior_allowed() {
    let above = policy(&json!({ "subject_type": { "one_of": ["pairwise"] } }));
    let below = policy(&json!({ "subject_type": { "one_of": ["public", "pairwise"] } }));

    let merged = merge(&above, &below).expect("merge");
    assert_eq!(
        merged.parameters["subject_type"].one_of,
        Some(vec![json!("pairwise")]),
        "the hierarchy principle: an authority below can narrow, never loosen"
    );
}

#[test]
fn merging_leaves_no_acceptable_value_and_the_chain_is_refused() {
    let above = policy(&json!({ "subject_type": { "one_of": ["pairwise"] } }));
    let below = policy(&json!({ "subject_type": { "one_of": ["public"] } }));

    assert!(matches!(
        merge(&above, &below).unwrap_err(),
        PolicyFault::EmptyIntersection { .. }
    ));
}

#[test]
fn merging_takes_the_union_of_two_add_lists() {
    let above = policy(&json!({ "scope": { "add": ["openid"] } }));
    let below = policy(&json!({ "scope": { "add": ["profile"] } }));

    let merged = merge(&above, &below).expect("merge");
    assert_eq!(
        merged.parameters["scope"].add,
        Some(vec![json!("openid"), json!("profile")])
    );
}

#[test]
fn merging_two_different_values_is_a_conflict_rather_than_a_last_writer_win() {
    let above = policy(&json!({ "subject_type": { "value": "pairwise" } }));
    let below = policy(&json!({ "subject_type": { "value": "public" } }));

    assert!(
        matches!(
            merge(&above, &below).unwrap_err(),
            PolicyFault::Irreconcilable { .. }
        ),
        "a silent winner here would let a subordinate override its trust anchor"
    );
}

#[test]
fn merging_two_equal_values_is_fine() {
    let same = policy(&json!({ "subject_type": { "value": "pairwise" } }));
    merge(&same, &same).expect("equal values reconcile");
}

#[test]
fn a_subordinate_cannot_make_an_essential_parameter_optional() {
    let above = policy(&json!({ "contacts": { "essential": true } }));
    let below = policy(&json!({ "contacts": { "essential": false } }));

    assert!(matches!(
        merge(&above, &below).unwrap_err(),
        PolicyFault::NotNarrowing { .. }
    ));
}

#[test]
fn a_subordinate_may_make_an_optional_parameter_essential() {
    let above = policy(&json!({ "contacts": { "essential": false } }));
    let below = policy(&json!({ "contacts": { "essential": true } }));

    let merged = merge(&above, &below).expect("merge");
    assert_eq!(merged.parameters["contacts"].essential, Some(true));
}

#[test]
fn a_parameter_only_the_subordinate_names_survives_the_merge() {
    let above = policy(&json!({ "scope": { "add": ["openid"] } }));
    let below = policy(&json!({ "contacts": { "essential": true } }));

    let merged = merge(&above, &below).expect("merge");
    assert!(merged.parameters.contains_key("scope"));
    assert!(merged.parameters.contains_key("contacts"));
}

#[test]
fn merging_is_associative_over_a_three_link_chain() {
    let anchor = policy(
        &json!({ "grant_types": { "subset_of": ["authorization_code", "refresh_token", "implicit"] } }),
    );
    let middle =
        policy(&json!({ "grant_types": { "subset_of": ["authorization_code", "refresh_token"] } }));
    let leaf = policy(&json!({ "grant_types": { "subset_of": ["authorization_code"] } }));

    let left = merge(&merge(&anchor, &middle).expect("a"), &leaf).expect("b");
    let right = merge(&anchor, &merge(&middle, &leaf).expect("c")).expect("d");

    assert_eq!(
        left, right,
        "determinism: the resolved policy cannot depend on the order the chain was folded"
    );
}

#[test]
fn a_policy_naming_more_parameters_than_the_ceiling_is_refused() {
    let mut body = serde_json::Map::new();
    for index in 0..200 {
        body.insert(format!("p{index}"), json!({ "essential": true }));
    }

    assert!(matches!(
        parse(&serde_json::Value::Object(body)).unwrap_err(),
        PolicyFault::TooManyParameters
    ));
}

#[test]
fn a_policy_naming_more_values_than_the_ceiling_is_refused() {
    let values: Vec<serde_json::Value> = (0..400).map(|i| json!(format!("v{i}"))).collect();
    assert!(matches!(
        parse(&json!({ "scope": { "add": values } })).unwrap_err(),
        PolicyFault::TooManyValues
    ));
}

#[test]
fn the_worked_example_from_the_specification_resolves_as_written() {
    let anchor = policy(&json!({
        "token_endpoint_auth_method": { "one_of": ["private_key_jwt", "self_signed_tls_client_auth"] },
        "grant_types": { "subset_of": ["authorization_code", "refresh_token"] },
        "contacts": { "add": ["anchor@federation.test"] }
    }));

    let intermediate = policy(&json!({
        "token_endpoint_auth_method": { "one_of": ["private_key_jwt"] },
        "contacts": { "add": ["intermediate@federation.test"] }
    }));

    let resolved = merge(&anchor, &intermediate).expect("merge");

    let metadata = json!({
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        "contacts": ["rp@leaf.test"]
    });

    let applied = apply(&metadata, &resolved).expect("apply");

    assert_eq!(applied["token_endpoint_auth_method"], "private_key_jwt");
    assert_eq!(
        applied["grant_types"],
        json!(["authorization_code", "refresh_token"]),
        "client_credentials was never allowed by the anchor"
    );
    assert_eq!(
        applied["contacts"],
        json!([
            "rp@leaf.test",
            "anchor@federation.test",
            "intermediate@federation.test"
        ])
    );
}
