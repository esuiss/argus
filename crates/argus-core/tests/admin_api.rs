#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use argus_core::admin::idempotency::{
    IdempotencyKey, KeyError, Outcome, Record, RecordState, decide,
};
use argus_core::admin::job::{ItemResult, Job, JobFault, JobState};
use argus_core::admin::manifest::{MANIFEST, Surface, requirement};
use argus_core::admin::merge_patch::{MergePatchError, apply, check_patch};
use argus_core::admin::page::{
    DEFAULT_LIMIT, MAX_LIMIT, PageError, PageRequest, encode_cursor, link_header,
};
use argus_core::admin::query::{QueryError, parse_filter, projection};
use serde_json::{Value, json};

const FIELDS: &[&str] = &["clientId", "displayName", "enabled", "createdAt"];

/// RFC 7396 Appendix A, verbatim. A merge patch implementation that passes
/// its own examples is the cheapest correctness a spec ever offers.
#[test]
fn the_rfc_7396_examples_all_hold() {
    let cases: &[(Value, Value, Value)] = &[
        (json!({"a":"b"}), json!({"a":"c"}), json!({"a":"c"})),
        (json!({"a":"b"}), json!({"b":"c"}), json!({"a":"b","b":"c"})),
        (json!({"a":"b"}), json!({"a":null}), json!({})),
        (
            json!({"a":"b","b":"c"}),
            json!({"a":null}),
            json!({"b":"c"}),
        ),
        (json!({"a":["b"]}), json!({"a":"c"}), json!({"a":"c"})),
        (json!({"a":"c"}), json!({"a":["b"]}), json!({"a":["b"]})),
        (
            json!({"a":{"b":"c"}}),
            json!({"a":{"b":"d","c":null}}),
            json!({"a":{"b":"d"}}),
        ),
        (json!({"a":[{"b":"c"}]}), json!({"a":[1]}), json!({"a":[1]})),
        (json!(["a", "b"]), json!(["c", "d"]), json!(["c", "d"])),
        (json!({"a":"b"}), json!(["c"]), json!(["c"])),
        (json!({"a":"foo"}), json!(null), json!(null)),
        (json!({"a":"foo"}), json!("bar"), json!("bar")),
        (json!({"e":null}), json!({"a":1}), json!({"e":null,"a":1})),
        (
            json!({"a":[{"b":"c"}]}),
            json!({"a":[{"b":"d"}]}),
            json!({"a":[{"b":"d"}]}),
        ),
    ];

    for (target, patch, expected) in cases {
        assert_eq!(
            &apply(target, patch).expect("patch"),
            expected,
            "target {target} patch {patch}"
        );
    }
}

#[test]
fn a_null_removes_a_member_rather_than_setting_it_to_null() {
    // The whole reason §24 #2 chose merge patch: Keycloak cannot tell "not
    // set" from "set to null" and says so in its own issue tracker.
    let out = apply(&json!({"displayName":"x"}), &json!({"displayName":null})).expect("patch");
    assert_eq!(out, json!({}));
    assert!(out.get("displayName").is_none());
}

#[test]
fn a_patch_nested_past_the_limit_is_refused() {
    let mut patch = json!("leaf");
    for _ in 0..40 {
        patch = json!({ "a": patch });
    }
    assert!(matches!(
        apply(&json!({}), &patch),
        Err(MergePatchError::TooDeep { .. })
    ));
}

#[test]
fn a_patch_touching_an_immutable_field_is_refused_before_it_is_applied() {
    // authentik CVE-2024-37905: a token whose owner could be patched.
    let patch = json!({"owner":"someone-else"});
    assert!(matches!(
        check_patch(&patch, &["owner", "displayName"], &["owner"]),
        Err(MergePatchError::Immutable { .. })
    ));
}

#[test]
fn a_patch_naming_an_unknown_field_is_refused() {
    assert!(matches!(
        check_patch(&json!({"nope": 1}), &["displayName"], &[]),
        Err(MergePatchError::Unknown { .. })
    ));
}

#[test]
fn a_filter_over_a_declared_field_parses() {
    parse_filter(r#"clientId eq "my-app""#, FIELDS).expect("filter");
    parse_filter(r#"displayName co "port" and enabled eq true"#, FIELDS).expect("filter");
    parse_filter("enabled pr", FIELDS).expect("filter");
}

#[test]
fn a_filter_naming_a_field_the_resource_does_not_have_is_refused() {
    // SCIM ignores this. An ignored filter returns every record, which is why
    // §24 #5 makes it an error instead.
    assert!(matches!(
        parse_filter(r#"secret eq "x""#, FIELDS),
        Err(QueryError::UnknownField { .. })
    ));
}

#[test]
fn the_ordered_comparisons_are_refused_by_name() {
    for raw in [
        r#"createdAt gt "2026-01-01""#,
        r#"createdAt ge "2026-01-01""#,
        r#"createdAt lt "2026-01-01""#,
        r#"createdAt le "2026-01-01""#,
    ] {
        assert!(
            matches!(
                parse_filter(raw, FIELDS),
                Err(QueryError::UnsupportedOperator { .. })
            ),
            "{raw} must be refused"
        );
    }
}

#[test]
fn a_projection_of_unknown_fields_is_refused() {
    assert_eq!(
        projection("clientId,enabled", FIELDS).expect("projection"),
        ["clientId", "enabled"]
    );
    assert!(matches!(
        projection("clientId,secret", FIELDS),
        Err(QueryError::UnknownProjection { .. })
    ));
}

#[test]
fn a_page_defaults_and_clamps() {
    assert_eq!(
        PageRequest::parse(None, None).expect("page").limit,
        DEFAULT_LIMIT
    );
    assert!(matches!(
        PageRequest::parse(None, Some("0")),
        Err(PageError::EmptyLimit)
    ));
    assert!(matches!(
        PageRequest::parse(None, Some(&(MAX_LIMIT + 1).to_string())),
        Err(PageError::LimitTooLarge { .. })
    ));
}

#[test]
fn a_cursor_this_server_did_not_issue_is_refused() {
    let cursor = encode_cursor("client-42");
    let page = PageRequest::parse(Some(&cursor), None).expect("page");
    assert_eq!(page.after.as_deref(), Some("client-42"));

    assert!(matches!(
        PageRequest::parse(Some("!!! not base64 !!!"), None),
        Err(PageError::InvalidCursor)
    ));
}

#[test]
fn the_link_header_names_the_next_page_as_a_link() {
    let header = link_header("/admin/api/clients/v1", Some("abc"), None).expect("link");
    assert_eq!(header, "</admin/api/clients/v1?cursor=abc>; rel=\"next\"");
    assert!(link_header("/x", None, None).is_none());
}

#[test]
fn every_route_the_manifest_declares_is_unique() {
    let mut seen: Vec<(&str, &str)> = MANIFEST
        .iter()
        .map(|entry| (entry.method, entry.path))
        .collect();
    let before = seen.len();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(before, seen.len(), "a route is declared twice");
}

#[test]
fn a_mutating_route_never_carries_a_read_only_relation() {
    for entry in MANIFEST {
        if entry.mutating {
            assert!(
                entry.relation.starts_with("manage_"),
                "{} {} mutates but requires {}",
                entry.method,
                entry.path,
                entry.relation
            );
        }
    }
}

#[test]
fn the_two_surfaces_share_no_path() {
    for entry in MANIFEST {
        let expected = match entry.surface {
            Surface::Platform => "/admin/platform",
            Surface::Tenant => "/admin/api",
        };
        assert!(
            entry.path.starts_with(expected),
            "{} is on the {:?} surface but does not live under {expected}",
            entry.path,
            entry.surface
        );
    }
}

#[test]
fn a_route_with_no_manifest_entry_has_no_requirement() {
    assert!(requirement("GET", "/admin/api/clients/v1").is_some());
    assert!(requirement("DELETE", "/admin/api/openapi/v1").is_none());
}

#[test]
fn an_idempotency_key_is_bounded_and_printable() {
    IdempotencyKey::new("abc-123").expect("key");
    assert!(matches!(IdempotencyKey::new(""), Err(KeyError::Empty)));
    assert!(matches!(
        IdempotencyKey::new(&"a".repeat(256)),
        Err(KeyError::TooLong { .. })
    ));
    assert!(matches!(
        IdempotencyKey::new("has space"),
        Err(KeyError::NotPrintable)
    ));
}

#[test]
fn an_idempotency_key_never_reaches_a_log_through_its_own_debug() {
    let key = IdempotencyKey::new("secret-looking-value").expect("key");
    let rendered = format!("{key:?}");
    assert!(
        !rendered.contains("secret-looking-value"),
        "the key was printed: {rendered}"
    );
}

#[test]
fn a_repeated_success_replays_and_a_repeated_failure_runs_again() {
    let fingerprint = [7_u8; 32];

    assert_eq!(decide(None, &fingerprint, 100), Outcome::Execute);

    let succeeded = Record {
        fingerprint,
        state: RecordState::Succeeded,
        stored_at: 100,
    };
    assert_eq!(decide(Some(&succeeded), &fingerprint, 200), Outcome::Replay);

    let failed = Record {
        state: RecordState::Failed,
        ..succeeded.clone()
    };
    assert_eq!(decide(Some(&failed), &fingerprint, 200), Outcome::Execute);

    let running = Record {
        state: RecordState::InFlight,
        ..succeeded.clone()
    };
    assert_eq!(decide(Some(&running), &fingerprint, 200), Outcome::InFlight);
}

#[test]
fn the_same_key_with_a_different_payload_is_told_apart_from_a_race() {
    let stored = Record {
        fingerprint: [1_u8; 32],
        state: RecordState::Succeeded,
        stored_at: 100,
    };
    assert_eq!(
        decide(Some(&stored), &[2_u8; 32], 200),
        Outcome::PayloadMismatch
    );
}

#[test]
fn a_record_past_the_published_window_no_longer_short_circuits() {
    let stored = Record {
        fingerprint: [1_u8; 32],
        state: RecordState::Succeeded,
        stored_at: 0,
    };
    assert_eq!(
        decide(Some(&stored), &[1_u8; 32], 40 * 24 * 60 * 60),
        Outcome::Execute
    );
}

#[test]
fn a_job_that_loses_some_items_reports_partial_rather_than_success() {
    let mut job = Job::new("j1", 3, 0).expect("job");
    job.start().expect("start");
    job.record(None).expect("ok");
    job.record(Some(ItemResult {
        index: 1,
        code: "duplicate_username".to_owned(),
        message: "the username is taken".to_owned(),
    }))
    .expect("failure");
    job.record(None).expect("ok");

    assert_eq!(job.finish().expect("finish"), JobState::PartiallySucceeded);

    let response = job.response().expect("terminal");
    assert_eq!(response.get("succeeded").and_then(Value::as_u64), Some(2));
    let first = response
        .get("failures")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("code"))
        .and_then(Value::as_str);
    assert_eq!(first, Some("duplicate_username"));
}

#[test]
fn a_job_where_everything_failed_is_a_failure_not_a_partial() {
    let mut job = Job::new("j2", 2, 0).expect("job");
    job.start().expect("start");
    for index in 0..2 {
        job.record(Some(ItemResult {
            index,
            code: "invalid".to_owned(),
            message: "no".to_owned(),
        }))
        .expect("failure");
    }
    assert_eq!(job.finish().expect("finish"), JobState::Failed);
}

#[test]
fn a_running_job_exposes_progress_but_no_result() {
    let mut job = Job::new("j3", 2, 0).expect("job");
    job.start().expect("start");
    job.record(None).expect("ok");

    assert_eq!(
        job.metadata().get("completed").and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        job.response().is_none(),
        "a result must not exist before the job is over"
    );
}

#[test]
fn a_job_cannot_skip_a_state() {
    let mut job = Job::new("j4", 1, 0).expect("job");
    assert!(matches!(
        job.finish(),
        Err(JobFault::IllegalTransition { .. })
    ));
    job.start().expect("start");
    assert!(matches!(
        job.start(),
        Err(JobFault::IllegalTransition { .. })
    ));
}

#[test]
fn a_job_larger_than_the_ceiling_is_refused() {
    assert!(matches!(
        Job::new("j5", 10_001, 0),
        Err(JobFault::TooManyItems { .. })
    ));
    assert!(matches!(Job::new("j6", 0, 0), Err(JobFault::Empty)));
}
