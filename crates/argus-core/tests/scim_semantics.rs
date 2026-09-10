#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::scim::{
    Page, ResourceType, ScimFault, decode_cursor, encode_cursor, evaluate, member_ids, paging,
    sort, sort_key, validate,
};
use argus_parse::scim_filter::parse;
use serde_json::{Value, json};

fn user() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": "2819c223-7f76-453a-919d-413861904646",
        "externalId": "Bjensen",
        "userName": "bjensen@example.com",
        "name": { "givenName": "Barbara", "familyName": "Jensen" },
        "active": true,
        "emails": [
            { "value": "bjensen@example.com", "type": "work", "primary": true },
            { "value": "babs@jensen.org", "type": "home" }
        ],
        "meta": { "resourceType": "User", "lastModified": "2011-05-13T04:42:34Z" }
    })
}

fn matches(filter: &str) -> bool {
    let parsed = parse(filter).unwrap_or_else(|e| panic!("{filter}: {e}"));
    evaluate(&user(), &parsed)
}

#[test]
fn rfc7644_figure_2_filter_examples_all_evaluate() {
    assert!(matches(r#"userName eq "bjensen@example.com""#));
    assert!(matches(r#"name.familyName co "Jen""#));
    assert!(matches(r#"userName sw "bjensen""#));
    assert!(matches(r#"userName ew "example.com""#));
    assert!(!matches("title pr"));
    assert!(matches(r#"meta.lastModified gt "2011-05-13T04:42:33Z""#));
    assert!(matches(r#"meta.lastModified lt "2011-05-13T04:42:35Z""#));
    assert!(matches(
        r#"userName eq "bjensen@example.com" and name.givenName eq "Barbara""#
    ));
    assert!(matches(
        r#"userName eq "nobody" or name.givenName eq "Barbara""#
    ));
    assert!(matches(
        r#"emails[type eq "work" and value co "example.com"]"#
    ));
}

#[test]
fn attribute_names_are_matched_without_regard_to_case() {
    assert!(matches(r#"USERNAME eq "bjensen@example.com""#));
    assert!(matches(r#"NAME.GIVENNAME eq "Barbara""#));
}

#[test]
fn a_non_case_exact_attribute_compares_without_regard_to_case() {
    assert!(matches(r#"userName eq "BJENSEN@EXAMPLE.COM""#));
}

#[test]
fn external_id_is_case_exact_so_the_wrong_case_does_not_match() {
    assert!(matches(r#"externalId eq "Bjensen""#));
    assert!(
        !matches(r#"externalId eq "bjensen""#),
        "externalId is declared caseExact; a case-folded compare would be a schema violation"
    );
}

#[test]
fn a_value_path_must_satisfy_every_clause_within_one_element() {
    assert!(
        !matches(r#"emails[type eq "home" and value co "example.com"]"#),
        "the home address is babs@jensen.org; matching across two different elements is wrong"
    );
}

#[test]
fn a_multivalued_attribute_matches_when_any_element_matches() {
    assert!(matches(r#"emails.value eq "babs@jensen.org""#));
    assert!(matches(r#"emails.type eq "work""#));
}

#[test]
fn presence_treats_an_empty_string_and_an_empty_array_as_absent() {
    let resource = json!({ "userName": "", "emails": [], "displayName": "x" });
    assert!(!evaluate(&resource, &parse("userName pr").unwrap()));
    assert!(!evaluate(&resource, &parse("emails pr").unwrap()));
    assert!(evaluate(&resource, &parse("displayName pr").unwrap()));
    assert!(!evaluate(&resource, &parse("title pr").unwrap()));
}

#[test]
fn ne_against_an_attribute_that_is_absent_is_true() {
    assert!(matches(r#"title ne "manager""#));
    assert!(!matches(r#"title eq "manager""#));
}

#[test]
fn not_inverts_the_whole_grouped_expression() {
    assert!(matches(r#"not (userName eq "someone else")"#));
    assert!(!matches(r#"not (userName eq "bjensen@example.com")"#));
}

#[test]
fn and_binds_more_tightly_than_or() {
    let resource = json!({ "a": "1", "b": "0", "c": "1" });
    let filter = parse(r#"a eq "1" or b eq "1" and c eq "1""#).unwrap();
    assert!(
        evaluate(&resource, &filter),
        "read as a or (b and c), which is true; a plain left fold would give false"
    );
}

#[test]
fn a_urn_qualified_path_resolves_to_the_bare_attribute() {
    let resource = json!({
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {},
        "department": "Tour Operations"
    });
    let filter =
        parse(r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Tour Operations""#)
            .unwrap();
    assert!(evaluate(&resource, &filter));
}

#[test]
fn booleans_compare_only_for_equality() {
    assert!(matches("active eq true"));
    assert!(!matches("active eq false"));
    assert!(matches("active ne false"));
}

#[test]
fn a_create_may_not_carry_a_server_assigned_identifier() {
    let fault = validate(&user(), ResourceType::User, true).unwrap_err();
    assert_eq!(fault, ScimFault::Immutable { attribute: "id" });
    assert_eq!(fault.scim_type(), "mutability");
}

#[test]
fn a_replace_silently_drops_the_read_only_attributes_instead_of_failing() {
    let accepted = validate(&user(), ResourceType::User, false).unwrap();
    assert!(
        accepted.get("id").is_none(),
        "RFC 7644 3.5.1 says readOnly attributes are ignored, not rejected, on a replace"
    );
    assert!(accepted.get("meta").is_none());
    assert_eq!(accepted["userName"], "bjensen@example.com");
}

#[test]
fn a_user_without_a_user_name_is_refused() {
    let body = json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"] });
    assert_eq!(
        validate(&body, ResourceType::User, true).unwrap_err(),
        ScimFault::Missing {
            attribute: "userName"
        }
    );
}

#[test]
fn a_body_declaring_the_wrong_schema_is_refused() {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "userName": "bjensen"
    });
    let fault = validate(&body, ResourceType::User, true).unwrap_err();
    assert!(matches!(fault, ScimFault::WrongSchema { .. }));
    assert_eq!(fault.scim_type(), "invalidSyntax");
}

#[test]
fn active_defaults_to_true_when_the_client_says_nothing() {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bjensen"
    });
    let accepted = validate(&body, ResourceType::User, true).unwrap();
    assert_eq!(accepted["active"], true);
}

#[test]
fn active_sent_as_a_string_is_refused_rather_than_coerced() {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bjensen",
        "active": "true"
    });
    assert!(matches!(
        validate(&body, ResourceType::User, true).unwrap_err(),
        ScimFault::WrongType { .. }
    ));
}

#[test]
fn a_group_member_without_a_value_is_refused() {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Tour Guides",
        "members": [{ "display": "Barbara" }]
    });
    assert!(matches!(
        validate(&body, ResourceType::Group, true).unwrap_err(),
        ScimFault::WrongType { .. }
    ));
}

#[test]
fn group_members_are_read_back_in_the_order_the_client_sent_them() {
    let group = json!({
        "members": [{ "value": "a" }, { "value": "b" }]
    });
    assert_eq!(member_ids(&group), ["a", "b"]);
    assert!(member_ids(&json!({})).is_empty());
}

#[test]
fn a_count_beyond_the_advertised_maximum_is_clamped_not_refused() {
    let page = paging(None, Some("100000"), None).unwrap();
    assert_eq!(page.count(), 200, "matches filter.maxResults in the config");
}

#[test]
fn a_start_index_below_one_is_read_as_one() {
    assert_eq!(
        paging(Some("0"), Some("10"), None).unwrap(),
        Page::Index {
            start: 1,
            count: 10
        }
    );
    assert_eq!(
        paging(Some("-5"), Some("10"), None).unwrap(),
        Page::Index {
            start: 1,
            count: 10
        }
    );
}

#[test]
fn a_negative_count_asks_for_the_total_without_any_resources() {
    let page = paging(None, Some("-1"), None).unwrap();
    assert_eq!(
        page.count(),
        0,
        "RFC 7644 3.4.2.4 reads a negative count as zero rather than rejecting the request"
    );
}

#[test]
fn a_count_that_is_not_an_integer_is_refused_with_the_keyword_rfc_9865_defines() {
    let fault = paging(None, Some("ten"), None).unwrap_err();
    assert_eq!(fault, ScimFault::InvalidCount);
    assert_eq!(fault.scim_type(), "invalidCount");
}

#[test]
fn a_bad_cursor_is_refused_with_the_keyword_rfc_9865_defines() {
    let fault = paging(None, None, Some("not-a-cursor")).unwrap_err();
    assert_eq!(fault, ScimFault::InvalidCursor);
    assert_eq!(fault.scim_type(), "invalidCursor");
}

#[test]
fn index_and_cursor_pagination_cannot_be_mixed() {
    assert!(
        paging(Some("1"), Some("10"), Some("")).is_err(),
        "RFC 9865 forbids combining the two pagination styles in one request"
    );
}

#[test]
fn an_empty_cursor_asks_for_the_first_page() {
    assert_eq!(
        paging(None, Some("10"), Some("")).unwrap(),
        Page::Cursor {
            after: None,
            count: 10
        }
    );
}

#[test]
fn a_cursor_this_server_did_not_issue_is_refused() {
    assert!(decode_cursor("not-a-cursor").is_err());
    assert!(decode_cursor("").is_err());
    assert!(decode_cursor("00000000000000000").is_err());
}

#[test]
fn a_cursor_round_trips() {
    for value in [0_u64, 1, 42, u64::MAX] {
        assert_eq!(decode_cursor(&encode_cursor(value)).unwrap(), value);
    }
}

#[test]
fn cursors_order_the_same_way_the_numbers_do() {
    assert!(
        encode_cursor(9) < encode_cursor(10),
        "a decimal cursor would sort 10 before 9 and silently skip records"
    );
}

#[test]
fn an_unknown_sort_order_is_refused() {
    assert!(sort(Some("userName"), Some("sideways")).is_err());
    assert!(!sort(Some("userName"), None).unwrap().unwrap().descending);
    assert!(
        sort(Some("userName"), Some("DESCENDING"))
            .unwrap()
            .unwrap()
            .descending
    );
    assert!(sort(None, Some("descending")).unwrap().is_none());
}

#[test]
fn sorting_a_multivalued_attribute_uses_the_primary_value() {
    assert_eq!(sort_key(&user(), "emails"), "bjensen@example.com");
}

#[test]
fn sorting_on_an_absent_attribute_places_the_resource_first() {
    assert_eq!(sort_key(&user(), "title"), "");
}
