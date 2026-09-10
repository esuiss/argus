#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_proto::jcs::{JcsError, TextFault, canonicalize, canonicalize_text, ecmascript_form};
use serde_json::json;

fn form(raw: &str) -> String {
    canonicalize_text(raw).expect("canonicalize")
}

fn form_via_value(raw: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(raw).expect("json");
    canonicalize(&value).expect("canonicalize")
}

#[test]
fn object_keys_are_sorted_and_whitespace_is_removed() {
    assert_eq!(
        form(r#"{ "b": 1, "a": 2 }"#),
        r#"{"a":2,"b":1}"#,
        "two servers must produce the same bytes for one document or the signature never matches"
    );
}

#[test]
fn the_rfc_8785_numbers_and_literals_canonicalize_as_published() {
    let input = r#"{
        "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
        "literals": [null, true, false]
    }"#;

    assert_eq!(
        form(input),
        r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}"#
    );
}

#[test]
fn the_rfc_8785_string_example_canonicalizes_as_published() {
    let value = json!({ "string": "\u{20ac}$\u{f}\nA'B\"\\\\\"/" });

    assert_eq!(
        canonicalize(&value).expect("canonicalize"),
        "{\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
    );
}

#[test]
fn keys_are_ordered_by_utf16_code_unit_and_not_by_scalar_value() {
    let value = json!({ "\u{1f600}": 1, "\u{fb33}": 2 });
    let ordered = canonicalize(&value).expect("canonicalize");

    assert!(
        ordered.find('\u{1f600}') < ordered.find('\u{fb33}'),
        "the astral character is a surrogate pair starting at D83D, which sorts before FB33; \
         sorting the UTF-8 bytes instead would put the other one first: {ordered}"
    );
}

#[test]
fn an_integer_keeps_its_integer_form() {
    assert_eq!(
        form("[0, 1, -1, 42, 9007199254740991]"),
        "[0,1,-1,42,9007199254740991]"
    );
}

#[test]
fn a_trailing_zero_after_the_point_is_dropped() {
    assert_eq!(form("[1.0, 4.50, 2.000]"), "[1,4.5,2]");
}

#[test]
fn very_large_and_very_small_numbers_use_the_exponent_form() {
    assert_eq!(ecmascript_form(1e21), "1e+21");
    assert_eq!(ecmascript_form(1e-7), "1e-7");
    assert_eq!(
        ecmascript_form(1e20),
        "100000000000000000000",
        "the boundary is at ten to the twenty first, not before it"
    );
    assert_eq!(ecmascript_form(1e-6), "0.000001");
}

#[test]
fn zero_has_one_canonical_form() {
    assert_eq!(ecmascript_form(0.0), "0");
    assert_eq!(ecmascript_form(-0.0), "0");
}

#[test]
fn the_control_characters_use_their_short_escapes_where_json_defines_them() {
    let value = json!({ "x": "\u{8}\u{c}\n\r\t" });
    assert_eq!(
        canonicalize(&value).expect("canonicalize"),
        r#"{"x":"\b\f\n\r\t"}"#
    );
}

#[test]
fn a_control_character_with_no_short_escape_uses_the_four_digit_form() {
    let value = json!({ "x": "\u{1}\u{1f}" });
    assert_eq!(
        canonicalize(&value).expect("canonicalize"),
        "{\"x\":\"\\u0001\\u001f\"}"
    );
}

#[test]
fn a_quote_and_a_backslash_are_escaped_and_nothing_else_is() {
    let value = json!({ "x": "a\"b\\c/d" });
    assert_eq!(
        canonicalize(&value).expect("canonicalize"),
        r#"{"x":"a\"b\\c/d"}"#,
        "escaping the solidus would change the bytes and break interoperability"
    );
}

#[test]
fn non_ascii_text_is_emitted_as_itself_rather_than_escaped() {
    let value = json!({ "name": "\u{dc}nal \u{d6}zt\u{fc}rk" });
    assert_eq!(
        canonicalize(&value).expect("canonicalize"),
        "{\"name\":\"\u{dc}nal \u{d6}zt\u{fc}rk\"}"
    );
}

#[test]
fn arrays_keep_the_order_they_were_written_in() {
    assert_eq!(form("[3, 1, 2]"), "[3,1,2]");
}

#[test]
fn nested_objects_are_sorted_at_every_level() {
    assert_eq!(
        form(r#"{"b": {"d": 1, "c": 2}, "a": 3}"#),
        r#"{"a":3,"b":{"c":2,"d":1}}"#
    );
}

#[test]
fn a_document_nested_past_the_ceiling_is_refused() {
    let mut value = json!(1);
    for _ in 0..64 {
        value = json!([value]);
    }

    assert_eq!(canonicalize(&value).unwrap_err(), JcsError::TooDeep);
}

#[test]
fn canonicalizing_twice_gives_the_same_bytes() {
    let value = json!({ "z": [1, {"b": true, "a": null}], "a": "x" });
    assert_eq!(
        canonicalize(&value).expect("once"),
        canonicalize(&value).expect("twice")
    );
}

#[test]
fn two_documents_that_differ_only_in_key_order_canonicalize_to_one_string() {
    let left: serde_json::Value =
        serde_json::from_str(r#"{"a":1,"b":{"c":2,"d":3}}"#).expect("json");
    let right: serde_json::Value =
        serde_json::from_str(r#"{"b":{"d":3,"c":2},"a":1}"#).expect("json");

    assert_eq!(
        canonicalize(&left).expect("left"),
        canonicalize(&right).expect("right")
    );
}

#[test]
fn two_documents_that_differ_in_content_do_not_canonicalize_to_one_string() {
    assert_ne!(
        canonicalize(&json!({ "amount": 100 })).expect("left"),
        canonicalize(&json!({ "amount": 1000 })).expect("right"),
        "a canonical form that erased a difference would let a signature cover the wrong document"
    );
}

#[test]
fn a_fractional_number_is_read_from_the_source_text_rather_than_a_reparsed_double() {
    let raw = "333333333.33333329";

    assert_eq!(
        form(raw),
        "333333333.3333333",
        "the JSON parser this project depends on rounds this literal one unit low; \
         canonicalizing the received bytes is what keeps a signature verifiable elsewhere"
    );

    assert_ne!(
        form_via_value(raw),
        form(raw),
        "this difference is the reason the text path exists; if it ever disappears the parser \
         was fixed and this test should be revisited rather than deleted"
    );
}

#[test]
fn the_two_paths_agree_on_everything_a_signed_document_actually_carries() {
    for raw in [
        r#"{"a":1,"b":"x","c":[1,2,3],"d":{"e":true,"f":null}}"#,
        r#"{"iat":1800000000,"exp":1800003600,"depth":2}"#,
        "[0,-1,42,9007199254740991]",
        r#"{"name":"Agent","version":"1.0.0"}"#,
    ] {
        assert_eq!(form(raw), form_via_value(raw), "for {raw}");
    }
}

#[test]
fn the_text_path_sorts_keys_by_utf16_code_unit_too() {
    let raw = "{\"\u{1f600}\":1,\"\u{fb33}\":2}";
    assert_eq!(form(raw), form_via_value(raw));
}

#[test]
fn the_text_path_refuses_a_document_that_is_not_well_formed() {
    for raw in ["{", "{\"a\"}", "[1,", "tru", "{\"a\":1,}"] {
        assert!(
            canonicalize_text(raw).is_err(),
            "{raw} is not JSON and must not canonicalize"
        );
    }
}

#[test]
fn the_text_path_refuses_bytes_after_the_top_level_value() {
    assert_eq!(
        canonicalize_text("{} trailing").unwrap_err(),
        TextFault::TrailingBytes,
        "a second document hiding after the first is how one signature covers two meanings"
    );
}

#[test]
fn the_text_path_refuses_a_document_nested_past_the_ceiling() {
    let deep = format!("{}1{}", "[".repeat(64), "]".repeat(64));
    assert_eq!(canonicalize_text(&deep).unwrap_err(), TextFault::TooDeep);
}

#[test]
fn the_text_path_decodes_escapes_before_it_re_encodes_them() {
    assert_eq!(
        form(r#"{"x":"Aé\t"}"#),
        "{\"x\":\"A\u{e9}\\t\"}",
        "an escape and the character it names must canonicalize to one form"
    );
}

#[test]
fn two_spellings_of_one_string_canonicalize_to_one_form() {
    assert_eq!(form(r#"{"k":"A"}"#), form(r#"{"k":"A"}"#));
}

#[test]
fn whitespace_anywhere_outside_a_string_makes_no_difference() {
    assert_eq!(
        form("{ \"a\" : [ 1 , 2 ] , \"b\" : { } }"),
        r#"{"a":[1,2],"b":{}}"#
    );
}
