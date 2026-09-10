#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::ldap::{
    Dn, DnFault, Entry, Membership, POSIX_ID_CEILING, POSIX_ID_FLOOR, Scope, escape_rdn_value,
    evaluate, posix_id, project,
};
use argus_parse::ber::{Reader, encode, encode_text};
use argus_parse::ldap_filter::{
    Filter, MATCHING_RULE_IN_CHAIN, MAX_FILTER_DEPTH, TAG_AND, TAG_EQUALITY, TAG_NOT, TAG_PRESENT,
    decode, escape, to_string,
};

const BASE: &str = "dc=idm,dc=example,dc=com";

struct Groups(Vec<(String, Vec<String>)>);

impl Membership for Groups {
    fn transitively_contains(&self, group_dn: &str, member_dn: &str) -> bool {
        let Ok(group) = Dn::parse(group_dn) else {
            return false;
        };

        self.0
            .iter()
            .filter(|(name, _)| Dn::parse(name).is_ok_and(|parsed| parsed.equals(&group)))
            .any(|(_, members)| members.iter().any(|m| m == member_dn))
    }
}

fn user() -> Entry {
    Entry {
        dn: format!("uid=bjensen,ou=people,{BASE}"),
        attributes: vec![
            (
                "objectClass".to_owned(),
                vec![
                    "top".to_owned(),
                    "inetOrgPerson".to_owned(),
                    "posixAccount".to_owned(),
                ],
            ),
            ("uid".to_owned(), vec!["bjensen".to_owned()]),
            ("cn".to_owned(), vec!["Barbara Jensen".to_owned()]),
            ("sn".to_owned(), vec!["Jensen".to_owned()]),
            ("mail".to_owned(), vec!["bjensen@example.com".to_owned()]),
            ("uidNumber".to_owned(), vec!["1000042".to_owned()]),
            ("userPassword".to_owned(), vec!["{ARGON2}secret".to_owned()]),
            (
                "memberOf".to_owned(),
                vec![format!("cn=staff,ou=groups,{BASE}")],
            ),
        ],
    }
}

fn no_groups() -> Groups {
    Groups(Vec::new())
}

#[test]
fn a_distinguished_name_compares_without_regard_to_case_or_spacing() {
    let left = Dn::parse("UID=BJensen, OU=People, DC=Idm, DC=Example, DC=Com").expect("parse");
    let right = Dn::parse("uid=bjensen,ou=people,dc=idm,dc=example,dc=com").expect("parse");

    assert!(
        left.equals(&right),
        "a naive string compare here would let one account bind under two names"
    );
}

#[test]
fn a_name_below_the_base_is_recognised_and_one_outside_it_is_not() {
    let base = Dn::parse(BASE).expect("base");
    let inside = Dn::parse(&format!("uid=bjensen,ou=people,{BASE}")).expect("inside");
    let outside = Dn::parse("uid=bjensen,ou=people,dc=other,dc=com").expect("outside");

    assert!(inside.is_under(&base));
    assert!(!outside.is_under(&base));
    assert_eq!(inside.depth_below(&base), 2);
}

#[test]
fn a_name_that_merely_ends_with_the_base_text_is_not_under_it() {
    let base = Dn::parse("dc=example,dc=com").expect("base");
    let impostor = Dn::parse("uid=x,dc=notexample,dc=com").expect("impostor");
    assert!(!impostor.is_under(&base));
}

#[test]
fn an_escaped_comma_does_not_split_a_relative_name() {
    let parsed = Dn::parse(r"cn=Jensen\, Barbara,ou=people,dc=example,dc=com").expect("parse");
    assert_eq!(parsed.components.len(), 4);
    assert_eq!(parsed.components[0].1, "Jensen, Barbara");
}

#[test]
fn a_hex_escape_in_a_relative_name_is_decoded() {
    let parsed = Dn::parse(r"cn=a\2Cb,dc=example,dc=com").expect("parse");
    assert_eq!(parsed.components[0].1, "a,b");
}

#[test]
fn a_name_with_no_equals_sign_is_refused() {
    assert_eq!(
        Dn::parse("uid,ou=people").unwrap_err(),
        DnFault::NoAttributeValue
    );
}

#[test]
fn a_name_ending_in_a_backslash_is_refused() {
    assert_eq!(Dn::parse(r"cn=x\").unwrap_err(), DnFault::TrailingEscape);
}

#[test]
fn an_absurdly_long_name_is_refused_rather_than_parsed() {
    let deep = (0..200)
        .map(|i| format!("dc=x{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(Dn::parse(&deep).unwrap_err(), DnFault::TooManyComponents);
}

#[test]
fn an_empty_name_is_the_root_and_everything_is_under_it() {
    let root = Dn::parse("").expect("root");
    assert!(root.components.is_empty());
    assert!(Dn::parse(BASE).expect("base").is_under(&root));
}

#[test]
fn a_value_that_would_split_a_name_is_escaped_when_this_server_writes_one() {
    assert_eq!(escape_rdn_value("Jensen, Barbara"), r"Jensen\, Barbara");
    assert_eq!(escape_rdn_value("a=b"), r"a\=b");
    assert_eq!(escape_rdn_value(" lead"), r"\ lead");
    assert_eq!(escape_rdn_value("trail "), r"trail\ ");
    assert_eq!(escape_rdn_value("#hash"), r"\#hash");
}

#[test]
fn a_display_name_cannot_forge_an_extra_component_in_the_name_this_server_builds() {
    let hostile = "admin,ou=people,dc=idm,dc=example,dc=com";
    let dn = format!("uid={},ou=people,{BASE}", escape_rdn_value(hostile));
    let parsed = Dn::parse(&dn).expect("parse");

    assert_eq!(
        parsed.components.len(),
        5,
        "the injected components must stay inside one value: {parsed:?}"
    );
    assert_eq!(parsed.components[0].1, hostile);
}

#[test]
fn an_equality_filter_matches_without_regard_to_case() {
    let filter = Filter::Equality {
        attribute: "uid".to_owned(),
        value: "BJENSEN".to_owned(),
    };
    assert!(evaluate(&user(), &filter, &no_groups()));
}

#[test]
fn a_password_comparison_is_case_exact_so_it_cannot_be_weakened_by_folding() {
    let filter = Filter::Equality {
        attribute: "userPassword".to_owned(),
        value: "{argon2}SECRET".to_owned(),
    };
    assert!(!evaluate(&user(), &filter, &no_groups()));
}

#[test]
fn a_present_filter_on_object_class_answers_for_every_entry() {
    let filter = Filter::Present {
        attribute: "objectClass".to_owned(),
    };
    assert!(evaluate(&user(), &filter, &no_groups()));
    assert!(evaluate(
        &Entry {
            dn: BASE.to_owned(),
            attributes: Vec::new()
        },
        &filter,
        &no_groups()
    ));
}

#[test]
fn a_present_filter_on_an_absent_attribute_does_not_match() {
    let filter = Filter::Present {
        attribute: "telephoneNumber".to_owned(),
    };
    assert!(!evaluate(&user(), &filter, &no_groups()));
}

#[test]
fn a_substring_filter_honours_the_order_of_its_parts() {
    let filter = |initial, any: Vec<&str>, last| Filter::Substrings {
        attribute: "cn".to_owned(),
        parts: argus_parse::ldap_filter::Substrings {
            initial: Some(String::from(initial)),
            any: any.into_iter().map(String::from).collect(),
            final_part: Some(String::from(last)),
        },
    };

    assert!(evaluate(
        &user(),
        &filter("Bar", vec!["ra J"], "sen"),
        &no_groups()
    ));
    assert!(
        !evaluate(
            &user(),
            &filter("Bar", vec!["sen", "ra"], "n"),
            &no_groups()
        ),
        "the any parts have to appear in the order they were given"
    );
}

#[test]
fn a_substring_filter_cannot_overlap_its_own_head_and_tail() {
    let filter = Filter::Substrings {
        attribute: "uid".to_owned(),
        parts: argus_parse::ldap_filter::Substrings {
            initial: Some("bjensen".to_owned()),
            any: Vec::new(),
            final_part: Some("bjensen".to_owned()),
        },
    };
    assert!(
        !evaluate(&user(), &filter, &no_groups()),
        "the value is seven characters, so it cannot both start and end with all seven twice"
    );
}

#[test]
fn a_nested_group_query_is_answered_from_the_membership_graph() {
    let staff = format!("cn=staff,ou=groups,{BASE}");
    let everyone = format!("cn=everyone,ou=groups,{BASE}");
    let subject = user();

    let groups = Groups(vec![
        (staff.clone(), vec![subject.dn.clone()]),
        (everyone.clone(), vec![subject.dn.clone()]),
    ]);

    let filter = Filter::InChain {
        attribute: "memberOf".to_owned(),
        value: everyone,
    };

    assert!(
        evaluate(&subject, &filter, &groups),
        "the AD nested group rule is what GitLab and Grafana send; answering it wrongly hides members"
    );

    let stranger = Filter::InChain {
        attribute: "memberOf".to_owned(),
        value: format!("cn=nobody,ou=groups,{BASE}"),
    };
    assert!(!evaluate(&subject, &stranger, &groups));
    let _ = staff;
}

#[test]
fn a_nested_group_rule_on_another_attribute_is_not_honoured() {
    let filter = Filter::InChain {
        attribute: "cn".to_owned(),
        value: format!("cn=staff,ou=groups,{BASE}"),
    };
    assert!(!evaluate(&user(), &filter, &no_groups()));
}

#[test]
fn a_password_is_never_returned_no_matter_what_the_client_asks_for() {
    for requested in [
        Vec::new(),
        vec!["*".to_owned()],
        vec!["+".to_owned()],
        vec!["userPassword".to_owned()],
        vec!["*".to_owned(), "userPassword".to_owned()],
    ] {
        let projected = project(&user(), &requested);
        assert!(
            projected.values("userPassword").is_empty(),
            "a stored credential must never leave over the wire, asked for or not"
        );
    }
}

#[test]
fn a_star_request_returns_user_attributes_and_leaves_operational_ones_out() {
    let projected = project(&user(), &["*".to_owned()]);
    assert!(!projected.values("cn").is_empty());
    assert!(
        projected.values("memberOf").is_empty(),
        "memberOf is operational; returning it under a star breaks clients that count attributes"
    );
}

#[test]
fn member_of_is_returned_when_it_is_asked_for_by_name() {
    let projected = project(&user(), &["cn".to_owned(), "memberOf".to_owned()]);
    assert!(!projected.values("memberOf").is_empty());
    assert!(projected.values("mail").is_empty());
}

#[test]
fn a_plus_request_returns_the_operational_attributes() {
    let projected = project(&user(), &["+".to_owned()]);
    assert!(!projected.values("memberOf").is_empty());
    assert!(projected.values("cn").is_empty());
}

#[test]
fn the_no_attributes_request_returns_a_bare_name() {
    let projected = project(&user(), &["1.1".to_owned()]);
    assert!(projected.attributes.is_empty());
    assert_eq!(projected.dn, user().dn);
}

#[test]
fn posix_identifiers_are_deterministic_and_land_inside_the_reserved_range() {
    let uuid = [
        0x01, 0x93, 0x4a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11,
        0x22,
    ];

    let first = posix_id(&uuid);
    assert_eq!(first, posix_id(&uuid), "provisioning must be repeatable");
    assert!((POSIX_ID_FLOOR..=POSIX_ID_CEILING).contains(&first));

    let other = posix_id(&[0xFF; 16]);
    assert!((POSIX_ID_FLOOR..=POSIX_ID_CEILING).contains(&other));
    assert_ne!(first, other);
}

#[test]
fn a_scope_this_server_does_not_recognise_is_refused() {
    assert_eq!(Scope::from_wire(0), Some(Scope::Base));
    assert_eq!(Scope::from_wire(1), Some(Scope::OneLevel));
    assert_eq!(Scope::from_wire(2), Some(Scope::Subtree));
    assert_eq!(Scope::from_wire(3), None);
    assert_eq!(Scope::from_wire(-1), None);
}

#[test]
fn a_filter_decoded_from_the_wire_reads_back_as_the_text_form() {
    let equality = encode(
        TAG_EQUALITY,
        &[encode_text(0x04, "uid"), encode_text(0x04, "bjensen")].concat(),
    );
    let present = encode_text(TAG_PRESENT, "objectClass");
    let conjunction = encode(TAG_AND, &[equality, present].concat());

    let element = Reader::new(&conjunction).read().expect("read");
    let filter = decode(&element).expect("decode");

    assert_eq!(to_string(&filter), "(&(uid=bjensen)(objectClass=*))");
}

#[test]
fn a_filter_nested_past_the_limit_is_refused() {
    let mut payload = encode_text(TAG_PRESENT, "objectClass");
    for _ in 0..MAX_FILTER_DEPTH + 4 {
        payload = encode(TAG_NOT, &payload);
    }

    let element = Reader::new(&payload).read().expect("read");
    assert!(
        decode(&element).is_err(),
        "an unauthenticated peer must not be able to choose this server's stack depth"
    );
}

#[test]
fn a_value_carrying_filter_syntax_cannot_change_the_filter_it_is_written_into() {
    assert_eq!(escape("a)(uid=*"), r"a\29\28uid=\2a");
    assert_eq!(escape(r"back\slash"), r"back\5cslash");

    let filter = Filter::Equality {
        attribute: "uid".to_owned(),
        value: "a)(objectClass=*".to_owned(),
    };
    let text = to_string(&filter);
    assert_eq!(
        text.matches('(').count(),
        1,
        "an unescaped value would open a second clause: {text}"
    );
}

#[test]
fn the_nested_group_rule_keeps_its_registered_object_identifier() {
    assert_eq!(MATCHING_RULE_IN_CHAIN, "1.2.840.113556.1.4.1941");
}
