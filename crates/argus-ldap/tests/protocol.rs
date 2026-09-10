#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::ldap::{
    CONFIDENTIALITY_REQUIRED, INSUFFICIENT_ACCESS_RIGHTS, INVALID_CREDENTIALS, OID_START_TLS,
    OID_WHO_AM_I, SUCCESS, Scope, UNWILLING_TO_PERFORM,
};
use argus_ldap::directory::{
    Directory, Group, MAX_SIZE_LIMIT, Person, effective_size_limit, effective_time_limit, search,
};
use argus_ldap::message::{
    MessageError, Operation, TAG_ADD_REQUEST, TAG_BIND_REQUEST, TAG_MODIFY_REQUEST,
    TAG_SEARCH_REQUEST, decode, framed_length, search_result_entry,
};
use argus_ldap::session::{
    BindDecision, Confidentiality, Identity, PasswordCheck, ReadAccess, access_of, decide_bind,
    refuse_search,
};
use argus_parse::ber::{
    Reader, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE, encode, encode_enumerated,
    encode_integer, encode_text,
};
use argus_parse::ldap_filter::{Filter, TAG_PRESENT};

const BASE: &str = "dc=idm,dc=example,dc=com";

fn directory() -> Directory {
    Directory {
        base: argus_core::ldap::Dn::parse(BASE).expect("base"),
        base_text: BASE.to_owned(),
        vendor_version: "0.0.0".to_owned(),
        start_tls_offered: true,
        people: vec![
            Person {
                uuid: [1; 16],
                uid: "bjensen".to_owned(),
                display_name: "Barbara Jensen".to_owned(),
                surname: "Jensen".to_owned(),
                given_name: "Barbara".to_owned(),
                mail: Some("bjensen@example.com".to_owned()),
                active: true,
                groups: vec!["staff".to_owned()],
            },
            Person {
                uuid: [2; 16],
                uid: "asmith".to_owned(),
                display_name: "Alan Smith".to_owned(),
                surname: "Smith".to_owned(),
                given_name: "Alan".to_owned(),
                mail: None,
                active: false,
                groups: Vec::new(),
            },
        ],
        groups: vec![
            Group {
                uuid: [3; 16],
                name: "staff".to_owned(),
                description: Some("All staff".to_owned()),
                member_uids: vec!["bjensen".to_owned()],
                member_groups: Vec::new(),
            },
            Group {
                uuid: [4; 16],
                name: "everyone".to_owned(),
                description: None,
                member_uids: Vec::new(),
                member_groups: vec!["staff".to_owned()],
            },
        ],
    }
}

struct OneCorrectPassword;

impl PasswordCheck for OneCorrectPassword {
    fn verify(&self, dn: &str, password: &[u8]) -> bool {
        dn.starts_with("uid=bjensen") && password == b"correct horse"
    }
}

fn bind(name: &str, password: &[u8], confidentiality: Confidentiality) -> BindDecision {
    let dir = directory();
    decide_bind(
        name,
        password,
        confidentiality,
        |candidate| {
            dir.find_by_bind_name(candidate)
                .map(|person| dir.person_dn(&person.uid))
        },
        &OneCorrectPassword,
    )
}

#[test]
fn an_anonymous_bind_succeeds_and_grants_only_the_root_entry() {
    let decision = bind("", b"", Confidentiality::Protected);
    assert_eq!(decision.code, SUCCESS);
    assert_eq!(decision.identity, Some(Identity::Anonymous));
    assert_eq!(access_of(&Identity::Anonymous), ReadAccess::RootDseOnly);
    assert_eq!(
        refuse_search(ReadAccess::RootDseOnly, false),
        Some(INSUFFICIENT_ACCESS_RIGHTS)
    );
    assert_eq!(refuse_search(ReadAccess::RootDseOnly, true), None);
}

#[test]
fn a_name_with_an_empty_password_is_refused_rather_than_treated_as_success() {
    let decision = bind(
        "uid=bjensen,ou=people,dc=idm,dc=example,dc=com",
        b"",
        Confidentiality::Protected,
    );
    assert_eq!(
        decision.code, UNWILLING_TO_PERFORM,
        "the unauthenticated bind is the oldest trap in LDAP: an empty password must never authenticate"
    );
    assert!(decision.identity.is_none());
}

#[test]
fn a_password_sent_over_an_unprotected_connection_is_refused() {
    let decision = bind("bjensen", b"correct horse", Confidentiality::Plaintext);
    assert_eq!(decision.code, CONFIDENTIALITY_REQUIRED);
    assert!(decision.identity.is_none());
}

#[test]
fn the_correct_password_over_a_protected_connection_authenticates() {
    let decision = bind("bjensen", b"correct horse", Confidentiality::Protected);
    assert_eq!(decision.code, SUCCESS);
    assert_eq!(
        decision.identity,
        Some(Identity::Person {
            dn: "uid=bjensen,ou=people,dc=idm,dc=example,dc=com".to_owned()
        })
    );
}

#[test]
fn a_wrong_password_is_refused_with_the_same_code_as_an_unknown_name() {
    let wrong = bind("bjensen", b"guess", Confidentiality::Protected);
    let unknown = bind("nobody", b"guess", Confidentiality::Protected);

    assert_eq!(wrong.code, INVALID_CREDENTIALS);
    assert_eq!(
        unknown.code, INVALID_CREDENTIALS,
        "a different code here would tell an attacker which accounts exist"
    );
    assert_eq!(wrong.message, unknown.message);
}

#[test]
fn a_bind_name_may_be_a_full_name_a_bare_uid_or_an_address() {
    for name in [
        "uid=bjensen,ou=people,dc=idm,dc=example,dc=com",
        "bjensen",
        "BJensen",
        "bjensen@example.com",
    ] {
        assert_eq!(
            bind(name, b"correct horse", Confidentiality::Protected).code,
            SUCCESS,
            "for {name}"
        );
    }
}

#[test]
fn the_root_entry_tells_a_client_where_the_directory_starts() {
    let root = directory().root_dse();
    assert_eq!(root.values("namingContexts"), [BASE]);
    assert_eq!(root.values("supportedLDAPVersion"), ["3"]);
    assert_eq!(root.values("subschemaSubentry"), ["cn=Subschema"]);
    assert!(
        root.values("supportedExtension")
            .iter()
            .any(|oid| oid == OID_WHO_AM_I)
    );
    assert!(
        root.values("supportedExtension")
            .iter()
            .any(|oid| oid == OID_START_TLS)
    );
    assert_eq!(root.values("vendorName"), ["Argus"]);
}

#[test]
fn the_root_entry_does_not_advertise_start_tls_when_it_is_off() {
    let mut dir = directory();
    dir.start_tls_offered = false;
    assert!(
        !dir.root_dse()
            .values("supportedExtension")
            .iter()
            .any(|oid| oid == OID_START_TLS),
        "advertising a capability that is switched off sends clients down a path that fails"
    );
}

#[test]
fn the_schema_entry_carries_the_definitions_java_clients_read_before_they_work() {
    let schema = directory().subschema();
    let classes = schema.values("objectClasses").join(" ");
    let types = schema.values("attributeTypes").join(" ");

    assert!(classes.contains("'inetOrgPerson'"));
    assert!(classes.contains("'posixAccount'"));
    assert!(classes.contains("'groupOfNames'"));
    assert!(classes.contains("'posixGroup'"));
    assert!(types.contains("'uidNumber'"));
    assert!(types.contains("'memberUid'"));
    assert!(types.contains("'memberOf'"));
}

#[test]
fn a_group_carries_both_the_name_form_and_the_uid_form_of_its_membership() {
    let dir = directory();
    let staff = dir.group_entry(&dir.groups[0]);

    assert_eq!(staff.values("memberUid"), ["bjensen"]);
    assert_eq!(
        staff.values("member"),
        ["uid=bjensen,ou=people,dc=idm,dc=example,dc=com"],
        "one client family reads member and the other reads memberUid, so a group has to carry both"
    );
}

#[test]
fn a_person_carries_the_posix_attributes_that_sssd_needs() {
    let dir = directory();
    let person = dir.person_entry(&dir.people[0]);

    assert_eq!(person.values("homeDirectory"), ["/home/bjensen"]);
    assert_eq!(person.values("loginShell"), ["/bin/bash"]);
    assert!(!person.values("uidNumber").is_empty());
    assert!(!person.values("gidNumber").is_empty());
}

#[test]
fn a_disabled_account_carries_the_control_bit_gitlab_reads() {
    let dir = directory();
    assert_eq!(
        dir.person_entry(&dir.people[0])
            .values("userAccountControl"),
        ["512"]
    );
    assert_eq!(
        dir.person_entry(&dir.people[1])
            .values("userAccountControl"),
        ["514"],
        "clients that check bit two need it set for a disabled account"
    );
}

#[test]
fn a_base_scope_search_of_the_empty_name_returns_the_root_entry() {
    let dir = directory();
    let filter = Filter::Present {
        attribute: "objectClass".to_owned(),
    };
    let outcome = search(&dir, "", Scope::Base, &filter, &[], 0);

    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.entries[0].dn, "");
    assert!(!outcome.entries[0].values("namingContexts").is_empty());
}

#[test]
fn a_one_level_search_of_the_people_container_lists_the_people_and_nothing_else() {
    let dir = directory();
    let filter = Filter::Present {
        attribute: "objectClass".to_owned(),
    };
    let outcome = search(&dir, &dir.people_base(), Scope::OneLevel, &filter, &[], 0);

    assert_eq!(outcome.entries.len(), 2);
    assert!(
        outcome
            .entries
            .iter()
            .all(|entry| entry.dn.starts_with("uid="))
    );
}

#[test]
fn a_subtree_search_of_the_base_reaches_people_and_groups() {
    let dir = directory();
    let filter = Filter::Present {
        attribute: "objectClass".to_owned(),
    };
    let outcome = search(&dir, BASE, Scope::Subtree, &filter, &[], 0);

    assert!(
        outcome
            .entries
            .iter()
            .any(|entry| entry.dn.starts_with("uid=bjensen"))
    );
    assert!(
        outcome
            .entries
            .iter()
            .any(|entry| entry.dn.starts_with("cn=staff"))
    );
    assert!(outcome.entries.iter().any(|entry| entry.dn == BASE));
}

#[test]
fn a_search_under_another_suffix_returns_nothing() {
    let dir = directory();
    let filter = Filter::Present {
        attribute: "objectClass".to_owned(),
    };
    let outcome = search(&dir, "dc=other,dc=com", Scope::Subtree, &filter, &[], 0);
    assert!(outcome.entries.is_empty());
}

#[test]
fn a_search_of_the_schema_name_returns_the_schema() {
    let dir = directory();
    let filter = Filter::Present {
        attribute: "objectClass".to_owned(),
    };
    let outcome = search(&dir, "cn=Subschema", Scope::Base, &filter, &[], 0);
    assert_eq!(outcome.entries.len(), 1);
    assert!(!outcome.entries[0].values("objectClasses").is_empty());
}

#[test]
fn a_nested_group_search_finds_a_member_of_a_member_group() {
    let dir = directory();
    let filter = Filter::InChain {
        attribute: "memberOf".to_owned(),
        value: dir.group_dn("everyone"),
    };

    let outcome = search(&dir, &dir.people_base(), Scope::Subtree, &filter, &[], 0);

    assert_eq!(
        outcome.entries.len(),
        1,
        "bjensen is in staff, and staff is in everyone, so the chain rule has to reach them"
    );
    assert!(outcome.entries[0].dn.starts_with("uid=bjensen"));
}

#[test]
fn a_group_cycle_does_not_hang_the_membership_walk() {
    let mut dir = directory();
    dir.groups[0].member_groups = vec!["everyone".to_owned()];

    let filter = Filter::InChain {
        attribute: "memberOf".to_owned(),
        value: dir.group_dn("everyone"),
    };

    let outcome = search(&dir, &dir.people_base(), Scope::Subtree, &filter, &[], 0);
    assert_eq!(outcome.entries.len(), 1);
}

#[test]
fn a_search_stops_at_the_server_limit_when_the_client_asks_for_none() {
    let dir = directory();
    let filter = Filter::Present {
        attribute: "objectClass".to_owned(),
    };
    let outcome = search(&dir, BASE, Scope::Subtree, &filter, &[], 2);

    assert_eq!(outcome.entries.len(), 2);
    assert!(outcome.truncated);
}

#[test]
fn the_server_applies_its_own_ceiling_when_a_client_asks_for_more() {
    assert_eq!(effective_size_limit(0), 500);
    assert_eq!(effective_size_limit(-1), 500);
    assert_eq!(effective_size_limit(10), 10);
    assert_eq!(
        effective_size_limit(MAX_SIZE_LIMIT + 1),
        500,
        "a client must not be able to ask this server to materialise an unbounded result"
    );

    assert_eq!(effective_time_limit(0), 30);
    assert_eq!(effective_time_limit(10), 10);
    assert_eq!(effective_time_limit(10_000), 30);
}

fn bind_message(version: i64, name: &str, password: &[u8]) -> Vec<u8> {
    let body = [
        encode_integer(version),
        encode_text(TAG_OCTET_STRING, name),
        encode(0x80, password),
    ]
    .concat();

    encode(
        TAG_SEQUENCE,
        &[encode_integer(1), encode(TAG_BIND_REQUEST, &body)].concat(),
    )
}

#[test]
fn a_simple_bind_is_read_off_the_wire() {
    let message = decode(&bind_message(3, "cn=admin", b"secret")).expect("decode");
    assert_eq!(message.id, 1);

    match message.operation {
        Operation::Bind(bind) => {
            assert_eq!(bind.name, "cn=admin");
            assert_eq!(bind.password, b"secret");
        }
        other => panic!("expected a bind, got {other:?}"),
    }
}

#[test]
fn a_bind_password_never_appears_in_a_debug_rendering() {
    let message = decode(&bind_message(3, "cn=admin", b"hunter2")).expect("decode");
    let rendered = format!("{:?}", message.operation);

    assert!(
        !rendered.contains("hunter2"),
        "a password that reaches a log line is a password that has leaked: {rendered}"
    );
    assert!(rendered.contains("redacted"));
}

#[test]
fn an_ldap_version_other_than_three_is_refused() {
    assert_eq!(
        decode(&bind_message(2, "cn=admin", b"secret")).unwrap_err(),
        MessageError::UnsupportedVersion { version: 2 }
    );
}

#[test]
fn a_sasl_bind_is_refused_rather_than_ignored() {
    let body = [
        encode_integer(3),
        encode_text(TAG_OCTET_STRING, ""),
        encode(0xA3, &encode_text(TAG_OCTET_STRING, "GSSAPI")),
    ]
    .concat();

    let message = encode(
        TAG_SEQUENCE,
        &[encode_integer(1), encode(TAG_BIND_REQUEST, &body)].concat(),
    );

    assert_eq!(
        decode(&message).unwrap_err(),
        MessageError::UnsupportedAuthentication
    );
}

#[test]
fn a_search_request_is_read_off_the_wire() {
    let body = [
        encode_text(TAG_OCTET_STRING, BASE),
        encode_enumerated(2),
        encode_enumerated(0),
        encode_integer(100),
        encode_integer(30),
        encode(TAG_BOOLEAN, &[0x00]),
        encode_text(TAG_PRESENT, "objectClass"),
        encode(
            TAG_SEQUENCE,
            &[
                encode_text(TAG_OCTET_STRING, "uid"),
                encode_text(TAG_OCTET_STRING, "mail"),
            ]
            .concat(),
        ),
    ]
    .concat();

    let message = encode(
        TAG_SEQUENCE,
        &[encode_integer(2), encode(TAG_SEARCH_REQUEST, &body)].concat(),
    );

    match decode(&message).expect("decode").operation {
        Operation::Search(request) => {
            assert_eq!(request.base, BASE);
            assert_eq!(request.scope, Scope::Subtree);
            assert_eq!(request.size_limit, 100);
            assert_eq!(request.attributes, ["uid", "mail"]);
            assert!(!request.types_only);
        }
        other => panic!("expected a search, got {other:?}"),
    }
}

#[test]
fn a_write_operation_is_answered_rather_than_dropped() {
    for tag in [TAG_ADD_REQUEST, TAG_MODIFY_REQUEST] {
        let message = encode(
            TAG_SEQUENCE,
            &[
                encode_integer(3),
                encode(tag, &encode_text(TAG_OCTET_STRING, "cn=x")),
            ]
            .concat(),
        );

        match decode(&message).expect("decode").operation {
            Operation::Refused { tag: refused } => assert_eq!(refused, tag),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn an_unbind_carries_no_response() {
    let message = encode(
        TAG_SEQUENCE,
        &[encode_integer(4), encode(0x42, &[])].concat(),
    );
    assert!(matches!(
        decode(&message).expect("decode").operation,
        Operation::Unbind
    ));
}

#[test]
fn an_abandon_names_the_message_it_cancels() {
    let message = encode(
        TAG_SEQUENCE,
        &[encode_integer(5), {
            let mut encoded = encode_integer(2);
            if let Some(first) = encoded.first_mut() {
                *first = 0x50;
            }
            encoded
        }]
        .concat(),
    );

    match decode(&message).expect("decode").operation {
        Operation::Abandon { target } => assert_eq!(target, 2),
        other => panic!("expected an abandon, got {other:?}"),
    }
}

#[test]
fn an_extended_request_names_the_operation_it_wants() {
    let body = encode_text(0x80, OID_WHO_AM_I);
    let message = encode(
        TAG_SEQUENCE,
        &[encode_integer(6), encode(0x77, &body)].concat(),
    );

    match decode(&message).expect("decode").operation {
        Operation::Extended { name, value } => {
            assert_eq!(name, OID_WHO_AM_I);
            assert!(value.is_none());
        }
        other => panic!("expected an extended request, got {other:?}"),
    }
}

#[test]
fn a_message_frame_is_measured_before_it_is_read() {
    let message = bind_message(3, "cn=admin", b"secret");
    assert_eq!(framed_length(&message), Some(Ok(message.len())));

    assert_eq!(framed_length(&[]), None, "an empty buffer needs more bytes");
    assert_eq!(framed_length(&[0x30]), None);
    assert!(
        framed_length(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).is_some_and(|r| r.is_err()),
        "a frame this server will never read must be rejected before it is buffered"
    );
    assert!(
        framed_length(&[0x02, 0x01, 0x01]).is_some_and(|r| r.is_err()),
        "a message that is not a sequence is not an LDAP message"
    );
}

#[test]
fn a_search_result_entry_this_server_writes_reads_back_as_a_sequence() {
    let dir = directory();
    let entry = dir.person_entry(&dir.people[0]);
    let encoded = search_result_entry(7, &entry, false);

    let element = Reader::new(&encoded).read().expect("envelope");
    assert_eq!(element.tag, TAG_SEQUENCE);

    let mut inner = element.nested().expect("descend");
    assert_eq!(inner.expect(TAG_INTEGER).expect("id").integer().unwrap(), 7);
    assert_eq!(inner.read().expect("body").tag, 0x64);
}

#[test]
fn a_types_only_search_returns_names_without_values() {
    let dir = directory();
    let entry = dir.person_entry(&dir.people[0]);

    let with_values = search_result_entry(1, &entry, false);
    let without = search_result_entry(1, &entry, true);

    assert!(with_values.len() > without.len());
    assert!(
        !String::from_utf8_lossy(&without).contains("bjensen@example.com"),
        "a types-only search must not carry the values it was told to leave out"
    );
}

#[test]
fn a_deeply_nested_search_filter_is_refused_before_the_stack_runs_out() {
    let mut filter = encode_text(TAG_PRESENT, "objectClass");
    for _ in 0..4_000 {
        filter = encode(0xA0, &filter);
    }

    let body = [
        encode_text(TAG_OCTET_STRING, BASE),
        encode_enumerated(2),
        encode_enumerated(0),
        encode_integer(0),
        encode_integer(0),
        encode(TAG_BOOLEAN, &[0x00]),
        filter,
        encode(TAG_SEQUENCE, &[]),
    ]
    .concat();

    let message = encode(
        TAG_SEQUENCE,
        &[encode_integer(9), encode(TAG_SEARCH_REQUEST, &body)].concat(),
    );

    assert!(
        message.len() < 64 * 1024,
        "this attack is small on the wire, which is why a byte limit does not catch it"
    );

    assert!(
        decode(&message).is_err(),
        "an unauthenticated peer must not be able to abort this process with one search"
    );
}

fn everything(dir: &Directory) -> Vec<argus_core::ldap::Entry> {
    let mut all = dir.entries();
    all.push(dir.root_dse());
    all.push(dir.subschema());
    all
}

#[test]
fn the_published_schema_names_every_attribute_this_server_can_return() {
    let dir = directory();
    let schema = dir.subschema();
    let published = schema.values("attributeTypes").join(" ");

    let mut emitted: Vec<String> = Vec::new();
    for entry in everything(&dir) {
        for (name, _) in &entry.attributes {
            if !emitted.iter().any(|seen| seen == name) {
                emitted.push(name.clone());
            }
        }
    }

    for name in &emitted {
        assert!(
            published.contains(&format!("NAME '{name}'")),
            "this server returns {name} but never publishes it; a schema-validating client \
             refuses the whole search over one unknown attribute"
        );
    }

    assert!(emitted.len() > 10, "the walk found almost nothing to check");
}

#[test]
fn the_published_schema_names_every_object_class_this_server_can_return() {
    let dir = directory();
    let published = dir.subschema().values("objectClasses").join(" ");

    for entry in everything(&dir) {
        for class in entry.values("objectClass") {
            assert!(
                published.contains(&format!("NAME '{class}'")),
                "this server claims the class {class} but never publishes its definition"
            );
        }
    }
}
