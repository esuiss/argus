#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::naive_bytecount
)]

use std::sync::Arc;

use argus_core::ldap::{
    COMPARE_FALSE, COMPARE_TRUE, INSUFFICIENT_ACCESS_RIGHTS, INVALID_CREDENTIALS, OID_WHO_AM_I,
    SUCCESS, UNWILLING_TO_PERFORM,
};
use argus_ldap::directory::{Directory, Group, Person};
use argus_ldap::message::{TAG_BIND_REQUEST, TAG_SEARCH_REQUEST};
use argus_ldap::server::{Service, serve};
use argus_ldap::session::{Confidentiality, PasswordCheck};
use argus_parse::ber::{
    Reader, TAG_BOOLEAN, TAG_OCTET_STRING, TAG_SEQUENCE, encode, encode_enumerated, encode_integer,
    encode_text,
};
use argus_parse::ldap_filter::{TAG_EQUALITY, TAG_PRESENT};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const BASE: &str = "dc=idm,dc=example,dc=com";

struct OnePassword;

impl PasswordCheck for OnePassword {
    fn verify(&self, dn: &str, password: &[u8]) -> bool {
        dn.starts_with("uid=bjensen") && password == b"correct horse"
    }
}

fn directory() -> Directory {
    Directory {
        base: argus_core::ldap::Dn::parse(BASE).expect("base"),
        base_text: BASE.to_owned(),
        vendor_version: "0.0.0".to_owned(),
        start_tls_offered: false,
        people: vec![Person {
            uuid: [1; 16],
            uid: "bjensen".to_owned(),
            display_name: "Barbara Jensen".to_owned(),
            surname: "Jensen".to_owned(),
            given_name: "Barbara".to_owned(),
            mail: Some("bjensen@example.com".to_owned()),
            active: true,
            groups: vec!["staff".to_owned()],
        }],
        groups: vec![Group {
            uuid: [3; 16],
            name: "staff".to_owned(),
            description: None,
            member_uids: vec!["bjensen".to_owned()],
            member_groups: Vec::new(),
        }],
    }
}

async fn listen() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr").to_string();

    let service = Arc::new(Service {
        directory: directory(),
        passwords: OnePassword,
    });

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                let _ = serve(&mut stream, &service, Confidentiality::Protected).await;
            });
        }
    });

    address
}

fn envelope(id: i64, body: &[u8]) -> Vec<u8> {
    encode(TAG_SEQUENCE, &[encode_integer(id), body.to_vec()].concat())
}

fn bind(id: i64, name: &str, password: &[u8]) -> Vec<u8> {
    envelope(
        id,
        &encode(
            TAG_BIND_REQUEST,
            &[
                encode_integer(3),
                encode_text(TAG_OCTET_STRING, name),
                encode(0x80, password),
            ]
            .concat(),
        ),
    )
}

fn search(id: i64, base: &str, scope: i64, filter: Vec<u8>, attributes: &[&str]) -> Vec<u8> {
    let list = attributes
        .iter()
        .map(|name| encode_text(TAG_OCTET_STRING, name))
        .collect::<Vec<_>>()
        .concat();

    envelope(
        id,
        &encode(
            TAG_SEARCH_REQUEST,
            &[
                encode_text(TAG_OCTET_STRING, base),
                encode_enumerated(scope),
                encode_enumerated(0),
                encode_integer(0),
                encode_integer(0),
                encode(TAG_BOOLEAN, &[0x00]),
                filter,
                encode(TAG_SEQUENCE, &list),
            ]
            .concat(),
        ),
    )
}

fn equality(attribute: &str, value: &str) -> Vec<u8> {
    encode(
        TAG_EQUALITY,
        &[
            encode_text(TAG_OCTET_STRING, attribute),
            encode_text(TAG_OCTET_STRING, value),
        ]
        .concat(),
    )
}

struct Reply {
    tags: Vec<u8>,
    codes: Vec<i64>,
    raw: Vec<u8>,
}

async fn exchange(address: &str, requests: &[Vec<u8>]) -> Reply {
    let mut stream = TcpStream::connect(address).await.expect("connect");

    for request in requests {
        stream.write_all(request).await.expect("write");
    }
    stream.flush().await.expect("flush");
    stream.shutdown().await.ok();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");

    let mut reader = Reader::new(&raw);
    let mut tags = Vec::new();
    let mut codes = Vec::new();

    while !reader.is_empty() {
        let Ok(element) = reader.read() else { break };
        let Ok(mut inner) = element.nested() else {
            break;
        };
        let Ok(_id) = inner.read() else { break };
        let Ok(body) = inner.read() else { break };
        tags.push(body.tag);

        if let Ok(mut fields) = body.nested()
            && let Ok(code) = fields.read()
            && code.tag == 0x0A
            && let Ok(value) = code.integer()
        {
            codes.push(value);
        }
    }

    Reply { tags, codes, raw }
}

#[tokio::test]
async fn a_client_binds_and_reads_the_directory_over_a_real_socket() {
    let address = listen().await;

    let reply = exchange(
        &address,
        &[
            bind(1, "bjensen", b"correct horse"),
            search(
                2,
                BASE,
                2,
                encode_text(TAG_PRESENT, "objectClass"),
                &["uid", "mail"],
            ),
        ],
    )
    .await;

    assert_eq!(
        reply.tags.first(),
        Some(&0x61),
        "a bind answers with a bind response"
    );
    assert_eq!(reply.codes.first(), Some(&SUCCESS));

    assert!(
        reply.tags.contains(&0x64),
        "the search returned no entries: {:?}",
        reply.tags
    );
    assert_eq!(reply.tags.last(), Some(&0x65));

    let text = String::from_utf8_lossy(&reply.raw);
    assert!(text.contains("bjensen@example.com"));
}

#[tokio::test]
async fn an_anonymous_client_reads_the_root_entry_but_nothing_else() {
    let address = listen().await;

    let reply = exchange(
        &address,
        &[
            search(1, "", 0, encode_text(TAG_PRESENT, "objectClass"), &[]),
            search(2, BASE, 2, encode_text(TAG_PRESENT, "objectClass"), &[]),
        ],
    )
    .await;

    assert!(
        String::from_utf8_lossy(&reply.raw).contains("namingContexts"),
        "a client discovers the base name before it binds"
    );
    assert!(
        reply.codes.contains(&INSUFFICIENT_ACCESS_RIGHTS),
        "reading the directory without binding must be refused: {:?}",
        reply.codes
    );
}

#[tokio::test]
async fn a_wrong_password_over_the_wire_is_refused_and_leaves_the_session_anonymous() {
    let address = listen().await;

    let reply = exchange(
        &address,
        &[
            bind(1, "bjensen", b"guess"),
            search(2, BASE, 2, encode_text(TAG_PRESENT, "objectClass"), &[]),
        ],
    )
    .await;

    assert_eq!(reply.codes.first(), Some(&INVALID_CREDENTIALS));
    assert!(
        reply.codes.contains(&INSUFFICIENT_ACCESS_RIGHTS),
        "a failed bind must not leave the previous or a partial identity in place: {:?}",
        reply.codes
    );
}

#[tokio::test]
async fn a_name_with_an_empty_password_is_refused_over_the_wire() {
    let address = listen().await;
    let reply = exchange(&address, &[bind(1, "bjensen", b"")]).await;
    assert_eq!(reply.codes.first(), Some(&UNWILLING_TO_PERFORM));
}

#[tokio::test]
async fn a_search_by_uid_returns_exactly_one_entry() {
    let address = listen().await;

    let reply = exchange(
        &address,
        &[
            bind(1, "bjensen", b"correct horse"),
            search(2, BASE, 2, equality("uid", "bjensen"), &["uid"]),
        ],
    )
    .await;

    assert_eq!(reply.tags.iter().filter(|tag| **tag == 0x64_u8).count(), 1);
}

#[tokio::test]
async fn who_am_i_names_the_identity_that_bound() {
    let address = listen().await;

    let extended = envelope(2, &encode(0x77, &encode_text(0x80, OID_WHO_AM_I)));

    let reply = exchange(&address, &[bind(1, "bjensen", b"correct horse"), extended]).await;

    let text = String::from_utf8_lossy(&reply.raw);
    assert!(
        text.contains("dn:uid=bjensen"),
        "a client uses this to confirm which account it is running as: {text}"
    );
}

#[tokio::test]
async fn a_write_request_is_answered_with_a_refusal_rather_than_a_dropped_connection() {
    let address = listen().await;

    let add = envelope(2, &encode(0x68, &encode_text(TAG_OCTET_STRING, "cn=x")));

    let reply = exchange(&address, &[bind(1, "bjensen", b"correct horse"), add]).await;

    assert!(
        reply.codes.contains(&UNWILLING_TO_PERFORM),
        "a client that gets no answer retries forever: {:?}",
        reply.codes
    );
}

#[tokio::test]
async fn a_compare_answers_true_and_false_rather_than_leaking_the_value() {
    let address = listen().await;

    let compare = |id: i64, value: &str| {
        envelope(
            id,
            &encode(
                0x6E,
                &[
                    encode_text(TAG_OCTET_STRING, &format!("uid=bjensen,ou=people,{BASE}")),
                    encode(
                        TAG_SEQUENCE,
                        &[
                            encode_text(TAG_OCTET_STRING, "uid"),
                            encode_text(TAG_OCTET_STRING, value),
                        ]
                        .concat(),
                    ),
                ]
                .concat(),
            ),
        )
    };

    let reply = exchange(
        &address,
        &[
            bind(1, "bjensen", b"correct horse"),
            compare(2, "bjensen"),
            compare(3, "someone-else"),
        ],
    )
    .await;

    assert!(reply.codes.contains(&COMPARE_TRUE));
    assert!(reply.codes.contains(&COMPARE_FALSE));
}

#[tokio::test]
async fn an_unbind_closes_the_connection_without_a_response() {
    let address = listen().await;

    let mut stream = TcpStream::connect(&address).await.expect("connect");
    stream
        .write_all(&envelope(1, &encode(0x42, &[])))
        .await
        .expect("write");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");

    assert!(
        raw.is_empty(),
        "RFC 4511 gives Unbind no response; sending one confuses clients"
    );
}

#[tokio::test]
async fn a_deeply_nested_filter_from_an_unauthenticated_peer_does_not_kill_the_server() {
    let address = listen().await;

    let mut filter = encode_text(TAG_PRESENT, "objectClass");
    for _ in 0..4_000 {
        filter = encode(0xA0, &filter);
    }

    let hostile = search(1, BASE, 2, filter, &[]);
    assert!(hostile.len() < 64 * 1024);

    let _ = exchange(&address, &[hostile]).await;

    let after = exchange(
        &address,
        &[
            bind(1, "bjensen", b"correct horse"),
            search(2, BASE, 2, equality("uid", "bjensen"), &["uid"]),
        ],
    )
    .await;

    assert_eq!(
        after.codes.first(),
        Some(&SUCCESS),
        "the server has to still be answering after the hostile message"
    );
    assert_eq!(after.tags.iter().filter(|tag| **tag == 0x64_u8).count(), 1);
}

#[tokio::test]
async fn a_frame_that_arrives_in_pieces_is_reassembled() {
    let address = listen().await;
    let request = bind(1, "bjensen", b"correct horse");

    let mut stream = TcpStream::connect(&address).await.expect("connect");
    for byte in &request {
        stream.write_all(&[*byte]).await.expect("write");
    }
    stream.flush().await.expect("flush");
    stream.shutdown().await.ok();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");

    let element = Reader::new(&raw).read().expect("a reply arrived");
    let mut inner = element.nested().expect("descend");
    inner.read().expect("id");
    assert_eq!(inner.read().expect("body").tag, 0x61);
}

#[tokio::test]
async fn a_message_that_is_not_ldap_at_all_closes_the_connection_without_a_panic() {
    let address = listen().await;

    let mut stream = TcpStream::connect(&address).await.expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    stream.shutdown().await.ok();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");

    let after = exchange(&address, &[bind(1, "bjensen", b"correct horse")]).await;
    assert_eq!(after.codes.first(), Some(&SUCCESS));
}
