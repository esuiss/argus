#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_parse::ber::{
    BerError, MAX_DEPTH, MAX_ELEMENT_BYTES, Reader, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE,
    encode, encode_integer, encode_length, encode_text,
};

#[test]
fn a_deeply_nested_element_is_refused_while_it_is_being_read_not_afterwards() {
    let mut payload = encode(TAG_OCTET_STRING, b"x");
    for _ in 0..8_000 {
        payload = encode(0xA0, &payload);
    }

    assert!(
        payload.len() < 64 * 1024,
        "the point of this attack is that it is small enough to pass a byte-size limit"
    );

    let mut reader = Reader::new(&payload);
    let mut depth = 0_u32;
    let error;

    let mut current = reader.read().expect("the outermost element parses");
    loop {
        match current.nested() {
            Err(e) => {
                error = Some(e);
                break;
            }
            Ok(mut inner) => match inner.read() {
                Err(e) => {
                    error = Some(e);
                    break;
                }
                Ok(next) => {
                    depth = depth.saturating_add(1);
                    current = next;
                }
            },
        }
    }

    assert_eq!(
        error,
        Some(BerError::TooDeep),
        "a nested element must fail closed rather than run the stack out"
    );
    assert!(
        depth < MAX_DEPTH,
        "the reader stopped at depth {depth}, which is past the limit"
    );
}

#[test]
fn descending_past_the_limit_is_refused_even_for_a_well_formed_encoding() {
    let mut payload = encode(TAG_OCTET_STRING, b"x");
    for _ in 0..MAX_DEPTH {
        payload = encode(TAG_SEQUENCE, &payload);
    }

    let mut reader = Reader::new(&payload);
    let mut element = reader.read().expect("outer");

    let mut descents = 0_u32;
    while let Ok(mut inner) = element.nested() {
        match inner.read() {
            Ok(next) => {
                element = next;
                descents = descents.saturating_add(1);
            }
            Err(_) => break,
        }
    }

    assert!(descents < MAX_DEPTH);
}

#[test]
fn a_length_that_would_allocate_gigabytes_is_refused_before_any_allocation() {
    let payload = [TAG_OCTET_STRING, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(
        Reader::new(&payload).read().unwrap_err(),
        BerError::LengthTooLarge,
        "a four byte length field must not be able to ask for four gigabytes"
    );
}

#[test]
fn a_length_larger_than_the_bytes_that_follow_is_refused() {
    let payload = [TAG_OCTET_STRING, 0x10, 0x01, 0x02];
    assert_eq!(
        Reader::new(&payload).read().unwrap_err(),
        BerError::Truncated
    );
}

#[test]
fn an_indefinite_length_is_refused() {
    let payload = [TAG_SEQUENCE, 0x80, 0x00, 0x00];
    assert_eq!(
        Reader::new(&payload).read().unwrap_err(),
        BerError::IndefiniteLength
    );
}

#[test]
fn a_length_padded_with_leading_zeroes_is_refused() {
    let payload = [TAG_OCTET_STRING, 0x82, 0x00, 0x01, 0x41];
    assert_eq!(
        Reader::new(&payload).read().unwrap_err(),
        BerError::LengthNotMinimal,
        "two encodings of one length let a peer smuggle a different message past a length check"
    );
}

#[test]
fn a_short_length_written_in_long_form_is_refused() {
    let payload = [TAG_OCTET_STRING, 0x81, 0x01, 0x41];
    assert_eq!(
        Reader::new(&payload).read().unwrap_err(),
        BerError::LengthNotMinimal
    );
}

#[test]
fn a_multi_byte_tag_is_refused() {
    let payload = [0x1F, 0x81, 0x00, 0x00];
    assert_eq!(
        Reader::new(&payload).read().unwrap_err(),
        BerError::MultiByteTag
    );
}

#[test]
fn an_empty_input_is_truncated_rather_than_an_empty_element() {
    assert_eq!(Reader::new(&[]).read().unwrap_err(), BerError::Truncated);
}

#[test]
fn integers_round_trip_across_the_sign_boundary() {
    for value in [
        0_i64,
        1,
        127,
        128,
        255,
        256,
        -1,
        -128,
        -129,
        i64::MAX,
        i64::MIN,
    ] {
        let encoded = encode_integer(value);
        let element = Reader::new(&encoded).read().expect("read");
        assert_eq!(element.tag, TAG_INTEGER);
        assert_eq!(element.integer().expect("integer"), value, "for {value}");
    }
}

#[test]
fn an_integer_longer_than_eight_octets_is_refused() {
    let payload = encode(TAG_INTEGER, &[0x01; 9]);
    let element = Reader::new(&payload).read().expect("read");
    assert_eq!(element.integer().unwrap_err(), BerError::IntegerTooLong);
}

#[test]
fn a_string_that_is_not_utf8_is_refused_rather_than_replaced() {
    let payload = encode(TAG_OCTET_STRING, &[0xFF, 0xFE]);
    let element = Reader::new(&payload).read().expect("read");
    assert_eq!(element.text().unwrap_err(), BerError::NotUtf8);
}

#[test]
fn lengths_encode_in_the_shortest_form() {
    assert_eq!(encode_length(0), [0x00]);
    assert_eq!(encode_length(127), [0x7F]);
    assert_eq!(encode_length(128), [0x81, 0x80]);
    assert_eq!(encode_length(255), [0x81, 0xFF]);
    assert_eq!(encode_length(256), [0x82, 0x01, 0x00]);
    assert_eq!(encode_length(65_536), [0x83, 0x01, 0x00, 0x00]);
}

#[test]
fn what_this_encoder_writes_this_reader_reads_back() {
    let inner = [encode_text(TAG_OCTET_STRING, "cn=admin"), encode_integer(3)].concat();
    let payload = encode(TAG_SEQUENCE, &inner);

    let element = Reader::new(&payload).read().expect("outer");
    let mut nested = element.nested().expect("descend");

    assert_eq!(
        nested.expect(TAG_OCTET_STRING).expect("dn").text().unwrap(),
        "cn=admin"
    );
    assert_eq!(
        nested
            .expect(TAG_INTEGER)
            .expect("version")
            .integer()
            .unwrap(),
        3
    );
    nested.finish().expect("nothing left over");
}

#[test]
fn a_message_with_bytes_left_over_is_refused() {
    let payload = [encode_integer(1), Vec::from([0x00_u8])].concat();
    let mut reader = Reader::new(&payload);
    reader.read().expect("first");
    assert_eq!(reader.finish().unwrap_err(), BerError::TrailingBytes);
}

#[test]
fn a_long_but_legitimate_element_still_parses() {
    let body = vec![b'a'; 100_000];
    let payload = encode(TAG_OCTET_STRING, &body);
    let element = Reader::new(&payload).read().expect("read");
    assert_eq!(element.content.len(), 100_000);
    assert!(body.len() < MAX_ELEMENT_BYTES);
}
