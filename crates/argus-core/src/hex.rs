const DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(digit(byte >> 4));
        out.push(digit(byte & 0x0F));
    }
    out
}

fn digit(nibble: u8) -> char {
    DIGITS.get(nibble as usize).copied().unwrap_or('0')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::encode;

    #[test]
    fn every_byte_becomes_two_lower_case_digits() {
        assert_eq!(encode(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn an_empty_input_encodes_to_an_empty_string() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn the_encoding_is_fixed_width_so_two_digests_never_collide_by_truncation() {
        assert_eq!(encode(&[1, 2]).len(), 4);
        assert_eq!(encode(&[0x12]), "12");
        assert_ne!(encode(&[0x01, 0x23]), encode(&[0x12, 0x30]));
    }
}
