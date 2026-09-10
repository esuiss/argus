use base64ct::{Base64, Encoding as _};

pub const MAX_ENCODED_MESSAGE_BYTES: usize = 256 * 1024;
pub const MAX_INFLATED_BYTES: usize = 512 * 1024;
pub const MAX_INFLATION_RATIO: usize = 100;
pub const MAX_RELAY_STATE_BYTES: usize = 80;

pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingFault {
    #[error("the encoded message is larger than this server will decode")]
    EncodedTooLarge,

    #[error("the message is not valid base64")]
    NotBase64,

    #[error("the message does not decompress")]
    NotDeflate,

    #[error("the message expands beyond the accepted limit")]
    InflationLimit,

    #[error("the message is not valid UTF-8")]
    NotUtf8,

    #[error("RelayState is longer than the 80 bytes SAML allows")]
    RelayStateTooLong,
}

pub fn decode_post(encoded: &str) -> Result<String, BindingFault> {
    let trimmed: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();

    if trimmed.len() > MAX_ENCODED_MESSAGE_BYTES {
        return Err(BindingFault::EncodedTooLarge);
    }

    let bytes = Base64::decode_vec(&trimmed).map_err(|_| BindingFault::NotBase64)?;

    if bytes.len() > MAX_INFLATED_BYTES {
        return Err(BindingFault::InflationLimit);
    }

    String::from_utf8(bytes).map_err(|_| BindingFault::NotUtf8)
}

#[must_use]
pub fn encode_post(message: &str) -> String {
    Base64::encode_string(message.as_bytes())
}

pub fn check_relay_state(relay_state: Option<&str>) -> Result<(), BindingFault> {
    match relay_state {
        None => Ok(()),
        Some(value) if value.len() <= MAX_RELAY_STATE_BYTES => Ok(()),
        Some(_) => Err(BindingFault::RelayStateTooLong),
    }
}

#[must_use]
pub fn inflate_budget(encoded_len: usize) -> usize {
    encoded_len
        .saturating_mul(MAX_INFLATION_RATIO)
        .min(MAX_INFLATED_BYTES)
}

pub type Inflate<'a> = dyn Fn(&[u8], usize) -> Option<Vec<u8>> + 'a;

pub fn decode_redirect(encoded: &str, inflate: &Inflate<'_>) -> Result<String, BindingFault> {
    let trimmed: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();

    if trimmed.len() > MAX_ENCODED_MESSAGE_BYTES {
        return Err(BindingFault::EncodedTooLarge);
    }

    let deflated = Base64::decode_vec(&trimmed).map_err(|_| BindingFault::NotBase64)?;

    let budget = inflate_budget(deflated.len());

    let bytes = inflate(&deflated, budget).ok_or(BindingFault::InflationLimit)?;

    if bytes.len() > budget {
        return Err(BindingFault::InflationLimit);
    }

    String::from_utf8(bytes).map_err(|_| BindingFault::NotUtf8)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use base64ct::{Base64, Encoding as _};

    use super::{
        BindingFault, MAX_ENCODED_MESSAGE_BYTES, check_relay_state, decode_post, decode_redirect,
        encode_post, inflate_budget,
    };

    #[test]
    fn a_post_message_round_trips() {
        let message = "<samlp:AuthnRequest/>";
        assert_eq!(decode_post(&encode_post(message)).unwrap(), message);
    }

    #[test]
    fn line_wrapped_base64_from_a_form_field_still_decodes() {
        let encoded = encode_post("<samlp:AuthnRequest/>");
        let wrapped = format!("{}\r\n{}", &encoded[..4], &encoded[4..]);
        assert_eq!(decode_post(&wrapped).unwrap(), "<samlp:AuthnRequest/>");
    }

    #[test]
    fn an_oversized_encoded_message_is_refused_before_it_is_decoded() {
        let huge = "A".repeat(MAX_ENCODED_MESSAGE_BYTES + 4);
        assert_eq!(
            decode_post(&huge).unwrap_err(),
            BindingFault::EncodedTooLarge
        );
    }

    #[test]
    fn a_message_that_is_not_base64_is_refused() {
        assert_eq!(
            decode_post("not base64!!!").unwrap_err(),
            BindingFault::NotBase64
        );
    }

    #[test]
    fn a_relay_state_beyond_eighty_bytes_is_refused() {
        assert!(check_relay_state(None).is_ok());
        assert!(check_relay_state(Some(&"a".repeat(80))).is_ok());
        assert_eq!(
            check_relay_state(Some(&"a".repeat(81))).unwrap_err(),
            BindingFault::RelayStateTooLong
        );
    }

    #[test]
    fn the_inflation_budget_is_bounded_both_by_ratio_and_by_an_absolute_ceiling() {
        assert_eq!(inflate_budget(10), 1_000);
        assert_eq!(
            inflate_budget(1_000_000),
            super::MAX_INFLATED_BYTES,
            "a small compressed payload must not be allowed to expand without limit"
        );
    }

    #[test]
    fn a_decompression_bomb_is_refused_rather_than_expanded() {
        let encoded = Base64::encode_string(&[0x00_u8; 64]);
        let result = decode_redirect(&encoded, &|_, budget| Some(vec![b'a'; budget + 1]));
        assert_eq!(result.unwrap_err(), BindingFault::InflationLimit);
    }

    #[test]
    fn a_message_that_does_not_decompress_is_refused() {
        let encoded = Base64::encode_string(&[0xFF_u8; 8]);
        assert_eq!(
            decode_redirect(&encoded, &|_, _| None).unwrap_err(),
            BindingFault::InflationLimit
        );
    }

    #[test]
    fn a_message_within_the_budget_decodes() {
        let encoded = Base64::encode_string(&[0x00_u8; 64]);
        assert_eq!(
            decode_redirect(&encoded, &|_, _| Some(b"<samlp:AuthnRequest/>".to_vec())).unwrap(),
            "<samlp:AuthnRequest/>"
        );
    }
}
