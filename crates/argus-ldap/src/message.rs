use argus_core::ldap::Scope;
use argus_parse::ber::{
    BerError, Reader, TAG_BOOLEAN, TAG_ENUMERATED, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE,
    encode, encode_enumerated, encode_integer, encode_text,
};
use argus_parse::ldap_filter::{Filter, FilterError, decode as decode_filter};

pub const TAG_BIND_REQUEST: u8 = 0x60;
pub const TAG_BIND_RESPONSE: u8 = 0x61;
pub const TAG_UNBIND_REQUEST: u8 = 0x42;
pub const TAG_SEARCH_REQUEST: u8 = 0x63;
pub const TAG_SEARCH_RESULT_ENTRY: u8 = 0x64;
pub const TAG_SEARCH_RESULT_DONE: u8 = 0x65;
pub const TAG_ABANDON_REQUEST: u8 = 0x50;
pub const TAG_COMPARE_REQUEST: u8 = 0x6E;
pub const TAG_COMPARE_RESPONSE: u8 = 0x6F;
pub const TAG_EXTENDED_REQUEST: u8 = 0x77;
pub const TAG_EXTENDED_RESPONSE: u8 = 0x78;
pub const TAG_ADD_REQUEST: u8 = 0x68;
pub const TAG_DELETE_REQUEST: u8 = 0x4A;
pub const TAG_MODIFY_REQUEST: u8 = 0x66;
pub const TAG_MODIFY_DN_REQUEST: u8 = 0x6C;

pub const TAG_SIMPLE_CREDENTIALS: u8 = 0x80;
pub const TAG_SASL_CREDENTIALS: u8 = 0xA3;
pub const TAG_CONTROLS: u8 = 0xA0;
pub const TAG_EXTENDED_REQUEST_NAME: u8 = 0x80;
pub const TAG_EXTENDED_REQUEST_VALUE: u8 = 0x81;
pub const TAG_EXTENDED_RESPONSE_NAME: u8 = 0x8A;
pub const TAG_EXTENDED_RESPONSE_VALUE: u8 = 0x8B;

pub const MAX_MESSAGE_BYTES: usize = 512 * 1024;
pub const MAX_REQUESTED_ATTRIBUTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    #[error("the message encoding is not readable: {0}")]
    Ber(#[from] BerError),

    #[error("the filter is not usable: {0}")]
    Filter(#[from] FilterError),

    #[error("the operation {tag:#04x} is not one this server implements")]
    UnsupportedOperation { tag: u8 },

    #[error("the search names a scope this server does not recognise")]
    UnknownScope,

    #[error("the bind uses an authentication method this server does not accept")]
    UnsupportedAuthentication,

    #[error("the bind names LDAP version {version}")]
    UnsupportedVersion { version: i64 },

    #[error("the search asks for more attributes than this server will return")]
    TooManyAttributes,

    #[error("the message is larger than this server will read")]
    TooLarge,
}

pub struct SimpleBind {
    pub name: String,
    pub password: Vec<u8>,
}

impl core::fmt::Debug for SimpleBind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SimpleBind")
            .field("name", &self.name)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub struct Search {
    pub base: String,
    pub scope: Scope,
    pub size_limit: i64,
    pub time_limit: i64,
    pub types_only: bool,
    pub filter: Filter,
    pub attributes: Vec<String>,
}

#[derive(Debug)]
pub enum Operation {
    Bind(SimpleBind),
    Unbind,
    Search(Search),
    Abandon {
        target: i64,
    },
    Compare {
        dn: String,
        attribute: String,
        value: String,
    },
    Extended {
        name: String,
        value: Option<Vec<u8>>,
    },
    Refused {
        tag: u8,
    },
}

#[derive(Debug)]
pub struct Message {
    pub id: i64,
    pub operation: Operation,
}

#[must_use]
pub fn framed_length(buffer: &[u8]) -> Option<Result<usize, MessageError>> {
    let first = buffer.first().copied()?;

    if first != TAG_SEQUENCE {
        return Some(Err(MessageError::Ber(BerError::UnexpectedTag {
            tag: first,
        })));
    }

    let length_octet = buffer.get(1).copied()?;

    let (header, length) = if length_octet & 0x80 == 0 {
        (2_usize, usize::from(length_octet))
    } else {
        let count = usize::from(length_octet & 0x7F);
        if count == 0 || count > 4 {
            return Some(Err(MessageError::Ber(BerError::LengthTooLarge)));
        }

        let mut value = 0_usize;
        for index in 0..count {
            let byte = buffer.get(2usize.saturating_add(index)).copied()?;
            value = value.saturating_mul(256).saturating_add(usize::from(byte));
        }

        (count.saturating_add(2), value)
    };

    let total = header.saturating_add(length);

    if total > MAX_MESSAGE_BYTES {
        return Some(Err(MessageError::TooLarge));
    }

    Some(Ok(total))
}

pub fn decode(bytes: &[u8]) -> Result<Message, MessageError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(MessageError::TooLarge);
    }

    let mut outer = Reader::new(bytes);
    let envelope = outer.expect(TAG_SEQUENCE)?;
    let mut reader = envelope.nested()?;

    let id = reader.expect(TAG_INTEGER)?.integer()?;
    let body = reader.read()?;

    let operation = match body.tag {
        TAG_BIND_REQUEST => {
            let mut fields = body.nested()?;
            let version = fields.expect(TAG_INTEGER)?.integer()?;
            if version != 3 {
                return Err(MessageError::UnsupportedVersion { version });
            }

            let name = fields.expect(TAG_OCTET_STRING)?.text()?.to_owned();
            let credentials = fields.read()?;

            match credentials.tag {
                TAG_SIMPLE_CREDENTIALS => Operation::Bind(SimpleBind {
                    name,
                    password: credentials.content.to_vec(),
                }),
                _ => return Err(MessageError::UnsupportedAuthentication),
            }
        }

        TAG_UNBIND_REQUEST => Operation::Unbind,

        TAG_ABANDON_REQUEST => Operation::Abandon {
            target: body.integer()?,
        },

        TAG_SEARCH_REQUEST => {
            let mut fields = body.nested()?;

            let base = fields.expect(TAG_OCTET_STRING)?.text()?.to_owned();
            let scope = Scope::from_wire(fields.expect(TAG_ENUMERATED)?.integer()?)
                .ok_or(MessageError::UnknownScope)?;
            let _alias = fields.expect(TAG_ENUMERATED)?.integer()?;
            let size_limit = fields.expect(TAG_INTEGER)?.integer()?;
            let time_limit = fields.expect(TAG_INTEGER)?.integer()?;
            let types_only = fields.expect(TAG_BOOLEAN)?.boolean()?;

            let filter_element = fields.read()?;
            let filter = decode_filter(&filter_element)?;

            let list = fields.expect(TAG_SEQUENCE)?;
            let mut attributes_reader = list.nested()?;
            let mut attributes = Vec::new();
            while !attributes_reader.is_empty() {
                attributes.push(attributes_reader.read()?.text()?.to_owned());
                if attributes.len() > MAX_REQUESTED_ATTRIBUTES {
                    return Err(MessageError::TooManyAttributes);
                }
            }

            Operation::Search(Search {
                base,
                scope,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            })
        }

        TAG_COMPARE_REQUEST => {
            let mut fields = body.nested()?;
            let dn = fields.expect(TAG_OCTET_STRING)?.text()?.to_owned();
            let assertion = fields.expect(TAG_SEQUENCE)?;
            let mut parts = assertion.nested()?;
            let attribute = parts.expect(TAG_OCTET_STRING)?.text()?.to_owned();
            let value = parts.expect(TAG_OCTET_STRING)?.text()?.to_owned();
            Operation::Compare {
                dn,
                attribute,
                value,
            }
        }

        TAG_EXTENDED_REQUEST => {
            let mut fields = body.nested()?;
            let name = fields.expect(TAG_EXTENDED_REQUEST_NAME)?.text()?.to_owned();
            let value = if fields.is_empty() {
                None
            } else {
                Some(fields.expect(TAG_EXTENDED_REQUEST_VALUE)?.content.to_vec())
            };
            Operation::Extended { name, value }
        }

        tag @ (TAG_ADD_REQUEST
        | TAG_DELETE_REQUEST
        | TAG_MODIFY_REQUEST
        | TAG_MODIFY_DN_REQUEST) => Operation::Refused { tag },

        tag => return Err(MessageError::UnsupportedOperation { tag }),
    };

    Ok(Message { id, operation })
}

fn envelope(id: i64, body: &[u8]) -> Vec<u8> {
    let inner = [encode_integer(id), body.to_vec()].concat();
    encode(TAG_SEQUENCE, &inner)
}

fn result(code: i64, matched_dn: &str, message: &str) -> Vec<u8> {
    [
        encode_enumerated(code),
        encode_text(TAG_OCTET_STRING, matched_dn),
        encode_text(TAG_OCTET_STRING, message),
    ]
    .concat()
}

#[must_use]
pub fn bind_response(id: i64, code: i64, message: &str) -> Vec<u8> {
    envelope(id, &encode(TAG_BIND_RESPONSE, &result(code, "", message)))
}

#[must_use]
pub fn search_result_done(id: i64, code: i64, matched_dn: &str, message: &str) -> Vec<u8> {
    envelope(
        id,
        &encode(TAG_SEARCH_RESULT_DONE, &result(code, matched_dn, message)),
    )
}

#[must_use]
pub fn compare_response(id: i64, code: i64) -> Vec<u8> {
    envelope(id, &encode(TAG_COMPARE_RESPONSE, &result(code, "", "")))
}

#[must_use]
pub fn extended_response(
    id: i64,
    code: i64,
    message: &str,
    name: Option<&str>,
    value: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = result(code, "", message);
    if let Some(name) = name {
        body.extend_from_slice(&encode_text(TAG_EXTENDED_RESPONSE_NAME, name));
    }
    if let Some(value) = value {
        body.extend_from_slice(&encode(TAG_EXTENDED_RESPONSE_VALUE, value));
    }
    envelope(id, &encode(TAG_EXTENDED_RESPONSE, &body))
}

#[must_use]
pub fn search_result_entry(id: i64, entry: &argus_core::ldap::Entry, types_only: bool) -> Vec<u8> {
    let mut attributes = Vec::new();

    for (name, values) in &entry.attributes {
        let mut encoded_values = Vec::new();
        if !types_only {
            for value in values {
                encoded_values.extend_from_slice(&encode_text(TAG_OCTET_STRING, value));
            }
        }

        let attribute = [
            encode_text(TAG_OCTET_STRING, name),
            encode(0x31, &encoded_values),
        ]
        .concat();

        attributes.extend_from_slice(&encode(TAG_SEQUENCE, &attribute));
    }

    let body = [
        encode_text(TAG_OCTET_STRING, &entry.dn),
        encode(TAG_SEQUENCE, &attributes),
    ]
    .concat();

    envelope(id, &encode(TAG_SEARCH_RESULT_ENTRY, &body))
}
