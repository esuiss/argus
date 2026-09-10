// §16 LDAP: GHSA-qcrp-p3rq-pffr, `lber`'daki yamalanmamış yığın tüketimi.
// Derinlik AYRIŞTIRMA SIRASINDA zorlanır, ayrıştırma bittikten sonra değil;
// sonradan bakmak yığını zaten tüketmiş olurdu.
pub const MAX_DEPTH: u32 = 16;
pub const MAX_ELEMENT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LENGTH_OCTETS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BerError {
    #[error("the encoding ends in the middle of an element")]
    Truncated,

    #[error("the element nests deeper than the accepted maximum")]
    TooDeep,

    #[error("the element declares a length this server will not allocate")]
    LengthTooLarge,

    #[error("the element uses an indefinite length, which BER forbids here")]
    IndefiniteLength,

    #[error("the length is encoded in more octets than a length ever needs")]
    LengthNotMinimal,

    #[error("the tag {tag:#04x} is not the one expected here")]
    UnexpectedTag { tag: u8 },

    #[error("a multi-byte tag is not accepted")]
    MultiByteTag,

    #[error("an integer is longer than this server accepts")]
    IntegerTooLong,

    #[error("a string is not valid UTF-8")]
    NotUtf8,

    #[error("the element carries trailing bytes")]
    TrailingBytes,
}

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_ENUMERATED: u8 = 0x0A;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    depth: u32,
}

pub struct Element<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    depth: u32,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            depth: 0,
        }
    }

    const fn at_depth(bytes: &'a [u8], depth: u32) -> Self {
        Self {
            bytes,
            position: 0,
            depth,
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.position >= self.bytes.len()
    }

    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn byte(&mut self) -> Result<u8, BerError> {
        let value = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or(BerError::Truncated)?;
        self.position = self.position.saturating_add(1);
        Ok(value)
    }

    pub fn read(&mut self) -> Result<Element<'a>, BerError> {
        if self.depth >= MAX_DEPTH {
            return Err(BerError::TooDeep);
        }

        let tag = self.byte()?;

        if tag & 0x1F == 0x1F {
            return Err(BerError::MultiByteTag);
        }

        let first = self.byte()?;

        let length = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7F);

            if count == 0 {
                return Err(BerError::IndefiniteLength);
            }

            if count > MAX_LENGTH_OCTETS {
                return Err(BerError::LengthTooLarge);
            }

            let mut value = 0_usize;
            for index in 0..count {
                let octet = self.byte()?;
                if index == 0 && octet == 0 {
                    return Err(BerError::LengthNotMinimal);
                }
                value = value
                    .checked_mul(256)
                    .and_then(|shifted| shifted.checked_add(usize::from(octet)))
                    .ok_or(BerError::LengthTooLarge)?;
            }

            if value < 128 {
                return Err(BerError::LengthNotMinimal);
            }

            value
        };

        if length > MAX_ELEMENT_BYTES {
            return Err(BerError::LengthTooLarge);
        }

        let end = self
            .position
            .checked_add(length)
            .ok_or(BerError::LengthTooLarge)?;

        let content = self
            .bytes
            .get(self.position..end)
            .ok_or(BerError::Truncated)?;

        self.position = end;

        Ok(Element {
            tag,
            content,
            depth: self.depth,
        })
    }

    pub fn expect(&mut self, tag: u8) -> Result<Element<'a>, BerError> {
        let element = self.read()?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(BerError::UnexpectedTag { tag: element.tag })
        }
    }

    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    pub fn finish(&self) -> Result<(), BerError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(BerError::TrailingBytes)
        }
    }
}

impl core::fmt::Debug for Element<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Element")
            .field("tag", &format_args!("{:#04x}", self.tag))
            .field("length", &self.content.len())
            .finish()
    }
}

impl<'a> Element<'a> {
    pub fn nested(&self) -> Result<Reader<'a>, BerError> {
        let deeper = self.depth.checked_add(1).ok_or(BerError::TooDeep)?;
        if deeper >= MAX_DEPTH {
            return Err(BerError::TooDeep);
        }
        Ok(Reader::at_depth(self.content, deeper))
    }

    pub fn integer(&self) -> Result<i64, BerError> {
        if self.content.is_empty() || self.content.len() > 8 {
            return Err(BerError::IntegerTooLong);
        }

        let negative = self.content.first().is_some_and(|first| first & 0x80 != 0);
        let mut value: i64 = if negative { -1 } else { 0 };

        for byte in self.content {
            value = (value << 8) | i64::from(*byte);
        }

        Ok(value)
    }

    pub fn text(&self) -> Result<&'a str, BerError> {
        core::str::from_utf8(self.content).map_err(|_| BerError::NotUtf8)
    }

    pub fn boolean(&self) -> Result<bool, BerError> {
        match self.content {
            [0x00] => Ok(false),
            [_] => Ok(true),
            _ => Err(BerError::IntegerTooLong),
        }
    }
}

#[must_use]
pub fn encode_length(length: usize) -> Vec<u8> {
    if length < 128 {
        return Vec::from([u8::try_from(length).unwrap_or(0x7F)]);
    }

    let mut octets = Vec::new();
    let mut remaining = length;
    while remaining > 0 {
        octets.push(u8::try_from(remaining & 0xFF).unwrap_or(0));
        remaining >>= 8;
    }
    octets.reverse();

    let mut out = Vec::with_capacity(octets.len().saturating_add(1));
    out.push(0x80 | u8::try_from(octets.len()).unwrap_or(0x7F));
    out.extend_from_slice(&octets);
    out
}

#[must_use]
pub fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(6));
    out.push(tag);
    out.extend_from_slice(&encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

#[must_use]
pub fn encode_integer(value: i64) -> Vec<u8> {
    let mut content = Vec::with_capacity(8);
    let bytes = value.to_be_bytes();

    let mut start = 0;
    while start < 7 {
        let current = bytes.get(start).copied().unwrap_or(0);
        let next = bytes.get(start.saturating_add(1)).copied().unwrap_or(0);
        let redundant =
            (current == 0x00 && next & 0x80 == 0) || (current == 0xFF && next & 0x80 != 0);
        if redundant {
            start = start.saturating_add(1);
        } else {
            break;
        }
    }

    content.extend_from_slice(bytes.get(start..).unwrap_or_default());
    encode(TAG_INTEGER, &content)
}

#[must_use]
pub fn encode_enumerated(value: i64) -> Vec<u8> {
    let mut encoded = encode_integer(value);
    if let Some(first) = encoded.first_mut() {
        *first = TAG_ENUMERATED;
    }
    encoded
}

#[must_use]
pub fn encode_text(tag: u8, value: &str) -> Vec<u8> {
    encode(tag, value.as_bytes())
}
