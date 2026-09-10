use serde_json::Value;

pub const MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JcsError {
    #[error("the document nests deeper than canonicalization accepts")]
    TooDeep,

    #[error("a number that is not finite has no canonical form")]
    NotFinite,
}

pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write(value, 0, &mut out)?;
    Ok(out)
}

fn write(value: &Value, depth: u32, out: &mut String) -> Result<(), JcsError> {
    if depth > MAX_DEPTH {
        return Err(JcsError::TooDeep);
    }

    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number_form(number)?),
        Value::String(text) => write_string(text, out),

        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write(item, depth.saturating_add(1), out)?;
            }
            out.push(']');
        }

        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort_by(|left, right| utf16_order(left, right));

            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                let Some(field) = fields.get(key) else {
                    continue;
                };
                write(field, depth.saturating_add(1), out)?;
            }
            out.push('}');
        }
    }

    Ok(())
}

fn utf16_order(left: &str, right: &str) -> core::cmp::Ordering {
    let mut a = left.encode_utf16();
    let mut b = right.encode_utf16();

    loop {
        match (a.next(), b.next()) {
            (None, None) => return core::cmp::Ordering::Equal,
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (Some(_), None) => return core::cmp::Ordering::Greater,
            (Some(left), Some(right)) => match left.cmp(&right) {
                core::cmp::Ordering::Equal => {}
                other => return other,
            },
        }
    }
}

const fn hex_digit(nibble: u32) -> char {
    match nibble {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');

    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let value = c as u32;
                out.push_str("\\u00");
                out.push(hex_digit(value >> 4));
                out.push(hex_digit(value & 0x0F));
            }
            c => out.push(c),
        }
    }

    out.push('"');
}

fn number_form(number: &serde_json::Number) -> Result<String, JcsError> {
    if let Some(value) = number.as_u64() {
        return Ok(value.to_string());
    }

    if let Some(value) = number.as_i64() {
        return Ok(value.to_string());
    }

    let value = number.as_f64().ok_or(JcsError::NotFinite)?;

    if !value.is_finite() {
        return Err(JcsError::NotFinite);
    }

    Ok(ecmascript_form(value))
}

#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "every index is derived from the length of the digit string just computed"
)]
// RFC 8785 §3.2.2.3: sayılar ECMAScript Number::toString biçiminde yazılır.
// Kanonikleştirmenin en ince yeri burasıdır; bir bit fark iki farklı imza
// demektir.
pub fn ecmascript_form(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }

    let negative = value < 0.0;
    let magnitude = value.abs();

    let (digits, exponent) = shortest(magnitude);

    let k = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    let n = exponent.saturating_add(1);

    let body = if k <= n && n <= 21 {
        let zeros = usize::try_from(n.saturating_sub(k)).unwrap_or(0);
        format!("{digits}{}", "0".repeat(zeros))
    } else if 0 < n && n <= 21 {
        let split = usize::try_from(n).unwrap_or(0);
        let (head, tail) = digits.split_at(split.min(digits.len()));
        format!("{head}.{tail}")
    } else if -6 < n && n <= 0 {
        let zeros = usize::try_from(-n).unwrap_or(0);
        format!("0.{}{digits}", "0".repeat(zeros))
    } else {
        let power = n.saturating_sub(1);
        let sign = if power < 0 { '-' } else { '+' };
        let head = &digits[..1];
        let tail = &digits[1..];

        if tail.is_empty() {
            format!("{head}e{sign}{}", power.abs())
        } else {
            format!("{head}.{tail}e{sign}{}", power.abs())
        }
    };

    if negative { format!("-{body}") } else { body }
}

fn shortest(magnitude: f64) -> (String, i32) {
    for precision in 0..=16_usize {
        let rendered = format!("{magnitude:.precision$e}");
        if rendered.parse::<f64>() == Ok(magnitude) {
            return split_scientific(&rendered);
        }
    }

    split_scientific(&format!("{magnitude:.17e}"))
}

fn split_scientific(rendered: &str) -> (String, i32) {
    let (mantissa, exponent) = rendered.split_once('e').unwrap_or((rendered, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);

    let mut digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();

    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }

    if digits.is_empty() {
        digits.push('0');
    }

    (digits, exponent)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TextFault {
    #[error("the document is not well formed JSON at byte {position}")]
    Malformed { position: usize },

    #[error("the document nests deeper than canonicalization accepts")]
    TooDeep,

    #[error("a number is not one IEEE 754 can hold exactly")]
    NotANumber,

    #[error("the document carries bytes after its top level value")]
    TrailingBytes,
}

// Sayıları kaynak baytlardan okur. Sebep ölçüldü: serde_json
// 333333333.33333329'u bir ULP aşağı yuvarlıyor (0x...5554, doğrusu
// 0x...5555). Bir `Value`'dan geçen kanonikleştirme o farkı taşır; kaynak
// metinden geçen taşımaz.
pub fn canonicalize_text(raw: &str) -> Result<String, TextFault> {
    let bytes = raw.as_bytes();
    let mut cursor = Cursor {
        bytes,
        text: raw,
        position: 0,
    };

    cursor.skip_whitespace();
    let value = cursor.value(0)?;
    cursor.skip_whitespace();

    if cursor.position != bytes.len() {
        return Err(TextFault::TrailingBytes);
    }

    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    text: &'a str,
    position: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position = self.position.saturating_add(1);
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), TextFault> {
        if self.peek() == Some(byte) {
            self.position = self.position.saturating_add(1);
            Ok(())
        } else {
            Err(TextFault::Malformed {
                position: self.position,
            })
        }
    }

    fn literal(&mut self, word: &str, rendered: &str) -> Result<String, TextFault> {
        let end = self.position.saturating_add(word.len());
        if self.text.get(self.position..end) == Some(word) {
            self.position = end;
            Ok(rendered.to_owned())
        } else {
            Err(TextFault::Malformed {
                position: self.position,
            })
        }
    }

    fn value(&mut self, depth: u32) -> Result<String, TextFault> {
        if depth > MAX_DEPTH {
            return Err(TextFault::TooDeep);
        }

        match self.peek() {
            None => Err(TextFault::Malformed {
                position: self.position,
            }),
            Some(b'n') => self.literal("null", "null"),
            Some(b't') => self.literal("true", "true"),
            Some(b'f') => self.literal("false", "false"),
            Some(b'"') => self.string(),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(_) => self.number(),
        }
    }

    fn array(&mut self, depth: u32) -> Result<String, TextFault> {
        self.expect(b'[')?;
        let mut out = String::from("[");
        self.skip_whitespace();

        if self.peek() == Some(b']') {
            self.position = self.position.saturating_add(1);
            out.push(']');
            return Ok(out);
        }

        loop {
            self.skip_whitespace();
            let item = self.value(depth.saturating_add(1))?;
            out.push_str(&item);
            self.skip_whitespace();

            match self.peek() {
                Some(b',') => {
                    self.position = self.position.saturating_add(1);
                    out.push(',');
                }
                Some(b']') => {
                    self.position = self.position.saturating_add(1);
                    out.push(']');
                    return Ok(out);
                }
                _ => {
                    return Err(TextFault::Malformed {
                        position: self.position,
                    });
                }
            }
        }
    }

    fn object(&mut self, depth: u32) -> Result<String, TextFault> {
        self.expect(b'{')?;
        self.skip_whitespace();

        if self.peek() == Some(b'}') {
            self.position = self.position.saturating_add(1);
            return Ok("{}".to_owned());
        }

        let mut members: Vec<(String, String, String)> = Vec::new();

        loop {
            self.skip_whitespace();

            let start = self.position;
            let key = self.string()?;
            let raw_key = decode_string(self.text, start)?;

            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();

            let value = self.value(depth.saturating_add(1))?;
            members.push((raw_key, key, value));

            self.skip_whitespace();

            match self.peek() {
                Some(b',') => self.position = self.position.saturating_add(1),
                Some(b'}') => {
                    self.position = self.position.saturating_add(1);
                    break;
                }
                _ => {
                    return Err(TextFault::Malformed {
                        position: self.position,
                    });
                }
            }
        }

        members.sort_by(|left, right| utf16_order(&left.0, &right.0));

        let mut out = String::from("{");
        for (index, (_, key, value)) in members.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push(':');
            out.push_str(value);
        }
        out.push('}');

        Ok(out)
    }

    fn string(&mut self) -> Result<String, TextFault> {
        let start = self.position;
        let decoded = decode_string(self.text, start)?;
        self.position = end_of_string(self.text, start)?;

        let mut out = String::new();
        write_string(&decoded, &mut out);
        Ok(out)
    }

    fn number(&mut self) -> Result<String, TextFault> {
        let start = self.position;

        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.position = self.position.saturating_add(1);
            } else {
                break;
            }
        }

        let token = self
            .text
            .get(start..self.position)
            .ok_or(TextFault::Malformed { position: start })?;

        if token.is_empty() {
            return Err(TextFault::Malformed { position: start });
        }

        if !token.contains(['.', 'e', 'E'])
            && let Ok(integer) = token.parse::<i64>()
        {
            return Ok(integer.to_string());
        }

        let value: f64 = token.parse().map_err(|_| TextFault::NotANumber)?;

        if !value.is_finite() {
            return Err(TextFault::NotANumber);
        }

        Ok(ecmascript_form(value))
    }
}

fn end_of_string(text: &str, start: usize) -> Result<usize, TextFault> {
    let bytes = text.as_bytes();

    if bytes.get(start) != Some(&b'"') {
        return Err(TextFault::Malformed { position: start });
    }

    let mut index = start.saturating_add(1);

    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'\\' => index = index.saturating_add(2),
            b'"' => return Ok(index.saturating_add(1)),
            _ => index = index.saturating_add(1),
        }
    }

    Err(TextFault::Malformed { position: start })
}

fn decode_string(text: &str, start: usize) -> Result<String, TextFault> {
    let end = end_of_string(text, start)?;
    let slice = text
        .get(start..end)
        .ok_or(TextFault::Malformed { position: start })?;

    serde_json::from_str::<String>(slice).map_err(|_| TextFault::Malformed { position: start })
}
