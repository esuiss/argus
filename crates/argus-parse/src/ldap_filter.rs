use crate::ber::{BerError, Element, Reader};

pub const MAX_FILTER_DEPTH: u32 = 12;
pub const MAX_FILTER_NODES: usize = 256;

pub const TAG_AND: u8 = 0xA0;
pub const TAG_OR: u8 = 0xA1;
pub const TAG_NOT: u8 = 0xA2;
pub const TAG_EQUALITY: u8 = 0xA3;
pub const TAG_SUBSTRINGS: u8 = 0xA4;
pub const TAG_GREATER_OR_EQUAL: u8 = 0xA5;
pub const TAG_LESS_OR_EQUAL: u8 = 0xA6;
pub const TAG_PRESENT: u8 = 0x87;
pub const TAG_APPROX: u8 = 0xA8;
pub const TAG_EXTENSIBLE: u8 = 0xA9;

pub const MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Equality {
        attribute: String,
        value: String,
    },
    Substrings {
        attribute: String,
        parts: Substrings,
    },
    GreaterOrEqual {
        attribute: String,
        value: String,
    },
    LessOrEqual {
        attribute: String,
        value: String,
    },
    Present {
        attribute: String,
    },
    Approx {
        attribute: String,
        value: String,
    },
    InChain {
        attribute: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Substrings {
    pub initial: Option<String>,
    pub any: Vec<String>,
    pub final_part: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("the filter encoding is not readable: {0}")]
    Ber(#[from] BerError),

    #[error("the filter nests deeper than the accepted maximum")]
    TooDeep,

    #[error("the filter has more nodes than the accepted maximum")]
    TooLarge,

    #[error("an and or or filter carries no clauses")]
    EmptySet,

    #[error("the filter choice {tag:#04x} is not one this server evaluates")]
    UnsupportedChoice { tag: u8 },

    #[error("a substring filter carries no parts")]
    EmptySubstrings,

    #[error("an extensible match names a matching rule this server does not implement")]
    UnsupportedMatchingRule,

    #[error("an extensible match names no attribute")]
    ExtensibleWithoutAttribute,
}

struct Budget {
    nodes: usize,
}

pub fn decode(element: &Element<'_>) -> Result<Filter, FilterError> {
    let mut budget = Budget { nodes: 0 };
    decode_at(element, 0, &mut budget)
}

fn decode_at(
    element: &Element<'_>,
    depth: u32,
    budget: &mut Budget,
) -> Result<Filter, FilterError> {
    if depth >= MAX_FILTER_DEPTH {
        return Err(FilterError::TooDeep);
    }

    budget.nodes = budget.nodes.saturating_add(1);
    if budget.nodes > MAX_FILTER_NODES {
        return Err(FilterError::TooLarge);
    }

    match element.tag {
        TAG_AND | TAG_OR => {
            let mut reader = element.nested()?;
            let mut clauses = Vec::new();
            while !reader.is_empty() {
                let inner = reader.read()?;
                clauses.push(decode_at(&inner, depth.saturating_add(1), budget)?);
            }
            if clauses.is_empty() {
                return Err(FilterError::EmptySet);
            }
            Ok(if element.tag == TAG_AND {
                Filter::And(clauses)
            } else {
                Filter::Or(clauses)
            })
        }

        TAG_NOT => {
            let mut reader = element.nested()?;
            let inner = reader.read()?;
            Ok(Filter::Not(Box::new(decode_at(
                &inner,
                depth.saturating_add(1),
                budget,
            )?)))
        }

        TAG_PRESENT => Ok(Filter::Present {
            attribute: element.text()?.to_owned(),
        }),

        TAG_EQUALITY | TAG_GREATER_OR_EQUAL | TAG_LESS_OR_EQUAL | TAG_APPROX => {
            let (attribute, value) = assertion(element)?;
            Ok(match element.tag {
                TAG_EQUALITY => Filter::Equality { attribute, value },
                TAG_GREATER_OR_EQUAL => Filter::GreaterOrEqual { attribute, value },
                TAG_LESS_OR_EQUAL => Filter::LessOrEqual { attribute, value },
                _ => Filter::Approx { attribute, value },
            })
        }

        TAG_SUBSTRINGS => {
            let mut reader = element.nested()?;
            let attribute = reader.read()?.text()?.to_owned();
            let list = reader.read()?;
            let mut parts = reader_parts(&list)?;

            if parts.initial.is_none() && parts.any.is_empty() && parts.final_part.is_none() {
                return Err(FilterError::EmptySubstrings);
            }

            parts.any.retain(|part| !part.is_empty());

            Ok(Filter::Substrings { attribute, parts })
        }

        TAG_EXTENSIBLE => {
            let mut reader = element.nested()?;
            let mut rule = None;
            let mut attribute = None;
            let mut value = None;

            while !reader.is_empty() {
                let field = reader.read()?;
                match field.tag {
                    0x81 => rule = Some(field.text()?.to_owned()),
                    0x82 => attribute = Some(field.text()?.to_owned()),
                    0x83 => value = Some(field.text()?.to_owned()),
                    0x84 => {}
                    tag => return Err(FilterError::UnsupportedChoice { tag }),
                }
            }

            let attribute = attribute.ok_or(FilterError::ExtensibleWithoutAttribute)?;
            let value = value.unwrap_or_default();

            match rule.as_deref() {
                Some(MATCHING_RULE_IN_CHAIN) => Ok(Filter::InChain { attribute, value }),
                None => Ok(Filter::Equality { attribute, value }),
                Some(_) => Err(FilterError::UnsupportedMatchingRule),
            }
        }

        tag => Err(FilterError::UnsupportedChoice { tag }),
    }
}

fn assertion(element: &Element<'_>) -> Result<(String, String), FilterError> {
    let mut reader = element.nested()?;
    let attribute = reader.read()?.text()?.to_owned();
    let value = reader.read()?.text()?.to_owned();
    Ok((attribute, value))
}

fn reader_parts(list: &Element<'_>) -> Result<Substrings, FilterError> {
    let mut reader: Reader<'_> = list.nested()?;
    let mut parts = Substrings::default();

    while !reader.is_empty() {
        let part = reader.read()?;
        let text = part.text()?.to_owned();
        match part.tag {
            0x80 => parts.initial = Some(text),
            0x81 => parts.any.push(text),
            0x82 => parts.final_part = Some(text),
            tag => return Err(FilterError::UnsupportedChoice { tag }),
        }
    }

    Ok(parts)
}

#[must_use]
pub fn to_string(filter: &Filter) -> String {
    match filter {
        Filter::And(clauses) => group('&', clauses),
        Filter::Or(clauses) => group('|', clauses),
        Filter::Not(inner) => format!("(!{})", to_string(inner)),
        Filter::Present { attribute } => format!("({}=*)", escape(attribute)),
        Filter::Equality { attribute, value } => {
            format!("({}={})", escape(attribute), escape(value))
        }
        Filter::GreaterOrEqual { attribute, value } => {
            format!("({}>={})", escape(attribute), escape(value))
        }
        Filter::LessOrEqual { attribute, value } => {
            format!("({}<={})", escape(attribute), escape(value))
        }
        Filter::Approx { attribute, value } => {
            format!("({}~={})", escape(attribute), escape(value))
        }
        Filter::InChain { attribute, value } => format!(
            "({}:{MATCHING_RULE_IN_CHAIN}:={})",
            escape(attribute),
            escape(value)
        ),
        Filter::Substrings { attribute, parts } => {
            let mut out = String::from("(");
            out.push_str(&escape(attribute));
            out.push('=');
            if let Some(initial) = parts.initial.as_ref() {
                out.push_str(&escape(initial));
            }
            out.push('*');
            for part in &parts.any {
                out.push_str(&escape(part));
                out.push('*');
            }
            if let Some(final_part) = parts.final_part.as_ref() {
                out.push_str(&escape(final_part));
            }
            out.push(')');
            out
        }
    }
}

fn group(operator: char, clauses: &[Filter]) -> String {
    let mut out = String::from("(");
    out.push(operator);
    for clause in clauses {
        out.push_str(&to_string(clause));
    }
    out.push(')');
    out
}

#[must_use]
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            other if (other as u32) < 0x20 || other == '\u{7f}' => {
                let byte = u8::try_from(other as u32).unwrap_or(0);
                out.push('\\');
                out.push(nibble(byte >> 4));
                out.push(nibble(byte & 0x0F));
            }
            other => out.push(other),
        }
    }
    out
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'a' + (value.saturating_sub(10))),
    }
}
