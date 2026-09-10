use argus_parse::ldap_filter::{Filter, Substrings};

pub const SUCCESS: i64 = 0;
pub const OPERATIONS_ERROR: i64 = 1;
pub const PROTOCOL_ERROR: i64 = 2;
pub const SIZE_LIMIT_EXCEEDED: i64 = 4;
pub const COMPARE_FALSE: i64 = 5;
pub const COMPARE_TRUE: i64 = 6;
pub const AUTH_METHOD_NOT_SUPPORTED: i64 = 7;
pub const STRONGER_AUTH_REQUIRED: i64 = 8;
pub const NO_SUCH_ATTRIBUTE: i64 = 16;
pub const INAPPROPRIATE_MATCHING: i64 = 18;
pub const NO_SUCH_OBJECT: i64 = 32;
pub const INVALID_DN_SYNTAX: i64 = 34;
pub const INVALID_CREDENTIALS: i64 = 49;
pub const INSUFFICIENT_ACCESS_RIGHTS: i64 = 50;
pub const UNAVAILABLE: i64 = 52;
pub const UNWILLING_TO_PERFORM: i64 = 53;
pub const CONFIDENTIALITY_REQUIRED: i64 = 13;

pub const OID_START_TLS: &str = "1.3.6.1.4.1.1466.20037";
pub const OID_WHO_AM_I: &str = "1.3.6.1.4.1.4203.1.11.3";
pub const OID_PASSWORD_MODIFY: &str = "1.3.6.1.4.1.4203.1.11.1";
pub const OID_PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Base,
    OneLevel,
    Subtree,
}

impl Scope {
    #[must_use]
    pub const fn from_wire(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Base),
            1 => Some(Self::OneLevel),
            2 => Some(Self::Subtree),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnFault {
    #[error("a relative name carries no equals sign")]
    NoAttributeValue,

    #[error("a relative name carries an empty attribute type")]
    EmptyAttribute,

    #[error("the distinguished name ends in a trailing escape")]
    TrailingEscape,

    #[error("the distinguished name nests more components than this server accepts")]
    TooManyComponents,
}

pub const MAX_DN_COMPONENTS: usize = 16;
pub const MAX_DN_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dn {
    pub components: Vec<(String, String)>,
}

impl Dn {
    pub fn parse(raw: &str) -> Result<Self, DnFault> {
        if raw.len() > MAX_DN_BYTES {
            return Err(DnFault::TooManyComponents);
        }

        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                components: Vec::new(),
            });
        }

        let mut components = Vec::new();

        for part in split_unescaped(trimmed, ',')? {
            let mut pieces = split_unescaped(&part, '=')?;
            if pieces.len() != 2 {
                return Err(DnFault::NoAttributeValue);
            }

            let value = pieces.pop().unwrap_or_default();
            let attribute = pieces.pop().unwrap_or_default();

            let attribute = attribute.trim().to_ascii_lowercase();
            if attribute.is_empty() {
                return Err(DnFault::EmptyAttribute);
            }

            components.push((attribute, unescape(value.trim())));

            if components.len() > MAX_DN_COMPONENTS {
                return Err(DnFault::TooManyComponents);
            }
        }

        Ok(Self { components })
    }

    #[must_use]
    pub fn normalised(&self) -> String {
        self.components
            .iter()
            .map(|(attribute, value)| format!("{attribute}={}", value.trim().to_lowercase()))
            .collect::<Vec<_>>()
            .join(",")
    }

    #[must_use]
    pub fn equals(&self, other: &Self) -> bool {
        self.normalised() == other.normalised()
    }

    #[must_use]
    pub fn is_under(&self, base: &Self) -> bool {
        if base.components.is_empty() {
            return true;
        }
        if self.components.len() < base.components.len() {
            return false;
        }
        let offset = self.components.len().saturating_sub(base.components.len());
        let tail = self.components.get(offset..).unwrap_or_default();
        Self {
            components: tail.to_vec(),
        }
        .normalised()
            == base.normalised()
    }

    #[must_use]
    pub fn depth_below(&self, base: &Self) -> usize {
        self.components.len().saturating_sub(base.components.len())
    }

    #[must_use]
    pub fn first_value(&self, attribute: &str) -> Option<&str> {
        self.components
            .iter()
            .find(|(name, _)| name == attribute)
            .map(|(_, value)| value.as_str())
    }
}

fn split_unescaped(input: &str, separator: char) -> Result<Vec<String>, DnFault> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for c in input.chars() {
        if escaped {
            current.push('\\');
            current.push(c);
            escaped = false;
            continue;
        }

        match c {
            '\\' => escaped = true,
            c if c == separator => {
                parts.push(core::mem::take(&mut current));
            }
            other => current.push(other),
        }
    }

    if escaped {
        return Err(DnFault::TrailingEscape);
    }

    parts.push(current);
    Ok(parts)
}

fn unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }

        let Some(first) = chars.next() else {
            break;
        };

        if first.is_ascii_hexdigit() {
            let second = chars.clone().next();
            if let Some(second) = second
                && second.is_ascii_hexdigit()
            {
                chars.next();
                let mut hex = String::with_capacity(2);
                hex.push(first);
                hex.push(second);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    out.push(char::from(byte));
                    continue;
                }
            }
        }

        out.push(first);
    }

    out
}

#[must_use]
pub fn escape_rdn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let count = value.chars().count();

    for (index, c) in value.chars().enumerate() {
        let leading = index == 0;
        let trailing = index.saturating_add(1) == count;

        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '#' if leading => out.push_str("\\#"),
            ' ' if leading || trailing => out.push_str("\\ "),
            '\u{0}' => out.push_str("\\00"),
            other => out.push(other),
        }
    }

    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub uuid: [u8; 16],
    pub uid: String,
    pub display_name: String,
    pub surname: String,
    pub given_name: String,
    pub mail: Option<String>,
    pub active: bool,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub uuid: [u8; 16],
    pub name: String,
    pub description: Option<String>,
    pub member_uids: Vec<String>,
    pub member_groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub dn: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

impl Entry {
    #[must_use]
    pub fn values(&self, attribute: &str) -> &[String] {
        self.attributes
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(attribute))
            .map_or(&[], |(_, values)| values.as_slice())
    }

    #[must_use]
    pub fn has(&self, attribute: &str) -> bool {
        self.attributes
            .iter()
            .any(|(name, values)| name.eq_ignore_ascii_case(attribute) && !values.is_empty())
    }
}

#[must_use]
pub fn attribute_is_case_exact(attribute: &str) -> bool {
    matches!(
        attribute.to_ascii_lowercase().as_str(),
        "userpassword" | "objectguid" | "entryuuid"
    )
}

fn compare_values(left: &str, right: &str, case_exact: bool) -> core::cmp::Ordering {
    if case_exact {
        left.cmp(right)
    } else {
        left.to_lowercase().cmp(&right.to_lowercase())
    }
}

fn matches_substrings(value: &str, parts: &Substrings, case_exact: bool) -> bool {
    let subject = if case_exact {
        value.to_owned()
    } else {
        value.to_lowercase()
    };

    let fold = |text: &str| {
        if case_exact {
            text.to_owned()
        } else {
            text.to_lowercase()
        }
    };

    let mut cursor = 0_usize;

    if let Some(initial) = parts.initial.as_ref() {
        let initial = fold(initial);
        if !subject.starts_with(&initial) {
            return false;
        }
        cursor = initial.len();
    }

    let tail_start = match parts.final_part.as_ref() {
        None => subject.len(),
        Some(final_part) => {
            let final_part = fold(final_part);
            if !subject.ends_with(&final_part) {
                return false;
            }
            let start = subject.len().saturating_sub(final_part.len());
            if start < cursor {
                return false;
            }
            start
        }
    };

    let middle = subject.get(cursor..tail_start).unwrap_or_default();
    let mut position = 0_usize;

    for part in &parts.any {
        let part = fold(part);
        let haystack = middle.get(position..).unwrap_or_default();
        match haystack.find(&part) {
            None => return false,
            Some(found) => {
                position = position.saturating_add(found).saturating_add(part.len());
            }
        }
    }

    true
}

pub trait Membership {
    fn transitively_contains(&self, group_dn: &str, member_dn: &str) -> bool;
}

pub struct NoMembership;

impl Membership for NoMembership {
    fn transitively_contains(&self, _group_dn: &str, _member_dn: &str) -> bool {
        false
    }
}

#[must_use]
pub fn evaluate(entry: &Entry, filter: &Filter, membership: &impl Membership) -> bool {
    match filter {
        Filter::And(clauses) => clauses
            .iter()
            .all(|clause| evaluate(entry, clause, membership)),

        Filter::Or(clauses) => clauses
            .iter()
            .any(|clause| evaluate(entry, clause, membership)),

        Filter::Not(inner) => !evaluate(entry, inner, membership),

        Filter::Present { attribute } => {
            if attribute.eq_ignore_ascii_case("objectClass") {
                return true;
            }
            entry.has(attribute)
        }

        Filter::Equality { attribute, value } | Filter::Approx { attribute, value } => {
            let case_exact = attribute_is_case_exact(attribute);
            entry
                .values(attribute)
                .iter()
                .any(|candidate| compare_values(candidate, value, case_exact).is_eq())
        }

        Filter::GreaterOrEqual { attribute, value } => {
            let case_exact = attribute_is_case_exact(attribute);
            entry
                .values(attribute)
                .iter()
                .any(|candidate| !compare_values(candidate, value, case_exact).is_lt())
        }

        Filter::LessOrEqual { attribute, value } => {
            let case_exact = attribute_is_case_exact(attribute);
            entry
                .values(attribute)
                .iter()
                .any(|candidate| !compare_values(candidate, value, case_exact).is_gt())
        }

        Filter::Substrings { attribute, parts } => {
            let case_exact = attribute_is_case_exact(attribute);
            entry
                .values(attribute)
                .iter()
                .any(|candidate| matches_substrings(candidate, parts, case_exact))
        }

        Filter::InChain { attribute, value } => {
            if !attribute.eq_ignore_ascii_case("memberOf") {
                return false;
            }
            membership.transitively_contains(value, &entry.dn)
        }
    }
}

pub const OPERATIONAL_ATTRIBUTES: [&str; 6] = [
    "memberof",
    "createtimestamp",
    "modifytimestamp",
    "entryuuid",
    "entrydn",
    "subschemasubentry",
];

#[must_use]
pub fn project(entry: &Entry, requested: &[String]) -> Entry {
    let wants_all_user = requested.is_empty() || requested.iter().any(|name| name == "*");
    let wants_all_operational = requested.iter().any(|name| name == "+");
    let no_attributes = requested.len() == 1 && requested.first().is_some_and(|name| name == "1.1");

    if no_attributes {
        return Entry {
            dn: entry.dn.clone(),
            attributes: Vec::new(),
        };
    }

    let mut attributes = Vec::new();

    for (name, values) in &entry.attributes {
        let lowered = name.to_ascii_lowercase();

        if lowered == "userpassword" {
            continue;
        }

        let operational = OPERATIONAL_ATTRIBUTES.contains(&lowered.as_str());
        let asked_for = requested
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(name));

        let include = if operational {
            asked_for || wants_all_operational
        } else {
            asked_for || wants_all_user
        };

        if include {
            attributes.push((name.clone(), values.clone()));
        }
    }

    Entry {
        dn: entry.dn.clone(),
        attributes,
    }
}

pub const POSIX_ID_FLOOR: u32 = 1_000_000;
pub const POSIX_ID_CEILING: u32 = 1_999_999;

#[must_use]
pub fn posix_id(uuid: &[u8; 16]) -> u32 {
    let mut value = 0_u32;
    for byte in uuid.iter().take(4) {
        value = (value << 8) | u32::from(*byte);
    }

    let span = POSIX_ID_CEILING
        .saturating_sub(POSIX_ID_FLOOR)
        .saturating_add(1);

    POSIX_ID_FLOOR.saturating_add(value % span)
}
