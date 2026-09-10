use argus_parse::scim_filter::{CompareOp, Filter, Value as FilterValue};
use serde_json::Value;

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

pub const MAX_PAGE_SIZE: usize = 200;
pub const DEFAULT_PAGE_SIZE: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    User,
    Group,
}

impl ResourceType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScimFault {
    #[error("the request body is not a JSON object")]
    NotAnObject,

    #[error("the schemas attribute is required and must list {expected}")]
    WrongSchema { expected: &'static str },

    #[error("the attribute {attribute} is required")]
    Missing { attribute: &'static str },

    #[error("the attribute {attribute} has the wrong type")]
    WrongType { attribute: String },

    #[error("the attribute {attribute} is read-only and cannot be set by a client")]
    Immutable { attribute: &'static str },

    #[error("{detail}")]
    InvalidValue { detail: String },

    #[error("the filter is not a valid SCIM filter: {detail}")]
    InvalidFilter { detail: String },

    #[error("the pagination parameters are not usable: {detail}")]
    InvalidPaging { detail: String },

    #[error("the cursor is not one this server issued")]
    InvalidCursor,

    #[error("the count is not a number this server can page by")]
    InvalidCount,
}

impl ScimFault {
    #[must_use]
    pub const fn scim_type(&self) -> &'static str {
        match self {
            Self::InvalidFilter { .. } => "invalidFilter",
            Self::WrongSchema { .. } | Self::NotAnObject => "invalidSyntax",
            Self::Immutable { .. } => "mutability",
            Self::InvalidCursor => "invalidCursor",
            Self::InvalidCount => "invalidCount",
            _ => "invalidValue",
        }
    }
}

#[must_use]
pub fn attribute_is_case_exact(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let bare = lower.rsplit(':').next().unwrap_or(&lower);
    matches!(
        bare,
        "id" | "externalid" | "members.value" | "members.$ref" | "$ref" | "meta.resourcetype"
    )
}

// Ara adımlarda diziler düzleştirilir. Her adımda bir nesne şart koşmak
// `emails.value` gibi bir filtrenin hiçbir zaman eşleşmemesine yol açıyordu:
// `emails` bir dizidir ve `value` onun elemanlarındadır.
fn resolve_all<'a>(resource: &'a Value, path: &str) -> Vec<&'a Value> {
    let bare = match path.rfind(':') {
        Some(index) => match path.get(index + 1..) {
            Some(rest) => rest,
            None => return Vec::new(),
        },
        None => path,
    };

    let mut current: Vec<&Value> = Vec::from([resource]);

    for segment in bare.split('.') {
        let mut next: Vec<&Value> = Vec::new();
        for node in current {
            if let Some(items) = node.as_array() {
                for item in items {
                    if let Some(found) = field(item, segment) {
                        next.push(found);
                    }
                }
            } else if let Some(found) = field(node, segment) {
                next.push(found);
            }
        }
        if next.is_empty() {
            return Vec::new();
        }
        current = next;
    }

    current
}

fn field<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn resolve<'a>(resource: &'a Value, path: &str) -> Option<&'a Value> {
    resolve_all(resource, path).first().copied()
}

fn present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
        _ => true,
    }
}

fn compare_one(actual: &Value, op: CompareOp, expected: &FilterValue, case_exact: bool) -> bool {
    match (actual, expected) {
        (Value::String(left), FilterValue::Str(right)) => {
            let (left, right) = if case_exact {
                (left.clone(), right.clone())
            } else {
                (left.to_lowercase(), right.to_lowercase())
            };
            match op {
                CompareOp::Eq => left == right,
                CompareOp::Ne => left != right,
                CompareOp::Co => left.contains(&right),
                CompareOp::Sw => left.starts_with(&right),
                CompareOp::Ew => left.ends_with(&right),
                CompareOp::Gt => left > right,
                CompareOp::Lt => left < right,
                CompareOp::Ge => left >= right,
                CompareOp::Le => left <= right,
            }
        }

        (Value::Bool(left), FilterValue::Bool(right)) => match op {
            CompareOp::Eq => left == right,
            CompareOp::Ne => left != right,
            _ => false,
        },

        (Value::Number(left), FilterValue::Number(right)) => {
            let Some(left) = left.as_f64() else {
                return false;
            };
            match op {
                CompareOp::Eq => (left - right).abs() < f64::EPSILON,
                CompareOp::Ne => (left - right).abs() >= f64::EPSILON,
                CompareOp::Gt => left > *right,
                CompareOp::Lt => left < *right,
                CompareOp::Ge => left >= *right,
                CompareOp::Le => left <= *right,
                _ => false,
            }
        }

        (Value::Null, FilterValue::Null) => matches!(op, CompareOp::Eq),

        (_, FilterValue::Null) => matches!(op, CompareOp::Ne),

        _ => false,
    }
}

#[must_use]
pub fn evaluate(resource: &Value, filter: &Filter) -> bool {
    match filter {
        Filter::Present { path } => resolve_all(resource, path).iter().any(|value| match value {
            Value::Array(items) => items.iter().any(present),
            other => present(other),
        }),

        Filter::Compare { path, op, value } => {
            let case_exact = attribute_is_case_exact(path);
            let found = resolve_all(resource, path);
            if found.is_empty() {
                return matches!(op, CompareOp::Ne) && !matches!(value, FilterValue::Null);
            }
            found.iter().any(|actual| match actual {
                Value::Array(items) => items
                    .iter()
                    .any(|item| compare_one(item, *op, value, case_exact)),
                other => compare_one(other, *op, value, case_exact),
            })
        }

        Filter::And(left, right) => evaluate(resource, left) && evaluate(resource, right),
        Filter::Or(left, right) => evaluate(resource, left) || evaluate(resource, right),
        Filter::Not(inner) => !evaluate(resource, inner),

        Filter::ValuePath { path, filter } => {
            resolve_all(resource, path)
                .iter()
                .any(|actual| match actual {
                    Value::Array(items) => items.iter().any(|item| evaluate(item, filter)),
                    other => evaluate(other, filter),
                })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    Index { start: usize, count: usize },
    Cursor { after: Option<u64>, count: usize },
}

impl Page {
    #[must_use]
    pub const fn count(&self) -> usize {
        match self {
            Self::Index { count, .. } | Self::Cursor { count, .. } => *count,
        }
    }
}

pub fn paging(
    start_index: Option<&str>,
    count: Option<&str>,
    cursor: Option<&str>,
) -> Result<Page, ScimFault> {
    if cursor.is_some() && start_index.is_some() {
        return Err(ScimFault::InvalidPaging {
            detail: "startIndex and cursor cannot be combined".to_owned(),
        });
    }

    let count = match count {
        None => DEFAULT_PAGE_SIZE,
        Some(raw) => {
            let parsed: i64 = raw.trim().parse().map_err(|_| ScimFault::InvalidCount)?;
            let parsed = usize::try_from(parsed).unwrap_or(0);
            parsed.min(MAX_PAGE_SIZE)
        }
    };

    if let Some(raw) = cursor {
        let after = if raw.is_empty() {
            None
        } else {
            Some(decode_cursor(raw)?)
        };
        return Ok(Page::Cursor { after, count });
    }

    let start = match start_index {
        None => 1,
        Some(raw) => {
            let parsed: i64 = raw.trim().parse().map_err(|_| ScimFault::InvalidPaging {
                detail: "startIndex must be an integer".to_owned(),
            })?;
            if parsed < 1 {
                1
            } else {
                usize::try_from(parsed).unwrap_or(usize::MAX)
            }
        }
    };

    Ok(Page::Index { start, count })
}

#[must_use]
pub fn encode_cursor(after: u64) -> String {
    format!("{after:016x}")
}

pub fn decode_cursor(raw: &str) -> Result<u64, ScimFault> {
    if raw.len() != 16 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ScimFault::InvalidCursor);
    }
    u64::from_str_radix(raw, 16).map_err(|_| ScimFault::InvalidCursor)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sort {
    pub by: String,
    pub descending: bool,
}

pub fn sort(by: Option<&str>, order: Option<&str>) -> Result<Option<Sort>, ScimFault> {
    let Some(by) = by.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };

    let descending = match order.map(str::to_ascii_lowercase).as_deref() {
        None | Some("ascending") => false,
        Some("descending") => true,
        Some(_) => {
            return Err(ScimFault::InvalidValue {
                detail: "sortOrder must be ascending or descending".to_owned(),
            });
        }
    };

    Ok(Some(Sort {
        by: by.to_owned(),
        descending,
    }))
}

#[must_use]
pub fn sort_key(resource: &Value, by: &str) -> String {
    match resolve(resource, by) {
        Some(Value::String(text)) => {
            if attribute_is_case_exact(by) {
                text.clone()
            } else {
                text.to_lowercase()
            }
        }
        Some(Value::Bool(flag)) => (if *flag { "1" } else { "0" }).to_owned(),
        Some(Value::Number(number)) => format!("{number:0>24}"),
        Some(Value::Array(items)) => items
            .iter()
            .find(|item| item.get("primary").and_then(Value::as_bool) == Some(true))
            .or_else(|| items.first())
            .and_then(|item| item.get("value"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_lowercase(),
        _ => String::new(),
    }
}

const READ_ONLY: [&str; 2] = ["id", "meta"];

#[allow(
    clippy::too_many_lines,
    reason = "one schema check per attribute reads better inline"
)]
pub fn validate(body: &Value, kind: ResourceType, is_create: bool) -> Result<Value, ScimFault> {
    let Some(object) = body.as_object() else {
        return Err(ScimFault::NotAnObject);
    };

    let expected = match kind {
        ResourceType::User => USER_SCHEMA,
        ResourceType::Group => GROUP_SCHEMA,
    };

    let declared = object
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or(ScimFault::WrongSchema { expected })?;

    if !declared
        .iter()
        .filter_map(Value::as_str)
        .any(|s| s.eq_ignore_ascii_case(expected))
    {
        return Err(ScimFault::WrongSchema { expected });
    }

    if is_create {
        for attribute in READ_ONLY {
            if object.contains_key(attribute) {
                return Err(ScimFault::Immutable { attribute });
            }
        }
    }

    let mut out = object.clone();
    out.remove("id");
    out.remove("meta");

    match kind {
        ResourceType::User => {
            let user_name = out
                .get("userName")
                .ok_or(ScimFault::Missing {
                    attribute: "userName",
                })?
                .as_str()
                .ok_or_else(|| ScimFault::WrongType {
                    attribute: "userName".to_owned(),
                })?;

            if user_name.trim().is_empty() {
                return Err(ScimFault::InvalidValue {
                    detail: "userName must not be blank".to_owned(),
                });
            }

            match out.get("active") {
                None => {
                    if is_create {
                        out.insert("active".to_owned(), Value::Bool(true));
                    }
                }
                Some(Value::Bool(_)) => {}
                Some(_) => {
                    return Err(ScimFault::WrongType {
                        attribute: "active".to_owned(),
                    });
                }
            }

            if let Some(emails) = out.get("emails")
                && !emails.is_array()
            {
                return Err(ScimFault::WrongType {
                    attribute: "emails".to_owned(),
                });
            }
        }

        ResourceType::Group => {
            let display_name = out
                .get("displayName")
                .ok_or(ScimFault::Missing {
                    attribute: "displayName",
                })?
                .as_str()
                .ok_or_else(|| ScimFault::WrongType {
                    attribute: "displayName".to_owned(),
                })?;

            if display_name.trim().is_empty() {
                return Err(ScimFault::InvalidValue {
                    detail: "displayName must not be blank".to_owned(),
                });
            }

            if let Some(members) = out.get("members") {
                let items = members.as_array().ok_or_else(|| ScimFault::WrongType {
                    attribute: "members".to_owned(),
                })?;
                for member in items {
                    let value = member.get("value").and_then(Value::as_str).ok_or_else(|| {
                        ScimFault::WrongType {
                            attribute: "members.value".to_owned(),
                        }
                    })?;
                    if value.trim().is_empty() {
                        return Err(ScimFault::InvalidValue {
                            detail: "a group member must carry a value".to_owned(),
                        });
                    }
                }
            }
        }
    }

    if let Some(external) = out.get("externalId")
        && !external.is_string()
    {
        return Err(ScimFault::WrongType {
            attribute: "externalId".to_owned(),
        });
    }

    Ok(Value::Object(out))
}

#[must_use]
pub fn member_ids(resource: &Value) -> Vec<String> {
    resource
        .get("members")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("value").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScimRecord {
    pub id: String,
    pub payload: Value,
    pub created_at: crate::time::Timestamp,
    pub last_modified: crate::time::Timestamp,
    pub seq: u64,
}

impl ScimRecord {
    #[must_use]
    pub fn rendered(&self, kind: ResourceType, base: &str) -> Value {
        let mut body = self.payload.clone();
        if let Some(object) = body.as_object_mut() {
            object.insert("id".to_owned(), Value::String(self.id.clone()));
            let schema = match kind {
                ResourceType::User => USER_SCHEMA,
                ResourceType::Group => GROUP_SCHEMA,
            };
            let mut declared: Vec<String> = object
                .get("schemas")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();

            if !declared.iter().any(|s| s.eq_ignore_ascii_case(schema)) {
                declared.insert(0, schema.to_owned());
            }

            let extensions: Vec<String> = object
                .keys()
                .filter(|key| key.starts_with("urn:"))
                .cloned()
                .collect();

            for urn in extensions {
                if !declared.iter().any(|s| s.eq_ignore_ascii_case(&urn)) {
                    declared.push(urn);
                }
            }

            object.insert(
                "schemas".to_owned(),
                Value::Array(declared.into_iter().map(Value::String).collect()),
            );
        }

        let plural = match kind {
            ResourceType::User => "Users",
            ResourceType::Group => "Groups",
        };
        let id = &self.id;

        if let Some(object) = body.as_object_mut() {
            object.insert(
                "meta".to_owned(),
                serde_json::json!({
                    "resourceType": kind.as_str(),
                    "created": crate::time::rfc3339(self.created_at),
                    "lastModified": crate::time::rfc3339(self.last_modified),
                    "location": format!("{base}/scim/v2/{plural}/{id}")
                }),
            );
        }

        body
    }
}
