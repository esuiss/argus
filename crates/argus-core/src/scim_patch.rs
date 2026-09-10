use argus_parse::scim_filter::{CompareOp, Filter, Value as FilterValue};
use argus_parse::scim_path::{self, Path};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Add,
    Remove,
    Replace,
}

impl Op {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "add" => Some(Self::Add),
            "remove" => Some(Self::Remove),
            "replace" => Some(Self::Replace),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub op: Op,
    pub path: Option<String>,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatchError {
    #[error("noTarget")]
    NoTarget,

    #[error("invalidPath")]
    InvalidPath,

    #[error("invalidValue")]
    InvalidValue,

    #[error("mutability")]
    Mutability,

    #[error("invalidSyntax")]
    InvalidSyntax,
}

impl PatchError {
    #[must_use]
    pub const fn scim_type(self) -> &'static str {
        match self {
            Self::NoTarget => "noTarget",
            Self::InvalidPath => "invalidPath",
            Self::InvalidValue => "invalidValue",
            Self::Mutability => "mutability",
            Self::InvalidSyntax => "invalidSyntax",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatchOutcome {
    pub resource: Value,
    pub changed: bool,
}

pub fn apply(resource: &Value, operations: &[Operation]) -> Result<PatchOutcome, PatchError> {
    if operations.is_empty() {
        return Err(PatchError::InvalidSyntax);
    }

    let mut working = resource.clone();
    let mut changed = false;

    for operation in operations {
        changed |= apply_one(&mut working, operation)?;
    }

    Ok(PatchOutcome {
        resource: working,
        changed,
    })
}

pub const KNOWN_SCHEMAS: [&str; 3] = [
    crate::scim::USER_SCHEMA,
    crate::scim::GROUP_SCHEMA,
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
];

// RFC 7644 §3.5.2: bir patch yolu URN nitelikli olabilir. Çekirdek şema URN'ü
// KAYNAĞIN KENDİSİNİ adresler; uzantı URN'leri ise iç içe geçer. İkisini aynı
// şekilde ele almak uzantı alanlarını üst seviyeye taşırdı.
fn split_schema(raw: &str) -> Option<(&'static str, &str)> {
    if !raw.starts_with("urn:") {
        return None;
    }

    for schema in KNOWN_SCHEMAS {
        if raw.len() == schema.len() && raw.eq_ignore_ascii_case(schema) {
            return Some((schema, ""));
        }

        let Some(rest) = raw.get(..schema.len()) else {
            continue;
        };

        if rest.eq_ignore_ascii_case(schema) && raw.as_bytes().get(schema.len()) == Some(&b':') {
            return Some((schema, raw.get(schema.len() + 1..).unwrap_or_default()));
        }
    }

    None
}

fn extension_slot<'a>(resource: &'a mut Value, schema: &str) -> Result<&'a mut Value, PatchError> {
    let target = object_mut(resource)?;
    Ok(target
        .entry(schema.to_owned())
        .or_insert_with(|| Value::Object(Map::new())))
}

fn apply_one(resource: &mut Value, operation: &Operation) -> Result<bool, PatchError> {
    if let Some(raw) = operation.path.as_deref()
        && let Some((schema, rest)) = split_schema(raw)
    {
        let core = schema == crate::scim::USER_SCHEMA || schema == crate::scim::GROUP_SCHEMA;

        if core {
            if rest.is_empty() {
                return Err(PatchError::InvalidPath);
            }
            let inner = Operation {
                op: operation.op,
                path: Some(rest.to_owned()),
                value: operation.value.clone(),
            };
            return apply_one(resource, &inner);
        }

        if rest.is_empty() {
            let changed = whole_extension(resource, schema, operation)?;
            if changed && operation.op != Op::Remove {
                declare(resource, schema);
            }
            return Ok(changed);
        }

        let inner = Operation {
            op: operation.op,
            path: Some(rest.to_owned()),
            value: operation.value.clone(),
        };

        let slot = extension_slot(resource, schema)?;
        let changed = apply_one(slot, &inner)?;

        let emptied = resource
            .as_object()
            .and_then(|object| object.get(schema))
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty);

        if emptied {
            if let Some(object) = resource.as_object_mut() {
                object.remove(schema);
            }
            undeclare(resource, schema);
        } else if changed {
            declare(resource, schema);
        }

        return Ok(changed);
    }

    match operation.op {
        Op::Remove => {
            let raw = operation.path.as_deref().ok_or(PatchError::NoTarget)?;
            let path = scim_path::parse(raw).map_err(|_| PatchError::InvalidPath)?;
            remove(resource, &path)
        }
        Op::Add => {
            let value = operation.value.clone().ok_or(PatchError::InvalidValue)?;
            match operation.path.as_deref() {
                None => merge_root(resource, &value),
                Some(raw) => {
                    let path = scim_path::parse(raw).map_err(|_| PatchError::InvalidPath)?;
                    add(resource, &path, &value)
                }
            }
        }
        Op::Replace => {
            let value = operation.value.clone().ok_or(PatchError::InvalidValue)?;
            match operation.path.as_deref() {
                None => merge_root(resource, &value),
                Some(raw) => {
                    let path = scim_path::parse(raw).map_err(|_| PatchError::InvalidPath)?;
                    replace(resource, &path, &value)
                }
            }
        }
    }
}

fn declare(resource: &mut Value, schema: &str) {
    let Some(object) = resource.as_object_mut() else {
        return;
    };

    let entry = object
        .entry("schemas".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));

    let Some(list) = entry.as_array_mut() else {
        return;
    };

    if !list.iter().any(|value| value == schema) {
        list.push(Value::String(schema.to_owned()));
    }
}

fn undeclare(resource: &mut Value, schema: &str) {
    if let Some(object) = resource.as_object_mut()
        && let Some(list) = object.get_mut("schemas").and_then(Value::as_array_mut)
    {
        list.retain(|value| value != schema);
    }
}

fn whole_extension(
    resource: &mut Value,
    schema: &str,
    operation: &Operation,
) -> Result<bool, PatchError> {
    let target = object_mut(resource)?;

    match operation.op {
        Op::Remove => Ok(target.remove(schema).is_some()),
        Op::Add | Op::Replace => {
            let value = operation.value.clone().ok_or(PatchError::InvalidValue)?;
            if !value.is_object() {
                return Err(PatchError::InvalidValue);
            }
            if target.get(schema) == Some(&value) {
                return Ok(false);
            }
            target.insert(schema.to_owned(), value);
            Ok(true)
        }
    }
}

fn object_mut(resource: &mut Value) -> Result<&mut Map<String, Value>, PatchError> {
    resource.as_object_mut().ok_or(PatchError::InvalidValue)
}

fn merge_root(resource: &mut Value, value: &Value) -> Result<bool, PatchError> {
    let incoming = value.as_object().ok_or(PatchError::InvalidValue)?.clone();
    let target = object_mut(resource)?;

    let mut changed = false;
    for (key, new) in incoming {
        if target.get(&key) == Some(&new) {
            continue;
        }
        target.insert(key.clone(), new);
        changed = true;
        note_extension_schema(target, &key);
    }
    Ok(changed)
}

fn note_extension_schema(target: &mut Map<String, Value>, attribute: &str) {
    let Some(separator) = attribute.rfind(':') else {
        return;
    };
    let Some(urn) = attribute.get(..separator) else {
        return;
    };
    if !urn.starts_with("urn:") {
        return;
    }

    let Some(Value::Array(schemas)) = target.get_mut("schemas") else {
        return;
    };
    if schemas.iter().any(|s| s.as_str() == Some(urn)) {
        return;
    }
    schemas.push(Value::String(urn.to_owned()));
}

fn add(resource: &mut Value, path: &Path, value: &Value) -> Result<bool, PatchError> {
    if let Some(filter) = path.value_filter.as_ref() {
        return add_into_filtered(resource, path, filter, value);
    }

    let Some(sub) = path.sub_attribute.as_deref() else {
        return add_plain(resource, &path.attribute, value);
    };

    let target = object_mut(resource)?;
    let entry = target
        .entry(path.attribute.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    let complex = entry.as_object_mut().ok_or(PatchError::InvalidValue)?;

    if complex.get(sub) == Some(value) {
        return Ok(false);
    }
    complex.insert(sub.to_owned(), value.clone());
    Ok(true)
}

fn add_plain(resource: &mut Value, attribute: &str, value: &Value) -> Result<bool, PatchError> {
    let target = object_mut(resource)?;

    match target.get_mut(attribute) {
        Some(Value::Array(existing)) => {
            let incoming = match value {
                Value::Array(items) => items.clone(),
                single => vec![single.clone()],
            };
            let mut changed = false;
            for item in incoming {
                if existing.contains(&item) {
                    continue;
                }
                existing.push(item);
                changed = true;
            }
            if changed {
                normalise_primary(existing, None);
            }
            Ok(changed)
        }
        Some(current) => {
            if current == value {
                return Ok(false);
            }
            *current = value.clone();
            Ok(true)
        }
        None => {
            target.insert(attribute.to_owned(), value.clone());
            if let Some(Value::Array(items)) = target.get_mut(attribute) {
                normalise_primary(items, None);
            }
            note_extension_schema(target, attribute);
            Ok(true)
        }
    }
}

fn add_into_filtered(
    resource: &mut Value,
    path: &Path,
    filter: &Filter,
    value: &Value,
) -> Result<bool, PatchError> {
    let target = object_mut(resource)?;

    let entry = target
        .entry(path.attribute.clone())
        .or_insert_with(|| Value::Array(Vec::new()));
    let items = entry.as_array_mut().ok_or(PatchError::InvalidValue)?;

    let mut changed = false;
    let mut matched = None;

    for (index, item) in items.iter_mut().enumerate() {
        if !matches(item, filter) {
            continue;
        }
        matched = Some(index);
        changed |= write_into(item, path.sub_attribute.as_deref(), value)?;
    }

    if matched.is_none() {
        let mut seeded = Map::new();
        seed_from_filter(&mut seeded, filter);
        let mut fresh = Value::Object(seeded);
        write_into(&mut fresh, path.sub_attribute.as_deref(), value)?;
        items.push(fresh);
        matched = Some(items.len().saturating_sub(1));
        changed = true;
    }

    if changed {
        normalise_primary(items, matched);
    }
    Ok(changed)
}

fn write_into(
    item: &mut Value,
    sub_attribute: Option<&str>,
    value: &Value,
) -> Result<bool, PatchError> {
    if let Some(name) = sub_attribute {
        let object = item.as_object_mut().ok_or(PatchError::InvalidValue)?;
        if object.get(name) == Some(value) {
            return Ok(false);
        }
        object.insert(name.to_owned(), value.clone());
        return Ok(true);
    }

    let incoming = value.as_object().ok_or(PatchError::InvalidValue)?.clone();
    let object = item.as_object_mut().ok_or(PatchError::InvalidValue)?;
    let mut changed = false;
    for (key, new) in incoming {
        if object.get(&key) == Some(&new) {
            continue;
        }
        object.insert(key, new);
        changed = true;
    }
    Ok(changed)
}

fn seed_from_filter(target: &mut Map<String, Value>, filter: &Filter) {
    match filter {
        Filter::Compare {
            path,
            op: CompareOp::Eq,
            value,
        } => {
            let seeded = match value {
                FilterValue::Str(v) => Value::String(v.clone()),
                FilterValue::Bool(v) => Value::Bool(*v),
                FilterValue::Number(v) => {
                    serde_json::Number::from_f64(*v).map_or(Value::Null, Value::Number)
                }
                FilterValue::Null => Value::Null,
            };
            target.insert(path.clone(), seeded);
        }
        Filter::And(left, right) => {
            seed_from_filter(target, left);
            seed_from_filter(target, right);
        }
        _ => {}
    }
}

fn replace(resource: &mut Value, path: &Path, value: &Value) -> Result<bool, PatchError> {
    if let Some(filter) = path.value_filter.as_ref() {
        let Some(Value::Array(items)) = object_mut(resource)?.get_mut(&path.attribute) else {
            return Err(PatchError::NoTarget);
        };

        let mut changed = false;
        let mut matched = None;
        for (index, item) in items.iter_mut().enumerate() {
            if !matches(item, filter) {
                continue;
            }
            matched = Some(index);
            changed |= write_into(item, path.sub_attribute.as_deref(), value)?;
        }

        if matched.is_none() {
            return Err(PatchError::NoTarget);
        }
        if changed {
            normalise_primary(items, matched);
        }
        return Ok(changed);
    }

    if path.sub_attribute.is_none() && !object_mut(resource)?.contains_key(&path.attribute) {
        return add(resource, path, value);
    }

    let Some(sub) = path.sub_attribute.as_deref() else {
        let target = object_mut(resource)?;
        if target.get(&path.attribute) == Some(value) {
            return Ok(false);
        }
        target.insert(path.attribute.clone(), value.clone());
        if let Some(Value::Array(items)) = target.get_mut(&path.attribute) {
            normalise_primary(items, None);
        }
        return Ok(true);
    };

    let target = object_mut(resource)?;
    let entry = target
        .entry(path.attribute.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    let complex = entry.as_object_mut().ok_or(PatchError::InvalidValue)?;

    if complex.get(sub) == Some(value) {
        return Ok(false);
    }
    complex.insert(sub.to_owned(), value.clone());
    Ok(true)
}

fn remove(resource: &mut Value, path: &Path) -> Result<bool, PatchError> {
    if let Some(filter) = path.value_filter.as_ref() {
        let Some(Value::Array(items)) = object_mut(resource)?.get_mut(&path.attribute) else {
            return Ok(false);
        };

        let before = items.len();

        match path.sub_attribute.as_deref() {
            Some(name) => {
                let mut changed = false;
                for item in items.iter_mut() {
                    if !matches(item, filter) {
                        continue;
                    }
                    if let Some(object) = item.as_object_mut()
                        && object.remove(name).is_some()
                    {
                        changed = true;
                    }
                }
                return Ok(changed);
            }
            None => items.retain(|item| !matches(item, filter)),
        }

        let changed = items.len() != before;
        if items.is_empty() {
            object_mut(resource)?.remove(&path.attribute);
        }
        return Ok(changed);
    }

    let target = object_mut(resource)?;

    let Some(sub) = path.sub_attribute.as_deref() else {
        return Ok(target.remove(&path.attribute).is_some());
    };

    let Some(entry) = target.get_mut(&path.attribute) else {
        return Ok(false);
    };
    let complex = entry.as_object_mut().ok_or(PatchError::InvalidValue)?;
    Ok(complex.remove(sub).is_some())
}

fn normalise_primary(items: &mut [Value], just_set: Option<usize>) {
    let primary = just_set.filter(|index| {
        items
            .get(*index)
            .and_then(|item| item.get("primary"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });

    let primary = primary.or_else(|| {
        items.iter().position(|item| {
            item.get("primary")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
    });

    let Some(primary) = primary else {
        return;
    };

    for (index, item) in items.iter_mut().enumerate() {
        if index == primary {
            continue;
        }
        if let Some(object) = item.as_object_mut()
            && object.get("primary").and_then(Value::as_bool) == Some(true)
        {
            object.insert("primary".to_owned(), Value::Bool(false));
        }
    }
}

fn matches(item: &Value, filter: &Filter) -> bool {
    match filter {
        Filter::Present { path } => item.get(path).is_some_and(|v| !v.is_null()),
        Filter::Compare { path, op, value } => item
            .get(path)
            .is_some_and(|actual| compare(actual, *op == CompareOp::Eq, *op, value)),
        Filter::And(a, b) => matches(item, a) && matches(item, b),
        Filter::Or(a, b) => matches(item, a) || matches(item, b),
        Filter::Not(inner) => !matches(item, inner),
        Filter::ValuePath { .. } => false,
    }
}

fn compare(actual: &Value, _is_eq: bool, op: CompareOp, expected: &FilterValue) -> bool {
    let (Some(left), FilterValue::Str(right)) = (actual.as_str(), expected) else {
        return match (actual, expected) {
            (Value::Bool(a), FilterValue::Bool(b)) => match op {
                CompareOp::Eq => a == b,
                CompareOp::Ne => a != b,
                _ => false,
            },
            (Value::Number(a), FilterValue::Number(b)) => {
                let a = a.as_f64().unwrap_or(f64::NAN);
                match op {
                    CompareOp::Eq => (a - b).abs() < f64::EPSILON,
                    CompareOp::Ne => (a - b).abs() >= f64::EPSILON,
                    CompareOp::Gt => a > *b,
                    CompareOp::Lt => a < *b,
                    CompareOp::Ge => a >= *b,
                    CompareOp::Le => a <= *b,
                    _ => false,
                }
            }
            _ => false,
        };
    };

    let a = left.to_lowercase();
    let b = right.to_lowercase();

    match op {
        CompareOp::Eq => a == b,
        CompareOp::Ne => a != b,
        CompareOp::Co => a.contains(&b),
        CompareOp::Sw => a.starts_with(&b),
        CompareOp::Ew => a.ends_with(&b),
        CompareOp::Gt => a > b,
        CompareOp::Lt => a < b,
        CompareOp::Ge => a >= b,
        CompareOp::Le => a <= b,
    }
}
