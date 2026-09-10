use serde_json::{Map, Value};

pub const MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MergePatchError {
    #[error("the patch nests deeper than the {allowed} levels this server accepts")]
    TooDeep { allowed: u32 },

    #[error("field {field} cannot be changed once the resource exists")]
    Immutable { field: String },

    #[error("field {field} is not part of this resource")]
    Unknown { field: String },
}

pub fn apply(target: &Value, patch: &Value) -> Result<Value, MergePatchError> {
    apply_at(target, patch, 0)
}

fn apply_at(target: &Value, patch: &Value, depth: u32) -> Result<Value, MergePatchError> {
    if depth > MAX_DEPTH {
        return Err(MergePatchError::TooDeep { allowed: MAX_DEPTH });
    }

    let Some(members) = patch.as_object() else {
        return Ok(patch.clone());
    };

    let mut out: Map<String, Value> = target.as_object().cloned().unwrap_or_else(Map::new);

    for (name, value) in members {
        if value.is_null() {
            out.remove(name);
            continue;
        }

        let merged = match out.get(name) {
            Some(existing) => apply_at(existing, value, depth + 1)?,
            None => apply_at(&Value::Null, value, depth + 1)?,
        };
        out.insert(name.clone(), merged);
    }

    Ok(Value::Object(out))
}

#[must_use]
pub fn touched(patch: &Value) -> Vec<String> {
    patch
        .as_object()
        .map(|members| members.keys().cloned().collect())
        .unwrap_or_default()
}

pub fn check_patch(
    patch: &Value,
    known: &[&str],
    immutable: &[&str],
) -> Result<(), MergePatchError> {
    for field in touched(patch) {
        if immutable.contains(&field.as_str()) {
            return Err(MergePatchError::Immutable { field });
        }
        if !known.contains(&field.as_str()) {
            return Err(MergePatchError::Unknown { field });
        }
    }
    Ok(())
}
