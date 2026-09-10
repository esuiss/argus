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

// RFC 7396. §24 #2 merge patch'i Keycloak'ın büyüttüğü gelişigüzel verb
// semantiğine tercih etti (stianst'in kendi itirafı: "POST sometimes work as
// a PUT, and sometimes as a PATCH"). Ayrıca explicit null sorusunu da çözer:
// patch'teki null üyeyi kaldırır, böylece "set edilmedi" ile "null'a set
// edildi" aynı tel biçimi olmaktan çıkar.
pub fn apply(target: &Value, patch: &Value) -> Result<Value, MergePatchError> {
    apply_at(target, patch, 0)
}

fn apply_at(target: &Value, patch: &Value, depth: u32) -> Result<Value, MergePatchError> {
    if depth > MAX_DEPTH {
        return Err(MergePatchError::TooDeep { allowed: MAX_DEPTH });
    }

    // Nesne olmayan bir patch hedefi tamamen değiştirir, diziler dahil.
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
// Patch'in dokunduğu alanlar, yalnızca üst seviye. Çağıran bunları kaynağın
// izin verdikleriyle karşılaştırır ve reddedilen bir patch hiçbir şeyi
// değiştirmemiş olur.
pub fn touched(patch: &Value) -> Vec<String> {
    patch
        .as_object()
        .map(|members| members.keys().cloned().collect())
        .unwrap_or_default()
}

// §24 #12: owner alanı yaratılışta sabitlenir. authentik CVE-2024-37905, user
// kimliği patch'lenebilen bir API token'ıydı; kimliği doğrulanmış her
// kullanıcı superuser olmaya tek istek uzaktaydı.
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
