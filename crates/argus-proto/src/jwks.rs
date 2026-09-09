use argus_crypto::PublicKeyComponents;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,

    pub crv: String,

    pub x: String,

    pub y: String,

    pub kid: String,

    #[serde(rename = "use")]
    pub key_use: String,

    pub alg: String,
}

impl Jwk {
    #[must_use]
    pub fn from_components(c: &PublicKeyComponents) -> Self {
        Self {
            kty: "EC".to_owned(),
            crv: c.curve().to_owned(),
            x: Base64UrlUnpadded::encode_string(&c.x),
            y: Base64UrlUnpadded::encode_string(&c.y),
            kid: c.kid.clone(),
            key_use: "sig".to_owned(),
            alg: c.algorithm().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    #[must_use]
    pub const fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Jwk, JwkSet};
    use argus_crypto::SigningKey;

    #[test]
    fn jwk_carries_no_private_component() {
        let (key, _) = SigningKey::generate("k1").expect("key generation");
        let jwk = Jwk::from_components(&key.public_components().expect("components"));
        let json = serde_json::to_string(&jwk).unwrap();

        assert!(!json.contains("\"d\""), "private component leaked: {json}");
        assert!(json.contains("\"kty\":\"EC\""));
        assert!(json.contains("\"crv\":\"P-256\""));
        assert!(json.contains("\"alg\":\"ES256\""));
        assert!(json.contains("\"use\":\"sig\""));
    }

    #[test]
    fn jwk_round_trips_through_json() {
        let (key, _) = SigningKey::generate("k1").expect("key generation");
        let jwk = Jwk::from_components(&key.public_components().expect("components"));
        let back: Jwk = serde_json::from_str(&serde_json::to_string(&jwk).unwrap()).unwrap();
        assert_eq!(jwk, back);
    }

    #[test]
    fn jwk_set_can_publish_old_and_new_together() {
        let (old, _) = SigningKey::generate("old").expect("key generation");
        let (new, _) = SigningKey::generate("new").expect("key generation");

        let set = JwkSet::new(vec![
            Jwk::from_components(&old.public_components().expect("components")),
            Jwk::from_components(&new.public_components().expect("components")),
        ]);

        assert_eq!(set.keys.len(), 2);
        let kids: Vec<&str> = set.keys.iter().map(|k| k.kid.as_str()).collect();
        assert_eq!(kids, ["old", "new"]);
    }
}
