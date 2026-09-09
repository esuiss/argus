//! Discovery ve JWKS endpoint'leri.
//!
//! Üç yol da aynı gövdeyi döner. §18: iki spec aynı issuer için farklı
//! well-known URL üretiyor ve istemcilerin hangisini deneyeceği belirsiz;
//! ikisini birden servis etmek maliyetsiz ve interop kırılmasını önlüyor.

use argus_proto::{AuthorizationServerMetadata, Jwk, JwkSet};

use crate::state::TenantContext;

/// Kiracının AS metadata'sı.
#[must_use]
pub fn metadata(tenant: &TenantContext) -> AuthorizationServerMetadata {
    tenant.metadata.clone()
}

/// Kiracının yayınlanan anahtar seti.
///
/// **Yayınlanan tüm anahtarlar** döner, yalnızca aktif olan değil: rotasyon
/// sırasında eski anahtarla imzalanmış token'lar hâlâ dolaşımdadır ve RP
/// cache'leri hemen tazelenmez.
///
/// # Errors
///
/// Bir anahtarın açık bileşenleri çıkarılamazsa.
pub fn jwks(tenant: &TenantContext) -> Result<JwkSet, argus_crypto::CryptoError> {
    let mut keys = Vec::with_capacity(tenant.published_keys.len());
    for key in &tenant.published_keys {
        keys.push(Jwk::from_components(&key.public_components()?));
    }
    Ok(JwkSet::new(keys))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{jwks, metadata};
    use crate::state::TenantContext;
    use argus_crypto::SigningKey;
    use argus_proto::AuthorizationServerMetadata;
    use std::sync::Arc;

    fn ctx() -> TenantContext {
        let (old, _) = SigningKey::generate("old").expect("key");
        let (new, _) = SigningKey::generate("new").expect("key");
        let new = Arc::new(new);
        TenantContext {
            metadata: AuthorizationServerMetadata::for_issuer("https://acme.argus.test"),
            active_key: Arc::clone(&new),
            published_keys: vec![Arc::new(old), new],
        }
    }

    #[test]
    fn metadata_issuer_matches_the_endpoints() {
        let m = metadata(&ctx());
        assert_eq!(m.issuer, "https://acme.argus.test");
        assert!(m.token_endpoint.starts_with(&m.issuer));
        assert!(m.jwks_uri.starts_with(&m.issuer));
    }

    /// Rotasyon penceresinde eski anahtar da yayınlanmalı, yoksa dolaşımdaki
    /// token'lar doğrulanamaz ve "0 adet 401" kriteri ihlal edilir.
    #[test]
    fn jwks_publishes_every_key_not_just_the_active_one() {
        let set = jwks(&ctx()).expect("jwks");
        let kids: Vec<&str> = set.keys.iter().map(|k| k.kid.as_str()).collect();
        assert_eq!(kids, ["old", "new"]);
    }

    #[test]
    fn jwks_never_contains_private_material() {
        let json = serde_json::to_string(&jwks(&ctx()).expect("jwks")).unwrap();
        assert!(!json.contains("\"d\""), "private component leaked: {json}");
    }
}
