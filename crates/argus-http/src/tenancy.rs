use std::collections::BTreeMap;
use std::sync::Arc;

use argus_core::id::TenantId;
use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use serde_json::json;

use crate::state::TenantContext;

// §18 ve §1 #8: issuer stratejisi subdomain birincil. Bir isteğin hangi kiracıya
// ait olduğu Host başlığından çözülür; şema baştan beri çok kiracılıydı ama
// çalışma zamanı tek bir kiracıya sabitlenmişti.
//
// Çözümleme FAIL-CLOSED: tanınmayan bir host 404 alır. Bilinen bir kiracıya
// düşmek, A kiracısının verisini B'nin host'unda sunmak demektir ve bu tam olarak
// §18'in kapatmak istediği sınıftır.
pub struct TenantEntry {
    pub id: TenantId,
    pub issuer: String,
    pub context: TenantContext,
}

#[derive(Clone)]
pub struct Tenant(Arc<TenantEntry>);

impl core::fmt::Debug for Tenant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tenant")
            .field("issuer", &self.0.issuer)
            .finish_non_exhaustive()
    }
}

impl Tenant {
    #[must_use]
    pub fn id(&self) -> TenantId {
        self.0.id
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }

    #[must_use]
    pub fn context(&self) -> &TenantContext {
        &self.0.context
    }
}

impl core::ops::Deref for Tenant {
    type Target = TenantContext;

    fn deref(&self) -> &Self::Target {
        &self.0.context
    }
}

#[derive(Default)]
pub struct TenantRegistry {
    by_host: BTreeMap<String, Arc<TenantEntry>>,
}

// Bir host adı büyük/küçük harf duyarsızdır ve port taşıyabilir; ikisi de
// normalize edilmezse aynı kiracı iki farklı anahtar altında görünür.
fn normalise(host: &str) -> String {
    let host = host.split(':').next().unwrap_or(host);
    host.trim().to_ascii_lowercase()
}

impl TenantRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, host: &str, entry: TenantEntry) {
        self.by_host.insert(normalise(host), Arc::new(entry));
    }

    // Tek kiracılı bir dağıtım ya da test için tek girişli defter.
    #[must_use]
    pub fn single(host: &str, entry: TenantEntry) -> Self {
        let mut registry = Self::new();
        registry.register(host, entry);
        registry
    }

    #[must_use]
    pub fn resolve(&self, host: &str) -> Option<Tenant> {
        self.by_host
            .get(&normalise(host))
            .map(|e| Tenant(Arc::clone(e)))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_host.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }

    #[must_use]
    pub fn hosts(&self) -> Vec<&str> {
        self.by_host.keys().map(String::as_str).collect()
    }

    // Tek kiracılı bir dağıtımda Host başlığı olmayan bir istek hâlâ hizmet
    // görmeli; birden fazla kiracı varsa başlık ZORUNLUDUR, yoksa hangi
    // kiracının kastedildiği bilinemez.
    #[must_use]
    pub fn only(&self) -> Option<Tenant> {
        if self.by_host.len() == 1 {
            self.by_host.values().next().map(|e| Tenant(Arc::clone(e)))
        } else {
            None
        }
    }
}

#[must_use]
pub fn host_of(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

// §9.5 #2: Host başlığına güvenilerek URL üretilmez. Burada başlık yalnızca bir
// ARAMA ANAHTARIDIR; bulunan kiracının issuer'ı kayıttan gelir, istekten değil.
// Keycloak'ın HOST header reflected XSS'i ve issuer manipülasyonu tam olarak
// bu ayrımın yokluğundan doğdu.
pub fn resolve(registry: &TenantRegistry, headers: &HeaderMap) -> Result<Tenant, Box<Response>> {
    if let Some(host) = host_of(headers)
        && let Some(tenant) = registry.resolve(host)
    {
        return Ok(tenant);
    }

    if let Some(only) = registry.only() {
        return Ok(only);
    }

    Err(Box::new(
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown_issuer" })),
        )
            .into_response(),
    ))
}
