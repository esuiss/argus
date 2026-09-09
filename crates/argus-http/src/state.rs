//! Sunucu durumu.

use std::sync::Arc;

use argus_crypto::SigningKey;
use argus_proto::AuthorizationServerMetadata;

use crate::store::{AuditSink, CodeStore, RefreshStore};

/// Bir kiracının çalışma zamanı bağlamı.
///
/// # Kiracı burada çözülmüş olmalı
///
/// §18 ve CVE-2026-41166: kiracı kimliği **host'tan** çözülür, istek gövdesinden
/// veya doğrulanmamış bir yol parçasından değil. Bu tip zaten çözülmüş bağlamı
/// taşır; ona ulaşan kod yolunun kiracıyı yeniden tahmin etmesi gerekmez.
pub struct TenantContext {
    /// Bu kiracının issuer'ı — token `iss` claim'iyle birebir aynı.
    pub metadata: AuthorizationServerMetadata,
    /// Aktif imzalama anahtarı.
    pub active_key: Arc<SigningKey>,
    /// Yayınlanan tüm anahtarlar.
    ///
    /// Rotasyon sırasında eski ve yeni birlikte durur: eskisini erken düşürmek
    /// §1 §9'un "anahtar rotasyonunda 0 adet 401" çıkış kriterini ihlal eder.
    pub published_keys: Vec<Arc<SigningKey>>,
}

/// Uygulama durumu.
pub struct AppState<C, R, A, S = (), U = ()>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    /// Şimdilik tek kiracı; çok kiracılık host çözümlemesiyle gelecek.
    pub tenant: TenantContext,
    /// Authorization code deposu.
    pub codes: C,
    /// Refresh token deposu.
    pub refresh: R,
    /// Denetim kaydı.
    pub audit: A,
    /// Çözülmüş kiracı kimliği.
    pub tenant_id: argus_core::id::TenantId,
    /// İstemci kaydı deposu.
    pub clients: S,
    /// Kullanıcı kimlik doğrulayıcı.
    ///
    /// ⚠️ Faz 1'de geliştirme amaçlı; Faz 3 gerçeğini getirecek.
    pub authenticator: U,
}

impl<C, R, A, S, U> AppState<C, R, A, S, U>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    /// Çözülmüş kiracı kimliği.
    #[must_use]
    pub const fn tenant_id(&self) -> argus_core::id::TenantId {
        self.tenant_id
    }
}
