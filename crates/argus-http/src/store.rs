//! Depolama sınırı.
//!
//! # Neden trait
//!
//! `argus-core` karar verir, bu katman kararı **uygular**. Uygulama bir depoya
//! ihtiyaç duyar ama hangi depo olduğu HTTP katmanını ilgilendirmez: aynı
//! endpoint kodu bellek içi bir depoyla (test) ve PostgreSQL'le (üretim) çalışır.
//!
//! # Sır değerleri burada da geçmez
//!
//! Arayüz kodun/token'ın **hash'ini** alır, kendisini değil. Ham değer yalnızca
//! istemciye dönerken bir kez görülür ve hiçbir yerde saklanmaz — §25 K27'nin
//! depolama tarafındaki karşılığı.

use argus_core::authz_code::StoredCode;
use argus_core::id::TenantId;
use argus_core::refresh::{FamilyId, RefreshToken};
use argus_core::time::Timestamp;

/// Depo hataları.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// Kayıt bulunamadı.
    #[error("record not found")]
    NotFound,
    /// Alt sistem hatası.
    ///
    /// ⚠️ §19 §7.1: bu, istemciye `invalid_grant` olarak DÖNMEZ. Geçici bir
    /// arızayı kalıcı bir çıkışa çevirmek yerine `503` + `Retry-After` dönülür.
    #[error("storage backend unavailable")]
    Unavailable,
}

/// Authorization code deposu.
pub trait CodeStore {
    /// Kodun hash'iyle kaydı okur.
    ///
    /// # Errors
    ///
    /// Kayıt yoksa veya depo erişilemezse.
    fn load(&self, tenant: TenantId, code_hash: &[u8; 32]) -> Result<StoredCode, StoreError>;

    /// Kodu tüketilmiş işaretler.
    ///
    /// # Errors
    ///
    /// Depo erişilemezse.
    fn consume(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError>;

    /// Bu koddan türeyen tüm token'ları iptal eder (RFC 9700 §4.1.1).
    ///
    /// # Errors
    ///
    /// Depo erişilemezse.
    fn revoke_tokens_issued_for_code(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        at: Timestamp,
    ) -> Result<(), StoreError>;
}

/// Refresh token deposu.
pub trait RefreshStore {
    /// Token'ın hash'iyle kaydı okur.
    ///
    /// # Errors
    ///
    /// Kayıt yoksa veya depo erişilemezse.
    fn load(&self, tenant: TenantId, token_hash: &[u8; 32]) -> Result<RefreshToken, StoreError>;

    /// Eskisini döndürülmüş işaretler, yenisini yazar.
    ///
    /// # Errors
    ///
    /// Depo erişilemezse.
    fn rotate(
        &self,
        tenant: TenantId,
        old_hash: &[u8; 32],
        new_hash: &[u8; 32],
        new_token: &RefreshToken,
        at: Timestamp,
    ) -> Result<(), StoreError>;

    /// Zincirin tamamını iptal eder (RFC 9700 §4.14.2).
    ///
    /// # Errors
    ///
    /// Depo erişilemezse.
    fn revoke_family(
        &self,
        tenant: TenantId,
        family: FamilyId,
        at: Timestamp,
    ) -> Result<(), StoreError>;
}

/// Denetim kaydı sınırı.
///
/// §1 #23: olay iş değişikliğiyle **aynı transaction'da** kalıcılaşır. Bu arayüz
/// o transaction'ın içinden çağrılmak üzere tasarlandı; ayrı bir kuyruğa yazan
/// bir uygulama kararı ihlal eder.
pub trait AuditSink {
    /// Denetim olayı kaydeder.
    ///
    /// # Errors
    ///
    /// Depo erişilemezse. **Bu hata yutulmaz:** kaydedilemeyen bir olay,
    /// isteğin başarısız olması demektir (AU-12/PCI 10.2 "all").
    fn record(&self, tenant: TenantId, event_type: &str, at: Timestamp) -> Result<(), StoreError>;
}
