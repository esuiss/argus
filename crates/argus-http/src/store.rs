//! Depolama sınırı.
//!
//! # Neden trait
//!
//! `argus-core` karar verir, bu katman kararı **uygular**. Uygulama bir depoya
//! ihtiyaç duyar ama hangi depo olduğu `HTTP` katmanını ilgilendirmez: aynı
//! endpoint kodu bellek içi bir depoyla (test) ve `PostgreSQL`'le (üretim) çalışır.
//!
//! # Sır değerleri burada da geçmez
//!
//! Metotlar `async`: gerçek depo ağ üzerinden konuşur ve senkron bir imza,
//! çağıranı ya bloklamaya ya da sonradan her şeyi çevirmeye zorlardı.
//! `argus-core` bundan etkilenmez — orada I/O yok (karar #15).
//!
//! # Neden `async fn` değil, `impl Future + Send`
//!
//! Trait'te `async fn` yazmak dönen future'ın `Send` olduğunu **ifade edemez**.
//! Çok thread'li bir çalışma zamanında (tokio multi-thread) handler'lar
//! thread'ler arasında taşınır; `Send` olmayan bir future orada derlenmez ve
//! hata, trait tanımında değil çok uzaktaki çağrı yerinde patlar. Sınırı burada
//! açıkça yazmak, o hatayı doğduğu yere taşır.
//!
//! Arayüz kodun/token'ın **hash'ini** alır, kendisini değil. Ham değer yalnızca
//! istemciye dönerken bir kez görülür ve hiçbir yerde saklanmaz — §25 K27'nin
//! depolama tarafındaki karşılığı.

use argus_core::authorize::RegisteredClient;
use argus_core::authz_code::StoredCode;
use argus_core::id::ClientId;
use argus_core::id::TenantId;
use argus_core::refresh::{FamilyId, RefreshToken};
use core::future::Future;

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
    fn load(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
    ) -> impl Future<Output = Result<StoredCode, StoreError>> + Send;

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
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

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
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// İstemci kayıt deposu.
pub trait ClientStore {
    /// Kayıtlı istemciyi okur. Bulunamazsa `None` — bu bir hata değil,
    /// yetkilendirme akışında `Fatal(UnknownClient)` sonucunu doğuran normal
    /// bir durumdur.
    fn find(
        &self,
        tenant: TenantId,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<RegisteredClient>, StoreError>> + Send;
}

/// Yeni authorization code yazma sınırı.
pub trait CodeIssuer {
    /// Kodu hash'iyle kaydeder.
    ///
    /// # Errors
    ///
    /// Depo erişilemezse.
    fn issue(
        &self,
        tenant: TenantId,
        code_hash: &[u8; 32],
        code: &StoredCode,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Refresh token deposu.
pub trait RefreshStore {
    /// Token'ın hash'iyle kaydı okur.
    ///
    /// # Errors
    ///
    /// Kayıt yoksa veya depo erişilemezse.
    fn load(
        &self,
        tenant: TenantId,
        token_hash: &[u8; 32],
    ) -> impl Future<Output = Result<RefreshToken, StoreError>> + Send;

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
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

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
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
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
    fn record(
        &self,
        tenant: TenantId,
        event_type: &str,
        at: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}
