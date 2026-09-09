//! Karar fonksiyonlarının çağırandan istediği yan etkiler.
//!
//! `argus-core` hiçbir şey yapmaz; ne **yapılması gerektiğini** söyler
//! ([ARGUS.md §3]: *"I/O çağıran değil, I/O isteyen bir tasarım"*).
//!
//! # Neden tek bir enum
//!
//! Authorization code ve refresh token akışları farklı kurallara sahip ama aynı
//! uygulayıcıya konuşur: `argus-http`'nin token endpoint'i. Etkiler tek tipte
//! toplanınca o uygulayıcı **tek bir `match`** yazar ve derleyici, yeni bir etki
//! eklendiğinde onu ele almayı unutmasına izin vermez.
//!
//! # Sözleşme
//!
//! Çağıran listeyi **sırayla ve tamamen** uygulamak zorundadır. Bir etkinin
//! atlanması sessiz bir güvenlik açığıdır: [`Effect::RevokeRefreshFamily`]
//! uygulanmazsa çalınmış bir refresh token zincirinin tamamı canlı kalır.

/// Kararın gerektirdiği tek bir işlem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Authorization code'u tüketilmiş işaretle.
    ConsumeCode,

    /// Bu koddan türeyen tüm token'ları iptal et.
    ///
    /// RFC 9700 §4.1.1: kod ikinci kez sunulduğunda, onun iki tarafça bilindiği
    /// kesindir; daha önce verilmiş token'lar artık güvenilmez.
    RevokeTokensIssuedForCode,

    /// Sunulan refresh token'ı döndür: eskisini kapat, yenisini ver.
    RotateRefreshToken,

    /// **Refresh zincirinin tamamını iptal et.**
    ///
    /// RFC 9700 §4.14.2: döndürülmüş bir refresh token ikinci kez sunulduğunda
    /// sunucu, meşru istemci ile saldırgandan hangisinin konuştuğunu **ayırt
    /// edemez**. Tek güvenli davranış zincirin tamamını düşürmektir; meşru
    /// istemci yeniden yetkilendirme yapar.
    RevokeRefreshFamily,

    /// Denetim olayı üret.
    ///
    /// Tip dizgesi §25 K29 taksonomisine göredir (`<parent>.<sublevel>.<action>`)
    /// ve `&'static str`'dir: olay adları derleme zamanında sabittir, çalışma
    /// zamanında kullanıcı girdisinden üretilemez.
    RecordAudit(&'static str),
}
