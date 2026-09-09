//! Refresh token rotasyonu ve yeniden kullanım tespiti.
//!
//! §5'in doğrudan tavsiyesi: *"refresh reuse detection'ı **baştan** tasarla."*
//! Sonradan eklenemez, çünkü tespit bir **zincir** kavramı gerektirir ve zincir
//! kimliği token verilirken yazılmak zorundadır.
//!
//! # Zincir (family) modeli
//!
//! Tek bir yetkilendirmeden doğan bütün refresh token'lar aynı [`FamilyId`]'yi
//! paylaşır ve her rotasyonda sıra numarası bir artar:
//!
//! ```text
//! authorization_code  →  gen 0  →  gen 1  →  gen 2
//!                        family: F  family: F  family: F
//! ```
//!
//! # Tespit neden zincirin tamamını düşürür
//!
//! RFC 9700 §4.14.2: döndürülmüş bir token ikinci kez sunulduğunda iki senaryo
//! vardır ve sunucu **hangisi olduğunu ayırt edemez**:
//!
//! 1. Saldırgan token'ı çaldı ve meşru istemciden önce kullandı;
//! 2. Meşru istemci yanıtı alamadı (ağ hatası) ve eskisini yeniden denedi.
//!
//! Ayrım imkânsız olduğu için tek güvenli davranış zinciri düşürmektir. (2)
//! senaryosunda bedel kullanıcının yeniden yetkilendirme yapmasıdır; (1)
//! senaryosunda kazanç saldırganın erişimini kaybetmesidir.
//!
//! # Mutlak zincir ömrü
//!
//! Rotasyon tek başına sonsuz erişim üretir: her kullanımda yenisi alındığı sürece
//! zincir hiç bitmez. Bu yüzden zincirin **ilk** token'ının verildiği andan
//! itibaren mutlak bir üst sınır uygulanır ve bu sınır rotasyonla yenilenmez.

use core::fmt;

use uuid::Uuid;

use crate::effect::Effect;
use crate::id::{ClientId, TenantId, UserId};
use crate::time::{Duration, Timestamp};

/// Bir zincirin varsayılan mutlak ömrü: 30 gün.
pub const DEFAULT_FAMILY_LIFETIME: Duration = Duration::from_seconds(30 * 24 * 60 * 60);

/// Tek bir refresh token'ın varsayılan ömrü: 14 gün.
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_seconds(14 * 24 * 60 * 60);

/// Refresh token zinciri kimliği.
///
/// [`crate::id`]'deki kimliklerle aynı gerekçelerle `Debug` elle yazıldı ve
/// `Deserialize` türetilmedi: zincir kimliği istemciden gelmez, sunucu üretir.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FamilyId(Uuid);

impl FamilyId {
    /// Doğrulanmış bir `Uuid`'den kurar.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Ham değeri verir — yalnızca depolama sınırında.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for FamilyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = Uuid::encode_buffer();
        let full = self.0.as_simple().encode_lower(&mut buf);
        let prefix = full.get(..8).unwrap_or(full);
        write!(f, "FamilyId({prefix}…)")
    }
}

/// Bir refresh token'ın durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshState {
    /// Kullanılabilir.
    Active,
    /// Kullanıldı ve yerine yenisi verildi.
    Rotated {
        /// Rotasyon anı.
        at: Timestamp,
    },
    /// İptal edildi — zincir düşürüldüğünde veya kullanıcı çıkış yaptığında.
    Revoked {
        /// İptal anı.
        at: Timestamp,
    },
}

/// Depodan okunmuş refresh token kaydı.
///
/// Token'ın **kendisi** burada yok: `argus-store` onu hash'leyerek tutar ve bu tip
/// çözülmüş kaydı temsil eder. Sır değeri karar mantığından hiç geçmez, dolayısıyla
/// log'a veya panik mesajına düşemez.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    /// Kiracı.
    pub tenant: TenantId,
    /// Token'ın verildiği istemci.
    pub client: ClientId,
    /// Özne.
    pub subject: UserId,
    /// Zincir kimliği.
    pub family: FamilyId,
    /// Zincir içindeki sıra; ilk token 0'dır.
    pub generation: u32,
    /// Zincirin **ilk** token'ının verildiği an. Mutlak ömür bundan sayılır.
    pub family_started_at: Timestamp,
    /// Bu token'ın sona erme anı.
    pub expires_at: Timestamp,
    /// Durum.
    pub state: RefreshState,
}

/// Token endpoint'ine gelen `grant_type=refresh_token` isteği.
#[derive(Debug, Clone)]
pub struct RefreshRequest {
    /// Doğrulanmış istemci.
    pub client: ClientId,
    /// Host'tan çözülmüş kiracı — istek gövdesinden DEĞİL.
    pub tenant: TenantId,
}

/// Rotasyonun sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedGrant {
    /// Özne.
    pub subject: UserId,
    /// İstemci.
    pub client: ClientId,
    /// Kiracı.
    pub tenant: TenantId,
    /// Yeni token'ın ait olacağı zincir — **aynı zincir**.
    pub family: FamilyId,
    /// Yeni token'ın sırası.
    pub next_generation: u32,
}

/// Reddetme sebebi.
///
/// [`crate::authz_code::DenialReason`] gibi hepsi istemciye `invalid_grant` olarak
/// döner; ayrım yalnızca denetim kaydı içindir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDenial {
    /// Token'ın süresi dolmuş.
    Expired,
    /// Zincirin mutlak ömrü dolmuş — rotasyon sonsuz erişim üretmez.
    FamilyExpired,
    /// Token başka bir istemciye verilmişti.
    ClientMismatch,
    /// Token başka bir kiracıya aitti.
    TenantMismatch,
    /// Token daha önce iptal edilmiş.
    Revoked,
    /// **Döndürülmüş bir token yeniden sunuldu.** Güvenlik olayı.
    Reused {
        /// İlk rotasyonun zamanı.
        rotated_at: Timestamp,
        /// Zincirdeki sırası — saldırganın ne kadar geriden geldiğini gösterir.
        generation: u32,
    },
}

impl RefreshDenial {
    /// İstemciye dönecek OAuth hata kodu (RFC 6749 §5.2).
    #[must_use]
    pub const fn oauth_error_code(&self) -> &'static str {
        "invalid_grant"
    }
}

/// [`rotate`] sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDecision {
    /// Yeni token verilebilir.
    Rotate {
        /// Yeni token'ın parametreleri.
        grant: RotatedGrant,
        /// Uygulanacak etkiler.
        effects: Vec<Effect>,
    },
    /// Reddedildi.
    Deny {
        /// İç sebep.
        reason: RefreshDenial,
        /// Uygulanacak etkiler.
        effects: Vec<Effect>,
    },
}

/// Bir refresh token'ı döndürmeye çalışır.
///
/// Saf fonksiyon: hiçbir şey yazmaz, saate bakmaz, token üretmez.
///
/// # Kontrol sırası
///
/// **Yeniden kullanım en başta.** Süresi dolmuş bir token'ın yeniden sunulması da
/// bir güvenlik olayıdır; "zaten süresi dolmuştu" diyerek zincir iptalini atlamak,
/// saldırganın çaldığı token'ı bekletmesini ödüllendirirdi — authorization code
/// tarafındaki kararın aynısı.
#[must_use]
pub fn rotate(
    token: &RefreshToken,
    request: &RefreshRequest,
    now: Timestamp,
    family_lifetime: Duration,
) -> RefreshDecision {
    // 1. Yeniden kullanım — her şeyden önce; zinciri düşürür.
    if let RefreshState::Rotated { at } = token.state {
        return RefreshDecision::Deny {
            reason: RefreshDenial::Reused {
                rotated_at: at,
                generation: token.generation,
            },
            effects: vec![
                Effect::RevokeRefreshFamily,
                Effect::RecordAudit("oauth.refresh_token.reuse_detected"),
            ],
        };
    }

    // 2. Zaten iptal edilmiş token. Zincir muhtemelen çoktan düşürüldü; yine de
    // denetim kaydı üretilir çünkü kimin denediği bilinmek istenir.
    if matches!(token.state, RefreshState::Revoked { .. }) {
        return RefreshDecision::Deny {
            reason: RefreshDenial::Revoked,
            effects: vec![Effect::RecordAudit("oauth.refresh_token.revoked_presented")],
        };
    }

    let deny = |reason: RefreshDenial, audit: &'static str| RefreshDecision::Deny {
        reason,
        effects: vec![Effect::RecordAudit(audit)],
    };

    if token.tenant != request.tenant {
        return deny(
            RefreshDenial::TenantMismatch,
            "oauth.refresh_token.tenant_mismatch",
        );
    }

    if token.client != request.client {
        return deny(
            RefreshDenial::ClientMismatch,
            "oauth.refresh_token.client_mismatch",
        );
    }

    // 3. Mutlak zincir ömrü — rotasyonun sonsuz erişime dönüşmesini engeller.
    if now.is_after(token.family_started_at.saturating_add(family_lifetime)) {
        return deny(
            RefreshDenial::FamilyExpired,
            "oauth.refresh_token.family_expired",
        );
    }

    if now.is_after(token.expires_at) {
        return deny(RefreshDenial::Expired, "oauth.refresh_token.expired");
    }

    RefreshDecision::Rotate {
        grant: RotatedGrant {
            subject: token.subject,
            client: token.client.clone(),
            tenant: token.tenant,
            family: token.family,
            // Taşmada doygunlaşır: `u32` sırası pratikte tükenmez ama sarması iki
            // farklı token'a aynı sırayı verirdi.
            next_generation: token.generation.saturating_add(1),
        },
        effects: vec![
            Effect::RotateRefreshToken,
            Effect::RecordAudit("oauth.refresh_token.rotated"),
        ],
    }
}
