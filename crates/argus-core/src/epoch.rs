//! Üç ayrı geçersizleme sayacı.
//!
//! # Karar (§1 #18, §2 Çelişki 4)
//!
//! Tek bir `revocation_epoch` iki farklı geçersizleme eksenini aynı sayaca sıkıştırır
//! ve ikisi de bozulur:
//!
//! - Rol değişiminde sayaç artarsa kullanıcının **tüm oturumları düşer** — kabul edilemez.
//! - Artmazsa yetkilendirme karar cache'i **bayat kalır** — güvenlik açığı.
//!
//! Doğru model üç ayrı sayaçtır ve üçü de **ayrı tiptir**: birini diğerinin yerine
//! geçirmek derleme hatasıdır.
//!
//! | Sayaç | Neyi geçersiz kılar | Ne zaman artar |
//! |---|---|---|
//! | [`SessionEpoch`] | Kullanıcının **tüm token'ları** | Parola değişimi, "tüm cihazlardan çık", hesap devre dışı, credential değişimi |
//! | [`AuthzEpoch`] | Kiracının **yetkilendirme karar cache'i** | Rol / politika / ilişki değişimi |
//! | [`KeyEpoch`] | JWKS cache'i | Anahtar rotasyonu |
//!
//! # Yayılım süreleri burada YOK
//!
//! "≤250 ms", "≤1 s" gibi hedefler bu tipe ait değil: yayılım bir teslimat sorunudur
//! ve teslimat algoritması **açık karardır** (§1 §10.2). Bu modül yalnızca sayaçların
//! anlamını ve monotonluğunu taşır.

use core::fmt;

/// Üç sayaç için ortak davranışı üreten makro.
///
/// Elle üç kez yazmak yerine makro kullanılıyor; tipler yine de **ayrı** kalır,
/// aralarında dönüşüm yoktur.
macro_rules! define_epoch {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// Monoton artar, asla azalmaz. `Default` başlangıç değeri sıfırdır ve bu
        /// güvenlidir: hiçbir token'ın epoch'u sıfırdan küçük olamaz.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(u64);

        impl $name {
            /// Başlangıç değeri.
            pub const ZERO: Self = Self(0);

            /// Depolanan ham değerden kurar.
            #[must_use]
            pub const fn from_raw(value: u64) -> Self {
                Self(value)
            }

            /// Ham değeri verir — yalnızca depolama sınırında ve token claim'i yazarken.
            #[must_use]
            pub const fn as_raw(self) -> u64 {
                self.0
            }

            /// Bir sonraki değeri üretir.
            ///
            /// Taşma durumunda doygunlaşır (`saturating_add`). Bu bilinçli bir seçim:
            /// `u64` taşması için saniyede bir milyon iptal ile yarım milyon yıl
            /// gerekir; ama taşırsa panik yerine doygunlaşmak **fail-safe** taraftır —
            /// sayaç sabitlenir, geriye sarmaz. Geriye sarma, iptal edilmiş bir
            /// token'ın yeniden geçerli olması demekti.
            #[must_use]
            pub const fn next(self) -> Self {
                Self(self.0.saturating_add(1))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_epoch! {
    /// Kullanıcı başına oturum geçersizleme sayacı.
    ///
    /// **Token'ın içinde claim olarak taşınır** ve doğrulamada node cache'indeki
    /// değerle karşılaştırılır — ağ turu gerektirmez. Bkz. [`SessionEpoch::is_token_revoked`].
    SessionEpoch
}

define_epoch! {
    /// Kiracı başına yetkilendirme karar cache'i sayacı.
    ///
    /// **Token'ın içinde taşınmaz.** Karar cache anahtarının bir parçasıdır; artınca
    /// eski anahtarlar adreslenemez hâle gelir ve doğal olarak tahliye edilir.
    ///
    /// ⚠️ Bu, tazeliği tek başına çözmez: epoch cache'i *adreslenemez* kılar ama
    /// cache'i *dolduran* okumanın tazeliği hakkında hiçbir şey söylemez. Doldurma
    /// sözleşmesi §1 §10.3 A6'da kabul edilmiş başlangıç modeli olarak duruyor.
    AuthzEpoch
}

define_epoch! {
    /// Kiracı başına JWKS cache sayacı. Anahtar rotasyonunda artar.
    KeyEpoch
}

impl SessionEpoch {
    /// Token'daki epoch'a bakarak token'ın ölü olup olmadığına karar verir.
    ///
    /// `self` kullanıcının **güncel** epoch'u, `token` ise token'ın taşıdığı değerdir.
    /// Kural tek satırdır: token'ın epoch'u güncelden küçükse token ölüdür.
    ///
    /// ```
    /// use argus_core::SessionEpoch;
    ///
    /// let current = SessionEpoch::from_raw(5);
    /// assert!(current.is_token_revoked(SessionEpoch::from_raw(4)));
    /// assert!(!current.is_token_revoked(SessionEpoch::from_raw(5)));
    /// ```
    ///
    /// # Bu fonksiyonun bilmediği şey
    ///
    /// `self`'in **taze** olduğunu varsayar. Bayat bir cache değeriyle çağrılırsa
    /// iptal edilmiş bir token'a `false` döner. Tazelik sözleşmesi burada değil,
    /// §1 §10.1'de — ve orası **açık karardır**.
    #[must_use]
    pub const fn is_token_revoked(self, token: Self) -> bool {
        token.0 < self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthzEpoch, KeyEpoch, SessionEpoch};

    #[test]
    fn epochs_start_at_zero() {
        assert_eq!(SessionEpoch::default(), SessionEpoch::ZERO);
        assert_eq!(AuthzEpoch::default().as_raw(), 0);
        assert_eq!(KeyEpoch::ZERO.as_raw(), 0);
    }

    #[test]
    fn next_is_monotonic() {
        let a = SessionEpoch::ZERO;
        let b = a.next();
        assert!(b > a);
        assert_eq!(b.as_raw(), 1);
    }

    /// Taşma geriye sarmaz. Sarsaydı iptal edilmiş token yeniden geçerli olurdu.
    #[test]
    fn next_saturates_instead_of_wrapping() {
        let max = SessionEpoch::from_raw(u64::MAX);
        assert_eq!(max.next(), max);
    }

    #[test]
    fn older_token_epoch_is_revoked() {
        let current = SessionEpoch::from_raw(5);
        assert!(current.is_token_revoked(SessionEpoch::from_raw(0)));
        assert!(current.is_token_revoked(SessionEpoch::from_raw(4)));
    }

    #[test]
    fn equal_or_newer_token_epoch_is_live() {
        let current = SessionEpoch::from_raw(5);
        assert!(!current.is_token_revoked(SessionEpoch::from_raw(5)));
        // Daha yeni bir epoch yalnızca cache bayatsa görülür; token'ı öldürmek için
        // bir sebep değildir.
        assert!(!current.is_token_revoked(SessionEpoch::from_raw(6)));
    }

    #[test]
    fn debug_shows_the_value() {
        assert_eq!(
            format!("{:?}", SessionEpoch::from_raw(7)),
            "SessionEpoch(7)"
        );
        assert_eq!(format!("{:?}", AuthzEpoch::from_raw(7)), "AuthzEpoch(7)");
    }
}
