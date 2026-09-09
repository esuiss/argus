//! Zaman.
//!
//! # Saat burada okunmaz
//!
//! `argus-core` sistem saatine bakmaz. `SystemTime::now()` teknik olarak I/O
//! değildir ama **ortam yetkisidir**: onu çağıran bir fonksiyon artık saf değildir,
//! aynı girdiyle farklı sonuç verir ve testte zamanı ileri sarmak için gerçekten
//! beklemek gerekir.
//!
//! Bunun yerine "şimdi" her karar fonksiyonuna **parametre olarak** girer. Süre
//! dolması, token ömrü ve cooldown testleri böylece anlık ve deterministik olur —
//! §10'un formel doğrulama için istediği şey de budur.

use core::fmt;

/// Unix epoch'undan itibaren saniye.
///
/// Saniye çözünürlüğü bilinçlidir: JWT'nin `exp`/`iat`/`nbf` claim'leri
/// (RFC 7519 §2 `NumericDate`) saniye cinsindendir ve daha ince bir iç gösterim,
/// tel üzerindeki değerle karşılaştırmalarda sessiz yuvarlama farkları üretirdi.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

/// İki zaman noktası arasındaki fark, saniye.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Duration(i64);

impl Timestamp {
    /// Unix saniyesinden kurar.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Unix saniyesi olarak verir. JWT claim'lerine yazarken kullanılır.
    #[must_use]
    pub const fn as_unix_seconds(self) -> i64 {
        self.0
    }

    /// Bu ana süre ekler.
    ///
    /// Taşmada doygunlaşır. Panik yerine doygunlaşma seçilmiştir: bir kimlik
    /// sağlayıcısında aritmetik taşma yüzünden süreç düşürmek, saldırgana ucuz bir
    /// hizmet reddi verir.
    /// Doygunlaşan bir `exp` ise "çok uzak gelecek" demektir ve bu tek başına
    /// güvenlik açığı değildir — üretilen token'ın ömrü ayrıca sınırlanır.
    #[must_use]
    pub const fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.0))
    }

    /// `self`'ten `earlier`'a kadar geçen süre. `earlier` daha ileriyse negatif.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    /// `deadline` geçilmiş mi?
    ///
    /// Sınır **dahil değildir**: `now == deadline` henüz süresi dolmamış sayılır.
    /// RFC 7519 §4.1.4 `exp` için "current date/time MUST be before" diyor, yani
    /// eşitlik anında token hâlâ geçerlidir.
    #[must_use]
    pub const fn is_after(self, deadline: Self) -> bool {
        self.0 > deadline.0
    }
}

impl Duration {
    /// Saniyeden kurar.
    #[must_use]
    pub const fn from_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Saniye değeri.
    #[must_use]
    pub const fn as_seconds(self) -> i64 {
        self.0
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, Timestamp};

    #[test]
    fn expiry_boundary_is_inclusive() {
        let deadline = Timestamp::from_unix_seconds(1_000);
        // RFC 7519 §4.1.4: eşitlik anında hâlâ geçerli.
        assert!(!Timestamp::from_unix_seconds(1_000).is_after(deadline));
        assert!(Timestamp::from_unix_seconds(1_001).is_after(deadline));
        assert!(!Timestamp::from_unix_seconds(999).is_after(deadline));
    }

    #[test]
    fn add_saturates_instead_of_panicking() {
        let far = Timestamp::from_unix_seconds(i64::MAX);
        assert_eq!(far.saturating_add(Duration::from_seconds(60)), far);
    }

    #[test]
    fn since_measures_elapsed_time() {
        let t0 = Timestamp::from_unix_seconds(100);
        let t1 = Timestamp::from_unix_seconds(160);
        assert_eq!(t1.since(t0), Duration::from_seconds(60));
        assert_eq!(t0.since(t1), Duration::from_seconds(-60));
    }
}
