//! Kimlik tipleri.
//!
//! Üçü de **opak**: içlerindeki değer üzerinde yetkilendirme kararı verilmez, yalnızca
//! eşitlik karşılaştırılır (§1 karar #11 — isim değil, opak-ID tabanlı yetkilendirme).
//!
//! # Neden `Debug` elle yazıldı
//!
//! Türetilmiş `Debug`, tipe sonradan eklenen bir alanı hiçbir log satırı değişmeden
//! sızdırır (§25 K27). Kimlikler sır değildir ama izolasyon sınırıdır: bir kiracının
//! log'unda başka bir kiracının kimliğinin tam hâlinin görünmesi gereksiz bir bilgi
//! akışıdır. Bu yüzden `Debug` ve `Display` kısaltılmış hâli basar; tam değere ulaşmak
//! isteyen `as_uuid()` çağırmak zorundadır — yani niyetini kodda beyan eder.

use core::fmt;

use uuid::Uuid;

use crate::error::IdError;

/// `client_id` için azami bayt uzunluğu.
pub const CLIENT_ID_MAX_LEN: usize = 255;

/// Log'da gösterilen kısaltılmış kimlik önekinin uzunluğu (onaltılık karakter).
const ID_PREFIX_LEN: usize = 8;

/// `Uuid`'yi log için kısaltarak yazar: `01937f2e…`.
fn write_redacted(f: &mut fmt::Formatter<'_>, id: Uuid) -> fmt::Result {
    let mut buf = Uuid::encode_buffer();
    let full = id.as_simple().encode_lower(&mut buf);
    // `indexing_slicing` deny — dilimleme yerine `get`, sınır aşılırsa tamamı yazılır.
    let prefix = full.get(..ID_PREFIX_LEN).unwrap_or(full);
    write!(f, "{prefix}…")
}

/// Kiracı kimliği.
///
/// # Türetilmeyenler ve sebepleri
///
/// - **`Debug`/`Display` türetilmedi** — yukarıdaki modül notu.
/// - **`Deserialize` türetilmedi.** Kiracı kimliği bir istek gövdesinden veya
///   doğrulanmamış bir yol parçasından **asla** üretilemez. Tek meşru kaynağı, istek
///   sınırındaki çözümleyicidir (host → kiracı). CVE-2026-41166 tam olarak bunun
///   yokluğuydu: `{realm}` yol parçası, çağıranın o realm'i yönetip yönetemeyeceği
///   kontrol edilmeden kullanılıyordu (§18).
/// - **`Default` türetilmedi.** "Varsayılan kiracı" diye bir şey yoktur; sıfır UUID
///   sessizce yanlış kapsam üretir.
///
/// # Tip ayrımını derleyici zorlar
///
/// Bir kullanıcı kimliğini kiracı kimliğiyle karşılaştırmak derleme hatasıdır.
/// Bu doctest, iddianın sınanabilir hâlidir: gövdesi derlenirse test **başarısız olur**.
///
/// ```compile_fail
/// use argus_core::{TenantId, UserId};
/// use uuid::Uuid;
///
/// let tenant = TenantId::from_uuid(Uuid::nil());
/// let user = UserId::from_uuid(Uuid::nil());
/// let _ = tenant == user;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Doğrulanmış bir `Uuid`'den kiracı kimliği kurar.
    ///
    /// Çağıran, değerin gerçekten bir kiracıya ait olduğunu **kanıtlamış** olmalıdır
    /// (veritabanı satırı veya çözümlenmiş host). Bu yapıcı doğrulama yapmaz.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Ham değeri verir. Yalnızca depolama sınırında ve sorgu parametresi bağlarken.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TenantId(")?;
        write_redacted(f, self.0)?;
        f.write_str(")")
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_redacted(f, self.0)
    }
}

/// Kullanıcı kimliği.
///
/// **Asla yeniden kullanılmaz** (§1 karar #14). Bir kullanıcı silindiğinde kimliği
/// tombstone olarak kalır; aynı değer ikinci bir özneye verilemez. Bunu şema zorlar,
/// bu tip yalnızca değeri taşır.
///
/// `TenantId` ile aynı sebeplerle `Debug`/`Display` elle yazıldı ve `Deserialize`
/// türetilmedi.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(Uuid);

impl UserId {
    /// Doğrulanmış bir `Uuid`'den kullanıcı kimliği kurar.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Ham değeri verir. Yalnızca depolama sınırında.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserId(")?;
        write_redacted(f, self.0)?;
        f.write_str(")")
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_redacted(f, self.0)
    }
}

/// OAuth istemci kimliği.
///
/// **Global benzersizdir** (§1 karar #5), kiracı-yerel değil. Keycloak'ın aksine:
/// sonradan globalleştirmek her müşterinin `client_id`'sini yeniden adlandırmak,
/// yani her RP konfigürasyonunu kırmak demektir.
///
/// `Uuid` değil `String`'dir; RFC 6749 §2.2 `client_id`'yi bir dizge olarak tanımlar
/// ve CIMD gibi profillerde bir URL olabilir.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(String);

impl ClientId {
    /// Bir dizgeden istemci kimliği kurar ve RFC 6749 Ek A'ya göre doğrular.
    ///
    /// # Errors
    ///
    /// Boşsa, [`CLIENT_ID_MAX_LEN`] aşılmışsa veya görünür ASCII dışı bir karakter
    /// varsa [`IdError`] döner.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();

        if value.is_empty() {
            return Err(IdError::ClientIdEmpty);
        }
        if value.len() > CLIENT_ID_MAX_LEN {
            return Err(IdError::ClientIdTooLong {
                len: value.len(),
                max: CLIENT_ID_MAX_LEN,
            });
        }
        // RFC 6749 Ek A: `client_id = *VSCHAR`, yani 0x20–0x7E.
        // `bytes()` üzerinden gidiyoruz: ASCII dışı her şey zaten aralık dışında kalır.
        if !value.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(IdError::ClientIdInvalidChar);
        }

        Ok(Self(value))
    }

    /// Ham değeri verir.
    ///
    /// `client_id` sır değildir — RFC 6749 §2.2'ye göre public client'larda zaten
    /// açıktır — bu yüzden `TenantId`'nin aksine redakte edilmez.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientId({:?})", self.0)
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{CLIENT_ID_MAX_LEN, ClientId, TenantId, UserId};
    use crate::error::IdError;
    use uuid::Uuid;

    /// Bilinen bir UUID — kısaltma davranışını sabitler.
    fn sample() -> Uuid {
        Uuid::from_u128(0x0193_7f2e_1234_5678_9abc_def0_1234_5678)
    }

    #[test]
    fn tenant_id_debug_is_redacted() {
        let id = TenantId::from_uuid(sample());
        let shown = format!("{id:?}");
        assert_eq!(shown, "TenantId(01937f2e…)");
        // Tam değer sızmamalı.
        assert!(!shown.contains("9abcdef0"));
    }

    #[test]
    fn user_id_debug_is_redacted() {
        let id = UserId::from_uuid(sample());
        assert_eq!(format!("{id:?}"), "UserId(01937f2e…)");
    }

    #[test]
    fn id_round_trips_through_uuid() {
        assert_eq!(TenantId::from_uuid(sample()).as_uuid(), sample());
        assert_eq!(UserId::from_uuid(sample()).as_uuid(), sample());
    }

    #[test]
    fn same_uuid_under_two_types_is_an_explicit_unwrap() {
        // Aynı UUID iki farklı kimlik tipinde taşınabilir. İkisini karşılaştırmanın
        // TEK yolu her ikisinde de `as_uuid()` çağırmaktır — yani tip sınırını
        // aşmak niyet beyanı gerektirir. Doğrudan karşılaştırma derlenmez;
        // bunun kanıtı `TenantId` üzerindeki `compile_fail` doctest'idir.
        let tenant = TenantId::from_uuid(sample());
        let user = UserId::from_uuid(sample());
        assert_eq!(tenant.as_uuid(), user.as_uuid());
    }

    #[test]
    fn client_id_accepts_valid_values() {
        for value in ["s6BhdRkqt3", "https://example.com/client", "a b~"] {
            assert!(ClientId::new(value).is_ok(), "rejected: {value}");
        }
    }

    #[test]
    fn client_id_rejects_invalid_values() {
        let cases: [(&str, IdError); 4] = [
            ("", IdError::ClientIdEmpty),
            ("bad\nline", IdError::ClientIdInvalidChar),
            ("tab\there", IdError::ClientIdInvalidChar),
            ("caf\u{e9}", IdError::ClientIdInvalidChar), // ASCII dışı
        ];
        for (value, expected) in cases {
            assert_eq!(
                ClientId::new(value).unwrap_err(),
                expected,
                "input: {value:?}"
            );
        }
    }

    #[test]
    fn client_id_enforces_max_length() {
        let ok = "a".repeat(CLIENT_ID_MAX_LEN);
        assert!(ClientId::new(ok).is_ok());

        let too_long = "a".repeat(CLIENT_ID_MAX_LEN + 1);
        assert_eq!(
            ClientId::new(too_long).unwrap_err(),
            IdError::ClientIdTooLong {
                len: CLIENT_ID_MAX_LEN + 1,
                max: CLIENT_ID_MAX_LEN,
            }
        );
    }

    #[test]
    fn client_id_is_not_redacted() {
        let id = ClientId::new("s6BhdRkqt3").unwrap();
        assert_eq!(id.to_string(), "s6BhdRkqt3");
    }
}
