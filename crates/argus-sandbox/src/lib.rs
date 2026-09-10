#![forbid(unsafe_code)]

//! §11 P1 #8-#10: süreç izolasyonu.
//!
//! Bu crate'in en önemli özelliği ne yaptığı değil, YAPAMADIĞINDA ne dediğidir.
//! §11 C.4 aynı tuzağı iki kez adlandırıyor: Landlock varsayılan best-effort
//! modunda desteklenmeyen kısıtlamaları SESSİZCE düşürür, ve `all_threads()`
//! eski bir kernel'de sessizce kaybolarak kardeş thread'leri kısıtlamasız
//! bırakır. İkisi de "sandbox'ınız olduğunu sanırsınız, olmaz" ile biter.
//!
//! Bu yüzden buradaki her yol ya zorlandığını kanıtlar ya da neden
//! zorlanamadığını söyler; hiçbiri sessizce başarılı olmaz.

use std::path::PathBuf;

/// Sürecin gerçekten ihtiyaç duyduğu şeyler. Listelenmemiş her şey reddedilir.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Salt okunur: imzalama anahtarları, sertifikalar, kök sertifika deposu.
    pub read_only: Vec<PathBuf>,

    /// Okuma ve yazma: yalnızca /tmp gibi geçici alanlar.
    pub read_write: Vec<PathBuf>,
}

impl Policy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn reading(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_only.push(path.into());
        self
    }

    #[must_use]
    pub fn writing(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_write.push(path.into());
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read_only.is_empty() && self.read_write.is_empty()
    }
}

/// Neyin gerçekten uygulandığı. Çağıran bunu log'lar; §11'in tamamı
/// "iddia etmeyin, ölçün" üzerine kurulu.
#[derive(Debug, Clone, PartialEq, Eq)]
// Her alan ayrı bir mekanizmanın uygulanıp uygulanmadığını taşır ve
// birleştirilemez: hangisinin tuttuğu, hangisinin tutmadığı ayrı ayrı
// bilinmek zorunda.
#[allow(clippy::struct_excessive_bools)]
pub struct Report {
    pub no_new_privs: bool,
    pub not_dumpable: bool,
    /// Uygulanan Landlock ABI seviyesi. `None` ise dosya sistemi kısıtlanmadı.
    pub landlock_abi: Option<i32>,
    /// Kısıtlamanın sürecin tamamını kapsayıp kapsamadığı. §11 C.4: Landlock
    /// yalnızca çağıran thread'i kısıtlar, o yüzden bu ancak kısıtlama anında
    /// süreçte TEK thread varsa doğrudur. Umulmuyor, ölçülüyor.
    pub all_threads: bool,
    pub capabilities_dropped: bool,
}

impl Report {
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "no_new_privs={} not_dumpable={} landlock={} all_threads={} caps_dropped={}",
            self.no_new_privs,
            self.not_dumpable,
            self.landlock_abi
                .map_or_else(|| "off".to_owned(), |abi| format!("abi{abi}")),
            self.all_threads,
            self.capabilities_dropped,
        )
    }

    /// Süreç izolasyonunun anlamlı olduğu tek durum. Çok thread'li bir sunucu
    /// bunu doğrulamadan hizmet vermemeli.
    #[must_use]
    pub const fn is_enforced(&self) -> bool {
        self.no_new_privs && self.landlock_abi.is_some() && self.all_threads
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    #[error("process isolation is a Linux kernel interface and this is {0}")]
    UnsupportedPlatform(&'static str),

    #[error("the kernel does not support Landlock, so the filesystem cannot be restricted")]
    LandlockUnavailable,

    #[error(
        "the process already has more than one thread; Landlock restricts only the calling \
         thread, so this would be a sandbox in name only. Harden before the async runtime starts."
    )]
    PerThreadOnly,

    #[error("{0}")]
    Refused(String),
}

#[cfg(target_os = "linux")]
mod linux;

/// Politikayı uygular. §11 P1 #8: ana thread'de ve runtime BAŞLAMADAN önce
/// çağrılmalı; Landlock thread bazlıdır ve bir tokio worker'ında uygulanırsa
/// diğer worker'lar kısıtlamasız kalır.
#[cfg(target_os = "linux")]
pub fn harden(policy: &Policy) -> Result<Report, SandboxError> {
    linux::harden(policy)
}

#[cfg(not(target_os = "linux"))]
pub fn harden(_policy: &Policy) -> Result<Report, SandboxError> {
    Err(SandboxError::UnsupportedPlatform(std::env::consts::OS))
}

/// Bu platformda izolasyonun mümkün olup olmadığı. Çağıran, üretimde
/// zorlanamayan bir dağıtımı reddetmek için buna bakar.
#[must_use]
pub const fn is_supported() -> bool {
    cfg!(target_os = "linux")
}
