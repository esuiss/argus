use landlock::{
    ABI, Access, AccessFs, Compatible, PathBeneath, PathFd, RestrictionStatus, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};

use crate::{Policy, Report, SandboxError};

// §11 C.3 forward-compat uyarısı: `BitFlags::all()` gibi hareketli hedeflere
// güvenilmez, hedef ABI AÇIKÇA belirtilir. Yoksa bir `cargo update` sessizce
// yeni access right'ları etkinleştirir ve daha önce çalışan bir politika
// sürecin kendi dosyalarını açamaz hâle gelir.
const TARGET_ABI: ABI = ABI::V5;

fn set_not_dumpable() -> bool {
    // PR_SET_DUMPABLE=0: core dump yok, /proc/self/mem başkasına açık değil.
    // Bir IdP'nin belleğinde imzalama anahtarı ve parola vardır.
    nix::sys::prctl::set_dumpable(false).is_ok()
}

fn set_no_new_privs() -> bool {
    // no_new_privs olmadan bir setuid ikilisi ayrıcalığı geri kazanabilir.
    nix::sys::prctl::set_no_new_privs().is_ok()
}

fn drop_capabilities() -> bool {
    use caps::{CapSet, clear};

    // Bounding set de temizlenir: yalnızca effective/permitted temizlemek,
    // exec sonrası yeniden kazanılabilen bir yol bırakır.
    [
        CapSet::Bounding,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Effective,
        CapSet::Permitted,
    ]
    .into_iter()
    .all(|set| clear(None, set).is_ok())
}

/// §11 C.4'ün tuzağına verilen cevap. Landlock VARSAYILAN OLARAK yalnızca
/// çağıran thread'i kısıtlar, ve ABI 8'in `all_threads()`'i eski bir kernel'de
/// best-effort modunda SESSİZCE düşer: "sandbox'ınız olduğunu sanırsınız,
/// olmaz."
///
/// `all_threads()`'in çalışmasını ummak yerine ön koşul ÖLÇÜLÜYOR: kısıtlama
/// anında süreçte başka thread var mı. Tek thread varsa kısıtlama tanım gereği
/// sürecin tamamını kapsar; varsa, kapsamaz ve bu bir hatadır.
fn thread_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/task")
        .ok()
        .map(|entries| entries.filter_map(Result::ok).count())
}

fn restrict_filesystem(policy: &Policy) -> Result<i32, SandboxError> {
    let read_only = AccessFs::from_read(TARGET_ABI);
    let read_write = AccessFs::from_all(TARGET_ABI);

    let mut ruleset = Ruleset::default()
        // Best-effort DEĞİL: desteklenmeyen bir kısıtlamayı sessizce düşürmek,
        // kurulmamış bir sandbox'ı kurulmuş sanmaktır.
        .set_compatibility(landlock::CompatLevel::HardRequirement)
        .handle_access(read_write)
        .map_err(|_| SandboxError::LandlockUnavailable)?
        .create()
        .map_err(|_| SandboxError::LandlockUnavailable)?;

    for path in &policy.read_only {
        let fd = PathFd::new(path)
            .map_err(|e| SandboxError::Refused(format!("{}: {e}", path.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, read_only))
            .map_err(|e| SandboxError::Refused(e.to_string()))?;
    }

    for path in &policy.read_write {
        let fd = PathFd::new(path)
            .map_err(|e| SandboxError::Refused(format!("{}: {e}", path.display())))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, read_write))
            .map_err(|e| SandboxError::Refused(e.to_string()))?;
    }

    let status: RestrictionStatus = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Refused(e.to_string()))?;

    // Kısmen uygulanmış bir kısıtlama bir başarı değildir.
    if !matches!(status.ruleset, RulesetStatus::FullyEnforced) {
        return Err(SandboxError::LandlockUnavailable);
    }

    Ok(TARGET_ABI as i32)
}

pub(crate) fn harden(policy: &Policy) -> Result<Report, SandboxError> {
    let not_dumpable = set_not_dumpable();
    let no_new_privs = set_no_new_privs();

    let threads = thread_count();
    // Bilinmiyorsa güvenli varsayım "hayır"dır.
    let all_threads = threads == Some(1);

    let abi = if policy.is_empty() {
        None
    } else {
        if !all_threads {
            return Err(SandboxError::PerThreadOnly);
        }
        Some(restrict_filesystem(policy)?)
    };

    // Yetenekler EN SONA: Landlock kuralları için dosya tanıtıcıları açmak
    // bazı ortamlarda yetenek ister.
    let capabilities_dropped = drop_capabilities();

    Ok(Report {
        no_new_privs,
        not_dumpable,
        landlock_abi: abi,
        all_threads,
        capabilities_dropped,
    })
}
