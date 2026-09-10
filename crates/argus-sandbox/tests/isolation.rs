#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_sandbox::{Policy, SandboxError, harden, is_supported};

#[test]
fn a_platform_without_the_kernel_interface_says_so_rather_than_pretending() {
    if is_supported() {
        return;
    }

    // §11'in tamamı "iddia etmeyin, ölçün" üzerine kurulu. Desteklenmeyen bir
    // platformda sessizce başarılı olmak, sandbox'ı olduğunu sanan bir dağıtım
    // üretir.
    let outcome = harden(&Policy::new().reading("/etc"));
    assert!(matches!(outcome, Err(SandboxError::UnsupportedPlatform(_))));
}

/// Bu test sürecin KENDİSİNİ kısıtlar, o yüzden kendi süreci içinde koşar ve
/// geri alınamaz. Landlock tasarımı gereği tek yönlüdür.
#[test]
#[cfg(target_os = "linux")]
fn the_filesystem_is_actually_restricted_and_not_merely_claimed() {
    use std::fs;

    let allowed = std::env::temp_dir().join("argus-sandbox-allowed");
    fs::create_dir_all(&allowed).expect("allowed dir");
    fs::write(allowed.join("in"), b"reachable").expect("seed");

    // Kısıtlamadan ÖNCE her ikisi de okunabilir olmalı, yoksa test aşağıda
    // hiçbir şey kanıtlamaz.
    assert!(fs::read(allowed.join("in")).is_ok());
    assert!(
        fs::read("/etc/hostname").is_ok(),
        "the control path must be readable before hardening"
    );

    let report = match harden(&Policy::new().writing(&allowed)) {
        Ok(report) => report,
        Err(e @ (SandboxError::LandlockUnavailable | SandboxError::PerThreadOnly)) => {
            // Eski bir kernel ya da çok thread'li bir süreç. Reddedilmiş olması
            // TAM OLARAK istenen davranış. Ama bu yol sessizce geçilirse test
            // hiçbir şey kanıtlamamış olur, o yüzden Landlock'un GERÇEKTEN
            // koştuğu bir ortamda bunu bir başarısızlık say.
            assert!(
                std::env::var("ARGUS_SANDBOX_REQUIRE").is_err(),
                "enforcement was required but refused: {e}"
            );
            return;
        }
        Err(e) => panic!("hardening failed for an unexpected reason: {e}"),
    };

    assert!(report.no_new_privs, "no_new_privs must be set");
    assert!(report.not_dumpable, "the process must not be dumpable");
    assert!(
        report.is_enforced(),
        "a report that is not enforced must not be returned as success: {}",
        report.describe()
    );

    assert!(
        fs::read(allowed.join("in")).is_ok(),
        "the policy allowed this path"
    );
    assert!(
        fs::write(allowed.join("out"), b"still writable").is_ok(),
        "the policy allowed writing here"
    );

    assert!(
        fs::read("/etc/hostname").is_err(),
        "a path outside the policy must no longer be readable"
    );
    assert!(
        fs::read_dir("/").is_err(),
        "the root directory must no longer be listable"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn an_empty_policy_is_not_reported_as_enforcement() {
    // Hiçbir yol vermeyen bir politika hiçbir şeyi kısıtlamaz ve bunu
    // söylemelidir; `is_enforced` burada false olmak zorunda.
    let report = harden(&Policy::new()).expect("an empty policy still sets the prctls");
    assert!(!report.is_enforced());
    assert!(report.landlock_abi.is_none());
}
