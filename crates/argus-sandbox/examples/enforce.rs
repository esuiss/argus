//! Zorlamanın GERÇEKTEN uygulandığını ölçer.
//!
//! Ayrı bir ikili olmasının sebebi şu: Rust'ın test koşucusu çok thread'lidir
//! ve Landlock yalnızca çağıran thread'i kısıtlar, o yüzden bir test içinde
//! zorlama meşru olarak reddedilir. §11 C.4'ün anlattığı tam olarak bu tuzak.
//! Burada süreçte tek thread var ve kısıtlama sürecin tamamını kapsıyor.

fn main() -> std::process::ExitCode {
    use std::fs;

    let allowed = std::env::temp_dir().join("argus-enforce");
    if fs::create_dir_all(&allowed).is_err() {
        eprintln!("cannot prepare the allowed directory");
        return std::process::ExitCode::FAILURE;
    }
    if fs::write(allowed.join("in"), b"reachable").is_err() {
        eprintln!("cannot seed the allowed directory");
        return std::process::ExitCode::FAILURE;
    }

    // Kontrol yolu kısıtlamadan ÖNCE okunabilir olmalı, yoksa aşağıdaki
    // ölçüm hiçbir şey kanıtlamaz.
    if fs::read("/etc/hostname").is_err() {
        eprintln!("the control path was not readable to begin with");
        return std::process::ExitCode::FAILURE;
    }

    let policy = argus_sandbox::Policy::new().writing(&allowed);
    let report = match argus_sandbox::harden(&policy) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    println!("report: {}", report.describe());

    let mut failures = Vec::new();

    if !report.is_enforced() {
        failures.push("the report does not claim enforcement");
    }
    if fs::read(allowed.join("in")).is_err() {
        failures.push("the allowed path became unreadable");
    }
    if fs::write(allowed.join("out"), b"still writable").is_err() {
        failures.push("the allowed path became unwritable");
    }
    if fs::read("/etc/hostname").is_ok() {
        failures.push("a path outside the policy is still readable");
    }
    if fs::read_dir("/").is_ok() {
        failures.push("the root directory is still listable");
    }
    if fs::write("/tmp/argus-enforce-escape", b"nope").is_ok() {
        failures.push("writing outside the policy still succeeds");
    }

    if failures.is_empty() {
        println!("enforced");
        std::process::ExitCode::SUCCESS
    } else {
        for failure in failures {
            eprintln!("FAIL: {failure}");
        }
        std::process::ExitCode::FAILURE
    }
}
