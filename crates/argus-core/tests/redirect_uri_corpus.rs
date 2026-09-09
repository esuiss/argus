//! `redirect_uri` eşleştirme regresyon corpus'u — snapshot testi.
//!
//! # Neden snapshot, neden tek tek `assert_eq!` değil
//!
//! Birim testleri "şu girdi şu sonucu vermeli" der; her biri ayrı bir iddiadır ve
//! yalnızca yazarının aklına gelen vakayı kapsar. Bu corpus ise **davranışın
//! tamamının fotoğrafını** çeker: eşleştirme mantığında yapılan herhangi bir
//! değişiklik, etkilediği HER satırla birlikte diff olarak görünür.
//!
//! §1 #24 için bu ayrım önemli. Karar "yalnızca tam dizge, tek istisna loopback
//! portu" diyor. Bir gün biri iyi niyetle "sondaki `/` farkını tolere edelim" derse,
//! bunu yakalayacak olan şey belirli bir birim testi değil — bu snapshot'taki
//! beklenmedik satırlardır.
//!
//! Corpus'a yeni satır eklemek serbesttir. Mevcut bir satırın sonucunun değişmesi
//! **bir karar değişikliğidir** ve snapshot'ı güncellemeden önce gerekçelendirilmelidir.

use core::fmt::Write as _;

use argus_core::{RedirectUri, RedirectUriMatch};

/// Kayıtlı URI'ler. Her biri gerçek bir dağıtım şeklini temsil eder.
const REGISTERED: &[&str] = &[
    "https://app.example.com/cb",
    "https://app.example.com/cb/",
    "http://127.0.0.1/callback",
    "http://[::1]/callback",
    "http://localhost/callback",
    "https://127.0.0.1/callback",
    "com.example.app:/oauth",
];

/// Sunulan URI'ler: meşru varyantlar ve bilinen saldırı şekilleri bir arada.
const PRESENTED: &[&str] = &[
    // Birebir aynılar
    "https://app.example.com/cb",
    "https://app.example.com/cb/",
    // authentik CVE-2024-52289: escape edilmemiş regex noktası
    "https://app0example.com/cb",
    // Sonek/önek genişletmeleri
    "https://app.example.com.evil.test/cb",
    "https://evil.test/https://app.example.com/cb",
    "https://app.example.com/cb/extra",
    "https://app.example.com/cb?x=1",
    "https://app.example.com:8443/cb",
    // Loopback: geçici portlar
    "http://127.0.0.1:3118/callback",
    "http://[::1]:51234/callback",
    "http://localhost:8080/callback",
    // Loopback gevşetmesinin sızmaması gereken yerler
    "https://127.0.0.1:3118/callback",
    "http://127.0.0.2:3118/callback",
    "http://127.0.0.1:3118/other",
    "http://evil.test:3118/callback",
    // Şema karışıklığı
    "com.example.app:/oauth",
    "com.example.app:/oauth?code=1",
];

fn describe(m: Option<RedirectUriMatch>) -> &'static str {
    match m {
        None => "-",
        Some(RedirectUriMatch::Exact) => "EXACT",
        Some(RedirectUriMatch::LoopbackPortIgnored) => "LOOPBACK",
    }
}

#[test]
fn redirect_uri_match_matrix() {
    let mut out = String::new();

    for registered in REGISTERED {
        let Ok(uri) = RedirectUri::register(*registered) else {
            let _ = writeln!(out, "{registered}\n  <kayit reddedildi>\n");
            continue;
        };

        let _ = writeln!(out, "{registered}   [loopback={}]", uri.is_loopback());
        for presented in PRESENTED {
            let verdict = describe(uri.match_presented(presented));
            if verdict != "-" {
                let _ = writeln!(out, "  {verdict:<9} {presented}");
            }
        }
        out.push('\n');
    }

    insta::assert_snapshot!(out);
}

/// Kayıt aşamasında reddedilenler ayrı bir snapshot: hangi girdinin hangi hatayı
/// verdiği de bir sözleşmedir (operatöre gösterilen mesaj buradan gelir).
#[test]
fn redirect_uri_registration_errors() {
    let inputs = [
        "https://*.example.com/cb",
        "https://example.com/*",
        "https://example.com/cb#frag",
        "/relative/cb",
        "not a uri",
        "",
    ];

    let mut out = String::new();
    for input in inputs {
        let result = match RedirectUri::register(input) {
            Ok(_) => "OK".to_owned(),
            Err(e) => e.to_string(),
        };
        let _ = writeln!(out, "{input:<28} -> {result}");
    }

    insta::assert_snapshot!(out);
}
