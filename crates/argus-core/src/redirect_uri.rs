//! `redirect_uri` kaydı ve eşleştirmesi.
//!
//! # Karar (§1 #24)
//!
//! Eşleştirme **yalnızca tam dizge**dir. Regex ve wildcard hiç implemente edilmez —
//! "opt-in tehlikeli özellik" olarak bile. authentik **CVE-2024-52289**: escape
//! edilmemiş bir regex noktası yüzünden `app.example.com` konfigürasyonu
//! `app0example.com` ile eşleşti ve kurban doğrudan saldırgana yönlendirildi.
//! RFC 9700 zaten tam eşleşmeyi zorunlu kılıyor.
//!
//! # Tek istisna: loopback
//!
//! Native uygulamalar geçici (ephemeral) bir porta bağlanır ve hangi portu
//! alacaklarını önceden bilemezler. RFC 8252 §7.3, IP-literal loopback için
//! **port bileşeninin yok sayılmasını** zorunlu kılar. Argus aynı esnekliği
//! `localhost` için de uygular — RFC 8252 §8.3 `localhost` kullanımını önermese de
//! gerçek istemciler (ör. Claude Code) bunu kullanıyor ve reddedersek bağlanamazlar.
//!
//! Bu bir wildcard **değildir**: yalnızca port serbesttir; şema, host ve yol yine
//! tam eşleşmek zorundadır.

use core::fmt;

use url::{Host, Url};

use crate::error::RedirectUriError;

/// Kayıtlı bir `redirect_uri`.
///
/// Kayıt anında doğrulanır, sonra değişmez. Doğrulama kuralları RFC 6749 §3.1.2'den:
/// mutlak URI olmalı ve fragment taşımamalıdır.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RedirectUri {
    /// Ayrıştırılmış hâl — loopback karşılaştırması için.
    parsed: Url,
    /// Kayıtta verilen ham dizge. Tam eşleşme **bunun** üzerinden yapılır:
    /// `Url` normalizasyonu (ör. sondaki `/` eklenmesi) karşılaştırmayı kaydırmasın.
    raw: String,
}

/// Bir `redirect_uri` eşleşmesinin nasıl kurulduğu.
///
/// Denetim kaydına yazılır: gevşetilmiş kuralla eşleşen her istek görünür olmalıdır.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectUriMatch {
    /// Ham dizgeler bayt bayt aynı.
    Exact,
    /// Loopback istisnası uygulandı: port dışında her şey aynı (RFC 8252 §7.3).
    LoopbackPortIgnored,
}

impl RedirectUri {
    /// Bir `redirect_uri`'yi kayıt için doğrular.
    ///
    /// # Errors
    ///
    /// - [`RedirectUriError::NotAbsolute`] — ayrıştırılamıyor veya göreli.
    /// - [`RedirectUriError::HasFragment`] — fragment içeriyor (RFC 6749 §3.1.2).
    /// - [`RedirectUriError::WildcardNotSupported`] — `*` içeriyor. Bu ayrı bir hata
    ///   çünkü sessizce reddedilirse operatör wildcard'ın çalıştığını sanabilir.
    pub fn register(raw: impl Into<String>) -> Result<Self, RedirectUriError> {
        let raw = raw.into();

        if raw.contains('*') {
            return Err(RedirectUriError::WildcardNotSupported);
        }

        let parsed = Url::parse(&raw).map_err(|_| RedirectUriError::NotAbsolute)?;

        if parsed.fragment().is_some() {
            return Err(RedirectUriError::HasFragment);
        }

        Ok(Self { parsed, raw })
    }

    /// Kayıtlı ham dizge.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Bu kayıt loopback gevşetmesine uygun mu?
    ///
    /// Koşullar birlikte sağlanmalı: şema `http` **ve** host loopback. `https` üzerinde
    /// gevşetme yok — loopback'te TLS gereksizdir ve `https` bir uzak host'a işaret
    /// ediyor olabilir.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        if self.parsed.scheme() != "http" {
            return false;
        }
        match self.parsed.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            // RFC 8252 §8.3 `localhost` önermiyor; yine de kabul ediyoruz, gerekçe
            // modül notunda.
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        }
    }

    /// Sunulan `redirect_uri`'nin bu kayıtla eşleşip eşleşmediğine karar verir.
    ///
    /// Eşleşme yoksa [`None`]. Çağıran bunu **kullanıcıyı yönlendirmeden** reddetmeli:
    /// doğrulanmamış bir `redirect_uri`'ye hata yönlendirmesi yapmak açık
    /// yönlendiricidir (RFC 9700).
    #[must_use]
    pub fn match_presented(&self, presented: &str) -> Option<RedirectUriMatch> {
        // 1. Tam dizge — ana yol, RFC 9700'ün istediği.
        if self.raw == presented {
            return Some(RedirectUriMatch::Exact);
        }

        // 2. Loopback istisnası. Yalnızca kayıt loopback ise değerlendirilir.
        if !self.is_loopback() {
            return None;
        }

        let other = Url::parse(presented).ok()?;
        if other.fragment().is_some() {
            return None;
        }

        // Port DIŞINDA her bileşen eşleşmeli. `host_str` yerine `host()` kullanıyoruz:
        // `Host` karşılaştırması IPv6'yı köşeli parantezden bağımsız normalize eder.
        let same_scheme = self.parsed.scheme() == other.scheme();
        let same_host = self.parsed.host() == other.host();
        let same_path = self.parsed.path() == other.path();
        let same_query = self.parsed.query() == other.query();

        // Sunulan taraf da loopback olmalı; aksi hâlde kayıtlı bir loopback,
        // uzak bir host'a eşleşebilirdi.
        let other_is_loopback = match other.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        };

        if same_scheme && same_host && same_path && same_query && other_is_loopback {
            Some(RedirectUriMatch::LoopbackPortIgnored)
        } else {
            None
        }
    }
}

impl fmt::Debug for RedirectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedirectUri({:?})", self.raw)
    }
}

impl fmt::Display for RedirectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{RedirectUri, RedirectUriMatch};
    use crate::error::RedirectUriError;

    fn reg(s: &str) -> RedirectUri {
        RedirectUri::register(s).unwrap()
    }

    #[test]
    fn exact_match_wins() {
        let uri = reg("https://app.example.com/cb");
        assert_eq!(
            uri.match_presented("https://app.example.com/cb"),
            Some(RedirectUriMatch::Exact)
        );
    }

    /// authentik CVE-2024-52289'un tam senaryosu: escape edilmemiş regex noktası
    /// `app.example.com` ile `app0example.com`'u eşleştirmişti.
    #[test]
    fn regex_dot_does_not_match_arbitrary_character() {
        let uri = reg("https://app.example.com/cb");
        assert_eq!(uri.match_presented("https://app0example.com/cb"), None);
    }

    #[test]
    fn no_prefix_or_suffix_matching() {
        let uri = reg("https://app.example.com/cb");
        for evil in [
            "https://app.example.com/cb/extra",
            "https://app.example.com/cb?x=1",
            "https://app.example.com.evil.test/cb",
            "https://evil.test/https://app.example.com/cb",
            "https://app.example.com:8443/cb",
        ] {
            assert_eq!(uri.match_presented(evil), None, "matched: {evil}");
        }
    }

    #[test]
    fn wildcard_is_rejected_at_registration() {
        assert_eq!(
            RedirectUri::register("https://*.example.com/cb").unwrap_err(),
            RedirectUriError::WildcardNotSupported
        );
    }

    #[test]
    fn fragment_is_rejected_at_registration() {
        assert_eq!(
            RedirectUri::register("https://app.example.com/cb#frag").unwrap_err(),
            RedirectUriError::HasFragment
        );
    }

    #[test]
    fn relative_uri_is_rejected() {
        assert_eq!(
            RedirectUri::register("/cb").unwrap_err(),
            RedirectUriError::NotAbsolute
        );
    }

    // --- Loopback istisnası (RFC 8252 §7.3) ---

    #[test]
    fn loopback_ipv4_ignores_port() {
        let uri = reg("http://127.0.0.1/callback");
        assert_eq!(
            uri.match_presented("http://127.0.0.1:3118/callback"),
            Some(RedirectUriMatch::LoopbackPortIgnored)
        );
    }

    #[test]
    fn loopback_ipv6_ignores_port() {
        let uri = reg("http://[::1]/callback");
        assert_eq!(
            uri.match_presented("http://[::1]:51234/callback"),
            Some(RedirectUriMatch::LoopbackPortIgnored)
        );
    }

    #[test]
    fn localhost_ignores_port() {
        let uri = reg("http://localhost/callback");
        assert_eq!(
            uri.match_presented("http://localhost:8080/callback"),
            Some(RedirectUriMatch::LoopbackPortIgnored)
        );
    }

    #[test]
    fn loopback_relaxation_does_not_cross_scheme_host_or_path() {
        let uri = reg("http://127.0.0.1/callback");
        for evil in [
            "https://127.0.0.1:3118/callback", // şema farklı
            "http://127.0.0.2:3118/callback",  // host farklı
            "http://127.0.0.1:3118/other",     // yol farklı
            "http://evil.test:3118/callback",  // loopback değil
            "http://127.0.0.1:3118/callback?x=1",
        ] {
            assert_eq!(uri.match_presented(evil), None, "matched: {evil}");
        }
    }

    #[test]
    fn https_loopback_gets_no_relaxation() {
        let uri = reg("https://127.0.0.1/callback");
        assert!(!uri.is_loopback());
        assert_eq!(uri.match_presented("https://127.0.0.1:3118/callback"), None);
    }

    #[test]
    fn non_loopback_never_gets_port_relaxation() {
        let uri = reg("https://app.example.com/cb");
        assert!(!uri.is_loopback());
        assert_eq!(uri.match_presented("https://app.example.com:9999/cb"), None);
    }
}
