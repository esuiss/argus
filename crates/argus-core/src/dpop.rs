//! `DPoP` kanıt doğrulaması — RFC 9449.
//!
//! # Neden önemli
//!
//! §1 §4.1: **bearer varsayılan değildir.** Bearer token'ın tek koşulu ona sahip
//! olmaktır; çalınan bir token saldırganın elinde meşru istemciyle aynı şeyi
//! yapar. `DPoP`, token'ı istemcinin **özel anahtarına** bağlar: token'ı çalmak
//! yetmez, anahtarı da çalmak gerekir.
//!
//! # Bu modülün sınırı
//!
//! Burada **imza doğrulanmaz** — o kripto işidir ve `argus-core` kripto taşımaz.
//! Bu modül, imzası **zaten doğrulanmış** bir kanıtın claim'lerinin kurallara
//! uyup uymadığına bakar. Çağıran sırayı bozarsa (önce claim, sonra imza)
//! doğrulanmamış veriye göre karar vermiş olur; bu yüzden [`validate`] imzanın
//! doğrulandığını **tip düzeyinde** ister.

use crate::time::{Duration, Timestamp};

/// Kanıtın kabul edildiği zaman penceresi.
///
/// RFC 9449 §4.3 "reasonably recent" diyor, sayı vermiyor. 60 saniye, saat
/// kaymasına tolerans tanırken çalınmış bir kanıtın kullanılabileceği pencereyi
/// dar tutar.
pub const DEFAULT_PROOF_WINDOW: Duration = Duration::from_seconds(60);

/// İmzası **doğrulanmış** bir `DPoP` kanıtı.
///
/// Bu tip yalnızca imza doğrulandıktan sonra kurulabilir: [`VerifiedProof::new`]
/// çağıran katmanın (`argus-proto` + `argus-crypto`) sorumluluğundadır ve
/// buradaki hiçbir fonksiyon imzasız bir kanıt kabul etmez.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// `jti` — tekrar tespiti için benzersiz kimlik.
    pub jti: String,
    /// `htm` — kanıtın bağlandığı `HTTP` metodu.
    pub htm: String,
    /// `htu` — kanıtın bağlandığı `HTTP` URI'si (query ve fragment hariç).
    pub htu: String,
    /// `iat` — kanıtın üretilme anı.
    pub iat: Timestamp,
    /// `ath` — access token'ın hash'i; kaynak sunucuya giden kanıtlarda zorunlu.
    pub ath: Option<String>,
    /// Kanıtı imzalayan anahtarın `JWK` thumbprint'i (RFC 7638), BASE64URL.
    ///
    /// Token'a `cnf.jkt` olarak yazılır ve bağlamayı kuran şey budur.
    pub jkt: String,
}

impl VerifiedProof {
    /// İmzası doğrulanmış bir kanıt kurar.
    ///
    /// # Sözleşme
    ///
    /// Çağıran, bu tipi kurmadan **önce** kanıtın imzasını, `typ` başlığının
    /// `dpop+jwt` olduğunu ve `alg`'ın izinli olduğunu doğrulamış olmalıdır.
    #[must_use]
    pub const fn new(
        jti: String,
        htm: String,
        htu: String,
        iat: Timestamp,
        ath: Option<String>,
        jkt: String,
    ) -> Self {
        Self {
            jti,
            htm,
            htu,
            iat,
            ath,
            jkt,
        }
    }
}

/// İsteğin, kanıtın bağlanması gereken hâli.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBinding {
    /// `HTTP` metodu, büyük harf.
    pub method: String,
    /// İstek URI'si — query ve fragment **çıkarılmış** hâlde (RFC 9449 §4.3).
    pub uri: String,
}

/// `DPoP` doğrulama hataları.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpopError {
    /// `htm` istekteki metotla eşleşmiyor.
    #[error("DPoP proof is bound to a different HTTP method")]
    MethodMismatch,

    /// `htu` istekteki URI ile eşleşmiyor.
    ///
    /// Bu, kanıtın başka bir endpoint'ten kopyalanmasını engeller: `/token` için
    /// üretilmiş bir kanıt kaynak sunucuda kullanılamaz.
    #[error("DPoP proof is bound to a different URI")]
    UriMismatch,

    /// `iat` kabul penceresinin dışında.
    #[error("DPoP proof is outside the acceptable time window")]
    StaleProof,

    /// `iat` gelecekte.
    ///
    /// Saat kayması için küçük bir tolerans tanınır; ötesi, kanıtın önceden
    /// üretilip saklandığını gösterir.
    #[error("DPoP proof is dated in the future")]
    FutureProof,

    /// `jti` daha önce görülmüş — tekrar.
    #[error("DPoP proof has already been used")]
    Replayed,

    /// Kanıt bir access token'a bağlı değil ama olması gerekiyordu.
    #[error("DPoP proof is missing the access token hash")]
    MissingTokenHash,

    /// `ath` sunulan access token'la eşleşmiyor.
    #[error("DPoP proof is bound to a different access token")]
    TokenHashMismatch,
}

/// Kanıtın tekrar edilip edilmediğini söyleyen sınır.
///
/// `argus-core` I/O yapmadığı için tekrar kaydı burada tutulamaz; çağıran
/// (`Redis`/Postgres) sağlar. §6 §4.4: `jti` replay koruması, Bloom/cuckoo
/// filtrenin tek meşru kullanım alanı — yanlış pozitifin bedeli tek bir isteğin
/// reddi, kullanıcı çıkışı değil.
pub trait ReplayGuard {
    /// `jti` daha önce görüldüyse `true`.
    fn seen(&self, jti: &str) -> bool;
}

/// Bir `DPoP` kanıtını isteğe karşı doğrular.
///
/// Saf fonksiyon: saate bakmaz, hiçbir şey yazmaz. `now` ve tekrar kaydı dışarıdan
/// gelir.
///
/// # Errors
///
/// Kanıt istekle eşleşmiyorsa, penceresi geçmişse veya tekrar edilmişse.
pub fn validate(
    proof: &VerifiedProof,
    binding: &RequestBinding,
    expected_token_hash: Option<&str>,
    now: Timestamp,
    window: Duration,
    replay: &impl ReplayGuard,
) -> Result<(), DpopError> {
    // Tekrar en başta: geçersiz bir kanıtın bile tekrar edildiğini bilmek isteriz.
    if replay.seen(&proof.jti) {
        return Err(DpopError::Replayed);
    }

    if proof.htm != binding.method {
        return Err(DpopError::MethodMismatch);
    }

    if proof.htu != binding.uri {
        return Err(DpopError::UriMismatch);
    }

    // Gelecek tarihli kanıt: saat kayması için pencere kadar tolerans.
    if proof.iat.since(now).as_seconds() > window.as_seconds() {
        return Err(DpopError::FutureProof);
    }

    if now.since(proof.iat).as_seconds() > window.as_seconds() {
        return Err(DpopError::StaleProof);
    }

    // Kaynak sunucuya giden kanıt access token'a bağlanmalıdır (RFC 9449 §4.3).
    if let Some(expected) = expected_token_hash {
        let Some(actual) = proof.ath.as_deref() else {
            return Err(DpopError::MissingTokenHash);
        };
        if actual != expected {
            return Err(DpopError::TokenHashMismatch);
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        DEFAULT_PROOF_WINDOW, DpopError, ReplayGuard, RequestBinding, VerifiedProof, validate,
    };
    use crate::time::{Duration, Timestamp};

    const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);

    struct NeverSeen;
    impl ReplayGuard for NeverSeen {
        fn seen(&self, _jti: &str) -> bool {
            false
        }
    }

    struct AlwaysSeen;
    impl ReplayGuard for AlwaysSeen {
        fn seen(&self, _jti: &str) -> bool {
            true
        }
    }

    fn proof() -> VerifiedProof {
        VerifiedProof::new(
            "jti-1".to_owned(),
            "POST".to_owned(),
            "https://acme.argus.test/token".to_owned(),
            NOW,
            None,
            "thumbprint".to_owned(),
        )
    }

    fn binding() -> RequestBinding {
        RequestBinding {
            method: "POST".to_owned(),
            uri: "https://acme.argus.test/token".to_owned(),
        }
    }

    fn go(p: &VerifiedProof, now: Timestamp) -> Result<(), DpopError> {
        validate(p, &binding(), None, now, DEFAULT_PROOF_WINDOW, &NeverSeen)
    }

    #[test]
    fn a_matching_proof_is_accepted() {
        assert!(go(&proof(), NOW).is_ok());
    }

    /// Kanıt metoda bağlıdır: `POST /token` için üretilmiş bir kanıt `GET` ile
    /// kullanılamaz.
    #[test]
    fn method_must_match() {
        let b = RequestBinding {
            method: "GET".to_owned(),
            ..binding()
        };
        assert_eq!(
            validate(&proof(), &b, None, NOW, DEFAULT_PROOF_WINDOW, &NeverSeen).unwrap_err(),
            DpopError::MethodMismatch
        );
    }

    /// Kanıt URI'ye bağlıdır: token endpoint'i için üretilmiş bir kanıt kaynak
    /// sunucuda kullanılamaz. Bu, kanıtın kopyalanmasını engelleyen asıl kuraldır.
    #[test]
    fn uri_must_match() {
        let b = RequestBinding {
            uri: "https://api.acme.test/data".to_owned(),
            ..binding()
        };
        assert_eq!(
            validate(&proof(), &b, None, NOW, DEFAULT_PROOF_WINDOW, &NeverSeen).unwrap_err(),
            DpopError::UriMismatch
        );
    }

    #[test]
    fn stale_proofs_are_rejected() {
        let late = Timestamp::from_unix_seconds(
            NOW.as_unix_seconds() + DEFAULT_PROOF_WINDOW.as_seconds() + 1,
        );
        assert_eq!(go(&proof(), late).unwrap_err(), DpopError::StaleProof);
    }

    #[test]
    fn proofs_at_the_window_edge_are_still_accepted() {
        let edge =
            Timestamp::from_unix_seconds(NOW.as_unix_seconds() + DEFAULT_PROOF_WINDOW.as_seconds());
        assert!(go(&proof(), edge).is_ok());
    }

    /// Önceden üretilip saklanmış kanıtlar reddedilir; saat kayması için pencere
    /// kadar tolerans var.
    #[test]
    fn future_dated_proofs_are_rejected() {
        let early = Timestamp::from_unix_seconds(
            NOW.as_unix_seconds() - DEFAULT_PROOF_WINDOW.as_seconds() - 1,
        );
        assert_eq!(go(&proof(), early).unwrap_err(), DpopError::FutureProof);
    }

    #[test]
    fn replayed_proofs_are_rejected() {
        assert_eq!(
            validate(
                &proof(),
                &binding(),
                None,
                NOW,
                DEFAULT_PROOF_WINDOW,
                &AlwaysSeen
            )
            .unwrap_err(),
            DpopError::Replayed
        );
    }

    /// Kaynak sunucuya giden kanıt access token'a bağlı olmalı.
    #[test]
    fn access_token_binding_is_enforced_when_required() {
        // `ath` yok ama isteniyor.
        assert_eq!(
            validate(
                &proof(),
                &binding(),
                Some("expected-hash"),
                NOW,
                DEFAULT_PROOF_WINDOW,
                &NeverSeen
            )
            .unwrap_err(),
            DpopError::MissingTokenHash
        );

        // `ath` var ama başka bir token'a ait.
        let mut p = proof();
        p.ath = Some("other-hash".to_owned());
        assert_eq!(
            validate(
                &p,
                &binding(),
                Some("expected-hash"),
                NOW,
                DEFAULT_PROOF_WINDOW,
                &NeverSeen
            )
            .unwrap_err(),
            DpopError::TokenHashMismatch
        );

        // Doğru bağlama.
        p.ath = Some("expected-hash".to_owned());
        assert!(
            validate(
                &p,
                &binding(),
                Some("expected-hash"),
                NOW,
                DEFAULT_PROOF_WINDOW,
                &NeverSeen
            )
            .is_ok()
        );
    }

    /// Pencere yapılandırılabilir; sıfır pencere yalnızca aynı saniyeyi kabul eder.
    #[test]
    fn the_window_is_configurable() {
        let one_second_late = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 1);
        assert_eq!(
            validate(
                &proof(),
                &binding(),
                None,
                one_second_late,
                Duration::from_seconds(0),
                &NeverSeen
            )
            .unwrap_err(),
            DpopError::StaleProof
        );
    }
}
