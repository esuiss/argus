use std::sync::Arc;
use std::time::Duration;

use argus_crypto::password::{PasswordError, Verdict};
use tokio::sync::Semaphore;

// §11 P0 #4 ve §9.5: parola login'i bir IdP'nin en pahalı işlemi ve fark
// neredeyse tamamen Argon2. Rauthy'nin `max_hash_threads=2` emsali aynı sorunun
// aynı cevabı.
//
// Üç şey birden gerekiyor:
//   1. `spawn_blocking` — Argon2 on milisaniyelerce CPU yakar. tokio çalışan
//      thread'inde koşarsa o thread boyunca BAŞKA HİÇBİR istek ilerlemez;
//      tek bir login akışı tüm sunucuyu durdurabilir.
//   2. Sınırlı eşzamanlılık — bellek tüketimi doğrudan buradan geliyor.
//      §9.5: pod bellek limiti = baseline + (max_concurrent × ~7 MB) + havuz.
//   3. Kuyruk dolunca 429, BEKLETME YOK (§9.5). Bekleyen bir istek hâlâ bellek
//      ve bir bağlantı tutar; reddetmek onu bırakır.
pub struct PasswordWork {
    permits: Arc<Semaphore>,
    concurrency: usize,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkRefusal {
    /// Kuyruk dolu. Çağıran 429 ve Retry-After döndürmeli.
    Saturated,
    /// İş başladı ama bütçesini aştı. Bu bir yapılandırma hatasının işaretidir,
    /// sıradan bir yük değil.
    TimedOut,
    Failed,
}

impl PasswordWork {
    #[must_use]
    pub fn new(concurrency: usize, timeout: Duration) -> Self {
        let concurrency = concurrency.max(1);
        Self {
            permits: Arc::new(Semaphore::new(concurrency)),
            concurrency,
            timeout,
        }
    }

    #[must_use]
    pub const fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Şu an kaç hash koşuyor. §11 G ve §24 #35: doygunluk görülemiyorsa
    /// operasyonel olarak kullanılamaz.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.concurrency
            .saturating_sub(self.permits.available_permits())
    }

    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "argon2(concurrency={} timeout={}ms)",
            self.concurrency,
            self.timeout.as_millis()
        )
    }

    async fn run<T, F>(&self, work: F) -> Result<T, WorkRefusal>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        // `try_acquire`, bekleyen değil reddeden davranıştır. §9.5 bunu açıkça
        // istiyor: "Kuyruk dolunca 429 + Retry-After, bekletme yok."
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| WorkRefusal::Saturated)?;

        let handle = tokio::task::spawn_blocking(move || {
            let outcome = work();
            drop(permit);
            outcome
        });

        match tokio::time::timeout(self.timeout, handle).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(WorkRefusal::Failed),
            Err(_) => Err(WorkRefusal::TimedOut),
        }
    }

    pub async fn verify(&self, password: &str, phc: &str) -> Result<Verdict, WorkRefusal> {
        let password = password.to_owned();
        let phc = phc.to_owned();

        self.run(move || argus_crypto::password::verify(&password, &phc))
            .await?
            // Bozuk bir PHC dizgesi doğru parola sayılmaz.
            .map_err(|_: PasswordError| WorkRefusal::Failed)
    }

    pub async fn hash(&self, password: &str) -> Result<String, WorkRefusal> {
        let password = password.to_owned();

        self.run(move || argus_crypto::password::hash(&password))
            .await?
            .map_err(|_: PasswordError| WorkRefusal::Failed)
    }
}

impl Default for PasswordWork {
    fn default() -> Self {
        // §9.5'in boyutlandırma çapası: parola login'i 15/s başına 1 vCPU.
        // Varsayılan muhafazakâr; operatör bellek bütçesinden türetmeli.
        Self::new(4, Duration::from_secs(5))
    }
}
