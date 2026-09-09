//! `argus-core` — Argus'un saf iş mantığı çekirdeği.
//!
//! # Bu crate'te ne YOK
//!
//! Hiçbir girdi/çıktı. Ne veritabanı, ne HTTP, ne dosya sistemi, ne soket, ne de
//! bir çalışma zamanı. Bu bir üslup tercihi değil, **§1 karar #15**:
//!
//! > Formel doğrulamanın tek girebileceği yer burasıdır; sonradan I/O'yu sökemezsin.
//!
//! Kural CI'da ve `.claude/hooks/invariant-guard.sh` içinde mekanik olarak zorlanır.
//! Bir karara veri lazımsa **çağıran** onu getirir ve parametre olarak verir; çekirdek
//! kendisi gidip almaz.
//!
//! # Bu crate'te ne VAR
//!
//! Kimlik tipleri, durum makineleri ve karar fonksiyonları. Hepsi saf: aynı girdi
//! daima aynı çıktıyı verir, yan etkisi yoktur, test edilmesi için hiçbir altyapı
//! gerekmez.

// `Cargo.toml` zaten `unsafe_code = "forbid"` uyguluyor. Attribute ayrıca
// yazılıyor çünkü kaynak dosyayı okuyan araçlar (cargo-geiger) lint tablosunu
// görmüyor — Faz 0 çıkış kriteri o araçla ifade edilmiş.
#![forbid(unsafe_code)]

pub mod authorize;
pub mod authz_code;
pub mod client_auth;
pub mod dpop;
pub mod effect;
pub mod epoch;
pub mod error;
pub mod id;
pub mod pkce;
pub mod redirect_uri;
pub mod refresh;
pub mod time;

pub use authorize::{AuthorizeOutcome, AuthorizeRequest, RegisteredClient};
pub use authz_code::{AuthorizationCode, Decision, Grant, StoredCode, TokenRequest};
pub use client_auth::{ClientAuthError, ClientAuthMethod, PresentedCredential};
pub use dpop::{DpopError, RequestBinding, VerifiedProof};
pub use effect::Effect;
pub use epoch::{AuthzEpoch, KeyEpoch, SessionEpoch};
pub use error::{IdError, PkceError, RedirectUriError};
pub use id::{ClientId, TenantId, UserId};
pub use pkce::{CodeChallenge, CodeChallengeMethod, Sha256};
pub use redirect_uri::{RedirectUri, RedirectUriMatch};
pub use refresh::{FamilyId, RefreshDecision, RefreshRequest, RefreshToken};
pub use time::{Duration, Timestamp};
