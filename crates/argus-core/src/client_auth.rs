//! İstemci kimlik doğrulaması — RFC 6749 §2.3.
//!
//! # Neden `client_secret_post` yok
//!
//! RFC 6749 §2.3.1 onu "MAY" olarak tanımlar ve **önermez**: sır istek gövdesine
//! girer, dolayısıyla proxy log'larına, hata izlerine ve tarayıcı geçmişine düşme
//! yüzeyi büyür. Argus onu temsil etmiyor, dolayısıyla kabul eden bir kod yolu
//! yazılamıyor.
//!
//! # Public client'lar
//!
//! [`ClientAuthMethod::None`] meşrudur (RFC 6749 §2.1) ama PKCE zorunludur ve o
//! zorunluluk authorization code akışında zaten yapısaldır: `code_verifier`
//! olmadan kod tüketilemez.

use subtle::ConstantTimeEq as _;

use crate::dpop::ReplayGuard;
use crate::id::ClientId;
use crate::time::{Duration, Timestamp};

/// İstekle sunulan kimlik bilgisi.
///
/// `Debug` **elle yazıldı**: türetilmiş olsaydı `secret` alanı düz metin olarak
/// log'a düşerdi (§25 K27).
#[derive(Clone, PartialEq, Eq)]
pub enum PresentedCredential {
    /// Hiçbir kimlik bilgisi sunulmadı.
    None,
    /// `Authorization: Basic` içinden çözülmüş sır.
    ClientSecret {
        /// Sunulan istemci kimliği.
        client_id: ClientId,
        /// Sunulan sır.
        secret: String,
    },
    /// Doğrulanmış bir `private_key_jwt` assertion'ı.
    ///
    /// İmza doğrulaması bu katmanda **yapılmaz** — `VerifiedProof` ile aynı
    /// desen: bu varyant yalnızca imzası doğrulanmış bir assertion için kurulur.
    VerifiedAssertion {
        /// Assertion'ın `sub` claim'i.
        client_id: ClientId,
    },
}

impl core::fmt::Debug for PresentedCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => f.write_str("PresentedCredential::None"),
            Self::ClientSecret { client_id, .. } => f
                .debug_struct("PresentedCredential::ClientSecret")
                .field("client_id", client_id)
                .field("secret", &"<redacted>")
                .finish(),
            Self::VerifiedAssertion { client_id } => f
                .debug_struct("PresentedCredential::VerifiedAssertion")
                .field("client_id", client_id)
                .finish(),
        }
    }
}

/// Kayıtlı istemcinin kimlik doğrulama yöntemi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// Public client — sır yok, PKCE ile korunur.
    None,
    /// `Authorization: Basic` başlığıyla client secret.
    ClientSecretBasic,
    /// RFC 7523 `private_key_jwt`.
    PrivateKeyJwt,
}

impl ClientAuthMethod {
    /// Metadata'da ilan edilen ad.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

/// Kayıtlı bir istemcinin açık imzalama anahtarı.
///
/// # Neden `JWK` değil, ham bileşenler
///
/// `argus-core` serileştirme biçimlerini tanımaz; `JWK` bir tel formatıdır ve
/// onu buraya sokmak, saf karar katmanını bir kodlama seçimine bağlardı.
/// Bileşenler `P-256` için sabit 32 baytlıktır — tip düzeyinde boyut hatası
/// imkânsız.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKey {
    /// Anahtar kimliği; `JWS` başlığındaki `kid` ile eşleşir.
    pub kid: String,
    /// `P-256` açık anahtarının `x` bileşeni.
    pub x: [u8; 32],
    /// `P-256` açık anahtarının `y` bileşeni.
    pub y: [u8; 32],
}

/// `private_key_jwt` assertion'ının claim'leri — `RFC` 7523 §3.
///
/// İmzası **doğrulanmış** bir assertion'dan çıkarılır; bu tip yalnızca imza
/// kontrolünden sonra kurulur (`VerifiedProof` ile aynı desen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionClaims {
    /// `iss` — `RFC` 7523 §3: istemcinin kendisi.
    pub issuer: String,
    /// `sub` — `RFC` 7523 §3: yine istemcinin kendisi.
    pub subject: String,
    /// `aud` — yetkilendirme sunucusu.
    pub audience: Vec<String>,
    /// `exp`.
    pub expires_at: Timestamp,
    /// `jti` — tekrar tespiti için.
    pub jti: String,
}

/// Assertion'ın azami kabul edilen ömrü.
///
/// `RFC` 7523 §3 bir üst sınır koymaz ama uzun ömürlü bir assertion, çalındığında
/// uzun süre kullanılabilir bir istemci kimlik bilgisidir. `RFC` 9700 §2.2.1'in
/// "kısa ömürlü tut" tavsiyesiyle uyumlu muhafazakâr bir tavan.
pub const MAX_ASSERTION_LIFETIME: Duration = Duration::from_seconds(300);

/// Assertion claim kurallarını uygular.
///
/// İmza bu fonksiyonun işi DEĞİLDİR: `claims` yalnızca imzası doğrulanmış bir
/// assertion'dan kurulabilir. Buradaki kontroller imzanın söylemediği her şeyi
/// kapatır — assertion'ın kime, hangi sunucu için ve ne zamana kadar geçerli
/// olduğunu imza değil claim'ler söyler.
///
/// # Errors
///
/// `iss`/`sub` istemciyle uyuşmazsa, `aud` bu sunucuyu göstermiyorsa, süre
/// dolmuş ya da makul olmayacak kadar uzunsa, veya `jti` tekrar edilmişse.
pub fn validate_assertion(
    claims: &AssertionClaims,
    client: &ClientId,
    accepted_audiences: &[&str],
    now: Timestamp,
    replay: &impl ReplayGuard,
) -> Result<(), ClientAuthError> {
    // Tekrar en başta: geçersiz bir assertion'ın bile tekrar edildiğini bilmek
    // isteriz.
    if replay.seen(&claims.jti) {
        return Err(ClientAuthError::Replayed);
    }

    // `RFC` 7523 §3: `iss` ve `sub` İKİSİ DE istemci olmalı. Yalnızca birini
    // kontrol etmek, bir istemcinin başkası adına assertion üretmesine kapı açar.
    if claims.issuer != client.as_str() || claims.subject != client.as_str() {
        return Err(ClientAuthError::ClientMismatch);
    }

    // `aud` olmadan, bir sunucu için üretilmiş assertion başka bir sunucuya
    // yeniden sunulabilir (cross-AS replay). Bu kontrol `RFC` 7523'ün tek
    // gerçek koruma noktasıdır.
    if !claims
        .audience
        .iter()
        .any(|a| accepted_audiences.contains(&a.as_str()))
    {
        return Err(ClientAuthError::AudienceMismatch);
    }

    if claims.expires_at.as_unix_seconds() <= now.as_unix_seconds() {
        return Err(ClientAuthError::Expired);
    }

    // Aşırı uzun ömür, çalınmış bir assertion'ı kalıcı bir kimlik bilgisine
    // çevirir.
    if claims.expires_at.since(now).as_seconds() > MAX_ASSERTION_LIFETIME.as_seconds() {
        return Err(ClientAuthError::LifetimeTooLong);
    }

    Ok(())
}

/// İstemci kimlik doğrulama hataları.
///
/// Hepsi istemciye `invalid_client` olarak döner (RFC 6749 §5.2); ayrım denetim
/// kaydı içindir.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientAuthError {
    /// Sunulan yöntem kayıtlı yöntemle uyuşmuyor.
    ///
    /// İstemci `none` ile kayıtlıyken sır sunması ya konfigürasyon hatasıdır ya
    /// da bir saldırı denemesi; ikisi de kabul edilmemeli.
    #[error("client authentication method does not match the registration")]
    MethodMismatch,

    /// Sunulan `client_id` beklenenle uyuşmuyor.
    #[error("client identity mismatch")]
    ClientMismatch,

    /// Sır yanlış.
    #[error("invalid client credential")]
    BadCredential,

    /// Kimlik bilgisi gerekiyordu ama sunulmadı.
    #[error("client authentication required")]
    Missing,

    /// Assertion'ın `jti`'si daha önce görüldü.
    #[error("the client assertion has already been used")]
    Replayed,

    /// Assertion başka bir yetkilendirme sunucusu için üretilmiş.
    #[error("the client assertion is not addressed to this server")]
    AudienceMismatch,

    /// Assertion'ın süresi dolmuş.
    #[error("the client assertion has expired")]
    Expired,

    /// Assertion makul olmayacak kadar uzun ömürlü.
    #[error("the client assertion lifetime exceeds the accepted maximum")]
    LifetimeTooLong,
}

impl ClientAuthError {
    /// İstemciye dönecek OAuth hata kodu.
    #[must_use]
    pub const fn oauth_error_code(&self) -> &'static str {
        "invalid_client"
    }
}

/// İstemciyi doğrular.
///
/// `expected_secret_hash` kayıtlı sırrın hash'idir; ham sır **hiçbir zaman**
/// saklanmaz. Karşılaştırma sabit zamanlıdır: §8, `client_secret`
/// karşılaştırmasını sabit zaman gerektiren maddeler arasında **"Evet"** olarak
/// işaretliyor. Buradaki sızıntı PKCE'dekinden daha tehlikelidir çünkü client
/// secret düşük entropili olabilir.
///
/// # Errors
///
/// Yöntem uyuşmazsa, kimlik uyuşmazsa veya sır yanlışsa.
pub fn authenticate(
    client: &ClientId,
    registered: ClientAuthMethod,
    presented: &PresentedCredential,
    expected_secret_hash: Option<&[u8; 32]>,
    hash_of: impl Fn(&str) -> [u8; 32],
) -> Result<(), ClientAuthError> {
    match (registered, presented) {
        (ClientAuthMethod::None, PresentedCredential::None) => Ok(()),

        (
            ClientAuthMethod::ClientSecretBasic,
            PresentedCredential::ClientSecret { client_id, secret },
        ) => {
            if client_id != client {
                return Err(ClientAuthError::ClientMismatch);
            }
            let expected = expected_secret_hash.ok_or(ClientAuthError::BadCredential)?;
            if hash_of(secret).ct_eq(expected).into() {
                Ok(())
            } else {
                Err(ClientAuthError::BadCredential)
            }
        }

        (ClientAuthMethod::PrivateKeyJwt, PresentedCredential::VerifiedAssertion { client_id }) => {
            if client_id == client {
                Ok(())
            } else {
                Err(ClientAuthError::ClientMismatch)
            }
        }

        // Kimlik bilgisi gerekiyordu ama gelmedi.
        (
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::PrivateKeyJwt,
            PresentedCredential::None,
        ) => Err(ClientAuthError::Missing),

        // Yöntem karışıklığı: kayıtlı olanla sunulan tutmuyor.
        _ => Err(ClientAuthError::MethodMismatch),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{ClientAuthError, ClientAuthMethod, PresentedCredential, authenticate};
    use crate::id::ClientId;

    fn client() -> ClientId {
        ClientId::new("acme-web").expect("client")
    }

    fn other() -> ClientId {
        ClientId::new("other-app").expect("client")
    }

    /// Test hash'i — gerçek SHA-256 değil, yalnızca eşleşme davranışını sınar.
    fn fake_hash(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in s.bytes().take(32).enumerate() {
            if let Some(slot) = out.get_mut(i) {
                *slot = b;
            }
        }
        out
    }

    #[test]
    fn public_client_needs_no_credential() {
        assert!(
            authenticate(
                &client(),
                ClientAuthMethod::None,
                &PresentedCredential::None,
                None,
                fake_hash
            )
            .is_ok()
        );
    }

    #[test]
    fn correct_secret_authenticates() {
        let expected = fake_hash("s3cret");
        assert!(
            authenticate(
                &client(),
                ClientAuthMethod::ClientSecretBasic,
                &PresentedCredential::ClientSecret {
                    client_id: client(),
                    secret: "s3cret".to_owned(),
                },
                Some(&expected),
                fake_hash
            )
            .is_ok()
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let expected = fake_hash("s3cret");
        assert_eq!(
            authenticate(
                &client(),
                ClientAuthMethod::ClientSecretBasic,
                &PresentedCredential::ClientSecret {
                    client_id: client(),
                    secret: "wrong".to_owned(),
                },
                Some(&expected),
                fake_hash
            )
            .unwrap_err(),
            ClientAuthError::BadCredential
        );
    }

    /// Doğru sırrı başka bir istemcinin kimliğiyle sunmak çalışmamalı.
    #[test]
    fn credential_is_bound_to_the_client_id() {
        let expected = fake_hash("s3cret");
        assert_eq!(
            authenticate(
                &client(),
                ClientAuthMethod::ClientSecretBasic,
                &PresentedCredential::ClientSecret {
                    client_id: other(),
                    secret: "s3cret".to_owned(),
                },
                Some(&expected),
                fake_hash
            )
            .unwrap_err(),
            ClientAuthError::ClientMismatch
        );
    }

    /// Yöntem karışıklığı iki yönde de reddedilir.
    #[test]
    fn method_downgrade_and_upgrade_are_both_rejected() {
        // Public kayıtlı, sır sunuyor.
        assert_eq!(
            authenticate(
                &client(),
                ClientAuthMethod::None,
                &PresentedCredential::ClientSecret {
                    client_id: client(),
                    secret: "x".to_owned(),
                },
                None,
                fake_hash
            )
            .unwrap_err(),
            ClientAuthError::MethodMismatch
        );

        // Gizli kayıtlı, hiçbir şey sunmuyor.
        assert_eq!(
            authenticate(
                &client(),
                ClientAuthMethod::ClientSecretBasic,
                &PresentedCredential::None,
                None,
                fake_hash
            )
            .unwrap_err(),
            ClientAuthError::Missing
        );
    }

    #[test]
    fn private_key_jwt_matches_on_client_id() {
        assert!(
            authenticate(
                &client(),
                ClientAuthMethod::PrivateKeyJwt,
                &PresentedCredential::VerifiedAssertion {
                    client_id: client()
                },
                None,
                fake_hash
            )
            .is_ok()
        );

        assert_eq!(
            authenticate(
                &client(),
                ClientAuthMethod::PrivateKeyJwt,
                &PresentedCredential::VerifiedAssertion { client_id: other() },
                None,
                fake_hash
            )
            .unwrap_err(),
            ClientAuthError::ClientMismatch
        );
    }

    /// §25 K27: sır `Debug`'da görünmemeli.
    #[test]
    fn debug_redacts_the_secret() {
        let c = PresentedCredential::ClientSecret {
            client_id: client(),
            secret: "SUPER-SECRET".to_owned(),
        };
        let shown = format!("{c:?}");
        assert!(!shown.contains("SUPER-SECRET"), "leaked: {shown}");
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn all_errors_surface_as_invalid_client() {
        for e in [
            ClientAuthError::MethodMismatch,
            ClientAuthError::ClientMismatch,
            ClientAuthError::BadCredential,
            ClientAuthError::Missing,
        ] {
            assert_eq!(e.oauth_error_code(), "invalid_client");
        }
    }
}
