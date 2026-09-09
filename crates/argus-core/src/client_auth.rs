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

use crate::id::ClientId;

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
