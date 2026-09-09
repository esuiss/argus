use subtle::ConstantTimeEq as _;

use crate::dpop::ReplayGuard;
use crate::id::ClientId;
use crate::time::{Duration, Timestamp};

#[derive(Clone, PartialEq, Eq)]
pub enum PresentedCredential {
    None,

    ClientSecret { client_id: ClientId, secret: String },

    VerifiedAssertion { client_id: ClientId },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    None,

    ClientSecretBasic,

    PrivateKeyJwt,
}

impl ClientAuthMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKey {
    pub kid: String,

    pub x: [u8; 32],

    pub y: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionClaims {
    pub issuer: String,

    pub subject: String,

    pub audience: Vec<String>,

    pub expires_at: Timestamp,

    pub jti: String,
}

pub const MAX_ASSERTION_LIFETIME: Duration = Duration::from_seconds(300);

pub fn validate_assertion(
    claims: &AssertionClaims,
    client: &ClientId,
    accepted_audiences: &[&str],
    now: Timestamp,
    replay: &impl ReplayGuard,
) -> Result<(), ClientAuthError> {
    if replay.seen(&claims.jti) {
        return Err(ClientAuthError::Replayed);
    }

    if claims.issuer != client.as_str() || claims.subject != client.as_str() {
        return Err(ClientAuthError::ClientMismatch);
    }

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

    if claims.expires_at.since(now).as_seconds() > MAX_ASSERTION_LIFETIME.as_seconds() {
        return Err(ClientAuthError::LifetimeTooLong);
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientAuthError {
    #[error("client authentication method does not match the registration")]
    MethodMismatch,

    #[error("client identity mismatch")]
    ClientMismatch,

    #[error("invalid client credential")]
    BadCredential,

    #[error("client authentication required")]
    Missing,

    #[error("the client assertion has already been used")]
    Replayed,

    #[error("the client assertion is not addressed to this server")]
    AudienceMismatch,

    #[error("the client assertion has expired")]
    Expired,

    #[error("the client assertion lifetime exceeds the accepted maximum")]
    LifetimeTooLong,
}

impl ClientAuthError {
    #[must_use]
    pub const fn oauth_error_code(&self) -> &'static str {
        "invalid_client"
    }
}

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

        (
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::PrivateKeyJwt,
            PresentedCredential::None,
        ) => Err(ClientAuthError::Missing),

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

    #[test]
    fn method_downgrade_and_upgrade_are_both_rejected() {
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
