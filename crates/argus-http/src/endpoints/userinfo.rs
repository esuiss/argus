use argus_core::dpop::{DEFAULT_PROOF_WINDOW, ReplayGuard, RequestBinding, VerifiedProof};
use argus_core::time::Timestamp;
use argus_crypto::{AwsLcSha256, VerifyingKey};
use argus_proto::jwt::AccessTokenClaims;
use argus_proto::{OAuthError, OAuthErrorCode, UserInfo};
use base64ct::{Base64UrlUnpadded, Encoding as _};

use crate::state::TenantContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserInfoError {
    MissingCredentials,

    InvalidToken,

    MissingProof,

    InvalidProof,
}

impl UserInfoError {
    #[must_use]
    pub const fn http_status(self) -> u16 {
        401
    }

    #[must_use]
    pub const fn challenge(self) -> &'static str {
        match self {
            Self::MissingCredentials => "Bearer",
            Self::InvalidToken => {
                r#"Bearer error="invalid_token", error_description="the access token is not valid""#
            }
            Self::MissingProof => {
                r#"DPoP error="invalid_token", error_description="a DPoP proof is required for this token", algs="ES256""#
            }
            Self::InvalidProof => {
                r#"DPoP error="invalid_token", error_description="the DPoP proof does not match this token or request", algs="ES256""#
            }
        }
    }

    #[must_use]
    pub const fn body(self) -> OAuthError {
        OAuthError::new(OAuthErrorCode::InvalidToken)
    }
}

fn credentials(raw: &str) -> Option<(Scheme, &str)> {
    let (scheme, token) = raw.split_once(' ')?;
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        Some((Scheme::Bearer, token))
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Some((Scheme::Dpop, token))
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Bearer,

    Dpop,
}

fn access_token_hash(access_token: &str) -> String {
    use argus_core::pkce::Sha256 as _;
    Base64UrlUnpadded::encode_string(&AwsLcSha256.sha256(access_token.as_bytes()))
}

fn verify_with_published_keys(
    tenant: &TenantContext,
    token: &str,
) -> Result<AccessTokenClaims, UserInfoError> {
    let keys: Vec<VerifyingKey> = tenant
        .published_keys
        .iter()
        .map(|k| k.verifying_key())
        .collect();

    keys.iter()
        .find_map(|key| argus_proto::jwt::verify(token, key).ok())
        .ok_or(UserInfoError::InvalidToken)
}

pub struct UserInfoRequest<'a> {
    pub authorization: Option<&'a str>,

    pub form_access_token: Option<&'a str>,

    pub dpop_proof: Option<&'a VerifiedProof>,

    pub method: &'a str,

    pub uri: &'a str,
}

pub fn handle(
    tenant: &TenantContext,
    request: &UserInfoRequest<'_>,
    now: Timestamp,
    replay: &impl ReplayGuard,
) -> Result<UserInfo, UserInfoError> {
    let (scheme, token) = match (request.authorization, request.form_access_token) {
        (Some(_), Some(_)) => return Err(UserInfoError::InvalidToken),
        (Some(header), None) => credentials(header).ok_or(UserInfoError::MissingCredentials)?,

        (None, Some(body)) if !body.trim().is_empty() => (Scheme::Bearer, body.trim()),
        _ => return Err(UserInfoError::MissingCredentials),
    };

    let claims = verify_with_published_keys(tenant, token)?;

    if claims.iss != tenant.metadata.issuer {
        return Err(UserInfoError::InvalidToken);
    }

    if claims.exp <= now.as_unix_seconds() {
        return Err(UserInfoError::InvalidToken);
    }

    match claims.cnf.as_ref() {
        Some(confirmation) => {
            if scheme != Scheme::Dpop {
                return Err(UserInfoError::MissingProof);
            }
            let Some(proof) = request.dpop_proof else {
                return Err(UserInfoError::MissingProof);
            };

            if proof.jkt != confirmation.jkt {
                return Err(UserInfoError::InvalidProof);
            }

            argus_core::dpop::validate(
                proof,
                &RequestBinding {
                    method: request.method.to_owned(),
                    uri: request.uri.to_owned(),
                },
                Some(&access_token_hash(token)),
                now,
                DEFAULT_PROOF_WINDOW,
                replay,
            )
            .map_err(|_| UserInfoError::InvalidProof)?;
        }

        None => {
            if scheme == Scheme::Dpop {
                return Err(UserInfoError::InvalidToken);
            }
        }
    }

    Ok(UserInfo { sub: claims.sub })
}
