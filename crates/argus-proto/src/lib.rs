#![forbid(unsafe_code)]

pub mod client_assertion;
pub mod discovery;
pub mod dpop;
pub mod error;
pub mod jwks;
pub mod jwt;
pub mod oidc;
pub mod token;

pub use client_assertion::{ASSERTION_TYPE, AssertionError};
pub use discovery::AuthorizationServerMetadata;
pub use dpop::{DpopParseError, jwk_thumbprint, parse_and_verify};
pub use error::{OAuthError, OAuthErrorCode};
pub use jwks::{Jwk, JwkSet};
pub use jwt::{AccessTokenClaims, Confirmation, JwtError};
pub use oidc::{IdTokenClaims, UserInfo};
pub use token::TokenResponse;
