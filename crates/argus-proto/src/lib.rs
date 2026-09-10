#![forbid(unsafe_code)]

pub mod cimd;
pub mod client_assertion;
pub mod discovery;
pub mod dpop;
pub mod error;
pub mod idjag;
pub mod jwks;
pub mod jwt;
pub mod oidc;
pub mod prm;
pub mod scim;
pub mod token;
pub mod webauthn;

pub use cimd::{ClientIdMetadataDocument, DocumentError, MAX_DOCUMENT_BYTES};
pub use client_assertion::{ASSERTION_TYPE, AssertionError};
pub use discovery::AuthorizationServerMetadata;
pub use dpop::{DpopParseError, jwk_thumbprint, parse_and_verify};
pub use error::{OAuthError, OAuthErrorCode};
pub use idjag::{IdJagClaims, sign_id_jag, verify_id_jag};
pub use jwks::{Jwk, JwkSet};
pub use jwt::{AccessTokenClaims, Audience, Confirmation, JwtError};
pub use oidc::{IdTokenClaims, UserInfo};
pub use prm::{ProtectedResourceMetadata, well_known_path};
pub use token::TokenResponse;
