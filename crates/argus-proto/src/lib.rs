//! `argus-proto` — OAuth 2.1 / OIDC tel formatı.
//!
//! Bu crate **yalnızca temsil** eder: serileştirme, alan adları, sabitler.
//! Karar mantığı `argus-core`'dadır ve o crate bu crate'i tanımaz — bağımlılık
//! tek yönlüdür. Sebep §10: `argus-core` formel doğrulamanın girdiği katman ve
//! serde'ye bağlanmamalı.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod error;
pub mod jwks;
pub mod jwt;
pub mod token;

pub use discovery::AuthorizationServerMetadata;
pub use error::{OAuthError, OAuthErrorCode};
pub use jwks::{Jwk, JwkSet};
pub use jwt::{AccessTokenClaims, JwtError};
pub use token::TokenResponse;
