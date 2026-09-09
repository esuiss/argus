use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    #[error("client_id must not be empty")]
    ClientIdEmpty,

    #[error("client_id is {len} bytes, maximum is {max}")]
    ClientIdTooLong { len: usize, max: usize },

    #[error("client_id contains a non-printable character (RFC 6749 App. A: *VSCHAR)")]
    ClientIdInvalidChar,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RedirectUriError {
    #[error("redirect_uri must be an absolute URI (RFC 6749 §3.1.2)")]
    NotAbsolute,

    #[error("redirect_uri must not contain a fragment (RFC 6749 §3.1.2)")]
    HasFragment,

    #[error("redirect_uri wildcards are not supported; register each URI exactly")]
    WildcardNotSupported,

    #[error(
        "redirect_uri scheme {scheme} is not allowed; use https, http on a loopback host, or a private-use scheme (RFC 8252 §7)"
    )]
    DisallowedScheme { scheme: String },

    #[error("plain http redirect_uri is only allowed on a loopback host (RFC 8252 §7.3)")]
    InsecureHttpHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResourceUriError {
    #[error("resource must be an absolute URI with a host (RFC 8707 §2)")]
    NotAbsolute,

    #[error("resource must not contain a fragment (RFC 8707 §2)")]
    HasFragment,

    #[error("resource scheme {scheme} is not allowed; MCP canonical URIs are http or https")]
    DisallowedScheme { scheme: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PkceError {
    #[error("unsupported code_challenge_method: {method}")]
    UnsupportedMethod { method: String },

    #[error("code_challenge is not valid BASE64URL")]
    MalformedChallenge,

    #[error("code_challenge decodes to {len} bytes, S256 requires 32")]
    ChallengeWrongLength { len: usize },

    #[error("code_verifier is {len} bytes, RFC 7636 §4.1 requires 43..=128")]
    VerifierWrongLength { len: usize },

    #[error("code_verifier contains a character outside the unreserved set")]
    VerifierInvalidChar,

    #[error("code_verifier does not match code_challenge")]
    VerifierMismatch,
}
