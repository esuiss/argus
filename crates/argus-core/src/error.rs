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
pub enum RpIdError {
    #[error("an RP ID must not be empty")]
    Empty,

    #[error("an RP ID is a bare domain: no scheme, port, path or IP literal")]
    NotABareDomain,

    #[error("the origin is not a URL")]
    MalformedOrigin,

    #[error("a WebAuthn origin must be https, or http on a loopback host")]
    InsecureOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClientIdUrlError {
    #[error("client_id is not a URL")]
    NotAUrl,

    #[error("a Client Identifier URL must use https (CIMD §3)")]
    NotHttps,

    #[error("a Client Identifier URL must not contain userinfo (CIMD §3)")]
    HasUserinfo,

    #[error("a Client Identifier URL must not contain a fragment (CIMD §3)")]
    HasFragment,

    #[error("a Client Identifier URL must have a path component (CIMD §3)")]
    NoPath,

    #[error("a Client Identifier URL must not contain . or .. path segments (CIMD §3)")]
    DottedPathSegment,

    #[error("a Client Identifier URL must name a routable host, not localhost or an IP literal")]
    NotRoutable,
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
