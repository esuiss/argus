use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    InvalidRequest,

    InvalidClient,

    InvalidGrant,

    UnauthorizedClient,

    UnsupportedGrantType,

    InvalidScope,

    ServerError,

    TemporarilyUnavailable,

    InvalidToken,

    InvalidTarget,

    AuthorizationPending,

    SlowDown,

    ExpiredToken,

    AccessDenied,
}

impl OAuthErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::InvalidTarget => "invalid_target",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::AccessDenied => "access_denied",
        }
    }

    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::InvalidClient | Self::InvalidToken => 401,
            Self::ServerError => 500,
            Self::TemporarilyUnavailable => 503,
            _ => 400,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthError {
    pub error: OAuthErrorCode,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<&'static str>,
}

impl OAuthError {
    #[must_use]
    pub const fn new(error: OAuthErrorCode) -> Self {
        Self {
            error,
            error_description: None,
        }
    }

    #[must_use]
    pub const fn with_description(error: OAuthErrorCode, description: &'static str) -> Self {
        Self {
            error,
            error_description: Some(description),
        }
    }

    #[must_use]
    pub const fn http_status(&self) -> u16 {
        self.error.http_status()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{OAuthError, OAuthErrorCode};

    #[test]
    fn error_codes_serialize_to_the_wire_names() {
        let json = serde_json::to_string(&OAuthError::new(OAuthErrorCode::InvalidGrant)).unwrap();
        assert_eq!(json, r#"{"error":"invalid_grant"}"#);
    }

    #[test]
    fn description_is_omitted_when_absent() {
        let json = serde_json::to_string(&OAuthError::new(OAuthErrorCode::InvalidRequest)).unwrap();
        assert!(!json.contains("error_description"));
    }

    #[test]
    fn http_status_follows_rfc6749() {
        assert_eq!(OAuthErrorCode::InvalidClient.http_status(), 401);
        assert_eq!(OAuthErrorCode::InvalidGrant.http_status(), 400);
        assert_eq!(OAuthErrorCode::InvalidRequest.http_status(), 400);
        assert_eq!(OAuthErrorCode::ServerError.http_status(), 500);
        assert_eq!(OAuthErrorCode::TemporarilyUnavailable.http_status(), 503);
    }

    #[test]
    fn as_str_matches_serde_representation() {
        for code in [
            OAuthErrorCode::InvalidRequest,
            OAuthErrorCode::InvalidClient,
            OAuthErrorCode::InvalidGrant,
            OAuthErrorCode::UnauthorizedClient,
            OAuthErrorCode::UnsupportedGrantType,
            OAuthErrorCode::InvalidScope,
            OAuthErrorCode::ServerError,
            OAuthErrorCode::TemporarilyUnavailable,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }
}
