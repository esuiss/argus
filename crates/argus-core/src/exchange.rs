use crate::id::ClientId;
use crate::resource::ResourceUri;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossAppConnection {
    pub requesting_client: ClientId,
    pub resource_as_issuer: String,
    pub resource: Option<ResourceUri>,
    pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRequest {
    pub requesting_client: ClientId,
    pub audience: String,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeGrant {
    pub resource_as_issuer: String,
    pub resource: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeError {
    #[error("no cross-app connection authorises this client for that audience")]
    NoConnection,

    #[error("the audience does not match the connection")]
    AudienceMismatch,

    #[error("the requested resource is not the one this connection targets")]
    InvalidTarget,

    #[error("the requested scope exceeds what the connection allows")]
    ScopeTooBroad,
}

impl ExchangeError {
    #[must_use]
    pub const fn oauth_error_code(self) -> &'static str {
        match self {
            Self::NoConnection | Self::AudienceMismatch => "invalid_grant",
            Self::InvalidTarget => "invalid_target",
            Self::ScopeTooBroad => "invalid_scope",
        }
    }
}

pub fn authorise(
    request: &ExchangeRequest,
    connection: Option<&CrossAppConnection>,
) -> Result<ExchangeGrant, ExchangeError> {
    let Some(connection) = connection else {
        return Err(ExchangeError::NoConnection);
    };

    if connection.requesting_client != request.requesting_client {
        return Err(ExchangeError::NoConnection);
    }

    if connection.resource_as_issuer != request.audience {
        return Err(ExchangeError::AudienceMismatch);
    }

    let resource = match request.resource.as_deref() {
        Some(raw) => {
            let Ok(parsed) = ResourceUri::parse(raw) else {
                return Err(ExchangeError::InvalidTarget);
            };
            match connection.resource.as_ref() {
                Some(expected) if expected == &parsed => Some(parsed.as_str().to_owned()),
                _ => return Err(ExchangeError::InvalidTarget),
            }
        }
        None => connection.resource.as_ref().map(|r| r.as_str().to_owned()),
    };

    let scopes = match request.scope.as_deref() {
        Some(requested) => {
            let asked: Vec<String> = requested
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if asked.iter().any(|s| !connection.allowed_scopes.contains(s)) {
                return Err(ExchangeError::ScopeTooBroad);
            }
            asked
        }
        None => connection.allowed_scopes.clone(),
    };

    Ok(ExchangeGrant {
        resource_as_issuer: connection.resource_as_issuer.clone(),
        resource,
        scopes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{CrossAppConnection, ExchangeError, ExchangeRequest, authorise};
    use crate::id::ClientId;
    use crate::resource::ResourceUri;

    fn client() -> ClientId {
        ClientId::new("chat-app").expect("client")
    }

    fn connection() -> CrossAppConnection {
        CrossAppConnection {
            requesting_client: client(),
            resource_as_issuer: "https://auth.chat.example".to_owned(),
            resource: Some(ResourceUri::parse("https://mcp.chat.example").expect("uri")),
            allowed_scopes: vec!["chat.read".to_owned(), "chat.history".to_owned()],
        }
    }

    fn request() -> ExchangeRequest {
        ExchangeRequest {
            requesting_client: client(),
            audience: "https://auth.chat.example".to_owned(),
            resource: Some("https://mcp.chat.example".to_owned()),
            scope: Some("chat.read".to_owned()),
        }
    }

    #[test]
    fn an_authorised_connection_yields_a_grant() {
        let grant = authorise(&request(), Some(&connection())).expect("granted");
        assert_eq!(grant.resource_as_issuer, "https://auth.chat.example");
        assert_eq!(grant.resource.as_deref(), Some("https://mcp.chat.example"));
        assert_eq!(grant.scopes, ["chat.read"]);
    }

    #[test]
    fn without_a_connection_nothing_is_issued() {
        assert_eq!(
            authorise(&request(), None).unwrap_err(),
            ExchangeError::NoConnection
        );
    }

    #[test]
    fn another_clients_connection_does_not_apply() {
        let mut other = connection();
        other.requesting_client = ClientId::new("other-app").expect("client");
        assert_eq!(
            authorise(&request(), Some(&other)).unwrap_err(),
            ExchangeError::NoConnection
        );
    }

    #[test]
    fn the_audience_must_be_the_resource_authorization_server() {
        let mut r = request();
        r.audience = "https://auth.evil.example".to_owned();
        assert_eq!(
            authorise(&r, Some(&connection())).unwrap_err(),
            ExchangeError::AudienceMismatch
        );
    }

    #[test]
    fn a_resource_outside_the_connection_is_invalid_target() {
        let mut r = request();
        r.resource = Some("https://mcp.evil.example".to_owned());
        assert_eq!(
            authorise(&r, Some(&connection())).unwrap_err(),
            ExchangeError::InvalidTarget
        );
        assert_eq!(
            ExchangeError::InvalidTarget.oauth_error_code(),
            "invalid_target"
        );
    }

    #[test]
    fn omitting_the_resource_falls_back_to_the_connection() {
        let mut r = request();
        r.resource = None;
        let grant = authorise(&r, Some(&connection())).expect("granted");
        assert_eq!(grant.resource.as_deref(), Some("https://mcp.chat.example"));
    }

    #[test]
    fn a_scope_beyond_the_connection_is_refused() {
        let mut r = request();
        r.scope = Some("chat.read chat.admin".to_owned());
        assert_eq!(
            authorise(&r, Some(&connection())).unwrap_err(),
            ExchangeError::ScopeTooBroad
        );
    }

    #[test]
    fn omitting_scope_grants_exactly_what_the_connection_allows() {
        let mut r = request();
        r.scope = None;
        let grant = authorise(&r, Some(&connection())).expect("granted");
        assert_eq!(grant.scopes, ["chat.read", "chat.history"]);
    }

    #[test]
    fn an_equivalent_resource_spelling_still_matches() {
        let mut r = request();
        r.resource = Some("HTTPS://MCP.CHAT.EXAMPLE/".to_owned());
        let grant = authorise(&r, Some(&connection())).expect("granted");
        assert_eq!(grant.resource.as_deref(), Some("https://mcp.chat.example"));
    }
}
