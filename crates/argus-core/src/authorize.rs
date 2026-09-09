use crate::client_auth::{ClientAuthMethod, ClientKey};
use crate::id::ClientId;
use crate::pkce::{CodeChallenge, CodeChallengeMethod};
use crate::redirect_uri::RedirectUri;
use crate::resource::ResourceUri;

#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub response_type: String,

    pub client_id: String,

    pub redirect_uri: Option<String>,

    pub state: Option<String>,

    pub code_challenge: Option<String>,

    pub code_challenge_method: Option<String>,

    pub scope: Option<String>,

    pub nonce: Option<String>,

    pub resources: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RegisteredClient {
    pub client_id: ClientId,

    pub redirect_uris: Vec<RedirectUri>,

    pub auth_method: ClientAuthMethod,

    pub keys: Vec<ClientKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizeFatal {
    #[error("client_id is missing or malformed")]
    UnknownClient,

    #[error("redirect_uri is required")]
    AmbiguousRedirectUri,

    #[error("redirect_uri is not registered for this client")]
    UnregisteredRedirectUri,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeError {
    UnsupportedResponseType,

    InvalidRequest,

    InvalidTarget,
}

impl AuthorizeError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidTarget => "invalid_target",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    Fatal(AuthorizeFatal),

    RedirectError {
        redirect_uri: RedirectUri,

        error: AuthorizeError,

        state: Option<String>,
    },

    Proceed {
        redirect_uri: RedirectUri,

        challenge: CodeChallenge,

        state: Option<String>,

        scope: Option<String>,

        nonce: Option<String>,

        resources: Vec<ResourceUri>,
    },
}

fn resolve_resources(
    requested: &[String],
    registered: &[ResourceUri],
) -> Result<Vec<ResourceUri>, AuthorizeError> {
    let mut granted = Vec::with_capacity(requested.len());

    for raw in requested {
        let Ok(parsed) = ResourceUri::parse(raw) else {
            return Err(AuthorizeError::InvalidTarget);
        };
        if !registered.contains(&parsed) {
            return Err(AuthorizeError::InvalidTarget);
        }
        if !granted.contains(&parsed) {
            granted.push(parsed);
        }
    }

    Ok(granted)
}

#[must_use]
pub fn validate(
    request: &AuthorizeRequest,
    client: Option<&RegisteredClient>,
    registered_resources: &[ResourceUri],
) -> AuthorizeOutcome {
    let Some(client) = client else {
        return AuthorizeOutcome::Fatal(AuthorizeFatal::UnknownClient);
    };

    let redirect_uri = match request.redirect_uri.as_deref() {
        Some(presented) => {
            let matched = client
                .redirect_uris
                .iter()
                .find(|registered| registered.match_presented(presented).is_some());
            match matched {
                Some(uri) => uri.clone(),
                None => {
                    return AuthorizeOutcome::Fatal(AuthorizeFatal::UnregisteredRedirectUri);
                }
            }
        }

        None => return AuthorizeOutcome::Fatal(AuthorizeFatal::AmbiguousRedirectUri),
    };

    let state = request.state.clone();
    let redirect_error = |error| AuthorizeOutcome::RedirectError {
        redirect_uri: redirect_uri.clone(),
        error,
        state: state.clone(),
    };

    if request.response_type != "code" {
        return redirect_error(AuthorizeError::UnsupportedResponseType);
    }

    let (Some(challenge_value), Some(method_value)) = (
        request.code_challenge.as_deref(),
        request.code_challenge_method.as_deref(),
    ) else {
        return redirect_error(AuthorizeError::InvalidRequest);
    };

    let Ok(method) = CodeChallengeMethod::parse(method_value) else {
        return redirect_error(AuthorizeError::InvalidRequest);
    };

    let Ok(challenge) = CodeChallenge::parse(method, challenge_value) else {
        return redirect_error(AuthorizeError::InvalidRequest);
    };

    let resources = match resolve_resources(&request.resources, registered_resources) {
        Ok(resources) => resources,
        Err(error) => return redirect_error(error),
    };

    AuthorizeOutcome::Proceed {
        redirect_uri,
        challenge,
        state,
        scope: request.scope.clone(),
        nonce: request.nonce.clone(),
        resources,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        AuthorizeError, AuthorizeFatal, AuthorizeOutcome, AuthorizeRequest, RegisteredClient,
        validate,
    };
    use crate::client_auth::ClientAuthMethod;
    use crate::id::ClientId;
    use crate::redirect_uri::RedirectUri;

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn uri(s: &str) -> RedirectUri {
        RedirectUri::register(s).expect("uri")
    }

    fn client() -> RegisteredClient {
        RegisteredClient {
            client_id: ClientId::new("acme-web").expect("client"),
            redirect_uris: vec![uri("https://app.example.com/cb")],
            auth_method: ClientAuthMethod::None,
            keys: Vec::new(),
        }
    }

    fn request() -> AuthorizeRequest {
        AuthorizeRequest {
            resources: Vec::new(),
            response_type: "code".to_owned(),
            client_id: "acme-web".to_owned(),
            redirect_uri: Some("https://app.example.com/cb".to_owned()),
            state: Some("xyz".to_owned()),
            code_challenge: Some(CHALLENGE.to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: None,
            nonce: Some("n-1".to_owned()),
        }
    }

    #[test]
    fn a_valid_request_proceeds() {
        assert!(matches!(
            validate(&request(), Some(&client()), &[]),
            AuthorizeOutcome::Proceed { .. }
        ));
    }

    #[test]
    fn unknown_client_is_fatal() {
        assert_eq!(
            validate(&request(), None, &[]),
            AuthorizeOutcome::Fatal(AuthorizeFatal::UnknownClient)
        );
    }

    #[test]
    fn unregistered_redirect_uri_is_fatal_and_never_redirects() {
        let mut r = request();
        r.redirect_uri = Some("https://evil.test/steal".to_owned());

        let outcome = validate(&r, Some(&client()), &[]);
        assert_eq!(
            outcome,
            AuthorizeOutcome::Fatal(AuthorizeFatal::UnregisteredRedirectUri)
        );
        assert!(
            !matches!(outcome, AuthorizeOutcome::RedirectError { .. }),
            "an unregistered URI must never become a redirect target"
        );
    }

    #[test]
    fn near_miss_redirect_uris_are_rejected() {
        for evil in [
            "https://app.example.com/cb/extra",
            "https://app0example.com/cb",
            "https://app.example.com.evil.test/cb",
        ] {
            let mut r = request();
            r.redirect_uri = Some(evil.to_owned());
            assert_eq!(
                validate(&r, Some(&client()), &[]),
                AuthorizeOutcome::Fatal(AuthorizeFatal::UnregisteredRedirectUri),
                "accepted: {evil}"
            );
        }
    }

    #[test]
    fn redirect_uri_is_required_even_with_a_single_registration() {
        let mut r = request();
        r.redirect_uri = None;
        assert_eq!(
            validate(&r, Some(&client()), &[]),
            AuthorizeOutcome::Fatal(AuthorizeFatal::AmbiguousRedirectUri)
        );
    }

    #[test]
    fn omitting_redirect_uri_is_fatal_when_several_are_registered() {
        let c = RegisteredClient {
            redirect_uris: vec![
                uri("https://app.example.com/cb"),
                uri("https://app.example.com/cb2"),
            ],
            ..client()
        };
        let mut r = request();
        r.redirect_uri = None;
        assert_eq!(
            validate(&r, Some(&c), &[]),
            AuthorizeOutcome::Fatal(AuthorizeFatal::AmbiguousRedirectUri)
        );
    }

    #[test]
    fn implicit_response_types_are_rejected_by_redirect() {
        for rt in ["token", "id_token", "code token"] {
            let mut r = request();
            r.response_type = rt.to_owned();
            match validate(&r, Some(&client()), &[]) {
                AuthorizeOutcome::RedirectError { error, state, .. } => {
                    assert_eq!(error, AuthorizeError::UnsupportedResponseType);
                    assert_eq!(state.as_deref(), Some("xyz"), "state must be echoed back");
                }
                other => panic!("expected a redirect error for {rt}, got {other:?}"),
            }
        }
    }

    #[test]
    fn pkce_is_mandatory_and_only_s256_is_accepted() {
        let cases = [
            (None, Some("S256")),
            (Some(CHALLENGE), None),
            (Some(CHALLENGE), Some("plain")),
            (Some("not-base64!"), Some("S256")),
        ];

        for (challenge, method) in cases {
            let mut r = request();
            r.code_challenge = challenge.map(ToOwned::to_owned);
            r.code_challenge_method = method.map(ToOwned::to_owned);

            match validate(&r, Some(&client()), &[]) {
                AuthorizeOutcome::RedirectError { error, .. } => {
                    assert_eq!(error, AuthorizeError::InvalidRequest);
                }
                other => {
                    panic!("expected invalid_request for {challenge:?}/{method:?}, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn loopback_port_variance_is_accepted() {
        let c = RegisteredClient {
            redirect_uris: vec![uri("http://127.0.0.1/callback")],
            ..client()
        };
        let mut r = request();
        r.redirect_uri = Some("http://127.0.0.1:51234/callback".to_owned());
        assert!(matches!(
            validate(&r, Some(&c), &[]),
            AuthorizeOutcome::Proceed { .. }
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod resource_tests {
    use super::{AuthorizeError, AuthorizeOutcome, AuthorizeRequest, RegisteredClient, validate};
    use crate::client_auth::ClientAuthMethod;
    use crate::id::ClientId;
    use crate::redirect_uri::RedirectUri;
    use crate::resource::ResourceUri;

    fn client() -> RegisteredClient {
        RegisteredClient {
            client_id: ClientId::new("acme-web").expect("client"),
            redirect_uris: vec![RedirectUri::register("https://app.example.com/cb").expect("uri")],
            auth_method: ClientAuthMethod::None,
            keys: Vec::new(),
        }
    }

    fn request(resources: &[&str]) -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: "code".to_owned(),
            client_id: "acme-web".to_owned(),
            redirect_uri: Some("https://app.example.com/cb".to_owned()),
            state: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: None,
            nonce: None,
            resources: resources.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    fn registered() -> Vec<ResourceUri> {
        vec![
            ResourceUri::parse("https://mcp.example.com/mcp").expect("uri"),
            ResourceUri::parse("https://files.example.com").expect("uri"),
        ]
    }

    fn granted(outcome: AuthorizeOutcome) -> Vec<String> {
        match outcome {
            AuthorizeOutcome::Proceed { resources, .. } => {
                resources.iter().map(|r| r.as_str().to_owned()).collect()
            }
            other => panic!("expected Proceed, got {other:?}"),
        }
    }

    fn error(outcome: AuthorizeOutcome) -> AuthorizeError {
        match outcome {
            AuthorizeOutcome::RedirectError { error, .. } => error,
            other => panic!("expected RedirectError, got {other:?}"),
        }
    }

    #[test]
    fn a_registered_resource_is_granted() {
        let out = validate(
            &request(&["https://mcp.example.com/mcp"]),
            Some(&client()),
            &registered(),
        );
        assert_eq!(granted(out), ["https://mcp.example.com/mcp"]);
    }

    #[test]
    fn an_unregistered_resource_is_invalid_target() {
        let out = validate(
            &request(&["https://evil.example.com"]),
            Some(&client()),
            &registered(),
        );
        assert_eq!(error(out), AuthorizeError::InvalidTarget);
        assert_eq!(AuthorizeError::InvalidTarget.as_str(), "invalid_target");
    }

    #[test]
    fn a_malformed_resource_is_invalid_target() {
        for bad in [
            "mcp.example.com",
            "https://mcp.example.com#frag",
            "not a uri",
        ] {
            let out = validate(&request(&[bad]), Some(&client()), &registered());
            assert_eq!(error(out), AuthorizeError::InvalidTarget, "accepted {bad}");
        }
    }

    #[test]
    fn several_resources_are_all_granted() {
        let out = validate(
            &request(&["https://mcp.example.com/mcp", "https://files.example.com"]),
            Some(&client()),
            &registered(),
        );
        assert_eq!(
            granted(out),
            ["https://mcp.example.com/mcp", "https://files.example.com"]
        );
    }

    #[test]
    fn one_unregistered_resource_poisons_the_whole_request() {
        let out = validate(
            &request(&["https://mcp.example.com/mcp", "https://evil.example.com"]),
            Some(&client()),
            &registered(),
        );
        assert_eq!(error(out), AuthorizeError::InvalidTarget);
    }

    #[test]
    fn equivalent_spellings_match_the_registration() {
        for form in [
            "https://mcp.example.com/mcp/",
            "HTTPS://MCP.EXAMPLE.COM/mcp",
            "https://mcp.example.com:443/mcp",
        ] {
            let out = validate(&request(&[form]), Some(&client()), &registered());
            assert_eq!(granted(out), ["https://mcp.example.com/mcp"], "{form}");
        }
    }

    #[test]
    fn a_duplicate_resource_is_granted_once() {
        let out = validate(
            &request(&[
                "https://mcp.example.com/mcp",
                "https://mcp.example.com/mcp/",
            ]),
            Some(&client()),
            &registered(),
        );
        assert_eq!(granted(out), ["https://mcp.example.com/mcp"]);
    }

    #[test]
    fn no_resource_parameter_grants_nothing() {
        let out = validate(&request(&[]), Some(&client()), &registered());
        assert!(granted(out).is_empty());
    }
}
