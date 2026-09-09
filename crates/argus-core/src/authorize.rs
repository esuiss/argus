use crate::client_auth::{ClientAuthMethod, ClientKey};
use crate::id::ClientId;
use crate::pkce::{CodeChallenge, CodeChallengeMethod};
use crate::redirect_uri::RedirectUri;

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
}

impl AuthorizeError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidRequest => "invalid_request",
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
    },
}

#[must_use]
pub fn validate(request: &AuthorizeRequest, client: Option<&RegisteredClient>) -> AuthorizeOutcome {
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

    AuthorizeOutcome::Proceed {
        redirect_uri,
        challenge,
        state,
        scope: request.scope.clone(),
        nonce: request.nonce.clone(),
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
            validate(&request(), Some(&client())),
            AuthorizeOutcome::Proceed { .. }
        ));
    }

    #[test]
    fn unknown_client_is_fatal() {
        assert_eq!(
            validate(&request(), None),
            AuthorizeOutcome::Fatal(AuthorizeFatal::UnknownClient)
        );
    }

    #[test]
    fn unregistered_redirect_uri_is_fatal_and_never_redirects() {
        let mut r = request();
        r.redirect_uri = Some("https://evil.test/steal".to_owned());

        let outcome = validate(&r, Some(&client()));
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
                validate(&r, Some(&client())),
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
            validate(&r, Some(&client())),
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
            validate(&r, Some(&c)),
            AuthorizeOutcome::Fatal(AuthorizeFatal::AmbiguousRedirectUri)
        );
    }

    #[test]
    fn implicit_response_types_are_rejected_by_redirect() {
        for rt in ["token", "id_token", "code token"] {
            let mut r = request();
            r.response_type = rt.to_owned();
            match validate(&r, Some(&client())) {
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

            match validate(&r, Some(&client())) {
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
            validate(&r, Some(&c)),
            AuthorizeOutcome::Proceed { .. }
        ));
    }
}
