use crate::id::ClientId;
use crate::time::{Duration, Timestamp};

// RFC 9126 §2.2. FAPI 2.0 Security Profile Final yetkilendirme isteklerinin
// PAR'dan geçmesini şart koşuyor; §1 §9 Faz 5'in çıkış kriteri.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
pub const MIN_LIFETIME: Duration = Duration::from_seconds(5);
pub const MAX_LIFETIME: Duration = Duration::from_seconds(600);
pub const DEFAULT_LIFETIME: Duration = Duration::from_seconds(90);
pub const IDENTIFIER_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParFault {
    #[error("a pushed request must not carry a request_uri of its own")]
    RequestUriInPushedRequest,

    #[error("the client_id in the pushed request does not match the authenticated client")]
    ClientMismatch,

    #[error("the request_uri is not one this server issued")]
    UnknownRequestUri,

    #[error("the request_uri has expired")]
    Expired,

    #[error("the request_uri has already been used")]
    AlreadyUsed,

    #[error("the request_uri belongs to another client")]
    NotYours,

    #[error("this server requires a pushed authorization request")]
    PushRequired,

    #[error("a pushed request must carry a client_id")]
    MissingClientId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedRequest {
    pub client: ClientId,
    pub parameters: Vec<(String, String)>,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed: bool,
}

impl PushedRequest {
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[must_use]
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.parameters
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

#[must_use]
pub fn request_uri_for(identifier: &str) -> String {
    format!("{REQUEST_URI_PREFIX}{identifier}")
}

#[must_use]
pub fn identifier_of(request_uri: &str) -> Option<&str> {
    let rest = request_uri.strip_prefix(REQUEST_URI_PREFIX)?;

    if rest.is_empty()
        || !rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return None;
    }

    Some(rest)
}

#[must_use]
pub fn lifetime(requested: Option<Duration>) -> Duration {
    let asked = requested.unwrap_or(DEFAULT_LIFETIME);

    if asked.as_seconds() < MIN_LIFETIME.as_seconds() {
        MIN_LIFETIME
    } else if asked.as_seconds() > MAX_LIFETIME.as_seconds() {
        MAX_LIFETIME
    } else {
        asked
    }
}

// PAR ucu istemci kimlik doğrulaması ister. İlk hâlinde yoktu: herkes kayıtlı
// herhangi bir istemci için istek push edebiliyordu. Yayına çıkmadan yakalandı.
pub fn check_push(
    parameters: &[(String, String)],
    authenticated: &ClientId,
) -> Result<(), ParFault> {
    if parameters.iter().any(|(key, _)| key == "request_uri") {
        return Err(ParFault::RequestUriInPushedRequest);
    }

    let declared = parameters
        .iter()
        .find(|(key, _)| key == "client_id")
        .map(|(_, value)| value.as_str())
        .ok_or(ParFault::MissingClientId)?;

    if declared != authenticated.as_str() {
        return Err(ParFault::ClientMismatch);
    }

    Ok(())
}

pub fn check_redemption(
    request: &PushedRequest,
    presenting: &ClientId,
    now: Timestamp,
) -> Result<(), ParFault> {
    if request.consumed {
        return Err(ParFault::AlreadyUsed);
    }

    if request.expires_at <= now {
        return Err(ParFault::Expired);
    }

    if &request.client != presenting {
        return Err(ParFault::NotYours);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Profile {
    pub require_pushed_requests: bool,
    pub require_sender_constrained_tokens: bool,
    pub forbid_public_clients: bool,
}

impl Profile {
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            require_pushed_requests: false,
            require_sender_constrained_tokens: false,
            forbid_public_clients: false,
        }
    }

    #[must_use]
    pub const fn financial_grade() -> Self {
        Self {
            require_pushed_requests: true,
            require_sender_constrained_tokens: true,
            forbid_public_clients: true,
        }
    }
}

pub fn check_authorize_entry(profile: Profile, request_uri: Option<&str>) -> Result<(), ParFault> {
    if profile.require_pushed_requests && request_uri.is_none() {
        return Err(ParFault::PushRequired);
    }

    Ok(())
}
