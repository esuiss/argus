use crate::id::{ClientId, TenantId, UserId};
use crate::resource::ResourceUri;
use crate::time::{Duration, Timestamp};

pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_seconds(5);
pub const DEFAULT_REQUEST_LIFETIME: Duration = Duration::from_seconds(300);
pub const MAX_REQUEST_LIFETIME: Duration = Duration::from_seconds(600);
pub const GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackchannelState {
    Pending,
    Approved,
    Denied,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelRequest {
    pub tenant: TenantId,
    pub client: ClientId,
    pub subject: UserId,
    pub scope: Option<String>,
    pub resources: Vec<ResourceUri>,
    pub state: BackchannelState,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub interval: Duration,
    pub last_polled_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    Pending,
    SlowDown,
    Expired,
    Denied,
    WrongClient,
    Approved {
        subject: UserId,
        scope: Option<String>,
        resources: Vec<ResourceUri>,
    },
}

impl PollOutcome {
    #[must_use]
    pub const fn oauth_error_code(&self) -> Option<&'static str> {
        match self {
            Self::Pending => Some("authorization_pending"),
            Self::SlowDown => Some("slow_down"),
            Self::Expired => Some("expired_token"),
            Self::Denied => Some("access_denied"),
            Self::WrongClient => Some("invalid_grant"),
            Self::Approved { .. } => None,
        }
    }
}

#[must_use]
pub fn poll(
    request: &BackchannelRequest,
    presenting_client: &ClientId,
    now: Timestamp,
) -> PollOutcome {
    if &request.client != presenting_client {
        return PollOutcome::WrongClient;
    }

    if request.state == BackchannelState::Consumed {
        return PollOutcome::WrongClient;
    }

    if now.as_unix_seconds() >= request.expires_at.as_unix_seconds() {
        return PollOutcome::Expired;
    }

    if let Some(previous) = request.last_polled_at
        && now.since(previous).as_seconds() < request.interval.as_seconds()
    {
        return PollOutcome::SlowDown;
    }

    match request.state {
        BackchannelState::Denied => PollOutcome::Denied,
        BackchannelState::Pending => PollOutcome::Pending,
        BackchannelState::Approved => PollOutcome::Approved {
            subject: request.subject,
            scope: request.scope.clone(),
            resources: request.resources.clone(),
        },
        BackchannelState::Consumed => PollOutcome::WrongClient,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{BackchannelRequest, BackchannelState, DEFAULT_POLL_INTERVAL, PollOutcome, poll};
    use crate::id::{ClientId, TenantId, UserId};
    use crate::time::{Duration, Timestamp};
    use uuid::Uuid;

    const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);

    fn client() -> ClientId {
        ClientId::new("acme-web").expect("client")
    }

    fn request(state: BackchannelState) -> BackchannelRequest {
        BackchannelRequest {
            tenant: TenantId::from_uuid(Uuid::from_u128(0x0a)),
            client: client(),
            subject: UserId::from_uuid(Uuid::from_u128(0xa1)),
            scope: Some("openid".to_owned()),
            resources: Vec::new(),
            state,
            issued_at: NOW,
            expires_at: NOW.saturating_add(Duration::from_seconds(300)),
            interval: DEFAULT_POLL_INTERVAL,
            last_polled_at: None,
        }
    }

    fn at(offset: i64) -> Timestamp {
        Timestamp::from_unix_seconds(NOW.as_unix_seconds() + offset)
    }

    #[test]
    fn a_pending_request_answers_authorization_pending() {
        let outcome = poll(&request(BackchannelState::Pending), &client(), at(1));
        assert_eq!(outcome, PollOutcome::Pending);
        assert_eq!(outcome.oauth_error_code(), Some("authorization_pending"));
    }

    #[test]
    fn polling_faster_than_the_interval_is_told_to_slow_down() {
        let mut r = request(BackchannelState::Pending);
        r.last_polled_at = Some(at(10));
        let outcome = poll(&r, &client(), at(12));
        assert_eq!(outcome, PollOutcome::SlowDown);
        assert_eq!(outcome.oauth_error_code(), Some("slow_down"));
    }

    #[test]
    fn polling_at_the_interval_is_allowed() {
        let mut r = request(BackchannelState::Pending);
        r.last_polled_at = Some(at(10));
        assert_eq!(poll(&r, &client(), at(15)), PollOutcome::Pending);
    }

    #[test]
    fn an_approved_request_yields_the_subject_and_scope() {
        let outcome = poll(&request(BackchannelState::Approved), &client(), at(1));
        let PollOutcome::Approved { subject, scope, .. } = outcome else {
            panic!("expected approval");
        };
        assert_eq!(subject, UserId::from_uuid(Uuid::from_u128(0xa1)));
        assert_eq!(scope.as_deref(), Some("openid"));
    }

    #[test]
    fn a_denied_request_is_access_denied() {
        let outcome = poll(&request(BackchannelState::Denied), &client(), at(1));
        assert_eq!(outcome, PollOutcome::Denied);
        assert_eq!(outcome.oauth_error_code(), Some("access_denied"));
    }

    #[test]
    fn expiry_beats_every_other_state() {
        for state in [
            BackchannelState::Pending,
            BackchannelState::Approved,
            BackchannelState::Denied,
        ] {
            let outcome = poll(&request(state), &client(), at(300));
            assert_eq!(
                outcome,
                PollOutcome::Expired,
                "{state:?} outlived its expiry"
            );
        }
    }

    #[test]
    fn another_client_cannot_collect_the_result() {
        let other = ClientId::new("other-app").expect("client");
        assert_eq!(
            poll(&request(BackchannelState::Approved), &other, at(1)),
            PollOutcome::WrongClient
        );
    }

    #[test]
    fn a_consumed_request_cannot_be_redeemed_twice() {
        assert_eq!(
            poll(&request(BackchannelState::Consumed), &client(), at(1)),
            PollOutcome::WrongClient
        );
    }

    #[test]
    fn the_wrong_client_is_refused_even_before_expiry_is_considered() {
        let other = ClientId::new("other-app").expect("client");
        assert_eq!(
            poll(&request(BackchannelState::Approved), &other, at(9999)),
            PollOutcome::WrongClient
        );
    }
}
