use crate::aal::Aal;
use crate::id::UserId;
use crate::time::{Duration, Timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// §22 hesap kurtarma. §1 #16: kimlik doğrulama akışı bir "flow"
// konfigürasyonu değil, TİPLİ BİR DURUM MAKİNESİDİR. Kurtarma bir IdP'nin en
// zayıf halkasıdır, o yüzden geçişler veriyle değil tiple taşınır.
pub enum RecoveryState {
    Requested,
    EvidenceMet,
    CoolingDown,
    RebindOpen,
    GracePeriod,
    Closed,
    Denied,
    Throttled,
    Locked,
}

impl RecoveryState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::EvidenceMet => "evidence_met",
            Self::CoolingDown => "cooling_down",
            Self::RebindOpen => "rebind_open",
            Self::GracePeriod => "grace_period",
            Self::Closed => "closed",
            Self::Denied => "denied",
            Self::Throttled => "throttled",
            Self::Locked => "locked",
        }
    }

    #[must_use]
    pub const fn requires_assurance(self) -> bool {
        !matches!(
            self,
            Self::Requested | Self::Throttled | Self::Locked | Self::Denied
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAttempt {
    pub subject: UserId,
    pub state: RecoveryState,
    pub required: Aal,
    pub achieved: Option<Aal>,
    pub evidence_consumed: bool,
    pub cooldown_until: Option<Timestamp>,
    pub grace_until: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEvent {
    EvidencePresented { achieved: Aal },
    CooldownElapsed,
    UserDenied,
    AuthenticatorRebound { grace: Duration },
    GraceElapsed,
    RateLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    #[error("that transition is not defined from this state")]
    UndefinedTransition,

    #[error("the evidence does not reach the assurance the account requires")]
    InsufficientAssurance,

    #[error("the evidence has already been consumed")]
    EvidenceAlreadyConsumed,

    #[error("the cooldown has not elapsed")]
    CooldownActive,
}

pub fn advance(
    attempt: &RecoveryAttempt,
    event: RecoveryEvent,
    cooldown: Duration,
    now: Timestamp,
) -> Result<RecoveryAttempt, RecoveryError> {
    let mut next = attempt.clone();

    match (attempt.state, event) {
        (RecoveryState::Requested, RecoveryEvent::EvidencePresented { achieved }) => {
            if !achieved.satisfies(attempt.required) {
                return Err(RecoveryError::InsufficientAssurance);
            }
            if attempt.evidence_consumed {
                return Err(RecoveryError::EvidenceAlreadyConsumed);
            }
            next.achieved = Some(achieved);
            next.evidence_consumed = true;
            next.state = RecoveryState::EvidenceMet;
            next.cooldown_until = Some(now.saturating_add(cooldown));
            next.state = RecoveryState::CoolingDown;
        }

        (RecoveryState::CoolingDown, RecoveryEvent::CooldownElapsed) => {
            let until = attempt.cooldown_until.unwrap_or(now);
            if now.as_unix_seconds() < until.as_unix_seconds() {
                return Err(RecoveryError::CooldownActive);
            }
            next.state = RecoveryState::RebindOpen;
        }

        (RecoveryState::CoolingDown | RecoveryState::RebindOpen, RecoveryEvent::UserDenied) => {
            next.state = RecoveryState::Denied;
        }

        (RecoveryState::RebindOpen, RecoveryEvent::AuthenticatorRebound { grace }) => {
            next.state = RecoveryState::GracePeriod;
            next.grace_until = Some(now.saturating_add(grace));
        }

        (RecoveryState::GracePeriod, RecoveryEvent::GraceElapsed) => {
            next.state = RecoveryState::Closed;
        }

        (RecoveryState::Requested, RecoveryEvent::RateLimited) => {
            next.state = RecoveryState::Throttled;
        }

        _ => return Err(RecoveryError::UndefinedTransition),
    }

    Ok(next)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        Aal, Duration, RecoveryAttempt, RecoveryError, RecoveryEvent, RecoveryState, Timestamp,
        advance,
    };
    use crate::id::UserId;
    use uuid::Uuid;

    const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);
    const COOLDOWN: Duration = Duration::from_seconds(86_400);

    fn attempt(state: RecoveryState) -> RecoveryAttempt {
        RecoveryAttempt {
            subject: UserId::from_uuid(Uuid::from_u128(0xa1)),
            state,
            required: Aal::Two,
            achieved: None,
            evidence_consumed: false,
            cooldown_until: None,
            grace_until: None,
        }
    }

    fn at(offset: i64) -> Timestamp {
        Timestamp::from_unix_seconds(NOW.as_unix_seconds() + offset)
    }

    #[test]
    fn evidence_weaker_than_the_account_is_refused() {
        let a = attempt(RecoveryState::Requested);
        assert_eq!(
            advance(
                &a,
                RecoveryEvent::EvidencePresented { achieved: Aal::One },
                COOLDOWN,
                NOW
            )
            .unwrap_err(),
            RecoveryError::InsufficientAssurance,
            "recovery must never be weaker than what it recovers"
        );
    }

    #[test]
    fn sufficient_evidence_consumes_it_and_starts_the_cooldown() {
        let a = attempt(RecoveryState::Requested);
        let next = advance(
            &a,
            RecoveryEvent::EvidencePresented { achieved: Aal::Two },
            COOLDOWN,
            NOW,
        )
        .expect("accepted");

        assert_eq!(next.state, RecoveryState::CoolingDown);
        assert!(
            next.evidence_consumed,
            "evidence must be consumed in the same step"
        );
        assert_eq!(next.achieved, Some(Aal::Two));
        assert_eq!(next.cooldown_until, Some(at(86_400)));
    }

    #[test]
    fn the_same_evidence_cannot_be_presented_twice() {
        let mut a = attempt(RecoveryState::Requested);
        a.evidence_consumed = true;
        assert_eq!(
            advance(
                &a,
                RecoveryEvent::EvidencePresented { achieved: Aal::Two },
                COOLDOWN,
                NOW
            )
            .unwrap_err(),
            RecoveryError::EvidenceAlreadyConsumed
        );
    }

    #[test]
    fn rebinding_cannot_open_before_the_cooldown_elapses() {
        let mut a = attempt(RecoveryState::CoolingDown);
        a.cooldown_until = Some(at(86_400));
        assert_eq!(
            advance(&a, RecoveryEvent::CooldownElapsed, COOLDOWN, at(100)).unwrap_err(),
            RecoveryError::CooldownActive
        );
        assert_eq!(
            advance(&a, RecoveryEvent::CooldownElapsed, COOLDOWN, at(86_400))
                .expect("elapsed")
                .state,
            RecoveryState::RebindOpen
        );
    }

    #[test]
    fn the_owner_signing_in_during_the_cooldown_denies_the_attempt() {
        let a = attempt(RecoveryState::CoolingDown);
        assert_eq!(
            advance(&a, RecoveryEvent::UserDenied, COOLDOWN, NOW)
                .expect("denied")
                .state,
            RecoveryState::Denied
        );
    }

    #[test]
    fn the_full_path_ends_closed() {
        let a = attempt(RecoveryState::Requested);
        let a = advance(
            &a,
            RecoveryEvent::EvidencePresented { achieved: Aal::Two },
            COOLDOWN,
            NOW,
        )
        .expect("evidence");
        let a =
            advance(&a, RecoveryEvent::CooldownElapsed, COOLDOWN, at(86_400)).expect("cooldown");
        let a = advance(
            &a,
            RecoveryEvent::AuthenticatorRebound {
                grace: Duration::from_seconds(3600),
            },
            COOLDOWN,
            at(86_401),
        )
        .expect("rebind");
        assert_eq!(a.state, RecoveryState::GracePeriod);

        let a = advance(&a, RecoveryEvent::GraceElapsed, COOLDOWN, at(90_002)).expect("grace");
        assert_eq!(a.state, RecoveryState::Closed);
    }

    #[test]
    fn an_email_only_attacker_cannot_reach_rebinding() {
        let a = attempt(RecoveryState::Requested);
        assert!(
            advance(&a, RecoveryEvent::CooldownElapsed, COOLDOWN, NOW).is_err(),
            "the cooldown cannot be skipped from requested"
        );
        assert!(
            advance(
                &a,
                RecoveryEvent::AuthenticatorRebound {
                    grace: Duration::from_seconds(1)
                },
                COOLDOWN,
                NOW
            )
            .is_err(),
            "rebinding cannot be reached without evidence"
        );
    }

    #[test]
    fn undefined_transitions_are_refused_rather_than_ignored() {
        for state in [
            RecoveryState::Denied,
            RecoveryState::Closed,
            RecoveryState::Throttled,
            RecoveryState::Locked,
        ] {
            let a = attempt(state);
            assert_eq!(
                advance(
                    &a,
                    RecoveryEvent::EvidencePresented {
                        achieved: Aal::Three
                    },
                    COOLDOWN,
                    NOW
                )
                .unwrap_err(),
                RecoveryError::UndefinedTransition,
                "{state:?} accepted evidence"
            );
        }
    }

    #[test]
    fn only_the_pre_evidence_states_are_exempt_from_the_assurance_check() {
        for state in [
            RecoveryState::Requested,
            RecoveryState::Throttled,
            RecoveryState::Locked,
            RecoveryState::Denied,
        ] {
            assert!(!state.requires_assurance(), "{state:?}");
        }
        for state in [
            RecoveryState::EvidenceMet,
            RecoveryState::CoolingDown,
            RecoveryState::RebindOpen,
            RecoveryState::GracePeriod,
            RecoveryState::Closed,
        ] {
            assert!(state.requires_assurance(), "{state:?}");
        }
    }
}
