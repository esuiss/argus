use crate::aal::Aal;
use crate::id::UserId;
use crate::time::{Duration, Timestamp};

pub const DEFAULT_ATTEMPT_LIFETIME: Duration = Duration::from_seconds(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Factor {
    Password,
    Passkey,
    HardwareKey,
}

impl Factor {
    #[must_use]
    pub const fn aal(self) -> Aal {
        match self {
            Self::Password => Aal::One,
            Self::Passkey => Aal::Two,
            Self::HardwareKey => Aal::Three,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::HardwareKey => "hardware_key",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthnState {
    AwaitingIdentifier,

    AwaitingFactor {
        subject: UserId,
        satisfied: Vec<Factor>,
    },

    AwaitingFactorForUnknownIdentifier,

    Authenticated {
        subject: UserId,
        achieved: Aal,
        at: Timestamp,
    },

    Failed {
        reason: AuthnFailure,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthnFailure {
    #[error("the attempt has expired")]
    Expired,

    #[error("too many attempts")]
    Throttled,

    #[error("the presented factor did not verify")]
    BadFactor,

    #[error("the account cannot reach the required assurance level")]
    AssuranceUnreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnAttempt {
    pub state: AuthnState,
    pub required: Aal,
    pub started_at: Timestamp,
    pub expires_at: Timestamp,
    pub failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    IdentifierResolved {
        subject: Option<UserId>,
        enrolled: &'a [Factor],
    },

    FactorVerified {
        factor: Factor,
    },

    FactorRejected,
}

pub const MAX_FAILURES: u32 = 5;

#[must_use]
pub fn advance(attempt: &AuthnAttempt, event: Event<'_>, now: Timestamp) -> AuthnAttempt {
    let mut next = attempt.clone();

    if matches!(
        attempt.state,
        AuthnState::Authenticated { .. } | AuthnState::Failed { .. }
    ) {
        return next;
    }

    if now.as_unix_seconds() >= attempt.expires_at.as_unix_seconds() {
        next.state = AuthnState::Failed {
            reason: AuthnFailure::Expired,
        };
        return next;
    }

    match event {
        Event::IdentifierResolved { subject, enrolled } => {
            let AuthnState::AwaitingIdentifier = attempt.state else {
                return next;
            };

            let Some(subject) = subject else {
                next.state = AuthnState::AwaitingFactorForUnknownIdentifier;
                return next;
            };

            let reachable = enrolled.iter().map(|f| f.aal()).max().unwrap_or(Aal::One);

            if !reachable.satisfies(attempt.required) {
                next.state = AuthnState::Failed {
                    reason: AuthnFailure::AssuranceUnreachable,
                };
                return next;
            }

            next.state = AuthnState::AwaitingFactor {
                subject,
                satisfied: Vec::new(),
            };
        }

        Event::FactorVerified { factor } => {
            let AuthnState::AwaitingFactor { subject, satisfied } = &attempt.state else {
                return next;
            };

            let mut satisfied = satisfied.clone();
            if !satisfied.contains(&factor) {
                satisfied.push(factor);
            }

            let achieved = satisfied.iter().map(|f| f.aal()).max().unwrap_or(Aal::One);

            if achieved.satisfies(attempt.required) {
                next.state = AuthnState::Authenticated {
                    subject: *subject,
                    achieved,
                    at: now,
                };
            } else {
                next.state = AuthnState::AwaitingFactor {
                    subject: *subject,
                    satisfied,
                };
            }
        }

        Event::FactorRejected => {
            next.failures = attempt.failures.saturating_add(1);
            if next.failures >= MAX_FAILURES {
                next.state = AuthnState::Failed {
                    reason: AuthnFailure::Throttled,
                };
            }
        }
    }

    next
}

#[must_use]
pub fn start(required: Aal, now: Timestamp) -> AuthnAttempt {
    AuthnAttempt {
        state: AuthnState::AwaitingIdentifier,
        required,
        started_at: now,
        expires_at: now.saturating_add(DEFAULT_ATTEMPT_LIFETIME),
        failures: 0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        Aal, AuthnFailure, AuthnState, Event, Factor, MAX_FAILURES, Timestamp, advance, start,
    };
    use crate::id::UserId;
    use uuid::Uuid;

    const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);

    fn user() -> UserId {
        UserId::from_uuid(Uuid::from_u128(0xa1))
    }

    fn at(offset: i64) -> Timestamp {
        Timestamp::from_unix_seconds(NOW.as_unix_seconds() + offset)
    }

    #[test]
    fn an_attempt_begins_by_awaiting_an_identifier() {
        let a = start(Aal::One, NOW);
        assert_eq!(a.state, AuthnState::AwaitingIdentifier);
        assert_eq!(a.failures, 0);
    }

    #[test]
    fn a_password_reaches_aal1_but_not_aal2() {
        let a = start(Aal::One, NOW);
        let a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password],
            },
            at(1),
        );
        let a = advance(
            &a,
            Event::FactorVerified {
                factor: Factor::Password,
            },
            at(2),
        );
        assert!(matches!(
            a.state,
            AuthnState::Authenticated {
                achieved: Aal::One,
                ..
            }
        ));
    }

    #[test]
    fn an_account_that_cannot_reach_the_required_level_fails_early() {
        let a = start(Aal::Two, NOW);
        let a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password],
            },
            at(1),
        );
        assert_eq!(
            a.state,
            AuthnState::Failed {
                reason: AuthnFailure::AssuranceUnreachable
            }
        );
    }

    #[test]
    fn a_passkey_satisfies_aal2() {
        let a = start(Aal::Two, NOW);
        let a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password, Factor::Passkey],
            },
            at(1),
        );
        let a = advance(
            &a,
            Event::FactorVerified {
                factor: Factor::Passkey,
            },
            at(2),
        );
        assert!(matches!(
            a.state,
            AuthnState::Authenticated {
                achieved: Aal::Two,
                ..
            }
        ));
    }

    #[test]
    fn a_password_alone_does_not_complete_an_aal2_attempt() {
        let a = start(Aal::Two, NOW);
        let a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password, Factor::Passkey],
            },
            at(1),
        );
        let a = advance(
            &a,
            Event::FactorVerified {
                factor: Factor::Password,
            },
            at(2),
        );
        assert!(matches!(a.state, AuthnState::AwaitingFactor { .. }));
    }

    #[test]
    fn an_unknown_identifier_still_awaits_a_factor() {
        let a = start(Aal::One, NOW);
        let a = advance(
            &a,
            Event::IdentifierResolved {
                subject: None,
                enrolled: &[],
            },
            at(1),
        );
        assert_eq!(
            a.state,
            AuthnState::AwaitingFactorForUnknownIdentifier,
            "an unknown account must still consume a factor step"
        );
    }

    #[test]
    fn no_sequence_of_events_authenticates_an_unknown_identifier() {
        let mut a = start(Aal::One, NOW);
        a = advance(
            &a,
            Event::IdentifierResolved {
                subject: None,
                enrolled: &[Factor::Password, Factor::Passkey, Factor::HardwareKey],
            },
            at(1),
        );

        for factor in [Factor::Password, Factor::Passkey, Factor::HardwareKey] {
            a = advance(&a, Event::FactorVerified { factor }, at(2));
            assert!(
                !matches!(a.state, AuthnState::Authenticated { .. }),
                "an identifier that resolved to nobody must never authenticate, \
                 whatever factor is claimed: {:?}",
                a.state
            );
        }
    }

    #[test]
    fn an_unknown_identifier_is_still_throttled_like_a_known_one() {
        let mut a = start(Aal::One, NOW);
        a = advance(
            &a,
            Event::IdentifierResolved {
                subject: None,
                enrolled: &[],
            },
            at(1),
        );
        for _ in 0..MAX_FAILURES {
            a = advance(&a, Event::FactorRejected, at(2));
        }
        assert_eq!(
            a.state,
            AuthnState::Failed {
                reason: AuthnFailure::Throttled
            },
            "throttling must look the same for both, or the counter leaks existence"
        );
    }

    #[test]
    fn repeated_rejections_throttle_the_attempt() {
        let mut a = start(Aal::One, NOW);
        a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password],
            },
            at(1),
        );
        for _ in 0..MAX_FAILURES {
            a = advance(&a, Event::FactorRejected, at(2));
        }
        assert_eq!(
            a.state,
            AuthnState::Failed {
                reason: AuthnFailure::Throttled
            }
        );
    }

    #[test]
    fn an_expired_attempt_cannot_be_advanced() {
        let a = start(Aal::One, NOW);
        let a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password],
            },
            at(601),
        );
        assert_eq!(
            a.state,
            AuthnState::Failed {
                reason: AuthnFailure::Expired
            }
        );
    }

    #[test]
    fn a_finished_attempt_is_immutable() {
        let a = start(Aal::One, NOW);
        let a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password],
            },
            at(1),
        );
        let done = advance(
            &a,
            Event::FactorVerified {
                factor: Factor::Password,
            },
            at(2),
        );
        let again = advance(
            &done,
            Event::FactorVerified {
                factor: Factor::HardwareKey,
            },
            at(3),
        );
        assert_eq!(
            done.state, again.state,
            "a completed attempt must not change"
        );
    }

    #[test]
    fn a_factor_cannot_be_presented_before_the_identifier() {
        let a = start(Aal::One, NOW);
        let a = advance(
            &a,
            Event::FactorVerified {
                factor: Factor::Password,
            },
            at(1),
        );
        assert_eq!(
            a.state,
            AuthnState::AwaitingIdentifier,
            "a factor without an identifier must not advance anything"
        );
    }

    #[test]
    fn the_same_factor_twice_does_not_stack() {
        let a = start(Aal::Three, NOW);
        let mut a = advance(
            &a,
            Event::IdentifierResolved {
                subject: Some(user()),
                enrolled: &[Factor::Password, Factor::HardwareKey],
            },
            at(1),
        );
        for _ in 0..3 {
            a = advance(
                &a,
                Event::FactorVerified {
                    factor: Factor::Password,
                },
                at(2),
            );
        }
        assert!(
            matches!(a.state, AuthnState::AwaitingFactor { .. }),
            "repeating a weak factor must not reach a higher level"
        );
    }
}
