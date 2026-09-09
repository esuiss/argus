use crate::time::{Duration, Timestamp};

pub const DEFAULT_PROOF_WINDOW: Duration = Duration::from_seconds(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    pub jti: String,

    pub htm: String,

    pub htu: String,

    pub iat: Timestamp,

    pub ath: Option<String>,

    pub jkt: String,
}

impl VerifiedProof {
    #[must_use]
    pub const fn new(
        jti: String,
        htm: String,
        htu: String,
        iat: Timestamp,
        ath: Option<String>,
        jkt: String,
    ) -> Self {
        Self {
            jti,
            htm,
            htu,
            iat,
            ath,
            jkt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBinding {
    pub method: String,

    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpopError {
    #[error("DPoP proof is bound to a different HTTP method")]
    MethodMismatch,

    #[error("DPoP proof is bound to a different URI")]
    UriMismatch,

    #[error("DPoP proof is outside the acceptable time window")]
    StaleProof,

    #[error("DPoP proof is dated in the future")]
    FutureProof,

    #[error("DPoP proof has already been used")]
    Replayed,

    #[error("DPoP proof is missing the access token hash")]
    MissingTokenHash,

    #[error("DPoP proof is bound to a different access token")]
    TokenHashMismatch,
}

pub trait ReplayGuard {
    fn seen(&self, jti: &str) -> bool;
}

pub fn validate(
    proof: &VerifiedProof,
    binding: &RequestBinding,
    expected_token_hash: Option<&str>,
    now: Timestamp,
    window: Duration,
    replay: &impl ReplayGuard,
) -> Result<(), DpopError> {
    if replay.seen(&proof.jti) {
        return Err(DpopError::Replayed);
    }

    if proof.htm != binding.method {
        return Err(DpopError::MethodMismatch);
    }

    if proof.htu != binding.uri {
        return Err(DpopError::UriMismatch);
    }

    if proof.iat.since(now).as_seconds() > window.as_seconds() {
        return Err(DpopError::FutureProof);
    }

    if now.since(proof.iat).as_seconds() > window.as_seconds() {
        return Err(DpopError::StaleProof);
    }

    if let Some(expected) = expected_token_hash {
        let Some(actual) = proof.ath.as_deref() else {
            return Err(DpopError::MissingTokenHash);
        };
        if actual != expected {
            return Err(DpopError::TokenHashMismatch);
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        DEFAULT_PROOF_WINDOW, DpopError, ReplayGuard, RequestBinding, VerifiedProof, validate,
    };
    use crate::time::{Duration, Timestamp};

    const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);

    struct NeverSeen;
    impl ReplayGuard for NeverSeen {
        fn seen(&self, _jti: &str) -> bool {
            false
        }
    }

    struct AlwaysSeen;
    impl ReplayGuard for AlwaysSeen {
        fn seen(&self, _jti: &str) -> bool {
            true
        }
    }

    fn proof() -> VerifiedProof {
        VerifiedProof::new(
            "jti-1".to_owned(),
            "POST".to_owned(),
            "https://acme.argus.test/token".to_owned(),
            NOW,
            None,
            "thumbprint".to_owned(),
        )
    }

    fn binding() -> RequestBinding {
        RequestBinding {
            method: "POST".to_owned(),
            uri: "https://acme.argus.test/token".to_owned(),
        }
    }

    fn go(p: &VerifiedProof, now: Timestamp) -> Result<(), DpopError> {
        validate(p, &binding(), None, now, DEFAULT_PROOF_WINDOW, &NeverSeen)
    }

    #[test]
    fn a_matching_proof_is_accepted() {
        assert!(go(&proof(), NOW).is_ok());
    }

    #[test]
    fn method_must_match() {
        let b = RequestBinding {
            method: "GET".to_owned(),
            ..binding()
        };
        assert_eq!(
            validate(&proof(), &b, None, NOW, DEFAULT_PROOF_WINDOW, &NeverSeen).unwrap_err(),
            DpopError::MethodMismatch
        );
    }

    #[test]
    fn uri_must_match() {
        let b = RequestBinding {
            uri: "https://api.acme.test/data".to_owned(),
            ..binding()
        };
        assert_eq!(
            validate(&proof(), &b, None, NOW, DEFAULT_PROOF_WINDOW, &NeverSeen).unwrap_err(),
            DpopError::UriMismatch
        );
    }

    #[test]
    fn stale_proofs_are_rejected() {
        let late = Timestamp::from_unix_seconds(
            NOW.as_unix_seconds() + DEFAULT_PROOF_WINDOW.as_seconds() + 1,
        );
        assert_eq!(go(&proof(), late).unwrap_err(), DpopError::StaleProof);
    }

    #[test]
    fn proofs_at_the_window_edge_are_still_accepted() {
        let edge =
            Timestamp::from_unix_seconds(NOW.as_unix_seconds() + DEFAULT_PROOF_WINDOW.as_seconds());
        assert!(go(&proof(), edge).is_ok());
    }

    #[test]
    fn future_dated_proofs_are_rejected() {
        let early = Timestamp::from_unix_seconds(
            NOW.as_unix_seconds() - DEFAULT_PROOF_WINDOW.as_seconds() - 1,
        );
        assert_eq!(go(&proof(), early).unwrap_err(), DpopError::FutureProof);
    }

    #[test]
    fn replayed_proofs_are_rejected() {
        assert_eq!(
            validate(
                &proof(),
                &binding(),
                None,
                NOW,
                DEFAULT_PROOF_WINDOW,
                &AlwaysSeen
            )
            .unwrap_err(),
            DpopError::Replayed
        );
    }

    #[test]
    fn access_token_binding_is_enforced_when_required() {
        assert_eq!(
            validate(
                &proof(),
                &binding(),
                Some("expected-hash"),
                NOW,
                DEFAULT_PROOF_WINDOW,
                &NeverSeen
            )
            .unwrap_err(),
            DpopError::MissingTokenHash
        );

        let mut p = proof();
        p.ath = Some("other-hash".to_owned());
        assert_eq!(
            validate(
                &p,
                &binding(),
                Some("expected-hash"),
                NOW,
                DEFAULT_PROOF_WINDOW,
                &NeverSeen
            )
            .unwrap_err(),
            DpopError::TokenHashMismatch
        );

        p.ath = Some("expected-hash".to_owned());
        assert!(
            validate(
                &p,
                &binding(),
                Some("expected-hash"),
                NOW,
                DEFAULT_PROOF_WINDOW,
                &NeverSeen
            )
            .is_ok()
        );
    }

    #[test]
    fn the_window_is_configurable() {
        let one_second_late = Timestamp::from_unix_seconds(NOW.as_unix_seconds() + 1);
        assert_eq!(
            validate(
                &proof(),
                &binding(),
                None,
                one_second_late,
                Duration::from_seconds(0),
                &NeverSeen
            )
            .unwrap_err(),
            DpopError::StaleProof
        );
    }
}
