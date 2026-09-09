use argus_core::aal::Aal;
use argus_core::id::TenantId;
use argus_core::recovery::{RecoveryAttempt, RecoveryError, RecoveryEvent, RecoveryState, advance};
use argus_core::time::{Duration, Timestamp};
use argus_crypto::blind_index::BlindIndexKey;
use serde::{Deserialize, Serialize};

use crate::store::{AuthnStore, RecoveryStore, StoreError};

pub const DEFAULT_COOLDOWN: Duration = Duration::from_seconds(86_400);

#[derive(Debug, Clone, Deserialize)]
pub struct StartRecovery {
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryAccepted {
    pub attempt_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PresentEvidence {
    pub attempt_id: String,
    pub achieved_aal: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttemptRef {
    pub attempt_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryStatus {
    pub state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryHttpError {
    #[error("no such recovery attempt")]
    Unknown,

    #[error("the evidence does not reach the assurance this account requires")]
    InsufficientAssurance,

    #[error("that transition is not allowed from the current state")]
    UndefinedTransition,

    #[error("the cooldown has not elapsed")]
    CooldownActive,

    #[error("the evidence has already been used")]
    EvidenceAlreadyConsumed,

    #[error("the attempt changed underneath this request")]
    Conflict,

    #[error("the store is unavailable")]
    Unavailable,
}

impl From<RecoveryError> for RecoveryHttpError {
    fn from(value: RecoveryError) -> Self {
        match value {
            RecoveryError::UndefinedTransition => Self::UndefinedTransition,
            RecoveryError::InsufficientAssurance => Self::InsufficientAssurance,
            RecoveryError::EvidenceAlreadyConsumed => Self::EvidenceAlreadyConsumed,
            RecoveryError::CooldownActive => Self::CooldownActive,
        }
    }
}

pub async fn start<S>(
    store: &S,
    tenant: TenantId,
    request: &StartRecovery,
    blind_index: &BlindIndexKey,
) -> Result<RecoveryAccepted, RecoveryHttpError>
where
    S: AuthnStore + RecoveryStore + Sync,
{
    let index = blind_index.compute(&request.identifier);

    let subject = store
        .find_user_by_blind_index(tenant, &index)
        .await
        .map_err(|_| RecoveryHttpError::Unavailable)?;

    let Some(subject) = subject else {
        return Ok(RecoveryAccepted { attempt_id: None });
    };

    let required = store
        .required_aal(tenant, subject)
        .await
        .map_err(|_| RecoveryHttpError::Unavailable)?;

    let attempt_id = uuid::Uuid::new_v4();

    store
        .open_recovery(
            tenant,
            attempt_id,
            &RecoveryAttempt {
                subject,
                state: RecoveryState::Requested,
                required,
                achieved: None,
                evidence_consumed: false,
                cooldown_until: None,
                grace_until: None,
            },
        )
        .await
        .map_err(|_| RecoveryHttpError::Unavailable)?;

    Ok(RecoveryAccepted {
        attempt_id: Some(attempt_id.simple().to_string()),
    })
}

async fn transition<S>(
    store: &S,
    tenant: TenantId,
    raw_id: &str,
    event: RecoveryEvent,
    now: Timestamp,
) -> Result<RecoveryStatus, RecoveryHttpError>
where
    S: RecoveryStore + Sync,
{
    let attempt_id = uuid::Uuid::parse_str(raw_id).map_err(|_| RecoveryHttpError::Unknown)?;

    let current = store
        .load_recovery(tenant, attempt_id)
        .await
        .map_err(|e| match e {
            StoreError::NotFound => RecoveryHttpError::Unknown,
            StoreError::Unavailable => RecoveryHttpError::Unavailable,
        })?;

    let next = advance(&current, event, DEFAULT_COOLDOWN, now)?;

    let applied = store
        .advance_recovery(tenant, attempt_id, &next, now)
        .await
        .map_err(|_| RecoveryHttpError::Unavailable)?;

    if !applied {
        return Err(RecoveryHttpError::Conflict);
    }

    Ok(RecoveryStatus {
        state: next.state.as_str().to_owned(),
    })
}

pub async fn present_evidence<S>(
    store: &S,
    tenant: TenantId,
    request: &PresentEvidence,
    now: Timestamp,
) -> Result<RecoveryStatus, RecoveryHttpError>
where
    S: RecoveryStore + Sync,
{
    let achieved =
        Aal::parse(&request.achieved_aal).ok_or(RecoveryHttpError::InsufficientAssurance)?;

    transition(
        store,
        tenant,
        &request.attempt_id,
        RecoveryEvent::EvidencePresented { achieved },
        now,
    )
    .await
}

pub async fn open_rebind<S>(
    store: &S,
    tenant: TenantId,
    request: &AttemptRef,
    now: Timestamp,
) -> Result<RecoveryStatus, RecoveryHttpError>
where
    S: RecoveryStore + Sync,
{
    transition(
        store,
        tenant,
        &request.attempt_id,
        RecoveryEvent::CooldownElapsed,
        now,
    )
    .await
}

pub async fn deny<S>(
    store: &S,
    tenant: TenantId,
    request: &AttemptRef,
    now: Timestamp,
) -> Result<RecoveryStatus, RecoveryHttpError>
where
    S: RecoveryStore + Sync,
{
    transition(
        store,
        tenant,
        &request.attempt_id,
        RecoveryEvent::UserDenied,
        now,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{DEFAULT_COOLDOWN, RecoveryError, RecoveryHttpError};

    #[test]
    fn every_core_refusal_maps_to_a_distinct_http_reason() {
        let mapped = [
            RecoveryError::UndefinedTransition,
            RecoveryError::InsufficientAssurance,
            RecoveryError::EvidenceAlreadyConsumed,
            RecoveryError::CooldownActive,
        ]
        .map(RecoveryHttpError::from);

        for (i, a) in mapped.iter().enumerate() {
            for b in mapped.iter().skip(i + 1) {
                assert_ne!(a, b, "two core refusals collapsed into one response");
            }
        }
    }

    #[test]
    fn the_default_cooldown_is_a_day() {
        assert_eq!(DEFAULT_COOLDOWN.as_seconds(), 86_400);
    }
}
