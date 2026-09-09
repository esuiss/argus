use argus_core::aal::Aal;
use argus_core::id::{TenantId, UserId};
use argus_core::pkce::Sha256;
use argus_core::time::{Duration, Timestamp};
use argus_proto::webauthn::{RelyingParty, StoredCredential};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::store::{
    AuthnSession, AuthnStore, CeremonyPurpose, CeremonyStore, PendingCeremony, SessionStore,
    StoreError,
};

pub const CEREMONY_LIFETIME: Duration = Duration::from_seconds(300);

#[derive(Debug, Clone, Serialize)]
pub struct ChallengeEnvelope<T> {
    pub ceremony_id: String,
    #[serde(flatten)]
    pub challenge: T,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FinishRegistration {
    pub ceremony_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StartAuthentication {
    pub identifier: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FinishAuthentication {
    pub ceremony_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebauthnError {
    #[error("this request requires an authenticated session")]
    NeedsSession,

    #[error("the ceremony is unknown or has expired")]
    UnknownCeremony,

    #[error("the authenticator response did not verify")]
    Rejected,

    #[error("the sign counter went backwards, which means the credential was cloned")]
    ClonedCredential,

    #[error("the store is unavailable")]
    Unavailable,
}

fn credentials_of(raw: &[String]) -> Vec<StoredCredential> {
    raw.iter()
        .filter_map(|serialised| serde_json::from_str(serialised).ok())
        .collect()
}

pub async fn start_registration<S>(
    store: &S,
    rp: &RelyingParty,
    tenant: TenantId,
    subject: Option<UserId>,
    hasher: &impl Sha256,
    now: Timestamp,
) -> Result<ChallengeEnvelope<serde_json::Value>, WebauthnError>
where
    S: AuthnStore + CeremonyStore + Sync,
{
    let subject = subject.ok_or(WebauthnError::NeedsSession)?;

    let existing = store
        .webauthn_credentials(tenant, subject)
        .await
        .map_err(|_| WebauthnError::Unavailable)?;

    let (challenge, state) = rp
        .start_registration(
            subject.as_uuid(),
            &subject.as_uuid().simple().to_string(),
            &subject.as_uuid().simple().to_string(),
            &credentials_of(&existing),
        )
        .map_err(|_| WebauthnError::Rejected)?;

    let ceremony_id = uuid::Uuid::new_v4().simple().to_string();
    let hash = hasher.sha256(ceremony_id.as_bytes());

    store
        .store_ceremony(
            tenant,
            &hash,
            &PendingCeremony {
                user: Some(subject),
                purpose: CeremonyPurpose::Registration,
                state: &state,
                issued_at: now,
                expires_at: now.saturating_add(CEREMONY_LIFETIME),
            },
        )
        .await
        .map_err(|_| WebauthnError::Unavailable)?;

    Ok(ChallengeEnvelope {
        ceremony_id,
        challenge: serde_json::to_value(challenge).unwrap_or(serde_json::Value::Null),
    })
}

pub async fn finish_registration<S>(
    store: &S,
    rp: &RelyingParty,
    tenant: TenantId,
    request: &FinishRegistration,
    hasher: &impl Sha256,
    now: Timestamp,
) -> Result<(), WebauthnError>
where
    S: AuthnStore + CeremonyStore + Sync,
{
    let hash = hasher.sha256(request.ceremony_id.as_bytes());

    let (subject, state) = store
        .take_ceremony(tenant, &hash, CeremonyPurpose::Registration, now)
        .await
        .map_err(|e| match e {
            StoreError::NotFound => WebauthnError::UnknownCeremony,
            StoreError::Unavailable => WebauthnError::Unavailable,
        })?;

    let subject = subject.ok_or(WebauthnError::UnknownCeremony)?;

    let credential = rp
        .finish_registration(&request.credential, &state)
        .map_err(|_| WebauthnError::Rejected)?;

    let serialised = serde_json::to_string(&credential).map_err(|_| WebauthnError::Unavailable)?;

    store
        .store_webauthn_credential(
            tenant,
            subject,
            &credential.credential_id,
            rp.rp_id(),
            &serialised,
        )
        .await
        .map_err(|_| WebauthnError::Unavailable)?;

    Ok(())
}

pub async fn start_authentication<S>(
    store: &S,
    rp: &RelyingParty,
    tenant: TenantId,
    request: &StartAuthentication,
    blind_index: &argus_crypto::blind_index::BlindIndexKey,
    hasher: &impl Sha256,
    now: Timestamp,
) -> Result<ChallengeEnvelope<serde_json::Value>, WebauthnError>
where
    S: AuthnStore + CeremonyStore + Sync,
{
    let index = blind_index.compute(&request.identifier);

    let subject = store
        .find_user_by_blind_index(tenant, &index)
        .await
        .map_err(|_| WebauthnError::Unavailable)?;

    let existing = match subject {
        Some(user) => store
            .webauthn_credentials(tenant, user)
            .await
            .map_err(|_| WebauthnError::Unavailable)?,
        None => Vec::new(),
    };

    let (challenge, state) = rp
        .start_authentication(&credentials_of(&existing))
        .map_err(|_| WebauthnError::Rejected)?;

    let ceremony_id = uuid::Uuid::new_v4().simple().to_string();
    let hash = hasher.sha256(ceremony_id.as_bytes());

    store
        .store_ceremony(
            tenant,
            &hash,
            &PendingCeremony {
                user: subject,
                purpose: CeremonyPurpose::Authentication,
                state: &state,
                issued_at: now,
                expires_at: now.saturating_add(CEREMONY_LIFETIME),
            },
        )
        .await
        .map_err(|_| WebauthnError::Unavailable)?;

    Ok(ChallengeEnvelope {
        ceremony_id,
        challenge: serde_json::to_value(challenge).unwrap_or(serde_json::Value::Null),
    })
}

pub async fn finish_authentication<S>(
    store: &S,
    rp: &RelyingParty,
    tenant: TenantId,
    request: &FinishAuthentication,
    hasher: &impl Sha256,
    now: Timestamp,
) -> Result<(UserId, String), WebauthnError>
where
    S: AuthnStore + CeremonyStore + SessionStore + Sync,
{
    let hash = hasher.sha256(request.ceremony_id.as_bytes());

    let (_, state) = store
        .take_ceremony(tenant, &hash, CeremonyPurpose::Authentication, now)
        .await
        .map_err(|e| match e {
            StoreError::NotFound => WebauthnError::UnknownCeremony,
            StoreError::Unavailable => WebauthnError::Unavailable,
        })?;

    let outcome = rp
        .finish_authentication(&request.credential, &state)
        .map_err(|_| WebauthnError::Rejected)?;

    let subject = store
        .user_for_credential(tenant, &outcome.credential_id)
        .await
        .map_err(|_| WebauthnError::Unavailable)?
        .ok_or(WebauthnError::Rejected)?;

    let advanced = store
        .advance_sign_count(
            tenant,
            &outcome.credential_id,
            i64::from(outcome.counter),
            now,
        )
        .await
        .map_err(|_| WebauthnError::Unavailable)?;

    if !advanced {
        return Err(WebauthnError::ClonedCredential);
    }

    let secret = uuid::Uuid::new_v4().simple().to_string();
    let session_hash = hasher.sha256(secret.as_bytes());

    store
        .create_session(
            tenant,
            &session_hash,
            &AuthnSession {
                subject,
                achieved: Aal::Two,
                authenticated_at: now,
                expires_at: now.saturating_add(crate::endpoints::authn::SESSION_LIFETIME),
            },
        )
        .await
        .map_err(|_| WebauthnError::Unavailable)?;

    Ok((subject, secret))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{WebauthnError, credentials_of};

    #[test]
    fn a_malformed_stored_credential_is_skipped_not_fatal() {
        let raw = vec!["not json".to_owned(), "{}".to_owned()];
        assert!(
            credentials_of(&raw).is_empty(),
            "one unreadable row must not take the whole ceremony down"
        );
    }

    #[test]
    fn a_backwards_sign_counter_is_named_as_cloning() {
        let message = WebauthnError::ClonedCredential.to_string();
        assert!(message.contains("cloned"), "{message}");
    }
}
