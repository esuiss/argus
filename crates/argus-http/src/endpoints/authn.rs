use argus_core::aal::Aal;
use argus_core::id::{TenantId, UserId};
use argus_core::pkce::Sha256;
use argus_core::time::{Duration, Timestamp};
use argus_crypto::blind_index::BlindIndexKey;
use argus_crypto::password::{Verdict, hash as hash_password, verify as verify_password};
use serde::{Deserialize, Serialize};

use crate::store::{AuthnSession, AuthnStore, SessionStore, StoreError};

pub const SESSION_LIFETIME: Duration = Duration::from_seconds(43_200);
pub const SESSION_COOKIE: &str = "argus_session";

const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$\
                         AAAAAAAAAAAAAAAAAAAAAA$\
                         S2VlcCB0aGUgdGltaW5nIHRoZSBzYW1lIGZvcg";

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordLoginForm {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginOutcome {
    Established { subject: UserId, achieved: Aal },
    Refused,
    Unavailable,
}

pub async fn password_login<S>(
    store: &S,
    tenant: TenantId,
    form: &PasswordLoginForm,
    hasher: &impl Sha256,
    blind_index: &BlindIndexKey,
    now: Timestamp,
) -> (LoginOutcome, Option<String>)
where
    S: AuthnStore + SessionStore + Sync,
{
    let index = blind_index.compute(&form.identifier);

    let subject = match store.find_user_by_blind_index(tenant, &index).await {
        Ok(found) => found,
        Err(StoreError::Unavailable) => return (LoginOutcome::Unavailable, None),
        Err(StoreError::NotFound) => None,
    };

    let stored = match subject {
        Some(user) => match store.password_of(tenant, user).await {
            Ok(found) => found,
            Err(StoreError::Unavailable) => return (LoginOutcome::Unavailable, None),
            Err(StoreError::NotFound) => None,
        },
        None => None,
    };

    let phc = stored.unwrap_or_else(|| DUMMY_PHC.to_owned());

    let verdict = verify_password(&form.password, &phc).unwrap_or(Verdict::Wrong);

    let (Some(subject), true) = (subject, verdict != Verdict::Wrong) else {
        return (LoginOutcome::Refused, None);
    };

    if verdict == Verdict::CorrectButNeedsRehash
        && let Ok(fresh) = hash_password(&form.password)
    {
        let _ = store.set_password(tenant, subject, &fresh).await;
    }

    let Ok(required) = store.required_aal(tenant, subject).await else {
        return (LoginOutcome::Unavailable, None);
    };

    if !Aal::One.satisfies(required) {
        return (LoginOutcome::Refused, None);
    }

    let secret = uuid::Uuid::new_v4().simple().to_string();
    let session_hash = hasher.sha256(secret.as_bytes());

    let session = AuthnSession {
        subject,
        achieved: Aal::One,
        authenticated_at: now,
        expires_at: now.saturating_add(SESSION_LIFETIME),
    };

    if store
        .create_session(tenant, &session_hash, &session)
        .await
        .is_err()
    {
        return (LoginOutcome::Unavailable, None);
    }

    (
        LoginOutcome::Established {
            subject,
            achieved: Aal::One,
        },
        Some(secret),
    )
}

#[must_use]
pub fn session_cookie(secret: &str, secure: bool) -> String {
    let flags = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={secret}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{flags}",
        SESSION_LIFETIME.as_seconds()
    )
}

#[must_use]
pub fn session_from_cookies(header: Option<&str>) -> Option<String> {
    header?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{DUMMY_PHC, SESSION_COOKIE, session_cookie, session_from_cookies};

    #[test]
    fn the_decoy_is_actually_verified_rather_than_rejected_as_malformed() {
        let verdict = argus_crypto::password::verify("anything", DUMMY_PHC);
        assert!(
            matches!(verdict, Ok(argus_crypto::password::Verdict::Wrong)),
            "a decoy that fails to parse short-circuits the work and destroys the \
             timing defence it exists for: {verdict:?}"
        );
    }

    #[test]
    fn an_unknown_account_costs_about_as_much_as_a_known_one() {
        let real = argus_crypto::password::hash("a real password").expect("hash");

        let start = std::time::Instant::now();
        let _ = argus_crypto::password::verify("wrong", &real);
        let known = start.elapsed();

        let start = std::time::Instant::now();
        let _ = argus_crypto::password::verify("wrong", DUMMY_PHC);
        let unknown = start.elapsed();

        let ratio = unknown.as_secs_f64() / known.as_secs_f64();
        assert!(
            (0.5..2.0).contains(&ratio),
            "the two paths must not be distinguishable by cost: known={known:?} \
             unknown={unknown:?} ratio={ratio}"
        );
    }

    #[test]
    fn the_dummy_hash_is_a_real_argon2id_string() {
        assert!(DUMMY_PHC.starts_with("$argon2id$"));
        assert!(
            DUMMY_PHC.contains("m=19456,t=2,p=1"),
            "the decoy must cost the same as a real verification"
        );
    }

    #[test]
    fn the_cookie_is_http_only_and_same_site() {
        let cookie = session_cookie("abc", true);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.starts_with(&format!("{SESSION_COOKIE}=abc;")));
    }

    #[test]
    fn the_secure_flag_is_dropped_only_when_asked() {
        assert!(!session_cookie("abc", false).contains("Secure"));
    }

    #[test]
    fn the_session_is_read_back_from_a_cookie_header() {
        assert_eq!(
            session_from_cookies(Some("a=1; argus_session=xyz; b=2")).as_deref(),
            Some("xyz")
        );
        assert_eq!(
            session_from_cookies(Some("argus_session=xyz")).as_deref(),
            Some("xyz")
        );
        assert!(session_from_cookies(Some("a=1; b=2")).is_none());
        assert!(session_from_cookies(None).is_none());
    }

    #[test]
    fn a_cookie_name_that_merely_ends_the_same_is_not_matched() {
        assert!(session_from_cookies(Some("not_argus_session=xyz")).is_none());
        assert!(session_from_cookies(Some("argus_session_x=xyz")).is_none());
    }
}
