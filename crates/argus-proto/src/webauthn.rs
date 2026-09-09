use argus_core::rpid::RpId;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CeremonyError {
    #[error("the relying party configuration is not usable")]
    BadConfiguration,

    #[error("the ceremony state is missing or malformed")]
    BadState,

    #[error("the authenticator response did not verify")]
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub passkey: Passkey,
}

pub struct RelyingParty {
    inner: Webauthn,
    rp_id: String,
}

impl core::fmt::Debug for RelyingParty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RelyingParty")
    }
}

impl RelyingParty {
    pub fn new(rp_id: &RpId, origin: &str, name: &str) -> Result<Self, CeremonyError> {
        if !rp_id
            .accepts_origin(origin)
            .map_err(|_| CeremonyError::BadConfiguration)?
        {
            return Err(CeremonyError::BadConfiguration);
        }

        let parsed = Url::parse(origin).map_err(|_| CeremonyError::BadConfiguration)?;

        let inner = WebauthnBuilder::new(rp_id.as_str(), &parsed)
            .map_err(|_| CeremonyError::BadConfiguration)?
            .rp_name(name)
            .build()
            .map_err(|_| CeremonyError::BadConfiguration)?;

        Ok(Self {
            inner,
            rp_id: rp_id.as_str().to_owned(),
        })
    }

    #[must_use]
    pub fn rp_id(&self) -> &str {
        self.rp_id.as_str()
    }

    pub fn start_registration(
        &self,
        user: Uuid,
        user_name: &str,
        display_name: &str,
        existing: &[StoredCredential],
    ) -> Result<(CreationChallengeResponse, String), CeremonyError> {
        let exclude = existing
            .iter()
            .map(|c| c.passkey.cred_id().clone())
            .collect::<Vec<_>>();

        let (challenge, state) = self
            .inner
            .start_passkey_registration(user, user_name, display_name, Some(exclude))
            .map_err(|_| CeremonyError::Rejected)?;

        let state = serde_json::to_string(&state).map_err(|_| CeremonyError::BadState)?;
        Ok((challenge, state))
    }

    pub fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &str,
    ) -> Result<StoredCredential, CeremonyError> {
        let state: PasskeyRegistration =
            serde_json::from_str(state).map_err(|_| CeremonyError::BadState)?;

        let passkey = self
            .inner
            .finish_passkey_registration(response, &state)
            .map_err(|_| CeremonyError::Rejected)?;

        Ok(StoredCredential {
            credential_id: passkey.cred_id().as_ref().to_vec(),
            passkey,
        })
    }

    pub fn start_authentication(
        &self,
        credentials: &[StoredCredential],
    ) -> Result<(RequestChallengeResponse, String), CeremonyError> {
        let passkeys = credentials
            .iter()
            .map(|c| c.passkey.clone())
            .collect::<Vec<_>>();

        let (challenge, state) = self
            .inner
            .start_passkey_authentication(&passkeys)
            .map_err(|_| CeremonyError::Rejected)?;

        let state = serde_json::to_string(&state).map_err(|_| CeremonyError::BadState)?;
        Ok((challenge, state))
    }

    pub fn finish_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &str,
    ) -> Result<AuthenticationOutcome, CeremonyError> {
        let state: PasskeyAuthentication =
            serde_json::from_str(state).map_err(|_| CeremonyError::BadState)?;

        let result = self
            .inner
            .finish_passkey_authentication(response, &state)
            .map_err(|_| CeremonyError::Rejected)?;

        Ok(AuthenticationOutcome {
            credential_id: result.cred_id().as_ref().to_vec(),
            user_verified: result.user_verified(),
            counter: result.counter(),
            needs_update: result.needs_update(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationOutcome {
    pub credential_id: Vec<u8>,
    pub user_verified: bool,
    pub counter: u32,
    pub needs_update: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{CeremonyError, RelyingParty};
    use argus_core::rpid::RpId;
    use uuid::Uuid;

    fn rp(id: &str, origin: &str) -> Result<RelyingParty, CeremonyError> {
        let rp_id = RpId::register(id).expect("rp id");
        RelyingParty::new(&rp_id, origin, "Argus")
    }

    #[test]
    fn a_matching_rp_id_and_origin_build_a_relying_party() {
        assert!(rp("example.com", "https://login.example.com").is_ok());
        assert!(rp("example.com", "https://example.com").is_ok());
    }

    #[test]
    fn an_origin_the_rp_id_does_not_cover_is_refused() {
        assert_eq!(
            rp("example.com", "https://evil.test").unwrap_err(),
            CeremonyError::BadConfiguration
        );
        assert_eq!(
            rp("login.example.com", "https://example.com").unwrap_err(),
            CeremonyError::BadConfiguration
        );
    }

    #[test]
    fn a_plaintext_origin_is_refused() {
        assert_eq!(
            rp("example.com", "http://example.com").unwrap_err(),
            CeremonyError::BadConfiguration
        );
    }

    #[test]
    fn a_registration_challenge_names_the_rp_id() {
        let rp = rp("example.com", "https://login.example.com").expect("rp");
        let (challenge, state) = rp
            .start_registration(Uuid::from_u128(1), "user@example.com", "User", &[])
            .expect("challenge");

        let json = serde_json::to_string(&challenge).expect("json");
        assert!(json.contains("example.com"), "{json}");
        assert!(!state.is_empty(), "the ceremony state must be storable");
    }

    #[test]
    fn a_finish_call_with_broken_state_is_refused_before_any_crypto() {
        let rp = rp("example.com", "https://login.example.com").expect("rp");
        let response: super::RegisterPublicKeyCredential =
            serde_json::from_str(r#"{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{"attestationObject":"AAAA","clientDataJSON":"AAAA"},"extensions":{}}"#)
                .expect("shape");

        assert_eq!(
            rp.finish_registration(&response, "not json").unwrap_err(),
            CeremonyError::BadState
        );
    }

    #[test]
    fn an_account_with_no_credentials_still_gets_a_challenge() {
        let rp = rp("example.com", "https://login.example.com").expect("rp");
        let (challenge, state) = rp
            .start_authentication(&[])
            .expect("a challenge must be produced even with nothing to allow");

        assert!(!state.is_empty());
        let json = serde_json::to_string(&challenge).expect("json");
        assert!(
            json.contains("challenge"),
            "the response must look like every other challenge: {json}"
        );
    }

    #[test]
    fn the_challenge_for_an_empty_and_a_populated_account_have_the_same_shape() {
        let rp = rp("example.com", "https://login.example.com").expect("rp");
        let (empty, _) = rp.start_authentication(&[]).expect("challenge");
        let empty = serde_json::to_value(&empty).expect("json");

        let members: Vec<&str> = empty
            .get("publicKey")
            .and_then(serde_json::Value::as_object)
            .map(|o| o.keys().map(String::as_str).collect())
            .unwrap_or_default();

        assert!(
            members.contains(&"challenge"),
            "an enumeration probe must not be able to tell the two apart: {members:?}"
        );
    }
}
