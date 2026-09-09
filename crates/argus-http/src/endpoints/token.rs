use argus_core::authz_code::{AuthorizationCode, Decision, TokenRequest, redeem};
use argus_core::client_auth::{
    MAX_ASSERTION_LIFETIME, PresentedCredential, authenticate, validate_assertion,
};
use argus_core::effect::Effect;
use argus_core::exchange::{ExchangeRequest, authorise};
use argus_core::id::ClientId;
use argus_core::pkce::Sha256;
use argus_core::refresh::{
    DEFAULT_FAMILY_LIFETIME, DEFAULT_TOKEN_LIFETIME, RefreshDecision, RefreshRequest, RefreshState,
    RefreshToken, rotate,
};
use argus_core::time::{Duration, Timestamp};
use argus_proto::idjag::IdJagClaims;
use argus_proto::jwt::{AccessTokenClaims, Audience, Confirmation, sign};
use argus_proto::oidc::{IdTokenClaims, at_hash, sign_id_token};
use argus_proto::{OAuthError, OAuthErrorCode, TokenResponse};
use serde::Deserialize;

use crate::effects::{EffectContext, Rotation, apply};
use crate::replay::consume;
use crate::state::AppState;
use crate::store::{
    AuditSink, ClientStore, CodeStore, ConnectionStore, JtiPurpose, RefreshStore, ReplayStore,
    StoreError,
};

pub const PLACEHOLDER_ACCESS_TOKEN_LIFETIME: Duration = Duration::from_seconds(300);

pub const ID_TOKEN_LIFETIME: Duration = Duration::from_seconds(300);

pub const ID_JAG_LIFETIME: Duration = Duration::from_seconds(300);

fn wants_openid(scope: Option<&str>) -> bool {
    scope.is_some_and(|s| s.split(' ').any(|v| v == "openid"))
}

pub type Binding = Option<String>;

#[derive(Debug, Clone, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,

    pub code: Option<String>,

    pub redirect_uri: Option<String>,

    pub code_verifier: Option<String>,

    pub client_id: Option<String>,

    pub refresh_token: Option<String>,

    pub client_assertion_type: Option<String>,

    pub client_assertion: Option<String>,

    pub requested_token_type: Option<String>,

    pub subject_token: Option<String>,

    pub subject_token_type: Option<String>,

    pub audience: Option<String>,

    pub resource: Option<String>,

    pub scope: Option<String>,
}

fn hash(hasher: &impl Sha256, secret: &str) -> [u8; 32] {
    hasher.sha256(secret.as_bytes())
}

const fn store_error_to_oauth(e: &StoreError) -> OAuthError {
    match e {
        StoreError::NotFound => OAuthError::new(OAuthErrorCode::InvalidGrant),
        StoreError::Unavailable => OAuthError::new(OAuthErrorCode::TemporarilyUnavailable),
    }
}

pub async fn handle<C, R, A, S, U, P, X, H>(
    state: &AppState<C, R, A, S, U, P, X>,
    form: &TokenForm,
    now: Timestamp,
    hasher: &H,
    binding: Binding,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    S: ClientStore + Send + Sync,
    P: ReplayStore + Send + Sync,
    X: ConnectionStore + Send + Sync,
    H: Sha256,
{
    let client = authenticate_client(state, form, now, hasher).await?;

    match form.grant_type.as_str() {
        "authorization_code" => {
            authorization_code(state, form, &client, now, hasher, binding).await
        }
        "refresh_token" => refresh_token(state, form, &client, now, hasher, binding).await,
        argus_proto::idjag::GRANT_TYPE_TOKEN_EXCHANGE => {
            token_exchange(state, form, &client, now).await
        }

        _ => Err(OAuthError::with_description(
            OAuthErrorCode::UnsupportedGrantType,
            "only authorization_code, refresh_token and token-exchange are supported",
        )),
    }
}

async fn authenticate_client<C, R, A, S, U, P, X, H>(
    state: &AppState<C, R, A, S, U, P, X>,
    form: &TokenForm,
    now: Timestamp,
    hasher: &H,
) -> Result<ClientId, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    S: ClientStore + Send + Sync,
    P: ReplayStore + Send + Sync,
    H: Sha256,
{
    let tenant = state.tenant_id();

    let claimed = match form.client_assertion.as_deref() {
        Some(raw) => {
            if form.client_assertion_type.as_deref() != Some(argus_proto::ASSERTION_TYPE) {
                return Err(OAuthError::with_description(
                    OAuthErrorCode::InvalidRequest,
                    "client_assertion_type must be the JWT bearer assertion type",
                ));
            }
            let unverified = argus_proto::client_assertion::parse(raw)
                .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

            if let Some(from_form) = form.client_id.as_deref()
                && from_form != unverified.client_id
            {
                return Err(OAuthError::new(OAuthErrorCode::InvalidClient));
            }
            unverified.client_id
        }
        None => form
            .client_id
            .clone()
            .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidClient))?,
    };

    let client =
        ClientId::new(claimed).map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

    let registered = state
        .clients
        .find(tenant, &client)
        .await
        .map_err(|e| store_error_to_oauth(&e))?
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidClient))?;

    let presented = match form.client_assertion.as_deref() {
        Some(raw) => {
            let claims = argus_proto::client_assertion::verify(raw, &registered.keys)
                .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

            let replay = consume(
                &state.replay,
                tenant,
                JtiPurpose::ClientAssertion,
                &claims.jti,
                now,
                MAX_ASSERTION_LIFETIME,
            )
            .await
            .map_err(|e| store_error_to_oauth(&e))?;

            validate_assertion(
                &claims,
                &client,
                &[
                    state.tenant.metadata.issuer.as_str(),
                    state.tenant.metadata.token_endpoint.as_str(),
                ],
                now,
                &replay,
            )
            .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

            PresentedCredential::VerifiedAssertion {
                client_id: client.clone(),
            }
        }
        None => PresentedCredential::None,
    };

    authenticate(
        &client,
        registered.auth_method,
        &presented,
        None,
        |secret| hasher.sha256(secret.as_bytes()),
    )
    .map_err(|_| OAuthError::new(OAuthErrorCode::InvalidClient))?;

    Ok(client)
}

async fn authorization_code<C, R, A, S, U, P, X, H>(
    state: &AppState<C, R, A, S, U, P, X>,
    form: &TokenForm,
    client: &ClientId,
    now: Timestamp,
    hasher: &H,
    binding: Binding,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    let code = form
        .code
        .as_deref()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;
    let redirect_uri = form
        .redirect_uri
        .clone()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;
    let code_verifier = form
        .code_verifier
        .clone()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    let tenant = state.tenant_id();
    let code_hash = hash(hasher, code);

    let stored = state
        .codes
        .load(tenant, &code_hash)
        .await
        .map_err(|e| store_error_to_oauth(&e))?;
    let record = AuthorizationCode::from_stored(stored);

    let decision = redeem(
        &record,
        &TokenRequest {
            client: client.clone(),
            redirect_uri,
            code_verifier,
            tenant,
        },
        now,
        hasher,
    );

    let (grant, effects) = match decision {
        Decision::Grant { grant, effects } => (grant, effects),
        Decision::Deny { reason, effects } => {
            apply_effects(state, &effects, &code_hash, None, now).await?;
            return Err(OAuthError::new(match reason.oauth_error_code() {
                "invalid_grant" => OAuthErrorCode::InvalidGrant,
                _ => OAuthErrorCode::InvalidRequest,
            }));
        }
    };

    apply_effects(state, &effects, &code_hash, None, now).await?;
    issue(
        state,
        &IssueRequest {
            subject: &grant.subject,
            client: &grant.client,
            refresh: None,
            binding,

            nonce: grant.nonce.as_deref(),
            scope: grant.scope.as_deref(),
            resources: &grant.resources,
        },
        now,
        hasher,
    )
}

async fn refresh_token<C, R, A, S, U, P, X, H>(
    state: &AppState<C, R, A, S, U, P, X>,
    form: &TokenForm,
    client: &ClientId,
    now: Timestamp,
    hasher: &H,
    binding: Binding,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    let presented = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    let tenant = state.tenant_id();
    let old_hash = hash(hasher, presented);

    let stored = state
        .refresh
        .load(tenant, &old_hash)
        .await
        .map_err(|e| store_error_to_oauth(&e))?;

    let decision = rotate(
        &stored,
        &RefreshRequest {
            client: client.clone(),
            tenant,
        },
        now,
        DEFAULT_FAMILY_LIFETIME,
    );

    match decision {
        RefreshDecision::Deny { reason, effects } => {
            let rotation = Rotation {
                old_hash: &old_hash,
                new_hash: &old_hash,
                new_token: &stored,
                family: stored.family,
            };
            apply_effects(state, &effects, &old_hash, Some(rotation), now).await?;
            let _ = reason;
            Err(OAuthError::new(OAuthErrorCode::InvalidGrant))
        }
        RefreshDecision::Rotate { grant, effects } => {
            let new_secret = new_secret();
            let new_hash = hash(hasher, &new_secret);
            let new_token = RefreshToken {
                tenant: grant.tenant,
                client: grant.client.clone(),
                subject: grant.subject,
                family: grant.family,
                generation: grant.next_generation,
                family_started_at: stored.family_started_at,
                expires_at: now.saturating_add(DEFAULT_TOKEN_LIFETIME),
                state: RefreshState::Active,
            };

            let rotation = Rotation {
                old_hash: &old_hash,
                new_hash: &new_hash,
                new_token: &new_token,
                family: grant.family,
            };
            apply_effects(state, &effects, &old_hash, Some(rotation), now).await?;

            issue(
                state,
                &IssueRequest {
                    subject: &grant.subject,
                    client: &grant.client,
                    refresh: Some(new_secret),
                    binding,
                    nonce: None,
                    scope: None,
                    resources: &[],
                },
                now,
                hasher,
            )
        }
    }
}

async fn token_exchange<C, R, A, S, U, P, X>(
    state: &AppState<C, R, A, S, U, P, X>,
    form: &TokenForm,
    client: &ClientId,
    now: Timestamp,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    X: ConnectionStore + Send + Sync,
{
    if form.requested_token_type.as_deref() != Some(argus_proto::idjag::TOKEN_TYPE) {
        return Err(OAuthError::with_description(
            OAuthErrorCode::InvalidRequest,
            "only the id-jag requested_token_type is supported",
        ));
    }

    let subject_token = form
        .subject_token
        .as_deref()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    let audience = form
        .audience
        .clone()
        .ok_or_else(|| OAuthError::new(OAuthErrorCode::InvalidRequest))?;

    let subject = subject_of(state, subject_token, now)?;

    let connection = state
        .resources
        .find_connection(state.tenant_id(), client, &audience)
        .await
        .map_err(|e| store_error_to_oauth(&e))?;

    let grant = authorise(
        &ExchangeRequest {
            requesting_client: client.clone(),
            audience,
            resource: form.resource.clone(),
            scope: form.scope.clone(),
        },
        connection.as_ref(),
    )
    .map_err(|e| {
        OAuthError::new(match e.oauth_error_code() {
            "invalid_target" => OAuthErrorCode::InvalidTarget,
            "invalid_scope" => OAuthErrorCode::InvalidScope,
            _ => OAuthErrorCode::InvalidGrant,
        })
    })?;

    let claims = IdJagClaims {
        iss: state.tenant.metadata.issuer.clone(),
        sub: subject,
        aud: grant.resource_as_issuer,
        client_id: client.as_str().to_owned(),
        jti: uuid::Uuid::new_v4().simple().to_string(),
        exp: now.saturating_add(ID_JAG_LIFETIME).as_unix_seconds(),
        iat: now.as_unix_seconds(),
        resource: grant.resource,
        scope: if grant.scopes.is_empty() {
            None
        } else {
            Some(grant.scopes.join(" "))
        },
        email: None,
    };

    let assertion = argus_proto::idjag::sign_id_jag(&claims, &state.tenant.active_key)
        .map_err(|_| OAuthError::new(OAuthErrorCode::ServerError))?;

    Ok(TokenResponse {
        access_token: assertion,
        token_type: "N_A".to_owned(),
        expires_in: ID_JAG_LIFETIME.as_seconds(),
        refresh_token: None,
        scope: None,
        id_token: None,
        issued_token_type: Some(argus_proto::idjag::TOKEN_TYPE.to_owned()),
    })
}

fn subject_of<C, R, A, S, U, P, X>(
    state: &AppState<C, R, A, S, U, P, X>,
    subject_token: &str,
    now: Timestamp,
) -> Result<String, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    for key in &state.tenant.published_keys {
        let verifying = key.verifying_key();

        if let Ok(claims) = argus_proto::oidc::verify_id_token(subject_token, &verifying)
            && claims.iss == state.tenant.metadata.issuer
            && claims.exp > now.as_unix_seconds()
        {
            return Ok(claims.sub);
        }

        if let Ok(claims) = argus_proto::jwt::verify(subject_token, &verifying)
            && claims.iss == state.tenant.metadata.issuer
            && claims.exp > now.as_unix_seconds()
        {
            return Ok(claims.sub);
        }
    }

    Err(OAuthError::with_description(
        OAuthErrorCode::InvalidGrant,
        "the subject_token was not issued by this server or has expired",
    ))
}

async fn apply_effects<C, R, A, S, U, P, X>(
    state: &AppState<C, R, A, S, U, P, X>,
    effects: &[Effect],
    code_hash: &[u8; 32],
    rotation: Option<Rotation<'_>>,
    now: Timestamp,
) -> Result<(), OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
{
    let ctx = EffectContext {
        tenant: state.tenant_id(),
        code_hash: Some(code_hash),
        rotation,
        now,
    };
    apply(effects, &ctx, &state.codes, &state.refresh, &state.audit)
        .await
        .map_err(|e| store_error_to_oauth(&e))
}

fn new_secret() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

struct IssueRequest<'a> {
    subject: &'a argus_core::id::UserId,

    client: &'a ClientId,

    refresh: Option<String>,

    binding: Binding,

    nonce: Option<&'a str>,

    scope: Option<&'a str>,

    resources: &'a [argus_core::resource::ResourceUri],
}

fn issue<C, R, A, S, U, P, X, H>(
    state: &AppState<C, R, A, S, U, P, X>,
    request: &IssueRequest<'_>,
    now: Timestamp,
    hasher: &H,
) -> Result<TokenResponse, OAuthError>
where
    C: CodeStore + Send + Sync,
    R: RefreshStore + Send + Sync,
    A: AuditSink + Send + Sync,
    H: Sha256,
{
    let subject = request.subject.as_uuid().simple().to_string();
    let exp = now.saturating_add(PLACEHOLDER_ACCESS_TOKEN_LIFETIME);

    let audience = if request.resources.is_empty() {
        Audience::One(request.client.as_str().to_owned())
    } else {
        Audience::of(
            &request
                .resources
                .iter()
                .map(|r| r.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    };

    let claims = AccessTokenClaims {
        iss: state.tenant.metadata.issuer.clone(),
        sub: subject.clone(),
        aud: audience,
        exp: exp.as_unix_seconds(),
        iat: now.as_unix_seconds(),
        jti: uuid::Uuid::new_v4().simple().to_string(),
        scope: request.scope.map(str::to_owned),
        sess: 0,

        cnf: request.binding.clone().map(|jkt| Confirmation { jkt }),
    };

    let bound = claims.cnf.is_some();

    let access_token = sign(&claims, &state.tenant.active_key)
        .map_err(|_| OAuthError::new(OAuthErrorCode::ServerError))?;

    let id_token = if wants_openid(request.scope) {
        let id_claims = IdTokenClaims {
            iss: state.tenant.metadata.issuer.clone(),
            sub: subject,

            aud: request.client.as_str().to_owned(),
            exp: now.saturating_add(ID_TOKEN_LIFETIME).as_unix_seconds(),
            iat: now.as_unix_seconds(),
            nonce: request.nonce.map(str::to_owned),

            auth_time: None,

            at_hash: Some(at_hash(&access_token, hasher)),
        };
        Some(
            sign_id_token(&id_claims, &state.tenant.active_key)
                .map_err(|_| OAuthError::new(OAuthErrorCode::ServerError))?,
        )
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,

        token_type: if bound {
            "DPoP".to_owned()
        } else {
            "Bearer".to_owned()
        },
        expires_in: PLACEHOLDER_ACCESS_TOKEN_LIFETIME.as_seconds(),
        refresh_token: request.refresh.clone(),
        scope: request.scope.map(str::to_owned),
        id_token,
        issued_token_type: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::wants_openid;

    #[test]
    fn openid_is_matched_as_a_whole_value() {
        assert!(wants_openid(Some("openid")));
        assert!(wants_openid(Some("profile openid email")));
        assert!(wants_openid(Some("openid profile")));
    }

    #[test]
    fn a_scope_that_merely_contains_openid_does_not_count() {
        assert!(!wants_openid(Some("openid-connect")));
        assert!(!wants_openid(Some("not-openid")));
        assert!(!wants_openid(Some("myopenid")));
    }

    #[test]
    fn absent_scope_never_asks_for_an_id_token() {
        assert!(!wants_openid(None));
        assert!(!wants_openid(Some("")));
    }
}
