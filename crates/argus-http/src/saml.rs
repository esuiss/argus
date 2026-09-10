use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argus_core::id::{TenantId, UserId};
use argus_core::time::{Duration, Timestamp};
use argus_saml::binding::{
    BINDING_POST, BindingFault, check_relay_state, decode_post, encode_post,
};
use argus_saml::metadata::{IdentityProvider, ServiceProvider, identity_provider};
use argus_saml::nameid::{NameId, PairwiseIdentifier, issue};
use argus_saml::request::{
    AuthnRequest, ConsumerServiceFault, RequestFault, parse as parse_request,
    resolve_consumer_service,
};
use argus_saml::response::{
    AUTHN_CONTEXT_MFA, AUTHN_CONTEXT_PASSWORD_PROTECTED, AssertionRequest, Attribute,
    DEFAULT_ASSERTION_LIFETIME, STATUS_NO_PASSIVE, STATUS_REQUESTER, failure, template,
};
use argus_saml::signature::{SignatureFault, XmlSigner};
use axum::Form;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;

pub trait ServiceProviderRegistry: Send + Sync {
    fn find(&self, entity_id: &str) -> Option<ServiceProvider>;
}

pub trait Subject: Send + Sync {
    fn resolve(&self, session: Option<&str>) -> Option<(UserId, Option<String>, bool)>;
}

pub struct SamlState<S, R, U> {
    pub signer: S,
    pub registry: R,
    pub subjects: U,
    pub tenant_id: TenantId,
    pub entity_id: String,
    pub sso_location: String,
    pub certificate_base64: String,
    pub pairwise: Box<dyn PairwiseIdentifier + Send + Sync>,
    pub session_lifetime: Duration,
}

type Shared<S, R, U> = Arc<SamlState<S, R, U>>;

fn now() -> Timestamp {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Timestamp::from_unix_seconds(secs)
}

#[derive(Debug, Deserialize)]
pub struct SsoForm {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,

    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,

    #[serde(default)]
    pub session: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SsoOutcome {
    Post {
        destination: String,
        saml_response: String,
        relay_state: Option<String>,
    },

    Refused {
        status: StatusCode,
        detail: String,
    },

    NeedsAuthentication,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SsoFault {
    #[error("the message could not be decoded: {0}")]
    Binding(#[from] BindingFault),

    #[error("the request is not usable: {0}")]
    Request(#[from] RequestFault),

    #[error("the service provider {entity_id} is not registered with this server")]
    UnknownServiceProvider { entity_id: String },

    #[error("the assertion consumer service is not acceptable: {0}")]
    ConsumerService(#[from] ConsumerServiceFault),

    #[error("the request names this server's endpoint incorrectly")]
    WrongDestination,

    #[error("the assertion could not be produced: {0}")]
    Signature(#[from] SignatureFault),

    #[error("the assertion could not be built")]
    Malformed,
}

pub struct SsoRequest<'a> {
    pub encoded: &'a str,
    pub relay_state: Option<&'a str>,
    pub subject: Option<(UserId, Option<String>, bool)>,
    pub response_id: &'a str,
    pub assertion_id: &'a str,
    pub session_index: &'a str,
    pub transient_handle: &'a str,
}

#[allow(
    clippy::too_many_lines,
    reason = "the single sign-on decision reads as one sequence and splitting it hides the order"
)]
pub fn handle<S, R, U>(
    state: &SamlState<S, R, U>,
    request: &SsoRequest<'_>,
) -> Result<SsoOutcome, SsoFault>
where
    S: XmlSigner,
    R: ServiceProviderRegistry,
    U: Subject,
{
    check_relay_state(request.relay_state)?;

    let decoded = decode_post(request.encoded)?;
    let authn: AuthnRequest = parse_request(&decoded)?;

    if let Some(destination) = authn.destination.as_deref()
        && destination != state.sso_location
    {
        return Err(SsoFault::WrongDestination);
    }

    let provider =
        state
            .registry
            .find(&authn.issuer)
            .ok_or_else(|| SsoFault::UnknownServiceProvider {
                entity_id: authn.issuer.clone(),
            })?;

    let endpoint = resolve_consumer_service(&authn, &provider.consumer_services)?;

    if endpoint.binding != BINDING_POST {
        return Ok(SsoOutcome::Refused {
            status: StatusCode::NOT_IMPLEMENTED,
            detail: "this server delivers assertions over HTTP-POST only".to_owned(),
        });
    }

    let Some((user, email, strong)) = request.subject.clone() else {
        if authn.is_passive {
            let body = failure(
                &state.entity_id,
                &endpoint.location,
                Some(&authn.id),
                request.response_id,
                STATUS_NO_PASSIVE,
                now(),
            )
            .map_err(|_| SsoFault::Malformed)?;

            return Ok(SsoOutcome::Post {
                destination: endpoint.location.clone(),
                saml_response: encode_post(&body),
                relay_state: request.relay_state.map(str::to_owned),
            });
        }
        return Ok(SsoOutcome::NeedsAuthentication);
    };

    let issued = issue(
        authn.name_id_format.as_deref(),
        state.tenant_id,
        &provider.entity_id,
        user,
        email.as_deref(),
        request.transient_handle,
        state.pairwise.as_ref(),
    );

    let Ok(name_id): Result<NameId, _> = issued else {
        {
            let body = failure(
                &state.entity_id,
                &endpoint.location,
                Some(&authn.id),
                request.response_id,
                STATUS_REQUESTER,
                now(),
            )
            .map_err(|_| SsoFault::Malformed)?;

            return Ok(SsoOutcome::Post {
                destination: endpoint.location.clone(),
                saml_response: encode_post(&body),
                relay_state: request.relay_state.map(str::to_owned),
            });
        }
    };

    let attributes: Vec<Attribute> = email
        .map(|address| Attribute {
            name: "urn:oid:0.9.2342.19200300.100.1.3".to_owned(),
            name_format: argus_saml::response::ATTRIBUTE_NAME_FORMAT_URI.to_owned(),
            values: Vec::from([address]),
        })
        .into_iter()
        .collect();

    let at = now();

    let unsigned = template(&AssertionRequest {
        issuer: &state.entity_id,
        audience: &provider.entity_id,
        recipient: &endpoint.location,
        in_response_to: Some(&authn.id),
        name_id: &name_id,
        session_index: request.session_index,
        authn_context: if strong {
            AUTHN_CONTEXT_MFA
        } else {
            AUTHN_CONTEXT_PASSWORD_PROTECTED
        },
        attributes: &attributes,
        response_id: request.response_id,
        assertion_id: request.assertion_id,
        certificate_base64: &state.certificate_base64,
        now: at,
        lifetime: DEFAULT_ASSERTION_LIFETIME,
        session_expiry: at.saturating_add(state.session_lifetime),
    })
    .map_err(|_| SsoFault::Malformed)?;

    let signed = state.signer.sign(&unsigned)?;

    Ok(SsoOutcome::Post {
        destination: endpoint.location.clone(),
        saml_response: encode_post(&signed),
        relay_state: request.relay_state.map(str::to_owned),
    })
}

#[must_use]
pub fn post_form(destination: &str, saml_response: &str, relay_state: Option<&str>) -> String {
    let relay = relay_state.map_or_else(String::new, |value| {
        format!(
            r#"<input type="hidden" name="RelayState" value="{}"/>"#,
            argus_saml::escape::attribute(value)
        )
    });

    format!(
        concat!(
            "<!DOCTYPE html><html><head><title>Continue</title></head>",
            r#"<body onload="document.forms[0].submit()">"#,
            r#"<form method="post" action="{}">"#,
            r#"<input type="hidden" name="SAMLResponse" value="{}"/>"#,
            "{}",
            r#"<noscript><button type="submit">Continue</button></noscript>"#,
            "</form></body></html>"
        ),
        argus_saml::escape::attribute(destination),
        argus_saml::escape::attribute(saml_response),
        relay
    )
}

async fn metadata_handler<S, R, U>(State(state): State<Shared<S, R, U>>) -> Response
where
    S: XmlSigner + Send + Sync + 'static,
    R: ServiceProviderRegistry + 'static,
    U: Subject + 'static,
{
    let document = identity_provider(&IdentityProvider {
        entity_id: &state.entity_id,
        sso_post_location: &state.sso_location,
        sso_redirect_location: &state.sso_location,
        signing_certificate_base64: &state.certificate_base64,
    });

    ([("content-type", "application/samlmetadata+xml")], document).into_response()
}

async fn sso_handler<S, R, U>(
    State(state): State<Shared<S, R, U>>,
    Form(form): Form<SsoForm>,
) -> Response
where
    S: XmlSigner + Send + Sync + 'static,
    R: ServiceProviderRegistry + 'static,
    U: Subject + 'static,
{
    let subject = state.subjects.resolve(form.session.as_deref());

    let response_id = format!("_r{}", uuid::Uuid::new_v4().simple());
    let assertion_id = format!("_a{}", uuid::Uuid::new_v4().simple());
    let session_index = format!("_s{}", uuid::Uuid::new_v4().simple());
    let transient_handle = format!("_t{}", uuid::Uuid::new_v4().simple());

    let request = SsoRequest {
        encoded: &form.saml_request,
        relay_state: form.relay_state.as_deref(),
        subject,
        response_id: &response_id,
        assertion_id: &assertion_id,
        session_index: &session_index,
        transient_handle: &transient_handle,
    };

    match handle(&state, &request) {
        Ok(SsoOutcome::Post {
            destination,
            saml_response,
            relay_state,
        }) => Html(post_form(
            &destination,
            &saml_response,
            relay_state.as_deref(),
        ))
        .into_response(),

        Ok(SsoOutcome::NeedsAuthentication) => (
            StatusCode::UNAUTHORIZED,
            "authentication is required before an assertion can be issued",
        )
            .into_response(),

        Ok(SsoOutcome::Refused { status, detail }) => (status, detail).into_response(),

        Err(fault) => (StatusCode::BAD_REQUEST, fault.to_string()).into_response(),
    }
}

pub fn build<S, R, U>(state: Shared<S, R, U>) -> Router
where
    S: XmlSigner + Send + Sync + 'static,
    R: ServiceProviderRegistry + 'static,
    U: Subject + 'static,
{
    Router::new()
        .route("/saml/metadata", get(metadata_handler::<S, R, U>))
        .route("/saml/sso", post(sso_handler::<S, R, U>))
        .with_state(state)
}
