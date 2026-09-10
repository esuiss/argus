use crate::xml::{self, SAML_ASSERTION_NS, SAML_PROTOCOL_NS, XmlFault};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnRequest {
    pub id: String,
    pub issuer: String,
    pub destination: Option<String>,
    pub assertion_consumer_service_url: Option<String>,
    pub assertion_consumer_service_index: Option<u16>,
    pub protocol_binding: Option<String>,
    pub name_id_format: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub issue_instant: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestFault {
    #[error("the request could not be parsed safely: {0}")]
    Xml(#[from] XmlFault),

    #[error("the root element is not a samlp:AuthnRequest")]
    NotAnAuthnRequest,

    #[error("the request carries no {attribute}")]
    Missing { attribute: &'static str },

    #[error("the request declares SAML version {version}")]
    WrongVersion { version: String },

    #[error("the request names both an assertion consumer service URL and an index")]
    AmbiguousConsumerService,

    #[error("the assertion consumer service index is not a number")]
    ConsumerServiceIndexNotANumber,
}

pub fn parse(document: &str) -> Result<AuthnRequest, RequestFault> {
    let parsed = xml::parse(document)?;

    let root = parsed
        .document_element()
        .ok_or(RequestFault::NotAnAuthnRequest)?;

    if !xml::is_element(&parsed, root, SAML_PROTOCOL_NS, "AuthnRequest") {
        return Err(RequestFault::NotAnAuthnRequest);
    }

    let version = parsed
        .get_attribute(root, "Version")
        .ok_or(RequestFault::Missing {
            attribute: "Version",
        })?;

    if version != "2.0" {
        return Err(RequestFault::WrongVersion {
            version: version.to_owned(),
        });
    }

    let id = parsed
        .get_attribute(root, "ID")
        .ok_or(RequestFault::Missing { attribute: "ID" })?
        .to_owned();

    let issue_instant = parsed
        .get_attribute(root, "IssueInstant")
        .ok_or(RequestFault::Missing {
            attribute: "IssueInstant",
        })?
        .to_owned();

    let issuer_node = parsed
        .first_child_element_by_name_ns(root, SAML_ASSERTION_NS, "Issuer")
        .ok_or(RequestFault::Missing {
            attribute: "Issuer",
        })?;

    let issuer = parsed
        .element_text(issuer_node)
        .unwrap_or_default()
        .trim()
        .to_owned();

    if issuer.is_empty() {
        return Err(RequestFault::Missing {
            attribute: "Issuer",
        });
    }

    let assertion_consumer_service_url = parsed
        .get_attribute(root, "AssertionConsumerServiceURL")
        .map(str::to_owned);

    let raw_index = parsed.get_attribute(root, "AssertionConsumerServiceIndex");

    if assertion_consumer_service_url.is_some() && raw_index.is_some() {
        return Err(RequestFault::AmbiguousConsumerService);
    }

    let assertion_consumer_service_index = match raw_index {
        None => None,
        Some(raw) => Some(
            raw.trim()
                .parse()
                .map_err(|_| RequestFault::ConsumerServiceIndexNotANumber)?,
        ),
    };

    let name_id_format = parsed
        .first_child_element_by_name_ns(root, SAML_PROTOCOL_NS, "NameIDPolicy")
        .and_then(|node| parsed.get_attribute(node, "Format"))
        .map(str::to_owned);

    Ok(AuthnRequest {
        id,
        issuer,
        destination: parsed.get_attribute(root, "Destination").map(str::to_owned),
        assertion_consumer_service_url,
        assertion_consumer_service_index,
        protocol_binding: parsed
            .get_attribute(root, "ProtocolBinding")
            .map(str::to_owned),
        name_id_format,
        force_authn: parsed.get_attribute(root, "ForceAuthn") == Some("true"),
        is_passive: parsed.get_attribute(root, "IsPassive") == Some("true"),
        issue_instant,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionConsumerService {
    pub index: u16,
    pub binding: String,
    pub location: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsumerServiceFault {
    #[error("the service provider has registered no assertion consumer service")]
    NoneRegistered,

    #[error("the requested assertion consumer service location is not registered for this peer")]
    LocationNotRegistered,

    #[error("the requested assertion consumer service index is not registered for this peer")]
    IndexNotRegistered,

    #[error("the requested binding does not match the registered endpoint")]
    BindingMismatch,
}

pub fn resolve_consumer_service<'a>(
    request: &AuthnRequest,
    registered: &'a [AssertionConsumerService],
) -> Result<&'a AssertionConsumerService, ConsumerServiceFault> {
    if registered.is_empty() {
        return Err(ConsumerServiceFault::NoneRegistered);
    }

    if let Some(url) = request.assertion_consumer_service_url.as_deref() {
        let found = registered
            .iter()
            .find(|entry| entry.location == url)
            .ok_or(ConsumerServiceFault::LocationNotRegistered)?;

        if let Some(binding) = request.protocol_binding.as_deref()
            && found.binding != binding
        {
            return Err(ConsumerServiceFault::BindingMismatch);
        }

        return Ok(found);
    }

    if let Some(index) = request.assertion_consumer_service_index {
        return registered
            .iter()
            .find(|entry| entry.index == index)
            .ok_or(ConsumerServiceFault::IndexNotRegistered);
    }

    registered
        .iter()
        .find(|entry| entry.is_default)
        .or_else(|| registered.first())
        .ok_or(ConsumerServiceFault::NoneRegistered)
}
