use crate::binding::{BINDING_POST, BINDING_REDIRECT};
use crate::escape::{attribute, text};
use crate::nameid::{FORMAT_EMAIL, FORMAT_PERSISTENT, FORMAT_TRANSIENT};
use crate::request::AssertionConsumerService;
use crate::xml::{self, SAML_METADATA_NS, XmlFault};

pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataFault {
    #[error("the metadata could not be parsed safely: {0}")]
    Xml(#[from] XmlFault),

    #[error("the root element is not an md:EntityDescriptor")]
    NotAnEntityDescriptor,

    #[error("the metadata carries no entityID")]
    NoEntityId,

    #[error("the metadata describes no service provider")]
    NoServiceProvider,

    #[error("the service provider registers no assertion consumer service")]
    NoConsumerService,

    #[error("a signing certificate in the metadata is not valid base64")]
    CertificateNotBase64,

    #[error("the service provider registers no signing certificate")]
    NoSigningCertificate,

    #[error("an assertion consumer service uses the unsupported binding {binding}")]
    UnsupportedBinding { binding: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProvider {
    pub entity_id: String,
    pub consumer_services: Vec<AssertionConsumerService>,
    pub signing_certificates: Vec<Vec<u8>>,
    pub wants_assertions_signed: bool,
    pub authn_requests_signed: bool,
}

pub fn parse_service_provider(document: &str) -> Result<ServiceProvider, MetadataFault> {
    use base64ct::{Base64, Encoding as _};

    let parsed = xml::parse(document)?;

    let root = parsed
        .document_element()
        .ok_or(MetadataFault::NotAnEntityDescriptor)?;

    if !xml::is_element(&parsed, root, SAML_METADATA_NS, "EntityDescriptor") {
        return Err(MetadataFault::NotAnEntityDescriptor);
    }

    let entity_id = parsed
        .get_attribute(root, "entityID")
        .ok_or(MetadataFault::NoEntityId)?
        .to_owned();

    let descriptor = parsed
        .first_child_element_by_name_ns(root, SAML_METADATA_NS, "SPSSODescriptor")
        .ok_or(MetadataFault::NoServiceProvider)?;

    let mut consumer_services = Vec::new();
    for node in
        parsed.child_elements_by_name_ns(descriptor, SAML_METADATA_NS, "AssertionConsumerService")
    {
        let binding = parsed
            .get_attribute(node, "Binding")
            .unwrap_or_default()
            .to_owned();

        if binding != BINDING_POST && binding != BINDING_REDIRECT {
            return Err(MetadataFault::UnsupportedBinding { binding });
        }

        let location = parsed
            .get_attribute(node, "Location")
            .unwrap_or_default()
            .to_owned();

        let index = parsed
            .get_attribute(node, "index")
            .and_then(|raw| raw.trim().parse().ok())
            .unwrap_or(0);

        consumer_services.push(AssertionConsumerService {
            index,
            binding,
            location,
            is_default: parsed.get_attribute(node, "isDefault") == Some("true"),
        });
    }

    if consumer_services.is_empty() {
        return Err(MetadataFault::NoConsumerService);
    }

    let mut signing_certificates = Vec::new();
    for key_descriptor in
        parsed.child_elements_by_name_ns(descriptor, SAML_METADATA_NS, "KeyDescriptor")
    {
        let use_attribute = parsed.get_attribute(key_descriptor, "use");
        if matches!(use_attribute, Some("encryption")) {
            continue;
        }

        let Some(key_info) =
            parsed.first_child_element_by_name_ns(key_descriptor, DSIG_NS, "KeyInfo")
        else {
            continue;
        };

        for data in parsed.child_elements_by_name_ns(key_info, DSIG_NS, "X509Data") {
            for certificate in parsed.child_elements_by_name_ns(data, DSIG_NS, "X509Certificate") {
                let raw: String = parsed
                    .element_text(certificate)
                    .unwrap_or_default()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();

                let der =
                    Base64::decode_vec(&raw).map_err(|_| MetadataFault::CertificateNotBase64)?;
                signing_certificates.push(der);
            }
        }
    }

    if signing_certificates.is_empty() {
        return Err(MetadataFault::NoSigningCertificate);
    }

    Ok(ServiceProvider {
        entity_id,
        consumer_services,
        signing_certificates,
        wants_assertions_signed: parsed.get_attribute(descriptor, "WantAssertionsSigned")
            == Some("true"),
        authn_requests_signed: parsed.get_attribute(descriptor, "AuthnRequestsSigned")
            == Some("true"),
    })
}

pub struct IdentityProvider<'a> {
    pub entity_id: &'a str,
    pub sso_post_location: &'a str,
    pub sso_redirect_location: &'a str,
    pub signing_certificate_base64: &'a str,
}

#[must_use]
pub fn identity_provider(descriptor: &IdentityProvider<'_>) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{}">"#,
            r#"<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false">"#,
            r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
            r#"<md:NameIDFormat>{}</md:NameIDFormat>"#,
            r#"<md:NameIDFormat>{}</md:NameIDFormat>"#,
            r#"<md:NameIDFormat>{}</md:NameIDFormat>"#,
            r#"<md:SingleSignOnService Binding="{}" Location="{}"/>"#,
            r#"<md:SingleSignOnService Binding="{}" Location="{}"/>"#,
            r#"</md:IDPSSODescriptor></md:EntityDescriptor>"#
        ),
        attribute(descriptor.entity_id),
        text(descriptor.signing_certificate_base64),
        text(FORMAT_PERSISTENT),
        text(FORMAT_TRANSIENT),
        text(FORMAT_EMAIL),
        attribute(BINDING_REDIRECT),
        attribute(descriptor.sso_redirect_location),
        attribute(BINDING_POST),
        attribute(descriptor.sso_post_location),
    )
}
