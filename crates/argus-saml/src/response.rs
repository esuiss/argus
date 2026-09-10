use core::fmt::Write as _;

use argus_core::time::{Duration, Timestamp, rfc3339};

use crate::escape::{attribute, text};
use crate::nameid::NameId;
use crate::signature::{ENVELOPED, EXCLUSIVE_C14N, RSA_SHA256, SHA256};

pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
pub const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
pub const STATUS_RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
pub const STATUS_NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

pub const CONFIRMATION_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

pub const AUTHN_CONTEXT_PASSWORD_PROTECTED: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
pub const AUTHN_CONTEXT_MFA: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication";

pub const DEFAULT_ASSERTION_LIFETIME: Duration = Duration::from_seconds(300);

pub struct Attribute {
    pub name: String,
    pub name_format: String,
    pub values: Vec<String>,
}

pub const ATTRIBUTE_NAME_FORMAT_URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
pub const ATTRIBUTE_NAME_FORMAT_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

pub struct AssertionRequest<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub recipient: &'a str,
    pub in_response_to: Option<&'a str>,
    pub name_id: &'a NameId,
    pub session_index: &'a str,
    pub authn_context: &'a str,
    pub attributes: &'a [Attribute],
    pub response_id: &'a str,
    pub assertion_id: &'a str,
    pub certificate_base64: &'a str,
    pub now: Timestamp,
    pub lifetime: Duration,
    pub session_expiry: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResponseFault {
    #[error("an identifier must start with a letter or underscore to be a valid xsd:ID")]
    IdentifierNotAnNcName,

    #[error("the assertion lifetime is not a usable window")]
    LifetimeUnusable,
}

fn is_ncname(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub fn template(request: &AssertionRequest<'_>) -> Result<String, ResponseFault> {
    if !is_ncname(request.assertion_id) || !is_ncname(request.response_id) {
        return Err(ResponseFault::IdentifierNotAnNcName);
    }

    if request.lifetime.as_seconds() <= 0 {
        return Err(ResponseFault::LifetimeUnusable);
    }

    let issue_instant = rfc3339(request.now);
    let not_on_or_after = rfc3339(request.now.saturating_add(request.lifetime));
    let session_not_on_or_after = rfc3339(request.session_expiry);

    let assertion_id = attribute(request.assertion_id);
    let response_id = attribute(request.response_id);
    let issuer = text(request.issuer);
    let recipient = attribute(request.recipient);
    let audience = text(request.audience);

    let in_response_to_response = request.in_response_to.map_or_else(String::new, |value| {
        format!(r#" InResponseTo="{}""#, attribute(value))
    });
    let in_response_to_confirmation = request.in_response_to.map_or_else(String::new, |value| {
        format!(r#" InResponseTo="{}""#, attribute(value))
    });

    let name_id = format!(
        r#"<saml:NameID Format="{}">{}</saml:NameID>"#,
        attribute(request.name_id.format.as_uri()),
        text(&request.name_id.value)
    );

    let attributes = if request.attributes.is_empty() {
        String::new()
    } else {
        let mut out = String::from("<saml:AttributeStatement>");
        for entry in request.attributes {
            let _ = write!(
                out,
                r#"<saml:Attribute Name="{}" NameFormat="{}">"#,
                attribute(&entry.name),
                attribute(&entry.name_format)
            );
            for value in &entry.values {
                let _ = write!(
                    out,
                    r#"<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{}</saml:AttributeValue>"#,
                    text(value)
                );
            }
            out.push_str("</saml:Attribute>");
        }
        out.push_str("</saml:AttributeStatement>");
        out
    };

    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXCLUSIVE_C14N}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{EXCLUSIVE_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##,
        text(request.certificate_base64)
    );

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{recipient}"{in_response_to_response}><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{STATUS_SUCCESS}"/></samlp:Status><saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}"><saml:Issuer>{issuer}</saml:Issuer>{signature}<saml:Subject>{name_id}<saml:SubjectConfirmation Method="{CONFIRMATION_BEARER}"><saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{recipient}"{in_response_to_confirmation}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{issue_instant}" NotOnOrAfter="{not_on_or_after}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{}" SessionNotOnOrAfter="{session_not_on_or_after}"><saml:AuthnContext><saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>{attributes}</saml:Assertion></samlp:Response>"#,
        attribute(request.session_index),
        text(request.authn_context)
    ))
}

pub fn failure(
    issuer: &str,
    recipient: &str,
    in_response_to: Option<&str>,
    response_id: &str,
    status: &str,
    now: Timestamp,
) -> Result<String, ResponseFault> {
    if !is_ncname(response_id) {
        return Err(ResponseFault::IdentifierNotAnNcName);
    }

    let in_response_to = in_response_to.map_or_else(String::new, |value| {
        format!(r#" InResponseTo="{}""#, attribute(value))
    });

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}"{in_response_to}><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:Response>"#,
        attribute(response_id),
        rfc3339(now),
        attribute(recipient),
        text(issuer),
        attribute(status)
    ))
}
