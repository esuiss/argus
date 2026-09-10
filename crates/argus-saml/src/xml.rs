use std::collections::HashSet;

use uppsala::{Document, NodeId, NodeKind};

// §16 §1.13: DOCTYPE ve ENTITY tümüyle reddedilir (XXE ve billion laughs),
// boyut, derinlik ve element sayısı sınırlıdır, yinelenen ID reddedilir.
// Ayrıştırıcı sınırları burada durur, imza doğrulamasında değil.
pub const MAX_DOCUMENT_BYTES: usize = 512 * 1024;
pub const MAX_DEPTH: usize = 64;
pub const MAX_ELEMENTS: usize = 20_000;

pub const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const SAML_METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

pub const ID_ATTRIBUTES: [&str; 3] = ["ID", "Id", "AssertionID"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlFault {
    #[error("the document is larger than this server will parse")]
    TooLarge,

    #[error("the document carries a document type declaration")]
    DoctypePresent,

    #[error("the document nests deeper than the accepted maximum")]
    TooDeep,

    #[error("the document has more elements than the accepted maximum")]
    TooManyElements,

    #[error("the identifier {id} is declared more than once")]
    DuplicateId { id: String },

    #[error("the document is not well formed: {detail}")]
    Malformed { detail: String },

    #[error("the document has no root element")]
    Empty,
}

pub fn parse(input: &str) -> Result<Document<'_>, XmlFault> {
    if input.len() > MAX_DOCUMENT_BYTES {
        return Err(XmlFault::TooLarge);
    }

    if contains_doctype(input) {
        return Err(XmlFault::DoctypePresent);
    }

    let document = uppsala::parse(input).map_err(|e| XmlFault::Malformed {
        detail: e.to_string(),
    })?;

    if document.doctype.is_some() {
        return Err(XmlFault::DoctypePresent);
    }

    let root = document.document_element().ok_or(XmlFault::Empty)?;

    audit(&document, root)?;

    Ok(document)
}

fn contains_doctype(input: &str) -> bool {
    let mut rest = input;
    while let Some(index) = rest.find("<!") {
        let Some(tail) = rest.get(index..) else {
            return false;
        };
        if tail.len() >= 9
            && tail
                .get(..9)
                .is_some_and(|s| s.eq_ignore_ascii_case("<!DOCTYPE"))
        {
            return true;
        }
        if tail.len() >= 8
            && tail
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("<!ENTITY"))
        {
            return true;
        }
        let Some(next) = rest.get(index + 2..) else {
            return false;
        };
        rest = next;
    }
    false
}

fn audit(document: &Document<'_>, root: NodeId) -> Result<(), XmlFault> {
    let mut identifiers: HashSet<String> = HashSet::new();
    let mut elements = 0_usize;
    let mut stack = vec![(root, 1_usize)];

    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(XmlFault::TooDeep);
        }

        if matches!(document.node_kind(node), Some(NodeKind::Element(_))) {
            elements = elements.saturating_add(1);
            if elements > MAX_ELEMENTS {
                return Err(XmlFault::TooManyElements);
            }

            for name in ID_ATTRIBUTES {
                if let Some(value) = document.get_attribute(node, name)
                    && !identifiers.insert(value.to_owned())
                {
                    return Err(XmlFault::DuplicateId {
                        id: value.to_owned(),
                    });
                }
            }
        }

        for child in document.children(node) {
            stack.push((child, depth.saturating_add(1)));
        }
    }

    Ok(())
}

#[must_use]
pub fn is_element(document: &Document<'_>, node: NodeId, namespace: &str, local: &str) -> bool {
    document
        .element(node)
        .is_some_and(|element| element.matches_name_ns(namespace, local))
}
