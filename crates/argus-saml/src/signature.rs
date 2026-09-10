use bergshamra::c14n::C14nMode;
use bergshamra::dsig::{DsigContext, VerifyResult};
use bergshamra::keys::KeysManager;
use bergshamra_xml::nodeset::NodeSet;
use uppsala::Document;

use crate::xml::{self, XmlFault};

pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureFault {
    #[error("the document could not be parsed safely: {0}")]
    Xml(#[from] XmlFault),

    #[error("the document carries no signature")]
    Unsigned,

    #[error("the signature does not verify: {reason}")]
    Invalid { reason: String },

    #[error("the signature does not cover the whole of what it claims to cover")]
    IncompleteCoverage,

    #[error("the signature covers nothing this server is willing to act on")]
    NothingSigned,

    #[error("the signature uses {algorithm}, which is not accepted")]
    DisallowedAlgorithm { algorithm: String },

    #[error("the signing key is not one this peer is registered with")]
    UnknownKey,

    #[error("the verified subtree could not be isolated: {detail}")]
    Isolation { detail: String },

    #[error("the reference {uri} points outside this document")]
    ReferenceLeavesTheDocument { uri: String },
}

pub struct VerifiedFragment {
    xml: String,
    reference_uri: String,
}

impl VerifiedFragment {
    #[must_use]
    pub fn xml(&self) -> &str {
        &self.xml
    }

    #[must_use]
    pub fn reference_uri(&self) -> &str {
        &self.reference_uri
    }

    pub fn document(&self) -> Result<Document<'_>, XmlFault> {
        xml::parse(&self.xml)
    }
}

impl core::fmt::Debug for VerifiedFragment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedFragment")
            .field("reference_uri", &self.reference_uri)
            .field("bytes", &self.xml.len())
            .finish()
    }
}

pub trait XmlVerifier {
    fn verify(
        &self,
        document: &str,
        certificates: &[Vec<u8>],
    ) -> Result<Vec<VerifiedFragment>, SignatureFault>;
}

#[derive(Debug, Default)]
pub struct BergshamraVerifier;

#[must_use]
// §16 §1.13 ve PortSwigger "The Fragile Lock" (10 Ara 2025): Void
// Canonicalization sınıfı, canonicalization çözülemeyen bir göreli URI'yle
// karşılaşınca güvenli şekilde fail etmek yerine BOŞ dizge döndürüp boş
// içeriğin geçerli hash'ini üretmesidir. Bu yüzden `#fragment` olmayan hiçbir
// referans kabul edilmez.
pub fn is_same_document_reference(uri: &str) -> bool {
    let Some(fragment) = uri.strip_prefix('#') else {
        return false;
    };
    !fragment.is_empty()
        && fragment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

fn allowed(algorithm: &str) -> bool {
    matches!(algorithm, "RSA" | "EC-P256" | "EC-P384")
}

impl XmlVerifier for BergshamraVerifier {
    fn verify(
        &self,
        document: &str,
        certificates: &[Vec<u8>],
    ) -> Result<Vec<VerifiedFragment>, SignatureFault> {
        let parsed = xml::parse(document)?;

        if certificates.is_empty() {
            return Err(SignatureFault::UnknownKey);
        }

        let mut manager = KeysManager::new();
        for (index, der) in certificates.iter().enumerate() {
            let key = bergshamra::keys::loader::load_x509_cert_der(der)
                .map_err(|_| SignatureFault::UnknownKey)?
                .with_name(format!("peer-{index}"));
            manager.add_key(key);
        }

        let context = DsigContext::new(manager)
            .with_trusted_keys_only(true)
            .with_strict_verification(true)
            .with_require_reference_digests(true)
            .with_skip_time_checks(true);

        let results = bergshamra::dsig::verify::verify_all_document(&context, &parsed).map_err(
            |e| match e {
                bergshamra::Error::MissingElement(_) => SignatureFault::Unsigned,
                other => SignatureFault::Invalid {
                    reason: other.to_string(),
                },
            },
        )?;

        if results.is_empty() {
            return Err(SignatureFault::Unsigned);
        }

        let mut fragments = Vec::new();

        for result in results {
            match result {
                VerifyResult::Invalid { reason } => {
                    return Err(SignatureFault::Invalid { reason });
                }
                VerifyResult::Valid {
                    references,
                    key_info,
                    ..
                } => {
                    if !allowed(&key_info.algorithm) {
                        return Err(SignatureFault::DisallowedAlgorithm {
                            algorithm: key_info.algorithm,
                        });
                    }

                    if references.is_empty() {
                        return Err(SignatureFault::NothingSigned);
                    }

                    for reference in references {
                        if !is_same_document_reference(&reference.uri) {
                            return Err(SignatureFault::ReferenceLeavesTheDocument {
                                uri: reference.uri,
                            });
                        }

                        if !reference.digest_verified {
                            return Err(SignatureFault::IncompleteCoverage);
                        }

                        let Some(node) = reference.resolved_node else {
                            return Err(SignatureFault::IncompleteCoverage);
                        };

                        // XSW savunmasının mimari çekirdeği. XSW1, 2, 3, 4 ve 7
                        // DOKÜMAN olarak başarıyla doğrulanır; onları yenen tek
                        // şey düğüm izolasyonudur. Doğrulama, doğrulanan düğümün
                        // exclusive c14n baytlarını döndürür, böylece çağıran
                        // imzalananla okuduğunu ayrıştıramaz.
                        let set = NodeSet::tree_without_comments(node, &parsed);
                        let bytes = bergshamra::c14n::canonicalize_doc::<&str>(
                            &parsed,
                            C14nMode::Exclusive,
                            Some(&set),
                            &[],
                        )
                        .map_err(|e| SignatureFault::Isolation {
                            detail: e.to_string(),
                        })?;

                        let xml =
                            String::from_utf8(bytes).map_err(|e| SignatureFault::Isolation {
                                detail: e.to_string(),
                            })?;

                        fragments.push(VerifiedFragment {
                            xml,
                            reference_uri: reference.uri,
                        });
                    }
                }
            }
        }

        Ok(fragments)
    }
}

pub trait XmlSigner {
    fn sign(&self, template: &str) -> Result<String, SignatureFault>;
}

pub struct BergshamraSigner {
    manager: KeysManager,
}

impl BergshamraSigner {
    pub fn from_rsa_private_pem(pem: &[u8]) -> Result<Self, SignatureFault> {
        let key = bergshamra::keys::loader::load_rsa_private_pem(pem)
            .map_err(|_| SignatureFault::UnknownKey)?;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        Ok(Self { manager })
    }
}

impl core::fmt::Debug for BergshamraSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BergshamraSigner")
    }
}

impl XmlSigner for BergshamraSigner {
    fn sign(&self, template: &str) -> Result<String, SignatureFault> {
        let context = DsigContext::new(self.manager.clone());

        bergshamra::dsig::sign::sign(&context, template).map_err(|e| SignatureFault::Invalid {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::is_same_document_reference;

    #[test]
    fn only_a_fragment_within_this_document_is_a_reference_this_server_will_follow() {
        assert!(is_same_document_reference("#_assertion-1"));
        assert!(is_same_document_reference("#id.1:x"));
    }

    #[test]
    fn a_reference_that_would_reach_the_file_system_or_the_network_is_refused() {
        assert!(!is_same_document_reference("unresolvable.xml"));
        assert!(!is_same_document_reference("../../etc/passwd"));
        assert!(!is_same_document_reference("file:///etc/passwd"));
        assert!(!is_same_document_reference(
            "https://attacker.test/payload.xml"
        ));
        assert!(!is_same_document_reference("cid:attachment"));
    }

    #[test]
    fn an_empty_reference_means_the_whole_document_and_is_refused() {
        assert!(
            !is_same_document_reference(""),
            "an empty URI selects the whole document, which is not a node this server acts on"
        );
        assert!(!is_same_document_reference("#"));
    }

    #[test]
    fn a_fragment_carrying_a_path_or_a_query_is_refused() {
        assert!(!is_same_document_reference("#../other"));
        assert!(!is_same_document_reference("#a/b"));
        assert!(!is_same_document_reference("#a?b"));
        assert!(!is_same_document_reference("#xpointer(/*)"));
    }
}
