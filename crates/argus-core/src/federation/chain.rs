use serde_json::Value;

use crate::time::Timestamp;

use super::policy::{self, MetadataPolicy};
use super::statement::{
    Constraints, EntityIdentifier, EntityStatement, StatementFault, check_configuration,
    check_freshness, check_subordinate, naming_permits,
};

pub const MAX_CHAIN_LENGTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainFault {
    #[error("a statement in the chain is not usable: {0}")]
    Statement(#[from] StatementFault),

    #[error("the chain applies a policy this server cannot reconcile: {0}")]
    Policy(#[from] policy::PolicyFault),

    #[error("the resolved metadata does not satisfy the chain's policy: {0}")]
    Apply(#[from] policy::ApplyFault),

    #[error("the chain is empty")]
    Empty,

    #[error("the chain is longer than this server will follow")]
    TooLong,

    #[error("the chain revisits {entity} and would not terminate")]
    Cycle { entity: String },

    #[error("the chain does not end at a trust anchor this server is configured with")]
    NoTrustAnchor,

    #[error("a constraint limits the path to {allowed} links and the chain has {actual}")]
    PathTooLong { allowed: u32, actual: usize },

    #[error("a naming constraint excludes {entity}")]
    NameNotPermitted { entity: String },

    #[error("the entity type {entity_type} is not one the chain allows")]
    EntityTypeNotAllowed { entity_type: String },

    #[error("the subject publishes no metadata for the entity type {entity_type}")]
    NoSuchEntityType { entity_type: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedEntity {
    pub subject: EntityIdentifier,
    pub trust_anchor: EntityIdentifier,
    pub entity_type: String,
    pub metadata: Value,
    pub expires_at: Timestamp,
    pub path_length: usize,
}

fn combine_constraints(into: &mut Constraints, from: &Constraints) {
    into.max_path_length = match (into.max_path_length, from.max_path_length) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    };

    into.naming_allowed
        .extend(from.naming_allowed.iter().cloned());
    into.naming_excluded
        .extend(from.naming_excluded.iter().cloned());

    into.allowed_entity_types = match (
        into.allowed_entity_types.take(),
        from.allowed_entity_types.clone(),
    ) {
        (Some(left), Some(right)) => Some(
            left.into_iter()
                .filter(|name| right.contains(name))
                .collect(),
        ),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    };
}

#[allow(
    clippy::too_many_lines,
    reason = "the chain checks read as one ordered list of what the specification requires"
)]
// OpenID Federation 1.1 §4: güven zinciri çözümlemesi. Yukarıdan aşağı
// doğrulanır — çıpa kendi anahtarlarıyla, her bildiri bir üstünün
// anahtarlarıyla, yaprak ise üstünün onayladığı anahtarlarla.
pub fn resolve(
    chain: &[EntityStatement],
    trust_anchors: &[EntityIdentifier],
    entity_type: &str,
    now: Timestamp,
) -> Result<ResolvedEntity, ChainFault> {
    let Some(leaf) = chain.first() else {
        return Err(ChainFault::Empty);
    };

    if chain.len() > MAX_CHAIN_LENGTH {
        return Err(ChainFault::TooLong);
    }

    if chain.len() == 1 {
        check_configuration(leaf, &leaf.subject)?;
        check_freshness(leaf, now)?;

        if !trust_anchors.iter().any(|known| known == &leaf.subject) {
            return Err(ChainFault::NoTrustAnchor);
        }

        let published =
            leaf.entity_type(entity_type)
                .ok_or_else(|| ChainFault::NoSuchEntityType {
                    entity_type: entity_type.to_owned(),
                })?;

        return Ok(ResolvedEntity {
            subject: leaf.subject.clone(),
            trust_anchor: leaf.subject.clone(),
            entity_type: entity_type.to_owned(),
            metadata: published.clone(),
            expires_at: leaf.expires_at,
            path_length: 0,
        });
    }

    let mut walked: Vec<&str> = Vec::with_capacity(chain.len());
    walked.push(leaf.subject.as_str());

    for statement in chain.get(1..chain.len().saturating_sub(1)).unwrap_or(&[]) {
        // Döngü tespiti ÖZNELERİ değil OTORİTELERİ yürür. Aynı özne bir zincirde
        // meşru olarak birden fazla kez görünebilir; kendini imzalayan bir
        // otorite döngüsü göremezsin.
        let authority = statement.issuer.as_str();
        if walked.contains(&authority) {
            return Err(ChainFault::Cycle {
                entity: authority.to_owned(),
            });
        }
        walked.push(authority);
    }

    for statement in chain {
        check_freshness(statement, now)?;
    }

    check_configuration(leaf, &leaf.subject)?;

    let anchor = chain.last().ok_or(ChainFault::Empty)?;

    if !trust_anchors.iter().any(|known| known == &anchor.subject) {
        return Err(ChainFault::NoTrustAnchor);
    }

    check_configuration(anchor, &anchor.subject)?;

    let mut expires_at = leaf.expires_at;
    let mut constraints = Constraints::default();
    let mut superior_policy = MetadataPolicy::default();

    let subordinates = chain.get(1..chain.len().saturating_sub(1)).unwrap_or(&[]);

    let mut expected_subject = &leaf.subject;

    for statement in subordinates {
        check_subordinate(statement, &statement.issuer, expected_subject)?;

        if !leaf.authority_hints.is_empty()
            && expected_subject == &leaf.subject
            && !leaf
                .authority_hints
                .iter()
                .any(|hint| hint == &statement.issuer)
        {
            return Err(ChainFault::NoTrustAnchor);
        }

        if statement.expires_at < expires_at {
            expires_at = statement.expires_at;
        }

        combine_constraints(&mut constraints, &statement.constraints);

        if let Some(raw) = statement.metadata_policy.as_ref() {
            let below = policy_for(raw, entity_type)?;
            superior_policy = policy::merge(&superior_policy, &below)?;
        }

        expected_subject = &statement.issuer;
    }

    if expected_subject != &anchor.subject {
        return Err(ChainFault::NoTrustAnchor);
    }

    if anchor.expires_at < expires_at {
        expires_at = anchor.expires_at;
    }

    let path_length = subordinates.len();

    if let Some(allowed) = constraints.max_path_length
        && path_length > allowed as usize
    {
        return Err(ChainFault::PathTooLong {
            allowed,
            actual: path_length,
        });
    }

    if !naming_permits(&leaf.subject, &constraints) {
        return Err(ChainFault::NameNotPermitted {
            entity: leaf.subject.as_str().to_owned(),
        });
    }

    if let Some(allowed) = constraints.allowed_entity_types.as_ref()
        && !allowed.iter().any(|name| name == entity_type)
    {
        return Err(ChainFault::EntityTypeNotAllowed {
            entity_type: entity_type.to_owned(),
        });
    }

    let published = leaf
        .entity_type(entity_type)
        .ok_or_else(|| ChainFault::NoSuchEntityType {
            entity_type: entity_type.to_owned(),
        })?;

    let metadata = policy::apply(published, &superior_policy)?;

    Ok(ResolvedEntity {
        subject: leaf.subject.clone(),
        trust_anchor: anchor.subject.clone(),
        entity_type: entity_type.to_owned(),
        metadata,
        expires_at,
        path_length,
    })
}

fn policy_for(raw: &Value, entity_type: &str) -> Result<MetadataPolicy, policy::PolicyFault> {
    let Some(object) = raw.as_object() else {
        return Err(policy::PolicyFault::NotAnObject);
    };

    match object.get(entity_type) {
        None => Ok(MetadataPolicy::default()),
        Some(body) => policy::parse(body),
    }
}
