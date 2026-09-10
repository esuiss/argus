use std::sync::Arc;

use argus_core::federation::chain::{self, ChainFault, MAX_CHAIN_LENGTH, ResolvedEntity};
use argus_core::federation::statement::{
    EntityIdentifier, EntityStatement, StatementFault, check_freshness, parse,
};
use argus_core::time::Timestamp;
use argus_proto::federation::{ENTITY_STATEMENT_TYPE, StatementJwtError, verify};

use super::fetch::{FetchFault, Reach, Resolver, fetch_configuration, fetch_subordinate};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveFault {
    #[error("an entity could not be fetched: {0}")]
    Fetch(#[from] FetchFault),

    #[error("a statement could not be verified: {0}")]
    Signature(#[from] StatementJwtError),

    #[error("a statement is not usable: {0}")]
    Statement(#[from] StatementFault),

    #[error("the chain is not usable: {0}")]
    Chain(#[from] ChainFault),

    #[error("the entity names no authority to climb towards")]
    NoAuthorityHints,

    #[error("no authority in the chain leads to a configured trust anchor")]
    NoRouteToAnchor,

    #[error("an authority publishes no fetch endpoint")]
    NoFetchEndpoint,
}

pub struct Walk {
    pub statements: Vec<EntityStatement>,
    pub tokens: Vec<String>,
}

pub struct Federation<R> {
    pub resolver: R,
    pub tls: Arc<rustls::ClientConfig>,
    pub trust_anchors: Vec<EntityIdentifier>,
    pub reach: Reach,
}

impl<R: Resolver> Federation<R> {
    pub async fn configuration(
        &self,
        entity: &EntityIdentifier,
        now: Timestamp,
    ) -> Result<(EntityStatement, String), ResolveFault> {
        let token = fetch_configuration(entity, &self.resolver, &self.tls, self.reach).await?;

        let statement = self.self_verified(&token, entity, now)?;
        Ok((statement, token))
    }

    #[allow(
        clippy::unused_self,
        reason = "it belongs to the runtime that owns the trust anchors and will read them"
    )]
    fn self_verified(
        &self,
        token: &str,
        entity: &EntityIdentifier,
        now: Timestamp,
    ) -> Result<EntityStatement, ResolveFault> {
        let unverified = decode_without_checking(token)?;

        if &unverified.issuer != entity || &unverified.subject != entity {
            return Err(ResolveFault::Statement(StatementFault::NotSelfIssued));
        }

        let body = verify(token, &unverified.keys, ENTITY_STATEMENT_TYPE)?;
        let statement = parse(&body)?;

        if &statement.issuer != entity || &statement.subject != entity {
            return Err(ResolveFault::Statement(StatementFault::NotSelfIssued));
        }

        check_freshness(&statement, now)?;
        Ok(statement)
    }

    pub async fn walk(
        &self,
        subject: &EntityIdentifier,
        now: Timestamp,
    ) -> Result<Walk, ResolveFault> {
        let (leaf, leaf_token) = self.configuration(subject, now).await?;

        if self.trust_anchors.iter().any(|known| known == subject) {
            return Ok(Walk {
                statements: vec![leaf],
                tokens: vec![leaf_token],
            });
        }

        if leaf.authority_hints.is_empty() {
            return Err(ResolveFault::NoAuthorityHints);
        }

        let mut best: Option<Walk> = None;

        for hint in &leaf.authority_hints {
            let attempt = Box::pin(self.climb(subject, hint, now, 1)).await;

            if let Ok(mut upward) = attempt {
                let mut statements = vec![leaf.clone()];
                let mut tokens = vec![leaf_token.clone()];
                statements.append(&mut upward.statements);
                tokens.append(&mut upward.tokens);

                best = Some(Walk { statements, tokens });
                break;
            }
        }

        best.ok_or(ResolveFault::NoRouteToAnchor)
    }

    async fn climb(
        &self,
        subject: &EntityIdentifier,
        authority: &EntityIdentifier,
        now: Timestamp,
        depth: usize,
    ) -> Result<Walk, ResolveFault> {
        if depth >= MAX_CHAIN_LENGTH {
            return Err(ResolveFault::Chain(ChainFault::TooLong));
        }

        let (authority_configuration, authority_token) = self.configuration(authority, now).await?;

        let fetch_endpoint = authority_configuration
            .federation_endpoint("federation_fetch_endpoint")
            .ok_or(ResolveFault::NoFetchEndpoint)?
            .to_owned();

        let subordinate_token = fetch_subordinate(
            &fetch_endpoint,
            subject,
            &self.resolver,
            &self.tls,
            self.reach,
        )
        .await?;

        let body = verify(
            &subordinate_token,
            &authority_configuration.keys,
            ENTITY_STATEMENT_TYPE,
        )?;

        let subordinate = parse(&body)?;

        if &subordinate.issuer != authority || &subordinate.subject != subject {
            return Err(ResolveFault::Statement(StatementFault::NotSelfIssued));
        }

        check_freshness(&subordinate, now)?;

        if self.trust_anchors.iter().any(|known| known == authority) {
            return Ok(Walk {
                statements: vec![subordinate, authority_configuration],
                tokens: vec![subordinate_token, authority_token],
            });
        }

        if authority_configuration.authority_hints.is_empty() {
            return Err(ResolveFault::NoRouteToAnchor);
        }

        for hint in &authority_configuration.authority_hints {
            let attempt = Box::pin(self.climb(authority, hint, now, depth.saturating_add(1))).await;

            if let Ok(mut upward) = attempt {
                let mut statements = vec![subordinate];
                let mut tokens = vec![subordinate_token];
                statements.append(&mut upward.statements);
                tokens.append(&mut upward.tokens);
                return Ok(Walk { statements, tokens });
            }
        }

        Err(ResolveFault::NoRouteToAnchor)
    }

    pub async fn resolve(
        &self,
        subject: &EntityIdentifier,
        entity_type: &str,
        now: Timestamp,
    ) -> Result<ResolvedEntity, ResolveFault> {
        let walk = self.walk(subject, now).await?;
        Ok(chain::resolve(
            &walk.statements,
            &self.trust_anchors,
            entity_type,
            now,
        )?)
    }
}

pub fn decode_without_checking(token: &str) -> Result<EntityStatement, ResolveFault> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    let body = token
        .split('.')
        .nth(1)
        .ok_or(ResolveFault::Signature(StatementJwtError::Malformed))?;

    let bytes = Base64UrlUnpadded::decode_vec(body)
        .map_err(|_| ResolveFault::Signature(StatementJwtError::Malformed))?;

    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ResolveFault::Signature(StatementJwtError::Malformed))?;

    Ok(parse(&value)?)
}

pub fn resolve_offline(
    tokens: &[String],
    trust_anchors: &[EntityIdentifier],
    entity_type: &str,
    now: Timestamp,
) -> Result<ResolvedEntity, ResolveFault> {
    if tokens.is_empty() {
        return Err(ResolveFault::Chain(ChainFault::Empty));
    }

    if tokens.len() > MAX_CHAIN_LENGTH {
        return Err(ResolveFault::Chain(ChainFault::TooLong));
    }

    let last = tokens.len().saturating_sub(1);
    let anchor_token = tokens
        .get(last)
        .ok_or(ResolveFault::Chain(ChainFault::Empty))?;

    let anchor_unverified = decode_without_checking(anchor_token)?;

    if anchor_unverified.issuer != anchor_unverified.subject {
        return Err(ResolveFault::Statement(StatementFault::NotSelfIssued));
    }

    if !trust_anchors
        .iter()
        .any(|known| known == &anchor_unverified.subject)
    {
        return Err(ResolveFault::Chain(ChainFault::NoTrustAnchor));
    }

    let anchor = parse(&verify(
        anchor_token,
        &anchor_unverified.keys,
        ENTITY_STATEMENT_TYPE,
    )?)?;

    let mut collected = vec![anchor.clone()];
    let mut superior_keys = anchor.keys;

    for index in (0..last).rev() {
        let token = tokens
            .get(index)
            .ok_or(ResolveFault::Chain(ChainFault::Empty))?;
        let statement = parse(&verify(token, &superior_keys, ENTITY_STATEMENT_TYPE)?)?;
        superior_keys = statement.keys.clone();
        collected.push(statement);
    }

    collected.reverse();

    Ok(chain::resolve(&collected, trust_anchors, entity_type, now)?)
}
