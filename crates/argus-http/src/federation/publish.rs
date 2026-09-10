use std::sync::Arc;

use argus_core::federation::statement::{
    ENTITY_TYPE_FEDERATION, ENTITY_TYPE_OPENID_PROVIDER, EntityIdentifier, Role,
};
use argus_core::time::{Duration, Timestamp};
use argus_crypto::SigningKey;
use argus_proto::federation::{ENTITY_STATEMENT_TYPE, StatementJwtError, jwks_of, sign};
use serde_json::{Map, Value};

pub const DEFAULT_CONFIGURATION_LIFETIME: Duration = Duration::from_seconds(86_400);
pub const DEFAULT_SUBORDINATE_LIFETIME: Duration = Duration::from_seconds(3_600);

pub struct FederationIdentity {
    pub entity: EntityIdentifier,
    pub role: Role,
    pub signing_keys: Vec<Arc<SigningKey>>,
    pub authority_hints: Vec<EntityIdentifier>,
    pub organization_name: Option<String>,
    pub trust_marks: Vec<Value>,
}

impl FederationIdentity {
    #[must_use]
    pub fn jwks(&self) -> Value {
        let borrowed: Vec<&SigningKey> = self.signing_keys.iter().map(AsRef::as_ref).collect();
        jwks_of(&borrowed)
    }

    fn active(&self) -> Option<&Arc<SigningKey>> {
        self.signing_keys.first()
    }

    fn federation_entity(&self) -> Value {
        let mut body = Map::new();

        if self.role.serves_subordinates() {
            body.insert(
                "federation_fetch_endpoint".to_owned(),
                Value::String(format!("{}/federation/fetch", self.entity.as_str())),
            );
            body.insert(
                "federation_list_endpoint".to_owned(),
                Value::String(format!("{}/federation/list", self.entity.as_str())),
            );
        }

        body.insert(
            "federation_resolve_endpoint".to_owned(),
            Value::String(format!("{}/federation/resolve", self.entity.as_str())),
        );

        if let Some(name) = self.organization_name.as_ref() {
            body.insert("organization_name".to_owned(), Value::String(name.clone()));
        }

        Value::Object(body)
    }

    pub fn entity_configuration(
        &self,
        provider_metadata: &Value,
        now: Timestamp,
        lifetime: Duration,
    ) -> Result<String, StatementJwtError> {
        let key = self.active().ok_or(StatementJwtError::UnusableKey)?;

        let mut metadata = Map::new();
        metadata.insert(ENTITY_TYPE_FEDERATION.to_owned(), self.federation_entity());
        metadata.insert(
            ENTITY_TYPE_OPENID_PROVIDER.to_owned(),
            provider_metadata.clone(),
        );

        let mut claims = Map::new();
        claims.insert(
            "iss".to_owned(),
            Value::String(self.entity.as_str().to_owned()),
        );
        claims.insert(
            "sub".to_owned(),
            Value::String(self.entity.as_str().to_owned()),
        );
        claims.insert("iat".to_owned(), Value::from(now.as_unix_seconds()));
        claims.insert(
            "exp".to_owned(),
            Value::from(now.saturating_add(lifetime).as_unix_seconds()),
        );
        claims.insert("jwks".to_owned(), self.jwks());
        claims.insert("metadata".to_owned(), Value::Object(metadata));

        if !self.authority_hints.is_empty() {
            claims.insert(
                "authority_hints".to_owned(),
                Value::Array(
                    self.authority_hints
                        .iter()
                        .map(|hint| Value::String(hint.as_str().to_owned()))
                        .collect(),
                ),
            );
        }

        if !self.trust_marks.is_empty() {
            claims.insert(
                "trust_marks".to_owned(),
                Value::Array(self.trust_marks.clone()),
            );
        }

        sign(&Value::Object(claims), key, ENTITY_STATEMENT_TYPE)
    }

    pub fn subordinate_statement(
        &self,
        subject: &EntityIdentifier,
        subject_jwks: &Value,
        metadata_policy: Option<&Value>,
        constraints: Option<&Value>,
        now: Timestamp,
        lifetime: Duration,
    ) -> Result<String, StatementJwtError> {
        if !self.role.serves_subordinates() {
            return Err(StatementJwtError::UnusableKey);
        }

        let key = self.active().ok_or(StatementJwtError::UnusableKey)?;

        let mut claims = Map::new();
        claims.insert(
            "iss".to_owned(),
            Value::String(self.entity.as_str().to_owned()),
        );
        claims.insert("sub".to_owned(), Value::String(subject.as_str().to_owned()));
        claims.insert("iat".to_owned(), Value::from(now.as_unix_seconds()));
        claims.insert(
            "exp".to_owned(),
            Value::from(now.saturating_add(lifetime).as_unix_seconds()),
        );
        claims.insert("jwks".to_owned(), subject_jwks.clone());
        claims.insert(
            "source_endpoint".to_owned(),
            Value::String(format!("{}/federation/fetch", self.entity.as_str())),
        );

        if let Some(policy) = metadata_policy {
            claims.insert("metadata_policy".to_owned(), policy.clone());
        }

        if let Some(constraints) = constraints {
            claims.insert("constraints".to_owned(), constraints.clone());
        }

        sign(&Value::Object(claims), key, ENTITY_STATEMENT_TYPE)
    }
}
