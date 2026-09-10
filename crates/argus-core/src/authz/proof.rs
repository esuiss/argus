use core::marker::PhantomData;

use super::check::{CheckError, CheckRequest, check};
use super::index::TupleIndex;
use super::model::{EntityRef, Model, SubjectRef};

pub trait Action {
    const RELATION: &'static str;
}

pub trait Resource {
    fn entity(&self) -> &EntityRef;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    #[error("the subject does not hold {relation} on {object}")]
    NotPermitted { object: String, relation: String },

    #[error(transparent)]
    Check(#[from] CheckError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized<R, A> {
    resource: R,
    revision: u64,
    action: PhantomData<A>,
}

impl<R, A: Action> Authorized<R, A> {
    #[must_use]
    pub const fn resource(&self) -> &R {
        &self.resource
    }

    #[must_use]
    pub fn into_inner(self) -> R {
        self.resource
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

pub fn authorize<R: Resource, A: Action>(
    model: &Model,
    index: &TupleIndex,
    subject: &SubjectRef,
    resource: R,
) -> Result<Authorized<R, A>, Denied> {
    let request = CheckRequest {
        object: resource.entity().clone(),
        relation: A::RELATION.to_owned(),
        subject: subject.clone(),
    };

    let decision = check(model, index, &request)?;

    if !decision.allowed {
        return Err(Denied::NotPermitted {
            object: request.object.to_string(),
            relation: A::RELATION.to_owned(),
        });
    }

    Ok(Authorized {
        resource,
        revision: decision.evaluated_at,
        action: PhantomData,
    })
}

impl Resource for EntityRef {
    fn entity(&self) -> &Self {
        self
    }
}
