use core::marker::PhantomData;

use super::check::{CheckError, CheckRequest, check};
use super::index::TupleIndex;
use super::model::{EntityRef, Model, SubjectRef};

/// An action the model understands. Implementors are unit types, so the
/// action a handler requires is part of its signature.
pub trait Action {
    const RELATION: &'static str;
}

/// Anything that can be addressed as an object in the relation graph.
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

/// Proof that a check said yes. The field is private and this module exposes
/// no constructor, so the only way to hold one is to have passed `authorize`.
/// A handler that takes `Authorized<T, A>` cannot be called without it.
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

    /// The revision the decision was taken at, so a caller that needs a fresher
    /// answer can tell how stale this proof is.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// The only way to produce an `Authorized`. §24 #9: the filter lives here and
/// not in a handler, so forgetting it is a compile error rather than a leak.
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
