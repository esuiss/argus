use std::collections::BTreeSet;

use super::check::{CheckError, CheckRequest, check};
use super::index::{MAX_TUPLES_PER_WRITE, TupleIndex};
use super::model::{EntityRef, Model, SubjectRef, Tuple};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TupleOp {
    Write(Tuple),
    Delete(Tuple),
}

impl TupleOp {
    #[must_use]
    pub const fn tuple(&self) -> &Tuple {
        match self {
            Self::Write(t) | Self::Delete(t) => t,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantRefusal {
    #[error("a write of {actual} tuples exceeds the {allowed} this server accepts")]
    TooManyTuples { allowed: usize, actual: usize },

    #[error("the actor does not hold {relation} on {object} and so cannot grant it")]
    GrantsWhatItDoesNotHold { object: String, relation: String },

    #[error("the actor holds no administrative relation on {object}")]
    NotAnAdministrator { object: String },

    #[error("the actor holds no administrative relation on {object}, the other end of the move")]
    NotAnAdministratorOfTheTarget { object: String },

    #[error("the write would give the actor {relation} on {object}, which it does not hold now")]
    RaisesTheActorsOwnPermissions { object: String, relation: String },

    #[error(transparent)]
    Check(#[from] CheckError),
}

/// Which relation on a type carries the authority to change that type's
/// tuples. §24 #14: any mechanism that can write a relation is a granting
/// mechanism and is subject to the same invariant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantPolicy {
    administrative: std::collections::BTreeMap<String, String>,
    structural: BTreeSet<(String, String)>,
}

impl GrantPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn administered_by(mut self, kind: &str, relation: &str) -> Self {
        self.administrative
            .insert(kind.to_owned(), relation.to_owned());
        self
    }

    /// A containment edge rather than a permission. §24 #11: moving one of
    /// these needs authority over both ends, and the actor is not expected to
    /// "hold" it, because being someone's parent is not a privilege.
    #[must_use]
    pub fn structural(mut self, kind: &str, relation: &str) -> Self {
        self.structural
            .insert((kind.to_owned(), relation.to_owned()));
        self
    }

    #[must_use]
    pub fn administrative_relation(&self, kind: &str) -> Option<&str> {
        self.administrative.get(kind).map(String::as_str)
    }

    #[must_use]
    pub fn is_structural(&self, kind: &str, relation: &str) -> bool {
        self.structural
            .contains(&(kind.to_owned(), relation.to_owned()))
    }
}

fn holds(
    model: &Model,
    index: &TupleIndex,
    object: &EntityRef,
    relation: &str,
    subject: &SubjectRef,
) -> Result<bool, CheckError> {
    let request = CheckRequest {
        object: object.clone(),
        relation: relation.to_owned(),
        subject: subject.clone(),
    };
    Ok(check(model, index, &request)?.allowed)
}

/// Every relation declared on the types the batch touches, which is the set
/// the escalation check compares before and after.
fn touched_pairs(model: &Model, ops: &[TupleOp]) -> BTreeSet<(EntityRef, String)> {
    let mut out = BTreeSet::new();

    for op in ops {
        let tuple = op.tuple();
        for object in [&tuple.object, tuple.subject.entity()] {
            if let Some(def) = model.type_def(object.kind()) {
                for relation in def.relations() {
                    out.insert((object.clone(), relation.to_owned()));
                }
            }
        }
    }

    out
}

fn apply(index: &TupleIndex, ops: &[TupleOp]) -> TupleIndex {
    let mut next = index.clone();
    for op in ops {
        match op {
            TupleOp::Write(t) => next.insert(t.clone()),
            TupleOp::Delete(t) => next.remove(t),
        }
    }
    next
}

/// The single gate every relation write passes through. §24 #13: HRU safety is
/// undecidable in general, so escalation is closed at run time instead of by
/// static analysis, and it is closed here rather than at each call site.
/// Keycloak declared this same principle and took five CVEs because the check
/// was not on every path.
pub fn may_apply(
    model: &Model,
    index: &TupleIndex,
    policy: &GrantPolicy,
    actor: &SubjectRef,
    ops: &[TupleOp],
) -> Result<(), GrantRefusal> {
    if ops.len() > MAX_TUPLES_PER_WRITE {
        return Err(GrantRefusal::TooManyTuples {
            allowed: MAX_TUPLES_PER_WRITE,
            actual: ops.len(),
        });
    }

    for op in ops {
        let tuple = op.tuple();

        // The actor must administer the object it is changing. Holding the
        // relation is not enough: a viewer must not be able to add viewers.
        match policy.administrative_relation(tuple.object.kind()) {
            Some(relation) => {
                if !holds(model, index, &tuple.object, relation, actor)? {
                    return Err(GrantRefusal::NotAnAdministrator {
                        object: tuple.object.to_string(),
                    });
                }
            }
            None => {
                return Err(GrantRefusal::NotAnAdministrator {
                    object: tuple.object.to_string(),
                });
            }
        }

        if policy.is_structural(tuple.object.kind(), &tuple.relation) {
            // §24 #11: both ends. Authority over the child alone is what let
            // CVE-2026-9099 reparent a privileged group under an attacker's.
            let target = tuple.subject.entity();
            match policy.administrative_relation(target.kind()) {
                Some(relation) => {
                    if !holds(model, index, target, relation, actor)? {
                        return Err(GrantRefusal::NotAnAdministratorOfTheTarget {
                            object: target.to_string(),
                        });
                    }
                }
                None => {
                    return Err(GrantRefusal::NotAnAdministratorOfTheTarget {
                        object: target.to_string(),
                    });
                }
            }
        } else if matches!(op, TupleOp::Write(_))
            && !holds(model, index, &tuple.object, &tuple.relation, actor)?
        {
            // A permission must already be held to be handed out. Removing one
            // is not a grant, so only writes are held to this.
            return Err(GrantRefusal::GrantsWhatItDoesNotHold {
                object: tuple.object.to_string(),
                relation: tuple.relation.clone(),
            });
        }
    }

    // §24 #11: a hierarchy move is two ordinary tuple changes, and each one
    // passes the checks above. What it must additionally not do is leave the
    // actor holding something it did not hold before. CVE-2026-9099 and
    // GitLab CVE-2026-35595 are both this shape.
    let after = apply(index, ops);

    for (object, relation) in touched_pairs(model, ops) {
        let before = holds(model, index, &object, &relation, actor)?;
        if before {
            continue;
        }
        if holds(model, &after, &object, &relation, actor)? {
            return Err(GrantRefusal::RaisesTheActorsOwnPermissions {
                object: object.to_string(),
                relation,
            });
        }
    }

    Ok(())
}
