use std::collections::{BTreeMap, BTreeSet};

use super::model::{EntityRef, SubjectRef, Tuple};

pub const MAX_TUPLES_PER_WRITE: usize = 1000;

#[derive(Debug, Clone, Default)]
pub struct TupleIndex {
    forward: BTreeMap<(String, String, String), BTreeSet<SubjectRef>>,
    reverse: BTreeMap<SubjectRef, BTreeSet<(EntityRef, String)>>,
    revision: u64,
}

fn forward_key(object: &EntityRef, relation: &str) -> (String, String, String) {
    (
        object.kind().to_owned(),
        object.id().to_owned(),
        relation.to_owned(),
    )
}

impl TupleIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn set_revision(&mut self, revision: u64) {
        self.revision = revision;
    }

    pub fn insert(&mut self, tuple: Tuple) {
        self.forward
            .entry(forward_key(&tuple.object, &tuple.relation))
            .or_default()
            .insert(tuple.subject.clone());
        self.reverse
            .entry(tuple.subject)
            .or_default()
            .insert((tuple.object, tuple.relation));
    }

    pub fn remove(&mut self, tuple: &Tuple) {
        let key = forward_key(&tuple.object, &tuple.relation);
        if let Some(set) = self.forward.get_mut(&key) {
            set.remove(&tuple.subject);
            if set.is_empty() {
                self.forward.remove(&key);
            }
        }
        if let Some(set) = self.reverse.get_mut(&tuple.subject) {
            set.remove(&(tuple.object.clone(), tuple.relation.clone()));
            if set.is_empty() {
                self.reverse.remove(&tuple.subject);
            }
        }
    }

    #[must_use]
    pub fn contains(&self, tuple: &Tuple) -> bool {
        self.forward
            .get(&forward_key(&tuple.object, &tuple.relation))
            .is_some_and(|set| set.contains(&tuple.subject))
    }

    #[must_use]
    pub fn subjects(&self, object: &EntityRef, relation: &str) -> Vec<SubjectRef> {
        self.forward
            .get(&forward_key(object, relation))
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn objects_of(&self, subject: &SubjectRef) -> Vec<(EntityRef, String)> {
        self.reverse
            .get(subject)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.forward.values().map(BTreeSet::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }
}
