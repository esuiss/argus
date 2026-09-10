use std::collections::BTreeSet;

use super::check::{CheckError, CheckRequest, check};
use super::index::TupleIndex;
use super::model::{EntityRef, Model, SubjectRef};

pub const MAX_RESULTS: usize = 1000;

pub const DEFAULT_STEP_BUDGET: u32 = 50_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSearch {
    pub subject: SubjectRef,
    pub relation: String,
    pub object_kind: String,
    pub limit: usize,
    pub after: Option<String>,
    pub step_budget: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub objects: Vec<EntityRef>,
    pub next: Option<String>,
    pub exhausted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SearchError {
    #[error("a search must ask for at least one result")]
    EmptyLimit,

    #[error(transparent)]
    Check(#[from] CheckError),
}

fn candidates(
    index: &TupleIndex,
    subject: &SubjectRef,
    kind: &str,
    budget: &mut u32,
) -> BTreeSet<EntityRef> {
    let mut found = BTreeSet::new();
    let mut frontier: Vec<SubjectRef> = vec![subject.clone()];
    let mut seen: BTreeSet<SubjectRef> = BTreeSet::new();

    while let Some(current) = frontier.pop() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;

        if !seen.insert(current.clone()) {
            continue;
        }

        for (object, relation) in index.objects_of(&current) {
            if object.kind() == kind {
                found.insert(object.clone());
            }
            if let Ok(next) = SubjectRef::userset(object.clone(), &relation) {
                frontier.push(next);
            }
            frontier.push(SubjectRef::direct(object));
        }
    }

    found
}

pub fn search_resources(
    model: &Model,
    index: &TupleIndex,
    request: &ResourceSearch,
) -> Result<Page, SearchError> {
    if request.limit == 0 {
        return Err(SearchError::EmptyLimit);
    }

    let limit = request.limit.min(MAX_RESULTS);
    let mut budget = request.step_budget;

    let mut candidates: Vec<EntityRef> =
        candidates(index, &request.subject, &request.object_kind, &mut budget)
            .into_iter()
            .collect();
    candidates.sort();

    let mut objects = Vec::new();
    let mut next = None;

    for object in candidates {
        if let Some(after) = request.after.as_deref()
            && object.id().as_bytes() <= after.as_bytes()
        {
            continue;
        }

        if budget == 0 {
            break;
        }
        budget -= 1;

        let allowed = check(
            model,
            index,
            &CheckRequest {
                object: object.clone(),
                relation: request.relation.clone(),
                subject: request.subject.clone(),
            },
        )?
        .allowed;

        if !allowed {
            continue;
        }

        if objects.len() == limit {
            next = Some(object.id().to_owned());
            break;
        }

        objects.push(object);
    }

    if next.is_some() {
        next = objects.last().map(|last| last.id().to_owned());
    }

    Ok(Page {
        objects,
        next,
        exhausted: budget == 0,
    })
}
