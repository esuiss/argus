use std::collections::BTreeSet;

use super::check::{CheckError, CheckRequest, check};
use super::index::TupleIndex;
use super::model::{EntityRef, Model, SubjectRef};

// §20 §7.5 aramayı 1000 sonuçla sınırlıyor ve sayfalamayı zorunlu kılıyor.
// Daha fazlasını isteyen çağıran bu kadarını alır.
pub const MAX_RESULTS: usize = 1000;

// §20 §7.5'teki 1 saniyelik sert deadline çağırana aittir; argus-core saat
// okumaz (§1 #15). Sınırlayabileceği şey iş miktarıdır, o yüzden arama bir
// adım bütçesi taşır ve bütçe bittiğinde sessizce kesmek yerine dürüstçe
// bildirir.
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
    // Yürüyüş bitmeden bütçe tükendiğinde true. Sayfa o zaman kısmî bir
    // cevaptır ve asla hepsi bu diye okunmamalıdır.
    pub exhausted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SearchError {
    #[error("a search must ask for at least one result")]
    EmptyLimit,

    #[error(transparent)]
    Check(#[from] CheckError),
}

// Aranan tipteki aday nesneler: öznenin yazılı olduğu her şey ve oradan
// erişilen her şey. §20 §7.7'nin F0 aşaması bilinçli olarak naif yürüyüştür,
// bu yüzden materialize indeks yerine önce sayar sonra kontrol eder.
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
            // Nesnenin kendisi başka öznelerin yerine geçebilir; bir grubun
            // üyesi olan bir grubun üyeliğine böyle ulaşılır.
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

    // İmleç döndürülen son kimliktir; sonraki sayfa ondan sonra devam eder.
    if next.is_some() {
        next = objects.last().map(|last| last.id().to_owned());
    }

    Ok(Page {
        objects,
        next,
        exhausted: budget == 0,
    })
}
