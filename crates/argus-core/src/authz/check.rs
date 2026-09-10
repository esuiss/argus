use std::collections::{BTreeMap, BTreeSet};

use super::index::TupleIndex;
use super::model::{EntityRef, Model, ModelError, Rewrite, SubjectRef};

// §20 §7.5: OpenFGA ile aynı tavan. Ziyaret kümesinden kaçan bir döngü bile
// burada sonlanır (CVE-2023-43645 sınıfı).
pub const MAX_DEPTH: u32 = 25;

// §20 §7.5: fan-out patlaması koruması. Bundan geniş bir tupleset yürünmez,
// reddedilir; tek bir ilişki bir check'i taramaya çeviremesin.
pub const MAX_WIDTH: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    #[error("resolution went deeper than the {allowed} levels this server accepts")]
    DepthExceeded { allowed: u32 },

    #[error(
        "relation {relation} on {object} fans out to {actual} objects and this server accepts {allowed}"
    )]
    WidthExceeded {
        object: String,
        relation: String,
        allowed: usize,
        actual: usize,
    },

    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    pub object: EntityRef,
    pub relation: String,
    pub subject: SubjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub evaluated_at: u64,
    pub reason_admin: Option<String>,
}

// Yürüyüşün tek adımı. Karar yeniden türetilmeden açıklanabilsin diye
// saklanır: §24 #10 her izin ve her retin denetlenebilir olmasını istiyor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceStep {
    pub depth: u32,
    pub object: String,
    pub relation: String,
    pub rule: &'static str,
    pub allowed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionTrace {
    pub steps: Vec<TraceStep>,
}

struct Resolver<'a> {
    model: &'a Model,
    index: &'a TupleIndex,
    memo: BTreeMap<(String, String, String), bool>,
    visiting: BTreeSet<(String, String, String)>,
    trace: Option<DecisionTrace>,
}

// Uzunluk önekli, asla birleştirilmiş değil. §20 §7.5 CVE-2026-48096'yı
// gösteriyor: dizgeleri uç uca ekleyerek kurulan bir anahtarda bir alan
// diğerine taşar ve iki farklı soru aynı cache girdisini paylaşır.
fn memo_key(object: &EntityRef, relation: &str, subject: &SubjectRef) -> (String, String, String) {
    let object = format!("{}:{}|{}", object.kind().len(), object.kind(), object.id());
    let relation = format!("{}|{relation}", relation.len());
    let subject = format!("{}|{subject}", subject.to_string().len());
    (object, relation, subject)
}

impl<'a> Resolver<'a> {
    fn new(model: &'a Model, index: &'a TupleIndex, trace: bool) -> Self {
        Self {
            model,
            index,
            memo: BTreeMap::new(),
            visiting: BTreeSet::new(),
            trace: trace.then(DecisionTrace::default),
        }
    }

    fn record(
        &mut self,
        depth: u32,
        object: &EntityRef,
        relation: &str,
        rule: &'static str,
        allowed: bool,
    ) {
        if let Some(trace) = self.trace.as_mut() {
            trace.steps.push(TraceStep {
                depth,
                object: object.to_string(),
                relation: relation.to_owned(),
                rule,
                allowed,
            });
        }
    }

    fn check(
        &mut self,
        object: &EntityRef,
        relation: &str,
        subject: &SubjectRef,
        depth: u32,
    ) -> Result<bool, CheckError> {
        if depth >= MAX_DEPTH {
            return Err(CheckError::DepthExceeded { allowed: MAX_DEPTH });
        }

        let key = memo_key(object, relation, subject);
        if let Some(known) = self.memo.get(&key) {
            return Ok(*known);
        }

        // Hâlâ çözümlenirken yeniden ulaşılan bir ilişki bir döngüdür.
        // `false` demek fail-closed seçimdir (§20 §6.4) ve yürüyüşü bitirir.
        if !self.visiting.insert(key.clone()) {
            self.record(depth, object, relation, "cycle", false);
            return Ok(false);
        }

        let rewrite = self.model.lookup(object.kind(), relation)?;
        let outcome = self.evaluate(object, relation, rewrite, subject, depth);

        self.visiting.remove(&key);

        let allowed = outcome?;
        self.memo.insert(key, allowed);
        Ok(allowed)
    }

    fn evaluate(
        &mut self,
        object: &EntityRef,
        relation: &str,
        rewrite: &Rewrite,
        subject: &SubjectRef,
        depth: u32,
    ) -> Result<bool, CheckError> {
        match rewrite {
            Rewrite::This => {
                let written = self.index.subjects(object, relation);

                if written.iter().any(|candidate| candidate == subject) {
                    self.record(depth, object, relation, "direct", true);
                    return Ok(true);
                }

                // Userset özne, o ilişkiyi tutan herkesin yerine geçer;
                // dolayısıyla her biri yeni bir sorudur.
                let usersets: Vec<SubjectRef> = written
                    .into_iter()
                    .filter(|candidate| !candidate.is_direct())
                    .collect();

                if usersets.len() > MAX_WIDTH {
                    return Err(CheckError::WidthExceeded {
                        object: object.to_string(),
                        relation: relation.to_owned(),
                        allowed: MAX_WIDTH,
                        actual: usersets.len(),
                    });
                }

                for candidate in usersets {
                    let Some(via) = candidate.relation() else {
                        continue;
                    };
                    if self.check(candidate.entity(), via, subject, depth + 1)? {
                        self.record(depth, object, relation, "userset", true);
                        return Ok(true);
                    }
                }

                self.record(depth, object, relation, "direct", false);
                Ok(false)
            }

            Rewrite::ComputedUserset { relation: other } => {
                let allowed = self.check(object, other, subject, depth + 1)?;
                self.record(depth, object, relation, "computed", allowed);
                Ok(allowed)
            }

            Rewrite::TupleToUserset { tupleset, computed } => {
                let parents = self.index.subjects(object, tupleset);

                if parents.len() > MAX_WIDTH {
                    return Err(CheckError::WidthExceeded {
                        object: object.to_string(),
                        relation: tupleset.clone(),
                        allowed: MAX_WIDTH,
                        actual: parents.len(),
                    });
                }

                for parent in parents {
                    if self.check(parent.entity(), computed, subject, depth + 1)? {
                        self.record(depth, object, relation, "tuple-to-userset", true);
                        return Ok(true);
                    }
                }

                self.record(depth, object, relation, "tuple-to-userset", false);
                Ok(false)
            }

            Rewrite::Union(operands) => {
                for operand in operands {
                    if self.evaluate(object, relation, operand, subject, depth + 1)? {
                        self.record(depth, object, relation, "union", true);
                        return Ok(true);
                    }
                }
                self.record(depth, object, relation, "union", false);
                Ok(false)
            }

            Rewrite::Intersection(operands) => {
                // Boş kesişim hiçbir şey vermez. Vacuous truth okuması
                // erişim dağıtırdı; §20 §6.4 fail-closed diyor.
                if operands.is_empty() {
                    self.record(depth, object, relation, "intersection", false);
                    return Ok(false);
                }
                for operand in operands {
                    if !self.evaluate(object, relation, operand, subject, depth + 1)? {
                        self.record(depth, object, relation, "intersection", false);
                        return Ok(false);
                    }
                }
                self.record(depth, object, relation, "intersection", true);
                Ok(true)
            }

            Rewrite::Exclusion { base, subtract } => {
                if !self.evaluate(object, relation, base, subject, depth + 1)? {
                    self.record(depth, object, relation, "exclusion", false);
                    return Ok(false);
                }
                let excluded = self.evaluate(object, relation, subtract, subject, depth + 1)?;
                self.record(depth, object, relation, "exclusion", !excluded);
                Ok(!excluded)
            }
        }
    }
}

// Tek karar noktası. Motorun geri kalanı bunun çağıranıdır; §24 #9 tam olarak
// tek bir tane olmasına dayanıyor.
pub fn check(
    model: &Model,
    index: &TupleIndex,
    request: &CheckRequest,
) -> Result<Decision, CheckError> {
    let mut resolver = Resolver::new(model, index, false);
    let allowed = resolver.check(&request.object, &request.relation, &request.subject, 0)?;
    Ok(Decision {
        allowed,
        evaluated_at: index.revision(),
        reason_admin: None,
    })
}

pub fn explain(
    model: &Model,
    index: &TupleIndex,
    request: &CheckRequest,
) -> Result<(Decision, DecisionTrace), CheckError> {
    let mut resolver = Resolver::new(model, index, true);
    let allowed = resolver.check(&request.object, &request.relation, &request.subject, 0)?;
    let trace = resolver.trace.take().unwrap_or_default();
    Ok((
        Decision {
            allowed,
            evaluated_at: index.revision(),
            reason_admin: None,
        },
        trace,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchSemantics {
    ExecuteAll,
    DenyOnFirstDeny,
    PermitOnFirstPermit,
}

// AuthZEN /evaluations (§20 §7.6 madde 2). Üç semantik yalnızca döngünün ne
// zaman durduğunda ayrışır; değerlendirilmeyen her istek reddedilmiş olarak
// raporlanır, böylece kısa devre asla izin olarak okunamaz.
pub fn batch_check(
    model: &Model,
    index: &TupleIndex,
    requests: &[CheckRequest],
    semantics: BatchSemantics,
) -> Result<Vec<Decision>, CheckError> {
    let mut out = Vec::with_capacity(requests.len());

    for request in requests {
        let decision = check(model, index, request)?;
        let allowed = decision.allowed;
        out.push(decision);

        match semantics {
            BatchSemantics::DenyOnFirstDeny if !allowed => break,
            BatchSemantics::PermitOnFirstPermit if allowed => break,
            BatchSemantics::ExecuteAll
            | BatchSemantics::DenyOnFirstDeny
            | BatchSemantics::PermitOnFirstPermit => {}
        }
    }

    while out.len() < requests.len() {
        out.push(Decision {
            allowed: false,
            evaluated_at: index.revision(),
            reason_admin: Some("not evaluated: the batch short circuited".to_owned()),
        });
    }

    Ok(out)
}
