use std::collections::{BTreeMap, BTreeSet};

use super::index::TupleIndex;
use super::model::{EntityRef, Model, ModelError, Rewrite, SubjectRef};

/// §20 §7.5: the same ceiling `OpenFGA` uses. A cycle that survives the visited
/// set still terminates here.
pub const MAX_DEPTH: u32 = 25;

/// Fan-out ceiling. A tupleset wider than this is refused rather than walked,
/// so one relation cannot turn a check into a scan.
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

/// One step of the walk, kept so a decision can be explained without being
/// re-derived. §24 #10 wants every allow and every deny to be auditable.
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

fn memo_key(object: &EntityRef, relation: &str, subject: &SubjectRef) -> (String, String, String) {
    // Length prefixed, never concatenated. §20 §7.5 cites CVE-2026-48096:
    // a key built by joining strings lets one field bleed into the next.
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

        // A relation reached again while it is still being resolved is a cycle.
        // Answering false is the fail-closed choice and terminates the walk.
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

                // A userset subject stands for everyone holding that relation,
                // so each one is a further question.
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
                if operands.is_empty() {
                    // An empty intersection grants nothing. The alternative
                    // reading, vacuous truth, would hand out access.
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

/// The single decision point. Everything else in the engine is a caller of
/// this function; §24 #9 depends on there being exactly one.
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

/// `AuthZEN` /evaluations. The three semantics differ only in when the loop
/// stops; every request that is not evaluated is reported as denied so a
/// short circuit can never read as a grant.
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
