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

// Bir tipin tuple'larını değiştirme yetkisini hangi ilişkinin taşıdığı.
// §24 #14: token'a claim yazabilen her mekanizma yetki-verendir ve aynı
// değişmeze tabidir.
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

    #[must_use]
    // İzin değil, içerme kenarı. §24 #11: bunu taşımak iki ucun ikisinde de
    // yetki ister ve aktörden bunu tutması beklenmez, çünkü birinin ebeveyni
    // olmak bir ayrıcalık değildir.
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

// Toplu işlemin dokunduğu tiplerde bildirilen her ilişki; yükseltme kontrolü
// öncesi ve sonrası tam olarak bu kümeyi karşılaştırır.
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

// Her ilişki yazmasının geçtiği tek kapı. §24 #13: HRU safety problemi genel
// halde karar verilemez (Harrison/Ruzzo/Ullman, CACM 19(8), 1976), o yüzden
// yükseltme statik analizle değil çalışma zamanında kapatılır, ve her çağrı
// yerinde değil burada kapatılır. Keycloak aynı prensibi beyan etti ama
// kontrol her yolda uygulanmadığı için beş CVE aldı.
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

        // Aktör değiştirdiği nesneyi yönetmeli. İlişkiyi tutmak yetmez:
        // bir viewer, viewer ekleyebilmemeli.
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
            // §24 #11: iki uç birden. Yalnızca çocuk üzerindeki yetki,
            // CVE-2026-9099'da ayrıcalıklı grubu saldırganın altına
            // taşımaya yeten şeydi.
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
            // Dağıtılan izne zaten sahip olunmalı. Bir izni kaldırmak verme
            // işlemi değildir, o yüzden yalnızca yazmalar buna bağlıdır.
            && !holds(model, index, &tuple.object, &tuple.relation, actor)?
        {
            return Err(GrantRefusal::GrantsWhatItDoesNotHold {
                object: tuple.object.to_string(),
                relation: tuple.relation.clone(),
            });
        }
    }

    // §24 #11: bir hiyerarşi taşıması iki sıradan tuple değişikliğidir ve her
    // biri yukarıdaki kontrollerden geçer. Ek olarak yapmaması gereken şey,
    // aktörü daha önce sahip olmadığı bir şeye sahip bırakmaktır.
    // CVE-2026-9099 ve GitLab CVE-2026-35595 aynı sınıftır.
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
