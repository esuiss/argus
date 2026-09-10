use std::collections::{BTreeMap, BTreeSet};

// §20 §7.5 zorunlu kotalar tablosu: store başına 200 tip. Model karmaşıklığı
// sınırı, hasar kontrolü amaçlı.
pub const MAX_TYPES: usize = 200;
pub const MAX_RELATIONS_PER_TYPE: usize = 64;
pub const MAX_REWRITE_OPERANDS: usize = 16;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_REWRITE_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityRef {
    kind: String,
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("an identifier must not be empty")]
    Empty,

    #[error("an identifier of {actual} bytes exceeds the {allowed} this server accepts")]
    TooLong { allowed: usize, actual: usize },

    #[error("an identifier must not contain '{0}'")]
    ReservedCharacter(char),

    #[error("the model declares {actual} types and this server accepts {allowed}")]
    TooManyTypes { allowed: usize, actual: usize },

    #[error("type {kind} declares {actual} relations and this server accepts {allowed}")]
    TooManyRelations {
        kind: String,
        allowed: usize,
        actual: usize,
    },

    #[error("a rewrite combines {actual} operands and this server accepts {allowed}")]
    TooManyOperands { allowed: usize, actual: usize },

    #[error("a rewrite nests deeper than the {allowed} levels this server accepts")]
    RewriteTooDeep { allowed: usize },

    #[error("type {kind} is not declared by the model")]
    UnknownType { kind: String },

    #[error("type {kind} declares no relation named {relation}")]
    UnknownRelation { kind: String, relation: String },

    #[error("relation {kind}#{relation} refers to itself without going through a tuple")]
    ImmediateSelfReference { kind: String, relation: String },
}

impl EntityRef {
    // Tuple grameri (§20 §7.4) üç karakteri ayırıcı olarak kullanıyor:
    // `tip:kimlik#ilişki@özne`. Bunlar tanımlayıcının içinde geçemez, yoksa
    // ayrıştırılmış bir tuple başka bir tuple olarak okunabilir.
    fn check_identifier(value: &str) -> Result<(), ModelError> {
        if value.is_empty() {
            return Err(ModelError::Empty);
        }
        if value.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::TooLong {
                allowed: MAX_IDENTIFIER_BYTES,
                actual: value.len(),
            });
        }
        for c in value.chars() {
            if matches!(c, ':' | '#' | '@') {
                return Err(ModelError::ReservedCharacter(c));
            }
        }
        Ok(())
    }

    pub fn new(kind: &str, id: &str) -> Result<Self, ModelError> {
        Self::check_identifier(kind)?;
        Self::check_identifier(id)?;
        Ok(Self {
            kind: kind.to_owned(),
            id: id.to_owned(),
        })
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl core::fmt::Display for EntityRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

// Özne ya bir varlıktır ya da bir varlık üzerinde bir ilişkiyi tutan herkes.
// `group:eng#member` ikinci biçimdir ve modeli rol tabanlı değil ilişki
// tabanlı yapan şey budur (§20 §7.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectRef {
    entity: EntityRef,
    relation: Option<String>,
}

impl SubjectRef {
    #[must_use]
    pub const fn direct(entity: EntityRef) -> Self {
        Self {
            entity,
            relation: None,
        }
    }

    pub fn userset(entity: EntityRef, relation: &str) -> Result<Self, ModelError> {
        EntityRef::check_identifier(relation)?;
        Ok(Self {
            entity,
            relation: Some(relation.to_owned()),
        })
    }

    #[must_use]
    pub const fn entity(&self) -> &EntityRef {
        &self.entity
    }

    #[must_use]
    pub fn relation(&self) -> Option<&str> {
        self.relation.as_deref()
    }

    #[must_use]
    pub const fn is_direct(&self) -> bool {
        self.relation.is_none()
    }
}

impl core::fmt::Display for SubjectRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.relation {
            Some(relation) => write!(f, "{}#{relation}", self.entity),
            None => write!(f, "{}", self.entity),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tuple {
    pub object: EntityRef,
    pub relation: String,
    pub subject: SubjectRef,
}

impl Tuple {
    pub fn new(object: EntityRef, relation: &str, subject: SubjectRef) -> Result<Self, ModelError> {
        EntityRef::check_identifier(relation)?;
        Ok(Self {
            object,
            relation: relation.to_owned(),
            subject,
        })
    }
}

impl core::fmt::Display for Tuple {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}#{}@{}", self.object, self.relation, self.subject)
    }
}

// Bir ilişkinin nasıl hesaplandığı. Yalnızca `This` tuple okur; diğer her
// biçim soruyu başka ilişkilere yeniden yazar (Zanzibar userset rewrite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rewrite {
    This,

    ComputedUserset {
        relation: String,
    },

    // Bu nesneden `tupleset` üzerinden erişilen her nesne için o nesnede
    // `computed` sorulur. İzinlerin kapsayıcı üzerinden kalıtılması budur:
    // bir klasörün okuyucuları içindeki her belgeyi okur.
    TupleToUserset {
        tupleset: String,
        computed: String,
    },

    Union(Vec<Rewrite>),

    Intersection(Vec<Rewrite>),

    // `base`'i verir ama `subtract`'i sağlayan öznelere vermez. Tek monoton
    // olmayan biçim: tuple eklemek erişimi kaldırabilir.
    Exclusion {
        base: Box<Rewrite>,
        subtract: Box<Rewrite>,
    },
}

impl Rewrite {
    fn check(&self, depth: usize) -> Result<(), ModelError> {
        if depth > MAX_REWRITE_DEPTH {
            return Err(ModelError::RewriteTooDeep {
                allowed: MAX_REWRITE_DEPTH,
            });
        }
        match self {
            Self::This | Self::ComputedUserset { .. } | Self::TupleToUserset { .. } => Ok(()),
            Self::Union(operands) | Self::Intersection(operands) => {
                if operands.len() > MAX_REWRITE_OPERANDS {
                    return Err(ModelError::TooManyOperands {
                        allowed: MAX_REWRITE_OPERANDS,
                        actual: operands.len(),
                    });
                }
                for operand in operands {
                    operand.check(depth + 1)?;
                }
                Ok(())
            }
            Self::Exclusion { base, subtract } => {
                base.check(depth + 1)?;
                subtract.check(depth + 1)
            }
        }
    }

    // Bu yeniden yazmanın, önce bir tuple okumadan AYNI nesnede ulaştığı
    // ilişkiler. Kendi kümesinde görünen bir ilişki tek nesnenin içinde
    // sonsuza kadar döner, o yüzden model bunu baştan reddeder.
    fn same_object_relations(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::This | Self::TupleToUserset { .. } => {}
            Self::ComputedUserset { relation } => {
                out.insert(relation.clone());
            }
            Self::Union(operands) | Self::Intersection(operands) => {
                for operand in operands {
                    operand.same_object_relations(out);
                }
            }
            Self::Exclusion { base, subtract } => {
                base.same_object_relations(out);
                subtract.same_object_relations(out);
            }
        }
    }

    fn referenced_relations(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::This => {}
            Self::ComputedUserset { relation } => {
                out.insert(relation.clone());
            }
            Self::TupleToUserset { tupleset, .. } => {
                out.insert(tupleset.clone());
            }
            Self::Union(operands) | Self::Intersection(operands) => {
                for operand in operands {
                    operand.referenced_relations(out);
                }
            }
            Self::Exclusion { base, subtract } => {
                base.referenced_relations(out);
                subtract.referenced_relations(out);
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeDef {
    relations: BTreeMap<String, Rewrite>,
}

impl TypeDef {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, relation: &str, rewrite: Rewrite) -> Self {
        self.relations.insert(relation.to_owned(), rewrite);
        self
    }

    #[must_use]
    pub fn rewrite(&self, relation: &str) -> Option<&Rewrite> {
        self.relations.get(relation)
    }

    pub fn relations(&self) -> impl Iterator<Item = &str> {
        self.relations.keys().map(String::as_str)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Model {
    types: BTreeMap<String, TypeDef>,
}

impl Model {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, kind: &str, def: TypeDef) -> Self {
        self.types.insert(kind.to_owned(), def);
        self
    }

    #[must_use]
    pub fn type_def(&self, kind: &str) -> Option<&TypeDef> {
        self.types.get(kind)
    }

    pub fn types(&self) -> impl Iterator<Item = &str> {
        self.types.keys().map(String::as_str)
    }

    // Buradan geçemeyen bir model tek bir tuple yazılmadan reddedilir;
    // böylece çözümleme karşılaştığı her ilişkinin var olduğunu varsayabilir.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.types.len() > MAX_TYPES {
            return Err(ModelError::TooManyTypes {
                allowed: MAX_TYPES,
                actual: self.types.len(),
            });
        }

        for (kind, def) in &self.types {
            if def.relations.len() > MAX_RELATIONS_PER_TYPE {
                return Err(ModelError::TooManyRelations {
                    kind: kind.clone(),
                    allowed: MAX_RELATIONS_PER_TYPE,
                    actual: def.relations.len(),
                });
            }

            for (relation, rewrite) in &def.relations {
                rewrite.check(0)?;

                let mut referenced = BTreeSet::new();
                rewrite.referenced_relations(&mut referenced);
                for name in &referenced {
                    if !def.relations.contains_key(name) {
                        return Err(ModelError::UnknownRelation {
                            kind: kind.clone(),
                            relation: name.clone(),
                        });
                    }
                }

                let mut same_object = BTreeSet::new();
                rewrite.same_object_relations(&mut same_object);
                if same_object.contains(relation) {
                    return Err(ModelError::ImmediateSelfReference {
                        kind: kind.clone(),
                        relation: relation.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    pub fn lookup(&self, kind: &str, relation: &str) -> Result<&Rewrite, ModelError> {
        let def = self
            .types
            .get(kind)
            .ok_or_else(|| ModelError::UnknownType {
                kind: kind.to_owned(),
            })?;
        def.rewrite(relation)
            .ok_or_else(|| ModelError::UnknownRelation {
                kind: kind.to_owned(),
                relation: relation.to_owned(),
            })
    }
}
