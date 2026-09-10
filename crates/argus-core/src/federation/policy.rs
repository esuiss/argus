use std::collections::BTreeMap;

use serde_json::Value;

pub const MAX_POLICY_PARAMETERS: usize = 128;
pub const MAX_POLICY_VALUES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operator {
    Value,
    Add,
    Default,
    OneOf,
    SubsetOf,
    SupersetOf,
    Essential,
}

impl Operator {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Add => "add",
            Self::Default => "default",
            Self::OneOf => "one_of",
            Self::SubsetOf => "subset_of",
            Self::SupersetOf => "superset_of",
            Self::Essential => "essential",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "value" => Some(Self::Value),
            "add" => Some(Self::Add),
            "default" => Some(Self::Default),
            "one_of" => Some(Self::OneOf),
            "subset_of" => Some(Self::SubsetOf),
            "superset_of" => Some(Self::SupersetOf),
            "essential" => Some(Self::Essential),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyFault {
    #[error("the policy is not a JSON object")]
    NotAnObject,

    #[error("the operator {name} is not one this server implements")]
    UnknownOperator { name: String },

    #[error("the operator {operator} carries a value of the wrong shape")]
    WrongShape { operator: &'static str },

    #[error("value cannot be combined with {other}")]
    ValueCombined { other: &'static str },

    #[error("one_of cannot be combined with {other}")]
    OneOfCombined { other: &'static str },

    #[error("a superior policy set {operator} to a value a subordinate cannot narrow")]
    NotNarrowing { operator: &'static str },

    #[error("two policies set {operator} to values that cannot be reconciled")]
    Irreconcilable { operator: &'static str },

    #[error("combining one_of left no acceptable value for {parameter}")]
    EmptyIntersection { parameter: String },

    #[error("the policy names more parameters than this server will apply")]
    TooManyParameters,

    #[error("the policy names more values than this server will apply")]
    TooManyValues,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyFault {
    #[error("{parameter} is essential and the metadata does not carry it")]
    MissingEssential { parameter: String },

    #[error("{parameter} is not one of the values the policy allows")]
    NotAllowed { parameter: String },

    #[error("{parameter} is not a subset of the values the policy allows")]
    NotASubset { parameter: String },

    #[error("{parameter} does not carry every value the policy requires")]
    NotASuperset { parameter: String },

    #[error("{parameter} must be an array for this policy to apply")]
    NotAnArray { parameter: String },

    #[error("the metadata is not a JSON object")]
    NotAnObject,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParameterPolicy {
    pub value: Option<Value>,
    pub add: Option<Vec<Value>>,
    pub default: Option<Value>,
    pub one_of: Option<Vec<Value>>,
    pub subset_of: Option<Vec<Value>>,
    pub superset_of: Option<Vec<Value>>,
    pub essential: Option<bool>,
}

impl ParameterPolicy {
    fn set_operators(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.add.is_some() {
            out.push("add");
        }
        if self.default.is_some() {
            out.push("default");
        }
        if self.one_of.is_some() {
            out.push("one_of");
        }
        if self.subset_of.is_some() {
            out.push("subset_of");
        }
        if self.superset_of.is_some() {
            out.push("superset_of");
        }
        out
    }

    fn check(&self) -> Result<(), PolicyFault> {
        if self.value.is_some()
            && let Some(other) = self.set_operators().first()
        {
            return Err(PolicyFault::ValueCombined { other });
        }

        if self.one_of.is_some() {
            for other in ["subset_of", "superset_of", "add"] {
                let present = match other {
                    "subset_of" => self.subset_of.is_some(),
                    "superset_of" => self.superset_of.is_some(),
                    _ => self.add.is_some(),
                };
                if present {
                    return Err(PolicyFault::OneOfCombined { other });
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataPolicy {
    pub parameters: BTreeMap<String, ParameterPolicy>,
}

fn array_of(value: &Value, operator: &'static str) -> Result<Vec<Value>, PolicyFault> {
    let items = value
        .as_array()
        .ok_or(PolicyFault::WrongShape { operator })?;

    if items.len() > MAX_POLICY_VALUES {
        return Err(PolicyFault::TooManyValues);
    }

    Ok(items.clone())
}

pub fn parse(raw: &Value) -> Result<MetadataPolicy, PolicyFault> {
    let object = raw.as_object().ok_or(PolicyFault::NotAnObject)?;

    if object.len() > MAX_POLICY_PARAMETERS {
        return Err(PolicyFault::TooManyParameters);
    }

    let mut parameters = BTreeMap::new();

    for (parameter, body) in object {
        let entry = body.as_object().ok_or(PolicyFault::NotAnObject)?;
        let mut policy = ParameterPolicy::default();

        for (name, operand) in entry {
            let operator = Operator::parse(name)
                .ok_or_else(|| PolicyFault::UnknownOperator { name: name.clone() })?;

            match operator {
                Operator::Value => policy.value = Some(operand.clone()),
                Operator::Default => policy.default = Some(operand.clone()),
                Operator::Add => policy.add = Some(array_of(operand, "add")?),
                Operator::OneOf => policy.one_of = Some(array_of(operand, "one_of")?),
                Operator::SubsetOf => policy.subset_of = Some(array_of(operand, "subset_of")?),
                Operator::SupersetOf => {
                    policy.superset_of = Some(array_of(operand, "superset_of")?);
                }
                Operator::Essential => {
                    policy.essential = Some(operand.as_bool().ok_or(PolicyFault::WrongShape {
                        operator: "essential",
                    })?);
                }
            }
        }

        policy.check()?;
        parameters.insert(parameter.clone(), policy);
    }

    Ok(MetadataPolicy { parameters })
}

fn union(left: &[Value], right: &[Value]) -> Vec<Value> {
    let mut out = left.to_vec();
    for value in right {
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
    out
}

fn intersection(left: &[Value], right: &[Value]) -> Vec<Value> {
    left.iter()
        .filter(|value| right.contains(value))
        .cloned()
        .collect()
}

fn merge_parameter(
    parameter: &str,
    superior: &ParameterPolicy,
    subordinate: &ParameterPolicy,
) -> Result<ParameterPolicy, PolicyFault> {
    let value = match (superior.value.as_ref(), subordinate.value.as_ref()) {
        (Some(above), Some(below)) if above != below => {
            return Err(PolicyFault::Irreconcilable { operator: "value" });
        }
        (Some(above), _) => Some(above.clone()),
        (None, below) => below.cloned(),
    };

    let default = match (superior.default.as_ref(), subordinate.default.as_ref()) {
        (Some(above), Some(below)) if above != below => {
            return Err(PolicyFault::Irreconcilable {
                operator: "default",
            });
        }
        (Some(above), _) => Some(above.clone()),
        (None, below) => below.cloned(),
    };

    let add = match (superior.add.as_ref(), subordinate.add.as_ref()) {
        (Some(above), Some(below)) => Some(union(above, below)),
        (Some(above), None) => Some(above.clone()),
        (None, below) => below.cloned(),
    };

    let one_of = match (superior.one_of.as_ref(), subordinate.one_of.as_ref()) {
        (Some(above), Some(below)) => {
            let merged = intersection(above, below);
            if merged.is_empty() {
                return Err(PolicyFault::EmptyIntersection {
                    parameter: parameter.to_owned(),
                });
            }
            Some(merged)
        }
        (Some(above), None) => Some(above.clone()),
        (None, below) => below.cloned(),
    };

    let subset_of = match (superior.subset_of.as_ref(), subordinate.subset_of.as_ref()) {
        (Some(above), Some(below)) => {
            let merged = intersection(above, below);
            if merged.is_empty() {
                return Err(PolicyFault::EmptyIntersection {
                    parameter: parameter.to_owned(),
                });
            }
            Some(merged)
        }
        (Some(above), None) => Some(above.clone()),
        (None, below) => below.cloned(),
    };

    let superset_of = match (
        superior.superset_of.as_ref(),
        subordinate.superset_of.as_ref(),
    ) {
        (Some(above), Some(below)) => Some(union(above, below)),
        (Some(above), None) => Some(above.clone()),
        (None, below) => below.cloned(),
    };

    let essential = match (superior.essential, subordinate.essential) {
        (Some(true), Some(false)) => {
            return Err(PolicyFault::NotNarrowing {
                operator: "essential",
            });
        }
        (Some(true), _) => Some(true),
        (above, below) => match (above, below) {
            (_, Some(true)) => Some(true),
            (Some(value), None) => Some(value),
            (_, below) => below,
        },
    };

    let merged = ParameterPolicy {
        value,
        add,
        default,
        one_of,
        subset_of,
        superset_of,
        essential,
    };

    merged.check()?;
    Ok(merged)
}

// OpenID Federation 1.1 §5.1.4: bir üstün politikasını bir alt kuruluşunkiyle
// birleştirir. `one_of` ve `subset_of` KESİŞİR, `value` ve `default` çatışırsa
// reddedilir, ve `essential` aşağıdan gevşetilemez — bir alt kuruluş üstünün
// dayattığı bir zorunluluğu kaldıramaz.
pub fn merge(
    superior: &MetadataPolicy,
    subordinate: &MetadataPolicy,
) -> Result<MetadataPolicy, PolicyFault> {
    let mut parameters = superior.parameters.clone();

    for (parameter, below) in &subordinate.parameters {
        let merged = match parameters.get(parameter) {
            None => below.clone(),
            Some(above) => merge_parameter(parameter, above, below)?,
        };
        parameters.insert(parameter.clone(), merged);
    }

    if parameters.len() > MAX_POLICY_PARAMETERS {
        return Err(PolicyFault::TooManyParameters);
    }

    Ok(MetadataPolicy { parameters })
}

pub fn apply(metadata: &Value, policy: &MetadataPolicy) -> Result<Value, ApplyFault> {
    let mut object = metadata.as_object().ok_or(ApplyFault::NotAnObject)?.clone();

    for (parameter, rule) in &policy.parameters {
        if let Some(value) = rule.value.as_ref() {
            if value.is_null() {
                object.remove(parameter);
            } else {
                object.insert(parameter.clone(), value.clone());
            }
        }

        if let Some(additions) = rule.add.as_ref() {
            let existing = object.get(parameter).cloned();
            let mut items = match existing {
                None => Vec::new(),
                Some(Value::Array(items)) => items,
                Some(_) => {
                    return Err(ApplyFault::NotAnArray {
                        parameter: parameter.clone(),
                    });
                }
            };

            for addition in additions {
                if !items.contains(addition) {
                    items.push(addition.clone());
                }
            }

            object.insert(parameter.clone(), Value::Array(items));
        }

        if let Some(fallback) = rule.default.as_ref()
            && !object.contains_key(parameter)
        {
            object.insert(parameter.clone(), fallback.clone());
        }

        if let Some(allowed) = rule.one_of.as_ref()
            && let Some(current) = object.get(parameter)
            && !allowed.contains(current)
        {
            return Err(ApplyFault::NotAllowed {
                parameter: parameter.clone(),
            });
        }

        if let Some(allowed) = rule.subset_of.as_ref()
            && let Some(current) = object.get(parameter)
        {
            let items = current.as_array().ok_or_else(|| ApplyFault::NotAnArray {
                parameter: parameter.clone(),
            })?;

            let kept: Vec<Value> = items
                .iter()
                .filter(|item| allowed.contains(item))
                .cloned()
                .collect();

            if kept.is_empty() {
                object.remove(parameter);
            } else {
                object.insert(parameter.clone(), Value::Array(kept));
            }
        }

        if let Some(required) = rule.superset_of.as_ref() {
            let current = object.get(parameter).cloned();
            let items = match current {
                None => Vec::new(),
                Some(Value::Array(items)) => items,
                Some(_) => {
                    return Err(ApplyFault::NotAnArray {
                        parameter: parameter.clone(),
                    });
                }
            };

            if !required.iter().all(|value| items.contains(value)) {
                return Err(ApplyFault::NotASuperset {
                    parameter: parameter.clone(),
                });
            }
        }

        if rule.essential == Some(true) && !object.contains_key(parameter) {
            return Err(ApplyFault::MissingEssential {
                parameter: parameter.clone(),
            });
        }
    }

    Ok(Value::Object(object))
}
