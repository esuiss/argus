use argus_parse::scim_filter::{CompareOp, Filter};

pub const MAX_FIELDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    #[error("the filter names {field}, which is not a field of this resource")]
    UnknownField { field: String },

    #[error("operator {operator} is not supported by this API")]
    UnsupportedOperator { operator: &'static str },

    #[error("a filter over the members of a complex attribute is not supported here")]
    ValuePathUnsupported,

    #[error("the projection names {field}, which is not a field of this resource")]
    UnknownProjection { field: String },

    #[error("a projection of {actual} fields exceeds the {allowed} this server accepts")]
    TooManyFields { allowed: usize, actual: usize },

    #[error("{0}")]
    Malformed(String),
}

const fn operator_name(op: CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "eq",
        CompareOp::Ne => "ne",
        CompareOp::Co => "co",
        CompareOp::Sw => "sw",
        CompareOp::Ew => "ew",
        CompareOp::Gt => "gt",
        CompareOp::Ge => "ge",
        CompareOp::Lt => "lt",
        CompareOp::Le => "le",
    }
}

const fn is_supported(op: CompareOp) -> bool {
    matches!(
        op,
        CompareOp::Eq | CompareOp::Ne | CompareOp::Co | CompareOp::Sw | CompareOp::Ew
    )
}

pub fn check_filter(filter: &Filter, fields: &[&str]) -> Result<(), QueryError> {
    match filter {
        Filter::Present { path } => known(path, fields),

        Filter::Compare { path, op, .. } => {
            if !is_supported(*op) {
                return Err(QueryError::UnsupportedOperator {
                    operator: operator_name(*op),
                });
            }
            known(path, fields)
        }

        Filter::And(left, right) | Filter::Or(left, right) => {
            check_filter(left, fields)?;
            check_filter(right, fields)
        }

        Filter::Not(inner) => check_filter(inner, fields),

        Filter::ValuePath { .. } => Err(QueryError::ValuePathUnsupported),
    }
}

fn known(path: &str, fields: &[&str]) -> Result<(), QueryError> {
    if fields.contains(&path) {
        Ok(())
    } else {
        Err(QueryError::UnknownField {
            field: path.to_owned(),
        })
    }
}

pub fn parse_filter(raw: &str, fields: &[&str]) -> Result<Filter, QueryError> {
    let filter =
        argus_parse::scim_filter::parse(raw).map_err(|e| QueryError::Malformed(e.to_string()))?;
    check_filter(&filter, fields)?;
    Ok(filter)
}

pub fn projection(raw: &str, fields: &[&str]) -> Result<Vec<String>, QueryError> {
    let wanted: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if wanted.len() > MAX_FIELDS {
        return Err(QueryError::TooManyFields {
            allowed: MAX_FIELDS,
            actual: wanted.len(),
        });
    }

    let mut out = Vec::with_capacity(wanted.len());
    for name in wanted {
        if !fields.contains(&name) {
            return Err(QueryError::UnknownProjection {
                field: name.to_owned(),
            });
        }
        out.push(name.to_owned());
    }

    Ok(out)
}
