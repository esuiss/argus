use crate::scim_filter::{self, Filter, FilterError};

#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    pub attribute: String,
    pub value_filter: Option<Filter>,
    pub sub_attribute: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("the path is empty")]
    Empty,

    #[error("the value filter is malformed")]
    BadFilter,

    #[error("the path is malformed")]
    Malformed,
}

impl From<FilterError> for PathError {
    fn from(_: FilterError) -> Self {
        Self::BadFilter
    }
}

pub fn parse(input: &str) -> Result<Path, PathError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PathError::Empty);
    }

    let Some(open) = trimmed.find('[') else {
        if trimmed.contains(']') {
            return Err(PathError::Malformed);
        }
        let (attribute, sub) = split_last_segment(trimmed);
        return Ok(Path {
            attribute,
            value_filter: None,
            sub_attribute: sub,
        });
    };

    let close = trimmed.rfind(']').ok_or(PathError::Malformed)?;
    if close < open {
        return Err(PathError::Malformed);
    }

    let attribute = trimmed.get(..open).ok_or(PathError::Malformed)?.to_owned();
    let inner = trimmed
        .get(open + 1..close)
        .ok_or(PathError::Malformed)?
        .trim();

    if attribute.is_empty() || inner.is_empty() {
        return Err(PathError::Malformed);
    }

    let rest = trimmed.get(close + 1..).unwrap_or_default();
    let sub_attribute = if rest.is_empty() {
        None
    } else {
        let name = rest.strip_prefix('.').ok_or(PathError::Malformed)?;
        if name.is_empty() || name.contains('.') {
            return Err(PathError::Malformed);
        }
        Some(name.to_owned())
    };

    Ok(Path {
        attribute,
        value_filter: Some(scim_filter::parse(inner)?),
        sub_attribute,
    })
}

fn split_last_segment(raw: &str) -> (String, Option<String>) {
    let urn_end = raw.rfind(':').map_or(0, |i| i + 1);
    let tail = raw.get(urn_end..).unwrap_or_default();

    match tail.split_once('.') {
        Some((head, sub)) if !sub.is_empty() && !sub.contains('.') => {
            let attribute = format!("{}{head}", raw.get(..urn_end).unwrap_or_default());
            (attribute, Some(sub.to_owned()))
        }
        _ => (raw.to_owned(), None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{PathError, parse};

    #[test]
    fn the_specs_figure_8_examples_parse() {
        let p = parse("members").expect("members");
        assert_eq!(p.attribute, "members");
        assert!(p.value_filter.is_none() && p.sub_attribute.is_none());

        let p = parse("name.familyName").expect("name.familyName");
        assert_eq!(p.attribute, "name");
        assert_eq!(p.sub_attribute.as_deref(), Some("familyName"));

        let p = parse(r#"addresses[type eq "work"]"#).expect("addresses");
        assert_eq!(p.attribute, "addresses");
        assert!(p.value_filter.is_some());
        assert!(p.sub_attribute.is_none());

        let p = parse(r#"members[value eq "2819c223"]"#).expect("members filter");
        assert_eq!(p.attribute, "members");
        assert!(p.value_filter.is_some());

        let p = parse(r#"members[value eq "2819c223"].displayName"#).expect("with sub");
        assert_eq!(p.attribute, "members");
        assert!(p.value_filter.is_some());
        assert_eq!(p.sub_attribute.as_deref(), Some("displayName"));
    }

    #[test]
    fn a_fully_qualified_extension_attribute_keeps_its_urn() {
        let p = parse("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber")
            .expect("urn");
        assert_eq!(
            p.attribute,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"
        );
        assert!(p.sub_attribute.is_none());
    }

    #[test]
    fn a_urn_qualified_complex_attribute_splits_only_on_the_final_dot() {
        let p = parse("urn:ietf:params:scim:schemas:core:2.0:User:name.familyName").expect("urn");
        assert_eq!(
            p.attribute,
            "urn:ietf:params:scim:schemas:core:2.0:User:name"
        );
        assert_eq!(p.sub_attribute.as_deref(), Some("familyName"));
    }

    #[test]
    fn an_empty_path_is_refused() {
        assert_eq!(parse("").unwrap_err(), PathError::Empty);
        assert_eq!(parse("   ").unwrap_err(), PathError::Empty);
    }

    #[test]
    fn a_malformed_bracket_is_refused() {
        for bad in [
            "members[",
            "members]",
            "members[]",
            "[type eq \"work\"]",
            "members[type eq \"work\"]value",
            "members[type eq \"work\"].a.b",
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_broken_value_filter_is_named_as_a_filter_problem() {
        assert_eq!(
            parse(r#"members[type like "work"]"#).unwrap_err(),
            PathError::BadFilter
        );
    }
}
