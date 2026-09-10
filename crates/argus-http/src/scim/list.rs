use argus_core::scim::{ResourceType, ScimRecord, Sort, evaluate, sort_key};
use argus_parse::scim_filter::Filter;
use serde_json::Value;

pub const MAX_SCAN: usize = 10_000;
pub const CHUNK: usize = 500;

#[must_use]
pub fn render_matching(
    records: &[ScimRecord],
    kind: ResourceType,
    base: &str,
    filter: Option<&Filter>,
) -> Vec<(u64, Value)> {
    records
        .iter()
        .map(|record| (record.seq, record.rendered(kind, base)))
        .filter(|(_, rendered)| filter.is_none_or(|f| evaluate(rendered, f)))
        .collect()
}

#[must_use]
pub fn sort_page(
    matched: Vec<Value>,
    sort: Option<&Sort>,
    start_index: usize,
    count: usize,
) -> Vec<Value> {
    let mut ordered = matched;

    if let Some(sort) = sort {
        ordered.sort_by(|left, right| {
            let ordering = sort_key(left, &sort.by).cmp(&sort_key(right, &sort.by));
            if sort.descending {
                ordering.reverse()
            } else {
                ordering
            }
        });
    }

    ordered
        .into_iter()
        .skip(start_index.saturating_sub(1))
        .take(count)
        .collect()
}
