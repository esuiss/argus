use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argus_core::scim::{
    Page, ResourceType, ScimFault, ScimRecord, Sort, encode_cursor, paging, sort as parse_sort,
    validate,
};
use argus_core::scim_patch::{Op, Operation, PatchError, apply};
use argus_core::time::Timestamp;
use argus_parse::scim_filter::{Filter, parse as parse_filter};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;

use crate::scim::list::{CHUNK, MAX_SCAN, render_matching, sort_page};
use argus_core::scim_event::{Event, EventKind, changed_attributes, resource_uri};

use crate::scim::{AuthFailure, ScimState};
use crate::store::{ScimConflict, ScimStore, ScimStoreError};

type Shared<S> = Arc<ScimState<S>>;
type Params = std::collections::HashMap<String, String>;
type Failure = Box<Response>;

fn now() -> Timestamp {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    Timestamp::from_unix_seconds(secs)
}

fn body(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    if let Ok(content_type) = argus_proto::scim::CONTENT_TYPE.parse() {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, content_type);
    }
    response
}

fn fault(status: u16, scim_type: Option<&str>, detail: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    let error = argus_proto::scim::ScimError::new(status.as_u16(), scim_type, detail);
    body(status, serde_json::to_value(error).unwrap_or(Value::Null))
}

fn from_scim_fault(f: &ScimFault) -> Response {
    fault(400, Some(f.scim_type()), &f.to_string())
}

fn from_store(error: &ScimStoreError) -> Response {
    match error {
        ScimStoreError::NotFound => fault(404, None, "the resource does not exist"),
        ScimStoreError::Unavailable => fault(500, None, "the request could not be completed"),
        ScimStoreError::Conflict(ScimConflict::UserNameTaken) => fault(
            409,
            Some("uniqueness"),
            "a user with that userName already exists",
        ),
        ScimStoreError::Conflict(ScimConflict::ExternalIdTaken) => fault(
            409,
            Some("uniqueness"),
            "a resource with that externalId already exists",
        ),
        ScimStoreError::Conflict(ScimConflict::UnknownMember(id)) => fault(
            400,
            Some("invalidValue"),
            &format!("the member {id} does not exist in this tenant"),
        ),
    }
}

fn from_auth(failure: AuthFailure) -> Response {
    let mut response = fault(failure.status(), None, failure.detail());
    if let Ok(challenge) = failure.challenge().parse() {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, challenge);
    }
    response
}

fn from_patch(error: PatchError) -> Response {
    let detail = error.to_string();
    fault(400, Some(error.scim_type()), &detail)
}

fn guard<S>(state: &ScimState<S>, headers: &HeaderMap) -> Result<(), Failure> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    state
        .authorize(authorization, now())
        .map(|_| ())
        .map_err(|failure| Box::new(from_auth(failure)))
}

struct ListQuery {
    filter: Option<Filter>,
    sort: Option<Sort>,
    page: Page,
    attributes: Option<String>,
    excluded: Option<String>,
}

fn read_list_query(params: &Params) -> Result<ListQuery, Failure> {
    let filter = match params.get("filter").map(String::as_str) {
        None => None,
        Some(raw) => Some(
            parse_filter(raw)
                .map_err(|e| Box::new(fault(400, Some("invalidFilter"), &e.to_string())))?,
        ),
    };

    let page = paging(
        params.get("startIndex").map(String::as_str),
        params.get("count").map(String::as_str),
        params.get("cursor").map(String::as_str),
    )
    .map_err(|e| Box::new(from_scim_fault(&e)))?;

    let sort = parse_sort(
        params.get("sortBy").map(String::as_str),
        params.get("sortOrder").map(String::as_str),
    )
    .map_err(|e| Box::new(from_scim_fault(&e)))?;

    Ok(ListQuery {
        filter,
        sort,
        page,
        attributes: params.get("attributes").cloned(),
        excluded: params.get("excludedAttributes").cloned(),
    })
}

fn read_search_body(request: &Value) -> Result<ListQuery, Failure> {
    let mut params = Params::new();
    if let Some(object) = request.as_object() {
        for key in [
            "filter",
            "startIndex",
            "count",
            "cursor",
            "sortBy",
            "sortOrder",
        ] {
            if let Some(value) = object.get(key) {
                let text = match value {
                    Value::String(text) => text.clone(),
                    Value::Number(number) => number.to_string(),
                    _ => continue,
                };
                params.insert(key.to_owned(), text);
            }
        }
        for key in ["attributes", "excludedAttributes"] {
            if let Some(Value::Array(items)) = object.get(key) {
                let joined = items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",");
                params.insert(key.to_owned(), joined);
            }
        }
    }
    read_list_query(&params)
}

async fn collect<F, Fut>(
    query: &ListQuery,
    kind: ResourceType,
    base: &str,
    scan: F,
) -> Result<Response, Failure>
where
    F: Fn(Option<u64>, usize) -> Fut,
    Fut: core::future::Future<Output = Result<Vec<ScimRecord>, ScimStoreError>>,
{
    let mut matched: Vec<(u64, Value)> = Vec::new();
    let mut scanned = 0_usize;

    let (mut after, wanted) = match query.page {
        Page::Cursor { after, count } => (after, Some(count + 1)),
        Page::Index { .. } => (None, None),
    };

    loop {
        let records = scan(after, CHUNK)
            .await
            .map_err(|e| Box::new(from_store(&e)))?;
        if records.is_empty() {
            break;
        }

        scanned = scanned.saturating_add(records.len());
        after = records.last().map(|record| record.seq);

        matched.extend(render_matching(&records, kind, base, query.filter.as_ref()));

        if let Some(wanted) = wanted
            && matched.len() >= wanted
        {
            break;
        }

        if scanned >= MAX_SCAN {
            return Err(Box::new(fault(
                400,
                Some("tooMany"),
                "the filter matches more resources than this server will process in one request",
            )));
        }
    }

    let (resources, total, start_index, next_cursor) = match query.page {
        Page::Index { start, count } => {
            let values: Vec<Value> = matched.into_iter().map(|(_, value)| value).collect();
            let total = values.len();
            (
                sort_page(values, query.sort.as_ref(), start, count),
                Some(total),
                start,
                None,
            )
        }
        Page::Cursor { count, .. } => {
            let has_more = matched.len() > count;
            let next = if has_more {
                matched
                    .get(count.saturating_sub(1))
                    .map(|(seq, _)| encode_cursor(*seq))
            } else {
                None
            };
            let values: Vec<Value> = matched
                .into_iter()
                .take(count)
                .map(|(_, value)| value)
                .collect();
            (values, None, 1, next)
        }
    };

    let projected: Vec<Value> = resources
        .iter()
        .map(|resource| {
            argus_proto::scim::project(
                resource,
                query.attributes.as_deref(),
                query.excluded.as_deref(),
            )
        })
        .collect();

    let count = projected.len();
    let mut list = serde_json::json!({
        "schemas": [argus_proto::scim::LIST_RESPONSE_SCHEMA],
        "Resources": projected,
        "itemsPerPage": count,
        "startIndex": start_index
    });

    if let Some(object) = list.as_object_mut() {
        if let Some(total) = total {
            object.insert("totalResults".to_owned(), Value::from(total));
        }
        if let Some(next) = next_cursor {
            object.insert("nextCursor".to_owned(), Value::String(next));
        }
    }

    Ok(body(StatusCode::OK, list))
}

fn announce<S>(
    state: &ScimState<S>,
    kind: EventKind,
    resource: ResourceType,
    id: &str,
    external_id: Option<&str>,
    attributes: Vec<String>,
) {
    let Some(publisher) = state.events.as_ref() else {
        return;
    };

    publisher.emit(
        &Event {
            kind,
            subject_uri: resource_uri(resource, id),
            external_id: external_id.map(str::to_owned),
            attributes,
            payload: None,
        },
        &state.issuer,
        now(),
    );
}

fn attribute_names(resource: &Value) -> Vec<String> {
    changed_attributes(&Value::Object(serde_json::Map::new()), resource)
}

fn external_id_of(resource: &Value) -> Option<String> {
    resource
        .get("externalId")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn activation_change(before: &Value, after: &Value) -> Option<EventKind> {
    let was = before
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let is = after.get("active").and_then(Value::as_bool).unwrap_or(true);

    match (was, is) {
        (true, false) => Some(EventKind::Deactivate),
        (false, true) => Some(EventKind::Activate),
        _ => None,
    }
}

fn created(record: &ScimRecord, kind: ResourceType, base: &str) -> Response {
    let rendered = record.rendered(kind, base);
    let location = rendered
        .get("meta")
        .and_then(|meta| meta.get("location"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let mut response = body(StatusCode::CREATED, rendered);
    if let Ok(value) = location.parse() {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, value);
    }
    response
}

fn patch_operations(request: &Value) -> Result<Vec<Operation>, Failure> {
    let declares = request
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .any(|s| s.eq_ignore_ascii_case(argus_proto::scim::PATCH_OP_SCHEMA))
        });

    if !declares {
        return Err(Box::new(fault(
            400,
            Some("invalidSyntax"),
            "a PATCH body must declare the PatchOp schema",
        )));
    }

    let raw = request
        .get("Operations")
        .or_else(|| request.get("operations"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Box::new(fault(
                400,
                Some("invalidSyntax"),
                "a PATCH body must carry an Operations array",
            ))
        })?;

    if raw.is_empty() {
        return Err(Box::new(fault(
            400,
            Some("invalidValue"),
            "a PATCH body must carry at least one operation",
        )));
    }

    let mut operations = Vec::with_capacity(raw.len());
    for entry in raw {
        let op = entry
            .get("op")
            .and_then(Value::as_str)
            .and_then(Op::parse)
            .ok_or_else(|| {
                Box::new(fault(
                    400,
                    Some("invalidSyntax"),
                    "each operation must name add, remove or replace",
                ))
            })?;

        operations.push(Operation {
            op,
            path: entry.get("path").and_then(Value::as_str).map(str::to_owned),
            value: entry.get("value").cloned(),
        });
    }

    Ok(operations)
}

macro_rules! resource_routes {
    (
        $kind:expr,
        $list_fn:ident, $create_fn:ident, $search_fn:ident,
        $get_fn:ident, $put_fn:ident, $patch_fn:ident, $delete_fn:ident,
        $scan:ident, $create:ident, $read:ident, $replace:ident, $delete:ident
    ) => {
        async fn $list_fn<S: ScimStore + Send + Sync + 'static>(
            State(state): State<Shared<S>>,
            headers: HeaderMap,
            Query(params): Query<Params>,
        ) -> Response {
            if let Err(response) = guard(&state, &headers) {
                return *response;
            }
            let query = match read_list_query(&params) {
                Ok(query) => query,
                Err(response) => return *response,
            };
            match collect::<_, _>(&query, $kind, &state.base, |after, limit| {
                state.store.$scan(state.tenant_id, after, limit)
            })
            .await
            {
                Ok(response) => response,
                Err(response) => *response,
            }
        }

        async fn $search_fn<S: ScimStore + Send + Sync + 'static>(
            State(state): State<Shared<S>>,
            headers: HeaderMap,
            Json(request): Json<Value>,
        ) -> Response {
            if let Err(response) = guard(&state, &headers) {
                return *response;
            }
            let query = match read_search_body(&request) {
                Ok(query) => query,
                Err(response) => return *response,
            };
            match collect::<_, _>(&query, $kind, &state.base, |after, limit| {
                state.store.$scan(state.tenant_id, after, limit)
            })
            .await
            {
                Ok(response) => response,
                Err(response) => *response,
            }
        }

        async fn $create_fn<S: ScimStore + Send + Sync + 'static>(
            State(state): State<Shared<S>>,
            headers: HeaderMap,
            Json(request): Json<Value>,
        ) -> Response {
            if let Err(response) = guard(&state, &headers) {
                return *response;
            }
            let accepted = match validate(&request, $kind, true) {
                Ok(accepted) => accepted,
                Err(f) => return from_scim_fault(&f),
            };
            match state.store.$create(state.tenant_id, &accepted, now()).await {
                Ok(record) => {
                    announce(
                        &state,
                        EventKind::CreateNotice,
                        $kind,
                        &record.id,
                        external_id_of(&record.payload).as_deref(),
                        attribute_names(&record.payload),
                    );
                    created(&record, $kind, &state.base)
                }
                Err(error) => from_store(&error),
            }
        }

        async fn $get_fn<S: ScimStore + Send + Sync + 'static>(
            State(state): State<Shared<S>>,
            headers: HeaderMap,
            Path(id): Path<String>,
            Query(params): Query<Params>,
        ) -> Response {
            if let Err(response) = guard(&state, &headers) {
                return *response;
            }
            match state.store.$read(state.tenant_id, &id).await {
                Ok(record) => body(
                    StatusCode::OK,
                    argus_proto::scim::project(
                        &record.rendered($kind, &state.base),
                        params.get("attributes").map(String::as_str),
                        params.get("excludedAttributes").map(String::as_str),
                    ),
                ),
                Err(error) => from_store(&error),
            }
        }

        async fn $put_fn<S: ScimStore + Send + Sync + 'static>(
            State(state): State<Shared<S>>,
            headers: HeaderMap,
            Path(id): Path<String>,
            Json(request): Json<Value>,
        ) -> Response {
            if let Err(response) = guard(&state, &headers) {
                return *response;
            }
            let accepted = match validate(&request, $kind, false) {
                Ok(accepted) => accepted,
                Err(f) => return from_scim_fault(&f),
            };
            let before = match state.store.$read(state.tenant_id, &id).await {
                Ok(record) => record.payload,
                Err(error) => return from_store(&error),
            };

            match state
                .store
                .$replace(state.tenant_id, &id, &accepted, now())
                .await
            {
                Ok(record) => {
                    let changed = changed_attributes(&before, &record.payload);
                    let activation = activation_change(&before, &record.payload);
                    if !changed.is_empty() {
                        announce(
                            &state,
                            activation.unwrap_or(EventKind::PutNotice),
                            $kind,
                            &record.id,
                            external_id_of(&record.payload).as_deref(),
                            if activation.is_some() {
                                Vec::new()
                            } else {
                                changed
                            },
                        );
                    }
                    body(StatusCode::OK, record.rendered($kind, &state.base))
                }
                Err(error) => from_store(&error),
            }
        }

        async fn $patch_fn<S: ScimStore + Send + Sync + 'static>(
            State(state): State<Shared<S>>,
            headers: HeaderMap,
            Path(id): Path<String>,
            Json(request): Json<Value>,
        ) -> Response {
            if let Err(response) = guard(&state, &headers) {
                return *response;
            }

            let operations = match patch_operations(&request) {
                Ok(operations) => operations,
                Err(response) => return *response,
            };

            let current = match state.store.$read(state.tenant_id, &id).await {
                Ok(record) => record,
                Err(error) => return from_store(&error),
            };

            let rendered = current.rendered($kind, &state.base);

            let outcome = match apply(&rendered, &operations) {
                Ok(outcome) => outcome,
                Err(error) => return from_patch(error),
            };

            if !outcome.changed {
                return body(StatusCode::OK, rendered);
            }

            let accepted = match validate(&outcome.resource, $kind, false) {
                Ok(accepted) => accepted,
                Err(f) => return from_scim_fault(&f),
            };

            match state
                .store
                .$replace(state.tenant_id, &id, &accepted, now())
                .await
            {
                Ok(record) => {
                    let changed = changed_attributes(&current.payload, &record.payload);
                    let activation = activation_change(&current.payload, &record.payload);
                    if !changed.is_empty() {
                        announce(
                            &state,
                            activation.unwrap_or(EventKind::PatchNotice),
                            $kind,
                            &record.id,
                            external_id_of(&record.payload).as_deref(),
                            if activation.is_some() {
                                Vec::new()
                            } else {
                                changed
                            },
                        );
                    }
                    body(StatusCode::OK, record.rendered($kind, &state.base))
                }
                Err(error) => from_store(&error),
            }
        }

        async fn $delete_fn<S: ScimStore + Send + Sync + 'static>(
            State(state): State<Shared<S>>,
            headers: HeaderMap,
            Path(id): Path<String>,
        ) -> Response {
            if let Err(response) = guard(&state, &headers) {
                return *response;
            }
            match state.store.$delete(state.tenant_id, &id).await {
                Ok(()) => {
                    announce(&state, EventKind::Delete, $kind, &id, None, Vec::new());
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(error) => from_store(&error),
            }
        }
    };
}

resource_routes!(
    ResourceType::User,
    users_list,
    users_create,
    users_search,
    user_get,
    user_put,
    user_patch,
    user_delete,
    scan_users,
    create_user,
    get_user,
    replace_user,
    delete_user
);

resource_routes!(
    ResourceType::Group,
    groups_list,
    groups_create,
    groups_search,
    group_get,
    group_put,
    group_patch,
    group_delete,
    scan_groups,
    create_group,
    get_group,
    replace_group,
    delete_group
);

async fn service_provider_config<S: ScimStore + Send + Sync + 'static>(
    State(state): State<Shared<S>>,
) -> Response {
    body(
        StatusCode::OK,
        argus_proto::scim::service_provider_config(&state.base),
    )
}

async fn resource_types<S: ScimStore + Send + Sync + 'static>(
    State(state): State<Shared<S>>,
) -> Response {
    let types = argus_proto::scim::resource_types(&state.base);
    let total = types.len();
    body(
        StatusCode::OK,
        serde_json::json!({
            "schemas": [argus_proto::scim::LIST_RESPONSE_SCHEMA],
            "totalResults": total,
            "itemsPerPage": total,
            "startIndex": 1,
            "Resources": types
        }),
    )
}

async fn resource_type<S: ScimStore + Send + Sync + 'static>(
    State(state): State<Shared<S>>,
    Path(id): Path<String>,
) -> Response {
    argus_proto::scim::resource_types(&state.base)
        .into_iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .map_or_else(
            || fault(404, None, "the resource type does not exist"),
            |entry| body(StatusCode::OK, entry),
        )
}

async fn schemas<S: ScimStore + Send + Sync + 'static>(State(state): State<Shared<S>>) -> Response {
    let all = argus_proto::scim::schemas(&state.base);
    let total = all.len();
    body(
        StatusCode::OK,
        serde_json::json!({
            "schemas": [argus_proto::scim::LIST_RESPONSE_SCHEMA],
            "totalResults": total,
            "itemsPerPage": total,
            "startIndex": 1,
            "Resources": all
        }),
    )
}

async fn schema<S: ScimStore + Send + Sync + 'static>(
    State(state): State<Shared<S>>,
    Path(id): Path<String>,
) -> Response {
    argus_proto::scim::schemas(&state.base)
        .into_iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .map_or_else(
            || fault(404, None, "the schema does not exist"),
            |entry| body(StatusCode::OK, entry),
        )
}

pub fn build<S: ScimStore + Send + Sync + 'static>(state: Shared<S>) -> Router {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config::<S>),
        )
        .route("/scim/v2/ResourceTypes", get(resource_types::<S>))
        .route("/scim/v2/ResourceTypes/{id}", get(resource_type::<S>))
        .route("/scim/v2/Schemas", get(schemas::<S>))
        .route("/scim/v2/Schemas/{id}", get(schema::<S>))
        .route(
            "/scim/v2/Users",
            get(users_list::<S>).post(users_create::<S>),
        )
        .route("/scim/v2/Users/.search", post(users_search::<S>))
        .route(
            "/scim/v2/Users/{id}",
            get(user_get::<S>)
                .put(user_put::<S>)
                .patch(user_patch::<S>)
                .delete(user_delete::<S>),
        )
        .route(
            "/scim/v2/Groups",
            get(groups_list::<S>).post(groups_create::<S>),
        )
        .route("/scim/v2/Groups/.search", post(groups_search::<S>))
        .route(
            "/scim/v2/Groups/{id}",
            get(group_get::<S>)
                .put(group_put::<S>)
                .patch(group_patch::<S>)
                .delete(group_delete::<S>),
        )
        .with_state(state)
}
