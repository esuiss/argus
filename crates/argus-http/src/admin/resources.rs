use argus_core::admin::manifest::Surface;
use argus_core::admin::merge_patch::{apply as merge_patch, check_patch};
use argus_core::admin::page::{PageRequest, encode_cursor, link_header};
use argus_core::admin::query::{parse_filter, projection};
use argus_store::admin::AdminClient;
use argus_store::subordinates::Subordinate;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

use super::guard::{
    AdminState, Idempotency, Shared, admit, close_idempotency, hidden, open_idempotency, problem,
};

/// Fields the subordinate resource exposes. §24 #5 and #26: a filter or a
/// projection naming anything else is an error, and a GET never invents a
/// field the caller did not set.
const SUBORDINATE_FIELDS: &[&str] = &["id", "jwks", "metadataPolicy", "constraints"];

const CLIENT_FIELDS: &[&str] = &["clientId", "clientType", "authMethod", "redirectUris"];

fn requirement(method: &str, path: &str) -> &'static argus_core::admin::RouteRequirement {
    // The router is built from the manifest, so this cannot miss. Failing
    // closed rather than unwrapping keeps that true even if it ever can.
    argus_core::admin::requirement(method, path).unwrap_or(&argus_core::admin::RouteRequirement {
        method: "NONE",
        path: "",
        surface: Surface::Platform,
        object_kind: "unmountable",
        relation: "unmountable",
        mutating: true,
    })
}

fn subordinate_view(subject: &str, record: &Subordinate) -> Value {
    let mut out = Map::new();
    out.insert("id".to_owned(), Value::String(subject.to_owned()));
    out.insert("jwks".to_owned(), record.jwks.clone());
    if let Some(policy) = record.metadata_policy.as_ref() {
        out.insert("metadataPolicy".to_owned(), policy.clone());
    }
    if let Some(constraints) = record.constraints.as_ref() {
        out.insert("constraints".to_owned(), constraints.clone());
    }
    Value::Object(out)
}

fn project(value: &Value, fields: &[String]) -> Value {
    if fields.is_empty() {
        return value.clone();
    }
    let mut out = Map::new();
    if let Some(members) = value.as_object() {
        for name in fields {
            if let Some(found) = members.get(name) {
                out.insert(name.clone(), found.clone());
            }
        }
    }
    Value::Object(out)
}

fn listing(
    base: &str,
    items: Vec<Value>,
    page: &PageRequest,
    cursor_of: impl Fn(&Value) -> String,
) -> Response {
    let mut items = items;
    let next = if items.len() > page.limit {
        items.truncate(page.limit);
        items.last().map(&cursor_of).map(|key| encode_cursor(&key))
    } else {
        None
    };

    let body = json!({ "items": items });
    let mut response = (StatusCode::OK, Json(body)).into_response();

    if let Some(header) = link_header(base, next.as_deref(), None)
        && let Ok(value) = header.parse()
    {
        response
            .headers_mut()
            .insert(axum::http::header::LINK, value);
    }

    response
}

type QueryParts = (Option<String>, Vec<String>, PageRequest);

fn query_of(raw: &BTreeMap<String, String>, fields: &[&str]) -> Result<QueryParts, Box<Response>> {
    if let Some(filter) = raw.get("q")
        && let Err(e) = parse_filter(filter, fields)
    {
        return Err(Box::new(problem(400, "invalid_query", &e.to_string())));
    }

    let projected = match raw.get("fields") {
        None => Vec::new(),
        Some(raw) => projection(raw, fields)
            .map_err(|e| Box::new(problem(400, "invalid_query", &e.to_string())))?,
    };

    let page = PageRequest::parse(
        raw.get("cursor").map(String::as_str),
        raw.get("limit").map(String::as_str),
    )
    .map_err(|e| Box::new(problem(400, "invalid_query", &e.to_string())))?;

    Ok((raw.get("q").cloned(), projected, page))
}

pub(super) async fn list_subordinates(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(raw): Query<BTreeMap<String, String>>,
) -> Response {
    let entry = requirement("GET", argus_core::admin::manifest::SUBORDINATES);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let (_, fields, page) = match query_of(&raw, SUBORDINATE_FIELDS) {
        Ok(parts) => parts,
        Err(response) => return *response,
    };

    let Ok(subjects) = state.store.list_subordinates(state.tenant_id).await else {
        return problem(503, "unavailable", "the registry is unreadable");
    };

    let mut items = Vec::new();
    for subject in subjects {
        if let Some(after) = page.after.as_deref()
            && subject.as_str() <= after
        {
            continue;
        }
        if items.len() > page.limit {
            break;
        }
        let Ok(record) = state
            .store
            .find_subordinate(state.tenant_id, &subject)
            .await
        else {
            continue;
        };
        items.push(project(&subordinate_view(&subject, &record), &fields));
    }

    listing(
        argus_core::admin::manifest::SUBORDINATES,
        items,
        &page,
        |item| {
            item.get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        },
    )
}

async fn write_subordinate(
    state: &AdminState,
    key: Option<&str>,
    id: &str,
    body: &Value,
    created: bool,
) -> Response {
    let key = key.map(str::to_owned);

    let Some(jwks) = body.get("jwks").filter(|v| v.is_object()).cloned() else {
        let response = problem(400, "invalid_request", "jwks must be a JSON object");
        close_idempotency(state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
        return response;
    };

    let record = Subordinate {
        subject: id.to_owned(),
        jwks,
        metadata_policy: body
            .get("metadataPolicy")
            .filter(|v| v.is_object())
            .cloned(),
        constraints: body.get("constraints").filter(|v| v.is_object()).cloned(),
    };

    if state
        .store
        .enrol_subordinate(state.tenant_id, &record)
        .await
        .is_err()
    {
        close_idempotency(state, key.as_deref(), Surface::Tenant, 503, &Value::Null).await;
        return problem(503, "unavailable", "the registry is unwritable");
    }

    // §24 #3: the full representation in the body, not an id in a header.
    let view = subordinate_view(id, &record);
    let status = if created { 201 } else { 200 };
    close_idempotency(state, key.as_deref(), Surface::Tenant, status, &view).await;

    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    (code, Json(view)).into_response()
}

pub(super) async fn create_subordinate(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let entry = requirement("POST", argus_core::admin::manifest::SUBORDINATES);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let key = match open_idempotency(&state, &headers, Surface::Tenant, &body).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    let Some(id) = body.get("id").and_then(Value::as_str) else {
        close_idempotency(&state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
        return problem(400, "invalid_request", "id is required");
    };

    if state
        .store
        .find_subordinate(state.tenant_id, id)
        .await
        .is_ok()
    {
        let response = problem(
            409,
            "already_exists",
            "this subordinate is already enrolled",
        );
        close_idempotency(&state, key.as_deref(), Surface::Tenant, 409, &Value::Null).await;
        return response;
    }

    write_subordinate(&state, key.as_deref(), id, &body, true).await
}

/// §24 #2: PUT is an upsert, and the status says which happened.
pub(super) async fn put_subordinate(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let entry = requirement("PUT", argus_core::admin::manifest::SUBORDINATE);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let key = match open_idempotency(&state, &headers, Surface::Tenant, &body).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    let existed = state
        .store
        .find_subordinate(state.tenant_id, &id)
        .await
        .is_ok();

    write_subordinate(&state, key.as_deref(), &id, &body, !existed).await
}

pub(super) async fn delete_subordinate(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let entry = requirement("DELETE", argus_core::admin::manifest::SUBORDINATE);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    match state.store.withdraw_subordinate(state.tenant_id, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(argus_store::traits::StoreError::NotFound) => hidden(),
        Err(_) => problem(503, "unavailable", "the registry is unwritable"),
    }
}

fn client_view(client: &AdminClient) -> Value {
    json!({
        "clientId": client.client_id,
        "clientType": client.client_type,
        "authMethod": client.auth_method,
        "redirectUris": client.redirect_uris,
    })
}

fn client_from(body: &Value, id: &str) -> Result<AdminClient, Box<Response>> {
    let client_type = body
        .get("clientType")
        .and_then(Value::as_str)
        .unwrap_or("public")
        .to_owned();

    // The schema couples the two, and a public client with a credential is a
    // contradiction rather than a preference.
    let auth_method = body
        .get("authMethod")
        .and_then(Value::as_str)
        .unwrap_or(if client_type == "confidential" {
            "private_key_jwt"
        } else {
            "none"
        })
        .to_owned();

    let redirect_uris = match body.get("redirectUris") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Some(uri) = item.as_str() else {
                    return Err(Box::new(problem(
                        400,
                        "invalid_request",
                        "every redirectUri must be a string",
                    )));
                };
                out.push(uri.to_owned());
            }
            out
        }
        Some(_) => {
            return Err(Box::new(problem(
                400,
                "invalid_request",
                "redirectUris must be an array",
            )));
        }
    };

    Ok(AdminClient {
        client_id: id.to_owned(),
        client_type,
        auth_method,
        redirect_uris,
    })
}

pub(super) async fn list_clients(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(raw): Query<BTreeMap<String, String>>,
) -> Response {
    let entry = requirement("GET", argus_core::admin::manifest::CLIENTS);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let (_, fields, page) = match query_of(&raw, CLIENT_FIELDS) {
        Ok(parts) => parts,
        Err(response) => return *response,
    };

    let Ok(clients) = state
        .store
        .list_clients(state.tenant_id, page.after.as_deref(), page.limit + 1)
        .await
    else {
        return problem(503, "unavailable", "the client registry is unreadable");
    };

    let items: Vec<Value> = clients
        .iter()
        .map(|client| project(&client_view(client), &fields))
        .collect();

    listing(argus_core::admin::manifest::CLIENTS, items, &page, |item| {
        item.get("clientId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    })
}

pub(super) async fn get_client(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let entry = requirement("GET", argus_core::admin::manifest::CLIENT);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    match state.store.describe_client(state.tenant_id, &id).await {
        Ok(Some(client)) => Json(client_view(&client)).into_response(),
        Ok(None) => hidden(),
        Err(_) => problem(503, "unavailable", "the client registry is unreadable"),
    }
}

async fn save_client(state: &AdminState, key: Option<&str>, id: &str, body: &Value) -> Response {
    let key = key.map(str::to_owned);

    let client = match client_from(body, id) {
        Ok(client) => client,
        Err(response) => {
            close_idempotency(state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
            return *response;
        }
    };

    match state.store.upsert_client(state.tenant_id, &client).await {
        Ok(created) => {
            let view = client_view(&client);
            let status = if created { 201 } else { 200 };
            close_idempotency(state, key.as_deref(), Surface::Tenant, status, &view).await;
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
            (code, Json(view)).into_response()
        }
        Err(argus_store::traits::StoreError::NotFound) => {
            close_idempotency(state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
            problem(
                400,
                "invalid_request",
                "the client the schema will not accept",
            )
        }
        Err(_) => {
            close_idempotency(state, key.as_deref(), Surface::Tenant, 503, &Value::Null).await;
            problem(503, "unavailable", "the client registry is unwritable")
        }
    }
}

pub(super) async fn create_client(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let entry = requirement("POST", argus_core::admin::manifest::CLIENTS);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    // The idempotency gate comes before the conflict check, or a retry of a
    // request that already succeeded would be told the resource exists rather
    // than being handed back what its first attempt produced. That is exactly
    // the case §24 #33 exists for.
    let key = match open_idempotency(&state, &headers, Surface::Tenant, &body).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    let Some(id) = body.get("clientId").and_then(Value::as_str) else {
        close_idempotency(&state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
        return problem(400, "invalid_request", "clientId is required");
    };

    if state
        .store
        .describe_client(state.tenant_id, id)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        let response = problem(409, "already_exists", "this client is already registered");
        close_idempotency(&state, key.as_deref(), Surface::Tenant, 409, &Value::Null).await;
        return response;
    }

    save_client(&state, key.as_deref(), id, &body).await
}

pub(super) async fn put_client(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let entry = requirement("PUT", argus_core::admin::manifest::CLIENT);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let key = match open_idempotency(&state, &headers, Surface::Tenant, &body).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    save_client(&state, key.as_deref(), &id, &body).await
}

/// §24 #2 and #12: the patch is checked against the resource's own fields
/// before anything is applied, and clientId cannot move.
pub(super) async fn patch_client(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<Value>,
) -> Response {
    let entry = requirement("PATCH", argus_core::admin::manifest::CLIENT);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    if let Err(e) = check_patch(&patch, CLIENT_FIELDS, &["clientId"]) {
        return problem(400, "invalid_request", &e.to_string());
    }

    let Ok(Some(current)) = state.store.describe_client(state.tenant_id, &id).await else {
        return hidden();
    };

    let updated = match merge_patch(&client_view(&current), &patch) {
        Ok(value) => value,
        Err(e) => return problem(400, "invalid_request", &e.to_string()),
    };

    let key = match open_idempotency(&state, &headers, Surface::Tenant, &patch).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    save_client(&state, key.as_deref(), &id, &updated).await
}

pub(super) async fn delete_client(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let entry = requirement("DELETE", argus_core::admin::manifest::CLIENT);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    match state.store.delete_client(state.tenant_id, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(argus_store::traits::StoreError::NotFound) => hidden(),
        Err(_) => problem(503, "unavailable", "the client registry is unwritable"),
    }
}

const TENANT_FIELDS: &[&str] = &["id", "slug", "issuerHost"];

fn tenant_view(record: &argus_store::admin::TenantRecord) -> Value {
    json!({
        "id": record.tenant_id,
        "slug": record.slug,
        "issuerHost": record.issuer_host,
    })
}

pub(super) async fn list_tenants(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(raw): Query<BTreeMap<String, String>>,
) -> Response {
    let entry = requirement("GET", argus_core::admin::manifest::TENANTS);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let (_, fields, page) = match query_of(&raw, TENANT_FIELDS) {
        Ok(parts) => parts,
        Err(response) => return *response,
    };

    let Ok(records) = state
        .store
        .list_tenants(page.after.as_deref(), page.limit + 1)
        .await
    else {
        return problem(503, "unavailable", "the tenant registry is unreadable");
    };

    let items: Vec<Value> = records
        .iter()
        .map(|record| project(&tenant_view(record), &fields))
        .collect();

    listing(argus_core::admin::manifest::TENANTS, items, &page, |item| {
        item.get("slug")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    })
}

pub(super) async fn get_tenant(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    let entry = requirement("GET", argus_core::admin::manifest::TENANT);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    match state.store.find_tenant(&slug).await {
        Ok(Some(record)) => Json(tenant_view(&record)).into_response(),
        Ok(None) => hidden(),
        Err(_) => problem(503, "unavailable", "the tenant registry is unreadable"),
    }
}

pub(super) async fn create_tenant(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let entry = requirement("POST", argus_core::admin::manifest::TENANTS);
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let key = match open_idempotency(&state, &headers, Surface::Platform, &body).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    let (Some(slug), Some(host)) = (
        body.get("slug").and_then(Value::as_str),
        body.get("issuerHost").and_then(Value::as_str),
    ) else {
        close_idempotency(&state, key.as_deref(), Surface::Platform, 400, &Value::Null).await;
        return problem(400, "invalid_request", "slug and issuerHost are required");
    };

    let Ok(record) = state.store.create_tenant(slug, host).await else {
        close_idempotency(&state, key.as_deref(), Surface::Platform, 409, &Value::Null).await;
        return problem(409, "already_exists", "the slug or issuer host is taken");
    };

    let view = tenant_view(&record);
    close_idempotency(&state, key.as_deref(), Surface::Platform, 201, &view).await;
    (StatusCode::CREATED, Json(view)).into_response()
}
