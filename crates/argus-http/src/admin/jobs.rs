use argus_core::admin::job::{ItemResult, Job};
use argus_core::admin::manifest::Surface;
use argus_store::admin::AdminClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::guard::{
    Idempotency, Shared, admit, close_idempotency, hidden, open_idempotency, problem,
};

// §24 #28: bulk senkron bir batch değil, uzun süren bir işlemdir. İncelenen
// her satıcı SCIM /Bulk'u desteklemediğini bildirip bunu yazdı, o yüzden şekil
// alt isteklerden oluşan bir zarf değil budur.
pub(super) async fn submit(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(entry) = argus_core::admin::requirement("POST", argus_core::admin::manifest::JOBS)
    else {
        return hidden();
    };
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    let key = match open_idempotency(&state, &headers, Surface::Tenant, &body).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    let Some(items) = body.get("clients").and_then(Value::as_array) else {
        close_idempotency(&state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
        return problem(400, "invalid_request", "clients must be an array");
    };

    if items.is_empty() || items.len() > argus_core::admin::job::MAX_ITEMS {
        close_idempotency(&state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
        return problem(
            400,
            "invalid_request",
            "a job carries between one and ten thousand items",
        );
    }

    let Ok(id) = state
        .store
        .create_job(state.tenant_id, "clients", items.len())
        .await
    else {
        close_idempotency(&state, key.as_deref(), Surface::Tenant, 503, &Value::Null).await;
        return problem(503, "unavailable", "the job registry is unwritable");
    };

    let mut job = match Job::new(&id, items.len(), 0) {
        Ok(job) => job,
        Err(e) => {
            close_idempotency(&state, key.as_deref(), Surface::Tenant, 400, &Value::Null).await;
            return problem(400, "invalid_request", &e.to_string());
        }
    };

    if job.start().is_err() {
        return problem(500, "server_error", "the job could not be started");
    }

    for (index, item) in items.iter().enumerate() {
        let outcome = apply_one(&state, item)
            .await
            .err()
            .map(|(code, message)| ItemResult {
                index,
                code,
                message,
            });
        if job.record(outcome).is_err() {
            break;
        }
    }

    let _ = job.finish();
    let _ = state.store.save_job(state.tenant_id, &job).await;

    // AIP-151 uyarınca 202 ve pollanacak bir job kaynağı. Terminal sonuç job'ın
    // üzerindedir, asla buraya gömülmez; çağıran kabul edilmeyi tamamlanmayla
    // karıştıramasın.
    let body = json!({
        "id": job.id,
        "metadata": job.metadata(),
        "self": format!("{}/admin/api/jobs/v1/{}", state.issuer, job.id),
    });
    close_idempotency(&state, key.as_deref(), Surface::Tenant, 202, &body).await;

    (StatusCode::ACCEPTED, Json(body)).into_response()
}

async fn apply_one(state: &super::guard::AdminState, item: &Value) -> Result<(), (String, String)> {
    let Some(client_id) = item.get("clientId").and_then(Value::as_str) else {
        return Err((
            "missing_client_id".to_owned(),
            "clientId is required".to_owned(),
        ));
    };

    let client_type = item
        .get("clientType")
        .and_then(Value::as_str)
        .unwrap_or("public")
        .to_owned();

    let auth_method = if client_type == "confidential" {
        "private_key_jwt"
    } else {
        "none"
    }
    .to_owned();

    let redirect_uris = item
        .get("redirectUris")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    state
        .store
        .upsert_client(
            state.tenant_id,
            &AdminClient {
                client_id: client_id.to_owned(),
                client_type,
                auth_method,
                redirect_uris,
            },
        )
        .await
        .map(|_| ())
        .map_err(|_| {
            (
                "rejected_by_schema".to_owned(),
                "the client is not one the schema accepts".to_owned(),
            )
        })
}

pub(super) async fn status(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(entry) = argus_core::admin::requirement("GET", argus_core::admin::manifest::JOB)
    else {
        return hidden();
    };
    if let Err(refusal) = admit(&state, &headers, entry).await {
        return *refusal;
    }

    match state.store.load_job(state.tenant_id, &id).await {
        Ok(job) => Json(json!({
            "id": job.id,
            "metadata": job.metadata(),
            "response": job.response(),
        }))
        .into_response(),
        Err(argus_store::traits::StoreError::NotFound) => hidden(),
        Err(_) => problem(503, "unavailable", "the job registry is unreadable"),
    }
}
