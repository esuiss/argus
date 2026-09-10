use argus_core::admin::manifest::Surface;
use argus_core::audit::record::{Checkpoint, inclusion_document};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::guard::{
    Caller, Idempotency, Shared, admit, close_idempotency, hidden, open_idempotency, problem,
};

fn chain_uid(permit: &Caller) -> String {
    format!(
        "{}{}",
        argus_core::audit::CHAIN_UID_PREFIX,
        permit.tenant().as_uuid()
    )
}

// §9.3. Crosby & Wallach: 80 milyon olaylı bir logda tek olayın kanıtı burada
// 3 KB, hash zincirinde 800 MB. Bu farktır bunu bir dipnot değil bir uç nokta
// yapan şey.
pub(super) async fn proof(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(entry) =
        argus_core::admin::requirement("GET", argus_core::admin::manifest::AUDIT_PROOF)
    else {
        return hidden();
    };
    let permit = match admit(&state, &headers, entry).await {
        Ok(permit) => permit,
        Err(refusal) => return *refusal,
    };

    let Ok(event_id) = uuid::Uuid::parse_str(&id) else {
        return problem(400, "invalid_request", "the event id is not a uuid");
    };

    match state
        .store
        .audit_proof(permit.tenant(), &event_id, &argus_crypto::AwsLcSha256)
        .await
    {
        Ok((index, leaf, checkpoint, path)) => Json(inclusion_document(
            &chain_uid(&permit),
            &leaf,
            index,
            &checkpoint,
            &path,
        ))
        .into_response(),
        // En yeni checkpoint'in kapsamadığı bir olayın henüz kanıtı yoktur ve
        // bunu söylemek, doğrulanamayacak bir kanıt vermekten iyidir.
        Err(argus_store::traits::StoreError::NotFound) => hidden(),
        Err(_) => problem(503, "unavailable", "the audit log is unreadable"),
    }
}

pub(super) async fn checkpoint(
    State(state): State<Shared>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    let Some(entry) =
        argus_core::admin::requirement("POST", argus_core::admin::manifest::AUDIT_CHECKPOINTS)
    else {
        return hidden();
    };
    let permit = match admit(&state, &headers, entry).await {
        Ok(permit) => permit,
        Err(refusal) => return *refusal,
    };

    let payload = body.map_or(Value::Null, |Json(value)| value);
    let key = match open_idempotency(&state, &permit, &headers, Surface::Tenant, &payload).await {
        Ok(Idempotency::Replay(response)) => return response,
        Ok(Idempotency::Run(key)) => key,
        Err(refusal) => return *refusal,
    };

    match state
        .store
        .checkpoint_audit(permit.tenant(), &argus_crypto::AwsLcSha256)
        .await
    {
        Ok(Some(checkpoint)) => {
            let view = view_of(&permit, &checkpoint);
            close_idempotency(&state, &permit, key.as_deref(), Surface::Tenant, 201, &view).await;
            (StatusCode::CREATED, Json(view)).into_response()
        }
        Ok(None) => {
            let view = json!({ "folded": 0 });
            close_idempotency(&state, &permit, key.as_deref(), Surface::Tenant, 200, &view).await;
            Json(view).into_response()
        }
        Err(_) => {
            close_idempotency(
                &state,
                &permit,
                key.as_deref(),
                Surface::Tenant,
                503,
                &Value::Null,
            )
            .await;
            problem(503, "unavailable", "the audit log is unwritable")
        }
    }
}

fn view_of(permit: &Caller, checkpoint: &Checkpoint) -> Value {
    argus_core::audit::record::checkpoint_document(&chain_uid(permit), checkpoint)
}
