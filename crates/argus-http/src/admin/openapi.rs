use argus_core::admin::manifest::{MANIFEST, Surface};
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::guard::{Shared, admit};

/// §24 #8: the specification is generated from the same table the router is
/// built from, so it cannot drift. Keycloak's v1 spec was written beside the
/// code and its own maintainer called it insufficient to generate clients
/// from. Keycloak v2's other good idea is here too: the document is served at
/// run time, so a generator adapts to the server it is talking to.
pub(super) async fn document(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let entry = argus_core::admin::requirement("GET", argus_core::admin::manifest::OPENAPI);
    if let Some(entry) = entry
        && let Err(refusal) = admit(&state, &headers, entry).await
    {
        return *refusal;
    }

    let mut paths: Map<String, Value> = Map::new();

    for route in MANIFEST {
        let operations = paths
            .entry(route.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));

        let Some(operations) = operations.as_object_mut() else {
            continue;
        };

        let scope = format!("{}{}", route.surface.scope_prefix(), route.relation);

        let mut responses = Map::new();
        responses.insert("200".to_owned(), json!({ "description": "the resource" }));
        if route.mutating {
            responses.insert(
                "201".to_owned(),
                json!({ "description": "the resource was created" }),
            );
            responses.insert(
                "409".to_owned(),
                json!({ "description": "the idempotency key is still in flight" }),
            );
            responses.insert(
                "422".to_owned(),
                json!({ "description": "the idempotency key was reused with another payload" }),
            );
        }
        // §24 #15: a caller without the permission is told the resource is not
        // there, so the document does not advertise a 403 that never comes.
        responses.insert(
            "404".to_owned(),
            json!({ "description": "no such resource, or not visible to this caller" }),
        );

        let mut operation = Map::new();
        operation.insert(
            "operationId".to_owned(),
            Value::String(operation_id(route.method, route.path)),
        );
        operation.insert("security".to_owned(), json!([{ "bearer": [scope] }]));
        operation.insert("responses".to_owned(), Value::Object(responses));

        if route.mutating {
            operation.insert(
                "parameters".to_owned(),
                json!([{
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": false,
                    "schema": { "type": "string", "maxLength": 255 },
                    "description": "safe to retry with the same key and the same payload"
                }]),
            );
        }

        operations.insert(route.method.to_lowercase(), Value::Object(operation));
    }

    Json(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Argus administrative API",
            "version": "1",
            "description": "Generated from the route permission manifest."
        },
        "servers": [{ "url": state.issuer.clone() }],
        "components": {
            "securitySchemes": {
                "bearer": {
                    "type": "oauth2",
                    "flows": {
                        "clientCredentials": {
                            "tokenUrl": format!("{}/token", state.issuer),
                            "scopes": scopes()
                        }
                    }
                }
            }
        },
        "paths": paths
    }))
    .into_response()
}

fn scopes() -> Value {
    let mut out = Map::new();
    for route in MANIFEST {
        let name = format!("{}{}", route.surface.scope_prefix(), route.relation);
        let description = match route.surface {
            Surface::Platform => "platform control plane",
            Surface::Tenant => "tenant administration",
        };
        out.insert(name, Value::String(description.to_owned()));
    }
    Value::Object(out)
}

fn operation_id(method: &str, path: &str) -> String {
    let tail: String = path
        .trim_start_matches('/')
        .replace(['/', '{', '}'], "_")
        .replace("__", "_");
    format!("{}_{tail}", method.to_lowercase())
}
