use axum::Router;
use axum::routing::{MethodRouter, delete, get, patch, post, put};

use argus_core::admin::manifest::{self, MANIFEST, RouteRequirement, Surface};

use super::guard::Shared;
use super::{audit, jobs, openapi, resources};

fn handler(entry: &RouteRequirement) -> Option<MethodRouter<Shared>> {
    Some(match (entry.method, entry.path) {
        ("GET", manifest::CLIENTS) => get(resources::list_clients),
        ("POST", manifest::CLIENTS) => post(resources::create_client),
        ("GET", manifest::CLIENT) => get(resources::get_client),
        ("PUT", manifest::CLIENT) => put(resources::put_client),
        ("PATCH", manifest::CLIENT) => patch(resources::patch_client),
        ("DELETE", manifest::CLIENT) => delete(resources::delete_client),

        ("GET", manifest::SUBORDINATES) => get(resources::list_subordinates),
        ("POST", manifest::SUBORDINATES) => post(resources::create_subordinate),
        ("PUT", manifest::SUBORDINATE) => put(resources::put_subordinate),
        ("DELETE", manifest::SUBORDINATE) => delete(resources::delete_subordinate),

        ("POST", manifest::JOBS) => post(jobs::submit),
        ("GET", manifest::JOB) => get(jobs::status),

        ("GET", manifest::AUDIT_PROOF) => get(audit::proof),
        ("POST", manifest::AUDIT_CHECKPOINTS) => post(audit::checkpoint),

        ("GET", manifest::OPENAPI) => get(openapi::document),

        ("GET", manifest::TENANTS) => get(resources::list_tenants),
        ("POST", manifest::TENANTS) => post(resources::create_tenant),
        ("GET", manifest::TENANT) => get(resources::get_tenant),

        _ => return None,
    })
}

pub fn build(state: Shared) -> Router {
    let mut router: Router<Shared> = Router::new();

    let serves_control_plane = state.store.serves_control_plane();

    for entry in MANIFEST {
        if entry.surface == Surface::Platform && !serves_control_plane {
            continue;
        }
        if let Some(method) = handler(entry) {
            router = router.route(entry.path, method);
        }
    }

    router.with_state(state)
}

#[must_use]
pub fn unimplemented() -> Vec<(&'static str, &'static str)> {
    MANIFEST
        .iter()
        .filter(|entry| handler(entry).is_none())
        .map(|entry| (entry.method, entry.path))
        .collect()
}
