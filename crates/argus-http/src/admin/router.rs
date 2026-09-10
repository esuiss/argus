use axum::Router;
use axum::routing::{MethodRouter, delete, get, patch, post, put};

use argus_core::admin::manifest::{self, MANIFEST, RouteRequirement, Surface};

use super::guard::Shared;
use super::{jobs, openapi, resources};

/// §24 #10. The router is generated from the permission manifest: every entry
/// gets a handler here, and a handler with no entry has nowhere to be mounted.
/// Zitadel CVE-2025-27507 was twelve endpoints opened by one wrong string in a
/// service definition, and the fix class is exactly this: the requirement is
/// data, and the wiring is derived from it rather than written beside it.
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

        ("GET", manifest::OPENAPI) => get(openapi::document),

        ("GET", manifest::TENANTS) => get(resources::list_tenants),
        ("POST", manifest::TENANTS) => post(resources::create_tenant),
        ("GET", manifest::TENANT) => get(resources::get_tenant),

        _ => return None,
    })
}

/// Every manifest entry that has a handler. A route the manifest declares and
/// nobody implemented is caught by a test rather than shipped as a 404.
pub fn build(state: Shared) -> Router {
    let mut router: Router<Shared> = Router::new();

    // §24 #21: the control plane routes exist only in a process that holds a
    // control plane connection. A tenant-serving deployment does not merely
    // refuse them, it does not carry them.
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

/// Manifest entries with no handler. The test suite asserts this is empty; it
/// is a function rather than a constant so the check runs against the same
/// table the router is built from.
#[must_use]
pub fn unimplemented() -> Vec<(&'static str, &'static str)> {
    MANIFEST
        .iter()
        .filter(|entry| handler(entry).is_none())
        .map(|entry| (entry.method, entry.path))
        .collect()
}
