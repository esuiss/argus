#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Platform,
    Tenant,
}

impl Surface {
    #[must_use]
    pub const fn audience_suffix(self) -> &'static str {
        match self {
            Self::Platform => "/admin/platform",
            Self::Tenant => "/admin/api",
        }
    }

    #[must_use]
    pub const fn scope_prefix(self) -> &'static str {
        match self {
            Self::Platform => "platform:",
            Self::Tenant => "tenant:",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRequirement {
    pub method: &'static str,
    pub path: &'static str,
    pub surface: Surface,
    pub object_kind: &'static str,
    pub relation: &'static str,
    pub mutating: bool,
}

pub const CLIENTS: &str = "/admin/api/clients/v1";
pub const CLIENT: &str = "/admin/api/clients/v1/{id}";
pub const SUBORDINATES: &str = "/admin/api/federation-subordinates/v1";
pub const SUBORDINATE: &str = "/admin/api/federation-subordinates/v1/{id}";
pub const JOBS: &str = "/admin/api/jobs/v1";
pub const JOB: &str = "/admin/api/jobs/v1/{id}";
pub const TENANTS: &str = "/admin/platform/tenants/v1";
pub const TENANT: &str = "/admin/platform/tenants/v1/{id}";
pub const OPENAPI: &str = "/admin/api/openapi/v1";
pub const AUDIT_PROOF: &str = "/admin/api/audit-proofs/v1/{id}";
pub const AUDIT_CHECKPOINTS: &str = "/admin/api/audit-checkpoints/v1";

pub const MANIFEST: &[RouteRequirement] = &[
    RouteRequirement {
        method: "GET",
        path: CLIENTS,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "view_clients",
        mutating: false,
    },
    RouteRequirement {
        method: "POST",
        path: CLIENTS,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_clients",
        mutating: true,
    },
    RouteRequirement {
        method: "GET",
        path: CLIENT,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "view_clients",
        mutating: false,
    },
    RouteRequirement {
        method: "PUT",
        path: CLIENT,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_clients",
        mutating: true,
    },
    RouteRequirement {
        method: "PATCH",
        path: CLIENT,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_clients",
        mutating: true,
    },
    RouteRequirement {
        method: "DELETE",
        path: CLIENT,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_clients",
        mutating: true,
    },
    RouteRequirement {
        method: "GET",
        path: SUBORDINATES,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "view_federation",
        mutating: false,
    },
    RouteRequirement {
        method: "POST",
        path: SUBORDINATES,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_federation",
        mutating: true,
    },
    RouteRequirement {
        method: "PUT",
        path: SUBORDINATE,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_federation",
        mutating: true,
    },
    RouteRequirement {
        method: "DELETE",
        path: SUBORDINATE,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_federation",
        mutating: true,
    },
    RouteRequirement {
        method: "POST",
        path: JOBS,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_clients",
        mutating: true,
    },
    RouteRequirement {
        method: "GET",
        path: JOB,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "view_clients",
        mutating: false,
    },
    RouteRequirement {
        method: "GET",
        path: AUDIT_PROOF,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "view_audit",
        mutating: false,
    },
    RouteRequirement {
        method: "POST",
        path: AUDIT_CHECKPOINTS,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "manage_audit",
        mutating: true,
    },
    RouteRequirement {
        method: "GET",
        path: OPENAPI,
        surface: Surface::Tenant,
        object_kind: "tenant",
        relation: "view_clients",
        mutating: false,
    },
    RouteRequirement {
        method: "GET",
        path: TENANTS,
        surface: Surface::Platform,
        object_kind: "platform",
        relation: "view_tenants",
        mutating: false,
    },
    RouteRequirement {
        method: "POST",
        path: TENANTS,
        surface: Surface::Platform,
        object_kind: "platform",
        relation: "manage_tenants",
        mutating: true,
    },
    RouteRequirement {
        method: "GET",
        path: TENANT,
        surface: Surface::Platform,
        object_kind: "platform",
        relation: "view_tenants",
        mutating: false,
    },
];

#[must_use]
pub fn requirement(method: &str, path: &str) -> Option<&'static RouteRequirement> {
    MANIFEST
        .iter()
        .find(|entry| entry.method == method && entry.path == path)
}

#[must_use]
pub fn tenant_relations() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = MANIFEST
        .iter()
        .filter(|entry| entry.surface == Surface::Tenant)
        .map(|entry| entry.relation)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[must_use]
pub fn platform_relations() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = MANIFEST
        .iter()
        .filter(|entry| entry.surface == Surface::Platform)
        .map(|entry| entry.relation)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}
