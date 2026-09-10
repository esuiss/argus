use crate::authz::grant::GrantPolicy;
use crate::authz::model::{Model, Rewrite, TypeDef};

use super::manifest::{platform_relations, tenant_relations};

/// The relation an administrator holds over a tenant or over the control
/// plane. §24 #13's invariant is enforced against this: an actor must
/// administer the object before it can change any relation on it.
pub const ADMINISTRATOR: &str = "admin";

fn granted_or_inherited() -> Rewrite {
    // Either written directly, or held because the subject administers the
    // object. Delegation is the first form: §24 #38 wants a tenant to be able
    // to hand out one narrow relation without handing out administration.
    Rewrite::Union(vec![
        Rewrite::This,
        Rewrite::ComputedUserset {
            relation: ADMINISTRATOR.to_owned(),
        },
    ])
}

/// The model the administrative API runs against, derived from the same
/// manifest the router is built from. A relation a route requires and the
/// model never declares would make that route unreachable, so the two cannot
/// drift apart.
#[must_use]
pub fn model() -> Model {
    let mut tenant = TypeDef::new().with(ADMINISTRATOR, Rewrite::This);
    for relation in tenant_relations() {
        tenant = tenant.with(relation, granted_or_inherited());
    }

    let mut platform = TypeDef::new().with(ADMINISTRATOR, Rewrite::This);
    for relation in platform_relations() {
        platform = platform.with(relation, granted_or_inherited());
    }

    Model::new()
        .with("user", TypeDef::new())
        .with("tenant", tenant)
        .with("platform", platform)
}

#[must_use]
pub fn policy() -> GrantPolicy {
    GrantPolicy::new()
        .administered_by("tenant", ADMINISTRATOR)
        .administered_by("platform", ADMINISTRATOR)
}
