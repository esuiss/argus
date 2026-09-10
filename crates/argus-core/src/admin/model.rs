use crate::authz::grant::GrantPolicy;
use crate::authz::model::{Model, Rewrite, TypeDef};

use super::manifest::{platform_relations, tenant_relations};

pub const ADMINISTRATOR: &str = "admin";

fn granted_or_inherited() -> Rewrite {
    Rewrite::Union(vec![
        Rewrite::This,
        Rewrite::ComputedUserset {
            relation: ADMINISTRATOR.to_owned(),
        },
    ])
}

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
