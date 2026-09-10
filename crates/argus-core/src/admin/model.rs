use crate::authz::grant::GrantPolicy;
use crate::authz::model::{Model, Rewrite, TypeDef};

use super::manifest::{platform_relations, tenant_relations};

// Bir yöneticinin kiracı ya da kontrol düzlemi üzerinde tuttuğu ilişki.
// §24 #13'ün değişmezi buna karşı zorlanır: aktör, üzerindeki hiçbir ilişkiyi
// değiştiremeden önce nesneyi yönetiyor olmalı.
pub const ADMINISTRATOR: &str = "admin";

// Ya doğrudan yazılmış ya da özne nesneyi yönettiği için tutuluyor. İlk biçim
// delegasyondur: §24 #38 bir kiracının yönetimi vermeden tek bir dar ilişkiyi
// dağıtabilmesini istiyor.
fn granted_or_inherited() -> Rewrite {
    Rewrite::Union(vec![
        Rewrite::This,
        Rewrite::ComputedUserset {
            relation: ADMINISTRATOR.to_owned(),
        },
    ])
}

#[must_use]
// Yönetim API'sinin koştuğu model, router'ın üretildiği manifestodan türer.
// Bir route'un istediği ama modelin bildirmediği bir ilişki o route'u
// erişilemez yapardı; ikisi ayrışamaz.
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
