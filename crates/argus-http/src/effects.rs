use argus_core::effect::Effect;
use argus_core::id::TenantId;
use argus_core::refresh::FamilyId;
use argus_core::time::Timestamp;

use crate::store::{AuditSink, CodeStore, RefreshStore, StoreError};

pub struct EffectContext<'a> {
    pub tenant: TenantId,

    pub code_hash: Option<&'a [u8; 32]>,

    pub rotation: Option<Rotation<'a>>,

    pub now: Timestamp,
}

pub struct Rotation<'a> {
    pub old_hash: &'a [u8; 32],

    pub new_hash: &'a [u8; 32],

    pub new_token: &'a argus_core::refresh::RefreshToken,

    pub family: FamilyId,
}

pub async fn apply<C, R, A>(
    effects: &[Effect],
    ctx: &EffectContext<'_>,
    codes: &C,
    refresh: &R,
    audit: &A,
) -> Result<(), StoreError>
where
    C: CodeStore,
    R: RefreshStore,
    A: AuditSink,
{
    for effect in effects {
        match effect {
            Effect::ConsumeCode => {
                let hash = ctx.code_hash.ok_or(StoreError::Unavailable)?;
                codes.consume(ctx.tenant, hash, ctx.now).await?;
            }
            Effect::RevokeTokensIssuedForCode => {
                let hash = ctx.code_hash.ok_or(StoreError::Unavailable)?;
                codes
                    .revoke_tokens_issued_for_code(ctx.tenant, hash, ctx.now)
                    .await?;
            }
            Effect::RotateRefreshToken => {
                let r = ctx.rotation.as_ref().ok_or(StoreError::Unavailable)?;
                refresh
                    .rotate(ctx.tenant, r.old_hash, r.new_hash, r.new_token, ctx.now)
                    .await?;
            }
            Effect::RevokeRefreshFamily => {
                let r = ctx.rotation.as_ref().ok_or(StoreError::Unavailable)?;
                refresh.revoke_family(ctx.tenant, r.family, ctx.now).await?;
            }
            Effect::RecordAudit(event_type) => {
                audit.record(ctx.tenant, event_type, ctx.now).await?;
            }
        }
    }
    Ok(())
}
