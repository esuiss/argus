use argus_core::dpop::ReplayGuard;
use argus_core::time::{Duration, Timestamp};

use crate::store::{JtiOutcome, JtiPurpose, ReplayStore, StoreError};

pub struct PrecheckedReplay(bool);

impl PrecheckedReplay {
    #[must_use]
    pub const fn fresh() -> Self {
        Self(false)
    }
}

impl ReplayGuard for PrecheckedReplay {
    fn seen(&self, _jti: &str) -> bool {
        self.0
    }
}

pub async fn consume<P>(
    store: &P,
    tenant: argus_core::id::TenantId,
    purpose: JtiPurpose,
    jti: &str,
    now: Timestamp,
    window: Duration,
) -> Result<PrecheckedReplay, StoreError>
where
    P: ReplayStore + Sync,
{
    let outcome = store
        .consume_jti(tenant, purpose, jti, now.saturating_add(window))
        .await?;
    Ok(PrecheckedReplay(outcome == JtiOutcome::Replayed))
}
