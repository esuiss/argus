//! Etki uygulayıcısı.
//!
//! `argus-core`'un döndürdüğü [`Effect`] listesini gerçekleştirir. Tek bir
//! `match` olması bilinçli: enum'a yeni bir etki eklendiğinde derleyici burayı
//! kırar ve uygulanmayan bir etkiyle üretime çıkmak imkânsız olur.
//!
//! Uygulanmayan bir etki sessiz bir güvenlik açığıdır — atlanan bir
//! [`Effect::RevokeRefreshFamily`], çalınmış bir zincirin canlı kalmasıdır.

use argus_core::effect::Effect;
use argus_core::id::TenantId;
use argus_core::refresh::FamilyId;
use argus_core::time::Timestamp;

use crate::store::{AuditSink, CodeStore, RefreshStore, StoreError};

/// Etkileri uygularken gereken bağlam.
///
/// Etkiler "neyi" söyler, "hangisini" söylemez: `ConsumeCode` hangi kodun
/// tüketileceğini taşımaz çünkü `argus-core` kod değerini hiç görmez. Bu yapı
/// eksik parçayı sağlar.
pub struct EffectContext<'a> {
    /// Kiracı.
    pub tenant: TenantId,
    /// İşlenen authorization code'un hash'i — kod akışında.
    pub code_hash: Option<&'a [u8; 32]>,
    /// Rotasyon parametreleri — refresh akışında.
    pub rotation: Option<Rotation<'a>>,
    /// Uygulama anı.
    pub now: Timestamp,
}

/// Rotasyon için gereken hash'ler ve yeni kayıt.
pub struct Rotation<'a> {
    /// Sunulan (eski) token'ın hash'i.
    pub old_hash: &'a [u8; 32],
    /// Yeni token'ın hash'i.
    pub new_hash: &'a [u8; 32],
    /// Yeni kayıt.
    pub new_token: &'a argus_core::refresh::RefreshToken,
    /// İptal edilecek zincir.
    pub family: FamilyId,
}

/// Etkileri sırayla uygular.
///
/// # Errors
///
/// Herhangi bir etki başarısız olursa **durur ve hatayı döndürür**. Kalanları
/// uygulamaya devam etmek, kısmen uygulanmış bir güvenlik kararı bırakırdı.
///
/// # Panics
///
/// Panic etmez; eksik bağlam [`StoreError::Unavailable`] olarak raporlanır çünkü
/// bu bir programlama hatasıdır ve istemciye ayrıntısı verilmez.
pub fn apply<C, R, A>(
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
                codes.consume(ctx.tenant, hash, ctx.now)?;
            }
            Effect::RevokeTokensIssuedForCode => {
                let hash = ctx.code_hash.ok_or(StoreError::Unavailable)?;
                codes.revoke_tokens_issued_for_code(ctx.tenant, hash, ctx.now)?;
            }
            Effect::RotateRefreshToken => {
                let r = ctx.rotation.as_ref().ok_or(StoreError::Unavailable)?;
                refresh.rotate(ctx.tenant, r.old_hash, r.new_hash, r.new_token, ctx.now)?;
            }
            Effect::RevokeRefreshFamily => {
                let r = ctx.rotation.as_ref().ok_or(StoreError::Unavailable)?;
                refresh.revoke_family(ctx.tenant, r.family, ctx.now)?;
            }
            Effect::RecordAudit(event_type) => {
                // §1 #23: denetim kaydı yutulmaz. Kaydedilemeyen bir olay,
                // isteğin başarısız olması demektir (AU-12/PCI 10.2 "all").
                audit.record(ctx.tenant, event_type, ctx.now)?;
            }
        }
    }
    Ok(())
}
