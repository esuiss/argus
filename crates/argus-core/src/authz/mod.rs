// Yetkilendirme motoru. §20 §7.2 harici bir motor yerine gömülü kendi
// motorumuzu seçti: OpenFGA ve SpiceDB Go'dur ve token endpoint'i için
// istek başına bir gRPC hop'u kabul edilemez. §20 §7.7 motoru fazlara
// ayırıyor; burası F0 ve F1: referans çözümleyici ve veri modeli. Karar
// cache'i, materialize indeks ve ağırlıklı planlayıcı YOK. Sonraki her
// aşama buna karşı diferansiyel test edilmek zorunda, o yüzden doğruluk
// yalnızca burada yaşar.

pub mod check;
pub mod grant;
pub mod index;
pub mod model;
pub mod proof;
pub mod search;

pub use check::{
    BatchSemantics, CheckError, CheckRequest, Decision, DecisionTrace, MAX_DEPTH, MAX_WIDTH,
    batch_check, check, explain,
};
pub use grant::{GrantPolicy, GrantRefusal, TupleOp, may_apply};
pub use index::{MAX_TUPLES_PER_WRITE, TupleIndex};
pub use model::{EntityRef, Model, ModelError, Rewrite, SubjectRef, Tuple, TypeDef};
pub use proof::{Action, Authorized, Denied, Resource, authorize};
pub use search::{MAX_RESULTS, Page, ResourceSearch, SearchError, search_resources};
