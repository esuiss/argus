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
