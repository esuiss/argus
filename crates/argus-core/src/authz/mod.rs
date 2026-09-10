//! The authorization engine. §20 §7.2 chose an embedded engine of our own
//! over an external one, and §20 §7.7 stages it: this is F0 and F1, the
//! reference resolver and its data model, with no materialized index, no
//! decision cache and no weighted planner. Those stages must be differentially
//! tested against this one, which is why correctness lives here alone.

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
