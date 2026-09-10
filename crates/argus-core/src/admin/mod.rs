//! The administrative API's decision logic. ARGUS.md §24 turns a survey of
//! five vendors' admin APIs into 38 concrete choices; the ones that are
//! decisions rather than plumbing live here, and argus-http only carries them
//! over the wire.

pub mod idempotency;
pub mod job;
pub mod manifest;
pub mod merge_patch;
pub mod model;
pub mod page;
pub mod query;

pub use idempotency::{IdempotencyKey, Outcome as IdempotencyOutcome, Record as IdempotencyRecord};
pub use job::{Job, JobFault, JobState};
pub use manifest::{MANIFEST, RouteRequirement, Surface, requirement};
pub use merge_patch::{MergePatchError, apply as merge_patch, check_patch};
pub use model::{ADMINISTRATOR, model, policy};
pub use page::{PageError, PageRequest, encode_cursor, link_header};
pub use query::{QueryError, parse_filter, projection};
