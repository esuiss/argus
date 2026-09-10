// Yönetim API'sinin karar mantığı. §24 beş satıcının admin API'sini
// inceleyip 38 somut karara çeviriyor; bunlardan tesisat değil karar
// olanlar burada durur, argus-http yalnızca tele taşır.

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
