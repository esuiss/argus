//! The administrative API. ARGUS.md §24 turned a survey of five vendors into
//! 38 decisions; this module carries them over the wire and argus-core holds
//! the judgement behind them.
//!
//! Two things here are structural rather than conventional. The router is
//! generated from the permission manifest, so a route that nobody declared a
//! permission for cannot be mounted at all: §24 #10, after Zitadel
//! CVE-2025-27507 opened twelve endpoints through one mistyped string. And a
//! caller who may not see a resource gets a 404, not a 403: §24 #15, because
//! a 403 confirms the resource exists.

mod guard;
mod jobs;
mod openapi;
mod resources;
mod router;

pub use guard::{AdminState, Caller, PLATFORM_OBJECT, Refusal, Shared};
pub use router::{build, unimplemented};
