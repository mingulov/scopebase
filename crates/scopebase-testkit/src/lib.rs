// SPDX-License-Identifier: Apache-2.0
//! Strict, bounded registry admission and immutable requirement selection.
//!
//! Callers provide their catalog bytes. Selection has no availability input,
//! filesystem access, runner, verdict or subject authority. A `FROZEN` definition
//! can still require unimplemented cases and establishes no qualification.
//!
//! ```
//! use scopebase_testkit::{CaseId, ProfileId};
//! assert!(CaseId::parse("H04.path_swap").is_ok());
//! assert!(CaseId::parse("H04.path_swap\n").is_err());
//! assert!(ProfileId::parse("foo/bar").is_err());
//! ```
//!
//! A transport cannot construct or mutate an admitted required cell:
//! ```compile_fail
//! use scopebase_testkit::RequiredCell;
//! let forged = RequiredCell { case_version: 1 };
//! ```
pub mod catalog;
pub mod ids;
pub mod profile;
pub use catalog::*;
pub use ids::*;
pub use profile::*;

pub mod adapter;
pub mod artifact;
pub mod fixture;
pub mod observation;
pub mod oracle;
pub mod result;
pub mod runner;
pub use adapter::*;
pub use artifact::*;
pub use fixture::*;
pub use observation::*;
pub use oracle::*;
pub use result::*;
pub use runner::*;
#[cfg(test)]
extern crate self as scopebase_testkit;
