// SPDX-License-Identifier: Apache-2.0
//! Host-only BPF error transport and explicit resource-cap configuration.
//!
//! This std-only foundation performs no native operations. Classification is
//! caller supplied; caps confer no allocation, work or live-resource authority.
//!
//! ```
//! use scopebase_bpf::{ErrorKind, Limits, OperationError, Stage};
//! let limits = Limits { input_bytes: 0, retained_bytes: 0, work_steps: 0,
//!     sites: 0, live_links: 0, pending_retirements: 0 };
//! assert!(limits.validate().is_ok()); // structurally valid disabled configuration
//! let error = OperationError::new(ErrorKind::LimitExceeded, Stage::Admission,
//!     None, None).with_required_size(8);
//! assert_eq!(error.kind(), ErrorKind::LimitExceeded);
//! assert_eq!(error.stage(), Stage::Admission);
//! assert_eq!(error.required_size(), Some(8)); // reporting is not allocation
//! ```
//!
//! From an unpacked package run `cargo test --offline --locked --all-targets`
//! and `cargo test --offline --locked --doc`. Downstream `cargo test` does not
//! automatically run dependency tests. External UI controls are described in
//! the package README. No installed operator route or BPF profile is qualified.
#![forbid(unsafe_code)]

pub mod error;
pub mod limits;

pub use error::{ErrorKind, OperationError, Stage};
pub use limits::Limits;
