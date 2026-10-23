// SPDX-License-Identifier: Apache-2.0
//! TT07 installed operator command and downstream package delivery.
//!
//! NEW (TT07): no donor lines copied.
//!
//! The operator runs versioned conformance profiles from explicit offline
//! inputs: a catalog, a fixture root with a hash-pinned closure manifest and
//! a writable output directory. Standalone runs use the linked
//! [`delivery::DeliveryAdapter`]; downstream consumers embed this library with
//! their own adapters against their own resolved versions. A receipt records
//! historical evidence only and is never runtime authority.

pub mod cleanup;
pub mod closure;
pub mod commands;
pub mod delivery;
pub mod describe;
pub mod error;
pub mod plan;
pub mod receipt;

pub use error::{exit_for_kind, OperatorError, OperatorErrorKind};
pub use error::{
    EXIT_BROKEN_PACKAGE, EXIT_FAILURE, EXIT_INCOMPLETE, EXIT_OK, EXIT_USAGE, NO_QUALIFICATION,
};
