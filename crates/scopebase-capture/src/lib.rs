// SPDX-License-Identifier: Apache-2.0
//! Pure capture values: caller domains, typed counts, counter windows and loss.
//!
//! No clock reads, ID generation, effects or authority are acquired. The
//! `json` feature gates strict replay vectors (`replay`); the neutral
//! semantic validator (`neutral`) builds without it.
//!
//! ```
//! use scopebase_capture::quantity::{Count, Events};
//! let total = Count::<Events>::new(2).checked_add(Count::new(3))?;
//! assert_eq!(total.get(), 5);
//! # Ok::<(), scopebase_capture::ContractError>(())
//! ```
//!
//! Units cannot be mixed implicitly:
//!
//! ```compile_fail
//! use scopebase_capture::quantity::{Count, Events, Records};
//! let _ = Count::<Events>::new(2).checked_add(Count::<Records>::new(3));
//! ```
pub mod provenance;
pub mod holder;
pub mod bounds;
pub mod closure;
pub mod conservation;
pub mod counter;
pub mod loss;
pub mod domain;
pub mod error;
pub mod generation;
pub mod neutral;
pub mod quantity;
#[cfg(feature = "json")]
pub mod replay;
pub mod time;
pub mod view;
pub mod feeds;
pub mod correction;
pub use error::ContractError;
