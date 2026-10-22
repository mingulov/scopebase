// SPDX-License-Identifier: Apache-2.0
//! TT08 causal selection core: affected-check selector, independent selection
//! oracle, and scheduling/accounting records over the TT01 catalog graph.
//!
//! [`select_affected`] maps a [`ChangeManifest`] to the required checks of the
//! requested profiles by reverse reachability over the catalog dependency
//! graph (see [`crate::CaseCatalog`]). [`expected_selection`] recomputes the same set independently by
//! forward closure intersection, and [`check_agreement`] names any dropped or
//! invented cells. [`RunAccounting`] derives executed-vs-plan records from the
//! actual selection, and [`qualification_gate`] keeps retry semantics honest.
//!
//! This core is pure: no CI workflow authoring or execution, no filesystem or
//! network access, no remote or secret handling. CI-platform binding stays
//! with the owner decision Q-TT08-1.
//!
//! ```
//! use scopebase_testkit::select::{ChangeManifest, SelectionLimits};
//! let manifest = ChangeManifest::new(vec![]);
//! assert!(manifest.changes().is_empty());
//! assert!(SelectionLimits::default().max_changes > 0);
//! ```

pub mod accounting;
pub mod manifest;
pub mod oracle;
pub mod selector;

pub use accounting::*;
pub use manifest::*;
pub use oracle::*;
pub use selector::*;
