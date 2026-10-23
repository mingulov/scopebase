// SPDX-License-Identifier: Apache-2.0
//! TC02: explicit compiler closure and bounded nested-build helper.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree):
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py`
//! (lines 122-126; line 114 is core-dump `setrlimit`, not ported),
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/run.py`
//! (lines 56-57, 63-66). Whole files are user-authored
//! (TC01). ADAPT of argv-array subprocess, wall-clock timeout, bounded
//! capture and hash-pinned-before-use; no upstream lines copied.
//! Grant: OWNER-2026-10-23.
//!
//! [`CompilerClosure`] admits a manifest in which every tool carries an
//! exact recorded sha256 and an offline origin; anything less refuses.
//! [`run_pinned`] executes one closure-pinned tool id at a caller-supplied
//! offline path under explicit byte/time/work bounds. There is no shell,
//! no inherited environment and no network access.
//!
//! [`SelectedClosure`] is the reconciled role-structured execution view
//! over an admitted manifest; [`CompilerExecutor`] runs
//! [`compile_fixture`] builds through a [`BuildScopeBackend`] with
//! persistent job custody and exclusive output-root leases. The narrow
//! host [`DirectScope`] runs one pinned direct tool under a child-only
//! no-children sandbox.
pub mod executor;
pub mod identity;
pub mod invoke;
pub mod scope;

pub use executor::{
    compile_fixture, CompileJob, CompileOutcome, CompileOutput, CompilerExecutor, ExecutorBudget,
    ExecutorClose, ExecutorLimits, ExecutorReport, ExecutorUsage, OutputReleaseError,
};
pub use identity::{CompilerClosure, PinnedTool};
#[doc(hidden)]
pub use invoke::run_pinned_with_builders;
pub use invoke::{run_pinned, NestedBounds, NestedOutput};
pub use scope::{
    BuildExit, BuildRequest, BuildScopeBackend, DirectScope, RoleBinding, RoleSelection, ScopePoll,
    ScopeStart, SelectedClosure, ToolBinary, ToolRole,
};
