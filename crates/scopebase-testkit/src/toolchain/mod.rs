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
pub mod identity;
pub mod invoke;

pub use identity::{CompilerClosure, PinnedTool};
pub use invoke::{run_pinned, NestedBounds, NestedOutput};
