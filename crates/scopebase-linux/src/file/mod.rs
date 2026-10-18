// SPDX-License-Identifier: Apache-2.0
//! Retained regular-file authority; acquisition does not read or map target data.
mod held;
pub use held::{AdoptFileError, HeldFile, ProcFdResolver, SymlinkPolicy};
