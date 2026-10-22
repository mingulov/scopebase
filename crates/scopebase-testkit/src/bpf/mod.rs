// SPDX-License-Identifier: Apache-2.0
//! Explicit descriptive BPF model operations; no native support attestation.
mod adapter;
pub use adapter::{profile_from_testkit, profile_to_testkit, BpfHostAdapter, BpfPreparedCall};
