// SPDX-License-Identifier: Apache-2.0
//! Independent caller resource caps; configuration is distinct from admission.
use crate::OperationError;

/// Explicit independent caps, without an implicit unlimited sentinel.
///
/// All representable configurations are valid, including zero and MAX. A zero
/// cap permits no corresponding positive work/resource at operation admission.
/// MAX remains finite: actual owners must check sizes and arithmetic before
/// allocation or effects. No cross-field inequality or derived arithmetic is
/// implied. Pure immutable values may be used after fork; they convey no live
/// owner rights. No Default is supplied: callers choose each cap explicitly.
///
/// ```compile_fail,E0599
/// use scopebase_bpf::Limits;
/// let limits = Limits::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum admitted input bytes.
    pub input_bytes: usize,
    /// Maximum retained bytes, independent of input bytes.
    pub retained_bytes: usize,
    /// Maximum operation-specific work steps.
    pub work_steps: u64,
    /// Maximum operation sites, independent of live links.
    pub sites: usize,
    /// Maximum live links.
    pub live_links: usize,
    /// Maximum pending retirements, independent of live links.
    pub pending_retirements: usize,
}

impl Limits {
    /// Validate configuration structurally, without admitting an operation.
    ///
    /// At version 0.1 every representable configuration is valid. This constant
    /// bounded check allocates nothing, mutates nothing and performs no derived
    /// arithmetic. Actual owners retain checked geometry, cumulative accounting,
    /// capacity and effect admission. Success is not permission to start work.
    pub fn validate(&self) -> Result<(), OperationError> {
        Ok(())
    }
}
