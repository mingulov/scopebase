// SPDX-License-Identifier: Apache-2.0
//! One conserved physical count with alternative candidate explanations.
//!
//! ADAPT: OSSLscope preview-r21 (`4bcb24c`) `src/evidence.rs:34-94,159-229`
//! (`SiteKey`, `CandidateCoverage`, `site_bound`/`match_bounds`) and
//! `tests/evidence_model.rs` regressions (`shared_site_conserves_calls`,
//! `ambiguous_require_is_unproven`, `within_alias_mixed_classes_are_unknown`,
//! `candidates_dedupe_and_sort`) plus mixed-class fix `00b135d` (H3:
//! mixed classes withhold definite claims). KryProbe algebra and p11scope
//! are explicitly excluded. H26 cross-check: MemVeil
//! `tests/unit/test_mappings.mojo` withholds occupancy while mapping
//! evidence is incomplete (`test_split_unpaired_map_withholds_occupancy`);
//! unknown candidates here likewise prove nothing, including at zero.
//!
//! DELTAS from the OSSL donor, all deliberate: (1) zero observed calls
//! with `Unknown` coverage yields `[0,None]`, not the donor's `(0,Some(0))`
//! (`zero_call_unknown_candidates_bound_known_zero`); an incomplete
//! candidate set cannot prove absence of unlisted activity. (2) The
//! donor's `AmbiguousComplete` coverage is not a separate variant:
//! callers express per-candidate ambiguity with [`MatchClass::Possible`],
//! which yields the same `(0,Some(n))` withholding. (3) An empty
//! `Complete` set refuses (`MissingProvenance`) instead of bounding;
//! absence of attribution is not absence of use, and an empty claim of
//! completeness carries no provenance. (4) Arithmetic refuses overflow
//! (`ArithmeticOverflow`) instead of saturating; callers admit limits.
//!
//! Classification is O(candidates); admission and combination
//! duplicate checks are O(candidates^2) pairwise scans. Extra storage is
//! O(1) beyond the retained candidate vector; no time, byte-retention or
//! cleanup bound is claimed.
use crate::{
    domain::{Epoch, PhysicalSiteId},
    quantity::{Count, CountBounds, Events},
    ContractError,
};
use std::fmt;

/// Whether the candidate list for one site is itself complete.
///
/// `Unknown` means candidates may be missing; it proves no lower bound
/// and no known upper, regardless of the observed count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateCoverage<C> {
    Complete(Vec<C>),
    Unknown,
}

/// The caller-supplied classification of one candidate alternative.
///
/// Meanings stay application supplied; no domain taxonomy enters this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchClass {
    Definite,
    Possible,
    Excluded,
}

/// One physical observation: a site, its conserved count and its candidates.
pub struct SiteCount<C> {
    epoch: Epoch,
    site: PhysicalSiteId,
    count: Count<Events>,
    candidates: CandidateCoverage<C>,
}

impl<C: Eq> SiteCount<C> {
    /// Retain one physical count with its candidate coverage.
    ///
    /// Refuses duplicate candidates (`DuplicateKey`), over-limit admission
    /// (`CapacityExceeded`) and an empty `Complete` set
    /// (`MissingProvenance`). Unknown coverage admits any count, including
    /// zero, without bounding it.
    pub fn new(
        epoch: Epoch,
        site: PhysicalSiteId,
        count: Count<Events>,
        candidates: CandidateCoverage<C>,
        max_candidates: usize,
    ) -> Result<Self, ContractError> {
        if let CandidateCoverage::Complete(list) = &candidates {
            if list.is_empty() {
                return Err(ContractError::MissingProvenance);
            }
            if list.len() > max_candidates {
                return Err(ContractError::CapacityExceeded);
            }
            for (index, candidate) in list.iter().enumerate() {
                if list[..index].contains(candidate) {
                    return Err(ContractError::DuplicateKey);
                }
            }
        }
        Ok(Self { epoch, site, count, candidates })
    }
    /// The retained epoch.
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// The retained physical-site label.
    pub fn site(&self) -> PhysicalSiteId {
        self.site
    }
    /// The conserved count, observed once.
    pub fn count(&self) -> Count<Events> {
        self.count
    }
    /// The retained candidate coverage.
    pub fn candidates(&self) -> &CandidateCoverage<C> {
        &self.candidates
    }
}

/// Bound one physical count by its alternative classifications.
///
/// Requires exactly one class per candidate (`ConservationMismatch`
/// otherwise). All `Definite` gives `[n,n]`; all `Excluded` gives
/// `[0,0]`; any other combination gives `[0,n]`. `Unknown` coverage
/// yields `[0,None]` and requires an empty class slice. The count is
/// never replicated into each alias.
pub fn classify_alternatives<C>(
    site: &SiteCount<C>,
    classes: &[MatchClass],
) -> Result<CountBounds<Events>, ContractError> {
    let n = site.count;
    match &site.candidates {
        CandidateCoverage::Unknown => {
            if !classes.is_empty() {
                return Err(ContractError::ConservationMismatch);
            }
            CountBounds::new(Count::new(0), None)
        }
        CandidateCoverage::Complete(list) => {
            if classes.len() != list.len() {
                return Err(ContractError::ConservationMismatch);
            }
            let all_definite = classes.iter().all(|c| matches!(c, MatchClass::Definite));
            let all_excluded = classes.iter().all(|c| matches!(c, MatchClass::Excluded));
            if all_definite {
                CountBounds::new(n, Some(n))
            } else if all_excluded {
                CountBounds::new(Count::new(0), Some(Count::new(0)))
            } else {
                CountBounds::new(Count::new(0), Some(n))
            }
        }
    }
}

/// Add bounds across distinct sites in one epoch.
///
/// Requires pairwise-distinct sites (`DuplicateKey`), one epoch
/// (`DomainMismatch`) and one bound per site (`ConservationMismatch`).
/// Lowers add; known uppers add with checked arithmetic; one unknown
/// upper makes the combined upper unknown. Empty input yields `[0,Some(0)]`.
pub fn combine_disjoint_sites<C>(
    sites: &[SiteCount<C>],
    bounds: &[CountBounds<Events>],
) -> Result<CountBounds<Events>, ContractError> {
    if sites.len() != bounds.len() {
        return Err(ContractError::ConservationMismatch);
    }
    for (index, site) in sites.iter().enumerate() {
        if index > 0 && sites[index - 1].epoch != site.epoch {
            return Err(ContractError::DomainMismatch);
        }
        if sites[..index].iter().any(|prior| prior.site == site.site) {
            return Err(ContractError::DuplicateKey);
        }
    }
    let mut lower = Count::new(0);
    let mut upper = Some(Count::new(0));
    for bound in bounds {
        lower = lower.checked_add(bound.lower())?;
        upper = match (upper, bound.upper()) {
            (Some(a), Some(b)) => Some(a.checked_add(b)?),
            _ => None,
        };
    }
    CountBounds::new(lower, upper)
}

impl<C: Clone> Clone for SiteCount<C> {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch.clone(),
            site: self.site,
            count: self.count,
            candidates: self.candidates.clone(),
        }
    }
}
impl<C: PartialEq> PartialEq for SiteCount<C> {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch
            && self.site == other.site
            && self.count == other.count
            && self.candidates == other.candidates
    }
}
impl<C: Eq> Eq for SiteCount<C> {}
impl<C> fmt::Debug for SiteCount<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteCount")
            .field("epoch", &self.epoch)
            .field("site", &self.site)
            .field("count", &self.count)
            .field("candidates", &"<redacted>")
            .finish()
    }
}
