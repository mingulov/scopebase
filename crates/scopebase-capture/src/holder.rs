// SPDX-License-Identifier: Apache-2.0
//! Paired report/export holders over versioned late corrections.
//!
//! NEW (CP11): reference-only; no donor lines copied. Two holders retain
//! independent copies of one corrected value. Applying a correction to one
//! holder never updates the other; [`HolderPair::divergence`] detects a
//! dropped update. Revisions are compared exactly; values only when the
//! caller supplies `PartialEq`.
use crate::{
    correction::{Correction, Revision, Versioned},
    ContractError,
};

/// Which copy of a corrected value a holder retains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderKind {
    /// The report copy.
    Report,
    /// The export copy.
    Export,
}

/// One named copy of a versioned value. A holder always retains a value:
/// a refused correction leaves the retained revision and value unchanged.
pub struct CorrectionHolder<T> {
    kind: HolderKind,
    current: Option<Versioned<T>>,
}

impl<T> CorrectionHolder<T> {
    /// Retain one initial versioned value under the given holder name.
    pub fn new(kind: HolderKind, initial: Versioned<T>) -> Self {
        Self {
            kind,
            current: Some(initial),
        }
    }

    /// Which copy this holder retains.
    pub fn kind(&self) -> HolderKind {
        self.kind
    }

    /// The exact retained revision.
    pub fn revision(&self) -> Revision {
        self.current
            .as_ref()
            .expect("CP11:holder always retains a value")
            .revision()
    }

    /// Borrow the whole retained value.
    pub fn value(&self) -> &T {
        self.current
            .as_ref()
            .expect("CP11:holder always retains a value")
            .value()
    }

    /// Apply one correction to this holder only. On refusal the retained
    /// value and revision are unchanged; the rejected replacement drops
    /// with ordinary caller-defined behavior. The replacement is retained
    /// before the displaced payload drops (S191), so even a panicking old
    /// `Drop` propagates with the holder still usable. This never touches
    /// the paired holder: the caller routes each correction explicitly.
    pub fn apply(&mut self, correction: Correction<T>) -> Result<(), ContractError> {
        let current = self
            .current
            .as_mut()
            .expect("CP11:holder always retains a value");
        let displaced = current.checked_replace(correction)?;
        drop(displaced);
        Ok(())
    }
}

/// A paired report/export copy with explicit agreement checks. The pair
/// performs no broadcast: each side advances only through its own apply.
pub struct HolderPair<T> {
    report: CorrectionHolder<T>,
    export: CorrectionHolder<T>,
}

impl<T> HolderPair<T> {
    /// Retain two independent starting copies. The two values are owned
    /// separately; sharing one allocation is the caller's choice to make.
    pub fn new(report: Versioned<T>, export: Versioned<T>) -> Self {
        Self {
            report: CorrectionHolder::new(HolderKind::Report, report),
            export: CorrectionHolder::new(HolderKind::Export, export),
        }
    }

    /// Borrow the report holder.
    pub fn report(&self) -> &CorrectionHolder<T> {
        &self.report
    }

    /// Borrow the export holder.
    pub fn export(&self) -> &CorrectionHolder<T> {
        &self.export
    }

    /// Apply one correction to the report holder only.
    pub fn apply_report(&mut self, correction: Correction<T>) -> Result<(), ContractError> {
        self.report.apply(correction)
    }

    /// Apply one correction to the export holder only.
    pub fn apply_export(&mut self, correction: Correction<T>) -> Result<(), ContractError> {
        self.export.apply(correction)
    }

    /// True when both holders retain equal revisions. Values are not
    /// compared: equal revisions with divergent routed replacements still
    /// agree here, and [`HolderPair::agree`] covers value equality.
    pub fn revisions_agree(&self) -> bool {
        self.report.revision() == self.export.revision()
    }

    /// True when revisions and values both agree.
    pub fn agree(&self) -> bool
    where
        T: PartialEq,
    {
        self.revisions_agree() && self.report.value() == self.export.value()
    }

    /// Diagnose a revision divergence, or `None` when revisions agree.
    pub fn divergence(&self) -> Option<HolderDivergence> {
        if self.revisions_agree() {
            None
        } else {
            Some(HolderDivergence {
                report: self.report.revision(),
                export: self.export.revision(),
            })
        }
    }
}

/// An observed revision divergence between the two holders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolderDivergence {
    report: Revision,
    export: Revision,
}

impl HolderDivergence {
    /// The report holder's retained revision.
    pub fn report(&self) -> Revision {
        self.report
    }

    /// The export holder's retained revision.
    pub fn export(&self) -> Revision {
        self.export
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CaptureId, Epoch, ProducerId};

    fn epoch() -> Epoch {
        Epoch::new(
            CaptureId::new([91; 16]).unwrap(),
            ProducerId::new([92; 16]).unwrap(),
            0,
        )
    }

    #[test]
    fn paired_apply_reaches_expected_revision_one() {
        let mut pair = HolderPair::new(
            Versioned::new(epoch(), 10u64),
            Versioned::new(epoch(), 10u64),
        );
        assert!(pair.revisions_agree());
        assert!(pair.agree());
        assert_eq!(pair.divergence(), None);
        pair.apply_report(Correction::new(epoch(), Revision::new(0), 7u64).unwrap())
            .unwrap();
        pair.apply_export(Correction::new(epoch(), Revision::new(0), 7u64).unwrap())
            .unwrap();
        assert_eq!(pair.report().revision(), Revision::new(1));
        assert_eq!(pair.export().revision(), Revision::new(1));
        assert_eq!(*pair.report().value(), 7);
        assert_eq!(*pair.export().value(), 7);
        assert!(pair.agree());
        assert_eq!(pair.divergence(), None);
    }

    #[test]
    fn dropped_export_update_is_detected() {
        let mut pair = HolderPair::new(
            Versioned::new(epoch(), 10u64),
            Versioned::new(epoch(), 10u64),
        );
        pair.apply_report(Correction::new(epoch(), Revision::new(0), 7u64).unwrap())
            .unwrap();
        assert!(!pair.revisions_agree());
        assert!(!pair.agree());
        let gap = pair.divergence().expect("CP11:dropped update diverges");
        assert_eq!(gap.report(), Revision::new(1));
        assert_eq!(gap.export(), Revision::new(0));
        assert_eq!(*pair.export().value(), 10);
    }

    #[test]
    fn same_revision_value_divergence_disagrees() {
        // S169: `agree` is the only API detecting same-revision value
        // divergence; degenerating it to `revisions_agree` must fail here.
        let mut pair = HolderPair::new(
            Versioned::new(epoch(), 10u64),
            Versioned::new(epoch(), 10u64),
        );
        pair.apply_report(Correction::new(epoch(), Revision::new(0), 7u64).unwrap())
            .unwrap();
        pair.apply_export(Correction::new(epoch(), Revision::new(0), 5u64).unwrap())
            .unwrap();
        assert_eq!(pair.report().revision(), Revision::new(1));
        assert_eq!(pair.export().revision(), Revision::new(1));
        assert!(pair.revisions_agree());
        assert!(!pair.agree());
        assert_eq!(pair.divergence(), None);
    }

    struct PanicOnDrop;

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("S191: old payload drop");
        }
    }

    #[test]
    fn panicking_old_drop_leaves_holder_usable() {
        // S191: the old payload's `Drop` runs after the replacement is
        // retained, so a catchable drop panic propagates without
        // poisoning the holder — accessors still behave.
        let mut holder =
            CorrectionHolder::new(HolderKind::Report, Versioned::new(epoch(), PanicOnDrop));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            holder.apply(Correction::new(epoch(), Revision::new(0), PanicOnDrop).unwrap())
        }));
        assert!(outcome.is_err(), "drop panic propagates to the caller");
        assert_eq!(holder.revision(), Revision::new(1));
        let _ = holder.value();
        std::mem::forget(holder);
    }

    #[test]
    fn stale_apply_preserves_value_and_revision() {
        let mut holder = CorrectionHolder::new(HolderKind::Report, Versioned::new(epoch(), 10u64));
        holder
            .apply(Correction::new(epoch(), Revision::new(0), 7u64).unwrap())
            .unwrap();
        let refused = holder
            .apply(Correction::new(epoch(), Revision::new(0), 5u64).unwrap())
            .expect_err("CP11:stale revision refuses");
        assert_eq!(refused, ContractError::StaleRevision);
        assert_eq!(holder.revision(), Revision::new(1));
        assert_eq!(*holder.value(), 7);
        assert_eq!(holder.kind(), HolderKind::Report);
    }
}
