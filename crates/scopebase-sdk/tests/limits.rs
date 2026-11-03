// SPDX-License-Identifier: Apache-2.0
//! SDK02 limits tests: zero/overflow refusal per independent field, error
//! rendering and the [`Limits::validate`] contract. Every field is faulted
//! alone so one unit's check cannot mask another's.

use scopebase_sdk::limits::{LimitField, Limits, LimitsError};
use std::time::Duration;

/// A fully valid baseline: every field is the smallest accepted value except
/// the byte budgets, which carry headroom for later suites.
fn valid_limits() -> Limits {
    Limits {
        input_bytes: 1,
        retained_bytes: 1024,
        work_items: 1,
        live_owners: 1,
        diagnostic_count: 4,
        diagnostic_bytes: 65_536,
        wait: Duration::from_millis(1),
    }
}

#[test]
fn limits_zero_overflow_and_independent_units() {
    // Baseline validates.
    assert_eq!(valid_limits().validate(), Ok(()));

    // Each field faulted alone reports its own Zero variant; sibling values
    // stay valid so every unit is checked independently.
    let mut zero = valid_limits();
    zero.input_bytes = 0;
    assert_eq!(
        zero.validate(),
        Err(LimitsError::Zero(LimitField::InputBytes))
    );

    let mut zero = valid_limits();
    zero.retained_bytes = 0;
    assert_eq!(
        zero.validate(),
        Err(LimitsError::Zero(LimitField::RetainedBytes))
    );

    let mut zero = valid_limits();
    zero.work_items = 0;
    assert_eq!(
        zero.validate(),
        Err(LimitsError::Zero(LimitField::WorkItems))
    );

    let mut zero = valid_limits();
    zero.live_owners = 0;
    assert_eq!(
        zero.validate(),
        Err(LimitsError::Zero(LimitField::LiveOwners))
    );

    let mut zero = valid_limits();
    zero.diagnostic_count = 0;
    assert_eq!(
        zero.validate(),
        Err(LimitsError::Zero(LimitField::DiagnosticCount))
    );

    let mut zero = valid_limits();
    zero.diagnostic_bytes = 0;
    assert_eq!(
        zero.validate(),
        Err(LimitsError::Zero(LimitField::DiagnosticBytes))
    );

    let mut zero = valid_limits();
    zero.wait = Duration::ZERO;
    assert_eq!(zero.validate(), Err(LimitsError::Zero(LimitField::Wait)));

    // Deterministic order: the first field in declaration order wins when
    // several are zero, so callers see a stable refusal.
    let all_zero = Limits {
        input_bytes: 0,
        retained_bytes: 0,
        work_items: 0,
        live_owners: 0,
        diagnostic_count: 0,
        diagnostic_bytes: 0,
        wait: Duration::ZERO,
    };
    assert_eq!(
        all_zero.validate(),
        Err(LimitsError::Zero(LimitField::InputBytes))
    );

    // Overflow: a byte/count value must be representable as usize on the
    // build target. Probe values track `usize::try_from` exactly on any
    // target width, so this pins overflow refusal on 32-bit targets and
    // documents full-range acceptance on 64-bit targets.
    for probe in [1u64, u64::from(u32::MAX), u64::from(u32::MAX) + 1, u64::MAX] {
        let fits = usize::try_from(probe).is_ok();
        for field in [
            LimitField::InputBytes,
            LimitField::RetainedBytes,
            LimitField::WorkItems,
            LimitField::DiagnosticBytes,
        ] {
            let mut limits = valid_limits();
            match field {
                LimitField::InputBytes => limits.input_bytes = probe,
                LimitField::RetainedBytes => limits.retained_bytes = probe,
                LimitField::WorkItems => limits.work_items = probe,
                LimitField::DiagnosticBytes => limits.diagnostic_bytes = probe,
                _ => unreachable!("u64 probe field"),
            }
            if fits {
                assert_eq!(limits.validate(), Ok(()), "{field:?} {probe}");
            } else {
                assert_eq!(
                    limits.validate(),
                    Err(LimitsError::OutOfRange(field)),
                    "{field:?} {probe}"
                );
            }
        }
    }

    // The u32 count fields are representable on every supported target, so
    // their maxima always validate.
    let mut limits = valid_limits();
    limits.live_owners = u32::MAX;
    limits.diagnostic_count = u32::MAX;
    assert_eq!(limits.validate(), Ok(()));

    // A nonzero wait of any magnitude validates; the wait is an observation
    // deadline, not a resource bound with an overflow ceiling.
    let mut limits = valid_limits();
    limits.wait = Duration::from_nanos(1);
    assert_eq!(limits.validate(), Ok(()));
    limits.wait = Duration::MAX;
    assert_eq!(limits.validate(), Ok(()));
}

#[test]
fn limits_errors_render_without_payloads() {
    // Structured variants satisfy the standard error interface and carry no
    // caller values beyond the field tag.
    for error in [
        LimitsError::Zero(LimitField::InputBytes),
        LimitsError::Zero(LimitField::RetainedBytes),
        LimitsError::Zero(LimitField::WorkItems),
        LimitsError::Zero(LimitField::LiveOwners),
        LimitsError::Zero(LimitField::DiagnosticCount),
        LimitsError::Zero(LimitField::DiagnosticBytes),
        LimitsError::Zero(LimitField::Wait),
        LimitsError::OutOfRange(LimitField::InputBytes),
        LimitsError::OutOfRange(LimitField::DiagnosticBytes),
    ] {
        assert!(!error.to_string().is_empty());
        assert!(
            format!("{error:?}").contains("Zero") || format!("{error:?}").contains("OutOfRange")
        );
        let _: &dyn std::error::Error = &error;
    }
    // Validation borrows only: calling it cannot mutate the limits.
    let limits = valid_limits();
    let snapshot = limits.clone();
    let _ = limits.validate();
    assert_eq!(limits, snapshot);
}

#[test]
fn bad_zero_limit_accepted_would_admit_unbounded_context() {
    // A mutant that skips validation would admit a zero-budget context; the
    // honest validator refuses every zero field before any context exists.
    let zero = Limits {
        input_bytes: 0,
        retained_bytes: 0,
        work_items: 0,
        live_owners: 0,
        diagnostic_count: 0,
        diagnostic_bytes: 0,
        wait: Duration::ZERO,
    };
    assert!(zero.validate().is_err(), "zero limits must be refused");
    assert!(
        valid_limits().validate().is_ok(),
        "nonzero limits must validate"
    );
}

#[test]
fn max_diagnostic_bytes_validates_per_pointer_width() {
    // S217: documents the 32-bit boundary the diagnostic budget
    // test must respect — `u64::MAX` validates on 64-bit but
    // refuses with `OutOfRange` on 32-bit, where `usize` cannot
    // hold it. Each arm runs only on its own target.
    let mut limits = valid_limits();
    limits.diagnostic_bytes = u64::MAX;
    #[cfg(target_pointer_width = "64")]
    assert_eq!(limits.validate(), Ok(()));
    #[cfg(target_pointer_width = "32")]
    assert_eq!(
        limits.validate(),
        Err(LimitsError::OutOfRange(LimitField::DiagnosticBytes))
    );
}
