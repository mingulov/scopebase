// SPDX-License-Identifier: Apache-2.0
//! TT06 focused 512-case property run: fixed regression seeds drive the
//! catalog-load state model. No property crate is used (see
//! docs/issues/qualification/dependency-choice.md); the schedule above is
//! deterministic and offline-resolvable.

use scopebase_catalog_model::{run_suite, ModelConfig};

/// Four fixed seeds x 128 cases: every directed invariant must hold and no
/// input may panic or produce a nondeterministic verdict.
#[test]
fn focused_512_case_run_passes() {
    for seed in [20261022u64, 7, 99, 0xC0FFEE] {
        let outcome = run_suite(&ModelConfig::new(seed, 128));
        assert!(outcome.setup_ok, "seed {seed}: setup must stay valid");
        assert_eq!(outcome.cases_run, 128, "seed {seed}: all cases must run");
        assert!(
            outcome.failures.is_empty(),
            "seed {seed}: unexpected failures: {:?}",
            &outcome.failures[..outcome.failures.len().min(3)]
        );
    }
}

/// Bad control: the mutant inverts I2 and must fail its semantic assertion
/// after valid setup, never crash setup.
#[test]
fn mutant_is_a_failing_bad_control() {
    let outcome = run_suite(&ModelConfig::mutant(20261022, 64));
    assert!(outcome.setup_ok, "mutant setup must stay valid");
    assert!(!outcome.failures.is_empty(), "mutant must fail its assertion");
}
