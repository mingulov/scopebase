// SPDX-License-Identifier: Apache-2.0
//! TT06 first state model: bounded catalog-load transition checks.
//!
//! Drives the accepted TT01 `CaseCatalog::load` over a deterministic,
//! seeded mutation schedule. The model never modifies the testkit; it
//! asserts independent invariants over load verdicts:
//!
//! * I1: the minimal valid catalog loads and its exact (id, version)
//!   pair resolves through `CaseCatalog::case`.
//! * I2: a duplicated (id, version) pair is rejected with `DuplicateId`.
//! * I3: an unknown JSON field is rejected with `UnknownField`.
//! * I4: truncation is rejected (any error kind), never accepted.
//! * I5: no input panics, and every verdict is deterministic across runs.
//!
//! Generic byte mutations assert only I5 plus the I1 repeat control,
//! because a flipped byte may still decode to a different valid catalog.
//! The mutant configuration inverts I2 (asserts duplicates are accepted)
//! and must fail its semantic assertion after valid setup.

use scopebase_testkit::{CaseCatalog, CaseId, CatalogErrorKind, CatalogLimits};

/// Minimal fully-consistent catalog accepted by the strict loader.
pub const MINIMAL_CATALOG: &str = r#"{"schema_version": 1, "catalog_revision": 1, "tasks": ["TT06"], "obligations": [{"kind": "regression_family", "id": "H99", "description": "TT06 model fixture", "owners": ["TT06"]}], "families": [{"id": "H99", "short_contract": "TT06 model fixture", "obligations": [{"kind": "regression_family", "id": "H99"}]}], "cells": [{"id": "model-cell", "tier": "T0", "description": "TT06 model cell", "binding": "LOGICAL_ONLY"}], "cases": [{"id": "H99.model-case", "family": "H99", "version": 1, "implementation_status": "UNIMPLEMENTED", "owners": ["TT06"], "obligations": [{"kind": "regression_family", "id": "H99"}], "required_cells": ["model-cell"], "registration": null}], "profiles": [{"id": "model-fixture-v1", "definition_state": "DRAFT", "requires_profiles": [], "requires_extensions": [], "required_cases": [{"case_id": "H99.model-case", "case_version": 1, "when_extensions": []}], "open_owners": ["TT06"]}], "extensions": []}"#;

/// Deterministic xorshift64* generator; std-only, no property crate needed.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Zero seeds still advance; mix in a nonzero constant.
        Self(seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0x2545F4914F6CDD1D) | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "rng bound must be positive");
        (self.next_u64() % bound as u64) as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mutation {
    FlipByte,
    DropByte,
    InsertByte,
    Truncate,
    DuplicateCase,
    UnknownField,
    BadVersion,
    ValidRepeat,
}

impl Mutation {
    fn schedule(rng: &mut Rng, index: usize) -> Self {
        // Directed mutations recur deterministically; every 64th case repeats
        // the valid base as an I1 control.
        if index % 64 == 63 {
            return Mutation::ValidRepeat;
        }
        match index % 8 {
            0 => Mutation::DuplicateCase,
            1 => Mutation::UnknownField,
            2 => Mutation::Truncate,
            3 => Mutation::BadVersion,
            4 => Mutation::FlipByte,
            5 => Mutation::DropByte,
            6 => Mutation::InsertByte,
            _ => match rng.below(7) {
                0 => Mutation::FlipByte,
                1 => Mutation::DropByte,
                2 => Mutation::InsertByte,
                3 => Mutation::Truncate,
                4 => Mutation::DuplicateCase,
                5 => Mutation::UnknownField,
                _ => Mutation::BadVersion,
            },
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Mutation::FlipByte => "flip-byte",
            Mutation::DropByte => "drop-byte",
            Mutation::InsertByte => "insert-byte",
            Mutation::Truncate => "truncate",
            Mutation::DuplicateCase => "duplicate-case",
            Mutation::UnknownField => "unknown-field",
            Mutation::BadVersion => "bad-version",
            Mutation::ValidRepeat => "valid-repeat",
        }
    }
}

pub fn apply_mutation(base: &[u8], mutation: Mutation, rng: &mut Rng) -> Vec<u8> {
    let mut bytes = base.to_vec();
    match mutation {
        Mutation::ValidRepeat => {}
        Mutation::FlipByte => {
            let pos = rng.below(bytes.len());
            let xor = 1u8 << rng.below(8);
            bytes[pos] ^= xor;
        }
        Mutation::DropByte => {
            let pos = rng.below(bytes.len());
            bytes.remove(pos);
        }
        Mutation::InsertByte => {
            let pos = rng.below(bytes.len() + 1);
            bytes.insert(pos, rng.next_u64() as u8);
        }
        Mutation::Truncate => {
            let len = rng.below(bytes.len());
            bytes.truncate(len);
        }
        Mutation::DuplicateCase => {
            // Append a second copy of the single case object: the loader
            // must reject the duplicated (id, version) pair.
            let close = find_subslice(&bytes, b"], \"profiles\"").expect("fixture case array closes");
            let case_start = find_subslice(&bytes, b"\"cases\": [{").expect("fixture holds cases")
                + "\"cases\": [".len();
            let case_obj = bytes[case_start..close].to_vec();
            let mut dup = bytes[..close].to_vec();
            dup.extend_from_slice(b", ");
            dup.extend_from_slice(&case_obj);
            dup.extend_from_slice(&bytes[close..]);
            bytes = dup;
        }
        Mutation::UnknownField => {
            let marker = b"\"schema_version\": 1";
            let pos = find_subslice(&bytes, marker).expect("fixture holds schema_version")
                + marker.len();
            let mut out = bytes[..pos].to_vec();
            out.extend_from_slice(b", \"tt06_surprise\": true");
            out.extend_from_slice(&bytes[pos..]);
            bytes = out;
        }
        Mutation::BadVersion => {
            let marker = b"\"version\": 1";
            let pos = find_subslice(&bytes, marker).expect("fixture holds version");
            let mut out = bytes[..pos].to_vec();
            out.extend_from_slice(b"\"version\": 4294967296");
            out.extend_from_slice(&bytes[pos + marker.len()..]);
            bytes = out;
        }
    }
    bytes
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[derive(Clone, Debug)]
pub struct ModelConfig {
    pub seed: u64,
    pub cases: usize,
    pub mutant: bool,
}

impl ModelConfig {
    pub fn new(seed: u64, cases: usize) -> Self {
        Self { seed, cases, mutant: false }
    }
    pub fn mutant(seed: u64, cases: usize) -> Self {
        Self { seed, cases, mutant: true }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseFailure {
    pub index: usize,
    pub mutation: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct SuiteOutcome {
    pub setup_ok: bool,
    pub setup_detail: String,
    pub cases_run: usize,
    pub failures: Vec<CaseFailure>,
}

impl SuiteOutcome {
    pub fn passed(&self) -> bool {
        self.setup_ok && self.failures.is_empty()
    }
}

fn verdict_of(bytes: &[u8]) -> Result<bool, CatalogErrorKind> {
    match CaseCatalog::load(bytes, CatalogLimits::default()) {
        Ok(_) => Ok(true),
        Err(e) => Err(e.kind()),
    }
}

/// I1 setup: the minimal catalog loads and its exact pair resolves.
pub fn check_setup() -> Result<String, String> {
    let catalog = CaseCatalog::load(MINIMAL_CATALOG.as_bytes(), CatalogLimits::default())
        .map_err(|e| format!("minimal catalog rejected: {:?}", e.kind()))?;
    let id = CaseId::parse("H99.model-case").map_err(|_| "fixture id must parse".to_string())?;
    match catalog.case(&id, 1) {
        Some(spec) if spec.version() == 1 => Ok("setup: minimal catalog loads; exact pair resolves".into()),
        _ => Err("setup: exact (id, version) pair lookup failed".into()),
    }
}

pub fn run_suite(config: &ModelConfig) -> SuiteOutcome {
    let (setup_ok, setup_detail) = match check_setup() {
        Ok(detail) => (true, detail),
        Err(detail) => (false, detail),
    };
    let mut outcome = SuiteOutcome { setup_ok, setup_detail, cases_run: 0, failures: Vec::new() };
    if !setup_ok {
        return outcome;
    }
    let base = MINIMAL_CATALOG.as_bytes();
    for index in 0..config.cases {
        let mut rng = Rng::new(config.seed.wrapping_add(index as u64));
        let mutation = Mutation::schedule(&mut rng, index);
        let bytes = apply_mutation(base, mutation, &mut rng);
        // I5 determinism: the same bytes must produce the same verdict twice.
        // A panic here fails loudly by aborting the case: no-panic is asserted
        // by the harness observing completion of every scheduled case.
        let first = verdict_of(&bytes);
        let second = verdict_of(&bytes);
        if first != second {
            outcome.failures.push(CaseFailure {
                index,
                mutation: mutation.name(),
                detail: format!("nondeterministic verdict: {first:?} then {second:?}"),
            });
            continue;
        }
        let failure = check_invariants(mutation, &first, config.mutant);
        outcome.cases_run += 1;
        if let Some(detail) = failure {
            outcome.failures.push(CaseFailure { index, mutation: mutation.name(), detail });
        }
    }
    outcome
}

fn check_invariants(
    mutation: Mutation,
    verdict: &Result<bool, CatalogErrorKind>,
    mutant: bool,
) -> Option<String> {
    match mutation {
        Mutation::DuplicateCase if !mutant => match verdict {
            Err(CatalogErrorKind::DuplicateId) => None,
            other => Some(format!("I2: duplicate pair must reject DuplicateId, got {other:?}")),
        },
        // Bad control: the mutant asserts duplicates are accepted, so this
        // invariant must fail against the correct strict loader.
        Mutation::DuplicateCase => match verdict {
            Ok(true) => None,
            other => Some(format!("MUTANT-I2: duplicate pair unexpectedly rejected: {other:?}")),
        },
        Mutation::UnknownField => match verdict {
            Err(CatalogErrorKind::UnknownField) => None,
            other => Some(format!("I3: unknown field must reject UnknownField, got {other:?}")),
        },
        Mutation::Truncate => match verdict {
            Err(_) => None,
            Ok(_) => Some("I4: truncated input must be rejected, got accept".into()),
        },
        Mutation::ValidRepeat => match verdict {
            Ok(true) => None,
            other => Some(format!("I1-repeat: valid base must load, got {other:?}")),
        },
        // Generic byte damage carries only the I5 no-panic/determinism
        // invariant: the damaged bytes may still decode to another valid
        // catalog, so accept and reject are both legal verdicts.
        Mutation::FlipByte | Mutation::DropByte | Mutation::InsertByte | Mutation::BadVersion => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_loads_and_resolves_exact_pair() {
        assert!(check_setup().is_ok());
    }

    #[test]
    fn directed_mutations_hit_intended_kinds() {
        let base = MINIMAL_CATALOG.as_bytes();
        let mut rng = Rng::new(1);
        let dup = apply_mutation(base, Mutation::DuplicateCase, &mut rng);
        assert_eq!(verdict_of(&dup), Err(CatalogErrorKind::DuplicateId));
        let unk = apply_mutation(base, Mutation::UnknownField, &mut rng);
        assert_eq!(verdict_of(&unk), Err(CatalogErrorKind::UnknownField));
        let trunc = apply_mutation(base, Mutation::Truncate, &mut rng);
        assert!(verdict_of(&trunc).is_err());
    }

    #[test]
    fn mutant_fails_semantic_assertion_after_valid_setup() {
        let outcome = run_suite(&ModelConfig::mutant(20261022, 64));
        assert!(outcome.setup_ok, "mutant setup must stay valid");
        assert!(!outcome.failures.is_empty(), "mutant must fail its assertion");
        assert!(outcome.failures.iter().all(|f| f.mutation == "duplicate-case"));
    }

    #[test]
    fn suite_is_deterministic_across_runs() {
        let config = ModelConfig::new(99, 128);
        let first = run_suite(&config);
        let second = run_suite(&config);
        assert_eq!(first.cases_run, second.cases_run);
        assert_eq!(first.failures, second.failures);
    }
}
