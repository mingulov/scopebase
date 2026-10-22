// SPDX-License-Identifier: Apache-2.0
//! SDK01 profile and admission tests: constructor caps, duplicate refusal,
//! the five capability states, the Ready/Incomplete/Refused table, an
//! independent oracle cross-check and bad controls.

use scopebase_sdk::profile::{
    Admission, CapabilityObservation, CapabilityRequirement, CapabilityState, Effect, Profile,
    ProfileError,
};

fn req(id: &'static str, required: bool) -> CapabilityRequirement {
    CapabilityRequirement { id, required }
}

fn obs(id: &'static str, state: CapabilityState) -> CapabilityObservation {
    CapabilityObservation {
        id,
        state,
        source: "test-fixture",
    }
}

/// Boundary tests need many distinct static ids; leaking boxed test strings
/// keeps the `&'static str` API shape without touching production code.
fn static_id(prefix: &str, index: usize) -> &'static str {
    Box::leak(format!("{prefix}-{index:03}").into_boxed_str())
}

fn profile(
    id: &'static str,
    requirements: Vec<CapabilityRequirement>,
    effects: Vec<Effect>,
) -> Profile {
    Profile::new(id, requirements, effects).expect("valid test profile")
}

#[test]
fn profile_rejects_duplicates_and_oversize() {
    // 64 requirements fit; the 65th is refused before any copying.
    let sixty_four: Vec<CapabilityRequirement> =
        (0..64).map(|i| req(static_id("cap", i), true)).collect();
    assert!(Profile::new("fits", sixty_four, vec![]).is_ok());
    let sixty_five: Vec<CapabilityRequirement> =
        (0..65).map(|i| req(static_id("cap", i), true)).collect();
    assert_eq!(
        Profile::new("overflow", sixty_five, vec![]),
        Err(ProfileError::Capacity)
    );

    // Duplicate requirement ids are refused, required or optional alike.
    assert_eq!(
        Profile::new("dup", vec![req("a", true), req("a", false)], vec![]),
        Err(ProfileError::DuplicateId)
    );
    assert_eq!(
        Profile::new("dup", vec![req("a", false), req("a", false)], vec![]),
        Err(ProfileError::DuplicateId)
    );

    // Duplicate effect entries are refused.
    assert_eq!(
        Profile::new(
            "dup-effect",
            vec![req("a", true)],
            vec![Effect::ReadOwnedFiles, Effect::ReadOwnedFiles],
        ),
        Err(ProfileError::DuplicateEffect)
    );

    // Empty and oversize identifiers are refused, for the profile and for
    // each requirement. Oversize means longer than 64 bytes, not 64.
    assert_eq!(
        Profile::new("", vec![req("a", true)], vec![]),
        Err(ProfileError::InvalidId)
    );
    assert_eq!(
        Profile::new("empty-req", vec![req("", true)], vec![]),
        Err(ProfileError::InvalidId)
    );
    let long_profile: &'static str = Box::leak("p".repeat(65).into_boxed_str());
    assert_eq!(
        Profile::new(long_profile, vec![req("a", true)], vec![]),
        Err(ProfileError::InvalidId)
    );
    let long_req: &'static str = Box::leak("r".repeat(65).into_boxed_str());
    assert_eq!(
        Profile::new("long-req", vec![req(long_req, true)], vec![]),
        Err(ProfileError::InvalidId)
    );
}

#[test]
fn profile_id_and_effect_boundaries_are_exact() {
    // Exactly 64 bytes and exactly five distinct effects are admitted.
    let id64: &'static str = Box::leak("i".repeat(64).into_boxed_str());
    let req64: &'static str = Box::leak("q".repeat(64).into_boxed_str());
    let all_effects = vec![
        Effect::ReadOwnedFiles,
        Effect::WriteOwnedFixtures,
        Effect::PrivateReadOnlyCalibration,
        Effect::SpawnOwnedChild,
        Effect::LoadBpf,
    ];
    let exact = Profile::new(id64, vec![req(req64, true)], all_effects)
        .expect("64-byte ids and five effects fit");
    assert_eq!(exact.id(), id64);
    for effect in [
        Effect::ReadOwnedFiles,
        Effect::WriteOwnedFixtures,
        Effect::PrivateReadOnlyCalibration,
        Effect::SpawnOwnedChild,
        Effect::LoadBpf,
    ] {
        assert!(exact.permits(effect), "declared effect must be permitted");
    }

    // A sixth effect entry exceeds the five-effect bound however it reads.
    // The closed five-variant enum forces a repeat, and the length bound is
    // checked first, so this pins Capacity rather than DuplicateEffect.
    let six = vec![
        Effect::ReadOwnedFiles,
        Effect::WriteOwnedFixtures,
        Effect::PrivateReadOnlyCalibration,
        Effect::SpawnOwnedChild,
        Effect::LoadBpf,
        Effect::LoadBpf,
    ];
    assert_eq!(
        Profile::new("six", vec![req("a", true)], six),
        Err(ProfileError::Capacity)
    );
}

#[test]
fn permits_gates_declared_effects_only() {
    let denied = profile("p", vec![req("a", true)], vec![]);
    for effect in [
        Effect::ReadOwnedFiles,
        Effect::WriteOwnedFixtures,
        Effect::PrivateReadOnlyCalibration,
        Effect::SpawnOwnedChild,
        Effect::LoadBpf,
    ] {
        assert!(!denied.permits(effect), "undeclared effect must not permit");
    }

    let partial = profile(
        "p",
        vec![req("a", true)],
        vec![Effect::ReadOwnedFiles, Effect::LoadBpf],
    );
    assert!(partial.permits(Effect::ReadOwnedFiles));
    assert!(partial.permits(Effect::LoadBpf));
    assert!(!partial.permits(Effect::WriteOwnedFixtures));
    assert!(!partial.permits(Effect::PrivateReadOnlyCalibration));
    assert!(!partial.permits(Effect::SpawnOwnedChild));
}

#[test]
fn required_unknown_is_incomplete() {
    // A required Unknown observation keeps admission incomplete.
    let p = profile("p", vec![req("net", true)], vec![]);
    assert_eq!(
        p.admission(&[obs("net", CapabilityState::Unknown)]),
        Admission::Incomplete
    );

    // A required capability with no observation at all is also incomplete.
    assert_eq!(p.admission(&[]), Admission::Incomplete);

    // One supported requirement cannot complete a missing sibling.
    let two = profile("p", vec![req("a", true), req("b", true)], vec![]);
    assert_eq!(
        two.admission(&[obs("a", CapabilityState::Supported)]),
        Admission::Incomplete
    );
    assert_eq!(
        two.admission(&[
            obs("a", CapabilityState::Supported),
            obs("b", CapabilityState::Unknown),
        ]),
        Admission::Incomplete
    );

    // Positive twin: every required capability supported admits Ready.
    assert_eq!(
        two.admission(&[
            obs("a", CapabilityState::Supported),
            obs("b", CapabilityState::Supported),
        ]),
        Admission::Ready
    );
}

#[test]
fn required_denied_is_refused() {
    // Each explicit required failure state refuses admission.
    for state in [
        CapabilityState::Denied,
        CapabilityState::Unsupported,
        CapabilityState::Incompatible,
    ] {
        let p = profile("p", vec![req("disk", true)], vec![]);
        assert_eq!(
            p.admission(&[obs("disk", state)]),
            Admission::Refused,
            "required {state:?} must refuse"
        );
    }

    // Refusal outranks incompleteness: a denied requirement refuses even
    // when a sibling is missing or unknown.
    let two = profile("p", vec![req("a", true), req("b", true)], vec![]);
    assert_eq!(
        two.admission(&[obs("a", CapabilityState::Denied)]),
        Admission::Refused
    );
    assert_eq!(
        two.admission(&[
            obs("a", CapabilityState::Denied),
            obs("b", CapabilityState::Unknown),
        ]),
        Admission::Refused
    );
    assert_eq!(
        two.admission(&[
            obs("a", CapabilityState::Supported),
            obs("b", CapabilityState::Incompatible),
        ]),
        Admission::Refused
    );
}

#[test]
fn all_five_states_map_through_the_table() {
    // The full per-state table for one required capability.
    let table = [
        (CapabilityState::Supported, Admission::Ready),
        (CapabilityState::Unsupported, Admission::Refused),
        (CapabilityState::Denied, Admission::Refused),
        (CapabilityState::Unknown, Admission::Incomplete),
        (CapabilityState::Incompatible, Admission::Refused),
    ];
    assert_eq!(table.len(), 5, "every CapabilityState must be pinned");
    for (state, expected) in table {
        let p = profile("p", vec![req("only", true)], vec![]);
        assert_eq!(
            p.admission(&[obs("only", state)]),
            expected,
            "required {state:?} must admit {expected:?}"
        );
    }
}

#[test]
fn optional_denied_stays_visible() {
    // An optional denial never refuses and never completes on its own, but
    // the observation itself stays in the caller's report input.
    for state in [
        CapabilityState::Denied,
        CapabilityState::Unsupported,
        CapabilityState::Unknown,
        CapabilityState::Incompatible,
    ] {
        let p = profile("p", vec![req("opt", false)], vec![]);
        let reports = [obs("opt", state)];
        assert_eq!(
            p.admission(&reports),
            Admission::Ready,
            "optional {state:?} must stay Ready"
        );
        assert_eq!(reports.len(), 1, "optional failure stays visible");
        assert_eq!(reports[0].state, state);
        assert_eq!(reports[0].id, "opt");
    }

    // Optional failures stay visible alongside satisfied requirements.
    let mixed = profile("p", vec![req("need", true), req("want", false)], vec![]);
    let reports = [
        obs("need", CapabilityState::Supported),
        obs("want", CapabilityState::Denied),
    ];
    assert_eq!(mixed.admission(&reports), Admission::Ready);
    assert_eq!(reports.len(), 2);

    // A missing optional capability is fine; a missing required one is not.
    assert_eq!(
        mixed.admission(&[obs("need", CapabilityState::Supported)]),
        Admission::Ready
    );
    assert_eq!(
        mixed.admission(&[obs("want", CapabilityState::Supported)]),
        Admission::Incomplete
    );
}

#[test]
fn profile_with_no_requirements_is_ready_without_observations() {
    // With no prerequisites the capability table is vacuously Ready. Binding
    // completeness (zero bindings refuse Ready) arrives with SDK02 AppContext
    // and is deliberately not part of this profile-level admission.
    let p = profile("empty", vec![], vec![]);
    assert_eq!(p.admission(&[]), Admission::Ready);
}

#[test]
fn observations_for_undeclared_ids_are_ignored() {
    // Stray reports name no prerequisite, so even a stray denial cannot
    // refuse or complete this profile.
    let p = profile("p", vec![req("a", true)], vec![]);
    assert_eq!(
        p.admission(&[obs("stray", CapabilityState::Denied)]),
        Admission::Incomplete
    );
    assert_eq!(
        p.admission(&[
            obs("a", CapabilityState::Supported),
            obs("stray", CapabilityState::Denied),
        ]),
        Admission::Ready
    );
}

#[test]
fn conflicting_duplicate_observations_resolve_toward_refusal() {
    // Every observation for a declared required id folds through the table,
    // so a denial is never masked by a sibling Supported report.
    let p = profile("p", vec![req("a", true)], vec![]);
    assert_eq!(
        p.admission(&[
            obs("a", CapabilityState::Supported),
            obs("a", CapabilityState::Denied),
        ]),
        Admission::Refused
    );
    assert_eq!(
        p.admission(&[
            obs("a", CapabilityState::Denied),
            obs("a", CapabilityState::Supported),
        ]),
        Admission::Refused
    );
    assert_eq!(
        p.admission(&[
            obs("a", CapabilityState::Supported),
            obs("a", CapabilityState::Supported),
        ]),
        Admission::Ready
    );
}

#[test]
fn errors_render_without_payloads() {
    // Errors stay structured, carry no identifier payloads and satisfy the
    // standard error interface without logging.
    for (error, name) in [
        (ProfileError::InvalidId, "InvalidId"),
        (ProfileError::DuplicateId, "DuplicateId"),
        (ProfileError::DuplicateEffect, "DuplicateEffect"),
        (ProfileError::Capacity, "Capacity"),
    ] {
        assert!(!error.to_string().is_empty());
        assert!(format!("{error:?}").contains(name));
        let _: &dyn std::error::Error = &error;
    }
}

// --- Independent oracle: same spec sentence, separate logic and types. ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelState {
    Supported,
    Unsupported,
    Denied,
    Unknown,
    Incompatible,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Ready,
    Incomplete,
    Refused,
}

/// Direct transcription of the admission sentence: a required explicit
/// unsupported/denied/incompatible observation refuses; a required missing or
/// unknown observation leaves the profile incomplete; anything else is ready.
/// Optional capabilities never affect the verdict. Uses no production code.
fn oracle(caps: &[(bool, Option<ModelState>)]) -> Verdict {
    let mut incomplete = false;
    for (required, observed) in caps {
        if !required {
            continue;
        }
        match observed {
            Some(ModelState::Unsupported | ModelState::Denied | ModelState::Incompatible) => {
                return Verdict::Refused
            }
            Some(ModelState::Unknown) | None => incomplete = true,
            Some(ModelState::Supported) => {}
        }
    }
    if incomplete {
        Verdict::Incomplete
    } else {
        Verdict::Ready
    }
}

fn to_production(state: ModelState) -> CapabilityState {
    match state {
        ModelState::Supported => CapabilityState::Supported,
        ModelState::Unsupported => CapabilityState::Unsupported,
        ModelState::Denied => CapabilityState::Denied,
        ModelState::Unknown => CapabilityState::Unknown,
        ModelState::Incompatible => CapabilityState::Incompatible,
    }
}

fn to_verdict(admission: Admission) -> Verdict {
    match admission {
        Admission::Ready => Verdict::Ready,
        Admission::Incomplete => Verdict::Incomplete,
        Admission::Refused => Verdict::Refused,
    }
}

#[test]
fn admission_matches_independent_oracle() {
    // Exhaustive cross-check: two required plus one optional capability,
    // each missing or in any of the five states (6^3 = 216 populations).
    // Every population also carries one stray denial for an undeclared id,
    // pinning that stray reports never move the verdict.
    let options: [Option<ModelState>; 6] = [
        None,
        Some(ModelState::Supported),
        Some(ModelState::Unsupported),
        Some(ModelState::Denied),
        Some(ModelState::Unknown),
        Some(ModelState::Incompatible),
    ];
    let mut checked = 0;
    for first in options {
        for second in options {
            for third in options {
                let spec = [(true, first), (true, second), (false, third)];
                let expected = oracle(&spec);
                let p = profile(
                    "oracle",
                    vec![req("a", true), req("b", true), req("c", false)],
                    vec![],
                );
                let mut reports = vec![obs("stray", CapabilityState::Denied)];
                for (id, (_, observed)) in ["a", "b", "c"].into_iter().zip(spec) {
                    if let Some(state) = observed {
                        reports.push(obs(id, to_production(state)));
                    }
                }
                assert_eq!(
                    to_verdict(p.admission(&reports)),
                    expected,
                    "oracle mismatch for {spec:?}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 216);
}

// --- Bad controls: each corrupted twin must move the verdict. ---

#[test]
fn bad_unknown_upgraded_to_supported_changes_verdict() {
    // A mutant that reads required Unknown as Supported would report Ready
    // where the oracle demands Incomplete; the control fails unless the two
    // verdicts differ.
    let p = profile("p", vec![req("a", true)], vec![]);
    let honest = p.admission(&[obs("a", CapabilityState::Unknown)]);
    let mutant = p.admission(&[obs("a", CapabilityState::Supported)]);
    assert_eq!(honest, Admission::Incomplete);
    assert_eq!(mutant, Admission::Ready);
    assert_ne!(honest, mutant, "unknown-as-supported must be detectable");
}

#[test]
fn bad_dropped_required_denial_changes_verdict() {
    // Dropping a required denial must move Refused to Incomplete, never
    // stay Refused and never become Ready.
    let p = profile("p", vec![req("a", true)], vec![]);
    let honest = p.admission(&[obs("a", CapabilityState::Denied)]);
    let mutant = p.admission(&[]);
    assert_eq!(honest, Admission::Refused);
    assert_eq!(mutant, Admission::Incomplete);
    assert_ne!(honest, mutant, "dropped denial must be detectable");
}

#[test]
fn bad_optional_denial_promoted_to_refusal_is_wrong() {
    // A mutant that lets optional failures refuse would report Refused;
    // the table requires Ready with the failure retained.
    let p = profile("p", vec![req("a", false)], vec![]);
    let reports = [obs("a", CapabilityState::Denied)];
    assert_eq!(p.admission(&reports), Admission::Ready);
    assert_ne!(
        p.admission(&reports),
        Admission::Refused,
        "optional denial must never refuse"
    );
}

#[test]
fn bad_removed_constructor_checks_stay_refused() {
    // Each constructor mutant below must keep returning its exact error.
    assert_eq!(
        Profile::new("dup", vec![req("a", true), req("a", true)], vec![]),
        Err(ProfileError::DuplicateId)
    );
    let long: &'static str = Box::leak("z".repeat(65).into_boxed_str());
    assert_eq!(
        Profile::new(long, vec![], vec![]),
        Err(ProfileError::InvalidId)
    );
    let many: Vec<CapabilityRequirement> = (0..65).map(|i| req(static_id("m", i), false)).collect();
    assert_eq!(
        Profile::new("many", many, vec![]),
        Err(ProfileError::Capacity)
    );
}
