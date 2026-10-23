// SPDX-License-Identifier: Apache-2.0
//! SDK02 context tests: declared-only observations with duplicate refusal,
//! exact component bindings, the binding-gated Ready/Refused/Incomplete
//! admission table, borrow-only reports and drop independence. Failed
//! operations leave the prior context unchanged.

use scopebase_sdk::context::{
    AppContext, ComponentBinding, ContextError, MAX_BINDINGS, MAX_BINDING_BACKEND_BYTES,
    MAX_BINDING_FEATURES, MAX_BINDING_FEATURE_BYTES, MAX_BINDING_PACKAGE_BYTES,
    MAX_BINDING_VERSION_BYTES, MAX_OBSERVATIONS,
};
use scopebase_sdk::limits::{LimitField, Limits, LimitsError};
use scopebase_sdk::profile::{
    Admission, CapabilityObservation, CapabilityRequirement, CapabilityState, Profile,
};
use std::time::Duration;

fn test_limits() -> Limits {
    Limits {
        input_bytes: 64,
        retained_bytes: 65_536,
        work_items: 64,
        live_owners: 8,
        diagnostic_count: 32,
        diagnostic_bytes: 65_536,
        wait: Duration::from_secs(2),
    }
}

fn req(id: &'static str, required: bool) -> CapabilityRequirement {
    CapabilityRequirement { id, required }
}

fn obs(id: &'static str, state: CapabilityState) -> CapabilityObservation {
    CapabilityObservation {
        id,
        state,
        source: "context-fixture",
    }
}

fn static_id(prefix: &str, index: usize) -> &'static str {
    Box::leak(format!("{prefix}-{index:03}").into_boxed_str())
}

fn binding(package: &str, version: &str) -> ComponentBinding {
    ComponentBinding {
        package: package.to_owned(),
        version: version.to_owned(),
        features: Vec::new(),
        backend: None,
        artifact_sha256: Some([0x42; 32]),
    }
}

fn ready_context() -> AppContext {
    // One required supported capability plus one digested binding: Ready.
    let profile =
        Profile::new("ready", vec![req("owned-files", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("owned-files", CapabilityState::Supported))
        .expect("declared observation");
    context
        .bind(binding("scopebase-capture", "0.1.0"))
        .expect("valid binding");
    assert_eq!(context.admission(), Admission::Ready);
    context
}

#[test]
fn binding_is_actual_component() {
    assert_eq!(MAX_OBSERVATIONS, 64);
    assert_eq!(MAX_BINDINGS, 8);
    assert_eq!(MAX_BINDING_PACKAGE_BYTES, 128);
    assert_eq!(MAX_BINDING_VERSION_BYTES, 64);
    assert_eq!(MAX_BINDING_BACKEND_BYTES, 64);
    assert_eq!(MAX_BINDING_FEATURES, 16);
    assert_eq!(MAX_BINDING_FEATURE_BYTES, 64);

    // A binding records the actual component exactly: package, version,
    // sorted features, backend and artifact digest are preserved byte for
    // byte with no normalization.
    let profile = Profile::new("bind", vec![], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    let features: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
    let input = ComponentBinding {
        package: "scopebase-linux".to_owned(),
        version: "0.1.0".to_owned(),
        features: features.clone(),
        backend: Some("held-file".to_owned()),
        artifact_sha256: Some([0x11; 32]),
    };
    context.bind(input.clone()).expect("valid binding");
    let stored = &context.report().bindings[0];
    assert_eq!(stored.package, "scopebase-linux");
    assert_eq!(stored.version, "0.1.0");
    assert_eq!(stored.features, features);
    assert_eq!(stored.backend.as_deref(), Some("held-file"));
    assert_eq!(stored.artifact_sha256, Some([0x11; 32]));
    assert_eq!(*stored, input, "binding must round-trip exactly");

    // Boundary lengths fit exactly: 128-byte package, 64-byte version,
    // 64-byte backend, sixteen 64-byte feature names.
    let profile = Profile::new("bounds", vec![], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    let wide = ComponentBinding {
        package: "p".repeat(128),
        version: "v".repeat(64),
        features: (0..16).map(|i| format!("f{i:02}")).collect(),
        backend: Some("b".repeat(64)),
        artifact_sha256: Some([0x22; 32]),
    };
    assert_eq!(wide.features.len(), 16);
    assert!(wide.features.windows(2).all(|pair| pair[0] < pair[1]));
    context.bind(wide).expect("boundary binding fits");

    // Every bound refuses exactly one over: 129-byte package, 65-byte
    // version, 65-byte backend, seventeen features, 65-byte feature name.
    for malformed in [
        ComponentBinding {
            package: "p".repeat(129),
            ..binding("x", "1")
        },
        ComponentBinding {
            version: "v".repeat(65),
            ..binding("x", "1")
        },
        ComponentBinding {
            backend: Some("b".repeat(65)),
            ..binding("x", "1")
        },
        ComponentBinding {
            features: (0..17).map(|i| format!("g{i:02}")).collect(),
            ..binding("x", "1")
        },
        ComponentBinding {
            features: vec!["f".repeat(65)],
            ..binding("x", "1")
        },
    ] {
        let profile = Profile::new("over", vec![], vec![]).expect("valid profile");
        let mut context = AppContext::new(profile, test_limits()).expect("valid context");
        assert_eq!(
            context.bind(malformed),
            Err(ContextError::InvalidBinding),
            "over-bound binding must be refused"
        );
        assert!(context.report().bindings.is_empty());
    }

    // Vacuous bindings are refused: empty package, version, backend or
    // feature name carries no component identity.
    for malformed in [
        ComponentBinding {
            package: String::new(),
            ..binding("x", "1")
        },
        ComponentBinding {
            version: String::new(),
            ..binding("x", "1")
        },
        ComponentBinding {
            backend: Some(String::new()),
            ..binding("x", "1")
        },
        ComponentBinding {
            features: vec![String::new()],
            ..binding("x", "1")
        },
    ] {
        let profile = Profile::new("vacuous", vec![], vec![]).expect("valid profile");
        let mut context = AppContext::new(profile, test_limits()).expect("valid context");
        assert_eq!(
            context.bind(malformed),
            Err(ContextError::InvalidBinding),
            "vacuous binding must be refused"
        );
    }

    // Features arrive sorted and unique; the context refuses to reorder or
    // deduplicate rather than silently rewriting the caller's record.
    let profile = Profile::new("order", vec![], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    assert_eq!(
        context.bind(ComponentBinding {
            features: vec!["b".to_owned(), "a".to_owned()],
            ..binding("ordered", "1")
        }),
        Err(ContextError::InvalidBinding)
    );
    assert_eq!(
        context.bind(ComponentBinding {
            features: vec!["a".to_owned(), "a".to_owned()],
            ..binding("ordered", "1")
        }),
        Err(ContextError::InvalidBinding)
    );
    assert!(context.report().bindings.is_empty());

    // Package coordinates (package, version, backend, features) must be
    // unique: an exact repeat is a duplicate even when the digest evidence
    // differs, while a new version or backend is a distinct component.
    let profile = Profile::new("dup", vec![], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .bind(binding("component", "1.0"))
        .expect("first binding");
    assert_eq!(
        context.bind(ComponentBinding {
            artifact_sha256: Some([0x99; 32]),
            ..binding("component", "1.0")
        }),
        Err(ContextError::DuplicateBinding)
    );
    assert_eq!(
        context.bind(binding("component", "1.0")),
        Err(ContextError::DuplicateBinding)
    );
    context
        .bind(binding("component", "2.0"))
        .expect("new version is distinct");
    context
        .bind(ComponentBinding {
            backend: Some("other".to_owned()),
            ..binding("component", "1.0")
        })
        .expect("new backend is distinct");
    assert_eq!(context.report().bindings.len(), 3);

    // Eight bindings fit; the ninth is refused before any copy.
    let profile = Profile::new("eight", vec![], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    for i in 0..8 {
        context
            .bind(binding(&format!("package-{i}"), "1.0"))
            .expect("binding fits");
    }
    assert_eq!(
        context.bind(binding("package-8", "1.0")),
        Err(ContextError::Capacity)
    );
    assert_eq!(context.report().bindings.len(), 8);

    // Structural bounds precede content: a full context reports Capacity
    // for malformed or duplicate bindings alike, matching profile
    // constructor precedence.
    assert_eq!(
        context.bind(ComponentBinding {
            package: String::new(),
            ..binding("package-8", "1.0")
        }),
        Err(ContextError::Capacity)
    );
    assert_eq!(
        context.bind(binding("package-0", "1.0")),
        Err(ContextError::Capacity)
    );
    assert_eq!(context.report().bindings.len(), 8);
}

#[test]
fn binding_payload_must_fit_retained_bytes() {
    // Binding UTF-8 string lengths are charged against retained_bytes with
    // checked arithmetic before cloning; exceeding the budget refuses with
    // Capacity and leaves the prior bindings unchanged.
    let profile = Profile::new("budget", vec![], vec![]).expect("valid profile");
    let mut limits = test_limits();
    limits.retained_bytes = 12;
    let mut context = AppContext::new(profile, limits).expect("valid context");
    // Payload 11 + 1 = 12 fits exactly.
    context
        .bind(binding(&"p".repeat(11), "v"))
        .expect("exact budget fits");
    // Any further payload exceeds the cumulative budget.
    assert_eq!(context.bind(binding("q", "w")), Err(ContextError::Capacity));
    assert_eq!(context.report().bindings.len(), 1);

    // One binding whose own payload exceeds the budget is refused alone.
    let profile = Profile::new("single", vec![], vec![]).expect("valid profile");
    let mut limits = test_limits();
    limits.retained_bytes = 4;
    let mut context = AppContext::new(profile, limits).expect("valid context");
    assert_eq!(
        context.bind(binding("toolong", "v")),
        Err(ContextError::Capacity)
    );
    assert!(context.report().bindings.is_empty());

    // Backend and feature bytes count with package and version bytes.
    let profile = Profile::new("parts", vec![], vec![]).expect("valid profile");
    let mut limits = test_limits();
    limits.retained_bytes = 8;
    let mut context = AppContext::new(profile, limits).expect("valid context");
    context
        .bind(ComponentBinding {
            features: vec!["ee".to_owned()],
            backend: Some("ff".to_owned()),
            ..binding("aa", "bb")
        })
        .expect("2+2+2+2 fits 8");
    assert_eq!(context.bind(binding("c", "d")), Err(ContextError::Capacity));
}

#[test]
fn duplicate_observation_cannot_replace_failure() {
    // A required denial refuses admission, and re-observing the same id --
    // even with a green retry -- is a duplicate error that keeps the
    // refusal. Evidence changes require a new explicit context.
    let profile = Profile::new("deny", vec![req("disk", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("disk", CapabilityState::Denied))
        .expect("first observation");
    assert_eq!(context.admission(), Admission::Refused);
    assert_eq!(
        context.observe(obs("disk", CapabilityState::Supported)),
        Err(ContextError::DuplicateObservation)
    );
    assert_eq!(
        context.observe(obs("disk", CapabilityState::Denied)),
        Err(ContextError::DuplicateObservation)
    );
    assert_eq!(context.admission(), Admission::Refused);
    assert_eq!(context.report().observations.len(), 1);
    assert_eq!(
        context.report().observations[0].state,
        CapabilityState::Denied
    );

    // Duplicates are refused for successes too, and the stored report keeps
    // its original source.
    let profile = Profile::new("ok", vec![req("net", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("net", CapabilityState::Supported))
        .expect("first observation");
    assert_eq!(
        context.observe(CapabilityObservation {
            id: "net",
            state: CapabilityState::Supported,
            source: "late-retry",
        }),
        Err(ContextError::DuplicateObservation)
    );
    assert_eq!(context.report().observations.len(), 1);
    assert_eq!(context.report().observations[0].source, "context-fixture");
}

#[test]
fn observations_require_declaration_and_bounded_storage() {
    // Observations for undeclared ids are refused: optional capabilities
    // must be declared too, and stray reports never enter the context.
    let profile = Profile::new("declared", vec![req("a", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    assert_eq!(
        context.observe(obs("stray", CapabilityState::Denied)),
        Err(ContextError::UnknownCapability)
    );
    assert_eq!(
        context.observe(obs("stray", CapabilityState::Supported)),
        Err(ContextError::UnknownCapability)
    );
    assert!(context.report().observations.is_empty());

    // Declared optional ids observe normally but never move the verdict.
    let profile = Profile::new(
        "optional",
        vec![req("need", true), req("want", false)],
        vec![],
    )
    .expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("want", CapabilityState::Denied))
        .expect("declared optional observes");
    assert_eq!(context.report().observations.len(), 1);

    // Sixty-four observations fit; structural capacity precedes content, so
    // a full context reports Capacity for duplicates and stray ids alike.
    let requirements: Vec<CapabilityRequirement> =
        (0..64).map(|i| req(static_id("cap", i), true)).collect();
    let ids: Vec<&'static str> = requirements.iter().map(|r| r.id).collect();
    let profile = Profile::new("full", requirements, vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    for id in &ids {
        context
            .observe(obs(id, CapabilityState::Supported))
            .expect("declared observation fits");
    }
    assert_eq!(context.report().observations.len(), 64);
    assert_eq!(
        context.observe(obs(ids[0], CapabilityState::Supported)),
        Err(ContextError::Capacity)
    );
    assert_eq!(
        context.observe(obs("stray-when-full", CapabilityState::Supported)),
        Err(ContextError::Capacity)
    );
    assert_eq!(context.report().observations.len(), 64);
}

#[test]
fn context_admission_gates_capabilities_with_bindings() {
    // Zero bindings refuse Ready even when every required capability is
    // supported: capability support without an exact artifact binding is
    // incomplete.
    let profile = Profile::new("gate", vec![req("a", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("a", CapabilityState::Supported))
        .expect("observation");
    assert_eq!(context.admission(), Admission::Incomplete);

    // A binding without an artifact digest is not an exact binding.
    context
        .bind(ComponentBinding {
            artifact_sha256: None,
            ..binding("undigested", "1.0")
        })
        .expect("digest-less binding stores");
    assert_eq!(context.admission(), Admission::Incomplete);

    // One digest-less sibling keeps a fully digested context incomplete.
    context
        .bind(binding("digested", "1.0"))
        .expect("digested binding stores");
    assert_eq!(context.admission(), Admission::Incomplete);

    // Required denials are retained through the binding gate: digested
    // bindings never soften a refusal.
    let profile = Profile::new("refuse", vec![req("a", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("a", CapabilityState::Denied))
        .expect("observation");
    context
        .bind(binding("digested", "1.0"))
        .expect("binding stores");
    assert_eq!(context.admission(), Admission::Refused);

    // Required unknown stays incomplete under digested bindings.
    let profile = Profile::new("unknown", vec![req("a", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("a", CapabilityState::Unknown))
        .expect("observation");
    context
        .bind(binding("digested", "1.0"))
        .expect("binding stores");
    assert_eq!(context.admission(), Admission::Incomplete);

    // Optional failures stay visible but Ready with supported requirements
    // and digested bindings.
    let profile = Profile::new("mixed", vec![req("need", true), req("want", false)], vec![])
        .expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("need", CapabilityState::Supported))
        .expect("observation");
    context
        .observe(obs("want", CapabilityState::Denied))
        .expect("optional observation");
    context
        .bind(binding("digested", "1.0"))
        .expect("binding stores");
    assert_eq!(context.admission(), Admission::Ready);
    assert_eq!(context.report().observations.len(), 2);

    // A profile with no prerequisites is Ready once an exact binding
    // exists, and Incomplete without one.
    let profile = Profile::new("empty", vec![], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    assert_eq!(context.admission(), Admission::Incomplete);
    context
        .bind(binding("digested", "1.0"))
        .expect("binding stores");
    assert_eq!(context.admission(), Admission::Ready);
}

// --- Independent oracle: capability sentence plus binding gate, separate
// logic and types, no production admission calls. ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelState {
    Supported,
    Unsupported,
    Denied,
    Unknown,
    Incompatible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelBindings {
    Zero,
    Undigested,
    Digested,
}

#[derive(Debug, PartialEq, Eq)]
enum ModelVerdict {
    Ready,
    Incomplete,
    Refused,
}

fn oracle(caps: &[Option<ModelState>], bindings: ModelBindings) -> ModelVerdict {
    let mut incomplete = false;
    for observed in caps {
        match observed {
            Some(ModelState::Unsupported | ModelState::Denied | ModelState::Incompatible) => {
                return ModelVerdict::Refused
            }
            Some(ModelState::Unknown) | None => incomplete = true,
            Some(ModelState::Supported) => {}
        }
    }
    if incomplete {
        return ModelVerdict::Incomplete;
    }
    match bindings {
        ModelBindings::Digested => ModelVerdict::Ready,
        ModelBindings::Zero | ModelBindings::Undigested => ModelVerdict::Incomplete,
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

fn to_model(admission: Admission) -> ModelVerdict {
    match admission {
        Admission::Ready => ModelVerdict::Ready,
        Admission::Incomplete => ModelVerdict::Incomplete,
        Admission::Refused => ModelVerdict::Refused,
    }
}

#[test]
fn context_admission_matches_independent_oracle() {
    // Two required capabilities, each missing or in any of five states,
    // crossed with zero/undigested/digested bindings: 6^2 x 3 = 108
    // populations. Setup uses production constructors; the verdict is
    // cross-checked against the separate oracle transcription.
    let options: [Option<ModelState>; 6] = [
        None,
        Some(ModelState::Supported),
        Some(ModelState::Unsupported),
        Some(ModelState::Denied),
        Some(ModelState::Unknown),
        Some(ModelState::Incompatible),
    ];
    let binding_options = [
        ModelBindings::Zero,
        ModelBindings::Undigested,
        ModelBindings::Digested,
    ];
    let mut checked = 0;
    for first in options {
        for second in options {
            for bindings in binding_options {
                let expected = oracle(&[first, second], bindings);
                let profile = Profile::new("oracle", vec![req("a", true), req("b", true)], vec![])
                    .expect("valid profile");
                let mut context = AppContext::new(profile, test_limits()).expect("valid context");
                for (id, observed) in ["a", "b"].into_iter().zip([first, second]) {
                    if let Some(state) = observed {
                        context
                            .observe(obs(id, to_production(state)))
                            .expect("distinct declared observation");
                    }
                }
                match bindings {
                    ModelBindings::Zero => {}
                    ModelBindings::Undigested => {
                        context
                            .bind(ComponentBinding {
                                artifact_sha256: None,
                                ..binding("oracle", "1.0")
                            })
                            .expect("digest-less binding stores");
                    }
                    ModelBindings::Digested => {
                        context
                            .bind(binding("oracle", "1.0"))
                            .expect("digested binding stores");
                    }
                }
                assert_eq!(
                    to_model(context.admission()),
                    expected,
                    "oracle mismatch for {first:?} {second:?} {bindings:?}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 108);
}

#[test]
fn context_reports_borrow_existing_storage() {
    // report() allocates nothing: repeated reports borrow the same stored
    // slices, and the profile id, limits, admission and omitted count match
    // the context inputs.
    let context = ready_context();
    let first = context.report();
    let second = context.report();
    assert_eq!(first.profile, "ready");
    assert_eq!(first.admission, Admission::Ready);
    assert_eq!(first.limits.input_bytes, 64);
    assert_eq!(first.observations.len(), 1);
    assert_eq!(first.bindings.len(), 1);
    assert_eq!(first.omitted.count, 0);
    assert!(!first.omitted.at_least);
    assert!(std::ptr::eq(first.limits, second.limits));
    assert!(std::ptr::eq(
        first.observations.as_ptr(),
        second.observations.as_ptr()
    ));
    assert!(std::ptr::eq(
        first.bindings.as_ptr(),
        second.bindings.as_ptr()
    ));
    assert!(std::ptr::eq(
        first.diagnostics.as_ptr(),
        second.diagnostics.as_ptr()
    ));
    assert_eq!(context.profile().id(), "ready");
}

#[test]
fn failed_operations_leave_prior_context_unchanged() {
    // Every refused observe/bind leaves admission, stored reports and
    // bindings exactly as before: checks run before any mutation.
    let mut context = ready_context();
    let snapshot = (
        context.admission(),
        context.report().observations.to_vec(),
        context.report().bindings.to_vec(),
        context.report().omitted.count,
    );
    assert_eq!(
        context.observe(obs("owned-files", CapabilityState::Supported)),
        Err(ContextError::DuplicateObservation)
    );
    assert_eq!(
        context.observe(obs("undeclared", CapabilityState::Supported)),
        Err(ContextError::UnknownCapability)
    );
    assert_eq!(
        context.bind(binding("scopebase-capture", "0.1.0")),
        Err(ContextError::DuplicateBinding)
    );
    assert_eq!(
        context.bind(ComponentBinding {
            package: String::new(),
            ..binding("bad", "1.0")
        }),
        Err(ContextError::InvalidBinding)
    );
    let after = (
        context.admission(),
        context.report().observations.to_vec(),
        context.report().bindings.to_vec(),
        context.report().omitted.count,
    );
    assert_eq!(snapshot, after, "failed operations must not mutate");

    // Constructor refusal carries the structured limits error and performs
    // no external effect.
    let profile = Profile::new("limits", vec![], vec![]).expect("valid profile");
    let mut limits = test_limits();
    limits.live_owners = 0;
    match AppContext::new(profile, limits) {
        Err(ContextError::Limits(LimitsError::Zero(LimitField::LiveOwners))) => {}
        other => panic!("expected structured limits refusal, got {other:?}"),
    }
}

#[test]
fn context_errors_render_without_payloads() {
    for (error, name) in [
        (
            ContextError::Limits(LimitsError::Zero(LimitField::Wait)),
            "Limits",
        ),
        (ContextError::InvalidBinding, "InvalidBinding"),
        (ContextError::DuplicateBinding, "DuplicateBinding"),
        (ContextError::DuplicateObservation, "DuplicateObservation"),
        (ContextError::UnknownCapability, "UnknownCapability"),
        (ContextError::Capacity, "Capacity"),
    ] {
        assert!(!error.to_string().is_empty());
        assert!(format!("{error:?}").contains(name));
        let _: &dyn std::error::Error = &error;
    }
}

#[test]
fn dropping_context_leaves_external_owners_untouched() {
    // The context owns only inert metadata. Dropping it after observing,
    // binding and diagnosing changes no external owner: an Arc strong count
    // is unchanged and an externally owned file keeps its exact bytes.
    use std::sync::Arc;
    let external = Arc::new(vec![1u8, 2, 3]);
    let count_before = Arc::strong_count(&external);

    let path = std::env::temp_dir().join(format!(
        "scopebase-sdk02-drop-{}-{}.tmp",
        std::process::id(),
        "context"
    ));
    std::fs::write(&path, b"external bytes").expect("fixture write");
    {
        let context = ready_context();
        let _ = &external;
        drop(context);
    }
    assert_eq!(Arc::strong_count(&external), count_before);
    assert_eq!(
        std::fs::read(&path).expect("fixture read"),
        b"external bytes"
    );
    std::fs::remove_file(&path).expect("fixture cleanup");

    // A fresh context after the drop behaves identically: no global
    // registry or residue survives the dropped context. Content, not
    // just counts: the fresh observation must be exactly the declared
    // one, with exactly the fresh binding and no carried diagnostics.
    let fresh = ready_context();
    assert_eq!(fresh.admission(), Admission::Ready);
    assert_eq!(
        fresh.report().observations,
        &[obs("owned-files", CapabilityState::Supported)]
    );
    assert_eq!(fresh.report().bindings.len(), 1);
    assert_eq!(
        fresh.report().bindings[0].package,
        "scopebase-capture",
        "fresh binding must be the declared coordinate, not residue"
    );
    assert!(fresh.report().diagnostics.is_empty());
}

// --- Bad controls: each corrupted twin must move the verdict or error. ---

#[test]
fn bad_zero_bindings_ready_would_certify_without_artifacts() {
    // A mutant that drops the binding gate would report Ready with no
    // artifact evidence; the honest verdict stays Incomplete.
    let profile = Profile::new("gate", vec![req("a", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("a", CapabilityState::Supported))
        .expect("observation");
    assert_eq!(context.admission(), Admission::Incomplete);
    assert_ne!(
        context.admission(),
        Admission::Ready,
        "zero bindings must never admit Ready"
    );
}

#[test]
fn bad_replaced_denial_would_hide_refusal() {
    // A mutant that lets a green retry replace a denial would report Ready;
    // the honest context refuses the duplicate and keeps Refused.
    let profile = Profile::new("deny", vec![req("a", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    context
        .observe(obs("a", CapabilityState::Denied))
        .expect("observation");
    context
        .bind(binding("digested", "1.0"))
        .expect("binding stores");
    assert_eq!(
        context.observe(obs("a", CapabilityState::Supported)),
        Err(ContextError::DuplicateObservation)
    );
    assert_eq!(context.admission(), Admission::Refused);
    assert_ne!(
        context.admission(),
        Admission::Ready,
        "replaced denial must stay detectable"
    );
}

#[test]
fn bad_undeclared_observation_would_forge_evidence() {
    // A mutant that admits stray ids would store forged evidence; the
    // honest context refuses and stores nothing.
    let profile = Profile::new("strict", vec![req("a", true)], vec![]).expect("valid profile");
    let mut context = AppContext::new(profile, test_limits()).expect("valid context");
    assert_eq!(
        context.observe(obs("forged", CapabilityState::Supported)),
        Err(ContextError::UnknownCapability)
    );
    assert!(context.report().observations.is_empty());
}
