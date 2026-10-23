// SPDX-License-Identifier: Apache-2.0
//! RL01 cross-package adversarial integration review: negative examples that
//! combine the actual selected public packages (capture + linux + bpf + sdk).
//!
//! Each test names the packages it binds and the refused or contained
//! behavior. NX-only negatives (native error-code drift, bridge lifetime,
//! C/Mojo clients) are deferred with a recorded list in
//! `docs/reviews/integration.md`: those domains do not exist yet.
//!
//! Fixture inputs below are independently authored literals.

#![cfg(feature = "bpf")]

use scopebase_bpf::{CpuTopology, ErrorKind, Limits, OperationError, Stage};
#[cfg(feature = "capture")]
use scopebase_capture::ContractError;
use scopebase_linux::error::Reason;
use scopebase_linux::file::{HeldFile, ProcFdResolver, SymlinkPolicy};

fn bpf_limits() -> Limits {
    Limits {
        input_bytes: 1 << 20,
        retained_bytes: 1 << 20,
        work_steps: 1 << 20,
        sites: 64,
        live_links: 64,
        pending_retirements: 64,
    }
}

/// RL01 negative 1 (scopebase-bpf): a fabricated per-CPU description parses
/// (it is descriptive input) but never equals live kernel truth, and the live
/// owner admits no degenerate caps. `ValidatedMap::from_owned_fd` acquires its
/// own `LiveCpuTopology` internally, so no descriptive value can be smuggled
/// into map reads.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
fn fabricated_topology_never_equals_live_truth() {
    use scopebase_bpf::LiveCpuTopology;

    // Fabricated high-ID range: parses fine as a description.
    let fabricated = CpuTopology::parse_possible(b"64512-65535", 65535, 65536)
        .expect("descriptive parse accepts caller bytes");
    assert_eq!(fabricated.count(), 1024);

    // Live truth comes only from the kernel-owned FDs.
    let live = LiveCpuTopology::acquire(&bpf_limits()).expect("live acquire works");
    assert_ne!(
        live.snapshot().ids(),
        fabricated.ids(),
        "fabricated bytes must not equal live kernel truth"
    );
    assert!(
        live.snapshot().count() < fabricated.count(),
        "live count {} must stay below the fabricated 1024",
        live.snapshot().count()
    );
    live.revalidate().expect("fresh live owner revalidates");

    // Degenerate admission refuses before touching sources.
    let mut zero_input = bpf_limits();
    zero_input.input_bytes = 0;
    // LiveCpuTopology is deliberately Debug-less (owns live FDs); match by hand.
    let refused = match LiveCpuTopology::acquire(&zero_input) {
        Ok(_) => panic!("zero input refuses"),
        Err(error) => error,
    };
    assert_eq!((refused.kind(), refused.stage()), (ErrorKind::LimitExceeded, Stage::Admission));
    let mut zero_work = bpf_limits();
    zero_work.work_steps = 0;
    let refused = match LiveCpuTopology::acquire(&zero_work) {
        Ok(_) => panic!("zero work refuses"),
        Err(error) => error,
    };
    assert_eq!(refused.kind(), ErrorKind::LimitExceeded);
}

/// RL01 negative 2 (scopebase-bpf + scopebase-linux + scopebase-capture +
/// scopebase-sdk): error text never echoes raw payloads across the boundary.
/// OperationError omits its source, LinuxError omits path text, ContractError
/// stays variant-typed, and the SDK foreign-PID refusal names no PID.
#[test]
fn error_text_carries_no_raw_payload() {
    #[derive(Debug)]
    struct Distinctive(std::borrow::Cow<'static, str>);
    impl std::fmt::Display for Distinctive {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Distinctive {}

    // BPF: Display is short ASCII and never formats the source.
    let source: Box<dyn std::error::Error + Send + Sync> =
        Box::new(Distinctive("RL01-DISTINCTIVE-SOURCE-PAYLOAD".into()));
    let error = OperationError::new(ErrorKind::Backend, Stage::Read, Some(-999), Some(source));
    let text = error.to_string();
    assert!(!text.contains("DISTINCTIVE"), "source must not echo: {text}");
    assert!(text.is_ascii() && text.len() <= 256, "bounded ASCII: {text}");
    let debug = format!("{error:?}");
    assert!(!debug.contains("DISTINCTIVE"), "Debug must not echo: {debug}");
    assert!(debug.len() <= 256, "bounded Debug: {debug}");

    // Linux: Display carries stage/reason/errno only, never the path text.
    let resolver = ProcFdResolver::open_self().expect("own proc resolver");
    let distinctive = std::path::Path::new("/nonexistent-rl01-distinctive-path-9f3c/input.dat");
    let failure =
        HeldFile::open(distinctive, &resolver, SymlinkPolicy::Follow).expect_err("missing refuses");
    assert_eq!(failure.reason(), Reason::Disappeared);
    let text = failure.to_string();
    assert!(!text.contains("distinctive"), "path must not echo: {text}");
    assert!(text.is_ascii() && text.len() <= 256, "bounded ASCII: {text}");

    // Capture: typed variants, compared, never rendered.
    #[cfg(feature = "capture")]
    assert_eq!(format!("{:?}", ContractError::DomainMismatch), "DomainMismatch");

    // SDK: the foreign-PID refusal is a fixed string with no PID value.
    let refusal = scopebase_sdk::observer::ObserverError::ForeignPid.to_string();
    assert_eq!(refusal, "refused: PID is not the owned workload");
    assert!(!refusal.chars().any(|c| c.is_ascii_digit()), "no PID digits: {refusal}");
}

/// RL01 negative 3 (scopebase-capture + scopebase-sdk): a returned validated
/// record is an immutable snapshot, never live authority. Attaching it moves
/// no admission, grants no second slot, and consumes nothing: the caller's
/// value stays usable.
#[cfg(feature = "capture")]
#[test]
fn validated_record_promotes_to_no_authority() {
    use scopebase_capture::neutral::{
        validate_v1, NeutralCounter, NeutralLimits, NeutralObservationV1, NeutralOrigin,
        NeutralPolicy, NeutralSource, NeutralUnit,
    };
    use scopebase_sdk::context::{AppContext, ComponentBinding, ContextError};
    use scopebase_sdk::limits::Limits as SdkLimits;
    use scopebase_sdk::profile::{Admission, Profile};
    use std::time::Duration;

    let raw = NeutralObservationV1 {
        source: NeutralSource {
            capture: [0x11; 16],
            producer: [0x22; 16],
            ordinal: 1,
            binding: [0x33; 32],
            origin: NeutralOrigin::AdapterReported,
        },
        unit: NeutralUnit::Events,
        counters: vec![NeutralCounter {
            channel: 1,
            policy: NeutralPolicy::Monotonic,
            clock: [0x44; 16],
            start: 0,
            end: 1,
            value: 10,
            unit: NeutralUnit::Events,
        }],
        losses: Vec::new(),
        signals: Vec::new(),
        claims: Vec::new(),
        partitions: Vec::new(),
        corrections: Vec::new(),
    };
    let validated = validate_v1(&raw, NeutralLimits::default()).expect("valid fixture");
    let mut context = AppContext::new(
        Profile::new("rl01", vec![], vec![]).expect("valid profile"),
        SdkLimits {
            input_bytes: 65_536,
            retained_bytes: 65_536,
            work_items: 64,
            live_owners: 8,
            diagnostic_count: 32,
            diagnostic_bytes: 65_536,
            wait: Duration::from_secs(2),
        },
    )
    .expect("valid context");
    context
        .bind(ComponentBinding {
            package: "scopebase-capture".to_owned(),
            version: "0.1.0".to_owned(),
            features: Vec::new(),
            backend: None,
            artifact_sha256: Some([0x42; 32]),
        })
        .expect("binding attaches");
    assert_eq!(context.admission(), Admission::Ready);

    context.capture(&validated).expect("snapshot attaches");
    // Admission is unmoved; the snapshot reads back equal; the caller's
    // validated value was borrowed, not consumed into authority.
    assert_eq!(context.admission(), Admission::Ready);
    assert_eq!(context.capture_snapshot(), Some(&validated));
    assert_eq!(validated.source().epoch().ordinal(), 1);

    // No second slot: a returned record cannot escalate into more standing.
    let again = context.capture(&validated).expect_err("second capture refuses");
    assert_eq!(again, ContextError::CaptureAlreadyPresent);
}
