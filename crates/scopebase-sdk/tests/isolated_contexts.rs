// SPDX-License-Identifier: Apache-2.0
//! SDK02 isolation tests: two concurrent host contexts keep independent
//! limits, observations, bindings, diagnostics and owner outcomes with no
//! hidden global lock, signal handler or resource registry. Shared mutation
//! needs caller synchronization; disjoint contexts need none.

use scopebase_sdk::context::{AppContext, ComponentBinding, ContextError, ContextReport};
use scopebase_sdk::diagnostic::{
    Diagnostic, DiagnosticDisposition, EffectState, OmittedDiagnostics, RetainedDiagnostic,
    Severity, Stage,
};
use scopebase_sdk::limits::{LimitField, Limits, LimitsError};
use scopebase_sdk::profile::{
    Admission, CapabilityObservation, CapabilityRequirement, CapabilityState, Effect, Profile,
    ProfileError,
};
use std::sync::{Arc, Barrier};
use std::time::Duration;

/// Owned snapshot of one thread's context report: the borrowed report cannot
/// cross the join boundary, so each worker copies its verdict inputs home.
/// Content, not just counts: swapped observations, bindings or diagnostic
/// text between workers must fail the comparison.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    profile: &'static str,
    admission: Admission,
    observations: Vec<(&'static str, &'static str)>,
    bindings: Vec<(String, Option<[u8; 32]>)>,
    diagnostics: Vec<(&'static str, String)>,
    omitted: u64,
    at_least: bool,
    input_bytes: u64,
}

fn snapshot(context: &AppContext) -> Snapshot {
    let report = context.report();
    Snapshot {
        profile: report.profile,
        admission: report.admission,
        observations: report
            .observations
            .iter()
            .map(|o| (o.id, o.source))
            .collect(),
        bindings: report
            .bindings
            .iter()
            .map(|b| (b.package.clone(), b.artifact_sha256))
            .collect(),
        diagnostics: report
            .diagnostics
            .iter()
            .map(|d| (d.code, d.text.clone()))
            .collect(),
        omitted: report.omitted.count,
        at_least: report.omitted.at_least,
        input_bytes: report.limits.input_bytes,
    }
}

fn worker_limits(input_bytes: u64, diagnostic_count: u32) -> Limits {
    Limits {
        input_bytes,
        retained_bytes: 65_536,
        work_items: 64,
        live_owners: 8,
        diagnostic_count,
        diagnostic_bytes: 65_536,
        wait: Duration::from_secs(2),
    }
}

fn diagnose<'a>(code: &'static str, text: &'a str) -> Diagnostic<'a> {
    Diagnostic {
        code,
        severity: Severity::Note,
        stage: Stage::Observation,
        effect: EffectState::None,
        text,
        path: None,
    }
}

/// Linux exposes this process's caught-signal mask; other hosts lack
/// /proc, in which case the check degrades to no assertion rather than a
/// false failure.
fn caught_signal_mask() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|line| line.starts_with("SigCgt:"))
        .map(str::to_owned)
}

fn process_limits_snapshot() -> Option<String> {
    std::fs::read_to_string("/proc/self/limits").ok()
}

#[test]
fn contexts_do_not_share_state() {
    let mask_before = caught_signal_mask();
    let limits_before = process_limits_snapshot();

    // Two workers build disjoint contexts behind a barrier so their
    // observation/binding/diagnostic sequences overlap in time. No worker
    // installs a signal handler or changes a process limit: the SDK API has
    // no such route.
    let barrier = Arc::new(Barrier::new(2));
    let worker = |name: &'static str,
                  cap: &'static str,
                  package: &'static str,
                  digest: u8,
                  note_code: &'static str,
                  note_text: &'static str,
                  input_bytes: u64,
                  over_cap: bool,
                  barrier: Arc<Barrier>| {
        std::thread::spawn(move || {
            let profile = Profile::new(
                name,
                vec![CapabilityRequirement {
                    id: cap,
                    required: true,
                }],
                vec![],
            )
            .expect("valid profile");
            let mut context =
                AppContext::new(profile, worker_limits(input_bytes, 4)).expect("valid context");
            barrier.wait();
            context
                .observe(CapabilityObservation {
                    id: cap,
                    state: CapabilityState::Supported,
                    source: name,
                })
                .expect("declared observation");
            context
                .bind(ComponentBinding {
                    package: package.to_owned(),
                    version: "1.0".to_owned(),
                    features: Vec::new(),
                    backend: None,
                    artifact_sha256: Some([digest; 32]),
                })
                .expect("valid binding");
            assert_eq!(
                context.diagnostic(diagnose(note_code, note_text)),
                DiagnosticDisposition::Retained
            );
            if over_cap {
                let over = "x".repeat(4_097);
                assert_eq!(
                    context.diagnostic(diagnose("WORKER_OVER", &over)),
                    DiagnosticDisposition::Truncated
                );
            }
            barrier.wait();
            snapshot(&context)
        })
    };

    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);
    let first = worker(
        "worker-a",
        "cap-a",
        "package-a",
        0xA1,
        "WORKER_NOTE_A",
        "diagnostic from worker-a",
        111,
        true,
        first_barrier,
    );
    let second = worker(
        "worker-b",
        "cap-b",
        "package-b",
        0xB2,
        "WORKER_NOTE_B",
        "diagnostic from worker-b",
        222,
        false,
        second_barrier,
    );
    let first = first.join().expect("worker joins");
    let second = second.join().expect("worker joins");

    // Each worker sees exactly its own profile, limits, observations,
    // bindings, diagnostics and omitted count; nothing crosses over.
    assert_eq!(
        first,
        Snapshot {
            profile: "worker-a",
            admission: Admission::Ready,
            observations: vec![("cap-a", "worker-a")],
            bindings: vec![("package-a".to_owned(), Some([0xA1; 32]))],
            diagnostics: vec![("WORKER_NOTE_A", "diagnostic from worker-a".to_owned())],
            omitted: 1,
            at_least: false,
            input_bytes: 111,
        }
    );
    assert_eq!(
        second,
        Snapshot {
            profile: "worker-b",
            admission: Admission::Ready,
            observations: vec![("cap-b", "worker-b")],
            bindings: vec![("package-b".to_owned(), Some([0xB2; 32]))],
            diagnostics: vec![("WORKER_NOTE_B", "diagnostic from worker-b".to_owned())],
            omitted: 0,
            at_least: false,
            input_bytes: 222,
        }
    );

    // No installed signal handler: the caught-signal mask is unchanged.
    // On Linux /proc must exist: require successful reads so the check
    // cannot pass vacuously when both snapshots are unavailable.
    let mask_after = caught_signal_mask();
    let limits_after = process_limits_snapshot();
    #[cfg(target_os = "linux")]
    {
        assert!(
            mask_before.is_some(),
            "SigCgt baseline must be readable on Linux"
        );
        assert!(
            limits_before.is_some(),
            "resource-limits baseline must be readable on Linux"
        );
        assert!(
            mask_after.is_some(),
            "SigCgt final read must succeed on Linux"
        );
        assert!(
            limits_after.is_some(),
            "resource-limits final read must succeed on Linux"
        );
    }
    assert_eq!(mask_after, mask_before);
    assert_eq!(limits_after, limits_before);

    // The main thread is unaffected: a fresh context starts empty with its
    // own limits, proving no shared registry carried worker state home.
    let profile = Profile::new(
        "main",
        vec![CapabilityRequirement {
            id: "cap-a",
            required: true,
        }],
        vec![],
    )
    .expect("valid profile");
    let main = AppContext::new(profile, worker_limits(333, 4)).expect("valid context");
    let main = snapshot(&main);
    assert!(main.observations.is_empty());
    assert!(main.bindings.is_empty());
    assert!(main.diagnostics.is_empty());
    assert_eq!(main.omitted, 0);
    assert_eq!(main.input_bytes, 333);
    assert_eq!(main.admission, Admission::Incomplete);
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn sdk02_types_are_send_sync() {
    // Supported Send/Sync behavior is asserted per type rather than inferred
    // from any Arc use: disjoint contexts cross thread boundaries by value.
    assert_send_sync::<Limits>();
    assert_send_sync::<LimitField>();
    assert_send_sync::<LimitsError>();
    assert_send_sync::<Profile>();
    assert_send_sync::<ProfileError>();
    assert_send_sync::<CapabilityRequirement>();
    assert_send_sync::<CapabilityObservation>();
    assert_send_sync::<CapabilityState>();
    assert_send_sync::<Effect>();
    assert_send_sync::<Admission>();
    assert_send_sync::<ComponentBinding>();
    assert_send_sync::<AppContext>();
    assert_send_sync::<ContextError>();
    assert_send_sync::<ContextReportAlias>();
    assert_send_sync::<Diagnostic<'static>>();
    assert_send_sync::<RetainedDiagnostic>();
    assert_send_sync::<OmittedDiagnostics>();
    assert_send_sync::<DiagnosticDisposition>();
    assert_send_sync::<Severity>();
    assert_send_sync::<Stage>();
    assert_send_sync::<EffectState>();
}

// `ContextReport` borrows its context; alias the 'static instantiation so
// the Send/Sync assertion names a concrete type.
type ContextReportAlias = ContextReport<'static>;
