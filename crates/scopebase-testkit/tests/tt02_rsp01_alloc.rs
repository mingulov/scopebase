// SPDX-License-Identifier: Apache-2.0
//! Isolated forwarding allocator observer for the prepared BP03 call.
//!
//! This is a separate single-purpose executable (`harness = false`,
//! `required-features = ["bpf-host"]`), never a case in the multithreaded
//! libtest harness. It installs a forwarding [`std::alloc::System`]
//! observer that counts actual `alloc`/`alloc_zeroed`/`realloc` entries on
//! the preinitialized measured thread only, and deallocations separately.
//! No failure is injected, no allocator is replaced, and no production or
//! helper behavior changes. All setup (adapter, invocation, fixtures,
//! literals, direct-attribution measurements) completes before arming; the
//! window is armed externally around the whole public consuming
//! [`PreparedExecution::execute`] call, then disarmed before any inspection,
//! assertion, printing or drop of returned values. In-window drops are
//! allowed and counted separately.
//!
//! Controls: an empty window and a deliberate allocation prove zero and
//! nonzero sensitivity on each run. Binding, dialect and zero-work refusal
//! windows must show zero allocator entries. The positive filter window must
//! show exactly the independently attributed direct BPF operation entries
//! plus the single fixed adapter output reservation. Key-clone,
//! public-constructor and `format!` mutants must each show nonzero entries;
//! restored twins pass.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

struct Observer;

static ARMED: AtomicBool = AtomicBool::new(false);
static MEASURED_THREAD: OnceLock<std::thread::ThreadId> = OnceLock::new();

thread_local! {
    static ALLOC_ENTRIES: Cell<usize> = const { Cell::new(0) };
    static DEALLOC_ENTRIES: Cell<usize> = const { Cell::new(0) };
}

fn measured_here() -> bool {
    match MEASURED_THREAD.get() {
        Some(id) => *id == std::thread::current().id(),
        None => false,
    }
}

unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Observer callbacks touch only preinitialized fixed Cell state and
        // forward the actual allocator call: no logging, allocation, lazy
        // initialization, formatting, locks or recursion.
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            ALLOC_ENTRIES.with(|c| c.set(c.get().wrapping_add(1)));
        }
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            ALLOC_ENTRIES.with(|c| c.set(c.get().wrapping_add(1)));
        }
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            ALLOC_ENTRIES.with(|c| c.set(c.get().wrapping_add(1)));
        }
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            DEALLOC_ENTRIES.with(|c| c.set(c.get().wrapping_add(1)));
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Observer = Observer;

#[allow(dead_code)]
#[path = "fixtures/bp03/controls.rs"]
mod controls;

use scopebase_testkit::bpf::BpfHostAdapter;
use scopebase_testkit::{
    CaseInvocation, CaseInvocationValues, ConsumerBinding, ConsumerBindingValues, Digest256,
    EffectBatch, FixtureAccess, FixtureInput, InvocationKey, InvocationKeyValues, Label,
    OperationScript, PreparedExecution, ResponsePreparedAdapter, RunLimits, SchemaBinding,
    SchemaBindingValues, SubjectBinding, SubjectBindingValues,
};

fn label(s: &str) -> Label {
    Label::parse(s).unwrap()
}

fn bpf_limits() -> scopebase_bpf::Limits {
    scopebase_bpf::Limits {
        input_bytes: 131072,
        retained_bytes: 262144,
        work_steps: 8388608,
        sites: 0,
        live_links: 0,
        pending_retirements: 0,
    }
}

fn subject(l: &RunLimits) -> SubjectBinding {
    let d = Digest256::of_bytes(b"BP03 allocator observer descriptive metadata");
    SubjectBinding::new(
        SubjectBindingValues {
            package_name: "scopebase-bpf".into(),
            package_version: "0.1.0".into(),
            source_sha256: d,
            build_inputs_sha256: d,
            features: vec![],
            backend: None,
            host: "x86_64-unknown-linux-gnu".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            consumer: ConsumerBinding::new(
                ConsumerBindingValues {
                    name: "bp03-observer".into(),
                    build_inputs_sha256: d,
                    executable_sha256: d,
                },
                l,
            )
            .unwrap(),
            objects: vec![],
            provenance: scopebase_testkit::BindingProvenance::SelfReported {
                reason: "allocator observer".into(),
            },
        },
        l,
    )
    .unwrap()
}

fn invocation(l: &RunLimits, schema: &str, op: &str, slots: &[&str]) -> CaseInvocation {
    use scopebase_testkit::{CaseId, CaseKey, CaseKeyValues, RunId};
    let script = serde_json::json!({"schema_version":1,"kind":"steps-v1","schema_id":schema,"steps":[{"step_id":"only-step","operation":op,"inputs":slots,"parameters":[]}]});
    CaseInvocation::new(
        CaseInvocationValues {
            key: InvocationKey::new(
                InvocationKeyValues {
                    run_id: RunId::parse("0123456789abcdef0123456789abcdef").unwrap(),
                    case_key: CaseKey::new(
                        CaseKeyValues {
                            case_id: CaseId::parse("H22.model-filter").unwrap(),
                            case_version: 1,
                            cell_id: "model".into(),
                        },
                        l,
                    )
                    .unwrap(),
                    attempt: 1,
                    operation_id: 1,
                },
                l,
            )
            .unwrap(),
            observation_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-model-result"),
                    revision: 1,
                },
                l,
            )
            .unwrap(),
            fixture_schema: SchemaBinding::new(
                SchemaBindingValues {
                    id: label("bp03-fixed-input"),
                    revision: 1,
                },
                l,
            )
            .unwrap(),
            script: OperationScript::load(&serde_json::to_vec(&script).unwrap(), l).unwrap(),
            limits: l.clone(),
        },
        l,
    )
    .unwrap()
}

/// Run `f` inside the armed whole-call window. Returns the closure value
/// plus the counted allocator entries. Disarms before returning.
fn measure<R, F: FnOnce() -> R>(f: F) -> (R, usize, usize) {
    ALLOC_ENTRIES.with(|c| c.set(0));
    DEALLOC_ENTRIES.with(|c| c.set(0));
    ARMED.store(true, Ordering::Relaxed);
    let value = f();
    ARMED.store(false, Ordering::Relaxed);
    (
        value,
        ALLOC_ENTRIES.with(|c| c.get()),
        DEALLOC_ENTRIES.with(|c| c.get()),
    )
}

fn main() {
    // Preinitialize all observer state and complete every setup allocation
    // before arming: TLS counters, measured-thread identity, adapter,
    // invocations, fixtures and direct-attribution inputs.
    ALLOC_ENTRIES.with(|c| c.set(0));
    DEALLOC_ENTRIES.with(|c| c.set(0));
    MEASURED_THREAD
        .set(std::thread::current().id())
        .unwrap_or(());
    assert!(measured_here(), "observer measures its own thread");

    let l = RunLimits::default();
    let mut failures = 0;
    let mut check = |name: &str, alloc: usize, dealloc: usize, want_alloc: Option<usize>| {
        let pass = match want_alloc {
            Some(n) => alloc == n,
            None => alloc != 0,
        };
        println!(
            "ALLOC_CHECK {name} alloc={alloc} dealloc={dealloc} expected={} result={}",
            match want_alloc {
                Some(n) => n.to_string(),
                None => "nonzero".to_string(),
            },
            if pass { "PASS" } else { "FAIL" }
        );
        if !pass {
            failures += 1;
        }
    };

    // Empty window: zero sensitivity with no setup contamination.
    let (_, alloc, dealloc) = measure(|| {});
    check("observer_empty_window", alloc, dealloc, Some(0));

    // Deliberate allocation: nonzero sensitivity.
    let (_, alloc, dealloc) = measure(|| {
        let v = vec![0u8; 64];
        assert_eq!(v.len(), 64);
    });
    check("observer_intentional_allocation", alloc, dealloc, None);

    // Binding refusal: scalar limits mismatch prepares an error-only
    // response; the consuming execution performs no operation allocation.
    {
        let mut values = l.values();
        values.execution_ms -= 1;
        let changed = RunLimits::new(values).unwrap();
        let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), changed).unwrap();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let refs = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
        let call = a.prepare_response(&i).unwrap();
        let (result, alloc, dealloc) = measure(|| call.execute(&f));
        let e = result.unwrap_err();
        assert_eq!(e.diagnostic_bytes(), b"run-limits-mismatch");
        check(
            "observer_binding_preflight_zero_work",
            alloc,
            dealloc,
            Some(0),
        );
        drop(e);
    }

    // Dialect refusal: unsupported schema never reaches input access or the
    // operation, so the whole consuming call allocates nothing.
    {
        let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
        let i = invocation(&l, "unsupported", "not-an-operation", &[]);
        let f = FixtureAccess::new(&[], &[], EffectBatch::empty(&l), &l).unwrap();
        let call = a.prepare_response(&i).unwrap();
        let (result, alloc, dealloc) = measure(|| call.execute(&f));
        let e = result.unwrap_err();
        assert_eq!(e.diagnostic_bytes(), b"unsupported-dialect");
        check("observer_dialect_refusal", alloc, dealloc, Some(0));
        drop(e);
    }

    // Zero-work refusal: the operation entry itself refuses before any input
    // scan or payload reservation.
    {
        let mut a = BpfHostAdapter::new(
            subject(&l),
            scopebase_bpf::Limits {
                work_steps: 0,
                ..bpf_limits()
            },
            l.clone(),
        )
        .unwrap();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let refs = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
        let call = a.prepare_response(&i).unwrap();
        let (result, alloc, dealloc) = measure(|| call.execute(&f));
        assert!(result.is_err());
        check("observer_zero_work_refusal", alloc, dealloc, Some(0));
    }

    // Positive filter route: independently attribute the direct public BPF
    // operation entries under identical inputs, then require the full
    // adapter window to equal that attribution plus the single fixed
    // adapter output reservation.
    {
        let population = scopebase_bpf::ProbePopulation {
            expected_owned_hits: 2,
            observed_owned_hits: 2,
            independently_executed_excluded: 1,
            observed_excluded_hits: 0,
        };
        let (_, direct, _) = measure(|| {
            let _ = scopebase_bpf::assess_filter_probe(&population).unwrap();
        });
        let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let refs = [FixtureInput::new(label("counts"), b"2\n2\n1\n0\n")];
        let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
        let call = a.prepare_response(&i).unwrap();
        let (result, alloc, dealloc) = measure(|| call.execute(&f));
        let v = result.unwrap();
        assert_eq!(v.bytes(), b"supported");
        println!("ALLOC_ATTRIBUTION filter direct_bpf={direct} adapter_output_reservation=1");
        check(
            "observer_filter_public_call",
            alloc,
            dealloc,
            Some(direct + 1),
        );
        drop(v);
    }

    // Profile route: attribute the direct public ID conversions with the
    // fixed admitted input, then require the full window to equal that
    // attribution plus the single fixed adapter output reservation.
    {
        let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
        let i = invocation(&l, "bp03-host-v1", "to-testkit-profile", &["profile"]);
        let refs = [FixtureInput::new(label("profile"), b"a\n")];
        let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
        let source = scopebase_bpf::ProfileId::new("a").unwrap();
        let (_, direct_new, _) = measure(|| {
            let _ = scopebase_bpf::ProfileId::new("a").unwrap();
        });
        let (_, direct_convert, _) = measure(|| {
            let _ = scopebase_testkit::bpf::profile_to_testkit(&source).unwrap();
        });
        let call = a.prepare_response(&i).unwrap();
        let (result, alloc, dealloc) = measure(|| call.execute(&f));
        let v = result.unwrap();
        assert_eq!(v.bytes(), b"ok:a");
        println!(
            "ALLOC_ATTRIBUTION profile direct_new={direct_new} direct_convert={direct_convert} adapter_output_reservation=1"
        );
        check(
            "observer_profile_public_call",
            alloc,
            dealloc,
            Some(direct_new + direct_convert + 1),
        );
        drop(v);
        drop(source);
    }

    // JSON routes: full-call observation stays armed while the operation
    // allocations are attributed separately through actual direct public
    // BPF calls with identical fixed admitted inputs and caps.
    #[cfg(feature = "bpf-host-json")]
    {
        let raw = controls::OBSERVATION_INPUT;
        let decode = |remaining: usize| scopebase_bpf::Limits {
            input_bytes: 131072,
            retained_bytes: remaining.min(131072),
            work_steps: (raw.len() as u64) * 32 + 1024,
            sites: 0,
            live_links: 0,
            pending_retirements: 0,
        };
        let (_, direct_base, _) = measure(|| {
            let _ = scopebase_bpf::CapabilityObservation::from_json(raw, &decode(262144)).unwrap();
        });
        let candidate =
            scopebase_bpf::CapabilityObservation::from_json(raw, &decode(262144)).unwrap();
        let (_, direct_candidate, _) = measure(|| {
            let _ = scopebase_bpf::CapabilityObservation::from_json(raw, &decode(262144)).unwrap();
        });
        // import-observation attribution: direct decode plus direct encode
        // with the fixed ceiling, plus the two fixed adapter buffers.
        let value = scopebase_bpf::CapabilityObservation::from_json(raw, &decode(262144)).unwrap();
        let (_, direct_encode, _) = measure(|| {
            let _ = value.to_json(&decode(262144)).unwrap();
        });
        let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
        let i = invocation(
            &l,
            "bp03-host-json-v1",
            "context-applies",
            &["base", "candidate"],
        );
        let refs = [
            FixtureInput::new(label("base"), raw),
            FixtureInput::new(label("candidate"), raw),
        ];
        let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
        let call = a.prepare_response(&i).unwrap();
        let (result, alloc, dealloc) = measure(|| call.execute(&f));
        let v = result.unwrap();
        assert_eq!(v.bytes(), b"true");
        println!(
            "ALLOC_ATTRIBUTION json_context direct_base={direct_base} direct_candidate={direct_candidate} adapter_output_reservation=1"
        );
        check(
            "observer_json_public_call",
            alloc,
            dealloc,
            Some(direct_base + direct_candidate + 1),
        );
        drop(v);
        let i = invocation(&l, "bp03-host-json-v1", "import-observation", &["record"]);
        let refs = [FixtureInput::new(label("record"), raw)];
        let f = FixtureAccess::new(&refs, &[], EffectBatch::empty(&l), &l).unwrap();
        let call = a.prepare_response(&i).unwrap();
        let (result, alloc, dealloc) = measure(|| call.execute(&f));
        let v = result.unwrap();
        assert_eq!(&v.bytes()[..9], b"imported\n");
        println!(
            "ALLOC_ATTRIBUTION json_import direct_decode={direct_base} direct_encode={direct_encode} adapter_result_buffer=1"
        );
        check(
            "observer_json_import_public_call",
            alloc,
            dealloc,
            Some(direct_base + direct_encode + 1),
        );
        drop(v);
        drop(value);
        drop(candidate);
    }

    // Mutants: each forbidden pattern finishes valid setup and is caught by
    // the observer with nonzero entries. Restored twins above pass zero or
    // exactly-attributed windows.
    {
        // Clone-after-Ready: cloning the live invocation key inside the
        // measured window allocates response-shaped storage.
        let l = RunLimits::default();
        let mut a = BpfHostAdapter::new(subject(&l), bpf_limits(), l.clone()).unwrap();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let call = a.prepare_response(&i).unwrap();
        let (_, alloc, dealloc) = measure(|| {
            let _cloned = i.key().clone();
            drop(call);
        });
        check("observer_mutant_clone_after_ready", alloc, dealloc, None);
    }
    {
        // Generic public Observation constructor on the success path: the
        // allocating validator path is observed, unlike the admitted finish.
        let l = RunLimits::default();
        let i = invocation(&l, "bp03-host-v1", "assess-filter", &["counts"]);
        let (_, alloc, dealloc) = measure(|| {
            let _fresh = scopebase_testkit::Observation::new(
                scopebase_testkit::ObservationValues {
                    key: i.key().clone(),
                    schema_id: i.observation_schema().id().clone(),
                    schema_revision: *i.observation_schema().revision(),
                    completed_steps: vec![i.script().steps()[0].step_id().clone()],
                    bytes: b"supported".to_vec(),
                    effects: EffectBatch::empty(&l),
                },
                &l,
            )
            .unwrap();
        });
        check(
            "observer_mutant_generic_observation_new",
            alloc,
            dealloc,
            None,
        );
    }
    {
        // format! refusal diagnostic: dynamic formatting allocates.
        let (_, alloc, dealloc) = measure(|| {
            let _text = format!("bpf:{}/{}", "limit_exceeded", "admission");
        });
        check("observer_mutant_format_refusal", alloc, dealloc, None);
    }

    println!(
        "BP03_ALLOC_OBSERVER bpf=scopebase-bpf/0.1.0 testkit=scopebase-testkit/0.1.0 failures={failures}"
    );
    if failures != 0 {
        std::process::exit(1);
    }
    println!("bp03-tt02-rsp01-alloc: all armed whole-call windows accounted");
}
