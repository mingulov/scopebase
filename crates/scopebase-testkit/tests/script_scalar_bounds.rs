// SPDX-License-Identifier: Apache-2.0
//! S177: script-scalar byte bounds are enforced before decode, without
//! per-byte transient amplification.

use scopebase_testkit::{HarnessErrorKind, OperationScript, RunLimits};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

struct PeakObserver;

static ARMED: AtomicBool = AtomicBool::new(false);
static MEASURED_THREAD: OnceLock<std::thread::ThreadId> = OnceLock::new();

thread_local! {
    static LIVE_BYTES: Cell<u64> = const { Cell::new(0) };
    static PEAK_BYTES: Cell<u64> = const { Cell::new(0) };
}

fn measured_here() -> bool {
    match MEASURED_THREAD.get() {
        Some(id) => *id == std::thread::current().id(),
        None => false,
    }
}

fn note_alloc(size: usize) {
    LIVE_BYTES.with(|live| {
        let now = live.get().saturating_add(size as u64);
        live.set(now);
        PEAK_BYTES.with(|peak| peak.set(peak.get().max(now)));
    });
}

fn note_free(size: usize) {
    LIVE_BYTES.with(|live| live.set(live.get().saturating_sub(size as u64)));
}

unsafe impl GlobalAlloc for PeakObserver {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            note_alloc(layout.size());
        }
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            note_alloc(layout.size());
        }
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            note_free(layout.size());
        }
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) && measured_here() {
            note_free(layout.size());
            note_alloc(new_size);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static OBSERVER: PeakObserver = PeakObserver;

fn script_with_hex_param(hex: &str) -> Vec<u8> {
    format!(
        r#"{{"schema_version":1,"kind":"steps-v1","schema_id":"s177-probe","steps":[{{"step_id":"only","operation":"probe","inputs":[],"parameters":[{{"kind":"bytes","hex":"{hex}"}}]}}]}}"#
    )
    .into_bytes()
}

#[test]
fn oversized_scalar_refuses_before_full_decode() {
    // S177 order leg: a hex scalar that is BOTH over the 4096 scalar
    // cap AND malformed (odd length) must trip the scalar bound, not
    // the hex decoder — the bound is checked before decode.
    let hex = "ab".repeat(5000) + "c";
    let doc = script_with_hex_param(&hex);
    let error = OperationScript::load(&doc, &RunLimits::default()).expect_err("must refuse");
    assert_eq!(error.kind(), HarnessErrorKind::LimitExceeded);
    assert!(
        error.diagnostic().contains("scalar"),
        "scalar bound trips first: {}",
        error.diagnostic()
    );
}

#[test]
fn oversized_scalar_decode_stays_proportional() {
    // S177 amplification leg: decoding a 1 MiB scalar (refused: over
    // the 4096 cap) must not materialize per-byte transient Values
    // (~32 MiB pre-fix). Peak live heap stays O(decoded bytes).
    let _ = MEASURED_THREAD.set(std::thread::current().id());
    let hex = "ab".repeat(1024 * 1024);
    let doc = script_with_hex_param(&hex);
    LIVE_BYTES.with(|c| c.set(0));
    PEAK_BYTES.with(|c| c.set(0));
    ARMED.store(true, Ordering::Relaxed);
    let error = OperationScript::load(&doc, &RunLimits::default()).expect_err("must refuse");
    ARMED.store(false, Ordering::Relaxed);
    assert_eq!(error.kind(), HarnessErrorKind::LimitExceeded);
    let peak = PEAK_BYTES.with(|c| c.get());
    assert!(peak > 0, "measurement engaged");
    assert!(
        peak < 10 * 1024 * 1024,
        "peak transient {peak} bytes exceeds O(decoded)"
    );
}
