// SPDX-License-Identifier: Apache-2.0
//! CP09 countermodels: quiet/detach/timeout prove nothing; late evidence
//! invalidates before reassessment; a new record retries with new proof.
use scopebase_capture::{
    closure::{
        assess_closure, BoundarySerial, ClosureGap, ClosureProfile, ClosureRecord, PredicateId,
        PredicateObservation,
    },
    domain::{BindingId, CaptureId, Epoch, Origin, ProducerId, SourceRef},
};

#[path = "support/json_mini.rs"]
mod json_mini;

use json_mini::Json;

fn epoch() -> Epoch {
    Epoch::new(CaptureId::new([1; 16]).unwrap(), ProducerId::new([2; 16]).unwrap(), 0)
}
fn source() -> SourceRef {
    SourceRef::new(epoch(), BindingId::new([3; 32]).unwrap(), Origin::AdapterReported)
}
fn pid(n: u16) -> PredicateId {
    PredicateId::new(n)
}
// 1=baseline 2=admission 3=closed 4=quiescence 5=drain 6=sample.
fn full_profile() -> ClosureProfile {
    ClosureProfile::new(
        1,
        &[pid(1), pid(2), pid(3), pid(4), pid(5), pid(6)],
        &[
            (pid(1), pid(2)),
            (pid(2), pid(3)),
            (pid(3), pid(4)),
            (pid(4), pid(5)),
            (pid(5), pid(6)),
        ],
        64,
    )
    .unwrap()
}
fn observe(record: &mut ClosureRecord, id: u16, serial: u64, drain: u64) {
    record
        .observe(PredicateObservation::new(
            pid(id),
            source(),
            BoundarySerial::new(serial),
            drain,
        ))
        .unwrap();
}
fn full_record() -> ClosureRecord {
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    for (id, serial) in [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)] {
        observe(&mut record, id, serial, 0);
    }
    record
}

#[test]
fn late_submit_invalidates_drain_and_sample() {
    // MemVeil stop.mojo: a submit landing after the drain recorded its
    // boundary claim invalidates the drain, and the sample that must
    // follow the last drain. A later drain re-proves the boundary.
    let profile = full_profile();
    let mut record = full_record();
    record.invalidate(&[pid(5)], ClosureGap::LateEvidence).unwrap();
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2), pid(3), pid(4)]);
    assert!(seen.invalidated().iter().any(|(p, g)| *p == pid(5) && *g == ClosureGap::LateEvidence));
    // Sample falls transitively: its prerequisite no longer stands.
    assert!(seen.invalidated().iter().any(|(p, g)| *p == pid(6) && *g == ClosureGap::LateEvidence));
    // Renewal needs a new record: duplicate observation refuses in this one.
    assert!(record
        .observe(PredicateObservation::new(pid(5), source(), BoundarySerial::new(7), 1))
        .is_err());
    // A new record with a later drain/sample attempt can satisfy them;
    // the new attempt re-establishes the whole chain in generation 1.
    let mut retry = ClosureRecord::new(epoch(), 16).unwrap();
    for (id, serial) in [(1, 1), (2, 2), (3, 3), (4, 4)] {
        observe(&mut retry, id, serial, 1);
    }
    observe(&mut retry, 5, 7, 1);
    observe(&mut retry, 6, 8, 1);
    let seen = assess_closure(&profile, &retry).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2), pid(3), pid(4), pid(5), pid(6)]);
    // The old record still shows the invalidation: history is not rewritten.
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2), pid(3), pid(4)]);
}

#[test]
fn late_admitted_event_after_final_drain_stays_partial() {
    // OSSL delayed-hit shape: the drain boundary was recorded, then an
    // admitted hit arrived late. The drain/sample pair cannot stand.
    let profile = full_profile();
    let mut record = full_record();
    record.invalidate(&[pid(5), pid(6)], ClosureGap::LateEvidence).unwrap();
    let seen = assess_closure(&profile, &record).unwrap();
    assert!(!seen.satisfied().contains(&pid(5)));
    assert!(!seen.satisfied().contains(&pid(6)));
    assert_eq!(seen.missing(), &[]);
}

#[test]
fn pending_writer_never_supplies_quiescence() {
    // Quiescence is an observed predicate, not the absence of a writer
    // record. A record that never observes 4 withholds 4/5/6 even when
    // every other predicate is present with ordered serials.
    let profile = full_profile();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    for (id, serial) in [(1, 1), (2, 2), (3, 3), (5, 5), (6, 6)] {
        observe(&mut record, id, serial, 0);
    }
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.missing(), &[pid(4)]);
    assert!(!seen.satisfied().contains(&pid(5)));
    assert!(!seen.satisfied().contains(&pid(6)));
    // The timeout-as-settled mutant (treat elapsed budget as quiescence)
    // would satisfy 4 without observing it; the assessment must not.
    assert!(!seen.satisfied().contains(&pid(4)));
}

#[test]
fn quiet_detach_does_not_fill_predicates() {
    // Quiet poll, detach and terminal markers supply no predicates: an
    // empty record reports every predicate missing, not settled.
    let profile = full_profile();
    let record = ClosureRecord::new(epoch(), 16).unwrap();
    let seen = assess_closure(&profile, &record).unwrap();
    assert!(seen.satisfied().is_empty());
    assert_eq!(seen.missing().len(), 6);
    // The return-final-on-quiet-poll mutant reports settled quiescence
    // and sample from silence; it must fail these missing assertions.
    assert!(!seen.satisfied().contains(&pid(4)), "quiet poll is not quiescence");
    assert!(!seen.satisfied().contains(&pid(6)), "quiet poll is not a sample");
    // The detach-as-quiescence mutant observes a non-predicate marker and
    // claims 4; unrequired observations are not predicates and change nothing.
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    record
        .observe(PredicateObservation::new(
            pid(99),
            source(),
            BoundarySerial::new(1),
            0,
        ))
        .unwrap();
    let seen = assess_closure(&profile, &record).unwrap();
    assert!(seen.satisfied().is_empty());
    assert_eq!(seen.missing().len(), 6);
    // Meanwhile an explicitly weaker bounded-drain profile reports only
    // its own predicates from the same record shape.
    let weak = ClosureProfile::new(1, &[pid(5)], &[], 64).unwrap();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    observe(&mut record, 5, 5, 0);
    let seen = assess_closure(&weak, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(5)]);
    assert!(seen.missing().is_empty());
}

#[test]
fn unresolved_cleanup_stays_visible() {
    let profile = full_profile();
    let mut record = full_record();
    record.invalidate(&[pid(4)], ClosureGap::UnresolvedCleanup).unwrap();
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(1), pid(2), pid(3)]);
    for id in [4, 5, 6] {
        assert!(
            seen.invalidated().iter().any(|(p, g)| *p == pid(id) && *g == ClosureGap::UnresolvedCleanup),
            "cleanup gap must propagate to {id}"
        );
    }
}

#[test]
fn kryprobe_every_slot_script_needs_each_obligation() {
    // KryProbe shape: every program/CPU obligation is its own predicate;
    // one missing slot withholds only its dependents, never the whole
    // record, and never synthesizes the missing slot.
    let profile = ClosureProfile::new(
        1,
        &[pid(10), pid(11), pid(12)],
        &[(pid(10), pid(12)), (pid(11), pid(12))],
        64,
    )
    .unwrap();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    observe(&mut record, 10, 1, 0);
    observe(&mut record, 12, 3, 0);
    let seen = assess_closure(&profile, &record).unwrap();
    assert_eq!(seen.satisfied(), &[pid(10)]);
    assert_eq!(seen.missing(), &[pid(11)]);
    assert!(!seen.satisfied().contains(&pid(12)));
}

fn fixture_pid(value: &Json) -> PredicateId {
    let id: u16 = value
        .as_u64()
        .expect("predicate id is a number")
        .try_into()
        .expect("predicate id fits u16");
    pid(id)
}

fn fixture_gap(name: &str, case: &str) -> ClosureGap {
    match name {
        "Missing" => ClosureGap::Missing,
        "LateEvidence" => ClosureGap::LateEvidence,
        "StaleSample" => ClosureGap::StaleSample,
        "UnresolvedCleanup" => ClosureGap::UnresolvedCleanup,
        "ContextChanged" => ClosureGap::ContextChanged,
        other => panic!("case {case}: unknown gap {other:?}"),
    }
}

fn run_closure_case(profile: &ClosureProfile, case: &Json) {
    let id = case.get("id").unwrap().as_str().unwrap();
    let mut record = ClosureRecord::new(epoch(), 16).unwrap();
    for item in case.get("observations").unwrap().as_arr().unwrap() {
        let triple = item.as_arr().unwrap();
        assert_eq!(triple.len(), 3, "case {id}: observation is [predicate, serial, drain]");
        record
            .observe(PredicateObservation::new(
                fixture_pid(&triple[0]),
                source(),
                BoundarySerial::new(triple[1].as_u64().unwrap()),
                triple[2].as_u64().unwrap(),
            ))
            .unwrap_or_else(|error| panic!("case {id}: scripted observation admits: {error:?}"));
    }
    for item in case.get("invalidations").unwrap().as_arr().unwrap() {
        let pair = item.as_arr().unwrap();
        assert_eq!(pair.len(), 2, "case {id}: invalidation is [predicate, gap]");
        record
            .invalidate(&[fixture_pid(&pair[0])], fixture_gap(pair[1].as_str().unwrap(), id))
            .unwrap_or_else(|error| panic!("case {id}: scripted invalidation admits: {error:?}"));
    }
    let expected = case.get("expected").unwrap();
    let want = |key: &str| -> Vec<PredicateId> {
        expected.get(key).unwrap().as_arr().unwrap().iter().map(fixture_pid).collect()
    };
    let seen = assess_closure(profile, &record).unwrap();
    assert_eq!(seen.satisfied().to_vec(), want("satisfied"), "case {id}: satisfied");
    assert_eq!(seen.missing().to_vec(), want("missing"), "case {id}: missing");
    // S195: compare full (predicate, gap) pairs — the old `|(id, _)|`
    // projection stayed green when every gap degraded to `Missing`.
    let want_invalidated: Vec<(PredicateId, ClosureGap)> = expected
        .get("invalidated")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|entry| {
            let pair = entry.as_arr().unwrap();
            assert_eq!(pair.len(), 2, "case {id}: expected invalidated is [predicate, gap]");
            (
                fixture_pid(&pair[0]),
                fixture_gap(pair[1].as_str().unwrap(), id),
            )
        })
        .collect();
    assert_eq!(
        seen.invalidated().to_vec(),
        want_invalidated,
        "case {id}: invalidated"
    );
}

#[test]
fn shipped_closure_vectors_match_the_script() {
    // The packaged JSON vectors are parsed strictly (invalid JSON fails
    // here, not silently) and every scripted case runs through the real
    // admission/assessment path with its expected sets compared.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/closure-v1.json");
    let text = std::fs::read_to_string(&path).expect("closure-v1.json ships with the package");
    assert!(text.len() < 8192, "vectors stay small");
    let root = json_mini::parse(&text).expect("closure-v1.json parses as strict JSON");
    assert_eq!(
        root.get("schema").unwrap().as_str().unwrap(),
        "scopebase.capture.closure-v1",
        "schema tag"
    );
    let version: u32 = root
        .get("version")
        .unwrap()
        .as_u64()
        .unwrap()
        .try_into()
        .expect("profile version fits u32");
    let predicates: Vec<PredicateId> =
        root.get("predicates").unwrap().as_arr().unwrap().iter().map(|entry| {
            fixture_pid(entry.get("id").unwrap())
        }).collect();
    let names: Vec<&str> = root
        .get("predicates")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|entry| entry.get("name").unwrap().as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["baseline", "admission", "closed", "quiescence", "drain", "sample"],
        "predicate script"
    );
    let edges: Vec<(PredicateId, PredicateId)> =
        root.get("edges").unwrap().as_arr().unwrap().iter().map(|entry| {
            let pair = entry.as_arr().unwrap();
            assert_eq!(pair.len(), 2, "edge is [from, to]");
            (fixture_pid(&pair[0]), fixture_pid(&pair[1]))
        }).collect();
    let profile = ClosureProfile::new(version, &predicates, &edges, 64).unwrap();
    assert_eq!(profile.version(), version, "fixture version is retained");
    let cases = root.get("cases").unwrap().as_arr().unwrap();
    assert_eq!(cases.len(), 6, "six scripted cases");
    for case in cases {
        run_closure_case(&profile, case);
    }
}
