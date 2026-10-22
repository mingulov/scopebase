// SPDX-License-Identifier: Apache-2.0
//! CP05 normalized donor subsets and bounded, pure identity histories.
//! K d153f3aa / M 8307a17d; exact ranges and deliberately deferred bodies are
//! recorded in THIRD-PARTY-NOTICES.md and docs/issues/capture/generations.md.
#[path = "support/generation_models.rs"]
mod models;
#[path = "support/generation_oracle.rs"]
mod oracle;

use models::*;
use oracle::{Action, Journal, Outcome};
use scopebase_capture::{
    domain::{CaptureId, Epoch, ProducerId},
    generation::{require_generation, ObjectKey},
    ContractError,
};
use std::{
    cell::Cell,
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
};

fn epoch() -> Epoch {
    epoch_parts(1, 2, 0)
}
fn epoch_parts(c: u8, p: u8, n: u64) -> Epoch {
    Epoch::new(
        CaptureId::new([c; 16]).unwrap(),
        ProducerId::new([p; 16]).unwrap(),
        n,
    )
}
fn key(raw: u64, generation: u64) -> ObjectKey<u64> {
    ObjectKey::new(epoch(), raw, generation)
}
fn refusal<K: Eq>(a: &ObjectKey<K>, b: &ObjectKey<K>, label: &str) {
    assert!(!a.matches(b), "CP05:full-key matches {label}");
    assert!(a != b, "CP05:full-key PartialEq {label}");
    assert_eq!(
        require_generation(a, b),
        Err(ContractError::GenerationMismatch),
        "CP05:require mismatch {label}"
    );
}

#[test]
fn full_key_match_requires_every_component() {
    let raw = RawDomain::new("d1", "kvirt", "tok9");
    let a = ObjectKey::new(epoch(), raw.clone(), 7);
    let b = ObjectKey::new(epoch(), raw.clone(), 7);
    assert!(a.matches(&b));
    assert!(a == b);
    assert_eq!(require_generation(&a, &b), Ok(()));
    for (e, label) in [
        (epoch_parts(3, 2, 0), "capture"),
        (epoch_parts(1, 3, 0), "producer"),
        (epoch_parts(1, 2, 1), "epoch ordinal"),
    ] {
        refusal(&a, &ObjectKey::new(e, raw.clone(), 7), label);
    }
    for (r, label) in [
        (RawDomain::new("d2", "kvirt", "tok9"), "device"),
        (RawDomain::new("d1", "gphys", "tok9"), "namespace"),
        (RawDomain::new("d1", "kvirt", "tok8"), "handle"),
    ] {
        refusal(&a, &ObjectKey::new(epoch(), r, 7), label);
    }
    refusal(&a, &ObjectKey::new(epoch(), raw, 8), "generation");
}

#[test]
fn late_completion_does_not_match_successor() {
    let submitted = key(7, 0);
    let mut current = Some(key(7, 1));
    if require_generation(&submitted, current.as_ref().unwrap()).is_ok() {
        current = None;
    }
    assert!(current.is_some(), "CP05:P03 successor stays live");
    refusal(
        &submitted,
        &ObjectKey::new(epoch_parts(1, 2, 1), 7, 0),
        "foreign epoch",
    );
    let mut same = Some(key(7, 0));
    if require_generation(&submitted, same.as_ref().unwrap()).is_ok() {
        same = None;
    }
    assert!(same.is_none(), "current-bound positive retires");
}

#[test]
fn generation_zero_and_exact_max_are_valid() {
    let zero = key(0, 0);
    assert_eq!(
        (*zero.raw(), zero.generation()),
        (0, 0),
        "CP05:generic zero remains valid"
    );
    let one = zero.next_generation().unwrap();
    assert_eq!(one.generation(), 1);
    assert_eq!(*one.raw(), 0);
    assert_eq!(one.epoch(), zero.epoch());
    let max = key(0, u64::MAX - 1).next_generation().unwrap();
    assert_eq!(max.generation(), u64::MAX);
    assert_eq!(*max.raw(), 0);
    assert_eq!(key(0, u64::MAX).generation(), u64::MAX);
}

struct Probe {
    marker: u64,
    eqs: Rc<Cell<usize>>,
    clones: Rc<Cell<usize>>,
    panic_eq: Rc<Cell<bool>>,
    panic_clone: Rc<Cell<bool>>,
}
impl Probe {
    fn new(marker: u64) -> Self {
        Self {
            marker,
            eqs: Rc::new(Cell::new(0)),
            clones: Rc::new(Cell::new(0)),
            panic_eq: Rc::new(Cell::new(false)),
            panic_clone: Rc::new(Cell::new(false)),
        }
    }
    fn sibling(&self, marker: u64) -> Self {
        Self {
            marker,
            eqs: self.eqs.clone(),
            clones: self.clones.clone(),
            panic_eq: self.panic_eq.clone(),
            panic_clone: self.panic_clone.clone(),
        }
    }
}
impl Clone for Probe {
    fn clone(&self) -> Self {
        self.clones.set(self.clones.get() + 1);
        assert!(!self.panic_clone.get(), "payload clone panic");
        self.sibling(self.marker)
    }
}
impl PartialEq for Probe {
    fn eq(&self, other: &Self) -> bool {
        self.eqs.set(self.eqs.get() + 1);
        assert!(!self.panic_eq.get(), "payload equality panic");
        self.marker == other.marker
    }
}
impl Eq for Probe {}

#[test]
fn generation_max_refuses() {
    assert!(
        matches!(
            key(7, u64::MAX).next_generation(),
            Err(ContractError::ArithmeticOverflow)
        ),
        "CP05:P04 overflow refusal"
    );
    let p = Probe::new(19);
    let count = p.clones.clone();
    let max = ObjectKey::new(epoch(), p, u64::MAX);
    let result = max.next_generation();
    assert_eq!(count.get(), 0, "CP05:P06 overflow clone count");
    assert!(
        matches!(result, Err(ContractError::ArithmeticOverflow)),
        "CP05:P04 overflow refusal"
    );
    assert_eq!((max.generation(), max.raw().marker), (u64::MAX, 19));
    assert_eq!(max.epoch(), &epoch());
    let p = Probe::new(20);
    let count = p.clones.clone();
    let last = ObjectKey::new(epoch(), p, u64::MAX - 1);
    let next = last.next_generation().unwrap();
    assert_eq!(count.get(), 1);
    assert_eq!((next.generation(), next.raw().marker), (u64::MAX, 20));
}

#[test]
fn payload_traits_and_debug_preserve_boundaries() {
    struct NoDebug(&'static str);
    let secret = ObjectKey::new(epoch(), NoDebug("CP05_RAW_SECRET_7ea419d2"), 0);
    assert_eq!(secret.raw().0, "CP05_RAW_SECRET_7ea419d2");
    let text = format!("{secret:?}");
    assert!(
        !text.contains("CP05_RAW_SECRET_7ea419d2"),
        "CP05:P09 raw Debug redaction"
    );
    struct CloneOnly(u8);
    impl Clone for CloneOnly {
        fn clone(&self) -> Self {
            Self(self.0 + 1)
        }
    }
    let c = ObjectKey::new(epoch(), CloneOnly(9), 0);
    let next = c.next_generation().unwrap();
    assert_eq!(
        next.raw().0,
        10,
        "caller clone result retained without validation"
    );
    assert_eq!(c.clone().raw().0, 10);
    struct EqOnly;
    impl PartialEq for EqOnly {
        fn eq(&self, _: &Self) -> bool {
            true
        }
    }
    impl Eq for EqOnly {}
    assert!(ObjectKey::new(epoch(), EqOnly, 0).matches(&ObjectKey::new(epoch(), EqOnly, 0)));
    struct PartialOnly;
    impl PartialEq for PartialOnly {
        fn eq(&self, _: &Self) -> bool {
            true
        }
    }
    assert!(ObjectKey::new(epoch(), PartialOnly, 0) == ObjectKey::new(epoch(), PartialOnly, 0));
    fn send_sync<T: Send + Sync>() {}
    send_sync::<ObjectKey<u64>>();
}

#[test]
fn payload_panics_do_not_change_wrapper_fields() {
    // Each public relation is checked independently; harness inspection never
    // compares or clones the probe. Metadata refusal must precede callbacks.
    for relation in 0..3 {
        for metadata in 0..3 {
            for equal in [false, true] {
                let p = Probe::new(31);
                let calls = p.eqs.clone();
                let panic = p.panic_eq.clone();
                let other = ObjectKey::new(
                    if metadata == 1 {
                        epoch_parts(3, 2, 0)
                    } else {
                        epoch()
                    },
                    p.sibling(if equal { 31 } else { 32 }),
                    if metadata == 2 { 1 } else { 0 },
                );
                let a = ObjectKey::new(epoch(), p, 0);
                let compare = || match relation {
                    0 => a == other,
                    1 => a.matches(&other),
                    _ => require_generation(&a, &other).is_ok(),
                };
                let result = compare();
                assert_eq!(
                    calls.get(),
                    usize::from(metadata == 0),
                    "CP05:P07/P08 exact raw equality calls"
                );
                assert_eq!(result, metadata == 0 && equal);
                calls.set(0);
                panic.set(true);
                let result = catch_unwind(AssertUnwindSafe(compare));
                assert_eq!(
                    result.is_err(),
                    metadata == 0,
                    "metadata refusal suppresses payload panic"
                );
                assert_eq!(calls.get(), usize::from(metadata == 0));
                assert_eq!((a.generation(), a.raw().marker), (0, 31));
                assert_eq!(a.epoch(), &epoch());
            }
        }
    }
    let p = Probe::new(41);
    let calls = p.clones.clone();
    p.panic_clone.set(true);
    let a = ObjectKey::new(epoch(), p, 6);
    assert!(catch_unwind(AssertUnwindSafe(|| a.next_generation())).is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!((a.generation(), a.raw().marker), (6, 41));
    assert_eq!(a.epoch(), &epoch());
}

#[test]
fn unknown_ids_are_nonjoinable() {
    let mut r = Reader::default();
    assert!(r.observe(41, None));
    assert!(
        r.observe(42, None),
        "CP05:second unknown observation admitted"
    );
    assert_eq!(
        r.events,
        vec![41, 42],
        "CP05:unknown observations remain distinct"
    );
    assert_eq!(r.known.len(), 0);
    let mut r = Reader::default();
    assert!(r.observe(1, Some(key(0, 0))));
    assert!(r.observe(2, None));
    assert!(r.observe(3, Some(key(0, 1))));
    assert_eq!(r.events, vec![1, 2, 3]);
    assert_eq!(r.known.len(), 2);
    assert!(
        !r.observe(4, Some(key(0, 0))),
        "CP05:known duplicate refuses"
    );
}

#[test]
fn bounded_tombstone_eviction_returns_unknown() {
    for cap in [2, 3] {
        let mut k = KModel::new(cap);
        for raw in 1..=3 {
            k.allocate(raw, true);
            k.proved_retire(raw);
        }
        assert_eq!(k.evictions, usize::from(cap == 2));
        assert_eq!(
            k.continuity(1),
            if cap == 2 {
                Outcome::UnknownContinuity
            } else {
                Outcome::Matched
            },
            "CP05:evicted continuity unknown"
        );
        if cap == 2 {
            assert_eq!(k.retired_ids(), vec![2, 3]);
        }
    }
    let mut k = KModel::new(2);
    k.allocate(7, true);
    k.submit_destroy(0, 7);
    k.allocate(7, true);
    for raw in [8, 9] {
        k.allocate(raw, true);
        k.proved_retire(raw);
    }
    assert_eq!(
        k.complete_destroy(0).outcome,
        Some(Outcome::Mismatch),
        "known stale remains definite after unrelated eviction"
    );
    assert_eq!(k.current(7).unwrap().generation(), 2);
}

#[test]
fn compaction_does_not_rebind_pending_identity() {
    let mut k = KModel::new(2);
    k.allocate(1, true);
    k.proved_retire(1);
    k.allocate(2, true);
    k.proved_retire(2);
    k.allocate(7, true);
    k.submit_destroy(11, 7);
    k.allocate(8, true);
    k.proved_retire(8); // older tombstone shifts raw7's storage index
    assert_eq!(
        k.complete_destroy(11).outcome,
        Some(Outcome::Matched),
        "CP05:stable binding survives compaction"
    );
    assert!(k.current(7).is_none());
    assert_eq!(k.retired_ids(), vec![3, 4]);
    k.allocate(9, true);
    k.submit_config(12, 9);
    k.allocate(10, true);
    k.proved_retire(10);
    assert!(k.complete_config(12));
    assert_eq!(k.record(5).unwrap().config_revision, 1);
}

// The following seventeen cases preserve the selected donor assertion subsets,
// not the original runtime decoder, renderer, metrics schema or fixture archive.
#[test]
fn k_alloc_pair_assigns_generation_with_provenance() {
    let mut k = KModel::new(16);
    let p = Provenance::literal("kxcipher", 0x05, 0x8f, "entry-owner");
    assert!(k.submit_alloc(2, p.clone()));
    assert_eq!(k.records.len(), 0, "CP05:allocation entry emits no key");
    assert!(k.complete_alloc(2, 7, "kxcipher-sync-t07a"));
    assert_eq!(k.records.len(), 1);
    let r = &k.records[0];
    assert_eq!(r.key.generation(), 1);
    assert_eq!(r.provenance.name, "kxcipher");
    assert_eq!((r.provenance.alg_type, r.provenance.mask), (0x05, 0x8f));
    assert_eq!(r.provenance.driver, "kxcipher-sync-t07a");
    assert_eq!(
        r.provenance.origin, "entry-owner",
        "CP05:entry provenance retained"
    );
    assert_eq!(k.completed_allocs, 1);
}
#[test]
fn k_pending_table_bound_refuses() {
    for cap in [1, 2] {
        let mut k = KModel::new(cap);
        assert!(k.submit_alloc(2, Provenance::default()));
        assert_eq!(
            k.submit_alloc(4, Provenance::default()),
            cap == 2,
            "CP05:pending capacity refusal"
        );
        assert_eq!(k.complete_alloc(4, 7, "drv"), cap == 2);
        assert_eq!(
            k.records.len(),
            usize::from(cap == 2),
            "CP05:refused pair creates no key"
        );
    }
}
#[test]
fn k_alloc_after_proved_retire_assigns_fresh_id() {
    let mut k = KModel::new(16);
    k.allocate(7, true);
    k.proved_retire(7);
    k.allocate(7, true);
    assert_eq!(
        k.records
            .iter()
            .map(|r| r.key.generation())
            .collect::<Vec<_>>(),
        vec![1, 2],
        "CP05:fresh stable ids"
    );
    assert!(k.records[0].retired && !k.records[1].retired);
    assert!(k.reuse_exact());
}
#[test]
fn k_alloc_for_live_base_forces_retire_as_ambiguous() {
    let mut k = KModel::new(16);
    k.allocate(7, true);
    k.allocate(7, true);
    assert!(
        k.records[0].key != k.records[1].key,
        "CP05:forced reuse assigns distinct keys"
    );
    assert_eq!(
        (k.records[0].key.generation(), k.records[1].key.generation()),
        (1, 2)
    );
    assert!(
        k.records[0].retired && k.records[0].ambiguous,
        "CP05:forced boundary ambiguous"
    );
    assert!(!k.records[1].retired && !k.records[1].ambiguous);
    assert_eq!(k.forced, 1);
    assert!(!k.reuse_exact());
    let mut twin = KModel::new(16);
    twin.allocate(7, true);
    twin.proved_retire(7);
    twin.allocate(7, true);
    assert!(twin.reuse_exact());
}
#[test]
fn k_destroy_return_after_realloc_retires_nothing() {
    let mut k = KModel::new(16);
    k.allocate(7, true);
    k.submit_destroy(4, 7);
    k.allocate(7, true);
    let s = k.complete_destroy(4);
    assert_eq!(
        s.outcome,
        Some(Outcome::Mismatch),
        "CP05:stale completion refuses successor"
    );
    assert_eq!(
        k.current(7).map(|k| k.generation()),
        Some(2),
        "CP05:successor stays live"
    );
    assert_eq!(k.proved, 0);
    assert_eq!(k.stale, 1);
    assert!(k.records[0].ambiguous);
    let mut twin = KModel::new(16);
    twin.allocate(7, true);
    twin.submit_destroy(4, 7);
    assert_eq!(twin.complete_destroy(4).outcome, Some(Outcome::Matched));
    assert_eq!(twin.proved, 1);
}
#[test]
fn k_destroy_entry_unmapped_then_live_refuses() {
    let mut k = KModel::new(16);
    k.submit_destroy(2, 7);
    k.allocate(7, true);
    assert_eq!(
        k.complete_destroy(2).outcome,
        Some(Outcome::UnknownContinuity),
        "CP05:unbound destroy remains unknown"
    );
    assert_eq!((k.colliding, k.unknown, k.stale, k.proved), (1, 0, 0, 0));
    assert!(k.current(7).is_some(), "CP05:unbound newcomer untouched");
    assert!(!k.reuse_exact());
    let mut t = KModel::new(16);
    t.allocate(7, true);
    t.submit_destroy(2, 7);
    assert_eq!(t.complete_destroy(2).outcome, Some(Outcome::Matched));
}
#[test]
fn k_overlapping_destroy_second_return_goes_stale() {
    let mut k = KModel::new(16);
    k.allocate(7, true);
    k.submit_destroy(4, 7);
    k.submit_destroy(6, 7);
    assert_eq!(k.complete_destroy(4).outcome, Some(Outcome::Matched));
    assert_eq!(
        k.complete_destroy(6).outcome,
        Some(Outcome::Mismatch),
        "CP05:overlap second return stale"
    );
    assert_eq!(
        (k.proved, k.stale, k.unknown),
        (1, 1, 0),
        "CP05:one proved retirement"
    );
}
#[test]
fn k_config_return_after_realloc_unlinks() {
    let mut k = KModel::new(16);
    k.allocate(7, true);
    k.submit_config(4, 7);
    k.allocate(7, true);
    assert!(!k.complete_config(4), "CP05:stale config unlinked");
    assert_eq!((k.records[1].config_revision, k.records[1].configs), (0, 0));
    k.submit_config(5, 7);
    assert!(k.complete_config(5));
    assert_eq!(k.records[1].config_revision, 1);
}
#[test]
fn k_config_entry_unmapped_then_live_unlinks() {
    let mut k = KModel::new(16);
    k.submit_config(2, 7);
    k.allocate(7, true);
    assert!(!k.complete_config(2), "CP05:unbound config unlinked");
    assert_eq!(k.records.len(), 1);
    assert_eq!(k.records[0].config_revision, 0);
    k.submit_config(3, 7);
    assert!(k.complete_config(3));
    assert_eq!(k.records[0].config_revision, 1);
}
#[test]
fn k_config_after_retire_admits_fresh_never_merges() {
    let mut k = KModel::new(16);
    k.allocate(7, true);
    k.submit_config(4, 7);
    assert!(k.complete_config(4));
    k.proved_retire(7);
    // The missing creation boundary is a supplied fact, not an implementation
    // of the ungranted donor first-seen admission/configuration branch.
    assert!(k.allocate(7, false));
    assert_eq!(
        k.unknown_creation, 1,
        "CP05:first-seen uncertainty at admission"
    );
    k.submit_config(8, 7);
    assert!(k.complete_config(8));
    assert_eq!(k.records[1].config_revision, 1);
    assert_eq!(
        k.unknown_creation, 1,
        "CP05:first-seen uncertainty counted once"
    );
    k.submit_config(9, 7);
    assert!(k.complete_config(9));
    assert_eq!(
        k.unknown_creation, 1,
        "CP05:first-seen uncertainty counted once"
    );
    assert!(!k.reuse_exact());
    assert_eq!(
        (
            k.records[0].key.generation(),
            k.records[0].config_revision,
            k.records[0].retired
        ),
        (1, 1, true)
    );
    assert_eq!(
        (
            k.records[1].key.generation(),
            k.records[1].config_revision,
            k.records[1].creation_observed
        ),
        (2, 2, false)
    );
    let mut twin = KModel::new(16);
    twin.allocate(7, true);
    twin.submit_config(8, 7);
    assert!(twin.complete_config(8));
    assert_eq!(twin.unknown_creation, 0);
    assert!(twin.reuse_exact());
}
#[test]
fn k_d4_live_cap_refuses_new_generations() {
    for cap in [2, 4] {
        let mut k = KModel::new(cap);
        for (token, raw) in [(2, 7), (4, 8)] {
            k.submit_alloc(token, Provenance::default());
            assert!(k.complete_alloc(token, raw, "drv"));
        }
        k.submit_alloc(6, Provenance::default());
        assert_eq!(
            k.complete_alloc(6, 9, "drv"),
            cap == 4,
            "CP05:third live capacity refusal"
        );
        assert_eq!(
            k.live_len(),
            if cap == 2 { 2 } else { 3 },
            "CP05:refused third admission preserves live count"
        );
        assert_eq!(
            k.current(9).is_some(),
            cap == 4,
            "CP05:refused third raw absent"
        );
        assert_eq!(k.completed_allocs, 3);
        assert_eq!(
            k.allocate(10, false),
            cap == 4,
            "CP05:first-seen live capacity refusal"
        );
        assert_eq!(
            k.live_len(),
            if cap == 2 { 2 } else { 4 },
            "CP05:refused first-seen preserves live count"
        );
        assert_eq!(
            k.current(10).is_some(),
            cap == 4,
            "CP05:refused first-seen raw absent"
        );
        assert!(
            k.current(7).is_some() && k.current(8).is_some(),
            "CP05:live never evicted"
        );
    }
}
#[test]
fn k_d4_retired_history_is_fifo_bounded() {
    for cap in [2, 4] {
        let mut k = KModel::new(cap);
        for raw in 1..=4 {
            assert!(k.allocate(raw, true));
            k.proved_retire(raw);
        }
        assert_eq!(
            k.retired_ids(),
            if cap == 2 {
                vec![3, 4]
            } else {
                vec![1, 2, 3, 4]
            },
            "CP05:FIFO retained ids"
        );
        assert_eq!(k.evictions, if cap == 2 { 2 } else { 0 });
        assert!(k.allocate(7, true));
        assert_eq!(k.current(7).unwrap().generation(), 5);
    }
    // Keep the original four explicit retirements above, and make its promise
    // that only retired entries evict nonvacuous in this same named subset.
    for cap in [2, 4] {
        let mut k = KModel::new(cap);
        assert!(k.allocate(99, true));
        for raw in 1..=4 {
            assert!(k.allocate(raw, true));
            k.proved_retire(raw);
        }
        assert_eq!(
            k.current(99).map(|key| key.generation()),
            Some(1),
            "CP05:retired eviction preserves live identity"
        );
        assert_eq!(k.live_len(), 1);
        assert_eq!(
            k.retired_ids(),
            if cap == 2 {
                vec![4, 5]
            } else {
                vec![2, 3, 4, 5]
            }
        );
        assert_eq!(k.evictions, if cap == 2 { 2 } else { 0 });
    }
}
#[test]
fn m_test_pairing_key_namespaces() {
    let a = ObjectKey::new(epoch(), RawDomain::new("d000001", "kvirt", "tok9"), 1);
    let b = ObjectKey::new(epoch(), RawDomain::new("d000001", "gphys", "tok9"), 1);
    let c = ObjectKey::new(epoch(), RawDomain::new("d000001", "kvirt", "tok9"), 1);
    let d = ObjectKey::new(epoch(), RawDomain::new("d000002", "kvirt", "tok9"), 1);
    assert!(!a.matches(&b), "CP05:namespace identity differs");
    assert!(a.matches(&c));
    assert!(!a.matches(&d), "CP05:device identity differs");
}
#[test]
fn m_test_generation_positive() {
    assert!(local_lineage(1));
    assert!(!local_lineage(0), "CP05:local positive-only lineage");
    assert_eq!(key(0, 0).generation(), 0);
    assert_eq!(key(0, u64::MAX).generation(), u64::MAX);
}
#[test]
fn m_test_reused_generation_two_samples() {
    let mut m = Mappings::new(16, 16);
    assert!(m.map(key(7, 1), 512, 100));
    assert!(m.unmap(&key(7, 1), 150));
    assert!(m.map(key(7, 2), 512, 200));
    assert!(m.unmap(&key(7, 2), 260));
    assert_eq!(
        m.durations,
        vec![50, 60],
        "CP05:closed mapping generations retained"
    );
    assert_eq!(
        (
            m.durations.iter().sum::<u64>() / 2,
            *m.durations.iter().min().unwrap(),
            *m.durations.iter().max().unwrap()
        ),
        (55, 50, 60)
    );
    assert_eq!(m.successes, 2);
}
#[test]
fn m_test_retired_history_bounded() {
    for cap in [4, 6] {
        let mut m = Mappings::new(16, cap);
        for i in 0..6 {
            assert!(m.map(key(i, 1), 4096, 1000 + i));
            assert!(m.unmap(&key(i, 1), 1500 + i));
        }
        assert_eq!(m.durations.len(), 6);
        assert_eq!(m.evictions, if cap == 4 { 2 } else { 0 });
        assert_eq!(m.partial, cap == 4, "CP05:history qualification sticky");
        assert_eq!(
            m.continuity(&key(0, 1)),
            if cap == 4 {
                Outcome::UnknownContinuity
            } else {
                Outcome::Matched
            },
            "CP05:mapping eviction uncertainty"
        );
        assert_eq!(m.map(key(0, 1), 4096, 5000), cap == 4);
        if cap == 4 {
            assert_eq!(m.live_bytes(), 4096);
            assert!(m.partial, "CP05:qualification survives fresh map");
        }
    }
}
#[test]
fn m_test_multiple_unassigned_map_results() {
    unknown_ids_are_nonjoinable();
}

#[test]
fn literal_limits_duplicates_domains_and_overlaps() {
    let mut k = KModel::new(0);
    assert!(!k.allocate(7, true));
    assert_eq!(
        k.submit_destroy(0, 7).outcome,
        Some(Outcome::CapacityRefused)
    );
    let mut k = KModel::new(1);
    assert!(k.allocate(7, true));
    assert!(!k.allocate(8, true));
    assert!(k.current(7).is_some());
    let mut k = KModel::new(2);
    k.allocate(7, true);
    let first = k.submit_destroy(0, 7);
    assert!(first.bound);
    k.allocate(7, true);
    assert!(
        k.submit_destroy(0, 7).duplicate,
        "CP05:duplicate token flag"
    );
    assert_eq!(
        k.complete_destroy(0).outcome,
        Some(Outcome::Mismatch),
        "CP05:duplicate retains first binding"
    );
    k.submit_destroy(0, 7);
    k.submit_destroy(1, 7);
    assert_eq!(
        k.submit_destroy(2, 7).outcome,
        Some(Outcome::CapacityRefused)
    );
    let mut m = Mappings::new(2, 0);
    assert!(m.map(key(8, 1), 4096, 0));
    assert!(m.unmap(&key(8, 1), 1));
    assert_eq!(m.evictions, 0);
    assert!(m.partial);
    assert_eq!(m.continuity(&key(8, 1)), Outcome::UnknownContinuity);
    let mut m = Mappings::new(2, 2);
    assert!(m.map(key(8, 1), 7, 0));
    assert!(!m.unmap(&ObjectKey::new(epoch_parts(3, 2, 0), 8, 1), 1));
    assert_eq!(m.live_bytes(), 7);
    assert!(
        !m.map_unknown(7),
        "missing known identity creates no active mapping"
    );
    assert_eq!(m.live.len(), 1);
}

#[test]
fn bounded_histories_match_independent_oracle() {
    use Action::{Allocate7 as A, CompleteDestroy as C, ProvedRetire7 as R, SubmitDestroy as S};
    // Literal counter discriminators: stale without reuse and two unbound
    // submissions do not certify reused-old or bound-same-target overlap.
    for (script, want) in [
        (vec![A, S(0), R, C(0)], [0, 0, 0, 0]),
        (vec![S(0), S(1)], [0, 2, 0, 0]),
        (vec![A, S(0), S(1)], [0, 0, 1, 0]),
        (vec![A, S(0), A, C(0)], [1, 0, 0, 0]),
        (vec![A, A, A, A], [0, 0, 0, 1]),
    ] {
        let mut journal = Journal::new();
        let mut events = [0usize; 4];
        for action in script {
            journal.observe(action);
            for (n, event) in events.iter_mut().zip(journal.population_events()) {
                *n += usize::from(event);
            }
        }
        assert_eq!(events, want, "CP05:literal nonvacuity event labels");
    }
    let mut scripts = 0;
    let mut actions = 0;
    let mut triggers = [0usize; 4];
    for length in 0..=6 {
        for mut number in 0..6usize.pow(length) {
            let mut script = vec![Action::Allocate7; length as usize];
            for a in script.iter_mut().rev() {
                *a = Action::ALPHABET[number % 6];
                number /= 6;
            }
            let mut model = KModel::new(2);
            let mut truth = Journal::new();
            assert_eq!(model.projection(None), truth.projection(None));
            scripts += 1;
            for action in script {
                let got = model.step(action);
                let expected = truth.observe(action);
                actions += 1;
                assert_eq!(
                    model.projection(Some(got)),
                    truth.projection(Some(expected)),
                    "CP05:independent history every prefix {:?}",
                    truth.actions()
                );
                assert!(
                    model.pending.len() <= 2
                        && model.live_len() <= 2
                        && model.retired_ids().len() <= 2
                );
                assert!(truth.rows.len() <= 6);
                assert!(truth.fact_count() <= 18);
                truth.check_fact_ids();
                for (n, event) in triggers.iter_mut().zip(truth.population_events()) {
                    *n += usize::from(event);
                }
            }
        }
    }
    assert_eq!((scripts, actions), (55_987, 324_726));
    assert!(
        triggers.iter().all(|n| *n > 0),
        "CP05:nonzero reused/unbound/overlap/eviction populations {triggers:?}"
    );
    println!("CP05 population scripts={scripts} actions={actions} triggers={triggers:?}; journal_rows<=6 facts<=18");
}
