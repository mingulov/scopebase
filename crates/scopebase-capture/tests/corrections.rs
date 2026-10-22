// SPDX-License-Identifier: Apache-2.0
#[path = "support/cp06_cases.rs"]
mod cases;
use cases::*;
use scopebase_capture::{correction::*, ContractError};
fn apply<T>(v: Versioned<T>, c: Correction<T>) -> Versioned<T> {
    match v.apply(c) {
        Ok(v) => v,
        Err(_) => panic!("CP06:valid correction"),
    }
}
#[test]
fn correction_is_exact_next_revision() {
    let v = Versioned::new(epoch(), "A");
    let v = apply(v, Correction::new(epoch(), Revision::new(0), "B").unwrap());
    assert_eq!(
        (v.revision(), *v.value()),
        (Revision::new(1), "B"),
        "CP06:exact next"
    );
    let result = v.apply(Correction::new(epoch(), Revision::new(0), "C").unwrap());
    assert!(result.is_err(), "CP06:stale refuses");
    let (v, e) = result.err().unwrap();
    assert_eq!(e, ContractError::StaleRevision, "CP06:stale refuses");
    assert_eq!(*v.value(), "B");
    let v = apply(v, Correction::new(epoch(), Revision::new(1), "D").unwrap());
    assert_eq!((v.revision(), *v.value()), (Revision::new(2), "D"));
    let result = Versioned::new(epoch(), "A")
        .apply(Correction::new(epoch(), Revision::new(1), "B").unwrap());
    assert!(result.is_err(), "CP06:premature refuses");
    let (v, e) = result.err().unwrap();
    assert_eq!(e, ContractError::StaleRevision);
    assert_eq!(*v.value(), "A");
}
#[test]
fn foreign_epoch_precedes_stale() {
    for e in foreign_epochs() {
        let (v, error) = Versioned::new(epoch(), "A")
            .apply(Correction::new(e, Revision::new(1), "B").unwrap())
            .err()
            .unwrap();
        assert_eq!(
            error,
            ContractError::DomainMismatch,
            "CP06:correction full epoch first"
        );
        assert_eq!((v.revision(), *v.value()), (Revision::new(0), "A"));
    }
}
#[test]
fn revision_overflow_is_explicit() {
    match Correction::new(epoch(), Revision::new(u64::MAX), "B") {
        Err(ContractError::ArithmeticOverflow) => {}
        _ => panic!("CP06:checked next revision"),
    }
    assert!(Correction::new(epoch(), Revision::new(u64::MAX - 1), "B").is_ok());
}
#[test]
fn foreign_epoch_payload_drop_journal() {
    use std::{cell::RefCell, rc::Rc};
    struct P {
        label: &'static str,
        log: Rc<RefCell<Vec<&'static str>>>,
    }
    impl Drop for P {
        fn drop(&mut self) {
            self.log.borrow_mut().push(self.label);
        }
    }
    let log = Rc::new(RefCell::new(Vec::new()));
    let p = |label| P {
        label,
        log: log.clone(),
    };
    // Foreign epoch with exact revision, then foreign-plus-stale: epoch is
    // checked before revision in both, and the rejected payload must drop
    // exactly once before the caller disposes the returned original.
    let mut cases = Vec::new();
    for e in foreign_epochs() {
        cases.push((e, 0, "rejected-exact"));
    }
    cases.push((foreign_epochs()[0].clone(), 5, "rejected-stale"));
    for (e, from, label) in cases {
        log.borrow_mut().clear();
        let holder = Versioned::new(epoch(), p("original"));
        let correction = Correction::new(e, Revision::new(from), p(label)).unwrap();
        let (holder, error) = holder.apply(correction).err().unwrap();
        assert_eq!(error, ContractError::DomainMismatch);
        assert_eq!(holder.revision(), Revision::new(0));
        assert_eq!(
            holder.value().label,
            "original",
            "CP06:foreign keeps original"
        );
        assert_eq!(
            *log.borrow(),
            [label],
            "CP06:foreign refusal drops replacement only"
        );
        drop(holder);
        assert_eq!(*log.borrow(), [label, "original"]);
    }
}
#[test]
fn same_metadata_does_not_identify_a_target() {
    let a = Versioned::new(epoch(), "wrong target");
    let a = apply(
        a,
        Correction::new(epoch(), Revision::new(0), "replacement").unwrap(),
    );
    assert_eq!(
        *a.value(),
        "replacement",
        "CP06:primitive has no target key"
    );
}
#[test]
fn revision_journal_all_781_scripts() {
    let (mut count, mut actions) = (0, 0);
    scripts(5, 4, |s| {
        count += 1;
        actions += s.len();
        let mut holder = Versioned::new(epoch(), "START");
        let mut accepted = Vec::new();
        for (i, &a) in s.iter().enumerate() {
            if a == 4 {
                error(
                    Correction::new(epoch(), Revision::new(u64::MAX), "E"),
                    ContractError::ArithmeticOverflow,
                );
                continue;
            }
            let (from, value, foreign) = match a {
                0 => (0, "A", false),
                1 => (1, "B", false),
                2 => (0, "C", false),
                3 => (0, "D", true),
                _ => unreachable!(),
            };
            let expected_revision = [0, 1, 2, 3, 4][accepted.len()];
            let correction = Correction::new(
                if foreign {
                    foreign_epochs()[0].clone()
                } else {
                    epoch()
                },
                Revision::new(from),
                value,
            )
            .unwrap();
            match holder.apply(correction) {
                Ok(v) => {
                    assert!(
                        !foreign && from == expected_revision,
                        "CP06:journal admits only exact next"
                    );
                    accepted.push((i, value));
                    holder = v;
                }
                Err((v, e)) => {
                    assert_eq!(
                        e,
                        if foreign {
                            ContractError::DomainMismatch
                        } else {
                            ContractError::StaleRevision
                        }
                    );
                    assert!(foreign || from != expected_revision);
                    holder = v;
                }
            }
            let expected = accepted.last().map(|&(_, v)| v).unwrap_or("START");
            assert_eq!(
                (holder.revision(), *holder.value()),
                (Revision::new([0, 1, 2, 3, 4][accepted.len()]), expected),
                "CP06:revision journal {s:?} {i}"
            );
        }
    });
    assert_eq!((count, actions), (781, 2930));
}
#[test]
fn generic_trait_and_drop_boundary() {
    struct NoTraits;
    let v = Versioned::new(epoch(), NoTraits);
    let _ = apply(
        v,
        Correction::new(epoch(), Revision::new(0), NoTraits).unwrap(),
    );
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<Versioned<u8>>();
    sync::<Correction<u8>>();
}
#[test]
fn ordinary_drop_effects_and_unwind_boundary() {
    use std::{
        cell::RefCell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };
    struct P {
        label: &'static str,
        log: Rc<RefCell<Vec<&'static str>>>,
        panic: bool,
    }
    impl Drop for P {
        fn drop(&mut self) {
            self.log.borrow_mut().push(self.label);
            assert!(!self.panic, "CP06:ordinary payload panic");
        }
    }
    let log = Rc::new(RefCell::new(Vec::new()));
    let p = |label, panic| P {
        label,
        panic,
        log: log.clone(),
    };
    let (v, e) = Versioned::new(epoch(), p("original", false))
        .apply(Correction::new(epoch(), Revision::new(1), p("rejected", false)).unwrap())
        .err()
        .unwrap();
    assert_eq!(e, ContractError::StaleRevision);
    assert_eq!(
        *log.borrow(),
        ["rejected"],
        "CP06:refusal drops replacement only"
    );
    drop(v);
    assert_eq!(*log.borrow(), ["rejected", "original"]);
    log.borrow_mut().clear();
    let v = apply(
        Versioned::new(epoch(), p("old", false)),
        Correction::new(epoch(), Revision::new(0), p("new", false)).unwrap(),
    );
    assert_eq!(*log.borrow(), ["old"], "CP06:success retires old");
    drop(v);
    assert_eq!(*log.borrow(), ["old", "new"]);
    log.borrow_mut().clear();
    error(
        Correction::new(epoch(), Revision::new(u64::MAX), p("overflow", false)),
        ContractError::ArithmeticOverflow,
    );
    assert_eq!(*log.borrow(), ["overflow"]);
    for kind in 0..3 {
        log.borrow_mut().clear();
        let result = catch_unwind(AssertUnwindSafe(|| match kind {
            0 => {
                let _ =
                    Correction::new(epoch(), Revision::new(u64::MAX), p("overflow-panic", true));
            }
            1 => {
                let _ = Versioned::new(epoch(), p("original", false)).apply(
                    Correction::new(epoch(), Revision::new(1), p("replacement-panic", true))
                        .unwrap(),
                );
            }
            _ => {
                let _ = Versioned::new(epoch(), p("old-panic", true))
                    .apply(Correction::new(epoch(), Revision::new(0), p("new", false)).unwrap());
            }
        }));
        assert!(result.is_err(), "CP06:Drop panic propagates"); // Root C07 ruling 29a9a1a7: a panic prevents the normal return;
                                                                // ordinary unwind MAY retire other owners but promises neither that event nor order.
        let events = log.borrow();
        let (panicking, other) = match kind {
            0 => ("overflow-panic", None),
            1 => ("replacement-panic", Some("original")),
            _ => ("old-panic", Some("new")),
        };
        assert_eq!(
            events.iter().filter(|&&e| e == panicking).count(),
            1,
            "CP06:panicking destructor once"
        );
        assert!(
            events.iter().all(|&e| e == panicking || Some(e) == other),
            "CP06:no impossible unwind events"
        );
        if let Some(other) = other {
            assert!(
                events.iter().filter(|&&e| e == other).count() <= 1,
                "CP06:no duplicate other retirement"
            );
        }
        eprintln!("CP06:observed unwind kind={kind} events={events:?}; other owner retirement is not promised");
    }
}
