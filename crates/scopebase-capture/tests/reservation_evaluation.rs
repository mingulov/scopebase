// SPDX-License-Identifier: Apache-2.0
//! CP12: cross-stage reservation evaluation with a gated internal pilot.
//!
//! The pilot under test lives in `support/reservation_pilot.rs` and is
//! test-only: it is never exported from `lib.rs` and gains no feature.
//! Expected charges come from the independent [`pilot::ReservationOracle`],
//! which enumerates live payload allocations from its own log and never
//! reads pilot totals to compute them.
#[path = "support/reservation_pilot.rs"]
mod pilot;

use pilot::{PilotBudget, ReservationOracle, StageId};
use scopebase_capture::ContractError;

const STAGING: StageId = StageId(0);
const RETAINED: StageId = StageId(1);

#[test]
fn one_global_budget_across_stages() {
    let mut pilot = PilotBudget::new(2, Some(16)).unwrap();
    let mut oracle = ReservationOracle::new(2, Some(16));
    // Two 8-byte payloads succeed against the one global budget.
    let a = pilot.reserve(1, 8).unwrap();
    let oa = oracle.reserve(1, 8).expect("CP12:oracle admits");
    let b = pilot.reserve(1, 8).unwrap();
    let ob = oracle.reserve(1, 8).expect("CP12:oracle admits");
    oracle.check(&pilot);
    assert_eq!((pilot.charged_counts(), pilot.charged_bytes()), (2, 16));
    // A third 1-byte payload refuses: the count ceiling is global, and the
    // byte pool is full. Rejection preserves prior state.
    let err = pilot.reserve(1, 1).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:third refuses");
    assert_eq!(oracle.reserve(1, 1), None, "CP12:oracle agrees");
    oracle.check(&pilot);
    // Staging -> retained keeps the global total at 16 charged bytes.
    let a = a.transfer(RETAINED).unwrap_or_else(|_| panic!("CP12:move stages"));
    oracle.transfer(oa, RETAINED);
    assert_eq!(a.stage(), RETAINED);
    oracle.check(&pilot);
    assert_eq!(pilot.charged_bytes(), 16, "CP12:move keeps charge");
    // One per-stage budget per stage would admit a third payload; the shared
    // pilot refuses it even though the destination stage holds only one.
    let err = pilot.reserve(1, 1).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:global, not per-stage");
    pilot.retire(a);
    oracle.retire(oa);
    pilot.retire(b);
    oracle.retire(ob);
    oracle.check(&pilot);
    assert_eq!((pilot.charged_counts(), pilot.charged_bytes()), (0, 0));
    let _ = STAGING;
}

#[test]
fn failed_transfer_returns_same_charge() {
    let mut pilot = PilotBudget::new(2, Some(16)).unwrap();
    let mut oracle = ReservationOracle::new(2, Some(16));
    let a = pilot.reserve(1, 8).unwrap();
    let oa = oracle.reserve(1, 8).expect("CP12:oracle admits");
    let b = pilot.reserve(1, 8).unwrap();
    let ob = oracle.reserve(1, 8).expect("CP12:oracle admits");
    // Moving a ticket into the stage it already occupies refuses and hands
    // back the very same reservation: same ticket, same charge.
    let ticket = a.ticket();
    let (back, err) = a.transfer(STAGING).unwrap_err();
    assert_eq!(err, ContractError::DuplicateKey, "CP12:same-stage refuses");
    assert_eq!(back.ticket(), ticket, "CP12:same ticket returned");
    assert_eq!((back.count(), back.bytes()), (1, 8), "CP12:same charge returned");
    assert_eq!(pilot.charged_bytes(), 16, "CP12:failed transfer leaves 16");
    oracle.check(&pilot);
    pilot.retire(back);
    oracle.retire(oa);
    pilot.retire(b);
    oracle.retire(ob);
    oracle.check(&pilot);
}

#[test]
fn cancel_refunds_only_after_payload_retired() {
    let mut pilot = PilotBudget::new(2, Some(16)).unwrap();
    let mut oracle = ReservationOracle::new(2, Some(16));
    let a = pilot.reserve(1, 8).unwrap();
    let oa = oracle.reserve(1, 8).expect("CP12:oracle admits");
    // Cancelling a live ticket marks custody but refunds nothing while any
    // payload owner is alive.
    assert!(pilot.cancel(a.ticket()), "CP12:live ticket cancels");
    oracle.cancel(oa);
    assert_eq!(pilot.charged_bytes(), 8, "CP12:cancel keeps live charge");
    // Repeated cleanup is stable: second cancel marks nothing new.
    assert!(!pilot.cancel(a.ticket()), "CP12:cancel is one-shot");
    assert_eq!(pilot.charged_bytes(), 8, "CP12:recancel keeps charge");
    oracle.check(&pilot);
    // Only the last owner's retirement releases the charge.
    let shared = a.shared_clone();
    pilot.retire(a);
    assert_eq!(pilot.charged_bytes(), 8, "CP12:first retire keeps charge");
    pilot.retire(shared);
    oracle.retire(oa);
    assert_eq!(pilot.charged_bytes(), 0, "CP12:last retire refunds");
    oracle.check(&pilot);
}

#[test]
fn shared_clone_not_double_charged() {
    let mut pilot = PilotBudget::new(2, Some(16)).unwrap();
    let mut oracle = ReservationOracle::new(2, Some(16));
    let a = pilot.reserve(1, 8).unwrap();
    let oa = oracle.reserve(1, 8).expect("CP12:oracle admits");
    let b = pilot.reserve(1, 8).unwrap();
    let ob = oracle.reserve(1, 8).expect("CP12:oracle admits");
    // A shared clone aliases the same payload allocation: no new ticket,
    // no new charge. The pool stays full at 16.
    let alias = a.shared_clone();
    assert_eq!(alias.ticket(), a.ticket(), "CP12:alias keeps ticket");
    assert_eq!(pilot.charged_bytes(), 16, "CP12:alias leaves 16");
    assert_eq!(pilot.live_tickets(), 2, "CP12:alias adds no ticket");
    oracle.check(&pilot);
    pilot.retire(a);
    assert_eq!(pilot.charged_bytes(), 16, "CP12:aliased charge retained");
    pilot.retire(alias);
    oracle.retire(oa);
    pilot.retire(b);
    oracle.retire(ob);
    oracle.check(&pilot);
}

#[test]
fn independent_copy_is_charged() {
    let mut pilot = PilotBudget::new(2, Some(16)).unwrap();
    let mut oracle = ReservationOracle::new(2, Some(16));
    let a = pilot.reserve(1, 8).unwrap();
    let oa = oracle.reserve(1, 8).expect("CP12:oracle admits");
    let b = pilot.reserve(1, 8).unwrap();
    let ob = oracle.reserve(1, 8).expect("CP12:oracle admits");
    // An independent 8-byte copy is a new payload allocation, not an alias:
    // while the pool is full it refuses instead of aliasing silently.
    let err = pilot.reserve(1, 8).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:copy refuses when full");
    assert_eq!(oracle.reserve(1, 8), None, "CP12:oracle agrees");
    oracle.check(&pilot);
    // After one payload retires, the copy fits and carries its own ticket.
    pilot.retire(a);
    oracle.retire(oa);
    let copy = pilot.reserve(1, 8).unwrap();
    let ocopy = oracle.reserve(1, 8).expect("CP12:oracle admits");
    assert_ne!(copy.ticket(), b.ticket(), "CP12:copy owns a ticket");
    assert_eq!(pilot.charged_bytes(), 16, "CP12:copy is charged");
    oracle.check(&pilot);
    pilot.retire(b);
    oracle.retire(ob);
    pilot.retire(copy);
    oracle.retire(ocopy);
    oracle.check(&pilot);
}

#[test]
fn absent_byte_limit_cannot_claim_memory_bound() {
    // A count-only pilot admits any byte size and reports its byte
    // guarantee as unknown: there is no byte number to quote.
    let mut pilot = PilotBudget::new(2, None).unwrap();
    assert_eq!(pilot.byte_guarantee(), None, "CP12:bytes unknown");
    let a = pilot.reserve(1, u64::MAX).unwrap();
    assert_eq!(pilot.byte_guarantee(), None, "CP12:still unknown");
    assert_eq!(pilot.charged_counts(), 1, "CP12:counts still bounded");
    let err = pilot.reserve(u64::MAX, 0).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:count ceiling holds");
    pilot.retire(a);
    // Freezing a reviewed limit afterwards restores byte refusal, but the
    // count-only phase never retroactively gains a memory bound.
    pilot.set_byte_limit(16);
    assert_eq!(pilot.byte_guarantee(), Some(16));
    let err = pilot.reserve(1, 17).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:frozen limit refuses");
}

#[test]
fn conversion_peak_overlap_is_recorded() {
    let mut pilot = PilotBudget::new(4, Some(32)).unwrap();
    let mut oracle = ReservationOracle::new(4, Some(32));
    // A conversion temporarily holds input and output together; the peak
    // records the overlap even after the input retires.
    let input = pilot.reserve(1, 8).unwrap();
    let oinput = oracle.reserve(1, 8).expect("CP12:oracle admits");
    let output = pilot.reserve(1, 8).unwrap();
    let ooutput = oracle.reserve(1, 8).expect("CP12:oracle admits");
    assert_eq!(pilot.charged_bytes(), 16);
    pilot.retire(input);
    oracle.retire(oinput);
    assert_eq!(pilot.charged_bytes(), 8, "CP12:input retired");
    assert_eq!(pilot.peak_bytes(), 16, "CP12:peak keeps overlap");
    assert_eq!(oracle.peak_bytes(), 16, "CP12:oracle agrees on peak");
    oracle.check(&pilot);
    pilot.retire(output);
    oracle.retire(ooutput);
    oracle.check(&pilot);
}

#[test]
fn max_boundary_refuses_without_wrap() {
    let mut pilot = PilotBudget::new(u64::MAX, Some(u64::MAX)).unwrap();
    let mut oracle = ReservationOracle::new(u64::MAX, Some(u64::MAX));
    let a = pilot.reserve(u64::MAX, u64::MAX).unwrap();
    let oa = oracle.reserve(u64::MAX, u64::MAX).expect("CP12:oracle admits MAX");
    oracle.check(&pilot);
    // Any further unit refuses against the ceiling; the running total never
    // wraps, the refusal preserves state and mints no ticket, and the
    // oracle independently agrees on every refusal.
    let err = pilot.reserve(1, 0).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:count ceiling");
    assert_eq!(oracle.reserve(1, 0), None, "CP12:oracle agrees");
    let err = pilot.reserve(0, 1).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:byte ceiling");
    assert_eq!(oracle.reserve(0, 1), None, "CP12:oracle agrees");
    assert_eq!(
        (pilot.charged_counts(), pilot.charged_bytes()),
        (u64::MAX, u64::MAX),
        "CP12:refusal preserves totals"
    );
    assert_eq!(pilot.live_tickets(), 1, "CP12:refusal mints no ticket");
    oracle.check(&pilot);
    pilot.retire(a);
    oracle.retire(oa);
    oracle.check(&pilot);
    assert_eq!((pilot.charged_counts(), pilot.charged_bytes()), (0, 0));
}

#[test]
fn per_stage_budgets_overadmit() {
    // Bad control: one independent budget per stage. Each stage fits 16
    // bytes, so the pair jointly holds 32 live bytes against a global
    // allowance of 16. The control passes by proving the mutant violates
    // the global cap the shared pilot enforces.
    let mut staging = PilotBudget::new(2, Some(16)).unwrap();
    let mut retained = PilotBudget::new(2, Some(16)).unwrap();
    let _ = staging.reserve(1, 8).unwrap();
    let _ = staging.reserve(1, 8).unwrap();
    let _ = retained.reserve(1, 8).unwrap();
    let _ = retained.reserve(1, 8).unwrap();
    let joint = staging.charged_bytes() + retained.charged_bytes();
    assert_eq!(joint, 32, "CP12:mutant setup holds 32");
    assert!(
        joint > 16,
        "CP12:per-stage budgets over-admit the global pool"
    );
}

#[test]
fn early_refund_loses_retained_charge() {
    // Bad control: refund the ticket at cancel time. The ledger reports 0
    // while the payload allocation is still alive, contradicting the live
    // allocation census. The control passes by proving the mutant lies.
    let mut pilot = PilotBudget::new(2, Some(16)).unwrap();
    let live = pilot.reserve(1, 8).unwrap();
    let mut early_refund_ledger: u64 = 8;
    assert!(pilot.cancel(live.ticket()));
    early_refund_ledger -= 8; // mutant: refund at cancel
    assert_eq!(early_refund_ledger, 0, "CP12:mutant reports empty");
    assert_eq!(pilot.charged_bytes(), 8, "CP12:pilot retains live charge");
    assert!(
        early_refund_ledger < pilot.charged_bytes(),
        "CP12:early refund under-reports retained bytes"
    );
    pilot.retire(live);
}
