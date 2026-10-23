// SPDX-License-Identifier: Apache-2.0
//! CP12 MemVeil-shaped stage experiment: observations flow observe -> view
//! under pool pressure; shared views alias, independent copies charge, and
//! cancellation retains until retirement. NEW (CP12): experiment-local, no
//! donor lines copied.
use capture_memveil_reference::stage_pipeline::{StagePipeline, OBSERVE, VIEW};
use scopebase_capture::ContractError;

#[test]
fn pool_pressure_views_copies_and_cancel() {
    let mut pipe = StagePipeline::new(2, Some(16));
    let obs = pipe.reserve(1, 8).expect("CP12:first observes");
    assert_eq!(obs.stage(), OBSERVE);
    let view = obs
        .transfer(VIEW)
        .unwrap_or_else(|_| panic!("CP12:to view"));
    // A shared view aliases the observation: no new ticket, no new charge.
    let alias = view.shared_clone();
    assert_eq!(alias.ticket(), view.ticket(), "CP12:alias keeps ticket");
    assert_eq!(pipe.charged_bytes(), 8, "CP12:alias uncharged");
    let _ = pipe.reserve(1, 8).expect("CP12:second observes");
    assert_eq!(pipe.charged_bytes(), 16, "CP12:pool full");
    // Pool pressure: a third observation refuses loudly; nothing is
    // silently dropped and no silent eviction frees room.
    let err = pipe.reserve(1, 8).unwrap_err();
    assert_eq!(
        err,
        ContractError::CapacityExceeded,
        "CP12:pressure refuses"
    );
    assert_eq!(pipe.live_tickets(), 2, "CP12:no silent eviction");
    // Cancellation retains the live charge until the last view retires.
    assert!(pipe.cancel(view.ticket()), "CP12:live ticket cancels");
    assert_eq!(pipe.charged_bytes(), 16, "CP12:cancel retains");
    pipe.retire(view);
    assert_eq!(pipe.charged_bytes(), 16, "CP12:aliased charge retained");
    pipe.retire(alias);
    assert_eq!(pipe.charged_bytes(), 8, "CP12:last view refunds");
    // The freed room admits one independent copy with its own ticket.
    let copy = pipe.reserve(1, 8).expect("CP12:copy fits");
    assert_eq!(pipe.live_tickets(), 2, "CP12:copy owns a ticket");
    pipe.retire(copy);
}

#[test]
fn count_only_pool_reports_bytes_unknown() {
    // Without a frozen byte limit the pool bounds observations but quotes
    // no byte guarantee: pool pressure is count pressure only.
    let mut pipe = StagePipeline::new(1, None);
    assert_eq!(pipe.byte_guarantee(), None, "CP12:bytes unknown");
    let obs = pipe.reserve(1, 1 << 40).expect("CP12:any bytes admit");
    assert_eq!(pipe.byte_guarantee(), None, "CP12:still unknown");
    let err = pipe.reserve(1, 0).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:count pressure");
    pipe.retire(obs);
    assert_eq!(pipe.charged_counts(), 0);
}
