// SPDX-License-Identifier: Apache-2.0
//! CP12 KryProbe-shaped stage experiment: ten events flow through
//! ingest -> fold -> report against one shared budget. NEW (CP12):
//! experiment-local, no donor lines copied.
use capture_kryprobe_reference::stage_pipeline::{StagePipeline, FOLD, INGEST, REPORT};
use scopebase_capture::ContractError;

#[test]
fn ten_events_flow_ingest_fold_report() {
    let mut pipe = StagePipeline::new(10, Some(80));
    let mut held = Vec::new();
    for _ in 0..10 {
        held.push(pipe.reserve(1, 8).expect("CP12:within shared budget"));
    }
    assert_eq!((pipe.charged_counts(), pipe.charged_bytes()), (10, 80));
    // An eleventh event refuses against the global pool even though every
    // single stage would fit it alone.
    let err = pipe.reserve(1, 1).unwrap_err();
    assert_eq!(err, ContractError::CapacityExceeded, "CP12:global cap");
    // Every event moves ingest -> fold -> report; the charge is unchanged
    // by stage moves and the peak records the full overlap.
    for r in held.iter() {
        assert_eq!(r.stage(), INGEST);
    }
    let mut held: Vec<_> = held
        .into_iter()
        .map(|r| r.transfer(FOLD).unwrap_or_else(|_| panic!("CP12:to fold")))
        .map(|r| {
            r.transfer(REPORT)
                .unwrap_or_else(|_| panic!("CP12:to report"))
        })
        .collect();
    assert_eq!(pipe.charged_bytes(), 80, "CP12:moves keep charge");
    assert_eq!(pipe.peak_bytes(), 80, "CP12:peak records overlap");
    // A failed move returns the same reservation with its charge intact.
    let last = held.pop().unwrap();
    let ticket = last.ticket();
    let (back, err) = last.transfer(REPORT).unwrap_err();
    assert_eq!(err, ContractError::DuplicateKey, "CP12:same-stage refuses");
    assert_eq!(back.ticket(), ticket, "CP12:same ticket back");
    assert_eq!(
        (back.count(), back.bytes()),
        (1, 8),
        "CP12:same charge back"
    );
    assert_eq!(pipe.charged_bytes(), 80, "CP12:failed move keeps 80");
    held.push(back);
    for r in held {
        pipe.retire(r);
    }
    assert_eq!((pipe.charged_counts(), pipe.charged_bytes()), (0, 0));
}
