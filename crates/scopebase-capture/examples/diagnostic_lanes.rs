// SPDX-License-Identifier: Apache-2.0
//! Separate diagnostics and typed facts; no producer, totals or policy inference.
use scopebase_capture::{
    domain::{BindingId, CaptureId, ChannelId, Epoch, Origin, ProducerId, SourceRef},
    loss::{fold_capped_signals, CappedLossSignal, LossFact, LossKind, LossMagnitude},
    quantity::{Count, Events, Records},
    ContractError,
};
fn main() -> Result<(), ContractError> {
    let source = SourceRef::new(
        Epoch::new(CaptureId::new([1; 16])?, ProducerId::new([2; 16])?, 0),
        BindingId::new([3; 32])?,
        Origin::Synthetic,
    );
    let signal = CappedLossSignal::new(
        source.clone(),
        ChannelId::new(1),
        fold_capped_signals(&[254, 4, 0], 255)?,
        255,
    )?;
    let records = LossFact::new(
        source.clone(),
        ChannelId::new(2),
        LossKind::Transport,
        LossMagnitude::<Records>::Exact(Count::new(3)),
    )?;
    let attribution = LossFact::new(
        source,
        ChannelId::new(3),
        LossKind::Attribution,
        LossMagnitude::<Events>::Unknown,
    )?;
    assert_eq!(signal.observed(), 255);
    assert_eq!(records.magnitude(), &LossMagnitude::Exact(Count::new(3)));
    assert_eq!(attribution.magnitude(), &LossMagnitude::Unknown);
    println!(
        "diagnostic signal: {} (cap {})",
        signal.observed(),
        signal.cap()
    );
    println!(
        "record loss: {:?}; attribution events: {:?}",
        records.magnitude(),
        attribution.magnitude()
    );
    Ok(())
}
