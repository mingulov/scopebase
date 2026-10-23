// SPDX-License-Identifier: Apache-2.0
//! Partial queries disappear in the next view; consumed loss persists.
//! NEW (CP11): reference-only; no donor lines copied.
use scopebase_capture::{
    domain::{BindingId, CaptureId, ChannelId, ClaimId, Epoch, Origin, ProducerId, SourceRef},
    loss::{LossFact, LossKind, LossMagnitude},
    quantity::{Count, Events},
    view::{ClaimLedger, LedgerLimits, QualityReason, QueryOverlay},
    ContractError,
};

fn source() -> Result<SourceRef, ContractError> {
    Ok(SourceRef::new(
        Epoch::new(CaptureId::new([41; 16])?, ProducerId::new([42; 16])?, 0),
        BindingId::new([43; 32])?,
        Origin::Synthetic,
    ))
}

fn open_ledger() -> Result<ClaimLedger, ContractError> {
    ClaimLedger::new(
        Epoch::new(CaptureId::new([41; 16])?, ProducerId::new([42; 16])?, 0),
        LedgerLimits {
            claims: 4,
            reasons_per_claim: 2,
            loss_facts: 4,
        },
    )
}

fn main() -> Result<(), ContractError> {
    let mut ledger = open_ledger()?;
    let loss = LossFact::new(
        source()?,
        ChannelId::new(0),
        LossKind::Transport,
        LossMagnitude::Exact(Count::<Events>::new(2)),
    )?;
    ledger.record_loss(&loss, &[ClaimId::new(1)])?;
    let overlay = QueryOverlay::new(&[ClaimId::new(1)], 4)?;
    let first = ledger.snapshot(&[ClaimId::new(1)], &overlay)?;
    assert_eq!(
        first[0].reasons(),
        &[QualityReason::ConsumedLoss, QualityReason::QueryPartial]
    );
    println!("partial view: {:?}", first[0].reasons());
    // The next query without the overlay drops QueryPartial; the actual
    // loss persists. No global completeness is claimed either way.
    let bare = QueryOverlay::new(&[], 4)?;
    let second = ledger.snapshot(&[ClaimId::new(1)], &bare)?;
    assert_eq!(second[0].reasons(), &[QualityReason::ConsumedLoss]);
    println!("final view: {:?}", second[0].reasons());
    // Exact zero is benign; a zero lower bound stays damaging.
    let mut benign = open_ledger()?;
    let zero = LossFact::new(
        source()?,
        ChannelId::new(0),
        LossKind::Transport,
        LossMagnitude::Exact(Count::<Events>::new(0)),
    )?;
    benign.record_loss(&zero, &[ClaimId::new(1)])?;
    let view = benign.snapshot(&[ClaimId::new(1)], &bare)?;
    assert!(view[0].reasons().is_empty());
    println!("exact zero leaves no reason");
    let mut damaging = open_ledger()?;
    let atleast = LossFact::new(
        source()?,
        ChannelId::new(0),
        LossKind::Transport,
        LossMagnitude::AtLeast(Count::<Events>::new(0)),
    )?;
    damaging.record_loss(&atleast, &[ClaimId::new(1)])?;
    let view = damaging.snapshot(&[ClaimId::new(1)], &bare)?;
    assert_eq!(view[0].reasons(), &[QualityReason::ConsumedLoss]);
    println!("at-least zero stays damaging");
    Ok(())
}
