// SPDX-License-Identifier: Apache-2.0
//! Explicit synthetic samples; this is not a producer-acquisition adapter.
use scopebase_capture::{
    counter::{sample_delta, AdvanceBound, CounterPolicy, Delta, DeltaUnknown, Sample},
    domain::{BindingId, CaptureId, ChannelId, ClockDomain, Epoch, Origin, ProducerId, SourceRef},
    quantity::{Count, Events},
    time::{TimeInterval, Timestamp},
    ContractError,
};
fn observed(
    policy: CounterPolicy,
    start: u64,
    end: u64,
    value: u64,
) -> Result<Sample<Events>, ContractError> {
    let source = SourceRef::new(
        Epoch::new(CaptureId::new([1; 16])?, ProducerId::new([2; 16])?, 0),
        BindingId::new([3; 32])?,
        Origin::Synthetic,
    );
    let clock = ClockDomain::new([4; 16])?;
    Sample::new(
        source,
        ChannelId::new(0),
        policy,
        TimeInterval::new(Timestamp::new(clock, start), Timestamp::new(clock, end))?,
        Count::new(value),
    )
}
fn main() -> Result<(), ContractError> {
    let baseline = observed(CounterPolicy::Monotonic, 0, 1, 7)?;
    let current = observed(CounterPolicy::Monotonic, 1, 2, 12)?;
    let delta = sample_delta(Some(&baseline), &current, None)?;
    assert_eq!(delta, Delta::Exact(Count::new(5)));
    println!("monotonic delta: {delta:?}");
    let missing = sample_delta(None, &current, None)?;
    assert_eq!(missing, Delta::Unknown(DeltaUnknown::MissingBaseline));
    println!("missing baseline: {missing:?}");
    let baseline = observed(CounterPolicy::Modulo { width: 8 }, 0, 1, 250)?;
    let current = observed(CounterPolicy::Modulo { width: 8 }, 1, 2, 3)?;
    // Independent caller assertion: this exact pair spans no reset and at most12 advances.
    let bound = AdvanceBound::new(&baseline, &current, Count::new(12))?;
    let delta = sample_delta(Some(&baseline), &current, Some(&bound))?;
    assert_eq!(delta, Delta::Exact(Count::new(9)));
    println!("bounded modulo delta: {delta:?}");
    assert_eq!(
        sample_delta(None, &current, Some(&bound))?,
        Delta::Unknown(DeltaUnknown::MissingBaseline)
    );
    Ok(())
}
