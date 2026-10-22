// SPDX-License-Identifier: Apache-2.0
//! Literal CP06 fixtures. No production output is used to calculate expected truth.
#![allow(dead_code)]
use scopebase_capture::{domain::*, loss::*, quantity::*, ContractError};
pub fn epoch() -> Epoch {
    Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    )
}
pub fn foreign_epochs() -> [Epoch; 3] {
    [
        Epoch::new(
            CaptureId::new([3; 16]).unwrap(),
            ProducerId::new([2; 16]).unwrap(),
            0,
        ),
        Epoch::new(
            CaptureId::new([1; 16]).unwrap(),
            ProducerId::new([3; 16]).unwrap(),
            0,
        ),
        epoch().successor().unwrap(),
    ]
}
pub fn source(e: Epoch) -> SourceRef {
    SourceRef::new(e, BindingId::new([4; 32]).unwrap(), Origin::Synthetic)
}
pub fn claim(n: u32) -> ClaimId {
    ClaimId::new(n)
}
pub fn channel(n: u32) -> ChannelId {
    ChannelId::new(n)
}
pub fn fact(n: u32, m: LossMagnitude<Events>) -> LossFact<Events> {
    LossFact::new(source(epoch()), channel(n), LossKind::Transport, m).unwrap()
}
pub fn exact(n: u32, value: u64) -> LossFact<Events> {
    fact(n, LossMagnitude::Exact(Count::new(value)))
}
pub fn error<T>(r: Result<T, ContractError>, want: ContractError) {
    match r {
        Err(e) => assert_eq!(e, want, "CP06:error order"),
        Ok(_) => panic!("CP06:expected refusal {want:?}"),
    }
}
/// Visit each fixed-base script once, retaining only one length-bounded prefix.
pub fn scripts(alphabet: u8, max: usize, mut visit: impl FnMut(&[u8])) {
    fn walk(a: u8, m: usize, p: &mut Vec<u8>, v: &mut impl FnMut(&[u8])) {
        v(p);
        if p.len() < m {
            for x in 0..a {
                p.push(x);
                walk(a, m, p, v);
                p.pop();
            }
        }
    }
    walk(alphabet, max, &mut Vec::new(), &mut visit)
}
pub const ORIGINAL_SUBSETS: [&str; 15] = [
    "K-S01", "K-S02", "K-S03", "K-S04", "M-S01", "M-S02", "M-S03", "M-S04", "M-S05", "M-S06",
    "M-S07", "M-S08", "O-S01", "O-S02", "O-S03",
];
/// Fixed required journal test names bound to baseline output. Baselines may
/// carry extra tests, but every listed (target, test) pair must pass as `ok`.
/// Deleting, renaming or ignoring a listed test fails the delivery as
/// incomplete; see the delivered helper's required-manifest and omission
/// controls. This list changes only by explicit owner repair.
pub const REQUIRED_JOURNAL_TESTS: &[(&str, &str)] = &[
    ("report_views", "occurrence_journal_all_9331_scripts"),
    ("feed_integrity", "inventory_all_1364_scripts"),
    ("corrections", "revision_journal_all_781_scripts"),
];
pub const CASES: [&str; 25] = [
    "CP06-V01",
    "CP06-V02",
    "CP06-V03",
    "CP06-V04",
    "CP06-V05",
    "CP06-V06",
    "CP06-V07",
    "CP06-V08",
    "CP06-V09",
    "CP06-F01",
    "CP06-F02",
    "CP06-F03",
    "CP06-F04",
    "CP06-F05",
    "CP06-C01",
    "CP06-C02",
    "CP06-C03",
    "CP06-C04",
    "CP06-C05",
    "CP06-C06",
    "CP06-C07",
    "CP06-DL01",
    "CP06-U01",
    "CP06-U02",
    "CP06-A01",
];
