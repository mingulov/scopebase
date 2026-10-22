// SPDX-License-Identifier: Apache-2.0
//! A caller-owned byte/occupancy reducer with explicit dependencies and keys.
//! Run as an ordinary independent package; no test oracle or private donor input.
use scopebase_capture::{
    correction::*, domain::*, generation::ObjectKey, loss::*, quantity::*, view::*,
};
#[derive(Clone, PartialEq, Eq)]
struct DeviceKey {
    namespace: u64,
    device: u64,
    token: u64,
}
#[derive(Debug, PartialEq, Eq)]
struct Facts {
    copy_bytes: u64,
    occupancy_bytes: u64,
    shared_bytes: u64,
    pool_samples: u64,
}
struct Viewer {
    entries: Vec<Entry>,
}
struct Entry {
    key: ObjectKey<DeviceKey>,
    facts: Option<Versioned<Facts>>,
    quality: ClaimLedger,
}
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Unknown,
    Foreign,
    Missing,
    Ambiguous,
    Incomplete,
}
fn epoch() -> Epoch {
    Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        0,
    )
}
fn key(token: u64) -> ObjectKey<DeviceKey> {
    ObjectKey::new(
        epoch(),
        DeviceKey {
            namespace: 7,
            device: 8,
            token,
        },
        0,
    )
}
enum Input {
    Copy(u64),
    Mapped(u64),
    Shared(u64),
    PoolSample,
}
fn initial() -> Facts {
    let mut copied = Count::<Bytes>::new(0);
    let mut mapped = Count::<Bytes>::new(0);
    let mut shared = Count::<Bytes>::new(0);
    let mut samples = Count::<Events>::new(0);
    for event in [
        Input::Copy(512),
        Input::Mapped(4096),
        Input::Shared(8192),
        Input::PoolSample,
        Input::PoolSample,
        Input::PoolSample,
    ] {
        match event {
            Input::Copy(n) => copied = copied.checked_add(Count::new(n)).unwrap(),
            Input::Mapped(n) => mapped = mapped.checked_add(Count::new(n)).unwrap(),
            Input::Shared(n) => shared = shared.checked_add(Count::new(n)).unwrap(),
            Input::PoolSample => samples = samples.checked_add(Count::new(1)).unwrap(),
        }
    }
    Facts {
        copy_bytes: copied.get(),
        occupancy_bytes: mapped.get(),
        shared_bytes: shared.get(),
        pool_samples: samples.get(),
    }
}

impl Viewer {
    fn index(&self, key: Option<&ObjectKey<DeviceKey>>) -> Result<usize, Route> {
        let key = key.ok_or(Route::Unknown)?;
        if key.epoch() != &epoch() {
            return Err(Route::Foreign);
        }
        let mut matches = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.key.matches(key).then_some(i));
        let i = matches.next().ok_or(Route::Missing)?;
        if matches.next().is_some() {
            return Err(Route::Ambiguous);
        }
        Ok(i)
    }
    fn revise(&mut self, key: Option<&ObjectKey<DeviceKey>>, facts: Facts) -> Result<(), Route> {
        let i = self.index(key)?;
        let holder = self.entries[i].facts.take().ok_or(Route::Incomplete)?;
        match holder.apply(Correction::new(epoch(), Revision::new(0), facts).unwrap()) {
            Ok(v) => {
                self.entries[i].facts = Some(v);
                Ok(())
            }
            Err((v, _)) => {
                self.entries[i].facts = Some(v);
                Err(Route::Incomplete)
            }
        }
    }
}
fn entry(token: u64) -> Entry {
    Entry {
        key: key(token),
        facts: Some(Versioned::new(epoch(), initial())),
        quality: ClaimLedger::new(
            epoch(),
            LedgerLimits {
                claims: 2,
                reasons_per_claim: 2,
                loss_facts: 4,
            },
        )
        .unwrap(),
    }
}
fn main() {
    let mut viewer = Viewer {
        entries: vec![entry(1), entry(2)],
    };
    let target = key(1);
    assert_eq!(viewer.index(None), Err(Route::Unknown));
    assert_eq!(viewer.index(Some(&key(99))), Err(Route::Missing));
    for bad in [
        ObjectKey::new(
            epoch().successor().unwrap(),
            DeviceKey {
                namespace: 7,
                device: 8,
                token: 1,
            },
            0,
        ),
        ObjectKey::new(
            Epoch::new(
                CaptureId::new([9; 16]).unwrap(),
                ProducerId::new([2; 16]).unwrap(),
                0,
            ),
            DeviceKey {
                namespace: 7,
                device: 8,
                token: 1,
            },
            0,
        ),
    ] {
        assert_eq!(viewer.index(Some(&bad)), Err(Route::Foreign));
    }
    for raw in [
        DeviceKey {
            namespace: 9,
            device: 8,
            token: 1,
        },
        DeviceKey {
            namespace: 7,
            device: 9,
            token: 1,
        },
    ] {
        assert_eq!(
            viewer.index(Some(&ObjectKey::new(epoch(), raw, 0))),
            Err(Route::Missing)
        );
    }
    assert_eq!(
        viewer.index(Some(&ObjectKey::new(
            epoch(),
            DeviceKey {
                namespace: 7,
                device: 8,
                token: 1
            },
            1
        ))),
        Err(Route::Missing)
    );
    let duplicate = Viewer {
        entries: vec![entry(1), entry(1)],
    };
    assert_eq!(duplicate.index(Some(&target)), Err(Route::Ambiguous));
    let copy = ClaimId::new(1);
    let occupancy = ClaimId::new(2);
    let mapping_gap = LossFact::<Objects>::new(
        SourceRef::new(epoch(), BindingId::new([3; 32]).unwrap(), Origin::Synthetic),
        ChannelId::new(0),
        LossKind::Attribution,
        LossMagnitude::Unknown,
    )
    .unwrap();
    viewer.entries[0]
        .quality
        .record_loss(&mapping_gap, &[occupancy])
        .unwrap();
    let partial = viewer.entries[0]
        .quality
        .snapshot(&[copy, occupancy], &QueryOverlay::new(&[copy], 2).unwrap())
        .unwrap();
    let plain = viewer.entries[0]
        .quality
        .snapshot(&[copy, occupancy], &QueryOverlay::new(&[], 2).unwrap())
        .unwrap();
    assert_eq!(partial[0].reasons(), [QualityReason::QueryPartial]);
    assert_eq!(plain[0].reasons(), [], "CP06:viewer copy independent");
    assert_eq!(plain[1].reasons(), [QualityReason::ConsumedLoss]);
    assert_eq!(
        viewer.entries[0].facts.as_ref().unwrap().value(),
        &Facts {
            copy_bytes: 512,
            occupancy_bytes: 4096,
            shared_bytes: 8192,
            pool_samples: 3
        }
    );
    viewer
        .revise(
            Some(&target),
            Facts {
                pool_samples: 4,
                ..initial()
            },
        )
        .unwrap();
    assert_eq!(
        viewer.entries[0].facts.as_ref().unwrap().value(),
        &Facts {
            copy_bytes: 512,
            occupancy_bytes: 4096,
            shared_bytes: 8192,
            pool_samples: 4
        },
        "CP06:viewer full replacement"
    );
    assert_eq!(
        viewer.entries[1].facts.as_ref().unwrap().value(),
        &Facts {
            copy_bytes: 512,
            occupancy_bytes: 4096,
            shared_bytes: 8192,
            pool_samples: 3
        }
    );
    assert_eq!(
        viewer.revise(Some(&target), initial()),
        Err(Route::Incomplete)
    );
    println!("CP06 fact viewer: copy512 occupancy4096 shared8192 pool3; local overlay, consumed mapping gap, complete-key revision verified");
}
