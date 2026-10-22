// SPDX-License-Identifier: Apache-2.0
//! Separate mapping client: structured domains, event identity and retired ring.
//! Literal scripted observations do not establish live mapping authority.
use scopebase_capture::{
    domain::{CaptureId, Epoch, ProducerId},
    generation::ObjectKey,
};
#[derive(Clone, PartialEq, Eq)]
struct Domain {
    device: &'static str,
    namespace: &'static str,
    token: &'static str,
}
struct Live {
    key: ObjectKey<Domain>,
    start: u64,
    bytes: u64,
}
struct MappingJournal {
    events: Vec<u64>,
    known: Vec<ObjectKey<Domain>>,
    live: Vec<Live>,
    retired: Vec<ObjectKey<Domain>>,
    cursor: usize,
    partial: bool,
    durations: Vec<u64>,
}
impl MappingJournal {
    fn observation(&mut self, event: u64, key: Option<ObjectKey<Domain>>) -> bool {
        if let Some(key) = key {
            if self.known.iter().any(|k| k.matches(&key)) {
                return false;
            }
            self.known.push(key);
        }
        self.events.push(event);
        true
    }
    fn open(&mut self, key: ObjectKey<Domain>, start: u64, bytes: u64) -> bool {
        if self.live.iter().any(|r| r.key.matches(&key))
            || self.retired.iter().any(|r| r.matches(&key))
        {
            return false;
        }
        self.live.push(Live { key, start, bytes });
        true
    }
    fn close(&mut self, key: &ObjectKey<Domain>, end: u64) -> bool {
        let Some(pos) = self.live.iter().position(|r| r.key.matches(key)) else {
            return false;
        };
        let row = self.live.remove(pos);
        self.durations.push(end - row.start);
        if self.retired.len() < 2 {
            self.retired.push(row.key);
        } else {
            self.retired[self.cursor] = row.key;
            self.cursor = (self.cursor + 1) % 2;
            self.partial = true;
        }
        true
    }
}
fn main() {
    let epoch = Epoch::new(
        CaptureId::new([31; 16]).unwrap(),
        ProducerId::new([32; 16]).unwrap(),
        1,
    );
    let make = |namespace, token, generation| {
        ObjectKey::new(
            epoch.clone(),
            Domain {
                device: "d1",
                namespace,
                token,
            },
            generation,
        )
    };
    let mut m = MappingJournal {
        events: Vec::new(),
        known: Vec::new(),
        live: Vec::new(),
        retired: Vec::new(),
        cursor: 0,
        partial: false,
        durations: Vec::new(),
    };
    assert!(m.observation(41, None));
    assert!(m.observation(42, None));
    assert_eq!(m.events, vec![41, 42]);
    assert!(m.known.is_empty());
    assert!(m.observation(43, Some(make("kvirt", "same", 0))));
    assert!(m.observation(44, Some(make("gphys", "same", 0))));
    assert!(!m.observation(45, Some(make("kvirt", "same", 0))));
    for (token, generation, start, end) in
        [("a", 1, 100, 150), ("a", 2, 200, 260), ("b", 1, 300, 370)]
    {
        let key = make("kvirt", token, generation);
        assert!(m.open(key.clone(), start, 4096));
        assert!(m.close(&key, end));
    }
    assert_eq!(m.durations, vec![50, 60, 70]);
    assert!(m.partial);
    assert_eq!(m.retired.len(), 2);
    assert!(m.open(make("kvirt", "a", 1), 500, 4096));
    assert!(m.partial);
    assert_eq!(m.live.iter().map(|r| r.bytes).sum::<u64>(), 4096);
    assert_eq!(m.events, vec![41, 42, 43, 44]);
    assert_eq!(m.known.len(), 2);
    println!("CP05 mapping client: unknown_events=2 known=2 durations=50,60,70 partial=true live_bytes=4096");
}
