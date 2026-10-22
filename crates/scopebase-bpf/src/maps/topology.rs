// SPDX-License-Identifier: Apache-2.0
// ADAPT K::possible_cpus_from_str: ascending/nonoverlapping, bounded, no fallback.
// Tighten Unicode trim to explicitly ASCII bytes; preserve exact source bytes.
use super::{
    budget::{capacity, Work},
    error,
};
use crate::{ErrorKind as K, OperationError, Stage as S};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuTopology {
    ids: Vec<u32>,
    pub(super) source: Vec<u8>,
}
fn ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}
fn trim(mut b: &[u8]) -> &[u8] {
    while b.first().is_some_and(|x| ws(*x)) {
        b = &b[1..]
    }
    while b.last().is_some_and(|x| ws(*x)) {
        b = &b[..b.len() - 1]
    }
    b
}
fn digits(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(u8::is_ascii_digit)
}
fn number(b: &[u8]) -> Result<u32, OperationError> {
    b.iter().try_fold(0u32, |n, x| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add((x - b'0') as u32))
            .ok_or_else(|| error(K::Overflow, S::Admission))
    })
}
fn item(b: &[u8]) -> Result<(u32, u32), OperationError> {
    let b = trim(b);
    // Lexical validation of the whole item precedes either conversion.
    let mut parts = b.split(|x| *x == b'-');
    let lo = trim(parts.next().unwrap_or_default());
    let high = parts.next().map(trim);
    if parts.next().is_some() || !digits(lo) || high.is_some_and(|x| !digits(x)) {
        return Err(error(K::Malformed, S::Admission));
    }
    let lo = number(lo)?;
    let hi = match high {
        Some(x) => number(x)?,
        None => lo,
    };
    if lo > hi {
        return Err(error(K::Malformed, S::Admission));
    }
    Ok((lo, hi))
}
impl CpuTopology {
    pub fn parse_possible(
        input: &[u8],
        max_cpu_id: u32,
        max_count: usize,
    ) -> Result<Self, OperationError> {
        Self::parse_budget(
            input,
            max_cpu_id,
            max_count,
            usize::MAX,
            0,
            &mut Work::new(u64::MAX),
        )
    }
    pub(super) fn parse_budget(
        input: &[u8],
        max_cpu_id: u32,
        max_count: usize,
        cap: usize,
        existing: usize,
        work: &mut Work,
    ) -> Result<Self, OperationError> {
        if input.len() > 65536 {
            return Err(error(K::LimitExceeded, S::Admission));
        }
        work.charge(
            input
                .len()
                .checked_mul(3)
                .ok_or_else(|| error(K::Overflow, S::Admission))?,
            S::Admission,
        )?;
        let mut previous = None;
        let mut count = 0usize;
        for b in input.split(|x| *x == b',') {
            let (lo, hi) = item(b)?;
            if hi > max_cpu_id.min(65535) {
                return Err(error(K::LimitExceeded, S::Admission));
            }
            if previous.is_some_and(|p| lo <= p) {
                return Err(error(K::Malformed, S::Admission));
            }
            count = count
                .checked_add((hi - lo) as usize + 1)
                .ok_or_else(|| error(K::Overflow, S::Admission))?;
            if count > max_count.min(65536) {
                return Err(error(K::LimitExceeded, S::Admission));
            }
            previous = Some(hi);
        }
        work.charge(count, S::Admission)?;
        let requested = count
            .checked_mul(4)
            .and_then(|n| n.checked_add(input.len()))
            .ok_or_else(|| error(K::Overflow, S::Allocate))?;
        capacity(existing, requested, cap)?;
        let mut ids = Vec::new();
        #[cfg(test)]
        let count_reserve = count + usize::from(IDS_OVERGRANT.with(|f| f.get()));
        #[cfg(not(test))]
        let count_reserve = count;
        ids.try_reserve_exact(count_reserve)
            .map_err(|_| error(K::LimitExceeded, S::Allocate))?;
        if ids.capacity() > 65536 {
            return Err(error(K::LimitExceeded, S::Allocate));
        }
        let before_source = ids
            .capacity()
            .checked_mul(4)
            .and_then(|n| n.checked_add(input.len()))
            .ok_or_else(|| error(K::Overflow, S::Allocate))?;
        capacity(existing, before_source, cap)?;
        #[cfg(test)]
        SOURCE_RESERVES.with(|n| n.set(n.get() + 1));
        let mut source = Vec::new();
        source
            .try_reserve_exact(input.len())
            .map_err(|_| error(K::LimitExceeded, S::Allocate))?;
        if source.capacity() > 65536 {
            return Err(error(K::LimitExceeded, S::Allocate));
        }
        let observed = ids
            .capacity()
            .checked_mul(4)
            .and_then(|n| n.checked_add(source.capacity()))
            .ok_or_else(|| error(K::Overflow, S::Allocate))?;
        capacity(existing, observed, cap)?;
        for b in input.split(|x| *x == b',') {
            let (lo, hi) = item(b)?;
            ids.extend(lo..=hi);
        }
        source.extend_from_slice(input);
        Ok(Self { ids, source })
    }
    pub fn count(&self) -> usize {
        self.ids.len()
    }
    pub fn ids(&self) -> &[u32] {
        &self.ids
    }
    pub(super) fn retained(&self) -> usize {
        self.ids.capacity() * 4 + self.source.capacity()
    }
}
#[cfg(test)]
thread_local! {static IDS_OVERGRANT:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};static SOURCE_RESERVES:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_id_overgrant_refuses_before_source_reserve() {
        IDS_OVERGRANT.with(|f| f.set(true));
        SOURCE_RESERVES.with(|n| n.set(0));
        let e = CpuTopology::parse_budget(b"0\n", 65535, 65536, 6, 0, &mut Work::new(1000))
            .unwrap_err();
        assert_eq!((e.kind(), e.stage()), (K::LimitExceeded, S::Allocate));
        assert_eq!(
            SOURCE_RESERVES.with(|n| n.get()),
            0,
            "no second allocation after observed overgrant"
        );
        IDS_OVERGRANT.with(|f| f.set(false));
        SOURCE_RESERVES.with(|n| n.set(0));
        let t =
            CpuTopology::parse_budget(b"0\n", 65535, 65536, 6, 0, &mut Work::new(1000)).unwrap();
        assert_eq!(t.ids(), &[0]);
        assert_eq!(t.source, b"0\n");
        assert_eq!(SOURCE_RESERVES.with(|n| n.get()), 1);
        // ID buffer alone fits8, but source requires2 more: refuse before source.
        IDS_OVERGRANT.with(|f| f.set(true));
        SOURCE_RESERVES.with(|n| n.set(0));
        let e = CpuTopology::parse_budget(b"0\n", 65535, 65536, 9, 0, &mut Work::new(1000))
            .unwrap_err();
        assert_eq!(e.kind(), K::LimitExceeded);
        assert_eq!(SOURCE_RESERVES.with(|n| n.get()), 0);
        IDS_OVERGRANT.with(|f| f.set(false));
    }
}
