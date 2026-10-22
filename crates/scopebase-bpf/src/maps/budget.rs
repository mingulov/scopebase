// SPDX-License-Identifier: Apache-2.0
use super::error;
use crate::{ErrorKind, OperationError, Stage};
pub(super) struct Work {
    used: u64,
    limit: u64,
}
impl Work {
    pub(super) fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }
    pub(super) fn charge(&mut self, n: usize, stage: Stage) -> Result<(), OperationError> {
        let n = u64::try_from(n).map_err(|_| error(ErrorKind::Overflow, stage))?;
        let next = self
            .used
            .checked_add(n)
            .ok_or_else(|| error(ErrorKind::Overflow, stage))?;
        if next > self.limit {
            return Err(error(ErrorKind::LimitExceeded, stage));
        }
        self.used = next;
        Ok(())
    }
}
pub(super) fn capacity(
    existing: usize,
    requested: usize,
    cap: usize,
) -> Result<(), OperationError> {
    let n = existing
        .checked_add(requested)
        .ok_or_else(|| error(ErrorKind::Overflow, Stage::Allocate))?;
    if n > cap {
        Err(error(ErrorKind::LimitExceeded, Stage::Allocate))
    } else {
        Ok(())
    }
}
pub(super) fn bytes(
    n: usize,
    existing: usize,
    cap: usize,
    work: &mut Work,
) -> Result<Vec<u8>, OperationError> {
    capacity(existing, n, cap)?;
    #[cfg(test)]
    ALLOCATIONS.with(|n| n.set(n.get() + 1));
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| error(ErrorKind::LimitExceeded, Stage::Allocate))?;
    capacity(existing, v.capacity(), cap)?;
    work.charge(n, Stage::Allocate)?;
    v.resize(n, 0);
    Ok(v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budget_zero_exact_overflow_and_capacity() {
        let mut work = Work::new(0);
        assert_eq!(
            work.charge(1, Stage::Read).unwrap_err().kind(),
            ErrorKind::LimitExceeded
        );
        let mut work = Work::new(u64::MAX);
        work.charge(usize::MAX, Stage::Read).unwrap();
        assert_eq!(
            work.charge(1, Stage::Read).unwrap_err().kind(),
            ErrorKind::Overflow
        );
        assert!(capacity(8, 8, 16).is_ok());
        assert_eq!(
            capacity(8, 8, 15).unwrap_err().kind(),
            ErrorKind::LimitExceeded
        );
        assert_eq!(
            capacity(usize::MAX, 1, usize::MAX).unwrap_err().kind(),
            ErrorKind::Overflow
        );
        let mut work = Work::new(8);
        assert_eq!(bytes(8, 8, 16, &mut work).unwrap(), [0; 8]);
        assert_eq!(
            bytes(1, 16, 16, &mut Work::new(100)).unwrap_err().kind(),
            ErrorKind::LimitExceeded
        );
    }
}

#[cfg(test)]
thread_local! {pub(super) static ALLOCATIONS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}
