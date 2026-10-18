// SPDX-License-Identifier: Apache-2.0
//! Bounded positional reads, adapted from the selected P/O held-file readers.
//! Before/after metadata is evidence of observations, never a content snapshot.
use super::HeldFile;
use crate::{
    control::OperationControl,
    error::{
        CleanupDisposition, DescriptorFlagEffect, EffectSummary, LimitKind, LinuxError, Reason,
        ResourceCharges, Stage,
    },
    identity::StatObservation,
};
use rustix::{
    fs::{self, FileType, OFlags},
    io::{self, Errno},
};
use std::{fmt, sync::Arc};

/// Explicit per-invocation ceilings. Allocator overhead and concurrent calls are separate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReadLimits {
    pub max_bytes: u64,
    pub max_read_calls: u64,
    pub max_buffer_capacity: usize,
}
/// Immutable, cheaply shared bytes. Contains no file authority or snapshot proof.
#[derive(Clone)]
pub struct FileRead {
    data: Arc<Vec<u8>>,
    observations: ReadObservations,
    charges: ReadCharges,
}
impl FileRead {
    pub fn bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
    pub fn observations(&self) -> &ReadObservations {
        &self.observations
    }
    pub fn charges(&self) -> ReadCharges {
        self.charges
    }
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ReadObservations {
    before: StatObservation,
    after: StatObservation,
}
impl ReadObservations {
    pub fn before(&self) -> StatObservation {
        self.before
    }
    pub fn after(&self) -> StatObservation {
        self.after
    }
    pub fn content_snapshot(&self) -> ContentSnapshot {
        ContentSnapshot::NotProven
    }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContentSnapshot {
    NotProven,
}
/// Allocation-local history. Clones share this allocation; summing aliases double counts.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ReadCharges {
    pub(crate) read_calls: u64,
    pub(crate) bytes_read: u64,
    pub(crate) requested_capacity: usize,
    pub(crate) granted_capacity: usize,
    pub(crate) retained_capacity: usize,
}
impl ReadCharges {
    pub fn read_calls(&self) -> u64 {
        self.read_calls
    }
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
    pub fn requested_capacity(&self) -> usize {
        self.requested_capacity
    }
    pub fn granted_capacity(&self) -> usize {
        self.granted_capacity
    }
    pub fn retained_capacity(&self) -> usize {
        self.retained_capacity
    }
}
impl fmt::Debug for FileRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileRead")
    }
}
impl fmt::Debug for ReadObservations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadObservations")
    }
}
impl fmt::Debug for ReadCharges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadCharges")
    }
}
impl HeldFile {
    /// Read from offset zero without changing the shared open-description cursor.
    ///
    /// Requires an actual EOF at the initial length and equal final descriptor
    /// metadata. Same-size writes can still escape observation or tear bytes.
    /// One size+1 payload reservation is attempted; overgrant refuses before use.
    /// Every pread (including EINTR/EOF) consumes work. Checkpoints cannot
    /// interrupt a pending syscall or impose hard time/RSS/allocator bounds.
    pub fn read_all(
        &self,
        limits: ReadLimits,
        control: &OperationControl,
    ) -> Result<FileRead, LinuxError> {
        read_all_with(self, limits, control, &mut ReadOps::default())
    }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Point {
    Entry,
    BeforeInitialStat,
    AfterInitialStat,
    BeforeGetFl,
    AfterGetFl,
    BeforeReserve,
    AfterReserve,
    BeforeInit(usize),
    AfterInit(usize),
    BeforeRead(u64),
    AfterRead(u64),
    BeforeFinalStat,
    AfterFinalStat,
    BeforeArc,
    Publish,
}
#[cfg(test)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Call {
    InitialStat,
    GetFl,
    Read(u64),
    FinalStat,
}
struct ReadOps {
    attempted: u64,
    completed: u64,
    read: ReadCharges,
    #[cfg(test)]
    hooks: tests::Hooks,
    #[cfg(test)]
    test_now: Option<std::time::Instant>,
}
impl Default for ReadOps {
    fn default() -> Self {
        Self {
            attempted: 0,
            completed: 0,
            read: ReadCharges {
                read_calls: 0,
                bytes_read: 0,
                requested_capacity: 0,
                granted_capacity: 0,
                retained_capacity: 0,
            },
            #[cfg(test)]
            hooks: tests::Hooks::default(),
            #[cfg(test)]
            test_now: None,
        }
    }
}
impl ReadOps {
    fn effect(&self) -> EffectSummary {
        EffectSummary {
            attempted: self.attempted,
            completed: self.completed,
            cleanup: CleanupDisposition::NotNeeded,
            flags: DescriptorFlagEffect::NotAttempted,
        }
    }
    fn charges(&self) -> ResourceCharges {
        ResourceCharges {
            syscalls: self.attempted,
            acquired: 0,
            peak: 0,
            read: Some(self.read),
        }
    }
    fn error(&self, reason: Reason, source: Option<std::io::Error>) -> LinuxError {
        LinuxError {
            stage: Stage::ReadFile,
            reason,
            source,
            effect: self.effect(),
            charges: self.charges(),
        }
    }
    fn semantic(&self, reason: Reason) -> LinuxError {
        self.error(reason, None)
    }
    fn errno(&self, e: Errno) -> LinuxError {
        let reason = match e {
            Errno::ACCESS | Errno::PERM => Reason::Denied,
            Errno::NOSYS | Errno::OPNOTSUPP | Errno::MFILE | Errno::NFILE | Errno::NOMEM => {
                Reason::Unavailable
            }
            Errno::NOENT | Errno::STALE => Reason::Disappeared,
            _ => Reason::Inconclusive,
        };
        self.error(reason, Some(e.into()))
    }
    fn checkpoint(&mut self, control: &OperationControl, _point: Point) -> Result<(), LinuxError> {
        #[cfg(test)]
        {
            self.hooks.points.push(_point);
            if let Some(event) = self.hooks.event.as_mut() {
                if let Some(now) = event(_point) {
                    self.test_now = Some(now);
                }
            }
        }
        #[cfg(test)]
        let result = match self.test_now {
            Some(now) => control.checkpoint_at(now),
            None => control.checkpoint(),
        };
        #[cfg(not(test))]
        let result = control.checkpoint();
        result.map_err(|stop| stop.into_error(Stage::ReadFile, self.effect(), self.charges()))
    }
    // P checked work charge: establish every counter update before committing any.
    fn charge_read(&mut self, max_read_calls: u64) -> Result<(), LimitKind> {
        let next = self
            .read
            .read_calls
            .checked_add(1)
            .filter(|n| *n <= max_read_calls)
            .ok_or(LimitKind::ReadCalls)?;
        let attempted = self.attempted.checked_add(1).ok_or(LimitKind::ReadCalls)?;
        self.read.read_calls = next;
        self.attempted = attempted;
        Ok(())
    }
    fn fixed_call<T>(
        &mut self,
        control: &OperationControl,
        point: Point,
        result: Result<T, Errno>,
    ) -> Result<T, LinuxError> {
        if result.is_ok() {
            self.completed += 1;
        }
        let post = self.checkpoint(control, point);
        match result {
            Err(e) => Err(self.errno(e)),
            Ok(value) => {
                post?;
                Ok(value)
            }
        }
    }
    fn stat(&mut self, held: &HeldFile, _final_stat: bool) -> Result<fs::Stat, Errno> {
        self.attempted += 1;
        #[cfg(test)]
        {
            let call = if _final_stat {
                Call::FinalStat
            } else {
                Call::InitialStat
            };
            self.hooks.calls.push(call);
            if let Some(f) = self.hooks.fault.as_mut() {
                if let Some(e) = f(call) {
                    return Err(e);
                }
            }
        }
        let result = fs::fstat(held);
        #[cfg(test)]
        let result = result.map(|mut s| {
            if let Some(f) = self.hooks.stat.as_mut() {
                f(_final_stat, &mut s);
            }
            s
        });
        result
    }
    fn getfl(&mut self, held: &HeldFile) -> Result<OFlags, Errno> {
        self.attempted += 1;
        #[cfg(test)]
        {
            self.hooks.calls.push(Call::GetFl);
            if let Some(f) = self.hooks.fault.as_mut() {
                if let Some(e) = f(Call::GetFl) {
                    return Err(e);
                }
            }
        }
        let result = fs::fcntl_getfl(held);
        #[cfg(test)]
        let result = result.map(|flags| self.hooks.flags.unwrap_or(flags));
        result
    }
    fn pread(&mut self, held: &HeldFile, bytes: &mut [u8], offset: u64) -> Result<usize, Errno> {
        #[cfg(test)]
        {
            let call = Call::Read(self.hooks.reads.len() as u64);
            self.hooks.calls.push(call);
            let fault = self.hooks.fault.as_mut().and_then(|f| f(call));
            let result = if let Some(e) = fault {
                Err(e)
            } else if let Some(f) = self.hooks.read.as_mut() {
                f(held, bytes, offset)
            } else {
                io::pread(held, &mut *bytes, offset)
            };
            self.hooks
                .reads
                .push((offset, bytes.len(), result.as_ref().ok().copied()));
            return result;
        }
        #[cfg(not(test))]
        io::pread(held, bytes, offset)
    }
    fn reserve(&mut self, requested: usize) -> Result<Vec<u8>, std::collections::TryReserveError> {
        #[cfg(test)]
        let result = if let Some(f) = self.hooks.reserve.as_mut() {
            f(requested)
        } else {
            reserve_exact(requested)
        };
        #[cfg(not(test))]
        let result = reserve_exact(requested);
        #[cfg(test)]
        if let Ok(v) = &result {
            self.hooks
                .reservations
                .push((requested, v.capacity(), v.as_ptr() as usize));
        }
        result
    }
}
fn reserve_exact(requested: usize) -> Result<Vec<u8>, std::collections::TryReserveError> {
    let mut data = Vec::new();
    data.try_reserve_exact(requested)?;
    Ok(data)
}
fn checked_offset(offset: u64) -> Option<u64> {
    i64::try_from(offset).ok().map(|_| offset)
}
fn admit_size(size: u64, limits: ReadLimits) -> Result<(usize, usize), LimitKind> {
    if size > limits.max_bytes {
        return Err(LimitKind::InputBytes);
    }
    let requested = size
        .checked_add(1)
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n <= isize::MAX as usize && *n <= limits.max_buffer_capacity)
        .ok_or(LimitKind::BufferCapacity)?;
    checked_offset(size).ok_or(LimitKind::BufferCapacity)?;
    Ok((
        usize::try_from(size).map_err(|_| LimitKind::BufferCapacity)?,
        requested,
    ))
}
fn read_all_with(
    held: &HeldFile,
    limits: ReadLimits,
    control: &OperationControl,
    ops: &mut ReadOps,
) -> Result<FileRead, LinuxError> {
    ops.checkpoint(control, Point::Entry)?;
    if limits.max_read_calls == 0
        || limits.max_read_calls > u64::MAX - 3
        || limits.max_buffer_capacity == 0
    {
        return Err(ops.semantic(Reason::InvalidInput));
    }
    ops.checkpoint(control, Point::BeforeInitialStat)?;
    let result = ops.stat(held, false);
    let initial = ops.fixed_call(control, Point::AfterInitialStat, result)?;
    if FileType::from_raw_mode(initial.st_mode) != FileType::RegularFile {
        return Err(ops.semantic(Reason::NonRegular));
    }
    let before =
        StatObservation::from_stat(&initial).ok_or_else(|| ops.semantic(Reason::Malformed))?;
    ops.checkpoint(control, Point::BeforeGetFl)?;
    let result = ops.getfl(held);
    let flags = ops.fixed_call(control, Point::AfterGetFl, result)?;
    if flags.contains(OFlags::PATH)
        || !matches!(flags & OFlags::ACCMODE, OFlags::RDONLY | OFlags::RDWR)
    {
        return Err(ops.semantic(Reason::Unreadable));
    }
    let (payload_len, requested) = admit_size(before.len(), limits)
        .map_err(|kind| ops.semantic(Reason::LimitExceeded(kind)))?;
    ops.checkpoint(control, Point::BeforeReserve)?;
    ops.read.requested_capacity = requested;
    let mut data = ops
        .reserve(requested)
        .map_err(|_| ops.semantic(Reason::Allocation))?;
    ops.read.granted_capacity = data.capacity();
    ops.checkpoint(control, Point::AfterReserve)?;
    if data.capacity() > limits.max_buffer_capacity {
        return Err(ops.semantic(Reason::LimitExceeded(LimitKind::BufferCapacity)));
    }
    let mut chunk = 0;
    while data.len() < requested {
        ops.checkpoint(control, Point::BeforeInit(chunk))?;
        data.resize(data.len() + 65536.min(requested - data.len()), 0);
        #[cfg(test)]
        ops.hooks.initialized.push(data.len());
        ops.checkpoint(control, Point::AfterInit(chunk))?;
        chunk += 1;
    }
    let mut offset = 0usize;
    loop {
        let call = ops.read.read_calls;
        ops.checkpoint(control, Point::BeforeRead(call))?;
        let wire_offset =
            checked_offset(offset as u64).ok_or_else(|| ops.semantic(Reason::Malformed))?;
        let request = 65536.min(
            requested
                .checked_sub(offset)
                .ok_or_else(|| ops.semantic(Reason::Malformed))?,
        );
        if request == 0 {
            return Err(ops.semantic(Reason::Malformed));
        }
        let end = offset
            .checked_add(request)
            .ok_or_else(|| ops.semantic(Reason::Malformed))?;
        ops.charge_read(limits.max_read_calls)
            .map_err(|kind| ops.semantic(Reason::LimitExceeded(kind)))?;
        let result = ops.pread(held, &mut data[offset..end], wire_offset);
        if let Ok(n) = result {
            ops.completed += 1;
            ops.read.bytes_read = ops
                .read
                .bytes_read
                .checked_add(n as u64)
                .ok_or_else(|| ops.semantic(Reason::Malformed))?;
        }
        let post = ops.checkpoint(control, Point::AfterRead(call));
        let n = match result {
            Err(e) if e == Errno::INTR && post.is_ok() => continue,
            Err(e) => return Err(ops.errno(e)),
            Ok(n) => {
                post?;
                n
            }
        };
        if n > request {
            return Err(ops.semantic(Reason::Malformed));
        }
        if n == 0 {
            if offset != payload_len {
                return Err(ops.semantic(Reason::ChangedSource));
            }
            break;
        }
        offset = offset
            .checked_add(n)
            .ok_or_else(|| ops.semantic(Reason::Malformed))?;
        if offset > payload_len {
            return Err(ops.semantic(if offset as u64 > limits.max_bytes {
                Reason::LimitExceeded(LimitKind::InputBytes)
            } else {
                Reason::ChangedSource
            }));
        }
    }
    ops.checkpoint(control, Point::BeforeFinalStat)?;
    let result = ops.stat(held, true);
    let final_stat = ops.fixed_call(control, Point::AfterFinalStat, result)?;
    if FileType::from_raw_mode(final_stat.st_mode) != FileType::RegularFile {
        return Err(ops.semantic(Reason::ChangedSource));
    }
    let after =
        StatObservation::from_stat(&final_stat).ok_or_else(|| ops.semantic(Reason::Malformed))?;
    if before != after {
        return Err(ops.semantic(Reason::ChangedSource));
    }
    data.truncate(payload_len);
    ops.checkpoint(control, Point::BeforeArc)?;
    let mut charges = ops.read;
    charges.retained_capacity = charges.granted_capacity;
    let result = FileRead {
        data: Arc::new(data),
        observations: ReadObservations { before, after },
        charges,
    };
    ops.checkpoint(control, Point::Publish)?;
    Ok(result)
}
#[cfg(test)]
mod tests;
