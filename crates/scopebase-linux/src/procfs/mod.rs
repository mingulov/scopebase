// SPDX-License-Identifier: Apache-2.0
//! Pure, bounded descriptive parsing of complete caller-provided proc snapshots.
//!
//! Parsed tuples and table-instance handles are observations, never retained file,
//! process or namespace authority. Nonempty inputs require a final LF; complete LF
//! prefixes cannot establish acquisition completeness. Byte/work/capacity bounds
//! do not promise elapsed time, RSS or allocator-internal syscall bounds.
use crate::error::{
    CleanupDisposition, DescriptorFlagEffect, EffectSummary, LimitKind, LinuxError, Reason,
    ResourceCharges, Stage,
};
use std::{fmt, mem::size_of};
mod maps;
mod mountinfo;
pub use maps::{parse_maps, MapsEntry, MapsPathEvidence, MapsPathKind, MapsSnapshot};
pub use mountinfo::{
    parse_mountinfo, MountEntry, MountField, MountOptionalField, MountOptionalKind,
    MountTableSnapshot, ParsedMountId,
};
/// All limits must be explicitly nonzero. Line bytes exclude LF.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_bytes: usize,
    pub max_entries: usize,
    pub max_line_bytes: usize,
}
/// Historical logical capacities and parsing work, including work before refusal.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ParseCharges {
    input_bytes: usize,
    entries_validated: usize,
    allocation_attempts: u64,
    peak_buffer_capacity_bytes: usize,
    peak_metadata_capacity_bytes: usize,
}
impl ParseCharges {
    fn new(bytes: usize) -> Self {
        Self {
            input_bytes: bytes,
            entries_validated: 0,
            allocation_attempts: 0,
            peak_buffer_capacity_bytes: 0,
            peak_metadata_capacity_bytes: 0,
        }
    }
    pub fn input_bytes(&self) -> usize {
        self.input_bytes
    }
    pub fn entries_validated(&self) -> usize {
        self.entries_validated
    }
    pub fn allocation_attempts(&self) -> u64 {
        self.allocation_attempts
    }
    pub fn peak_buffer_capacity_bytes(&self) -> usize {
        self.peak_buffer_capacity_bytes
    }
    pub fn peak_metadata_capacity_bytes(&self) -> usize {
        self.peak_metadata_capacity_bytes
    }
}
impl fmt::Debug for ParseCharges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ParseCharges")
    }
}
fn error(stage: Stage, reason: Reason, line: Option<usize>, c: ParseCharges) -> LinuxError {
    LinuxError {
        stage,
        reason,
        parse_line: line,
        source: None,
        effect: EffectSummary {
            attempted: 0,
            completed: 0,
            cleanup: CleanupDisposition::NotNeeded,
            flags: DescriptorFlagEffect::NotAttempted,
        },
        charges: ResourceCharges {
            syscalls: 0,
            acquired: 0,
            peak: 0,
            read: None,
            parse: Some(c),
        },
    }
}
fn preflight(
    input: &[u8],
    l: ParseLimits,
    stage: Stage,
    c: ParseCharges,
) -> Result<usize, LinuxError> {
    if l.max_bytes == 0 || l.max_entries == 0 || l.max_line_bytes == 0 {
        return Err(error(stage, Reason::InvalidInput, None, c));
    }
    if input.len() > l.max_bytes {
        return Err(error(
            stage,
            Reason::LimitExceeded(LimitKind::InputBytes),
            None,
            c,
        ));
    }
    let (mut rows, mut len, mut nul) = (0usize, 0usize, false);
    for &b in input {
        if b != b'\n' {
            if len == l.max_line_bytes {
                return Err(error(
                    stage,
                    Reason::LimitExceeded(LimitKind::LineBytes),
                    Some(rows + 1),
                    c,
                ));
            }
            len += 1;
            nul |= b == 0;
            continue;
        }
        rows = rows.checked_add(1).ok_or_else(|| {
            error(
                stage,
                Reason::LimitExceeded(LimitKind::BufferCapacity),
                None,
                c,
            )
        })?;
        if rows > l.max_entries {
            return Err(error(
                stage,
                Reason::LimitExceeded(LimitKind::Entries),
                Some(rows),
                c,
            ));
        }
        if len == 0 || nul {
            return Err(error(stage, Reason::Malformed, Some(rows), c));
        }
        len = 0;
        nul = false;
    }
    if !input.is_empty() && !input.ends_with(b"\n") {
        let row = rows + 1;
        if row > l.max_entries {
            return Err(error(
                stage,
                Reason::LimitExceeded(LimitKind::Entries),
                Some(row),
                c,
            ));
        }
        return Err(error(stage, Reason::Malformed, Some(row), c));
    }
    Ok(rows)
}
// Exactly the specified logical capacity arithmetic, before any allocation.
fn capacity_request(bytes: usize, rows: usize, mount: bool) -> Option<usize> {
    if mount {
        bytes.checked_mul(2)?.checked_add(rows.checked_mul(
            size_of::<mountinfo::MountRecord>().checked_add(size_of::<(u64, usize)>())?,
        )?)
    } else {
        bytes.checked_add(rows.checked_mul(size_of::<maps::MapRecord>())?)
    }
}
#[derive(Copy, Clone)]
enum ReserveMode {
    Normal,
    #[cfg(test)]
    Fail(u64),
    #[cfg(test)]
    Overgrant(u64),
}
fn reserve<T>(
    v: &mut Vec<T>,
    n: usize,
    buffer: bool,
    c: &mut ParseCharges,
    stage: Stage,
    mode: ReserveMode,
) -> Result<(), LinuxError> {
    c.allocation_attempts += 1;
    #[cfg(test)]
    if matches!(mode,ReserveMode::Fail(i) if i==c.allocation_attempts) {
        return Err(error(stage, Reason::Allocation, None, *c));
    }
    #[cfg(not(test))]
    let _ = mode;
    #[allow(unused_mut)]
    let mut request = n;
    #[cfg(test)]
    if matches!(mode,ReserveMode::Overgrant(i) if i==c.allocation_attempts) {
        request += 1;
    }
    v.try_reserve_exact(request)
        .map_err(|_| error(stage, Reason::Allocation, None, *c))?;
    let bytes = v.capacity().saturating_mul(size_of::<T>());
    if buffer {
        c.peak_buffer_capacity_bytes = c.peak_buffer_capacity_bytes.saturating_add(bytes)
    } else {
        c.peak_metadata_capacity_bytes = c.peak_metadata_capacity_bytes.saturating_add(bytes)
    }
    if v.capacity() > n {
        return Err(error(
            stage,
            Reason::LimitExceeded(LimitKind::BufferCapacity),
            None,
            *c,
        ));
    }
    Ok(())
}
// ADAPT LX05-S03/S12: raw scanner, exactly one separator, digit-only checked u64.
fn split_once(b: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let mut parts = b.split(|b| *b == separator);
    let a = parts.next()?;
    let z = parts.next()?;
    if a.is_empty() || z.is_empty() || parts.next().is_some() {
        None
    } else {
        Some((a, z))
    }
}
fn number(b: &[u8], radix: u64) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut n = 0u64;
    for &b in b {
        let d = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return None,
        };
        if d >= radix {
            return None;
        }
        n = n.checked_mul(radix)?.checked_add(d)?;
    }
    Some(n)
}
#[cfg(test)]
mod tests;
