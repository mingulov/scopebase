// SPDX-License-Identifier: Apache-2.0
// ADAPT P LX05-S01..S06/S12. Source and destination terms are distinct;
// exact Apache destination admission: 2026-10-18-lx05-proc.json.
use super::*;
use crate::identity::MapsFileKey;
use std::ops::Range;
pub(super) struct MapRecord {
    start: u64,
    end: u64,
    offset: u64,
    permissions: [u8; 4],
    key: MapsFileKey,
    raw_path: Option<Range<usize>>,
}
/// One fully validated ordered snapshot, with no implicit allocating clone.
pub struct MapsSnapshot {
    raw: Vec<u8>,
    records: Vec<MapRecord>,
    charges: ParseCharges,
}
#[derive(Copy, Clone)]
pub struct MapsEntry<'a> {
    record: &'a MapRecord,
    raw: &'a [u8],
}
#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum MapsPathKind {
    Absent,
    Absolute,
    Other,
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MapsPathEvidence {
    deleted: bool,
    escaped: bool,
    utf8: bool,
}
impl MapsPathEvidence {
    pub fn has_deleted_suffix(&self) -> bool {
        self.deleted
    }
    pub fn has_escaped_newline(&self) -> bool {
        self.escaped
    }
    pub fn is_utf8(&self) -> bool {
        self.utf8
    }
}
impl MapsSnapshot {
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn entries(&self) -> impl ExactSizeIterator<Item = MapsEntry<'_>> + DoubleEndedIterator {
        self.records.iter().map(|record| MapsEntry {
            record,
            raw: &self.raw,
        })
    }
    /// Half-open numeric lookup; no ELF translation or backing-file association.
    pub fn containing(&self, address: u64) -> Option<MapsEntry<'_>> {
        let i = self.records.partition_point(|r| r.start <= address);
        i.checked_sub(1)
            .and_then(|i| self.records.get(i))
            .filter(|r| address < r.end)
            .map(|record| MapsEntry {
                record,
                raw: &self.raw,
            })
    }
    pub fn charges(&self) -> ParseCharges {
        self.charges
    }
}
impl<'a> MapsEntry<'a> {
    pub fn start(&self) -> u64 {
        self.record.start
    }
    pub fn end(&self) -> u64 {
        self.record.end
    }
    pub fn file_offset(&self) -> u64 {
        self.record.offset
    }
    pub fn file_offset_at(&self, address: u64) -> Option<u64> {
        if address < self.record.start || address >= self.record.end {
            return None;
        }
        self.record.offset.checked_add(address - self.record.start)
    }
    pub fn permissions(&self) -> [u8; 4] {
        self.record.permissions
    }
    pub fn file_key(&self) -> MapsFileKey {
        self.record.key
    }
    pub fn raw_path(&self) -> Option<&'a [u8]> {
        self.record.raw_path.as_ref().map(|r| &self.raw[r.clone()])
    }
    pub fn path_kind(&self) -> MapsPathKind {
        match self.raw_path() {
            None => MapsPathKind::Absent,
            Some(b) if b.starts_with(b"/") => MapsPathKind::Absolute,
            _ => MapsPathKind::Other,
        }
    }
    pub fn path_evidence(&self) -> MapsPathEvidence {
        let b = self.raw_path().unwrap_or_default();
        MapsPathEvidence {
            deleted: b.ends_with(b" (deleted)"),
            escaped: b.windows(4).any(|w| w == b"\\012"),
            utf8: std::str::from_utf8(b).is_ok(),
        }
    }
}
macro_rules! debug_label {
    ($t:ty,$label:literal) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($label)
            }
        }
    };
}
debug_label!(MapsSnapshot, "MapsSnapshot");
debug_label!(MapsEntry<'_>, "MapsEntry");
debug_label!(MapsPathKind, "MapsPathKind");
debug_label!(MapsPathEvidence, "MapsPathEvidence");
/// Parse every row or refuse the entire caller-provided snapshot.
pub fn parse_maps(input: &[u8], limits: ParseLimits) -> Result<MapsSnapshot, LinuxError> {
    parse_inner(input, limits, ReserveMode::Normal)
}
pub(super) fn parse_inner(
    input: &[u8],
    limits: ParseLimits,
    mode: ReserveMode,
) -> Result<MapsSnapshot, LinuxError> {
    let stage = Stage::ParseMaps;
    let mut c = ParseCharges::new(input.len());
    let n = preflight(input, limits, stage, c)?;
    if capacity_request(input.len(), n, false).is_none() {
        return Err(error(
            stage,
            Reason::LimitExceeded(LimitKind::BufferCapacity),
            None,
            c,
        ));
    }
    let mut raw = Vec::new();
    let mut records = Vec::<MapRecord>::new();
    if n != 0 {
        reserve(&mut raw, input.len(), true, &mut c, stage, mode)?;
        reserve(&mut records, n, false, &mut c, stage, mode)?;
        raw.extend_from_slice(input);
    }
    let mut base = 0;
    for (row, line) in input.split_inclusive(|b| *b == b'\n').enumerate() {
        let line = &line[..line.len() - 1];
        let record = parse_line(line, base)
            .filter(|r| r.offset.checked_add(r.end - r.start - 1).is_some())
            .filter(|r| records.last().is_none_or(|prev| prev.end <= r.start))
            .ok_or_else(|| error(stage, Reason::Malformed, Some(row + 1), c))?;
        records.push(record);
        c.entries_validated += 1;
        base += line.len() + 1;
    }
    Ok(MapsSnapshot {
        raw,
        records,
        charges: c,
    })
}
fn field<'a>(line: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    while line.get(*cursor).is_some_and(|b| *b == b' ' || *b == b'\t') {
        *cursor += 1
    }
    let start = *cursor;
    while line.get(*cursor).is_some_and(|b| *b != b' ' && *b != b'\t') {
        *cursor += 1
    }
    if start == *cursor {
        None
    } else {
        Some(&line[start..*cursor])
    }
}
fn parse_line(line: &[u8], base: usize) -> Option<MapRecord> {
    let mut cursor = 0;
    let range = field(line, &mut cursor)?;
    let perms = field(line, &mut cursor)?;
    let offset = field(line, &mut cursor)?;
    let device = field(line, &mut cursor)?;
    let inode = field(line, &mut cursor)?;
    let (start, end) = split_once(range, b'-')?;
    let start = number(start, 16)?;
    let end = number(end, 16)?;
    if start >= end {
        return None;
    }
    let permissions: [u8; 4] = perms.try_into().ok()?;
    if !matches!(permissions[0], b'r' | b'-')
        || !matches!(permissions[1], b'w' | b'-')
        || !matches!(permissions[2], b'x' | b'-')
        || !matches!(permissions[3], b'p' | b's')
    {
        return None;
    }
    let offset = number(offset, 16)?;
    let (major, minor) = split_once(device, b':')?;
    let key = MapsFileKey {
        major: number(major, 16)?,
        minor: number(minor, 16)?,
        inode: number(inode, 10)?,
    };
    while line.get(cursor).is_some_and(|b| *b == b' ' || *b == b'\t') {
        cursor += 1
    }
    let raw_path = (cursor < line.len()).then(|| base + cursor..base + line.len());
    Some(MapRecord {
        start,
        end,
        offset,
        permissions,
        key,
        raw_path,
    })
}
