// SPDX-License-Identifier: Apache-2.0
// ADAPT LX05-S14 decimal mount number/device facts. Complete byte grammar,
// fixed arenas and descriptive borrowed provenance are the frozen NEW seams.
use super::*;
use crate::identity::MountDevice;
use std::ops::Range;
struct FieldSpan {
    raw: Range<usize>,
    decoded_len: usize,
}
pub(super) struct MountRecord {
    id: u64,
    parent: u64,
    device: MountDevice,
    fields: [FieldSpan; 6],
    optional_block: Range<usize>,
}
pub struct MountTableSnapshot {
    raw: Vec<u8>,
    decoded: Vec<u8>,
    records: Vec<MountRecord>,
    sorted_id_index: Vec<(u64, usize)>,
    charges: ParseCharges,
}
#[derive(Copy, Clone)]
pub struct MountEntry<'a> {
    table: &'a MountTableSnapshot,
    record: &'a MountRecord,
}
/// Equality is local to a single borrowed table object, never a runtime view.
#[derive(Copy, Clone)]
pub struct ParsedMountId<'a> {
    table: &'a MountTableSnapshot,
    number: u64,
}
impl ParsedMountId<'_> {
    pub fn number(&self) -> u64 {
        self.number
    }
}
impl PartialEq for ParsedMountId<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.table, other.table) && self.number == other.number
    }
}
impl Eq for ParsedMountId<'_> {}
#[derive(Copy, Clone)]
pub struct MountField<'a> {
    raw: &'a [u8],
    decoded: &'a [u8],
}
impl<'a> MountField<'a> {
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
    pub fn decoded(&self) -> &'a [u8] {
        self.decoded
    }
}
#[derive(Copy, Clone)]
pub struct MountOptionalField<'a> {
    field: MountField<'a>,
    kind: MountOptionalKind,
}
impl<'a> MountOptionalField<'a> {
    pub fn field(&self) -> MountField<'a> {
        self.field
    }
    pub fn kind(&self) -> MountOptionalKind {
        self.kind
    }
}
#[derive(Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum MountOptionalKind {
    Shared(u64),
    Master(u64),
    PropagateFrom(u64),
    Unbindable,
    Unknown,
}
impl MountTableSnapshot {
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn entries(&self) -> impl ExactSizeIterator<Item = MountEntry<'_>> + DoubleEndedIterator {
        self.records.iter().map(|record| MountEntry {
            table: self,
            record,
        })
    }
    /// Raw lexical lookup only in this already validated table.
    pub fn entry_by_number(&self, number: u64) -> Option<MountEntry<'_>> {
        self.sorted_id_index
            .binary_search_by_key(&number, |&(n, _)| n)
            .ok()
            .map(|i| MountEntry {
                table: self,
                record: &self.records[self.sorted_id_index[i].1],
            })
    }
    pub fn charges(&self) -> ParseCharges {
        self.charges
    }
    fn field(&self, f: &FieldSpan) -> MountField<'_> {
        MountField {
            raw: &self.raw[f.raw.clone()],
            decoded: &self.decoded[f.raw.start..f.raw.start + f.decoded_len],
        }
    }
}
impl<'a> MountEntry<'a> {
    pub fn id(&self) -> ParsedMountId<'a> {
        ParsedMountId {
            table: self.table,
            number: self.record.id,
        }
    }
    pub fn parent_id(&self) -> ParsedMountId<'a> {
        ParsedMountId {
            table: self.table,
            number: self.record.parent,
        }
    }
    pub fn device(&self) -> MountDevice {
        self.record.device
    }
    pub fn root(&self) -> MountField<'a> {
        self.table.field(&self.record.fields[0])
    }
    pub fn mount_point(&self) -> MountField<'a> {
        self.table.field(&self.record.fields[1])
    }
    pub fn mount_options(&self) -> MountField<'a> {
        self.table.field(&self.record.fields[2])
    }
    pub fn filesystem_type(&self) -> MountField<'a> {
        self.table.field(&self.record.fields[3])
    }
    pub fn source(&self) -> MountField<'a> {
        self.table.field(&self.record.fields[4])
    }
    pub fn super_options(&self) -> MountField<'a> {
        self.table.field(&self.record.fields[5])
    }
    pub fn optional_fields(&self) -> impl Iterator<Item = MountOptionalField<'a>> {
        let table = self.table;
        let block = self.record.optional_block.clone();
        let mut cursor = block.start;
        std::iter::from_fn(move || {
            if cursor >= block.end {
                return None;
            }
            let r = token(&table.raw[..block.end], &mut cursor)?;
            let len = decoded_length(&table.raw[r.clone()]);
            let field = MountField {
                raw: &table.raw[r.clone()],
                decoded: &table.decoded[r.start..r.start + len],
            };
            Some(MountOptionalField {
                field,
                kind: optional_kind(field.decoded).expect("validated optional token"),
            })
        })
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
debug_label!(MountTableSnapshot, "MountTableSnapshot");
debug_label!(MountEntry<'_>, "MountEntry");
debug_label!(ParsedMountId<'_>, "ParsedMountId");
debug_label!(MountField<'_>, "MountField");
debug_label!(MountOptionalField<'_>, "MountOptionalField");
debug_label!(MountOptionalKind, "MountOptionalKind");
pub fn parse_mountinfo(
    input: &[u8],
    limits: ParseLimits,
) -> Result<MountTableSnapshot, LinuxError> {
    parse_inner(input, limits, ReserveMode::Normal)
}
pub(super) fn parse_inner(
    input: &[u8],
    limits: ParseLimits,
    mode: ReserveMode,
) -> Result<MountTableSnapshot, LinuxError> {
    let stage = Stage::ParseMounts;
    let mut c = ParseCharges::new(input.len());
    let n = preflight(input, limits, stage, c)?;
    if capacity_request(input.len(), n, true).is_none() {
        return Err(error(
            stage,
            Reason::LimitExceeded(LimitKind::BufferCapacity),
            None,
            c,
        ));
    }
    let (mut raw, mut decoded, mut records, mut index) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    if n != 0 {
        reserve(&mut raw, input.len(), true, &mut c, stage, mode)?;
        reserve(&mut decoded, input.len(), true, &mut c, stage, mode)?;
        reserve(&mut records, n, false, &mut c, stage, mode)?;
        reserve(&mut index, n, false, &mut c, stage, mode)?;
        raw.extend_from_slice(input);
        decoded.extend_from_slice(&raw);
    }
    let mut base = 0;
    for (row, line) in input.split_inclusive(|b| *b == 10).enumerate() {
        let end = base + line.len() - 1;
        let record = parse_line(&raw, &mut decoded, base..end)
            .ok_or_else(|| error(stage, Reason::Malformed, Some(row + 1), c))?;
        index.push((record.id, row));
        records.push(record);
        c.entries_validated += 1;
        base = end + 1;
    }
    index.sort_unstable_by_key(|&(number, row)| (number, row));
    for pair in index.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(error(stage, Reason::Malformed, Some(pair[1].1 + 1), c));
        }
    }
    Ok(MountTableSnapshot {
        raw,
        decoded,
        records,
        sorted_id_index: index,
        charges: c,
    })
}
fn token(raw: &[u8], cursor: &mut usize) -> Option<Range<usize>> {
    while raw.get(*cursor) == Some(&b' ') {
        *cursor += 1
    }
    let start = *cursor;
    while raw.get(*cursor).is_some_and(|b| *b != b' ') {
        *cursor += 1
    }
    if start == *cursor {
        None
    } else {
        Some(start..*cursor)
    }
}
fn positive(raw: &[u8]) -> Option<u64> {
    number(raw, 10).filter(|n| *n != 0)
}
fn parse_line(raw: &[u8], decoded: &mut [u8], line: Range<usize>) -> Option<MountRecord> {
    let bytes = &raw[line.clone()];
    if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') || bytes.contains(&b'\t') {
        return None;
    }
    let r = &raw[..line.end];
    let mut cursor = line.start;
    let mut fixed: [Range<usize>; 6] = std::array::from_fn(|_| 0..0);
    for f in &mut fixed {
        *f = token(r, &mut cursor)?;
    }
    let optional_start = cursor;
    let separator = loop {
        let t = token(r, &mut cursor)?;
        if &raw[t.clone()] == b"-" {
            break t;
        }
    };
    let mut tail: [Range<usize>; 3] = std::array::from_fn(|_| 0..0);
    for t in &mut tail {
        *t = token(r, &mut cursor)?;
    }
    if token(r, &mut cursor).is_some() {
        return None;
    }
    let id = positive(&raw[fixed[0].clone()])?;
    let parent = positive(&raw[fixed[1].clone()])?;
    let (major, minor) = split_once(&raw[fixed[2].clone()], b':')?;
    let device = MountDevice {
        major: number(major, 10)?,
        minor: number(minor, 10)?,
    };
    let mut fields: [FieldSpan; 6] = std::array::from_fn(|_| FieldSpan {
        raw: 0..0,
        decoded_len: 0,
    });
    for i in 0..3 {
        let span = decode(raw, decoded, fixed[i + 3].clone())?;
        let first = decoded[span.raw.start];
        // Mount points stay strict: the kernel always renders absolute paths.
        if i == 1 && first != b'/' {
            return None;
        }
        // LX06 repair (2026-10-23), ratified by controller ruling
        // RATIFY-2026-10-23-LX05-NSFS: the frozen LX05 contract required
        // roots to begin with `/`, but real kernels render namespace
        // pseudo-names (`net:[4026532307]`, `mnt:[...]`, ...) as nsfs mount
        // roots, which refused every real mount table containing a netns
        // bind. Accept exactly that documented shape; every other non-`/`
        // root (including the existing `relative` bad-control) still
        // refuses, and unknown future shapes fail closed.
        if i == 0
            && first != b'/'
            && !is_ns_pseudo_root(&decoded[span.raw.start..span.raw.start + span.decoded_len])
        {
            return None;
        }
        fields[i] = span;
    }
    let optional_block = optional_start..separator.start;
    let mut at = optional_start;
    let mut seen = 0u8;
    while let Some(t) = token(&raw[..separator.start], &mut at) {
        let s = decode(raw, decoded, t)?;
        let k = optional_kind(&decoded[s.raw.start..s.raw.start + s.decoded_len])?;
        let bit = match k {
            MountOptionalKind::Shared(_) => 1,
            MountOptionalKind::Master(_) => 2,
            MountOptionalKind::PropagateFrom(_) => 4,
            MountOptionalKind::Unbindable => 8,
            MountOptionalKind::Unknown => 0,
        };
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
    }
    for i in 0..3 {
        fields[i + 3] = decode(raw, decoded, tail[i].clone())?;
    }
    Some(MountRecord {
        id,
        parent,
        device,
        fields,
        optional_block,
    })
}
fn decode(raw: &[u8], decoded: &mut [u8], range: Range<usize>) -> Option<FieldSpan> {
    let (mut read, mut write) = (range.start, range.start);
    while read < range.end {
        let b = raw[read];
        if b != b'\\' {
            decoded[write] = b;
            read += 1;
        } else {
            let digits = raw.get(read + 1..read.checked_add(4)?)?;
            if read + 4 > range.end || !digits.iter().all(|b| matches!(b, b'0'..=b'7')) {
                return None;
            }
            let n = (digits[0] - b'0') as u16 * 64
                + (digits[1] - b'0') as u16 * 8
                + (digits[2] - b'0') as u16;
            if n == 0 || n > 255 {
                return None;
            }
            decoded[write] = n as u8;
            read += 4;
        }
        write += 1;
    }
    Some(FieldSpan {
        decoded_len: write - range.start,
        raw: range,
    })
}
/// Kernel namespace pseudo-name as rendered for nsfs mount roots:
/// `name:[digits]` with a nonempty lowercase alphanumeric/underscore name
/// (`net`, `uts`, `mnt`, `time_for_children`, ...) and nonempty decimal
/// digits. Same shape family as the `pid:[N]`/`mnt:[N]` link grammar.
/// Unknown shapes fail closed (refuse), never accept.
fn is_ns_pseudo_root(decoded: &[u8]) -> bool {
    let Some(colon) = decoded.iter().position(|b| *b == b':') else {
        return false;
    };
    let (name, rest) = decoded.split_at(colon);
    if name.is_empty()
        || !name
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
    {
        return false;
    }
    let Some(inner) = rest.strip_prefix(b":[") else {
        return false;
    };
    let Some(digits) = inner.strip_suffix(b"]") else {
        return false;
    };
    !digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit())
}
fn decoded_length(raw: &[u8]) -> usize {
    let (mut i, mut n) = (0, 0);
    while i < raw.len() {
        i += if raw[i] == b'\\' { 4 } else { 1 };
        n += 1;
    }
    n
}
fn optional_kind(b: &[u8]) -> Option<MountOptionalKind> {
    for (key, kind) in [
        (b"shared".as_slice(), 0),
        (b"master", 1),
        (b"propagate_from", 2),
    ] {
        if b == key {
            return None;
        }
        if b.starts_with(key) && b.get(key.len()) == Some(&b':') {
            let n = positive(&b[key.len() + 1..])?;
            return Some(match kind {
                0 => MountOptionalKind::Shared(n),
                1 => MountOptionalKind::Master(n),
                _ => MountOptionalKind::PropagateFrom(n),
            });
        }
    }
    if b == b"unbindable" {
        Some(MountOptionalKind::Unbindable)
    } else if b.starts_with(b"unbindable:") {
        None
    } else {
        Some(MountOptionalKind::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::is_ns_pseudo_root;

    #[test]
    fn ns_pseudo_roots_accept_exact_kernel_shapes() {
        // Observed real nsfs mount roots.
        for good in [
            b"net:[4026532307]".as_slice(),
            b"mnt:[4026531840]",
            b"uts:[4026531838]",
            b"pid:[4026531836]",
            b"ipc:[4026531839]",
            b"cgroup:[4026531835]",
            b"time:[4026531834]",
            b"user:[4026531837]",
            b"time_for_children:[4026531834]",
            b"a:[0]",
        ] {
            assert!(is_ns_pseudo_root(good), "{}", String::from_utf8_lossy(good));
        }
        // Everything else fails closed, including the existing `relative`
        // bad-control and near-miss bracket shapes.
        for bad in [
            b"relative".as_slice(),
            b"",
            b"/",
            b"net:",
            b"net:[]",
            b"net:[4026532307",
            b"net:4026532307]",
            b"net:[40a6532307]",
            b"[4026532307]",
            b":[4026532307]",
            b"net:[4026532307]x",
            b"Net:[1]",
            b"net-name:[1]",
            b"net:[1]:[2]",
            b"/net:[1]",
        ] {
            assert!(!is_ns_pseudo_root(bad), "{}", String::from_utf8_lossy(bad));
        }
    }
}
