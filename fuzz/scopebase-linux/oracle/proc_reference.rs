// SPDX-License-Identifier: Apache-2.0
//! Independently authored allocating test oracle: u128 arithmetic, linear address
//! lookup and quadratic duplicate checks; no production parsing/index/serializer.
#![allow(dead_code)]
use scopebase_linux::{
    error::{LimitKind, Reason},
    procfs::ParseLimits,
};
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Refusal {
    pub reason: Reason,
    pub line: Option<usize>,
}
fn malformed(line: usize) -> Refusal {
    Refusal {
        reason: Reason::Malformed,
        line: Some(line),
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Map {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub major: u64,
    pub minor: u64,
    pub inode: u64,
    pub permissions: [u8; 4],
    pub path: Option<Vec<u8>>,
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Field {
    pub raw: Vec<u8>,
    pub decoded: Vec<u8>,
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Optional {
    Shared(u64),
    Master(u64),
    PropagateFrom(u64),
    Unbindable,
    Unknown,
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Mount {
    pub id: u64,
    pub parent: u64,
    pub major: u64,
    pub minor: u64,
    pub fields: [Field; 6],
    pub optional: Vec<(Field, Optional)>,
}
pub fn number(b: &[u8], radix: u32) -> Result<u64, ()> {
    if b.is_empty()
        || !b.iter().all(|x| match radix {
            16 => x.is_ascii_hexdigit(),
            _ => x.is_ascii_digit(),
        })
    {
        return Err(());
    }
    let s = std::str::from_utf8(b).map_err(|_| ())?;
    u128::from_str_radix(s, radix)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}
pub fn decode(b: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != 92 {
            if b[i] == 0 {
                return Err(());
            }
            out.push(b[i]);
            i += 1;
        } else {
            let d = b.get(i + 1..i + 4).ok_or(())?;
            if !d.iter().all(|x| (b'0'..=b'7').contains(x)) {
                return Err(());
            }
            let n = 64 * (d[0] - 48) as u16 + 8 * (d[1] - 48) as u16 + (d[2] - 48) as u16;
            if !(1..=255).contains(&n) {
                return Err(());
            }
            out.push(n as u8);
            i += 4;
        }
    }
    Ok(out)
}
pub fn duplicate_line(n: &[u64]) -> Option<usize> {
    let mut lowest = None;
    for i in 0..n.len() {
        for j in i + 1..n.len() {
            if n[i] == n[j] && lowest.is_none_or(|(v, _)| n[i] < v) {
                lowest = Some((n[i], j + 1));
            }
        }
    }
    lowest.map(|(_, line)| line)
}
fn shape(b: &[u8], l: ParseLimits) -> Result<Vec<&[u8]>, Refusal> {
    if l.max_bytes == 0 || l.max_entries == 0 || l.max_line_bytes == 0 {
        return Err(Refusal {
            reason: Reason::InvalidInput,
            line: None,
        });
    }
    if b.len() > l.max_bytes {
        return Err(Refusal {
            reason: Reason::LimitExceeded(LimitKind::InputBytes),
            line: None,
        });
    }
    let rows: Vec<_> = b.split_inclusive(|b| *b == 10).collect();
    let mut out = vec![];
    for (i, row) in rows.iter().enumerate() {
        let row = row.strip_suffix(b"\n").unwrap_or(row);
        let reason = if row.len() > l.max_line_bytes {
            Some(Reason::LimitExceeded(LimitKind::LineBytes))
        } else if i >= l.max_entries {
            Some(Reason::LimitExceeded(LimitKind::Entries))
        } else if row.is_empty() || row.contains(&0) {
            Some(Reason::Malformed)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Refusal {
                reason,
                line: Some(i + 1),
            });
        }
        out.push(row)
    }
    if !b.is_empty() && !b.ends_with(b"\n") {
        return Err(malformed(rows.len()));
    }
    Ok(out)
}
fn pair(b: &[u8], sep: u8) -> Result<(&[u8], &[u8]), ()> {
    let p: Vec<_> = b.split(|b| *b == sep).collect();
    if p.len() != 2 {
        return Err(());
    }
    Ok((p[0], p[1]))
}
pub fn maps(b: &[u8], l: ParseLimits) -> Result<Vec<Map>, Refusal> {
    let rows = shape(b, l)?;
    let mut out: Vec<Map> = vec![];
    for (i, row) in rows.into_iter().enumerate() {
        let parse = || -> Result<Map, ()> {
            let spans: Vec<_> = row
                .split(|x| *x == 32 || *x == 9)
                .filter(|x| !x.is_empty())
                .collect();
            if spans.len() < 5 {
                return Err(());
            }
            let (a, z) = pair(spans[0], 45)?;
            let (d0, d1) = pair(spans[3], 58)?;
            let p = spans[1];
            if p.len() != 4
                || !b"r-".contains(&p[0])
                || !b"w-".contains(&p[1])
                || !b"x-".contains(&p[2])
                || !b"ps".contains(&p[3])
            {
                return Err(());
            }
            // Find the pathname by skipping exactly five original structural spans.
            let mut at = 0;
            for _ in 0..5 {
                while at < row.len() && (row[at] == 32 || row[at] == 9) {
                    at += 1
                }
                while at < row.len() && row[at] != 32 && row[at] != 9 {
                    at += 1
                }
            }
            while at < row.len() && (row[at] == 32 || row[at] == 9) {
                at += 1
            }
            let m = Map {
                start: number(a, 16)?,
                end: number(z, 16)?,
                offset: number(spans[2], 16)?,
                major: number(d0, 16)?,
                minor: number(d1, 16)?,
                inode: number(spans[4], 10)?,
                permissions: p.try_into().map_err(|_| ())?,
                path: (at < row.len()).then(|| row[at..].to_vec()),
            };
            if m.start >= m.end
                || m.offset as u128 + m.end as u128 - m.start as u128 - 1 > u64::MAX as u128
            {
                return Err(());
            }
            for prev in &out {
                if prev.start >= m.start || prev.end > m.start {
                    return Err(());
                }
            }
            Ok(m)
        };
        out.push(parse().map_err(|_| malformed(i + 1))?)
    }
    Ok(out)
}
pub fn offset_at(m: &[Map], a: u64) -> Option<u64> {
    m.iter()
        .find(|m| m.start <= a && a < m.end)
        .map(|m| (m.offset as u128 + a as u128 - m.start as u128) as u64)
}
fn positive(b: &[u8]) -> Result<u64, ()> {
    let n = number(b, 10)?;
    if n == 0 {
        Err(())
    } else {
        Ok(n)
    }
}
fn field(b: &[u8]) -> Result<Field, ()> {
    Ok(Field {
        raw: b.to_vec(),
        decoded: decode(b)?,
    })
}
fn optional(b: &[u8]) -> Result<Optional, ()> {
    if b == b"unbindable" {
        return Ok(Optional::Unbindable);
    }
    if b.starts_with(b"unbindable:") {
        return Err(());
    }
    for (key, which) in [
        (b"shared".as_slice(), 0),
        (b"master", 1),
        (b"propagate_from", 2),
    ] {
        if b == key {
            return Err(());
        }
        if let Some(value) = b
            .strip_prefix(key)
            .and_then(|suffix| suffix.strip_prefix(b":"))
        {
            let n = positive(value)?;
            return Ok(match which {
                0 => Optional::Shared(n),
                1 => Optional::Master(n),
                _ => Optional::PropagateFrom(n),
            });
        }
    }
    Ok(Optional::Unknown)
}
pub fn mounts(b: &[u8], l: ParseLimits) -> Result<Vec<Mount>, Refusal> {
    let rows = shape(b, l)?;
    let mut out = vec![];
    for (i, row) in rows.into_iter().enumerate() {
        let parse = || -> Result<Mount, ()> {
            if row.starts_with(b" ") || row.ends_with(b" ") || row.contains(&9) {
                return Err(());
            }
            let tokens: Vec<_> = row.split(|b| *b == 32).filter(|s| !s.is_empty()).collect();
            if tokens.len() < 10 {
                return Err(());
            }
            let sep = (6..tokens.len()).find(|&n| tokens[n] == b"-").ok_or(())?;
            if tokens.len() != sep + 4 {
                return Err(());
            }
            let id = positive(tokens[0])?;
            let parent = positive(tokens[1])?;
            let (major, minor) = pair(tokens[2], 58)?;
            let major = number(major, 10)?;
            let minor = number(minor, 10)?;
            let fields = [
                field(tokens[3])?,
                field(tokens[4])?,
                field(tokens[5])?,
                field(tokens[sep + 1])?,
                field(tokens[sep + 2])?,
                field(tokens[sep + 3])?,
            ];
            if !fields[0].decoded.starts_with(b"/") || !fields[1].decoded.starts_with(b"/") {
                return Err(());
            }
            let mut optionals: Vec<(Field, Optional)> = vec![];
            for t in &tokens[6..sep] {
                let f = field(t)?;
                let k = optional(&f.decoded)?;
                for (_, prev) in &optionals {
                    let duplicate = matches!(
                        (&k, prev),
                        (Optional::Shared(_), Optional::Shared(_))
                            | (Optional::Master(_), Optional::Master(_))
                            | (Optional::PropagateFrom(_), Optional::PropagateFrom(_))
                            | (Optional::Unbindable, Optional::Unbindable)
                    );
                    if duplicate {
                        return Err(());
                    }
                }
                optionals.push((f, k));
            }
            Ok(Mount {
                id,
                parent,
                major,
                minor,
                fields,
                optional: optionals,
            })
        };
        out.push(parse().map_err(|_| malformed(i + 1))?)
    }
    let ids: Vec<_> = out.iter().map(|m| m.id).collect();
    if let Some(line) = duplicate_line(&ids) {
        return Err(malformed(line));
    }
    Ok(out)
}
