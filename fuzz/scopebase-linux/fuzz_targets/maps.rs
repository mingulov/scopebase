#![no_main]
// SPDX-License-Identifier: Apache-2.0
use libfuzzer_sys::fuzz_target;
use scopebase_linux::{
    error::Stage,
    procfs::{parse_maps, MapsPathKind, ParseLimits},
};
#[path = "../oracle/proc_reference.rs"]
mod reference;
const LIMITS: ParseLimits = ParseLimits {
    max_bytes: 4096,
    max_entries: 64,
    max_line_bytes: 512,
};
fuzz_target!(|data: &[u8]| {
    match (reference::maps(data, LIMITS), parse_maps(data, LIMITS)) {
        (Err(w), Err(e)) => {
            assert_eq!(e.stage(), Stage::ParseMaps);
            assert_eq!((e.reason(), e.parse_line()), (w.reason, w.line));
        }
        (Ok(rows), Ok(s)) => {
            assert_eq!(s.len(), rows.len());
            assert_eq!(s.charges().input_bytes(), data.len());
            assert_eq!(s.charges().entries_validated(), rows.len());
            assert_eq!(
                s.charges().allocation_attempts(),
                if rows.is_empty() { 0 } else { 2 }
            );
            for (e, w) in s.entries().zip(&rows) {
                assert_eq!(
                    (
                        e.start(),
                        e.end(),
                        e.file_offset(),
                        e.permissions(),
                        e.file_key().device_major(),
                        e.file_key().device_minor(),
                        e.file_key().inode(),
                        e.raw_path()
                    ),
                    (
                        w.start,
                        w.end,
                        w.offset,
                        w.permissions,
                        w.major,
                        w.minor,
                        w.inode,
                        w.path.as_deref()
                    )
                );
                let raw = w.path.as_deref().unwrap_or_default();
                assert_eq!(
                    (
                        e.path_evidence().has_deleted_suffix(),
                        e.path_evidence().has_escaped_newline(),
                        e.path_evidence().is_utf8()
                    ),
                    (
                        raw.ends_with(b" (deleted)"),
                        raw.windows(4).any(|s| s == b"\\012"),
                        std::str::from_utf8(raw).is_ok()
                    )
                );
                assert_eq!(
                    e.path_kind(),
                    match &w.path {
                        None => MapsPathKind::Absent,
                        Some(p) if p.starts_with(b"/") => MapsPathKind::Absolute,
                        _ => MapsPathKind::Other,
                    }
                );
                for addr in [w.start, w.end - 1, w.end, w.start.wrapping_sub(1)] {
                    let expected = if w.start <= addr && addr < w.end {
                        Some((w.offset as u128 + addr as u128 - w.start as u128) as u64)
                    } else {
                        None
                    };
                    assert_eq!(e.file_offset_at(addr), expected);
                }
            }
            for addr in rows
                .iter()
                .flat_map(|r| [r.start, r.end - 1, r.end])
                .chain([0, u64::MAX])
            {
                let expected = rows.iter().find(|r| r.start <= addr && addr < r.end);
                assert_eq!(
                    s.containing(addr).map(|e| e.start()),
                    expected.map(|r| r.start)
                );
                assert_eq!(
                    s.containing(addr).and_then(|e| e.file_offset_at(addr)),
                    reference::offset_at(&rows, addr)
                );
            }
        }
        _ => panic!("independent maps acceptance mismatch"),
    }
});
