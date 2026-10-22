#![no_main]
// SPDX-License-Identifier: Apache-2.0
use libfuzzer_sys::fuzz_target;
use scopebase_linux::{
    error::Stage,
    procfs::{parse_mountinfo, MountOptionalKind, ParseLimits},
};
#[path = "../oracle/proc_reference.rs"]
mod reference;
const LIMITS: ParseLimits = ParseLimits {
    max_bytes: 4096,
    max_entries: 64,
    max_line_bytes: 512,
};
fuzz_target!(|data: &[u8]| {
    match (
        reference::mounts(data, LIMITS),
        parse_mountinfo(data, LIMITS),
    ) {
        (Err(w), Err(e)) => {
            assert_eq!(e.stage(), Stage::ParseMounts);
            assert_eq!((e.reason(), e.parse_line()), (w.reason, w.line));
        }
        (Ok(rows), Ok(s)) => {
            assert_eq!(s.len(), rows.len());
            assert_eq!(s.charges().input_bytes(), data.len());
            assert_eq!(s.charges().entries_validated(), rows.len());
            assert_eq!(
                s.charges().allocation_attempts(),
                if rows.is_empty() { 0 } else { 4 }
            );
            let other = parse_mountinfo(data, LIMITS).unwrap();
            assert!(s.entry_by_number(0).is_none());
            for (e, w) in s.entries().zip(rows) {
                assert_eq!(
                    (
                        e.id().number(),
                        e.parent_id().number(),
                        e.device().major(),
                        e.device().minor()
                    ),
                    (w.id, w.parent, w.major, w.minor)
                );
                assert_eq!(s.entry_by_number(w.id).unwrap().id(), e.id());
                assert_ne!(other.entry_by_number(w.id).unwrap().id(), e.id());
                if let Some(parent) = s.entry_by_number(w.parent) {
                    assert_eq!(parent.id(), e.parent_id());
                }
                for (f, w) in [
                    e.root(),
                    e.mount_point(),
                    e.mount_options(),
                    e.filesystem_type(),
                    e.source(),
                    e.super_options(),
                ]
                .into_iter()
                .zip(w.fields)
                {
                    assert_eq!(
                        (f.raw(), f.decoded()),
                        (w.raw.as_slice(), w.decoded.as_slice())
                    );
                }
                let fields: Vec<_> = e.optional_fields().collect();
                assert_eq!(fields.len(), w.optional.len());
                for (f, (w, kind)) in fields.into_iter().zip(w.optional) {
                    assert_eq!(
                        (f.field().raw(), f.field().decoded()),
                        (w.raw.as_slice(), w.decoded.as_slice())
                    );
                    assert_eq!(
                        f.kind(),
                        match kind {
                            reference::Optional::Shared(n) => MountOptionalKind::Shared(n),
                            reference::Optional::Master(n) => MountOptionalKind::Master(n),
                            reference::Optional::PropagateFrom(n) =>
                                MountOptionalKind::PropagateFrom(n),
                            reference::Optional::Unbindable => MountOptionalKind::Unbindable,
                            reference::Optional::Unknown => MountOptionalKind::Unknown,
                        }
                    );
                }
            }
        }
        _ => panic!("independent mountinfo acceptance mismatch"),
    }
});
