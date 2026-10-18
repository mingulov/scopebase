// SPDX-License-Identifier: Apache-2.0
//! Parser observations on fixed owned bytes. GAP observations are not strict parsing support.
#[allow(dead_code)]
fn process_api(pid: i32, root: std::path::PathBuf) {
    let _new: fn(i32) -> procfs::ProcResult<procfs::process::Process> =
        procfs::process::Process::new;
    let _root: fn(std::path::PathBuf) -> procfs::ProcResult<procfs::process::Process> =
        procfs::process::Process::new_with_root;
    let _ = (pid, root); // No live Process is constructed.
}
#[allow(dead_code)]
fn open_api(p: &procfs::process::Process) -> procfs::ProcResult<std::fs::File> {
    p.open_relative_flags(
        "maps",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
    )
}
#[cfg(test)]
mod tests {
    use procfs_core::{
        process::{MMapPath, MemoryMaps, MountInfos},
        FromBufRead,
    };
    fn maps(bytes: &[u8]) -> procfs_core::ProcResult<MemoryMaps> {
        MemoryMaps::from_buf_read(std::io::Cursor::new(bytes))
    }
    fn mounts(bytes: &[u8]) -> procfs_core::ProcResult<MountInfos> {
        MountInfos::from_buf_read(std::io::Cursor::new(bytes))
    }
    const ROW: &[u8] = b"1000-2000 r-xp 00000000 00:01 1 /a\n";
    #[test]
    fn maps_public_fields() {
        let result = maps(ROW).unwrap();
        assert_eq!(result.len(), 1);
        let m = &result.0[0];
        assert_eq!(m.address, (0x1000, 0x2000));
        assert_eq!(m.offset, 0);
        assert_eq!(m.dev, (0, 1));
        assert_eq!(m.inode, 1);
    }
    #[test]
    fn raw_bytes_observation() {
        assert!(maps(ROW).is_ok());
        let bytes = b"1000-2000 r-xp 00000000 00:01 1 /\xff\n";
        assert!(
            maps(bytes).is_err(),
            "GAP: raw non-UTF8 path cannot be preserved"
        );
        let strict_raw_accepts = maps(bytes).is_ok();
        assert!(
            std::panic::catch_unwind(|| assert!(strict_raw_accepts, "raw path contract")).is_err()
        );
    }
    #[test]
    fn permissive_map_observations() {
        let malformed = maps(b"1000-2000 q 00000000 00:01 1 /a\n").unwrap();
        assert_eq!(malformed.len(), 1);
        let reversed = maps(b"2000-1000 r-xp 00000000 00:01 1 /a\n").unwrap();
        assert_eq!(reversed.0[0].address, (0x2000, 0x1000));
        let overlap =
            maps(b"1000-2000 r-xp 00000000 00:01 1 /a\n1800-2800 r-xp 00000000 00:01 2 /b\n")
                .unwrap();
        assert_eq!(overlap.len(), 2);
        // Sensitive controls: valid parse is setup; each stronger strict-contract assertion fails.
        assert!(std::panic::catch_unwind(|| assert!(
            malformed.len() == 0,
            "strict permission refusal"
        ))
        .is_err());
        assert!(std::panic::catch_unwind(|| assert!(
            reversed.0[0].address.0 < reversed.0[0].address.1,
            "ordered interval"
        ))
        .is_err());
        assert!(std::panic::catch_unwind(|| assert!(
            overlap.0[0].address.1 <= overlap.0[1].address.0,
            "nonoverlap"
        ))
        .is_err());
    }
    #[test]
    fn paths_observation() {
        let result = maps(b"1000-2000 r-xp 00000000 00:01 1 /a\\040b (deleted)\n").unwrap();
        match &result.0[0].pathname {
            MMapPath::Path(p) => assert_eq!(p, std::path::Path::new(r"/a\040b (deleted)")),
            other => panic!("unexpected {other:?}"),
        }
        // Observation only: neither decoding escapes nor deleted-suffix identity is supplied.
    }
    #[test]
    fn mount_ids_and_limits_observation() {
        let row = b"1 0 0:1 / / rw - tmpfs tmpfs rw\n";
        let one = mounts(row).unwrap();
        assert_eq!(one.0.len(), 1);
        assert_eq!(one.0[0].mnt_id, 1);
        let two = mounts(&[row.as_slice(), row.as_slice()].concat()).unwrap();
        assert_eq!(two.0.len(), 2);
        assert_eq!(
            two.0[0].mnt_id, two.0[1].mnt_id,
            "GAP: duplicate mount IDs retained"
        );
        assert!(std::panic::catch_unwind(|| assert_ne!(
            two.0[0].mnt_id, two.0[1].mnt_id,
            "strict unique ID contract"
        ))
        .is_err());
        for n in [2, 3] {
            assert_eq!(maps(&ROW.repeat(n)).unwrap().len(), n);
            assert_eq!(mounts(&row.repeat(n)).unwrap().0.len(), n);
        }
        // FromBufRead exposes no entry/byte/work-limit argument. These samples do not prove memory bounds.
    }
}
