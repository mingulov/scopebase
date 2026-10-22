// SPDX-License-Identifier: Apache-2.0
// ADAPT K exact possible-lane lookup and L scratch-before-success commitment.
use super::{
    budget::{self, Work},
    error, native,
    provenance::LiveCpuTopology,
    CpuTopology, MapExpectation, MapMetadata, PerCpuGeometry,
};
use crate::{ErrorKind as K, Limits, OperationError, Stage as S};
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;
/// Actual retained map and internally acquired native topology. No raw FD or
/// replacement geometry is exposed; values remain opaque packed lane bytes.
pub struct ValidatedMap {
    pub(super) fd: OwnedFd,
    pub(super) metadata: MapMetadata,
    pub(super) geometry: PerCpuGeometry,
    topology: LiveCpuTopology,
    limits: Limits,
}
fn flags(kind: u32) -> u32 {
    if kind == 5 {
        0x1c1
    } else {
        0x180
    }
}
fn expectation(e: &MapExpectation) -> Result<(), OperationError> {
    if !matches!(e.map_type, 5 | 6) {
        return Err(error(K::Unsupported, S::Admission));
    }
    if e.key_size == 0
        || e.value.size == 0
        || e.max_entries == 0
        || !(1..=8).contains(&e.value.alignment)
        || !e.value.alignment.is_power_of_two()
        || e.btf
            .is_some_and(|b| b.key_type_id == 0 || b.value_type_id == 0)
    {
        return Err(error(K::InvalidInput, S::Admission));
    }
    u32::try_from(e.value.size).map_err(|_| error(K::Overflow, S::Admission))?;
    if e.required_flags & !flags(e.map_type) != 0 {
        return Err(error(K::Unsupported, S::Admission));
    }
    Ok(())
}
fn metadata(
    b: &[u8; 88],
    info_len: usize,
    e: &MapExpectation,
) -> Result<MapMetadata, OperationError> {
    let u = |at| native::u32at(b, at);
    let m = MapMetadata {
        map_type: u(0),
        map_id: u(4),
        key_size: u(8),
        value_size: u(12),
        max_entries: u(16),
        flags: u(20),
        btf_id: u(64),
        btf_key_type_id: u(68),
        btf_value_type_id: u(72),
    };
    if !matches!(m.map_type, 5 | 6) {
        return Err(error(K::Unsupported, S::Metadata));
    }
    if m.map_type != e.map_type
        || m.key_size != e.key_size
        || m.value_size as usize != e.value.size
        || m.max_entries != e.max_entries
        || m.map_id == 0
        || (m.map_type == 6 && m.key_size != 4)
    {
        return Err(error(K::Incompatible, S::Metadata));
    }
    if u(40) != 0
        || u(44) != 0
        || native::u64at(b, 48) != 0
        || native::u64at(b, 56) != 0
        || (info_len >= 80 && u(76) != 0)
        || (info_len >= 88 && native::u64at(b, 80) != 0)
    {
        return Err(error(K::Unsupported, S::Metadata));
    }
    if m.flags & !flags(m.map_type) != 0 {
        return Err(error(K::Unsupported, S::Metadata));
    }
    if m.flags & e.required_flags != e.required_flags {
        return Err(error(K::Incompatible, S::Metadata));
    }
    Ok(m)
}
fn btf(
    fd: &OwnedFd,
    m: &MapMetadata,
    e: &MapExpectation,
    l: &Limits,
    w: &mut Work,
) -> Result<(), OperationError> {
    let Some(expected) = e.btf else { return Ok(()) };
    if m.btf_id == 0
        || m.btf_key_type_id != expected.key_type_id
        || m.btf_value_type_id != expected.value_type_id
    {
        return Err(error(K::Incompatible, S::BtfQuery));
    }
    let linked = native::btf_fd(m.btf_id, w)?;
    let first = native::btf_info(&linked, None, w)?;
    let size = native::u32at(&first, 8) as usize;
    if native::u32at(&first, 28) != 0 {
        return Err(error(K::Unsupported, S::BtfQuery));
    }
    if native::u32at(&first, 12) != m.btf_id || size == 0 {
        return Err(error(K::Incompatible, S::BtfQuery));
    }
    if size > 16 * 1024 * 1024 || size > l.input_bytes || size > isize::MAX as usize {
        return Err(error(K::LimitExceeded, S::BtfQuery));
    }
    let mut bytes = budget::bytes(size, 0, l.retained_bytes, w)?;
    let second = native::btf_info(&linked, Some(&mut bytes), w)?;
    if native::u32at(&second, 8) != size as u32
        || native::u32at(&second, 12) != m.btf_id
        || native::u32at(&second, 28) != 0
    {
        return Err(error(K::Changed, S::BtfQuery));
    }
    w.charge(size, S::BtfQuery)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    w.charge(32, S::BtfQuery)?;
    if digest != expected.image.0 {
        return Err(error(K::Incompatible, S::BtfQuery));
    }
    // fd is retained by caller throughout; its linked BTF cannot be ID-reused.
    let _ = fd;
    Ok(())
}
impl ValidatedMap {
    pub fn from_owned_fd(
        fd: OwnedFd,
        expected: &MapExpectation,
        limits: &Limits,
    ) -> Result<Self, OperationError> {
        expectation(expected)?;
        let mut w = Work::new(limits.work_steps);
        if limits.input_bytes < 88 {
            return Err(error(K::LimitExceeded, S::Admission));
        }
        let info = native::map_info(&fd, &mut w)?;
        let metadata = metadata(info.bytes(), info.len(), expected)?;
        // Bloom and every unsupported actual kind already refused, before heap,
        // topology, witness or value copy.
        if metadata.key_size as usize > 65536 || metadata.key_size as usize > limits.input_bytes {
            return Err(error(K::LimitExceeded, S::Admission));
        }
        {
            let mut key =
                budget::bytes(metadata.key_size as usize, 0, limits.retained_bytes, &mut w)?;
            native::key_witness(&info, &mut key, &mut w)?;
        }
        btf(&fd, &metadata, expected, limits, &mut w)?;
        let topology = LiveCpuTopology::acquire_work(limits, &mut w)?;
        let geometry = PerCpuGeometry::checked(
            metadata.value_size as usize,
            topology.snapshot().count(),
            usize::MAX,
        )?;
        if geometry.buffer_len() > i32::MAX as usize
            || geometry.buffer_len() > isize::MAX as usize
            || geometry.buffer_len() > u32::MAX as usize
        {
            return Err(error(K::Unsupported, S::Admission));
        }
        if geometry.buffer_len() > limits.input_bytes {
            return Err(error(K::LimitExceeded, S::Allocate));
        }
        budget::capacity(
            topology.retained(),
            geometry.buffer_len(),
            limits.retained_bytes,
        )?;
        Ok(Self {
            fd,
            metadata,
            geometry,
            topology,
            limits: *limits,
        })
    }
    pub fn metadata(&self) -> &MapMetadata {
        &self.metadata
    }
    pub fn geometry(&self) -> &PerCpuGeometry {
        &self.geometry
    }
    pub fn topology(&self) -> &CpuTopology {
        self.topology.snapshot()
    }
    fn admit(&self, key: &[u8], output: Option<usize>) -> Result<(), OperationError> {
        self.topology.usable()?;
        if key.len() != self.metadata.key_size as usize {
            return Err(error(K::InvalidInput, S::Admission));
        }
        if key.len() > self.limits.input_bytes {
            return Err(error(K::LimitExceeded, S::Admission));
        }
        if output.is_some_and(|n| n < self.geometry.buffer_len()) {
            return Err(error(K::LimitExceeded, S::Admission)
                .with_required_size(self.geometry.buffer_len()));
        }
        budget::capacity(
            self.topology.retained(),
            self.geometry.buffer_len(),
            self.limits.retained_bytes,
        )
    }
    pub fn lookup(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, OperationError> {
        self.admit(key, None)?;
        read_io(
            self,
            key,
            &self.limits,
            &mut Work::new(self.limits.work_steps),
        )
    }
    pub fn lookup_into(&mut self, key: &[u8], output: &mut [u8]) -> Result<bool, OperationError> {
        self.admit(key, Some(output.len()))?;
        copy_read(
            self,
            key,
            output,
            &self.limits,
            &mut Work::new(self.limits.work_steps),
        )
    }
}
// Narrow private fault seam. Only ValidatedMap's implementation invokes native
// value copying, deriving its extent from its own retained authenticated owner.
// A model implementation cannot manufacture or access that native owner.
pub(super) trait LookupIo {
    fn extent(&self) -> usize;
    fn retained(&self) -> usize;
    fn revalidate(&self, w: &mut Work, existing: usize) -> Result<(), OperationError>;
    fn value(&self, key: &[u8], scratch: &mut [u8], w: &mut Work) -> Result<bool, OperationError>;
}
impl LookupIo for ValidatedMap {
    fn extent(&self) -> usize {
        self.geometry.buffer_len()
    }
    fn retained(&self) -> usize {
        self.topology.retained()
    }
    fn revalidate(&self, w: &mut Work, existing: usize) -> Result<(), OperationError> {
        self.topology.revalidate_work(w, existing)
    }
    fn value(&self, key: &[u8], scratch: &mut [u8], w: &mut Work) -> Result<bool, OperationError> {
        native::lookup(self, key, scratch, w)
    }
}
fn read_io(
    io: &impl LookupIo,
    key: &[u8],
    limits: &Limits,
    w: &mut Work,
) -> Result<Option<Vec<u8>>, OperationError> {
    io.revalidate(w, io.retained())?;
    let mut scratch = budget::bytes(io.extent(), io.retained(), limits.retained_bytes, w)?;
    #[cfg(test)]
    BEFORE_VALUE.with(|hook| {
        if let Some(callback) = hook.borrow_mut().take() {
            callback();
        }
    });
    let found = io.value(key, &mut scratch, w)?;
    let existing = io
        .retained()
        .checked_add(scratch.capacity())
        .ok_or_else(|| error(K::Overflow, S::Allocate))?;
    io.revalidate(w, existing)?;
    if found {
        Ok(Some(scratch))
    } else {
        Ok(None)
    }
}
pub(super) fn copy_read(
    io: &impl LookupIo,
    key: &[u8],
    output: &mut [u8],
    limits: &Limits,
    w: &mut Work,
) -> Result<bool, OperationError> {
    let Some(scratch) = read_io(io, key, limits, w)? else {
        return Ok(false);
    };
    w.charge(scratch.len(), S::Read)?;
    output[..scratch.len()].copy_from_slice(&scratch);
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Model {
        source_calls: Cell<usize>,
        value_calls: Cell<usize>,
        post_error: bool,
        map_errno: Option<i32>,
        absent: bool,
        poison: Cell<bool>,
    }
    impl Model {
        fn good() -> Self {
            Self {
                source_calls: Cell::new(0),
                value_calls: Cell::new(0),
                post_error: false,
                map_errno: None,
                absent: false,
                poison: Cell::new(false),
            }
        }
    }
    impl LookupIo for Model {
        fn extent(&self) -> usize {
            16
        }
        fn retained(&self) -> usize {
            0
        }
        fn revalidate(&self, _: &mut Work, _: usize) -> Result<(), OperationError> {
            let n = self.source_calls.get() + 1;
            self.source_calls.set(n);
            if self.poison.get() {
                return Err(error(K::Poisoned, S::Admission));
            }
            if self.post_error && n == 2 {
                self.poison.set(true);
                return Err(error(K::Changed, S::Admission));
            }
            Ok(())
        }
        fn value(
            &self,
            _: &[u8],
            scratch: &mut [u8],
            _: &mut Work,
        ) -> Result<bool, OperationError> {
            self.value_calls.set(self.value_calls.get() + 1);
            scratch.fill(42);
            if let Some(n) = self.map_errno {
                return Err(native::os_error(n, S::Read));
            }
            Ok(!self.absent)
        }
    }
    fn limits() -> Limits {
        Limits {
            input_bytes: 4096,
            retained_bytes: 4096,
            work_steps: 100000,
            sites: 0,
            live_links: 0,
            pending_retirements: 0,
        }
    }
    #[test]
    fn output_short_exact_long_and_partial_failure() {
        let io = Model::good();
        let mut out = [0xa5; 20];
        assert!(copy_read(&io, &[0; 4], &mut out, &limits(), &mut Work::new(10000)).unwrap());
        assert_eq!(&out[..16], &[42; 16]);
        assert_eq!(&out[16..], &[0xa5; 4]);
        for (absent, errno, post) in [
            (true, None, false),
            (false, Some(libc::EIO), false),
            (false, None, true),
        ] {
            let io = Model {
                absent,
                map_errno: errno,
                post_error: post,
                ..Model::good()
            };
            let mut out = [0xa5; 20];
            let r = copy_read(&io, &[0; 4], &mut out, &limits(), &mut Work::new(10000));
            if absent {
                assert!(!r.unwrap());
            } else {
                assert!(r.is_err());
            }
            assert_eq!(out, [0xa5; 20], "scratch is never committed after failure");
        }
    }
    #[test]
    fn map_error_precedes_task_postcheck() {
        let io = Model {
            post_error: true,
            map_errno: Some(libc::EIO),
            ..Model::good()
        };
        let e = read_io(&io, &[0; 4], &limits(), &mut Work::new(10000)).unwrap_err();
        assert_eq!((e.stage(), e.raw_os_error()), (S::Read, Some(libc::EIO)));
        assert_eq!(io.source_calls.get(), 1);
        assert_eq!(io.value_calls.get(), 1);
    }
    #[test]
    fn topology_change_invalidates_sample() {
        for absent in [false, true] {
            let io = Model {
                post_error: true,
                absent,
                ..Model::good()
            };
            let mut out = [0xa5; 20];
            let e =
                copy_read(&io, &[0; 4], &mut out, &limits(), &mut Work::new(10000)).unwrap_err();
            assert_eq!((e.kind(), e.stage()), (K::Changed, S::Admission));
            assert_eq!(out, [0xa5; 20]);
            assert!(io.poison.get());
        }
    }
}
#[cfg(test)]
mod metadata_tests {
    use super::*;
    fn expected() -> MapExpectation {
        MapExpectation {
            map_type: 6,
            key_size: 4,
            value: super::super::ValueLayout {
                size: 8,
                alignment: 8,
                schema: [0; 32],
            },
            max_entries: 2,
            required_flags: 0,
            btf: None,
        }
    }
    fn info(_len: usize) -> [u8; 88] {
        let mut bytes = [0; 88];
        for (o, v) in [(0, 6), (4, 123), (8, 4), (12, 8), (16, 2)] {
            native::put32(&mut bytes, o, v);
        }
        bytes
    }
    #[test]
    fn map_metadata_kind_and_extent() {
        for len in [76, 80, 88] {
            assert_eq!(metadata(&info(len), len, &expected()).unwrap().map_id, 123);
        }
        for (offset, value, kind) in [
            (0, 30, K::Unsupported),
            (0, 1, K::Unsupported),
            (4, 0, K::Incompatible),
            (8, 8, K::Incompatible),
            (12, 9, K::Incompatible),
            (16, 3, K::Incompatible),
            (20, 1, K::Unsupported),
            (40, 1, K::Unsupported),
            (44, 1, K::Unsupported),
            (48, 1, K::Unsupported),
            (56, 1, K::Unsupported),
            (76, 1, K::Unsupported),
            (80, 1, K::Unsupported),
        ] {
            let mut i = info(88);
            native::put32(&mut i, offset, value);
            let e = metadata(&i, 88, &expected()).unwrap_err();
            assert_eq!(
                (e.kind(), e.stage()),
                (kind, S::Metadata),
                "offset {offset}"
            );
        }
    }
    #[test]
    fn bloom_refuses_before_extent_and_copy() {
        let mut i = info(88);
        native::put32(&mut i, 0, 30);
        native::put32(&mut i, 12, u32::MAX);
        let e = metadata(&i, 88, &expected()).unwrap_err();
        assert_eq!((e.kind(), e.stage()), (K::Unsupported, S::Metadata));
    }
}

#[cfg(test)]
thread_local! { pub(super) static BEFORE_VALUE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) }; }
