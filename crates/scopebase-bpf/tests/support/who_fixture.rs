// SPDX-License-Identifier: Apache-2.0
// ADAPT selected owner-authorized K ranges, historical GPL-3.0-or-later.
#![allow(dead_code)]
/// `VWho.identity_present` marker: the lane whose `BPF_NOEXIST`
/// insert created the `KWHO` key carries this value; every other lane
/// carries 0 (kernel-zeroed at insert, never marked by the hit path).
/// Twinned in `kcrypto.rs` (`KWHO_IDENTITY_PRESENT`).
pub const KWHO_IDENTITY_PRESENT: u32 = 1;
/// `KWHO` key: row hash + thread-group id (16B).
///
/// `kh` is [`kh_of`] over the full `KAgg` key (fam/op/res/ctx +
/// alg/drv words); `tgid` scopes the caller identity to one thread
/// group (per-tgid rows, not per-tid — `tid` rides the value as a
/// last-writer hint).
///
/// Twin: `KWhoKey` in `crates/bpf-kcrypto/src/bin/kcrypto.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct KWhoKey {
    /// [`kh_of`] of the `KAGG` row this identity belongs to.
    pub kh: u64,
    /// Thread-group id of the calling thread group.
    pub tgid: u32,
    /// Padding, zero.
    pub _pad: u32,
}

impl KWhoKey {
    /// Manually-maintained field list (allowlist tripwire, declaration
    /// order — see [`KConfig::FIELDS`]).
    pub const FIELDS: &[&str] = &["kh", "tgid", "_pad"];
}

/// `KWHO` value: caller identity + call tallies (88B).
///
/// First-seen fields (`comm` initial, `uid`, `cgroup`, `ppid`, `pcomm`,
/// `stack`) are written once at insert; the hit path updates only
/// `calls`, `last_ns`, and the last-writer `tid`/`comm`. Per-CPU lanes
/// (like [`VAgg`]): the kernel initializes ONLY the inserting CPU's
/// lane from the insert value and zeroes every other lane (Linux 6.12
/// `pcpu_init_value` — an insert is NOT a broadcast), so secondary
/// lanes hold zeroed identity until their first hit, and stay
/// unmarked even after count updates.
///
/// Insertion provenance: `identity_present` is
/// [`KWHO_IDENTITY_PRESENT`] on exactly the lane whose
/// `BPF_NOEXIST` insert created the key (a losing racer must never
/// mark its lane). [`try_fold_vwho`] sources insertion-frozen
/// identity from that unique marked lane and folds `tid`/`comm`
/// from the latest writer; missing or conflicting provenance
/// refuses — an unmarked numeric zero is never an observed identity.
///
/// Twin: `VWho` in `crates/bpf-kcrypto/src/bin/kcrypto.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct VWho {
    /// Calling thread `comm` (`TASK_COMM_LEN`, NUL-padded; last-writer).
    pub comm: [u8; 16],
    /// Calling thread id (last-writer; the key carries the tgid).
    pub tid: u32,
    /// Calling uid (low 32 of `bpf_get_current_uid_gid`).
    pub uid: u32,
    /// Calling cgroup id (`bpf_get_current_cgroup_id`).
    pub cgroup: u64,
    /// Parent thread-group id (0 when `parent_ok` is false or the chase
    /// failed).
    pub ppid: u32,
    /// Parent `comm` (zeros when `parent_ok` is false or the chase
    /// failed).
    pub pcomm: [u8; 16],
    /// `KSTACK` id (`bpf_get_stackid`, first-seen only); negative is the
    /// raw helper errno (no `KSTACK` row).
    pub stack: i32,
    /// Observations attributed to this row (per lane; sum over lanes).
    pub calls: u64,
    /// First-observation time per lane (min-folded over busy lanes; 0
    /// when `calls` is 0).
    pub first_ns: u64,
    /// Last-observation time per lane (max-folded).
    pub last_ns: u64,
    /// Insertion provenance: [`KWHO_IDENTITY_PRESENT`] on the lane
    /// whose `BPF_NOEXIST` insert created the key, 0 elsewhere.
    pub identity_present: u32,
    /// Reserved, zero.
    pub _rsv: u32,
}

impl VWho {
    /// Manually-maintained field list (allowlist tripwire, declaration
    /// order — see [`KConfig::FIELDS`]).
    pub const FIELDS: &[&str] = &[
        "comm",
        "tid",
        "uid",
        "cgroup",
        "ppid",
        "pcomm",
        "stack",
        "calls",
        "first_ns",
        "last_ns",
        "identity_present",
        "_rsv",
    ];
}
/// Fold per-CPU `VWho` lanes into one qualified total.
///
/// Insertion-frozen identity (`uid`, `cgroup`, `ppid`, `pcomm`,
/// `stack`) comes from the UNIQUE lane carrying
/// [`KWHO_IDENTITY_PRESENT`] (per-key insertion-time meaning);
/// `tid`/`comm` fold separately from the latest-writer lane
/// (greatest `last_ns`, first on ties); `calls` sums checked (the
/// [`try_fold_vagg`] N5 contract: a saturated input word or an
/// overflowing sum refuses); `first_ns` is the minimum over lanes
/// with `calls > 0` (0 when no lane observed anything); `last_ns`
/// is the maximum. The folded value carries
/// [`KWHO_IDENTITY_PRESENT`] (qualified insertion-observed
/// identity) with zero reserved padding.
///
/// `None` (refuse — callers fail loud, never guess): no lane
/// marked, more than one lane marked, a non-marker nonzero
/// `identity_present` value, or a saturated/overflowing `calls`
/// sum. Stamps stay exempt (min/max-folded, never summed).
pub fn try_fold_vwho(lanes: &[VWho]) -> Option<VWho> {
    let mut marked: Option<usize> = None;
    for (i, lane) in lanes.iter().enumerate() {
        if lane.identity_present == KWHO_IDENTITY_PRESENT {
            if marked.is_some() {
                return None;
            }
            marked = Some(i);
        } else if lane.identity_present != 0 {
            return None;
        }
    }
    let source = lanes.get(marked?)?;
    let mut out = VWho::default();
    let mut first = u64::MAX;
    let mut any = false;
    let mut best = 0usize;
    for (i, lane) in lanes.iter().enumerate() {
        if lane.calls == u64::MAX {
            return None;
        }
        out.calls = out.calls.checked_add(lane.calls)?;
        if lane.calls > 0 {
            any = true;
            first = first.min(lane.first_ns);
        }
        if lane.last_ns > out.last_ns {
            out.last_ns = lane.last_ns;
            best = i;
        }
    }
    out.first_ns = if any { first } else { 0 };
    out.uid = source.uid;
    out.cgroup = source.cgroup;
    out.ppid = source.ppid;
    out.pcomm = source.pcomm;
    out.stack = source.stack;
    if let Some(winner) = lanes.get(best) {
        out.comm = winner.comm;
        out.tid = winner.tid;
    }
    out.identity_present = KWHO_IDENTITY_PRESENT;
    Some(out)
}
/// Decode one `u64` lane word; `None` on a short buffer.
fn lane_word(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .map(|w| u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]))
}
/// Decode one `u32` field; `None` on a short buffer.
fn lane_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// Decode one `i32` field; `None` on a short buffer.
fn lane_i32(bytes: &[u8], at: usize) -> Option<i32> {
    bytes
        .get(at..at + 4)
        .map(|w| i32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}
/// Decode a `KWhoKey` map key from exactly 16 bytes (`None` otherwise).
#[must_use]
pub fn kwho_key_from_bytes(bytes: &[u8]) -> Option<KWhoKey> {
    if bytes.len() != 16 {
        return None;
    }
    Some(KWhoKey {
        kh: lane_word(bytes, 0)?,
        tgid: lane_u32(bytes, 8)?,
        _pad: lane_u32(bytes, 12)?,
    })
}

/// Decode a `VWho` map value from exactly 88 bytes (`None` otherwise).
#[must_use]
pub fn vwho_from_bytes(bytes: &[u8]) -> Option<VWho> {
    if bytes.len() != 88 {
        return None;
    }
    let mut comm = [0u8; 16];
    comm.copy_from_slice(bytes.get(0..16)?);
    let mut pcomm = [0u8; 16];
    pcomm.copy_from_slice(bytes.get(36..52)?);
    Some(VWho {
        comm,
        tid: lane_u32(bytes, 16)?,
        uid: lane_u32(bytes, 20)?,
        cgroup: lane_word(bytes, 24)?,
        ppid: lane_u32(bytes, 32)?,
        pcomm,
        stack: lane_i32(bytes, 52)?,
        calls: lane_word(bytes, 56)?,
        first_ns: lane_word(bytes, 64)?,
        last_ns: lane_word(bytes, 72)?,
        identity_present: lane_u32(bytes, 80)?,
        _rsv: lane_u32(bytes, 84)?,
    })
}

/// Caller-owned key iteration; every known-key failure aborts the entire report.
/// Hoist one decoded lane allocation across rows (K snapshot_who M8).
pub fn report_rows<F>(
    keys: &[&[u8]],
    count: usize,
    mut lookup: F,
) -> Result<Vec<(KWhoKey, VWho)>, String>
where
    F: FnMut(&[u8]) -> Result<Option<Vec<u8>>, String>,
{
    let mut out = Vec::new();
    let mut lanes = Vec::with_capacity(count);
    for key in keys {
        let key_value = kwho_key_from_bytes(key).ok_or("WHO key requires 16 bytes")?;
        let raw = lookup(key)?.ok_or("known WHO key disappeared")?;
        if raw.len() != count.checked_mul(88).ok_or("WHO extent overflow")? {
            return Err("WHO schema/extent requires 88-byte lanes".into());
        }
        lanes.clear();
        for bytes in raw.chunks_exact(88) {
            lanes.push(vwho_from_bytes(bytes).ok_or("WHO lane decode")?);
        }
        let value = try_fold_vwho(&lanes).ok_or("WHO insertion provenance/counter refusal")?;
        out.push((key_value, value));
    }
    Ok(out)
}
