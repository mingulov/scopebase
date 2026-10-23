// SPDX-License-Identifier: Apache-2.0
//! TT03 first-increment developer driver: parent-side worker launch, exact
//! protocol service, original-owner lifecycle and file verification.
//!
//! Grant: OWNER-2026-10-23 (user-owned donor slices to Apache-2.0).
//!
//! | Facet | Donor slice | Disposition |
//! |---|---|---|
//! | TT03-SF-07 lifecycle order | P `src/process.rs:2381-2384,2388-2392,2396-2400,2404-2410` @ `2c2713e66292b0d2688508a25f79e813ae823d81` | ADAPT_LIFECYCLE_ONLY: original birth/pidfd capture, live WNOWAIT, kill+poll+WNOWAIT, exact reap then ECHILD; denial helper, ReapOnDrop and helper ACKs not copied |
//! | TT03-SF-14 no-control | O `tests/target_lifecycle.rs:359-375` @ `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a` | ADAPT_NO_CONTROL_FACET: borrow-only observation leaves independent A/B sentinels responsive; signals/waits stay in original-parent custody outside any subject window |
//!
//! Resume handshake/regrant, sibling/task verification, third-slot canary
//! inventory, the deadline hold and worker-death outage injection are NEW
//! narrow fixture composition over accepted TT02, as the TT03 contract
//! authorizes.
//!
//! Outage controls arm through the A worker's boot Hello (`worker_exit`,
//! `partial_file_write`) or fail parent setup after the named registration
//! (`parent_failure_after_register`). Deaths report typed [`DriverErrorKind::WorkerDeath`]
//! with the observed wait status and never hang past the reply deadline;
//! setup failures report [`DriverErrorKind::SetupFailure`] with the exact
//! registered prefix. Snapshot full-schema conformance is a documented
//! follow-up.
pub use super::manifest::{control_pairing_applies, Control, Scenario, ScenarioStep};
use super::oracle::{exited_unreaped_owned, TRICKY_COMM};
use super::wire::{
    canonical_json, parse_canonical, run_id_from_hex, sha256_of, validate_hello_reply,
    Action, Actor, AdvanceReply, AdvanceRequest, CloseBody, CloseReason, Envelope, FdDirection,
    FdRole, FdTransferBody, FragmentPrefix, InputChunkAck, MessageKind, RawRequest, WireError,
    CHUNK_MAX, DATAGRAM_MAX, HEADER_BYTES, PAYLOAD_MAX,
};
use rustix::fd::{AsFd, OwnedFd};
use rustix::io::{IoSlice, IoSliceMut};
use std::os::unix::io::AsRawFd;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const POLL_TIMEOUT_MS: i64 = 10_000;
const EXIT_WAIT_MS: i32 = 5_000;
const IMAGE_BYTES_MAX: u64 = 33_554_432;
const FILE_BYTES_MAX: usize = 65536;

pub struct LaunchConfig {
    /// Spawnable worker binary for auxiliary (inventory) children. The A/B
    /// slots boot from their own images below.
    pub worker: std::path::PathBuf,
    pub image_a: std::path::PathBuf,
    pub image_b: std::path::PathBuf,
    pub root: std::fs::File,
    pub run_hex: String,
    pub operation_id: u64,
    pub manifest_sha256: [u8; 32],
    pub scenario: Scenario,
    pub deadline_ns: u64,
    pub cancel: Arc<AtomicBool>,
    /// Closed outage-injection triple for the worker-death row. Worker kinds
    /// (`worker_exit`, `partial_file_write`) arm the A worker through its boot
    /// Hello; the parent kind (`parent_failure_after_register`) fails parent
    /// setup after the named registration. Pairing is validated before any
    /// native effect; `None` runs the valid twin.
    pub control: Option<Control>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverErrorKind {
    Protocol,
    Io,
    Timeout,
    Refused,
    Cancelled,
    Deferred,
    /// The owned worker died mid-protocol: the step never completed and no
    /// ACK covers it. Never silent: the diagnostic carries the step and the
    /// observed wait status, and the drained-raw prefix stays readable.
    WorkerDeath,
    /// Parent setup failed after registering the named native prefix
    /// (injected `parent_failure_after_register`). The diagnostic names every
    /// registered owner and the cleanup proof records its retirement.
    SetupFailure,
}

#[derive(Clone, Debug)]
pub struct CleanupProof {
    pub spawned: bool,
    pub a_reaped: bool,
    pub b_reaped: bool,
    /// Registered PIDs when a child actually spawned; `None` proves nothing.
    pub a_pid: Option<u32>,
    pub b_pid: Option<u32>,
    /// Observed wait statuses; a reap without an observed status is unsettled.
    pub a_exit: Option<ReapedExit>,
    pub b_exit: Option<ReapedExit>,
    /// Whether the created case directory was actually removed again.
    pub case_root_removed: bool,
}

#[derive(Clone, Debug)]
pub struct DriverError {
    kind: DriverErrorKind,
    errno: Option<i32>,
    step: Option<String>,
    diagnostic: String,
    cleanup: CleanupProof,
}
impl DriverError {
    fn new(kind: DriverErrorKind, step: Option<&str>, diagnostic: String) -> Self {
        Self {
            kind,
            errno: None,
            step: step.map(str::to_string),
            diagnostic,
            cleanup: CleanupProof {
                spawned: false,
                a_reaped: false,
                b_reaped: false,
                a_pid: None,
                b_pid: None,
                a_exit: None,
                b_exit: None,
                case_root_removed: false,
            },
        }
    }
    fn with_cleanup(mut self, cleanup: CleanupProof) -> Self {
        self.cleanup = cleanup;
        self
    }
    fn with_note(mut self, note: String) -> Self {
        self.diagnostic.push_str("; ");
        self.diagnostic.push_str(&note);
        self
    }
    pub fn kind(&self) -> DriverErrorKind {
        self.kind
    }
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }
    pub fn step_id(&self) -> Option<&str> {
        self.step.as_deref()
    }
    pub fn diagnostic_bytes(&self) -> &[u8] {
        self.diagnostic.as_bytes()
    }
    pub fn cleanup_proof(&self) -> &CleanupProof {
        &self.cleanup
    }
}
impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "driver {:?}: {}", self.kind, self.diagnostic)
    }
}
impl std::error::Error for DriverError {}

fn protocol(step: Option<&str>, detail: impl Into<String>) -> DriverError {
    DriverError::new(DriverErrorKind::Protocol, step, detail.into())
}
fn refused(step: Option<&str>, detail: impl Into<String>) -> DriverError {
    DriverError::new(DriverErrorKind::Refused, step, detail.into())
}
fn worker_death(step: Option<&str>, status: ReapedExit) -> DriverError {
    let status_text = match (status.signal, status.code) {
        (Some(signal), _) => format!("killed by signal {signal}"),
        (None, Some(code)) => format!("exited with code {code}"),
        (None, None) => "gone with unknown wait status".to_string(),
    };
    DriverError::new(
        DriverErrorKind::WorkerDeath,
        step,
        format!("worker died mid-protocol with no ACK for this step ({status_text})"),
    )
}
fn setup_failure(step: Option<&str>, detail: impl Into<String>) -> DriverError {
    DriverError::new(DriverErrorKind::SetupFailure, step, detail.into())
}
fn io_error(step: Option<&str>, error: rustix::io::Errno) -> DriverError {
    let mut e = DriverError::new(
        DriverErrorKind::Io,
        step,
        format!("native io: {error}"),
    );
    e.errno = Some(error.raw_os_error());
    e
}
fn std_io_error(step: Option<&str>, error: std::io::Error) -> DriverError {
    let mut e = DriverError::new(
        DriverErrorKind::Io,
        step,
        format!("native io: {error}"),
    );
    e.errno = error.raw_os_error();
    e
}
fn wire_error(step: Option<&str>, error: WireError) -> DriverError {
    protocol(step, format!("wire refused: {}", error.detail()))
}

#[derive(Clone, Debug)]
pub struct DrainedRecord {
    pub actor: String,
    pub step_id: String,
    pub record_index: u32,
    pub kind: String,
    pub bytes: Vec<u8>,
}

/// One recorded third-slot inventory child: its registered PID, which
/// population it served, and whether it was exactly reaped. Recorded at
/// spawn; `reaped` flips only after the exact wait succeeds, so a failed
/// reap stays visible as unsettled instead of vanishing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryRecord {
    pub pid: u32,
    pub positive: bool,
    pub reaped: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReapedExit {
    pub signal: Option<i32>,
    pub code: Option<i32>,
}

#[derive(Clone, Debug)]
pub struct ShutdownReport {
    pub case_root_removed: bool,
    pub a_exit: Option<ReapedExit>,
    pub b_exit: Option<ReapedExit>,
}

pub(crate) type SharedPair = Arc<Mutex<PairInner>>;

#[derive(Debug)]
struct ChildState {
    child: Option<Child>,
    pidfd: Option<OwnedFd>,
    pid: u32,
    reaped: bool,
    exit: Option<ReapedExit>,
}

impl ChildState {
    /// Non-blocking exit poll that records the reap exactly once. Returns
    /// `Some` status when the child is gone (newly observed or previously
    /// recorded) and `None` while it is still alive. A wait error (the status
    /// was already consumed) means gone-with-unknown-status: losing a status
    /// is honest, hanging on a dead child is not.
    fn poll_gone(&mut self) -> Option<ReapedExit> {
        if self.reaped {
            return Some(self.exit.unwrap_or(ReapedExit {
                signal: None,
                code: None,
            }));
        }
        let Some(child) = self.child.as_mut() else {
            self.reaped = true;
            return Some(self.exit.unwrap_or(ReapedExit {
                signal: None,
                code: None,
            }));
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                let exit = exit_of(status);
                self.exit = Some(exit);
                self.reaped = true;
                self.child.take();
                Some(exit)
            }
            Ok(None) => None,
            Err(_) => {
                self.reaped = true;
                self.child.take();
                Some(self.exit.unwrap_or(ReapedExit {
                    signal: None,
                    code: None,
                }))
            }
        }
    }
}

/// Graceful gone-poll for transport-failure paths. The kernel closes a
/// dying worker's socket before the task becomes a zombie, so EOF/EPIPE/
/// ECONNRESET may arrive while waitpid still says running. Spin briefly
/// for the zombie; a worker still alive afterwards is a genuine protocol
/// violator, not a death. Bounded (100ms) far under the reply timeout.
fn poll_gone_graceful(state: &mut ChildState) -> Option<ReapedExit> {
    if let Some(status) = state.poll_gone() {
        return Some(status);
    }
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        if let Some(status) = state.poll_gone() {
            return Some(status);
        }
    }
    None
}

#[derive(Debug)]
struct Channel {
    sock: OwnedFd,
    child: ChildState,
    sequence: u64,
    pending_seq: Option<u64>,
    image_epoch: u32,
    next_record: u32,
    run_id: [u8; 16],
    operation_id: u64,
    authenticated: bool,
    closed: bool,
}

impl Channel {
    fn poll_ready(&mut self, step: Option<&str>, wait_ms: i64) -> Result<(), DriverError> {
        let mut remaining = wait_ms;
        loop {
            let chunk = remaining.min(500);
            let timeout = rustix::event::Timespec {
                tv_sec: chunk / 1000,
                tv_nsec: (chunk % 1000) * 1_000_000,
            };
            let mut fds = [rustix::event::PollFd::new(&self.sock, rustix::event::PollFlags::IN)];
            let ready =
                rustix::event::poll(&mut fds, Some(&timeout)).map_err(|e| io_error(step, e))?;
            if ready > 0 {
                return Ok(());
            }
            if let Some(status) = self.child.poll_gone() {
                return Err(worker_death(step, status));
            }
            remaining -= chunk;
            if remaining <= 0 {
                return Err(DriverError::new(
                    DriverErrorKind::Timeout,
                    step,
                    "worker reply timed out".to_string(),
                ));
            }
        }
    }

    /// Non-blocking gone check with reap recording, for pre-step guards.
    fn observed_gone(&mut self) -> bool {
        self.child.poll_gone().is_some()
    }

    fn send(
        &mut self,
        step: Option<&str>,
        kind: MessageKind,
        script_index: u32,
        payload: &[u8],
        fd: Option<&OwnedFd>,
    ) -> Result<u64, DriverError> {
        if payload.len() > PAYLOAD_MAX {
            return Err(protocol(step, "payload exceeds ceiling"));
        }
        let seq = self.sequence;
        self.sequence = seq.checked_add(1).ok_or_else(|| protocol(step, "sequence overflow"))?;
        let envelope = Envelope {
            kind,
            payload_len: payload.len() as u32,
            fd_count: if fd.is_some() { 1 } else { 0 },
            run_id: self.run_id,
            operation_id: self.operation_id,
            sequence: seq,
            script_index,
        };
        let header = envelope.encode();
        let iov = [IoSlice::new(&header), IoSlice::new(payload)];
        let sent = match fd {
            Some(pass) => {
                let borrowed = pass.as_fd();
                let send_fds = [borrowed];
                let mut space =
                    [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                let mut cbuf = rustix::net::SendAncillaryBuffer::new(&mut space);
                if !cbuf.push(rustix::net::SendAncillaryMessage::ScmRights(&send_fds)) {
                    return Err(protocol(step, "ancillary space exhausted"));
                }
                rustix::net::sendmsg(&self.sock, &iov, &mut cbuf, rustix::net::SendFlags::empty())
            }
            None => {
                let mut space = [std::mem::MaybeUninit::uninit(); 0];
                let mut cbuf = rustix::net::SendAncillaryBuffer::new(&mut space);
                rustix::net::sendmsg(&self.sock, &iov, &mut cbuf, rustix::net::SendFlags::empty())
            }
        }
        .map_err(|e| {
            // Any transport failure with a dead peer is the death, whatever
            // errno flavor the teardown race produced (EPIPE, ECONNRESET).
            if let Some(status) = poll_gone_graceful(&mut self.child) {
                return worker_death(step, status);
            }
            io_error(step, e)
        })?;
        if sent != HEADER_BYTES + payload.len() {
            return Err(protocol(step, "short datagram send"));
        }
        self.pending_seq = Some(seq);
        Ok(seq)
    }

    fn recv(
        &mut self,
        step: Option<&str>,
        expect: MessageKind,
        want_fd: bool,
    ) -> Result<(Envelope, Vec<u8>, Option<OwnedFd>), DriverError> {
        self.poll_ready(step, POLL_TIMEOUT_MS)?;
        let mut data = vec![0u8; DATAGRAM_MAX];
        let mut iov = [IoSliceMut::new(&mut data)];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut cbuf = rustix::net::RecvAncillaryBuffer::new(&mut space);
        let received = rustix::net::recvmsg(
            &self.sock,
            &mut iov,
            &mut cbuf,
            rustix::net::RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(|e| {
            if let Some(status) = poll_gone_graceful(&mut self.child) {
                return worker_death(step, status);
            }
            io_error(step, e)
        })?;
        if received.flags.contains(rustix::net::ReturnFlags::TRUNC)
            || received.flags.contains(rustix::net::ReturnFlags::CTRUNC)
        {
            return Err(protocol(step, "truncated datagram or ancillary"));
        }
        if received.bytes < HEADER_BYTES {
            // A zero-byte read is EOF: the peer closed, which only happens
            // when the worker exited. Report the typed death, never a bare
            // short datagram, whenever the owned child is gone.
            if let Some(status) = poll_gone_graceful(&mut self.child) {
                return Err(worker_death(step, status));
            }
            return Err(protocol(step, "datagram shorter than header"));
        }
        let header: [u8; HEADER_BYTES] = data[..HEADER_BYTES].try_into().unwrap();
        let envelope = Envelope::decode(&header).map_err(|e| wire_error(step, e))?;
        if envelope.kind != expect {
            if envelope.kind == MessageKind::Error {
                let body = parse_canonical(
                    &data[HEADER_BYTES..received.bytes],
                    PAYLOAD_MAX,
                )
                .map_err(|e| wire_error(step, e))?;
                return Err(protocol(
                    step,
                    format!("worker error reply: {body}"),
                ));
            }
            return Err(protocol(step, "unexpected reply kind"));
        }
        if envelope.run_id != self.run_id
            || envelope.operation_id != self.operation_id
            || Some(envelope.sequence) != self.pending_seq
        {
            return Err(protocol(step, "reply identity mismatch"));
        }
        self.pending_seq = None;
        if received.bytes != HEADER_BYTES + envelope.payload_len as usize {
            return Err(protocol(step, "payload length mismatch"));
        }
        let mut fds = Vec::new();
        for message in cbuf.drain() {
            match message {
                rustix::net::RecvAncillaryMessage::ScmRights(rights) => {
                    fds.extend(rights);
                }
                _ => return Err(protocol(step, "unexpected ancillary kind")),
            }
        }
        if want_fd {
            if fds.len() != 1 || envelope.fd_count != 1 {
                return Err(protocol(step, "fd cardinality mismatch"));
            }
            Ok((
                envelope,
                data[HEADER_BYTES..received.bytes].to_vec(),
                Some(fds.pop().unwrap()),
            ))
        } else {
            if !fds.is_empty() || envelope.fd_count != 0 {
                return Err(protocol(step, "unsolicited descriptor"));
            }
            Ok((envelope, data[HEADER_BYTES..received.bytes].to_vec(), None))
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

fn read_bounded(path: &std::path::Path, max: u64) -> Result<Vec<u8>, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "image exceeds ceiling",
        ));
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    use std::io::Read;
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "image exceeds ceiling",
        ));
    }
    Ok(bytes)
}

fn spawn_worker(
    worker: &std::path::Path,
    slot: &str,
    sock_end: OwnedFd,
) -> Result<Child, std::io::Error> {
    std::process::Command::new(worker)
        .arg("--scopebase-fixture-v1")
        .arg("--slot")
        .arg(slot)
        .arg("--handover")
        .arg("-")
        .stdin(Stdio::from(sock_end))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
}

fn hello_invocation(run_hex: &str, operation_id: u64) -> serde_json::Value {
    serde_json::json!({
        "run_id": run_hex,
        "case_key": {"case_id": "TT03.first", "case_version": 1, "cell_id": "host"},
        "attempt": 1,
        "operation_id": operation_id.to_string(),
    })
}

fn transport_limits() -> serde_json::Value {
    serde_json::json!({
        "invocations": 16, "children_concurrent": 3, "child_registrations": 4,
        "sibling_threads": 1, "image_entries": 6, "open_fds_parent": 64,
        "inventory_slots": 32, "case_directories": 1, "leaf_names": 4, "steps": 10,
        "datagrams": 568, "payload_bytes": 65536, "diagnostic_bytes": 1024,
        "raw_file_bytes": 1048576, "read_calls_per_source": 4096,
        "native_calls_parent": 16384, "native_cleanup_reserve_parent": 512,
        "native_calls_per_image": 4096, "native_cleanup_reserve_per_image": 128,
        "file_bytes": 65536, "file_work_bytes": 1048576, "ledger_bytes": 4194304,
        "image_bytes": 33554432, "hash_work_bytes": 294453760,
        "parent_retained_bytes": 268435456, "fixed_metadata_bytes": 1048576,
        "immutable_snapshot_slots": 4, "subsidiary_errors": 32, "nspid_entries": 32,
        "executable_path_bytes": 4096, "manifest_metadata_bytes_per_invocation": 16384,
        "manifest_fixed_metadata_bytes": 16384, "manifest_encoded_bytes": 6569984,
        "manifest_hash_work_bytes": 6569984, "encoded_work_bytes": 34145792,
    })
}

#[derive(Debug)]
pub(crate) struct PairInner {
    a: Channel,
    b: Channel,
    scenario: Scenario,
    completed: Vec<String>,
    cursor: usize,
    raw: Vec<DrainedRecord>,
    case_dir: std::path::PathBuf,
    case_root: Option<OwnedFd>,
    blobs: [Option<Vec<u8>>; 3],
    uploaded: [bool; 3],
    file_a: Option<OwnedFd>,
    file_b: Option<OwnedFd>,
    tid: Option<u32>,
    inventory: Vec<InventoryRecord>,
    invocation: serde_json::Value,
    images: Vec<ImageExpectation>,
    image_shas: [[u8; 32]; 2],
    worker: std::path::PathBuf,
    deadline_ns: u64,
    manifest_sha_hex: String,
    root: OwnedFd,
    cancel: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
struct ImageExpectation {
    artifact: &'static str,
    path_hex: String,
    sha_hex: String,
}

fn authenticate_executable(
    pid: u32,
    expected_sha: &[u8; 32],
    step: Option<&str>,
) -> Result<(), DriverError> {
    let exe = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    let bytes = read_bounded(&exe, IMAGE_BYTES_MAX).map_err(|e| std_io_error(step, e))?;
    if &sha256_of(&bytes) != expected_sha {
        return Err(refused(step, "worker executable digest differs from expected image"));
    }
    Ok(())
}

fn hello_exchange(
    channel: &mut Channel,
    scenario: Scenario,
    invocation: &serde_json::Value,
    images: &[ImageExpectation],
    slot: Actor,
    marker: &'static str,
    deadline_ns: u64,
    manifest_sha_hex: &str,
    mode: &str,
    completed_steps: u32,
    image_epoch: u32,
    next_record: u32,
    control: Option<&Control>,
    step: Option<&str>,
) -> Result<(), DriverError> {
    let steps: Vec<serde_json::Value> = scenario
        .steps()
        .iter()
        .map(|s| serde_json::json!({"id": s.id, "action": s.action.as_str(), "actor": s.actor.as_str()}))
        .collect();
    let control_value = match control {
        Some(armed) => serde_json::json!({
            "kind": armed.kind, "step_id": armed.step_id, "point": armed.point,
        }),
        None => serde_json::Value::Null,
    };
    let request = serde_json::json!({
        "schema_version": 1,
        "invocation": invocation,
        "mode": mode,
        "slot": slot.as_str(),
        "scenario": scenario.as_str(),
        "manifest_sha256": manifest_sha_hex,
        "images": [
            {"artifact": images[0].artifact, "marker": "A",
             "path_hex": images[0].path_hex, "sha256": images[0].sha_hex},
            {"artifact": images[1].artifact, "marker": "B",
             "path_hex": images[1].path_hex, "sha256": images[1].sha_hex},
        ],
        "steps": steps,
        "completed_steps": completed_steps,
        "image_epoch": image_epoch,
        "next_record_index": next_record,
        "execution_deadline_ns": deadline_ns.to_string(),
        "limits": transport_limits(),
        "blobs": [],
        "control": control_value,
        "inherited_fds": [0, 1, 2],
    });
    let body = canonical_json(&request).map_err(|e| wire_error(step, e))?;
    channel.send(step, MessageKind::HelloRequest, 0, body.as_bytes(), None)?;
    let (_, reply_bytes, _) = channel.recv(step, MessageKind::HelloReply, false)?;
    let reply = parse_canonical(&reply_bytes, 4096).map_err(|e| wire_error(step, e))?;
    validate_hello_reply(&reply, slot.as_str()).map_err(|e| wire_error(step, e))?;
    if reply["pid"] != channel.child.pid
        || reply["image_marker"] != marker
        || reply["mode"] != mode
        || reply["image_epoch"] != image_epoch
    {
        return Err(protocol(step, "hello reply identity mismatch"));
    }
    Ok(())
}

/// Post-exec resume: the worker already exec'd after its pre-exec reply, so
/// the parent handshakes the new image, resets record continuity,
/// re-authenticates the running executable and regrants the case root (all
/// CLOEXEC worker state was dropped by the exec).
fn resume_after_exec(
    inner: &mut PairInner,
    step_id: &str,
    script_index: u32,
    marker: &'static str,
    target_index: usize,
) -> Result<(), DriverError> {
    let new_epoch = inner.a.image_epoch.checked_add(1).ok_or_else(|| {
        protocol(Some(step_id), "image epoch overflow at resume")
    })?;
    let completed = inner.completed.len() as u32;
    let deadline_ns = inner.deadline_ns;
    let manifest_sha_hex = inner.manifest_sha_hex.clone();
    let scenario = inner.scenario;
    let invocation = inner.invocation.clone();
    let images = inner.images.clone();
    hello_exchange(
        &mut inner.a,
        scenario,
        &invocation,
        &images,
        Actor::A,
        marker,
        deadline_ns,
        &manifest_sha_hex,
        "resume",
        completed,
        new_epoch,
        1,
        // Outage controls arm the boot Hello only; an armed worker never
        // survives to exec, so resume carries no control.
        None,
        Some(step_id),
    )?;
    inner.a.image_epoch = new_epoch;
    inner.a.next_record = 1;
    let expected = inner.image_shas[target_index];
    authenticate_executable(inner.a.child.pid, &expected, Some(step_id))?;
    let root = inner.case_root.as_ref().expect("case root").as_fd().try_clone_to_owned();
    match root {
        Ok(owned) => {
            let body = FdTransferBody {
                direction: FdDirection::Push,
                role: FdRole::CaseRoot,
                image_epoch: new_epoch,
                grant_id: new_epoch,
            };
            inner.a.send(
                Some(step_id),
                MessageKind::FdTransferRequest,
                script_index,
                &body.encode(),
                Some(&owned),
            )?;
            let (_, reply, _) = inner.a.recv(Some(step_id), MessageKind::FdTransferReply, false)?;
            let echo = FdTransferBody::decode(&reply).map_err(|e| wire_error(Some(step_id), e))?;
            if echo != body {
                return Err(protocol(Some(step_id), "post-exec root regrant not echoed"));
            }
            Ok(())
        }
        Err(e) => Err(std_io_error(Some(step_id), e)),
    }
}

fn spawn_channel(
    worker: &std::path::Path,
    slot_name: &'static str,
    run_id: [u8; 16],
    operation_id: u64,
    step: Option<&str>,
) -> Result<Channel, DriverError> {
    let (parent_end, child_end) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| io_error(step, e))?;
    let child = spawn_worker(worker, slot_name, child_end).map_err(|e| std_io_error(step, e))?;
    let pid = child.id();
    Ok(Channel {
        sock: parent_end,
        child: ChildState {
            child: Some(child),
            pidfd: None,
            pid,
            reaped: false,
            exit: None,
        },
        sequence: 1,
        pending_seq: None,
        image_epoch: 1,
        next_record: 1,
        run_id,
        operation_id,
        authenticated: false,
        closed: false,
    })
}

fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    let raw = i32::try_from(pid).unwrap_or(0);
    rustix::process::Pid::from_raw(raw)
        .and_then(|p| rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty()).ok())
}

/// Best-effort case-dir removal with an honest outcome note for the
/// setup-failure diagnostic: success is claimed only when observed.
fn dir_retirement_note(case_dir: &std::path::Path) -> (String, bool) {
    match std::fs::remove_dir_all(case_dir) {
        Ok(()) => ("case dir retired".to_string(), true),
        Err(e) => (format!("case dir removal FAILED ({e})"), false),
    }
}

/// Shutdown reap: recorded reaps are preserved, and a live worker gets a
/// bounded wait for its natural post-close exit before any SIGKILL. The
/// close-handshake counterpart exits in microseconds; killing first would
/// race its teardown and randomly report signal 9 instead of code 0.
fn reap_shutdown(channel: &mut Channel) {
    if channel.child.poll_gone().is_some() {
        return;
    }
    let Some(child) = channel.child.child.as_mut() else {
        channel.child.reaped = true;
        return;
    };
    match exact_wait(child, None) {
        Ok(exit) => {
            channel.child.exit = Some(exit);
        }
        Err(_) => {
            let _ = child.kill();
            if let Ok(status) = child.wait() {
                channel.child.exit = Some(exit_of(status));
            }
        }
    }
    channel.child.reaped = true;
    channel.child.child.take();
}

/// Setup-path retirement for a never-helloed worker: SIGKILL plus a
/// blocking reap. The child runs no protocol yet, so no channel exchange is
/// attempted; the recorded status feeds the setup-failure cleanup proof.
fn kill_and_reap_setup(channel: &mut Channel) {
    if channel.child.poll_gone().is_none() {
        if let Some(child) = channel.child.child.as_mut() {
            let _ = child.kill();
            if let Ok(status) = child.wait() {
                channel.child.exit = Some(exit_of(status));
            }
            channel.child.reaped = true;
            channel.child.child.take();
        }
    }
}

fn cleanup_children(a: &mut Channel, b: &mut Channel) -> CleanupProof {
    for channel in [&mut *a, &mut *b] {
        if channel.child.poll_gone().is_none() {
            if let Some(child) = channel.child.child.as_mut() {
                let _ = child.kill();
                if let Ok(status) = child.wait() {
                    channel.child.exit = Some(exit_of(status));
                }
                channel.child.reaped = true;
                channel.child.child.take();
            }
        }
    }
    let a_pid = a.child.pid;
    let b_pid = b.child.pid;
    CleanupProof {
        spawned: true,
        a_reaped: a.child.reaped,
        b_reaped: b.child.reaped,
        a_pid: Some(a_pid),
        b_pid: Some(b_pid),
        a_exit: a.child.exit,
        b_exit: b.child.exit,
        case_root_removed: false,
    }
}

fn exit_of(status: std::process::ExitStatus) -> ReapedExit {
    use std::os::unix::process::ExitStatusExt;
    ReapedExit {
        signal: status.signal(),
        code: status.code(),
    }
}

fn premeasure(path: &std::path::Path, marker: &'static str) -> Result<([u8; 32], String), DriverError> {
    use std::os::unix::ffi::OsStrExt;
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.is_empty() || path_bytes.len() > 4096 || path_bytes.contains(&0) {
        return Err(refused(None, format!("{marker} path is not admittable")));
    }
    let bytes = read_bounded(path, IMAGE_BYTES_MAX)
        .map_err(|e| std_io_error(None, e))?;
    Ok((sha256_of(&bytes), hex_bytes(path_bytes)))
}

pub fn launch_pair(config: &LaunchConfig) -> Result<LivePair, DriverError> {
    if config.operation_id == 0 {
        return Err(protocol(None, "operation id must be positive"));
    }
    let run_id = run_id_from_hex(&config.run_hex).map_err(|e| wire_error(None, e))?;
    if !config.worker.is_absolute() || !config.image_a.is_absolute() || !config.image_b.is_absolute()
    {
        return Err(refused(None, "worker and image paths must be absolute"));
    }
    if let Some(control) = &config.control {
        if !control_pairing_applies(
            &control.kind,
            &control.step_id,
            &control.point,
            config.scenario,
        ) {
            return Err(refused(
                None,
                format!(
                    "control pairing {} at {}/{} is not applicable to {}",
                    control.kind,
                    control.step_id,
                    control.point,
                    config.scenario.as_str(),
                ),
            ));
        }
        match control.kind.as_str() {
            "worker_exit" | "partial_file_write" | "parent_failure_after_register" => {}
            other => {
                return Err(refused(
                    None,
                    format!("control kind {other} has no driver population on this route"),
                ))
            }
        }
    }
    if config.cancel.load(Ordering::Relaxed) {
        return Err(DriverError::new(
            DriverErrorKind::Cancelled,
            Some("s01-ready"),
            "cancelled before first creation".to_string(),
        ));
    }
    let (sha_a, path_hex_a) = premeasure(&config.image_a, "image_a")?;
    let (sha_b, path_hex_b) = premeasure(&config.image_b, "image_b")?;
    let case_name = format!("tt03-{}-{}", config.run_hex, config.operation_id);
    let root_is_dir = config
        .root
        .metadata()
        .map_err(|e| std_io_error(None, e))?
        .is_dir();
    if !root_is_dir {
        return Err(refused(None, "root must be a directory"));
    }
    // SAFETY: the caller's root File outlives this borrow.
    let root_fd = unsafe { rustix::fd::BorrowedFd::borrow_raw(config.root.as_raw_fd()) };
    if let Err(e) =
        rustix::fs::mkdirat(&root_fd, &case_name, rustix::fs::Mode::from_bits_truncate(0o700))
    {
        return Err(refused(None, format!("case directory refused: {e}")));
    }
    let case_root: OwnedFd = rustix::fs::openat(
        &root_fd,
        &case_name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| io_error(None, e))?;
    let root_owned: OwnedFd = config
        .root
        .try_clone()
        .map_err(|e| std_io_error(None, e))?
        .into();
    let case_dir_owned: std::path::PathBuf = {
        let link = std::fs::read_link(format!("/proc/self/fd/{}", config.root.as_raw_fd()))
            .map_err(|e| std_io_error(None, e))?;
        link.join(&case_name)
    };
    let invocation = hello_invocation(&config.run_hex, config.operation_id);
    let manifest_sha_hex = hex_bytes(&config.manifest_sha256);
    let parent_failure = match &config.control {
        Some(armed) if armed.kind == "parent_failure_after_register" => Some(armed.point.clone()),
        _ => None,
    };
    if parent_failure.as_deref() == Some("after_case_root_register") {
        let (dir_note, dir_removed) = dir_retirement_note(&case_dir_owned);
        return Err(setup_failure(
            Some("s01-ready"),
            format!(
                "parent setup failed after case-root registration \
                 (parent_failure_after_register/after_case_root_register at s01-ready): \
                 registered [case-root]; no child ever spawned; {dir_note}"
            ),
        )
        .with_cleanup(CleanupProof {
            spawned: false,
            a_reaped: false,
            b_reaped: false,
            a_pid: None,
            b_pid: None,
            a_exit: None,
            b_exit: None,
            case_root_removed: dir_removed,
        }));
    }
    let mut channel_a = spawn_channel(&config.image_a, "a", run_id, config.operation_id, None)?;
    if parent_failure.as_deref() == Some("after_child_register") {
        let pid = channel_a.child.pid;
        kill_and_reap_setup(&mut channel_a);
        let (dir_note, dir_removed) = dir_retirement_note(&case_dir_owned);
        return Err(setup_failure(
            Some("s01-ready"),
            format!(
                "parent setup failed after child registration \
                 (parent_failure_after_register/after_child_register at s01-ready): \
                 registered [case-root, child-A pid={pid}]; B never spawned; \
                 child-A reaped and {dir_note}"
            ),
        )
        .with_cleanup(CleanupProof {
            spawned: true,
            a_reaped: true,
            b_reaped: false,
            a_pid: Some(pid),
            b_pid: None,
            a_exit: channel_a.child.exit,
            b_exit: None,
            case_root_removed: dir_removed,
        }));
    }
    channel_a.child.pidfd = open_pidfd(channel_a.child.pid);
    if parent_failure.as_deref() == Some("after_pidfd_register") {
        let pid = channel_a.child.pid;
        let pidfd_state = if channel_a.child.pidfd.is_some() { "held" } else { "missing" };
        kill_and_reap_setup(&mut channel_a);
        let (dir_note, dir_removed) = dir_retirement_note(&case_dir_owned);
        if channel_a.child.pidfd.is_some() {
            return Err(setup_failure(
                Some("s01-ready"),
                format!(
                    "parent setup failed after pidfd registration \
                     (parent_failure_after_register/after_pidfd_register at s01-ready): \
                     registered [case-root, child-A pid={pid}, pidfd-A]; B never spawned; \
                     child-A reaped and {dir_note}"
                ),
            )
            .with_cleanup(CleanupProof {
                spawned: true,
                a_reaped: true,
                b_reaped: false,
                a_pid: Some(pid),
                b_pid: None,
                a_exit: channel_a.child.exit,
                b_exit: None,
                case_root_removed: dir_removed,
            }));
        }
        return Err(DriverError::new(
            DriverErrorKind::Io,
            Some("s01-ready"),
            format!(
                "pidfd-A {pidfd_state}: after_pidfd_register cannot populate on this kernel; \
                 child-A reaped and {dir_note}"
            ),
        )
        .with_cleanup(CleanupProof {
            spawned: true,
            a_reaped: true,
            b_reaped: false,
            a_pid: Some(pid),
            b_pid: None,
            a_exit: channel_a.child.exit,
            b_exit: None,
            case_root_removed: dir_removed,
        }));
    }
    let mut channel_b = spawn_channel(&config.image_b, "b", run_id, config.operation_id, None)?;
    channel_b.child.pidfd = open_pidfd(channel_b.child.pid);
    let mut inner = PairInner {
        a: channel_a,
        b: channel_b,
        scenario: config.scenario,
        completed: Vec::new(),
        cursor: 0,
        raw: Vec::new(),
        case_dir: case_dir_owned,
        case_root: Some(case_root),
        blobs: [None, None, None],
        uploaded: [false, false, false],
        file_a: None,
        file_b: None,
        tid: None,
        inventory: Vec::new(),
        invocation,
        images: vec![
            ImageExpectation {
                artifact: "tt03-worker-a",
                path_hex: path_hex_a,
                sha_hex: hex_bytes(&sha_a),
            },
            ImageExpectation {
                artifact: "tt03-worker-b",
                path_hex: path_hex_b,
                sha_hex: hex_bytes(&sha_b),
            },
        ],
        image_shas: [sha_a, sha_b],
        worker: config.worker.clone(),
        deadline_ns: config.deadline_ns,
        manifest_sha_hex: manifest_sha_hex.clone(),
        root: root_owned,
        cancel: Arc::clone(&config.cancel),
    };
    let shas = [sha_a, sha_b];
    let worker_control = match &config.control {
        Some(armed) if matches!(armed.kind.as_str(), "worker_exit" | "partial_file_write") => {
            Some(armed)
        }
        _ => None,
    };
    let mut failed: Option<DriverError> = None;
    for (index, (slot, marker)) in [(Actor::A, "A"), (Actor::B, "B")].into_iter().enumerate() {
        let outcome = (|| -> Result<(), DriverError> {
            let channel = if index == 0 { &mut inner.a } else { &mut inner.b };
            // Outage controls are A-only; B always boots clean.
            let hello_control = if index == 0 { worker_control } else { None };
            hello_exchange(
                channel,
                inner.scenario,
                &inner.invocation,
                &inner.images,
                slot,
                marker,
                config.deadline_ns,
                &manifest_sha_hex,
                "boot",
                0,
                1,
                1,
                hello_control,
                None,
            )?;
            authenticate_executable(channel.child.pid, &shas[index], None)?;
            channel.authenticated = true;
            Ok(())
        })();
        if let Err(error) = outcome {
            let channel = if index == 0 { &mut inner.a } else { &mut inner.b };
            let gone = channel.observed_gone();
            failed = Some(if gone {
                refused(
                    None,
                    format!(
                        "boot image cannot serve the fixture protocol: {}",
                        String::from_utf8_lossy(error.diagnostic_bytes())
                    ),
                )
            } else {
                error
            });
            break;
        }
    }
    if failed.is_none() {
        let root = inner.case_root.as_ref().expect("case root").as_fd().try_clone_to_owned();
        match root {
            Ok(owned) => {
                let body = FdTransferBody {
                    direction: FdDirection::Push,
                    role: FdRole::CaseRoot,
                    image_epoch: 1,
                    grant_id: 1,
                };
                let sent = inner.a.send(None, MessageKind::FdTransferRequest, 1, &body.encode(), Some(&owned));
                let outcome = sent.and_then(|_| {
                    let (_, reply, _) = inner.a.recv(None, MessageKind::FdTransferReply, false)?;
                    let echo = FdTransferBody::decode(&reply).map_err(|e| wire_error(None, e))?;
                    if echo != body {
                        return Err(protocol(None, "case root grant not echoed"));
                    }
                    Ok(())
                });
                if let Err(error) = outcome {
                    failed = Some(error);
                }
            }
            Err(e) => failed = Some(std_io_error(None, e)),
        }
    }
    if let Some(error) = failed {
        let mut proof = cleanup_children(&mut inner.a, &mut inner.b);
        proof.case_root_removed = std::fs::remove_dir_all(&inner.case_dir).is_ok();
        return Err(error.with_cleanup(proof));
    }
    let a_pid = inner.a.child.pid;
    let b_pid = inner.b.child.pid;
    Ok(LivePair {
        inner: Arc::new(Mutex::new(inner)),
        a_pid,
        b_pid,
    })
}

fn check_cancel(cancel: &AtomicBool, step: &str) -> Result<(), DriverError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(DriverError::new(
            DriverErrorKind::Cancelled,
            Some(step),
            "cancelled after ack".to_string(),
        ));
    }
    Ok(())
}

fn drain_records(
    channel: &mut Channel,
    invocation: &serde_json::Value,
    raw: &mut Vec<DrainedRecord>,
    step_id: &str,
    first: u32,
    count: u32,
    slot: &str,
) -> Result<(), DriverError> {
    if count == 0 || count > 9 {
        return Err(protocol(Some(step_id), "record count outside 1..9"));
    }
    for offset in 0..count {
        let index = first + offset;
        if index != channel.next_record {
            return Err(protocol(Some(step_id), "record index not contiguous"));
        }
        let request = RawRequest {
            record_index: index,
            offset: 0,
            max_chunk_bytes: CHUNK_MAX as u32,
        };
        channel.send(Some(step_id), MessageKind::RawRequest, 0, &request.encode(), None)?;
        let (_, first_bytes, _) = channel.recv(Some(step_id), MessageKind::RawReply, false)?;
        if first_bytes.len() < 48 {
            return Err(protocol(Some(step_id), "raw reply shorter than prefix"));
        }
        let prefix = FragmentPrefix::decode(&first_bytes[..48]).map_err(|e| wire_error(Some(step_id), e))?;
        if prefix.index != index || prefix.offset != 0 {
            return Err(protocol(Some(step_id), "fragment index or offset mismatch"));
        }
        let mut assembled = first_bytes[48..].to_vec();
        if prefix.chunk_bytes as usize != assembled.len() {
            return Err(protocol(Some(step_id), "fragment length mismatch"));
        }
        while assembled.len() < prefix.total_bytes as usize {
            let follow = RawRequest {
                record_index: index,
                offset: assembled.len() as u32,
                max_chunk_bytes: (prefix.total_bytes - assembled.len() as u32).min(CHUNK_MAX as u32),
            };
            channel.send(Some(step_id), MessageKind::RawRequest, 0, &follow.encode(), None)?;
            let (_, more, _) = channel.recv(Some(step_id), MessageKind::RawReply, false)?;
            if more.len() < 48 {
                return Err(protocol(Some(step_id), "continuation shorter than prefix"));
            }
            let next = FragmentPrefix::decode(&more[..48]).map_err(|e| wire_error(Some(step_id), e))?;
            if next.index != index
                || next.total_bytes != prefix.total_bytes
                || next.offset != assembled.len() as u32
                || next.whole_sha256 != prefix.whole_sha256
            {
                return Err(protocol(Some(step_id), "fragment continuity break"));
            }
            assembled.extend_from_slice(&more[48..]);
        }
        if assembled.len() != prefix.total_bytes as usize {
            return Err(protocol(Some(step_id), "assembled length mismatch"));
        }
        if sha256_of(&assembled) != prefix.whole_sha256 {
            return Err(protocol(Some(step_id), "record digest mismatch"));
        }
        let value = parse_canonical(&assembled, PAYLOAD_MAX).map_err(|e| wire_error(Some(step_id), e))?;
        if value["invocation"] != *invocation
            || value["step_id"] != step_id
            || value["record_index"] != index
        {
            return Err(protocol(Some(step_id), "record identity mismatch"));
        }
        let kind = value["record_kind"].as_str().unwrap_or("").to_string();
        raw.push(DrainedRecord {
            actor: slot.to_string(),
            step_id: step_id.to_string(),
            record_index: index,
            kind,
            bytes: assembled,
        });
        channel.next_record += 1;
    }
    Ok(())
}

fn advance_exchange(
    channel: &mut Channel,
    action: Action,
    actor: Actor,
    image_epoch: u32,
    blob_mask: u32,
    script_index: u32,
    step_id: &str,
) -> Result<AdvanceReply, DriverError> {
    let request = AdvanceRequest {
        action,
        actor,
        image_epoch,
        blob_mask,
    };
    channel.send(
        Some(step_id),
        MessageKind::AdvanceRequest,
        script_index,
        &request.encode(),
        None,
    )?;
    let (_, reply_bytes, _) = channel.recv(Some(step_id), MessageKind::AdvanceReply, false)?;
    let reply = AdvanceReply::decode(&reply_bytes).map_err(|e| wire_error(Some(step_id), e))?;
    if reply.action != action || reply.actor != actor {
        return Err(protocol(Some(step_id), "advance echo mismatch"));
    }
    Ok(reply)
}

fn advance_a_with_reply(
    inner: &mut PairInner,
    action: Action,
    blob_mask: u32,
    script_index: u32,
    step_id: &str,
) -> Result<AdvanceReply, DriverError> {
    if !inner.a.authenticated {
        return Err(protocol(Some(step_id), "channel not authenticated"));
    }
    let epoch = inner.a.image_epoch;
    let reply = advance_exchange(&mut inner.a, action, Actor::A, epoch, blob_mask, script_index, step_id)?;
    if reply.image_epoch != epoch {
        return Err(protocol(Some(step_id), "unexpected epoch change"));
    }
    if reply.pid != inner.a.child.pid {
        return Err(protocol(Some(step_id), "reply pid differs from owned child"));
    }
    let first = reply.first_record;
    let count = reply.record_count;
    if count == 0 {
        match action {
            Action::ExecB | Action::ExecA | Action::ExecFromSibling => {}
            _ => return Err(protocol(Some(step_id), "only exec steps drain zero records")),
        }
    } else {
        drain_records(&mut inner.a, &inner.invocation, &mut inner.raw, step_id, first, count, "a")?;
    }
    Ok(reply)
}

fn worker_advance(
    inner: &mut PairInner,
    action: Action,
    blob_mask: u32,
    script_index: u32,
    step_id: &str,
) -> Result<(), DriverError> {
    advance_a_with_reply(inner, action, blob_mask, script_index, step_id)?;
    Ok(())
}

fn verify_tricky_comm(pid: u32, step_id: &str) -> Result<(), DriverError> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).map_err(|e| std_io_error(Some(step_id), e))?;
    let (comm, _, _) = super::oracle::parse_stat_comm_state_starttime(&stat)
        .map_err(|e| protocol(Some(step_id), format!("stat parse: {}", e.detail())))?;
    if comm != TRICKY_COMM.as_bytes() {
        return Err(protocol(Some(step_id), "worker comm differs from tricky literal"));
    }
    Ok(())
}

fn fstat_size(fd: &OwnedFd, step_id: &str) -> Result<u64, DriverError> {
    rustix::fs::fstat(fd)
        .map(|s| s.st_size as u64)
        .map_err(|e| io_error(Some(step_id), e))
}

fn read_fd_all(fd: &OwnedFd, step_id: &str) -> Result<Vec<u8>, DriverError> {
    use std::os::unix::fs::FileExt;
    let dup: OwnedFd = fd.try_clone().map_err(std::io::Error::from).map_err(|e| std_io_error(Some(step_id), e))?;
    let file: std::fs::File = dup.into();
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut offset = 0u64;
    loop {
        if out.len() > FILE_BYTES_MAX {
            return Err(protocol(Some(step_id), "file exceeds byte ceiling"));
        }
        match file.read_at(&mut chunk, offset) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                out.extend_from_slice(&chunk[..n]);
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(std_io_error(Some(step_id), e)),
        }
    }
}

fn pull_file(
    inner: &mut PairInner,
    role: FdRole,
    grant_id: u32,
    step_id: &str,
    script_index: u32,
) -> Result<OwnedFd, DriverError> {
    let body = FdTransferBody {
        direction: FdDirection::Pull,
        role,
        image_epoch: inner.a.image_epoch,
        grant_id,
    };
    inner.a.send(
        Some(step_id),
        MessageKind::FdTransferRequest,
        script_index,
        &body.encode(),
        None,
    )?;
    let (_, reply, fd) = inner.a.recv(Some(step_id), MessageKind::FdTransferReply, true)?;
    let echo = FdTransferBody::decode(&reply).map_err(|e| wire_error(Some(step_id), e))?;
    if echo != body {
        return Err(protocol(Some(step_id), "fd pull not echoed"));
    }
    fd.ok_or_else(|| protocol(Some(step_id), "fd pull delivered nothing"))
}

fn exact_wait(child: &mut Child, step_id: Option<&str>) -> Result<ReapedExit, DriverError> {
    let mut waited = 0;
    loop {
        match child.try_wait().map_err(|e| std_io_error(step_id, e))? {
            Some(status) => return Ok(exit_of(status)),
            None => {
                if waited >= EXIT_WAIT_MS {
                    return Err(DriverError::new(
                        DriverErrorKind::Timeout,
                        step_id,
                        "exact child wait timed out".to_string(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
                waited += 20;
            }
        }
    }
}

fn pidfd_ready(
    pidfd: Option<&OwnedFd>,
    step_id: Option<&str>,
    bound_ms: i32,
) -> Result<bool, DriverError> {
    let Some(pidfd) = pidfd else {
        return Err(protocol(step_id, "no pidfd for readiness poll"));
    };
    let mut waited = 0;
    loop {
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        let mut fds = [rustix::event::PollFd::new(pidfd, rustix::event::PollFlags::IN)];
        let ready =
            rustix::event::poll(&mut fds, Some(&timeout)).map_err(|e| io_error(step_id, e))?;
        if ready > 0 {
            return Ok(true);
        }
        waited += 100;
        if waited >= bound_ms {
            return Ok(false);
        }
    }
}

/// Executable digest via a known-live thread. `/proc/<tgid>/exe` follows
/// the group leader's mm, which is gone (ENOENT) once the leader is a
/// zombie, so thread phases address the live sibling's task path instead.
fn exe_sha_of(pid: u32, live: Option<u32>, step_id: &str) -> Result<[u8; 32], DriverError> {
    let exe = match live {
        Some(tid) => std::path::PathBuf::from(format!("/proc/{pid}/task/{tid}/exe")),
        None => std::path::PathBuf::from(format!("/proc/{pid}/exe")),
    };
    let bytes = read_bounded(&exe, IMAGE_BYTES_MAX).map_err(|e| std_io_error(Some(step_id), e))?;
    Ok(sha256_of(&bytes))
}

fn task_tids_of(pid: u32, step_id: &str) -> Result<Vec<u32>, DriverError> {
    let mut tids = Vec::new();
    let dir = std::fs::read_dir(format!("/proc/{pid}/task")).map_err(|e| std_io_error(Some(step_id), e))?;
    for entry in dir {
        let entry = entry.map_err(|e| std_io_error(Some(step_id), e))?;
        let tid = entry
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|_| protocol(Some(step_id), "non-numeric task entry"))?;
        tids.push(tid);
    }
    tids.sort_unstable();
    Ok(tids)
}

fn task_state_of(pid: u32, tid: u32, step_id: &str) -> Result<u8, DriverError> {
    let stat = std::fs::read(format!("/proc/{pid}/task/{tid}/stat"))
        .map_err(|e| std_io_error(Some(step_id), e))?;
    super::oracle::parse_stat_comm_state_starttime(&stat)
        .map(|(_, state, _)| state)
        .map_err(|e| protocol(Some(step_id), format!("task stat parse: {}", e.detail())))
}

/// The exit-leader reply is already on the wire while the leader task may
/// still be exiting, so poll boundedly for the zombie-leader/live-sibling
/// task pair. The kernel keeps the dead group leader visible (state Z) with
/// the tgid pinned to it until process exit; sibling service proves the
/// process survives.
fn poll_leader_zombie(pid: u32, sibling: u32, step_id: &str) -> Result<(), DriverError> {
    let mut waited = 0;
    loop {
        let leader = task_state_of(pid, pid, step_id)?;
        let sib = task_state_of(pid, sibling, step_id)?;
        if leader == b'Z' && sib != b'Z' {
            return Ok(());
        }
        if waited >= EXIT_WAIT_MS {
            return Err(protocol(
                Some(step_id),
                format!(
                    "leader-only exit left states leader={} sibling={}",
                    leader as char, sib as char
                ),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        waited += 20;
    }
}

/// Third-slot descriptor inventory: after the file prefix ran (both parent
/// and worker hold their original FileA/B owners), spawn the positive child
/// with the inherited canary pipe and the negative child without it,
/// sequentially in one slot. Each child is inspected live via its own
/// /proc/PID/fd, then killed and exactly reaped before the next spawns.
fn run_inventory(inner: &mut PairInner, step_id: &str) -> Result<(), DriverError> {
    if inner.file_a.is_none() || inner.file_b.is_none() {
        return Err(protocol(Some(step_id), "inventory needs offered FileA/B first"));
    }
    const CANARY_HEX: &str = "53424649585455524543414e41525931";
    let token: Vec<u8> = (0..CANARY_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&CANARY_HEX[i..i + 2], 16).unwrap())
        .collect();
    // NOTE: plain pipe() is NOT cloexec; only the explicit stderr grant may
    // cross exec, never the parent's own canary ends.
    let (canary_read, canary_write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .map_err(|e| io_error(Some(step_id), e))?;
    {
        let mut writer: std::fs::File = canary_write
            .try_clone()
            .map_err(std::io::Error::from)
            .map_err(|e| std_io_error(Some(step_id), e))?
            .into();
        use std::io::Write;
        writer.write_all(&token).map_err(|e| std_io_error(Some(step_id), e))?;
    }
    let canary_ino = rustix::fs::fstat(&canary_read)
        .map_err(|e| io_error(Some(step_id), e))?
        .st_ino;
    let want_link = format!("pipe:[{canary_ino}]");

    let worker_path = inner.worker.clone();
    let positive = spawn_inventory_child(&worker_path, Some(&canary_write), step_id)?;
    wait_for_exec(positive.pid, &worker_path, step_id)?;
    let positive_hit = scan_child_for_canary(positive.pid, &want_link, step_id)?;
    let positive_pid = positive.pid;
    inner.inventory.push(InventoryRecord {
        pid: positive_pid,
        positive: true,
        reaped: false,
    });
    kill_and_reap_inventory(positive.child, step_id)?;
    inner
        .inventory
        .last_mut()
        .expect("just pushed positive")
        .reaped = true;
    let negative = spawn_inventory_child(&worker_path, None, step_id)?;
    wait_for_exec(negative.pid, &worker_path, step_id)?;
    let negative_hit = scan_child_for_canary(negative.pid, &want_link, step_id)?;
    let negative_pid = negative.pid;
    inner.inventory.push(InventoryRecord {
        pid: negative_pid,
        positive: false,
        reaped: false,
    });
    kill_and_reap_inventory(negative.child, step_id)?;
    inner
        .inventory
        .last_mut()
        .expect("just pushed negative")
        .reaped = true;

    let Some((fd_no, dev, ino, fdinfo_hex)) = positive_hit else {
        return Err(protocol(Some(step_id), "positive child lacks the canary FD"));
    };
    if fd_no != 2 {
        return Err(protocol(Some(step_id), "canary must arrive only as the granted stderr"));
    }
    if negative_hit.is_some() {
        return Err(protocol(Some(step_id), "negative child unexpectedly holds the canary"));
    }
    for (channel, what) in [(&mut inner.a, "A"), (&mut inner.b, "B")] {
        if channel.observed_gone() {
            return Err(protocol(Some(step_id), format!("child {what} died during inventory")));
        }
    }
    let positive_values = serde_json::json!({
        "slot": fd_no,
        "device": dev.to_string(),
        "inode": ino.to_string(),
        "file_type": "fifo",
        "size": "0",
        "fdinfo_hex": fdinfo_hex,
        "getfd": null,
        "getfl": null,
        "canary_hex": CANARY_HEX,
    });
    let negative_values = serde_json::json!({
        "slot": null,
        "device": null,
        "inode": null,
        "file_type": null,
        "size": "0",
        "fdinfo_hex": null,
        "getfd": null,
        "getfl": null,
        "canary_hex": null,
    });
    for (actor, values) in [
        ("parent-positive", positive_values),
        ("parent-negative", negative_values),
    ] {
        let body = serde_json::json!({
            "schema_version": 1,
            "invocation": inner.invocation.clone(),
            "step_id": step_id,
            "record_index": 0,
            "sequence": null,
            "actor_slot": actor,
            "record_kind": "fd",
            "source": "parent_proc",
            "bytes_hex": null,
            "values": values,
            "call_result": "observed",
            "errno": null,
            "producer_charges": null,
        });
        let bytes = canonical_json(&body).map_err(|e| wire_error(Some(step_id), e))?.into_bytes();
        inner.raw.push(DrainedRecord {
            actor: actor.to_string(),
            step_id: step_id.to_string(),
            record_index: 0,
            kind: "fd".to_string(),
            bytes,
        });
    }
    Ok(())
}

struct InventoryChild {
    child: Child,
    pid: u32,
    _sock: OwnedFd,
}

fn spawn_inventory_child(
    worker: &std::path::Path,
    canary: Option<&OwnedFd>,
    step_id: &str,
) -> Result<InventoryChild, DriverError> {
    let (parent_end, child_end) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| io_error(Some(step_id), e))?;
    let stderr = match canary {
        Some(fd) => {
            let owned: OwnedFd = fd.try_clone().map_err(std::io::Error::from).map_err(|e| std_io_error(Some(step_id), e))?;
            Stdio::from(owned)
        }
        None => Stdio::null(),
    };
    let mut child = std::process::Command::new(worker)
        .arg("--scopebase-fixture-v1")
        .arg("--slot")
        .arg("a")
        .arg("--handover")
        .arg("-")
        .stdin(Stdio::from(child_end))
        .stdout(Stdio::null())
        .stderr(stderr)
        .env_clear()
        .spawn()
        .map_err(|e| std_io_error(Some(step_id), e))?;
    let pid = child.id();
    match child.try_wait().map_err(|e| std_io_error(Some(step_id), e))? {
        None => Ok(InventoryChild { child, pid, _sock: parent_end }),
        Some(_) => Err(protocol(Some(step_id), "inventory child exited before inspection")),
    }
}

fn scan_child_for_canary(
    pid: u32,
    want_link: &str,
    step_id: &str,
) -> Result<Option<(u32, u64, u64, String)>, DriverError> {
    let dir = std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(|e| std_io_error(Some(step_id), e))?;
    for entry in dir {
        let entry = entry.map_err(|e| std_io_error(Some(step_id), e))?;
        let link = std::fs::read_link(entry.path()).map_err(|e| std_io_error(Some(step_id), e))?;
        if link.to_string_lossy() == want_link {
            let fd_no: u32 = entry
                .file_name()
                .to_string_lossy()
                .parse()
                .map_err(|_| protocol(Some(step_id), "non-numeric child fd"))?;
            let stat = std::fs::metadata(entry.path()).map_err(|e| std_io_error(Some(step_id), e))?;
            use std::os::unix::fs::MetadataExt;
            let fdinfo = std::fs::read(format!("/proc/{pid}/fdinfo/{fd_no}"))
                .map_err(|e| std_io_error(Some(step_id), e))?;
            let capped = fdinfo.len().min(4096);
            return Ok(Some((fd_no, stat.dev(), stat.ino(), hex_bytes(&fdinfo[..capped]))));
        }
    }
    Ok(None)
}

/// Exec barrier: a spawned child still holds the full parent FD table in
/// the fork/exec window, so never scan its descriptors until its own
/// executable link proves the new image runs.
fn wait_for_exec(pid: u32, worker: &std::path::Path, step_id: &str) -> Result<(), DriverError> {
    let mut waited = 0;
    loop {
        match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(link) if link == worker => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(std_io_error(Some(step_id), e)),
        }
        if waited >= EXIT_WAIT_MS {
            return Err(DriverError::new(
                DriverErrorKind::Timeout,
                Some(step_id),
                "inventory child did not exec the worker image".to_string(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        waited += 5;
    }
}

fn kill_and_reap_inventory(mut child: Child, step_id: &str) -> Result<(), DriverError> {
    child.kill().map_err(|e| std_io_error(Some(step_id), e))?;
    exact_wait(&mut child, Some(step_id))?;
    Ok(())
}

pub(crate) fn advance_a_step(shared: &SharedPair, step_id: &str) -> Result<(), DriverError> {
    let mut inner = shared.lock().expect("pair lock");
    let scenario = inner.scenario;
    let script = scenario.steps();
    let position = script.iter().position(|s| s.id == step_id);
    let Some(index) = position else {
        return Err(protocol(Some(step_id), "step is not in the scenario script"));
    };
    if index != inner.cursor {
        return Err(protocol(Some(step_id), "step is out of order"));
    }
    let script_index = (index + 1) as u32;
    let action = script[index].action;
    if script[index].actor == Actor::Parent && action == Action::Close {
        close_channel_step(&mut inner, true, step_id, script_index)?;
        close_channel_step(&mut inner, false, step_id, script_index)?;
        inner.completed.push(step_id.to_string());
        inner.cursor += 1;
        return Ok(());
    }
    match action {
        Action::Ready | Action::CaptureRaw | Action::SetTrickyComm => {
            // Expected deaths (after parent_exit) are witnessed WITHOUT
            // reaping, so the later parent_reap still performs the exact
            // wait; unexpected deaths reap here for their wait status.
            let a_dead = inner.a.child.reaped || wnowait_dead(inner.a.child.pid);
            if action == Action::CaptureRaw && a_dead {
                sample_post_death(&mut inner, step_id)?;
            } else if a_dead {
                let status = inner.a.child.poll_gone().unwrap_or(ReapedExit {
                    signal: None,
                    code: None,
                });
                return Err(worker_death(Some(step_id), status));
            } else {
                worker_advance(&mut inner, action, 0, script_index, step_id)?;
                if action == Action::SetTrickyComm {
                    let pid = inner.a.child.pid;
                    verify_tricky_comm(pid, step_id)?;
                }
            }
        }
        Action::CreateFiles => {
            if !inner.uploaded.iter().all(|u| *u) {
                return Err(protocol(Some(step_id), "blobs must upload before create"));
            }
            match worker_advance(&mut inner, action, 3, script_index, step_id) {
                Ok(()) => {}
                Err(e) if e.kind() == DriverErrorKind::WorkerDeath => {
                    return Err(record_create_death(&mut inner, step_id, e));
                }
                Err(e) => return Err(e),
            }
            for (leaf, expect) in [
                ("a", inner.blobs[0].as_ref().unwrap().len() as u64),
                ("b", inner.blobs[1].as_ref().unwrap().len() as u64),
            ] {
                let root = inner.case_root.as_ref().expect("case root");
                let fd: OwnedFd = rustix::fs::openat(
                    root,
                    leaf,
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|e| io_error(Some(step_id), e))?;
                let size = fstat_size(&fd, step_id)?;
                if size != expect {
                    return Err(protocol(Some(step_id), "created file size mismatch"));
                }
            }
        }
        Action::OfferFiles => {
            let fa = pull_file(&mut inner, FdRole::FileA, 4, step_id, script_index)?;
            let fb = pull_file(&mut inner, FdRole::FileB, 5, step_id, script_index)?;
            inner.file_a = Some(fa);
            inner.file_b = Some(fb);
            let expect_a = inner.blobs[0].as_ref().expect("blob a").clone();
            let got_a = read_fd_all(inner.file_a.as_ref().unwrap(), step_id)?;
            if got_a != expect_a {
                return Err(protocol(Some(step_id), "pulled file A content mismatch"));
            }
            let expect_b = inner.blobs[1].as_ref().expect("blob b").clone();
            let got_b = read_fd_all(inner.file_b.as_ref().unwrap(), step_id)?;
            if got_b != expect_b {
                return Err(protocol(Some(step_id), "pulled file B content mismatch"));
            }
        }
        Action::ReplaceFileA | Action::UnlinkOriginalA => {
            worker_advance(&mut inner, action, 0, script_index, step_id)?;
        }
        Action::MutateFileA => {
            match worker_advance(&mut inner, action, 4, script_index, step_id) {
                Ok(()) => {}
                Err(e) if e.kind() == DriverErrorKind::WorkerDeath => {
                    return Err(record_mutate_death(&mut inner, step_id, e));
                }
                Err(e) => return Err(e),
            }
            let expect = inner.blobs[2].as_ref().expect("mutation").clone();
            let got = read_fd_all(inner.file_a.as_ref().expect("file a"), step_id)?;
            if got != expect {
                return Err(protocol(Some(step_id), "mutated content mismatch"));
            }
        }
        Action::ParentExit => {
            let pidfd = inner.a.child.pidfd.as_ref();
            match pidfd {
                Some(fd) => {
                    rustix::process::pidfd_send_signal(fd, rustix::process::Signal::TERM)
                        .map_err(|e| io_error(Some(step_id), e))?;
                }
                None => return Err(protocol(Some(step_id), "parent exit needs the original pidfd")),
            }
            if !pidfd_ready(inner.a.child.pidfd.as_ref(), Some(step_id), EXIT_WAIT_MS)? {
                return Err(DriverError::new(
                    DriverErrorKind::Timeout,
                    Some(step_id),
                    "target did not exit".to_string(),
                ));
            }
        }
        Action::ParentReap => {
            let child = inner
                .a
                .child
                .child
                .as_mut()
                .ok_or_else(|| protocol(Some(step_id), "no owned child to reap"))?;
            let exit = exact_wait(child, Some(step_id))?;
            inner.a.child.exit = Some(exit);
            inner.a.child.reaped = true;
            inner.a.child.child.take();
        }
        Action::Close => {
            return Err(protocol(Some(step_id), "close must run through both channels"));
        }
        Action::ExecB | Action::ExecA | Action::ExecFromSibling => {
            let (marker, target): (&'static str, usize) = match action {
                Action::ExecB => ("B", 1),
                Action::ExecA => ("A", 0),
                _ => ("B", 1),
            };
            let from_sibling = action == Action::ExecFromSibling;
            let live_before = if from_sibling { inner.tid } else { None };
            if from_sibling && live_before.is_none() {
                return Err(protocol(Some(step_id), "nonleader exec without a live sibling"));
            }
            let sha_before = exe_sha_of(inner.a.child.pid, live_before, step_id)?;
            worker_advance(&mut inner, action, 0, script_index, step_id)?;
            resume_after_exec(&mut inner, step_id, script_index, marker, target)?;
            if from_sibling {
                inner.tid = None;
            }
            let sha_after = exe_sha_of(inner.a.child.pid, None, step_id)?;
            if sha_before == sha_after && inner.image_shas[0] != inner.image_shas[1] {
                return Err(protocol(Some(step_id), "exec left the running image unchanged"));
            }
            if from_sibling {
                let tids = task_tids_of(inner.a.child.pid, step_id)?;
                if tids != vec![inner.a.child.pid] {
                    return Err(protocol(Some(step_id), "nonleader exec left sibling threads behind"));
                }
            }
        }
        Action::ExecMissing => {
            let live = inner.tid;
            let sha_before = exe_sha_of(inner.a.child.pid, live, step_id)?;
            worker_advance(&mut inner, action, 0, script_index, step_id)?;
            let sha_after = exe_sha_of(inner.a.child.pid, live, step_id)?;
            if sha_before != sha_after {
                return Err(protocol(Some(step_id), "failed exec changed the running image"));
            }
            let witnessed = inner.raw.iter().any(|r| {
                if r.step_id != step_id || r.kind != "exec" {
                    return false;
                }
                serde_json::from_slice::<serde_json::Value>(&r.bytes)
                    .map(|v| {
                        v["errno"] == rustix::io::Errno::NOENT.raw_os_error()
                            && v["call_result"] == "failed"
                    })
                    .unwrap_or(false)
            });
            if !witnessed {
                return Err(protocol(Some(step_id), "failed exec lacks ENOENT evidence"));
            }
        }
        Action::StartSibling => {
            let reply = advance_a_with_reply(&mut inner, action, 0, script_index, step_id)?;
            let pid = inner.a.child.pid;
            let tids = task_tids_of(pid, step_id)?;
            if tids.len() != 2 || !tids.contains(&pid) {
                return Err(protocol(Some(step_id), "sibling start lacks exactly two tasks"));
            }
            let sibling = *tids.iter().find(|t| **t != pid).unwrap();
            if reply.tid != sibling {
                return Err(protocol(
                    Some(step_id),
                    "worker-reported sibling TID disagrees with the /proc task scan",
                ));
            }
            inner.tid = Some(sibling);
        }
        Action::ExitLeader => {
            let sibling = inner
                .tid
                .ok_or_else(|| protocol(Some(step_id), "exit_leader without a live sibling"))?;
            worker_advance(&mut inner, action, 0, script_index, step_id)?;
            poll_leader_zombie(inner.a.child.pid, sibling, step_id)?;
        }
        Action::Inventory => {
            run_inventory(&mut inner, step_id)?;
        }
    }
    if inner.cancel.load(Ordering::Relaxed) {
        check_cancel(&inner.cancel, step_id)?;
    }
    inner.completed.push(step_id.to_string());
    inner.cursor += 1;
    Ok(())
}

/// Non-reaping liveness witness for expected-death captures: true only
/// when waitid/WNOWAIT observes the owned child exited-but-unreaped.
/// Witness errors (including ECHILD after a recorded reap) mean "not
/// observed dead"; the protocol exchange then decides with typed errors.
fn wnowait_dead(pid: u32) -> bool {
    matches!(exited_unreaped_owned(pid, 8), Ok(Some(_)))
}

enum LeafSample {
    Absent,
    Unreadable,
    Bytes(Vec<u8>),
}

fn push_parent_mutation(
    inner: &mut PairInner,
    step_id: &str,
    slot: &str,
    sample: &LeafSample,
) -> Result<(), ()> {
    let (byte_count, readback_hex) = match sample {
        LeafSample::Bytes(bytes) => (
            bytes.len().to_string(),
            serde_json::Value::String(hex_bytes(bytes)),
        ),
        _ => ("0".to_string(), serde_json::Value::Null),
    };
    let body = serde_json::json!({
        "schema_version": 1,
        "invocation": inner.invocation.clone(),
        "step_id": step_id,
        "record_index": 0,
        "sequence": null,
        "actor_slot": "parent",
        "record_kind": "mutation",
        "source": "parent_file",
        "bytes_hex": null,
        "values": {
            "original_slot": slot,
            "replacement_slot": null,
            "operation": "worker_death_sample",
            "offset": "0",
            "byte_count": byte_count,
            "readback_hex": readback_hex,
        },
        "call_result": "observed",
        "errno": null,
        "producer_charges": null,
    });
    let bytes = canonical_json(&body).map_err(|_| ())?.into_bytes();
    inner.raw.push(DrainedRecord {
        actor: "parent".to_string(),
        step_id: step_id.to_string(),
        record_index: 0,
        kind: "mutation".to_string(),
        bytes,
    });
    Ok(())
}

/// Parent-side file-prefix sampling after a worker death during create:
/// each leaf is opened through the retained case root and its actual bytes
/// are sealed into mutation records. Sampling never masks the death: any
/// sampling failure returns the original error unchanged.
fn record_create_death(inner: &mut PairInner, step_id: &str, death: DriverError) -> DriverError {
    let samples: Option<Vec<LeafSample>> = (|| {
        let case_root = inner.case_root.as_ref()?;
        let mut out = Vec::with_capacity(2);
        for leaf in ["a", "b"] {
            let fd: OwnedFd = match rustix::fs::openat(
                case_root,
                leaf,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(_) => {
                    out.push(LeafSample::Absent);
                    continue;
                }
            };
            match read_fd_all(&fd, step_id) {
                Ok(bytes) => out.push(LeafSample::Bytes(bytes)),
                Err(_) => out.push(LeafSample::Unreadable),
            }
        }
        Some(out)
    })();
    let Some(samples) = samples else {
        return death;
    };
    let mut notes = Vec::with_capacity(2);
    for (leaf, slot, sample) in
        [("a", "linux.file-a"), ("b", "linux.file-b")]
            .into_iter()
            .zip(samples.iter())
            .map(|((leaf, slot), sample)| (leaf, slot, sample))
    {
        match sample {
            LeafSample::Bytes(bytes) => notes.push(format!("{leaf}: present {} bytes", bytes.len())),
            LeafSample::Absent => notes.push(format!("{leaf}: absent")),
            LeafSample::Unreadable => notes.push(format!("{leaf}: unreadable")),
        }
        if push_parent_mutation(inner, step_id, slot, sample).is_err() {
            return death;
        }
    }
    death.with_note(format!("file prefix at death: {}", notes.join(", ")))
}

/// Parent-side partial-write sampling after a worker death during mutate:
/// the actual bytes are read through the retained original FileA owner and
/// sealed into a mutation record with the matched mutation prefix counted.
fn record_mutate_death(inner: &mut PairInner, step_id: &str, death: DriverError) -> DriverError {
    let readback: Option<Vec<u8>> = (|| {
        let file_a = inner.file_a.as_ref()?;
        read_fd_all(file_a, step_id).ok()
    })();
    let Some(readback) = readback else {
        return death;
    };
    let (mutation_len, matched_prefix) = match inner.blobs[2].as_ref() {
        Some(mutation) => (
            mutation.len(),
            readback.iter().zip(mutation.iter()).take_while(|(a, b)| a == b).count(),
        ),
        None => (0, 0),
    };
    if push_parent_mutation(inner, step_id, "linux.file-a", &LeafSample::Bytes(readback.clone()))
        .is_err()
    {
        return death;
    }
    death.with_note(format!(
        "file-a partial: {matched_prefix}/{mutation_len} mutation bytes from offset 0; \
         {} bytes retained",
        readback.len()
    ))
}

fn sample_post_death(inner: &mut PairInner, step_id: &str) -> Result<(), DriverError> {
    let pid = inner.a.child.pid;
    let bytes = std::fs::read(format!("/proc/{pid}/stat")).unwrap_or_default();
    inner.raw.push(DrainedRecord {
        actor: "parent".to_string(),
        step_id: step_id.to_string(),
        record_index: 0,
        kind: "proc".to_string(),
        bytes,
    });
    Ok(())
}

fn close_channel_step(
    inner: &mut PairInner,
    is_a: bool,
    step_id: &str,
    script_index: u32,
) -> Result<(), DriverError> {
    let channel = if is_a { &mut inner.a } else { &mut inner.b };
    if channel.closed {
        return Ok(());
    }
    // A dead A retires through close: the reap is already recorded by the
    // poll, so no second wait is attempted (a second wait would fail ECHILD).
    // B must always close clean.
    let gone = channel.observed_gone();
    if gone && is_a {
        channel.closed = true;
        return Ok(());
    }
    if gone {
        return Err(protocol(Some(step_id), "B exited before close"));
    }
    let completed = inner.completed.len() as u32;
    let body = CloseBody {
        reason: CloseReason::Normal,
        actor: if is_a { Actor::A } else { Actor::B },
        image_epoch: channel.image_epoch,
        last_completed_step: completed,
    };
    channel.send(
        Some(step_id),
        MessageKind::CloseRequest,
        script_index,
        &body.encode(),
        None,
    )?;
    let (_, reply, _) = channel.recv(Some(step_id), MessageKind::CloseReply, false)?;
    let echo = CloseBody::decode(&reply).map_err(|e| wire_error(Some(step_id), e))?;
    if echo != body {
        return Err(protocol(Some(step_id), "close not echoed"));
    }
    channel.closed = true;
    if let Some(child) = channel.child.child.as_mut() {
        let exit = exact_wait(child, Some(step_id))?;
        channel.child.exit = Some(exit);
        channel.child.reaped = true;
        channel.child.child.take();
    }
    Ok(())
}

pub(crate) fn heartbeat_b(shared: &SharedPair, step_id: &str) -> Result<(), DriverError> {
    let mut inner = shared.lock().expect("pair lock");
    if !inner.b.authenticated || inner.b.closed {
        return Err(protocol(Some(step_id), "B channel is not serviceable"));
    }
    let action = if step_id == "s01-ready" {
        Action::Ready
    } else {
        Action::CaptureRaw
    };
    let Some(position) = inner.scenario.steps().iter().position(|s| s.id == step_id) else {
        return Err(protocol(Some(step_id), "heartbeat step is not in script"));
    };
    let epoch = inner.b.image_epoch;
    let reply =
        advance_exchange(&mut inner.b, action, Actor::B, epoch, 0, (position + 1) as u32, step_id)?;
    if reply.pid != inner.b.child.pid {
        return Err(protocol(Some(step_id), "B reply pid mismatch"));
    }
    let first = reply.first_record;
    let count = reply.record_count;
    let pair: &mut PairInner = &mut inner;
    drain_records(&mut pair.b, &pair.invocation, &mut pair.raw, step_id, first, count, "b")
}

pub(crate) fn upload_blobs_shared(
    shared: &SharedPair,
    a: &[u8],
    b: &[u8],
    mutation: &[u8],
) -> Result<(), DriverError> {
    for bytes in [a, b, mutation] {
        if bytes.len() > FILE_BYTES_MAX {
            return Err(protocol(None, "blob exceeds file byte ceiling"));
        }
    }
    if a.len() != mutation.len() {
        return Err(protocol(None, "mutation must equal file A length"));
    }
    let mut inner = shared.lock().expect("pair lock");
    inner.blobs = [Some(a.to_vec()), Some(b.to_vec()), Some(mutation.to_vec())];
    for (slot, bytes) in [(1u32, a), (2, b), (3, mutation)] {
        if bytes.is_empty() {
            inner.uploaded[slot as usize - 1] = true;
            continue;
        }
        let total = bytes.len() as u32;
        let digest = sha256_of(bytes);
        let mut offset = 0u32;
        while offset < total {
            let chunk = (total - offset).min(CHUNK_MAX as u32);
            let prefix = FragmentPrefix {
                index: slot,
                total_bytes: total,
                offset,
                chunk_bytes: chunk,
                whole_sha256: digest,
            };
            let mut payload = prefix.encode().to_vec();
            payload.extend_from_slice(&bytes[offset as usize..(offset + chunk) as usize]);
            inner.a.send(None, MessageKind::InputChunkRequest, 0, &payload, None)?;
            let (_, ack_bytes, _) = inner.a.recv(None, MessageKind::InputChunkAck, false)?;
            let ack = InputChunkAck::decode(&ack_bytes).map_err(|e| wire_error(None, e))?;
            if ack.blob_index != slot || ack.total_bytes != total || ack.next_offset != offset + chunk
            {
                return Err(protocol(None, "chunk ack mismatch"));
            }
            offset += chunk;
        }
        inner.uploaded[slot as usize - 1] = true;
    }
    Ok(())
}

#[derive(Debug)]
pub struct LivePair {
    pub(crate) inner: SharedPair,
    a_pid: u32,
    b_pid: u32,
}

impl LivePair {
    pub fn a_pid(&self) -> u32 {
        self.a_pid
    }
    pub fn b_pid(&self) -> u32 {
        self.b_pid
    }
    pub fn scenario(&self) -> Scenario {
        self.inner.lock().expect("pair lock").scenario
    }
    pub fn a_process(&self) -> super::phase::LinuxProcessFixture {
        super::phase::LinuxProcessFixture::bind(Arc::clone(&self.inner), self.a_pid)
    }
    pub fn b_process(&self) -> super::phase::LinuxProcessFixture {
        super::phase::LinuxProcessFixture::bind_excluded(Arc::clone(&self.inner), self.b_pid)
    }
    pub fn b_heartbeat(&self, step: &crate::Label) -> Result<(), DriverError> {
        heartbeat_b(&self.inner, step.as_str())
    }
    pub fn drained_raw(&self) -> Vec<DrainedRecord> {
        self.inner.lock().expect("pair lock").raw.clone()
    }
    pub fn inventory_children(&self) -> Vec<InventoryRecord> {
        self.inner.lock().expect("pair lock").inventory.clone()
    }
    pub fn terminate_a(&self) -> Result<(), DriverError> {
        let mut inner = self.inner.lock().expect("pair lock");
        let child = inner
            .a
            .child
            .child
            .as_mut()
            .ok_or_else(|| protocol(None, "no owned A to terminate"))?;
        child.kill().map_err(|e| std_io_error(None, e))
    }
    pub fn a_exit_ready(&self, timeout_ms: i32) -> Result<bool, DriverError> {
        let inner = self.inner.lock().expect("pair lock");
        pidfd_ready(inner.a.child.pidfd.as_ref(), None, timeout_ms.max(100))
    }
    pub fn a_exited_unreaped(&self) -> Result<Option<i32>, DriverError> {
        exited_unreaped_owned(self.a_pid, 8).map_err(|e| std_io_error(None, e))
    }
    pub fn reap_a(&self) -> Result<ReapedExit, DriverError> {
        let mut inner = self.inner.lock().expect("pair lock");
        if inner.a.child.reaped {
            return Err(protocol(None, "A is already reaped"));
        }
        let child = inner
            .a
            .child
            .child
            .as_mut()
            .ok_or_else(|| protocol(None, "no owned A to reap"))?;
        let exit = exact_wait(child, None)?;
        inner.a.child.exit = Some(exit);
        inner.a.child.reaped = true;
        inner.a.child.child.take();
        Ok(exit)
    }
    pub fn upload_blobs(&self, a: &[u8], b: &[u8], mutation: &[u8]) -> Result<(), DriverError> {
        upload_blobs_shared(&self.inner, a, b, mutation)
    }
    pub fn deadline_hold(
        &self,
        completed_prefix: &str,
        execution_ms: u64,
        maximum_hold_ms: u64,
    ) -> Result<DeadlineHoldReport, DriverError> {
        deadline_hold_run(&self.inner, completed_prefix, execution_ms, maximum_hold_ms)
    }
    pub fn pulled_file_a(&self) -> std::io::Result<std::fs::File> {
        self.pulled_file(true)
    }
    pub fn pulled_file_b(&self) -> std::io::Result<std::fs::File> {
        self.pulled_file(false)
    }
    fn pulled_file(&self, is_a: bool) -> std::io::Result<std::fs::File> {
        let inner = self.inner.lock().expect("pair lock");
        let fd = if is_a { inner.file_a.as_ref() } else { inner.file_b.as_ref() }.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                if is_a { "file A not pulled" } else { "file B not pulled" },
            )
        })?;
        let owned: OwnedFd = fd.try_clone().map_err(std::io::Error::from)?;
        Ok(owned.into())
    }
    pub fn shutdown(self) -> ShutdownReport {
        let mut inner = self.inner.lock().expect("pair lock");
        for is_a in [true, false] {
            let attempt_close = {
                let pair: &mut PairInner = &mut inner;
                let channel = if is_a { &mut pair.a } else { &mut pair.b };
                !channel.child.reaped && !channel.closed
            };
            if attempt_close {
                let pair: &mut PairInner = &mut inner;
                let completed = pair.completed.len() as u32;
                let channel = if is_a { &mut pair.a } else { &mut pair.b };
                let body = CloseBody {
                    reason: CloseReason::Normal,
                    actor: if is_a { Actor::A } else { Actor::B },
                    image_epoch: channel.image_epoch,
                    last_completed_step: completed,
                };
                let _ = channel.send(None, MessageKind::CloseRequest, 0, &body.encode(), None);
                let _ = channel.recv(None, MessageKind::CloseReply, false);
                channel.closed = true;
            }
            let pair: &mut PairInner = &mut inner;
            let channel = if is_a { &mut pair.a } else { &mut pair.b };
            reap_shutdown(channel);
        }
        if let Some(case_root) = inner.case_root.as_ref() {
            for leaf in ["a", "b", "a-original", "missing-executable"] {
                let _ =
                    rustix::fs::unlinkat(case_root, leaf, rustix::fs::AtFlags::empty());
            }
        }
        drop(inner.case_root.take());
        let name = inner
            .case_dir
            .file_name()
            .expect("case dir name")
            .to_string_lossy()
            .into_owned();
        let removed =
            rustix::fs::unlinkat(&inner.root, &name, rustix::fs::AtFlags::REMOVEDIR).is_ok();
        ShutdownReport {
            case_root_removed: removed,
            a_exit: inner.a.child.exit,
            b_exit: inner.b.child.exit,
        }
    }
}

pub(crate) fn nonleader_tid_of(shared: &SharedPair) -> Option<u32> {
    shared.lock().expect("pair lock").tid
}

#[derive(Clone, Debug)]
pub struct DeadlineHoldReport {
    pub completed_prefix: String,
    pub elapsed_ns: u64,
    pub extra_worker_datagrams: u64,
}

/// Runner-deadline schedule hold: after a real ACK + drain at
/// `completed_prefix`, wait the full `execution_ms` in bounded sleep chunks
/// (<=500ms, <=64 clock checks), send zero worker datagrams, then witness
/// both children still alive with non-blocking polls only.
pub(crate) fn deadline_hold_run(
    shared: &SharedPair,
    completed_prefix: &str,
    execution_ms: u64,
    maximum_hold_ms: u64,
) -> Result<DeadlineHoldReport, DriverError> {
    if execution_ms == 0 || execution_ms > maximum_hold_ms || maximum_hold_ms > 31_000 {
        return Err(protocol(
            Some(completed_prefix),
            "hold window must satisfy 1 <= execution <= maximum <= 31000 ms",
        ));
    }
    {
        let inner = shared.lock().expect("pair lock");
        if !inner.completed.iter().any(|s| s == completed_prefix) {
            return Err(protocol(
                Some(completed_prefix),
                "hold prefix is not a completed step",
            ));
        }
    }
    let target = std::time::Duration::from_millis(execution_ms);
    let start = std::time::Instant::now();
    let mut checks: u32 = 0;
    while start.elapsed() < target {
        if checks >= 64 {
            break;
        }
        let remaining = target.saturating_sub(start.elapsed());
        let chunk = remaining
            .min(std::time::Duration::from_millis(500))
            .max(std::time::Duration::from_millis(1));
        std::thread::sleep(chunk);
        checks += 1;
    }
    let elapsed = start.elapsed();
    if elapsed < target {
        return Err(DriverError::new(
            DriverErrorKind::Timeout,
            Some(completed_prefix),
            "hold exhausted clock checks before the execution duration".to_string(),
        ));
    }
    {
        let mut inner = shared.lock().expect("pair lock");
        for what in ["A", "B"] {
            let channel = if what == "A" { &mut inner.a } else { &mut inner.b };
            if channel.observed_gone() {
                return Err(protocol(
                    Some(completed_prefix),
                    format!("child {what} died during the hold"),
                ));
            }
        }
    }
    Ok(DeadlineHoldReport {
        completed_prefix: completed_prefix.to_string(),
        elapsed_ns: elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
        extra_worker_datagrams: 0,
    })
}

