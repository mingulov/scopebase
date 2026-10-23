// SPDX-License-Identifier: Apache-2.0
//! TT03 standalone fixture worker: serves one protocol channel on fd 0.
//!
//! Fixed argv: `[image, --scopebase-fixture-v1, --slot, a|b, --handover, -]`.
//! Serves boot/resume Hello, ready, capture_raw, set_tricky_comm (via
//! /proc/self/comm), blob upload, file create/offer/pull, replace, unlink,
//! mutate, real exec (A/B round-trip, failing missing-leaf attempt, nonleader
//! exec), real sibling thread spawn plus leader-only exit with service
//! handover, and close. The parent owns all exits and reaps.
//!
//! Closed outage controls (`worker_exit`, `partial_file_write`) arrive on the
//! A worker's boot Hello and terminate the worker at the named point with
//! exit status 3 and no ACK: after the case-root grant echo, after FileA is
//! created (before FileB exists), or after writing exactly the first mutation
//! byte. A violated partial-write premise is a typed Error refusal, never a
//! death.
//!
//! Grant: OWNER-2026-10-23 (user-owned donor slices to Apache-2.0).
//!
//! | Facet | Donor slice | Disposition |
//! |---|---|---|---|
//! | Exec epoch carry | P `src/process.rs:2205-2222` @ `2c2713e66292b0d2688508a25f79e813ae823d81` | ADAPT_ENV_CARRY: re-exec state (epoch/marker/slot) rides explicit env vars over an otherwise cleared environment, mirroring the donor re-exec helper's env-carried errno/target/start/token |
//!
//! Sibling spawn/handover, exec-attempt evidence, resume Hello and outage
//! triggers are NEW narrow fixture composition over accepted TT02, as the
//! TT03 contract authorizes; the wire codec already froze their record shapes.
#[cfg(not(target_os = "linux"))]
compile_error!("scopebase-tt03-worker is Linux-only");

use scopebase_testkit::fixture::linux::wire::{
    canonical_json, parse_canonical, parse_hello_control, sha256_of, validate_hello_request,
    Action, Actor, AdvanceReply, AdvanceRequest, Charges, CloseBody, CloseReason, Envelope,
    FdDirection, FdRole, FdTransferBody, FragmentPrefix, HelloControl, InputChunkAck, MessageKind,
    ProducerCharges, RawRecord, RawRequest, DATAGRAM_MAX, HEADER_BYTES, PAYLOAD_MAX,
};
use scopebase_testkit::fixture::linux::TRICKY_COMM;
use scopebase_testkit::fixture::linux::{control_pairing_applies, Scenario};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

const EXIT_USAGE: i32 = 2;
/// Control-triggered worker death: distinct from close (0), transport loss
/// (1) and usage (2), so the parent's retained wait status names the outage.
const EXIT_CONTROL_DEATH: i32 = 3;
/// Post-exec resume state, set only by this worker immediately before a real
/// execve. Value: `<epoch>:<marker>:<slot>`, e.g. `2:B:a`.
const RESUME_ENV: &str = "SCOPEBASE_TT03_RESUME";
/// Leaf the worker attempts (and must fail) to execute for `exec_missing`.
const MISSING_LEAF: &str = "missing-executable";

fn fail(message: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "tt03-worker: {message}");
    std::process::exit(EXIT_USAGE);
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

struct Blob {
    total: Option<u32>,
    digest: Option<[u8; 32]>,
    data: Vec<u8>,
}
impl Blob {
    fn empty() -> Self {
        Self {
            total: None,
            digest: None,
            data: Vec::new(),
        }
    }
    fn complete(&self) -> bool {
        match (self.total, self.digest) {
            (Some(total), Some(_)) => self.data.len() as u32 == total,
            _ => false,
        }
    }
}

enum PostReply {
    None,
    Exec {
        target: PathBuf,
        marker: &'static str,
    },
    Handover,
}

/// Armed outage trigger from the boot Hello control. Parent-side controls
/// are refused here; only worker death points arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArmedOutage {
    WorkerExitAfterRootGrant,
    WorkerExitAfterFileRegister,
    PartialFileWrite,
}

struct Worker {
    // SAFETY: fd 0 is the inherited protocol socket for the process lifetime.
    sock: rustix::fd::BorrowedFd<'static>,
    slot: Actor,
    marker: &'static str,
    invocation: serde_json::Value,
    manifest_sha: String,
    steps: Vec<String>,
    epoch: u32,
    next_record: u32,
    records: Vec<Vec<u8>>,
    blobs: [Blob; 3],
    case_root: Option<rustix::fd::OwnedFd>,
    file_a: Option<rustix::fd::OwnedFd>,
    file_b: Option<rustix::fd::OwnedFd>,
    charges: Charges,
    hello_done: bool,
    image_paths: [Option<PathBuf>; 2],
    sibling_tid: Option<u32>,
    sibling_handoff: Option<std::sync::mpsc::Sender<Worker>>,
    leader_exited: bool,
    resume_pending: bool,
    armed: Option<ArmedOutage>,
}

fn assert_worker_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Worker>();
}

/// Exact kernel thread id of the calling thread.
fn thread_tid() -> u32 {
    // SAFETY: gettid takes no arguments and always succeeds on Linux.
    unsafe { libc::gettid() as u32 }
}

/// Own-thread proc path: `/proc/self/<file>` follows the group leader, whose
/// mm is gone (ENOENT) once it is a zombie, so serving threads address their
/// own task entries. Identical bytes while single-threaded.
fn self_task_file(name: &str) -> String {
    format!("/proc/self/task/{}/{}", thread_tid(), name)
}

fn decode_hex_lower(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("path_hex must be lowercase hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "hex decode".to_string()))
        .collect()
}

fn parse_resume_env(value: &str, slot: Actor) -> Result<(u32, &'static str), String> {
    let mut parts = value.split(':');
    let (epoch_s, marker_s, slot_s) = match (parts.next(), parts.next(), parts.next(), parts.next())
    {
        (Some(e), Some(m), Some(s), None) => (e, m, s),
        _ => return Err("resume env must be <epoch>:<marker>:<slot>".to_string()),
    };
    let epoch: u32 = epoch_s
        .parse()
        .ok()
        .filter(|e| *e >= 2)
        .ok_or_else(|| "resume epoch must be >= 2".to_string())?;
    let marker = match marker_s {
        "A" => "A",
        "B" => "B",
        _ => return Err("resume marker must be A or B".to_string()),
    };
    if slot_s != slot.as_str() {
        return Err("resume slot differs from argv slot".to_string());
    }
    Ok((epoch, marker))
}

fn check_control(
    slot: Actor,
    scenario: Scenario,
    control: &HelloControl,
) -> Result<ArmedOutage, String> {
    if slot != Actor::A {
        return Err("outage controls are A-only".to_string());
    }
    if !control_pairing_applies(&control.kind, &control.step_id, &control.point, scenario) {
        return Err("control pairing is not applicable to this scenario".to_string());
    }
    match (control.kind.as_str(), control.point.as_str()) {
        ("worker_exit", "after_root_grant") => Ok(ArmedOutage::WorkerExitAfterRootGrant),
        ("worker_exit", "after_file_register") => Ok(ArmedOutage::WorkerExitAfterFileRegister),
        ("partial_file_write", "before_ack") => Ok(ArmedOutage::PartialFileWrite),
        _ => Err("control kind is parent-side and not servable by the worker".to_string()),
    }
}

fn term_disposition_default() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let mut masks = Vec::new();
    for line in status.lines() {
        for key in ["SigBlk:", "SigIgn:", "SigCgt:"] {
            if let Some(value) = line.strip_prefix(key) {
                masks.push(value.trim().to_string());
            }
        }
    }
    if masks.len() != 3 {
        return false;
    }
    masks.iter().all(|mask| {
        u64::from_str_radix(mask, 16)
            .map(|bits| bits & (1 << 14) == 0)
            .unwrap_or(false)
    })
}

impl Worker {
    fn send(
        &mut self,
        envelope: Envelope,
        payload: &[u8],
        fd: Option<&rustix::fd::OwnedFd>,
    ) -> std::io::Result<()> {
        self.charges.datagram_send_attempts += 1;
        let header = envelope.encode();
        let iov = [
            rustix::io::IoSlice::new(&header),
            rustix::io::IoSlice::new(payload),
        ];
        let sent = match fd {
            Some(pass) => {
                let borrowed = rustix::fd::AsFd::as_fd(pass);
                let send_fds = [borrowed];
                let mut space =
                    [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                let mut cbuf = rustix::net::SendAncillaryBuffer::new(&mut space);
                if !cbuf.push(rustix::net::SendAncillaryMessage::ScmRights(&send_fds)) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "ancillary space exhausted",
                    ));
                }
                rustix::net::sendmsg(&self.sock, &iov, &mut cbuf, rustix::net::SendFlags::empty())
            }
            None => {
                let mut space = [std::mem::MaybeUninit::uninit(); 0];
                let mut cbuf = rustix::net::SendAncillaryBuffer::new(&mut space);
                rustix::net::sendmsg(&self.sock, &iov, &mut cbuf, rustix::net::SendFlags::empty())
            }
        };
        let sent = sent?;
        if sent != HEADER_BYTES + payload.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short datagram send",
            ));
        }
        self.charges.datagrams_sent += 1;
        Ok(())
    }

    fn recv(&mut self) -> std::io::Result<(Envelope, Vec<u8>, Vec<rustix::fd::OwnedFd>)> {
        self.charges.datagram_receive_attempts += 1;
        let mut data = vec![0u8; DATAGRAM_MAX];
        let mut iov = [rustix::io::IoSliceMut::new(&mut data)];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut cbuf = rustix::net::RecvAncillaryBuffer::new(&mut space);
        let received = rustix::net::recvmsg(
            &self.sock,
            &mut iov,
            &mut cbuf,
            rustix::net::RecvFlags::CMSG_CLOEXEC,
        )?;
        if received.bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "parent closed the channel",
            ));
        }
        if received.flags.contains(rustix::net::ReturnFlags::TRUNC)
            || received.flags.contains(rustix::net::ReturnFlags::CTRUNC)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "truncated datagram",
            ));
        }
        if received.bytes < HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "datagram shorter than header",
            ));
        }
        let header: [u8; HEADER_BYTES] = data[..HEADER_BYTES].try_into().unwrap();
        let envelope = Envelope::decode(&header).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.detail().to_string())
        })?;
        if received.bytes != HEADER_BYTES + envelope.payload_len as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "payload length mismatch",
            ));
        }
        let mut fds = Vec::new();
        for message in cbuf.drain() {
            match message {
                rustix::net::RecvAncillaryMessage::ScmRights(rights) => fds.extend(rights),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unexpected ancillary kind",
                    ))
                }
            }
        }
        if fds.len() != envelope.fd_count as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fd cardinality mismatch",
            ));
        }
        self.charges.datagrams_received += 1;
        Ok((envelope, data[HEADER_BYTES..received.bytes].to_vec(), fds))
    }

    fn reply_envelope(
        &self,
        request: &Envelope,
        kind: MessageKind,
        payload_len: u32,
        fd_count: u16,
    ) -> Envelope {
        Envelope {
            kind,
            payload_len,
            fd_count,
            run_id: request.run_id,
            operation_id: request.operation_id,
            sequence: request.sequence,
            script_index: request.script_index,
        }
    }

    fn send_error(&mut self, request: &Envelope, step_id: &str, stage: &str, detail: &str) {
        let body = serde_json::json!({
            "category": "Other",
            "native_stage": stage,
            "errno": null,
            "call_result": null,
            "step_id": step_id,
            "completed_steps": 0,
            "diagnostic_hex": hex_bytes(&detail.as_bytes()[..detail.len().min(256)]),
            "reason": "Other",
            "limit_kind": null,
            "producer_charges": {
                "image_prefix": self.charges.to_json(),
                "handover_carry": null,
            },
        });
        let Ok(canonical) = canonical_json(&body) else {
            return;
        };
        let envelope = self.reply_envelope(request, MessageKind::Error, canonical.len() as u32, 0);
        let _ = self.send(envelope, canonical.as_bytes(), None);
    }

    fn task_record(&mut self, step_id: &str, sequence: u64, tid: u32) -> Result<Vec<u8>, String> {
        self.charges.native_attempts += 1;
        let pid = std::process::id();
        self.charges.native_successes += 1;
        let record = RawRecord {
            invocation: self.invocation.clone(),
            step_id: step_id.to_string(),
            record_index: self.next_record,
            sequence: Some(sequence),
            actor_slot: self.slot.as_str().to_string(),
            record_kind: "task".to_string(),
            source: "worker_kernel".to_string(),
            bytes_hex: None,
            values: serde_json::json!({
                "pid": pid,
                "tid": tid,
                "parent_slot": null,
                "self_link_hex": null,
                "thread_self_link_hex": null,
            }),
            call_result: None,
            errno: None,
            producer_charges: Some(ProducerCharges {
                image_prefix: self.charges,
                handover_carry: None,
            }),
        };
        let bytes = record.encode().map_err(|e| e.detail().to_string())?;
        self.charges.encoded_bytes += bytes.len() as u64;
        self.next_record += 1;
        Ok(bytes)
    }

    fn stat_record(&mut self, step_id: &str, sequence: u64) -> Result<Vec<u8>, String> {
        self.charges.native_attempts += 1;
        self.charges.read_attempts += 1;
        let stat = std::fs::read(self_task_file("stat")).map_err(|e| e.to_string())?;
        self.charges.native_successes += 1;
        self.charges.read_bytes += stat.len() as u64;
        let record = RawRecord {
            invocation: self.invocation.clone(),
            step_id: step_id.to_string(),
            record_index: self.next_record,
            sequence: Some(sequence),
            actor_slot: self.slot.as_str().to_string(),
            record_kind: "proc".to_string(),
            source: "worker_kernel".to_string(),
            bytes_hex: Some(hex_bytes(&stat)),
            values: serde_json::json!({
                "descriptor_slot": null,
                "file_name": "stat",
                "read_calls": "1",
                "bytes_read": stat.len().to_string(),
                "eof": true,
                "overflow_probe": false,
            }),
            call_result: None,
            errno: None,
            producer_charges: Some(ProducerCharges {
                image_prefix: self.charges,
                handover_carry: None,
            }),
        };
        let bytes = record.encode().map_err(|e| e.detail().to_string())?;
        self.charges.encoded_bytes += bytes.len() as u64;
        self.next_record += 1;
        Ok(bytes)
    }

    fn exec_record(
        &mut self,
        step_id: &str,
        sequence: u64,
        image_before: &str,
        image_after: &str,
        call_result: &str,
        errno: Option<i32>,
    ) -> Result<Vec<u8>, String> {
        self.charges.native_attempts += 1;
        let exe = std::fs::read(self_task_file("exe")).map_err(|e| e.to_string())?;
        let stat = std::fs::read(self_task_file("stat")).map_err(|e| e.to_string())?;
        self.charges.native_successes += 1;
        let (_, _, birth) =
            scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime(&stat)
                .map_err(|e| e.detail().to_string())?;
        let record = RawRecord {
            invocation: self.invocation.clone(),
            step_id: step_id.to_string(),
            record_index: self.next_record,
            sequence: Some(sequence),
            actor_slot: self.slot.as_str().to_string(),
            record_kind: "exec".to_string(),
            source: "worker_kernel".to_string(),
            bytes_hex: None,
            values: serde_json::json!({
                "image_before": image_before,
                "image_after": image_after,
                "executable_slot": self.slot.as_str(),
                "executable_sha256": hex_bytes(&sha256_of(&exe)),
                "birth_ticks": birth.to_string(),
            }),
            call_result: Some(call_result.to_string()),
            errno,
            producer_charges: Some(ProducerCharges {
                image_prefix: self.charges,
                handover_carry: None,
            }),
        };
        let bytes = record.encode().map_err(|e| e.detail().to_string())?;
        self.charges.encoded_bytes += bytes.len() as u64;
        self.next_record += 1;
        Ok(bytes)
    }

    fn serve_hello(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        let value = parse_canonical(payload, PAYLOAD_MAX).map_err(|e| e.detail().to_string())?;
        validate_hello_request(&value).map_err(|e| e.detail().to_string())?;
        let mode = value["mode"].as_str().unwrap_or("");
        match (mode, self.resume_pending) {
            ("boot", false) => {}
            ("resume", true) => {}
            ("boot", true) => {
                return Err("boot hello after exec state; resume required".to_string())
            }
            ("resume", false) => return Err("resume hello without post-exec state".to_string()),
            _ => return Err("hello mode must be boot or resume".to_string()),
        }
        if value["slot"] != self.slot.as_str() {
            return Err("hello slot mismatch".to_string());
        }
        if mode == "resume" && value["image_epoch"] != self.epoch {
            return Err("resume epoch differs from post-exec epoch".to_string());
        }
        let scenario = Scenario::parse(value["scenario"].as_str().unwrap_or(""))
            .ok_or_else(|| "hello scenario is not a closed scenario".to_string())?;
        let control = parse_hello_control(&value["control"]).map_err(|e| e.detail().to_string())?;
        match (mode, control) {
            ("boot", None) => self.armed = None,
            ("boot", Some(armed)) => {
                self.armed = Some(check_control(self.slot, scenario, &armed)?);
            }
            // Resume carries no control; an armed worker never survives to
            // exec, so boot-armed state simply persists across the barrier.
            ("resume", _) => {}
            _ => return Err("hello mode must be boot or resume".to_string()),
        }
        if !term_disposition_default() {
            return Err("SIGTERM disposition is not default/unblocked".to_string());
        }
        self.invocation = value["invocation"].clone();
        self.manifest_sha = value["manifest_sha256"].as_str().unwrap_or("").to_string();
        self.steps = value["steps"]
            .as_array()
            .map(|steps| {
                steps
                    .iter()
                    .map(|s| s["id"].as_str().unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default();
        let images = value["images"]
            .as_array()
            .ok_or("hello images must be an array")?;
        if images.len() != 2 {
            return Err("hello must carry exactly two images".to_string());
        }
        for (index, image) in images.iter().enumerate() {
            let path_hex = image["path_hex"]
                .as_str()
                .ok_or("image path_hex must be hex")?;
            let bytes = decode_hex_lower(path_hex)?;
            if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
                return Err("image path is not admittable".to_string());
            }
            self.image_paths[index] = Some(PathBuf::from(
                std::ffi::OsStr::from_bytes(&bytes).to_os_string(),
            ));
        }
        let pid = std::process::id();
        let tid = thread_tid();
        let reply = serde_json::json!({
            "schema_version": 1,
            "mode": mode,
            "slot": self.slot.as_str(),
            "manifest_sha256": self.manifest_sha,
            "image_marker": self.marker,
            "image_epoch": self.epoch,
            "pid": pid,
            "tid": tid,
            "inherited_fds": [0, 1, 2],
            "signal_profile": {"term_blocked": false, "term_disposition": "default"},
        });
        let canonical = canonical_json(&reply).map_err(|e| e.detail().to_string())?;
        let envelope =
            self.reply_envelope(request, MessageKind::HelloReply, canonical.len() as u32, 0);
        self.send(envelope, canonical.as_bytes(), None)
            .map_err(|e| e.to_string())?;
        self.hello_done = true;
        self.resume_pending = false;
        Ok(())
    }

    fn step_label(&self, script_index: u32) -> Result<String, String> {
        if script_index == 0 || script_index as usize > self.steps.len() {
            return Err("advance script index is outside the hello script".to_string());
        }
        Ok(self.steps[script_index as usize - 1].clone())
    }

    fn serve_advance(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        let decoded = AdvanceRequest::decode(payload).map_err(|e| e.detail().to_string())?;
        if decoded.actor != self.slot {
            return Err("advance actor mismatch".to_string());
        }
        if decoded.image_epoch != self.epoch {
            return Err("advance epoch mismatch".to_string());
        }
        let first = self.next_record;
        let made: u32;
        let reply_tid: u32;
        let post: PostReply;
        let step_hint = self.step_label(request.script_index)?;
        match decoded.action {
            Action::Ready => {
                if decoded.blob_mask != 0 {
                    return Err("ready takes no blob mask".to_string());
                }
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 1;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            Action::CaptureRaw => {
                if decoded.blob_mask != 0 {
                    return Err("capture takes no blob mask".to_string());
                }
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                let fresh = self.stat_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 2;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            Action::SetTrickyComm => {
                if decoded.blob_mask != 0 {
                    return Err("set_tricky_comm takes no blob mask".to_string());
                }
                std::fs::write("/proc/self/comm", TRICKY_COMM).map_err(|e| e.to_string())?;
                let stat = std::fs::read(self_task_file("stat")).map_err(|e| e.to_string())?;
                let (comm, _, _) =
                    scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime(&stat)
                        .map_err(|e| e.detail().to_string())?;
                if comm != TRICKY_COMM.as_bytes() {
                    return Err("comm did not take the tricky literal".to_string());
                }
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                let fresh = self.stat_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 2;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            Action::ExecB | Action::ExecA | Action::ExecFromSibling => {
                if decoded.blob_mask != 0 {
                    return Err("exec takes no blob mask".to_string());
                }
                let (target_index, marker): (usize, &'static str) = match decoded.action {
                    Action::ExecB => (1, "B"),
                    Action::ExecA => (0, "A"),
                    _ => (1, "B"),
                };
                if decoded.action == Action::ExecFromSibling && !self.leader_exited {
                    return Err("exec_from_sibling needs the leader-only exit first".to_string());
                }
                if decoded.action != Action::ExecFromSibling
                    && (self.sibling_tid.is_some() || self.leader_exited)
                {
                    return Err("plain exec refuses while sibling state is active".to_string());
                }
                let target = self.image_paths[target_index]
                    .clone()
                    .ok_or("exec needs hello-bound image paths")?;
                let metadata = std::fs::metadata(&target).map_err(|e| e.to_string())?;
                if !metadata.is_file() {
                    return Err("exec target is not a file".to_string());
                }
                self.charges.native_attempts += 1;
                self.charges.native_successes += 1;
                // No pre-exec record: the old image execs immediately after
                // this reply, so no drain could ever fetch one. The parent
                // authenticates the transition via the resume handshake plus
                // its own executable-digest witnesses.
                made = 0;
                reply_tid = thread_tid();
                post = PostReply::Exec { target, marker };
            }
            Action::ExecMissing => {
                if decoded.blob_mask != 0 {
                    return Err("exec_missing takes no blob mask".to_string());
                }
                let errno = self.attempt_missing_exec()?;
                let fresh = self.exec_record(
                    &step_hint,
                    request.sequence,
                    self.marker,
                    self.marker,
                    "failed",
                    Some(errno),
                )?;
                self.records.push(fresh);
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 2;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            Action::StartSibling => {
                if decoded.blob_mask != 0 {
                    return Err("start_sibling takes no blob mask".to_string());
                }
                let sibling = self.start_sibling()?;
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 1;
                reply_tid = sibling;
                post = PostReply::None;
            }
            Action::ExitLeader => {
                if decoded.blob_mask != 0 {
                    return Err("exit_leader takes no blob mask".to_string());
                }
                if self.sibling_tid.is_none() || self.sibling_handoff.is_none() {
                    return Err("exit_leader needs a live sibling".to_string());
                }
                let sibling = self.sibling_tid.unwrap();
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 1;
                reply_tid = sibling;
                post = PostReply::Handover;
            }
            Action::CreateFiles => {
                if decoded.blob_mask != 3 {
                    return Err("create_files needs blob mask 3".to_string());
                }
                self.create_files()?;
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 1;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            Action::ReplaceFileA => {
                if decoded.blob_mask != 0 {
                    return Err("replace takes no blob mask".to_string());
                }
                self.replace_file_a()?;
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 1;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            Action::UnlinkOriginalA => {
                if decoded.blob_mask != 0 {
                    return Err("unlink takes no blob mask".to_string());
                }
                self.unlink_original_a()?;
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 1;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            Action::MutateFileA => {
                if decoded.blob_mask != 4 {
                    return Err("mutate needs blob mask 4".to_string());
                }
                self.mutate_file_a()?;
                let fresh = self.task_record(&step_hint, request.sequence, thread_tid())?;
                self.records.push(fresh);
                made = 1;
                reply_tid = thread_tid();
                post = PostReply::None;
            }
            other => {
                return Err(format!("{} is a follow-up increment", other.as_str()));
            }
        }
        let pid = std::process::id();
        let reply = AdvanceReply {
            action: decoded.action,
            actor: self.slot,
            image_epoch: self.epoch,
            pid,
            tid: reply_tid,
            first_record: first,
            record_count: made,
            phase_flags: 0,
        };
        let encoded = reply.encode();
        let envelope =
            self.reply_envelope(request, MessageKind::AdvanceReply, encoded.len() as u32, 0);
        self.send(envelope, &encoded, None)
            .map_err(|e| e.to_string())?;
        match post {
            PostReply::None => Ok(()),
            PostReply::Exec { target, marker } => self.exec_into(target, marker),
            PostReply::Handover => self.handover_to_sibling(),
        }
    }

    /// Real failing exec: the missing case-root leaf is probed natively and
    /// then genuinely execve'd so the returned errno is the kernel's exec
    /// refusal, not a canned value. The leaf must stay absent; a present leaf
    /// refuses instead of executing an unexpected program.
    fn attempt_missing_exec(&mut self) -> Result<i32, String> {
        use std::os::unix::io::AsRawFd;
        let root = self
            .case_root
            .as_ref()
            .ok_or("exec_missing needs the case root")?;
        self.charges.native_attempts += 1;
        match rustix::fs::openat(
            root,
            MISSING_LEAF,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(_) => return Err("missing leaf unexpectedly present; refusing to exec".to_string()),
            Err(e) if e == rustix::io::Errno::NOENT => {}
            Err(e) => return Err(format!("missing-leaf probe failed: {e}")),
        }
        let fd_path = format!("/proc/self/fd/{}/{}", root.as_raw_fd(), MISSING_LEAF);
        let path = std::ffi::CString::new(fd_path).map_err(|e| e.to_string())?;
        let arg0 = std::ffi::CString::new("missing").map_err(|e| e.to_string())?;
        let argv = [arg0.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        self.charges.native_attempts += 1;
        // SAFETY: execve with valid pointers; it returns only on failure.
        let rc = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        if rc == 0 {
            return Err("execve of the missing leaf unexpectedly succeeded".to_string());
        }
        // SAFETY: errno read immediately on the failing thread.
        let errno = unsafe { *libc::__errno_location() };
        self.charges.native_successes += 1;
        Ok(errno)
    }

    /// Real image exec: carries epoch/marker/slot over the cleared
    /// environment, then execve's the hello-bound target with the fixed boot
    /// argv. Success never returns; failure clears the carry so the stale
    /// resume state cannot be mistaken for a post-exec barrier.
    fn exec_into(&mut self, target: PathBuf, marker: &'static str) -> Result<(), String> {
        let epoch = self.epoch.checked_add(1).ok_or("epoch overflow")?;
        std::env::set_var(
            RESUME_ENV,
            format!("{epoch}:{marker}:{}", self.slot.as_str()),
        );
        let argv0 =
            std::ffi::CString::new(target.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let a1 = std::ffi::CString::new("--scopebase-fixture-v1").unwrap();
        let a2 = std::ffi::CString::new("--slot").unwrap();
        let a3 = std::ffi::CString::new(self.slot.as_str()).unwrap();
        let a4 = std::ffi::CString::new("--handover").unwrap();
        let a5 = std::ffi::CString::new("-").unwrap();
        let argv = [
            argv0.as_ptr(),
            a1.as_ptr(),
            a2.as_ptr(),
            a3.as_ptr(),
            a4.as_ptr(),
            a5.as_ptr(),
            std::ptr::null(),
        ];
        let carry = std::ffi::CString::new(format!(
            "{RESUME_ENV}={epoch}:{marker}:{}",
            self.slot.as_str()
        ))
        .map_err(|e| e.to_string())?;
        let envp = [carry.as_ptr(), std::ptr::null()];
        self.charges.native_attempts += 1;
        // SAFETY: execve with valid pointers; success never returns.
        unsafe { libc::execve(argv0.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        // SAFETY: errno read immediately on the failing thread.
        let errno = unsafe { *libc::__errno_location() };
        std::env::remove_var(RESUME_ENV);
        Err(format!(
            "execve of image {marker} failed with errno {errno}"
        ))
    }

    /// Real sibling spawn: a second OS thread reports its kernel TID and then
    /// parks for the leader-exit handover. Refused once sibling state exists.
    fn start_sibling(&mut self) -> Result<u32, String> {
        if self.sibling_tid.is_some() || self.leader_exited {
            return Err("sibling already started or leader exited".to_string());
        }
        let (tid_tx, tid_rx) = std::sync::mpsc::channel::<u32>();
        let (handoff_tx, handoff_rx) = std::sync::mpsc::channel::<Worker>();
        std::thread::Builder::new()
            .name("tt03-sibling".to_string())
            .spawn(move || {
                let tid = thread_tid();
                if tid_tx.send(tid).is_err() {
                    std::process::exit(1);
                }
                match handoff_rx.recv() {
                    Ok(mut worker) => serve_forever(&mut worker),
                    Err(_) => std::process::exit(1),
                }
            })
            .map_err(|e| e.to_string())?;
        let tid = tid_rx.recv().map_err(|e| e.to_string())?;
        if tid == thread_tid() {
            return Err("sibling TID equals the leader TID".to_string());
        }
        self.charges.native_attempts += 1;
        self.charges.native_successes += 1;
        self.sibling_tid = Some(tid);
        self.sibling_handoff = Some(handoff_tx);
        Ok(tid)
    }

    /// Leader-only native exit: the pre-handover reply is already on the
    /// wire; the whole service state moves to the parked sibling and the
    /// calling (leader) thread exits natively while the process survives.
    /// The exit is the raw thread-exit syscall, not `pthread_exit`: forced
    /// unwinding through Rust frames aborts (nounwind boundary since Rust
    /// 1.81; `C-unwind` dies with libgcc "exception not rethrown"), while the
    /// raw exit ends exactly this task with no locks held. The leader task
    /// remains visible as a zombie (state Z) until process exit; the kernel
    /// keeps the tgid pinned to it. Verified by probe 2026-10-23.
    fn handover_to_sibling(&mut self) -> Result<(), String> {
        let handoff = self
            .sibling_handoff
            .take()
            .ok_or("handover needs a parked sibling")?;
        // SAFETY: fd 0 is the inherited protocol socket for the process lifetime.
        let sock: rustix::fd::BorrowedFd<'static> =
            unsafe { rustix::fd::BorrowedFd::borrow_raw(0) };
        let mut tombstone = Worker {
            sock,
            slot: self.slot,
            marker: self.marker,
            invocation: serde_json::Value::Null,
            manifest_sha: String::new(),
            steps: Vec::new(),
            epoch: self.epoch,
            next_record: 1,
            records: Vec::new(),
            blobs: [Blob::empty(), Blob::empty(), Blob::empty()],
            case_root: None,
            file_a: None,
            file_b: None,
            charges: Charges::default(),
            hello_done: false,
            image_paths: [None, None],
            sibling_tid: None,
            sibling_handoff: None,
            leader_exited: true,
            resume_pending: false,
            armed: None,
        };
        std::mem::swap(self, &mut tombstone);
        tombstone.leader_exited = true;
        handoff.send(tombstone).map_err(|e| e.to_string())?;
        // SAFETY: the raw thread-exit syscall ends only the calling task;
        // no lock is held here (the handoff send completed) and no
        // thread-local destructor is required. It diverges.
        unsafe { libc::syscall(libc::SYS_exit, 0) };
        unreachable!("raw thread exit never returns")
    }

    fn create_files(&mut self) -> Result<(), String> {
        let root = self
            .case_root
            .as_ref()
            .ok_or("create needs the case root")?;
        for (index, leaf) in [(0usize, "a"), (1, "b")] {
            let blob = &self.blobs[index];
            if !blob.complete() {
                return Err("create needs complete blobs".to_string());
            }
            let bytes = blob.data.clone();
            self.charges.native_attempts += 1;
            let fd = rustix::fs::openat(
                root,
                leaf,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_bits_truncate(0o600),
            )
            .map_err(|e| e.to_string())?;
            self.charges.native_successes += 1;
            let mut file: std::fs::File = fd.try_clone().map_err(|e| e.to_string())?.into();
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            self.charges.file_work_bytes += bytes.len() as u64;
            use std::os::unix::fs::FileExt;
            let mut back = vec![0u8; bytes.len()];
            file.read_exact_at(&mut back, 0)
                .map_err(|e| e.to_string())?;
            if back != bytes {
                return Err("create readback mismatch".to_string());
            }
            if index == 0 {
                self.file_a = Some(fd);
                // worker_exit/after_file_register: FileA is registered
                // first; the worker dies here, before FileB exists, with
                // no ACK.
                if self.armed == Some(ArmedOutage::WorkerExitAfterFileRegister) {
                    std::process::exit(EXIT_CONTROL_DEATH);
                }
            } else {
                self.file_b = Some(fd);
            }
        }
        Ok(())
    }

    fn replace_file_a(&mut self) -> Result<(), String> {
        let root = self
            .case_root
            .as_ref()
            .ok_or("replace needs the case root")?;
        self.charges.native_attempts += 2;
        rustix::fs::renameat(root, "a", root, "a-original").map_err(|e| e.to_string())?;
        rustix::fs::renameat(root, "b", root, "a").map_err(|e| e.to_string())?;
        self.charges.native_successes += 2;
        Ok(())
    }

    fn unlink_original_a(&mut self) -> Result<(), String> {
        let root = self
            .case_root
            .as_ref()
            .ok_or("unlink needs the case root")?;
        self.charges.native_attempts += 1;
        rustix::fs::unlinkat(root, "a-original", rustix::fs::AtFlags::empty())
            .map_err(|e| e.to_string())?;
        self.charges.native_successes += 1;
        Ok(())
    }

    /// One-byte partial write: the contract premise (file and mutation
    /// share length >= 2; bytes 0 and 1 each differ) is verified natively,
    /// then exactly the first mutation byte lands at offset 0 and the worker
    /// exits with no ACK. A violated premise is a typed refusal, never a
    /// death, and the worker stays alive to refuse again.
    fn partial_file_write(&mut self) -> Result<(), String> {
        let mutation = self.blobs[2].data.clone();
        if !self.blobs[2].complete() {
            return Err("partial write needs the complete mutation blob".to_string());
        }
        let file_a = self.file_a.as_ref().ok_or("partial write needs file A")?;
        let size = rustix::fs::fstat(file_a)
            .map_err(|e| e.to_string())?
            .st_size as usize;
        if mutation.len() != size || size < 2 {
            return Err(
                "partial-write premise unsatisfied: file and mutation must share length >= 2"
                    .to_string(),
            );
        }
        let dup: rustix::fd::OwnedFd = file_a.try_clone().map_err(|e| e.to_string())?;
        let file: std::fs::File = dup.into();
        use std::os::unix::fs::FileExt;
        let mut current = [0u8; 2];
        file.read_exact_at(&mut current, 0)
            .map_err(|e| e.to_string())?;
        if current[0] == mutation[0] || current[1] == mutation[1] {
            return Err(
                "partial-write premise unsatisfied: bytes 0 and 1 must each differ".to_string(),
            );
        }
        self.charges.native_attempts += 1;
        file.write_all_at(&mutation[..1], 0)
            .map_err(|e| e.to_string())?;
        self.charges.file_work_bytes += 1;
        std::process::exit(EXIT_CONTROL_DEATH);
    }

    fn mutate_file_a(&mut self) -> Result<(), String> {
        if self.armed == Some(ArmedOutage::PartialFileWrite) {
            return self.partial_file_write();
        }
        let mutation = self.blobs[2].data.clone();
        if !self.blobs[2].complete() {
            return Err("mutate needs the complete mutation blob".to_string());
        }
        let file_a = self.file_a.as_ref().ok_or("mutate needs file A")?;
        let size = rustix::fs::fstat(file_a)
            .map_err(|e| e.to_string())?
            .st_size as usize;
        if mutation.len() != size {
            return Err("mutation must equal file A length".to_string());
        }
        let dup: rustix::fd::OwnedFd = file_a.try_clone().map_err(|e| e.to_string())?;
        let file: std::fs::File = dup.into();
        use std::os::unix::fs::FileExt;
        file.write_all_at(&mutation, 0).map_err(|e| e.to_string())?;
        self.charges.file_work_bytes += mutation.len() as u64;
        let mut back = vec![0u8; mutation.len()];
        file.read_exact_at(&mut back, 0)
            .map_err(|e| e.to_string())?;
        if back != mutation {
            return Err("mutate readback mismatch".to_string());
        }
        Ok(())
    }

    fn serve_raw(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        let decoded = RawRequest::decode(payload).map_err(|e| e.detail().to_string())?;
        let record = self
            .records
            .get(decoded.record_index as usize - 1)
            .ok_or("unknown record index")?;
        if decoded.offset as usize > record.len() {
            return Err("fragment offset outside record".to_string());
        }
        let end = (decoded.offset as usize + decoded.max_chunk_bytes as usize).min(record.len());
        let chunk = &record[decoded.offset as usize..end];
        let prefix = FragmentPrefix {
            index: decoded.record_index,
            total_bytes: record.len() as u32,
            offset: decoded.offset,
            chunk_bytes: chunk.len() as u32,
            whole_sha256: sha256_of(record),
        };
        let mut body = prefix.encode().to_vec();
        body.extend_from_slice(chunk);
        let envelope = self.reply_envelope(request, MessageKind::RawReply, body.len() as u32, 0);
        self.send(envelope, &body, None).map_err(|e| e.to_string())
    }

    fn serve_chunk(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        if payload.len() < 48 {
            return Err("chunk shorter than prefix".to_string());
        }
        let prefix = FragmentPrefix::decode(&payload[..48]).map_err(|e| e.detail().to_string())?;
        if prefix.index < 1 || prefix.index > 3 {
            return Err("chunk blob index outside 1..3".to_string());
        }
        if prefix.chunk_bytes as usize != payload.len() - 48 {
            return Err("chunk length mismatch".to_string());
        }
        if prefix.total_bytes as usize > 65536 {
            return Err("blob exceeds file byte ceiling".to_string());
        }
        let blob = &mut self.blobs[prefix.index as usize - 1];
        match blob.total {
            None => {
                blob.total = Some(prefix.total_bytes);
                blob.digest = Some(prefix.whole_sha256);
            }
            Some(total)
                if total == prefix.total_bytes && blob.digest == Some(prefix.whole_sha256) => {}
            _ => return Err("chunk contradicts declared blob".to_string()),
        }
        if prefix.offset as usize != blob.data.len() {
            return Err("chunk offset is not contiguous".to_string());
        }
        blob.data.extend_from_slice(&payload[48..]);
        if blob.data.len() as u32 == prefix.total_bytes {
            if sha256_of(&blob.data) != prefix.whole_sha256 {
                return Err("blob digest mismatch".to_string());
            }
        }
        self.charges.file_work_bytes += prefix.chunk_bytes as u64;
        let ack = InputChunkAck {
            blob_index: prefix.index,
            total_bytes: prefix.total_bytes,
            next_offset: blob.data.len() as u32,
        };
        let encoded = ack.encode();
        let envelope =
            self.reply_envelope(request, MessageKind::InputChunkAck, encoded.len() as u32, 0);
        self.send(envelope, &encoded, None)
            .map_err(|e| e.to_string())
    }

    fn serve_fd(
        &mut self,
        request: &Envelope,
        payload: &[u8],
        fds: Vec<rustix::fd::OwnedFd>,
    ) -> Result<(), String> {
        let body = FdTransferBody::decode(payload).map_err(|e| e.detail().to_string())?;
        if body.image_epoch != self.epoch {
            return Err("fd transfer epoch mismatch".to_string());
        }
        match (body.direction, body.role) {
            (FdDirection::Push, FdRole::CaseRoot) => {
                if body.grant_id != self.epoch || fds.len() != 1 {
                    return Err("case root grant shape".to_string());
                }
                let mut fds = fds;
                self.case_root = Some(fds.pop().unwrap());
                let encoded = body.encode();
                let envelope = self.reply_envelope(
                    request,
                    MessageKind::FdTransferReply,
                    encoded.len() as u32,
                    0,
                );
                self.send(envelope, &encoded, None)
                    .map_err(|e| e.to_string())?;
                if self.armed == Some(ArmedOutage::WorkerExitAfterRootGrant) {
                    std::process::exit(EXIT_CONTROL_DEATH);
                }
                Ok(())
            }
            (FdDirection::Pull, FdRole::FileA) | (FdDirection::Pull, FdRole::FileB) => {
                if !fds.is_empty() {
                    return Err("pull request carries no descriptor".to_string());
                }
                let expect_grant = if body.role == FdRole::FileA { 4 } else { 5 };
                if body.grant_id != expect_grant {
                    return Err("pull grant id mismatch".to_string());
                }
                let file = if body.role == FdRole::FileA {
                    self.file_a.as_ref()
                } else {
                    self.file_b.as_ref()
                }
                .ok_or("pull needs a created file")?;
                let pass: rustix::fd::OwnedFd = file.try_clone().map_err(|e| e.to_string())?;
                let encoded = body.encode();
                let envelope = self.reply_envelope(
                    request,
                    MessageKind::FdTransferReply,
                    encoded.len() as u32,
                    1,
                );
                self.send(envelope, &encoded, Some(&pass))
                    .map_err(|e| e.to_string())
            }
            _ => Err("fd direction and role pair refused".to_string()),
        }
    }

    fn serve_close(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        let body = CloseBody::decode(payload).map_err(|e| e.detail().to_string())?;
        if body.actor != self.slot || body.image_epoch != self.epoch {
            return Err("close identity mismatch".to_string());
        }
        if body.reason != CloseReason::Normal {
            return Err("only normal close in this increment".to_string());
        }
        let encoded = body.encode();
        let envelope =
            self.reply_envelope(request, MessageKind::CloseReply, encoded.len() as u32, 0);
        self.send(envelope, &encoded, None)
            .map_err(|e| e.to_string())?;
        std::process::exit(0);
    }

    fn serve_one(&mut self, request: Envelope, payload: Vec<u8>, fds: Vec<rustix::fd::OwnedFd>) {
        if request.kind != MessageKind::HelloRequest && !self.hello_done {
            self.send_error(&request, "s01-ready", "Ready", "hello comes first");
            return;
        }
        let outcome = match request.kind {
            MessageKind::HelloRequest => self.serve_hello(&request, &payload),
            MessageKind::AdvanceRequest => self.serve_advance(&request, &payload),
            MessageKind::RawRequest => self.serve_raw(&request, &payload),
            MessageKind::InputChunkRequest => self.serve_chunk(&request, &payload),
            MessageKind::FdTransferRequest => self.serve_fd(&request, &payload, fds),
            MessageKind::CloseRequest => self.serve_close(&request, &payload),
            _ => Err("message kind is not servable here".to_string()),
        };
        if let Err(detail) = outcome {
            self.send_error(&request, "s01-ready", "Advance", &detail);
        }
    }
}

fn serve_forever(worker: &mut Worker) -> ! {
    loop {
        match worker.recv() {
            Ok((request, payload, fds)) => worker.serve_one(request, payload, fds),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => std::process::exit(1),
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "tt03-worker transport: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    assert_worker_send();
    // R03: non-UTF-8 argv refuses with usage, never panics in args().
    let argv = match scopebase_testkit::cli::argv_strings() {
        Some(argv) => argv,
        None => fail("argv is not valid Unicode"),
    };
    if argv.len() != 6
        || argv[1] != "--scopebase-fixture-v1"
        || argv[2] != "--slot"
        || argv[4] != "--handover"
        || argv[5] != "-"
    {
        fail("usage: worker --scopebase-fixture-v1 --slot a|b --handover -");
    }
    let (slot, boot_marker) = match argv[3].as_str() {
        "a" => (Actor::A, "A"),
        "b" => (Actor::B, "B"),
        _ => fail("slot must be a or b in this increment"),
    };
    let (epoch, marker, resume_pending) = match std::env::var(RESUME_ENV) {
        Ok(value) => {
            let (epoch, marker) = parse_resume_env(&value, slot).unwrap_or_else(|d| fail(&d));
            std::env::remove_var(RESUME_ENV);
            (epoch, marker, true)
        }
        Err(_) => (1, boot_marker, false),
    };
    // SAFETY: fd 0 is the inherited protocol socket; it is never closed here.
    let sock: rustix::fd::BorrowedFd<'static> = unsafe { rustix::fd::BorrowedFd::borrow_raw(0) };
    let mut worker = Worker {
        sock,
        slot,
        marker,
        invocation: serde_json::Value::Null,
        manifest_sha: String::new(),
        steps: Vec::new(),
        epoch,
        next_record: 1,
        records: Vec::new(),
        blobs: [Blob::empty(), Blob::empty(), Blob::empty()],
        case_root: None,
        file_a: None,
        file_b: None,
        charges: Charges::default(),
        hello_done: false,
        image_paths: [None, None],
        sibling_tid: None,
        sibling_handoff: None,
        leader_exited: false,
        resume_pending,
        armed: None,
    };
    serve_forever(&mut worker);
}
