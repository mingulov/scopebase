// SPDX-License-Identifier: Apache-2.0
//! TT03 standalone fixture worker: serves one protocol channel on fd 0.
//!
//! Fixed argv: `[image, --scopebase-fixture-v1, --slot, a|b, --handover, -]`.
//! First increment serves boot Hello, ready, capture_raw, set_tricky_comm
//! (via /proc/self/comm), blob upload, file create/offer/pull, replace,
//! unlink, mutate and close. Exec, sibling, inventory and resume Hello are
//! refused with typed Error replies; the parent owns all exits and reaps.
#[cfg(not(target_os = "linux"))]
compile_error!("scopebase-tt03-worker is Linux-only");

use scopebase_testkit::fixture::linux::TRICKY_COMM;
use scopebase_testkit::fixture::linux::wire::{
    canonical_json, parse_canonical, sha256_of, validate_hello_request, Action, Actor,
    AdvanceReply, AdvanceRequest, Charges, CloseBody, CloseReason, Envelope, FdDirection,
    FdRole, FdTransferBody, FragmentPrefix, InputChunkAck, MessageKind, ProducerCharges, RawRecord,
    RawRequest, DATAGRAM_MAX, HEADER_BYTES, PAYLOAD_MAX,
};
use std::io::Write;

const EXIT_USAGE: i32 = 2;

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
}

fn current_tid() -> std::io::Result<u32> {
    let mut tids = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task")? {
        let name = entry?.file_name();
        if let Some(tid) = name.to_string_lossy().parse::<u32>().ok() {
            tids.push(tid);
        }
    }
    tids.into_iter().next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no task entry")
    })
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
        u64::from_str_radix(mask, 16).map(|bits| bits & (1 << 14) == 0).unwrap_or(false)
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
        let envelope =
            Envelope::decode(&header).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.detail().to_string()))?;
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

    fn reply_envelope(&self, request: &Envelope, kind: MessageKind, payload_len: u32, fd_count: u16) -> Envelope {
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

    fn task_record(&mut self, step_id: &str, sequence: u64) -> Result<Vec<u8>, String> {
        self.charges.native_attempts += 1;
        let pid = std::process::id();
        let tid = current_tid().map_err(|e| e.to_string())?;
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
        let stat = std::fs::read("/proc/self/stat").map_err(|e| e.to_string())?;
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

    fn serve_hello(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        let value = parse_canonical(payload, PAYLOAD_MAX).map_err(|e| e.detail().to_string())?;
        validate_hello_request(&value).map_err(|e| e.detail().to_string())?;
        if value["mode"] != "boot" {
            return Err("resume hello is a follow-up increment".to_string());
        }
        if value["slot"] != self.slot.as_str() {
            return Err("hello slot mismatch".to_string());
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
        let pid = std::process::id();
        let tid = current_tid().map_err(|e| e.to_string())?;
        let reply = serde_json::json!({
            "schema_version": 1,
            "mode": "boot",
            "slot": self.slot.as_str(),
            "manifest_sha256": self.manifest_sha,
            "image_marker": self.marker,
            "image_epoch": 1,
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
        Ok(())
    }

    fn step_label(&self, script_index: u32) -> Result<String, String> {
        if script_index == 0 || script_index as usize > self.steps.len() {
            return Err("advance script index is outside the hello script".to_string());
        }
        Ok(self.steps[script_index as usize - 1].clone())
    }

    fn serve_advance(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        let decoded =
            AdvanceRequest::decode(payload).map_err(|e| e.detail().to_string())?;
        if decoded.actor != self.slot {
            return Err("advance actor mismatch".to_string());
        }
        if decoded.image_epoch != self.epoch {
            return Err("advance epoch mismatch".to_string());
        }
        let first = self.next_record;
        let made: u32;
        let step_hint = self.step_label(request.script_index)?;
        match decoded.action {
            Action::Ready => {
                if decoded.blob_mask != 0 {
                    return Err("ready takes no blob mask".to_string());
                }
                let fresh = self.task_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 1;
            }
            Action::CaptureRaw => {
                if decoded.blob_mask != 0 {
                    return Err("capture takes no blob mask".to_string());
                }
                let fresh = self.task_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                let fresh = self.stat_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 2;
            }
            Action::SetTrickyComm => {
                if decoded.blob_mask != 0 {
                    return Err("set_tricky_comm takes no blob mask".to_string());
                }
                std::fs::write("/proc/self/comm", TRICKY_COMM).map_err(|e| e.to_string())?;
                let stat = std::fs::read("/proc/self/stat").map_err(|e| e.to_string())?;
                let (comm, _, _) =
                    scopebase_testkit::fixture::linux::parse_stat_comm_state_starttime(&stat)
                        .map_err(|e| e.detail().to_string())?;
                if comm != TRICKY_COMM.as_bytes() {
                    return Err("comm did not take the tricky literal".to_string());
                }
                let fresh = self.task_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                let fresh = self.stat_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 2;
            }
            Action::CreateFiles => {
                if decoded.blob_mask != 3 {
                    return Err("create_files needs blob mask 3".to_string());
                }
                self.create_files()?;
                let fresh = self.task_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 1;
            }
            Action::ReplaceFileA => {
                if decoded.blob_mask != 0 {
                    return Err("replace takes no blob mask".to_string());
                }
                self.replace_file_a()?;
                let fresh = self.task_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 1;
            }
            Action::UnlinkOriginalA => {
                if decoded.blob_mask != 0 {
                    return Err("unlink takes no blob mask".to_string());
                }
                self.unlink_original_a()?;
                let fresh = self.task_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 1;
            }
            Action::MutateFileA => {
                if decoded.blob_mask != 4 {
                    return Err("mutate needs blob mask 4".to_string());
                }
                self.mutate_file_a()?;
                let fresh = self.task_record(&step_hint, request.sequence)?;
                self.records.push(fresh);
                made = 1;
            }
            other => {
                return Err(format!("{} is a follow-up increment", other.as_str()));
            }
        }
        let pid = std::process::id();
        let tid = current_tid().map_err(|e| e.to_string())?;
        let reply = AdvanceReply {
            action: decoded.action,
            actor: self.slot,
            image_epoch: self.epoch,
            pid,
            tid,
            first_record: first,
            record_count: made,
            phase_flags: 0,
        };
        let encoded = reply.encode();
        let envelope =
            self.reply_envelope(request, MessageKind::AdvanceReply, encoded.len() as u32, 0);
        self.send(envelope, &encoded, None).map_err(|e| e.to_string())
    }

    fn create_files(&mut self) -> Result<(), String> {
        let root = self.case_root.as_ref().ok_or("create needs the case root")?;
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
            file.read_exact_at(&mut back, 0).map_err(|e| e.to_string())?;
            if back != bytes {
                return Err("create readback mismatch".to_string());
            }
            if index == 0 {
                self.file_a = Some(fd);
            } else {
                self.file_b = Some(fd);
            }
        }
        Ok(())
    }

    fn replace_file_a(&mut self) -> Result<(), String> {
        let root = self.case_root.as_ref().ok_or("replace needs the case root")?;
        self.charges.native_attempts += 2;
        rustix::fs::renameat(root, "a", root, "a-original").map_err(|e| e.to_string())?;
        rustix::fs::renameat(root, "b", root, "a").map_err(|e| e.to_string())?;
        self.charges.native_successes += 2;
        Ok(())
    }

    fn unlink_original_a(&mut self) -> Result<(), String> {
        let root = self.case_root.as_ref().ok_or("unlink needs the case root")?;
        self.charges.native_attempts += 1;
        rustix::fs::unlinkat(root, "a-original", rustix::fs::AtFlags::empty())
            .map_err(|e| e.to_string())?;
        self.charges.native_successes += 1;
        Ok(())
    }

    fn mutate_file_a(&mut self) -> Result<(), String> {
        let mutation = self.blobs[2].data.clone();
        if !self.blobs[2].complete() {
            return Err("mutate needs the complete mutation blob".to_string());
        }
        let file_a = self.file_a.as_ref().ok_or("mutate needs file A")?;
        let size = rustix::fs::fstat(file_a).map_err(|e| e.to_string())?.st_size as usize;
        if mutation.len() != size {
            return Err("mutation must equal file A length".to_string());
        }
        let dup: rustix::fd::OwnedFd =
            file_a.try_clone().map_err(|e| e.to_string())?;
        let file: std::fs::File = dup.into();
        use std::os::unix::fs::FileExt;
        file.write_all_at(&mutation, 0).map_err(|e| e.to_string())?;
        self.charges.file_work_bytes += mutation.len() as u64;
        let mut back = vec![0u8; mutation.len()];
        file.read_exact_at(&mut back, 0).map_err(|e| e.to_string())?;
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
        let end =
            (decoded.offset as usize + decoded.max_chunk_bytes as usize).min(record.len());
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
        let envelope =
            self.reply_envelope(request, MessageKind::RawReply, body.len() as u32, 0);
        self.send(envelope, &body, None).map_err(|e| e.to_string())
    }

    fn serve_chunk(&mut self, request: &Envelope, payload: &[u8]) -> Result<(), String> {
        if payload.len() < 48 {
            return Err("chunk shorter than prefix".to_string());
        }
        let prefix =
            FragmentPrefix::decode(&payload[..48]).map_err(|e| e.detail().to_string())?;
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
            Some(total) if total == prefix.total_bytes && blob.digest == Some(prefix.whole_sha256) => {}
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
        self.send(envelope, &encoded, None).map_err(|e| e.to_string())
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
                self.send(envelope, &encoded, None).map_err(|e| e.to_string())
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
                let pass: rustix::fd::OwnedFd =
                    file.try_clone().map_err(|e| e.to_string())?;
                let encoded = body.encode();
                let envelope = self.reply_envelope(
                    request,
                    MessageKind::FdTransferReply,
                    encoded.len() as u32,
                    1,
                );
                self.send(envelope, &encoded, Some(&pass)).map_err(|e| e.to_string())
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
        self.send(envelope, &encoded, None).map_err(|e| e.to_string())?;
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

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() != 6
        || argv[1] != "--scopebase-fixture-v1"
        || argv[2] != "--slot"
        || argv[4] != "--handover"
        || argv[5] != "-"
    {
        fail("usage: worker --scopebase-fixture-v1 --slot a|b --handover -");
    }
    let (slot, marker) = match argv[3].as_str() {
        "a" => (Actor::A, "A"),
        "b" => (Actor::B, "B"),
        _ => fail("slot must be a or b in this increment"),
    };
    // SAFETY: fd 0 is the inherited protocol socket; it is never closed here.
    let sock: rustix::fd::BorrowedFd<'static> =
        unsafe { rustix::fd::BorrowedFd::borrow_raw(0) };
    let mut worker = Worker {
        sock,
        slot,
        marker,
        invocation: serde_json::Value::Null,
        manifest_sha: String::new(),
        steps: Vec::new(),
        epoch: 1,
        next_record: 1,
        records: Vec::new(),
        blobs: [Blob::empty(), Blob::empty(), Blob::empty()],
        case_root: None,
        file_a: None,
        file_b: None,
        charges: Charges::default(),
        hello_done: false,
    };
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
