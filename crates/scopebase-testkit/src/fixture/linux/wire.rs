// SPDX-License-Identifier: Apache-2.0
//! TT03 closed core protocol codec: the sole framing/JSON implementation
//! shared by the packaged worker and the parent driver.
//!
//! Normative: `protocol.md`, `contract-data.json`, `schema-contract.json`.
//! All integers little-endian; JSON canonical per protocol.md (sorted keys,
//! no whitespace, lowercase `\u00xx` for every U+0000..U+001F).
use std::fmt;

pub const MAGIC: &[u8; 8] = b"SBFIX001";
pub const HEADER_BYTES: usize = 64;
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const PAYLOAD_MAX: usize = 65536;
pub const DATAGRAM_MAX: usize = HEADER_BYTES + PAYLOAD_MAX;
pub const CHUNK_MAX: usize = 65488;
pub const FRAGMENT_PREFIX_BYTES: usize = 48;
pub const EXEC_HANDOVER_MAGIC: &[u8; 8] = b"SBFH0001";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireError {
    detail: String,
}
impl WireError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}
impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire: {}", self.detail)
    }
}
impl std::error::Error for WireError {}

pub fn is_lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

pub fn run_id_from_hex(hex: &str) -> Result<[u8; 16], WireError> {
    let b = hex.as_bytes();
    if b.len() != 32 || !is_lower_hex(b) {
        return Err(WireError::new("run_id must be 32 lowercase hex"));
    }
    let mut out = [0u8; 16];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
        out[i] = hi << 4 | lo;
    }
    Ok(out)
}

pub fn run_id_to_hex(run_id: &[u8; 16]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for b in run_id {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    HelloRequest = 1,
    HelloReply = 2,
    AdvanceRequest = 3,
    AdvanceReply = 4,
    RawRequest = 5,
    RawReply = 6,
    FdTransferRequest = 7,
    FdTransferReply = 8,
    CloseRequest = 9,
    CloseReply = 10,
    Error = 11,
    InputChunkRequest = 12,
    InputChunkAck = 13,
    InventoryRequest = 14,
    InventoryReply = 15,
}
impl MessageKind {
    pub fn code(self) -> u16 {
        self as u16
    }
    pub fn parse(code: u16) -> Result<Self, WireError> {
        Ok(match code {
            1 => Self::HelloRequest,
            2 => Self::HelloReply,
            3 => Self::AdvanceRequest,
            4 => Self::AdvanceReply,
            5 => Self::RawRequest,
            6 => Self::RawReply,
            7 => Self::FdTransferRequest,
            8 => Self::FdTransferReply,
            9 => Self::CloseRequest,
            10 => Self::CloseReply,
            11 => Self::Error,
            12 => Self::InputChunkRequest,
            13 => Self::InputChunkAck,
            14 => Self::InventoryRequest,
            15 => Self::InventoryReply,
            _ => return Err(WireError::new("unknown message kind")),
        })
    }
    pub fn fixed_body_bytes(self) -> Option<usize> {
        match self {
            Self::AdvanceRequest => Some(16),
            Self::AdvanceReply => Some(32),
            Self::RawRequest => Some(16),
            Self::FdTransferRequest | Self::FdTransferReply => Some(16),
            Self::CloseRequest | Self::CloseReply => Some(16),
            Self::InputChunkAck => Some(16),
            Self::InventoryReply => Some(16),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Ready,
    CaptureRaw,
    SetTrickyComm,
    ExecB,
    ExecA,
    ExecMissing,
    StartSibling,
    ExitLeader,
    ExecFromSibling,
    CreateFiles,
    OfferFiles,
    ReplaceFileA,
    UnlinkOriginalA,
    MutateFileA,
    Inventory,
    ParentExit,
    ParentReap,
    Close,
}
impl Action {
    pub fn opcode(self) -> u16 {
        match self {
            Self::Ready => 1,
            Self::CaptureRaw => 2,
            Self::SetTrickyComm => 3,
            Self::ExecB => 4,
            Self::ExecA => 5,
            Self::ExecMissing => 6,
            Self::StartSibling => 7,
            Self::ExitLeader => 8,
            Self::ExecFromSibling => 9,
            Self::CreateFiles => 10,
            Self::OfferFiles => 11,
            Self::ReplaceFileA => 12,
            Self::UnlinkOriginalA => 13,
            Self::MutateFileA => 14,
            Self::Inventory => 15,
            Self::ParentExit => 16,
            Self::ParentReap => 17,
            Self::Close => 18,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::CaptureRaw => "capture_raw",
            Self::SetTrickyComm => "set_tricky_comm",
            Self::ExecB => "exec_b",
            Self::ExecA => "exec_a",
            Self::ExecMissing => "exec_missing",
            Self::StartSibling => "start_sibling",
            Self::ExitLeader => "exit_leader",
            Self::ExecFromSibling => "exec_from_sibling",
            Self::CreateFiles => "create_files",
            Self::OfferFiles => "offer_files",
            Self::ReplaceFileA => "replace_file_a",
            Self::UnlinkOriginalA => "unlink_original_a",
            Self::MutateFileA => "mutate_file_a",
            Self::Inventory => "inventory",
            Self::ParentExit => "parent_exit",
            Self::ParentReap => "parent_reap",
            Self::Close => "close",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ready" => Self::Ready,
            "capture_raw" => Self::CaptureRaw,
            "set_tricky_comm" => Self::SetTrickyComm,
            "exec_b" => Self::ExecB,
            "exec_a" => Self::ExecA,
            "exec_missing" => Self::ExecMissing,
            "start_sibling" => Self::StartSibling,
            "exit_leader" => Self::ExitLeader,
            "exec_from_sibling" => Self::ExecFromSibling,
            "create_files" => Self::CreateFiles,
            "offer_files" => Self::OfferFiles,
            "replace_file_a" => Self::ReplaceFileA,
            "unlink_original_a" => Self::UnlinkOriginalA,
            "mutate_file_a" => Self::MutateFileA,
            "inventory" => Self::Inventory,
            "parent_exit" => Self::ParentExit,
            "parent_reap" => Self::ParentReap,
            "close" => Self::Close,
            _ => return None,
        })
    }
    pub fn from_opcode(code: u16) -> Result<Self, WireError> {
        Ok(match code {
            1 => Self::Ready,
            2 => Self::CaptureRaw,
            3 => Self::SetTrickyComm,
            4 => Self::ExecB,
            5 => Self::ExecA,
            6 => Self::ExecMissing,
            7 => Self::StartSibling,
            8 => Self::ExitLeader,
            9 => Self::ExecFromSibling,
            10 => Self::CreateFiles,
            11 => Self::OfferFiles,
            12 => Self::ReplaceFileA,
            13 => Self::UnlinkOriginalA,
            14 => Self::MutateFileA,
            15 => Self::Inventory,
            16 => Self::ParentExit,
            17 => Self::ParentReap,
            18 => Self::Close,
            _ => return Err(WireError::new("unknown action opcode")),
        })
    }
    pub fn parent_only(self) -> bool {
        matches!(
            self,
            Self::Close | Self::Inventory | Self::OfferFiles | Self::ParentExit | Self::ParentReap
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Actor {
    A,
    B,
    Parent,
    InventoryPositive,
    InventoryNegative,
}
impl Actor {
    pub fn code(self) -> Option<u16> {
        match self {
            Self::A => Some(1),
            Self::B => Some(2),
            Self::Parent => None,
            Self::InventoryPositive => Some(3),
            Self::InventoryNegative => Some(4),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
            Self::Parent => "parent",
            Self::InventoryPositive => "inventory-positive",
            Self::InventoryNegative => "inventory-negative",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "a" => Self::A,
            "b" => Self::B,
            "parent" => Self::Parent,
            "inventory-positive" => Self::InventoryPositive,
            "inventory-negative" => Self::InventoryNegative,
            _ => return None,
        })
    }
    pub fn from_code(code: u16) -> Result<Self, WireError> {
        Ok(match code {
            1 => Self::A,
            2 => Self::B,
            3 => Self::InventoryPositive,
            4 => Self::InventoryNegative,
            _ => return Err(WireError::new("unknown actor code")),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub kind: MessageKind,
    pub payload_len: u32,
    pub fd_count: u16,
    pub run_id: [u8; 16],
    pub operation_id: u64,
    pub sequence: u64,
    pub script_index: u32,
}
impl Envelope {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut h = [0u8; HEADER_BYTES];
        h[0..8].copy_from_slice(MAGIC);
        h[8..10].copy_from_slice(&MAJOR.to_le_bytes());
        h[10..12].copy_from_slice(&MINOR.to_le_bytes());
        h[12..14].copy_from_slice(&self.kind.code().to_le_bytes());
        h[16..20].copy_from_slice(&self.payload_len.to_le_bytes());
        h[20..22].copy_from_slice(&self.fd_count.to_le_bytes());
        h[24..40].copy_from_slice(&self.run_id);
        h[40..48].copy_from_slice(&self.operation_id.to_le_bytes());
        h[48..56].copy_from_slice(&self.sequence.to_le_bytes());
        h[56..60].copy_from_slice(&self.script_index.to_le_bytes());
        h
    }
    pub fn decode(h: &[u8; HEADER_BYTES]) -> Result<Self, WireError> {
        if &h[0..8] != MAGIC {
            return Err(WireError::new("bad magic"));
        }
        if u16::from_le_bytes([h[8], h[9]]) != MAJOR || u16::from_le_bytes([h[10], h[11]]) != MINOR
        {
            return Err(WireError::new("bad version"));
        }
        let kind = MessageKind::parse(u16::from_le_bytes([h[12], h[13]]))?;
        if u16::from_le_bytes([h[14], h[15]]) != 0 {
            return Err(WireError::new("flags must be zero"));
        }
        let payload_len = u32::from_le_bytes([h[16], h[17], h[18], h[19]]);
        if payload_len as usize > PAYLOAD_MAX {
            return Err(WireError::new("payload length exceeds ceiling"));
        }
        let fd_count = u16::from_le_bytes([h[20], h[21]]);
        if fd_count > 1 || u16::from_le_bytes([h[22], h[23]]) != 0 {
            return Err(WireError::new("bad fd count or reserved"));
        }
        let mut run_id = [0u8; 16];
        run_id.copy_from_slice(&h[24..40]);
        let operation_id = u64::from_le_bytes(h[40..48].try_into().unwrap());
        let sequence = u64::from_le_bytes(h[48..56].try_into().unwrap());
        if operation_id == 0 || sequence == 0 {
            return Err(WireError::new("operation and sequence must be positive"));
        }
        let script_index = u32::from_le_bytes([h[56], h[57], h[58], h[59]]);
        if u32::from_le_bytes([h[60], h[61], h[62], h[63]]) != 0 {
            return Err(WireError::new("trailing reserved must be zero"));
        }
        if let Some(fixed) = kind.fixed_body_bytes() {
            if payload_len as usize != fixed {
                return Err(WireError::new("fixed body length mismatch"));
            }
        }
        Ok(Self {
            kind,
            payload_len,
            fd_count,
            run_id,
            operation_id,
            sequence,
            script_index,
        })
    }
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvanceRequest {
    pub action: Action,
    pub actor: Actor,
    pub image_epoch: u32,
    pub blob_mask: u32,
}
impl AdvanceRequest {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&self.action.opcode().to_le_bytes());
        b[2..4].copy_from_slice(&self.actor.code().unwrap_or(0).to_le_bytes());
        b[4..8].copy_from_slice(&self.image_epoch.to_le_bytes());
        b[8..12].copy_from_slice(&self.blob_mask.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != 16 || u32le(&b[12..16]) != 0 {
            return Err(WireError::new("advance request length or reserved"));
        }
        Ok(Self {
            action: Action::from_opcode(u16le(&b[0..2]))?,
            actor: Actor::from_code(u16le(&b[2..4]))?,
            image_epoch: u32le(&b[4..8]),
            blob_mask: u32le(&b[8..12]),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvanceReply {
    pub action: Action,
    pub actor: Actor,
    pub image_epoch: u32,
    pub pid: u32,
    pub tid: u32,
    pub first_record: u32,
    pub record_count: u32,
    pub phase_flags: u32,
}
impl AdvanceReply {
    pub fn encode(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..2].copy_from_slice(&self.action.opcode().to_le_bytes());
        b[2..4].copy_from_slice(&self.actor.code().unwrap_or(0).to_le_bytes());
        b[4..8].copy_from_slice(&self.image_epoch.to_le_bytes());
        b[8..12].copy_from_slice(&self.pid.to_le_bytes());
        b[12..16].copy_from_slice(&self.tid.to_le_bytes());
        b[16..20].copy_from_slice(&self.first_record.to_le_bytes());
        b[20..24].copy_from_slice(&self.record_count.to_le_bytes());
        b[24..28].copy_from_slice(&self.phase_flags.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != 32 || u32le(&b[28..32]) != 0 {
            return Err(WireError::new("advance reply length or reserved"));
        }
        let phase_flags = u32le(&b[24..28]);
        if phase_flags & !0x7 != 0 {
            return Err(WireError::new("phase flag outside bits 0..2"));
        }
        Ok(Self {
            action: Action::from_opcode(u16le(&b[0..2]))?,
            actor: Actor::from_code(u16le(&b[2..4]))?,
            image_epoch: u32le(&b[4..8]),
            pid: u32le(&b[8..12]),
            tid: u32le(&b[12..16]),
            first_record: u32le(&b[16..20]),
            record_count: u32le(&b[20..24]),
            phase_flags,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawRequest {
    pub record_index: u32,
    pub offset: u32,
    pub max_chunk_bytes: u32,
}
impl RawRequest {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.record_index.to_le_bytes());
        b[4..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..12].copy_from_slice(&self.max_chunk_bytes.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != 16 || u32le(&b[12..16]) != 0 {
            return Err(WireError::new("raw request length or reserved"));
        }
        let r = Self {
            record_index: u32le(&b[0..4]),
            offset: u32le(&b[4..8]),
            max_chunk_bytes: u32le(&b[8..12]),
        };
        if r.record_index == 0 || r.max_chunk_bytes == 0 || r.max_chunk_bytes > CHUNK_MAX as u32 {
            return Err(WireError::new("raw request index or chunk bound"));
        }
        Ok(r)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentPrefix {
    pub index: u32,
    pub total_bytes: u32,
    pub offset: u32,
    pub chunk_bytes: u32,
    pub whole_sha256: [u8; 32],
}
impl FragmentPrefix {
    pub fn encode(&self) -> [u8; FRAGMENT_PREFIX_BYTES] {
        let mut b = [0u8; FRAGMENT_PREFIX_BYTES];
        b[0..4].copy_from_slice(&self.index.to_le_bytes());
        b[4..8].copy_from_slice(&self.total_bytes.to_le_bytes());
        b[8..12].copy_from_slice(&self.offset.to_le_bytes());
        b[12..16].copy_from_slice(&self.chunk_bytes.to_le_bytes());
        b[16..48].copy_from_slice(&self.whole_sha256);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != FRAGMENT_PREFIX_BYTES {
            return Err(WireError::new("fragment prefix length"));
        }
        let mut whole_sha256 = [0u8; 32];
        whole_sha256.copy_from_slice(&b[16..48]);
        Ok(Self {
            index: u32le(&b[0..4]),
            total_bytes: u32le(&b[4..8]),
            offset: u32le(&b[8..12]),
            chunk_bytes: u32le(&b[12..16]),
            whole_sha256,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdDirection {
    Push = 1,
    Pull = 2,
}
impl FdDirection {
    pub fn parse(code: u16) -> Result<Self, WireError> {
        Ok(match code {
            1 => Self::Push,
            2 => Self::Pull,
            _ => return Err(WireError::new("unknown fd direction")),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdRole {
    CaseRoot = 1,
    FileA = 2,
    FileB = 3,
}
impl FdRole {
    pub fn parse(code: u16) -> Result<Self, WireError> {
        Ok(match code {
            1 => Self::CaseRoot,
            2 => Self::FileA,
            3 => Self::FileB,
            _ => return Err(WireError::new("unknown fd role")),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdTransferBody {
    pub direction: FdDirection,
    pub role: FdRole,
    pub image_epoch: u32,
    pub grant_id: u32,
}
impl FdTransferBody {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&(self.direction as u16).to_le_bytes());
        b[2..4].copy_from_slice(&(self.role as u16).to_le_bytes());
        b[4..8].copy_from_slice(&self.image_epoch.to_le_bytes());
        b[8..12].copy_from_slice(&self.grant_id.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != 16 || u32le(&b[12..16]) != 0 {
            return Err(WireError::new("fd transfer length or reserved"));
        }
        Ok(Self {
            direction: FdDirection::parse(u16le(&b[0..2]))?,
            role: FdRole::parse(u16le(&b[2..4]))?,
            image_epoch: u32le(&b[4..8]),
            grant_id: u32le(&b[8..12]),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    Normal = 1,
    CaseRetire = 2,
    RunRetire = 3,
    SetupFailure = 4,
}
impl CloseReason {
    pub fn parse(code: u16) -> Result<Self, WireError> {
        Ok(match code {
            1 => Self::Normal,
            2 => Self::CaseRetire,
            3 => Self::RunRetire,
            4 => Self::SetupFailure,
            _ => return Err(WireError::new("unknown close reason")),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseBody {
    pub reason: CloseReason,
    pub actor: Actor,
    pub image_epoch: u32,
    pub last_completed_step: u32,
}
impl CloseBody {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&(self.reason as u16).to_le_bytes());
        b[2..4].copy_from_slice(&self.actor.code().unwrap_or(0).to_le_bytes());
        b[4..8].copy_from_slice(&self.image_epoch.to_le_bytes());
        b[8..12].copy_from_slice(&self.last_completed_step.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != 16 || u32le(&b[12..16]) != 0 {
            return Err(WireError::new("close length or reserved"));
        }
        Ok(Self {
            reason: CloseReason::parse(u16le(&b[0..2]))?,
            actor: Actor::from_code(u16le(&b[2..4]))?,
            image_epoch: u32le(&b[4..8]),
            last_completed_step: u32le(&b[8..12]),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputChunkAck {
    pub blob_index: u32,
    pub total_bytes: u32,
    pub next_offset: u32,
}
impl InputChunkAck {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.blob_index.to_le_bytes());
        b[4..8].copy_from_slice(&self.total_bytes.to_le_bytes());
        b[8..12].copy_from_slice(&self.next_offset.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != 16 || u32le(&b[12..16]) != 0 {
            return Err(WireError::new("chunk ack length or reserved"));
        }
        Ok(Self {
            blob_index: u32le(&b[0..4]),
            total_bytes: u32le(&b[4..8]),
            next_offset: u32le(&b[8..12]),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryReply {
    pub entry_count: u32,
    pub first_record: u32,
    pub record_count: u32,
}
impl InventoryReply {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.entry_count.to_le_bytes());
        b[4..8].copy_from_slice(&self.first_record.to_le_bytes());
        b[8..12].copy_from_slice(&self.record_count.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() != 16 || u32le(&b[12..16]) != 0 {
            return Err(WireError::new("inventory reply length or reserved"));
        }
        Ok(Self {
            entry_count: u32le(&b[0..4]),
            first_record: u32le(&b[4..8]),
            record_count: u32le(&b[8..12]),
        })
    }
}

fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                const H: &[u8; 16] = b"0123456789abcdef";
                let v = c as u32 as u8;
                out.push_str("\\u00");
                out.push(H[(v >> 4) as usize] as char);
                out.push(H[(v & 15) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Canonical JSON: sorted keys, no whitespace, exact escapes, no floats.
/// serde_json::Map iterates in byte order; any duplicate key or non-canonical
/// spelling fails the byte-compare in [`parse_canonical`].
pub fn canonical_json(value: &serde_json::Value) -> Result<String, WireError> {
    use serde_json::Value as V;
    fn go(out: &mut String, v: &V) -> Result<(), WireError> {
        match v {
            V::Null => out.push_str("null"),
            V::Bool(true) => out.push_str("true"),
            V::Bool(false) => out.push_str("false"),
            V::Number(n) => {
                if n.is_f64() {
                    return Err(WireError::new("floats are not canonical"));
                }
                out.push_str(&n.to_string());
            }
            V::String(s) => escape_into(out, s),
            V::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    go(out, item)?;
                }
                out.push(']');
            }
            V::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape_into(out, k);
                    out.push(':');
                    go(out, v)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    go(&mut out, value)?;
    Ok(out)
}

pub fn parse_canonical(bytes: &[u8], max_bytes: usize) -> Result<serde_json::Value, WireError> {
    if bytes.len() > max_bytes {
        return Err(WireError::new("json exceeds bound"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| WireError::new("json parse"))?;
    let canonical = canonical_json(&value)?;
    if canonical.as_bytes() != bytes {
        return Err(WireError::new("json is not canonical"));
    }
    Ok(value)
}

fn exact_keys(value: &serde_json::Value, keys: &[&str], what: &str) -> Result<(), WireError> {
    let map = value
        .as_object()
        .ok_or_else(|| WireError::new(format!("{what} must be an object")))?;
    if map.len() != keys.len() || keys.iter().any(|k| !map.contains_key(*k)) {
        return Err(WireError::new(format!(
            "{what} keys must be exactly closed"
        )));
    }
    Ok(())
}

pub const HELLO_REQUEST_KEYS: [&str; 16] = [
    "schema_version",
    "invocation",
    "mode",
    "slot",
    "scenario",
    "manifest_sha256",
    "images",
    "steps",
    "completed_steps",
    "image_epoch",
    "next_record_index",
    "execution_deadline_ns",
    "limits",
    "blobs",
    "control",
    "inherited_fds",
];
pub const HELLO_REPLY_KEYS: [&str; 10] = [
    "schema_version",
    "mode",
    "slot",
    "manifest_sha256",
    "image_marker",
    "image_epoch",
    "pid",
    "tid",
    "inherited_fds",
    "signal_profile",
];
pub const ERROR_KEYS: [&str; 10] = [
    "category",
    "native_stage",
    "errno",
    "call_result",
    "step_id",
    "completed_steps",
    "diagnostic_hex",
    "reason",
    "limit_kind",
    "producer_charges",
];
pub const INVENTORY_REQUEST_KEYS: [&str; 3] = ["schema_version", "mode", "slots"];
pub const RAW_RECORD_KEYS: [&str; 13] = [
    "schema_version",
    "invocation",
    "step_id",
    "record_index",
    "sequence",
    "actor_slot",
    "record_kind",
    "source",
    "bytes_hex",
    "values",
    "call_result",
    "errno",
    "producer_charges",
];

pub fn validate_hello_request(value: &serde_json::Value) -> Result<(), WireError> {
    exact_keys(value, &HELLO_REQUEST_KEYS, "hello request")?;
    if value["schema_version"] != 1 {
        return Err(WireError::new("hello schema_version must be 1"));
    }
    match value["mode"].as_str() {
        Some("boot") | Some("resume") => {}
        _ => return Err(WireError::new("hello mode must be boot or resume")),
    }
    if value["inherited_fds"] != serde_json::json!([0, 1, 2]) {
        return Err(WireError::new("hello inherited_fds must be [0,1,2]"));
    }
    Ok(())
}

/// Closed outage-control value carried by the Hello `control` field: null
/// or exactly `{kind,step_id,point}` with nonempty strings. Shape only; the
/// driver and worker additionally check scenario pairing via the manifest
/// predicate before arming anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelloControl {
    pub kind: String,
    pub step_id: String,
    pub point: String,
}

pub fn parse_hello_control(value: &serde_json::Value) -> Result<Option<HelloControl>, WireError> {
    if value.is_null() {
        return Ok(None);
    }
    exact_keys(value, &["kind", "step_id", "point"], "hello control")?;
    let mut parts = Vec::with_capacity(3);
    for key in ["kind", "step_id", "point"] {
        match value[key].as_str() {
            Some(s) if !s.is_empty() && s.len() <= 256 => parts.push(s.to_string()),
            _ => return Err(WireError::new("hello control fields must be 1..256 chars")),
        }
    }
    Ok(Some(HelloControl {
        kind: parts.remove(0),
        step_id: parts.remove(0),
        point: parts.remove(0),
    }))
}

pub fn validate_hello_reply(value: &serde_json::Value, slot: &str) -> Result<(), WireError> {
    exact_keys(value, &HELLO_REPLY_KEYS, "hello reply")?;
    if value["schema_version"] != 1 || value["slot"] != slot {
        return Err(WireError::new("hello reply version or slot echo"));
    }
    for key in ["pid", "tid"] {
        match value[key].as_i64() {
            Some(n) if n >= 1 && n <= i32::MAX as i64 => {}
            _ => return Err(WireError::new("hello pid/tid must be positive i32")),
        }
    }
    if value["signal_profile"]
        != serde_json::json!({"term_blocked": false, "term_disposition": "default"})
    {
        return Err(WireError::new(
            "hello signal profile must be default/unblocked",
        ));
    }
    Ok(())
}

pub fn validate_error_body(value: &serde_json::Value) -> Result<(), WireError> {
    exact_keys(value, &ERROR_KEYS, "error body")
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Charges {
    pub native_attempts: u64,
    pub native_successes: u64,
    pub read_attempts: u64,
    pub read_bytes: u64,
    pub file_work_bytes: u64,
    pub hash_work_bytes: u64,
    pub encoded_bytes: u64,
    pub retained_capacity_bytes: u64,
    pub datagram_send_attempts: u64,
    pub datagram_receive_attempts: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
}
impl Charges {
    pub fn to_json(&self) -> serde_json::Value {
        let u = |n: u64| serde_json::Value::String(n.to_string());
        serde_json::json!({
            "native_attempts": u(self.native_attempts),
            "native_successes": u(self.native_successes),
            "read_attempts": u(self.read_attempts),
            "read_bytes": u(self.read_bytes),
            "file_work_bytes": u(self.file_work_bytes),
            "hash_work_bytes": u(self.hash_work_bytes),
            "encoded_bytes": u(self.encoded_bytes),
            "retained_capacity_bytes": u(self.retained_capacity_bytes),
            "datagram_send_attempts": u(self.datagram_send_attempts),
            "datagram_receive_attempts": u(self.datagram_receive_attempts),
            "datagrams_sent": u(self.datagrams_sent),
            "datagrams_received": u(self.datagrams_received),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Carry {
    pub datagrams: u64,
    pub native_attempts: u64,
    pub encoded_raw_bytes: u64,
    pub file_work_bytes: u64,
}
impl Carry {
    pub fn to_json(&self) -> serde_json::Value {
        let u = |n: u64| serde_json::Value::String(n.to_string());
        serde_json::json!({
            "datagrams": u(self.datagrams),
            "native_attempts": u(self.native_attempts),
            "encoded_raw_bytes": u(self.encoded_raw_bytes),
            "file_work_bytes": u(self.file_work_bytes),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProducerCharges {
    pub image_prefix: Charges,
    pub handover_carry: Option<Carry>,
}
impl ProducerCharges {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "image_prefix": self.image_prefix.to_json(),
            "handover_carry": self.handover_carry.map(|c| c.to_json()),
        })
    }
}

pub const RAW_KIND_TASK: &str = "task";
pub const TASK_VALUE_KEYS: [&str; 5] = [
    "pid",
    "tid",
    "parent_slot",
    "self_link_hex",
    "thread_self_link_hex",
];
pub const PROC_VALUE_KEYS: [&str; 6] = [
    "descriptor_slot",
    "file_name",
    "read_calls",
    "bytes_read",
    "eof",
    "overflow_probe",
];

pub fn validate_raw_values(kind: &str, values: &serde_json::Value) -> Result<(), WireError> {
    let keys: &[&str] = match kind {
        "task" => &TASK_VALUE_KEYS,
        "proc" => &PROC_VALUE_KEYS,
        "fd" => &[
            "slot",
            "device",
            "inode",
            "file_type",
            "size",
            "fdinfo_hex",
            "getfd",
            "getfl",
            "canary_hex",
        ],
        "view" => &[
            "proc_root_slot",
            "proc_fs_type",
            "pid_ns_slot",
            "pid_ns_device",
            "pid_ns_inode",
            "mount_ns_slot",
            "mount_ns_device",
            "mount_ns_inode",
            "self_link_hex",
            "nspid",
        ],
        "exit" => &[
            "child_slot",
            "method",
            "poll_revents",
            "si_pid",
            "si_code",
            "si_status",
            "exit_status",
        ],
        "exec" => &[
            "image_before",
            "image_after",
            "executable_slot",
            "executable_sha256",
            "birth_ticks",
        ],
        "mutation" => &[
            "original_slot",
            "replacement_slot",
            "operation",
            "offset",
            "byte_count",
            "readback_hex",
        ],
        "failure" => &[
            "native_stage",
            "reason",
            "limit_kind",
            "completed_steps",
            "subsidiary_errors",
        ],
        _ => return Err(WireError::new("unknown raw record kind")),
    };
    exact_keys(values, keys, "raw values")
}

#[derive(Clone, Debug)]
pub struct RawRecord {
    pub invocation: serde_json::Value,
    pub step_id: String,
    pub record_index: u32,
    pub sequence: Option<u64>,
    pub actor_slot: String,
    pub record_kind: String,
    pub source: String,
    pub bytes_hex: Option<String>,
    pub values: serde_json::Value,
    pub call_result: Option<String>,
    pub errno: Option<i32>,
    pub producer_charges: Option<ProducerCharges>,
}
impl RawRecord {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.record_index == 0 {
            return Err(WireError::new("record index must be positive"));
        }
        validate_raw_values(&self.record_kind, &self.values)?;
        if self.record_kind == "proc" {
            if self.bytes_hex.is_none() {
                return Err(WireError::new("proc records carry bytes_hex"));
            }
        } else if self.bytes_hex.is_some() {
            return Err(WireError::new("only proc records carry bytes_hex"));
        }
        let v = serde_json::json!({
            "schema_version": 1,
            "invocation": self.invocation,
            "step_id": self.step_id,
            "record_index": self.record_index,
            "sequence": self.sequence,
            "actor_slot": self.actor_slot,
            "record_kind": self.record_kind,
            "source": self.source,
            "bytes_hex": self.bytes_hex,
            "values": self.values,
            "call_result": self.call_result,
            "errno": self.errno,
            "producer_charges": self.producer_charges.map(|c| c.to_json()),
        });
        exact_keys(&v, &RAW_RECORD_KEYS, "raw record")?;
        Ok(canonical_json(&v)?.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope {
            kind: MessageKind::AdvanceRequest,
            payload_len: 16,
            fd_count: 0,
            run_id: [7u8; 16],
            operation_id: 3,
            sequence: 9,
            script_index: 2,
        }
    }

    #[test]
    fn envelope_roundtrip() {
        let e = envelope();
        assert_eq!(Envelope::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn envelope_rejects_mutants() {
        let good = envelope().encode();
        for (i, name) in [
            (0, "magic"),
            (8, "major"),
            (12, "kind"),
            (14, "flags"),
            (20, "fd count"),
            (60, "reserved"),
        ] {
            let mut bad = good;
            bad[i] ^= 0xff;
            assert!(Envelope::decode(&bad).is_err(), "{name} mutant accepted");
        }
        let mut bad = good;
        bad[12] = 99;
        bad[13] = 0;
        assert!(Envelope::decode(&bad).is_err());
        let mut bad = good;
        bad[40..48].copy_from_slice(&0u64.to_le_bytes());
        assert!(Envelope::decode(&bad).is_err());
        let mut bad = good;
        bad[16..20].copy_from_slice(&17u32.to_le_bytes());
        assert!(Envelope::decode(&bad).is_err());
    }

    #[test]
    fn bodies_roundtrip() {
        let ar = AdvanceRequest {
            action: Action::CaptureRaw,
            actor: Actor::A,
            image_epoch: 1,
            blob_mask: 0,
        };
        assert_eq!(AdvanceRequest::decode(&ar.encode()).unwrap(), ar);
        let rp = AdvanceReply {
            action: Action::Ready,
            actor: Actor::B,
            image_epoch: 1,
            pid: 10,
            tid: 11,
            first_record: 1,
            record_count: 2,
            phase_flags: 3,
        };
        assert_eq!(AdvanceReply::decode(&rp.encode()).unwrap(), rp);
        assert!(AdvanceReply::decode(&{
            let mut b = rp.encode();
            b[24] = 8;
            b
        })
        .is_err());
        let rr = RawRequest {
            record_index: 2,
            offset: 0,
            max_chunk_bytes: CHUNK_MAX as u32,
        };
        assert_eq!(RawRequest::decode(&rr.encode()).unwrap(), rr);
        assert!(RawRequest::decode(&[0u8; 16]).is_err());
        let fp = FragmentPrefix {
            index: 1,
            total_bytes: 9,
            offset: 0,
            chunk_bytes: 9,
            whole_sha256: [1u8; 32],
        };
        assert_eq!(FragmentPrefix::decode(&fp.encode()).unwrap(), fp);
        let fd = FdTransferBody {
            direction: FdDirection::Push,
            role: FdRole::CaseRoot,
            image_epoch: 1,
            grant_id: 1,
        };
        assert_eq!(FdTransferBody::decode(&fd.encode()).unwrap(), fd);
        assert!(FdTransferBody::decode(&[9, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let cb = CloseBody {
            reason: CloseReason::Normal,
            actor: Actor::A,
            image_epoch: 1,
            last_completed_step: 7,
        };
        assert_eq!(CloseBody::decode(&cb.encode()).unwrap(), cb);
        let ack = InputChunkAck {
            blob_index: 1,
            total_bytes: 5,
            next_offset: 5,
        };
        assert_eq!(InputChunkAck::decode(&ack.encode()).unwrap(), ack);
        let ir = InventoryReply {
            entry_count: 3,
            first_record: 4,
            record_count: 4,
        };
        assert_eq!(InventoryReply::decode(&ir.encode()).unwrap(), ir);
    }

    #[test]
    fn opcodes_cover_all_actions() {
        for code in 1u16..=18 {
            let a = Action::from_opcode(code).unwrap();
            assert_eq!(a.opcode(), code);
            assert_eq!(Action::parse(a.as_str()), Some(a));
        }
        assert!(Action::from_opcode(0).is_err());
        assert!(Action::from_opcode(19).is_err());
        assert!(Action::parse("retire").is_none());
        assert!(Action::Close.parent_only());
        assert!(!Action::Ready.parent_only());
    }

    #[test]
    fn canonical_vectors() {
        let v: serde_json::Value = serde_json::json!({"b":1,"a":[true,null,"x"]});
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":[true,null,"x"],"b":1}"#
        );
        let v: serde_json::Value = serde_json::json!({"s":"a\"b\\c\nd\tE"});
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"s":"a\"b\\c\u000ad\u0009E"}"#
        );
        let v: serde_json::Value = serde_json::json!({"cell":"héllo\u{1}✓"});
        assert_eq!(canonical_json(&v).unwrap(), "{\"cell\":\"héllo\\u0001✓\"}");
        let v: serde_json::Value = serde_json::json!({"n": 18446744073709551615u64});
        assert_eq!(canonical_json(&v).unwrap(), r#"{"n":18446744073709551615}"#);
        assert!(parse_canonical(br#"{"a":1}"#, 99).is_ok());
        for bad in [
            &br#"{"a": 1}"#[..],
            br#"{"b":1,"a":1}"#,
            br#"{"a":1,"a":1}"#,
            br#"{"a":1.0}"#,
            br#"{"a":1} "#,
            br#"{"a":"\u0041"}"#,
        ] {
            assert!(parse_canonical(bad, 99).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn hello_shapes() {
        let req = serde_json::json!({
            "schema_version": 1, "invocation": {"run_id": "00"}, "mode": "boot",
            "slot": "a", "scenario": "leader-lifecycle", "manifest_sha256": "00",
            "images": [], "steps": [], "completed_steps": 0, "image_epoch": 1,
            "next_record_index": 1, "execution_deadline_ns": "9", "limits": {},
            "blobs": [], "control": null, "inherited_fds": [0, 1, 2],
        });
        assert!(validate_hello_request(&req).is_ok());
        let mut bad = req.clone();
        bad["mode"] = serde_json::json!("boot2");
        assert!(validate_hello_request(&bad).is_err());
        let reply = serde_json::json!({
            "schema_version": 1, "mode": "boot", "slot": "a",
            "manifest_sha256": "00", "image_marker": "A", "image_epoch": 1,
            "pid": 5, "tid": 5, "inherited_fds": [0, 1, 2],
            "signal_profile": {"term_blocked": false, "term_disposition": "default"},
        });
        assert!(validate_hello_reply(&reply, "a").is_ok());
        assert!(validate_hello_reply(&reply, "b").is_err());
    }

    #[test]
    fn raw_record_encode_and_closed_values() {
        let invocation = serde_json::json!({"run_id": "00"});
        let task = RawRecord {
            invocation: invocation.clone(),
            step_id: "s02-live".into(),
            record_index: 1,
            sequence: Some(4),
            actor_slot: "a".into(),
            record_kind: "task".into(),
            source: "worker_kernel".into(),
            bytes_hex: None,
            values: serde_json::json!({
                "pid": 5, "tid": 5, "parent_slot": null,
                "self_link_hex": null, "thread_self_link_hex": null,
            }),
            call_result: None,
            errno: None,
            producer_charges: Some(ProducerCharges::default()),
        };
        let bytes = task.encode().unwrap();
        let back = parse_canonical(&bytes, 65536).unwrap();
        assert_eq!(back["record_kind"], "task");
        let mut bad = task.clone();
        bad.record_index = 0;
        assert!(bad.encode().is_err());
        let mut bad = task.clone();
        bad.values = serde_json::json!({"pid": 5});
        assert!(bad.encode().is_err());
        let mut bad = task;
        bad.bytes_hex = Some("00".into());
        assert!(bad.encode().is_err());
        for kind in ["fd", "view", "exit", "exec", "mutation", "failure"] {
            assert!(validate_raw_values(kind, &serde_json::json!({})).is_err());
        }
        assert!(validate_raw_values("bogus", &serde_json::json!({})).is_err());
    }

    #[test]
    fn run_id_hex_roundtrip() {
        let hex = "0123456789abcdef0123456789abcdef";
        let id = run_id_from_hex(hex).unwrap();
        assert_eq!(run_id_to_hex(&id), hex);
        assert!(run_id_from_hex("0123").is_err());
        assert!(run_id_from_hex(&"AB".repeat(16)).is_err());
        assert_eq!(
            sha256_of(b"abc")[..],
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()[..]
        );
    }

    #[test]
    fn hello_control_shapes() {
        assert_eq!(parse_hello_control(&serde_json::Value::Null).unwrap(), None);
        let good = serde_json::json!({
            "kind": "worker_exit", "step_id": "s01-ready", "point": "after_root_grant",
        });
        assert_eq!(
            parse_hello_control(&good).unwrap(),
            Some(HelloControl {
                kind: "worker_exit".to_string(),
                step_id: "s01-ready".to_string(),
                point: "after_root_grant".to_string(),
            })
        );
        for bad in [
            serde_json::json!({"kind": "worker_exit", "step_id": "s01-ready"}),
            serde_json::json!({
                "kind": "worker_exit", "step_id": "s01-ready",
                "point": "after_root_grant", "extra": 1,
            }),
            serde_json::json!({
                "kind": "", "step_id": "s01-ready", "point": "after_root_grant",
            }),
            serde_json::json!({
                "kind": "worker_exit", "step_id": "s01-ready", "point": 7,
            }),
            serde_json::json!("worker_exit"),
            serde_json::json!(["worker_exit"]),
        ] {
            assert!(parse_hello_control(&bad).is_err(), "accepted {bad}");
        }
    }

    mod hex {
        pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
            if s.len() % 2 != 0 {
                return Err(());
            }
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
                .collect()
        }
    }
}
