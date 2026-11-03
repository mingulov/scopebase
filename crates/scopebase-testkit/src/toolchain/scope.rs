// SPDX-License-Identifier: Apache-2.0
//! TC02: role-structured closure selection and build-scope backends.
//!
//! Donor slices (p11scope-ws w000 @ 6f97aa47, frozen tree; whole
//! user-authored files): `llvm-bpf-toolchain-experiment.md` (lines 1-216),
//! `llvm-bpf-atomic-load-report.md` (lines 1-140; loaded-LLVM distinction at
//! lines 76-80: the actually loaded `libLLVM.so.22.1-rust-1.97.0-nightly`
//! versus native Clang 18.1.8, "the two must not be conflated"; `llc`
//! generic/v3/v4 CPU matrix and bpf-linker `--cpu v4` parser refusal at
//! lines 64-74),
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/prepare.py`
//! (lines 108-113: explicit `--llc` tool path, `--cpu` choices admit list,
//! simple-label check; lines 122-126: argv-array spawn with `-mtriple`,
//! `-mcpu`, `-O2`, `-filetype=obj`, `timeout=20`, per-case logs) and
//! `evidence/llvm-toolchain-review-20260922/kernel-oracle/run.py`
//! (lines 63-66: hash re-verified before execution, argv array,
//! `timeout=10`). ADAPT to Rust with role-structured selection,
//! hash-pinned-before-use and a sandboxed direct scope; no upstream lines
//! copied. Grant: OWNER-2026-10-23.
//!
//! The shipped [`CompilerClosure`][crate::toolchain::CompilerClosure] stays
//! the admitted pin manifest ("which hashes exist"). [`SelectedClosure`] is
//! the reconciled role-structured execution view the toolchain spec names
//! (`cargo`/`rustc`/`rust_sysroot`/`clang`/`llc`/`linker`/`loaded_llvm`):
//! each role binds one manifest pin id plus a caller-resolved offline path,
//! with the pin hash carried into the run. Selection is structural only and
//! touches no filesystem; pair coherence and file existence are enforced at
//! [`compile_fixture`][crate::toolchain::compile_fixture] admission, and
//! byte hashes are re-verified by the backend before use.
use scopebase_bpf::{ErrorKind, OperationError, Stage};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::object::invalid;
use crate::toolchain::identity::CompilerClosure;
use crate::toolchain::invoke::{join_readers, kill_and_wait, spawn_capped_reader_on};

/// One selected compiler tool: offline path, recorded hash, version evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolBinary {
    pub executable: PathBuf,
    pub sha256: [u8; 32],
    pub version_output: Vec<u8>,
}

/// Compiler-closure roles, including the recorded loaded LLVM library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolRole {
    Cargo,
    Rustc,
    RustSysroot,
    Clang,
    Llc,
    Linker,
    LoadedLlvm,
}

impl ToolRole {
    /// Stable role name used in `ToolMissing` reports.
    pub fn name(self) -> &'static str {
        match self {
            ToolRole::Cargo => "cargo",
            ToolRole::Rustc => "rustc",
            ToolRole::RustSysroot => "rust_sysroot",
            ToolRole::Clang => "clang",
            ToolRole::Llc => "llc",
            ToolRole::Linker => "linker",
            ToolRole::LoadedLlvm => "loaded_llvm",
        }
    }
}

/// One role binding: manifest pin id, offline path, recorded version bytes.
#[derive(Debug, Clone)]
pub struct RoleBinding {
    pub pin: String,
    pub path: PathBuf,
    pub version_output: Vec<u8>,
}

/// Requested role bindings. `loaded_llvm` is always required; every other
/// role is optional, and unselected roles never trigger discovery.
#[derive(Debug, Clone)]
pub struct RoleSelection {
    pub cargo: Option<RoleBinding>,
    pub rustc: Option<RoleBinding>,
    pub rust_sysroot: Option<PathBuf>,
    pub clang: Option<RoleBinding>,
    pub llc: Option<RoleBinding>,
    pub linker: Option<RoleBinding>,
    pub loaded_llvm: Option<RoleBinding>,
}

impl RoleSelection {
    /// Empty selection: every role unbound.
    pub fn none() -> Self {
        Self {
            cargo: None,
            rustc: None,
            rust_sysroot: None,
            clang: None,
            llc: None,
            linker: None,
            loaded_llvm: None,
        }
    }
}

/// Role-structured execution closure over an admitted pin manifest.
///
/// Built only by [`SelectedClosure::select`], which binds each requested
/// role to one manifest pin of the matching role class and carries the pin
/// hash into the run. `loaded_llvm` accepts any pin: it records which LLVM
/// library was loaded, independently of Rust's embedded LLVM and Clang's
/// LLVM, exactly as the donor reports distinguish them. Selection performs
/// no filesystem access; existence, pair coherence and byte hashes are
/// enforced later by executor admission and the scope backend.
#[derive(Debug, Clone)]
pub struct SelectedClosure {
    manifest: CompilerClosure,
    cargo: Option<(String, ToolBinary)>,
    rustc: Option<(String, ToolBinary)>,
    rust_sysroot: Option<PathBuf>,
    clang: Option<(String, ToolBinary)>,
    llc: Option<(String, ToolBinary)>,
    linker: Option<(String, ToolBinary)>,
    loaded_llvm: (String, ToolBinary),
}

impl SelectedClosure {
    /// Bind requested roles to manifest pins. Unknown pin ids, role-class
    /// mismatches, empty version evidence and a missing `loaded_llvm`
    /// refuse with `InvalidInput/Admission`.
    pub fn select(
        manifest: &CompilerClosure,
        selection: &RoleSelection,
    ) -> Result<Self, OperationError> {
        fn bind(
            manifest: &CompilerClosure,
            binding: &RoleBinding,
            class: Option<&str>,
        ) -> Result<(String, ToolBinary), OperationError> {
            let pin = manifest
                .find(&binding.pin)
                .ok_or_else(|| invalid("role pin not in manifest"))?;
            if let Some(class) = class {
                if pin.role() != class {
                    return Err(invalid("role pin class mismatch"));
                }
            }
            if binding.version_output.is_empty() {
                return Err(invalid("missing version evidence"));
            }
            Ok((
                binding.pin.clone(),
                ToolBinary {
                    executable: binding.path.clone(),
                    sha256: *pin.sha256(),
                    version_output: binding.version_output.clone(),
                },
            ))
        }

        let cargo = selection
            .cargo
            .as_ref()
            .map(|b| bind(manifest, b, Some("cargo")))
            .transpose()?;
        let rustc = selection
            .rustc
            .as_ref()
            .map(|b| bind(manifest, b, Some("rust")))
            .transpose()?;
        let clang = selection
            .clang
            .as_ref()
            .map(|b| bind(manifest, b, Some("frontend")))
            .transpose()?;
        let llc = selection
            .llc
            .as_ref()
            .map(|b| bind(manifest, b, Some("backend")))
            .transpose()?;
        let linker = selection
            .linker
            .as_ref()
            .map(|b| bind(manifest, b, Some("linker")))
            .transpose()?;
        let loaded_llvm = match selection.loaded_llvm.as_ref() {
            Some(binding) => bind(manifest, binding, None)?,
            None => return Err(invalid("loaded_llvm required")),
        };
        Ok(Self {
            manifest: manifest.clone(),
            cargo,
            rustc,
            rust_sysroot: selection.rust_sysroot.clone(),
            clang,
            llc,
            linker,
            loaded_llvm,
        })
    }

    /// The admitted pin manifest this selection binds.
    pub fn manifest(&self) -> &CompilerClosure {
        &self.manifest
    }

    /// Selected Cargo binary, if any.
    pub fn cargo(&self) -> Option<&ToolBinary> {
        self.cargo.as_ref().map(|(_, tool)| tool)
    }

    /// Selected rustc binary, if any.
    pub fn rustc(&self) -> Option<&ToolBinary> {
        self.rustc.as_ref().map(|(_, tool)| tool)
    }

    /// Selected Rust sysroot, if any.
    pub fn rust_sysroot(&self) -> Option<&Path> {
        self.rust_sysroot.as_deref()
    }

    /// Selected Clang binary, if any.
    pub fn clang(&self) -> Option<&ToolBinary> {
        self.clang.as_ref().map(|(_, tool)| tool)
    }

    /// Selected llc binary, if any.
    pub fn llc(&self) -> Option<&ToolBinary> {
        self.llc.as_ref().map(|(_, tool)| tool)
    }

    /// Selected linker binary, if any.
    pub fn linker(&self) -> Option<&ToolBinary> {
        self.linker.as_ref().map(|(_, tool)| tool)
    }

    /// The recorded loaded LLVM library. Always present.
    pub fn loaded_llvm(&self) -> &ToolBinary {
        &self.loaded_llvm.1
    }

    /// Manifest pin id bound to a role, if the role is selected. The
    /// sysroot carries no pin and always reports `None`.
    pub fn role_pin(&self, role: ToolRole) -> Option<&str> {
        match role {
            ToolRole::Cargo => self.cargo.as_ref().map(|(pin, _)| pin.as_str()),
            ToolRole::Rustc => self.rustc.as_ref().map(|(pin, _)| pin.as_str()),
            ToolRole::RustSysroot => None,
            ToolRole::Clang => self.clang.as_ref().map(|(pin, _)| pin.as_str()),
            ToolRole::Llc => self.llc.as_ref().map(|(pin, _)| pin.as_str()),
            ToolRole::Linker => self.linker.as_ref().map(|(pin, _)| pin.as_str()),
            ToolRole::LoadedLlvm => Some(self.loaded_llvm.0.as_str()),
        }
    }
}

/// One fixture build request: task roots, target profile, explicit
/// environment and byte/time bounds. Paths preserve non-UTF8 bytes.
/// Compiler, target and CPU selection belongs to the closure and these
/// fields; smuggling alternates through `environment` refuses.
#[derive(Debug, Clone)]
pub struct BuildRequest {
    pub source_root: PathBuf,
    pub output_root: PathBuf,
    pub target: String,
    pub cpu: Option<String>,
    pub features: Vec<String>,
    pub environment: BTreeMap<OsString, OsString>,
    pub deadline: Instant,
    pub max_output_bytes: usize,
    pub max_artifact_bytes: usize,
}

impl BuildRequest {
    /// Request with no CPU, features or environment. Any representable
    /// bound is valid configuration; exceeding one at runtime aborts.
    pub fn new(
        source_root: PathBuf,
        output_root: PathBuf,
        target: String,
        deadline: Instant,
        max_output_bytes: usize,
        max_artifact_bytes: usize,
    ) -> Self {
        Self {
            source_root,
            output_root,
            target,
            cpu: None,
            features: Vec::new(),
            environment: BTreeMap::new(),
            deadline,
            max_output_bytes,
            max_artifact_bytes,
        }
    }
}

/// Scope-start outcome: a live scope owner, proof of no effect, or an
/// uncertain start whose custody the executor retains.
#[derive(Debug)]
pub enum ScopeStart<J> {
    Started(J),
    NoEffect(OperationError),
    Uncertain { custody: J, cause: OperationError },
}

/// Settled process exit: code or fatal signal number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildExit {
    Exited(i32),
    Signaled(i32),
}

/// Scope-poll outcome: still running, positively settled with exit,
/// objects and diagnostics, or unresolved with a typed cause.
#[derive(Debug)]
pub enum ScopePoll {
    Running,
    Settled {
        exit: BuildExit,
        objects: Vec<PathBuf>,
        diagnostic: Vec<u8>,
    },
    Unresolved(OperationError),
}

/// Whole-scope ownership contract for one build profile.
///
/// # Safety
///
/// `Settled` is an authority claim: every process, thread and descendant
/// capable of writing the job outputs has ceased, pending I/O has reached
/// the declared stable boundary, and owned-scope cleanup is complete.
/// `Job` must retain every native scope, control and output resource,
/// including ambiguous start effects; `NoEffect` requires proof of no
/// surviving effect. `poll`/`request_stop` are cooperative and nonblocking;
/// budgets bound control calls, not arbitrary syscall interruption.
pub unsafe trait BuildScopeBackend {
    type Job;

    fn start(&mut self, tools: &SelectedClosure, request: &BuildRequest) -> ScopeStart<Self::Job>;
    fn poll(&mut self, job: &mut Self::Job) -> ScopePoll;
    fn request_stop(&mut self, job: &mut Self::Job) -> ScopePoll;
}

// ---------------------------------------------------------------------------
// Direct no-children scope (`direct-no-children-v1`).
// ---------------------------------------------------------------------------

/// audited direct-tool CPU admit list. `None` omits `-mcpu`; anything else
/// refuses. Mirrors the donor `--cpu` choices shape with the donor-observed
/// `generic` preset added.
const DIRECT_CPUS: &[&str] = &["generic", "v3", "v4"];

fn valid_target(target: &str) -> bool {
    !target.is_empty()
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn valid_feature(feature: &str) -> bool {
    !feature.is_empty()
        && feature.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b':')
        })
}

fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let bytes = std::fs::read(path)?;
    Ok(Sha256::digest(&bytes).into())
}

fn unsupported(message: &'static str) -> OperationError {
    OperationError::new(
        ErrorKind::Unsupported,
        Stage::Admission,
        None,
        Some(Box::new(ScopeDetail(message))),
    )
}

fn scope_backend(error: std::io::Error) -> OperationError {
    OperationError::new(
        ErrorKind::Backend,
        Stage::Execute,
        error.raw_os_error(),
        Some(Box::new(ScopeDetail("direct scope backend failure"))),
    )
}

#[derive(Debug)]
struct ScopeDetail(&'static str);

impl std::fmt::Display for ScopeDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc02 scope: {}", self.0)
    }
}

impl std::error::Error for ScopeDetail {}

// --- Child-only no-children enforcement ------------------------------------
//
// Classic BPF filter, installed after fork and before exec, that kills the
// child on any process-creation or socket/IPC syscall. The parent never
// installs it. Syscall numbers are Linux UAPI facts
// (asm-generic/unistd.h plus the x86_64/aarch64 tables), not copied code.

/// Kernel `struct sock_filter` layout (code/jt/jf/k).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

const BPF_LOAD_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// x86_64: clone, fork, vfork, clone3, socket, socketpair, connect,
/// sendto, sendmsg.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NATIVE_KILLS: &[u32] = &[56, 57, 58, 435, 41, 53, 42, 44, 46];
/// aarch64: clone, clone3, socket, socketpair, connect, sendto, sendmsg
/// (aarch64 has no fork/vfork; clone covers process creation).
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const NATIVE_KILLS: &[u32] = &[220, 435, 198, 199, 203, 206, 211];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NATIVE_ARCH: u32 = AUDIT_ARCH_X86_64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const NATIVE_ARCH: u32 = AUDIT_ARCH_AARCH64;

/// Maximum filter length: arch load, arch check, nr load, nine kill
/// checks, allow, kill.
const MAX_FILTER: usize = 14;

/// Fill `out` with the no-children filter and return its length. Layout:
/// load arch, kill unless native (blocks compat-ABI bypass), load nr,
/// kill on each listed syscall, allow otherwise.
fn build_filter(arch: u32, kills: &[u32], out: &mut [SockFilter; MAX_FILTER]) -> usize {
    debug_assert!(3 + kills.len() + 2 <= MAX_FILTER);
    let mut next = 0;
    out[next] = SockFilter {
        code: BPF_LOAD_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH,
    };
    next += 1;
    let arch_check = next;
    next += 1;
    out[next] = SockFilter {
        code: BPF_LOAD_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR,
    };
    next += 1;
    let mut kill_at = [0usize; MAX_FILTER];
    for (index, nr) in kills.iter().enumerate() {
        kill_at[index] = next;
        out[next] = SockFilter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 0,
            k: *nr,
        };
        next += 1;
    }
    out[next] = SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    };
    next += 1;
    let kill = next;
    out[next] = SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    };
    next += 1;
    out[arch_check] = SockFilter {
        code: BPF_JEQ_K,
        jt: 0,
        jf: (kill - arch_check - 1) as u8,
        k: arch,
    };
    for index in 0..kills.len() {
        out[kill_at[index]].jt = (kill - kill_at[index] - 1) as u8;
    }
    next
}

/// Whether the child-only sandbox can be installed on this platform.
fn enforcement_available() -> bool {
    cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
}

/// Install the no-children filter and close inherited descriptors.
///
/// Runs after fork, before exec: stack memory and direct syscalls only, no
/// allocation, no locks, no panic. std applies stdio redirection before
/// `pre_exec`, so descriptors 0/1/2 are already the declared pipes and
/// everything from 3 up is closed. The order matters: the sandbox installs
/// first so a failure still reports through std's error pipe.
#[cfg(target_os = "linux")]
fn install_no_children() -> Result<(), i32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let mut filter = [SockFilter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        }; MAX_FILTER];
        let len = build_filter(NATIVE_ARCH, NATIVE_KILLS, &mut filter);
        #[repr(C)]
        struct Prog {
            len: u16,
            filter: *const SockFilter,
        }
        let prog = Prog {
            len: len as u16,
            filter: filter.as_ptr(),
        };
        // SAFETY: prctl takes integers only; prog points at live stack memory.
        let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if no_new_privs != 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EPERM));
        }
        // Raw syscall: some libcs lack the seccomp wrapper; SYS_seccomp is stable.
        let applied =
            unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) };
        if applied != 0 {
            // A raw syscall returns the negated errno directly.
            let errno = i32::try_from(-applied).unwrap_or(libc::EPERM);
            return Err(if errno == 0 { libc::EPERM } else { errno });
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return Err(libc::ENOSYS);
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let cap = fd_cap();
        let mut fd = 3;
        while fd < cap {
            // SAFETY: close takes an integer only; EBADF on unopened fds is fine.
            unsafe {
                libc::close(fd);
            }
            fd += 1;
        }
        Ok(())
    }
}

/// Non-Linux stub: enforcement is unavailable, never silently absent.
#[cfg(not(target_os = "linux"))]
fn install_no_children() -> Result<(), i32> {
    Err(libc::ENOSYS)
}

/// Upper bound for the pre-exec descriptor sweep: the soft fd limit with a
/// hard cap so a huge limit cannot stall the spawn.
#[cfg(target_os = "linux")]
fn fd_cap() -> libc::c_int {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only through the live stack pointer.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if read != 0 {
        return 1024;
    }
    libc::c_int::try_from(limit.rlim_cur.min(1 << 20)).unwrap_or(1 << 20)
}

fn install_pre_exec() -> std::io::Result<()> {
    install_no_children().map_err(std::io::Error::from_raw_os_error)
}

// --- Direct scope ------------------------------------------------------------

/// Narrow host scope for one pinned direct tool (`direct-no-children-v1`).
///
/// This is a build-scope ID, not a conformance profile. It runs exactly one
/// of the `llc`/`clang` roles with fully derived, audited argv after the
/// shape `[tool, -mtriple, -mcpu?, --mattr*, -O2, -filetype=obj, input, -o,
/// output]`; Cargo, rustc, sysroots, linkers, plugins, response files and
/// implicit helpers are not admitted. The child runs under the no-children
/// sandbox with cleared environment plus forced `CARGO_NET_OFFLINE=true`.
/// `start` refuses before exec when enforcement is unavailable.
#[derive(Debug, Default)]
pub struct DirectScope;

impl DirectScope {
    /// Stateless narrow host scope.
    pub fn new() -> Self {
        Self
    }

    /// Whether the child-only sandbox installs on this platform.
    pub fn enforcement_available() -> bool {
        enforcement_available()
    }
}

/// Owned direct-tool child: process, capped readers and settle state. All
/// effectful worker state lives here; dropping a live job kills the owned
/// child without claiming any settlement.
pub struct DirectJob {
    child: Option<Child>,
    stdout_reader: Option<std::thread::JoinHandle<crate::toolchain::invoke::CappedOutput>>,
    stderr_reader: Option<std::thread::JoinHandle<crate::toolchain::invoke::CappedOutput>>,
    stdout_hit: Arc<AtomicBool>,
    stderr_hit: Arc<AtomicBool>,
    state: DirectState,
    tool_pin: String,
    loaded_llvm_hex: String,
    output_object: PathBuf,
    max_output_bytes: usize,
}

impl std::fmt::Debug for DirectJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectJob")
            .field("tool_pin", &self.tool_pin)
            .finish()
    }
}

impl Drop for DirectJob {
    /// Last resort: kill the owned child so no orphan survives. Claims no
    /// settlement, joins nothing and never panics; reader threads drain to
    /// EOF on their own once the pipes close.
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug)]
enum DirectState {
    Running,
    Reaped {
        status: ExitStatus,
        stdout_overrun: bool,
        stderr_overrun: bool,
        stderr: Vec<u8>,
        read_error: bool,
        /// Stabilization sample: `None` until the first post-reap stat,
        /// then the last observed object size (`None` = still missing).
        sampled_size: Option<Option<u64>>,
    },
}

// SAFETY: `Settled` is claimed only after the owned immediate child is
// reaped and the single expected object is stat-stable across polls. The
// no-children sandbox makes descendants impossible, and the executor holds
// the output root exclusively, so no other writer can exist.
unsafe impl BuildScopeBackend for DirectScope {
    type Job = DirectJob;

    fn start(&mut self, tools: &SelectedClosure, request: &BuildRequest) -> ScopeStart<Self::Job> {
        if !Self::enforcement_available() {
            return ScopeStart::NoEffect(unsupported("no-children enforcement unavailable"));
        }
        let (pin, tool) = match (tools.llc(), tools.clang()) {
            (Some(tool), None) => (tools.role_pin(ToolRole::Llc).unwrap_or("llc"), tool),
            (None, Some(tool)) => (tools.role_pin(ToolRole::Clang).unwrap_or("clang"), tool),
            _ => {
                return ScopeStart::NoEffect(invalid(
                    "direct scope needs exactly one of llc/clang",
                ));
            }
        };
        if tools.cargo().is_some()
            || tools.rustc().is_some()
            || tools.rust_sysroot().is_some()
            || tools.linker().is_some()
        {
            return ScopeStart::NoEffect(invalid("cargo/rust/linker not admitted to direct scope"));
        }
        // Hash-pinned-before-use: every bound byte string must still match.
        //
        // S224 trust assumption (tool-dir-immutable): the hash and the
        // `Command::new(&tool.executable)` spawn below are bound only
        // by pathname — a writer with tool-directory access could swap
        // the binary in between. `std::fs::read` already hashes
        // through a single open description, so no re-read narrows
        // this; only fd-bound exec would close it, which is out of
        // proportion here. Callers must hold the tool directory
        // immutable across the start — executable contents as well as
        // pathname bindings. The hash voids steady-state corruption
        // and misbinding, not a live swapper.
        let mut bound: Vec<(&str, &ToolBinary)> = vec![("tool", tool)];
        bound.push(("loaded_llvm", tools.loaded_llvm()));
        for (what, binary) in bound {
            match sha256_file(&binary.executable) {
                Ok(sum) if sum == binary.sha256 => {}
                _ => {
                    return ScopeStart::NoEffect(invalid(match what {
                        "tool" => "tool bytes differ from pin",
                        _ => "loaded LLVM bytes differ from pin",
                    }));
                }
            }
        }
        if !valid_target(&request.target) {
            return ScopeStart::NoEffect(invalid("target"));
        }
        let cpu = match request.cpu.as_deref() {
            None => None,
            Some(cpu) if DIRECT_CPUS.contains(&cpu) => Some(cpu),
            _ => return ScopeStart::NoEffect(invalid("cpu")),
        };
        for feature in &request.features {
            if !valid_feature(feature) {
                return ScopeStart::NoEffect(invalid("feature"));
            }
        }
        let input = request.source_root.join("input.ll");
        if std::fs::symlink_metadata(&input).is_err() {
            return ScopeStart::NoEffect(invalid("input.ll missing"));
        }
        let output = request.output_root.join("output.o");
        let mut argv: Vec<OsString> = Vec::new();
        argv.push(OsString::from(format!("-mtriple={}", request.target)));
        if let Some(cpu) = cpu {
            argv.push(OsString::from(format!("-mcpu={cpu}")));
        }
        for feature in &request.features {
            argv.push(OsString::from(format!("--mattr={feature}")));
        }
        argv.push(OsString::from("-O2"));
        argv.push(OsString::from("-filetype=obj"));
        argv.push(input.into_os_string());
        argv.push(OsString::from("-o"));
        argv.push(output.clone().into_os_string());

        let mut command = std::process::Command::new(&tool.executable);
        command
            .args(&argv)
            .env_clear()
            .envs(request.environment.iter())
            .env("CARGO_NET_OFFLINE", "true")
            .current_dir(&request.source_root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: install_pre_exec uses stack memory and direct syscalls
        // only; it allocates nothing, locks nothing and never panics.
        unsafe {
            use std::os::unix::process::CommandExt as _;
            command.pre_exec(install_pre_exec);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ScopeStart::NoEffect(OperationError::new(
                    ErrorKind::InvalidInput,
                    Stage::Execute,
                    error.raw_os_error(),
                    Some(Box::new(ScopeDetail("tool executable missing"))),
                ));
            }
            Err(error) => return ScopeStart::NoEffect(scope_backend(error)),
        };
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let stdout_hit = Arc::new(AtomicBool::new(false));
        let stderr_hit = Arc::new(AtomicBool::new(false));
        // R06: reader-thread spawn is fallible; a denial retires
        // the child with no effect instead of panicking.
        let stdout_reader = match spawn_capped_reader_on(
            std::thread::Builder::new().name("scope-stdout".to_string()),
            stdout,
            request.max_output_bytes,
            Arc::clone(&stdout_hit),
        ) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = kill_and_wait(&mut child);
                return ScopeStart::NoEffect(scope_backend(error));
            }
        };
        let stderr_reader = match spawn_capped_reader_on(
            std::thread::Builder::new().name("scope-stderr".to_string()),
            stderr,
            request.max_output_bytes,
            Arc::clone(&stderr_hit),
        ) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = kill_and_wait(&mut child);
                let _ = stdout_reader.join();
                return ScopeStart::NoEffect(scope_backend(error));
            }
        };
        ScopeStart::Started(DirectJob {
            child: Some(child),
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            stdout_hit,
            stderr_hit,
            state: DirectState::Running,
            tool_pin: pin.to_owned(),
            loaded_llvm_hex: tools
                .loaded_llvm()
                .sha256
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            output_object: output,
            max_output_bytes: request.max_output_bytes,
        })
    }

    fn poll(&mut self, job: &mut Self::Job) -> ScopePoll {
        if matches!(job.state, DirectState::Running) {
            match drive_running(job) {
                Ok(running) => {
                    if running {
                        return ScopePoll::Running;
                    }
                }
                Err(error) => return ScopePoll::Unresolved(error),
            }
        }
        stabilize(job)
    }

    fn request_stop(&mut self, job: &mut Self::Job) -> ScopePoll {
        if let Some(child) = job.child.as_mut() {
            let pid = child.id();
            // SAFETY: an owned, not-yet-reaped child; the pid cannot be
            // recycled while this Child exists. ESRCH (already exited)
            // resolves in the poll below.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        self.poll(job)
    }
}

/// Drive a running direct job one step: reap on overrun or exit, and report
/// whether it is still running. Reader threads join only after the child is
/// gone, so joining never blocks on a live child.
fn drive_running(job: &mut DirectJob) -> Result<bool, OperationError> {
    let overrun = job.stdout_hit.load(Ordering::SeqCst) || job.stderr_hit.load(Ordering::SeqCst);
    let child = job.child.as_mut().expect("running job owns its child");
    let status = if overrun {
        kill_and_wait(child)?;
        child
            .try_wait()
            .map_err(scope_backend)?
            .expect("killed child reaps")
    } else {
        match child.try_wait().map_err(scope_backend)? {
            None => return Ok(true),
            Some(status) => status,
        }
    };
    let stdout_reader = job.stdout_reader.take().expect("readers join once");
    let stderr_reader = job.stderr_reader.take().expect("readers join once");
    let (stdout, stderr) = join_readers(stdout_reader, stderr_reader)?;
    // Stdout is cap-enforced but discarded: object files are the output
    // channel, and the diagnostic carries the header plus stderr only.
    drop(stdout.data);
    job.state = DirectState::Reaped {
        status,
        stdout_overrun: stdout.overrun,
        stderr_overrun: stderr.overrun,
        stderr: stderr.data,
        read_error: stdout.read_error || stderr.read_error,
        sampled_size: None,
    };
    Ok(false)
}

/// Report the exit of a reaped job once its object is stat-stable. The
/// diagnostic is a fixed header (scope, exit, tool pin, loaded LLVM,
/// overrun) plus stderr truncated to the output cap; stdout is enforced
/// but discarded because object files are the output channel. Objects are
/// claimed only with trusted capture and a present regular file.
fn stabilize(job: &mut DirectJob) -> ScopePoll {
    use std::os::unix::process::ExitStatusExt as _;
    let DirectState::Reaped {
        status,
        stdout_overrun,
        stderr_overrun,
        stderr,
        read_error,
        sampled_size,
    } = &mut job.state
    else {
        return ScopePoll::Running;
    };
    let current = std::fs::metadata(&job.output_object)
        .ok()
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len());
    // A present file counts only when it is stat-stable across two polls.
    match sampled_size {
        None => {
            *sampled_size = Some(current);
            return ScopePoll::Running;
        }
        Some(last) if *last == current => {}
        Some(last) => {
            *last = current;
            return ScopePoll::Running;
        }
    }
    let exit = match (status.code(), status.signal()) {
        (Some(code), _) => BuildExit::Exited(code),
        (None, Some(signal)) => BuildExit::Signaled(signal),
        (None, None) => {
            return ScopePoll::Unresolved(OperationError::new(
                ErrorKind::Backend,
                Stage::Execute,
                None,
                Some(Box::new(ScopeDetail("undecodable child status"))),
            ));
        }
    };
    let overrun = if *stdout_overrun {
        "stdout"
    } else if *stderr_overrun {
        "stderr"
    } else {
        "none"
    };
    let trusted = !*stdout_overrun && !*stderr_overrun && !*read_error;
    let objects = if trusted && current.is_some() {
        vec![job.output_object.clone()]
    } else {
        Vec::new()
    };
    let mut diagnostic = format!(
        "direct-no-children-v1 exit={exit:?} tool={} loaded_llvm={} overrun={overrun}\n",
        job.tool_pin, job.loaded_llvm_hex
    )
    .into_bytes();
    let keep = stderr.len().min(job.max_output_bytes);
    diagnostic.extend_from_slice(&stderr[..keep]);
    ScopePoll::Settled {
        exit,
        objects,
        diagnostic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_layout_kills_listed_calls_and_allows_rest() {
        #[cfg(target_arch = "x86_64")]
        let arch = AUDIT_ARCH_X86_64;
        #[cfg(target_arch = "aarch64")]
        let arch = AUDIT_ARCH_AARCH64;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let arch = 0u32;
        let mut out = [SockFilter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        }; MAX_FILTER];
        let kills = [56u32, 57, 435];
        let len = build_filter(arch, &kills, &mut out);
        assert_eq!(len, 3 + kills.len() + 2);
        // Load arch, then a check that falls through to the nr load on match
        // and jumps to the kill tail on mismatch.
        assert_eq!((out[0].code, out[0].k), (BPF_LOAD_ABS, SECCOMP_DATA_ARCH));
        assert_eq!(out[1].code, BPF_JEQ_K);
        assert_eq!(out[1].k, arch);
        assert_eq!(out[1].jt, 0);
        assert_eq!(usize::from(out[1].jf), len - 2 - 1);
        assert_eq!((out[2].code, out[2].k), (BPF_LOAD_ABS, SECCOMP_DATA_NR));
        // Each kill check jumps to the kill tail on match.
        for (index, nr) in kills.iter().enumerate() {
            let at = 3 + index;
            assert_eq!((out[at].code, out[at].k), (BPF_JEQ_K, *nr));
            assert_eq!(usize::from(out[at].jt), len - at - 2);
            assert_eq!(out[at].jf, 0);
        }
        assert_eq!(
            (out[len - 2].code, out[len - 2].k),
            (BPF_RET_K, SECCOMP_RET_ALLOW)
        );
        assert_eq!(
            (out[len - 1].code, out[len - 1].k),
            (BPF_RET_K, SECCOMP_RET_KILL_PROCESS)
        );
    }

    #[test]
    fn audit_shapes_match_direct_profile() {
        assert!(valid_target("bpfel-unknown-none"));
        assert!(!valid_target(""));
        assert!(!valid_target("bpf el"));
        assert!(!valid_target("a;b"));
        assert!(valid_feature("+v4"));
        assert!(valid_feature("-y"));
        assert!(valid_feature("ok_feat"));
        assert!(!valid_feature(""));
        assert!(!valid_feature("@resp"));
        assert!(!valid_feature("bad feat"));
        assert!(!valid_feature("a;b"));
    }

    #[test]
    fn request_new_leaves_profile_open() {
        let request = BuildRequest::new(
            PathBuf::from("src"),
            PathBuf::from("out"),
            "t".to_owned(),
            Instant::now(),
            1,
            2,
        );
        assert!(request.cpu.is_none());
        assert!(request.features.is_empty());
        assert!(request.environment.is_empty());
    }
}
