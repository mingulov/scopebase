# scopebase-linux

ScopeBase `0.1.0` supplies retained readable regular-file acquisition and descriptor stat observations on Linux. This includes LX02 acquisition, LX04 cooperative control primitives and LX03 bounded positional reads. Mapping association, process APIs, developer conformance adapters, installed operator clients and supported conformance profiles remain later work.

```rust
use scopebase_linux::file::{HeldFile, ProcFdResolver, SymlinkPolicy};
use std::path::Path;
let resolver = ProcFdResolver::open_self()?;
let held = HeldFile::open(Path::new("input"), &resolver, SymlinkPolicy::Follow)?;
let observation = held.stat()?;
# Ok::<(), scopebase_linux::error::LinuxError>(())
```

`open` first pins an O_PATH descriptor and rejects a nonregular object before a data open. It reopens through a retained validated proc-FD directory, compares both raw device and inode while both descriptors remain live, then retains the readable owner. It never falls back to the original pathname or retries. `RejectFinal` refuses only the final symlink; intermediate symlinks still resolve normally. Raw Unix path bytes must be nonempty, at most 4095 bytes, and contain no NUL. Non-UTF8 paths are supported; kernel component and resolution limits still apply.

`ProcFdResolver::open_self` checks procfs type, canonical own-PID links and resolution of a fresh anonymous pipe created after directory acquisition. It supports ordinary threads sharing the creating process's FD table, with main-thread proc entries available. Recreate after a context transition. Fork-without-exec reuse, private/unshared tables, coherent hostile descriptor/mount substitution and malicious kernels are unsupported. The PID check is defensive. A retained directory remains in use across ordinary replacement of the ambient `/proc` pathname. This check is not universal namespace attestation or a uniqueness guarantee for stat identities.

`HeldFile::from_file` consumes exactly the submitted readable regular `File`. It never dupes, reopens, seeks or changes status flags. Every refusal returns that original owner in `AdoptFileError.file`. Admission establishes CLOEXEC; refusals distinguish a set that was not attempted from Unchanged/CloexecSet/Unknown after one failed-set verification and preserves the primary errno without rollback or retry. Earlier inheritance exposure of a submitted non-CLOEXEC FD is not retroactively removed. Library-created descriptors have atomic CLOEXEC.

Share owners with `Arc`. `AsFd` lends integration access; deliberate close, flag changes and other mutating syscalls through a borrow invalidate affected guarantees. Stat getters describe the held descriptor, including signed seconds, without proving immutable content, mapping identity or an atomic snapshot. Observations cannot construct owners. Debug uses fixed owner/observation labels; error Display and Debug are silent, ASCII and bounded to 256 bytes, with no paths, payload, raw owner fields or source-error text. Opt-in getters expose errno and observations.

Failures report stage/reason, actual primary `io::Error`, operation effects and incurred syscall/FD charges. Successful predicates that later refuse remain charged. Pipe creation counts one syscall and two FDs; PID queries count operations but no explicit syscall. RAII close is excluded. `Complete` cleanup records release of temporary owners, without claiming observed close or backend retirement success. Acquisition and stat do not read target content. Explicit positional reads are described below. No mapping, hidden thread, process-global policy change, hard syscall/Drop time or RSS bound is supplied.

From this package source, run `cargo test --lib`, `cargo test --test held_file`, `cargo test --test traits` and `cargo test --doc`. `cargo build --example fd_probe` builds the single-purpose exec/retirement oracle; setting `SCOPEBASE_EXEC_PROBE` to that executable when running `held_file` uses it directly. Without that override, tests run a single selected fixture in a new test process. `tests/ui/cases.json` binds shipped compile-refusal sources to exact diagnostic code/message/primary line, with a positive source first. The ScopeBase SB02 bounded JSON-diagnostic route executes these against the same archived library/features on both selected compilers. Dependency tests do not automatically run from a downstream client's `cargo test`.

Host target: `x86_64-unknown-linux-gnu`; edition 2021; MSRV 1.88.0. Default host features require no BPF, async runtime or native compiler. Additive `process`, `mapping`, `supervision` and `walk` retain package boundaries; these feature names do not implement their future APIs. Rustix 1.1.5 uses only `std`, `fs`, `pipe`. Apache-2.0 project source and explicit third-party options/notices are distinct.

Selected source preservation: P at `2c2713e66292b0d2688508a25f79e813ae823d81`, `crates/manifest/src/identity.rs::open_regular` and `src/discovery/identity.rs::{Pin,pin_of,pin_from_metadata,open_view_object_cached}`; O at `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`, `src/plan.rs::{PinnedFile,resolve_pinned,resolve_pinned_retry}` and `tests/count_deadline.rs` retention/replacement regressions. Historical source headers were GPL-3.0-or-later. The owner's D03 grant authorizes Apache-2.0 for these selected host adaptations; observed author attribution includes Denis Mingulov and the owner-authorized `osslscope-dev` automation alias. Existing third-party dependency terms remain in the notices. Resolver/adoption/error wrappers are new narrow mechanisms absent from those selected slices.

| Original regression | Preserved acquisition behavior |
| --- | --- |
| P `retained_view_object_open_rejects_a_fifo_without_data_open` | Public FIFO refusal plus private operation-order trace |
| P `retained_mapped_identity_keeps_the_original_file_and_rejects_changes` | Distinct same-bytes inodes, original Arc lifetime and descriptor stat after truncate/replacement; mapping proof remains LX06 |
| O `resolve_pinned_stats_the_open_file` | Independent `MetadataExt` descriptor oracle and missing-input errno |
| O `h4_t1_mid_attach_swap_binds_pinned_inode_via_fd_path` | A barrier confirms B installation before retained reopen; separate complete A→B→A and unlink-before-reopen populations |
| O `h4_t3_pin_survives_path_deletion_until_session_drop` | Unlink retention, Arc sharing and single-purpose exact-slot retirement with a live alias; attachment retirement remains BP04/MG02 |
| O `h4_t2_pin_open_retries_bounded_then_fails` | Its bounded 1/2/3-attempt, last-error retry remains O application policy; ScopeBase makes one attempt and preserves the first errno |

Real host fixtures, model conversion/fault seams, actual compiler diagnostics and later kernel/installed/profile qualification are separate evidence tiers. Acquisition success does not qualify `held-file-v1` or `mapped-image-v1`.

`control::{CancelToken, MonotonicDeadline, OperationControl}` provides explicit
shared cancellation and opaque process-local absolute deadlines. Clone shares
the token and copies the deadline; dropping a handle never resets or signals it.
`OperationControl::new` consumes a token handle, so clone first to retain the
ability to cancel. `unlimited` has a fresh token and no deadline; operation
numeric/resource limits still apply. These primitives add no control argument
to the existing acquisition APIs.

```rust
use scopebase_linux::control::{CancelToken, MonotonicDeadline, OperationControl};
use std::time::Duration;
let token = CancelToken::new();
let deadline = MonotonicDeadline::after(Duration::from_secs(1))?;
let control = OperationControl::new(Some(deadline), token.clone());
token.cancel();
# Ok::<(), scopebase_linux::error::LinuxError>(())
```

A deadline uses one `Instant::now` and checked addition. Zero duration is valid
and expired at equality. Overflow returns `ConfigureControl / InvalidInput`,
with no source, zero effects/charges, cleanup `NotNeeded` and descriptor flags
`NotAttempted`. There is no raw timestamp/Instant conversion or public clock
injection. The clock domain follows platform `Instant`, including its suspension
behavior; it promises no CLOCK_BOOTTIME or wall-clock equivalence.

The private operation checkpoint checks cancellation first, querying the clock
only for an uncancelled deadline. Generic controls have no shared first-stop
latch: separate invocations observe the current reason. A collection adapter
owns any collection-wide terminal policy. Cancellation after the final atomic
load can coexist with success and is observed at a later checkpoint. The token
uses Release/Acquire but supplies no arbitrary application-data publication,
fairness or notification-latency guarantee.

Operation owners check before effects and publication, record successful effects
and incurred charges before post-call checks, and preserve actual syscall errors
as primary even when cancellation races. The consuming private error bridge
moves actual metadata unchanged; it never refunds work or invents cleanup.
Cancellation discards unpublished payload while the owner retains resources
through its own cleanup/partial-effect protocol. The control owns no worker and
cannot interrupt an inner blocking read, open, close or other syscall, nor prove
retirement. It performs no explicit I/O, allocation, sleep, lock or background
work at checkpoints; `Instant::now` may enter the kernel and has no hard duration
bound. Clock/configuration queries are excluded from operational syscall charges.
Token construction has ordinary allocator failure/abort limitations. Control
Drop releases only Rust handles and supplies no wait/kill/reap/unmap/cleanup proof.

Run `cargo test --test controls` and `cargo test --lib` from delivered package
source, along with the acquisition/trait/doctest commands above. Private model
fixtures exercise entry/post-read/publication checks, exact incurred metadata,
clock boundaries, panic/poison and failed-errno precedence. C10's release gate
signals inside its model `Read` method. C11 uses a real UnixStream pre-read
handshake, which does not prove kernel syscall entry. Each blocking fixture uses
an owned outer-watchdog subprocess, releases/joins on success and fails on
watchdog expiry after killing/reaping its exact child. They neither implement
nor qualify HeldFile reads, regular-file blocking, traversal, mapping or native
retirement. Source and archive UI fixtures retain the existing authority negatives
and add controls' private construction/checkpoint, absent clock injection and
numeric-deadline refusals, with a separate positive control client.

LX04 adapts frozen P `inventory_cgroup.rs::CollectionControl` cancellation and
scan read/publication boundaries and O `args.rs::deadline_at` checked addition
and `target.rs::run_under_control` cancellation-first preflight. Captured heads
and historical licenses are the P/O pins above; the owner's Apache-2.0 host
grant covers the explicitly admitted slices. Full P collection latching and
traversal regressions stay with LX10; O abandoned-worker fail-fast behavior stays
application-local. LX03 supplies bounded HeldFile read integration and numerical byte/
work ceilings; LX06/LX09 own unresolved mapping/child custody; LX11/LX12 retain
standalone/installed conformance qualification.


`HeldFile::read_all(ReadLimits, &OperationControl)` reads from offset zero with
positional I/O, preserving the open-description cursor. Callers set separate
input-byte, pread-attempt and payload-capacity ceilings. The operation attempts
one initial-length-plus-one reservation and requests at most 64 KiB per read.
EOF, EINTR and positive sentinel bytes consume their actual work/byte charges;
errors retain historical requested/granted capacity and return no partial bytes.
Allocator overgrant can occur transiently before refusal; this is no hard RSS
or global memory bound. Cooperative cancellation cannot interrupt a blocked
syscall, allocation or scheduling. No FD or mapping is acquired by a read.

A successful `FileRead` shares one immutable payload across clones, including
after the original `HeldFile` is dropped. Equal before/after descriptor metadata
only brackets observations: same-size writes can evade detection or tear content,
so `ContentSnapshot::NotProven` is unconditional. No snapshot or mapped-image
proof is created. Full runtime, filesystem, installed/operator and migration
qualification remain later gates.

The package ships `tests/positional_read.rs`, deterministic read-loop regression
fixtures, privacy cases, and independently wired public client sources in
`tests/support/read_{adopted,opened}.rs`. Run package tests explicitly with
`cargo test --locked`; a downstream dependency's tests do not run automatically.

Selected user-owned p11scope and OSSLscope host mechanisms and regression shapes are adapted under the owner-authorized Apache-2.0 destination terms. Their historical GPL-3.0-or-later source labels remain recorded in ScopeBase source-admission and selected-port receipts LX02, LX04 and LX03; the destination grant does not relicense unrelated third-party or kernel/BPF source. LX03 preserves positional/short-read handling, bounded allocation and EOF checks, final-stat raced-read refusal, shared payloads and checked work accounting. Application policies and broader mapped-image behavior remain separate.

## Strict bounded proc observations

`procfs::parse_maps(&[u8], ParseLimits)` and `parse_mountinfo(&[u8], ParseLimits)` validate complete caller-supplied byte snapshots without acquiring files or process authority. All three limits (bytes, entries, line bytes excluding LF) must be nonzero. Empty bytes are valid absence; nonempty inputs require final LF. Every malformed row refuses the entire table, with a one-based `LinuxError::parse_line()` and historical `charges().parse()` counters. Maps are ordered half-open intervals with checked offsets. Raw path bytes, deleted suffixes and ambiguous literal `\012` markers remain descriptive evidence. Maps keys differ from stat keys; matching tuples do not prove physical-file identity.

Mount fields expose raw and single-pass decoded octal bytes; options stay opaque. Entries retain input order with logarithmic numeric lookup and duplicate refusal. `ParsedMountId` equality requires the same borrowed table object and number; it conveys no runtime namespace/view identity. Snapshots are immutable, Send + Sync, and deliberately have no allocating Clone.

Parsing uses two/four fallible exact vector reserves after shape validation, bounded accepted logical capacities and O(bytes) / O(bytes + entries log entries) work. Allocator overgrant refuses with historical peak capacity charged. Input storage, allocator overhead, RSS and elapsed time are separate; no hard runtime bound is promised. Existing file/read/control behavior is unchanged.

The delivered package includes independent literal fixtures, public/private tests, a maps inventory client and a distinct mount auditor. From a standalone extracted archive (outside repositories or Cargo workspaces), run:

```sh
python3 /absolute/scopebase-linux-0.1.0/tests/support/run_proc_parser_checks.py \
  --package-root /absolute/scopebase-linux-0.1.0 \
  --cargo /absolute/toolchain/bin/cargo \
  --rustc /absolute/toolchain/bin/rustc \
  --rustdoc /absolute/toolchain/bin/rustdoc \
  --cargo-home /absolute/prepared-offline-cargo-home \
  --target-dir /absolute/fresh-target \
  --output-dir /absolute/fresh-results \
  --configuration minimal
```

Python 3.11+ and a prepared offline Cargo closure are required. Configurations are `minimal`, `default`, `union`; tools are explicit, no installation occurs. The helper creates an enclosing resolver-2 workspace and separate clients, freezes locks before offline locked executions, binds metadata/features and compiler diagnostics, and verifies package bytes unchanged. The subject parent must be writable and have no Cargo manifest. Source projections require a bound Linux-only lock prepared from the workspace lock before invocation; do not change an archive's delivered lock/manifest. Results qualify this pure parser increment only, not live filesystem mapping support or a runtime conformance profile.
