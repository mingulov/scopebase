# ScopeBase Linux Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver independently usable ScopeBase Linux file/mapping/process components, shipped conformance and two real standalone clients, while preserving an explicit later product-migration handoff.

**Architecture:** `scopebase-linux` keeps retained Linux authority separate from typed observations and reports. Positional reads, strict proc views, per-range mapping evidence and optional child supervision/walking share explicit resource/error contracts but have independently qualified profiles. Distributed clients exercise public production APIs through the common testkit; donor products need no edits for package readiness.

**Tech Stack:** Rust edition 2021; proposed MSRV 1.88.0 qualified by SB02; Linux x86_64 GNU; existing descriptor/syscall/procfs/path libraries where they meet the contract; no BPF dependency or compiler in host builds.

**Spec:** [ScopeBase Linux design](../specs/2026-10-17-scopebase-linux-design.md).

## Global Constraints

- Follow the [decision register](../specs/2026-10-18-scopebase-decisions.md) and [executor contract](../specs/2026-10-18-scopebase-executor-contract.md). The [task-origin routes and concrete repair packets](2026-10-18-scopebase-plan-repair.md#task-origins-and-decision-routes) supplement this task; broad source groups are not dispatch-ready source selections.
- PORT/ADAPT preserves the identified donor mechanism, affected call sites, original regression, independent oracle and bad control together. NEW requires the recorded missing-mechanism reason and frozen design. Unresolved architecture, source, license, support or expected-result choices return NEEDS_DECISION; no fresh approximation or weaker gate.
- Apply provisional Apache-2.0 userspace / GPL-2.0-only BPF / GPL-3.0-or-later application terms and the shared-source/third-party rules in D03–D04. Keep source SPDX, author authorization, actual target input option and kernel runtime declaration distinct.

- Initial package version is 0.1.0. Rust edition 2021 and proposed host MSRV 1.88.0 are subject to foundation compile qualification. User-owned userspace code follows the provisional Apache-2.0 policy in D03; historical donor SPDX and authorized destination terms remain distinct, with actual third-party terms retained.
- Initial runtime qualification targets `x86_64-unknown-linux-gnu`; other targets are unsupported until added to the matrix with build and runtime evidence.
- The named host qualification cells are Linux 5.15, Linux 6.12 and a pinned current control selected by SB02 before qualification; they do not establish a universal BPF floor.
- `scopebase-linux` is a Linux-only Rust package. Its host-only default has no BPF, Aya, libbpf, LLVM, native-compiler, async-runtime or donor-application dependency.
- No tools, host privileges, credentials, limits, signals, mounts or namespaces change implicitly. Research donor workspaces remain read-only.
- Every command below is a future implementation/verification command; none is runnable or passing as a result of writing this plan.
- Package qualification uses real standalone independently wired clients; p11scope/OSSLscope integration remains MG01/MG02 work in the master plan.
- Required fixture/profile selection precedes environment discovery; denied/missing required branches remain incomplete.
- No Cargo-heavy or privileged lane runs concurrently without its named environment/build owner; one writer owns each source set.

## Review Focus

- Shared nonzero cursor plus aliased open descriptions must still return complete offset-zero bytes without moving either cursor (LX03).
- A transient target-backed mmap during an error or retained-proof branch must fail no-new mode even if final maps are unchanged (LX07).
- Two genuinely different Btrfs objects with equal raw maps keys must not receive ExactRange merely from calibration (LX06–LX07).
- Cancellation after SIGCONT succeeds but before result delivery must expose released child custody and forbid a duplicate release (LX09).
- An inherited/changed mount table or exec interval must not turn old proof into current-image authority (LX06/LX08).

---

## File map, dependencies and parallel ownership

All paths below are future outputs unless already linked as research/specification. SB02 established the empty root Cargo workspace and dependency policy. The controller now serializes root workspace/lock/dependency changes across component owners; each LX owner owns its declared package files. TT owns fixture sources/provisioners/runner/schema. Linux case oracles below are Linux-owned wrappers and expectations, not another fixture worker.

| File set | Responsibility / sole writer |
|---|---|
| `crates/scopebase-linux/{Cargo.toml,src/lib.rs}` | LX01 package/feature boundary; coordinate root manifest with SB02 |
| `crates/scopebase-linux/src/{error.rs,identity.rs}` | LX02 common Linux error and observation types; later additions serialized by this owner |
| `crates/scopebase-linux/src/file/{mod.rs,held.rs,read.rs}` | LX02 acquisition and LX03 read implementation, disjoint files |
| `crates/scopebase-linux/src/control.rs` | LX04 cancellation/deadline primitives |
| `crates/scopebase-linux/src/procfs/{mod.rs,maps.rs,mountinfo.rs}` | LX05 strict bounded parsers |
| `crates/scopebase-linux/src/process/{mod.rs,observation.rs,epoch.rs}` | LX08 process observation and epoch |
| `crates/scopebase-linux/src/mapping/{mod.rs,proof.rs,calibration.rs,custody.rs,pool.rs}` | LX06 mapping evidence, effects and retirement |
| `crates/scopebase-linux/src/process/{supervisor.rs,pool.rs,child.rs,helper_protocol.rs}` | LX09 optional child authority; helper executable source belongs to TT03, protocol reviewed jointly |
| `crates/scopebase-linux/src/walk.rs` | LX10 traversal budgets |
| `crates/scopebase-linux/tests/{held_file.rs,positional_read.rs,controls.rs,proc_parsers.rs,process_observation.rs,mapping_contract.rs,mapping_linux.rs,supervision.rs,walk.rs,traits.rs}` | Named LX task tests; each task owns its listed file |
| `crates/scopebase-linux/tests/ui/` | LX02 forged authority/borrow misuse and LX08 observation-control rejection compile-fail cases; serialize additions |
| `crates/scopebase-linux/conformance/{mod.rs,held.rs,mapping.rs,process.rs}` | LX11 development/example adapter source, packaged as examples/test support rather than production dependency |
| `examples/held-file-inspector/` | LX11 first independent real client and lockfile |
| `tests/downstream/linux-adapter/` | LX11 second independent real client and lockfile |
| `docs/components/scopebase-linux/{contract.md,source-register.md,qualification.md,migration-handoff.md}` | LX01/LX12/LX13 component contract, source lineage, results and later migration packet |
| `fuzz/scopebase-linux/{Cargo.toml,fuzz_targets/}` | LX05 bounded parser and LX06 history fuzz targets; coordinate a single writer |

DAG: SB01/SB02 → LX01 → LX02 → LX03; LX01 → LX04; LX02 → LX05 → LX08; LX02/LX04/LX05/LX08 → LX06 → LX07; LX04/LX08/TT03 → LX09; LX02/LX04 → LX10; LX02–LX10 + TT01–TT04 → LX11; LX11 + TT06–TT10 + SB03 → LX12. LX13 consumes selected interfaces and later feeds MG01/MG02 without gating LX12. A held-file-only readiness review uses only its applicable dependencies and cannot mark mapped-image ready.

Safe parallel lanes after LX02 freeze: LX03 read, LX04 controls, LX05 parser. LX08 follows LX05; LX06 follows LX08. LX09 helper and LX10 traversal may proceed beside LX06 in disjoint files after their inputs freeze. LX07 real filesystem work and LX09 actual child runs serialize shared privileged resources through TT. LX11 clients can be prepared separately but do not qualify a stub. Review interface changes with dependent owners before mutation; do not concurrently edit error.rs, identity.rs, module export files or manifests.

## LX01: Foundation choices and selected donor contract register

**Requirements:** LX-R01/LX-R22. **TODO:** L01, F01–F03, G19/G20. **Depends:** SB01/SB02.

**Files:** Create package boundary/manifest, `src/lib.rs`, `docs/components/scopebase-linux/{contract.md,source-register.md}`. Tests: `tests/traits.rs` and SB02 external feature workspace.

**Interfaces:** consumes SB02 pinned workspace dependency/MSRV policy; produces crate `scopebase_linux` and additive features `process`, `mapping`, `supervision`, `walk`, with default `[]`; mapping and supervision each enable process observation and no BPF dependency. Held-file API lives in default feature. Public upstream handle types do not escape except stable std OwnedFd/BorrowedFd/File/Path types.

- [ ] Select the relevant captured donor files from the completed private snapshots: P `crates/manifest/src/{identity.rs,maps.rs}`, `src/{process.rs,pidns.rs}`, `src/discovery/identity.rs`; O `src/{pin.rs,plan.rs,target.rs}` and relevant tests. Preserve historical pins, captured worktree/WIP mappings, exact selected-file hashes and author/license/regression provenance. Do not refresh live heads; use each snapshot's explicit history and gitless-checkout mapping.
- [ ] Consume the accepted SB02 syscall/ELF/procfs comparisons and exact versions. Keep rustix-process with LX08, object/goblin with TC05/TC06 (LX13 retains local ELF/export/cache boundaries), and procfs with LX04/LX05/LX08. Evaluate cap-std/pathrs at the first actual confined traversal consumer, normally LX10. Mapping proof remains LX06 and real filesystem cases LX07/TT03/TT04. Implement no new generic syscall/proc/path framework.
- [ ] Create a failing external compile case importing only `scopebase_linux` with no-default features, and an additive feature-union case combining mapping/supervision/walk without BPF tools in PATH. Expected initial failure is missing package; after this boundary step only crate import/features must pass. Do not export a placeholder HeldFile or no-op behavior: LX02 introduces the real authority type with its implementation and tests.
- [ ] Add package docs stating profile boundaries, prospective MSRV and unsupported targets; verify `cargo check -p scopebase-linux --no-default-features` and SB02 feature-union build. Inspect dependency tree for BPF/compiler/build-script leakage.
- [ ] Record scoped result, review source/licensing, and commit this task's package boundary and register; do not describe it as implemented file behavior.

## LX02: Held regular-file authority, errors and encapsulation

**Requirements:** LX-R02/LX-R05/LX-R06/LX-R15/LX-R21. **TODO:** L02–L03, G02/G03/G06/G09–G11/G18/G22; H04/H06, UC01/UC08/UC10–UC11. **Depends:** LX01.

**Files:** Create `src/file/{mod.rs,held.rs}`, `src/{error.rs,identity.rs}`, `tests/held_file.rs`, authority UI cases; extend `tests/traits.rs`. Export required modules in `src/lib.rs` serially.

**Interfaces:** produces the file signatures and exact stat/error/effect/charge getters in the [Linux file contract](../specs/2026-10-17-scopebase-linux-design.md#public-file-interfaces), [stat handoff](../specs/2026-10-17-scopebase-linux-design.md#lx02-stat-observations) and [interface registry](../../contracts/interfaces.md#held-file). No read/control/future identity or cleanup placeholder is exported. Acquisition acceptance is not held-file-v1 readiness.

**WHAT/WHY:** ADAPT P O_PATH-before-data-open/type gate and O opened-file/retained-owner behavior and original regressions. NEW bounded retained resolver/adoption/error wrappers fill mechanisms absent from those source slices. Procfs type and inherited-directory parity do not prove own descriptor context; use the specified fresh-pipe check with explicit support limits. Do not replace source mechanisms, add a generic runtime/calibration framework, or silently retry through a pathname. O bounded retry/last-error behavior remains O application policy. Existing D03 authorization covers selected project-owned automation-alias regression lines; preserve historical attribution and actual third-party terms separately.

**Dispatch inputs:** controller binds completed frozen P/O snapshot/history/gitless-checkout mappings, exact selected slices/bytes/adoption records, accepted SB02/LX01 artifacts, rustix 1.1.5 `std,fs,pipe` feature/notice/lock policy and focused pipe/readlink/fstatfs/access-mode API trials. No live donor refresh. Controller binds actual SB02 UI/mutant runner invocation/hash, isolated Cargo/target/result paths and build lease; missing bindings are not permission to invent a harness. Shared exports/manifests/lock/package policy/archive allowlists/spec/provenance/ledger edits remain controller-serialized.

- [ ] Preserve original P FIFO refusal and retained-owner/same-bytes-different-inode cases; O opened-file stat, missing-input, mid-attach pathname replacement and unlink/retention cases remain distinct. Add full A→B→A and unlink-before-reopen populations, without describing O's original replacement-only test as full ABA. Backend retirement/installed_at remain BP04/MG02; content/mapping proof remains LX03/LX06.
- [ ] Add public `open_holds_a_through_a_b_a_and_unlink`, `rejects_fifo_before_read_open`, `resolver_denial_never_reopens_path`, `adopt_error_returns_original_file`, `reject_final_differs_from_follow`, `stat_tracks_held_descriptor`, `cloexec_survives_exec_fixture`, `debug_escapes_without_payload` and retention/Send+Sync tests. Independently create distinct live A/B identities and payloads. A private post-O_PATH barrier acknowledges B installation before reopening A; restore A and separately unlink. Assert exact key/payload/errno and original owner, not net FD counts.
- [ ] Add resolver current-proc/shared-thread positives, non-proc/foreign-PID-view refusals, and a real child FD-table negative established before the new pipe. A private phase seam supplies the child's actual proc-fd directory; independently verify its slot absent or distinct. Demonstrate inherited-directory parity's blind spot with inherited real directories and the fresh-pipe check's refusal; parent's directory is the valid twin. Do not call injected validation a public overmount test. Include pipe denial/exhaustion, fstat/check-open/check-stat failure, FIFO/key mismatch and cleanup at each step. Coherent hostile substitution remains unsupported; real mount/namespace cells remain later qualification.
- [ ] Keep per-invocation failure/checkpoint seams cfg(test) inside held.rs, around the same algorithm, with no mutable global hook/public backend trait/injection feature or production callback. Real owners retain custody; pure synthetic metadata yields model outcomes, never live authority. Effect-then-error tests perform the real owned effect. Public integration tests use only shipped APIs; use barriers, not sleeps.
- [ ] Add private failure-prefix accounting tests: resolver success 11 explicit calls/13 operations/6 acquired FDs/peak4/final1; file open 4/5/2/peak2/final1; stat one call/no new FD; adoption three/four calls/no new FD. Pipe2 is one operation/two FDs, successful-predicate-refusal remains charged, PID queries are not explicit syscall charges, RAII closes are excluded, and no spent charge is refunded. Verify exact classifications, primary errno, zero mapping counts and temporary-owner release before returning errors.
- [ ] Adoption tests cover RDONLY/RDWR positives, O_PATH/WRONLY/nonregular refusal and fstat/F_GETFL/F_GETFD/F_SETFD faults. Assert the exact original FD/key returns; shared aliases retain cursor/status; dup descriptor flags stay independent. Test NotAttempted, failed-set unchanged, real set effect then injected error, and failed verification Unknown without replacing primary errno or rollback. Exec helper includes a deliberate non-CLOEXEC canary and checks original FD identities before allocating unrelated FDs. Library-created FDs are atomically CLOEXEC; adopted input has no retroactive inheritance guarantee.
- [ ] Test stat against independent MetadataExt observations, held-A after replacement, in-place truncate, pre-epoch seconds and model conversion boundaries. Test raw paths of 0/1/4095/4096 bytes, embedded NUL and non-UTF8; rejected inputs execute zero operations and admitted paths may still fail kernel limits. Test complete Display/Debug/alternate/nested values <=256 ASCII bytes with malicious long source/path/payload canaries absent and helper stdout/stderr silent; owner/stat Debug is fixed labels only.
- [ ] Compile separate UI clients against the actual package/features with the accepted SB02 JSON-diagnostic route on both bound Rust 1.88.0 and 1.98.1 compilers. Positive twins build first. Private real-field access requires E0616; `needs_clone::<HeldFile/ProcFdResolver>()` requires E0277 (reference clone is legal); into_raw_fd/into_inner calls require E0599; coercion to &File/&mut File requires E0308; owner from observation/key/raw-FD `.into()` requires E0277; drop owner then use AsFd borrow requires E0505. Match expected code and primary marked fixture span. Wrong diagnostics and Cargo/lock/toolchain failures are setup failures, not passing negatives. Bind real private field names, not nonexistent fields. Report unexpected compiler behavior to controller rather than broadening the gate. Ship required UI/support sources through the archive allowlist.
- [ ] Run RED/GREEN behavior checks under the accepted offline/locked inputs and build lease: `cargo +VERSION test --offline --locked -p scopebase-linux --lib`, `--test held_file`, `--test traits`, and `--doc`, separately for VERSION 1.88.0 and 1.98.1. Initial failure must reach the intended missing behavior after valid setup, not a timeout or resolution error. Invoke the bound external UI/package-policy commands, not an invented `--test ui` target.
- [ ] Implement the exact resolver/open/stat/adoption/error/bounds sequences from the spec, preserving original source maps. No target data reads/mappings, helper thread, mount/credential/limit mutation or public raw-key factory. Reject unavailable fresh-pipe validation without fallback. Continue retained-directory lookup across ordinary ambient /proc replacement; do not claim universal namespace-change detection.
- [ ] Execute semantic wrong controls and restored twins: pathname fallback must acquire B and fail retained-A assertions; early drop must fail actual retained access; FIFO data-open uses NONBLOCK so it fails forbidden-operation ordering rather than timing out; bypassed resolver check must accept the validly arranged wrong table and fail refusal; retry mutant fails first-error/one-attempt contract; inode-only/path-stat mutant fails independent key/stat truth; owner dup/reopen/status/seek mutation fails exact ownership/cursor assertions; false-Unchanged fails changed/unknown effect checks; cleared-CLOEXEC fails exec identity checks; raw/derived Debug leaks a canary; exposing forbidden API makes its UI negative unexpectedly compile. Every control needs valid setup and intended semantic failure; preserve separate model versus real-kernel tiers.
- [ ] Rerun affected package feature/import/union/archive/notice checks, independently review source preservation, FD/effect/count/error paths and UI controls, and record acquisition-only acceptance. Required unavailable cells remain incomplete. No profile, installed-consumer or live attachment readiness is inferred; retain LX03/LX04/LX11/LX12 and BP04 obligations. Commit only the owned implementation and coordinated amendments.

## LX03: Positional full reads and explicit memory/work accounting

**Requirements:** LX-R03/LX-R04/LX-R11/LX-R15. **TODO:** L03, G01/G04/G05/G10/G18; H06, UC01/UC09/UC13. **Depends:** LX02; LX04 control primitive interface may be stubbed only in the test-first stage.

**Files:** Create `src/file/read.rs`, `tests/positional_read.rs`; extend private FileRead/ReadLimits exports in file/mod.rs.

**Interfaces:** `HeldFile::read_all(&self, ReadLimits, &OperationControl) -> Result<FileRead,LinuxError>`. ReadLimits has max_bytes:u64, max_read_calls:u64, max_buffer_capacity:usize. FileRead privately owns Arc<Vec<u8>>, exposes bytes/observations/charges, and Clone shares allocation.

- [ ] Add failing `shared_cursor_does_not_create_suffix_success`: write independently known `0123456789`, seek a submitted File to 4, dup its description, interleave reads through the alias and read_all; assert returned bytes are all ten bytes and the package has not moved the shared cursor. Include two concurrent positional readers.
- [ ] Add cap N/N+1, empty EOF, premature zero, short reads, EINTR work exhaustion, huge advertised size, usize/u64 addition overflow, growth/truncation barriers, metadata change, same-size/restored-mtime limitation and clone-accounting tests. Assert no allocation from untrusted length before validation; no partial bytes on failure; no false immutable-snapshot claim.
- [ ] Run `cargo test -p scopebase-linux --test positional_read`; demonstrate current-cursor mutant returns suffix and fails complete-byte assertion while setup succeeds. Demonstrate removed final-stat and oversize-sentinel mutants fail intended change/bound assertions.
- [ ] Implement bounded pread loop, max 64 KiB call size, mandatory EOF probe, exact requested reservation strategy and `try_reserve_exact` error path. Count all attempts including EINTR; validate before allocating and carry consumed charges on errors. Record requested, allocator-granted and retained capacities separately, with no process-RSS/OOM recovery promise.
- [ ] Run the target and allocation-accounting controls under small budgets. Assert cloned results share the payload pointer and no Vec→Arc slice copy occurs; concurrent reads preserve cursor semantics. Review and commit.

## LX04: Cooperative deadline/cancellation and structured effect handling

**Requirements:** LX-R04/LX-R05/LX-R14/LX-R15. **TODO:** G03–G05/G07/G09/G17/G18. **Depends:** LX01; error additions serialize with LX02.

**Files:** Create `src/control.rs`, private `src/control/tests.rs`, and external `tests/controls.rs`; add per-invocation deterministic seams only under test configuration. Serialize `src/error.rs`/`src/lib.rs` with accepted LX02; preserve all existing acquisition signatures and getters.

**Interfaces:** `CancelToken::{new,cancel}`, `OperationControl::{unlimited,new(Option<MonotonicDeadline>,CancelToken)}`, `MonotonicDeadline::after(Duration)->Result<Self,LinuxError>`. Produces a private checkpoint helper and consuming stop-to-LinuxError context bridge used by reads/mapping/supervision/walk; it never owns an abandonment worker. Clone shares cancellation and copies the absolute deadline, without generic shared first-stop state. The collection adapter owns any shared first-reason policy. Constructor overflow uses implemented ConfigureControl/InvalidInput; a failed syscall preserves its actual primary errno ahead of concurrent cancellation. Successful work records charges/effects before post-call cancellation/deadline checks.

- [ ] Add failing deadline-at-equality, checked-add overflow, cancel-before-first-effect, cancel-after-read-before-publication and racing-cancel tests. Independent operation ledger asserts completed effects/charged calls remain visible even when bytes are discarded.
- [ ] Add `blocked_inner_read_is_not_claimed_interrupted`: a model source signals that it entered the actual blocking read, then a controller cancels; assert the synchronous call remains pending until the fixture releases it and then returns Cancelled with charges. Run this fixture in an owned outer-watchdog subprocess so the test cannot strand CI.
- [ ] Run `cargo test -p scopebase-linux --lib` for private checkpoint/seam behavior and `cargo test -p scopebase-linux --test controls` for external constructors/traits, expecting missing primitive/incorrect result failures; implement checkpoints and typed monotonic deadline without wall-clock/kernel-time comparison or async runtime.
- [ ] Run clock-jump/domain-offset model cases, callback-panic/poison controls at the development seam and the target. Document no hard syscall/open/close deadline and ordinary abort limits. Restore a valid control after cancellation/charge-erasure mutants. Run source and actual packaged-source tests on Rust 1.88.0 and 1.98.1 with no-default/default/supported-union features, exact package inventory and compiler-refusal controls. Private operation fixtures do not implement or qualify HeldFile reads, collection traversal or native retirement; LX03/LX06/LX09/LX10 retain those integration gates. Commit.

## LX05: Strict bounded maps/mount observations

**Requirements:** LX-R07/LX-R11. **TODO:** L01/L02/L04, G04/G12/G18; H02/H05/H06, UC02/UC05. **Depends:** LX02.

**Files:** Create `src/procfs/{mod.rs,maps.rs,mountinfo.rs}`, `tests/proc_parsers.rs`, `fuzz/scopebase-linux/fuzz_targets/{maps.rs,mountinfo.rs}`.

**Interfaces:** `parse_maps(&[u8],ParseLimits)->Result<MapsSnapshot,LinuxError>` and `parse_mountinfo(&[u8],ParseLimits)->Result<MountTableSnapshot,LinuxError>`. ParseLimits has byte/entry/line ceilings. Parsed snapshots are descriptive observations; no parser constructs retained proof, process authority or file owner.

- [ ] Add failing raw-byte fixtures with paths containing spaces, non-UTF8, parentheses, escaped mount fields and deleted suffix. Assert maps ordering/nonoverlap, valid absence versus malformed, exact offset arithmetic and mount-ID view tagging; keys of different domains do not compare through the public API.
- [ ] Add max bytes/lines/entries N/N+1, invalid numeric/escape fields, duplicate mount IDs, unterminated input, integer overflow and resource-accounting tests. Compare against a tiny independently authored interval/field reference, not production reserialization.
- [ ] Run `cargo test -p scopebase-linux --test proc_parsers`; implement the selected upstream parser adapter or narrow missing parsing layer without unbounded collect/sort/allocation.
- [ ] Run target plus a fixed 10,000-input bounded fuzz campaign for each target (`cargo fuzz run maps -- -runs=10000`, `cargo fuzz run mountinfo -- -runs=10000` from `fuzz/scopebase-linux`, only with explicitly provided cargo-fuzz). Minimize failures into deterministic cases. Domain-cast/overlap-acceptance mutants must fail the semantic assertion, then valid twin passes; commit.

## LX06: Mapping relations, explicit calibration and retained custody

**Requirements:** LX-R07–LX-R11/LX-R14. **TODO:** L04/U01–U02, G02/G03/G06–G12/G18; H04/H05/H19, UC02–UC11. **Depends:** LX02/LX04/LX05/LX08.

**Files:** Create `src/mapping/{mod.rs,proof.rs,calibration.rs,custody.rs,pool.rs}`, `tests/mapping_contract.rs`; add mapping-history fuzz target in the serialized fuzz lane.

**Interfaces:** `observe_mapping(MappingRequest<'_>,&OperationControl)->Result<MappingOutcome,MappingFailure>`; MappingPolicy variants NoNewTargetMappings and AllowPrivateCalibration{max_mapped_bytes}; outcomes ExactRange(MapRangeProof), KeyCompatible(MappingProof), Mismatch and Inconclusive. Proof owns Arc<HeldFile>; MappingFailure retains optional MappingCustody. MappingRequest.pool borrows an explicit `MappingPool`; `MappingPool::new(MappingPoolLimits)->Result<Self,LinuxError>` creates a caller-owned domain, Clone shares it, and status/retry_unresolved/close expose occupied permits and reconciliation. close returns the pool in MappingPoolCloseFailure until zero owners; Closing/Closed blocks admission across clones. Exact API data definitions are in the spec.

- [ ] Add failing table/model tests for stat/maps/mount domain mismatch, equal raw key on distinct objects, wrong mount view, stale/foreign epoch/proof, empty file, fstatfs failure, proc denial, map/read/unmap failure, cap exhaustion, changed metadata and overlapping calibration admission. Verify raw-key and content equality can at most yield KeyCompatible.
- [ ] Write the exact-range test oracle using an independently acquired actual map_files descriptor and held A/B descriptors. If that descriptor cannot be obtained/comparably identified, require Inconclusive/KeyCompatible, never ExactRange. Bracket birth/view/range reads and explicitly report no atomic-current-mm guarantee.
- [ ] Run `cargo test -p scopebase-linux --features mapping --test mapping_contract`; implement map-files association, one-refresh mount lookup, ext4-only eligible retained-key reuse and no-new branch with zero target mmap calls.
- [ ] Implement explicit one-page private PROT_READ calibration with bounded proc reads, observed address-containing line, no executable mapping and fallible unmap custody. Successful key calibration establishes only the key relation. Preallocate the caller-owned pool slots and reserve mapping/page-rounded-byte permits before mmap. Preserve the permit, original file Arc and any successful MappingOutcome separately on cleanup error. MappingCustody Drop retries munmap once, then transfers the complete still-charged owner into that pool without allocation. Last-public-handle loss anchors terminal unresolved state; it cannot release the Arc or pretend cleanup. Define per-slot exclusive retry/unwind/poison behavior with no lock held across syscalls.
- [ ] Add and run `failed_unmap_drop_keeps_owner_and_charge`, `same_pool_reconstruction_cannot_reset_capacity`, `repeated_unmap_fail_drop_then_admit_refuses`, `pool_close_blocks_stale_clones`, `last_pool_handle_retains_terminal_custody` and `independent_pool_is_separate_accounting_domain`. Retain a test-only cleanup guard for terminal-retention tests so failure injection cannot leak real resources from the test lane. Assert original FD and mapped range stay owned after every failed Drop, occupied bytes/slots never fall early, and successful retry alone frees capacity. A refund-on-Drop mutant must reach and fail the capacity/FD assertion; restored twin passes.
- [ ] Run target with raw-key-as-exact, ignored-fstatfs-error, hidden-calibration, wrong-owner and early-unmap-success mutants. Require the intended relation/effect/cleanup assertion to fail after valid setup; then restored twins pass. Explore 10,000 bounded acquire/reuse/cancel/retire histories against an independent fact-log model and commit.

## LX07: Real filesystem, namespace and effect qualification adapters

**Requirements:** LX-R08–LX-R10/LX-R19. **TODO:** L04/U05–U06; H05, UC02–UC07/UC10–UC13. **Depends:** LX06/TT03/TT04; privileged lane ownership required.

**Files:** Create `tests/mapping_linux.rs`, Linux-owned case expectations in conformance/mapping.rs and `docs/components/scopebase-linux/qualification.md`. Fixture worker, audit helper and provisioners remain TT03/TT04 files.

**Interfaces:** consumes TT's verified fixture manifest/operation ledger and exact `ConformanceAdapter` invocation/observation schema. Produces required per-cell mapping observations, semantic assertions and cleanup assertions; never supplies fixture truth from the production resolver.

- [ ] Freeze required cells before running: ordinary ext4; Btrfs base/subvolume and distinct-object actual raw-key collision; overlay split lower/upper and aligned+verified copy-up; foreign mount-table/churn; real restrictions/effects. Freeze each admitted overlay layout/xino/metacopy/credential combination through TT04 manifests. Missing selected triggers remain incomplete.
- [ ] Add IPC-barrier tests opening/mapping A before path replacement, verifying Btrfs distinct-object collision, proving copy-up occurred, changing target mount view, and denying map_files/proc/calibration. Compare raw worker fstat/fdinfo/maps/mountinfo via the independent minimal oracle. Assert mismatched/missing fixtures are setup failures, never successful mismatch cases.
- [ ] Run future `cargo test -p scopebase-linux --features mapping --test mapping_linux -- --test-threads=1` only inside admitted TT04 fixtures. Save exact library/client/kernel/fixture identities and separate assertion/capability/coverage/cleanup records. Required unsupported permissions do not yield a positive-support pass.
- [ ] Run both policies and an installed transient-mmap audit. Insert hidden calibration only during the observer phase and require UC07 failure even when final maps count is unchanged; verify setup mappings are separately recorded. Force unmap failure/cancel and prove unresolved custody blocks clean completion.
- [ ] Restore valid twins, review fixture independence/trigger coverage and commit adapters plus bounded qualification records. Do not launch donor workloads or BPF merely to increase evidence tier.

## LX08: Observation authority, task birth and observer epochs

**Requirements:** LX-R06/LX-R07/LX-R10–LX-R12/LX-R16. **TODO:** L02/L05/L09, G06/G10–G12/G18; H01–H03, UC05/UC11. **Depends:** LX02/LX04/LX05.

**Files:** Create `src/process/{mod.rs,observation.rs,epoch.rs}`, `tests/process_observation.rs` and observation-control UI case.

**Interfaces:** `ProcessObservation::{acquire(Pid,&ObserverEpoch,ProcLimits,&OperationControl),read_maps,read_mountinfo,verify_birth}` and `ObserverEpoch::new()`. Produces retained pidfd/proc/view/birth observation only; no signal/wait/adopt-child method. `ProcSnapshot::read_unpinned` is explicitly descriptive and cannot upgrade itself.

**Mandatory source slice:** Include P `src/process.rs` and `src/pidns.rs`, O `src/pin.rs` and their actual process acquisition/death/birth/exec regressions; the coarse held-file group alone omitted these inputs. Freeze source symbols, destination methods and all rejection tests before implementation. D07 keeps observation/control and birth/exec distinct.

- [ ] Add failing tricky-comm stat parsing, death-during-acquire, pidfd denial, namespace numbering mismatch, birth changed around proc open, zombie exit and retained-proc-does-not-freeze-exec tests. Owned fixture execs A→B→A while birth is constant; require no SameImage/atomic-mm statement.
- [ ] Add UI attempt to signal/wait from ProcessObservation and model old-epoch/reused-PID history. Assert two new live epochs never compare equal and deserialized report IDs cannot construct an epoch/proof.
- [ ] Run `cargo test -p scopebase-linux --features process --test process_observation`; implement original pidfd/proc retention and liveness/birth/view brackets without automatic stat-only fallback. Real PID reuse is a bounded optional stress supplement; deterministic identity-change injection must cover the semantic refusal independent of reuse luck.
- [ ] Run actual fork/exec/exit and foreign namespace fixtures from TT03/TT04, plus same-owner concurrent reads and CLOEXEC assertions. Wrong-proc-view and birth-equals-image mutants must fail intended assertions; valid twins pass. Commit and freeze process input for LX06/LX09.

## LX09: Optional stopped-child supervision and explicit unresolved ownership

**Requirements:** LX-R05/LX-R12–LX-R15. **TODO:** L05–L06, G03/G04/G07–G11/G13; H19/H20. **Depends:** LX04/LX08/TT03 helper protocol; no publication registry.

**Files:** Create `src/process/{supervisor.rs,pool.rs,child.rs,helper_protocol.rs}`, `tests/supervision.rs`; TT03 owns actual helper implementation/distribution, reviewed against this protocol.

**Interfaces:** SupervisorPool::new(SupervisorLimits,ReapIntegration)->Result<Self,LinuxError>; ChildSupervisor::new(VerifiedHelper,&SupervisorPool), spawn_stopped(ChildSpec,&OperationControl); StoppedChild::{release,terminate}; RunningChild::{wait,terminate,detach}. ReleaseFailure returns Unreleased(StoppedChild) before commit or Released(RunningChild) after commit; other failure wrappers return original phase/owner or reaped disposition; ChildWaitOutcome preserves Pending/Unresolved owners. Pool clones and every child owner retain one accounting domain; detach keeps its permit. pool.drain(policy,&control) visits only queued children; consuming close returns its domain on incomplete cleanup and disables future spawn. Exact signatures/states are in the spec.

- [ ] Add failing real owned-child cases for ready→stopped→released→exec→exit→reap, missing helper, setup FIFO/stalled handshake, pre-stop deadline, ECHILD from a deliberately competing owned reaper, SIGCHLD=IGN/SA_NOCLDWAIT preflight, child exec failure and FD routing with closed stdio. Snapshot parent credentials, limits and signal disposition and assert unchanged.
- [ ] Add state-model barriers before spawn, after spawn, before/after stop acknowledgment, successful SIGCONT, before result delivery, signal error and wait completion. Cancel each barrier; assert one identity-bound effect, explicit custody, no false reaped receipt and no PID/PGID kill. Cancel-after-commit mutant must fail a released-state assertion.
- [ ] Run `cargo test -p scopebase-linux --features supervision --test supervision -- --test-threads=1` in an outer-watchdog subprocess where needed. Implement standard Command→verified helper with no user pre_exec callback or hidden handler/global registry. Child-side helper logic uses its audited bounded protocol; caller-exclusive reaping/SIGCONT assumptions are explicit.
- [ ] Implement pre-reserved shared SupervisorPool/queue state; max_children/max_pending_setup/max_unresolved N/N+1 tests refuse before spawn across all controllers in that domain. Repeated stalled waits and dropped/reconstructed controllers cannot reset permits. DetachedChild retains its slot until successful exact-child reap; owner Drop transfers original wait authority/pidfd/phase/FDs to the preallocated pool queue. Running owner Drop has no hidden kill. Last-public-handle loss anchors a terminal unresolved state while the process lives; it never discards custody or claims process exit solved cleanup. No global accounting claim extends across deliberately independent pools.
- [ ] Add `detached_owner_keeps_admission_charge`, `controller_drop_before_child_preserves_pool`, `child_drop_before_controller_preserves_queue`, `reconstruct_controller_same_pool_cannot_overadmit`, `repeated_failed_reap_drop_reconstruct_is_bounded`, `close_blocks_every_stale_controller`, `last_public_handle_retains_child_authority`, `queued_drain_does_not_touch_live_child_handle` and `independent_supervisor_pool_has_separate_budget`. Exercise all controller/child/pool destruction orders, retained-pool recovery with ReapOnly/explicit termination policy, poison/unwind and close failure returning the original domain. Hold an independent test cleanup guard when testing terminal retention; no leaked/stopped child can escape the test lane. Slot-release-on-detach and pool-recreation-reset mutants must fail their intended admission assertion after real child setup.
- [ ] Run exact-child wait/PID-reuse controls and a foreign sentinel child alongside two supervisors stopped in both orders. Assert no foreign signal/reap and no global state interference. Review immediate-child-only authority, post-fork restrictions, panic paths and actual installed-helper identity; restore valid twins and commit.

## LX10: Explicit bounded descriptor-relative discovery

**Requirements:** LX-R04/LX-R16/LX-R17. **TODO:** L08/L09, G04/G05/G07/G17; H06/H20. **Depends:** LX02/LX04; independent of donor migration L07.

**Files:** Create `src/walk.rs`, `tests/walk.rs`.

**Interfaces:** `walk(&HeldDirectory,&mut WalkBudget,&OperationControl)->Result<WalkBatch,WalkFailure>` with explicit WalkPolicy, charged batch state and epoch. No default root, no directory-symlink following; mount crossing only explicit. Root/path capability uses selected existing path library where sufficient.

- [ ] Add failing per-round/global entry, queue, depth, path-byte, retained-output, open-FD, stat/read-call and read-byte limits at N/N+1. Place the blocking fixture inside the actual charged directory-open/read operation, not an expired outer loop; assert consumed work is never refunded on cancellation.
- [ ] Add aliases, symlink escape, mount-boundary, malformed/non-UTF8 names, repeated partial batch, bounded sort and new-epoch-resume tests. Expected traversal derives from a fixture construction ledger, independent of production enumeration order.
- [ ] Run `cargo test -p scopebase-linux --features walk --test walk`; implement precharging descriptor-relative traversal and bounded batches without collect-then-check or a hidden filesystem worker.
- [ ] Run late-check-budget, symlink-follow and lost-queue-custody controls; require exact bound/ownership assertions to fail and restored valid twins to pass. Check no global lock or unbounded per-path cache; commit.

## LX11: Two independently wired real clients and developer conformance

**Requirements:** LX-R18/LX-R21/LX-R22. **TODO:** T05–T07/U03–U04/G19/G20/G22/UC14. **Depends:** selected complete LX production profiles, TT01–TT03; TT07 for installed route.

**Files:** Create `examples/held-file-inspector/`, `tests/downstream/linux-adapter/`, Linux conformance adapter sources and user contract examples. Each client has a separate Cargo manifest/lockfile excluded from the root workspace.

**Interfaces:** implement `scopebase_testkit::adapter::ConformanceAdapter { fn subject(&self)->SubjectBinding; fn execute(&mut self,&CaseInvocation,&FixtureAccess)->Result<Observation,CaseError>; }`. Subject is compiled actual package/build/features/backend; Observation is bounded schema-tagged bytes independently checked by TT. These clients do not delegate both flows to a shared fake backend/test helper.

- [ ] Implement first client as a useful held-file/mapped-image inspector over explicit owned fixture roots; it opens/reads actual files and observes existing worker maps. Implement second as an owned-workload client with its own control flow, actual child supervision and input inspection. No mock filesystem, mocked mapping or fake child supplies their integration evidence.
- [ ] Add CaseId/ProfileId admission tests for ASCII `[A-Za-z0-9][A-Za-z0-9._-]*`, maximum 96/64 bytes respectively; reject slash, non-ASCII, empty and max+1 lengths. Valid boundary IDs must round-trip through the frozen TT protocol without loosening its grammar.
- [ ] Add package-copy binding test: deliberately resolve two scopebase-linux versions/builds and verify subject binding identifies the adapter's actual copy; the runner's linked copy cannot certify it. Add no-default/default/supported-union external Cargo builds and previous-contract refusal vectors.
- [ ] Run future `cargo test --manifest-path examples/held-file-inspector/Cargo.toml --locked` and `cargo test --manifest-path tests/downstream/linux-adapter/Cargo.toml --locked` against packaged source dependencies in a clean export. Exercise applicable H/UC scenarios through each actual adapter; ordinary dependency cargo test alone does not run the package's tests.
- [ ] Integrate TT07 installed operator route with explicit fixture root/output/effect plan and no compiler/network/donor source dependency. Run source-free/read-only-prefix cases offline, including changed worker/manifest/library binding and terminal-control-path diagnostics.
- [ ] Confirm both clients have different useful workflows and independent expected operation ledgers. Publish exact build identities and incomplete profiles without product-integration wording; review and commit.

## LX12: Package/profile acceptance and affected-check routing

**Requirements:** all applicable LX-R01–LX-R19/LX-R21–LX-R22. **TODO:** U01–U08/T01–T07; full advertised profile gates. **Depends:** LX11, selected production profile tasks, TT06–TT10, SB03. LX13/MG01/MG02 are not dependencies.

**Files:** Update `docs/components/scopebase-linux/{contract.md,qualification.md}`, package README/examples and component section of root release manifest through its owner.

**Interfaces:** consumes TT10 fixed required-profile inventory and result validator; produces a profile-specific package-readiness decision with exact artifact closure, not a runtime authority token.

- [ ] Run future `cargo test -p scopebase-linux --no-default-features`, `cargo test -p scopebase-linux --all-features --all-targets`, `cargo test -p scopebase-linux --all-features --doc`, and SB02 MSRV/minimal/default/union builds at the final bytes. Coordinate Cargo ownership. Preserve required NOT_RUN/BLOCKED rather than adding them to PASS totals.
- [ ] Run TT06 applicable model/fault/fuzz controls and TT09 resource/coexistence bounds once at the candidate closure. Run required real cells through packaged clients/operator route on named 5.15/6.12/current profiles and actual fixture trigger cells. Named H05 cells may use additional reproducing environments; no historical receipt substitutes for changed bytes.
- [ ] Run future installed profiles with the frozen command `scopebase-conformance run --profile ID --fixture-root PATH --output PATH [--fixture-manifest PATH] [--mapping-policy POLICY]`. Execute `held-file-v1`, `process-observation-v1`, `owned-child-v1` and `bounded-walk-v1` for their advertised contracts. Execute `mapped-image-v1` separately with `--mapping-policy no-new-target-mappings` and `--mapping-policy allow-private-calibration`; filesystem cells add `--fixture-manifest <admitted-manifest>` to that same mapped-image-v1 invocation. Every run supplies explicit owned fixture and output paths. No profile aliases are accepted. Require source-free/offline/read-only-prefix UC14 and exact client copy binding.
- [ ] Independently inspect persistent-pool repeated-failure/destruction-order controls, known-bad evidence, nonempty positive/excluded populations, collision/copy-up/split triggers, transient mmap audit, memory/work accounting and final child/FD/mapping dispositions. An unresolved required resource or missing positive branch blocks that profile.
- [ ] Document affected-check routing: file/read→LX02–LX04 plus reached proof validity; proc/domain/proof→LX05–LX08 and reached real cells; custody→LX06/LX09; packaging/features→LX11/UC14; fixture/oracle changes→all cases whose previous truth depended on them. Do not rerun unrelated BPF/performance suites without a causal reason.
- [ ] Review and commit the accurate ready/incomplete statement, support exclusions, commands and artifact identity. Definition of done is complete production behavior plus required case evidence and shipped user route; design/test source alone never closes it.

## LX13: Product migration compatibility packet, without donor edits

**Requirements:** LX-R20. **TODO:** L07; feeds master MG01/MG02. **Depends:** frozen selected interfaces; can proceed before package readiness but cannot imply migration. **Files:** Create `docs/components/scopebase-linux/migration-handoff.md` only.

**Interfaces:** produces donor call-site-to-public-API mapping and exact-tip acceptance/rollback/retirement checklist. Master MG01 owns p11scope changes; MG02 owns OSSLscope changes. No product checkout, lockfile or dependency is modified by LX13.

- [ ] Re-pin selected P/O implementation and test files read-only, recording dirty selected-file hashes/deltas. Map P manifest open/read/maps proof and O plan PinnedFile/bounded-read seams onto HeldFile/ReadLimits/MappingOutcome without conflating maps and stat keys. Keep ELF/export parsing and product cache policy local.
- [ ] Specify product adapter ownership: hand Arc<HeldFile> into native attachment owners until confirmed retirement or explicit unresolved custody; backend-specific attach/detach and H19 gates belong to the BPF/master migration work. Map current-cursor behavior to deliberate positional full-file semantics and document any intentional behavior change.
- [ ] List exact application-owned regressions: P held proof/no-new mapping/replacement and H04/H05/H06; O site_identity growth/size/cursor/cached-budget and count_deadline pinned attach/delete; add actual live attachment positives/active negatives at changed tips. Historical fake-backend tests cannot satisfy live cutover acceptance.
- [ ] Write rollback as dependency/adapter reversal with preserved issue cases. Retire old duplicate only after exact-tip product oracle and relevant real/live gates pass; until MG completion mark unchanged products explicitly. Review packet with MG owners and commit documentation only.

## Coverage and execution handoff

There are 22 LX requirements and 13 LX tasks. Every requirement has an owning task in the spec; LX13 supplies a later compatibility packet, while MG tasks own actual migration. Existing L01–L09 map respectively to LX01, LX02/LX05/LX08, LX02–LX04, LX06–LX07, LX08–LX09, LX09, LX13→MG01/MG02, LX10 and LX08/LX10. G01–G13/G17–G18 are resolved within their applicable profiles. G14 minimum semantics is explicit in MappingOutcome/no fallback; G15 BPF resource import belongs to BPF work, with separate child/file coexistence tests here; G16 sampled BPF/capture counters belongs to capture/BPF and is not fabricated by Linux observations. G19/G20/G22 are joint SB/TT/LX11 gates. G21/G23 belong to toolchain/capture startup work; they are not Linux-file prerequisites.

Execution begins with SB inputs and LX01, then follows the DAG with disjoint lanes and serial shared export/manifest mutations. Implementation needs a selected isolated checkout and the applicable execution skill. This document authorizes no donor edits, publication, external issues or privileged test run by itself; the user's implementation/runtime authorization and explicit environment ownership determine those actions. The present task delivers specifications and plans only.
