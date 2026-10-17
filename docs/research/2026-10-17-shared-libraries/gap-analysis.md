# Additional gaps before shared-library contracts are ready

2026-10-17. Independent static gap audit of the proposed Rust libraries, testkit and later SDK. This reviews README, TODO, overlap, testing strategy, both prior reviews and donor notes, with selected donor-source checks. It changes no product source and runs no builds, runtime tests, privileged probes, mounts or installations. None of the findings below is a freshly reproduced donor bug or a claim that an existing test failed.

The proposal has strong regression requirements, but an application mechanism plus its historical tests is not yet a public library contract. The remaining gaps concentrate on what an unrelated caller may do, which outcomes it can rely on, how independently versioned packages compose, and which resource effects survive interruption. The recommendation remains independent Rust components first, an SDK second, C/Mojo third.

Filesystem identity coverage and the delivered, user-runnable conformance package are specified separately in [user conformance](user-conformance.md). This audit does not substitute an internal CI plan for that delivery requirement. In particular, mapping checks required by the supported ready-package contract must ship runnable by library users. Their delivery does not establish that any environment was actually tested here.

## Interpretation and source checks

- **D: confirmed design gap** means the reviewed proposal does not settle a necessary public contract or assign its concrete exit. It does not mean donor implementations lack the mechanism.
- **E: source coverage not established** means the inspected source/notes do not establish the proposed guarantee or its adversarial test. Search/read coverage is not proof that no such implementation or test exists elsewhere.
- **P0: before releasing the affected public operation.** A supported operation may instead be omitted, narrowed, or explicitly refused. P0 does not require implementing every later feature in the first crate.
- **P1: before adding the named supported profile.** Work may proceed separately from the first held-file/read component.
- **P2: before the later SDK/build/native capability is advertised.**

New G identifiers are contract/design obligations, not replacements for H01–H32. Existing H cases should be reused where relevant; adding a G item does not mean relabeling an existing regression as a new discovery.

Selected direct checks used these source snapshots:

| Shorthand | Source and scope |
|---|---|
| P | `/home/user/src/m/p11scope-ws/.worktrees/v040-integration`, HEAD `eb6bbe1df910a3cf40b6b7e8965cc65c69f203ae`. Selected `crates/manifest/src/identity.rs`, `crates/bpf-multi/src/lib.rs`, `src/attach/cleanup_worker.rs` are unchanged against the study's `fb81ee74b5c185d8abaef1cd93b168d6c241989e` pin. Read-only diff confirmed that narrow fact; it does not qualify the whole moving integration tree. |
| O | `agent@um790:/work/osslscope-ws/osslscope/.worktrees/preview-r21`, HEAD `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`. Selected `src/plan.rs`, `src/target.rs`, `src/capture.rs` had no tracked working-tree delta at the check. |
| K | `/home/user/src/m/kryprobe-ws/kryprobe`, HEAD `d153f3aaf9a3931337b47c9e1b046c692da55083`; selected `crates/kryprobe-privilege/src/workload_launch.rs` was inspected, plus the source-pinned [KryProbe note](kryprobe.md). |
| M | The [MemVeil/bridge note](memveil.md), including its consumed-versus-sibling-version distinction and ownership restrictions. This lane did not freshly inspect all remote MemVeil source or repeat its branch census. |

The all-ref/worktree/WIP census remains in the four donor notes. These selected checks supplement that census, rather than replacing it with a HEAD-only claim. Promoting an API still requires F02's selected-file/WIP refresh.

## Which gaps stop the pilot and the requested ready package

The first file/read API is an internal pilot, not completion of the requested ready mapped-image package. Its public boundary needs G01–G06, its applicable G09–G11 guarantees, G18–G20, and G22 resolved at a deliberately small scope. Most resolutions can be a short API decision and focused test; they do not require a runtime, process supervisor, BPF backend or new architecture support. A synchronous pilot API may resolve G07 by documenting that it is synchronous and not interruptible while inside a syscall. G08 becomes a gate only when fallible asynchronous retirement is exposed. File-only users must not inherit process, capture, compiler or native milestones accidentally.

The requested ready mapped-image package must also deliver the complete user-facing mapping profile and tests in [user conformance](user-conformance.md), including its relevant environmental cells and explicit weaker outcomes. Select the obligations from advertised claims before discovering what happens to be available locally; an unavailable required cell stays incomplete. Runtime object/context-bound mapping evidence, descriptive filesystem facts and a local conformance report are distinct outputs. Actual attachment, helper supervision, capture semantics and build support add the G items marked for those profiles below. No package can advertise those features merely because later work is listed. Completing a held-file-only milestone cannot close the requested ready-package mapping obligations.


## Action and dependency index

This index makes every G obligation assignable in TODO; the sections below preserve the evidence and exact scope. “Pilot/public file” means the narrow file API when exported, not readiness of the requested mapping package. P0 applies only to the operation actually exposed.

| Gap / priority / scope | Action | Acceptance to preserve | Dependency / natural backlog home |
|---|---|---|---|
| G01 P0 pilot/public file | Choose positional full-file versus explicit stream/range semantics. | Nonzero/shared cursor cannot produce silent suffix success. | F01/L02 → L03 |
| G02 P0 affected file/attach | Declare proc-fd dependency; typed refusal, no path reopen fallback. | Denied/missing resolver plus path replacement cannot retarget. | L01–L03 → L03/B02 |
| G03 P0 public operations | Structured stage/source/effect errors and caller retry policy. | No text parsing or duplicated effects on retry. | F01/F05 → L02/B03 |
| G04 P0 byte/time claims | Separate byte/work/wait/cleanup bounds. | Inner stalled operation and repeated abandonment remain within declared custody limits. | F01/L03 → L03; L05/L06 for workers |
| G05 P0 memory-bound claims | Define peak/retained/working memory and allocation-failure policy. | Small-limit peak overlap and clone accounting match bound. | L03; Q06 only if selected |
| G06 P0 public file | Encapsulate evidence/FD; define borrow, clone, escape and CLOEXEC. | Cannot safely forge owner/evidence or release it too early; exec inheritance matches contract. | L02 → L03 |
| G07 P1 async/deadline | Define cancellation commit/result/custody semantics. | Future dropped at every transition cannot duplicate effect or lose owner. | G03/G04/G06 → L05/B02/T04 |
| G08 P1 retirement | Explicit close receipt, Drop policy, bounded quarantine admission. | Failed close remains unresolved; repeated failures cannot create unlimited hidden custody. | B02/L05/G03/G07 → B02/T04 |
| G09 P0 public callbacks, P1 later adapters | Specify panic/poison behavior without promising abort recovery. | Panic during transfer preserves safe permitted state and no double-panic destructor. | G03/G06 → L03/T04 |
| G10 P0 public owners | Declare auto-traits, same-owner concurrency and reentrancy. | Trait checks plus allowed concurrent/reentrant use agree. | G01/G06/G09 → L02/T04 |
| G11 P0 FD inheritance, P1 worker fork | Separate caller fork/exec from observed target lifecycle. | No accidental inherited descriptors or waits on nonexistent post-fork workers. | G06/G10; G08/L06 only for retirement/workers |
| G12 P0 exported cached evidence, P1 added BPF profile | Scope receipts and cache invalidation to object/context/operation. | Changed context cannot reuse a positive as present authorization. | L02 for file/mount evidence; B03/B04/B10 only for selected BPF profiles |
| G13 P1 process/BPF/helper | Document permissions and parent-state effects; no implicit privilege policy. | Denial preserves parent credentials/limits/signals. | B03/L05/L06 → L06/B03 |
| G14 P1 fallback profiles | Negotiate minimum semantics before admission/effects. | Strong requirement refuses weaker fallback; allowed degradation is explicit. | B03/Q01/Q03/G12 → B03/Q03 |
| G15 P1 advertised coexistence | Define imported/shared map/link/cursor ownership. | Stop/rollback cannot affect foreign resources; second ring consumer refuses. | B01/B02/B07/B08/G10 → T04 |
| G16 P1 sampled capture counters | Define sample epoch, reset, wrap and non-atomicity. | Reset/replacement/partial sampling cannot fabricate a valid delta. | Q01/B01/G12/G23 → Q01/Q04 |
| G17 P1 timestamps/deadlines | Type clock domains, conversion, failure and suspend behavior. | Clock failure/offset/jump/overflow cannot become valid time evidence. | L08/Q01/G04 → L08/Q01 |
| G18 P0 public reader/budget, P1 backends | Write checked safe-backend pre/postconditions and trust boundaries. | Invalid returns cannot cause memory unsafety; coherent backend assertions retain explicit provenance and cannot mint trusted Linux evidence. | G01/G03/G09/G10 → L02/T01; user conformance for shipped harness |
| G19 P0 Rust package composition | Define additive features/public dependency types. | Two external feature consumers build together without unwanted BPF setup. | F03/T05/T06 → T05/T06 |
| G20 P0 public API evolution | Set Rust/error/receipt/vector/MSRV compatibility policy. | Prior consumer and old/new vectors work or reject incompatibility explicitly. | F03/F06/G03/G19 → F03/T07 |
| G21 P2 build/object profiles | Separate host tools, generated target and runtime profile/environment. | Supported cross-target emits intended object; conflicting target/env fails clearly. | C02/C04/C05/G19 → C05 |
| G22 P0 public diagnostics | Opt-in bounded sink, safe display, structured sensitive fields. | Weird paths/oversized messages neither corrupt framing nor leak bytes/log implicitly. | G03/F03 → T07/L03 |
| G23 P1 capture startup | Stage baseline/config/links/readiness/admission explicitly. | Immediate attach-time activity and late setup failure cannot erase early loss. | B02/B03/Q01/G14 → B02/Q04 |

## G01. Specify read origin, full-read success and shared-cursor behavior

**D; P0; first component. Depends on F01/L02.** O `src/plan.rs:339–415` defines `ReadBoundedSource: Read` and reads from the source's current cursor. Its length comparison does not by itself prove that bytes start at offset zero or cover the whole advertised file. P `crates/manifest/src/identity.rs:277–319` instead uses an explicit offset and refuses a premature zero read. These are different interfaces, even when every H06 size/race case passes. Neither prior review resolves the difference for a user-supplied, previously read or duplicated file.

Choose full-file positional reads for a file-capability API, or make offset/range/partial semantics explicit in a distinct stream API. Specify whether reads change the caller's offset and what constitutes success for empty files, short reads and interruption. **Exit:** start a real file at a nonzero offset, share its open description with a duplicated descriptor, interleave unrelated reads, and verify independently expected complete bytes and cursor preservation, or the documented refusal. A borrowed handle must not silently yield a valid-looking suffix.

## G02. Expose procfs dependencies and refuse unsafe reopening fallbacks

**D/E; P0 for affected file acquisition/attach adapters. Depends on L01–L03.** P `identity.rs:177–193` obtains `O_PATH`, checks regular-file type, then opens `/proc/self/fd/N`; O `PinnedFile::link_path` at `plan.rs:223–229` also returns that procfs spelling. Standalone use therefore depends on a usable procfs view even before process discovery. Existing support cells name permissions generically, but do not define behavior when that reopening route is absent, filtered, mismounted or inaccessible.

Document this dependency and return a typed unavailable/denied outcome at the failed stage. Never reopen the original pathname after a held-descriptor route fails: doing so discards the acquired binding. An injected descriptor resolver can exercise this without requiring a mount operation in ordinary tests. **Exit:** denied/missing proc-fd resolution plus an A→B→A pathname change cannot cause a fresh path open; test correct cleanup and a successful proc-fd twin. Alternative routes require their own same-object proof, not a silent compatibility fallback. Detailed filesystem cells remain in user conformance.

## G03. Define typed errors with stage, partial effect and retry rules

**D; P0; first component, then every adapter. Depends on F01/F05.** L02/B03 distinguish evidence states, but those are not an operational error model. P file functions return `String`; `is_missing_mount_id_error` at `identity.rs:165–170` recognizes a message substring. O wraps some `io::Error` values with new formatted errors (`plan.rs:424–428`), which can discard the original raw errno. A general caller must not parse text or infer that every error occurred before acquisition/effect.

Define stable error categories with original source/errno where available, operation stage, and ownership/partial-effect disposition. Put retry/isolation policy in the consuming adapter; preserve differing p11/OSSL attach policies. **Exit:** callers can distinguish invalid input, denied access, disappeared source, limit exceeded, changed source and failed cleanup without message matching. Retrying after an ambiguous effect cannot duplicate an attachment/publication. This extends H19/H21's mechanics with the public decision contract; it does not duplicate those scenarios.

## G04. Separate byte/work bounds from elapsed-time guarantees

**D/E; P0; first component. Depends on F01/L03; supervision extension depends on L05/L06.** H06 bounds bytes/allocation and T04 discusses stalls, but the first API's public blocking guarantee is unset. A regular-file inode does not imply bounded syscall latency: open, fstat, read or close can stall on a userspace/network filesystem. P's positional loop and O's `read_to_end` are synchronous. A deadline checked before/between reads cannot interrupt a currently blocked syscall.

Publish separate byte, work, wait and cleanup bounds. The first synchronous API may promise only byte/work bounds and state its syscall blocking behavior. A future deadline wrapper must budget abandoned workers/handles and expose unresolved custody; thread cancellation cannot prove the syscall stopped or resources disappeared. **Exit:** a controlled blocking backend reaches the actual inner operation, caller return and eventual worker/resource disposition match the selected contract, and repeated timed-out calls cannot create unbounded hidden workers. Real blocking-filesystem qualification belongs only to a profile claiming it.

## G05. State what memory bounds include and how allocation failure behaves

**D/E; P0 for memory-bound claims; first component. Depends on L03 and Q06 only if reservations are used.** H06 and Q06 establish important input/reservation limits, but do not define peak live memory for one library call or for retained clones. P grows a `Vec`; O reads into a `Vec` and converts it into `Arc<[u8]>` (`plan.rs:398–415`). A maximum input size is not automatically an equal peak-allocation ceiling, especially while old retained payloads and temporary conversions coexist.

Define whether a budget covers returned bytes, working allocation, retained snapshots, callback buffers and shared payloads, and whether allocator failure is returned or follows ordinary Rust allocation-abort behavior. Do not promise universal recoverable OOM. **Exit:** boundary tests account for peak overlapping allocations using small limits, cloned payloads do not double-charge shared storage, and replacing/releasing results changes the correct reservation. Publish a conservative documented bound, rather than an unproved exact cap. Existing queue-conservation tests remain Q06's responsibility.

## G06. Encapsulate file capabilities and decide descriptor escape/clone semantics

**D; P0; first component. Depends on L02.** O `PinnedFile` exposes `fd`, `device` and `ino` as independently public fields (`plan.rs:208–217`). Copying that shape into a public library would let safe caller code move/replace the descriptor or construct inconsistent evidence. Owned-FD language in A2 does not settle borrowing, duplication, `into_inner`, close-on-exec or whether user code may change the shared file cursor/status flags.

Keep evidence and retained owner internally consistent. Prefer scoped `BorrowedFd`/`AsFd` access and explicit consuming escape hatches with documented loss of library guarantees; cloned owners must preserve the claimed lifetime. Do not claim safety against a caller using unsafe raw-FD closure. **Exit:** compile-fail/API examples reject safe construction of forged evidence and premature movement of the retained owner; owned/borrowed/clone tests verify close exactly once, no accidental FD reuse, and documented `CLOEXEC` behavior across an owned exec fixture. Actual link retention still adds H04/H19.

## G07. Give each interruptible operation an explicit cancellation-safety contract

**D; P1 for async/deadline adapters; synchronous first release may explicitly defer. Depends on G03/G04/G06.** H19/H20 and T04 test cancellation during ownership transfers, but do not settle the caller-facing distinction between cancelling a wait, cancelling the operation, and discarding its eventual result. O `target.rs:857–919` intentionally moves work to a worker that may continue after abandonment. An SDK wrapping such a call in a future would inherit that distinction.

For every future/controlled call specify the commit point, whether dropping the future transfers responsibility, how the result is recovered, and whether retry is safe. Keep the base library usable without a compulsory async runtime. **Exit:** drop before first poll, at each pending point, after completion-before-delivery and during cleanup; a subsequent call neither duplicates effects nor loses the original owner. A runtime wrapper's cancellation must not silently convert an unresolved operation into `CancelledAndCleaned`.

## G08. Separate explicit fallible close, Drop fallback and quarantine capacity

**D; P1 for attachment/helper retirement. Depends on B02/L05/G03/G07.** H19 already preserves quarantine; the missing contract is how a general long-lived process manages it. P `cleanup_worker.rs:392–410,753–771` deliberately retains unresolved owners until process exit; P `bpf-multi::bisect_attach_counted` counts leaves and drops them (`lib.rs:416–432`). Counting dropped owners does not prove successful native detach. These CLI choices cannot silently become an unlimited service-lifetime resource policy.

Provide explicit close/retirement outcomes with attempted, released and unresolved counts; keep `Drop` non-panicking under its stated blocking policy. Define who retains quarantine, its capacity, and what happens when a caller tries to create more work after exhaustion. **Exit:** a fallible closer, timeout and repeated failed retirements preserve original file custody without claiming successful close or growing hidden state beyond policy. No requirement to force-release an unsafe owner is implied. A raw held-file wrapper with no such retirement feature needs only its simpler documented destructor policy.

## G09. Define panic behavior for user callbacks, adapters and destructors

**D/E; P0 where callbacks/traits are public; otherwise P1. Depends on G03/G06.** FFI unwind rules exist in X04, but Rust callbacks have a separate public boundary. P `cleanup_worker.rs:281–296` catches closer unwinding with `AssertUnwindSafe` and converts it to failure; poison and destruction require retained owners. The proposal does not establish equivalent behavior for public readers, budget callbacks or attach backends, nor justify importing every product-specific `catch_unwind`.

Specify propagation versus containment, state validity after panic, poisoned-lock behavior and the limits under `panic=abort`. Prefer performing user code outside internal locks. **Exit:** an injected callback panic before/after an ownership transfer leaves only the permitted state, a later API call cannot use poisoned state as valid evidence, and destruction during unwinding does not cause a second panic. The guarantee need not recover from process abort or an unsafe backend violating its contract.

## G10. Declare Send, Sync, cloning and callback reentrancy per Rust owner

**D/E; P0 for exported owners; first component can keep a narrow model. Depends on G01/G06/G09.** Native single-thread restrictions are explicit in M and X04, while Rust owners have no equivalent contract. A `File` or `Arc` being movable/shareable does not establish that a compound cache, callback, budget, close ticket or active ring reader is safe under all operations. T04's concurrent-consumer requirement does not specify which operations may run together on one object.

Record intended auto-traits and allowed same-owner concurrency; use immutable shared payloads or exclusive mutable access where sufficient. State whether callbacks may call the same owner recursively. **Exit:** compile-time positive/negative trait assertions match the public contract, two threads exercising supported operations preserve offsets/ownership, and a reentrant callback either works or returns a documented refusal without deadlocking. Shared-reader features must separately preserve the ring's single-consumer rule; no unsafe `Send`/`Sync` may be inferred from pointer ownership.

## G11. Distinguish observed target exec from the caller's own fork/exec lifecycle

**D/E; P0 for descriptor inheritance; P1 for worker/process facilities. Depends on G06/G10; G08/L06 only for retirement/supervision.** H01/H02 cover the observed target, and L06 names SIGCHLD/pre-exec hazards. They do not specify what happens when an application using the library forks itself while owners, worker threads, locks or registries exist. Child processes inherit descriptors and userspace state; a worker thread does not continue in the child.

Set `CLOEXEC` atomically on internal FDs and document the ordinary multithreaded-fork restriction. Stateful APIs can be unsupported in the post-fork child until exec; do not add global atfork machinery by default. **Exit:** an owned fork/exec fixture finds only intentionally inherited descriptors, and documented post-fork use cannot wait on an absent worker or operate a stale parent registry. The first file-only API need not implement fork-safe supervisors to meet this requirement.

## G12. Bind cached capability evidence to its execution context and lifetime

**D/E; P0 for exported cached file/mount evidence; P1 for added BTF/attach profiles. Depends on L02 for host file/mount evidence; B03/B04/B10 apply only to a selected BPF profile.** The proposal distinguishes probe tiers and identity domains, but not the validity interval/context of a cached `supported` result. O lifecycle subscription can fail in a user namespace ([O3](osslscope.md#o3-kernel-process-lifecycle-transport-with-explicit-loss-and-close-evidence)); metadata, load, attach and behavior conclusions can change after namespace/security-context changes, object replacement or relevant CPU/topology changes.

Represent the tested operation/profile and relevant context in a capability receipt, or document that probes apply only to immediate use in an unchanged context. Specify invalidation/reprobe triggers and which runtime errors still override a prior positive. **Exit:** use evidence in a different namespace/security context or with a changed object/profile and require refusal/revalidation; a cached allowed result cannot suppress a real denial. Do not require full namespace machinery in the file-only crate. This adds cache validity to H22's already-required non-vacuity.

## G13. Specify permission requirements without taking over host privilege policy

**D; P1 for process/BPF/helper features; G02 covers the first file API. Depends on B03/L05/L06.** Feature-result labels separate denial from unsupported, but do not say which process/thread may perform privileged setup, what credential transition is supported, or whether a helper may modify process-wide resource limits/signals. K `workload_launch.rs:1011–1110,1288–1325` explicitly manages child credentials, capabilities, `no_new_privs`, FD inheritance and SIGCHLD. Those are application integration contracts, not harmless generic defaults.

Document required capabilities/syscalls/proc visibility for each operation, their scope, and failure under seccomp/LSM/hidepid policies. Do not install capabilities, raise limits, change parent credentials, mount bpffs or alter parent signals implicitly. **Exit:** denied setup leaves parent credential/limit/signal state unchanged and reports the failed operation; an explicit supported privilege-drop sequence behaves as documented. An already-acquired observation handle must not imply a later operation is currently authorized.

## G14. Negotiate required semantics before selecting fallbacks

**D; P1 for optional capability/transport profiles. Depends on B03/Q01/Q03/G12.** README correctly warns that a perf fallback does not reproduce ring ordering and polling is partial. It does not define how a caller requests minimum semantics or whether a library may fall back after partial setup. A result field saying degraded is insufficient if the caller already acted assuming the stronger mode.

Use explicit requirements/preferences and return the selected semantic profile before admission/effects. Some requirements may have no fallback. Explain if mid-session degradation terminates, starts a new epoch or continues with a named weaker contract. **Exit:** force primary setup failure, then verify a caller demanding its ordering/identity/closure property refuses rather than silently using the weaker backend; a caller allowing the weaker profile receives it explicitly. Reuse existing countermodels for the semantic distinction rather than inventing another universal quality boolean.

## G15. Define ownership rules for shared kernel resources and duplicate observers

**D/E; P1 only for advertised coexistence. Depends on B01/B02/B07/B08 and G10.** T04 requests joint observers with isolated resources, and M keeps coexistence open. A public BPF adapter additionally needs a rule for externally supplied/pinned maps and links: metadata compatibility does not establish sole ownership, mutability rights or a stable snapshot. Two consumers of one ring can violate its single-consumer protocol even when their Rust wrappers have disjoint memory.

Default to per-session owned resources; explicitly scope any map reuse, freezing, external FD import, cursor authority and cleanup ownership. Do not destroy foreign pins/resources during rollback. **Exit:** two independently owned observers can start/stop in both orders without tearing down the other's resources; attempts to add a second consumer to the same single-consumer ring refuse. Shared-map sampling labels non-atomic views honestly. Pair-specific event/performance coexistence qualification remains separate and must not gate the simple file crate.

## G16. Define counter sampling, reset and baseline semantics

**D/E; P1 for capture/map counters. Depends on Q01/B01/G12 and G23.** Q01 specifies units and H03/H24 cover identifier wrap/arithmetic rejection, but the synthesis does not settle when a counter delta is valid. M's corpus recommendations explicitly include counter-reset/epoch mismatch, while O retains keys because in-flight increments may still update them ([O9](osslscope.md#o9-generation-aware-count-session-attach-isolation-and-conserved-attribution)). A smaller sampled value could be reset, replacement, wrap or incoherent sampling; unsigned subtraction alone cannot select the explanation.

Bind samples to map/session/profile epoch and counter width; define saturation, modulo wrap and reset behavior per counter class. Multi-key/per-CPU samples need an observation interval or stated non-atomicity. **Exit:** reset/replaced-map, near-wrap and partial-read scripts yield the allowed delta or explicit unknown, never a giant fabricated loss or silently lost work. This is a sampled-counter protocol, not a new generic overflow test.

## G17. Give timestamps and deadlines explicit clock domains

**D/E; P1 for process/capture/deadline APIs. Depends on L08/Q01/G04.** The plan specifies half-open windows and post-drain sampling, but does not define conversion between kernel timestamps, host `Instant`, wall time, suspend behavior and time namespaces. O `capture.rs:2574–2595` separately provides `CLOCK_MONOTONIC`, `Instant` and `SystemTime`; its monotonic helper does not return `clock_gettime` failure. Reusing bare `u64` would hide both domain and read validity.

Define typed domains/units, checked conversions and failure, deadline overflow, suspend semantics and any calibration uncertainty. Never compare a producer timestamp with a different domain merely because both are nanoseconds. **Exit:** a fake clock jump, failed read, offset clock domain, deadline boundary and suspend-model script cannot extend admission or produce negative/overflowed durations disguised as valid. Actual suspend/time-namespace support is conditional; declaring it unsupported is a valid initial profile.

## G18. Specify public backend traits as contracts with checked trust boundaries

**D/E; P0 for public first-file reader/budget traits; P1 for BPF adapters. Depends on G01/G03/G09/G10.** T01–T07 describe test adapters, but a user implementing a backend needs exact pre/postconditions. P's reader callback accepts a supplied length and O's `ReadBoundedSource` supplies identity tuples. A successful custom implementation is not automatically truthful evidence, and a safe trait must not make memory safety depend on undocumented honesty.

Specify valid returned extents, monotonic budget charging, identity domains, output preservation on error, ownership transfer and which facts are backend assertions versus independently checked. Keep memory-safety obligations at explicit unsafe/internal boundaries; do not use Rust `unsafe` merely to label an unverified semantic assertion. **Exit:** safe backends returning oversized lengths, inconsistent metadata, duplicate receipts, panic or partial effects cannot cause memory unsafety; detectable structural violations reject/degrade. A coherent lying backend cannot be identified from its own answers alone, so its assertions retain backend provenance and cannot construct independently trusted Linux evidence. The published conformance harness and its invocation belong in user conformance; this item defines the API that harness must judge.

## G19. Test Cargo feature unification and public dependency boundaries

**D/E; P0; independently usable Rust packages. Depends on F03/T05/T06.** Minimal/default-feature tests already exist in the plan, but Cargo can enable the union requested by unrelated consumers. No policy states whether Aya/libbpf adapters may coexist, whether optional features change semantic defaults, or whether public types expose exact dependency-version identities. A downstream using two scopebase consumers may otherwise acquire a BPF toolchain or incompatible handle types unexpectedly.

Keep features additive; separate conflicting backend/runtime implementations by modules/types or refuse a documented combination. Avoid host-only build scripts invoking BPF tooling and avoid exposing unstable upstream internals without a deliberate version commitment. **Exit:** an external workspace with two small dependencies enabling different supported feature sets builds and preserves each contract; disabled features do not change existing type meaning. Include no-default, default and supported-union cells, and verify host-only source archives have no implicit sibling/toolchain requirement. This extends T06 to ordinary dependency composition.

## G20. Version Rust semantics and cross-package contracts deliberately

**D; P0 before public API freeze; applies narrowly to first package. Depends on F03/F06/G03/G19.** Independent package releases are recommended, and binary/wire/schema versions are separated. The missing policy is how Rust error/outcome enums, capability receipts, test vectors and sibling contracts evolve without accidentally treating an old consumer as conformant to stronger new semantics. A stable field spelling or same-size struct is not sufficient.

State the policy for pre-1.0 compatibility, `non_exhaustive` outcomes, unknown variants, feature-dependent APIs, MSRV bumps and which sibling/testkit versions qualify a contract. Keep constructors validating invariants across deserialization and version conversion. **Exit:** a small consumer compiled against the previous supported API plus old/new fixture variants either behaves correctly or gets an explicit incompatibility; old receipts cannot silently satisfy a newly added proof predicate. No stable C ABI is required now, and a coordinated monorepo release is an acceptable initial policy if stated.

## G21. Separate build host, object target and runtime target contracts

**D/E; P2 for build helpers/object-kit claims; not a file-library dependency. Depends on C02/C04/C05/G19.** C05 covers the Cargo/rustc/sysroot pair and output isolation, and H29–H32 test actual final objects. They do not explicitly assign host-versus-target selection, cross compilation, target-endian/pointer-width admission or inherited environment behavior. Selecting a matching host compiler pair cannot prove that an intended BPF/native target was built.

Make host tool execution, generated object target, ABI/data layout and runtime profile separate inputs. Define supported target triples and handling of `CARGO_ENCODED_RUSTFLAGS`, wrappers, linker overrides and cross sysroots; preserve explicit caller policy rather than silently installing tools. **Exit:** a declared supported cross-target fixture emits the intended object and metadata, while wrong-endian/architecture and inherited conflicting flags fail at their intended stage. Pure Rust capture utilities may support more hosts than Linux helpers; unsupported package targets should fail clearly without attempting privileged or unrelated tool setup.

## G22. Give diagnostics a bounded, library-appropriate disclosure contract

**D/E; P0; first component with a small scope. Depends on G03/F03.** Product privacy allowlists remain application-owned, but that alone does not define what a shared library emits. P/O errors can contain paths and backend details, and the proposed diagnostic/doctor integration is later work. Hidden stderr logging, arbitrary path bytes rendered unsafely, or raw process/pointer data in `Debug` would bypass a consumer's own privacy and output policy.

Return structured diagnostics; make sinks opt-in, preserve raw source identity separately from safe display, and document sensitive fields. Bound message/record volume and report diagnostic truncation without claiming exact omitted counts. Never copy file contents into errors by default. **Exit:** non-UTF8/control-character paths and a backend producing a very large/repeated diagnostic cannot corrupt terminal framing, exceed the documented diagnostic bound or leak payload bytes; a library-only invocation writes nothing to stdout/stderr unless the caller explicitly selects a sink. Raw access remains available only under a deliberate caller contract.

## G23. Define startup admission and baseline ordering, alongside shutdown

**D/E; P1 for capture/attachment sessions. Depends on B02/B03/Q01 and G14.** H18/Q03 deeply specify the closing side, but there is no corresponding synthesized acceptance item for the opening cut: configuration, diagnostic baselines, link acquisition, readiness and admission must agree on when observations start. K's fixed loader explicitly samples the miss baseline before the first attach ([K12](kryprobe.md#12-strict-qualification-operands-and-source-bound-replay--adopt-schemasoracles-keep-workload-equations-local), source `btf_resolve.rs:731,752,805`). Reading it after attachment can erase early misses while retaining early events.

Specify a staged setup transaction: required baseline/configuration established before any admitted producer, an explicit ready/admission point, and rollback outcomes when setup fails after some links exist. **Exit:** force immediate hits/misses during first attachment, fail later setup, and verify that admitted work is accounted or explicitly outside the named window; no synthetic-zero baseline or partial-ready session can masquerade as a fully observed interval. This fills the startup side without merging product-specific close protocols or adding an SDK dependency.

## Proposed follow-through

Extend F01/F03/L02/L03 with the small first-component decisions G01–G06, G09–G11, G18–G20 and G22. Record explicit exclusions rather than stubbing future process/BPF interfaces. Add profile-scoped follow-ups for G07/G08 and G12–G17/G23, with G21 attached to the existing compiler workstream. Preserve H01–H32 as the regression inventory; associate these contract obligations with the appropriate existing cases and add focused tests only where the missing public behavior is distinct.

The next implementation plan should include one concrete API sketch, two exact migration seams, the shipped conformance command, supported/unsupported operation profiles and the applicable exits above. A deep gap list is not implementation, qualification, or a reason to withhold a useful narrow crate until unrelated features exist.
