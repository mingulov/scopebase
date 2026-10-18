# ScopeBase BPF and Compiler Regression Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver independently usable checked BPF/BTF host components, optional existing-loader adapters and a packaged compiler/object regression suite with user-run tests.

**Architecture:** Keep pure geometry, evidence and protocol arithmetic separate from Aya/libbpf adapters and from compiler execution. Adapt existing BTF/ELF parsers, retain original file authority through explicit link retirement, and validate the exact final objects with independent semantic oracles. Library package readiness uses real independent downstream clients; all four product migrations remain deferred.

**Tech Stack:** Rust edition 2021, proposed MSRV 1.88.0 subject to SB02 dependency qualification, existing Aya/libbpf/object/BTF parsers, Proptest and selective userspace models, minimal C/Rust/IR BPF fixtures, shared ScopeBase conformance runner.

**Spec:** [BPF, BTF and compiler regression design](../specs/2026-10-17-scopebase-bpf-toolchain-design.md).

## Global Constraints

- Follow the [decision register](../specs/2026-10-18-scopebase-decisions.md) and [executor contract](../specs/2026-10-18-scopebase-executor-contract.md). The [task-origin routes and concrete repair packets](2026-10-18-scopebase-plan-repair.md#task-origins-and-decision-routes) supplement this task; broad source groups are not dispatch-ready source selections.
- PORT/ADAPT preserves the identified donor mechanism, affected call sites, original regression, independent oracle and bad control together. NEW requires the recorded missing-mechanism reason and frozen design. Unresolved architecture, source, license, support or expected-result choices return NEEDS_DECISION; no fresh approximation or weaker gate.
- Apply provisional Apache-2.0 userspace / GPL-2.0-only BPF / GPL-3.0-or-later application terms and the shared-source/third-party rules in D03–D04. Keep source SPDX, author authorization, actual target input option and kernel runtime declaration distinct.

- Default and `--no-default-features` builds of `scopebase-bpf` are host-only.
- `btf`, `aya`, `libbpf`, and `producer-fixtures` are opt-in features.
- Host crates use edition 2021 and proposed MSRV 1.88.0; SB02 must qualify selected dependencies at that compiler before implementation claims support.
- No new standalone `scopebase-btf` or build-support crate is planned now.
- No build script downloads tools or changes rlimits, credentials, signals, namespaces or kernel configuration.
- Product migrations are deferred: package readiness requires real external package consumers of the delivered API, but does not require p11scope, KryProbe, OSSLscope or MemVeil to migrate.
- Initial live claims target x86-64 little-endian Linux only; AArch64, big-endian and arbitrary weak-memory claims are Unsupported until separately designed and qualified.
- `Authority` in the Linux adapter is `std::sync::Arc<scopebase_linux::file::HeldFile>`.
- `execute_plan` requires a caller-owned persistent `RetirementPool`; unresolved/dropped tickets retain both native custody and capacity charges.
- Parsed `CpuTopology` cannot authorize per-CPU native lookup; `ValidatedMap` acquires its private authenticated `LiveCpuTopology` internally.
- Compiler timeouts return owner-bearing jobs registered in a persistent executor; Cargo/rustc/linker execution requires a whole owned guest/job scope, not an immediate-child exit.
- Ordinary downstream `cargo test` does not run dependency tests; the delivered conformance API and installed route explicitly run them.
- ScopeBase packages, test commands, fixtures and runner extensions below are future deliverables. This planning turn creates no implementation or passing suite.

## Review Focus

1. A sparse possible-CPU list combined with a stale 80-byte consumer must refuse before kernel output can overrun or silently misfold the WHO88 layout; BP02 owns guarded-buffer and actual consumer-stride tests.
2. Policy panic or a native partial effect during split attachment must preserve every active link and the original held file; BP04/BP05 own panic/unknown-effect/retirement identity tests.
3. A fixed ring boundary at cursor wrap with BUSY/discard and a later producer extension must not become empty/complete or cross the captured stop; BP06 owns real mapped-reader and model controls.
4. A successful BTF parse with a same-name rival type or wrong split string space must not admit a pointer/prototype or keyed-map type linkage; BP09/TC05 own independent graph and final kernel-ID controls.
5. A compiler/linker change can emit accepted-but-wrong atomics or silently discard metadata despite exit zero; TC04/TC05 own old/new-value oracles and metadata-dropping successful-exit mutants.

---

## Execution boundary, ownership and dependencies

This is a complete proposed execution route, not permission to execute it now. All checklist items are open. Commands are proposed commands to create/run after the named implementation exists; the repository currently has no ScopeBase Cargo command. Do not run live probes during documentation review. At execution, use the selected implementation workflow and isolated worktree per the applicable skill; preserve donor custody and any existing dirty files.

Read the spec before each task. BP-Rxx/TC-Rxx are normative requirements; B01–B10/C01–C06/H/UC/G retain their canonical [research backlog](../../research/2026-10-17-shared-libraries/TODO.md) meanings. SB01 contracts/provenance, SB02 workspace/dependency policy and SB03 compatibility/docs are foundation dependencies. TT01/TT02 provide registry/harness, TT05 environment orchestration, TT07 installed delivery, TT08 affected-check CI and TT10 release profiles. This lane owns semantic fixtures/checkers, not duplicate provisioning or a second verdict engine. NX03–NX06 own actual libbpf-mojo native overlay execution, configuration and map-kind/geometry/close tests; this lane supplies neutral vectors and Rust adapters only.

BP01 and TC01 first freeze one registry/profile/schema interface under SB01; BP02/BP03/BP04 can then proceed independently in disjoint modules. BP04 delivers only pure plan validation/splitting and backend result contracts; BP05 then implements the effectful executor together with the persistent pool/retirement mechanism and Linux HeldFile component; BP06/BP07/BP09 can proceed independently with private evidence dirs. BP08 depends on BP03/BP09 and TC05/TC06 object checks. BP09 completes its host parser increment against independently emitted/admitted static BTF fixtures before TC05; live final-map linkage remains TC05/TC07/BP11 work, avoiding a parser/object dependency cycle. TC06 owns its independent minimal verifier-shape fixtures and never waits for BP08, which later consumes its checker. BP10 integrates BP02–BP06 and TC03/TC05. BP11 follows all advertised BP feature tasks and TT07. BP03/BP05/BP06 deliver their independently tested host/T3 increments first; their actual native probes/custody/reader cells run under BP11 after BP10 exists, not as circular prerequisites of BP10. Mark those integration cells NOT_RUN until then; they remain mandatory package gates. TC02 follows TC01 only, implementing executor/scope API, models and the direct-no-children first slice before TT05; TC03 direct/prebuilt-object admission then enables TT05 core orchestration; TC07 integrates the whole-guest BuildScopeBackend after TT05 exists, with TC08 mixed-build package/profile gates; TC03 follows TC02; TC04 and TC05 can follow TC03 independently; TC06 follows TC05; TC07 follows the objects/cases it runs; TC08 closes selected TC profiles and is not dependent on product migrations.

Use one writer per file set. Shared `Cargo.toml`, crate export files, fixture index, catalog/profile registry and runner registration are serialized under the integration owner. Separate build/evidence directories per task; serialize Cargo-heavy work and all privileged/guest activity through TT05 ownership. No parallel tasks attach to the same workload or share a ring cursor. If delegation is used, substantial implementation/investigation uses GPT-6.1-Sol and architectural/adversarial review uses GPT-6-Astra per AGENTS.md; agents receive disjoint paths and reviewed results.

Assertions below are exact test obligations to implement in the named tests, with fixture construction in that test file or its named packaged fixture. They are not claims that helpers, code or fixtures already exist. Each task ends with a reviewable, independently tested increment and a proposed commit only during authorized implementation. Implementation prerequisites are distinct from selected-profile gates: TC02–TC06 establish executor/inspectors/oracles/rules against direct-tool emitted or pinned genuine-object fixtures. TC07 later supplies the real whole-guest build path and reruns them on newly built final mixed objects; TC08 applies distribution/profile gates. No earlier task depends on TC07 to implement/test its reusable mechanism. A subset may ship under a narrowed profile; no subset closes the entire BPF/toolchain plan.

## File structure

Runnable case IDs obey the shared 1..96-byte ASCII grammar: alphanumeric first, then alphanumeric/dot/underscore/hyphen, with no slash. Dotted subcase names below are registry IDs; prose family combinations and profile-selected subcase groups are not CLI selectors. The future operator route is `scopebase-conformance run --profile ID --fixture-root PATH --output PATH`, with the optional fixture manifest defined by TT. `direct-no-children-v1` is a BuildScope ID and is never passed to `--profile`.

The spec's file map is normative. BP tasks own `crates/scopebase-bpf/`, BPF case adapters in `crates/scopebase-testkit/src/bpf/`, relevant `fixtures/bpf/` subtrees and downstream BPF clients. TC tasks own `crates/scopebase-testkit/src/{object,toolchain}/`, `tools/bpf-compat/`, compiler/object fixture subtrees and compiler client tests. TT owns shared CLI/report/verdict/provisioning code. Add exports through a serialized integration edit instead of letting several workers rewrite `lib.rs`.

### BP01: Freeze BPF boundaries and issue provenance

**Requirements:** BP-R01/BP-R12/BP-R13; F02–F05/B05/B10/G19/G20. **Depends on:** SB01/SB02/SB03.

**Files:** Create `crates/scopebase-bpf/{Cargo.toml,README.md}`, `crates/scopebase-bpf/src/{lib,error,limits}.rs`, `crates/scopebase-bpf/tests/api_contract.rs`, `fixtures/bpf/provenance.json`; modify SB01's contract registry and root manifests through their owner.

**Interfaces:** Consume SB02's actual dependency/MSRV policy. Produce spec `ErrorKind`, `Stage`, `OperationError::{kind,stage,raw_os_error}`, `Limits::validate`, host-only feature graph and full selected donor/source/dirty-file/license manifest.

**Preservation/decision gate:** Freeze the D03–D04 host/BPF/shared/tool input roles and compatible actual dependency option. New source-license policy does not authorize Apache-only input in a GPLv2 payload. Keep user authorization separate from historical SPDX; no blanket GPL or MIT default.

**TC-R10/H33 facet:** host/BPF/shared input policy and actual dependency-role decisions. Follow D03–D04; other facets remain with their named owners.

- [ ] **Step 1: Write `api_contract` tests.** Check `Limits` with each budget 0 admits no corresponding work, usize/u64 maximum calculations refuse Overflow before allocation, raw EACCES survives as `Denied/Admission`, error sources are accessible without display parsing, and host-only exports contain no Aya/libbpf types. Use positive and negative compile assertions for intended auto-traits.
- [ ] **Step 2: Verify failure.** Future: `cargo test -p scopebase-bpf --no-default-features --test api_contract`; expect missing crate/API, then the precise invariant failures until implemented. A compiler/dependency/tooling setup error is not a semantic red test.
- [ ] **Step 3: Implement the minimal host crate and pin ledger.** Read-only refresh visible donor refs/worktrees and selected files from the spec's pin table, record selected full SHA/dirty hashes and SPDX, and explain acceptance of any changed donor bytes. Do not fetch/checkout/clean donors. Freeze parser/backend releases from proof-of-fit, record host GNU 5.15/6.12/exact-current profile eligibility, and register only planned—not passing—cases.
- [ ] **Step 4: Verify host isolation.** Future: `cargo +1.88.0 test -p scopebase-bpf --no-default-features --all-targets` and `cargo +1.88.0 test -p scopebase-bpf --no-default-features --doc`; run with no BPF compiler/native loader installed. Verify dependency tree includes neither loader unless explicitly selected; otherwise adjust pin/claim through SB02.
- [ ] **Step 5: Review and commit.** Stage only listed owned paths/approved registry edit; proposed commit `feat: establish host-only BPF contracts and provenance`. Acceptance: no hidden BPF prerequisite and every selected donor issue has provenance/contract/known-bad/oracle fields; NOT_RUN live cells remain open.

### BP02: Checked possible-CPU map geometry and ABI-safe lookup

**Requirements:** BP-R02/BP-R09/BP-R14; B01/H15/H16/H28. **Depends on:** BP01.

**Files:** Create `crates/scopebase-bpf/src/maps/{mod,topology,geometry,handle,provenance}.rs`, `crates/scopebase-bpf/tests/maps.rs`, `fixtures/bpf/maps/{topology.json,who88.json,map-kinds.json}`.

**Interfaces:** Produce `CpuTopology::{parse_possible,count,ids}` for pure models, opaque `LiveCpuTopology::{acquire,snapshot,revalidate}`, `PerCpuGeometry::{checked,stride,buffer_len}`, `ValidatedMap::{from_owned_fd,lookup,metadata,geometry}` and spec metadata/layout types. `ValidatedMap::from_owned_fd(fd:OwnedFd,expected:&MapExpectation,limits:&Limits)` accepts no caller topology; it internally authenticates and retains the live possible-CPU source. Metadata comes from the actual retained FD; syscall-facing code stays private/audited.

- [ ] **Step 1: Write geometry and consumer tests.** Named tests: `stride_1_7_8_9_13`, `sparse_offline_possible`, `overlap_missing_and_overflow_refuse`, `who88_every_lookup_path`, `bloom_refuses_before_extent_and_copy`, `topology_change_invalidates_sample`, `parsed_zero_cannot_authorize_live_copy`, `wrong_source_and_bind_online_refuse_before_syscall`. Add compile-fail passing `CpuTopology::parse_possible(b"0",...)` to any live native method; no such parameter/conversion exists. Pin assertions:

  ```rust
  // possible list 0-1,4,7 is four possible lanes, including offline CPUs.
  assert_eq!(strides, [8, 8, 8, 16, 16]);
  assert_eq!(buffer_lengths_for_four_lanes, [32, 32, 32, 64, 64]);
  assert_eq!(who88_stride, 88);
  assert_eq!(who88_four_lane_bytes, 352);
  assert_eq!(stale_who80_result.kind(), ErrorKind::Incompatible);
  assert_eq!(bloom_lookup_calls, 0);
  assert_eq!(bloom_output_after, bloom_output_before);
  ```

  Construct a real metadata-backed per-CPU array/hash in the admitted live map profile, read offline lanes into guarded buffers, and prove the actual public lookup and downstream decoder use the 88-byte stride. Keep syscall-independent arithmetic tests unprivileged. On a real multi-lane kernel test a well-formed caller `"0"` undercount, fake possible file, bind-mounted online attribute, sysfs subtree disguised as root and replaced kernel source; every unauthenticated live route refuses before kernel copy, with valid authenticated twin. Include malicious `0-2,2`, empty/missing source, high ID/count, contradictory counts, `usize::MAX` rounding/multiplication and cap N/N+1.
- [ ] **Step 2: Run the pure red tests.** Future: `cargo test -p scopebase-bpf --test maps`; expect the named geometry/schema/map-kind assertions to fail against injected stale-stride/online-count/output-bloom implementations. Live map setup refusal is incomplete for its positive cell.
- [ ] **Step 3: Implement checked lookup.** Keep parsed/model topology separate from opaque native authority. Pin/authenticate the actual kernel sysfs root/possible attribute without symlink or bind crossings and retain boot/source/context identity. Verify the kernel possible-mask immutability/same-map-mask invariant for the supported configuration; refuse unknown/mutable profiles rather than relying on a before/after race check for memory safety. The live constructor obtains this privately and lookup revalidates it before syscall. Round checked by 8, validate map type/key/value/flags against actual metadata, own FD, allocate only after trusted geometry admission, and return bytes without arbitrary typed aliasing. Reject bloom before geometry arithmetic/allocation/native lookup. Preserve output on native failure via scratch copies where caller output exists.
- [ ] **Step 4: Verify pure, real-map and downstream paths.** Future pure command above; TT05 runnable registry cases `H15.abi-stride` and `H28.bloom-output`, plus the requested profile’s required H16 subcases (a prose family grouping, not a runnable selector). Online-count and 80-byte mutants must reach lookup/fold; a safe caller topology undercount/wrong-source must be rejected before a native copy. Source/topology substitution or change invalidates the safe route and its sample. The size/stride mutants must reach lookup/fold and fail intended size/identity assertions; restored WHO88 twin passes with guard identities intact.
- [ ] **Step 5: Review and commit.** Proposed `feat: validate possible CPU map geometry and ABI lookup`. Acceptance: unknown or caller-forged topology cannot cause kernel-copy allocation, every real consumer uses admitted layout, and map-kind errors preserve outputs. Record live readiness only for exercised cells.

### BP03: Capability and hazard evidence with non-vacuous probes

**Requirements:** BP-R03/BP-R13; B03/B10/H22/G12/G14. **Depends on:** BP01, TT01/TT02 for case integration.

**Files:** Create `crates/scopebase-bpf/src/capability.rs`, `crates/scopebase-bpf/tests/capability.rs`, `fixtures/bpf/capability/populations.json`, `crates/scopebase-testkit/src/bpf/adapter.rs`.

**Interfaces:** Produce spec `CapabilityState`, `EvidenceStage`, `HazardState`, `CapabilityObservation::{state,stage,applies_to}`, `ProbeContext`, `ProbePopulation`, `assess_filter_probe(&ProbePopulation)->Result<CapabilityState,OperationError>`. Consume shared `ConformanceAdapter`/`SubjectBinding`/`CaseInvocation`/`FixtureAccess`/`Observation`/`CaseError`; adapter provides observations, never expected truth.

**Preservation/decision gate:** Add H33 same-errno/different-cause and GPL-helper admission cases. Preserve BPF_PROG_LOAD operation, raw errno and bounded verifier evidence; verifier/license refusal is not automatically Denied. Unknown cause stays Unknown. Bridge BP/testkit ProfileIds by checked unchanged bytes; slash/long/uppercase domain-only inputs refuse in the receiving grammar.

**TC-R10/H33 facet:** cause classification and planned runtime-license controls; live execution remains later. Follow D03–D04; other facets remain with their named owners.

- [ ] **Step 1: Write `capability` tests.** `quiet_zero_is_unknown` asserts zero expected/observed trigger cannot be Supported; `active_excluded_hit_is_incompatible` uses independently executed nonempty child plus own-thread positives; `denied_is_not_unsupported` preserves EACCES/stage; `receipt_cannot_mint_runtime_authority` is compile-fail; `context_change_invalidates` changes object/profile/namespace/security/BTF/topology one at a time. Hazard override leaves Denied unchanged. `ProfileId::new` tests 1..128-byte `[a-z0-9][a-z0-9._/-]*` IDs, rejecting empty, non-ASCII, newline and 129-byte inputs.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-bpf --test capability`; known all-zero-as-supported and denied-as-unsupported mutants fail their exact classification assertions.
- [ ] **Step 3: Implement descriptive observations and pure assessment.** Store immutable artifact/profile/context/provenance fields. Construction or deserialize cannot create handles, attached links or closure authority. Expose no implicit probe in constructors. Register explicit owned-workload probe invocations; invalidate cached evidence and honor current native errors.
- [ ] **Step 4: Verify pure and actual probe paths.** Pure command above; register BP11/TT05 `H22.filter-canary` and `H22.uretprobe-hazard` for execution after BP10 using admitted owned workloads and distro counterexample. Disable trigger/attach and widen PID filter separately; require intended verdict failure rather than setup crash. Keep real denied/unsupported/unknown cases separate from support positives.
- [ ] **Step 5: Review and commit.** Proposed `feat: report scoped BPF capability and hazard evidence`. Acceptance: observation/report never substitutes for runtime authority, no zero-activity canary passes a positive-support gate.

### BP04: Finite attachment planner and caller error policy

**Requirements:** BP-R04/BP-R05; B02/H21/G03/G06/G23. **Depends on:** BP01.

**Files:** Create `crates/scopebase-bpf/src/attach/{mod,plan}.rs`, `crates/scopebase-bpf/tests/attach.rs`, `fixtures/bpf/attach/split-trees.json`.

**Interfaces:** Produce `Site`, `AttachMode`, `AttachPlan::{checked,sites,split_sites}`, `ErrorAction`, `ErrorPolicy::classify`, unsafe `AttachBackend::{custody_charge,attach,retire,retire_uncertain}`, `NativeAttach::{Attached,NoEffect,Uncertain}`, the exact final `execute_plan` seam is specified but implemented only by BP05 after the pool exists. `NativeAttach::Uncertain` carries `B::Uncertain` custody; it is not an ownerless error. `split_sites(Range<usize>)->Result<Option<(Range<usize>,Range<usize>)>,OperationError>` is the independently testable pure production split primitive; no placeholder effectful API is exported in BP04.

- [ ] **Step 1: Write `attach` tests.** Enumerate nonempty n=1..8 trees, all-success, every terminal failure position and mixed bad leaves; assert `attempts <= 2*n-1`, each successful group attempted once, offset-cookie pairs exact, duplicate cookie/site refusal and n=0 refusal. Permission/resource/unknown-effect failures cannot split even if policy requests it. BP04 tests the pure production split primitive and a bounded decision model without native effects: 0..4 splits into 0..2 and 2..4, singleton returns None, and invalid/empty/out-of-bounds ranges refuse. Reserve effectful policy-panic and uncertain-native tests for BP05 after its pool-backed executor exists; they are not prerequisites for completing this pure increment.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-bpf --test attach`; unbounded-single-retry, parallel-offset-cookie-swap and split-on-EPERM mutants fail their specific bound/grouping/call-count assertions.
- [ ] **Step 3: Implement balanced disjoint splitting.** Implement checked Site/cookie/offset uniqueness, AttachPlan construction and the pure deterministic split_sites primitive in plan.rs. Define ErrorPolicy, NativeAttach and unsafe backend custody/retirement contracts without calling a native backend. Pin the decision model: attempt each node once, split only side-effect-free isolatable NoEffect multi nodes, singleton refusal/Uncertain/terminal denial roll back the eventual effectful operation. BP05 implements that effectful execution and persistent reservation transaction; this task does not depend on a pool or native link owner.
- [ ] **Step 4: Verify bounds and policy.** Same future test command plus Proptest bounded trees under the exact n/site/link/work cap; assert range coverage, no duplicate nodes and deterministic decisions, with effectful owner-identity checks assigned to BP05. Restore valid twin after each mutant. Review unsafe trait's charge/no-effect/uncertain-custody/retirement preconditions. An API with ambiguous effects and no recoverable native owner is refused before invocation.
- [ ] **Step 5: Review and commit.** Proposed `feat: add bounded attachment planning and error policy`. Acceptance: pure production planner and backend contracts are independently tested with no EINVAL-as-universal-isolatable assumption; effectful execution/ownership and native cases remain BP05/BP10/BP11 gates, with no application admission-window atomicity claim.

### BP05: Held-file attachment custody and explicit retirement

**Requirements:** BP-R04/BP-R05; H04/H19/H21/G06–G10/G15. **Depends on:** BP04 and Linux `Arc<HeldFile>`/`AsFd` seam.

**Files:** Create `crates/scopebase-bpf/src/attach/{execute,retire,pool}.rs`, `crates/scopebase-bpf/tests/retirement.rs`; extend `crates/scopebase-bpf/tests/attach.rs` with effectful fake-backend tests, `fixtures/bpf/attach/retirement.json`.

**Interfaces:** Produce `execute_plan<B,P>(&mut RetirementPool<B>,B,B::Authority,AttachPlan,&mut P,&Limits)->AttachOutcome<B>`, `RetirementPool<B>::{new,usage,reconcile,close}` with exact spec capacity/usage/budget/report types and `PoolClose::{Closed,Unresolved}`, `AttachmentSet<B>::retire(self,&mut RetirementPool<B>)->Retirement<B>`, `UnresolvedAttachments<B>::retry_retire(self,&mut RetirementPool<B>)->Retirement<B>` and `remaining_links(&self,&RetirementPool<B>)->Result<usize,OperationError>`, `Retirement::{Retired,Pending,Failed}`; built-in backend `Authority=Arc<scopebase_linux::file::HeldFile>`. Consume Linux `HeldFile::open` or `from_file`, borrowed `AsFd`; no historical pathname reopen.

- [ ] **Step 1: Write custody tests.** `aba_retains_original_fd`, `pending_and_failed_keep_all_parents`, `foreign_ticket_and_old_epoch_refuse`, `transfer_panic_is_owned`, `capacity_reserved_before_first_link`, `drop_unresolved_keeps_authority`, `second_ring_owner_and_foreign_pin_refuse`, `fork_child_native_owner_refuses_before_exec`, `repeated_unresolved_drop_consumes_same_pool`, `reconcile_releases_exact_confirmed_charge`, `close_returns_unresolved_pool`. Add effectful split-tree tests at every failure position through n=1..8: attempts ≤2n−1, exact grouping, successful groups not duplicated, terminal denials/resource failures not split and rollback successful leaves. Policy panic after prior success leaves all native owners registered in the pool. Ambiguous acquisition before FD delivery and late completion after timeout produce Unresolved, no extra attach/splitting and intact recovery ownership. With capacity two groups, perform two unresolved attaches and drop both tickets; attempt three refuses before native call despite fresh per-call Limits. Reconcile one to confirmed Retired then exactly one new admission succeeds; pending/failed retries release no credit. Test foreign pool/session/generation returns original ticket without native calls and active held tickets are excluded from orphan reconciliation. Inject before/after every attach/retire transfer, pending→retired and failure→retry, proc-fd denial and A→B→A rename/deletion. Assert original file FD identity remains alive until all links are positively retired, then is released; a successful unrelated close cannot satisfy it.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-bpf --test retirement`; early-file-drop and detach-success-on-timeout mutants fail original-FD/retirement assertions. Genuine native retirement failure remains a required TT05 case, not replaced by fake-link tests.
- [ ] **Step 3: Implement consuming retirement and retained custody.** Implement execute_plan using BP04 split_sites and the caller-owned persistent pool as the actual owner of backend/program/file/links/uncertain acquisitions, with move-only generation/domain tickets. Reserve one group plus audited worst-case link/retained-byte charge before effects; active/pending/uncertain/orphan states keep it until confirmed native retirement. Dropping a ticket only marks the entry orphaned; it releases no native object or credit. Reconcile pending/orphan entries within explicit call budget without disturbing active held tickets; close returns the unresolved pool. Last-resort pool Drop retains/leaks the whole charged state, never pretends a clean close. Document per-domain bound and require callers/SDK to include all live pools; constructing a fresh pool cannot reset an application-wide bound. No hidden global registry and no link creation during retry.
- [ ] **Step 4: Verify staged and live custody.** Pure/T3 command above; register BP11/TT05 `H04.held-file-live`, profile-selected H19 subcases, `H21.rollback-live` for execution after BP10. Use independently known workload operations at the original inode and active negative replacement. Outer timeout preserves unresolved custody; do not claim it interrupted native cleanup.
- [ ] **Step 5: Review and commit.** Proposed `feat: retain file authority until explicit link retirement`. Acceptance: original authority and persistent charges survive all unproved native outcomes and dropped tickets; repeated failures hit capacity, clean conformance rejects unresolved owners, trait/concurrency/unwind limits are documented.

### BP06: Ring frame arithmetic, bounded reader and copied staging

**Requirements:** BP-R06/BP-R07; B07/H12/H13/G10/G15. **Depends on:** BP01; BP10 integrates native readers later.

**Files:** Create `crates/scopebase-bpf/src/ring/{mod,frame,bounded,stage}.rs`, `crates/scopebase-bpf/tests/ring.rs`, `fixtures/bpf/ring/{cursors.json,staging.json}`.

**Interfaces:** Produce spec `frame_step`, `BoundedRingSource::{snapshot,consume_before}`, `DrainBudget`, `DrainResult`, `BoundaryState`, `StagedRecord::{new,offer,copy_into,stats}`, `StageStats`. Generic bounded results never contain Quiescent/Settled.

- [ ] **Step 1: Write `ring` tests.** Cover 8-byte header/alignment, `usize::MAX-15` wrap, BUSY→Pending with unchanged consumer, discard advances once, producer extension does not extend stop, crossing stop refuses, invalid distance/capacity/length/reserved bits, record N/N+1 byte/work budgets. Short destination is unchanged and held bytes survive two retries and source mutation; final copy delivered once. Assert `received == delivered + held + malformed + dropped`, including occupied-slot drop, malformed zero/oversize, EINTR and error/stop tails.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-bpf --test ring`; BUSY-as-empty, stop-extension, double-drop and short-buffer-consumes-input mutants fail intended boundary/delivery assertions.
- [ ] **Step 3: Implement checked frame/stage logic and source contract.** Use bounded modular distance (<half modulus), checked aligned step and explicit boundary validation. Copy borrowed record into one owned bounded staging slot before callback return. Preserve framing/payload/ABI/schema version distinction. Keep source traits non-cloneable and exclusive `&mut`; use no new raw mmap ring implementation.
- [ ] **Step 4: Verify models and real reader.** Same pure command; register BP11/TT05 profile-selected H12 subcases real read-only controlled mapping through selected Aya reader and actual producer after BP10. Preserve Relaxed-load+Acquire-fence/read-only atomic behavior, Release publication and wakeup ordering. BP10's libbpf reader may refuse fixed-boundary profile if unavailable. Shared H13 vector closure is executed natively by NX03 separately; Rust vectors alone make no C/Mojo claim.
- [ ] **Step 5: Review and commit.** Proposed `feat: expose bounded ring outcomes and stable staged records`. Acceptance: source/queue/kernel loss remain distinct, bounded drain does not grant closure, supported ordering claims match actual architecture tests.

### BP07: Program/CPU writer ownership, insertion provenance and full-map diagnostics

**Requirements:** BP-R08/BP-R09; B08/H14–H18/G16. **Depends on:** BP02 and TC03; TC06 may later add checks over these producer fixtures without gating their initial fixture creation.

**Files:** Create `crates/scopebase-bpf/src/{writer,loss}.rs`, extend `maps/provenance.rs`, create `crates/scopebase-bpf/tests/writer_identity.rs`, `fixtures/bpf/writers/{interleavings.json,who-insert.json,full-map-loss.json}`.

**Interfaces:** Produce `writer_slot(&WriterDeclaration,WriterPartition,&CpuTopology)->Result<usize,OperationError>`, `insertion_owner(&[IdentityLane])->Result<usize,OperationError>`, `fold_degradation_255(&[u8])->DiagnosticFlag` and getters. Capture's general loss types remain independent; cap flag has no exact-count conversion.

- [ ] **Step 1: Write writer/provenance/loss tests.** Nine program ordinals × eight drop sites × possible lanes map to distinct slots. Model different-program same-CPU interleave and same-program guarded refusal with independent miss ledger. Unique marker=1 owns even zero UID/stack payload; marker=0 contributes counts only; missing/multiple/invalid markers refuse. For loss, assert folds `[0,0]→0`, `[7,8]→15`, `[250,10]→255`, repeated cap→255; primary map full cannot prevent independent loss observation. Add preexisting loss, cross-program/CPU, reset/epoch/map-replacement/partial read and KCTX-distinct controls.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-bpf --test writer_identity`; shared-perCPU-slot, overwrite-insertion-identity and primary-map-diagnostic mutants fail exact expected increment/identity/degradation assertions rather than a setup overflow.
- [ ] **Step 3: Implement arithmetic and typed flags only.** Keep product-specific key/UID/request state local. Declare architecture/guard/atomic requirements and no shared live fence. Package minimal independently authored BPF writer/full-map producers for conformance; inspect their actual per-program partitions and independent preallocated diagnostic array. A timeout or detach cannot issue Quiescent.
- [ ] **Step 4: Verify live discrimination.** TT05 profile-selected H14 subcases, `H15.migration`, profile-selected H17 subcases, selected H18 every-lane/stuck-writer/deadline/late-entrant countermodels on x86-64 6.12/7.0 fixture profiles. Workload ledger knows competing inserts/migrations/failures; host mirror is explicitly T0/T1. Missing intended live interleave stays incomplete.
- [ ] **Step 5: Review and commit.** Proposed `feat: preserve writer partitions and independent degradation signals`. Acceptance: no per-CPU-implies-exclusive claim, no capped flag passed off as exact count, no identity mutation on migrated secondary lane.

### BP08: Optional producer task/exec identity protocol

**Requirements:** BP-R10; B09/H01/H03/H08/G12. **Depends on:** BP03/BP09, TC05/TC06, and TT05's independently executed fork/exec operation/IPC ledger. Linux supplies birth/view/owned-child authority only, not an exec-proof API.

**Files:** Create `crates/scopebase-bpf/src/identity.rs`, `crates/scopebase-bpf/include/scopebase/{task_identity,producer_contract}.h`, `crates/scopebase-bpf/tests/producer_identity.rs`, `fixtures/bpf/identity/{producer.c,ledger.schema.json,exec-shapes/}`.

**Interfaces:** Produce spec `ProducerDomain`, `TaskCookie(NonZeroU64)`, zero-valid `ExecGeneration(u64)`, `ProducerIdentity`, `same_execution`. Packaged C schema/helpers export `scopebase_identity_assign_task_v1(out,producer_domain,nonzero_cookie)` and `scopebase_identity_advance_exec_v1(identity)`, fixed 32-byte/align8 layout with offsets 0/16/24 and status 0/-1/-2 as specified; production hooks emit identities, with map/helper choices declared by fixture profile.

- [ ] **Step 1: Write identity tests.** Same domain/task/exec compares equal; token zero refuses; exec zero is valid; old session/domain, generation wrap and cookie exhaustion refuse. TT05-owned independent fork/CLONE_THREAD/leader/nonleader-exec/failed-exec fixture ledger records intended operation IDs, barriers and actual syscall success/failure, pinning expected birth and successful exec transitions. No expected exec generation comes from the producer identity under test or a nonexistent Linux exec-proof seam. Native model must explicitly represent task replacement and stale delivery; no polling heuristic is accepted as producer evidence.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-bpf --features producer-fixtures --test producer_identity`; generation-erasure and PID-only mutants fail the lineage assertion. No BPF compiler is invoked by `--no-default-features` host tests.
- [ ] **Step 3: Implement narrow protocol and native fixtures.** Rewrite reusable helpers from selected pin with provenance; exclude START/privacy/product maps. Missing/scalar/bitmap CO-RE shape guards precede reads. Explicitly initialize padding and bind producer domain/cookies. Checked exhaustion refuses and is observed in the independent diagnostic channel when specified. Test C/Rust offsets/size/alignment, unchanged output on zero-cookie/exec-overflow and valid zero exec; header helpers alone do not allocate or prove production hook continuity.
- [ ] **Step 4: Verify actual objects and live continuity.** TT05 profile-selected H01 subcases, profile-selected H03 subcases, `H08.task-exec` on selected 5.15/6.12/7.0 shape/refusal cells, object-check manifest and independent ledger. Unsupported shape/refusal assertion can pass while producer capability remains unsupported. Object tests do not replace producer continuity.
- [ ] **Step 5: Review and commit.** Proposed `feat: package task and exec identity protocol conformance`. Acceptance: host values may ship independently, but advertise `producer-task-exec-v1` only after its required exact-object/live cells; no cross-restart persistence claim.

### BP09: Bounded domain-aware BTF parser adaptation

**Requirements:** BP-R11/BP-R12; B04/H08/H11. **Depends on:** BP01 and selected parser corpus trial.

**Files:** Create `crates/scopebase-bpf/src/btf/{mod,domain,query,adapt}.rs`, `crates/scopebase-bpf/tests/btf.rs`, `fixtures/bpf/btf/{graphs.json,images/,expected.json}`; add parser-specific fuzz target only for this bounded input boundary.

**Interfaces:** Produce spec `BtfView::{parse,domain_id,types_named,shape,canonical,member,function,map_types}`, `BtfDomainId`, `TypeRef`, `BtfLimits`, `BtfImages`, `ByteOrder`, `MemberExtent`, `FunctionShape`, `TypeKind`, `TypeShape`. Same-name lookup returns all bounded candidates; callers inspect shape and exact identity, never first-match compatibility. Select one existing parser implementation first; do not add all alternatives.

- [ ] **Step 1: Write hostile and exact-identity tests.** Cover truncated records, unknown kinds, offset overflow, misalignment, wrapper cycle/depth, nested parent escape, same-name wrong pointee, anonymous member/qualifier, DECL_TAG length, malformed prototype, combined base/module type and string routing, foreign refs, missing map key/value IDs. Assert exact domain+type/byte+bit extent against independently authored graph vectors, not parser roundtrip. Big input returns Unsupported in the initial profile.
- [ ] **Step 2: Run parser trial red tests.** Future: `cargo test -p scopebase-bpf --features btf --test btf`; btf-rs comparator research pin is a trial input, not an automatic adoption. Same-name, ignored-parent-bound and module-string-space mutants fail intended ref/extent assertions. Record any candidate parser acceptance mismatch and choose adapter/upstream correction under BP01.
- [ ] **Step 3: Implement bounded parser wrapper.** Enforce byte/type/string/work caps before unbounded parser allocation, narrow preflight if justified, fail unknown graph forms, retain exact image/domain identities and route split contexts. Keep crypto/DMA hook profiles outside. If no existing parser can meet hostile-input caps, stop advertising that profile and record a concrete upstream/preflight task; do not silently implement a universal parser.
- [ ] **Step 4: Verify corpus, bounds and emitted map types.** Future command above, bounded fuzz/minimized cases with configured work cap, and independently emitted static BTF/map-definition fixture queries. TC05/TC07/BP11 later own final-loader/kernel-ID integration cells; they are not a dependency for this host parser increment. Differential selected parser/Aya/libbpf results supplement independent graph oracle. No `.BTF exists` shortcut qualifies map types.
- [ ] **Step 5: Review and commit.** Proposed `feat: adapt bounded BTF queries with explicit type domains`. Acceptance: all critical semantics decided and tested; separate `scopebase-btf` crate remains uncreated unless two consumers justify it with a separate reviewed decision.

### BP10: Narrow existing-loader adapters and native contract vectors

**Requirements:** BP-R04–BP-R07/BP-R12/BP-R14; B02/B05/B06/H07–H13/H19/H21/H22/H28. **Depends on:** BP02–BP06, BP08 host identity types, BP09 as selected, TC03/TC05, Linux HeldFile.

**Files:** Create `crates/scopebase-bpf/src/adapters/{aya,libbpf}.rs`, `crates/scopebase-bpf/tests/{aya_adapter,libbpf_adapter}.rs`, `fixtures/bpf/native/{configure.json,output-spans.json}`, add backend-specific manifests under `tools/bpf-compat/profiles/`.

**Interfaces:** Produce `AyaBackend::from_loaded(program: aya::programs::UProbe, domain: ProducerDomain)->Result<Self,ProgramAdoptError<aya::programs::UProbe>>` and `LibbpfBackend::from_loaded(object: libbpf_rs::Object, program_name:&std::ffi::CStr, domain:ProducerDomain)->Result<Self,ProgramAdoptError<libbpf_rs::Object>>`. `ProgramAdoptError<T>::into_parts(self)->(T,OperationError)` preserves original owner on admission failure. Both implement `AttachBackend<Authority=Arc<HeldFile>>` and retain loaded parent/program. No backend-neutral loader is added. Version `0.1.0` and pre-1.0 minor-version breaking-change policy apply. Caller-fork children must exec and reacquire before using native owners; test inherited owner refusal without claiming native child destructor retirement. Provide documented backend-specific ring adaptation only for actually supported `BoundedRingSource` semantics.

- [ ] **Step 1: Write adapter tests through public APIs.** Same paired sites/cookies/held file across single/multi entry/return paths; wrong/unloaded program refuses with original owner; partial attach rollback and native failure custody. Local-map actual emitted object resolves distinct sentinel FDs, malformed addend negatives refuse, and live loaded map IDs differ. Package H28 bloom/output/configuration vector assertions: unchanged sentinel output on lookup failure, native autoload/target/generation unchanged on configure failure, rollback failure explicitly poisoned. NX03–NX06 execute the corresponding bridge vectors; Rust tests do not claim C/Mojo execution.
- [ ] **Step 2: Run red tests per backend alone.** Future: `cargo test -p scopebase-bpf --no-default-features --features aya --test aya_adapter` and separately libbpf equivalent. Intentionally stale loader patch, cookie swap and generation-only transaction-success mutants fail the named identity/native-state assertions.
- [ ] **Step 3: Implement wrappers over selected upstream APIs.** Hold loaded object/program and `Arc<HeldFile>`, use held FD route with no pathname fallback, capture errno immediately, preserve explicit mode and caller policy. Track only required patches with preimage checks. Backends unable to prove no-effect-on-error cannot enter the safe adapter without retained partial-effect recovery. Native configuration is before loading/attachment; no fabricated post-load autoload API is introduced.
- [ ] **Step 4: Verify exact-object/live adapters.** TT05 H07–H13/H19/H21/H22 per selected backend/profile and required old/current/affected/distro/refusal cells. Actual libbpf cannot enforce fixed tail: assert Unsupported for that requested profile. Verify independent feature builds and supported union, including compile-time !Sync/native owner restrictions.
- [ ] **Step 5: Review and commit.** Proposed `feat: add optional Aya and libbpf contract adapters`. Acceptance: current upstream/backport comparison recorded, no compulsory dual-loader dependency, no universal loader/fence and no tracepoint-only libbpf-mojo claim silently stretched into uprobe support.

### BP11: BPF package and installed downstream conformance

**Requirements:** BP-R01/BP-R13; T5/UC14/G19/G20. **Depends on:** advertised BP feature tasks and TT01/TT02/TT06/TT07/TT08/TT09/TT10. TT05/TC07 are additional gates for selected live profiles; `bpf-host-v1` does not require a live-kernel claim.

**Files:** Create `crates/scopebase-testkit/src/bpf/{mod,cases}.rs`, `tests/downstream/bpf-{minimal,aya,libbpf,feature-union}/`, `tests/installed/bpf-conformance/`; modify BPF package include lists and README feature/profile instructions.

**Interfaces:** Implement shared `ConformanceAdapter` against actual package APIs; register subject binding with package/source/features/backend and exact final object IDs. Use single TT runner, independent expected results and TT profile accounting. No production dependency on testkit.

**Preservation/decision gate:** Apply H33 for the actual selected source/object/backend/package profiles, including independent runtime string/cause checks and delivered notices. Do not certify another compiled copy or count expected refusal as supported behavior.

- [ ] **Step 1: Write downstream/package red tests.** Two independent public API consumers build from packaged archives in external workspaces with independent lockfiles and no sibling paths. One minimal geometry/map client and one image-attachment/BTF client test their own behavior; loader-specific clients select only supported features. Intentionally resolve copy A and B and require report binding to refuse A→B certification. Remove fixture, swap object/backend, change features or omit required case: required coverage remains incomplete.
- [ ] **Step 2: Verify packaging failures are visible.** Future: `cargo package -p scopebase-bpf --list`, package/external-client scripts owned by TT07, and installed runner tests using the canonical `scopebase-conformance run --profile ID --fixture-root PATH --output PATH` route with BPF profile IDs. Missing fixture is ERROR/BLOCKED, never skipped into a complete verdict.
- [ ] **Step 3: Package API, fixture closure and profile instructions.** Prebuilt final objects and static fixtures enable offline inspection/live routes without compilers; compile profiles declare their tools separately. Install shared runner into read-only prefix, write only explicit owned scratch root, no source/network access. Document component readiness separately from product migration status.
- [ ] **Step 4: Verify distribution.** Future minimal/default/all-target tests and explicit doctests at MSRV; each independent loader feature and supported union; source archive builds; source-free installed operator route across required declared cells. TT05 maintains owned live environments. Mutants must reach semantic assertions; unknown/unresolved cleanup blocks a positive support claim.
- [ ] **Step 5: Review and commit.** Proposed `test: ship BPF package and installed conformance routes`. Acceptance: actual candidate copy tested; operator route independently usable; every advertised profile's required cases/cells accounted and passing. Pending product migrations do not block library package-ready but remain explicitly unclaimed.

### TC01: Recover issue fixtures, toolchain pins and patch register

**Requirements:** TC-R01/TC-R08; C01/C06/B05. **Depends on:** SB01/SB02/SB03 and BP01 registry seam.

**Files:** Create `tools/bpf-compat/{README.md,profiles.schema.json,patches.json,issues/}`, `fixtures/bpf/{atomic-rmw,atomic-load,isa,metadata,object-graph}/provenance.json`, `crates/scopebase-testkit/tests/bpf_profile_schema.rs`.

**Interfaces:** Produce `ObjectContract::from_json(&[u8],&Limits)->Result<Self,OperationError>` and strict versioned serialization and individually scoped patch/workaround records; consume shared artifact/profile/case IDs with validated constructors. Preserve no public paths into private evidence archives.

**Preservation/decision gate:** Record H33 source/destination grants, actual target versus host-tool closure, selected upstream option and applicable notice texts. Retain the user-authorized Apache destination without changing observed donor GPL fields; three selected Aya packages lack standalone license texts, so record exact upstream text delivery.

**TC-R10/H33 facet:** source/build/option/runtime requirement manifest and notice provenance. Follow D03–D04; other facets remain with their named owners.

- [ ] **Step 1: Write profile/register parsing tests.** Reject duplicate JSON fields, malformed/newline-suffixed hashes, unknown required schema version, contradictory CPU/ISA feature state, missing exact backend identity, wildcard-required kernel cells and a patch missing preimage/removal test. Assert LLVM atomic correction and private linker repair are separate records with separate tests.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-testkit --features object --test bpf_profile_schema`; permissive parsing and patch-merged-equals-expired mutants fail admission assertions.
- [ ] **Step 3: Populate exact provenance and finite cells.** Read-only refresh selected donor reproducer sources/dirty hashes; preserve original defect and tier limits, license each fixture. Freeze exact 5.15/6.9/6.12/6.15/6.19/affected7.0/current/fixed-kernel cell manifests only where relevant, including configuration/BTF/architecture/artifact/expected support-or-refusal. Select known-affected and fixed backend binaries or reproducible builds with hashes; upstream source merge alone is insufficient. No actual probe/build now.
- [ ] **Step 4: Verify inventory and docs.** Parse schemas/records; local links and IDs resolve; issue rows map H07–H11/H29–H32/B/C and patch expirations. Future `cargo test` command above passes strict valid twins. Store research/historical result as historical, never current PASS.
- [ ] **Step 5: Review and commit.** Proposed `test: preserve compiler issues and patch expiration contracts`. Acceptance: testkit/tools workstream is first-class with pinned inputs, not blocked on a speculative build-support crate or product migration.

### TC02: Explicit compiler closure and bounded nested-build helper

**Requirements:** TC-R01; C05/G21. **Depends on:** TC01 only for the executor/scope API, fake/model tests and direct-no-children backend. Whole-guest mixed-build integration is a TC07/TC08 profile gate after TT05 exists; it is not a TC02 prerequisite. Linux immediate-child helpers qualify only the explicitly sandboxed no-descendant direct-tool profile.

**Files:** Create `crates/scopebase-testkit/src/toolchain/{mod,identity,invoke,executor,scope}.rs`, `crates/scopebase-testkit/tests/toolchain_invoke.rs`, `fixtures/bpf/toolchain/fake-tools/`.

**Interfaces:** Produce spec `ToolBinary`, `CompilerClosure`, `BuildRequest`, unsafe `BuildScopeBackend::{start,poll,request_stop}` with `ScopeStart/ScopePoll/BuildExit`, `CompilerExecutor<S>::{new,usage,reconcile,close}`, `CompileJob<S>::{reconcile,request_stop}`, `CompileOutput<S>::{objects,release}`, `CompileOutcome<S>` and `compile_fixture<S>(&mut CompilerExecutor<S>,&CompilerClosure,&BuildRequest)->CompileOutcome<S>`. Timeout/unresolved outcomes carry live CompileJob tickets; Settled and CompileOutput require positive whole-scope/no-writer proof. Executor capacity and output-root leases persist across calls/drop.

- [ ] **Step 1: Write invocation tests.** Non-UTF8 input/tool/output paths retain bytes; inherited conflicting RUSTC/target/CPU refuses; Cargo/rustc/sysroot mismatch refuses; missing executable is ToolMissing; stuck linker returns TimedOut with CompileJob custody; parent exit while linker descendant writes cannot settle or release its output root; stdout/stderr N/N+1 cap; two output-root users—including aliases—refuse shared ownership. With two executor job slots, two timed-out dropped tickets saturate the executor and the third call refuses before spawn; scope reconciliation/confirmed writer retirement releases exactly the recovered reservation. Wrong-executor job/output tickets remain owned and fail without native action. Output lease release fails/retains custody on unresolved cleanup. ScopeStart::NoEffect with failed root cleanup still returns an owner-bearing output-only CompileJob; ToolMissing/Rejected cannot discard such custody. Signaled/nonzero tool exits become Refused only after whole-scope settlement; Emitted requires Exited(0). A direct-tool helper trying fork/linker spawning is refused by child-only no-children enforcement, and cannot run as a host Cargo profile. TC02 models parent-exit/descendant-writing states through a scripted BuildScopeBackend and proves the executor retains job/root custody; the real descendant and positive mixed Cargo→rustc→linker guest tests are TC07/TC08 gates after TT05. TC02 does not run host Cargo as a weaker substitute. Fake linker records loaded LLVM identity distinct from Rust and Clang. `None`, empty, generic, v3 and v4 CPU arguments remain distinct.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-testkit --features toolchain --test toolchain_invoke`; shell-string interpolation, ambient compiler substitution and wrong-pair mutants fail exact argv/tool-identity assertions. No fake helper is mistaken for real compiler support.
- [ ] **Step 3: Implement argument-array execution with explicit environment and ownership.** Implement persistent executor reservations before starting any native scope. Retain actual ScopeStart::Started/Uncertain job owners and held output-root identity; preserve all charges across timeout/unwind/dropped tickets. Return Emitted/Refused only after BuildScopeBackend proves entire scope/descendants and writable output backends settled; produce a checked output lease and require explicit release before reuse. Implement the narrow host direct-no-children scope with audited pinned arguments and child-only fork/clone/IPC enforcement; refuse if enforcement unavailable. Define/test the whole-guest BuildScopeBackend ownership contract here without requiring a guest implementation. TC07 later implements its TT05 controller adapter for Cargo/rustc/linker: no writable host source/output sharing, positive whole-guest/controller/output-backend retirement before object extraction/sealing, no substitution of parent exit or guessed process-group signaling. TC02 does not depend on TT05/TC03 or a mixed-build object. Bound diagnostics/artifact storage and aggregate reservations separately. No downloads, dependency updates, global configuration or compiler invocation from a library build script.
- [ ] **Step 4: Verify fake-tool and selected real compiler path.** Same command plus the `direct-no-children-v1` BuildScope and scripted scope model; exercise modeled stop while parent exited/descendant writer active, root alias/admission after timeout and final cleanup. Register real whole-guest/mixed-builder checks for TC07/TC08 after TT05; actual loaded LLVM provenance must be recorded or capability Unknown. A standalone llc result cannot qualify mixed Rust/C path. No separate build-support crate unless a later decision proves two real API consumers.
- [ ] **Step 5: Review and commit.** Proposed `test: bind BPF fixture builds to explicit compiler closure`. Acceptance: host-only crates still build without fixture toolchain; process/time/output/custody bounds are distinct, every timed-out job remains in the persistent executor, and no root/new build is admitted until its prior scope and lease are resolved. Whole-guest scope proof cannot be inferred from Linux immediate-child cleanup. Completion of this reusable executor/direct-tool task makes no mixed-build qualification claim; TC07/TC08 retain that open profile gate.

### TC03: Final-object inventory and explicit ISA profile admission

**Requirements:** TC-R02/TC-R07; C02/H30/H31. **Depends on:** TC01/TC02 direct-tool first slice and BP09 where BTF queries apply. The inspector is implemented/tested with direct C/IR actual emitted or pinned actual-object fixtures before TT05; mixed-build/live cells are later TC07/TC08 profile gates.

**Files:** Create `crates/scopebase-testkit/src/object/{mod,manifest,inspect,rules}.rs`, `crates/scopebase-testkit/tests/object_isa.rs`, `fixtures/bpf/isa/{sources/,expected.json,mutants.json}`.

**Interfaces:** Produce `inspect_final_object(&[u8],&ObjectContract,&Limits)->Result<ObjectInspection,OperationError>` over selected existing decoder; produce `ObjectInspection::{object_id,violations,conforms}` and `RuleViolation` from the spec, with per-rule location/category and internal decoded inventories. Consume explicit compiler closure output and actual object hashes.

**Preservation/decision gate:** Add H33 final-object rules: bounded unambiguous NUL-terminated runtime license declaration after transformation, source/runtime fields kept separate, exact loader-supplied string and reachable helper/kfunc/type requirements. Missing, duplicated, truncated, swapped or incompatible declarations fail the intended rule.

**TC-R10/H33 facet:** bounded final-object declaration and expected loader binding; actual runtime remains later. Follow D03–D04; other facets remain with their named owners.

- [ ] **Step 1: Write decoded-object tests.** Every advertised instruction family has a minimal emitted fixture and exact expected encoding class, including extended jumps/JMP32/ALU32/original-v4 forms/acquire-release/indirect jumps as selected. Forbidden opcode, missing required form, wrong endian/target ABI and unknown instruction refuse. Empty CPU/generic/v3 and feature-masked v4 produce independently recorded expected subsets; a preset drift cannot silently broaden a profile.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-testkit --features object --test object_isa`; preset-name-as-proof and forbidden-opcode mutants fail the instruction/profile assertion even if compiler exits zero.
- [ ] **Step 3: Implement manifest-driven inventory.** Distinguish source/IR compile, instruction support, helper/map/kfunc requirements, loader relocation, BTF/CO-RE shapes, attach and behavior. Decode final linked/transformed artifacts; outputs from intermediate IR alone cannot satisfy admission. Bound sections/symbols/relocations/instructions and reject unsupported shapes.
- [ ] **Step 4: Verify profile drift and kernel distinctions.** Future object tests pass emitted valid twins and reject semantic mutants. TT05 runs exact final hashes in each preselected ISA cell; source observations at 6.9/6.15/6.19 remain eligibility until actual load/behavior is recorded. A successful ordinary atomic load does not imply acquire-load opcode requirement.
- [ ] **Step 5: Review and commit.** Proposed `test: admit final BPF instructions against explicit profiles`. Acceptance: effective backend/features and final opcodes control support; no universal kernel floor or version-preset boolean.

### TC04: Atomic RMW old/new-value and AtomicLoad selector regressions

**Requirements:** TC-R03/TC-R04; C01/C03/H29/H31. **Depends on:** TC02/TC03.

**Files:** Create `fixtures/bpf/atomic-rmw/{cases.json,producer.c,producer.rs,mutants.json}`, `fixtures/bpf/atomic-load/{minimal.ll,minimal.c,minimal.rs,expectations.json}`, `crates/scopebase-testkit/src/object/atomic.rs`, `crates/scopebase-testkit/tests/atomic_oracle.rs`.

**Interfaces:** Produce `atomic_reference(&AtomicCase)->Result<AtomicExpected,OperationError>` and spec atomic types. Consume exact compiler closure, emitted inspection and TT05 owned socket-filter/BPF_PROG_TEST_RUN executor; no hidden live invocation in pure oracle tests.

- [ ] **Step 1: Write independent arithmetic tests.** Width-masked expected values for i32 add/sub/and/or/xor and i64 add/sub plus supported exchange/CAS/unused-result controls; signed/unsigned boundary/overflow cases use wrapping bit semantics. Assert old and new separately: initial=7, operand=3, add returns old=7 and stores new=10. Non-fetch mutant with memory=10/return=10 must fail returned-old assertion, not setup. AtomicLoad expectation table distinguishes compile refusal, ordinary u64 load and acquire load under explicit feature masks.
- [ ] **Step 2: Run pure red tests.** Future: `cargo test -p scopebase-testkit --features object --test atomic_oracle`; memory-only oracle and wrong-selector-feature expectation mutants fail intended old-value/compile-output classifications.
- [ ] **Step 3: Implement fixture/oracle and affected/fixed compilation.** Keep independent reference arithmetic outside generated BPF source. Preserve used/unused results, decoded fetch bit and CAS controls. Build selected direct C/IR affected/fixed fixtures (or inspect pinned genuine emitted fixtures) for this oracle/tool increment; schedule actual final mixed C/Rust path through the recorded linker under TC07 after whole-guest integration; no volatile substitution and no compiler refusal labeled verifier rejection.
- [ ] **Step 4: Verify exact-artifact execution.** Register TC07/TT05 H29/H31 on admitted kernel cells after actual whole-guest mixed-build integration; TC04 itself verifies the reusable oracle/selector checker on direct/pinned emitted fixtures: positive workload nonempty, both values checked, bad non-fetch mutant executes then fails old-value assertion, restored twin passes. Track LLVM upstream fix inclusion in actual backend. Separate concurrent shared-map RMW/CAS linearization schedules and memory-order tests from stack-memory single-run profile; unsupported ordering stays unclaimed.
- [ ] **Step 5: Review and commit.** Proposed `test: preserve BPF atomic return and selector regressions`. Acceptance: accepted-but-wrong execution is detected; fixed upstream source without actual binary/object/live evidence cannot expire workaround.

### TC05: ELF/BTF relocation, call graph and metadata preservation

**Requirements:** TC-R05/TC-R06; C04/H07/H10/H11/H32. **Depends on:** TC03/BP09 core admission/query tools. Use direct-tool or pinned genuine mixed-object fixtures to implement/check this inspector; newly built actual mixed Rust/C/linker outputs are a TC07/TC08 profile gate after guest integration.

**Files:** Create `crates/scopebase-testkit/src/object/graph.rs`, `crates/scopebase-testkit/tests/object_graph.rs`, `fixtures/bpf/metadata/{mixed.c,mixed.rs,expected.json,mutants.json}`, `fixtures/bpf/object-graph/{maps/,callbacks/,malformed/}`.

**Interfaces:** Extend `inspect_final_object` with exact-definition map relocation, call/function-pointer ownership, alignment, callback FUNC/FUNC_PROTO and meaningful map key/value BTF checks. Consume `BtfView` queries with exact domains. `ObjectInspection` records expected named types/relocations, not merely section presence.

- [ ] **Step 1: Write graph/metadata tests.** Two map section-symbol/addend definitions resolve distinct sentinel FDs; interior/ambiguous/missing/signed-confused references refuse. Calls/callbacks target complete aligned intended functions. Mixed Rust/C debug records remain valid through each transformation and final BTF/BTF.ext retains named map/function types. Metadata-dropping parser exits zero but fails required type assertion. Same-size map with zero key/value IDs refuses.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-testkit --features object --test object_graph`; same-map FD alias, wrong callback, dropped metadata and missing map type-linkage mutants fail distinct semantic assertions.
- [ ] **Step 3: Implement graph/rule adapters over existing decoder.** Preserve pre/post sanitation snapshots/hashes, selected linker repair as separate patch, exact function extents and relocation containment. No custom unrestricted loader and no inference from parser exit zero. Unrecognized graph forms refuse rather than guessing.
- [ ] **Step 4: Verify emitted/translated/live paths.** Validate this inspector with direct emitted and pinned genuine mixed compiler/linker artifacts; register TC07/TT05 selected newly built final mixed artifacts, loader translated-image comparison and H07/H10/H11/H32 after guest integration; callback exact N×M execution and loaded key/value BTF IDs independently inspected. Parser/source green cannot substitute. Kernel verifier/load/callback verdicts remain separate.
- [ ] **Step 5: Review and commit.** Proposed `test: validate BPF graph and mixed-language metadata retention`. Acceptance: repaired final objects retain meaningful semantics and bad successful-exit paths are detected at intended layer.

### TC06: Restricted dead-code repair and verifier-sensitive rule manifests

**Requirements:** TC-R06; C04/H08–H10. **Depends on:** TC05. Own independent minimal verifier-shape fixtures here; BP08 subsequently consumes this checker and cannot be a prerequisite.

**Files:** Create `crates/scopebase-testkit/src/object/prune.rs`, `crates/scopebase-testkit/tests/object_rules.rs`, `fixtures/bpf/object-graph/dead-builtins/`, `tools/bpf-compat/profiles/{padding,linkage,stack,private-stack}.json`.

**Interfaces:** Produce `prune_dead_code(&[u8],&ObjectContract,&Limits)->Result<Vec<u8>,OperationError>` for restricted admitted graph shapes; extend object rules with per-function/path initialized-byte/linkage/call/stack/prologue requirements.

**Preservation/decision gate:** Preserve SelectionTransport named initialized padding and add the old-verifier EACCES classification counterexample. Do not remove the private-stack/argument/linkage workaround from current-kernel success. Keep the independent negative/valid twins on actual final bytes.

- [ ] **Step 1: Write regression tests.** Dead retained memcpy/memmove/memset roots and relocations are removed only when unreachable; live callback/root remains. Shifted entry target, interior call, misalignment/truncated input and unsupported relocations refuse. Explicit initialized padding survives widened copies; required global linkage is GLOBAL in symbol/BTF; six-scalar BPF call has prescribed pointer-bundled replacement. Stack rule uses selected per-frame minimum accounting; path-scoped initializer guard rejects only forbidden relevant memset path, accepts unrelated memset twin. Required private-stack prologue removal fails current rule.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-testkit --features object --test object_rules`; size-only padding, object-wide memset ban, live-root-strip and removed-prologue mutants fail their intended allowance/refusal assertions.
- [ ] **Step 3: Implement restricted transformations and manifest rules.** Audit symbols/calls/relocations/BTF and rewrite consistently; preserve original/transformed hashes. Keep donor-specific function inventory in manifests. Confirm direct-tool or pinned genuine final backend codegen fixtures here, with newly built mixed-object reruns assigned to TC07; confirm combined stack budget and old verifier complexity/global-local linkage rather than host ABI alone. No “disable-memory-builtins” flag treated as proof roots disappeared.
- [ ] **Step 4: Verify emitted/live old/new cells.** Use direct-tool/pinned genuine independent minimal objects to verify these rules, then register TC07/TT05 H08–H10 using newly built same-rule final objects on 5.15/6.2 oldest/reproducing lanes where selected, modern control and affected7.0 private-stack cell. BP08 later adds its own exact-object integration cases. Per-thread START keys and explicit same-CPU preemption ledger are required for live corruption reproduction. Repaired-kernel control is distinct; non-reproduction without schedule trigger remains inconclusive.
- [ ] **Step 5: Review and commit.** Proposed `test: preserve verifier-sensitive object rules and restricted pruning`. Acceptance: new transformed bytes re-admitted and rerun; private-stack workaround not expired by a compiler-only pass or a newer release number.

### TC07: Exact-artifact kernel behavior and concurrent compiler claims

**Requirements:** TC-R03/TC-R07; C02–C04/B10/H07–H11/H29–H32. **Depends on:** applicable TC03–TC06 core tools/direct-or-pinned fixture increments and TT05 orchestration; no earlier task requires TC07 to finish its tooling increment. Integrate TC02 BuildScopeBackend with TT05 whole-guest authority here; TC02 and TC03 core tooling do not depend on this task.

**Files:** Create `crates/scopebase-testkit/src/toolchain/guest.rs`, `tools/bpf-compat/profiles/runtime-cells.json`, `fixtures/bpf/atomic-rmw/concurrent/`, `crates/scopebase-testkit/src/bpf/runtime_cases.rs`, `crates/scopebase-testkit/tests/runtime_result_contract.rs`.

**Interfaces:** Implement TC02 `BuildScopeBackend::{start,poll,request_stop}` over TT05 actual owned build-guest/controller/output authority; consume frozen case/profile/fixture closure and `ConformanceAdapter`; produce bounded observations for independent expected workload/atomic/callback oracles. No executor replaces TT05's owned-environment controller.

**Preservation/decision gate:** Execute H33 GPL-only-helper positive, otherwise-valid non-GPL declaration refusal, helper-free non-GPL control where permitted, and only advertised type/kfunc gates. Require intended kernel reason plus actual nonempty valid activity; lack of privilege/helper/config, malformed bytecode or EACCES alone stays incomplete/Unknown. Retain source/loader/object/kernel bindings and positive native retirement.

**TC-R10/H33 facet:** intended kernel refusal and actual valid/helper-free workload controls. Follow D03–D04; other facets remain with their named owners.

- [ ] **Step 1: Write result/admission tests.** Real owned-guest scope test starts Cargo→rustc→linker, forces parent exit with descendant linker still writing, and asserts the executor cannot emit/seal/release/reuse output until whole-guest/controller/writable-backend retirement is proved. Stop timeout returns CompileJob; repeated dropped jobs retain executor reservations. Restored fully settled build produces stable final objects. Wrong object/profile/backend/kernel/BTF binding refuses. Compile refusal, malformed artifact, unsupported feature, denied load, verifier rejection, incorrect execution and unknown are distinct. Required missing cells stay incomplete. Concurrent-map oracle uses returned-old histories plus final values/CAS success counts and declared ordering schedules, rejecting duplicate/missing/swapped operation IDs even if aggregate totals match.
- [ ] **Step 2: Run red tests.** Future: `cargo test -p scopebase-testkit --features object --test runtime_result_contract`; old-green/new-object substitution, aggregate-only and required-skip-as-pass mutants fail intended binding/semantic/coverage assertions.
- [ ] **Step 3: Integrate semantic cases with TT05.** Implement the TC02 scope trait against TT05 owned guest lifecycle control with no writable host source/output sharing; retain actual control/output authority in each Job until positively settled. Run actual descendant-writer/mixed-builder controls and only then compile once under pinned producer closure and move exact final hashed bytes into admitted isolated cells; no guest rebuild hidden behind same ID. Select oldest/current/affected/backport/refusal cells before availability discovery; no universal floor. Each live workload has independently completed positives and active negatives, named schedules, bounds and owned cleanup.
- [ ] **Step 4: Execute only authorized required cells.** Future TT05 profiles from the spec. Record object admission, load, verifier/JIT, behavior, concurrency, cleanup and performance separately. Pin x86 ordering assumptions; AArch64 remains unsupported. After failure investigate causal defect; no repeat-until-green. A named missing trigger remains incomplete even when no corruption occurred.
- [ ] **Step 5: Review and commit.** Proposed `test: qualify exact BPF objects across declared kernel cells`. Acceptance: every selected required live claim has actual evidence on same final bytes, unsupported/refused lanes tested without inflating positive-support verdicts.

### TC08: Distribute compiler/object suite and expire only proven workarounds

**Requirements:** TC-R08/TC-R09; C03/C06/T5/UC14/G19/G20. **Depends on:** TC01–TC07 for advertised claims, TT07/TT08/TT10 tooling. Mixed-build readiness additionally requires TC07 real whole-guest scope integration/descendant-writer controls after TT05; completing TC02/TC03 tooling alone does not claim that profile.

**Files:** Create `tests/downstream/compiler-{object-client,mixed-producer}/`, `tests/installed/bpf-compat/`, `tools/bpf-compat/issues/index.md`; update package include lists, `patches.json` and compatibility cookbook.

**Interfaces:** Expose developer toolchain/object APIs and shared runner profiles `compiler-object-v1`/`compiler-runtime-x86-v1`; consume actual subject source/features/backend/final-object bindings. Operator installed inspection needs no compiler; explicit developer compilation requires declared tools.

**Preservation/decision gate:** Ship H33 source/option/notice manifest and final-object/runtime checks with installed closure. Removing a required notice or substituting ELF GPL text for source provenance fails the package gate; kernel success cannot waive it.

**TC-R10/H33 facet:** distributed object/source/notice closure. Follow D03–D04; other facets remain with their named owners.

- [ ] **Step 1: Write package/expiration tests.** Independent object-client and mixed C/Rust producer consume packaged library/toolkit APIs without donor sources. Installed offline closure lists/runs static inspection and declared prebuilt workload cases from read-only prefix. Wrong candidate copy/features/backend/object refuses. Patch preimage mismatch fails without fuzzy application; merged-source-only and missing removal-cell records cannot mark patch expired.
- [ ] **Step 2: Verify red package controls.** Future TT07 source archive and installed route commands; remove fixture or metadata file, substitute same-semver different source and drop a required cell. Each gives incomplete/error/binding refusal, never complete support.
- [ ] **Step 3: Finish documentation and patch register.** Separate compiler wrong-code, selector refusal, legal loader relocation, verifier limits, JIT/private-stack hazards and environmental denial. Each issue has exact trigger, defect explanation, pin, public reproducer/oracle, fixed/bad twins and removal/reopen rule. Publish no upstream issue or package as part of this task without separate instruction.
- [ ] **Step 4: Verify shipped user route and affected checks.** Source package and both independent clients; installed no-source/no-network/no-compiler static route; declared compiler-enabled developer route; selected exact-kernel live profile where advertised. Future `cargo test -p scopebase-testkit --features object,toolchain --all-targets` plus explicit `--doc`. Any dependency/compiler/feature/oracle/object change reopens causally affected cases through TT08, not every unrelated fixture.
- [ ] **Step 5: Review and commit.** Proposed `test: distribute compiler regressions and patch retirement checks`. Acceptance: all selected package/profile requirements met; old workaround removed only after selected replacement binary, final mixed objects, independent semantic bad/valid controls, affected kernel cells and downstream routes pass. Otherwise retain patch with reason, not a false complete claim.

## Requirement coverage and completion ledger

| Requirement | Owning tasks | Deliverable readiness boundary |
|---|---|---|
| BP-R01 | BP01/BP11 | Host feature/dependency/MSRV/trait/package tests. |
| BP-R02 | BP02 | Parsed/model and authenticated live topology are separate; actual ABI-safe native map consumer. |
| BP-R03 | BP03 | Scoped descriptive capability/hazard observations, actual probe non-vacuity. |
| BP-R04 | BP04/BP05/BP10 | Pure finite splitting, pool-backed effectful executor, paired sites and held-file backend route. |
| BP-R05 | BP05 | Persistent pool accounting across active/uncertain/pending/orphan custody and real native failure. |
| BP-R06/BP-R07 | BP06/BP10 | Bounded reader, stable staging, actual mappings/backend, no closure upgrade. |
| BP-R08/BP-R09 | BP07/BP02 | Program lanes, insertion identity and independent diagnostic flag. |
| BP-R10 | BP08 | Actual producer continuity object/live profile. |
| BP-R11 | BP09/TC05 | Bounded domain-aware parser queries and final linkage. |
| BP-R12 | BP01/BP10/BP11 | Narrow actual-object backends and individual patch gates. |
| BP-R13 | BP11 | Two external package clients and installed operator closure. |
| BP-R14 | BP02/BP10, NX03–NX06 for existing native bridge | Map-kind output refusal and transactional native state/configuration vectors. |
| TC-R01 | TC01/TC02 | Actual toolchain closure, persistent job/output custody and whole-scope completion proof. |
| TC-R02 | TC03 | Explicit final-object ISA/ABI profile. |
| TC-R03/TC-R04 | TC04/TC07 | Old/new-value and selector semantics; concurrent claims separate. |
| TC-R05 | TC05 | Meaningful mixed-language metadata preserved. |
| TC-R06 | TC05/TC06 | Restricted graph transformations and named verifier rules. |
| TC-R07 | TC03/TC07 | Distinct exact-object/verifier/execution/cleanup cells. |
| TC-R08 | TC01/TC08 | Per-workaround application and expiration evidence. |
| TC-R09 | TC08 | Actual downstream and offline installed tool suite. |
| TC-R10 | SB01/SB02/BP01/BP03/TC01/TC03/TC07/TC08/TT01/TT02/TT05/TT07/NX02/RL02 | H33 source/option, final/runtime declaration, intended GPL-only refusal and notice delivery remain separate, task-owned gates. |

DoD for a task: required tests and bad/valid twins discriminate the named semantic defect, limits/ownership failures are explicit, provenance/license/contract/case links resolve, and checks are tied to changed bytes. DoD for a package profile additionally requires source archive, public API/doctest/feature set, two independently useful downstream consumers, independently runnable installed route and every preselected required cell for that profile. A correct refusal test may pass while capability is Unsupported/Denied/Unknown; required positive support cannot close from that result. Missing fixtures, untriggered concurrency, unresolved cleanup and required BLOCKED/SKIPPED/NOT_RUN remain incomplete. Performance and product integration are separate claims.

Later migration records must identify selected consumer checkout/pin, old local mechanism, shared replacement seam, exact-tip product observable tests and duplicate-removal/rollback criterion. They are not executable migration tasks here and do not gate library package-ready. The whole workstream remains open until every requested profile is implemented/qualified or explicitly scoped out by the owner; shipping `bpf-host-v1` alone is an increment, not completion of this full specification.

## Planning self-review

Reviewed spec coverage, interface names/types, BP/TC requirement mapping and the five Review Focus inputs against the task tests. Every critical exported operation has a named owner/path and acceptance test; unsafe loader/retirement boundaries remain visible. Shell/compiler/privileged commands are explicitly future operations. This document adds no existing build or runtime success claim. Final implementation review must rerun only affected checks after changed inputs, never substitute an old donor receipt or a repeated stress count for a discriminating oracle.
