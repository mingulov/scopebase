# p11scope reuse research, 2026-10-17

Read-only source/history research; no builds, tests, privileged operations, fetches, commits, source edits, or resource cleanup. Test names below identify existing regressions, not tests run for this study. Historical kernel observations are attributed to source/commit records, not reproduced here.

## Revision and authority

`P` below means `/home/user/src/m/p11scope-ws/.worktrees/v040-integration`; citations `P/path:line` refer to product baseline **`fb81ee74b5c185d8abaef1cd93b168d6c241989e`**, branch `v040-h7-object-wire`. This is the authoritative product tree, explicitly named by the current outer `handoff.md:27`. The nested public checkout is not the active implementation.

At initial inspection, product `src/semantics_objects/journal.rs` was modified. During research another owner advanced HEAD to `cf413029dc9e092925a00b7eabdd8acbe02fa3fb` and the tree became clean. A read-only `git diff BASE -- <all cited implementation areas>` showed no changes in the candidate files inspected here; journal work is deliberately excluded. Root documentation repo: `6f97aa47171147fb2aea58bce5a50aa4c34a8173`, branch `main`, two tracked modifications (`.agents/memory/decisions.md`, `handoff.md`) and 3,436 untracked entries with normal directory collapsing. Nested `p11scope/`: `7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4`, branch `main`, two untracked entries, no tracked modifications. Counts are observations, not retention requirements.

Final read-only refresh on 2026-10-17 observed integration HEAD **`eb6bbe1df910a3cf40b6b7e8965cc65c69f203ae`**, with a clean working tree. Its one-commit delta from `cf413029` changes five application semantic/journal/state and test files; `crates/manifest/src/identity.rs`, the selected first-library donor, is unchanged. The earlier uncommitted shared-ledger work below is therefore historical WIP observed during the study, with a later committed N1c successor; no new qualification or full review of that successor is asserted. The census below preserves its original observation pins. Refresh selected files again before extraction.

Current handoff reports T0–T2 complete, T3/H8 approved at `0c761a64`, T4/H9 fix round 2 in progress; it does **not** establish completed v0.4 release qualification (`/home/user/src/m/p11scope-ws/handoff.md:19`). Its original T4 review describes production integration, exact-call seals, retirement, and retention deficiencies; subsequent commits address many of these, so the original findings are not asserted as still unfixed. This active correction loop makes H8/H9 a poor first extraction target.

## Recommended boundaries (12 candidates)

Difficulty: low = already small, coherent boundary; medium = separate product policy/adapters; high = cross-language or lifetime protocol whose tests must move together. These estimates concern engineering complexity, not elapsed time.

| Candidate and exact source | Reusable invariant/interface | Recommendation, coupling, general Rust use |
|---|---|---|
| **1. Multi-uprobe links and bounded attachment bisection**. `P/crates/bpf-multi/src/lib.rs:268` `attach_group`; `:398` `bisect_attach`; `:408` `bisect_attach_counted`; `:623` `probe_pid_filter_hits`. | Generic link handle permits no-kernel tests; bisection has at most `2n-1` attempts. Permission failures do not split; exhaustion/unsupported halt and close successful leaves; EINVAL on a proven capable kernel isolates bad offsets. Raw pid=0 means all processes, unlike legacy perf semantics. | **Extract/adopt, low–medium.** Existing crate needs neutral naming and capability-result inputs. Shared by user-space probes; little benefit to ordinary non-BPF apps. Explicitly borrowed from OSSLscope, so consolidate rather than create another copy. Keep program loading in Aya: the sibling raw loader rejects the real object's BTF, task-storage maps and typed tracepoints (`:16–36`). |
| **2. Aya ring reader corrections and bounded cursor API**. `P/third-party/patches/aya-0.14.0/aya-ring-reader.patch:105` `snapshot_positions`, `:141` `next_before`, `:236` `validate_stop`. | Retain one consumer; wrapping aligned cursor advancement; fixed producer boundary; BUSY is pending; discarded records advance/count; stop crossing is an error. Read-only mapped atomic loads use Relaxed + Acquire fence, preserving Release cursor publication and SeqCst wakeup. | **Upstream first; share a single pinned patch meanwhile, medium.** Do not fork another ring parser. Useful to any Aya consumer and as mmap/atomic regression technique for general Rust. x86-64/read-only atomic contract and real kernel aliasing remain separate concerns (`P/third-party/README.md:55–73`). |
| **3. LLVM local-map relocation repair**. `P/third-party/patches/aya-obj-0.3.0/aya-obj-map-relocation.patch:30–88`, `:237–247`. | Resolve section-symbol references by exact `.maps` definition offset plus unsigned 32-bit LD_imm64 addend; reject missing/interior/ambiguous definitions; whole-section fallback only for global-data maps. | **Upstream; share regression/object fixtures, low integration/medium maintenance.** Prevents map-FD aliasing/debug assertion as native C/Rust compilation changes. Aya-specific; general Rust relevance is the exact-symbol/offset object-loader discipline. Not evidence of a compiler defect: LLVM's representation must be handled by the loader. |
| **4. Held-file and mapped-object identity**. `P/crates/manifest/src/identity.rs:111` `mapping_file_key`, `:177` `open_regular`, `:401` `SelfMappingProbe`, `:417` `KernelSelfMappingProbe`; `P/src/discovery/identity.rs:154` `RetainedMappedIdentities`. | Open O_PATH, verify regular inode, reopen that held FD; hash/parse the held object. Distinguish fstat device from maps device, mount IDs from global devices, namespace view from observer view. A private PROT_READ map calibrates actual kernel identity; inconclusive proof refuses. Reuse proof only while original FD and metadata pin remain valid. | **Extract a narrow Linux identity crate, medium.** Useful beyond BPF to profilers, debuggers, plugin inspectors and process scanners. Keep PKCS#11 export witnesses, manifest attestation, overlay heuristic merging and product capture budgets outside. Metadata change checks are explicitly best-effort, not a security boundary (`P/src/discovery/identity.rs:2–6`). |
| **5. Live process custody and proc views**. `P/src/process.rs:719` `PidPin`, `:726` `acquire_proc_dir_with`, `:756` `ProcPin`, `:501` `ProcessView`; `P/src/pidns.rs`. | Original pidfd is signaling authority; proc-stat fallback can establish weaker observation only. Strict proc acquisition requires original pidfd + admission start time and checks liveness around open/read. Retained proc directory pins a PID object, **not an mm**; full-image brackets supply stronger authority. Namespace numbering must agree. | **Extract small capability types, medium.** Broad Linux Rust applicability. Do not expose one boolean “process valid” for signaling, historic attribution and current-image actions. PID-only `Tracker::identify`/`poll_exited` ladder is cfg(test), not the production algorithm (`P/src/process.rs:22–29`). |
| **6. BPF producer-owned process/image identity**. `P/crates/ebpf/native/image_identity.c:38` `cookie_for`, `:123` `identity_for`, `:147` `p11_link_current_identity`; `P/crates/ebpf/native/image_identity_fork.c:16` `task_newtask`; `P/src/history.rs:65` `Registry::admit`. | Non-reused task-storage cookie + same typed task's exec ID; cookie 0 invalid, exec ID 0 valid. Bounded ticket allocation/CAS failures are explicit. Consumer namespace includes retained map domain; reject old exec generations/foreign domains, retire predecessor when exec advances. CLONE_THREAD is not a new process; fork identities originate at birth hook. | **Extract protocol plus adapters, high.** Shared user/kernel observation use; general Rust pattern is owner-issued identities and epoch-scoped tokens. Need a C/BPF and Rust contract package, not merely a Rust struct. Never recreate historical identity using current `/proc` lookup; consumer domain must survive FD/map lifetime. |
| **7. Exec continuity, physical rearm and retirement**. `P/src/attach/pid_continuity.rs:18` `PidContinuityRefusal`, `:31` `OwnerHealth`, `:114` `NativeAttempt`; `P/src/attach/native_retirement.rs:18` `RetirementTicket`, `:55` `NativeRetirement`; `P/src/attach/global_retirement.rs:42` `same_retained_point`. | Keep identity continuity separate from physical links. Preserve pairs only with exact request/domain/loss/clock/registration proof; task replacement can require rearm even if pathname/offset are unchanged. Quarantine pending/failed close while holding original file; foreign/old tickets cannot settle it. Gap clocks include failed wide attempts before bisection. | **Extract smaller state machines after second consumer, high.** Keep session orchestration product-local. General Rust value: asynchronous resource retirement with capability tickets and quarantine. No claim of universal five-second cleanup or final settlement; preserve unknown/pending outcomes. |
| **8. BPF owner leases and quiescent drain**. `P/crates/ebpf/native/task_owner.h:22–81`; `P/crates/ebpf/native/stop_gate.h:20` `p11_stop_gate_enter`, `:56` leave; `P/src/events.rs:291` `BoundedRecordSource`; `P/src/attach/cleanup_worker.rs:416` `CleanupWorker`. | Count admitted producer bodies; stop forbids new admission; leave exactly once. Freeze loader configuration before links; poison/debt terminal. Proven quiescence plus fixed cursor boundary authorizes finite drain; BUSY below proven Q is an ungated-writer violation, not success (`P/src/events.rs:266`). Owners survive pending detach. | **Extract mechanisms and regression kit, high.** Task-storage lease accounting currently embeds START/discovery/object layouts and limits; do not transplant whole header. BPF-specific implementation, general shutdown/ownership pattern. Couple admission, object checker, consumer boundary and close-error tests; do not ship a lone stop flag abstraction. |
| **9. Functional kernel capability/hazard probes**. `P/src/uretprobe_hazard.rs:36` `KernelVerdict`, `:90` `decide`, `:245` `probe_kernel`; multi PID filter in candidate 1. | Distinguish clean, affected, unknown and missing privilege. Probe owned child/thread/process; validate positive own-thread hits and negative child hits. Unknown cannot silently become safe; override does not cure missing privilege. Kernel release string is insufficient for distro backports. | **Extract probe engine/results, keep operator policy adapter, medium.** Critical across user-probe products; ordinary Rust applicability limited to host-feature detection. Test harness must own/reap child and restore signal handling; serialization avoids probes counting each other's calls. |
| **10. Compiler/tool selection and output isolation**. `P/build_support/bpf_tools.rs:29` `bpf_cargo_command`, `:66` `isolate_bpf_output`, `:75` `selected_rustc_library_path`; `P/build_support/clang_resolve.rs`; `P/build.rs:337`. | Select Cargo/rustc as pair, derive LLVM libraries from selected rustc sysroot, preserve non-UTF8 paths, reject partial/relative/nonexecutable pair, remove inherited wrappers. Child Cargo must override both target and intermediate build directories to avoid parent-lock deadlock. BTF/CO-RE required in every build. | **Extract build-support helpers, low–medium.** Broad general Rust use for nested Cargo/toolchain builds. Parameterize toolchain/prefix; do not universalize `nightly-2026-05-20`, clang-18, linker 0.10.4, or product release Rust 1.98.1. Carry PATH/permissions/sysroot-failure tests. |
| **11. Verifier and emitted-object regression kit**. `P/scripts/check-bpf-map-defs.py`; `P/scripts/check-stop-gate-object.py`; `P/tests/bpf_map_contracts.rs:64`; `P/tests/exec_task_continuity.rs:171`. | Check actual emitted maps, relocations, helper signatures, call paths, atomic lowering and stack discipline; perturb object bytes to prove checker sensitivity. CO-RE field existence before size/offset/read; unsupported shapes refuse. Native helpers plus synthetic target BTF exercise the compiled predicate. | **Share test infrastructure plus product rule manifests, medium.** Highest cross-project return; build regression checks alongside reusable primitives. Generic ELF/BTF decoder/checker core is separable; exact p11 map/program inventories and allowed memory reads remain adapters. Host relocation/interpreter tests do not qualify any kernel verifier. |
| **12. Strict maps/ELF inspection**. `P/crates/manifest/src/maps.rs:57` `parse_maps`, `:216` `MapIndex`, `:268` `mapped_path`; `P/crates/manifest/src/identity.rs:203` `inspect_file_with_reader`; `P/crates/manifest/src/elf.rs`. | Preserve pathname bytes; reject malformed/overlapping/unsorted snapshots; checked file-offset arithmetic; distinguish valid absence from invalid snapshot. Read/hash/ELF classification share bytes and charge each read; build ID is producer-supplied evidence, full SHA256 authorizes manifest reuse. | **Extract generic parser/inspector layer, medium.** Strong non-BPF Rust applicability. Existing object crate should remain parser backend; do not write another ELF decoder. Keep PKCS#11 function-table/names/version interpretation in product. Fixed 256 MiB input cap should be caller policy. |

## Hard fixes worth carrying with their regressions

1. **Wrong map descriptor after local-map relocation.** Multiple definitions in `.maps` were treated as one section map; local LLVM section references could select an arbitrary FD or trigger a debug assertion. The correction's own regression functions are `section_map_offsets_select_distinct_descriptors`, `section_map_offset_uses_unsigned_32_bit_addend`, and missing/interior/ambiguous cases at `P/third-party/patches/aya-obj-0.3.0/aya-obj-map-relocation.patch:149–178`. Application regression `embedded_maps_relocate_without_kernel_syscalls` assigns distinct sentinel FDs to the actual embedded object and checks native-map references (`P/tests/bpf_map_contracts.rs:61–100`). Ordered-patch packaging landed in `17139209215da1584b5ab7a120416b84db98daf9`; that packaging commit is not claimed as the original fix authoring commit.
2. **New-kernel private-stack corruption.** Commit `d69c940ae6651c1d063a6644a11319f6e936b379` records a Linux 7.0, 12-thread SoftHSM run where one thread's return probe saw another's START key. Its diagnosis: x86 private BPF stacks introduced for KPROBE programs also applied to preemptible uprobes; migration disabling alone did not prevent a second task overwriting the shared per-CPU frame. Current `keep_kernel_stack` / `keep_endpoint_stack` deliberately issue out-of-range tail calls, keeping a task kernel stack, with separate arrays for expected attach types (`P/crates/ebpf/src/main.rs:173–205`). Actual-object mutation regression is `MapDefsTests.test_classic_uprobe_kernel_stack` (`P/tests/python/test_bpf_map_defs.py:274`), wired by `P/tests/bpf_map_contracts.rs:117`. Keep this workaround and test centrally until actual upstream/kernel coverage proves safe removal; the source mentions an upstream discussion without a URL.
3. **Ring cursor wrap and drain boundary.** The reader once panicked when an aligned eight-byte payload advanced `usize::MAX - 15` to zero. Tests now cover ordinary/wrapping cursor publication, Drop exactly once, discard before data, and BUSY without consumption (`P/third-party/patches/aya-0.14.0/aya-ring-reader.patch:783–860`). Fixed-tail regressions include producer extension, word wrap, invalid boundary and crossing record (`:655–755`). Current patch also contains H8 additions at commit `b346e5ea3e18fc3063a28f6bbf630aed23c669a2`; separate minimal upstream reader fixes from product-motivated bounded API proposals.

Additional concrete lessons:

- **Old kernels expose uninitialized padding that new ones accept.** `SelectionTransport` now has repr(C), explicitly initialized padding and offset assertions; the comment records identical object accepted by 6.5+ but rejected by 5.15/6.2 with `invalid read from stack off -72+3 size 8` (`P/crates/ebpf/src/main.rs:750–780`). A size-only assertion would miss implicit padding. Likewise separate globally verified template walkers avoid repeated 5.15 state exploration exceeding 1,000,000 instructions (`:2140–2155`), and nullable map lookup must be checked even when one-entry array logic makes failure unlikely (`P/crates/ebpf/native/stop_gate.h:49–63`).
- **Btrfs and pre-6.8 overlay identity are different fixes.** Mount-table device resolves Btrfs anonymous subvolume st_dev; pre-6.8 overlay can still render a different kernel maps identity and needs actual held-FD calibration. Commit `54980467ed1dbb1daa40762098a06991f5ae979c`; regressions `overlay_probe_match_accepts_a_split_identity`, mismatch/inconclusive refusal (`P/src/discovery/identity.rs:3322–3381`). `7efdc70b` moved the probe into manifest; `dcc1645a` bound pre-exec loader pins; `6adbe91f` reuses held proof to avoid remapping watched files. Mapping a watched target for calibration can itself interfere with attachment/cleanup; keep `KernelAnchorExclusions` (`P/src/discovery/kernel_identity.rs:29–73`). A generalized identity API therefore needs a no-new-mapping mode and retained proof reuse.
- **Same PID is neither same image nor same physical attach.** `3eab63207f08277bc8e841abb1a1a35bbc316172` fixes redundant rearm after task replacement (preceding RED `151e508e`); earlier `a5cf75f6` preserves proven pairs across automatic exec. `NativeRetirement` tests pin original FD retention, foreign/old ticket rejection, failed-close quarantine and transfer failure (`P/src/attach/native_retirement_tests.rs:100,274,329,490`). Share these adversarial scenarios, not just happy-path fork/exec fixtures.
- **CO-RE compatibility needs explicit unknown shape behavior.** `p11_exec_dumpability` handles old scalar flags and nested bitmap flags, rejects newer `exec_state` layout, guards field existence/size/signedness/shifts (`P/crates/ebpf/native/exec_task.c:18–76`). `exec_task_core_supported_and_unknown_shapes_take_safe_compiled_paths` relocates generated BTF shapes and interprets emitted instructions (`P/tests/exec_task_continuity.rs:171`); separate ignored root test is explicitly only host-verifier load coverage (`:245–249`). Do not relabel synthetic-shape success as old/new kernel runtime support.
- **Capability evidence needs negative populations.** Multi PID self-probe requires own two threads = 2 and forked other process = 0 (`P/crates/bpf-multi/src/lib.rs:600–620`). Uretprobe/seccomp source records Ubuntu 6.11.0-17 affected versus 6.11.0-29 clean, proving uname minor-version gating inadequate (`P/src/uretprobe_hazard.rs:4–18`). Unknown fail-closed correction: `127d70cb7eca1814ee0ff83aed398e236432c772`.

## Dependency, upstream, and licensing facts

Root manifest selects `aya = "=0.14.0"`, `aya-obj = "=0.3.0"` through reconstructed local `-p2` packages (`P/Cargo.toml:29–65`). `P/third-party/sources.json` records ordered patch files, archive hashes and expected trees, rather than relying on generated source edits:

| Package | Registry archive SHA256 | Expected reconstructed tree SHA256 at baseline |
|---|---|---|
| Aya 0.14.0 revision 2 | `66e644424fada9fff4fdc63848db1732fb69b626e8328202ef55c03df1f4d939` | `68514bc26d1b30382b52e270799605f4651416b6c8367cb8dafe11cfa00317c2` |
| aya-obj 0.3.0 revision 2 | `8c76b9c75d9cdc155ff8f6a06d61e873f67bf47be8cfa92a3b5aaea43f4b4077` | `e2c4a68d41a052fed8387406f2a627a9cdb695050fc4728ef6a257b4d1ca6176` |

Aya archive records upstream `302985c72850cd9a8f1d791a11d247a4fbe1c5b1`; aya-obj records `269dfaf4a20b99f2e3d384e3e5d13b226f507360`. Documented multi backport: [Aya PR 1417](https://github.com/aya-rs/aya/pull/1417), commit [5c1a79e0bdc36e77b304c1a08ff8b05e6b823108](https://github.com/aya-rs/aya/commit/5c1a79e0bdc36e77b304c1a08ff8b05e6b823108); local extension `UProbe::load_multi` chooses expected attach type at runtime (`P/third-party/README.md:89–105`). Local-map correction cites the [LLVM BPF relocation specification](https://docs.kernel.org/bpf/llvm_reloc.html), not an LLVM bug ticket. Uretprobe source cites kernel fix `cf6cb56ef244`, not a full URL. No live upstream status check was performed in this repository lane.

Current build docs pin BPF nightly `nightly-2026-05-20`, bpf-linker 0.10.4, release Rust 1.98.1; old Rust 1.88 command remains in third-party patch documentation and must not be treated as current project MSRV. Compiler/library-selection repair is `4f6250b34a59c0e8839198e73cac2a946e737cc4`. Both root and BPF Cargo locks matter, but generated patched trees are not editing locations (`P/AGENTS.md:42–49`). Linux 5.15 qualification remains explicit despite newer host (`P/docs/development.md:77–80`).

Metadata only, no legal conclusion: userspace crates (`p11scope`, manifest, discover, bpf-multi), docs and scripts say **GPL-3.0-or-later**; BPF says **GPL-2.0-only**; `crates/ebpf-common` says **GPL-2.0-or-later** (`P/CONTRIBUTING.md:7–17`, crate manifests and per-file SPDX). Aya source/backport retains **MIT / Apache-2.0** attribution (`P/third-party/README.md:41–45,102–105`). bpf-multi explicitly cites OSSLscope GPL-3.0-or-later provenance at revision `807dbba8f06c0d215f1c43c57090fe6c3436896f` (`:20–27`). Extraction must preserve file boundaries and actual notices; do not assume all code can adopt one new library license.

## Extraction order and negative recommendations

First consolidate dependency patches/tests; then link-only multi attach, build support, strict maps parser and held-object identity. These reduce repeated bugs without moving the product controller. Next design producer-domain/process capabilities with at least two actual consumer adapters. Retirements and quiescent drain should follow only with their concurrency/fault/foreign-token tests and real-kernel matrix; accepting one project's Session shape as a universal API would cement coupling.

Keep PKCS#11 descriptor catalogs, operation/object/key reducers, allowlists and privacy decisions, manifest attestation policy, inventory presentation/schema and H8/H9 semantic journal behavior product-specific. Current journal comments can still describe earlier “inactive” slices while later code has wired producers; source wiring/current handoff outrank stage labels. Do not extract abandoned test-only PID tracker, old raw loader, or entire `ebpf-common` just because they appear reusable. Do not promote absent observations to absence proof, old gate reports to present qualification, successful BTF relocation to verifier acceptance, or simulated owner fixtures to concurrency proof.

The reusable regression deliverable should be source fixtures plus adapters: local map symbol/addend mutations; read-only ring BUSY/discard/wrap/fixed tail; fork/thread/leader/nonleader exec; PID reuse and denied pidfd; failed exec vs successful exec; fd/path replacement, Btrfs and overlay; scalar/bitmap/missing BTF fields; compiler PATH and output-lock isolation; poisoned counters, wrong-domain tokens and failed/asynchronous close. Keep commands runnable and results explicit; do not duplicate the historical private evidence archive.

## Complete local ref/worktree census (expanded scope)

Read-only `for-each-ref refs/heads refs/remotes`, `worktree list --porcelain`, every registered worktree status, and `git cherry BASE TIP` were inspected. No remote refresh. Patch-equivalence is Git patch-id equivalence for nonmerge commits, not proof of identical final behavior. A full census does not mean every historical source file was rereviewed. Product has 199 refs, 193 distinct tips, 73 registered worktrees.

<details><summary>Exact product refs and worktree locations; all local and remote-tracking refs</summary>

| Ref | Full tip | Relation to research baseline | Registered worktree |
|---|---|---|---|
| `refs/heads/ci-fix/20261006` | `068b56b595a22d2749e4929a3bd311b3ad0fa71c` | ancestor/equal |  |
| `refs/heads/dev/v0.3.0` | `792530713348f3a74e9100140226a51aea65a666` | ancestor/equal |  |
| `refs/heads/dev/v0.4.0` | `cfaea1888b448451b46c9ede4bc9b272da93f49d` | ancestor/equal |  |
| `refs/heads/dev/v0.4.0-managed` | `3282dacae8832116ed3c1eb6e6ede64968c637de` | ancestor/equal |  |
| `refs/heads/keep/v040-before-linearization-20261009` | `cbb280054148fbf057441c06aa34a2bc7210408d` | 78 unmatched, 29 equivalent |  |
| `refs/heads/main` | `7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4` | ancestor/equal | `W/p11scope` |
| `refs/heads/task/v040-attach-e2e-workload-lifetime` | `10a9c619c875bd25f219d70e7e2209ec5ae24010` | ancestor/equal | `W/.worktrees/v040-h6-system-name` |
| `refs/heads/task/v040-attested-subset` | `55d58df460ac7ae1d35100ba6da745bdc4878749` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-capacity-fixtures` | `823f90bbbe5969af0696108cfa462fc7a2f69014` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-capacity-public-growth` | `f89027e2e1d0eafc0ca581f2fa038f0b8bae1bea` | 1 unmatched, 0 equivalent |  |
| `refs/heads/task/v040-capture-wording` | `926c41f25dc4ace6e66365594eaa0fe93ab1ae0a` | 68 unmatched, 6 equivalent |  |
| `refs/heads/task/v040-catalog-profile` | `3556a23fc1c8b7ea5d5621e80deb04f62c8977f1` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-cgroup-admission` | `abfb093df779060749bbf8196b08dd123063b459` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-cgroup-consumer` | `6b586c1cabba62a7bbb90eb66ec04ae3f6b115de` | 71 unmatched, 24 equivalent |  |
| `refs/heads/task/v040-cgroup-facade` | `e7813f153e13008c18b06d4f0124d580ef2b9fe3` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-cgroup-runtime` | `a911a2ca17fe5add8a7cfa7bfa42f816c2f9a832` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-cgroup-trace` | `e4bf85657235fbf56f66f417f3caa436cd2dcd4c` | 71 unmatched, 23 equivalent |  |
| `refs/heads/task/v040-cgroup-trace-live` | `28cb337027e4d8851c907156c9d711d15e8bd4a9` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-cgroup-trace-matrix` | `67bc9f9443ff9e611feb66eeee2329a70d9eb0f3` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-ci-5358-fixes` | `2504f02c2c92efd50ee1847a6d735b6412689629` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-ci-attach-diagnostics` | `fefeb3fbb408629a4f5d77931ec246b447932d63` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-ci-diagnostic-contract` | `7991b676c5dcc92ddfbe584972e68f4c692c5a35` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-ci-lifecycle-fixture` | `a14328ad29054c240d48f0f9dfef8d8e3096299b` | ancestor/equal | `W/.worktrees/v040-ci-lifecycle-fixture` |
| `refs/heads/task/v040-ci-proven-pid-retirement` | `a633ae52060d69fa1db175bacbf55e781232ee15` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-ci-runtime` | `d239b4bcda912102b24ba94f13cd0f2a397bd962` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-current-receipts` | `34da8e9282fd4a748be30c635ea4a976339dbf29` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-d3a-userspace` | `49bab5c8d15b60a94c91d5d88de03c63ffc8a14c` | 68 unmatched, 2 equivalent |  |
| `refs/heads/task/v040-d3c-policy` | `e4ed42049b4fb52fbebcf2edaa6d166a308f82c9` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-d3d-backend` | `b74d37b3d484b1442dd5a8ebbefef1fb346f3df1` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-demotion-fixture` | `2ca7a476a4b54757766244b9235c89e3d9dc99ad` | 71 unmatched, 17 equivalent |  |
| `refs/heads/task/v040-demotion-oracle` | `a97069d26bb76a94c374ccded32218f7dbb1a430` | 67 unmatched, 4 equivalent |  |
| `refs/heads/task/v040-demotion-receipt-oracle` | `40b034e4b7af29eba9e8ef1755f20928b40b1018` | 71 unmatched, 16 equivalent |  |
| `refs/heads/task/v040-detailed-demand` | `64cde47d0c53fe4196c9899d0119b583b96590db` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-detailed-resources` | `8ff690a336de5f2add9f9654a077286903648904` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-diagnostics` | `4cfbbf8d531e5214144c1594e4cb23a49aad709b` | 74 unmatched, 22 equivalent |  |
| `refs/heads/task/v040-diagnostics-hooks` | `c856876280d2c4cc6cd25fabf6dcb5d0e3bc165d` | 74 unmatched, 26 equivalent |  |
| `refs/heads/task/v040-diagnostics-runtime` | `4cb55f771d260f6a27a1d0af34b2646aaf4951a9` | 76 unmatched, 26 equivalent |  |
| `refs/heads/task/v040-event-identity` | `be7937c66d7e6ba81f4873fd9bbf73f44095e670` | 71 unmatched, 14 equivalent |  |
| `refs/heads/task/v040-fix-d3ext` | `9c7cf1f16a5b3b5442e38ef349b9a72fbeb98043` | 18 patch-equivalent commits |  |
| `refs/heads/task/v040-fix-h3ext` | `82376e8b6e1cb3a9343ca13f41bc985da91a0b29` | 20 patch-equivalent commits |  |
| `refs/heads/task/v040-fix-h5h6ext` | `0d8a7cea6ea0397ab74668d522cdd45f41ea81c1` | 19 patch-equivalent commits |  |
| `refs/heads/task/v040-fix-h5h6ext-f9` | `ade44c7020de7334a811d0bb5104bfc69a267731` | 5 patch-equivalent commits |  |
| `refs/heads/task/v040-full-image-proof` | `0a8dc50f35d2d7c4d3f36c6227afdc612bb2f8ef` | 7 patch-equivalent commits |  |
| `refs/heads/task/v040-gate-readiness` | `5395e844a2a152c9afa941416d054d1220607c6c` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-guidance` | `6bfcfcb043c22507448026bd46ec7c508607ed90` | 68 unmatched, 6 equivalent |  |
| `refs/heads/task/v040-h3-bindmulti` | `5c1c0a24972fac55722f65e92a034ba984ca86d3` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h3-bounded-cleanup` | `fd8f9a51fc1049914293637675bee7d28464765c` | 3 patch-equivalent commits | `W/.worktrees/v040-h3-bounded-cleanup` |
| `refs/heads/task/v040-h3-owner-admission` | `24458aa9cf66feb7137e9e92556e39316e5078cc` | 3 patch-equivalent commits | `W/.worktrees/v040-h3-owner-admission` |
| `refs/heads/task/v040-h3-owner-admission-refusals` | `246f2cdf53dbdb6e0d066e4c25738364c9fd889e` | 9 patch-equivalent commits | `W/.worktrees/v040-h3-owner-admission-refusals` |
| `refs/heads/task/v040-h3-semantic-validation` | `2d36b20b901501c9a97a36b5baa2b7004e349d7b` | 4 patch-equivalent commits | `W/.worktrees/v040-h3-semantic-validation` |
| `refs/heads/task/v040-h3-task3` | `c9c89e10517369174dbe9a8ae70a3eb1c12c7f0f` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-h3-task5` | `2f4b6e293edd4cfb63bd3a01df92ed20ea7ad2fd` | 5 patch-equivalent commits |  |
| `refs/heads/task/v040-h5-pressure` | `45a676a36cc6d1ed0ae2f29495048c13b3288815` | 5 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-async-global-consumer` | `622197b260c55911588cbd73b0fa3f12520845ad` | ancestor/equal |  |
| `refs/heads/task/v040-h6-async-global-retirement` | `ef37b640171e774d32e1d19e05aff0a8f1a87b2d` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-cgroup-gap-domain` | `39810b310f3a099967f7c36aded9283d4b5eb86e` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-async-global-retirement` |
| `refs/heads/task/v040-h6-cgroup-operator-path` | `7d3fe51c73756d7323c6e3acc446eac9f538665a` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-cgroup-replacement` | `e3da4829dc601f51a6d04cb5ec33dc7883c65293` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-cgroup-replacement` |
| `refs/heads/task/v040-h6-cgroup-stop` | `2f294b3b68bc0688b0c72b12fc51c1676e8544eb` | 4 patch-equivalent commits | `W/.worktrees/v040-h6-cgroup-stop` |
| `refs/heads/task/v040-h6-cleanup` | `831ec6c2527ca395d8549adb8b61d830f3f32a2b` | ancestor/equal |  |
| `refs/heads/task/v040-h6-conservative-global-retirement` | `7c138213bc3bf9052b0717b639433d061f24fd09` | ancestor/equal |  |
| `refs/heads/task/v040-h6-count-only-hooks` | `7817146a0afefb6524ac16f5ea84b670505ee586` | 6 patch-equivalent commits | `W/.worktrees/v040-h6-count-only-hooks` |
| `refs/heads/task/v040-h6-current-refresh` | `5fd6370e73571ddc1c16d5ad34aac976a1379f3d` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-current-refresh` |
| `refs/heads/task/v040-h6-driver-repair` | `640536cc1a3cb7a429fe99ca12b78d61a7112bd5` | 19 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-early-detach` | `946472e7e43e4feaea996b9052c5afdeca5825aa` | 8 patch-equivalent commits | `W/.worktrees/v040-h6-early-detach` |
| `refs/heads/task/v040-h6-exec` | `6c84e6b5c00d76e715ad7a24df92f14774acee65` | 13 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-fd-close-fixtures` | `bf70964961e1361030e3c8c17c09d7f1810168b4` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-fd-close-fixtures` |
| `refs/heads/task/v040-h6-final-gap-disclosures` | `8da8e9af0c7ea451dcceeeaaf2c20c722c365957` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-final-gap-disclosures` |
| `refs/heads/task/v040-h6-gap-oracle` | `d8c18e8538bf994f8e14f794c9c79e81d8fdce7b` | 2 patch-equivalent commits | `W/.worktrees/v040-detailed-resources` |
| `refs/heads/task/v040-h6-gap-public` | `ab7de33fdc78b22f273fd37a68dafd4a8851ee8b` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-driver-repair` |
| `refs/heads/task/v040-h6-gap-vocabulary` | `8a9aac4b9cfbd26f9ed314358c3273bb93bd1431` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-gap-vocabulary` |
| `refs/heads/task/v040-h6-global-static-gap` | `baf6039143479d62b0a0a8e077caedc92b30d49a` | 3 patch-equivalent commits | `W/.worktrees/v040-h6-global-static-gap` |
| `refs/heads/task/v040-h6-held-identity` | `451f84aa4dc322c2261aadcda20c8ecce707eebd` | 4 patch-equivalent commits | `W/.worktrees/v040-h6-held-identity` |
| `refs/heads/task/v040-h6-ia32` | `ba3d8240f013bfbd11bd3dcb984bf3d54b160f51` | ancestor/equal | `W/.worktrees/v040-h6-ia32` |
| `refs/heads/task/v040-h6-ia32-shared-drain` | `902f38eaa2b579eb965970bc69706c8da0c75495` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-ia32-shared-drain` |
| `refs/heads/task/v040-h6-inherited-loss` | `469fdd04e04dd658449f00f45e4bb7ac252e5fe4` | 4 patch-equivalent commits | `W/.worktrees/v040-h6-inherited-loss` |
| `refs/heads/task/v040-h6-initial-coverage` | `ad28a305b83e7b94b4433651cac5fb53b806b3a9` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-initial-coverage` |
| `refs/heads/task/v040-h6-initial-exec-controller` | `f24c08bbb417e59a1d929cd9234c57b83a8c6225` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-initial-exec-process` | `b5134531450ade7c60366d9d1e3be5de6d85f139` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-initial-exec-process` |
| `refs/heads/task/v040-h6-initial-readiness` | `4b6d8341bd467f29bd67e2594c887b98c3bcac26` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-initial-readiness` |
| `refs/heads/task/v040-h6-inspect-stable-child` | `8d87ab0af0d788b0f4a103f1a60034c755c52fe3` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-inspect-stable-child` |
| `refs/heads/task/v040-h6-inventory-admission-control` | `ed21ffa17966107446182daf3ca0c112eb7cdf1b` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-initial-exec-controller` |
| `refs/heads/task/v040-h6-inventory-exit-retention` | `757a4c27af93016a3551bb950f240f3889067d51` | 1 unmatched, 1 equivalent | `W/.worktrees/v040-h6-inventory-exit-retention` |
| `refs/heads/task/v040-h6-kernel-anchor-exclusion` | `fc76de885300fb265cae066b17de7b26e26955ef` | 4 patch-equivalent commits | `W/.worktrees/v040-h6-kernel-anchor-exclusion` |
| `refs/heads/task/v040-h6-late-provider-exec-boundary` | `2fb12a5ca78549514fdcdb2487f9bb4cd96b53ae` | 6 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-leader-held-entry` | `d31ba59af652e716416e4d36f6a5b1becb15c634` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-leader-held-entry` |
| `refs/heads/task/v040-h6-live-child-fixture` | `1a66e28421375ae929257cbf463b830337003e46` | 1 unmatched, 1 equivalent | `W/.worktrees/v040-h6-live-child-fixture` |
| `refs/heads/task/v040-h6-loader-readiness` | `b89aa445d65c120ec16b06b871008e08f00e8357` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-measured-refusal` | `187f8cb49e70ace859201ab7d523bc84933e7855` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-measured-refusal` |
| `refs/heads/task/v040-h6-metrics-metadata` | `d2f577ec084d23a30e1a266668ca42d0a050f79e` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-physical-ledger` | `55a83ae45536788912968ea6b28f5757f560937f` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-physical-ledger` |
| `refs/heads/task/v040-h6-product-repair` | `3eab63207f08277bc8e841abb1a1a35bbc316172` | ancestor/equal |  |
| `refs/heads/task/v040-h6-provider-receipt` | `c6f1376e9437c6f788e8bfc70f22e2d839bcc945` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-provider-receipt` |
| `refs/heads/task/v040-h6-ptrace-seize-options` | `a72b3eb80632abc53fbddb8eea5f460357808600` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-rapid-cleanup-scope` | `6076319335b74ed274e0977420bed74e5e84b844` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-reader-eof` | `db7527b40760074a0ea292caddc3ac996af6a06a` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-reader-eof` |
| `refs/heads/task/v040-h6-readiness-cadence` | `c4c064fa0d7e611b2e62e1e3be25357e0cfad876` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-readiness-cadence` |
| `refs/heads/task/v040-h6-recovery-followup` | `adb6675230d15e41b23b1f715b64bd4a23278f5e` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-registry-initial-coverage` | `788032210a0f601b0f8f3ee7aabadebb915622b6` | 4 patch-equivalent commits | `W/.worktrees/v040-h6-registry-initial-coverage` |
| `refs/heads/task/v040-h6-replacement-readiness` | `78aec61d7a5878cdd924d6d23c4b786925a1601a` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-replacement-readiness` |
| `refs/heads/task/v040-h6-replay-tests` | `d7b84c45e3c5a712935a2dfa48fc450438f4bb33` | 10 patch-equivalent commits | `W/.worktrees/v040-h6-replay-tests` |
| `refs/heads/task/v040-h6-retained-map-identity` | `1a5987a77432d89fd22ed748ada8b02421808a6b` | 4 patch-equivalent commits | `W/.worktrees/v040-h6-retained-map-identity` |
| `refs/heads/task/v040-h6-runner-curation` | `4cd080da4bfa2c91985aa546e71873fc741c0187` | 2 patch-equivalent commits | `W/p11scope/.worktrees/v040-h6-runner-curation` |
| `refs/heads/task/v040-h6-running-detach` | `3a3a78489f8fba0dfceef077044a50f84f6a9f00` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-running-detach` |
| `refs/heads/task/v040-h6-semantic-admission-eligibility-tests` | `e13fac43ebbcaf49db9089e24af12a9c24d48675` | 4 patch-equivalent commits | `W/.worktrees/v040-h6-semantic-admission-eligibility-tests` |
| `refs/heads/task/v040-h6-semantic-eligibility` | `8f978ae439b83709bff6f563b476d5bc5d32d046` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-semantic-eligibility` |
| `refs/heads/task/v040-h6-sibling-shape` | `fd3a949cfe745951dd207907571172572630cff5` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-sibling-shape` |
| `refs/heads/task/v040-h6-sibling-stage-test` | `4918bf65eefe971fef98a5d2cc333f68a9b53676` | 1 unmatched, 0 equivalent | `W/.worktrees/v040-h6-sibling-stage-test` |
| `refs/heads/task/v040-h6-stop-baseline` | `d0edf67c4dce4177ea2ada5e7b178a2ab0f44804` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-stop-baseline` |
| `refs/heads/task/v040-h6-stop-fixture-key` | `305e1f943eae0a883883ef62a114b05b38021c62` | 1 patch-equivalent commits | `W/.worktrees/v040-h6-stop-fixture-key` |
| `refs/heads/task/v040-h6-stop-inventory` | `2ba5270a14dcbf75e59195979e6d0b4f5a73b885` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-stop-inventory` |
| `refs/heads/task/v040-h6-system-anchor-native` | `3eb713352d82531983d020d6f15cef5ba3dd4326` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-system-anchor-native` |
| `refs/heads/task/v040-h6-system-disclosures` | `d8d0bd4d9b42890bff29a9bd01531b179bd2a3df` | 1 unmatched, 1 equivalent | `W/.worktrees/v040-h6-system-disclosures` |
| `refs/heads/task/v040-h6-system-name` | `0e1d32026c4d3c6f54e8c9854ad89096388cec77` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-system-name-credit-retry` | `57bbfdbae3f7b8668545e981ce197952b6880c32` | 1 unmatched, 1 equivalent |  |
| `refs/heads/task/v040-h6-system-name-late-provider` | `7236ecfc1ce524615a3c9240540858bf72d17906` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-system-name-live-association` | `7a2a61af0afe51b6555bc45bed3e338ae27d8a1c` | 4 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-system-name-priority` | `1dff8e271f90caef96e4333fdf3588a44730a2b7` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-system-name-provider-fixture` | `addabc5f4befd632de6c2779e0a5efbdae02eca9` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-system-prewarm-admission` | `c9668e646d3642c7fbde19d76bc2a67abdfd86fb` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-system-prewarm-admission` |
| `refs/heads/task/v040-h6-system-result-list` | `dcf8ea8d3041a331ff28518fa35a515cd37a0d0a` | 2 unmatched, 8 equivalent | `W/.worktrees/v040-h6-system-result-list` |
| `refs/heads/task/v040-h6-system-sibling-baseline` | `57747d447453a46e1ac57e30947b1d0f96d46d90` | 1 unmatched, 1 equivalent | `W/.worktrees/v040-h6-system-sibling-baseline` |
| `refs/heads/task/v040-h6-target-preuse-disclosure` | `6c85c26db7c859e83a717899ecfbfa7cbff61d88` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-target-preuse-disclosure` |
| `refs/heads/task/v040-h6-task-replaced-rearm` | `3eab63207f08277bc8e841abb1a1a35bbc316172` | ancestor/equal | `W/.worktrees/v040-h6-task-replaced-rearm` |
| `refs/heads/task/v040-h6-va-reuse` | `4ee07402c0197858542a83e5909a079bf099c224` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-h6-va-reuse-pad` | `3376c138483b80040bc4ee29c7a7bc60eb315619` | 1 unmatched, 0 equivalent | `W/.worktrees/v040-h6-va-reuse-pad` |
| `refs/heads/task/v040-h6-warmup-pacing` | `261d91b34efb9b8b79e6580641b9af2fdf5b22b1` | 2 patch-equivalent commits | `W/.worktrees/v040-h6-warmup-pacing` |
| `refs/heads/task/v040-harness-gate` | `3adc565662d6761837f4b4a9d565b4e4c9ddf66c` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-help` | `879e2e5234ba373923db516165e4b28aef2bc6ef` | 68 unmatched, 7 equivalent |  |
| `refs/heads/task/v040-ia32-cli-temp` | `c1245bf834701d17eb884f9b44cc21b6750e74ea` | 1 patch-equivalent commits | `W/.worktrees/v040-ia32-cli-temp` |
| `refs/heads/task/v040-identity-integration` | `baf649fa94456ccc3b91a32ff14d7477f9aceccb` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-image-proof` | `d0adcfcf2db784dcbd4b876c484faacb57c766e2` | ancestor/equal |  |
| `refs/heads/task/v040-image-routing` | `6853fbd73bf30515da773d397581d35431037c7a` | 2 unmatched, 9 equivalent |  |
| `refs/heads/task/v040-inspect-identity` | `1427e119bc082428d1cae4a125606e5a88864a62` | 71 unmatched, 14 equivalent |  |
| `refs/heads/task/v040-inspect-readiness` | `1819f90b4f0e0d158784a2179f2fb34f1523945a` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-inspect-system` | `3bf175643840e1747a632e20427935be6b10e161` | 76 unmatched, 27 equivalent |  |
| `refs/heads/task/v040-installed-journeys` | `1eb3313dd29a812672f66bf8b36f014f02fc4212` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-instance-s1` | `c7989959df87245f3f38d2df348d317635332d72` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-inventory-capacity` | `666349952ba43d2212a88a03e143fdac841d6cd5` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-inventory-cgroup` | `ec37f5592ab3fc4ac0acee3e9fb3cda2553f47fd` | 76 unmatched, 28 equivalent |  |
| `refs/heads/task/v040-inventory-reader` | `779c02e648384ed3624c53bf9e28ad5f6091d94e` | 68 unmatched, 7 equivalent |  |
| `refs/heads/task/v040-kernel-mapping-release` | `6c47ed831178960ab706f05d7d332a31695d584c` | 3 patch-equivalent commits | `W/.worktrees/v040-kernel-mapping-release` |
| `refs/heads/task/v040-kernel-proof` | `5aede3fde401b05357701cf3a6018fb46479c3a6` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-kernel-segments` | `488fab295e513daa008c08a564c680f50853868a` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-key-operation-fixture` | `15c12f6eacfcad35fba082fea293e307d5936510` | 1 patch-equivalent commits | `W/.worktrees/v040-key-operation-fixture` |
| `refs/heads/task/v040-linear-history` | `602f00b7d59c6a1386148ba035fe4f2df6b23332` | ancestor/equal |  |
| `refs/heads/task/v040-loaded-seed-peer-readiness` | `822b6d283eafbc661b24fbdc11280f1aca13e0e0` | 8 patch-equivalent commits |  |
| `refs/heads/task/v040-loader-plan-reuse` | `e663989ddbe915fb9056fe8181870eb51c3ab8f0` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-matrix-contract` | `e8942954d28a7ea65f159c3d741a14567b410a26` | 70 unmatched, 3 equivalent |  |
| `refs/heads/task/v040-n3-path-fix` | `4f0f729e957fa534221e894e330e13194d44d820` | 2 patch-equivalent commits |  |
| `refs/heads/task/v040-output-harness-flake` | `fa265934e2f2e1b38f745d4c4737a5ea6bd0c210` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-output-integration` | `55b56de1f55a16d53fe2a065d36ad1c0f3eff906` | 68 unmatched, 2 equivalent |  |
| `refs/heads/task/v040-privacy-canary` | `0000cd2f998036d82ad895d7bd9ed9d56f7a61a9` | 2 patch-equivalent commits | `W/.worktrees/v040-privacy-canary` |
| `refs/heads/task/v040-privacy-canary-red` | `9ecb26cbac84386484bc99367198c3cdf8088a14` | 1 patch-equivalent commits | `W/.worktrees/v040-privacy-canary-red` |
| `refs/heads/task/v040-privacy-test-child` | `8abf38e600aa11650b87cd5b2b83d4fae1747313` | 4 patch-equivalent commits | `W/.worktrees/v040-privacy-test-child` |
| `refs/heads/task/v040-public-cli-mapped-pin` | `aef39eba61a67555ecdd3afe3cf51e3021cfe67c` | 78 unmatched, 27 equivalent |  |
| `refs/heads/task/v040-public-cli-oracle` | `080ab6b84f343632418afe6a86506f691006752f` | 68 unmatched, 3 equivalent |  |
| `refs/heads/task/v040-public-journeys` | `ee26bb0c8d728d59c19e9cff081be1fbf200ef40` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-python-lint` | `e4540e241ee1b5cc0e2e6da70468418710e82ba7` | 76 unmatched, 28 equivalent |  |
| `refs/heads/task/v040-refresh-ci` | `74110d4d279ea478629ee4f8775157c1eb6c0ddd` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-refresh-fairness` | `cf07e351dc38d130572590d68c4579466b8d269c` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-refresh-overflow` | `0b3e3eb26a8c68d6ba07dda2269fa53b20e8750d` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-refresh-queue-fairness` | `926af868b36e9a35c68104aeecaf3f21414a9abb` | 78 unmatched, 28 equivalent |  |
| `refs/heads/task/v040-retirement` | `23314dd987827ddf4026faccb7caff5ccb149586` | 76 unmatched, 27 equivalent |  |
| `refs/heads/task/v040-s4-ci-repair` | `d4b46780b526ce7afcc14bb8c7a83626ea3f4368` | 3 patch-equivalent commits |  |
| `refs/heads/task/v040-semantic-budget` | `f9cfa44c9c022eda77bbd94b0036d3dc84a2c4f2` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-semantic-budget-output` | `33f4718ce0106483221687896f0a620383563903` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-semantic-resources` | `e6f737bb4ccb86d0c8a51c0efe21fb257c6a6106` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-stage3-ci` | `345bce888f89e2fba13965dd339f222f4f998d54` | 67 unmatched, 0 equivalent | `/home/user/src/m/p11scope-wt-v040-stage3` |
| `refs/heads/task/v040-stage3-managed` | `329075780a9f5d30d613638761b049b567a53861` | 67 unmatched, 4 equivalent |  |
| `refs/heads/task/v040-system-throughput` | `bacd6e36f2844a9a62cd1483745b0a919750ac58` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-t4final-mem` | `4297f0255221c4a4a711f1760d8494c4026cedd1` | 1 patch-equivalent commits |  |
| `refs/heads/task/v040-tabled-ready-protocol` | `9baafaf9828b42403a4962d7d80c31cc367109c4` | 2 patch-equivalent commits | `W/.worktrees/v040-tabled-ready-protocol` |
| `refs/heads/task/v040-test-binary-size` | `76e1fc4b7a41c97446022bcf93deecb90c80d307` | 4 patch-equivalent commits | `W/.worktrees/v040-test-binary-size` |
| `refs/heads/task/v040-trace-consumer` | `e8c1f56be9bcbdd053395aaf85e6af4ccea143b7` | 72 unmatched, 15 equivalent |  |
| `refs/heads/task/v040-trace-proof` | `e37a1d203c21373a737d3e92a495067bf203bc0a` | 68 unmatched, 6 equivalent |  |
| `refs/heads/task/v040-ux-assertions` | `57cf9c469f623b8b21f21727be46baa8b6516809` | 76 unmatched, 31 equivalent |  |
| `refs/heads/task/v040-validator-timeouts` | `1f81399a0244881e250ea0731cf6fa184f5405ea` | 76 unmatched, 29 equivalent |  |
| `refs/heads/task3-stage-a` | `40e0a557e20050c436c13052d3ef711f42ff23ec` | 95 unmatched, 6 equivalent |  |
| `refs/heads/v030-stage-a` | `31dde074d68b69fea5b254a9e3a40bb142032379` | ancestor/equal |  |
| `refs/heads/v030-stage2` | `cb8b732264881b59b0d804b4ce7c9b006c657306` | ancestor/equal |  |
| `refs/heads/v030-stage2-oracle-o` | `9924c140488b5901476121b9a949f496540a300a` | 8 patch-equivalent commits |  |
| `refs/heads/v040-h7-activation` | `c19381020d2ee35a99a788d424064d0f3d4cfd84` | ancestor/equal |  |
| `refs/heads/v040-h7-adapters` | `b0daded71a98656adc059813d67cc059ca59c1ef` | ancestor/equal |  |
| `refs/heads/v040-h7-capture-core` | `250faf6f030a6d7bef4296ec19724d670446147c` | 2 patch-equivalent commits | `W/.worktrees/v040-h7-capture-core` |
| `refs/heads/v040-h7-object-wire` | `cf413029dc9e092925a00b7eabdd8acbe02fa3fb` | 1 unmatched, 0 equivalent | `W/.worktrees/v040-integration` |
| `refs/heads/v040-h7-owner-store` | `b942cfc628feeb4ebd827272737b1b627ee3670a` | 2 patch-equivalent commits | `W/.worktrees/v040-h7-owner-store` |
| `refs/heads/v040-h7-scrub-split` | `355502d29dbae711182419aa3dc65087e46acd87` | ancestor/equal |  |
| `refs/heads/v040-h7-sweep-diet` | `5c7c143ad7aec5095fc522e3ce3fd7fe4603072b` | ancestor/equal |  |
| `refs/heads/v040-h7-sweep-final` | `a64968b16815736eb3f5bb3555f0697f0ffd90e9` | ancestor/equal |  |
| `refs/heads/v040-h7entry-abandon-report` | `47df418d01f191d7dbc3fabfbe663dd54bea9e5c` | 4 patch-equivalent commits |  |
| `refs/remotes/origin/HEAD` | `792530713348f3a74e9100140226a51aea65a666` | ancestor/equal |  |
| `refs/remotes/origin/ci-fix/20261006` | `068b56b595a22d2749e4929a3bd311b3ad0fa71c` | ancestor/equal |  |
| `refs/remotes/origin/dev/v0.3.0` | `792530713348f3a74e9100140226a51aea65a666` | ancestor/equal |  |
| `refs/remotes/origin/dev/v0.4.0-managed` | `d851ebf8cafc9233b7291a6b7a81fa0d93b7ab91` | 401 patch-equivalent commits |  |
| `refs/remotes/origin/main` | `792530713348f3a74e9100140226a51aea65a666` | ancestor/equal |  |
| `refs/remotes/origin/task/v040-h6-product-repair` | `786775d4927818735bf074fc3baffdc6aaf3bf24` | 397 patch-equivalent commits |  |
| `refs/remotes/origin/v030-stage2` | `cb8b732264881b59b0d804b4ce7c9b006c657306` | ancestor/equal |  |
| `refs/remotes/origin/v030-stage3` | `c8c1bdb5215c14e34711a1e665fd2e7cd949cd77` | 67 unmatched, 0 equivalent |  |
| detached | `655feaa3e29610359d2fd938eb5f958708f44640` | detached inspection tree | `/home/user/p11scope-base-655feaa3` |
| detached | `e7d035f76a3ea46539152f31a6891f90af440f20` | detached inspection tree | `/home/user/src/m/p11scope-ws/.worktrees/fixbase-check` |

`W/` = `/home/user/src/m/p11scope-ws/`. Worktree statuses and WIP interpretations follow below.

</details>

### Branch, worktree, documentation and WIP triage

The expanded request was applied after the first source pass: **journal WIP was then inspected explicitly**. Of 193 distinct ref tips, 21 were ancestor/equal, 128 had only patch-equivalent nonmerge changes, and 44 had unmatched patch IDs. The latter is a search queue, not 44 missing-fix claims: older Stage 3 work was combined/linearized and numerous final methods/tests exist in the baseline despite differing patch IDs. Examples `task/v040-full-image-proof` and `task/v040-fix-d3ext` are entirely patch-equivalent; older `task/v040-image-routing` has unmatched patch IDs but every newly introduced function name examined is present in the integration baseline. No source branch was changed.

| Local-visible area | Observed state and concrete reuse finding | Assessment |
|---|---|---|
| Current integration `v040-h7-object-wire` | Initially dirty journal became commit `cf413029dc9e092925a00b7eabdd8acbe02fa3fb`. It charges H8 begins before insertion, refunds void/invalidation paths, and transfers a ticket from H8 open to model population, restoring on failed conversion. New uncommitted changes then threaded `&mut StagingLedger` through `ObjectSemantics::{begin,complete,settle,invalidate,abandon_domain}` and model removal (`P/src/semantics_objects.rs:1128`; working `P/src/semantics_objects/state.rs:706`). | **Active WIP, useful general Rust design lesson.** One cross-stage budget prevents each independently bounded population multiplying the global allowance; owned/move-only reservation transfer and idempotent release are potential future primitives. The baseline ledger explicitly leaves `byte_limit=None` until reviewed sizing (`fb81ee74:src/semantics_objects/journal.rs:290–308`). Do not claim bounded retained bytes or stable API from comments or this in-flight wiring. |
| `task/v040-h6-inventory-exit-retention`, worktree `.worktrees/v040-h6-inventory-exit-retention` | Commit `a82bc301ed025cf82bfa710473b7f77783a9f9d6` contains host-only pending/failed/unstarted retirement controls absent by those names from current baseline. `src/attach/inventory/capture/cgroup_tests.rs:352` at that commit tests prompt return while real close is gated; `:368` failed handoff; `:376` residual custody. Source uses real owned harmless FDs and worker jobs; it deliberately does not fabricate native state. | **Harvest regression scenarios after rebase/adaptation.** Commit message says Cargo/runtime RED execution had not occurred at that checkpoint. The branch's later fix is patch-equivalent to baseline, but these test shapes remain valuable; absent names alone do not prove baseline lacks equivalent coverage. |
| `task/v040-h6-live-child-fixture`, `.worktrees/v040-h6-live-child-fixture` | `1a66e28421375ae929257cbf463b830337003e46:src/inventory_semantics_tests.rs:6487` adds ignored `h6_owned_child_immediate_exec_identity_probe`: held expected executable; up to 100 independently reaped children under 10-second limit; immediately compare actual exe and original process pin. | **Diagnostic test kit candidate, not product fix.** Absent by name from baseline. A clean run only means mismatch not reproduced. Reuse owner cleanup and first-mismatch reporting, parameterize executable. |
| `task/v040-h6-va-reuse-pad`, `.worktrees/v040-h6-va-reuse-pad` | `3376c138483b80040bc4ee29c7a7bc60eb315619` reserves one anonymous inaccessible page in the initial image to reproduce successor loader/XOL mapping pressure; test at `tests/python/test_automatic_exec_oracle.py:691` proves exec removes it. | **Keep as narrowly labeled experiment.** Not in baseline by test name. Never adopt the padding as a production workaround or let engineered address reuse substitute for measured same-address/replaced-address populations. |
| H6 sibling/system/capacity branch family | Small unmatched patches include `4918bf65`, `d8d0bd4d`, `57bbfdba`, `2d626cd3`, `9fd334f8`, `aaf9bc6a`, `f89027e2`. Examined their patches and final symbols. Baseline already contains corresponding measurement-stage sibling controls, read-credit retry and provider-identity tests, with subsequent changes. | **Use integrated descendants, preserve task-branch counterexamples.** Name/patch matching is triage, not whole-tree behavioral equivalence. |
| External Stage 3 worktree `/home/user/src/m/p11scope-wt-v040-stage3` | Actual registered path is the external path, HEAD `345bce888f89e2fba13965dd339f222f4f998d54`. Two modified files: `build.rs`, `tests/identity_iter_standalone.rs`; three untracked source files: `scripts/check-bpf-noninterference.py`, `tests/python/test_bpf_noninterference.py`, `tests/fixtures/bpf-noninterference/fake-tool.py`. Diff replaces development-host whole-object digest gates with reviewed source/argv tripwires and executed compiler/object receipt checks, plus fresh same-environment baseline/candidate comparison. | **Historical WIP with integrated successors.** Baseline has `93c53889` integration and a more developed noninterference script; direct file comparison shows later PATH validation, independent coordinator/offline helpers and truthful uncapped-output disclosure. Prefer current tracked harness; preserve local WIP. General lesson: reproducible comparison uses same environment; a historical full ELF hash confounds compiler/debug metadata with semantic change. |
| Nested public `p11scope/` | Untracked `docs/superpowers/plans/2026-10-04-pass-profile-experiment.md:1` proposes stage-normalized 4,096-process scan profiles, interleaved A/B pools, and task_vma iterator assessment; explicit no-cross-pass-identity-cache rule at `:17`. Other untracked files are generated older Aya/aya-obj p1 trees. | **Documentation-only design input.** Unchecked boxes are not benchmark results. Keep indicative timings distinct; prefer maintained p2 patches over generated p1 files. No existing experiment checkout was inferred from plan text. |
| Outer untracked diagnostic tools | `W/scripts/agent-tools/diagnose-h6-cold.py:1`, `diagnose-h6-reexec.py:1`, `test_h6_relocated_acceptance.py:266–353` were read. Tests require actual measured relocation, reject absent measurements and foreign/incomplete target sets, and forbid readiness or successful forced cleanup from pretending to be acceptance. Tools contain historical staging paths and bounded private diagnostic parsing. | **Reuse oracle logic after path/config extraction.** Three untracked files are source, not disposable output; no tests executed. Cold/nonleader and relocated same-path scenarios complement public VA-reuse tests. Sanitized failure reporting deliberately avoids arbitrary exception/argv capture. |
| Outer tracked documentation WIP | Modified `handoff.md` gives current T4 loop; `.agents/memory/decisions.md` adds historical remote-host setup/authorization notes, including superseded no-KVM then KVM-present observations. | **Context only.** No remote contact or assumption that historical authorization applies here. Live host state not verified. |
| Historical untracked source/docs | Outer `ls-files --others` returned 3,980 files; 210 selected source/doc extensions: 181 vendor material, 11 review snapshot source, one spike source, 12 recovery source, two large historical document-boundary patches, three active diagnostic tools. Of 24 nonvendor snapshot/recovery Rust/Python files, 20 matched an existing blob in product object database. Four unmatched earlier/RED fixture versions were diffed against preserved finals: later files add exact lifecycle link-kind checks, explicit unqualified guard, loaded-map report ordering and independent terminal-population mutants. Large boundary patches were inventoried by changed paths. | **Useful counterexamples, not newer replacements.** Blob presence establishes byte existence in local product object storage, not reachability/qualification. Four unmatched older versions lose checks present in their finals; do not import them. Large patches mainly relocate/remove internal docs and preserve attribution; not an extraction implementation. No archives/vendor trees were broadly re-reviewed or mutated. |

`W` means `/home/user/src/m/p11scope-ws`. Outer repo exact refs: `refs/heads/main=6f97aa47171147fb2aea58bce5a50aa4c34a8173`; `refs/remotes/origin/HEAD` and `refs/remotes/origin/main=79061ca45cd7d1215cda4b50ea7ba843ff7dbafe`; its only registered worktree is W. Across 73 product worktrees, tracked modifications were observed only in integration and external Stage 3; remaining 71 had none. Main and Stage 3 also had the untracked material described above. Worktree enumeration/status is complete at that observation, not an inactivity proof, and active integration can change immediately.

### Additional reusable identity/BTF boundary recovered through branch research

`P/src/attach/identity_iter.rs:1–9` explicitly has **no `crate::` dependency** and combines the `task_vma` object loader, bounded record parser/run reader, raw iterator syscalls and anchor arena. It is a better extraction boundary than the higher-level discovery controller. Treat it as the kernel accelerator companion of candidate 4, with candidate 11's tests. Medium/high extraction difficulty because Rust loader, native `vma_identity.{c,h}`, raw UAPI, map-access restrictions and capability rules must travel together; generic Linux introspection applicability, not general cross-platform Rust.

The source names upstream kernel fix **`7ff94f276f8e`**, “bpf: keep a reference to the mm, in case the task is dead.” (`P/src/attach/identity_iter.rs:1251`). Eligibility scans raw BTF for `bpf_iter_seq_task_vma_info.mm` and parameterized task-iterator support, with function/enum witnesses for stripped-FUNC BTF (`:1218–1248`). This avoids unsafe uname inference under Debian backports. Separately, `btf_extra_len` documents a concrete parser mistake: BTF DECL_TAG has **4 extra bytes**, not 8, because `type` overlays the common header; wrong size desynchronized at real `bpf_fastcall` tags (`:1391–1414`). Regression `btf_walk_survives_decl_tag_records` at `:7315`, malformed/eligibility matrix at `:7355,7406`, and independent host-BTF walk must accompany reuse. These are local source assertions, not newly verified upstream history.

The 2026-10-15 regression plan contributes reusable *specifications* still requiring execution: multi-provider isolation with independent nonempty populations (`W/docs/superpowers/plans/2026-10-15-v040-regression-test-plan.md:165`), cross-session/reload/uncertain concurrency (`:308`), ring-size × sink × cancellation matrices (`:335`), and actual capability-based kernel/backport coverage (`:344`). They supplement implemented tests; none becomes PASS because the plan exists.
