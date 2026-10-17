# Shared-library testing strategy

Proposed future work, 2026-10-17. No tests or product changes were made for this document.
Priority: independent Rust crates first; a framework for new scope applications second; C/Mojo interoperability third.
The goal is to preserve observable contracts and expose plausible wrong implementations, not to reproduce donor pass counts.

## Source and evidence rules

Inputs: [p11scope](p11scope.md), [KryProbe](kryprobe.md), [OSSLscope](osslscope.md), [MemVeil/libbpf-mojo/MojoBPF](memveil.md), and [external options](external-comparison.md).
The owner's added delivery requirement is specified in [user conformance](user-conformance.md): UC01–UC14 extend the H corpus into runnable package/environment scenarios. [G01–G23](gap-analysis.md) add public API and packaging acceptance obligations. All three inventories must be considered for the selected capability; the 32 H rows alone are not the full readiness gate.
The [testing delivery plan](testing-delivery-plan.md) defines the issue-to-consumer workflow, finite cell selection, harness controls and close/reopen rules. The [machine-readable catalog](regression-catalog.json) indexes the H families and their planned oracle, bad control, tiers, candidate consumers and related obligations; it is not executable selection logic or qualification evidence.
Use their exact revision/worktree inventories, including divergent branches, uncommitted changes, and untracked documentation; do not silently substitute each repository's main branch.
The notes identify test source and historical receipts. Neither constitutes a passing extraction test.
Before porting a donor case, record its full source SHA, dirty-file hashes where applicable, SPDX/provenance, original defect, and accepted scope.
Public tests must stand alone; selected scenarios may be rewritten, while private evidence archives and coordination documents remain private.

Path aliases below resolve to the source roots pinned in those notes:

| Alias | Donor root |
|---|---|
| P | `/home/user/src/m/p11scope-ws/.worktrees/v040-integration` |
| W | `/home/user/src/m/p11scope-ws`; preserved compiler research at workspace commit `33fdd75ee69575cf3f309da1ddef2e0fad5d3181` |
| K | `/home/user/src/m/kryprobe-ws/kryprobe` |
| O | `agent@um790:/work/osslscope-ws/osslscope/.worktrees/preview-r21` |
| M | `agent@um790:/work/memveil-ws/repos/memveil` |
| L | `agent@um790:/work/memveil-ws/repos/libbpf-mojo` |
| LJ | `agent@um790:/work/mojobpf-ws/.worktrees/libbpf-joint-integration-20261016` |
| J | `agent@um790:/work/mojobpf-ws/.worktrees/mojobpf-cr09-m1` |

Evidence labels: **S** = existing inspected source; **W** = preserved, unaccepted/unqualified work or documentation; **P** = future port/new test; **L** = live proof still required for the proposed library.
Every matrix row below is proposed **P** work, even when its donor is **S**. An **L** requirement remains NOT_RUN until an admitted environment and exact artifact exist; unmet prerequisites become BLOCKED, never an inferred pass.

## Six test tiers and their acceptance boundaries

| Tier | Concrete future suite | Acceptance / what it cannot establish |
|---|---|---|
| T0: pure Rust contracts | Small table tests, independent reference reducers, Proptest event scripts, parser fuzz targets, compile-fail API tests. | Checked invariants and bounded refusal; no syscall, compiler-object, kernel, or real concurrency claim. |
| T1: userspace state models | Explicit small transition models; Loom for Rust atomics/locks actually represented; Shuttle for reproducible scheduler exploration where useful. | Model and implementation correspondence reviewed; model bounds/assumptions reported. Neither framework automatically models BPF, raw mmap, FFI, JIT, syscalls, or hardware ordering. |
| T2: emitted objects | Build tiny actual C/Rust BPF producers with selected toolchain; inspect ELF/BTF/relocations and relocated instruction images; mutate copies. | Codegen/loader/checker properties on these bytes. Synthetic BTF relocation and byte interpreters are separate from verifier acceptance. |
| T3: unprivileged Linux integration | Owned subprocesses, procfs/pidfd operations when permitted, real temporary files/FDs, controlled mmap rings, bounded pipe/FIFO fixtures. | Real syscall/ownership behavior under named permissions/filesystem. A denied operation is a named omission, not a successful fallback proof. |
| T4: isolated live kernel | Prebuilt candidate in owned disposable guest; independent workload ledger, actual load/attach/firing, fault/cleanup checks. | Only the exact artifact/profile/capability cell exercised. Separate verifier, event semantics, performance, and cleanup verdicts. |
| T5: consumer/package conformance | Two actual Rust consumers plus external source-free installed test; later C/Mojo adapters over the same vectors. | API and package integration in those consumers. Equivalent output is meaningful only under shared semantics and independent expected results. |

A pure host crate should not require a BPF toolchain merely to run T0/T3. Feature-specific suites declare dependencies explicitly.
Prefer Proptest/cargo-fuzz and selected existing parser/syscall libraries from the external comparison; do not add every alternative framework as a dependency.
Use Miri where the extracted pure Rust unsafe boundary is supported, and ASan/UBSan for relevant native code; neither substitutes for live BPF evidence.

## Hard-regression matrix: 32 scenarios with component-specific gates

Each row names an oracle or deliberately bad variant, a concrete donor, and the missing extraction work.
Tests need explicit expected values or permitted outcome sets; “did not crash” is insufficient where semantic correctness is claimed.
The inventory spans all proposed components. Each component selects its applicable rows and tiers, records justified exclusions, and retains the remaining cases for later work. A file-only library does not wait for unrelated DMA, FFI or BPF compiler gates. The first slice needs H04/H06 and applicable FD/cap/ownership controls; maps-domain support adds H05, attachment retention adds live H04/H19, and child custody adds H02/H20.
The file-only slice is an internal increment toward the requested ready mapped-image package. That ready capability requires H05 and UC01–UC14's applicable real filesystem/namespace, production-policy and installed-delivery cases. An explicit calibration policy does not permit omitting its tests. Determine required cases from the advertised claim before inspecting available fixtures, so absent environments stay incomplete.

| ID | Scenario and discriminating assertion | Existing donor source / status | Future tier and missing work |
|---|---|---|---|
| H01 | Fork versus CLONE_THREAD, leader/nonleader exec, failed exec: only successful image transition advances the appropriate lineage; child birth is distinct. | **S** P `crates/ebpf/native/image_identity_fork.c`; `tests/exec_task_continuity.rs:171`; O `tests/target_lifecycle.rs:2224`. | T0/T2/T4; create neutral birth/exec scripts and owned fixture ledger; actual producer continuity needs live proof. |
| H02 | PID reuse, death between acquisition steps, denied pidfd: never retarget original authority; weaker observation cannot acquire signaling rights. | **S** P `src/process.rs:719-756`; O `src/pin.rs:144-176`. | T0/T3/T4; deterministic acquisition fault seam plus real process fixture; forced reuse tests require isolated namespace/environment. |
| H03 | Foreign map/session domain, old exec ID, token zero, counter wrap: reject foreign capabilities; exec zero remains valid where specified. | **S** P `crates/ebpf/native/image_identity.c`; `src/attach/native_retirement_tests.rs:274,329`; M `tests/unit/test_identity.mojo`. | T0/T1/T2; add restart/session domain vectors and exhausted-ticket negatives without inventing cross-restart persistence. |
| H04 | A→B→A pathname replacement, deletion, aliases, retained link: attachment targets held inode; link drops before its original FD. | **S** O `tests/count_deadline.rs:552,599`; `tests/site_identity.rs:261,320`; P `src/discovery/identity.rs`. | T0/T3/T4; controlled rename barriers and actual attach-to-held-file oracle; content mutation remains a distinct limit. |
| H05 | Btrfs anonymous subvolume device, overlay maps/stat mismatch, namespace view: typed domains never compare as interchangeable integers. | **S** P `src/discovery/identity.rs:3322-3381`; O `tests/identity_domain_audit.rs:105`. | T0/T3/T4; retain match/mismatch/inconclusive vectors; real Btrfs/overlay/mount cells need admitted filesystems. |
| H06 | File advertises huge length, grows, changes inode, or cache exceeds remaining budget: reject before oversized allocation and disclose raced read. | **S** O `tests/site_identity.rs:1247,1287,1322,1382`; `tests/capture_controller.rs:7487,8782`. | T0/T3; guarded reader/allocator and real-file controls; do not claim same-size restored-mtime writes are impossible. |
| H07 | Local section-symbol map relocations: two maps get distinct sentinel FDs; interior/ambiguous/missing definition and signed-addend confusion refuse. | **S** P `tests/bpf_map_contracts.rs:61-100`; `third-party/patches/aya-obj-0.3.0/aya-obj-map-relocation.patch:149-178`. | T2/T4; port actual-object test and mutate offsets; verify distinct live map IDs when adopting a replacement loader. |
| H08 | Task-storage map metadata, scalar/bitmap/missing CO-RE fields, padding: safe compiled paths or explicit refusal; no unchecked field read. | **S** P `tests/exec_task_continuity.rs:171,245`; `tests/python/test_bpf_map_defs.py`; `scripts/check-stop-gate-object.py`. | T2/T4; preserve synthetic-shape and actual-object cases separately; run oldest claimed verifier cell and live identity fixture. |
| H09 | Private BPF stack cross-task corruption under concurrent uprobes: no thread sees another START key; distinguish affected-kernel reproduction from safe workaround removal. | **S** P `tests/python/test_bpf_map_defs.py:274`; `crates/ebpf/src/main.rs:173-205`; fix `d69c940`. | T2/T4; removing the stack-preserving path fails the current object rule. Live corruption is required only in the pinned affected cell, with per-thread keys; non-reproduction is inconclusive there. A repaired-kernel control may justify removal after the independent workload and remaining gates pass. |
| H10 | Dead `.text`, call/function-pointer relocation ownership, alignment and callback BTF: malformed graph refuses; intended callback executes exact N×M. | **S** K `xtask/src/bpf/strip.rs:1019-1193`; O `src/loader.rs:3110-3611`; `tests/d_btf_load.rs:250,405,452,652,706`. | T2/T4; preserve emitted images and translated-image comparison; parser success alone cannot qualify callback execution. |
| H11 | BTF wrapper cycle, parent escape, same-name wrong type, split-module strings, missing map type linkage: reject or resolve exact intended identity. | **S** K `crates/kryprobe-privilege/src/btf.rs:1966,2088,2394,2460`; **W/current branch** J `tests/elf/test_map_btf.py`; commit `f520a52`. | T0/T2/T4; differential against selected parser plus independent graph oracle; inspect kernel type linkage rather than `.BTF` presence only. |
| H12 | Ring BUSY, discard, aligned wraparound, producer extension and fixed-tail crossing: advance exactly as specified; BUSY never means complete. | **S** P `third-party/patches/aya-0.14.0/aya-ring-reader.patch:655-860`; K `crates/kryprobe-privilege/src/drain/frame.rs:86-144`. | T0/T1/T3/T4; real reader on controlled mappings plus actual producer; architecture/memory-order claims need their own live evidence. |
| H13 | Short destination repeated retry, callback-source mutation, EINTR, malformed record: deliver held bytes once; conservation includes held/malformed/drop. | **S** L `tests/native/ring_conformance.c:216-392,447-577`; `tests/native/generic_ring.c`. | T0/T3 as contract vectors; T5 for a delivered Rust adapter, C/Mojo adapters later when selected. Test negative callback consumes input and distinguish transport from kernel loss. |
| H14 | Same-CPU reentry from different programs and guarded same-program entry: no lost increments; refused execution appears in its own miss channel. | **S** K `docs/decisions/ADR-0013.md`; `crates/kryprobe-privilege/src/kcrypto_fence.rs:406,534`; `crates/bpf-kcrypto/src/bin/kcrypto.rs:815`. | T1/T2/T4; preserve plain-store countermodel, inspect writer partitioning, force named interleavings live; atomics-only models do not prove plain stores. |
| H15 | CPU migration, competing first inserts, zero UID/stack and 80→88-byte ABI stride: freeze insertion identity and sum secondary lanes correctly. | **S** K `crates/kryprobe-privilege/tests/kcrypto_who.rs:532,585,637,661,677`; `crates/kryprobe-abi/src/kcrypto_agg.rs:1172`. | T0/T2/T4; ABI consumer inventory plus independent task ledger; model producer mirrors are not live migration proof. |
| H16 | Possible versus online CPUs, sparse/overlapping lists, offline lanes and 1/7/8/9/13-byte values: checked stride×possible count or refusal. | **S** K `crates/kryprobe-privilege/src/mapops.rs:526-616`; L `tests/native/generic_maps.c`; O `tests/target_lifecycle.rs:2528,2571`. | T0/T3/T4; explicit topology snapshots, overflow/protected buffers and changed-topology close; no guessed CPU count. |
| H17 | Full identity map plus repeated/cross-CPU loss: failure reporting survives the failed map; capped degradation flag never pretends exact omitted count. | **S** K `crates/kryprobe-privilege/tests/kcrypto_who.rs:783-1021`; `crates/kryprobe-abi/src/kcrypto_agg.rs:133-154`. | T0/T2/T4; below-capacity positive twin, independent expected failure count, nonzero preexisting-loss and cap tests. |
| H18 | Late entrant/submit after stop/drain, stale final sample, stuck writer: no settlement receipt until all required stages prove closure. | **S** K `crates/kryprobe-privilege/src/kcrypto_fence.rs:534-627`; M `tests/unit/test_stop.mojo:96-194,320-503`; O `tests/count_deadline.rs:1273-1284`. | T1/T3/T4; keep O's late-hit countermodel; MemVeil live protocol remains open; never turn timeout/detach/quiet into proof. |
| H19 | Pending/failed/asynchronous detach, foreign retirement ticket, transfer failure: retain original file/owner and expose unresolved quarantine. | **S** P `src/attach/native_retirement_tests.rs:100,274,329,490`; `src/attach/cleanup_worker.rs:416`. | T0/T1/T3/T4; cancellation at each ownership transfer and genuine cleanup failure; bounded return does not mean resources vanished. |
| H20 | FIFO setup, pre-stop deadline, stuck publisher and late worker versus successor: bounded cancellation; never truncate successor or kill foreign target. | **S** O `tests/target_lifecycle.rs:802,865,1247,1386,1653,1740,1901`; K `crates/kryprobe-privilege/src/workload_launch.rs`. | T1/T3; run blocking fixture in owned subprocess with outer watchdog; assert custody/FD/child disposition and preserved sentinel. |
| H21 | Partial attach tree, permission denial, unsupported result, capacity exhaustion: ≤2n−1 attempts; rollback successful leaves on terminal failure. | **S** P `crates/bpf-multi/src/lib.rs:268,398,408`; O `src/plan.rs:675-707`; L `tests/native/attach_rollback.c`. | T0/T3/T4; fake-link drop accounting then live owned mixed-good/bad sites; permission failures must not amplify retries. |
| H22 | Capability canary observes no activity or wrong process: require nonempty own-thread positives and independently active excluded child. | **S** P `crates/bpf-multi/src/lib.rs:600-620`; `src/uretprobe_hazard.rs`; **W** K selftest branch `scripts/test_sudo_lane.py`. | T0/T4; mutations remove attach/trigger or widen PID filter; each must invalidate the intended verdict, including quiet all-zero run. |
| H23 | Duplicate JSON members/terminals, NaN, bool-as-count, newline-suffixed pin, contradictory summary or missing loss operand: refuse before evidence promotion. | **S** K `tests/kcrypto_perf/test_successor.py:316,335,386,393,570`; **W** MojoBPF `doc/validation/2026-10-15-f02-fullmatch-boundary.md`. | T0/T3; immutable malicious corpus, independently expected diagnostics, truncate-at-every-boundary fuzzing; exact pin grammar tests. |
| H24 | Replay claims resolved identity with cgroup zero, contradictory intervals, wrong scope sums, lost synthetic flag or u64 overflow: semantic validation rejects. | **S** K `crates/kryprobe-core/src/workload/{evidence,scope,observation}.rs`; M `tests/unit/test_reader.mojo:330,339`. | T0/T5; parse and constructor must enforce same invariants; independent expected records, not serializer round trips only. |
| H25 | Unknown/reused IDs, late completion of old generation, repeated allocation, release loss: unknowns do not collide; old completion cannot retire new object. | **S** M `tests/unit/test_reader.mojo:1912`; `tests/unit/test_mappings.mojo:534-562`; K `crates/kryprobe-privilege/tests/kcrypto_tfm_lifecycle.rs:593,613,816,886,1081,1129`. | T0/T1/T5; generated bounded histories with explicit epoch and tombstone limits; exhaustion yields uncertainty, never synthetic continuity. |
| H26 | Unpaired copy, missing release, independent counter and detail totals: preserve independent bytes while withholding dependent occupancy; never double count. | **S** M `tests/unit/test_mappings.mojo:206-237,656-784,933-1205`; O `tests/evidence_model.rs:108,233,522,590`. | T0/T5; fact-dependency reference model, unit-typed counters, missing-versus-zero and shared-physical-site conservation mutants. |
| H27 | Reordered intervals/ties, partial snapshots and late contradictions: peak needs its ordering proof; snapshots do not poison later facts; holders apply corrections. | **S** M `tests/unit/test_mappings.mojo:302-501`; `tests/unit/test_engine.mojo:762,805,890`; O `tests/scan_oracle.rs:1195,1244,2336,2581,2734`. | T0/T1/T5; pure persistent model, repeated snapshots, real gap monotonicity, producer-admissible correction scripts. |
| H28 | Retained native view outlives parent, stale generation, absent destroy symbol, short/aliased output or bloom lookup: refuse safely; destroy exactly once. | **S** L `tests/native/generic_object.c`; `tests/native/generic_maps.c:469`; `tests/mojo/compile_fail/`; **W** LJ `tests/integration/standard_objects/test_first_live_maps.py`. | T3/T5 later; C/Rust/Mojo layout and ownership adapters, library-unload ordering, installed consumers and generic live success remain separate gates. |
| H29 | Used-result atomic RMW: both returned old value and stored new value match independent arithmetic for each width/op; unused-result and CAS controls distinguish the defect. | **W** W `llvm-bpf-toolchain-experiment.md:46-75`; `evidence/llvm-toolchain-review-20260922/kernel-oracle/{cases.json,prepare.py}`; upstream [LLVM PR 210371](https://github.com/llvm/llvm-project/pull/210371). | T2/T4/T5; port single-run stack-memory oracle through actual mixed C/Rust consumer build, decode fetch bit, and test selected fixed/unfixed backends. A forced non-fetch mutant must fail on returned value even if memory is correct. Concurrent shared-map RMW/CAS and ordering require separate schedules and evidence; historical single-run results do not establish them. |
| H30 | CPU preset drift: an LLVM upgrade cannot silently introduce instructions outside the advertised profile; empty CPU, generic, v3 and feature-controlled v4 remain distinct. | **W** W `llvm-bpf-toolchain-experiment.md:77-110`; `sdd/p11scope/SYSTEM-PLAN/task-bpf-v4-baseline-review.md:54-83`; [compatibility investigation](kernel-toolchain-notes.md#1-bpf-cpu-v1-v4-is-a-versioned-compiler-contract). | T2/T4; minimal fixture for every claimed instruction family, exact backend/feature manifest and decoded final opcodes; inject a forbidden opcode/preset change and require profile rejection. Kernel acceptance is independently exercised per intended cell; a feature name alone cannot raise or prove a kernel floor. |
| H31 | AtomicLoad instruction selection: minimal monotonic i64 load compiles or refuses as declared; feature-gated compilation must not be mistaken for kernel opcode need. | **W** W `llvm-bpf-atomic-load-report.md:18-114`; minimal `load atomic i64 ... monotonic, align 8`; [selector investigation](kernel-toolchain-notes.md#3-atomicload-selector-failure-compiler-feature-gate-not-kernel-rejection). | T2, plus T4 only for a kernel support claim; run minimal IR and consumer Rust/C path with explicit CPU/features. Assert diagnostic category or decode actual ordinary/acquire load. Wrong expected feature mask must fail; compiler rejection cannot be mislabeled verifier failure or repaired generically by volatile access. |
| H32 | Mixed Rust/C linker transformations: debug records remain valid and final BTF/BTF.ext retain meaningful function/map type information; exit zero alone is insufficient. | **W** W `sdd/p11scope/SYSTEM-PLAN/task-llvm23-{pipeline-debug-review,linker-repair-report,linker-repair-review}.md`; retained repair `4727b154a014dd74b9cceb038c365b058f48a53a`; [linker investigation](kernel-toolchain-notes.md#4-mixed-rustc-linker-debug-record-repair). | T2/T4/T5; validate metadata after each transformation and through the actual consumer toolchain; assert expected types/relocations in final object. Strip metadata or replay through a dropping parser to prove the checker rejects nominal compile success. Loader/verifier/live callback behavior remain separate required gates for the selected object. |

## Properties and model correspondence

Generate operations, not just bytes: acquire, observe, fork, exec, retire, lose, cancel, snapshot, drain, finalize, restart.
Keep a small independent reference model built from an append-only fact log; avoid copying the implementation's caches, eviction algorithm or transition helper.
Define preconditions and valid/invalid event grammars separately. Wire-impossible adversarial input tests validate the reader; they cannot demonstrate producer correctness.
Required properties:

1. Identity is scoped by its explicit session/producer domain and generation; display names, pathnames, PIDs and pointers alone never confer continuity.
2. Missing identity is not one shared identity. Generation changes prevent old completion from acting on the successor; exhaustion refuses rather than wrapping.
3. Real consumed loss remains recorded for its dependent claims within an epoch; starting a new epoch requires an explicit boundary, not a silent reset. Unknown evidence may be refined by new independent facts, but never by treating missing input as zero or silently erasing a gap. The consumer's contract determines which dependent claims can recover.
4. A call-local partial view is non-destructive. Repeated snapshots cannot alter later reducer results; an actual intervening gap remains visible.
5. Conservation uses typed units and disjoint categories. Details and counters for the same work are alternative measurements; relation loss degrades only justified dependencies.
6. A successful terminal result implies all declared proof predicates, including sample-after-final-drain. Missing predicates produce a named weaker result.
7. Failed operations preserve the specified outputs/ownership, or report the exact partial effect. Every acquired resource is owned, transferred, retired, or explicitly unresolved.
8. Every queue/map/tombstone/cache/parser allocation has a configured bound and tested N/N+1 behavior; eviction must not manufacture a completeness claim.

Use deterministic small limits to exhaust states, plus boundary sizes from production layouts. Record Proptest seeds, minimized scripts and fuzz dictionary/schema versions.
Loom/Shuttle tests must identify which production atomic/locking code they exercise and which edges are abstracted; review those assumptions with the implementation.
Include known countermodels as tests of refusal. A best-effort close passing its own specification must still fail a stronger, deliberately requested exact-close claim.
For x86-only BPF protocols, document the ordering assumptions and emitted atomic/fence instructions; an ARM claim requires separate design and actual architecture evidence.

## Oracles, mutations and canary non-vacuity

Every successful observation test needs an independently generated expected population: explicit operation IDs, count, participants, image generation, and admission window.
The workload ledger must prove it executed. Include admitted positives, excluded active negatives, and expected omissions with independently known reasons.
Reject an empty expected population unless emptiness is the named negative test and has a nonempty positive twin using the same acquisition path.
Join by explicit identity/operation, not timestamp proximity; aggregate equality alone can hide swaps, duplicate/missing pairs or wrong-process attribution.
Mutation families: disable attach/trigger; widen filter; alias two map FDs; erase generation; suppress loss; drop a correction; return early from drain; count unknown as zero; weaken parser; release FD early.
For each mutant, state the exact assertion that must fail and the layer reached. A setup crash or timeout does not prove the semantic oracle killed the mutant.
Run a restored valid twin after the mutation to show the harness can accept good behavior; retain the rejected mutant identity and complete verdict.
Differential testing against Aya/libbpf/object/btf-rs or a second consumer is supplementary: shared bugs or differing contracts can produce misleading agreement/disagreement.
Do not copy KryProbe's evolving AST regression checker into a trusted shared harness; prefer small structural checks plus runtime bad-implementation controls.

## Resource, cancellation and failure campaigns

Measure owned resources: live FD identities, children, worker handles, retained bytes, queue occupancy, map entries/BPF memory, and outstanding retirement tickets.
Assert bounds throughout a run, not only before/after. A net-zero FD count can hide replacement of a foreign FD or leaked-then-cleaned resource.
Inject failure before and after each acquisition/transfer: allocation, open/read, spawn, link, mmap, epoll, poll, map access, detach, publish, reap and final sample.
Cancellation points cover blocked I/O, worker handoff and publication; fake clocks prove deterministic deadlines, while an outer real watchdog proves the test cannot hang indefinitely.
Elapsed-time bounds include all stages/retries and cleanup. Timeout records unresolved ownership and preserves evidence; it never authorizes signaling an unproven PID/PGID.
Use small exact fault schedules on pull requests; larger repeated/saturation campaigns run only for relevant changes or release qualification.
Trigger the larger campaign when ownership, concurrency, ABI, cancellation, resource limits, parser acceptance, compiler/loader pins, or kernel profile changes; also after a newly discovered counterexample.
No repeat-for-confidence loop after the required gates pass unless bytes changed, a failure appeared, or a named coverage concern remains.
Keep one writer per build/evidence directory and serialize resource-heavy or privileged lanes under the environment's actual ownership rules.

## Compatibility cells, consumer adoption and delivery

Define cells by architecture/CPU features, exact kernel/config/BTF, helper/map/link capabilities, compiler/linker, object hash, userspace ABI/libc and consumer version.
Test the oldest claimed profile, a current profile and the profile reproducing each workaround; distro backports need functional probes, not release-string comparisons.
Do not inherit one union support floor: p11scope's older-kernel obligations, OSSLscope's narrower envelope and MemVeil's >=7.0 policy are separate consumer requirements.
For toolchain changes, compare actual object shapes and rerun dependent relocation/stack/task-storage/callback controls before retiring a patch.
Store per-cell PASS/FAIL/BLOCKED/SKIPPED/NOT_RUN, expected/actual populations, independent oracle, losses, cleanup, hashes, limits and raw-evidence locations.
Host-only lanes list omitted live tests explicitly; required skips cannot inflate pass counts. Performance is a separate measured claim with workload, baselines, variance and ceilings.

First extraction acceptance: port the relevant donor regressions, integrate two real consumers through their actual library adapters, and preserve both consumers' observable behavior at exact tips.
Compare only contract-approved normalization; do not erase sequence, generation, scope, ambiguity or terminal differences to make outputs match.
Test default/minimal features, documented MSRV where adopted, source archives and installed consumers without workspace/sibling-source access.
Also test supported feature unions and dependency-version combinations (G19/G20), including a consumer that would otherwise resolve two library copies. The conformance runner records which copy/features/backend it exercised; its own linked version cannot certify another application. Package tests/fixtures and an embeddable developer API plus a runnable operator route. Run doctests explicitly as well as applicable all-target tests; see [distribution constraints](test-distribution-options.md).
For a later framework, reuse these suites at its seams: discovery → admission → attach → collection → normalization → reduction → finalization → report.
Framework integration needs explicit failure propagation at each seam and must keep backend-specific state machines and product privacy/semantic oracles separate.

C/Mojo/MojoBPF is priority 3: share schema/vector definitions first, preserving independent ABI/framing/payload/schema versions and exact integer semantics.
Then verify C/Rust/Mojo sizes/offsets/alignment/signedness, move-only ownership, loader lifetime, error capture, mutable spans and failure-output guarantees.
Use existing libbpf-mojo rather than inventing a second bridge; its joint branch's tracepoint/cleanup receipt does not qualify generic map/test-run/installed paths.
MojoBPF typed map-BTF work and uncommitted packaging/target-contract docs are candidate inputs; re-pin actual source/WIP before adopting their vectors.
No language migration or forced shared runtime is needed to execute this strategy.

## Concrete missing deliverables and completion gate

| Task | Required output | Exit evidence |
|---|---|---|
| TS1: case inventory | Versioned case IDs, provenance/license, contract, independent expected outcome, tier and donor/WIP status. | All 32 scenarios assigned or explicitly deferred with a reason; each component maps its applicable subset and exclusions. No unexplained empty positive population. |
| TS2: first Rust ports | Small crate test adapters and independent reference models for selected extracted boundaries. | Exact-tip T0/T1/T3 results, minimized regressions, mutation assertions and bounded-resource evidence. |
| TS3: object kit | Reproducible producers, object hashes, manifest-driven checks and corrupt/mutant fixtures. | Actual-object T2 controls discriminate loader/compiler/metadata defects without claiming live support. |
| TS4: live cells | Admitted isolated environment and exact prebuilt candidate/workload closures. | Required T4 cells passed or explicit blocked claim boundary; independent positives/negatives and cleanup retained. |
| TS5: two consumers and user delivery | Product-built adapters, versioned case/fixture closure, embeddable developer API and installed operator route. | Exact-version T5 from source archive and source-free installed consumer; UC14 plus applicable UC01–UC13, distinct product oracle and live evidence. No hidden compiler/workspace/network dependency. |
| TS6: later polyglot | Neutral vectors plus existing-bridge adapters; no product migration. | C/Mojo ABI/ownership and exact installed/live results, with unsupported concurrency/architecture claims withheld. |

These deliverables are proposed and unexecuted. A library is ready for its named consumers only when its changed bytes meet the selected contract and compatibility gates; historical donor success cannot substitute.

For the requested mapped-image package, maintainer qualification must include every declared required environment cell and both explicit calibration policies. User runs preserve separate scenario result, capability state and overall coverage: a correct refusal can pass its assertion while the capability stays denied/unknown. Missing fixtures, untriggered copy-up/collision behavior, invalid harness setup or unresolved cleanup cannot yield a complete support result. Runtime object/context checks still apply after any successful diagnostic run.
