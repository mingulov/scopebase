# ScopeBase decision register

Date: 2026-10-18. This register records what an executor must preserve, why the decision exists, and who can change it. Read it with the [project specification](2026-10-17-scopebase-design.md) and [execution contract](2026-10-18-scopebase-executor-contract.md). It amends the earlier permissive-license proposal and execution assumptions; it does not qualify a library.

`SETTLED` means follow the decision. `PROVISIONAL` means the user has accepted it for current planning/development and may revisit it; publication still requires the selected final terms. `PREDECESSOR` means the named earlier task must produce the exact input before the dependent executor starts. An executor cannot turn these states into permission to choose a different design.

## D01 — Preserve mechanisms, regressions and explanations together

**Status:** SETTLED by the user's original purpose and renewed direction. **Owners:** controller, SB01 and each component owner.

**What:** Port or narrowly adapt the selected, fixed donor mechanism and its regression. Keep a map from original defect to invariant, source symbol, destination symbol, independent oracle, sensitive wrong implementation and support limitation. Combine the applicable behavior from all donors; the first implementation found is not automatically the complete contract.

**Why:** The reusable asset is the accumulated repair knowledge. A fresh implementation of a pleasant API can silently reproduce a defect already fixed elsewhere. A list of filenames or test names preserves an inventory, not behavior.

**Executor rule:** `PORT` and `ADAPT` start from identified donor/upstream code. `NEW` requires an explicit reason that the mechanism is genuinely missing and an already specified interface. A missing header, inconvenient license label or large donor file is not permission to rewrite. API improvements require a recorded compatibility map and the same discriminating cases.

**Reopen only when:** a concrete contract mismatch or unnecessary application policy is identified, alternatives and affected regressions are reviewed, and the controller amends the packet before implementation.

## D02 — Independent components precede composition

**Status:** SETTLED. **Owners:** SB02, LX/BP/CP, SDK and NX.

**What:** Keep independently usable host Linux, host BPF adapters and pure capture packages. Build the SDK after real component consumers exist. Reuse the existing native bridge and standard object formats selectively. Product migrations remain MG01–MG05, later.

**Why:** Applications have different identity, privacy, loss and shutdown semantics. A universal runtime would couple those policies and make independent use harder.

**Executor rule:** No new universal core, loader, daemon, reducer, event schema or shutdown protocol. A separate BTF/build crate still needs its existing two-consumer justification. Two wrappers around the same mocked path do not establish independent consumers.

## D03 — License by code ownership and actual build destination

**Status:** PROVISIONAL user choice, 2026-10-18. **Owners:** user/controller; SB01 records, SB02/BP01/TC01/NX02 apply.

**What:** The working project license for user-owned **userspace ScopeBase libraries is Apache-2.0**, without a project MIT alternative. The intended application licenses remain GPL-3.0-or-later; the intended kernel BPF program license is GPL-2.0-only. Project-owned source genuinely shared between userspace and GPL-2.0-only BPF needs the explicit choice `Apache-2.0 OR GPL-2.0-only`, or separate implementations with an approved reason. It must not become Apache-only input to the GPL-2.0-only target.

**Why:** Apache-2.0 code can be incorporated into GPLv3 works, while ordinary Apache-2.0-only code is not GPLv2-compatible. The userspace library and the separately loaded BPF program are distinct artifacts. Merely writing GPL on the final BPF object does not change an input's source grant. See the [Apache compatibility explanation](https://www.apache.org/licenses/GPL-compatibility.html) and [kernel BPF licensing documentation](https://docs.kernel.org/bpf/bpf_licensing.html).

**Executor rule:** Preserve the historical donor SPDX observation separately from the destination license and the author's authorization. The user's ownership permits a different grant for their contributions; a historical GPL header is not a prohibition on that decision. Preserve actual third-party terms/notices and distinguish copied upstream material from the user's modifications. Do not change donor workspaces, invent a third-party grant or claim that a missing SPDX header alone proves the author's code cannot be used.

**Build boundary:** A host crate named `scopebase-bpf` is still userspace. Target BPF functions, inlines, generated wrappers, headers and linked runtime fragments need their own target closure review. Host compiler/linker dependencies are not automatically target code. Pure ABI declarations still need an explicit shared-source policy; do not assume that all header text is free of copyright.

**Dependency decision:** The selected Aya BPF crates offer upstream `MIT OR Apache-2.0`. The target closure cannot silently select ordinary Apache-only terms for GPL-2.0-only output. SB02/BP01 must record the compatible upstream option and notice delivery, including whether the user's rejection of MIT concerns their own project license or also an existing third-party option. The latter is not yet a settled prohibition or permission. Do not rewrite Aya or change the BPF program license to hide this issue. Host-only Aya can use its Apache option. `Apache-2.0 WITH LLVM-exception` is a different grant from bare Apache-2.0 and requires checking the actual supplied exception.

**Reopen when:** the user revisits the provisional choice, an actual third-party contribution differs, or the actual target closure changes. Review distribution terms before publication; unrelated host work need not wait for an unselected target dependency decision.

## D04 — Source licensing and the kernel's license string are separate checks

**Status:** SETTLED technical requirement. **Owners:** BP01/BP03, TC03/TC07, TT05 and NX02.

**What:** Preserve source grants and independently check the final ELF license section, loader-supplied license bytes and the selected kernel's GPL-compatible admission. Use the existing `GPL` declaration for GPL-2.0-only program fixtures. Do not put an SPDX expression or invent `Dual Apache/GPL` in place of a supported runtime string. Linux 6.12's [license check](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/linux/license.h) shows that these are specific recognized strings.

**Why:** GPL-only helpers, kfuncs and some program types require compatible admission. Successful loading does not determine copyright permission, and a source header does not prove that the loader submitted the correct bytes.

**Executor rule:** The positive GPL fixture must load, execute its owned workload and produce independently expected activity. Its otherwise equivalent non-GPL declaration control must fail at the intended license check. Missing privilege, an unavailable helper, an invalid program, zero activity or a generic EPERM/EACCES is not that result. Test source terms, object bytes, runtime admission and execution as separate assertions.

**Scope and ordering:** These live assertions apply to selected live BPF claims. Host-only/source checks do not load programs. BP03 implements cause logic and registers cases; TC03 checks objects. TC07/BP11 apply actual TT05 runtime evidence after backend/fixture prerequisites exist. Do not add a backwards dependency or claim a model has run that kernel check.

## D05 — Kernel support is a feature/artifact contract

**Status:** SETTLED. **Owners:** BP03/BP08, TC01–TC08 and TT05.

**What:** Retain the original helper, map, CO-RE/BTF, opcode, verifier, attachment and workaround requirements. Select oldest/current/affected/backport/refusal cells per profile before discovering availability. Decode and run the exact final object from the actual Rust/C/Mojo/compiler/linker closure.

**Why:** Kernel version numbers omit backports and configuration; compiler CPU presets can change instruction output. A successful intermediate compile or a new LLVM source commit does not prove final object behavior. The 7.0 private-stack investigation is an issue cell, not a universal minimum.

**Executor rule:** No floor inferred from uname, no automatic new CPU preset, no deleting initialized padding/private-stack paths because a current kernel accepts the object, and no substituting a standalone llc result for mixed consumer codegen. Preserve H08–H11/H29–H32 and the exact workaround-removal tests.

## D06 — Diagnose refusal by operation and evidence

**Status:** SETTLED correction. **Owners:** BP03, TC06/TC07, TT02/TT05.

**What:** Preserve operation, stage, raw errno and bounded verifier/backend evidence. Permission denial, unsupported operation, verifier refusal, license refusal and unknown cause remain distinguishable. An ambiguous load error remains unknown; it must not manufacture permission or support knowledge.

**Why:** The p11scope `SelectionTransport` fix records old-verifier uninitialized stack rejection returning EACCES on 5.15/6.2. Therefore EACCES alone cannot mean permission denial. The same observation matters to the license negative control.

**Executor rule:** Do not classify BPF_PROG_LOAD from errno alone. Add same-errno/different-cause controls, preserve original diagnostics, and avoid falling back or splitting on a misclassified failure. A textual message from an untrusted backend is still a backend assertion.

The normative [TT02 intent/cause matrix](2026-10-18-scopebase-tt02-engine.md#intent-cause-and-capability-matrix) makes this concrete: exact operation/step/stage and independent cause witness plus a functional positive twin gate cause-specific refusals. H33 model evidence remains separate from BP03/TT05 actual inference and activity.

## D07 — Authority cannot be reconstructed from reports

**Status:** SETTLED. **Owners:** LX02/LX06/LX08, BP02/BP05 and TT02.

**What:** Keep process control, birth/exec, stat/maps/mount identity, content observation, BTF domains, retained owners and descriptive reports distinct. Require the original owner for live operations; serialization loses authority.

**Why:** A pathname, PID, integer descriptor, raw maps key or plausible receipt can name a different object or context. Btrfs and overlay expose why apparently equal numeric identities are insufficient.

**Executor rule:** No path fallback after held acquisition, foreign proof reuse, guessed CPU geometry, test receipt promoted to native authority, or calibration result promoted to universal identity. Process observation is not signaling authority; pidfd retention is not an exec snapshot.

The normative [TT02 actual-contract import boundary](2026-10-18-scopebase-tt02-engine.md#result-schema-actual-contract-matching-and-import-boundary) recomputes descriptive verdicts while preserving Imported origin; it retains fixed actual entry/final metadata and raw elapsed/cancellation/completion observations for pure gate reconstruction, but cannot re-execute arbitrary oracle logic or authenticate a coherent forged host claim.

## D08 — Cleanup and bounded work are observable contracts

**Status:** SETTLED. **Owners:** LX04/LX06/LX09, BP05/BP06, TC02/TC07 and NX03–NX06.

**What:** Keep explicit caller accounting domains and unresolved native owners. State byte, memory, work, descriptor/link, child and elapsed bounds separately. Cancellation/drop does not replenish outstanding permits or certify successful cleanup.

**Why:** The same hidden work can survive a timeout, a failed detach, a new client instance or a parent process exit. Losing its owner creates repeated resource leaks and unsafe reuse.

**Executor rule:** No destructor-only success claim, ownerless partial effect, close-as-release substitution or process-wide handler/policy change. Preserve active identity/owner assertions; final resource counts alone can hide replacement.

The normative [TT02 cumulative retirement and immutable ledger contract](2026-10-18-scopebase-tt02-engine.md#effect-ledger-and-retirement-reconciliation) fixes adapter-then-fixture order, explicit uncalled participation outcomes and one cumulative allowance. Unknown inventory stays sticky; exact known resources may settle at run scope without rewriting their case-end state. The [32-field limits](2026-10-18-scopebase-tt02-engine.md#exact-limits-and-bounded-artifact-measurement) separate parser retention from streamed byte work and cooperative elapsed bounds. This supplies a precise engine realization of D08 without claiming hard interruption or cleanup.

### LX03-R1 clarification under D08

**Status:** SETTLED by root controller ratification on 2026-10-18. **Owners:** LX03 and controller; D01/D07/D09/D11–D14 continue to apply. This adds no decision/task/requirement ID or dependency edge.

**What:** Freeze the exact [LX03 read contract](2026-10-18-scopebase-lx03-read-contract.md): ReadObservations/ReadCharges/LimitKind and ResourceCharges::read signatures, three fixed non-read calls and `u64::MAX-3` headroom, initial-length+1 admission/reservation, requested/granted/retained capacities, syscall/control/EINTR ordering, EOF/final metadata, private seams and R01–R15. Every refusal keeps consumed charges and zero retained payload. Existing non-read ResourceCharges literals and the old LX04 erase-context mutation template gain only mechanical `read:None` initialization under serialized ownership; retain all prior no-refund assertions. New in-crate fixtures allocating FDs retain accepted `crate::FD_TABLE` through owner close and worker join/child reap, with no child-thread reacquisition while the guarding parent joins. Preserve ordinary parallel harness execution and the actual FD-reuse repair; this is no production lock.

**Why:** A caller must distinguish work already spent and transient granted capacity from currently retained storage. Primary failed-syscall evidence and retry bounds must coexist without erasing LX04's accepted precedence. Before/after metadata cannot create an immutable snapshot or reconstruct live ownership. Source slices, original regressions, independent oracles/mutants and actual shipped consumers preserve the donor repairs and make changed bytes reviewable.

**Risk and limit:** An allocator may transiently overgrant before refusal; Arc/allocator abort, blocking syscall, Drop, scheduling, RSS and atomic-content bounds are not guaranteed. Matching metadata can miss torn same-size writes. A final successful checkpoint does not retract publication after later cancellation. Retained-capacity snapshots across cloned aliases are not additive pool accounting. Private seams do not establish installed/operator/kernel/filesystem support. Required full-profile and later delivery gates remain open; no implementation/test status, source grant or historical acceptance is changed by this ruling.

**Executor rule:** Follow the exact addendum rather than choosing a new API, reader/backend, error winner or weaker regression. Preserve actual P/O mechanism correspondence and the existing owner/control tests. Root binds immutable source admission and job inputs before implementation, then independently validates candidate-bound tests and selected-port receipt before accepting only this increment.

### TT02-R2: own the cancellation observer independently

**What:** The [exact amendment](2026-10-18-scopebase-tt02-cancellation.md) replaces the fixture-session poll with one owned `Box<dyn CancellationProbe + 'static>`, acquired under the entry clock before borrowed preparation and retained through completion. Vector sessions seal the selected AtomicBool source at acquisition. All checkpoints and six new focused controls remain required; wire slots/limits/IDs do not change.

**Why:** `prepare(&mut self)` lends typed resources through execute, so polling the same session while that borrow lives is rejected by safe Rust. An independent owned observer preserves resource custody and cancellation without aliasing. Acquisition time counts toward the existing deadline; configuration sealing prevents stale observers.

**Limit:** Custom metadata/probe/destructor behavior remains an honest-provider boundary; no hard interruption or native cleanup guarantee is added. Root ratified Astra amendment `f276eb47bad0b761712f3857b2f905fa382d14b4512ed98f0ce2f21dcf7c7a05`; task acceptance still needs actual engine tests and independent review.

## D09 — Test truth is independent and delivered to users

**Status:** SETTLED. **Owners:** domain case owners and TT01–TT10.

**What:** Each promoted behavior carries a positive twin, a sensitive wrong implementation, an independent expected result and its required evidence tiers. Package users get both the developer adapter and an installed operator route bound to the actual consumer build.

**Why:** Source inspection, model execution, object inspection, Linux integration, live BPF and installed clients answer different questions. An old green donor run or dependency test suite does not run automatically in a user's build.

**Executor rule:** Fix required cases before environment discovery. No denominator shrinkage, expected-output copy from the implementation, empty positive population, missing fixture, skip-to-pass, same-engine roundtrip-only oracle or second-library-copy certification. The bad control fails the intended semantic assertion after valid setup.

The normative [TT02 engine addendum](2026-10-18-scopebase-tt02-engine.md) fixes the four-argument session seam, external expected bindings, working vector provider and package-delivered wrong-value corpus. It preserves full TT02 ownership; TT03 later supplies Linux truth and TT07 supplies installed operator delivery. Per-assertion prerequisites retain an independently valid Fail even when another assertion lacks a twin. Contract ratification and engine acceptance are separate controller actions; no domain profile becomes qualified.

## D10 — Generic types do not erase application policy

**Status:** SETTLED. **Owners:** CP02–CP12, SDK and NX07.

**What:** Preserve insertion-frozen identity including genuine zero, independent loss channels, unknown generations, independent facts, partial views, alternatives and explicit closure evidence. Domain reducers remain local.

**Why:** KryProbe, OSSLscope and MemVeil encode different guarantees. Renaming their state to a common boolean or total would silently strengthen or erase one of them.

**Executor rule:** No shared stop-complete flag, inferred live MemVeil closure, detail-total substitution, snapshot poisoning or reset-as-wrap guess. A generic new primitive requires the existing independent consumer and countermodel criteria. CP12 may conclude that a reservation abstraction remains internal or product-local.

### CP03 counter and loss rulings

**Status:** SETTLED for implementation on 2026-10-18 after Astra architecture review and controller ratification. These refine D10; they add no requirement/task or qualified profile. The [capture contract](2026-10-17-scopebase-capture-design.md#samples-loss-and-conservation) specifies exact API and validation order.

- **C1 — Exact sample-pair bound.** AdvanceBound owns immutable baseline/current samples and an independently asserted maximum, including an explicit no-reset assertion. A source-only bound could accidentally survive channel, interval or value changes. The old signature was unimplemented, so compatibility does not justify preserving that risk. Equal-by-value pairs can reuse a bound; distinct real observations with identical caller metadata still require honest adapter observation/epoch management. Cost: a legitimate reusable external limit must be asserted again for each changed pair.
- **C2 — Deterministic refusal order.** Validate bound/current context and exact value first, then missing baseline, actual pair context, bound/baseline exactness, temporal order and arithmetic. Constructors validate policy before range, and bound context before Modulo policy/order. This makes malformed evidence distinguishable from an absent baseline or overlapping observation. No stored sample silently supplies missing evidence.
- **C3 — Preserve reset and saturation meaning.** A decrease from a saturated baseline remains ResetOrWrap; equal saturated samples are Saturated, and reaching the cap is AtLeast. Modulo requires a strict independent bound below the u128 modulus; an insufficient bound is unknown, a contradictory smaller bound is invalid. This deliberately strengthens donor saturating subtraction that could erase decreases as zero.
- **C4 — Retain units without invented policy.** Generic traits require only Unit; marker traits and raw identity Debug must not leak. Every declared kind/unit/magnitude remains valid, including exact zero and unknown. Classifying ordinary activity as loss remains an explicit caller decision. No total or automatic magnitude conversion is introduced.
- **C5 — Check every diagnostic lane.** Preserve KryProbe's actual capped fold, adapted to the specified byte protocol. Validate all lanes even after reaching cap; otherwise a late invalid lane could be hidden. O(n) work and caller-owned length admission are explicit; cap255 is not 255 known lost events.
- **C6 — Narrow adaptation and later ownership.** Admit only the six selected K/O host/data-vector fragments in the CP03 admission snapshot, preserving earlier O scopes and historical GPL source provenance under the existing owner Apache-2.0 authorization. P first-use observations remain supplemental reference-only; no P source/vector copy or kernel-source choice is authorized here. CP04 owns full-map host models, BP07 real producer/baseline behavior, CP06 persistent/exactly-once loss policy, CP11 real application consumers and CP13 installed conformance. Two packaged pure API examples do not close those tasks.

Acceptance requires independent modulo enumeration and a separately generated transition-table population, literal width64/saturation rows, wrong-pair controls for every retained field, complete diagnostic validation, semantic mutants with restored twins, exact primary unit-refusal diagnostics and actual source/archive consumers on both pinned compilers. A control that only fails setup or crashes does not establish the intended defect detection.

## D11 — Existing dependencies plus narrow adapters

**Status:** SETTLED approach; exact versions/APIs are PREDECESSOR SB02/BP01 outputs.

**What:** Probe the selected syscall, procfs, ELF/BTF and loader APIs against the real rejection cases on Rust1.88.0 and the pinned current toolchain. Select a primary dependency and only the adapter needed for a demonstrated missing contract.

**Why:** A library name, successful import or repository-level license badge does not establish API visibility, bounds, semantic fit, exact package license or MSRV. Existing Aya BTF internals, for example, cannot be assumed public.

**Executor rule:** No silent MSRV increase, speculative API, compulsory dual loader, donor path dependency, or default-host BPF/compiler setup. A failed probe produces a decision input, not permission for the executor to replace the subsystem.

## D12 — Expert decisions precede bounded execution

**Status:** SETTLED by the user's plan-repair request. **Owners:** controller/expert reviewer.

**What:** Use the task's exact source and interface packet. Sol high/xhigh can implement a bounded, specified port; Astra reviews architecture and critical invariants. Model escalation does not substitute for a complete packet. Luna handles mechanical work and Muse remains optional supplementary review.

**Why:** A capable executor still makes choices where a plan is silent. Leaving source, license, kernel, fallback or evidence policy unspecified transfers the architectural decision to the wrong role.

**Executor rule:** Return `NEEDS_DECISION` with the missing input, source evidence and affected work when an unresolved choice is encountered. Continue only independent ready work. Do not create a new policy, weaken a test, choose a new support profile or fill a public API with a placeholder to unblock yourself.

## D13 — Source custody includes implicit Git effects

**Status:** SETTLED. **Owners:** SB01 and every donor-intake step.

**What:** Read exact selected commits and WIP hashes without changing donors, contacting remotes, invoking configured helpers or lazily obtaining objects. Missing locally promised objects remain incomplete.

**Why:** Independent SB01 review demonstrated that an ordinary Git blob read can fetch into a partial clone. A command named local or read-only can still mutate the donor.

**Executor rule:** No fetch/reset/clean/checkout/update in a donor. Explicitly suppress lazy fetching and preserve missing-object versus missing-path distinctions. Test an owned partial-clone negative and a complete local twin; inspect transport invocation and object-store changes.

## D14 — Progress does not equal support

**Status:** SETTLED. **Owners:** controller, readiness tasks and RL01–RL04.

**What:** Keep plan readiness, source observation, implementation, profile qualification, installed delivery, migration and publication separate. Maintain exact open gates and failed evidence.

**Why:** A source inventory, structural checker, model report or tested coordinator can be correct while the requested library capability is absent.

**Executor rule:** No product completion from scaffolding, declared case counts, setup-tool tests or current-kernel loading. Preserve the original requirements, 86 tasks and existing H/G/UC identities; TC-R10/H33 append the explicit license boundary, giving 120 requirements and 33 families. Add necessary work with an owner, dependency and exit criterion; do not silently omit it or invent another framework to postpone the first port.
