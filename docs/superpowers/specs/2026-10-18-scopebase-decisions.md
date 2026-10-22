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

### TT03 owned fixture transport, raw truth and cleanup

Controller-selected 2026-10-22. The [exact TT03 contract](2026-10-22-scopebase-tt03-linux-fixture.md), [verification plan](../plans/2026-10-22-scopebase-tt03-verification.md) and [unaltered root ratification](tt03-linux/design-ratification.json) adopt frozen r4 index `1b003f8350c3653aa0d29c7ee781d3e5a0e04717ce9e18f6c36949bba3e9d822`; root decision SHA256 `ccde378b41f96e718628da7c780662c7fb490d81b59d08953b2db09410ac746d`. WHAT: full-key transport, immutable raw snapshots/counters, original-owner one-shot session and constructor custody, reached actual-runner deadline, retained creator context and one closed guard mapping. WHY: the accepted TT02 borrowing seam and native transport/owner/error boundaries must be fixed before implementing independent fixtures. Wrong context or lost ownership would invalidate later native qualification. Full r3 review index `24c8dc8ae28ca75c0d9f6ddb789d6a790018ab695e3e356be61d4f766a0d9a24` and scoped r4 index `5f3c47c55eb83095815a59e6d71f43b811823125d404cfe8c154247ae573bf27` retain their exact distinct scope. Fourteen P/seven F rows, full TT03 and mapped-image exits remain open. Actual product/C7/provider/worker/consumer/archive/build/output, TT04 realms, EOF/auditor, LX09 helper and final-index LX08 compatibility remain UNBOUND; no task acceptance, PACKET_READY or execution admission follows.

### LX08 strict creator and process observation

Controller-selected 2026-10-22. The [exact LX08 contract](2026-10-22-scopebase-lx08-process.md) and [verification plan](../plans/2026-10-22-scopebase-lx08-verification.md) ratify strict fallible epoch creation with original creator pidfd and authenticated active-PID namespace, FD-free descriptive markers, creator-first current-Own checks, exact errors/accounting/bounds and the actual native-EOF/owned-exit witness with combined bad control. They preserve all 34 selected source objects and 12 deferred objects. The WHAT/WHY/alternatives/cost table includes N01; the private independent r2 review found no additional blocking choice. Design approval does not accept LX08 or TT03, make a packet ready, or qualify any native/package/profile result. Actual product/C7/TT02 maintenance/TT03/TT04/EOF/audit and separate final-index joint compatibility bindings remain UNBOUND. The prior TT03 protocol snapshot and changed final r2 protocol remain explicitly distinct.

### LX05 parser scope and strict byte contract

The [exact LX05 contract](2026-10-18-scopebase-lx05-proc-contract.md) preserves both two-argument parsers, owned non-Clone snapshots, nominal stat/maps/mount domains and borrowed table-instance ParsedMountId. No observation becomes runtime authority. Mountinfo decoding consumes exactly three octal digits 001..377 once in each designated text field, preserving raw/decoded opaque options and rejecting NUL/out-of-byte/non-octal/truncated escapes; extra digits remain following bytes. Duplicate diagnostics sort the existing index by(number,original_row), then report the second original occurrence of the lowest repeated numeric ID without reordering records. O-S27 remains reference-only; its new three-good-plus-bad fixture is independently authored. These choices preserve 5 source files/31 slices/15 copying recommendations/16 references, 13 selected originals/10 deferred originals/11 new groups. The exact selected-source admission is separately recorded; implementation, two real 10,000-run fuzz campaigns and acceptance remain open gates.

### BP02 clarification under D07

**Status:** SETTLED by controller ratification on 2026-10-18, including independently approved BP02-R1. **Owners:** BP02 and controller. This adds no decision/task/requirement ID or dependency edge. **What/why:** The [BP02 map contract and six R1 alternatives](2026-10-18-scopebase-bp02-maps.md#ratified-choices-and-reasons) freeze executable ABI/source/task preconditions, authentic whole-root bind admission, one private audited unsafe module, metadata-before-bloom refusal, lookup_into/shared ArtifactId/actual linked-BTF matching, and exact grammar/error/resource bounds. Version/config/report strings cannot authorize native copies. The [native predicate](2026-10-18-scopebase-bp02-native.md#bp02-r1-exact-original-task-continuity-phase) additionally retains exact original authenticated thread-self text and requires a fresh positive one-byte stat read relative to the original held task directory: proc inode numbers wrap, getattr can outlive a task and cached output cannot prove current liveness. Keep its precise initial/admitted error/sticky/output/accounting rules and [independent controls](../plans/2026-10-18-scopebase-bp02-verification.md#bp02-r1-focused-amendment-controls). This is continuity at checks, distinct from the unchanged immutable-global-mask copy bound. Design ratification does not admit source/dependencies, qualify a kernel or close BP02; the controller binds those inputs and owned live resources separately, without making resource discovery a prerequisite of source implementation.



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

### TT02-R3: retain typed fixture failures and one chronological effects list

**What:** The [exact fixture failure amendment](2026-10-18-scopebase-tt02-fixture-errors.md) adds required nullable fixture_failure to every case, retains actual prepare/collect category/progress/effects, and validates the existing chronological effect batches against their nested mirrors before folding them once. Collect failure preserves the preceding adapter outcome. Seven focused controls cover stops, refusal separation, partial tails and effects.

**Why:** Diagnostic text cannot reconstruct a provider-reported stop or preserve its provenance. Treating a setup denial as an operation refusal could incorrectly qualify a broken fixture; folding a nested effect twice could corrupt resource custody. Exact typed evidence makes both run and import use the same decisions.

**Limit:** Provider TimedOut is not proof of a reached runner deadline or interrupted syscall. Import checks consistency, not transcript authenticity. Existing bounds, checkpoints and retirement slots stay fixed. Root ratified Astra supplement `d38b4e3ac616b949a6369a32c853e49bf687766aa24fdbc030b0b6a0d19d718e`; actual engine acceptance remains open.

## D09 — Test truth is independent and delivered to users

**Status:** SETTLED. **Owners:** domain case owners and TT01–TT10.

**What:** Each promoted behavior carries a positive twin, a sensitive wrong implementation, an independent expected result and its required evidence tiers. Package users get both the developer adapter and an installed operator route bound to the actual consumer build.

**Why:** Source inspection, model execution, object inspection, Linux integration, live BPF and installed clients answer different questions. An old green donor run or dependency test suite does not run automatically in a user's build.

**Executor rule:** Fix required cases before environment discovery. No denominator shrinkage, expected-output copy from the implementation, empty positive population, missing fixture, skip-to-pass, same-engine roundtrip-only oracle or second-library-copy certification. The bad control fails the intended semantic assertion after valid setup.

The normative [TT02 engine addendum](2026-10-18-scopebase-tt02-engine.md) fixes the four-argument session seam, external expected bindings, working vector provider and package-delivered wrong-value corpus. It preserves full TT02 ownership; TT03 later supplies Linux truth and TT07 supplies installed operator delivery. Per-assertion prerequisites retain an independently valid Fail even when another assertion lacks a twin. Contract ratification and engine acceptance are separate controller actions; no domain profile becomes qualified.

### TT02-R4: preserve the complete actual oracle return

**What:** The [exact oracle amendment](2026-10-18-scopebase-tt02-oracle-verdict.md) replaces flattened oracle_checks with required nullable oracle_verdict. It preserves the complete actual AssertionVerdict while deriving effective checks and capability separately. No response, valid returned judgment, typed harness Invalid and malformed response remain distinct. Four focused controls cover these boundaries.

**Why:** A checks-only record loses the independent harness verdict and original capability evidence. A zero-or-one vector would add cardinality rules to an inherently optional return. Retaining the complete response gives imports the evidence needed to reconstruct Invalid and prevents a copied Pass summary from masking it.

**Limit:** Import does not rerun or authenticate a custom oracle. Missing fields and the superseded alias reject in the unreleased major-1 schema; partial mode does not rehabilitate malformed returned records. Root ratified Astra supplement `c63b83bcaa0f08320189be41814ecc426a7dd7ac335d9ec9df508922c4febc70`; task/profile status is unchanged.

### TT02-R5: preserve typed dialect rejection

**What:** Add CaseErrorCategory::UnsupportedSchema with whole-script preflight, empty operation progress, Unknown cause and unchanged execute/receipt channels; enforce the [exact amendment](2026-10-18-scopebase-tt02-dialect-errors.md). **Why:** InvalidOutput plus a magic stage string loses the promised typed distinction, while Refused/UnsupportedOperation invents operation evidence. Structural envelope, adapter dialect and malformed operation data stay separate. Retain actual effects/oracle/error records and lifecycle custody; recompute zero effective operation activity. Eight focused groups with independent positive/negative controls remain required before TT02 acceptance. No task or profile is promoted by this decision.

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

### CP04 insertion provenance rulings

**Status:** SETTLED for implementation, 2026-10-18. Controller ratifies Astra P1-P5 plus S1-S2 in the [exact CP04 contract](2026-10-18-scopebase-cp04-insertion.md). These refine D10 without adding task IDs, requirements or qualified profiles. The contract includes complete required tests, delivered fixture schema, actual source/archive consumers and helper routing. The private architecture and supplement hashes are retained there.

#### P1. Exact counts and explicit saturated lanes

Keep `ProvenanceLane::new(LaneIdentity<I>, Count<U>) -> Self` as an exact-count constructor, including `Count::new(u64::MAX)`. Add `ProvenanceLane::saturated(LaneIdentity<I>) -> Self`. Store a private discriminated exact/saturated count state. Add payload-free `ContractError::SaturatedCount`. An explicit saturated lane cannot yield an exact fold, even when its identity marker is secondary or its cap would be zero. There is no automatic numerical cap inference in the generic constructor. The saturated constructor intentionally stores neither a cap nor a lower bound: this API only answers whether an exact total is justified, and returns no partial result. Callers needing bounds retain their original observation separately.

The KryProbe-shaped fixture adapter converts **every** raw `calls == u64::MAX` to `saturated`, including the owner and secondary lanes. All smaller raw words become exact counts. In this donor protocol, `MAX` is not an exact lane value. Exact generic callers can legitimately supply that value. A sum `(MAX-1)+1` succeeds in both generic and donor-shaped paths; `(MAX-1)+2` overflows. This is an explicit ADAPT of the donor sentinel into a typed distinction, not deletion of the original refusal.

Alternatives rejected: (a) reject `Count::MAX` everywhere, which weakens CP02 exact counts; (b) accept all raw donor values as exact, which erases saturation; (c) make the sole constructor accept a new public count-state enum, which breaks the already planned exact constructor and adds a type without additional capability; (d) infer saturation from a global policy or mutable option, which makes the same input's meaning depend on ambient state. The two constructors supply the missing mechanism with a smaller public surface. No wire decoder is added here.

#### P2. Cardinality, failure ordering and identity cost

First pass: inspect marker variants only, return `ConflictingProvenance` immediately upon the second owner; if no owner remains after the pass, return `MissingProvenance` (including empty input). Equal payloads never deduplicate owners. Do not call `I::eq`, inspect values for zero, clone identities or perform count arithmetic during this pass.

Second pass: walk original slice order. At each lane, return `SaturatedCount` for its explicit saturated state, otherwise checked-add its exact count and return `ArithmeticOverflow` on failure. Thus overflow in a prefix precedes saturation later in the slice; an earlier saturated lane precedes later overflow. This preserves the donor's left-to-right second pass while making its formerly undifferentiated refusal visible. Reordering a valid all-exact population preserves success/total; reordering differently malformed lanes may change the first count error by design. Owner cardinality always precedes both count errors.

After both passes succeed, clone the unique owner's payload exactly once into `InsertionFold`. Keep the specified `I: Eq + Clone` bound for this task, but folding performs **zero Eq calls**. The Eq bound is a public eligibility constraint, not an algorithmic justification to compare owners. All zero-valued identities and a uniquely marked zero-activity owner are valid. A result is insertion provenance asserted by the caller, not evidence that an insertion occurred in a kernel.

#### P3. Full-map and migration helpers are shipped test fixtures

Adapt `PcpuWho` and the selected full-map `Sim*` mechanisms into package `tests/support/cp04_model.rs`. They are reusable package test source, not public library exports or a universal table/producer policy. A local identity-gate table, local finite attribution table, independent preallocated diagnostic slots, and independent aggregate counts remain separate. Existing-key hits at capacity must succeed; new keys refuse without mutation. A wrong lazy diagnostic entry in a full gate reproduces the historical loss hole.

Retain donor-shaped fields and assertions only as necessary in the fixture: insertion identity tuple, latest display fields, local first/last stamps and raw saturating tally. Production folds only identity plus exact total. Test fixtures may demonstrate that the latest display changes while the original identity remains; no generic timestamp/latest-writer reducer is exported. Distinct program/CPU slots in the fixture illustrate independent storage but do not qualify real program ordinals, CPU geometry, writer exclusion, reentry, wire layout or a loadable BPF object.

The historical 256-entry identity gate / 2048-entry attribution population and below-capacity 128-entry twin remain alongside the plan's five-operation capacity-one/capacity-five pair. New small cases supplement the original defect population. A preexisting signal254 plus four failures becomes255, never an exact omitted-event count. CP03's shipped capped fold is called; it is not reimplemented in the model.

#### P4. New value types, traits and disclosure

Implement the already specified `ObservedIdentity<I>` and `IdentityUnknown` value vocabulary in `provenance.rs`. Known zero is known; explicit unknown reasons stay explicit. Equality of two Unknown values is equality of their reason only and cannot make them a joinable identity. No unknown-to-default key conversion or generation tracker is added (CP05).

All identity-bearing Debug implementations redact payloads and require no `I: Debug`. Generic wrapper trait implementations require only the corresponding payload trait and `U: Unit`, never `U: Clone`, `U: Eq` or `U: Debug`. Fold success costs two linear traversals plus one caller-defined clone; rejected input performs no payload clone or equality. A clone may allocate, block, panic or have caller-defined effects; ScopeBase neither catches it nor promises bounded payload bytes/time. This refines broad 'pure/no effects' wording to describe library-owned operations honestly. Structural wrapper sizes are fixed; indirect payload allocations belong to the caller. Auto Send/Sync follows actual fields, without manual unsafe implementations.

#### P5. Source and completion boundaries

Only the named frozen KryProbe source at `d153f3aaf9a3931337b47c9e1b046c692da55083` is selected. Source inspection matched both full-file hashes and all four controller ranges. Narrow proposed copy scopes and reference-only portions are in `source-selection.json`. Existing grants cover other portions and must not be stretched. Root admitted the twelve selected scopes in the [immutable CP04 snapshot](../../provenance/admissions/2026-10-18-cp04-insertion.json), preserving earlier scopes and the existing owner authorization. Historical GPL-3.0-or-later observations remain; destination host/test/data terms are Apache-2.0. No target/BPF/shared-source grant follows.

Two independently wired packaged API consumers exercise different caller reducers and units, with separately locked external builds against the source and actual archive. They establish this increment's usable API boundaries. They do not close CP11's three donor-shaped application adapters, CP13's installed conformance route, UC14 or a full capture profile. Source/archive semantic controls and previous CP02/CP03 evidence remain separately bound.

S1 explicitly limits unwind preservation to library-owned wrapper/count fields; arbitrary caller Clone effects can remain. S2 makes the new helper's wrapper optional and explicit, with direct pinned Cargo as its standalone default. Coordinated cells use the wrapper, and one actual archive campaign under one outer lease proves the portable route. Existing CP03 helper portability remains TT07/CP13 work without repeating accepted unchanged production controls.

### CP05 generation and retained-history rulings

Controller-selected 2026-10-22. The [exact contract](2026-10-22-scopebase-cp05-generations.md) and [verification plan](../plans/2026-10-22-scopebase-cp05-verification.md) record WHAT/WHY, alternatives/cost, all eight source selections and seventeen original assertion subsets. No CP05 implementation or passing product test follows from these rulings.

- **CP05-D1:** Object-generation exhaustion returns ArithmeticOverflow; every false complete key relation returns GenerationMismatch from require_generation. A domain/error split or a new exhaustion variant would add public semantics without a demonstrated consumer need. Capture EpochExhausted stays separate. Supplied object generations 0/MAX remain valid.
- **CP05-D2:** ObjectKey conditionally implements Clone/PartialEq/Eq and redacted Debug without K:Debug; no Copy/Ord/Hash, Epoch expansion or unsafe auto-trait promise. Compare complete epoch, then generation, then one raw equality; overflow checks precede raw cloning. A raw mismatch requires Eq. Direct production probes, distinct from fixture matching, retain zero/one call counts, panic order and the limit of library-owned field preservation; caller interior effects can remain.
- **CP05-D2 local evidence:** Keep K submit-bound stable IDs and M reader/retired-ring policies separate. Missing retained history is UnknownContinuity, while known key mismatch stays definite. The fixed six-action alphabet/lengths 0..6 yields 55,987 scripts/324,726 actions. Its journal has at most six action rows and eighteen facts with explicit kinds/IDs; duplicate tokens retain the first binding and their own refusal flag. K first-seen creation uncertainty is scripted/counts once at admission; M text validators/rendering and ungranted K first-seen branch bodies stay outside copied CP05 behavior.
- **CP05-D3:** The [adopted combined source admission](../../provenance/admissions/2026-10-22-next-host-scopes.json), SHA256 `e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`, binds the narrow scopes under existing owner authorization and preserves previous grants/reference-only inputs. Actual copied subsets/destination hashes still require a candidate-bound receipt. Source admission does not bind the actual post-BP02 product execution base or make the packet ready. Exact current prerequisites/checkout/resource/output bindings remain required.

The K lifetime repair is `2b59c24db0d4ce176980a2858a66001636a5f75e`; `e529862ea898ca9918b1b64548505e34bd45f8e2` repairs completion-count test equations. Use selected current frozen bytes and source-specific regressions. Two distinct scoped clients, source/archive controls on both compilers/three selections and six affected capture archive cells establish only this pure/package increment. CP08/CP11/CP13/TT07/MG authority, installed conformance and live retirement gates remain open.

### CP06 scoped views, feed presence and correction rulings

Controller-ratified exact r3, 2026-10-22: [contract](2026-10-22-scopebase-cp06-views.md), [verification](../plans/2026-10-22-scopebase-cp06-verification.md) and [D1–D9 / review / ratification support](cp06-views/README.md). Full r2 and scoped r3 review preserve all 25 case IDs, fifteen original subsets and 29 ranges. Accepted CP05 is separately bound. The [reviewed narrow D9 successor](cp06-views/d9-private-unit-successor.md) now satisfies only the exact-bound-delta prototype prerequisite: retain the original declaration allowance and add private_interfaces only to the exact seven macro-generated implementation method declarations. Actual product/source/archive privacy/API/dyn/compiler, quantity-port and final packet/resource gates remain open; implementation is not admitted.

WHAT/WHY: keep persistent per-claim consumed loss separate from immutable call-local partial overlays; preserve private full source/channel/unit/kind/magnitude observations without value deduplication. Required feeds enforce declared per-channel presence, rather than numeric totals or completeness. Keyless correction envelopes replace an exact next revision; complete CP05 key routing and all-holder distribution remain application responsibilities. Ordinary payload Drop can panic; only normally returned metadata refusals promise the returned original owner. No public UnitKind, audit accessor, serialization, target-key issuer or hidden broadcaster follows.

The ratified private sealed-token/method design preserves the public Unit spelling and intended dyn compatibility, subject to the exact-bound-delta prototype prerequisite now satisfied by the reviewed successor and the still-open actual product/source/archive/compiler/privacy gates. Duplicate-before-reserve preflight on immutable ID slices is explicitly pairwise `O(n²)` with `O(1)` extra duplicate-check memory after length admission, refining broad linear-work prose. Payload-free normal errors expose no retained tags. CP10 public audit/export/neutral serialization, CP11 real reducers/protected-history regression preservation/all holders and CP13/TT07 exact-consumer installed delivery remain open. Actual OSSLscope migration/protected per-TID history/real 5,000-foreign-close application control belongs to MG02, KryProbe migration to MG03, and MemVeil pool-pressure/independent-copy/retired-history application controls to MG04, with accepted CP05 as prerequisite and dependencies/exits in root TODO. Historical MG03 shorthand in sealed CP06 bodies/JSON does not assign O/M application ownership or make migration a gate for independent component qualification.

## D11 — Existing dependencies plus narrow adapters

**Status:** SETTLED approach; exact versions/APIs are PREDECESSOR SB02/BP01 outputs.

**What:** Probe the selected syscall, procfs, ELF/BTF and loader APIs against the real rejection cases on Rust1.88.0 and the pinned current toolchain. Select a primary dependency and only the adapter needed for a demonstrated missing contract.

**Why:** A library name, successful import or repository-level license badge does not establish API visibility, bounds, semantic fit, exact package license or MSRV. Existing Aya BTF internals, for example, cannot be assumed public.

**Executor rule:** No silent MSRV increase, speculative API, compulsory dual loader, donor path dependency, or default-host BPF/compiler setup. A failed probe produces a decision input, not permission for the executor to replace the subsystem.

## D12 — Expert decisions precede bounded execution

**Status:** SETTLED by the user's plan-repair request. **Owners:** controller/expert reviewer.

**What:** Use the task's exact source and interface packet. Sol high/xhigh can implement a bounded, specified port; Sol max reviews architecture and critical invariants. The user's 2026-10-18 quota instruction reserves Astra for rare serious unresolved problems after Sol max investigation, with the need recorded before exceptional dispatch. Model escalation does not substitute for a complete packet. Luna handles mechanical work and Muse remains optional supplementary review.

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

### BP03 descriptive host rulings

Root ratified the exact independently reviewed r2 [host contract](2026-10-22-scopebase-bp03-host.md) and [verification plan](../plans/2026-10-22-scopebase-bp03-verification.md). All eight choices and R1–R4 repairs are normative: complete filter truth, move-only bounded observations with explicit Arc sharing, restricted JSON prepayment/errors, explicit adapter Limits/RunLimits composition, literal-ledger limits, separate descriptive domains and complete inherited-manifest/client/cell/tool/cache delivery. Their finite seeds/templates ship under bp03-host. This is descriptive/model design only; actual execution bindings, implementation, full BP03 native/operator/profile qualification and selected-port receipts remain open.

### TT02-RSP01: strong actual prepared response and scalar no-dispatch

**Status:** SETTLED exact-r2 design by root ratification; maintenance implementation
not admitted / NOT_RUN / NOT_PACKET_READY. **Owners:** TT02-RSP01 and BP03/root.
**WHAT:** Independent ResponsePreparedAdapter/GAT consuming call, additive shared
run_profile_prepared, prepared-only strict BP03, actual R<=F and allocation-free
response metadata finish. Preserve scalar preparation cause/zero-based position,
first followup HarnessError and one moved truthful nonterminal partial v1 with
fixed cleanup and Invalid > Failed > Incomplete. Dedicated forwarding allocation
observer is the explicit noninjecting test-policy exception. **WHY:** Actual key
admission itself may fail, so old total keyed return cannot guarantee a bounded
fallback; fresh clone/format/generic validator would violate strong actual F.
[Complete contract](2026-10-22-scopebase-tt02-prepared-response.md) preserves
alternatives, ownership/chronology and all thirteen PRP/delivery gates.
Existing TT02 acceptance/schema1/public IDs/legacy callers remain unchanged.
No task/requirement/mapping count changes; actual final packet remains UNBOUND.
