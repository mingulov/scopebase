# ScopeBase preservation and executor-readiness plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans when implementation resumes. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing M0–M6 plan executable without asking an implementer to rediscover donor fixes or invent architecture, licensing, kernel support or test policy.

**Architecture:** Keep the existing packages and 86-task DAG. Add a normative decision register, a concrete task-packet contract and source-to-destination preservation records. Repair the source intake before relying on it; do not build another coordination system.

**Tech Stack:** Existing Rust2021/Linux/BPF/native design, proposed MSRV1.88.0, existing Git/Python development tools. This revision writes plans and working instructions; no product implementation or live qualification follows from it.

**Spec:** [Executor contract](../specs/2026-10-18-scopebase-executor-contract.md), [decision register](../specs/2026-10-18-scopebase-decisions.md), [master specification](../specs/2026-10-17-scopebase-design.md).

## Global Constraints

- Port selected fixed donor mechanisms, their regressions and explanations together. NEW mechanisms require an explicit reviewed reason and interface.
- Use the provisional Apache-2.0 userspace / GPL-2.0-only BPF / GPL-3.0-or-later application split in D03–D04; no MIT option for project-owned code. Shared target source needs compatible grants. Do not silently decide an upstream dependency option.
- Source observations, author authorization, destination terms and kernel runtime license bytes are distinct fields and checks.
- Preserve full source/WIP pins, identity domains, original owners, partial effects, limits, compiler/kernel workarounds and application policy boundaries.
- Freeze exact required profiles/cells before discovery. Object acceptance, loading, semantic activity, cleanup and installed use are separate gates.
- Existing product migrations and publication remain later. The 120 requirements, 86 tasks and existing H01–H32/G01–G23/UC01–UC14 identities stay stable. H33 and TC-R10 append the explicit license-boundary obligation without renumbering prior IDs.
- No donor mutation/fetch, package installation, privileged probe or product code change during this plan-repair pass.

## Review Focus

1. A whole-file source group hides an omitted process or insertion-identity fix: select symbols and original tests per mechanism before dispatch.
2. A permissive host license leaks into GPLv2 target inputs: inspect the actual target closure, shared headers and loader declaration independently.
3. An old-verifier EACCES is classified as missing privilege: retain cause/stage evidence and same-errno/different-cause tests.
4. A local metadata check fetches promised objects or ignores nested regression references: repair SB01's demonstrated counterexamples before acceptance.
5. A boundary stub or mocked case makes an unimplemented capability look ready: expose behavior only with its implementation and preserve tier/profile completion boundaries.

## Current custody and acceptance

The original repair pass below is historical. Its SB01/SB02/SB03 and later foundation repairs are now accepted within the scopes in [TODO](../../../TODO.md). At the 2026-10-18 transfer checkpoint, thirteen tasks are accepted; TT02 candidate `e7de8916`, staged BP02 on `c2a6e6c` and LX05 candidate `e86ff68a` remain in progress. The goal is paused for transfer. Use the single [handoff](../../../handoff.md#resume-here) for the exact candidates, stop receipts, remaining checks and access-program routing; [transfer evidence](../../reviews/2026-10-18-scopebase-transfer.md) does not accept these tasks. No renewed source inventory, re-login or packet redesign is needed to continue those three existing assignments.

### Historical repair-intake baseline

Main contains the accepted development helpers at `bbcad0d9b52d8cb607ca7d1d6e120823e7c169b9`, with 70 setup-tool tests at the reviewed implementation bytes. Those tests are not ScopeBase library tests.

SB01 candidate `8417beead68a03ecaff361d0d76da5f38c09820f` remains **unaccepted** in `.worktrees/sb01-intake`; its integration copy is on `feat/m0-foundations` in `.worktrees/m0-integration`. Independent comparison preserved 124 source observations, eight authorities, two dirty inputs, original regression candidates and all 178 obligation mappings. Review nevertheless found a real lazy-fetch mutation and unvalidated nested family/regression references. Its historical compulsory-GPL destination policy is superseded by D03 and must be amended before use.

The separate progress-check candidate `ca9169a7a8da866e2a00503e93a81087d04a782e` had independent PASS but was not product acceptance. These paragraphs describe the starting repair state, not current instructions to redo completed work. Preserve all worktrees/reports/evidence and consult the current checkpoint above.

## Repair intake validation

**Owning task:** SB01. **Starting source:** the exact candidate above, not a fresh validator. **Owned files:** `tools/planning/check_traceability.py`, `tools/planning/tests/test_traceability.py`, `docs/provenance/{donors.json,licenses.md,adoption-decisions.md}`; root controller alone updates the registry, TODO and acceptance record. Existing interface/evidence documents stay unchanged unless a reviewed incompatibility is found.

**Consumed interfaces:** existing `validate(registry, ledger, repo_root)` contract and `verify_local_sources(ledger, source_roots)` result split; preserve structural mode and CLI exit0 valid, exit2 incomplete source availability, exit3 invalid. The executor must read the existing signatures rather than substitute another API.

**Required changes and tests:**

- [ ] Add `test_promised_blob_is_incomplete_without_fetch`: create an owned filtered `file://` clone with commit/tree present and the selected blob promised but absent; capture its object-store inventory and a transport sentinel. Run explicit local verification. Assert exit2, no transport invocation, identical object inventory and no donor checkout change. A complete local twin returns verified. A path genuinely absent from the selected tree remains invalid, not a missing-object excuse.
- [ ] Prevent lazy fetching for **every** Git command in `verify_local_sources` with Git's global `--no-lazy-fetch` option, retaining replace-ref and optional-lock controls. Git2.53.0 in this workspace accepts that option; a Git lacking it returns incomplete before source inspection. Distinguish an existing selected tree entry whose blob is locally missing (exit2) from a genuinely absent selected path (exit3); use literal path matching. Do not repair missing objects, configure donors or fetch them.
- [ ] Add `test_case_family_and_regression_references_are_total`: delete H04, introduce G99/UC99/nonexistent TODO refs, point a selected regression at `MISSING:absent.rs`, remove its recorded symbol candidate, change its line and remove group membership. Each must fail its intended reference assertion. Keep documentation files with genuinely zero symbols valid.
- [ ] Validate every canonical case-family input, nested reference, independent oracle/control description and selected regression against its donor, selected file, group and observed symbol/line. Require the preservation collections; a valid top-level owner list does not compensate for a lost nested test.
- [ ] Replace “destination license equals historical SPDX” with the D03 authorization model below. Add authorized-owner, ungranted-third-party and host/BPF/shared role controls. Preserve original raw observations and hashes exactly.
- [ ] Run `python3 -m unittest discover -s tools/planning/tests -v`, the default structural checker, the relevant planning/progress checks and `git diff --check`. The partial-clone control uses only owned temporary repositories. No actual private source re-scan is needed for unchanged observations.
- [ ] Submit one focused candidate and its preserved RED/GREEN/control evidence for independent review. Accept SB01 only after the real findings and destination policy are resolved. Do not repeatedly rebuild the unchanged 124-file inventory.

**Destination-license model:** implement the frozen record contract below. Keep `license.spdx` as the source observation; it is not the destination grant. User authorization applies to their own contributions and does not change upstream portions. `NOASSERTION` alone does not prohibit an authorized owner's port. No metadata record proves legal ownership or kernel runtime compatibility.

**Done:** unchanged observations remain intact; nested preserved knowledge is validated; local inspection has no fetch side effect; the approved destination policy is representable without rewriting history. No Rust capability is qualified by this foundation acceptance.

### SB01 adoption record contract

This is the next validator's input contract, not a general SPDX compatibility engine or the later final-object dependency manifest. Bump the intake `schema_version` from `1.0.0` to `2.0.0`. Keep `validate(...)` returning its existing error list and keep the CLI/result/exit contracts. A well-formed unresolved record can pass structural intake validation; it cannot admit a source copy. The controller checks that every selected port slice is `READY_FOR_SELECTED_SCOPE` before dispatch. SB01 acceptance permits unresolved, unselected future inputs.

Add top-level `authorizations`, an array containing exactly the one canonical owner grant below for this version. Its ID must be unique; the decision link resolves against the repository and is checked as a path plus anchor:

```json
{
  "id": "OWNER-2026-10-18",
  "authority": "USER_DECLARED_AUTHOR",
  "status": "PROVISIONAL",
  "scope": "USER_CONTRIBUTIONS_IN_SELECTED_FILES",
  "decision_ref": "docs/superpowers/specs/2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination",
  "allowed_destinations": {
    "host": "Apache-2.0",
    "bpf-target": "GPL-2.0-only",
    "shared-target-source": "Apache-2.0 OR GPL-2.0-only",
    "host-build-tool": "Apache-2.0",
    "data-document": "Apache-2.0"
  }
}
```

This records the user's existing authorship statement and provisional grant; it does not require asking for permission again or proving authorship line by line. It covers only their contributions in a selected file/slice bound by the existing file ID, commit and observed SHA-256. It cannot authorize an upstream portion. An unknown authorization ID, duplicate ID, changed grant, dangling decision link or grant applied outside that scope is invalid. A new grant needs an expert/controller amendment of this contract; the executor cannot mint one.

Every file's `adoption` object has all the following fields. Reject missing required fields, wrong types, unknown enum values and unknown adoption/authorization/third-party-record keys; `null` means explicitly unselected or unknown, never an empty string or an absent field.

| Field | Frozen type and meaning |
|---|---|
| `disposition` | Retain existing enum: PORT_SOURCE, DEPENDENCY_ADAPTER, INDEPENDENT_CONTRACT, VECTORS_ONLY, PRODUCT_LOCAL, REFERENCE_ONLY |
| `copy_status` | Existing NOT_COPIED or BLOCKED; SB01 records no actual copies |
| `decision_status` | READY_FOR_SELECTED_SCOPE, NEEDS_DECISION or REFERENCE_ONLY; these describe adoption metadata, never runtime/package readiness |
| `source_scope` | `null`, literal `FILE`, or a nonempty array of `[first_line,last_line]` pairs: positive JSON integers, excluding booleans, inclusive, sorted, nonoverlapping; file ID/hash come from the parent record |
| `ownership_basis` | USER_OWNED, THIRD_PARTY, MIXED or UNRESOLVED; user declaration applies to owned contributions; only concrete upstream portions need separate terms |
| `artifact_role` | `null` or host, bpf-target, shared-target-source, host-build-tool, data-document; one proposed use/scope, with shared host/target source using the shared role |
| `destination_license` | `null` or the exact selected SPDX expression; the owner's contribution uses D03's role grant, while THIRD_PARTY retains its selected original option |
| `authorization_ref` | `null` or the exact owner-grant ID above, resolved through `authorizations`; required for ready USER_OWNED/MIXED and `null` for THIRD_PARTY/UNRESOLVED |
| `third_party_terms` | `null` means not yet classified; `[]` records no third-party portion in the selected scope; otherwise a nonempty array of the fragment records below |
| `blocked_reason` | `null` only for READY_FOR_SELECTED_SCOPE; otherwise a nonempty concrete reason naming the missing decision or reference-only boundary |

A third-party fragment record has exactly `source_scope`, `offered_spdx`, `selected_option`, `license_evidence` and `notice_evidence`. Scope uses the same FILE/range form, is non-null and must lie within the parent selection; multiple fragments cannot overlap. Its source pin/hash is the parent file's pin/hash. `offered_spdx` is an observed expression or NOASSERTION; `selected_option` is a supported offered option or `null` when undecided. Both evidence fields are arrays of existing license-evidence-shaped `{path,sha256}` records: safe repository-relative source path and full SHA-256. `license_evidence` must be nonempty for a selected option; `notice_evidence` may be empty only when no separate notice is required. These are source observations; actual notice delivery is checked by later packaging tasks. Range containment is structural; correspondence to source text is inspected by the expert and, when requested, against locally available selected bytes. Structural validity alone does not establish that the declared list contains every upstream fragment.

Supported option selection is deliberately finite: a single observed Apache-2.0, GPL-2.0-only, GPL-3.0-or-later or Apache-2.0 WITH LLVM-exception retains that exact expression; GPL-2.0-or-later permits GPL-2.0-only or GPL-2.0-or-later; MIT OR Apache-2.0 permits either offered branch. NOASSERTION supplies no third-party grant. Do not infer an LLVM exception or parse an unfamiliar expression into a new policy. Unlisted expressions remain observed but NEEDS_DECISION until the expert amends the supported set.

**Admission rules:**

1. READY_FOR_SELECTED_SCOPE requires non-null scope/role/destination, NOT_COPIED, no blocked reason, a disposition other than REFERENCE_ONLY/PRODUCT_LOCAL and resolved ownership. USER_OWNED requires the owner reference and `third_party_terms: []`; MIXED requires that reference and nonempty third-party records; THIRD_PARTY requires no owner reference and nonempty third-party records covering the full selected scope. Every third-party fragment must have its offered option resolved. The validator checks these declarations; independent review checks that the selected scope actually matches them.
2. For USER_OWNED/MIXED, the destination must equal the owner grant for that role. For THIRD_PARTY, the destination must equal the retained selected option of every fragment; differing retained options require NEEDS_DECISION and a narrower selection. Do not replace upstream terms with the owner grant.
3. For ready host/build-tool/data-document inputs, supported retained upstream options are Apache-2.0 and Apache-2.0 WITH LLVM-exception. For a ready GPLv2 BPF input, GPL-2.0-only and GPL-2.0-or-later are supported retained options. Shared host/BPF source can be ready under the owner's dual grant with no upstream portion; any shared upstream portion remains NEEDS_DECISION in this version. A GPL-only upstream portion cannot supply the Apache branch. These rules are a small conservative supported set, not a claim that every other combination is legally impossible.
4. An upstream MIT branch or a BPF/shared use of Apache-2.0 WITH LLVM-exception remains NEEDS_DECISION in this version. The first needs the unresolved dependency-policy choice; the second needs review of the actual supplied exception and fragments. Bare Apache-2.0 target inputs, GPLv3-only inputs claimed as an Apache library, or incompatible shared grants cannot be marked ready. Do not select an upstream MIT branch automatically or treat this gate as a ban on all third-party MIT use.
5. NEEDS_DECISION requires NOT_COPIED and a reason. Missing scope/role/destination/grant/terms may be explicit `null`; a non-null reference must still resolve and any non-null field must satisfy its type, selection and source-binding rules. It admits preservation of knowledge, not copying. REFERENCE_ONLY requires BLOCKED, disposition REFERENCE_ONLY or PRODUCT_LOCAL, a reason, and null destination; it does not imply the user's ownership grant was unavailable. Neither state blocks unrelated ready host work or foundation acceptance.
6. Changing role, source hash or selected scope requires rechecking the record against that use. A primary-use intake record is not a final build-closure claim. The later payload manifest enumerates every actual source/generated input and role; do not invent that manifest during this metadata repair.

For example, this adoption object is structurally ready for a **synthetic user-owned host fixture** whose source observation is GPL-3.0-or-later or NOASSERTION. It does not classify a real donor file without inspection:

```json
{
  "disposition": "PORT_SOURCE",
  "copy_status": "NOT_COPIED",
  "decision_status": "READY_FOR_SELECTED_SCOPE",
  "source_scope": "FILE",
  "ownership_basis": "USER_OWNED",
  "artifact_role": "host",
  "destination_license": "Apache-2.0",
  "authorization_ref": "OWNER-2026-10-18",
  "third_party_terms": [],
  "blocked_reason": null
}
```

**Required sensitive fixture pairs:** retain the source observation/hash in each pair and fail the named metadata assertion, not fixture setup.

| Valid or unresolved control | Invalid twin / expected assertion |
|---|---|
| Owner fixture above, including NOASSERTION source | Missing/dangling owner reference or substituted grant: authorization resolution fails |
| Same owner fixture with shared role and Apache-2.0 OR GPL-2.0-only | Shared/BPF role with bare Apache destination: role/grant mismatch fails |
| Pure upstream Apache fixture, no owner ref, full-scope original terms/evidence | Upstream GPLv3 fixture relabeled Apache or owner reference used for it: ungranted third-party/role assertion fails |
| Mixed owner/Apache upstream fixture with retained fragment pin/scope/evidence | Delete that portion's terms, extend outside selection, change source binding or claim USER_OWNED with remaining upstream records: fragment assertion fails |
| NEEDS_DECISION fixture with null third-party classification | Mark ready while keeping null terms: completeness assertion fails; `[]` is a distinct explicit declaration, not evidence that classification occurred |
| Unselected Aya target option preserved as NEEDS_DECISION | Mark ready with MIT automatically selected, or bare Apache for GPLv2 target: unresolved policy/target-compatibility assertion fails |
| LLVM exception preserved in host fragment, original evidence retained | Drop the supplied exception, invent it for bare Apache, or mark unreviewed BPF use ready: offered-option/role assertion fails |

**Migration:** preserve every `license`, raw observation, source pin/hash, source-evidence record, regression and original source-obligation value. Add the new metadata without rescanning unchanged donors. Default unclassified or not-yet-selected scopes to NEEDS_DECISION with explicit nulls/reason; do not infer ownership from GPL/NOASSERTION and do not carry the old automatic 14-file block forward as policy. Existing reference-only technical choices may remain with a concrete reason. Populate READY only for the expert-selected fixture/source scopes actually classified under this contract. Update obsolete tests that asserted compulsory historical-license equality and explain their supersession. These changes do not qualify any of the 124 donor files as executed ScopeBase behavior.

The repair uses the accepted plan amendment as its planning baseline: 120 requirements, 179 mappings and H01–H33. Preserve the original 178 observation/obligation values and H01–H32 inputs; append H33 as the explicit new ScopeBase planning obligation with no invented historical donor failure. The controller integrates these plan inputs into the isolated repair checkout before dispatch and records the exact resulting product base; this does not merge or accept the uncorrected M0 candidate.

### Selected-port receipt contract

This is bounded SB01 provenance maintenance, supplementing schema 2.0.0 without changing its adoption semantics or historical observations. NOT_COPIED/BLOCKED describe pre-copy admission state at a bound snapshot; they are not mutable current-copy flags. Retain an immutable task-specific ready intake snapshot and append `docs/provenance/ports/<task>-<receipt-id>.json` for actual selected PORT/ADAPT/VECTORS_ONLY completion. First real LX02/CP02 receipts require their completed candidate mappings; receipt-tool fixtures are not product receipts or acceptance.

The version 1 object has exactly these fields:

| Field | Required value or binding |
|---|---|
| `schema_version`, `kind` | JSON integer `1` (not boolean/float), `SELECTED_PORT_RECEIPT` |
| `id`, `task_id` | Unique receipt ID using the existing ASCII job/profile grammar `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; task ID resolves in the supplied task registry |
| `copy_state` | `PORTED_SELECTED_SCOPE`; no whole-file, accepted or qualified inference |
| `admission` | Exactly `{path,sha256}` for the retained ready schema 2.0.0 intake actually used; preserve nested source observations and grants |
| `mappings` | Nonempty array of exactly `{file_id,source_scope,destinations}`; file ID resolves in that intake; FILE/ranges use the existing grammar and must be contained in its READY_FOR_SELECTED_SCOPE grant |
| `destinations` | Per mapping, nonempty array of exactly `{path,sha256,symbols}`; actual destination file digest and nonempty symbol/section labels |
| `preservation_map` | Exactly `{path,sha256}` for the existing reviewed task map: source/destination symbols, original regression IDs, independent oracle/control, deliberate differences and unported scope; no second case database or inferred pass/fail summary |
| `supersedes` | `null` or exactly `{path,sha256}` of the previous immutable receipt; same task, admission path/hash and normalized file/scope identity; different source/admission starts a separate lineage |

All artifact paths are safe repository-relative regular-file paths. Reject absolute/traversal/empty components, backslashes, NUL, symlinks (including parents), duplicate JSON members, duplicate receipt IDs or mapping entries, unresolved references, stale hashes and unresolved/reference-only grants. Receipt IDs are unique across distinct supplied/chain documents; a shared identical chain ancestor is the same document, not a second receipt ID. Duplicate explicitly requested paths are invalid. Mapping identity normalizes adjacent inclusive ranges; mapping order does not affect lineage identity. Multiple selected ranges/destinations are permitted without claiming every line in a grant was ported. Labels contain 1–256 characters with non-whitespace content.

Caps are 1 MiB each for receipt, admission and preservation documents; 128 mappings, destinations per mapping, labels per destination and explicitly requested receipts; 16 supersedes links. Destination hashing reads 64 KiB chunks with a 16 MiB/file cap. These bound parsing/read/hash work, not syscall duration or semantic copying. The requested receipt compares actual current destination bytes; historical chain documents/grants/preservation maps remain hash-checked, while historical destination hashes are observations about their old bytes, not the new tip. Explicitly checking an old receipt against changed current files returns mismatch. Review checks correspondence and regression completeness; hashes provide no authenticity or ownership proof.

Use repeatable explicit `--port-receipt PATH` with `tools/planning/check_traceability.py`; `validate_port_receipt` returns errors and required-evidence unavailability without source acquisition. The receipt check rechecks its consumed parent source pins/hashes and ready adoption/owner grants from the bound schema 2.0.0 snapshot; it does not reopen historical research/license links or repeat full source-intake validation. No automatic global scan, donor read, build, network or task acceptance occurs. The legacy invocation/report/exit behavior stays intact: without receipts it is intake-only and cannot assert no port occurred. Invalid input/binding is INVALID/3; missing named required evidence is INCOMPLETE/2. Every expected first-port receipt must be named at acceptance; omission is not evidence of absence. The controller retains snapshots/receipts and binds the same destination hashes plus actual reviewed revision separately in the acceptance record. Real source mapping and retained-regression coverage require independent review.

## Freeze source slices and missing design inputs

**Owning tasks:** SB01 supplies the selection/preservation format; SB02/SB03 and component foundation tasks supply their own exact decisions. These are refinements of existing tasks, not 86 new administrative tasks.

Before a PORT/ADAPT task is dispatched, select function/type and original regression names from the pinned files, map them to the named destination module and list any cross-donor differences. A broad set such as “all 21 capture files” is not a port recipe. Preserve application-specific pieces explicitly as product-local; do not silently drop their counterexamples.

| Concrete missing input | Owner / dependency | Exit criterion |
|---|---|---|
| LX08 process authority inputs omitted by a coarse file group | SB01 then LX01/LX08 | Include P `src/process.rs`, `src/pidns.rs`, O `src/pin.rs` and their birth/death/acquisition tests in LX08's selected slice; distinguish observation from control |
| CP03/CP04 insertion/loss ABI input omitted | SB01 then CP01/CP03/CP04 | Include K `crates/kryprobe-abi/src/kcrypto_agg.rs`, `try_fold_vwho`, `identity_present`, `kattrloss_fold` and genuine-zero/full-map tests; compare against actual signatures before porting |
| CP12 successor source is not selected | CP12 after CP06/CP11 | Refresh and pin the accepted shared-ledger successor or document its absence. Execute the stated evaluation and retain an internal/product-local outcome when justified; do not invent a production abstraction to fill the gap |
| Dependency APIs/features and public visibility | SB02, then BP01/LX01 | Checked probe result, exact version/feature/lock, MSRV and primary dependency choice; unavailable or private APIs cannot become implementation assumptions |
| Mapping/supervision pools and helper protocol | LX01/LX04/LX06/LX09 with TT03 | Frozen new ownership algorithm, state transitions, protocol framing/FD transfer, partial-effect and fork tests; identify which donor pieces are ported versus newly composed |
| Consumer build identity | TT01/TT02 before adapters | Defined source/build/features/backend/artifact identity recipe and bounded encoding; a caller-provided digest cannot silently certify another resolved library |
| Actual filesystem/audit recipes | TT03/TT04 before LX07 | Deterministic collision/copy-up/denial recipes, independent trigger evidence and audit sensitivity; no claim from a generic mount or final maps comparison |
| Native consumed version and patch necessity | NX02 before NX03–NX06 | Actual symbols/ABI/compiler/build closure, existing fixed behavior and minimal required overlay; no second bridge or invented API |
| Upstream target license option | SB02/BP01/TC01 before selected BPF build | Compatible actual target inputs and notice bundle, plus the explicit dependency-policy choice in D03; host-only decisions proceed independently |

The expert/controller owns these decisions. The implementer may run the specified probe/evaluation and return evidence; it cannot choose a different architecture or weaken the contract when a probe fails. Every requested API improvement records old/new behavior, reason, affected consumers and the tests preventing a regression.

## First dependency/workspace packet

**Owning task:** SB02, after accepted SB01. **Allowed paths:** root `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, task-specific `.gitignore` entries, `tools/build/`, `tests/package-policy/` and `docs/dependencies.md`. The integration owner serializes root manifest changes; no donor dependency edits.

- [ ] Probe exact installed host compilers 1.88.0 and selected current1.98.1 in isolated output roots. Their presence is observed; actual dependency builds remain NOT_RUN. Do not install or raise the floor automatically.
- [ ] Start candidate trials from cached rustix1.1.5 versus nix0.31.3 for descriptors, object0.39.1 versus goblin0.10.7 for ELF, and optional Aya0.14.0/aya-obj0.3.0 for host adapters. Use the existing defect corpus to select one primary implementation. These are trial pins, not already qualified or compulsory dependencies.
- [ ] Declare procfs0.18.0 and pinned btf-rs as explicit comparator inputs. Their missing cached source is an availability result, not an API failure or permission to write another parser. Fetching a deliberately selected dependency into owned ScopeBase scratch, if needed, is separate from forbidden implicit donor fetching.
- [ ] Compile the exact descriptor/offset/ELF/BTF APIs and run positive/refusal contracts. Preserve optional JSON and std-only capture builds. Record target-code versus host-tool dependencies for the BPF license review.
- [ ] Create workspace configuration without fake behavior exports. An empty workspace metadata result is allowed as configuration evidence only. Generate lockfiles using Cargo for actual existing members/probes; no invented passing library build.
- [ ] Exercise external minimal/default/supported-union clients with independent lockfiles, explicit doctests, package allowlists and the hostile sibling-path/BPF-build-script controls in the original SB02 task.
- [ ] Produce `docs/dependencies.md` with choice, reason, exact feature/API probes, remaining contract gap, license branch and removal/revisit criterion. Request an expert decision for a failed required probe; do not make the executor invent a replacement.

**Done:** the selected dependency/feature/toolchain inputs are real and independent; component behavior and BPF runtime support remain separately open.

## Required BPF admission additions

**Owning tasks:** BP01/BP03, TC03/TC06/TC07, TT01/TT02/TT05, NX02. Use existing requirement/case families; `H33.license-admission` below is a **planned subcase**, not a new historical donor test or an implemented runner.

- [ ] BP01 records the source-license/target closure and accepted runtime declaration independently. TC03 inventories the **final** object's license bytes, helper/kfunc requirements and selected program type after linking/transformation. Missing/malformed/wrong declaration has its own error, separate from missing source notices.
- [ ] BP03/TT05 select a fixture with an independently verified GPL-only helper and supported program type for each selected kernel cell. The matching GPL fixture must load and execute a nonempty owned workload with independently expected output. The otherwise equivalent non-GPL control must be rejected for the intended licensing reason; it does not run. Keep source, instruction, BTF, map and attachment differences fixed except the declared mutation.
- [ ] TT02 refuses to count an EPERM/EACCES, unsupported helper or malformed program as the license control. A failed/missing positive, absent privilege or unavailable required cell leaves the capability incomplete. Preserve bounded verifier output and actual operation evidence.
- [ ] Add same-errno controls for permission denial, old-verifier initialized-padding rejection and license refusal. Ambiguous causes remain Unknown, with raw errno/stage retained; they cannot select an implicit fallback or split.
- [ ] TC06 keeps `SelectionTransport` initialized padding and the existing private-stack/argument/linkage rules. TC07 runs exact final bytes in required old/current/affected cells. A current-kernel pass cannot retire old-kernel protection.
- [ ] Preserve BPF-versus-testkit ProfileId domains. A catalog ID must satisfy the catalog grammar; a BPF-valid slash/long ID does not become a testkit ID by truncation or sanitization. Test explicit failed conversion and valid known-profile twins.
- [ ] Deliver the license/object checks and applicable owned live route through the same package/operator conformance path. Ordinary host-only tests never start privileged probes.

**Done:** actual target source inputs and kernel admission have independent evidence; license refusal cannot be confused with privilege or verifier shape, and no new blanket kernel minimum or license is inferred.

This is a multi-task obligation, not a new all-or-nothing prerequisite. SB01/SB02 own source/option records; BP03 owns pure cause logic and case registration; TC03 owns bounded final-object checks; TT01/TT02 own selection/verdict controls; TC07/BP11 use TT05 for the later actual runtime checks; TC08/TT07/RL02 deliver the notices/installed closure. Native input roles are NX02's part. Unrelated host-only packages do not acquire a kernel test dependency, and no existing DAG edge is reversed.

## Task origins and decision routes

The table below covers all existing task IDs. It supplements each detailed task's exact Interfaces/Files/tests; it does not replace them or claim every future packet is ready. `PORT` preserves existing code and tests; `ADAPT` wraps a selected existing dependency; `NEW` is specified missing infrastructure/composition; `EVAL` is a gated decision; `QUAL` executes qualification. A combination must be split by mechanism in the actual packet. `LATER` tasks are outside current M0–M6 work.

| Task / detailed contract | Origin | Input the packet must freeze | Preservation / decision gate |
|---|---|---|---|
| [SB01](2026-10-17-scopebase.md#sb01-source-intake-licensing-and-contract-ledger) | NEW/PORT | Pinned observations, author grants, family/regression references | R1/R2 controls and task-specific source slices; D01/D03/D13 |
| [SB02](2026-10-17-scopebase.md#sb02-workspace-dependency-selection-and-independent-builds) | NEW/ADAPT | Exact dependency API/feature/MSRV and license options | Probe evidence then expert selection; no automatic replacement; D03/D11 |
| [SB03](2026-10-17-scopebase.md#sb03-versioning-support-and-documentation-contracts) | NEW | Version/effect/compatibility and issue-record formats | Freeze public categories and documentation checks; D07/D09/D14 |
| [LX01](2026-10-17-scopebase-linux.md#lx01-foundation-choices-and-selected-donor-contract-register) | ADAPT | Descriptor/proc/path choices and selected donor symbols | Crate boundary only; no placeholder HeldFile; D01/D11 |
| [LX02](2026-10-17-scopebase-linux.md#lx02-held-regular-file-authority-errors-and-encapsulation) | PORT | P identity/discovery and O pin regular-file acquisition | Retained inode, FIFO/path fallback/adoption/exec tests; D01/D07 |
| [LX03](2026-10-17-scopebase-linux.md#lx03-positional-full-reads-and-explicit-memorywork-accounting) | PORT | P/O positional bounded-read implementations and tests | Cursor aliases, EOF/EINTR/bounds/races and bytes/hash parity; D01/D08 |
| [LX04](2026-10-17-scopebase-linux.md#lx04-cooperative-deadlinecancellation-and-structured-effect-handling) | PORT/NEW | Donor cancellation checks plus explicit new control seam | Freeze deadline/effect/accounting behavior before reads; D08/D12 |
| [LX05](2026-10-17-scopebase-linux.md#lx05-strict-bounded-mapsmount-observations) | PORT/ADAPT | P maps/mount parsing and strict byte/identity rules | Raw paths, malformed/range/ceiling controls; D07/D11 |
| [LX06](2026-10-17-scopebase-linux.md#lx06-mapping-relations-explicit-calibration-and-retained-custody) | PORT/NEW | P mapping-domain fixes plus specified persistent pool | Expert freezes new pool/retained-proof transitions; D07/D08 |
| [LX07](2026-10-17-scopebase-linux.md#lx07-real-filesystem-namespace-and-effect-qualification-adapters) | QUAL | TT real collision/copy-up/namespace/audit recipes | Actual trigger, both policies and cleanup; D07/D09 |
| [LX08](2026-10-17-scopebase-linux.md#lx08-observation-authority-task-birth-and-observer-epochs) | PORT | P process/pidns and O pin, including omitted routing | Birth/exec/death acquisition and observer epoch tests; D01/D07 |
| [LX09](2026-10-17-scopebase-linux.md#lx09-optional-stopped-child-supervision-and-explicit-unresolved-ownership) | PORT/NEW | Owned child donor pieces plus frozen supervisor/helper | FD transfer, late worker, SIGCONT effect and unresolved custody; D08 |
| [LX10](2026-10-17-scopebase-linux.md#lx10-explicit-bounded-descriptor-relative-discovery) | PORT/ADAPT | Donor bounded traversal plus selected descriptor library | Each traversal budget and foreign/symlink refusal; D08/D11 |
| [LX11](2026-10-17-scopebase-linux.md#lx11-two-independently-wired-real-clients-and-developer-conformance) | NEW/QUAL | Actual Linux public API and consumer-linked testkit | Two differently wired clients and distributed checks; D09/D14 |
| [LX12](2026-10-17-scopebase-linux.md#lx12-packageprofile-acceptance-and-affected-check-routing) | QUAL | Selected Linux profile closure and real current results | File pilot cannot close mapped-image profile; D09/D14 |
| [LX13](2026-10-17-scopebase-linux.md#lx13-product-migration-compatibility-packet-without-donor-edits) | NEW | Accepted mapping/file APIs and original product contract | Compatibility packet only; no donor migration; D02/D14 |
| [BP01](2026-10-17-scopebase-bpf-toolchain.md#bp01-freeze-bpf-boundaries-and-issue-provenance) | NEW/PORT | Actual dependency choice and donor invariant/role map | Host/BPF/shared license and kernel rules frozen; D01/D03/D05 |
| [BP02](2026-10-17-scopebase-bpf-toolchain.md#bp02-checked-possible-cpu-map-geometry-and-abi-safe-lookup) | PORT/ADAPT | K mapops/WHO stride and native map-kind corpus | Possible-mask authority and every consumer; D07/D08 |
| [BP03](2026-10-17-scopebase-bpf-toolchain.md#bp03-capability-and-hazard-evidence-with-non-vacuous-probes) | PORT/ADAPT | Functional donor canaries and cause classification | Active/excluded positives, H33 intended refusal, checked IDs; D04/D06 |
| [BP04](2026-10-17-scopebase-bpf-toolchain.md#bp04-finite-attachment-planner-and-caller-error-policy) | PORT | P bpf-multi and O balanced split decision model | Finite disjoint 2n-1 plan; no effectful placeholder; D01/D08 |
| [BP05](2026-10-17-scopebase-bpf-toolchain.md#bp05-held-file-attachment-custody-and-explicit-retirement) | PORT/NEW | P retirement custody plus specified persistent pool | Expert-frozen pool; original HeldFile through partial effects; D07/D08 |
| [BP06](2026-10-17-scopebase-bpf-toolchain.md#bp06-ring-frame-arithmetic-bounded-reader-and-copied-staging) | PORT/ADAPT | Aya boundary/wrap repair and native copied staging | BUSY/discard/fixed-tail/mutation/short-retry controls; D01/D08 |
| [BP07](2026-10-17-scopebase-bpf-toolchain.md#bp07-programcpu-writer-ownership-insertion-provenance-and-full-map-diagnostics) | PORT | K writer partition/insertion/full-map diagnostics | Reentry, genuine zero, migration and independent loss; D01/D10 |
| [BP08](2026-10-17-scopebase-bpf-toolchain.md#bp08-optional-producer-taskexec-identity-protocol) | PORT/NEW | P task/exec fixes plus specified neutral producer schema | Actual hooks, old/current shapes and ownership; D05/D07 |
| [BP09](2026-10-17-scopebase-bpf-toolchain.md#bp09-bounded-domain-aware-btf-parser-adaptation) | ADAPT/PORT | Bounded K graph queries plus selected public parser API | No assumed private Aya API or new full parser; D07/D11 |
| [BP10](2026-10-17-scopebase-bpf-toolchain.md#bp10-narrow-existing-loader-adapters-and-native-contract-vectors) | ADAPT | Actual selected Aya/libbpf APIs and parent-owner contract | Exact held-file/link/ring semantics; no new loader; D02/D08 |
| [BP11](2026-10-17-scopebase-bpf-toolchain.md#bp11-bpf-package-and-installed-downstream-conformance) | QUAL | Actual package/backend/feature/profile artifacts | Independent clients, H33 closure and installed route; D09/D14 |
| [TC01](2026-10-17-scopebase-bpf-toolchain.md#tc01-recover-issue-fixtures-toolchain-pins-and-patch-register) | PORT | W compiler reports/patches and final producer closure | Each patch preimage/removal test and input license role; D03/D05 |
| [TC02](2026-10-17-scopebase-bpf-toolchain.md#tc02-explicit-compiler-closure-and-bounded-nested-build-helper) | PORT/NEW | Donor helper behavior plus frozen compile-job custody | No immediate-child wrapper for whole mixed build; D08/D12 |
| [TC03](2026-10-17-scopebase-bpf-toolchain.md#tc03-final-object-inventory-and-explicit-isa-profile-admission) | PORT/ADAPT | Final-object decoder and explicit instruction profile | ISA/helper/BTF/license separate and bounded; D04/D05 |
| [TC04](2026-10-17-scopebase-bpf-toolchain.md#tc04-atomic-rmw-oldnew-value-and-atomicload-selector-regressions) | PORT | W atomic old/new and AtomicLoad reproducers | Independent arithmetic/selector oracles on selected backend; D05 |
| [TC05](2026-10-17-scopebase-bpf-toolchain.md#tc05-elfbtf-relocation-call-graph-and-metadata-preservation) | PORT | K/O graph/pruning and P relocation/BTF fixes | Sentinel maps, exact roots/callback/type identity; D01/D05 |
| [TC06](2026-10-17-scopebase-bpf-toolchain.md#tc06-restricted-dead-code-repair-and-verifier-sensitive-rule-manifests) | PORT | P padding/arguments/private stack and graph-safe rules | Path-scoped old/new verifier mutation controls; D05/D06 |
| [TC07](2026-10-17-scopebase-bpf-toolchain.md#tc07-exact-artifact-kernel-behavior-and-concurrent-compiler-claims) | QUAL/NEW | Frozen owned-guest build scope and exact objects | Independent semantic activity, H33 and descendant retirement; D04/D08 |
| [TC08](2026-10-17-scopebase-bpf-toolchain.md#tc08-distribute-compilerobject-suite-and-expire-only-proven-workarounds) | QUAL | Pinned reproducer corpus, notices and installed closure | Actual consumer fix inclusion before workaround removal; D05/D09 |
| [CP01](2026-10-17-scopebase-capture.md#task-cp01-package-donor-custody-and-issue-contracts) | NEW/PORT | Capture source slices and explicit primitive boundaries | No fresh rewrite to evade historical GPL; D01/D03/D10 |
| [CP02](2026-10-17-scopebase-capture.md#task-cp02-domain-quantity-partition-and-interval-foundations) | PORT/NEW | Donor quantities/domains and specified Rust wrappers | Units/epoch/interval exact contracts; no product reducer; D10 |
| [CP03](2026-10-17-scopebase-capture.md#task-cp03-counter-protocol-loss-units-and-diagnostic-signals) | PORT | K kcrypto_agg kattrloss_fold plus donor loss protocols | Corrected ABI routing, units/reset/wrap/missingness; D01/D10 |
| [CP04](2026-10-17-scopebase-capture.md#task-cp04-insertion-frozen-provenance-and-survives-full-map-model) | PORT | K try_fold_vwho/identity_present plus insertion tests | Genuine zero, winning inserter and full-map diagnostics; D01/D10 |
| [CP05](2026-10-17-scopebase-capture.md#task-cp05-explicit-generations-and-bounded-lifecycle-histories) | PORT | K/M generations/reuse and bounded lifecycle histories | Late old completion cannot retire new generation; D10 |
| [CP06](2026-10-17-scopebase-capture.md#task-cp06-scoped-immutable-views-required-feeds-and-corrections) | PORT | M/O partial-view/correction and feed requirements | Snapshots do not mutate persistent facts; D10 |
| [CP07](2026-10-17-scopebase-capture.md#task-cp07-physical-site-alternatives-and-checked-count-bounds) | PORT | O physical-site alternatives/conservation | Independent count bounds, no shared-site double count; D10 |
| [CP08](2026-10-17-scopebase-capture.md#task-cp08-scoped-interval-ordering-proof) | PORT | M/O interval and ordering-proof behavior | Half-open/tied/reordered bounds with independent oracle; D10 |
| [CP09](2026-10-17-scopebase-capture.md#task-cp09-closure-evidence-profiles-and-late-evidence-countermodels) | PORT/NEW | K/O/M explicit closure facts and countermodels | No model promoted into unimplemented live protocol; D10 |
| [CP10](2026-10-17-scopebase-capture.md#task-cp10-canonical-neutral-validation-and-strict-replay-vectors) | PORT/NEW | K/M strict replay plus specified canonical neutral seam | Duplicate/unknown/u64/constructor parity and bounded decode; D10 |
| [CP11](2026-10-17-scopebase-capture.md#task-cp11-independent-real-consumers-examples-and-correction-holders) | NEW/QUAL | Actual primitives and two independent reducer clients | Real correction holders and independent expectations; D09 |
| [CP12](2026-10-17-scopebase-capture.md#task-cp12-cross-stage-reservation-evaluation-with-a-gated-internal-pilot) | EVAL | Accepted successor source after CP06/CP11, or absence | Select evidence; internal/product-local outcome permitted; D10/D12 |
| [CP13](2026-10-17-scopebase-capture.md#task-cp13-packaged-conformance-installed-operator-route-and-release-gate) | QUAL | Actual capture package/schema/conformance artifacts | Installed source-free route and binding; D09/D14 |
| [TT01](2026-10-17-scopebase-testing.md#tt01-versioned-caseprofile-and-traceability-registry) | NEW/PORT | H01-H33/UC/G and task-to-source obligations | Exact immutable required-case/profile selection; D09 |
| [TT02](2026-10-17-scopebase-testing.md#tt02-subject-binding-independent-oracles-and-verdict-engine) | NEW | Frozen build identity/encoding and independent verdict API | Wrong subject, missing trigger/cause/cleanup cannot pass; D06/D09 |
| [TT03](2026-10-17-scopebase-testing.md#tt03-owned-linux-fixture-worker-and-independent-raw-truth) | NEW/PORT | Frozen worker framing/FD protocol and independent truth | Actual owned fixtures; no production resolver oracle; D07/D09 |
| [TT04](2026-10-17-scopebase-testing.md#tt04-real-filesystem-cells-and-mapping-policy-audit) | NEW/QUAL | Exact FS/overlay/collision/no-mmap audit recipes | Verify active trigger/sensitivity and resource custody; D07/D09 |
| [TT05](2026-10-17-scopebase-testing.md#tt05-isolated-object-and-live-kernel-orchestration) | NEW/QUAL | Owned guest/image/config and final artifact transport | True old/current kernel cells and H33 controls; D04/D05 |
| [TT06](2026-10-17-scopebase-testing.md#tt06-fault-schedules-propertymodelfuzz-and-sanitizer-campaigns) | NEW/PORT | Original countermodels and frozen campaign budgets | Semantic mutants and bounded model/fuzz/sanitizer scope; D09 |
| [TT07](2026-10-17-scopebase-testing.md#tt07-installed-operator-command-and-downstream-package-delivery) | NEW/QUAL | Actual package/consumer/installed operator formats | Offline readonly-prefix, exact subject and notice closure; D09 |
| [TT08](2026-10-17-scopebase-testing.md#tt08-causal-ci-selection-and-safe-parallel-scheduling) | NEW | Causal case/source/fixture/profile dependency map | No self-authored green from missing required jobs; D09/D14 |
| [TT09](2026-10-17-scopebase-testing.md#tt09-resource-performance-and-concurrent-consumer-qualification) | QUAL | Frozen per-domain resource/workload baselines | Concurrent clients and outstanding owner bounds; D08/D09 |
| [TT10](2026-10-17-scopebase-testing.md#tt10-qualified-support-matrix-and-test-delivery-completion) | NEW/QUAL | Independent completion checker over actual results | Implement checker separately from certifying a profile; D09/D14 |
| [SDK01](2026-10-17-scopebase-sdk-native.md#sdk01-explicit-profile-capability-and-effects-admission) | NEW | Accepted component support/effect/error profiles | No hidden probe, fallback or universal shutdown; D02/D10 |
| [SDK02](2026-10-17-scopebase-sdk-native.md#sdk02-bounded-context-diagnostics-and-component-bindings) | NEW | Frozen component interfaces and bounded context | Composition only; no duplicate lifetime engine; D02/D08 |
| [SDK03](2026-10-17-scopebase-sdk-native.md#sdk03-capture-metadata-integration-and-consumer-linked-conformance) | ADAPT | Actual capture and consumer-linked testkit contracts | Metadata cannot mint authority or certify another build; D07/D09 |
| [SDK04](2026-10-17-scopebase-sdk-native.md#sdk04-independently-useful-owned-workload-host-observer) | NEW | Owned host observation recipe over real components | Useful application, startup/output/stop failures; D02/D08 |
| [SDK05](2026-10-17-scopebase-sdk-native.md#sdk05-standalone-starter-and-host-package-submilestone) | NEW/QUAL | Actual host app and standalone distributed starter | Usable host milestone only, no live claim; D09/D14 |
| [SDK06](2026-10-17-scopebase-sdk-native.md#sdk06-actual-live-observation-recipe-over-existing-aya) | NEW/ADAPT | Selected real Aya backend and exact BPF object | Independent live workload and honest cleanup; D04/D05 |
| [SDK07](2026-10-17-scopebase-sdk-native.md#sdk07-package-sdk-and-starter-with-both-reference-routes) | QUAL | Host/live SDK packages and starter closure | Actual independent distributions/features; D09 |
| [SDK08](2026-10-17-scopebase-sdk-native.md#sdk08-fault-concurrency-and-causal-ci-qualification) | QUAL | SDK concrete faults/concurrency/causal CI | No mocked-only live acceptance or hidden fallback; D09/D10 |
| [SDK09](2026-10-17-scopebase-sdk-native.md#sdk09-sdk-acceptance-and-mg-handoff) | QUAL | All selected SDK/component profile closure | Host plus actual live app; migration remains later; D14 |
| [NX01](2026-10-17-scopebase-sdk-native.md#nx01-independent-neutral-corpus-and-semantic-bindings) | PORT/NEW | Independent donor binary/text neutral vectors | Actual expected bytes, no serializer-only oracle; D09/D10 |
| [NX02](2026-10-17-scopebase-sdk-native.md#nx02-exact-libbpf-mojo-and-mojobpf-integration-audit) | ADAPT | Actual consumed libbpf-mojo/MojoBPF symbols/closure | Freeze version/patch need, role/options and native limits; D03/D11 |
| [NX03](2026-10-17-scopebase-sdk-native.md#nx03-native-copied-record-retention-and-retry-contribution) | PORT/ADAPT | Existing bridge staging/retention functions | Minimal overlay or prove already fixed; no new bridge; D01/D08 |
| [NX04](2026-10-17-scopebase-sdk-native.md#nx04-transactional-native-configuration-and-stale-views) | PORT/ADAPT | Existing bridge configure/generation behavior | Rollback/poisoned owner and stale-view tests; D08 |
| [NX05](2026-10-17-scopebase-sdk-native.md#nx05-exact-native-map-geometry-and-live-map-control) | PORT/ADAPT | Existing map-kind/stride APIs and live map metadata | Refuse before arithmetic/copy, actual map controls; D07/D08 |
| [NX06](2026-10-17-scopebase-sdk-native.md#nx06-existing-bridge-lifetime-close-release-and-standard-objects) | PORT/ADAPT | Existing parent/borrow/close and object APIs | Actual C/Mojo lifetime and standard-object tests; D08/D11 |
| [NX07](2026-10-17-scopebase-sdk-native.md#nx07-narrow-stateless-scopebase-capture-abi) | NEW | Frozen canonical capture validator and narrow ABI | Stateless bounded ABI, explicit layouts/errors; D02/D10 |
| [NX08](2026-10-17-scopebase-sdk-native.md#nx08-independently-useful-c-and-mojo-validation-applications) | NEW | Actual ABI plus independent C and Mojo clients | Useful programs and independent vectors; D09 |
| [NX09](2026-10-17-scopebase-sdk-native.md#nx09-sanitizers-fuzzing-and-installed-offline-bundles) | QUAL | Actual native libraries/compiler/install closure | Sanitizers/fuzz/offline clients on exact bytes; D09 |
| [NX10](2026-10-17-scopebase-sdk-native.md#nx10-native-acceptance-contribution-custody-and-mg-handoff) | QUAL | Selected native/ELF profiles and contribution custody | Actual consumed-version proof, no product migration; D14 |
| [RL01](2026-10-17-scopebase.md#rl01-cross-package-api-and-adversarial-integration-review) | QUAL | Actual cross-package APIs/authority/feature boundaries | Adversarial integration tests, no broad redesign; D07/D08 |
| [RL02](2026-10-17-scopebase.md#rl02-package-archives-offline-artifacts-and-reproducible-inputs) | NEW/QUAL | Exact archives/bundles/objects/licenses and allowlists | Installed closure, notices and reproducibility scope; D03/D09 |
| [RL03](2026-10-17-scopebase.md#rl03-candidate-acceptance-and-release-preparation) | QUAL | Frozen concrete candidate/required profiles/results | Honest support matrix; publication remains separate; D14 |
| [RL04](2026-10-17-scopebase.md#rl04-new-kernels-architectures-and-long-term-regression-maintenance) | EVAL/QUAL | New target/kernel/toolchain profile amendment | Affected reproducer/removal gates per extension; D05/D14 |
| [MG01](2026-10-17-scopebase.md#mg01-p11scope-migration) | LATER | Fresh selected p11scope tip and qualified ScopeBase | Separate application tests/rollback/duplicate retirement |
| [MG02](2026-10-17-scopebase.md#mg02-osslscope-migration) | LATER | Fresh OSSLscope worktree and qualified package | Preserve provider/privacy/late-close policy |
| [MG03](2026-10-17-scopebase.md#mg03-kryprobe-migration) | LATER | Fresh KryProbe product/fix worktrees and package | Preserve insertion provenance and batch/live separation |
| [MG04](2026-10-17-scopebase.md#mg04-memveil-and-consumed-libbpf-mojo-adoption) | LATER | Actual MemVeil consumed bridge/compiler closure | No forced Rust rewrite; preserve domain reducers |
| [MG05](2026-10-17-scopebase.md#mg05-mojobpf-object-contract-integration) | LATER | Fresh selected MojoBPF branch/WIP/final objects | Object-contract adoption; no second runtime/loader |

## Safe parallel schedule

1. Finish plan/decision repair and record remaining provisional choices. Repair SB01's specific findings and policy representation in its existing isolated lane; independently review that focused change. No new coordinator framework.
2. SB02 freezes actual dependency/MSRV/feature inputs; SB03 freezes compatibility/evidence formats. Component foundation packets may be prepared read-only alongside this, but cannot assume unresolved outputs.
3. After SB02, disjoint Linux, capture and testkit lanes can proceed. Within each lane, freeze shared APIs first and serialize exports/manifests. BPF/toolchain foundation work follows SB03 and the selected target dependency decisions. New ownership/protocol design stays with the expert until frozen; ordinary executors receive bounded slices.
4. Serialize one heavy Cargo/native build and each owned privileged guest/resource. Parallel pure work needs separate outputs. Containers sharing the host kernel do not qualify a different kernel; each required old/current/affected cell has its real admitted image/config.
5. Finish each useful port with its relevant regressions and documentation. Stop at a meaningful review boundary; do not accumulate a giant unreviewed rewrite. SDK/native consumers start only after their actual inputs exist, with early independent corpus work allowed by the existing DAG.
6. Use causal CI selection and local/guest tests from TT08. Required missing remote service, fixture or kernel evidence stays open. The current repository has no configured remote; preparing a workflow does not run external CI or authorize publication.

## Plan completion and handoff

Completed planning checks are recorded in the [amendment verification](../reviews/2026-10-18-scopebase-plan-hardening-verification.md). The implementation checkboxes above remain open.

- [x] Check all existing task IDs, dependencies, source obligations, public signatures and decision links against the six original plans. Attach newly found necessary work to its owner and exit criterion; preserve stable IDs.
- [x] Self-review for executor choices left implicit, source/license/kernel contradictions, unsupported placeholder exports and tests without intended trigger/oracle/control.
- [x] Obtain independent kernel/BPF and cross-plan review of the actual amended bytes. Fix material plan defects; keep speculative extensions outside the ready increments.
- [x] Run `python3 tools/check_planning_docs.py` and `git diff --check`; inspect untracked new documents as well. These checks establish structural consistency, not semantic or runtime correctness.
- [x] Save the current root handoff with exact candidate/worktree custody, accepted decisions, missing decisions and the next bounded task. Current request ends with reviewable improved plans; do not resume implementation in the same breath merely because this checklist is green.
