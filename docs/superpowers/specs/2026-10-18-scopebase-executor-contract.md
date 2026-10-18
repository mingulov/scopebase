# ScopeBase executor contract

Date: 2026-10-18. This is a normative amendment to the [project specification](2026-10-17-scopebase-design.md) and all six product plans. The [decision register](2026-10-18-scopebase-decisions.md) supplies the what and why; the [repair plan](../plans/2026-10-18-scopebase-plan-repair.md) supplies the next concrete work. It introduces no new runtime or orchestration service.

## Purpose

An executor should implement a reviewed port without reconstructing the architecture or rediscovering historical defects. The controller must give the executor enough exact information to choose one reasonable implementation. The absence of information is a missing decision, not a license to guess.

The plan repair is accepted and the active M0–M6 goal has resumed with the bounded SB01 repair, now accepted in its [foundation record](../../reviews/2026-10-18-sb01-foundation.md). A planning check alone does not accept an implementation. Existing product requirements and task IDs stay stable. All source workspaces, WIP and evidence remain in custody.

## Task packet required before execution

Each task brief must contain the following table filled with concrete values or the exact accepted predecessor artifact. A broad port-group name, a reference to all research, or “write appropriate tests” is not a filled field.

| Field | Required content |
|---|---|
| Purpose and scope | Task ID, smallest useful increment, included behaviors, explicit non-goals and package/profile claim |
| Decisions | Applicable D01–D14 decisions, selected alternatives and reasons; exact unresolved decisions and their owner |
| Starting bytes | Product base SHA; completed private donor snapshot and checkout mapping; each donor/upstream full SHA, captured worktree/WIP hash, selected path, function/type and relevant original regression |
| Origin per mechanism | PORT, ADAPT, NEW, EVALUATE or QUALIFY; NEW has a concrete reason the mechanism is absent and the reviewed replacement design |
| Inputs | Accepted prerequisite artifact/version/hash, exact consumed signatures, domain conversions and supported feature/backend/toolchain/profile inputs |
| Outputs | Exact owned paths and produced signatures/layouts/error categories; no placeholder production export |
| Preservation map | Each original defect/invariant to its destination code, original test, independent oracle, positive twin, bad control and support limit |
| License boundary | Historical source grant, owner authorization, destination terms, third-party option/notices and host/BPF/shared/build-tool artifact role |
| Tests | Exact target/case/assertions, setup/trigger evidence, expected refusal versus support, required tier/cells and intended bad-control failure |
| Effects and bounds | Allowed syscalls/privilege/process/mount/load/attach effects; byte/work/memory/time/resource limits and partial-effect ownership |
| Resources and parallelism | Sole writer, isolated targets/results, shared export/manifest owner, guest/host/build leases and release condition |
| Acceptance | Exact commands and expected semantic results, independent reviewer scope, completeness level, open gates and next consumer |

`PACKET_READY` is an expert/controller statement that all implementation choices above are resolved for the selected increment. It is not a test result or runtime authority. A predecessor reference is usable only after the actual artifact exists and satisfies its contract. Future task packets are not ready merely because their task is listed in the DAG.

The existing job helper binds files and prepares a worktree; it does **not** enforce this new packet completeness contract. Until SB01/EX integration adds and tests that admission check, the controller must check the table explicitly. Do not call the unimplemented guard a passing safety check.

## Preservation sequence

1. Read the selected original mechanism and applicable donor variants from the completed private frozen copies. Verify selected copied bytes and retain captured branch/WIP differences. Resolve the task-specific source selection rather than assuming a coarse file group is sufficient. The user's 2026-10-18 direction supersedes earlier live-refresh wording: do not repeatedly inspect moving donor heads or wait for donor cleanliness. A later capture/update needs a named technical reason; ongoing development alone is not one.
2. Name the defect's trigger and invariant before writing implementation. Map cross-donor differences: stronger behavior to preserve, deliberate policy differences to keep local, and unsupported behavior to refuse.
3. Port the original regression and expected behavior. Add an independent oracle and a plausible wrong implementation where the original test is insensitive. Do not replace all original cases with one representative example.
4. Establish the test's sensitivity. A historical fixed donor may already pass its original test; do not damage the donor or demand that it fail. Use an owned wrong implementation/control, or the unimplemented destination, and show the intended assertion fails after valid setup. Restore the valid twin.
5. Port/adapt the mechanism to the frozen API. Maintain a source-to-destination mapping even when a large donor function is split. Retain errno, partial effects, units, identity domains, counter epochs and owners. At the completed candidate, bind the actual selected file IDs/scopes and destination hashes/symbols plus the reviewed preservation map in an immutable [selected-port receipt](../plans/2026-10-18-scopebase-plan-repair.md#selected-port-receipt-contract). Keep the ready intake snapshot as pre-copy admission evidence; do not relabel whole files or rewrite historical receipts.
6. Run the affected checks on destination bytes, then the independently wired actual consumers and required environment cells at their readiness tasks. Donor parity, pure tests, object checks and live qualification have separate records.
7. Review the preservation map, implementation and tests together. Record any intentional deviation and why; an executor cannot self-approve a weakening. For actual PORT/ADAPT/VECTORS_ONLY completion, the controller explicitly validates every expected selected-port receipt against the candidate, confirms scope/regression correspondence independently, and binds receipt digest, destination hashes and the actual reviewed revision in acceptance. Intake-only success does not establish current-copy state; missing receipts delay acceptance bookkeeping, not already authorized implementation. A replacement retains the same task/admission/slice identity, appends a bounded supersedes reference and records changed destination/preservation bindings; changed source/admission starts a separate lineage. Close only the selected increment's real definition of done.

## Forbidden substitutions

- A new implementation chosen only because it is shorter, looks cleaner, or avoids understanding donor code.
- A source SPDX observation used as proof that the author cannot authorize different terms, or an owner grant used to relicense third-party code.
- Apache-only target inputs relabeled GPLv2 at the final object, or a runtime `license` string used as proof of source-license compatibility.
- Current-kernel loading used to remove an old-verifier, instruction, BTF, padding, stack or linker workaround.
- EPERM/EACCES used as a universal BPF failure classification.
- A type name reused across packages without the declared domain conversion; do not unify independently specified identifiers merely because both are called ProfileId.
- Mocked truth, unchanged final maps, total FD counts, quiet output or exit zero substituted for the operation/identity/trigger being tested.
- A no-op/todo/unimplemented public function exported to make an interface test compile. Package-boundary tasks test the boundary only; behavior exports appear with their implementation.
- A missing required environment reclassified as optional after discovery; a skipped positive counted as a supported capability.
- Repeated coordinator work, new job frameworks or broad stress reruns used to postpone an identified product port. Existing helpers are sufficient unless a concrete blocking defect is named.

## Required stop report

Use `NEEDS_DECISION` when source selection, license option, API, error classification, support cell, fallback, cleanup authority or expected outcome is unresolved. The report contains the exact missing field, relevant source observations, viable alternatives, the recommended smallest decision, affected dependent tasks and independent work that remains ready. The controller/expert resolves it and updates the same packet. Do not ask the user to reauthorize already authorized routine implementation; ask only for an actually missing user choice.

Use `BLOCKED_ENVIRONMENT` for unavailable required resources and keep the capability incomplete. Use `FAILED` for a semantic assertion failure. Preserve both instead of shrinking scope or retrying until a green summary appears. These report states do not automatically change the goal tool's status.

## Acceptance of the amended plan

The plan is acceptable when all 86 tasks have an explicit origin/decision route, the next executable task has a concrete packet, critical donor/kernel constraints and source-routing corrections are attached to owning tasks, the provisional license split is consistent, and the existing structural documentation checks pass. This is plan readiness. Code fixes, product tests and required real-kernel qualification remain their own open work.
