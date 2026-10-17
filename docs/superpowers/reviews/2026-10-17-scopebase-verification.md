# ScopeBase specification and plan review

Date: 2026-10-17. Scope: documentation and declarative planning only. No ScopeBase production crate, fixture runner, object build, live-kernel test, product migration or release was performed. Proposed commands in the plans are future implementation instructions.

## Deliverables and coverage

The [master specification](../specs/2026-10-17-scopebase-design.md) and [master plan](../plans/2026-10-17-scopebase.md) link five subsystem specification/plan pairs. Together they define 119 requirements and 86 tasks, including testing, SDK, C/Mojo interoperability, release preparation and later migrations. The [root TODO](../../../TODO.md) is the execution ledger; [traceability](../plans/2026-10-17-scopebase-traceability.json) records dependencies and source coverage.

The 178 source-obligation mappings comprise 81 research TODO entries, 32 H families, 23 G gaps, 14 UC scenarios and 28 overlap rows. G gaps are also in the 81 TODO entries. These are overlapping design obligations, not a count of distinct bugs or implemented tests. Every implementation task remains PLANNED and every source obligation remains OPEN.

## Review and corrections

GPT-6.1-Sol authored/reviewed disjoint Linux, BPF/toolchain, capture and SDK/native pairs. GPT-6-Astra reviewed architecture and cross-package boundaries, then checked the specific corrections. GPT-6-Luna independently checked IDs, source coverage, task links and dependency edges. The root author reviewed the master/testing plans and integrated interfaces and acceptance rules. These reviews concern design; they do not establish implementation safety.

| Review issue | Correction preserved in the plan |
|---|---|
| Safe per-CPU lookup could trust caller-supplied CPU geometry | Internally authenticated live topology is distinct from parsed/model topology; BP02 tests an adversarial safe caller and actual buffer extents |
| Failed cleanup could escape limits when a controller or ticket was dropped | Persistent caller-owned MappingPool, SupervisorPool, RetirementPool and CompilerExecutor retain accounting and unresolved custody; reconstruction/abandonment tests are required |
| Native attachment failure could have an unreported partial effect | Owner-bearing uncertain attachment outcomes and bounded reconciliation keep retained file/link authority and charges |
| Compiler timeout or parent exit could leave descendant writers using outputs | Direct no-descendant sandbox scope and whole-guest build authority are explicit; job/output leases remain unresolved until the entire admitted scope is retired |
| Compiler and guest qualification created circular work ordering | TC02 core/direct execution precedes TC03 inspection, then TT05 guest orchestration and TC07 whole-build integration |
| Generation-local event ordinals collided during interval sweeps | Sweep-unique IDs use an explicit injective mapping; equal-timestamp order and reused local ordinals have independent cases |
| Native errors could drift from canonical Rust validation | Explicit stable codes cover all canonical errors, including conservation mismatch; exhaustive cross-language controls avoid enum ordinals |
| Installed commands, case grammar and profile IDs disagreed | One CLI, exact dotted case IDs, 19 canonical runnable profiles and a distinct compiler BuildScope identifier |
| A green composite SDK/native result could omit required component profiles | Transitive profile/extension closure freezes before discovery and TT10 independently checks every required bound component result |
| BTF runtime linkage had only a prose conditional gate | Versioned extension plus typed `when_extensions` gate; base-only results cannot claim runtime linkage |
| BP11 text made live orchestration mandatory for the host-only profile | TT05/TC07 are selected live-profile gates; the host-only package keeps its independent claim |
| Earlier research treated product migrations as package prerequisites | Current research dependencies and master acceptance now use independent real reference clients; MG retains actual product migration and duplicate-retirement gates |

Astra's final bounded recheck found no remaining defect in the corrected composite closure/conditional-gate contract and verified the 19-profile graph is acyclic. Luna found the BP11 heading inconsistency above; it was corrected. Neither statement is a proof that future implementation has no defects.

## Repeatable document checks

Run `python3 tools/check_planning_docs.py` from the repository root. This existing documentation checker validates Markdown links/anchors, fences, tables and whitespace; JSON parsing; source catalog IDs/status/pins; requirement/task ownership; the root TODO; task and profile dependency graphs; and the SDK/native profile closure. It is distinct from the future `tools/planning/check_traceability.py` and from the unimplemented conformance runner.

The documentation checker passed with no reported errors: 35 Markdown documents, 4 JSON documents, 84 tables, all 119 requirements, 86 task links, 178 source-obligation mappings, 19 canonical profiles and one versioned extension. Both dependency graphs are acyclic and all planned/unrun status guards hold. `git diff --check` supplements this check; the Python checker also reads untracked files. These are structural/documentation results, not executed software acceptance tests.

## Remaining implementation obligations

All 86 execution tasks remain open. Source intake must refresh selected donor branches, worktrees and dirty bytes because the source projects continue to change. Dependencies/MSRV, filesystem fixtures, real kernel and compiler cells, independently built reference clients, native ABI consumers and installed delivery still require actual qualification. No package names are reserved and no artifact is published by this work.

Start implementation with SB01, then follow the registry's prerequisites and root TODO parallelization rules. Preserve the user priorities: reusable Rust mechanisms/tests/docs first, SDK second, selective native interoperability third. Existing-product migrations remain later and separately measured.
