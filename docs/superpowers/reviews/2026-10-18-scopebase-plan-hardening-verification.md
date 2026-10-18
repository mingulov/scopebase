# ScopeBase plan-hardening verification

Date: 2026-10-18. Status: **reviewed planning amendment**, with no remaining material finding in the reviewed scope. The [repair plan](../plans/2026-10-18-scopebase-plan-repair.md), [decision register](../specs/2026-10-18-scopebase-decisions.md) and [executor contract](../specs/2026-10-18-scopebase-executor-contract.md) amend the earlier plan. All 86 product tasks remain open; this record accepts no library implementation or runtime capability.

## Reviewed bytes and findings

The base is the accepted development-setup main commit `bbcad0d9b52d8cb607ca7d1d6e120823e7c169b9`. Planning work used `.worktrees/plan-hardening`, branch `docs/executor-plan-hardening`; source/product candidates remain in their separate preserved worktrees.

- A Sol inventory covered all 86 tasks and identified coarse source slices, omitted process/pin and KryProbe insertion/loss inputs, unresolved predecessor designs and CP12's missing successor selection.
- An independent Astra kernel/BPF analysis covered actual host/target/shared licensing roles, source grants versus runtime strings, old-verifier EACCES classification, exact final-object/kernel checks and preserved compiler workarounds.
- Astra's full static review of `9280fcb30483ccc2d7ba476334762a8dc4728268` found two material plan defects: the next SB01 packet left its authorization/adoption schema undefined, and current handoff instructions retained a withdrawn policy and stale active-worker claims.
- Focused correction `01d05c69e62abb3cf8f4672415848408607c8a64` freezes schema2.0.0, reference/null/ownership/fragment/role rules, finite supported options, unresolved-state admission, migration and sensitive fixture pairs. It also corrects the single current handoff. Astra's focused follow-up verdict is **PASS: both findings resolved**, with no additional blocker in that changed range.

The initial immutable review package SHA-256 is `0a4567d28927a92c1cf62a79a44b74f0f8b837f70f882074a0c8ba9f24ce40de`; the correction package SHA-256 is `9aee2d602b953b014efa3203a8130a7cc9f6421146082b6d64e823ef80738667`. Private packages, bindings and reviewer reports remain in the plan worktree's `.scopebase/final-plan-review/`; the BPF analysis and task inventory remain in its `.scopebase/`. Reviewers independently checked package hashes and candidate identity. Later acceptance bookkeeping updates navigation/status, this record and planning checkboxes; it changes no reviewed adoption rule or product contract.

## Preservation and changed obligations

The original 119 requirement records, 178 source-obligation mappings, H01–H32 case objects, all 86 task dependencies/topological order and all 19 profile definitions remain unchanged as JSON values. All 86 tasks have origin/decision routes; future task packets are not claimed ready before their actual inputs exist.

TC-R10/H33 append the explicit source/build/kernel licensing obligation. The current totals are **120 requirements, 86 tasks, 179 source mappings and 33 H families**. H33 is a new ScopeBase planning obligation, not an invented donor failure. The catalog remains PLANNED/NOT_IMPLEMENTED/NOT_RUN and is not runnable.

The user's working choice is **provisional Apache-2.0 for owned userspace ScopeBase code**, GPL-2.0-only for BPF programs and GPL-3.0-or-later for applications, with an explicit compatible dual grant for genuinely shared owned source. No project MIT alternative is selected. The actual Aya target dependency option and scope of the user's third-party MIT preference remain open before the affected payload; unrelated host work need not wait. Historical source observations and actual upstream terms remain separate from the owner's destination grant.

## Verification and limits

The controller ran these affected checks on the corrected candidate:

- `python3 tools/check_planning_docs.py`: PASS; stable IDs, links, tables, source/requirement coverage, dependency/profile closure and planned/unrun guards, including 120 requirements, 86 tasks, 179 mappings and 33 families.
- `python3 -m unittest discover -s tests/orchestration -p test_planning_discovery.py -v`: one test PASS in0.797s.
- Parsed both new normative JSON examples successfully; `git diff --check` and staged whitespace checks passed.

The same affected checks also passed on the final acceptance bookkeeping: 51 Markdown files, five JSON files, one discovery test in 0.700s and no whitespace errors. The unchanged 70-test setup suite is historical setup evidence and was not repeated for this documentation amendment. The planning checker changed only its two explicit expected requirement/family counts; no product validator or new runtime guard was implemented here.

Static reviews and documentation checks do not validate the proposed schema implementation, source ownership claims, actual notice delivery, compiler outputs, privileged BPF/filesystem behavior or installed downstream consumers. This pass ran no donor operation, dependency build, privileged test, migration or publication. The original SB01 candidate remains unaccepted, including its known lazy-fetch and nested-reference defects.

The next implementation increment is the existing candidate's [bounded SB01 repair](../plans/2026-10-18-scopebase-plan-repair.md#repair-intake-validation), after the controller integrates the accepted plan inputs and pins the actual repair base. Future decisions and required tests remain assigned in [TODO](../../../TODO.md). The current handoff preserves exact candidate/evidence custody and the reviewable end of this plan-repair pass.
