# ScopeBase execution setup implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Prepare the selected native-worker and supplementary Muse-review workflow for the active ScopeBase M0–M6 goal.

**Architecture:** The controller uses the existing product DAG and small local helpers. Native agents implement and review; an explicitly invoked Muse process supplies additional readonly review, with immutable artifacts and no acceptance authority.

**Tech Stack:** Python standard library, Git worktrees, Linux flock, installed Muse/Codex CLIs; no new package dependencies.

**Spec:** [Execution specification](../specs/2026-10-18-scopebase-execution-design.md).

## Global Constraints

- At setup acceptance product requirements/tasks were 119/86 and open; the later TC-R10/H33 amendment raises requirements to 120. Setup remains a separate deliverable and does not qualify the new contract.
- Sol high/xhigh implements; Sol max requires an escalation reason; Astra reviews critical contracts; Luna handles mechanical checks; Muse Spark1.3 max/Contributor on supplies supplementary readonly review.
- One writer per worktree, explicit disjoint paths, one heavy build slot, immutable bases and private fresh evidence.
- No tool installation, global config change, donor mutation, automatic model call, goal creation, merge, push or publication in helper commands.
- Exactly one valid matching terminal plus a valid review report and process exit zero are required for successful Muse execution; no helper claims task acceptance.

## Review Focus

1. Concurrent preparations race on identical/overlapping ownership: EX01 uses a controller lock and real competing-process tests.
2. A zero-exit service omits or contradicts its terminal: EX02 tests absent/malformed/duplicate/failed/mismatched candidate outputs.
3. Child exit 75 is confused with lock contention: EX02 verifies a sentinel is written once and the status is preserved.
4. Local ignored worktrees contaminate documentation discovery: EX03 checks real tracked/untracked/ignored document behavior.
5. A helper result is mistaken for completed library work: EX03 preserves all product checkboxes and records setup-only evidence.

## Ownership and dependency scan

| Task | Files / interfaces | Dependency and conflict check |
|---|---|---|
| EX01 | `tools/scopebase_job.py`, `bin/scopebase-job`, `tests/orchestration/test_jobs.py`; consumes policy/spec | Separate implementation checkout; root owner supplies docs/config. No shared code file with EX02 |
| EX02 | `tools/muse_run.py`, `tools/build_lock.py`, `bin/muse-run.sh`, `bin/scopebase-build`, `tests/orchestration/test_muse.py`, `tests/orchestration/test_lock.py` | Consumes fixed CLI/event/lock contracts. No call to EX01 needed; can proceed in parallel |
| EX03 | `DEVELOPMENT.md`, `handoff.md`, `orchestration/common-rules.md`, `orchestration/templates/`, `orchestration/MUSE-ORCHESTRATION.md`, root README/AGENTS/TODO, documentation checker/test | Owns shared files. Integrates tested EX01/EX02 interfaces; no concurrent manifest/index writers |
| EX04 | independent review, focused fixes, final setup verification record | After integration of EX01–EX03. Exact final bytes and real/fake evidence remain separate |

### EX01: Task preparation and immutable review packages

**Requirements:** ORG-R01–ORG-R03/ORG-R06. **Files:** as table. **Interfaces:** exact `scopebase-job` commands and private job layout in spec.

- [x] Write real temporary-Git tests for valid SB01 preparation/model dispatch, relative/escaping ownership, duplicate jobs, overlap, missing prerequisite, max without reason, readonly roles, stale/dirty review source, both directions of cross-boundary renames, selected-base symlink escapes, all86actual task-heading extraction, full BASE..HEAD packages across fix commits and recorded resource-retired reconciliation. Run `python3 -m unittest discover -s tests/orchestration -p test_jobs.py -v`; observe intended failures before implementation.
- [x] Implement the specified validation, controller lock, fresh worktree/job binding and exact task extraction. No agent launch or automatic task completion.
- [x] Run the tests and valid/invalid real-repository controls; record commands and limits. Commit only the owned helper/bin/test files with report.

### EX02: Readonly Muse wrapper and cooperative resource lock

**Requirements:** ORG-R03–ORG-R05/ORG-R07. **Files:** as table. **Interfaces:** exact positional Muse wrapper and build-lock command in spec.

- [x] Write tests using a controlled executable in place of the external service, real temp Git and real flock subprocesses. Check valid report, raw exit failure, zero-exit failed/missing/duplicate/malformed terminal, wrong/dirty candidate before or during execution, oversized prompt, protected artifacts, paths with spaces, dry-run no invocation, no flag override, child75 exactly once and contended timeout without execution.
- [x] Run `python3 -m unittest discover -s tests/orchestration -p 'test_muse.py' -v` and the matching `test_lock.py` command; save red evidence.
- [x] Implement the specified helpers and thin bin entrypoints. Keep the underlying tool/protocol provenance and effective-tier uncertainty explicit.
- [x] Rerun controlled tests plus local version/help and dry-run; preserve output and commit only owned files. An actual model call is separately recorded if the controller selects one.

### EX03: Controller instructions, templates and restart route

**Requirements:** ORG-R01/ORG-R06/ORG-R07. **Files:** as table, plus `tests/orchestration/test_planning_discovery.py`.

- [x] Write a failing real-repository check showing ignored worker Markdown is excluded while a new untracked bad local link is detected. Implement Git-aware document discovery and rerun the documentation checker.
- [x] Write the controller workflow, common worker rules and worker/reviewer/fix/report templates. Record routing/escalation, exact task/review evidence, serial integration/resource ownership, effects, handoff and explicit missing-environment status.
- [x] Add the Muse-specific route, reference file hashes and known wrapper failure cases without copying Haskoki assumptions. Add a single root handoff with the active M0–M6 goal and first product task SB01.
- [x] Update navigation/TODO to distinguish completed preparation from open product work. Run all orchestration tests and `python3 tools/check_planning_docs.py`.

### EX04: Independent review and setup acceptance

**Requirements:** ORG-R01–ORG-R07. **Files:** `docs/superpowers/reviews/2026-10-18-scopebase-execution-verification.md`; focused owned fixes if needed.

- [x] Produce one immutable full diff review package and ask Astra to review contracts, resource/evidence races and tests; use supplementary Muse for a bounded readonly ideas/review run if available.
- [x] Rule on findings against the spec, send fixes to the owning implementer and re-review the changed scope. Report remaining concerns without claiming acceptance of broken required behavior.
- [x] Run the full focused suite, planning checker, real doctor/dry-run and Git checks on final bytes. Recheck Haskoki reference hashes and donor custody.
- [x] Commit/integrate the local setup, preserve its worktree/evidence, update the single handoff and report readiness plus any actual missing prerequisite. No product task closes.

**Definition of done:** Helpers/tests/docs are usable and independently reviewed; native routing is explicit; the optional Muse route is honestly labeled by its actual evidence; all product implementation/qualification remains open and the user's next goal can select dependency-ready work without repeating setup.
