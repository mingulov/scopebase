# Developing ScopeBase

The controller follows the [master plan](docs/superpowers/plans/2026-10-17-scopebase.md), [product TODO](TODO.md) and [current handoff](handoff.md). The [execution specification](docs/superpowers/specs/2026-10-18-scopebase-execution-design.md) defines the helpers. The active user goal is M0–M6; existing-product migrations and publication remain later. Preserve and port the donor fixes, tests and explanations. Better APIs/architecture are allowed when the existing behavior and its edge cases remain covered; genuinely missing components may be implemented and tested independently.

## Controller and worker roles

The [decision register](docs/superpowers/specs/2026-10-18-scopebase-decisions.md), [executor contract](docs/superpowers/specs/2026-10-18-scopebase-executor-contract.md) and [repair plan](docs/superpowers/plans/2026-10-18-scopebase-plan-repair.md) govern every task. The plan repair, SB01/SB02/SB03/LX01/CP01 foundations, LX02 held-file acquisition, CP02 pure values, TT01 versioned registry, BP01 host foundation and LX04 cooperative controls are accepted within their recorded scopes. The active M0–M6 goal continues with TT02, CP03 and LX03 contract preparation; the exact SHA-256 dependency prerequisite is accepted. The expert/controller freezes source slices and architecture/license/kernel decisions before a bounded executor starts. Existing job preparation binds inputs; it does not check the new packet's semantic completeness.

| Role | Model / effort | Responsibility |
|---|---|---|
| Controller | Current root session | Select dependency-ready work, freeze scope, hold ledgers, rule on conflicts, integrate and verify |
| Implementer | GPT-6.1-Sol high; xhigh for complex contracts | Port/adapt one reviewable task with tests and documentation |
| Escalated implementer | Fresh GPT-6.1-Sol max, with recorded reason | Investigate an unresolved hard case, including after Astra consultation |
| Ordinary reviewer | Fresh GPT-6.1-Sol high/xhigh | Independent specification and code review |
| Critical reviewer / architect | GPT-6-Astra high/xhigh | Authority, ownership, concurrency, unsafe/FFI, compiler/BPF and oracle/verdict review |
| Mechanical worker | GPT-6-Luna medium/high | Bounded inventories, links and straightforward transformations |
| Supplementary reviewer | Muse Spark1.3 max, Contributor on | Quick independent ideas and counterexamples; controller/Sol/Astra adjudicate findings |

The machine-readable [policy](orchestration/policy.json) is local project policy, not a global Codex configuration. Every native dispatch explicitly sets `model`, `reasoning_effort` and `fork_turns: none`. Check the current tool allowlist before dispatch. Availability failures are recorded; they never silently select a different model or downgrade a critical review. Native implementers are resumed for fixes. A Muse fix/review invocation is a fresh process with the prior report/rulings; no assumption that a headless session can resume.

Default to at most three independent implementation lanes and one heavy build slot. Actual capacity, overlapping interfaces and available reviewers may reduce this. One writer owns every worktree and shared file set. Reviewers use a pinned source checkout/package and remain read-only; the worker never creates its own approving reviewer.

Freeze shared task inputs for each assignment. New jobs use a clean immutable detached controller checkout as their origin, plus exact copied expert inputs, so unrelated integration can proceed without changing their bindings. Finish candidates and their reviews against those original inputs; integrate accepted progress and required canonical amendments together. A necessary interface amendment explicitly invalidates affected assignments; record the amendment and prepare fresh bindings rather than bypassing a mismatch. Unrelated source changes outside the bound inputs do not justify repeating completed checks.

## Starting from the user's goal

1. Read the active goal with the goal tool and refresh `handoff.md`; preserve the exact goal in `.scopebase/goal.md` for task preparation. This snapshot does not create or replace the tool's goal. No token budget is inferred.
2. Run `bin/scopebase-job doctor --repo /absolute/repository`. It performs local checks only. Current product toolchains/environments must be admitted by their own tasks.
3. Read the selected specification/task and applicable decisions, then select exact source bytes from completed private donor captures. Use each manifest's explicit independent history/checkouts mapping; a gitless copied checkout is not itself a Git repository. Do not repeatedly inspect live donor heads. Fill the executor-contract table with source symbols/tests, destination API, origin, cross-donor differences, grants/target roles and independent oracle/control. The expert resolves choices before dispatch. Port the accepted mechanism/regression together; no fresh approximation or placeholder behavior. NEEDS_DECISION identifies the missing field and affected work.
4. Select an allowed path set and prepare a job. Example for initial SB01, after a real goal file exists:

```sh
bin/scopebase-job prepare --repo /home/user/src/m/bpfscope \
  --task SB01 --job sb01-intake --role implementer \
  --goal-file /home/user/src/m/bpfscope/.scopebase/goal.md \
  --write-path docs/provenance --write-path docs/contracts \
  --write-path docs/issues --write-path tools/planning
```

5. Read the generated brief/manifest/dispatch, attach the completed expert-reviewed packet and WHAT/WHY decisions, check dependencies and ownership, then dispatch using the native agent tool. Preparation creates files and a worktree; it does not launch a worker or enforce the new packet contract. Give the worker relevant exact source/specification context. Use private TMPDIR, Cargo target and evidence directories.
6. Require an explicit worker report and independently inspect its commits/working tree. Generate `bin/scopebase-job review-package --repo /absolute/repository --job ID --head FULL_SHA`, then supply the immutable package, brief, report and candidate source to a fresh reviewer. A report's DONE does not accept the task.
7. Record findings and rulings, send focused fixes to the owner, and review the changed range. Every fix commit receives a new immutable `job/reviews/FULL_SHA/` package; an old package is never overwritten. A real correctness or evidence-integrity defect stays blocking. Cosmetic debt has an owner and exit criterion; it cannot hide a structural flaw. Refresh the candidate binding after every changed byte.
8. Run the causal affected checks on the final candidate, integrate only locally owned work, and update product TODO/traceability/handoff together. A local integration is distinct from external publication. After actual resource retirement and accepted or deliberately abandoned work, use `bin/scopebase-job reconcile --repo PATH --job ID --reason TEXT --evidence-file /absolute/controller-evidence.md --resources-retired` to release administrative writable ownership. The helper snapshots the evidence and preserves the manifest, checkout and reviews; it cannot infer that runtime resources are gone or accept the product task. Keep the claim while custody is unresolved.

## Tests and resource coordination

Use the [testing specification](docs/superpowers/specs/2026-10-17-scopebase-testing-design.md). Tests must exercise the historical defect and plausible wrong implementation with an independent expected result. Arrange real host races with barriers; keep model/property/fuzz limits visible. Preserve all affected sites and consumers rather than replacing a full regression with a representative case.

The user explicitly permits appropriate CI/CD and privileged local tests. For BPF, qualify the final emitted/transformed object actually loaded, independent positive/excluded workloads, semantic kernel behavior and cleanup. Select old/current/distro/reproducer cells before discovering availability. Use owned disposable environments, record resource identity/leases and coordinate existing users. Local locks do not prove exclusive ownership of a remote VM or replace a donor's existing lease. Do not change global host policy to manufacture support. Missing required cells remain incomplete.

Wrap cooperative heavy work with `bin/scopebase-build -- COMMAND ARG...`. All participating ScopeBase jobs must use the same host/user lock root and resource. The initial single build slot avoids simultaneous heavy Cargo/native builds. Distinct Cargo output roots remain necessary. Acquisition timeout does not kill the running build or prove descendant retirement; TC02/TC07 define those stronger product contracts.

Current foundation/tooling verification commands:

```sh
python3 -m unittest discover -s tests/orchestration -v
python3 -m unittest discover -s tools/planning/tests -v
python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json
python3 tools/check_planning_docs.py
python3 -m unittest discover -s tests/package-policy -p 'test_*.py' -v
git diff --check
```

These commands test development tooling, including SB02 package build-policy checks and dependency/compiler/feature probes. The root Cargo workspace now contains `scopebase-linux`, `scopebase-capture`, `scopebase-testkit` and `scopebase-bpf`. The TT01 integration at 6b225d1 passed all sixteen then-declared cells. BP01 at c0d3583 passed four affected cells (42 PASS rows); LX04 at b832dca passed six (56 PASS rows). The current twenty-cell matrix was not rerun in full. These checks cover the accepted bounded APIs; complete runtime/conformance profiles and kernel behavior remain unqualified. A normal downstream Cargo test does not automatically run dependency tests. See [dependency policy and probe results](docs/dependencies.md) for the recorded probe scope.

For a deliberate full package-matrix rerun, coordinate the shared build slot and assign `SCOPEBASE_RUN` a fresh run-specific path under the private job root outside this worktree. This is the current supported `check_features.py` invocation; it creates its output directory and writes its report at the supplied paths:

```sh
SCOPEBASE_RUN=/home/user/src/m/bpfscope/.scopebase/jobs/foundation-check-$(date -u +%Y%m%dT%H%M%SZ)
bin/scopebase-build -- python3 tools/build/check_features.py \
  --manifest Cargo.toml \
  --matrix package-policy.json \
  --output-dir "${SCOPEBASE_RUN}-output" \
  --report "${SCOPEBASE_RUN}-report.json"
```

The historical complete 134-row receipt is recorded in the TT01 acceptance record. Latest affected receipts are in the BP01/LX04 acceptance records and `.scopebase/controller/{bp01,lx04}-integration-20261018/`. This example is not evidence of another run.

## Recovery and continuation

Root TODO records accepted product progress. The active product ledger lives in `.worktrees/m0-integration/.superpowers/sdd/2026-10-17-scopebase/progress.md`; preserved setup/source evidence lives under the setup worktree's `.scopebase/preparation-20261018/`. Prepared job manifests/reports live in the canonical Git-common repository root's `.scopebase/jobs/`. `handoff.md` is the single current restart route. Review actual Git refs/status, ledger, pending owners and goal before dispatching again. A quiet log, absent PID, old green CI or stale DONE cannot release custody or certify a new candidate.

Preserve attempts rather than overwriting them. On service failure, inspect existing commits and report before a fresh attempt. Do not automatically retry an ambiguous side effect, re-dispatch completed work, delete worktrees, or remove evidence to make status look clean. Record unresolved resources and who owns them. Automation remains cooperative coordination; administrative records and local reports do not create runtime authority.
