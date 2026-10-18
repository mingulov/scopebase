# ScopeBase transfer checkpoint

Date: 2026-10-18. This is the current user-requested documentation-only freeze after the TT02, BP02 and LX05 review/repair wave. It records custody, observed evidence and exact restart gates. It is not package acceptance, live qualification, integration or a complete runtime/conformance result. The active M0–M6 goal reports `paused`.

The single restart route is [handoff.md](../../handoff.md#resume-here). [TODO](../../TODO.md) and [traceability](../superpowers/plans/2026-10-17-scopebase-traceability.json) remain the product ledger and dependency map. Thirteen of 86 tasks are accepted, three are in progress and 70 are planned. Latest accepted product bytes remain `f2952ee8661e27e90e1f965550021d615a31f96a`.

## Controller and process custody

Controller integration is `/home/user/src/m/bpfscope/.worktrees/m0-integration`, branch `feat/m0-foundations`. Before the present documentation edits, it and `main` were clean at `df0211ba44d1f3112fd37f34bcdef5eb0427dcd9`. The three implementation worktrees retain uncommitted work. No reset, clean, merge, dependency update, donor refresh or evidence deletion was performed.

At this freeze check, `/proc` showed no matching local task runner, Cargo, QEMU, Muse or Codex worker process. All bounded CLI review and repair runs had returned. No post-format LX05 rerun was started. No BP02 guest product payload has run. The previous remote custody receipt remains historical evidence for the old v5 preparation; the repaired BP02 contract requires fresh v7 payload and run identities before any guest execution.

The earlier transfer receipt `.scopebase/controller/transfer-20261018/custody-and-inputs.json`, SHA-256 `7d9d2673f3e6828e9e7d248bf049dac12b79b68ddfb14f8171316c59e8685b59`, remains a valid record of that earlier stop. Its TT02 40/64 and pre-review BP02/LX05 state is superseded by this checkpoint. Preserve it as history; do not use its progress counts as current state.

## Current task states

| Task | Worktree state | Current evidence | Why still open |
|---|---|---|---|
| TT02 | Branch `scopebase/tt02-engine-20261018`, base `e7de89165765d295a1e0519436daeb64de1ae8f8`; modified `result.rs`, `runner.rs`, `verdict.rs`; untracked repair evidence/report | Baseline final matrix PASS, 64/64 current required rows and 165 command rows; linked controls PASS, 48 rows. Independent Daybreak review found a live stop-order defect; repair source and a two-operation regression now exist | Repair bytes have no observed Cargo RED/GREEN or affected source/archive run, and no final independent approval, commit, shared dependency activation or integration |
| BP02 | Branch `scopebase/bp02-maps-20261018`, base `c2a6e6c88448fae77c998f5d80b69efae97d1eab`; original 54-file candidate remains staged; repair edits and four new files remain outside that staged snapshot | Independent Daybreak release review verified old package bindings but found three release-blocking delivery/test gaps. Repair implementation passed 13 focused Python tests and static checks | Fresh v7 Rust mutants, package/archive consumers, native preparation, payload, guest cells and independent final review remain unexecuted |
| LX05 | Branch `scopebase/lx05-proc-20261018`, base `e86ff68aff788fad4396dcfb8f8f33013bc2a103`; five tracked test/helper/doc edits, two new A3 fixtures and untracked fuzz project | Exact A3 control, six package cells, 24 clients and two 10,000-run ASan campaigns passed before the final formatting pass | Rustfmt changed candidate bytes after the receipts. Three prepared changed-byte reruns, documentation rebinding and final independent review remain |

No task state changes here. TT02, BP02 and LX05 remain `IN_PROGRESS`; none is `ACCEPTED`, `BLOCKED` or product-migrated.

## TT02 evidence and restart boundary

The pre-repair baseline completed after the earlier transfer:

- `.scopebase/jobs/tt02-engine-20261018/evidence/final-matrix-r1-v2/results.json`, SHA-256 `26f213480e1826ad0b2ebe49c72d80228360f35ac560d3ec182d5fa6bc6c6f93`, reports PASS for all 64 current required rows and 165 command rows. The earlier interrupted row remains retained history.
- `.scopebase/jobs/tt02-engine-20261018/evidence/linked-controls-final-v1/results.json`, SHA-256 `2cb525ea2dc4e73d9048bcb8ac12d01769be9537f6b3af7b37f564cb394749c6`, reports PASS for 48 rows.

Independent Daybreak review `.scopebase/controller/finish-candidates-20261018/tt02-final-review-daybreak-run02/final.txt`, SHA-256 `d5a416e28dac3ae4909b3aa4b2b6090886f9b503023d0a4e12c6a99ee34b00ce`, returned `BLOCK_TT02_CANDIDATE`. It verified the baseline delivery but showed that wrong-artifact progress returned with an `Io` fixture failure could allow a later scheduled prepare before receipt reconstruction rejected the protocol. It also required a live two-invocation negative and corrected stale evidence labels.

The repair worker output is `.scopebase/controller/finish-candidates-20261018/tt02-review-fix-daybreak-run02/final.txt`, SHA-256 `be383080bc78e812846bc429d1ea7e3e732bcff10ec851dba7d71d66711f2bf9`. The worktree report `tt02-review-fix-report.md` binds before/after source hashes. The repair validates progress against the frozen contract at the live failure boundary and shares the validator with receipt reconstruction. Its new regression requires no second prepare, retained partial failure/progress/effect evidence, `NotRun` for operation two and owner retirement.

The worker's rustfmt, whitespace, planning and evidence-index checks passed. Its Cargo commands stopped before launch because that sandbox could not write the controller-selected `/run` lock. Therefore the old matrix cannot qualify the repair.

Restart sequence:

1. Use the common absolute build wrapper to obtain an observed semantic RED against old behavior or an exact scoped mutant, then GREEN on the current repair.
2. Run affected fixture-failure, receipt, retirement and runner tests, followed by the changed-byte source/archive and linked-control cells.
3. Reconcile the successor indexes in `tt02-review-fix-evidence/` while retaining original receipts and interrupted history.
4. Obtain a new independent Daybreak review. Then commit, activate the actual member/dependency/policy/notice/lock deltas under the root writer, integrate and record acceptance only if every gate passes.

## BP02 evidence and restart boundary

Independent review `.scopebase/controller/finish-candidates-20261018/bp02-release-review-daybreak-run05/final.txt`, SHA-256 `7373127ede527623872ad4992db2f619cbd955ad506f2fd1f8c2f59add2ed77a`, returned `BLOCK_OWNED_GUEST_RUN`. It found:

1. Half of the 48 old mutant rows exercised a test-only WHO model and were described too broadly.
2. Stale-80 mutants died at a later valid-88 unwrap instead of the intended stale-input assertion.
3. The guest route did not enforce all resource/compiler/feature/manifest bindings or retain child and cleanup outcomes on every failure path.

The repair worker output is `.scopebase/controller/finish-candidates-20261018/bp02-review-fix-daybreak-run02/final.txt`, SHA-256 `a448efb6bba62c66ce2dbbe0da945e8d2d2bf9ba44c06fdd8678b67df3c1ef21`. The task report is `bp02-review-fix-report.md`. Repairs now classify library/model tiers, require 12 rows in each tier per compiler, use three unique stale-80 failure markers, enforce prebuilt bindings, retain child/cleanup rows and ship a bounded payload runner plus summary verifier.

Thirteen focused Python tests, Python and shell syntax, rustfmt for the changed Rust test, planning checks and whitespace checks passed. Rust mutant execution, restored positives, archive execution and live cells remain `NOT_RUN`; the worker could not acquire the common build lock. The broader package-policy attempt is not a passing result because its Cargo-dependent rows failed at the same lock boundary.

The old `bp02-final-001` guest and `bp02-final-run-001` name are superseded. They bind pre-repair v5 bytes and must not be executed or reused.

Restart sequence:

1. Incorporate staged plus repair bytes into a fresh v7 candidate/package workspace and supersede the changed selected-port destination receipt.
2. Run the WHO positive and both compilers' complete v7 mutation campaigns. Require each named stale-80 marker, restored positives and 12 production-library plus 12 test-model rows per compiler.
3. Rerun source/archive consumers, verify both new payload files ship, and create fresh resource/compiler/feature/manifest-bound native specs.
4. Stage and verify a fresh payload from the shipped template, exercise positive/missing-binding/cleanup-failure summary controls, build and transfer a fresh initramfs, and allocate new guest/run IDs.
5. Run the required owned-kernel cells; inspect bindings, semantic controls, child reaping, cleanup and archive-native rows. Obtain final independent review before commit and integration.

## LX05 evidence and restart boundary

Independent review `.scopebase/controller/finish-candidates-20261018/lx05-review-daybreak-run02/final.txt`, SHA-256 `a10a962bdbe982c1fec4be427967e94dd9403ff87a7f771a9e775dfb988c2c4a`, returned `BLOCK_PURE_CANDIDATE` because the candidate used a generic malformed population instead of the exact A3 rows fixed by the verification plan. It found no additional parser defect in the inspected bytes.

The worktree now contains the exact A3 positive and negative fixtures, literal row/address assertions, independent oracle agreement and a skip-malformed-row mutant. Root observed the intended mutant failure and restored success, the full Linux package suite, six affected package cells and twelve source/archive helper receipts. Root also completed locked/offline build and startup checks and both required 10,000-run ASan campaigns over 241 independently bound seeds. Pre-format receipts include:

- A3: `.scopebase/controller/finish-candidates-20261018/lx05-a3-final-r1/result.json`, SHA-256 `eddd4f748ad774ca740d00aefcc8d1ec70d82041808c22a2f4aa1a18c58dc884`.
- Fuzz: `.scopebase/controller/finish-candidates-20261018/lx05-fuzz-final-r1/result.json`, SHA-256 `c7f218ad924b65edb219541b6c4aa7b47a71f242b36f3356c35a2da93a4c1995`.
- Qualification: `.scopebase/controller/finish-candidates-20261018/lx05-qualification-r2/receipts/result.json`; the worktree qualification note records SHA-256 `e1ec3cda1b606b6895bfd703142f6db9304a82916d1e1e2f3369e583ba820e4d` and its 56-row package gate SHA-256 `831c6b13cb3fbdaa64d938f1c4f889e6c8b4ffa198973fe62f9498430197c541`.

A final rustfmt pass changed the tests, helper and two fuzz targets after those runs. Formatting and whitespace checks then passed, but the receipts are not final changed-byte evidence. The controller prepared and Python-compiled three rerun drivers without launching them:

- `run-lx05-a3-final-r2.py`, SHA-256 `7ac489f43afe367097d7a444e1bbf3345406fb023b9e8a4b44c854c7008eb3ae`;
- `lx05-run-qualification-r3.py`, SHA-256 `a0be25f9ad30e3ac20037bbac6da6bb7420df3a7a3712626f0e36aca52e2c31a`;
- `run-lx05-fuzz-final-r2.py`, SHA-256 `32bd5c81a8b8fb042ef8e6a0a742d2618c1d0f7d1196a6bfad42c662437594e1`.

Restart sequence:

1. Run those three drivers against the current formatted bytes and their fresh output roots.
2. Retain concise receipts/logs only; do not copy the large target directories into the repository.
3. Update `fuzz/scopebase-linux/qualification.md`, `preparation-index.json` successor bindings and `review-fix-report.md` to the new results.
4. Recheck JSON, rustfmt, whitespace and the selected package evidence, then obtain an independent Daybreak final review before commit and integration.

## Model routing and scope limits

The successful critical reviews and repair invocations used `gpt-6-sol --cyber-access-program daybreak_blue` at max effort. Earlier 400/403 model/program starts did not execute their tasks and remain historical diagnostics. The explicit Daybreak route worked for all current review findings. No re-login, global configuration edit, account change or Astra consultation is required for this continuation.

On resume, GPT-6.1-Sol high/xhigh remains the default implementer, Sol max the architecture/adversarial reviewer, and Luna the bounded mechanical helper. Astra is reserved for a serious unresolved issue after a recorded Sol max investigation. The three worktrees are disjoint, but all Cargo/native children use the common absolute wrapper; the remote guest has separate ownership. Root alone edits shared lock/policy/member/export and acceptance records.

This checkpoint makes no claim about later Linux runtime authority, filesystem mapping cells, old/new kernel support, complete BPF profiles, SDK readiness, C/Mojo interoperability, product migration or publication. Their existing TODO owners and acceptance criteria remain unchanged.
