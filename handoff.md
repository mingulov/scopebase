# ScopeBase current handoff

Date: 2026-10-18. Continue the active M0–M6 implementation goal. Seven of 86 tasks are accepted: SB01, SB02, SB03, LX01, LX02, CP01 and CP02. The exact latest implemented subject is `365a312c5673fa68ffcad7132970f0aefc1ab812`; canonical bookkeeping and the next-task contract amendments follow it. Re-read actual refs/status and the private ledger before dispatch. No complete runtime/conformance profile is qualified.

## Goal and working location

Implement the full planned libraries, reusable regressions/docs, SDK and selective native interoperability in dependency order. Preserve donor fixes and edge cases; use independent reviews and exact affected checks. Appropriate CI/CD and owned privileged/kernel tests are authorized. Existing-product migrations and external publication remain later.

Integration checkout: `/home/user/src/m/bpfscope/.worktrees/m0-integration`, branch `feat/m0-foundations`. The root main checkout may lag during an implementation wave. Current controller ledger: `.worktrees/m0-integration/.superpowers/sdd/2026-10-17-scopebase/progress.md`. Canonical execution state is [TODO](TODO.md) plus [traceability](docs/superpowers/plans/2026-10-17-scopebase-traceability.json); the ledger preserves exact current jobs and private evidence paths. Preserve the existing goal rather than creating a replacement or inferring a budget.

## Accepted implementation

The actual packages export held-file acquisition (`scopebase-linux`) and pure capture values (`scopebase-capture`). Read [LX02 acceptance](docs/reviews/2026-10-18-lx02-held-file.md) and [CP02 acceptance](docs/reviews/2026-10-18-cp02-values.md) for exact scope, source preservation, negative controls and remaining gates. Earlier [SB01](docs/reviews/2026-10-18-sb01-foundation.md), [SB02](docs/reviews/2026-10-18-sb02-foundation.md), [SB03](docs/reviews/2026-10-18-sb03-foundation.md), [LX01](docs/reviews/2026-10-18-lx01-foundation.md) and [CP01](docs/reviews/2026-10-18-cp01-foundation.md) records retain their historical evidence scope.

The final combined package matrix is `.scopebase/controller/lx02-cp02-integration-20261018/matrix-report.json`, SHA256 `ba4e54a85dcd2041dcd8ae03c562e340a7f74a96a1d97e7cc8d9ac4bab076842`: 102 PASS, 101 required, all 12 compiler/configuration cells and no omitted or incomplete rows. Both actual archives match their independently reviewed bytes. Controller acceptance SHA256 is `f9ef75786dc2d2bcbd062d70b9901096997ba8bff73a8826116f6a45b6d198ed`; it verifies 176 log hashes and 76 locked commands with unchanged inputs. Product qualification remains false. Those workers are finished and their administrative ownership reconciled; checkouts and evidence remain retained.

The selected-port validator and exact compiler-primary-location helper are accepted development tools. Completed first ports have explicit receipts beneath `docs/provenance/ports/`; their immutable intake snapshots retain original NOT_COPIED observations. The mandatory-minimal-dependency helper repair at `5111e16` is independently accepted, with exact opt-in closure and unchanged legacy behavior. Its actual archived fixture and negative controls passed; this does not accept TT01 itself.

## Current and next work

TT01 is in progress: job `.scopebase/jobs/tt01-registry-20261018`, worker `.worktrees/tt01-registry-20261018`, immutable origin `.worktrees/dispatch-base-38261a0`. The original packet and exact case-revision amendment are copied into the job. Supplemental rulings and accepted-tool binding are separate retained artifacts. Current candidate and final archive/review state are recorded in the private ledger; inspect those records before integrating or repeating work. All initial cases remain UNIMPLEMENTED and profiles DRAFT; a valid registry does not establish execution or support.

The prepared next independent lanes are BP01 std-only error/budget configuration and LX04 cooperative controls. Canonical specifications now record their frozen boundaries. BP01 preserves independent zero/MAX caps while actual operation admission and overflow checks stay with BP02/BP04/BP05/BP06/BP09/TC02. LX04 preserves shared cancellation, absolute deadlines, errno/effects and publication checks; P's collection-wide first-stop latch stays an explicit LX10 regression. Both require actual implementation, review and package checks before acceptance. Root owns shared Cargo/lock/policy, status and cross-component contracts.

New jobs bind a clean immutable detached controller origin and copied expert inputs. A separately accepted helper successor uses an explicit supplemental binding, never a silent worker monkeypatch. Use at most three implementation lanes and one coordinated heavy-build slot, with disjoint file ownership and private outputs. [DEVELOPMENT](DEVELOPMENT.md) gives supported commands and reconciliation rules. Substantial implementation uses Sol high/xhigh, architectural/adversarial review Astra, bounded mechanical work Luna. Do not create another competing handoff.

## Donor and evidence custody

Private frozen donor copies are complete and pruned for the recorded scope at `.scopebase/donor-snapshots/2026-10-18/`; see [frozen donor index](docs/provenance/frozen-donors-2026-10-18.md). Captures include applicable branches/worktrees, WIP, untracked source/docs and independent Git histories. Retain source, history, deliberate regression fixtures and concise defect records. Cleanup applied only to private generated binaries/caches/VM images and bulk logs; current implementation evidence remains intact.

Continue from these copies. Do not recapture, poll live heads, repeat full history/hash audits or wait for active donors to become clean. Read selected frozen bytes only for a named port. Gitless copies require the explicit independent history mapping and disabled lazy fetch. Source intake now has 128 selected file records: the original 124 plus four LX04 inputs; sixteen narrow grants are ready, 109 await later decisions and three remain reference-only. Only explicit completed port receipts claim destination adaptation.

## Remaining qualification

Full reads, process/mapping/calibration, real Btrfs/overlay/namespace cells, native/BPF behavior, independently useful consumers and installed user conformance remain open under their task owners. Kernels 5.15.223/6.12.113/7.2.11 are selected source inputs, not booted or qualified environments. The inventory remains 120 requirements, 86 tasks and 179 source-obligation mappings. Do not repeat unchanged dependency probes or historical green suites; run affected checks for changed inputs, failures or a named coverage gap.
