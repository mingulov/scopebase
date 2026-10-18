# ScopeBase current handoff

Date: 2026-10-18. The active M0–M6 implementation goal continues. **SB01 is accepted** at `f1280b010099100daeec9fd2233bbeacea5443e0`; [foundation acceptance](docs/reviews/2026-10-18-sb01-foundation.md) records scope, independent review, tests and limits. SB02 is the next dependency-ready task. No shared Rust library or runtime profile is implemented or qualified yet. The inventory remains 120 requirements, 86 tasks and 179 source mappings; TC-R10/H33 append licensing coverage.

## Goal and working rules

Implement ScopeBase through M0–M6 in dependency order, with independent reviews and each advertised capability's required qualification. Existing product migrations and publication remain later. Port and preserve donor fixes, regressions and knowledge, including applicable branches, worktrees and WIP. Better architecture/APIs are allowed with preserved behavior and edge cases. Missing necessary components may be independently implemented/tested and added to TODO with dependencies and acceptance. Appropriate CI/CD and privileged tests for actual BPF/kernel behavior are authorized within owned, coordinated resources.

Read the thread goal tool at restart; do not create another goal or infer a budget. `.scopebase/goal.md` is only the local task-preparation snapshot. Follow [TODO](TODO.md), the [master plan](docs/superpowers/plans/2026-10-17-scopebase.md), [development workflow](DEVELOPMENT.md), [decision register](docs/superpowers/specs/2026-10-18-scopebase-decisions.md), [executor contract](docs/superpowers/specs/2026-10-18-scopebase-executor-contract.md) and [repair plan](docs/superpowers/plans/2026-10-18-scopebase-plan-repair.md).

## Accepted foundation and evidence

The bounded SB01 repair preserves 124 selected file observations across eight authorities, two dirty MojoBPF input hashes, 1,529 symbol candidates and 389 regression candidates. The original 178 source mappings and H01–H32 are unchanged; H33 is appended. Schema 2 separates source observations, author-authorized destination terms, artifact roles and third-party fragments. No source slice is ready to copy solely from intake acceptance: 121 records still need adoption decisions and three remain technical reference-only/product-local inputs.

Independent review closed implicit lazy fetching, incomplete nested-reference validation, missing-tree classification and known non-commit classification. At the accepted subject, all 54 intake tests passed, including seven focused real-Git controls. The unchanged coordination boundary has 92 passing tests at `328454059cec78686be4b387e5624f4749332e33`. Final structural intake is VALID with source verification NOT_RUN and qualification NOT_EVALUATED. Planning and whitespace checks are rerun with acceptance bookkeeping; no donor refresh, Cargo build or runtime test is inferred from these results.

The accepted plan-hardening and setup records remain in [plan verification](docs/superpowers/reviews/2026-10-18-scopebase-plan-hardening-verification.md) and [setup verification](docs/superpowers/reviews/2026-10-18-scopebase-execution-verification.md). Their earlier counts/results are historical, not acceptance of changed bytes.

## Checkouts and custody

Main repository: `/home/user/src/m/bpfscope`. Current acceptance bookkeeping is on `.worktrees/m0-integration`, branch `feat/m0-foundations`, above reviewed subject `f1280b010099100daeec9fd2233bbeacea5443e0`. The controller may fast-forward clean local main after affected checks. Re-read actual refs/status before acting; a checkout's existence is not task acceptance.

The active private product ledger is `.worktrees/m0-integration/.superpowers/sdd/2026-10-17-scopebase/progress.md`. Its `SB01-repair/` directory retains briefs, bindings, original and focused independent reports, RED/GREEN logs and preservation comparisons. The original intake candidate remains at `8417beead68a03ecaff361d0d76da5f38c09820f` in `.worktrees/sb01-intake`. Do not redispatch or discard it. Its superseded mandatory historical-GPL/NOASSERTION copying policy is not current policy.

Preserve `.worktrees/execution-setup` at `bbcad0d9b52d8cb607ca7d1d6e120823e7c169b9`, its `.scopebase/preparation-20261018/` source refresh and source hashes, setup helper/smoke worktrees, and `.worktrees/plan-hardening`. The original auxiliary progress-check candidate and count refresh remain in `.worktrees/progress-checks` at `60c9e9f31ecf59549768551073eeee7923f3f799`; their integration copies are already in M0. Do not repeat their implementation. Administrative job manifests and reviews under `.scopebase/jobs/` remain in custody.

No SB01 writer/reviewer or privileged runtime lane remains active. Record new SB02 owners and candidates here when dispatched. No donor/worktree/evidence cleanup is authorized by completion.

## Next: SB02 workspace and dependency qualification

1. Confirm SB01 acceptance metadata and clean local integration. SB02's private expert packet is under the M0 product ledger's `SB02-preparation/`; bind the final controller-ratified packet and accepted base before execution. It specifies actual dependency API/fit probes, source/build-input policy, independent clients, feature controls, doctests and package allowlists. Do not create placeholder production exports or treat an empty workspace as a library build.
2. Use Rust 1.88.0 and selected current 1.98.1, both already observed locally. Verify identities in actual executions. No compiler installation is needed. Source APIs and candidate features were inspected, but no dependency probe has yet been built. Resolve comparator gaps from evidence; do not silently raise MSRV or replace a parser/loader.
3. Prefer Cargo's own explicit `fetch`/`vendor` acquisition into an owned `CARGO_HOME`, freeze hashes/configuration/locks, then execute offline locked builds with approved build-script/proc-macro inputs. Do not build a second registry package manager or write global Cargo caches. Preserve the separately acquired pinned procfs/BTF sources and Apache text under `SB02-preparation/acquired/`.
4. If splitting probes and build-policy work, use disjoint paths/worktrees and frozen shared matrix/report contracts. Root owns the initial license text and shared status. Authoritative probe execution waits for the immutable policy-tool candidate. Use the existing single heavy-build lease and separate Cargo/target/evidence roots. Independently review the integrated SB02 candidate before acceptance.
5. After SB02, follow the DAG for SB03 and independent Linux/capture/testkit foundations. Refresh exact donor slices before ports. Complete ready components and their tests before SDK/native reference consumers; product migrations remain later.

## Open policy and qualification limits

Licensing is provisional at the user's latest direction: Apache-2.0 for owned userspace ScopeBase, GPL-2.0-only BPF and GPL-3.0-or-later apps, without a project MIT option. Owned source genuinely shared with a BPF target needs `Apache-2.0 OR GPL-2.0-only` or approved separation. Preserve actual third-party terms/notices. Existing Aya target dependencies need a scoped compatible-option decision before that payload; do not silently select an option or broaden the no-MIT preference. Unrelated host work proceeds. Source terms, final ELF license bytes and kernel admission are separate checks.

Packets require actual source symbols, tests, destination contracts, preservation/oracle/control maps, predecessor artifacts and WHAT/WHY decisions. The existing job helper binds inputs but does not mechanically judge those semantic fields; the controller does. No new coordination framework is required.

There is no configured Git remote. Local qualification and prepared CI configuration do not imply external service execution or publication. No runtime resource is currently owned. Model routing remains Sol high/xhigh implementation, reasoned fresh Sol max escalation, independent Astra architectural/critical review, Luna mechanical tasks and optional Muse Spark1.3 max/Contributor-on supplementary read-only review.
