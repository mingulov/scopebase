# KEEP notice: scopebase/bp03-prepared-integration-20261022-r1

- Worktree: `.worktrees/bp03-prepared-integration-20261022-r1` (plus branch)
- Verdict: KEEP — Codex gpt-6.1-sol/xhigh bpf lane, 2026-11-14
  (thread `01a1d980-d78b-7d02-9c57-4e7c7a256626`; full text `/tmp/wt-review/bpf/final.txt`)
- Unique evidence: parent `bd9d361` pre-fix
  `crates/scopebase-testkit/src/bpf/adapter.rs`
  (blob `db32475b…`, absent from `main`/`HEAD`; sole container is this branch).
  The tip itself matches `bfb9452` over all 91 touched paths. Worktree is clean.

## What it is evidence FOR

The frozen candidate the prepared-integration review bound: it collapsed
source-profile constructor errors into `source-id-error` and lacked the
exact-refusal classification + regression test the fix added.

## Re-creatable?

No — historical state. But fully archivable: tagging tip `e4a4629` keeps
`bd9d361` reachable (ancestry verified).

## Consolidation record (2026-11-14)

No worktree-local bytes existed (clean). Tip tagged
`archive/bp03-prepared-integration-20261022-r1-tip` (`e4a4629`), keeping
`bd9d361` reachable; branch + worktree deleted. supersedes the release
condition below.

## Release condition (executed, see above)

Tag the tip per archive convention, then the branch + worktree may be deleted.
No worktree-local files need copying.
