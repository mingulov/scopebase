# KEEP notice: chore/setup-review-tools

- Worktree: `.worktrees/setup-review-tools` (plus branch of the same name)
- Verdict: KEEP — Codex gpt-6.1-sol/xhigh chore lane, 2026-11-14
  (thread `01a1d982-5ff4-7cf1-89e2-c25d6cfc3724`; full text `/tmp/wt-review/chore/final.txt`)
- Unique evidence: 57 ignored files, 760 KB, under `.scopebase/`
  (41 blobs absent from `main`/`HEAD`): `EX02-report.md` and `EX02-evidence/`
  (red/green logs, dry runs, schema, plus `wrong-candidate-control/`,
  `retry-75-control/`, `lost-lock-fd-control/` incl. mutant sources).
  Code preserved (`bd3b9d2→5264a04`, `9f7099f→c02a564`, `619f978→79318cf`).

## What it is evidence FOR

The review-tools authorship (EX02): TDD record, rulings, and the
negative-control evidence (deliberate mutants, semantic-failure logs, filter
regressions, dry runs) behind the guarded review/lock helpers.

## Re-creatable?

No — historical run logs and hand-built control fixtures.

## Consolidation record (2026-11-14)

`.scopebase` (57 files, 760 KB) copied to
`.scopebase/worktree-evidence/setup-review-tools/` (`diff -r` verified); tip
tagged `archive/setup-review-tools-tip` (`619f978`); branch + worktree
deleted. supersedes the release condition below.

## Release condition (executed, see above)

Copy the 760 KB `.scopebase` dir to root `.scopebase/jobs/` (or a tracked
dir) and tag the tip, then the branch + worktree may be deleted.
