# KEEP notice: chore/setup-job-helper

- Worktree: `.worktrees/setup-job-helper` (plus branch of the same name)
- Verdict: KEEP — Codex gpt-6.1-sol/xhigh chore lane, 2026-11-14
  (thread `01a1d982-5ff4-7cf1-89e2-c25d6cfc3724`; full text `/tmp/wt-review/chore/final.txt`)
- Unique evidence: 17 ignored files, 204 KB, under `.scopebase/` (all blobs
  absent from `main`/`HEAD`): `EX01-report.md` and 16 files in `EX01-evidence/`
  (red/green/control logs, doctor output). Code preserved
  (`3488596→d3b6ba4`, `6be7983→9fc6fbe`).

## What it is evidence FOR

The job-helper authorship (EX01): TDD record plus control evidence —
external-diff invocation, smudge-filter run, worktree/ownership boundaries,
real-flock behavior — behind the ownership-review and reconciliation repairs.

## Re-creatable?

No — historical run logs and control observations.

## Consolidation record (2026-11-14)

`.scopebase` (17 files, 204 KB) copied to
`.scopebase/worktree-evidence/setup-job-helper/` (`diff -r` verified); tip
tagged `archive/setup-job-helper-tip` (`6be7983`); branch + worktree deleted.
supersedes the release condition below.

## Release condition (executed, see above)

Copy the 204 KB `.scopebase` dir to root `.scopebase/jobs/` (or a tracked
dir) and tag the tip, then the branch + worktree may be deleted.
