# KEEP notice: chore/setup-doc-checker

- Worktree: `.worktrees/setup-doc-checker` (plus branch of the same name)
- Verdict: KEEP — Codex gpt-6.1-sol/xhigh chore lane, 2026-11-14
  (thread `01a1d982-5ff4-7cf1-89e2-c25d6cfc3724`; full text `/tmp/wt-review/chore/final.txt`)
- Unique evidence: 2 ignored files, 8 KB, under `.scopebase/` (both blobs
  absent from `main`/`HEAD`): `EX03-discovery-report.md`, `EX03-discovery-red.txt`.
  Code preserved (`28df22e→bbd9c72`).

## What it is evidence FOR

The Git-aware planning-document discovery fix (EX03): the implementation
report and the RED log showing the ignored-worker doc wrongly scanned.

## Re-creatable?

No — historical run record.

## Consolidation record (2026-11-14)

`.scopebase` (2 files, 8 KB) copied to
`.scopebase/worktree-evidence/setup-doc-checker/` (`diff -r` verified); tip
tagged `archive/setup-doc-checker-tip` (`28df22e`); branch + worktree deleted.
supersedes the release condition below.

## Release condition (executed, see above)

Copy the 8 KB `.scopebase` dir to root `.scopebase/jobs/` (or a tracked
dir) and tag the tip, then the branch + worktree may be deleted.
