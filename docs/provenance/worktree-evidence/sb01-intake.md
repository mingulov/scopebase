# KEEP notice: feat/sb01-intake

- Worktree: `.worktrees/sb01-intake` (plus branch of the same name)
- Verdict: KEEP — Codex gpt-6.1-sol/xhigh intake lane, 2026-11-14
  (thread `01a1d982-1184-7a22-9179-fa4f7b7ee590`; full text `/tmp/wt-review/intake/final.txt`)
- Unique evidence: 12 ignored files, 128 KB, under `.scopebase/` (all blobs
  absent from `main`/`HEAD`): `assignment.json`, `SB01-report.md`,
  `SB01-evidence/{normalize_intake.py,normalization-audit.json,green-tests.log,orchestration-tests.log,planning-docs.log,red-catalog-source.log,red-metadata.log,red-nested-schema.log,red-tests.log,structural-check.json}`.
  Tracked code preserved at `c3fb21b`.

## What it is evidence FOR

SB01 intake authorship: the controller assignment, how `donors.json` was
derived (private generator + full normalization audit), and the TDD
RED→GREEN record plus structural checks behind the shared contract ledger.

## Re-creatable?

No. The generator's input `sb01-source-refresh.json` (SHA-256 `3665…dc40f3`)
is not in root `.scopebase` — it lived in the removed `execution-setup`
worktree — so the derivation cannot be re-run; the logs are historical.
The committed foundation receipt summarizes acceptance but preserves none
of these exact files.

## Consolidation record (2026-11-14)

`.scopebase` (12 files, 128 KB) copied to
`.scopebase/worktree-evidence/sb01-intake/` (`diff -r` verified); tip tagged
`archive/sb01-intake-tip` (`8417bee`); branch + worktree deleted. supersedes
the release condition below.

## Release condition (executed, see above)

Copy the 128 KB `.scopebase` dir to root `.scopebase/jobs/` (or a tracked
dir) and tag the tip, then the branch + worktree may be deleted.
