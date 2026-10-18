# Supplementary Muse reviews for ScopeBase

Muse Spark1.3 supplies additional ideas/counterexamples. Native Sol implements; Sol/Astra provide the primary independent review, and Astra reviews critical contracts. This adapts the workflow in `/home/user/src/m/haskoki-ws/ws/muse-jobs/MUSE-ORCHESTRATION.md` and its bin scripts. Haskoki is a read-only reference, not a ScopeBase dependency or source of passing tests.

Use `bin/muse-run.sh WORKTREE PROMPTFILE OUTPREFIX --dry-run` to inspect a planned invocation without contacting a model. All three paths are absolute. Prompt text is bounded to65,536UTF-8 bytes. The source checkout must be clean before and after review, while ignored private inputs remain permitted. Use a fresh output prefix for every attempt. Remove `--dry-run` only when the controller selects an actual supplementary review. The wrapper defaults to 32 model steps; `--max-steps N` can set a bounded smaller review. This is headless fresh execution, not a reliable resume mechanism.

The wrapper requests model `muse-spark-1.3`, reasoning `max`, Contributor `on`, provider `meta` and the named already-owned worktree. It disables write, shell, web, reminders and user-input tools. It preserves the default sandbox with approval-mode never and workspace trust; it does not copy the reference's unconditional `--yolo`. A worktree is not an OS security boundary. Do not provide secrets or privileged resources to a supplementary reviewer.

The prompt names the exact full candidate SHA, brief/report/package and relevant source files. Paths must be readable in the selected worktree; copy only necessary review inputs into its ignored private directory if workspace policy requires it. Ask for a JSON final report:

```json
{
  "status": "REVIEW_COMPLETE",
  "reviewed_commit": "FULL_CANDIDATE_SHA_FROM_THE_CONTROLLER",
  "summary": "Review outcome and limits",
  "findings": [{"severity": "idea", "message": "Concrete observation or counterexample"}],
  "concerns": []
}
```

Allowed finding severities are critical/important/minor/idea. A completed review may report defects; execution success is separate from acceptance. Sol/Astra/controller compare findings with the actual contract and evidence. Do not accept or reject a finding solely because Muse produced it.

Output files are private `.jsonl`, `.err`, `.final.txt`, `.execution.json` plus a private TMPDIR. Read the small execution/final files first, not whole transcripts. Raw nonzero process status remains nonzero. Zero exit with absent/malformed/conflicting/failed terminal, empty/invalid final report or changed/wrong candidate is not successful execution. Reusing an output prefix refuses rather than truncates evidence. Review artifacts are not published or treated as library support receipts.

Contributor-on is a request. Effective tier is confirmed only by the matching successful provider status, when available: `runtime.session` → `payload.event.details.phase == stream_succeeded` and a producer facet `detail.model`, correlated by `payload.run_id`. Base `model_completed` is insufficient. The wrapper may report effective tier unverified; it does not infer pricing or Contributor success from the requested flag.

## Reference lessons retained

| Reference behavior | ScopeBase behavior |
|---|---|
| Process exit alone determined success; parser tolerated missing terminal | Preserve raw exit, require a valid unique terminal and candidate-bound JSON review |
| Reused output prefix could overwrite evidence; umask022 | Exclusive private reservation and 0600/0700 artifacts |
| Arbitrary trailing arguments could override fixed launch configuration | Fixed reviewed flags and bounded named options |
| Build command exit75 was confused with lock contention | Acquire the lock separately, then execute exactly once |
| Verifier printed failures/skipped missing binaries yet could exit zero | No universal copied verifier; actual task checks aggregate their own required outcomes |
| Haskoki-specific Cabal/GHC/proxy/touch/delete/debug behavior | Excluded from ScopeBase; no source touching or build-product deletion |
| Automatic rebase/push/CI/cron patterns | Controller-selected local integration and explicit goal continuation; publication separately instructed |

Reference hash/provenance and actual installed-tool/test evidence are recorded in the [setup verification](../docs/superpowers/reviews/2026-10-18-scopebase-execution-verification.md). Do not reinterpret the reference author's project-specific experience as a general model benchmark.
