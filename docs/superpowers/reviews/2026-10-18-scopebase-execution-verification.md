# ScopeBase execution setup verification

Status: integration/review in progress. This record concerns the development helpers, not library/BPF/kernel qualification. All 86 product tasks remain open. The [setup plan](../plans/2026-10-18-scopebase-execution.md) and [specification](../specs/2026-10-18-scopebase-execution-design.md) define acceptance.

## Sources and observed tools

The Haskoki orchestration document and four bin scripts were inspected read-only and hash-snapshotted before adaptation. Their project-specific Cabal/GHC/proxy, automatic push/rebase/cron and forced process cleanup behavior was excluded. Source hashes and final custody comparison will be recorded with the completed setup checks.

Observed locally: Muse Code 1.4.10 (1.4.10-R6427.1), codex-cli 0.163.0, Python3, Git and flock. Actual CLI help confirms the fixed headless/read-only/model/effort/Contributor flags. Version/help observations are not authenticated model calls.

The reference's actual terminal envelope distinguishes outer session stream from payload run stream; they are not equal IDs. The complete redacted shape was supplied to the wrapper implementer. Requesting Contributor on is distinct from confirming effective provider identity.

## Integration and review evidence

Isolated Sol workers implement EX01/EX02; a Luna worker handles Git-aware document discovery. Each saves initial failing and final focused checks in its private worktree evidence directory. The controller must inspect those reports and rerun the integrated affected checks before final acceptance. Astra independent review and any real Muse review are still pending in this draft record.

Controlled external-service tests exercise the wrapper/parser with real subprocesses and synthetic protocol events. They cannot establish live Meta service behavior. Real flock/temp Git/worktree tests exercise local coordination behavior, with their declared cooperative limits. The planning checker remains a structural/documentation check.

## Goal and remaining work

The user has now activated M0–M6 development, explicitly prioritizing preservation/porting of existing fixes and their edge cases, allowing justified architecture/API improvements and independent implementation/testing of genuinely missing components. Appropriate CI/CD and privileged tests are authorized within owned resources. Product migrations and publication remain later.

Finish setup acceptance, refresh selected source/WIP under SB01, then follow the product DAG. No task status or worker report here substitutes for required runtime evidence.
