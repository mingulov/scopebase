# ScopeBase execution setup verification

Status: accepted development setup, independently reviewed at implementation commit `79318cfcccd7bbabe728974c857c27b0bc57ff78`. This record concerns the development helpers, not library/BPF/kernel qualification. All 86 product tasks remain open. The [setup plan](../plans/2026-10-18-scopebase-execution.md) and [specification](../specs/2026-10-18-scopebase-execution-design.md) define acceptance.

## Sources and observed tools

The Haskoki orchestration document and four bin scripts were inspected read-only and hash-snapshotted before adaptation. Their project-specific Cabal/GHC/proxy, automatic push/rebase/cron and forced process cleanup behavior was excluded. All five hashes were rechecked unchanged after integration. The [Muse guide](../../../orchestration/MUSE-ORCHESTRATION.md) records their exact hashes and paths; private comparison evidence is `preparation-20261018/evidence/reference-final-hashes.json` in the setup worktree's `.scopebase/`.

Observed locally: Muse Code 1.4.10 (1.4.10-R6427.1), codex-cli 0.163.0, Python3, Git and flock. Actual CLI help confirms the fixed headless/read-only/model/effort/Contributor flags. Version/help observations are not authenticated model calls.

The reference's actual terminal envelope distinguishes outer session stream from payload run stream; they are not equal IDs. The complete redacted shape was supplied to the wrapper implementer. Requesting Contributor on is distinct from confirming effective provider identity.

## Integration and review evidence

Isolated Sol xhigh workers implemented EX01/EX02; a Luna worker implemented Git-aware document discovery. Their reports retain initial failing checks, semantic controls and final focused results. The controller inspected their reports, integrated only the owned commits, and checked the combined bytes.

Astra reviewed the complete setup at `d3b6ba4a6cf7ad0b6466c41318ce95200e846df3`, the coordinated fix range through `2e60fd24c4f8fe9674dcbcaa4488a5a428558954`, and the final narrow filter repair through `79318cfcccd7bbabe728974c857c27b0bc57ff78`. The final scoped verdict is PASS, with no remaining blocker.

| Finding | Repair and discriminating control |
|---|---|
| EXREV-01: rename hides unowned deletion | Ownership enumeration disables rename detection; both cross-boundary directions refuse |
| EXREV-02: 26 real tasks cannot be extracted | Exact IDs and heading depth; all 86 actual task sections, missing and ambiguous controls |
| EXREV-03: older base contains escaping symlink | Validate selected tree and populated checkout; failed preparation retains custody |
| EXREV-04: HEAD alone does not bind available source | Require clean tracked/untracked source before/after review; preserve invalid attempts |
| EXREV-05: fixes cannot get a fresh package; retained claims exhaust lanes | Immutable package per full candidate SHA and explicit evidence-bound administrative reconciliation |
| New regression in EXREV-04 repair: Git filters execute or conceal changes | Suppress configured filter drivers; real clean/process execution sentinels and same-length dirty-byte controls before/after review |

These were concrete reproductions in real temporary Git repositories, with intended semantic failures before repair. The final filter controls matter: a different-length replacement could already be detected by Git's stat shortcut. Same-length replacement was necessary to expose the defect.

The integrated suite before the final filter repair passed 66 tests in 59.371s. The final affected Muse suite passed 29 tests in 14.374s. The final combined command `python3 -m unittest discover -s tests/orchestration -v` passed **70 tests in 34.729s** on the final implementation bytes; the planning checker and whitespace check also passed. Private logs remain under `preparation-20261018/evidence/` in the setup worktree's `.scopebase/`. The actual doctor returned `READY_FOR_PREPARATION` with valid policy; an actual LX01 read-only preparation extracted its correct section, generated explicit Sol/high/fresh-context dispatch and produced an immutable package. No worker was launched. Explicit reconciliation preserved the checkout/artifacts and recorded that no build, VM, lease or runtime resource had been created.

An actual installed-CLI dry-run at the final implementation SHA passed with clean source, fixed `--max-tool-output-bytes 65536`, requested Spark1.3/max/Contributor-on, and no model invocation. Dry-run raw exit/report fields remain null.

One real supplementary Muse review ran at the earlier `d3b6ba4` candidate and returned process zero, one valid completed terminal and `REVIEW_DELIVERED`, with acceptance `NOT_DECIDED`. This proves delivery for that attempt, not review correctness or provider behavior for changed wrappers. Effective provider tier remains unverified. Its claim that Muse/lock tests were absent was rejected against committed files and actual test output; lifecycle and bounded-input suggestions informed the fixes. A second paid run was unnecessary for the narrowly reviewed local changes.

Controlled external-service tests exercise the wrapper/parser with real subprocesses and synthetic protocol events. They cannot establish live Meta service behavior. Real flock/temp Git/worktree tests exercise local coordination behavior, with their declared cooperative limits. The planning checker remains a structural/documentation check.

## Goal and remaining work

The user has now activated M0–M6 development, explicitly prioritizing preservation/porting of existing fixes and their edge cases, allowing justified architecture/API improvements and independent implementation/testing of genuinely missing components. Appropriate CI/CD and privileged tests are authorized within owned resources. Product migrations and publication remain later.

SB01 is already implementing in its separate worktree; the refresh covers 124 selected files from eight authorities and two dirty MojoBPF inputs. A separate bounded SB02 preflight records installed toolchains and dependency/API gaps; no dependency build has been qualified. Follow the product DAG after independent SB01 acceptance. No task status or worker report here substitutes for required runtime evidence.

## Controller rulings and limits

- Preserve all worktrees/evidence rather than the skill cleanup default; this costs local disk space.
- Use Muse as supplementary read-only review with independently adjudicated findings; it supplies no task acceptance or critical-review substitute.
- Amend the literal setup contract for per-candidate packages, explicit reconciliation, full task-heading coverage, selected-base paths and clean source. Conservative refusal can require a corrected assignment; reconciliation is a controller assertion, never runtime authority.
- Repair the newly introduced filter regression beyond the skill's initial final-wave cap because the user's requirement to cover real defects takes precedence. This adds one narrow implementer/reviewer exchange and avoids knowingly accepting a broken required check.
- Start independent SB01 with a pinned manual assignment while helpers receive fixes; disjoint ownership and no product prerequisites make the cost limited to isolated rework.

Locks remain cooperative per-user host coordination. Before/after source checks do not freeze another writer. Reference hashes prove observed selected-file custody, not all donor activity. No library, compiler object, kernel, installed downstream or release capability is qualified by this setup record. No external push, publication, product migration or privileged probe occurred.
