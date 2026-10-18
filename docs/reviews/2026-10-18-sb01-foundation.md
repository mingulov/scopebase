# SB01 foundation acceptance

Date: 2026-10-18. Controller acceptance of **SB01**, reviewed subject
`f1280b010099100daeec9fd2233bbeacea5443e0`. This accepts the source-intake,
provenance, contract and validation foundation. Shared Rust libraries, dependency
qualification, installed consumers and runtime profiles remain unimplemented.

## Accepted scope and decisions

The original candidate `8417beead68a03ecaff361d0d76da5f38c09820f` supplied the
source inventory, contract/evidence documents, issue index and intake validator.
The [bounded repair packet](../superpowers/plans/2026-10-18-scopebase-plan-repair.md#repair-intake-validation)
preserved those inputs while repairing source custody, nested references and the
source/destination licensing distinction. The [decision register](../superpowers/specs/2026-10-18-scopebase-decisions.md)
remains normative; its licensing choice is provisional.

- Local Git inspection explicitly disables lazy fetching, replacement objects
  and optional locks, and treats paths literally. Missing local objects produce
  INCOMPLETE/exit 2; demonstrated source contradictions produce INVALID/exit 3.
  Unsupported Git controls leave verification incomplete. No implicit fetch or
  donor mutation is permitted.
- Family, obligation, donor, path, group, symbol and line references are checked
  together. Valid documentation with no symbols remains admissible.
- Schema 2 distinguishes historical source observations, owner authorization,
  destination terms, artifact roles and actual third-party fragments/options.
  Missing SPDX alone is not an automatic prohibition on author-owned code.
  Structural validity does not adjudicate ownership or authorize a source port.
- Original observations were retained: 124 files, eight authorities, two dirty
  input hashes, 1,529 symbol candidates and 389 regression candidates. H01–H32
  and the original 178 source-obligation rows were unchanged; H33 and its 179th
  mapping were appended with an explicit planning origin.
- There are 121 NEEDS_DECISION adoption records and three technical
  PRODUCT_LOCAL/REFERENCE_ONLY records. No source slice is marked ready to copy.
  Actual component ports must refresh their selected donor bytes and resolve
  their own adoption and regression-preservation records.

## Review and corrective evidence

Independent review identified and closed four concrete validator defects:
implicit partial-clone fetching (R1), unchecked nested preservation references
(R2), missing promised root trees misclassified as invalid (R1b), and known
non-commit objects misclassified as unavailable (R1c). The latter pair was found
by independent real-Git controls after the first repair.

The final two-file correction has diff SHA-256
`f693c272e53c760e4d128ac331aa759c2c438afcddf52f0f9336c0f5b51dfdd8`.
Independent Astra review approved specification compliance and task quality at
the exact subject above, with no remaining findings. The preceding review's
preservation, adoption and nested-reference conclusions were unaffected by that
correction. Reviewers inspected worker executions and ran discriminating checks
where needed; the final scoped review did not repeat unchanged suites.

The controller independently compared original source observations against the
repaired ledger. The retained source-refresh artifact has SHA-256
`3665452e50a77e6c244b2e686b64470ce751b1bdead0fb8b2d83bc28a3dc40f3`.
Private briefs, immutable review packages, complete logs and original observations
remain in the preserved setup and M0 integration worktrees. They are development
evidence, not package contents or runtime authority.

## Verification and limits

| Command / check | Observed result and subject |
|---|---|
| `python3 -m unittest discover -s tools/planning/tests -v` | 54 tests PASS at `f1280b010099100daeec9fd2233bbeacea5443e0`; 19.074 seconds |
| Focused real-Git controls | Seven PASS, including complete twins, absent promised blob/tree, unavailable commit, wrong object type, wrong tree and absent path; transport sentinels unused and donor stores/checkouts unchanged |
| Focused RED controls before final repair | Two tests exposed three intended assertion failures: missing root tree and available tree/blob identities; no setup or custody failure |
| `python3 -m unittest discover -s tests/orchestration -v` | 92 tests PASS at `328454059cec78686be4b387e5624f4749332e33`; 48.494 seconds. Later changes do not touch this tooling boundary |
| `python3 tools/planning/check_traceability.py docs/superpowers/plans/2026-10-17-scopebase-traceability.json` | VALID/STRUCTURAL at final implementation; source verification NOT_RUN, qualification NOT_EVALUATED |
| `python3 tools/check_planning_docs.py` and `git diff --check` | Rechecked with acceptance bookkeeping; see the current handoff for integration state |

The 54-test log SHA-256 is
`f7a08d35e049410a5e27562367af045ef39ac21efce6cd451b1afc7a9aaab31a`.
Tests use owned fixtures and disposable Git repositories. No current donor scan,
source copying, Cargo dependency probe, final BPF object, privileged kernel
test, installed consumer, migration or publication is claimed by this acceptance.

SB02 is now dependency-ready. Its workspace/dependency decisions and subsequent
component contracts must satisfy their own tests and independent review before
acceptance. Requirements, regression families and support profiles remain open.
