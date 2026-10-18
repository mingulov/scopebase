# TT02 first critical review and required repairs

Date: 2026-10-18. **MUST_FIX; TT02 remains in progress.** Two independent
GPT-6.1-Sol max reviews examined frozen candidate
`a45c23da7a843fca12e23332d825a08c531a1113`. The controller inspected the relevant
implementation and accepted the following repair groups. These are corrections
to the [existing engine contract](../superpowers/specs/2026-10-18-scopebase-tt02-engine.md),
not additional accepted tasks or a reduction of its requirements.

| Group | Defect and consequence | Required exit evidence |
|---|---|---|
| A1 | Lower selected limits are not consistently reapplied to contract structure, serialization and nested values | Lowered depth/edges, receipt, labels, effects, artifact and observation/error limits refuse at the correct boundary; equal valid twins pass |
| A2 | Vec-to-Arc conversion temporarily duplicates a retained vector payload | Account for the actual peak or move the payload without copying; exercise the 8 MiB/9 MB case and later-vector failure with persistent meter/cursor custody |
| A3 | The builtin authored T0 vector population can be retagged as higher-tier evidence | T3/T4-retagged execution and import controls cannot qualify; the actual T0 positive remains valid |
| A4 | Actual executable/archive measurements do not identify the implementations selected by the client | Bind measured case/oracle/control/fixture source members to the actual build; a different valid registered implementation fails the binding assertion |
| A5 | Invalid digest syntax reaches file reads before rejection | Invalid descriptor produces zero opens/reads/hash progress; valid descriptor with changed bytes fails separately after actual measurement |
| B1 | A returned effect-bearing response with an unrecorded after checkpoint can omit its ledger mirror | Every retained typed return has one exact mirror; omitted mirrors reject while entered/no-return partial tails remain incomplete |
| B2 | Expected evidence is validated after oracle calls and possibly later invocations | Wrong key/oracle/schema/ledger/truth stops normal work before judge or later prepare, retaining the actual response and required retirement |
| B3 | Missing case rows can precede later normal-work evidence | Only genuine unfinished trailing omissions are accepted; interior gaps and later sampled normal work reject |
| B4 | Retirement remaining time and hook duration use different starting instants | Request-preparation delay cannot turn an honest deadline overrun into InvalidProtocol; transitions remain and fixed allowance is not refreshed |
| B5 | Derived diagnostic/capability/effect copies are not fully charged | Reserve engine-owned payload before growth, including repeated reconstruction; insufficient space preserves bounded partial custody and cannot qualify |

Each repair requires an independently authored failing regression and restored
positive, followed by affected checks on the new frozen bytes and independent
review of the correction. Existing successful campaigns remain evidence for the
branches they covered. They do not overrule these counterexamples, certify the
repair or justify repeating unrelated campaigns.

The permitted separate host-binding exercise remains available. Its selected
source inventory must describe implementations actually used; an archive merely
containing other registered sources is insufficient. Generated/imported metadata
remains a descriptive trust boundary, not authentication of dishonest providers.

The worker's one-line uncommitted linked-control source-copy correction was
preserved separately. Only its linked-controls-v2 receipt used that changed
driver; it is not attributed to the frozen commit. The controller authorized it
to enter the repair candidate. Shared source-tree staging limits and dependency
policy/lock activation remain separately owned controller work.

Exact reports, bindings and root ruling are retained under
`.scopebase/jobs/tt02-engine-20261018/amendments/critical-review-r1-20261018/`.
The amendment index SHA256 is
`481a63bba72429945fdf98c0f782c68a48dd6b579792d7ba079464651ac3c757`;
the controller ruling SHA256 is
`6d226d36a65b365b50cb98d0cb66ef1fa78fdf4527699156b5698c95698f94bf`.
The reviews ran no compiler or live kernel tests. Their static findings require
the focused runtime controls above before closure. No profile qualification or
release claim follows.
