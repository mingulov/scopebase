# TT03 execution-gate adoptions: task supplement (Q-TT03-2) + C7/delivery amendment (Q-TT03-1)

Status: both root adoptions authored and adopted as design/review only
(adoption-decisions Revision 14, 2026-10-23). TT03 r4 design RATIFIED,
task PLANNED, packet_ready=false. No PORT/ADAPT/VECTORS_ONLY execution,
port, build, probe, C7 union compile or runtime qualification is admitted
by this packet. The Rev 12/13 routing supplement plus RC7-R1-01 companion
remain the prior adopted design base; this packet layers the task-level
subset binding (Q-TT03-2) and the spec-level amendment adoption (Q-TT03-1)
on top of them.

## Status and scope

Adopted, unexecuted: [task supplement JSON](../../provenance/admissions/2026-10-23-tt03-task-supplement.json)
SHA256 `612efb3d36f71853c1dd89d3d76fb79968bbbf84daba5e73993719c0be0957d3`
(38563 bytes), [human record](../../provenance/tt03-task-supplement-20261023.md),
and adoption-decisions Revision 14. Verified by recomputation, not copied
from briefs: all nine selected range hashes (9/9) and both whole-file
hashes (`b9b74b11…`, `3e1457da…`) match the gitless frozen checkouts;
every selected range sits inside a READY scope of immutable `e29cc889`;
the r2 materializer selection file itself hashes `99017919…` (match).
No combined multi-file digest is claimed: per-file hashes above are the
verifiable record, and any combined-digest construction must be bound
before first dispatch if one is ever needed.

Q-TT03-2 ADOPTED: TT03 joins `references.tasks` (LX09/LX10/LX11/LX08/LX06/
TT03) on P:src/process.rs and O:tests/target_lifecycle.rs for exactly the
six first-increment facets: SF-06 ADAPT, SF-07 ADAPT_LIFECYCLE_ONLY, SF-09
and SF-10 VECTORS_ONLY, SF-11 ADAPT, SF-14 ADAPT_NO_CONTROL_FACET. Six
denial/namespace facets stay DEFERRED/uncopied; SF-01/SF-05 stay
REFERENCE_ONLY/uncopied; SF-15 stays UNGRANTED/REFERENCE_ONLY/uncopied.
new_source_grant=false; no NEEDS_OWNER_GRANT raised (no selected range
falls outside).

Q-TT03-1 ADOPTED as design only: the narrow C7/delivery amendment —
spec header plus C7 row, verification-plan C7/delivery section, and the
nine r2 materializer files (contract, fields, DAG, controls,
source-selection, delivery, preservation, spec, verification). The
unchanged r4 process/protocol/creator contract retains its predecessor
ratification (`ccde378b41f96e718628da7c780662c7fb490d81b59d08953b2db09410ac746d`).
The C7 selected union and strict whole-subject materialization are
adopted design, still uncompiled and unexecuted.

UNKNOWN — every execution binding; owner: future TT03 execution packet;
exit criterion: separately bound base/receipts/C7 artifacts/binaries/
resources per row below. UNKNOWN — independent re-review of this packet;
owner: root; exit criterion: Sol max review recorded before first
PORT/ADAPT dispatch consumes it.

## Trigger and invariant

TT03 cannot start PORT/ADAPT/VECTORS_ONLY execution until root adopts
both the source task/subset supplement and the scoped C7/delivery
amendment (verification plan: "Before execution, root adopts the source
task/subset supplement and the scoped amendment"). The invariant this
packet establishes: TT03's first-increment execution subset is exactly
nine frozen ranges, all inside already-granted ready scopes, with the
C7/delivery design frozen — while every actual artifact, binding and
measurement stays explicitly UNBOUND. The routing layer (Rev 12) answered
"which ranges may TT03 consume"; this task layer answers "which subset
gates first-increment execution, verified how"; the amendment layer
answers "which delivery/C7 design is frozen". None of them answers "what
was built, run or qualified" — nothing was.

## Selected source and license

Frozen inputs (read-only, never refreshed): P p11scope
`2c2713e66292b0d2688508a25f79e813ae823d81`, src/process.rs
`b9b74b11…` (89140 bytes); O OSSLscope
`4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`,
tests/target_lifecycle.rs `3e1457da…` (125083 bytes). Historical
GPL-3.0-or-later observations preserved per file; selected owned host
scopes use the existing provisional OWNER-2026-10-18 authorization with
Apache-2.0 host destinations (D03). No third-party implementation inside
the selected scopes; no whole-file or future-range grant; P:src/pidns.rs
receives no new TT03 selection. Range containment (admission e29cc889):
P [2343,2367] ⊂ [1929,2427]; P [2381,2384],[2388,2392],[2396,2400],
[2404,2410] ⊂ [1929,2427]; P [1555,1617] ⊂ [1552,1617]; P [1745,1760] ⊂
[1739,1760]; P [1883,1917] ⊂ [1877,1917]; O [359,375] ⊂ [358,375].
SF-15 O [336,356] is outside O's ready scopes and stays ungranted.

## Mechanism and destination

No destination code is written or selected by this packet. The JSON file
rows restate the Rev 12 ranges with TT03 in `references.tasks`; the new
`tt03_task_supplement` section adds per-range admitted-scope citations,
the recomputed verification record, the full 15-facet disposition table
(6 selected / 6 deferred / 3 reference-only), adoption status and the
UNBOUND remainder. Future PORT/ADAPT/VECTORS_ONLY dispatches consume this
subset through candidate-bound selected-port receipts that bind this
supplement plus chained `e29cc889` and `7c487fe2`. The amendment adoption
freezes the delivery interface surface (canonical fixture paths, strict
materializer, two literal manifests, explicit driver/binder CLIs, 152-row
command DAG, M01–M23 controls) and the C7 union
(rustix=1.1.5 defaults-off std/fs/pipe/process/event/net/time/try_close;
direct libc=0.2.191 in the standalone worker only; literal .toml.in
templates with frozen locks; external caller-anchored inventory) without
admitting any base, manifest, lock, tool, archive, build or execution.

## Original regression

Preserved, unrun: the six selected facet regressions from the exact r2
selection — `exited_unreaped` (WNOWAIT nonreaping witness),
`run_pidfd_denial_case` (lifecycle order only; denial helper and
destructor excluded), same-birth zombie plus transport/permission/
missing-birth counterexamples, NotFound-versus-denied/malformed absence
vectors, the nine-byte tricky-comm live/zombie/reaped invariant, and the
external no-control sentinel. Deferred and reference-only facet contexts
(SF-01–SF-05, SF-08, SF-12, SF-13, SF-15) are preserved in the JSON
without selection. No donor test was executed; no product test exists.

## Independent oracle

The oracle for this packet is recomputation, and it passed: 9/9 range
hashes plus 2/2 whole-file hashes recomputed from frozen bytes match the
selection; 9/9 containment checks against `e29cc889` scopes hold; 9/9
r2 materializer files match the ratified bytes; file rows equal the
adopted Rev 12 rows except the task-supplement mapping note; facet
contracts equal the r2 selection verbatim. RC7-R1-01 supervision and the
routing review record (2026-10-22-tt03-routing, verdict ADMIT
design/review only) are consumed as adopted records, not re-verified
here: their private prep bytes (sealed indexes `c0b0113e…`, `5f2ffc0d…`)
are outside this lane's reach and remained sealed per that record.

## Known-bad control and positive twin

- Out-of-scope range mutant: any selected range moved outside its cited
  admitted scope (e.g. SF-15's [336,356] treated as selected) must fail
  the containment check and raise NEEDS_OWNER_GRANT instead of inventing
  coverage. Positive twin: all nine selected ranges verify inside.
- Hash-drift mutant: any range byte change must fail the recomputed-hash
  comparison. Positive twin: 9/9 match.
- Scope-creep mutant: copying a deferred facet (e.g. SF-04 denial helper)
  or SF-15 under this supplement must fail receipt binding, which admits
  only the nine listed ranges. Positive twin: the JSON's deferred/
  reference-only tables name every unselected facet explicitly.
- Execution-confusion mutant: treating this adoption as PACKET_READY or
  quoting its static checks as run results must fail against the explicit
  UNBOUND list below. Positive twin: packet_ready=false is recorded in
  the JSON, the human record, the decisions entry and this packet.

## Contract references

Task TT03 (owned Linux fixture worker and independent raw truth),
requirements TT-R04/TT-R06/TT-R12 facets per traceability; H01/H02/H20,
G03/G04/G07/G08/G09/G11/G12/G13, UC05/UC10/UC13, TODO
B09/L02/L05/L06/T01/T02/T03/T04 per the TT03 port group. Ratified r4
design plus r2 materializer contracts; accepted TT02 borrowing
maintenance (`2921606`, receipt `dd9362f4…`) stays the bound prerequisite.
LX08 (34 selected/12 deferred objects), LX09 helper, TT04 provisioners
and the final-index joint compatibility record keep their own owners and
are not admitted here.

## Effects bounds and cleanup

Review-only packet authoring: four files written, zero builds, zero
probes, zero executions launched, zero commits. Changed paths:
`docs/provenance/admissions/2026-10-23-tt03-task-supplement.json` (new),
`docs/provenance/tt03-task-supplement-20261023.md` (new),
`docs/provenance/adoption-decisions.md` (Revision 14 entry appended),
`docs/issues/testkit/tt03-adoption.md` (this file, new). The ratified r4
spec was not edited. No cleanup obligation exists; no owner, lease,
worktree, lock or donor state was touched.

## Remaining UNBOUND list (both adoptions)

Future execution base; candidate selected-port receipts; actual
destination hashes; actual C7 product/dependency/feature/lock/notice
artifacts (the union is still uncompiled — the historical dead-caller
proof `6aaf00ab…` does not cover it); provider/worker/consumer/archive
binaries; build/output resources; TT04 realms; EOF assets; operation
tracer; LX09 helper compatibility; final-index LX08 joint compatibility;
private creator-guard source artifacts; all 152 delivery DAG rows
(NOT_RUN); all fourteen P and seven F rows (NOT_RUN); installed operator
delivery. TT03 stays PLANNED with packet_ready=false until a future
execution packet binds these.
