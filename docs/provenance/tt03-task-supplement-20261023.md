# TT03 narrow task/subset supplement (Q-TT03-2)

ADOPTED design/review-only record, 2026-10-23, NOT_COPIED, qualification
NOT_RUN. Owner: SB01/controller lane. No TT03 execution, port, build,
probe or runtime qualification follows from this adoption.

WHAT: This supplement binds TT03 as an explicit consumer for the exact six
selected first-increment facets and nine exact frozen ranges from
P:src/process.rs and O:tests/target_lifecycle.rs. It chains the immutable
scope authority
[2026-10-22-next-host-scopes.json](admissions/2026-10-22-next-host-scopes.json)
SHA256 `e29cc889d99b73d3790a48fe555f4f74c60c4f718f7e184bd000f142a01e7bc1`
and the adopted Rev 12 consumer routing
[2026-10-22-tt03-selected-host-routing.json](admissions/2026-10-22-tt03-selected-host-routing.json)
SHA256 `7c487fe2934a1c10a3252312b3c1ef70757fdc13b5b2a0037d83d0422ccc1bad`.
The normative [task JSON](admissions/2026-10-23-tt03-task-supplement.json)
SHA256 `612efb3d36f71853c1dd89d3d76fb79968bbbf84daba5e73993719c0be0957d3`
(38563 bytes) carries the two file rows with TT03 in `references.tasks`,
the P/O donor records, the single TT03 port group and the
`tt03_task_supplement` adoption section with per-range admitted-scope
citations. No destination port exists.

WHY: The immutable `e29cc889` admission `references.tasks` omits TT03 on
these two rows (LX09/LX10/LX11/LX08/LX06 only). The exact r2 materializer
selection
[materializer-source-selection.json](../superpowers/specs/tt03-linux/materializer-source-selection.json)
SHA256 `99017919830f93965b169644471292538c3f837530a64f2eb3d2938eb62ed020`
requires this separately adopted task-consumer mapping before any
PORT/ADAPT/VECTORS_ONLY execution or receipt binding. Existing
OWNER-2026-10-18 host Apache-2.0 terms already cover the selected owned
scopes; this is no new author grant, whole-file permission, copying or
qualification.

The source bytes are fixed at P `2c2713e66292b0d2688508a25f79e813ae823d81`
and O `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`. Whole-file hashes
`b9b74b11…` (P, 89140 bytes) and `3e1457da…` (O, 125083 bytes) and all
nine range hashes were recomputed from the gitless frozen checkouts and
match the selection exactly (9/9). Gitless frozen checkout mappings use
their separate local captured histories, never a parent repository or
live origin. No donor test was executed.

## Selected first-increment subset

Every range sits inside a READY scope of `e29cc889`; the containing
admitted scope is cited per range. No selected range falls outside, so no
NEEDS_OWNER_GRANT is raised.

| Facet | File range | Mode | Admitted scope in e29cc889 |
|---|---|---|---|
| TT03-SF-06 `exited_unreaped` | P 2343–2367 | ADAPT | P [1929,2427] |
| TT03-SF-07 `run_pidfd_denial_case` lifecycle | P 2381–2384, 2388–2392, 2396–2400, 2404–2410 | ADAPT_LIFECYCLE_ONLY | P [1929,2427] ×4 |
| TT03-SF-09 same-birth zombie/counterexamples | P 1555–1617 | VECTORS_ONLY | P [1552,1617] |
| TT03-SF-10 absence-versus-unobserved | P 1745–1760 | VECTORS_ONLY | P [1739,1760] |
| TT03-SF-11 tricky comm/birth invariants | P 1883–1917 | ADAPT | P [1877,1917] |
| TT03-SF-14 no-control sentinel | O 359–375 | ADAPT_NO_CONTROL_FACET | O [358,375] |

Per-facet destination contracts, excluded context and
positive/oracle/bad-control/assertion/why preservation contracts are
unchanged from the exact r2 materializer selection and the adopted Rev 12
routing; the task JSON repeats them verbatim for receipt binding.

## Not selected

Six denial/namespace facets stay DEFERRED/uncopied: SF-02 (P 1972–2025),
SF-03 (P 2030–2036), SF-04 (P 2054–2180), SF-08 (P 2422–2426), SF-12
(pidns 595–635), SF-13 (pidns 729–772). Two in-range facets stay
REFERENCE_ONLY/uncopied: SF-01 (P 1945–1967), SF-05 (P 2185–2339).
SF-15 (O 336–356, stopped-child setup baseline) sits outside the O ready
scopes ([122,127],[129,138],[358,375]) and stays
UNGRANTED/REFERENCE_ONLY/uncopied; it is not selected, so no owner grant
is requested for it. P:src/pidns.rs receives no new TT03 selection here.
LX09 primary ownership, prior consumers, all dispositions and narrower
grants stay immutable. Original GPL observations, actual third-party
notices/options and existing provisional owner authority stay distinct
from destination terms.

## Remainder and receipt rule

This adoption answers Q-TT03-2 only, as design/review. The narrow
C7/delivery amendment (Q-TT03-1) is adopted separately in the same
Revision 14. All execution bindings remain UNBOUND: future base,
candidate selected-port receipts, actual destination hashes, C7
product/dependency/feature/lock/notice artifacts, provider/worker/
consumer/archive binaries, build/output resources, TT04 realms, EOF
assets, operation tracer, LX09 helper compatibility, final-index LX08
joint compatibility and private creator-guard source artifacts. All 152
delivery DAG rows and all fourteen P/seven F rows remain NOT_RUN. TT03
stays PLANNED; packet_ready stays false.

Each later selected-port receipt must bind this supplement plus chained
`e29cc889` and `7c487fe2`, the actual selected subset, destination
hashes/symbols and its assertion-level preservation map. Granted-but-
unused ranges cannot be reported as ported. Source readiness does not
make an executor packet ready or retire any later native, installed,
runtime, application-adapter or migration gate.
