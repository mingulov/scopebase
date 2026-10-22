# View isolation: queries must not taint retained evidence

CP06 delivers a bounded epoch-local claim ledger, call-local query overlays,
explicit required-feed presence and checked holder corrections. Its [exact
contract](../../superpowers/specs/2026-10-22-scopebase-cp06-views.md) and
[verification plan](../../superpowers/plans/2026-10-22-scopebase-cp06-verification.md)
retain the original defect populations. The repaired candidate lives
uncommitted in the CP06 source worktree; early-review findings ESR1-01/02/03
and the two delivery gaps are repaired with causal bad/restored controls.
Candidate implementation is separate from independent final review, the
atomic root/source freeze, source/archive qualification and any task, profile
or migration acceptance.

A partial query must never rewrite retained evidence, reorder another view's
selection or leak a prefix of a refused whole. `ClaimLedger::record` retains
every accepted occurrence with its provenance, unit and magnitude, staging
the sorted claim set with a forward merge of old claims and sorted affected
IDs: monotone cursors, one emission per entry, OR of the damaging flag on
overlaps, no shifting or revisiting, so staging past sorting is `O(C + A)`.
`snapshot` returns caller-selected-order assessments without changing the
ledger; whole-result reason admission precedes output allocation, so no
refused prefix escapes. The `QueryOverlay` is call-local: outsiders are
ignored, and re-sorting selected output by ClaimId is a refused fabrication.
Error order is domain, length, duplicates, projected claims, F, R,
reservation; all fallible work precedes the library-owned commit moves.

Required-feed presence is independent of numeric loss totals. `FeedRegistry`
checks full epoch, declared membership, then duplicate presence, and commits
exactly one bit per accepted feed with no allocation. `finish` is an
observational, idempotent presence check: a missing-feed refusal does not
seal the registry, and the missing declared feed can still be supplied later.
Presence of Unknown loss satisfies cardinality without establishing absence
of loss; first accepted presence, duplicate refusal and missing-feed refusal
are preserved, with no lenient rollup.

A correction replaces one complete caller-routed value. Construction is
exactly from+1 with `checked_add`, refusing MAX with ArithmeticOverflow;
`apply` checks the complete epoch before the exact current revision, then
moves the whole payload without payload Eq/Clone/Debug. Complete-key routing
refuses same-token/different-namespace, device or generation holders before
changing anything. A normally returned refusal returns the unchanged
original owner while the rejected replacement is consumed and dropped exactly
once: the foreign-epoch journal asserts DomainMismatch, unchanged original
label/value/revision, `[rejected]` before caller disposal and `[rejected,
original]` after, with no duplicate destruction. Same metadata cannot detect
a caller's wrong target key, and nothing here distributes to other holders.

The controls keep 25 stable case IDs and three fixed journal populations
across the unit, ledger and revision journals, with fifteen narrow adapted
original subsets (K `d153f3a`, M `8307a17`, O `4bcb24c`) run as regression
vectors rather than donor-reducer executions. Every repaired finding carries
an active bad subject that fails its named semantic assertion plus a
byte-restored twin: the overlap-missing merge, the five V06/V08/V09/C03/C06
mutants, the foreign `mem::forget` leak, the ignored-journal omission
against the fixed required-name manifest, and the explicit build-wrapper
path/hash binding. The shared injected/ordinary reserve mapping, zero-reserve
preflight visits and the reserve/commit boundary from A01 remain intact.

All mechanisms here are T0/T1 host evidence. No installed operator, runtime
profile, reducer behavior, application migration or duplicate retirement is
qualified. CP10 owns public audit/export and strict replay, CP11 real
reducers with holder routing and protected histories, CP13/TT installed
exact-consumer conformance, and MG02–MG04 the actual application migrations
with rollback proof. No donor duplicate is removed here.
