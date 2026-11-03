# Integration evidence audit — tier verdicts (2026-11-02)

## Method

Input: the [2026-11-01 census](2026-11-01-integration-evidence-census.md)
(51/51 subjects resolve, 51/51 records exist, zero orphan acceptances),
each record's stated review lanes/verdicts (extracted
`/tmp/sregen-closeout/record-signals.txt`, scratch), and the
[S-regen report](2026-11-02-s-regen-report.md) for post-acceptance delta
implications. Every verdict below binds the task to its review artifact
(lanes + verdict + subject); root re-verification is evidence, never a
review lane.

## Tier rules (applied uniformly)

- **FULL**: two independent review lanes (different reviewers/methods)
  with recorded APPROVE / zero open findings at acceptance; fix rounds
  (if any) re-reviewed to APPROVE; provenance grants resolved; no
  post-acceptance code deltas except independently reviewed ones.
- **ALPHA**: anything else — single review lane, lane ACCEPT without a
  second lane, integrator-only verification, or pending review
  follow-ups. Alpha is an explicit tier, not a failure.
- Post-acceptance deltas: S-regen (S160–S229, batch1 R5 READY +
  batch2 R2 READY, `gpt-6.1-sol` medium) and R-stream (C7/C8/R-set,
  R2 READY) deltas HAVE fresh independent review, satisfying the
  "fixup deltas get fresh independent review" rule for those
  surfaces. Deltas are mapped per task family below.
- License grants: the 10-22 lane records for BP04/BP06/CP07/CP08
  withheld acceptance pending owner source grants; the 10-23 blanket
  grant `OWNER-2026-10-23` (AGENTS.md alpha mode) resolved
  user-owned slices afterward. Third-party/upstream lines were never
  covered and remain excluded by the grant's own terms.

## Result: 12 FULL, 39 ALPHA, 0 unbound

No aggregate-green claim is made: 39 acceptances are alpha-tier,
BP10/CP12 still owe fresh independent review, and the S-regen fix
tree is uncommitted. BP10/CP12 review is a required follow-up, not
part of this verdict pass.

### FULL tier (12)

| Task | Subject | Record | Lanes (verdict) | S-delta implication |
|---|---|---|---|---|
| BP02 | 8f10d948bdd6 | 2026-10-22-bp02-maps.md | independent pre-guest APPROVE + independent post-guest APPROVE + root audit | BP-family S-ids (below); deltas B1R5 READY |
| BP03 | bfb94520bda8 | 2026-10-22-bp03-host.md | independent final APPROVE + Codex max BLOCK/3→fix→APPROVE, zero open | BP-family S-ids; deltas B1R5 READY |
| BP04 | 8645321a0c61 | 2026-10-22-bp04-bp06.md | wave-9 scoped APPROVE + Codex re-review APPROVE; grants via blanket | BP-family S-ids; deltas B1R5 READY |
| BP06 | 8645321a0c61 | 2026-10-22-bp04-bp06.md | wave-9 scoped APPROVE + Codex re-review APPROVE; grants via blanket | BP-family S-ids (S182 ring); deltas B1R5 READY |
| CP06 | e6fe76c0add0 | 2026-10-22-cp06-views.md | independent final APPROVE + Codex max APPROVE, zero open | CP-family S-ids; deltas B1R5 READY |
| CP07 | 046d35fb0999 | 2026-10-22-cp07-cp08-cp09.md | wave-9 scoped APPROVE + Codex re-review APPROVE; grants via blanket | CP-family S-ids; deltas B1R5 READY |
| CP08 | 046d35fb0999 | 2026-10-22-cp07-cp08-cp09.md | wave-9 scoped APPROVE + Codex re-review APPROVE; grants via blanket | CP-family S-ids; deltas B1R5 READY |
| CP09 | 046d35fb0999 | 2026-10-22-cp07-cp08-cp09.md | wave-9 scoped APPROVE + Codex re-review APPROVE (NEW code, no donor) | CP-family S-ids; deltas B1R5 READY |
| TT02 | 04a47f052a7a | 2026-10-22-tt02-engine.md | two Sol max reviews + Daybreak final approval (stop-order defect closed) | testkit S-ids + R-stream; deltas READY |
| TT06 | e34ff709f39f | 2026-10-22-tt06-sdk01-tt08core.md | wave-14 scoped APPROVE + Codex final APPROVE (residual F4 fixed) | testkit S-ids; deltas B1R5/B2R2 READY |
| SDK01 | 3336d57c2c4f | 2026-10-22-tt06-sdk01-tt08core.md | wave-14 scoped APPROVE + Codex final APPROVE | SDK-family S-ids; deltas B1R5/B2R2 READY |
| SDK02 | b11d8c96d04a | 2026-10-23-sdk02-tt03adopt.md | wave-18 scoped APPROVE + Codex re-review APPROVE | SDK-family S-ids; deltas B1R5/B2R2 READY |

### ALPHA tier (39)

Single review lane (+ root re-verification) unless noted. BARE =
census class (TODO row carries no acceptance note; registry is the
record — see decision below).

| Task | Subject | Record | Lane (verdict) | S-delta implication |
|---|---|---|---|---|
| BP01 | c0d35832d401 | 2026-10-18-bp01-foundation.md | Astra independent, no findings (BARE) | BP-family S-ids; deltas B1R5 READY |
| BP05 | f1a34e46069c | 2026-10-23-bp05-custody.md | lane APPROVE, 6 minors closed | BP-family S-ids; deltas B1R5 READY |
| BP07 | 0e055c9c7dc6 | 2026-10-23-bp07-writer.md | lane ACCEPT (bounded slice) | BP-family S-ids (S186 writer); deltas B1R5 READY |
| BP08 | 9641a17bf324 | 2026-10-23-bp08-identity.md | lane ACCEPT (bounded increment) | BP-family S-ids; deltas B1R5 READY |
| BP09 | 9c4cf63787f1 | 2026-10-23-bp09-btf.md | lane PASS, minors closed | BP-family S-ids (S160/S163/S181 BTF); deltas B1R5 READY |
| BP10 | d66350ea71df | 2026-10-23-wave29.md | integrator verification ONLY — fresh independent review REQUIRED (follow-up) | BP-family S-ids (S161/S168/S183 adapters); deltas B1R5 READY |
| CP01 | 69c59459486d | 2026-10-18-cp01-foundation.md | independent repair + integration reviews (BARE) | CP-family S-ids; deltas B1R5 READY |
| CP02 | 365a312c5673 | 2026-10-18-cp02-values.md | independent review (BARE) | CP-family S-ids; deltas B1R5 READY |
| CP03 | c145e28f1f84 | 2026-10-18-cp03-counters.md | Astra independent, no findings | CP-family S-ids; deltas B1R5 READY |
| CP04 | f2952ee8661e | 2026-10-18-cp04-insertion.md | independent review + byte audit | CP-family S-ids; deltas B1R5 READY |
| CP05 | 7d992e12bd73 | 2026-10-22-cp05-generations.md | independent R1 source + R2 delivery (BARE) | CP-family S-ids; deltas B1R5 READY |
| CP10 | f9eefd03f9da | 2026-10-23-cp10-replay.md | lane behavior PASS + RATIFY-2026-10-23-CP10 (spec amended) | CP-family S-ids (S189–S193 replay); deltas B1R5 READY |
| CP11 | 9552e961582f | 2026-10-23-cp11-consumers.md | lane ACCEPT, no blocking | CP-family + consumer S174/S202–S205; deltas B1R5 READY |
| CP12 | 765402017262 | 2026-10-23-wave29.md | integrator verification ONLY — fresh independent review REQUIRED (follow-up) | CP-family S-ids; deltas B1R5 READY |
| LX01 | 69c59459486d | 2026-10-18-lx01-foundation.md | Astra independent x2 (BARE) | LX-family S-ids; deltas B1R5 READY |
| LX02 | 365a312c5673 | 2026-10-18-lx02-held-file.md | independent successor IR-01–IR-06 (BARE) | LX-family S-ids; deltas B1R5 READY |
| LX03 | 1f25798bfeef | 2026-10-18-lx03-reads.md | Astra repair review | LX-family S-ids; deltas B1R5 READY |
| LX04 | b832dcab35fb | 2026-10-18-lx04-controls.md | Astra critical review (BARE) | LX-family S-ids; deltas B1R5 READY |
| LX05 | 04a47f052a7a | 2026-10-22-lx05-proc.md | Daybreak A3 + Daybreak final, no new counterexample (one lane, two rounds) | LX-family S-ids; deltas B1R5 READY |
| LX06 | 72c749584c70 | 2026-10-23-lx06-mapping.md | lane ACCEPT (bounded increment) | LX-family S-ids; deltas B1R5 READY |
| LX10 | 019347911dff | 2026-10-23-lx10-walk.md | lane APPROVE, minors closed | LX-family S-ids (S206/S207 walk); deltas B1R5 READY |
| LX11 | bdfc3d0f66c3 | 2026-10-23-lx11-clients.md | lane ACCEPT | LX-family + consumer S172/S173; deltas B1R5 READY |
| RL01 | 99b5b1ca002e | 2026-10-23-rl01-review.md | lane ACCEPT (accepted-only scope, per RL01 decision; process task, no code) | none — no code surface |
| SB01 | f1280b010099 | 2026-10-18-sb01-foundation.md | independent + Astra reviews (BARE) | none — tooling untouched |
| SB02 | 4bc7ae95c0cc | 2026-10-18-sb02-foundation.md | independent + Astra reviews (BARE); v4 successor 65/65 | S210 ci_local.sh adjacent; deltas B1R5 READY |
| SB03 | f81f121f7ec7 | 2026-10-18-sb03-foundation.md | independent + Astra repair reviews (BARE) | none — tooling untouched |
| SDK03 | c86ed4d71c17 | 2026-10-23-sdk03-metadata.md | lane ACCEPT, no blocking | SDK-family S-ids; deltas B1R5/B2R2 READY |
| SDK04 | c9ff38227b26 | 2026-10-23-sdk04-observer.md | lane ACCEPT-adapted (binary deviation recorded) | SDK-family S-ids (S212/S213/S218 observer); deltas READY |
| TC01 | 5d8295684180 | 2026-10-23-tc01-register.md | lane APPROVE, 3 minors closed | testkit S-ids; deltas B1R5/B2R2 READY |
| TC02 | aca297200c67 | 2026-10-23-tc02-closure.md | lane PASS, no blocking | testkit S-ids (S221 drivers); deltas READY |
| TC03 | 98097ff0e841 | 2026-10-23-tc03-isa.md | lane ACCEPT + 1 minor | testkit S-ids; deltas READY |
| TC04 | bf0077befa72 | 2026-10-23-tc04-atomics.md | lane ACCEPT (oracle arms cited) | testkit S-ids (S178/S227/S228 atomics); deltas READY |
| TC05 | fd334dd705e2 | 2026-10-23-tc05-graph.md | lane ACCEPT-bounded (deviations recorded) | testkit S-ids (S179/S228 graph); deltas READY |
| TC06 | f1bb43f358d8 | 2026-10-23-tc06-prune.md | lane ACCEPT | testkit S-ids (S168/S227/S228 rules); deltas READY |
| TT01 | 6b225d1ae8d3 | 2026-10-18-tt01-registry.md | Astra repair review (BARE) | testkit S-ids + R-stream; deltas READY |
| TT04 | fbd4ec7eb762 | 2026-10-23-tt04-cells.md | lane ACCEPT + 1 nit | testkit S-ids (S229 cells); deltas READY |
| TT07 | 9279426138d1 | 2026-10-23-tt07-operator.md | lane ACCEPT | conformance S196–S201; deltas B1R5 READY |
| TT08 | 043e019f697c | 2026-10-23-tt08-tail.md | lane APPROVE (ci.yml deviation accepted) | testkit S-ids (S222/S229 select); deltas READY |
| TT09 | a3923c70f1f4 | 2026-10-23-tt09-perf.md | lane ACCEPT + 2 minors | testkit S-ids (S223 resource); deltas READY |

## S-id family legend (all deltas externally READY)

- BP-family (`scopebase-bpf`): S160, S161, S162, S163, S164, S165,
  S166 (REFUTED, no delta), S167, S168, S180–S188 — batch1 R5 READY.
- CP-family (`scopebase-capture`): S169, S170, S171, S189–S195 —
  batch1 R5 READY.
- Conformance (`scopebase-conformance`, TT07): S196–S201 — batch1
  R5 READY.
- LX-family (`scopebase-linux`): S175, S206–S211 — batch1 R5 READY.
- SDK-family (`scopebase-sdk`): S176, S212–S218 — batch1 R5 /
  batch2 R2 READY.
- Testkit-family (`scopebase-testkit`): S177, S178, S179,
  S219 (REFUTED, no delta), S220–S229 — batch1 R5 / batch2 R2
  READY; plus R-stream C7/C8/R-set (R2 READY) on the fixture
  surface.
- Consumers: S172, S173 (LX11 clients), S174, S202–S205 (CP11
  clients) — batch1 R5 READY.
- Tooling: S210 (`tools/qualification/ci_local.sh`) — batch1 R5
  READY. SB01/SB03 and RL01 have no delta surface.

Per-finding verdicts, fix evidence and round trails: the [S-regen
report](2026-11-02-s-regen-report.md). No S-finding remains
unadjudicated: 68 PASS, 2 REFUTED, 0 DEFERRED, 0 open.

## BARE-row decision

The 13 census-BARE TODO rows (BP01, BP03, CP01, CP02, CP05, CP06,
LX01, LX02, LX04, SB01, SB02, SB03, TT01) keep the registry record
as authoritative; one-line acceptance summaries were added to those
TODO rows at audit close (same commit as this verdict doc) so the
ledger reads without a registry join. Summaries change no status
and no count (checker re-verified).

## Required follow-ups (not part of this pass)

1. BP10 + CP12 fresh independent review (second lane; zero-open
   bar) — their acceptances rest on integrator verification only.
2. Traceability tier field: verdicts live in this doc (+ amendment
   entry). Adding a machine-readable tier to the registry schema is
   an owner decision (schema + checker impact); until then this
   doc is the tier record.
3. Commit of the uncommitted S-regen fix tree (owner authorization
   pending) — tier verdicts assume those deltas land as reviewed.

## Audit verdict

**Integration evidence audit CLOSED 2026-11-02: 51/51 acceptances
bound (12 FULL, 39 ALPHA), S-implications mapped, 0 unadjudicated
findings.** No aggregate-green or qualification claim is made in
this pass. Next: product frontier in TODO/traceability dependency
order (TT03 F-rows/final-index, then the LX08×TT03-final-index
joint record before LX08 dispatch).
