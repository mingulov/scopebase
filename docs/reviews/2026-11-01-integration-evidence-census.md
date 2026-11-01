# Integration evidence census — 2026-11-01 (EVIDENCE ONLY)

Scope: mechanical inventory for the integration evidence audit (TODO
corrections row). For each of the 51 ACCEPTED tasks it records the
registry acceptance object (subject commit + evidence record), verifies
both resolve, and classifies the TODO row's acceptance note. It renders
NO tier verdicts (full vs alpha), NO S-implication calls, and NO
aggregate-green claim — those wait for the owner S-call plus the audit
pass. Method: registry dump + TODO accepted-row join + `git cat-file -t`
per subject + `isfile` per record, run 2026-11-01 on `main`.

## Existence results

- 51/51 subject commits resolve (`git cat-file -t` → commit).
- 51/51 evidence records exist on disk.
- 51/51 accepted tasks have a TODO accepted row (zero orphan acceptances).

## Observations (census-level, not verdicts)

- 13 TODO rows carry NO acceptance note (prerequisites only) although the
  registry holds a record: BP01, BP03, CP01, CP02, CP05, CP06, LX01, LX02,
  LX04, SB01, SB02, SB03, TT01. The audit must decide whether to
  summarize these records into TODO or accept the registry as the record.
- Shared evidence records: `2026-10-22-bp04-bp06.md` (BP04+BP06),
  `2026-10-22-cp07-cp08-cp09.md` (CP07+CP08+CP09),
  `2026-10-23-wave29.md` (BP10+CP12),
  `2026-10-22-tt06-sdk01-tt08core.md` (TT06+SDK01).
- Shared subject commits: `8645321a0c61` (BP04+BP06), `046d35fb0999`
  (CP07+CP08+CP09), `04a47f052a7a` (LX05+TT02, different records),
  `69c59459486d` (CP01+LX01), `365a312c5673` (CP02+LX02).
- TODO-note classes: BARE 13, SCOPED-PKG 6, TWO-LANE 4, ALPHA+ROOT 25,
  ALPHA 3. Class reflects the TODO note's wording only, not a tier call.

## Census table

| Task | Subject | Record | Class | TODO note (truncated) |
|---|---|---|---|---|
| BP01 | c0d35832d401 | 2026-10-18-bp01-foundation.md | BARE | prerequisites only |
| BP02 | 8f10d948bdd6 | 2026-10-22-bp02-maps.md | SCOPED-PKG | scoped package + owned-kernel evidence |
| BP03 | bfb94520bda8 | 2026-10-22-bp03-host.md | BARE | prerequisites only |
| BP04 | 8645321a0c61 | 2026-10-22-bp04-bp06.md | ALPHA+ROOT | O pin byte-identical; bpf 147/0 root |
| BP05 | f1a34e46069c | 2026-10-23-bp05-custody.md | ALPHA+ROOT | retirement 24/24 root; live cells later |
| BP06 | 8645321a0c61 | 2026-10-22-bp04-bp06.md | ALPHA+ROOT | attribution byte-verified; bpf 147/0 root |
| BP07 | 0e055c9c7dc6 | 2026-10-23-bp07-writer.md | ALPHA+ROOT | bounded host slice; writer_identity 24/24 root |
| BP08 | 9641a17bf324 | 2026-10-23-bp08-identity.md | ALPHA+ROOT | bounded host increment; 15/15 root |
| BP09 | 9c4cf63787f1 | 2026-10-23-bp09-btf.md | ALPHA+ROOT | btf 37/0 root; locked btf-rs |
| BP10 | d66350ea71df | 2026-10-23-wave29.md | ALPHA | scoped adapters green; live to BP11/TT05 |
| CP01 | 69c59459486d | 2026-10-18-cp01-foundation.md | BARE | prerequisites only |
| CP02 | 365a312c5673 | 2026-10-18-cp02-values.md | BARE | prerequisites only |
| CP03 | c145e28f1f84 | 2026-10-18-cp03-counters.md | SCOPED-PKG | exact counter/loss evidence; runtime open |
| CP04 | f2952ee8661e | 2026-10-18-cp04-insertion.md | SCOPED-PKG | f2952ee; ABI/producer + migration separate |
| CP05 | 7d992e12bd73 | 2026-10-22-cp05-generations.md | BARE | prerequisites only |
| CP06 | e6fe76c0add0 | 2026-10-22-cp06-views.md | BARE | prerequisites only |
| CP07 | 046d35fb0999 | 2026-10-22-cp07-cp08-cp09.md | ALPHA+ROOT | capture 193/0 root |
| CP08 | 046d35fb0999 | 2026-10-22-cp07-cp08-cp09.md | ALPHA+ROOT | capture 193/0 root |
| CP09 | 046d35fb0999 | 2026-10-22-cp07-cp08-cp09.md | TWO-LANE | NEW model-only; two-lane APPROVE |
| CP10 | f9eefd03f9da | 2026-10-23-cp10-replay.md | ALPHA+ROOT | replay 15/15 + neutral 8/8 root; ratified |
| CP11 | 9552e961582f | 2026-10-23-cp11-consumers.md | ALPHA+ROOT | 3 consumers 8/8 each root |
| CP12 | 765402017262 | 2026-10-23-wave29.md | ALPHA | 10/10 pilot + 2 experiments; export deferred |
| LX01 | 69c59459486d | 2026-10-18-lx01-foundation.md | BARE | prerequisites only |
| LX02 | 365a312c5673 | 2026-10-18-lx02-held-file.md | BARE | prerequisites only |
| LX03 | 1f25798bfeef | 2026-10-18-lx03-reads.md | SCOPED-PKG | bounded reader; mapped-image + installed open |
| LX04 | b832dcab35fb | 2026-10-18-lx04-controls.md | BARE | prerequisites only |
| LX05 | 04a47f052a7a | 2026-10-22-lx05-proc.md | SCOPED-PKG | scoped package + integration evidence |
| LX06 | 72c749584c70 | 2026-10-23-lx06-mapping.md | ALPHA+ROOT | bounded increment; mapping_contract 20/20 root |
| LX10 | 019347911dff | 2026-10-23-lx10-walk.md | ALPHA+ROOT | walk 34/0 root; D03 consumed |
| LX11 | bdfc3d0f66c3 | 2026-10-23-lx11-clients.md | ALPHA+ROOT | consumers 10/10 + 8/8 root |
| RL01 | 99b5b1ca002e | 2026-10-23-rl01-review.md | ALPHA | accepted-only; 6 negatives; NX deferred |
| SB01 | f1280b010099 | 2026-10-18-sb01-foundation.md | BARE | prerequisites only |
| SB02 | 4bc7ae95c0cc | 2026-10-18-sb02-foundation.md | BARE | prerequisites only |
| SB03 | f81f121f7ec7 | 2026-10-18-sb03-foundation.md | BARE | prerequisites only |
| SDK01 | 3336d57c2c4f | 2026-10-22-tt06-sdk01-tt08core.md | TWO-LANE | NEW sdk package; two-lane review |
| SDK02 | b11d8c96d04a | 2026-10-23-sdk02-tt03adopt.md | TWO-LANE | NEW bindings; two-lane + 4 mutation fixes |
| SDK03 | c86ed4d71c17 | 2026-10-23-sdk03-metadata.md | ALPHA+ROOT | sdk 62/0 root |
| SDK04 | c9ff38227b26 | 2026-10-23-sdk04-observer.md | ALPHA+ROOT | in-crate 11/11 root; binary follow-up |
| TC01 | 5d8295684180 | 2026-10-23-tc01-register.md | ALPHA+ROOT | schema 14/14 root |
| TC02 | aca297200c67 | 2026-10-23-tc02-closure.md | ALPHA+ROOT | executor 55/55 + invoke 16/16 root |
| TC03 | 98097ff0e841 | 2026-10-23-tc03-isa.md | ALPHA+ROOT | object_isa 24/24 root |
| TC04 | bf0077befa72 | 2026-10-23-tc04-atomics.md | ALPHA+ROOT | atomic_oracle 17/17 root |
| TC05 | fd334dd705e2 | 2026-10-23-tc05-graph.md | ALPHA+ROOT | bounded slice; object_graph 20/20 root |
| TC06 | f1bb43f358d8 | 2026-10-23-tc06-prune.md | ALPHA+ROOT | object_rules 31/31 root |
| TT01 | 6b225d1ae8d3 | 2026-10-18-tt01-registry.md | BARE | prerequisites only |
| TT02 | 04a47f052a7a | 2026-10-22-tt02-engine.md | SCOPED-PKG | scoped package + integration evidence |
| TT04 | fbd4ec7eb762 | 2026-10-23-tt04-cells.md | ALPHA+ROOT | provision 17/17 + cells 19/19 root |
| TT06 | e34ff709f39f | 2026-10-22-tt06-sdk01-tt08core.md | TWO-LANE | NEW scaffolding; PPV mutation proof |
| TT07 | 9279426138d1 | 2026-10-23-tt07-operator.md | ALPHA+ROOT | operator 16/16 + matrix 23/23 root |
| TT08 | 043e019f697c | 2026-10-23-tt08-tail.md | ALPHA+ROOT | select 12/12 + qual 57/57 root |
| TT09 | a3923c70f1f4 | 2026-10-23-tt09-perf.md | ALPHA+ROOT | 22/22 + 6/6 + 76/76 root; baselines unbuilt |

## Explicitly deferred to the audit pass (needs the S-call)

- Tier verdict per task (full vs alpha) with per-task reasoning.
- Whether any unadjudicated S-finding implicates a task's evidence.
- Any aggregate-green or qualification claim.
- Whether the 13 BARE TODO rows should summarize their records.
