# CP07 preservation map

Candidate host implementation for alternative candidate measurements in
`crates/scopebase-capture/src/bounds.rs` plus
`crates/scopebase-capture/tests/alternative_bounds.rs`, with deltas recorded in
`docs/issues/capture/alternative-measurements.md`. This is a source/defect map,
not acceptance or a test-result ledger. No CP07 admission or selected-port
receipt exists yet; grant findings below are per-slice against the current
`docs/provenance/admissions/*.json` and `docs/provenance/adoption-decisions.md`.

Only frozen OSSLscope `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a`
(`osslscope-ws/checkout/osslscope/.worktrees/preview-r21`,
`task/integration-preview-r21`) and MemVeil
`8307a17d4c1d01d2e6fa66679f0e7bed113fa416`
(`memveil-ws/checkout/repos/memveil`, `main`) are selected, 17 inclusive line
slices in total. KryProbe and p11scope are explicitly excluded. All slice
hashes were computed over the gitless private capture with
`sed -n 'A,Bp' FILE | sha256sum` (exact inclusive lines, trailing newline per
line preserved); no live donor or implicit Git lookup was used. The mixed-class
fix `00b135d` (`00b135dff28836c24f315fea218f8fdfecb70a4d`, "feat: H3 mixed-class
sites withhold definite claims") was located in frozen
`osslscope-ws/histories/repo-001/history.git` and verified an ancestor of
preview-r21 (`merge-base --is-ancestor`); its surviving mechanism is sliced
from the preview-r21 checkout files below. Frozen whole-file hashes match the
admitted `head_blob_sha256` exactly: `O:src/evidence.rs`
`49c206bb…7d6a9`, `O:tests/evidence_model.rs` `e1d7af05…49ea`,
`O:src/capture.rs` `711ab095…05ac`, `M:tests/unit/test_mappings.mojo`
`8348f3d7…f3e1`. Historical GPL-3.0-or-later source observations and
author-authorized destination terms remain separate; destination host/test/data
terms are Apache-2.0. No third-party or target/BPF/shared-source grant is
inferred. Earlier CP02/CP03/CP04/CP05/CP06 grants/receipts and production bytes
remain unchanged.

| Frozen source scope | Exact slice SHA256 | Origin and destination symbols | Preserved difference or limit |
|---|---|---|---|
| `O:src/evidence.rs:30–39` (`SiteKey`) | `af0408145351f5773a861c0109ef25f7bcf4ddff1c8abe471e41d21a399717e6` | ADAPT; `bounds.rs::SiteCount::{site}`, `domain::PhysicalSiteId` | Preserve one physical site label per observation; device/inode/offset triple stays caller identity, never a universal key. Fingerprint/registry vocabulary not extracted. |
| `O:src/evidence.rs:41–77` (`CandidateIdentity::new`) | `e1e702e0a9bf9c5d6c5ece3a30e42a33d1659ad7ff238d6fe57f7c0701375aa0` | ADAPT; `bounds.rs::SiteCount<C>`, generic `C` + `MatchClass` | Preserve candidate-as-alternative-explanation. Provider/op/funcid/algorithm taxonomy and weak-alias flag stay product-local; classification meanings stay caller-supplied. |
| `O:src/evidence.rs:79–94` (`CandidateCoverage`) | `8a3f36dfd739db36359a58395fab4f78642583000fb530312d0f1878829298d7` | ADAPT; `bounds.rs::CandidateCoverage::{Complete,Unknown}` | Preserve Unknown-means-no-bounds. Donor `AmbiguousComplete` is NOT a variant here: callers express per-candidate ambiguity with `MatchClass::Possible`, which withholds identically to `(0,Some(n))`. |
| `O:src/evidence.rs:136–152` (`PredicateMatch`, `MatchBounds`) | `600a69a3a8138dc994eb075136c035597fbc0dc191550e56c6935ef15d49bb8f` | ADAPT; `bounds.rs::MatchClass`, `quantity::{CountBounds,Count<Events>}` | Preserve three-valued classification and definite/possible shape. Donor predicate closures over product taxonomy are not extracted; class-per-candidate is positional. |
| `O:src/evidence.rs:154–229` (`site_bound`, `match_bounds`) | `867f9db2de77964dcde5abfa592858295d1d0ad26f322cc38840b46d004226e8` | ADAPT; `bounds.rs::{classify_alternatives,combine_disjoint_sites}` | Preserve conserved single-`n` bounds and unknown-upper poisoning. DELTAS: zero-call Unknown yields `[0,None]` not `(0,Some(0))`; empty `Complete` refuses (`MissingProvenance`) instead of bounding; overflow refuses instead of saturating. |
| `O:src/evidence.rs:300–348` (`CounterKind`, `CounterUnits`, `CounterSource`, `GapCounter::forces_partial`) | `6df66297cd1dca7477f763c3eab79948e664e37009407c89004a0e3b68b66cb8` | VECTORS_ONLY; vocabulary reference; actual counter types live in CP03 `loss.rs`/`counter.rs` | Only loss/activity kind and units/source vocabulary inform the `discovery.mixed_classes` Activity reading. No counter type is re-ported here; CP03 owns the mechanism. |
| `O:tests/evidence_model.rs:105–130` (`shared_site_conserves_calls`) | `06517480a3a434f04bdde32b1b10f6abe0b457d07098f338ae24bcf020a54ad0` | VECTORS_ONLY; `alternative_bounds.rs::one_physical_count_is_not_duplicated_across_aliases` | Preserve n=7-stays-7 conservation and the anti-14 assertion shape. Donor `site()`/`cand()`/`Predicate` helpers are not copied; the destination reimplements `epoch`/`site`/`bounds` fixtures. |
| `O:tests/evidence_model.rs:132–148` (`ambiguous_require_is_unproven`) | `d7208c5505eed777d2f966f38861d692c0ea4615afa3d684d60327b37f4db5f4` | VECTORS_ONLY; `alternative_bounds.rs::all_candidates_vs_mixed_bounds` mixed rows | Preserve ambiguous-means-unproven. Donor `Rule::Require`/`evaluate_rule` policy engine is not extracted; CP07 stops at bounds, no verdicts. |
| `O:tests/evidence_model.rs:468–491` (`within_alias_mixed_classes_are_unknown`) | `db5291ec46bb409599cf5ffcc89bfd65d8be0f672be179c1571832de0be2749f` | VECTORS_ONLY; `alternative_bounds.rs::{all_candidates_vs_mixed_bounds,small_world_oracle_agrees_on_all_class_pairs}` | Preserve within-alias mixing yields Unknown, never first-alias boolean. Donor `Predicate::Algorithm::eval` taxonomy is not extracted; `Possible` carries the semantics. |
| `O:tests/evidence_model.rs:631–649` (`candidates_dedupe_and_sort`) | `d89d1c29f39c428b3fd87a1ef1d1afd8f6b9275ae7211636ce40b7d8daed3988` | VECTORS_ONLY; `bounds.rs::SiteCount::new` (`DuplicateKey`, `CapacityExceeded`) | Preserve no-silent-duplicate intent with a DELTA: duplicates refuse at admission instead of sorting/deduping. Donor `normalize`/`finalize` canonicalization is not extracted. |
| `O:src/capture.rs:3163–3167` (`sites_mixed`, fix `00b135d`) | `0a4345529d04da4487683530b4858b77d8d52455e3ff5689bbe09fc82b38816f` | ADAPT (rule only); `bounds.rs::MatchClass::Possible` withholding | Preserve mixed-is-ambiguity-not-lost-identity. The sticky adapter set itself is NOT extracted: CP07 keeps no cross-call state; each call classifies fresh. |
| `O:src/capture.rs:3574–3621` (mixed/bad_read split, fix `00b135d`) | `dc3c691c7fdb4efc01f407722b06f2a8855ea1067462734570e2b0b0f09db4f8` | ADAPT (rule only); `bounds.rs::classify_alternatives` Possible arm | Preserve mixed riding its own set, never `bad_read`. Arrival grouping, epoch sets, novelty index and `sites_ok`/`sites_bad_read` machinery are not extracted. |
| `O:src/capture.rs:3645–3663` (pure-mixed/unknown fold, fix `00b135d`) | `29f3b34eb30efa0eb28b43964845f615f52343c9f32695540eb2bc0ad9129c16` | ADAPT (rule only); `bounds.rs::classify_alternatives` Unknown arm | Preserve blend-withhold and finite-but-unattributable pure-mixed bounds. Op closure, taint flags and table-proof evaluation stay product-local. |
| `O:src/capture.rs:6046–6060` (`discovery.mixed_classes` Activity counter, fix `00b135d`) | `1da0fd05f941bfa98c09c20c918855599e3ea13aa826ce2e3bb961b218bd9dac` | VECTORS_ONLY; `alternative-measurements.md` H3 accounting note | Preserve mixed-counted-once-as-Activity, never a taint input. Counter emission and assembly-time aggregation are not extracted; no CP07 counter is minted. |
| `O:tests/capture_controller.rs:2267–2362` (`h3_t2_mixed_arrival_withholds_definite_claim_sticky`, fix `00b135d`) | `242a67414990cf12663a0b555a895c8f66280a582928b27ccd317a825b9541f8` | VECTORS_ONLY; `alternative_bounds.rs::all_candidates_vs_mixed_bounds` Possible rows (withhold half only) | Preserve min-label-plus-weak-preserved withholding. Re-walk stickiness and denominator assertions are NOT extracted: no adapter state, no coverage census here. Harness (`Harness`, `FirePlan`) not copied. |
| `O:tests/policy_contract.rs:443–485` (`h3_t3_mixed_sites_never_yield_definite_verdicts`, fix `00b135d`) | `a9cb12eb0dc50b56579ac2ff369e6230559f752fcc65e16fd65cad795414949b` | VECTORS_ONLY; `alternative_bounds.rs::all_candidates_vs_mixed_bounds` definite==0 rows | Preserve mixed-shape feeds no definite verdict either direction. `evaluate_document`/`PolicyRule` completion-policy engine is not extracted. |
| `M:tests/unit/test_mappings.mojo:1174–1203` (`test_split_unpaired_map_withholds_occupancy`, H26 cross-check) | `289f1e1293f88977b8a14742a989814a326826d87df94a9b94311ec089f5c23a` | VECTORS_ONLY; `alternative_bounds.rs::unknown_candidates_cannot_prove_absence` | Preserve incomplete-evidence-withholds-occupancy rule, including at zero. `MappingTracker`, metrics schema and scoped-coverage machinery are not extracted. |

ADAPT retains donor mechanisms; VECTORS_ONLY retains case shape/literal
expectations without importing unselected helper implementations. In particular
the O adapter state (`sites_mixed`/`sites_ok`/`sites_bad_read` stickiness,
arrival grouping, epoch/table proofs), the O policy/completion engine
(`Rule`/`evaluate_rule`/`evaluate_document`, `finalize`), the O discovery
classifier (`classify_alg_with`, `ALG_MIXED` kernel status, group-id table
build, `sites_mixed` re-walk stickiness) and the M tracker/metrics machinery
are vector context only. `00b135d` hunks in `crates/ebpf-common/src/lib.rs`,
`src/kinds.rs`, `src/discovery/harvest.rs`, `src/loader.rs`,
`tests/discovery_protocol.rs` (H3-T1) and the H3-T4 fenced-mixed test are
explicitly NOT selected (BPF payload, kernel classifier, product discovery,
fence machinery). Donor `AmbiguousComplete`, saturation, silent dedupe and the
zero-call `(0,Some(0))` bound are deliberately not preserved; see the DELTAS
in `docs/issues/capture/alternative-measurements.md`.

## Defect, independent truth and sensitivity

| Defect/invariant | Original correspondence and delivered assertions | Independent truth and semantic control |
|---|---|---|
| One physical count with two alias candidates is one observation, never two populations or a multiplied total. | O `shared_site_conserves_calls` (n=7, anti-14) maps to `one_physical_count_is_not_duplicated_across_aliases` (n=5, anti-10). | Every classification bounds the single n=5; the alias-multiplication mutant (10) fails the explicit bound assertion; all-Definite twins keep `[5,5]`. |
| Ambiguity between or within candidates withholds definite claims; mixed classes are never definite. | O `ambiguous_require_is_unproven`, `within_alias_mixed_classes_are_unknown`, H3-T2/T3 map to `all_candidates_vs_mixed_bounds` Possible/mixed rows. | Any `Possible` yields `[0,n]` with definite 0; never-definite holds in both require and deny directions. |
| Unknown candidates prove nothing, including at zero observed calls. | M H26 `test_split_unpaired_map_withholds_occupancy` (withheld occupancy, scoped copy rows intact) maps to `unknown_candidates_cannot_prove_absence` at n in `{0,1,5,MAX}`. | `[0,None]` at every n; the unknown-as-empty mutants (`[0,Some(0)]`, `[0,Some(n)]`) fail explicit assertions. DELTA vs donor `zero_call_unknown_candidates_bound_known_zero` is pinned, not inherited. |
| Duplicate/empty/overflowing claims refuse rather than silently repair. | O `candidates_dedupe_and_sort` (dedupe intent) maps to `SiteCount::new` refusal rows and `duplicate_site_or_epoch_refuses`. | `DuplicateKey`/`MissingProvenance`/`CapacityExceeded`/`ArithmeticOverflow`/`DomainMismatch`/`ConservationMismatch` twins refuse; distinct-site twins combine. |

## Grant coverage

Checked every slice against all `docs/provenance/admissions/*.json`
`adoption.source_scope` ranges and `docs/provenance/adoption-decisions.md`
("No whole-file or future-range grant follows from a selected range"; a slice
is covered only if fully inside a granted range). No grant is invented.

- COVERED: `O:src/evidence.rs:300–348` exactly matches the granted
  `PORT_SOURCE` range `[300,348]` in
  `2026-10-22-cp06-scopes.json` (also present in
  `2026-10-18-{bp02-maps,cp03-counters,cp04-insertion,lx03-read,lx05-proc}.json`
  and `2026-10-22-next-host-scopes.json`), `READY_FOR_SELECTED_SCOPE` under
  `OWNER-2026-10-18`, `USER_OWNED`, host destination Apache-2.0. CP07 uses it
  as vocabulary reference only; CP03 owns the ported counter types.
- NEW-GRANT-NEEDED (16 slices): `O:src/evidence.rs` `30–39`, `41–77`,
  `79–94`, `136–152`, `154–229`; `O:tests/evidence_model.rs` `105–130`,
  `132–148`, `468–491`, `631–649`; `O:src/capture.rs` `3163–3167`,
  `3574–3621`, `3645–3663`, `6046–6060`;
  `O:tests/capture_controller.rs` `2267–2362`; `O:tests/policy_contract.rs`
  `443–485` (file has no admission entry at all);
  `M:tests/unit/test_mappings.mojo` `1174–1203`. Partial overlaps do not
  cover: granted `[145,152]` lies inside slice `136–152`, and granted
  `[110,110]`/`[121,126]` lie inside slice `105–130`.
- Exact missing authorization questions: (1) Does `OWNER-2026-10-18`
  authorize `PORT_SOURCE` of `O:src/evidence.rs` lines `30–39`, `41–77`,
  `79–94`, `136–152`, `154–229` at `4bcb24c` (plus the already-granted
  `300–348` as referenced vocabulary) to Apache-2.0 host
  `crates/scopebase-capture/src/bounds.rs` for CP07? (2) Does it authorize
  `VECTORS_ONLY` of `O:tests/evidence_model.rs` lines `105–130`, `132–148`,
  `468–491`, `631–649` to `tests/alternative_bounds.rs`? (3) Does it
  authorize `PORT_SOURCE`-of-rule/`VECTORS_ONLY` of `O:src/capture.rs` lines
  `3163–3167`, `3574–3621`, `3645–3663`, `6046–6060`,
  `O:tests/capture_controller.rs` lines `2267–2362`, and a first-time
  admission plus `VECTORS_ONLY` of `O:tests/policy_contract.rs` lines
  `443–485`, for the `00b135d` H3 withhold rule? (4) Does it authorize
  `VECTORS_ONLY` of `M:tests/unit/test_mappings.mojo` lines `1174–1203`
  (H26 cross-check) to `tests/alternative_bounds.rs`?

## Later owners and duplicate retirement

All mechanisms here are T0/T1 host evidence. No product classifier, domain
taxonomy, loader binding, live scan or completeness policy is qualified. OSSL
product reducers, scan oracle truth and completion policy stay with the
product; CP10 owns strict replay of alternative records; CP11 owns real
application adapters; CP13/TT installed exact-consumer conformance. No donor
duplicate is removed here.
