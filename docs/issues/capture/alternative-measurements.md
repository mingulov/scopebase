# Alternative candidate measurements stay one physical observation

CP07 adapts OSSLscope preview-r21 (`4bcb24c`) `src/evidence.rs`
(`SiteKey`/`CandidateCoverage`/`site_bound`/`match_bounds`, typed
`GapCounter` units/sources) and `tests/evidence_model.rs` regressions
(`shared_site_conserves_calls`, `ambiguous_require_is_unproven`,
`within_alias_mixed_classes_are_unknown`, `candidates_dedupe_and_sort`)
plus mixed-class fix `00b135d` (H3: mixed classes withhold definite
claims). KryProbe algebra and p11scope are excluded. H26 cross-check:
MemVeil `tests/unit/test_mappings.mojo`
(`test_split_unpaired_map_withholds_occupancy`) withholds occupancy
while mapping evidence is incomplete; unknown candidates here likewise
prove nothing, including at zero observed calls.

One physical count with two alias candidates is one observation, not
two populations. Copying `n` into each alias, adding the site count to
a classified bound, or summing a second counter view of the same site
fabricates events. Classification therefore bounds the single `n`:
all-Definite `[n,n]`, all-Excluded `[0,0]`, anything else `[0,n]`, and
`Unknown` coverage `[0,None]` with an empty class slice. A complete
set must be nonempty with exactly one class per candidate; duplicates
refuse at admission rather than silently deduping. Combination adds
lowers and known uppers across distinct sites in one epoch; one
unknown upper makes the combined upper unknown, and duplicate sites,
mixed epochs, length mismatch or overflow refuse.

Deliberate donor deltas: (1) zero calls with `Unknown` coverage yields
`[0,None]`, not the donor's `(0,Some(0))`
(`zero_call_unknown_candidates_bound_known_zero`); an incomplete set
cannot prove absence of unlisted activity. (2) The donor's
`AmbiguousComplete` is expressed per-candidate with `Possible`, which
withholds identically. (3) An empty `Complete` set refuses
(`MissingProvenance`) instead of bounding. (4) Arithmetic refuses
overflow instead of saturating.

Bad controls: alias-multiplication (`[5,5]` must not read `10`),
unknown-as-empty (`[0,None]` must not collapse to `[0,Some(0)]` or
`[0,Some(n)]`), and sum-counter-plus-detail (`n` added to a bound)
each fail the explicit bound assertion. A small-world oracle
enumerates which single alternative could have produced the count for
all nine class pairs at `n` in `{0,1,5,MAX}` without calling
production classification; duplicate-site/epoch twins refuse while
distinct-site twins combine.

All mechanisms here are T0/T1 host evidence. No product classifier,
domain taxonomy, loader binding, live scan or completeness policy is
qualified. OSSL product reducers, scan oracle truth and completion
policy stay with the product; CP10 owns strict replay of alternative
records; CP11 owns real application adapters; CP13/TT installed
exact-consumer conformance. No donor duplicate is removed here.
