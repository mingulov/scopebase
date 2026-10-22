# TT06 model, fuzz and campaign limits

Status: scaffolding. Applies to `profiles/campaigns-v1.json`,
`tools/qualification/run_campaign.py`, `tests/models/` and
`fuzz/scopebase-testkit/`. This records what each bound means and what it
does not prove. No campaign result here qualifies a product or a profile.

## Per-target bound declarations

Every campaign states time, work and memory separately in its `limits` entry.
The runner enforces time and work deterministically; memory is observed only.

| Campaign | `time_secs` | `max_work_items` | `max_memory_bytes` | Expected |
|---|---|---|---|---|
| `catalog-model-512` | 300 | 512 (one per scheduled case) | 2147483648 | EXHAUSTED |
| `catalog-model-mutant` | 300 | 64 (one per scheduled case) | 2147483648 | FAILED |
| `catalog-fuzz-smoke` | 300 | 48 (6 seeds x 8-input fan-out) | 2147483648 | EXHAUSTED |
| `catalog-miri-boundary` | 600 | 512 | 2147483648 | PREREQUISITE_UNMET |

Time is a wall budget around the target process: exceeding it retires the
whole child process group and yields TIME_BOUNDED with `completed: false`,
never a pass by silence. Each invocation writes to a unique pid+uuid result
path, so a surviving late writer can never poison a later invocation. Work
is the target-reported `work_items` count: reaching `max_work_items` with a
passing assertion yields EXHAUSTED; exceeding it yields BOUND_EXCEEDED.
Memory is the sampled peak child RSS around the run; an overrun sets
`observed.memory_overrun` without changing the deterministic verdict.

## Known limits (explicit gaps, not coverage)

- Memory bounds are recorded, not enforced. There is no cgroup or RLIMIT
  accounting; a target that exceeds its memory bound is flagged, not stopped.
- Shipped campaign targets run through `cargo run --offline`, so observed
  peak RSS includes cargo/rustc wrapper overhead on rebuilds. The qualified
  route for memory-sensitive claims is direct-binary invocation after a
  separate locked build; the manifest records the wrapper route honestly.
- Campaign builds share the host build slot. Hold it while running campaigns
  (`./bin/scopebase-build -- python3 tools/qualification/run_campaign.py ...`);
  campaign targets deliberately do not take a nested lock, which would
  deadlock against the operator-held slot.
- `catalog-fuzz-smoke` is a finite 48-input corpus walk, not the plan's
  60-minute-per-target qualification campaign. Changed-target 10-minute
  campaigns, failure minimization and corpus preservation policy are future
  work behind the `cargo-fuzz`/`libfuzzer-sys` admission gate.
- The libFuzzer entry in `fuzz_targets/catalog_load.rs` (`#[cfg(fuzzing)]`)
  cannot build until `libfuzzer-sys` is admitted; attempting it is a
  documented PREREQUISITE_UNMET path, not a silent fallback to the smoke
  engine.
- Miri (`catalog-miri-boundary`) binds the `cargo +nightly miri run` command
  form with its documented nightly-toolchain requirement; the runner refuses
  unbound sanitizer targets without execution, so no Miri verdict is accepted
  without the bound command. Tool support missing here stays
  PREREQUISITE_UNMET, an incomplete diagnostic the gate never passes on.
  Native sanitizer profiles remain unbound.
- The state model asserts loader verdicts over scheduled mutations; it does
  not model TT02 session/retirement state, ownership transfer, or
  cancellation. Those schedules belong to later domain-owned models.
- A timeout does not prove a worker, mapping or link was retired, and
  campaign success never constructs runtime authority for another subject.

## Target protocol

Campaign targets write one JSON record to the `{result}` path (also passed
as `CAMPAIGN_RESULT_FILE`): `{"setup_ok": bool, "assertion":
"pass"|"fail"|"error", "work_items": int, "seed": int?, "detail": str}`.
Targets should write a partial `setup_ok: true` record immediately after
valid setup so timeouts report TIME_BOUNDED with setup evidence. Exit 0
covers passing and assertion-failing runs alike; nonzero exits mean crash or
IO failure. Verdict mapping: valid setup + `fail` gives FAILED; valid setup
+ `pass` at the work bound gives EXHAUSTED, below it TIME_BOUNDED; missing
or negative setup gives SETUP_ERROR or CRASH. Only EXHAUSTED matching its
declaration sets `qualifies`, and only for the declared finite claim.

## Running

```sh
./bin/scopebase-build -- python3 tools/qualification/run_campaign.py \
  --manifest profiles/campaigns-v1.json --campaign catalog-model-512 \
  --output-root /tmp/tt06-out
```

Exit 0 means gate-pass: the observed verdict matched `expected_verdict` on
a complete run. Exit 1 means it executed but mismatched, or ended
incomplete: `PREREQUISITE_UNMET` never gate-passes even when it matches its
documented expectation. Exit 2 means manifest or usage error. Each run
writes `<campaign-id>.json` (the `CampaignResult`, carrying the explicit
`gate` status) under the output root.
