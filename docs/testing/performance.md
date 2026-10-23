# TT09 resource, performance and concurrent-consumer qualification

Owner: TT09. Status: harness built, pure-domain baselines measured on the
executor below; live cells stay UNBUILT with exact reasons (never estimated).

## What is qualified

- **Resource bounds** (`scopebase-testkit::resource`): per-domain
  byte/work/memory/time caps asserted separately. `check_bounds` fails typed
  (`BoundKind::{Bytes,Work,Memory,Time}` with domain, observed and cap);
  `violations` lists every failing dimension in fixed order. Checked
  arithmetic everywhere: an overflowing byte sum overruns even a `u64::MAX`
  cap instead of wrapping to a silent pass.
- **Peak accounting** (`PeakTracker`): monotonic high-water mark with explicit
  reallocation-transient (`old + new`) and clone-transient (`2 * size`)
  recording; overflow fails typed with the peak unchanged.
- **Concurrent consumers** (`Ledger`): N parallel consumers with per-consumer
  reservation tickets (reserve/settle/charge/refund), exact reservation
  transfer, bounded failed-cleanup quarantine and typed interference
  detection (foreign retirement/ticket, early refund, double charge/refund).
  Conservation is auditable: `settled == refunded + outstanding + quarantined`.
- **Downstream coexistence** (`tests/downstream/coexistence`): standalone
  crate using only the public API. Two consumers coexist, interference is
  detected at the intended assertion, and a foreign sentinel file proves no
  cross-consumer cleanup escapes custody.

## Executor and baselines (measured, not estimated)

Machine: `lu26`, Linux 7.0.0-38-generic x86_64, AMD Ryzen AI 9 HX PRO 370
w/ Radeon 890M, 12 CPUs, 14676696 kB RAM, rustc 1.98.1, bench profile
(optimized), base commit `05b12b8`.

Command: `cargo --offline --locked bench -p scopebase-testkit --bench
contract_costs -- --reps 21 --out <report>`

Frozen record: `profiles/performance-v1.json` (workload, parameters,
environment, baseline, metric interpretation).

| Workload | Oracle (asserted every rep) | Median/run | Ops/s |
|---|---|---|---|
| `bounds_check` (512 mixed samples) | 158 violations, check==violations agreement | 6623 ns | 76,234,774 |
| `ledger_cycle` (1 x 5000) | settled=refunded=245016, conservative | 834206 ns | 5,562,318 |
| `ledger_concurrent` (8 x 1000) | settled=refunded=392136, sentinel kept | 8134569 ns | 985,917 |

Timing distributions inform scheduling/cost review only and never gate caps.
Cross-machine timing comparison is invalid; same-environment relative
comparison only. Overlapping memory metrics are reported separately and never
summed.

## How to run

```sh
# Rust contract tests (22) + full testkit suite, offline
cargo --offline --locked test -p scopebase-testkit --test tt09_resource
cargo --offline --locked test -p scopebase-testkit --offline --locked

# Standalone downstream consumers (6), offline, own lockfile
cargo test --offline --locked --manifest-path tests/downstream/coexistence/Cargo.toml

# Measurement tooling unit tests (19)
python3 -m unittest discover -s tools/qualification/tests -p test_measure_resources.py

# Bench (deterministic assertions gate; timing reported)
cargo --offline --locked bench -p scopebase-testkit --bench contract_costs -- --reps 21

# Bounded sampler + cap check on a live pid
python3 tools/qualification/measure_resources.py sample --pid <pid> --epoch 0 --out /tmp/s.json
python3 tools/qualification/measure_resources.py check --sample /tmp/s.json --bounds <bounds.json> --elapsed-ms 0 --out /tmp/c.json
```

## Regression and tradeoff policy

- Deterministic assertions (violation counts, settled/refunded bytes,
  conservation, sentinel bytes) gate: any mismatch fails the run regardless
  of timing. Violated caps are never accepted as timing noise.
- Timing regressions trigger review, not automatic failure: re-run on the
  same environment, compare distributions with `compare-time` (report-only),
  and record the decision here. No baseline is updated without a measured
  same-environment run.
- A timeout interrupts no syscall and proves no worker/mapping/link
  retirement; time-bound failures carry no byte/work/memory implication.

## Mutant controls (each fails at its intended assertion)

- Early refund (refund before settle) -> `EarlyRefund`; no balance change.
- Double refund -> `DoubleRefund`; refunded total unchanged (no double credit).
- Double work charge -> `DoubleCharge`; work total unchanged (no double debit).
- Cross-consumer refund/quarantine -> `ForeignRetirement`; victim untouched.
- Cross-consumer settle/charge/transfer -> `ForeignTicket`.
- Byte-sum overflow -> `Bytes` overrun at saturated `u64::MAX`, never a wrap.
- Failed quarantine (cap+1) -> `QuarantineOverflow`; quarantine total unchanged.
- Unknown/dead sampler target -> typed `no_such_process`/`denied`, never zeros.

## Output privacy and cost

Samples carry counts and byte totals only: no file content, paths, PIDs of
other users' processes beyond the explicitly sampled pid, or diagnostic text
from observed processes. Sampler reads are bounded (1 MiB per /proc file,
65536 fd/task entries, 1M maps lines); failures are typed records, and folds
refuse partial peaks rather than skipping silently. The bench allocates only
its fixed fixture plus the ledger working set, whose size is observable via
`live_records()`.

## UNBUILT (exact reasons)

- `tt03_pair_launch`: no leased live cell on this executor (needs TT03 worker
  images plus an isolated Linux fixture cell with native process authority).
- `bpf_live_workload`: no privileged BPF cell (needs kernel BPF authority in
  an isolated live-kernel cell).
- `capture_domain_live`: no live capture feed bound (needs a real feed owner
  with measured loss/counter populations).

These gates belong to the TT03/BP/CP readiness owners; this harness supplies
the contracts they will assert against.
