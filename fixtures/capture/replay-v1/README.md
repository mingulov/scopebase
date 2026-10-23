# Strict replay vectors (v1)

Hand-authored oracle for `scopebase-capture` CP10 strict replay.
`vectors.jsonl` holds one candidate document per line;
`expected.jsonl` holds the line-correlated expectation:
`{"expect":"accept","records":N}` or `{"expect":"refuse","kind":K}`
where `K` is the exact `ReplayErrorKind` debug spelling
(`Contract(..)` carries the neutral `ContractError` variant).
No encode/decode self-roundtrip is the oracle: these bytes and the
direct-constructor parity tests are.

## Document shape

```json
{"schema":"scopebase-capture/replay-v1","capture":"<32 hex>",
 "producer":"<32 hex>","epoch":"<u64>","binding":"<64 hex>",
 "origin":"adapter-reported|synthetic|replayed",
 "unit":"events|records|bytes|objects|attempts|nonexecutions|diagnostic-signals",
 "records":[ "...", {"kind":"terminal", ...} ]}
```

Every integer-typed field is a canonical decimal string (`0` or
`[1-9][0-9]{0,19}` within `u64`); bare JSON numbers, booleans and null
refuse as `TypeMismatch`, and non-canonical strings refuse as
`NonCanonicalNumber`. Hex pins are exact lowercase fullmatches: any
length, case or alphabet deviation (including a trailing newline)
refuses as `TypeMismatch`. Unknown members and kinds refuse; nothing
is defaulted. Each record echoes the document `epoch`; disagreement
refuses as `EpochMismatch`.

## Record kinds

- `counter`: `channel`, `policy` (`"monotonic"`,
  `{"saturating":"<u64>"}`, `{"modulo":"<u8>"}`), `clock` (32 hex),
  `start`, `end`, `value`, `unit` (must equal the document unit).
- `loss`: `channel`, `loss-kind`, `magnitude` (`"unknown"`,
  `{"exact":"<u64>"}`, `{"at-least":"<u64>"}`), `unit`.
- `signal`: `channel`, `observed`, `cap`, `unit` (must be
  `diagnostic-signals`).
- `claim`: `claim`, `reasons` (reason vocabulary array).
- `partition`: `total`, `parts` (conserved sum), `unit`.
- `correction`: `from`, `to` (single step from genesis: `0` to `1`).
- `terminal`: the last element, exactly once, carrying
  `counters`/`loss`/`signals`/`claims`/`partitions`/`corrections`
  counts equal to the unique prior records of each kind.

## Limits (installed)

Bytes 1,048,576; data records 4,096 (the mandatory terminal holds one
extra structural slot); nesting 16; items 4,096 per object, array and
semantic collection; strings 256 raw bytes. Limits precede collection
growth: the 4,097th data record refuses before any record buffer
grows.
