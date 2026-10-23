# Strict neutral validation and replay vectors

CP10 delivers the canonical neutral semantic seam for capture
evidence: `neutral::validate_v1` checks one single-epoch v1 snapshot
by calling the existing public constructors, and the `json`-gated
`replay` module decodes strict replay-v1 documents into the same
validator. Direct construction, strict replay and the frozen native
seam agree on acceptance and on typed refusals; framing and byte
preallocation in FFI remain the native adapter's obligation, not a
claimed capture feature.

A receipt parser that last-wins duplicate members silently overwrites
earlier evidence: a valid `misses` object overwrites
`{"unavailable":true}`, and a second terminal contradicts the first
without a trace. V1 refuses duplicate members at every object depth
(comparing decoded names, so an escaped twin refuses), requires
exactly one terminal as the last record, and inventories the terminal
against the unique prior records. Counts are canonical decimal
strings (`0` or `[1-9][0-9]{0,19}` within `u64`): `9007199254740993`
and `18446744073709551615` parse exactly, while `01`, `+1`, bare
numbers, booleans and floats refuse with typed errors and NaN refuses
as malformed JSON. Hex pins are exact lowercase fullmatches, so a
newline-suffixed binding refuses; exact pins including zero parse.
Known zero and unknown magnitudes stay distinct, synthetic origins
are preserved exactly and never promoted, and nothing is defaulted:
missing members refuse.

Limits precede collection growth at every phase. The structural
pre-scan enforces byte, nesting, string, breadth and duplicate rules
before the JSON parser builds its DOM, counts the records array, and
records element offsets for later refusals. The semantic walk checks
every push: the 4,097th data record refuses before any record buffer
grows (the mandatory terminal holds one extra structural slot), and
parts/reasons collections check `max_items` before growing. Installed
limits are bytes 1,048,576, records 4,096, nesting 16, items 4,096 and
strings 256. `ReplayError` carries a typed kind and byte offset only;
no raw payload is echoed and library calls emit no stdout/stderr.

## Deliberate deltas and limits

- Surface redesign (ratified by controller ruling RATIFY-2026-10-23-CP10):
  the implemented v1 surface differs deliberately from the pre-CP10 spec
  draft — `max_*` replay limit names, kind/epoch/field raw records with a
  closed 6-kind + terminal vocabulary, 18 `ReplayErrorKind` variants,
  `ReplayDocument::new(source, unit, records, terminal)`, a versionless
  `scopebase-capture/replay-v1` document with
  `schema/capture/producer/epoch/binding/origin/unit/records` keys,
  preserved (never forced-`Replayed`) origins, per-row validated types
  and 8 `ValidatedNeutralV1` accessors. The spec now describes this
  surface exactly; code is unchanged.
- V1 corrects the KryProbe donor's bare-integer acceptance: bare JSON
  numbers refuse as `TypeMismatch`, so no float or bare-int coercion
  exists. The digit-string grammar itself is unchanged.
- V1 corrections are single steps from a genesis revision (`0` to
  `1`); a `0` to `2` record refuses as `StaleRevision`. Longer
  revision chains stay with the caller's `Versioned` values.
- Neutral cardinality limits cover counters, claims and reasons per
  the plan; loss/signal/partition/correction rows share the replay
  record budget. Claim reasons are validated as vocabulary shape and
  limits; ledger assessment composition is later work.
- V1 has no generation, alternative-candidate or closure record
  kinds; those constructors stay available for direct use.
- The optional TT06 fuzz target is not included; the 38-line fixture
  corpus is the seed corpus for that later campaign.
- MojoBPF anchor resolved read-only on 2026-10-23: coordination
  `2b26baee78011fac5b7e0a743bcb692f6c764c7e`, untracked
  `doc/validation/2026-10-15-f02-fullmatch-boundary.md` (F02 exact-pin
  fullmatch, MBPF305), product `_check_pattern` fullmatch observed in
  `.worktrees/mojobpf-quality-native` (live HEAD `dcce5bf9`; receipt
  recorded `63348333`). No lines were copied from live donor state;
  the binding grammar cites the receipt's vector concept.

## Verification

- `cargo test -p scopebase-capture --no-default-features
  --test neutral_validation`: 8 passed.
- `cargo test -p scopebase-capture --features json
  --test strict_replay`: 15 passed, including the 38-line
  hand-authored fixture oracle, every truncation boundary of the
  small valid vectors, the 4,096/4,097 record boundary, canonical
  encoding bytes, the control script and the owned-subprocess
  silence probe.
- `cargo test -p scopebase-capture --features json --doc`: 8 passed,
  including the 4 CP10 compile-fail opacity blocks (`ValidatedCounter`,
  `ValidatedNeutralV1`, `ReplayError`, `ReplayDocument`).
- Full package: 203 passed with `--no-default-features`, 220 passed
  with `--features json`; zero failures. CP10 files are clippy- and
  rustfmt-clean.
