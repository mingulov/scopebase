# TC lane: compiler/object compatibility records

TC01–TC02 state. This directory holds strict, offline, versioned records for
the compiler/object workstream. Nothing here builds, probes or installs a
toolchain. Records are data plus strict parsers; actual fixture payloads,
executors and live cells belong to TC02–TC08.

## Layout

| Path | Content |
|---|---|
| `profiles.schema.json` | Shape contract for profile, patch-register and toolchain-inventory documents (`schema_version` 1). |
| `patches.json` | Patch register: 4 individually scoped records (TC-R08/B05). |
| `toolchains.json` | Pinned toolchain inventory: 11 exact version pins, hashes where recorded (TC-R01/C05). |
| `compiler-closure.json` | Explicit compiler closure: the 5 recorded-hash TC01 pins, every tool pinned and offline-resolvable (TC02, TC-R01/C05). |
| `issues/` | Issue lessons: H07/H29/H30/H31/H32 plus the H/C/B mapping. |

Issue provenance per area lives in `fixtures/bpf/<area>/provenance.json`
(`atomic-rmw`, `atomic-load`, `isa`, `metadata`, `object-graph`).

## Strictness

`scopebase_testkit::object` (feature `object`) admits the three envelopes:

- duplicate JSON fields refuse at every object level (escape-insensitive);
- unknown fields refuse; new fields require a new `schema_version`;
- hashes are exact lowercase hex (64 for sha256, 40 for git-sha1); malformed,
  truncated or newline-suffixed values refuse;
- CPU/feature contradictions refuse (generic/null admits no enabled features,
  v3 refuses v4-only `acqrel`/`indirect-jumps`, no feature both enabled and
  disabled);
- backend identity is mandatory and enumerated; required/optional cells are
  exact ids, never wildcards;
- every patch record carries scope, preimage, patch hash, applicability,
  affected profiles, owner, defect/inclusion/removal tests and upstream
  status. A merged upstream source alone never expires a record.

Run:

```sh
cargo test -p scopebase-testkit --features object --test bpf_profile_schema --offline --locked
```

The suite proves the register, inventory and all five provenance files load,
pins resolve with no network reference, provenance cross-references resolve,
and the LLVM RMW correction and the private linker repair are separate
records with separate removal tests.

## TC02 closure and bounded nested builds

`compiler-closure.json` is the explicit compiler closure: exactly the 5 TC01
pins with recorded hashes (LLVM 23.1.2 source archive, pristine and
PR-210371 `llc` identities, unrepaired and repaired `bpf-linker` binaries).
The 6 unrecorded system-observed installs stay out: a closure tool without
an exact hash refuses admission. `scopebase_testkit::toolchain` (feature
`toolchain`) admits the manifest and runs one pinned tool id at a
caller-supplied offline path under byte/time/work bounds: argument array
only (no shell), explicit environment plus forced `CARGO_NET_OFFLINE=true`,
per-stream byte caps, wall-clock timeout, arg/env count caps. Bound
overruns abort with `LimitExceeded` after killing the child; unknown ids,
missing executables, malformed requests and network-bearing env refuse
typed. Fake tools live in `fixtures/bpf/toolchain/fake-tools/` (no real
compiler is invoked or required).

Run:

```sh
cargo test -p scopebase-testkit --features toolchain --test toolchain_invoke --offline --locked
```

## Attribution and license boundary

Donor input is six whole user-authored files from p11scope-ws w000 at
`6f97aa47` (frozen tree): `llvm-bpf-toolchain-experiment.md`,
`llvm-bpf-atomic-load-report.md`, and kernel-oracle `cases.json`,
`prepare.py`, `run.py`, `run-raw-bpf.c`. The register records patch identity
and preimage hashes only. No upstream Aya/bpf-linker context or deletion
lines and no third-party `sources.json`/`README` content are copied anywhere
in this lane. Preimage file hashes for the two Aya patches were reconstructed
by exact reverse-apply against frozen postimage bytes in a temp dir and
round-trip verified; only the hashes are recorded. Grant: `OWNER-2026-10-23`
(user-owned donor slices to Apache-2.0 destinations).

Historical donor results stay `HISTORICAL` or `NOT_RUN` in provenance cells;
they are never current PASS verdicts.
