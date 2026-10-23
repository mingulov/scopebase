# LX11 consumer seams

Reference-only consumer seams over `scopebase-linux`. NEW (LX11): no donor
lines copied. p11scope/OSSLscope product integrations remain explicitly
LATER; no product policy is normalized away for equality.

## Standalone consumers

Two materially different reference consumers, each with its own manifest,
lockfile, binary and `ConformanceAdapter` implementation. No code is shared
between them beyond `scopebase-linux` itself; each records its own fixed
script constants and operation ledger.

| Consumer | Shape | Linux surface |
|---|---|---|
| `consumers/linux-heldfile-reference/` | held-file inspector | `HeldFile::open/stat/read_all`, `CancelToken`, `parse_maps`/`parse_mountinfo`, `HeldDirectory`/`WalkBudget`/`walk` |
| `consumers/linux-observe-reference/` | owned-workload observer | `ObserverEpoch`, `ProcessObservation::{acquire,verify_birth,read_maps,read_mountinfo}`, `observe_mapping` under `NoNewTargetMappings`, TT03 stat oracle cross-check |

Each adapter dispatches on the invocation's operation name plus a
`case=<name>(;<key>=<value>)*;` fixture script over explicit caller paths,
encodes Linux contract refusals as observed `refuse=<Stage>:<Reason>[:line=N];`
bytes, and reserves `CaseError` for adapter-level failures (missing slot,
unknown operation/case, malformed script, missing parameter). Observations
are schema-tagged (`heldfile-reference-v1` / `observe-reference-v1`,
revision 1) bounded actual bytes, never expected truth.

Shared script intent, independently recorded per consumer: real files under
explicit owned roots, a pre-cancelled control, malformed parser rows, tight
walk ceilings, a hermetic spawned child (the observer's own binary in
`child` mode, no /bin dependency), an unmapped kernel-space range, and an
incoherent mapping ceiling. Live observations assert relational facts (birth
equality, stack-address containment, verdict kinds), never absolute counts.

## Developer conformance API

`crates/scopebase-linux/src/conformance.rs` (`ExpectedLedger`,
`FixtureRoot`, `refusal_of`): deterministic `op=detail;` operation ledgers,
explicit caller-owned fixture roots with path-escape refusal and exactly-once
`close` cleanup (no `Drop` retirement), and stable refusal encoding shared by
both consumers, the three crate examples and downstream tests.

## Unknown versus refused

Refusals stay typed and observed: `AcquirePath:Disappeared` for missing
inputs, `ValidateFile:NonRegular` for directories and un-followed links
(O_PATH|NOFOLLOW opens the link itself, so the type gate fires, not ELOOP),
`ReadFile:Cancelled` for pre-cancelled controls,
`WalkDirectory:LimitExceeded(Entries)` for tight ceilings,
`AcquireProcess:Disappeared` for dead PIDs, `ConfigureMapping:InvalidInput`
for incoherent ceilings, and whole-input `ParseMaps`/`ParseMounts:Malformed`
with the 1-based offending line. Mapping outcomes stay verdicts, not errors:
`inconclusive:EmptyFile` and `mismatch:RangeUnmapped` are successful
observations of a real `observe_mapping` call.

## Actual future product call sites (LATER)

- p11scope manifest open/read/maps proof: held-file inspector seams behind a
  live acquisition adapter (MG01 product work, not this task).
- OSSLscope plan PinnedFile/bounded-read seams: observer seams behind its
  evidence pipeline (MG02 product work, not this task).

## Later MG requirements

Product migrations MG01–MG05 own live acquisition, duplicate retirement, and
installed qualification of these seams. LX12 owns the packaged conformance
closure over the LX11 consumers. Testkit-side Linux adapter glue stays with
its single owner.
