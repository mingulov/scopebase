# TT06 property/fuzz/model dependency choice (SB02 record)

Status: scaffolding choice, recorded 2026-10-22. No new registry dependency
is admitted by this work.

## Decision

The TT06 campaign scaffolding uses **no new crates**:

- `tools/qualification/run_campaign.py` and its tests use the Python 3
  standard library only, matching the existing qualification tools.
- `tests/models` (`scopebase-catalog-model 0.1.0`) uses a std-only
  deterministic generator (xorshift64*) and fixed regression seeds instead
  of a property framework. Its only dependency is the path-bound
  `scopebase-testkit =0.1.0`, whose exact pins (`serde =1.0.229`,
  `serde_json =1.0.151`, `sha2 =0.11.0`) are already admitted and resolve
  offline from the shared cache.
- `fuzz/scopebase-testkit` (`scopebase-testkit-fuzz 0.0.0`) likewise depends
  only on the path-bound testkit. Its stable smoke engine needs no fuzzing
  crate; the `#[cfg(fuzzing)]` libFuzzer entry is source-only until a
  `libfuzzer-sys` admission exists.

Both new crates are standalone workspaces with their own lockfiles, so they
add no entries to the root `Cargo.toml`/`Cargo.lock` and require no shared
manifest edits.

## Considered and deferred

- `proptest 1.11.0` is present in the local cargo cache but is **not**
  admitted: no SB02 source/build approval, notice review, or lock binding
  exists for it or its transitive closure in this task's scope. The fixed
  512-case schedule with directed mutations covers the scaffolding contract
  without it. A future packet may admit proptest (or `quickcheck`, absent
  from the cache) with its own executed probe and approval records.
- `libfuzzer-sys` (any version) is absent from the local cache, requires a
  nightly `-Zbuild-std`/sanitizer-capable toolchain for real campaigns, and
  has no admission record. The `cargo-fuzz` route therefore stays an
  explicit PREREQUISITE_UNMET path. Admitting it needs the SB02 acquisition
  flow (pinned fetch, vendored offline closure, build approval), not a
  manifest edit alone.
- Miri and native sanitizers (ASan/UBSan via NX profiles) have no admitted
  tool support in this environment: no executed tool-support probe exists.
  The `catalog-miri-boundary` campaign binds the `cargo +nightly miri run`
  command form and records the missing toolchain as PREREQUISITE_UNMET
  instead of claiming it; that incomplete diagnostic never gate-passes.

## Revisit conditions

Admit a property or fuzzing crate only through a component packet that binds
the actual consumer version, exact lock, source approval digests,
build-script/proc-macro review and license notices, with the new closure
resolving `--offline`. Availability in a local cache is not admission.
