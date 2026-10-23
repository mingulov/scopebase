# SPDX-License-Identifier: Apache-2.0
# H33 executable license-boundary bindings (TT10 lane)

Three of the four H33 cells execute in CI through
[`check_h33.py`](../../tools/qualification/check_h33.py); the fourth stays an
explicit SKIP. Each executing cell has a catalog `REGISTERED_EXECUTABLE`
record whose four artifacts (executable, fixture, oracle, bad control) are
byte-pinned, plus an independent oracle
([`h33_oracle.py`](../../tools/qualification/h33_oracle.py)) whose agreement
with the checker is asserted on the real tree and on every mutant by
[`test_h33.py`](../../tools/qualification/tests/test_h33.py).

## Per-cell audit (2026-10-23)

| Cell | Verdict | Binding |
|---|---|---|
| `h33-source-closure` (T0) | EXECUTES | `python3 tools/qualification/check_h33.py source-closure --root .` — 584 checks: 6 workspace manifests declare known options, every option text sits beside its manifest with its canonical marker, all crate notice records select only offered options with well-formed pins, and the tree scan finds no unlisted non-own grant and no unlisted runtime-license carrier (475 own headers, the `lic.ll` carrier listed). |
| `h33-final-object-license` (T2) | EXECUTES | `... final-object-license --root .` — 8 checks: the pinned llc-emitted `lic.o` decodes to `GPL`, matching the declared runtime token, while the source grant (`Apache-2.0`) stays a separate offered record; the emitter id matches the TC03 record. |
| `h33-license-admission` (T4) | SKIP (exact reason in `cell_bindings`) | Live `BPF_PROG_LOAD` GPL-positive / intended-reason-refusal / helper-free assertions need a pinned owned kernel cell with privilege leased via TT05. This CI runs unprivileged on unowned hosted kernels, so those assertions are `NOT_RUN`. Cause-separation logic is covered by the source/object gates and the `scopebase-bpf` attach tests. |
| `h33-installed-notices` (T5) | EXECUTES | `... installed-notices --bundle crates/scopebase-conformance/delivery` — 62 checks: every selected option of all 19 bundle entries has a byte-matching vendored notice text, and every bundle byte is closure-pinned. |

The steady-state CI verdict stays `INCOMPLETE` (exit 3): one required cell is
unavailable. That is the honest signal — only exit `0` attests the full
matrix, and the live-kernel cell cannot genuinely execute here.

## What the gates check

- Option-text presence (S2/N2): the canonical text for each selected option
  exists and carries its marker needles.
- Notice-text match (S3/N1/N3/N4): records select only offered options;
  vendored texts are byte-exact upstream copies (hashes match the pins);
  per-entry, per-option byte coverage holds (MIT per-holder texts included).
- Boundary refusal (S4/O4/N5): a non-own source grant, a runtime-license
  carrier, or a bundle byte without a closure record fails; a runtime token
  is never accepted as a source grant.

Negatives (25 mutants × checker + oracle): missing texts, stripped markers,
mismatched selections, malformed pins, smuggled grants/bytes, truncated and
wrong-byte objects, grant/runtime confusion, emitter drift, tampered and
unpinned bundle bytes. Vectors:
`tools/qualification/tests/vectors/h33_*_bad.json`.

## Donor slices (user-owned p11scope, `.worktrees/v040-integration`)

Commit `2c2713e66292b0d2688508a25f79e813ae823d81`, verified against the
2026-10-18 frozen snapshot (anchor hashes match `license-boundaries.md`):

- ADAPT: grant/runtime separation from `crates/ebpf/native/image_identity.c:1`
  + `:161` (twin `vma_identity.c:1` + `:317`).
- ADAPT: option-declaration pattern from `crates/ebpf/Cargo.toml:5`.
- PORT (quoted comment, cited): refusal-layering lesson from
  `crates/ebpf/src/main.rs:750-759` — a bare errno never identifies the
  refusing layer, so every rule names its own.

Checker/oracle/test logic is NEW (no donor license checker exists). The seven
`delivery/notices/` texts are byte-exact upstream license notices reproduced
as H33 requires ("a Cargo license string alone is not delivery of those
texts"); they are attributed third-party notices, not ScopeBase source, and
the source scan excludes that directory.

## Limits

- Source grants are recognized only in the first five lines of
  `.rs/.py/.c/.h/.ll/.sh` files; buried identifiers are vectors/quotes, not
  grants. Runtime-carrier patterns are scanned only in `.c/.h/.ll` files.
- The object gate decodes ELF structure, not provenance: it cannot prove the
  object was built from the recorded source (that binding is TC03's emitter
  record, cross-checked by id only).
- H33 registration paths intentionally keep the safe unknown-broadening
  fallback: the checker/oracle are shared across three cases and one changed
  path yields one change, so narrowing would under-select.
- `LGPL-2.1-or-later` (btf-rs, scopebase-bpf notices) is a known atom for
  records; no LGPL text ships in any bundle, and no crate manifest may
  declare an unmapped option without failing closed.
