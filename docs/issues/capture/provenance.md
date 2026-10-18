# Capture provenance and source custody

CP01 adds a pure host package boundary and a derived preservation register.
There is no copied donor implementation, fixture, runtime export, parser or
ported donor test in this increment. Every source row remains
`REGISTERED_NOT_COPIED` / `NOT_COPIED`; all donor tests remain NOT_RUN.

The [donor manifest](donor-manifest.json) references the accepted
[SB01 intake](../../provenance/donors.json) by exact source ID, full commit and
SHA256, retaining its authority for adoption and historical grants. It is not a
second adoption authority. The [contract map](contract-map.md) preserves defects,
invariants, original regressions, independent expected truth, meaningful mutants,
support limits and actual later owners. A future PORT/ADAPT packet must select
exact slices and retain the mechanism and regression together; NEW wrappers
require the recorded missing-mechanism reason and approved design.

## Frozen inputs and observed differences

All CP01 byte checks used the completed private captures under
`/home/user/src/m/bpfscope/.scopebase/donor-snapshots/2026-10-18/`, following the
[canonical frozen index](../../provenance/frozen-donors-2026-10-18.md).
No live donor was polled, refreshed, inventoried or changed. Frozen checkouts are
Gitless; independent history mappings are explicit below. No implicit parent Git
search, lazy fetch or source-branch merge was used.

| Source | Exact selected commit | Frozen checkout / independent history | Historical source grant |
|---|---|---|---|
| K | `d153f3aaf9a3931337b47c9e1b046c692da55083` | `kryprobe-ws/tree/kryprobe` / `kryprobe-ws/history/r001.git` | GPL-3.0-or-later as recorded per file in intake |
| M | `8307a17d4c1d01d2e6fa66679f0e7bed113fa416` | `memveil-ws/checkout/repos/memveil` / `memveil-ws/histories/repo-001/history.git` | GPL-3.0-or-later as recorded per file in intake |
| O | `4bcb24ce2ad23faf3db7c95bf05fb9e85ce4c59a` | `osslscope-ws/checkout/osslscope/.worktrees/preview-r21` / `osslscope-ws/histories/repo-001/history.git` | GPL-3.0-or-later as recorded per file in intake |
| L | `ff6ea5087cb6cab3db51a9ffaf99922f880da8c9` | `memveil-ws/checkout/repos/libbpf-mojo` / `memveil-ws/histories/repo-002/history.git` | Apache-2.0 WITH LLVM-exception as recorded per file in intake |

All 38 selected working-file SHA256 values match the accepted intake. Selected
symbol and regression-name presence was checked in those same frozen bytes,
including the cross-owned K ABI/WHO loss/migration cases. This is source evidence
only. No donor suite, source executable, native/Mojo compiler, bridge binary or
live kernel was run. Existing selected-path clean observations and commit/blob
relationships are intake facts; CP01 did not refresh live status.

K's captured `selftest-lane-policy` descendant
`1296533fcb6e21753562bc6547fcb8038f0b8719` and dirty
`scripts/test_sudo_lane.py` stay unadopted harness work. Capture was non-atomic;
its copied dirty bytes, index and diff can represent different instants. No
WIP is imported as trusted capture code or qualification infrastructure. Other
captured branch histories, experiments, locks and evidence remain in custody.
The original source tests are registered even when their primary intake owner
is BP02, so CP03/CP04 cannot lose WHO/KATTRLOSS obligations behind coarse routing.

M's selected `toolchain.lock.json` records consumed libbpf-mojo
`681096cb588379307d0c8e94e1d77e53de4be22f`, version0.2.0, bundle SHA256
`c5a3fd69e0afc00a5dcb16909bad5ad65f8d583e7e0f80936aeab8fd3b836253`.
Current L `ff6ea508` conservation source does not prove that consumed bundle
contains those changes. L/LJ selected core similarities do not collapse their
different support docs, tests or toolchain locks. LJ `e55ecbef` succeeds research
`54bcebd5` and diverges from L per accepted intake; CP01 does not refresh/adopt it.
Actual bundle/bridge qualification remains NX/BP work. Neither libbpf-mojo nor
Mojo is a Rust capture dependency; only portable conservation vectors are routed
to CP02. P reservation source selection remains explicit future CP12 work.

## Source terms and destination authorization

New user-owned host package, tests and documents use the provisional
Apache-2.0 userspace terms from
[D03](../../superpowers/specs/2026-10-18-scopebase-decisions.md#d03--license-by-code-ownership-and-actual-build-destination),
with no project MIT alternative. The exact Apache text is shipped in the package.
Historical donor SPDX, the user's author authorization and actual third-party
source grants remain separate facts. Historical GPL or missing headers alone
are not copying prohibitions for the user's contributions. Conversely, this
register does not invent upstream permission, change canonical adoption statuses,
or select actual source slices for a later port. The canonical authorization is
`OWNER-2026-10-18`; canonical adoption references remain the corresponding IDs in
[adoption decisions](../../provenance/adoption-decisions.md). Source-specific
PORT/ADAPT scope review belongs to its actual task/controller before copying.

The optional JSON declarations match accepted SB02: serde1.0.229 and
serde_json1.0.151, defaults disabled, std only, optional. There is no derive,
arbitrary_precision, preserve_order, raw_value or unbounded_depth feature.
The package notice inventory uses the reviewed product preamble and exact SB02
notice records, including retained upstream options/text hashes and third-party
MIT-only components. Dependency source texts remain in the admitted offline
source inventory, `bundled:false`; they are not falsely claimed bundled into the
crate. The controller binds the actual resolved allowlist/build-script grants,
source inventory and matrix to this package candidate. A Cargo license string
alone is not notice delivery. No target BPF payload, shared-target source grant,
ELF/runtime license string or Aya target option is selected here.

## Evidence limits and successor gates

The shipped Python3.11+ `tomllib` helper is test-only and manifest-relative. Its
fixed dependency/feature expectations do not learn policy from the manifest.
It reads at most65,537 bytes to reject a manifest over65,536 bytes, emits fixed
reasons and never resolves dependencies. The Rust boundary target exercises
valid twins, impossible-target and ordinary forbidden edges, build inputs,
metadata/options/feature changes, malformed TOML and oversized input. Optional
JSON ordinary Rust build scripts are separately admitted; the package itself has
no build script or platform/codegen dependency.

Compiler/client/archive results must be bound to the final integrated root
manifest, unchanged locked Cargo.lock, product matrix, admitted offline closure,
actual package archive and both exact compilers. Import-only clients establish
wiring; CP11 independently useful consumers and CP13/TT installed conformance
remain open. Required unavailable cells are NOT_RUN, never inherited PASS.
Package boundary acceptance does not qualify CP02–CP13 runtime behavior, mapped
images, native delivery, producer settlement, a product migration or publication.

## CP03 selected adaptations and NEW protocol

The immutable [CP03 admission](../../provenance/admissions/2026-10-18-cp03-counters.json)
extends six K/O source scopes under OWNER-2026-10-18. Historical
GPL-3.0-or-later labels remain recorded independently of the Apache-2.0 owned
userspace destination. Existing CP02 scopes/receipt hashes remain unchanged.
No third-party implementation, target source, shared-target license or Aya
option is added by this pure increment. The derived register's `cp03_increment`
records selected whole-file and slice hashes without rewriting CP01 history.

ADAPT K `kattrloss_fold`133–161 retains independent capped accumulation. CP03's
byte protocol additionally refuses invalid lanes, checking every lane after cap.
Selected WHO862–954 vectors retain nonzero accumulation, repeated-attempt cap,
already-capped stability and CPU/program separation; these are pure pre-capped
host observations, not producer/full-map execution. K integrity172–191/235–259
contributes saturation/queue/empty vectors; whole rollup, shared feeds and the
application integrity summary remain outside CP03.

ADAPT O `drops_delta`1504–1515/8881–8890 retains unknown-versus-known-zero baseline
semantics. The ratified generic protocol explicitly strengthens decreasing
values to ResetOrWrap instead of saturating subtraction. O evidence300–348 and
evidence_model520–554 retain source/unit/classification and loss-versus-activity
separation without copying product finalizers, schemas or Completeness policy.

NEW `Sample`/`AdvanceBound`/`Delta` supplies the specification's width-generic,
unit-safe, exact-owned-pair assertion: selected donors do not contain this
mechanism. Root-ratified C1–C4 fix its complete metadata, constructor/refusal order,
strict independent modulus bound and generic trait behavior. Two independently
generated finite counter populations and literal 64-bit rows check it; neither
oracle calls the production comparison or uses its expected result.

P first-use source remains supplemental reference only: no code or vectors are
copied and no clean-at-HEAD/intake claim is inferred. Its actual-read/read-window
and missing-value requirements constrain adapters owned by BP07. O SeqState's
half-range/first-sighting policy is also reference only and is not imported.
Actual producer acquisition, full identity-map storage, persistent rollup,
CP11 real applications and CP13 installed conformance remain separate open work.
The worker supplies private source-to-final-destination receipt drafts; root owns
canonical port receipts and independent acceptance.

## CP04 selected host adaptation

The immutable [CP04 admission](../../provenance/admissions/2026-10-18-cp04-insertion.json)
selects twelve ranges across the existing K ABI/WHO rows at
`d153f3aaf9a3931337b47c9e1b046c692da55083`. Both whole-file hashes and every
selected slice match the private frozen copy. No live donor/Git/fetch/refresh or
donor build was used. Historical GPL-3.0-or-later observations and the existing
OWNER-2026-10-18 Apache-2.0 host/test/data authorization remain distinct. No
third-party implementation, target/BPF/shared-source or kernel license grant is
added. The package notice format and dependency grants stay unchanged.

The [CP04 receipt](../../provenance/ports/CP04-20261018-insertion.json) binds the
actual destination hashes and [per-slice preservation map](../../provenance/ports/CP04-preservation-20261018.md).
ADAPT retains the unique-owner scan, ordered count errors and winning identity,
plus PcpuWho/Sim* fixture mechanisms. VECTORS_ONLY retains all seven original
host migration shapes and historical capacities/full/below populations. The
unselected ABI who_lane implementation, raw marker decoding, timestamp/latest
reducer, wire fields/strides and actual producer sites are not copied. Generic
wrappers/typed saturation, independent oracle, runner and distinct API consumers
are NEW for the frozen reasons in the exact contract. Earlier selected-port
receipts remain immutable; CP02/CP03 production/tests/controls are unchanged.

The authoritative delivered corpus has a generated exact root compatibility
mirror. Source verification checks equality; archive verification needs only its
own corpus and helper. CP04's optional explicit wrapper supports direct Cargo
without repository/env/PATH wrapper discovery. This bounded development route
is separate from CP13 installed operator/conformance delivery and does not repair
the unchanged CP03 helper's later TT07/CP13 portability obligation. No
live/ABI/profile/product-migration acceptance follows from this host increment.
