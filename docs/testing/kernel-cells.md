# Kernel cells: isolated-object and live-kernel orchestration (TT05 slice)

Bounded TT05 slice: exact object admission, exclusive kernel-cell leases,
capability-gated execution with loud skip reasons, operation ledgers and
independent cleanup inspection. Privileged live-kernel cells that cannot
run on the current host SKIP with an exact reason (cell name plus missing
capability); they never pass vacuously and never fail the suite.

Tools (stdlib-only Python):

- `tools/qualification/admit_object.py`:
  `admit_object(manifest_path, object_path, profile_path) -> Admission`
- `tools/qualification/run_guest.py`:
  `run_guest(admission_path, environment_path, owned_run_root, ...)`
  `-> RunManifest`
- `tools/qualification/inspect_cleanup.py`:
  `inspect_cleanup(run_manifest_path, ...) -> CleanupReport`
- `tools/qualification/kernel_common.py`: shared strict-JSON, hashing
  and lease prelude. `tools/qualification/workloads/cell_probe.py`:
  unprivileged identity/capability workloads.

Cell inventory: `profiles/environments/kernel-v1.json` (7 cells).
Tests: `tools/qualification/tests/test_kernel_*.py` (59 checks).

## Cell catalog

| Cell | Kind | Requirements | Runs here |
|---|---|---|---|
| `host-object-identity` | host-unprivileged | none | PASS: re-hash plus ELF/machine/type re-check |
| `host-capability-probe` | host-unprivileged | none | PASS: records read-only capability evidence |
| `host-bpf-load` | host-privileged | `root-euid`, `bpffs-writable` | SKIP: `root-euid` (euid 1000) |
| `owned-guest-debian13` | owned-guest | `kvm-rw`, `tool:vng`, `file:/var/lib/scopebase/guests/debian13.img` | SKIP: guest image absent (`kvm-rw` and `tool:vng` pass) |
| `host-license-gpl-activity` | host-privileged | `root-euid`, `bpffs-writable` | SKIP: `root-euid` (H33 positive) |
| `host-license-nongpl-refusal` | host-privileged | `root-euid`, `bpffs-writable` | SKIP: `root-euid` (H33 refusal) |
| `host-license-helperfree-baseline` | host-privileged | `root-euid`, `bpffs-writable` | SKIP: `root-euid` (H33 baseline) |

`host-bpf-load` additionally excludes target `isa:bpfel-arm64`: an
active excluded target refuses (`active-excluded-target-required`),
never silently skips. The inventory targets the x86_64 authoring host;
per-arch environment variants are future work.

Containers sharing the host kernel do not qualify another kernel; every
run manifest records the observed `kernel_release`.

## Requirement, target and release-probe vocabularies

Requirements are ordered per cell; the first missing one gates. Probes
are read-only and deterministic; unknown kinds are invalid (exit 2),
never a silent pass:

- `root-euid`: `os.geteuid() == 0`
- `bpffs-writable`: `/sys/fs/bpf` writable and searchable
- `bpf-unprivileged-allowed`: sysctl
  `kernel.unprivileged_bpf_disabled` reads `0` (unreadable counts as
  missing: allowed cannot be established)
- `kvm-rw`: `/dev/kvm` readable and writable
- `tool:<name>`: resolved via `PATH` (`[A-Za-z0-9._+-]+`, no slash)
- `file:<abs-path>`: absolute regular file, symlinks refused
- `kernel-release-prefix:<prefix>`: `uname -r` prefix match

Excluded targets use `isa:<label>` matched against the admission's
`isa_profile`. Release probes: `no-owned-procs` (recorded workload pids
reaped, starttime-compared so pid reuse cannot forge liveness),
`run-root-retired` (only the receipt pair remains) and `bpffs-empty`
(an unreadable bpffs is NOT_PROBED and fails retirement closed).

## Lease protocol

Lease state lives under an explicit `--lease-root` (no hidden state):

```text
<lease-root>/<cell>/lock        # flock file
<lease-root>/<cell>/lease.json  # present only while held
<lease-root>/<cell>/state.json  # clean|dirty plus bounded history (32)
```

`lease.json` adapts the KryProbe lease-1 record (exclusive holder,
lock file, resources, pid, UTC start). Acquisition opens the lock
`O_RDONLY` (creating only when absent, so sticky-directory
`protected_regular` denial is avoided) and takes
`LOCK_EX|LOCK_NB`. Refusals:

- `lease-exhausted`: names the live holder; a second holder never
  shares a cell (leases are exclusive; capacity is 1 by design)
- `dirty-cell`: a failed/crashed run marked the cell dirty; reuse is
  refused until an explicit inspected recovery
- `stale-lease-record`: the lock is free but a record lingers; the
  lease is never silently adopted

Release is holder-verified: any other holder, double release or
release without a live record is `unleased-access` and is refused.
Recovery path: `inspect_cleanup --retire` (removes owned files, writes
a `retirement.json` marker) then `inspect_cleanup --accept-clean CELL`
(re-verifies lease-free, residue-free and foreign-intact, flips
dirty to clean with an audit entry). Both refuse while leased.

## Skip contract and exit codes

The exact skip marker is:

```text
SKIP (cell-gated): <cell> requires <requirement> (see docs/testing/kernel-cells.md)
```

A semantic cell with no bound workload is `INCOMPLETE`
(`no-reproducer: ...`), never a pass. Any other skip text in workload
output fails the run (`unexplained-skip-text`). Exit codes:
0 executed-and-passed, 1 refused/failed/setup-error, 2
usage/manifest error, 3 skipped/incomplete. `SETUP_ERROR` (workload
setup failed) never satisfies an expected-failure control.

## Cleanup inspection

`inspect_cleanup` defaults to read-only. Verdict precedence: run-root
presence and exact owned-file set (`RESIDUE` on any extra or missing
owned file), foreign-pin byte identity (`FOREIGN_DISTURBED`), workload
pids reaped (`STILL_ALIVE`), lease released (`STILL_LEASED`, needs
`--lease-root`) and cell clean (`DIRTY_CELL`). Foreign pins are never
cleanup targets and never residue, even inside the owned root;
`--retire` never deletes them. A tampered `retirement.json` reports
`RUN_ROOT_TAMPERED`, never clean.

## Admission binding

`admit_object` consumes TC03 final-object manifests (`kind
tc03_final_object_manifest`) and ISA profiles (`kind tc03_isa_profile`)
without rewriting them, enforcing: strict documents (UTF-8,
duplicate/unknown-field refusal, bounded strings, lowercase hex64,
identifier rules); exactly one entry matching the presented bytes
(zero refuse `uninventoried-object`, two refuse `ambiguous-object`);
ELF64 plus `EM_BPF` bytes whose `ET_REL`/`ET_EXEC` type matches the
entry kind; entry `isa_profile`/`isa_version` equal to the profile
name/version; and the license gate (declared-vs-observed equality,
required-but-missing and unlisted-license refusal).

Deferred to the TC01/TC03 Rust `check_object` (this tool takes no
contract input): contract `(cpu, features)` drift and decoded-family
checks. The admission carries no build fields and `run_guest` has no
build path, so a guest cannot rebuild the admitted object implicitly;
transfer re-hashes staged bytes and refuses drift.

## Observed run (this environment, 2026-10-23)

One observed run on kernel `7.0.0-38-generic` x86_64, euid 1000,
`unprivileged_bpf_disabled=2`, `/dev/kvm` rw, `vng` present. This is a
single witnessed transcript, not a qualification claim:

```text
admit: admitted tt05-demo-object 29a8aa17...
host-object-identity: exit=0 PASS (transfer == admission digest)
  inspect: CLEAN; retire: RETIRED_CLEAN
host-capability-probe: exit=0 PASS (3/8 probes true: kvm-rw, qemu, vng, docker, python3)
host-bpf-load: exit=3 SKIP (cell-gated): host-bpf-load requires root-euid
owned-guest-debian13: exit=3 SKIP (cell-gated): owned-guest-debian13 requires
  file:/var/lib/scopebase/guests/debian13.img
host-license-gpl-activity: exit=3 SKIP: requires root-euid
host-license-nongpl-refusal: exit=3 SKIP: requires root-euid
host-license-helperfree-baseline: exit=3 SKIP: requires root-euid
```

Reproduce: build demo fixtures with
`tools/qualification/tests/tt05_helpers.py` (`build_elf`,
`manifest_bytes`, `profile_bytes`), admit with `admit_object.py`, then
run each cell in `profiles/environments/kernel-v1.json` via
`run_guest.py` with an explicit `--lease-root`. The committed
`test_shipped_*` checks execute the same matrix.

## Source-obligation dispositions (26 TT05 rows)

The slice closes the TT05 orchestration facet (admission, leases, skip
machinery, ledgers, cleanup inspection, runnable-here cells). Full
obligation closure needs producers, live cells or shared-owner facets
as noted; traceability updates stay with integration.

| ID | Slice contribution | Status / exact blocker |
|---|---|---|
| B08 writer ownership docs | lease holder/ownership records | OPEN: producer-owner design doc; needs BP07/CP04 |
| B10 kernel/arch matrix | 7-cell registry mechanism | OPEN: maintainer matrix selection; no second/older kernel here |
| T03 harness controls | exact skips, unexplained-skip-fails, negatives, loud broken controls | OPEN (shared): TT02/TT03/TT04 facets plus live-cell sensitivity |
| H01 exec lineage | orchestration only | OPEN: needs LX08/TT03 live process cells plus privileged host |
| H04 held-file retention | foreign-pin preservation rules | OPEN: needs LX06/BP05/BP10 producers plus live cells |
| H07 relocation | orchestration only | OPEN: needs TC05/BP10 producers plus live load |
| H08 CO-RE/task-storage | orchestration only | OPEN: needs BP08/BP09/TC05/TC06 producers plus live load |
| H09 uprobe concurrency | guest-cell declaration | OPEN: needs two kernels (affected plus repaired control); no reproducer bound |
| H14 writer slots | orchestration only | OPEN: BP07 planned; no live maps here |
| H15 insertion identity | orchestration only | OPEN: BP07/CP04 live-map work; no live maps here |
| H16 per-CPU stride | orchestration only | OPEN: BP07/NX05 live topology; no live maps here |
| H17 loss signaling | orchestration only | OPEN: BP07/CP03/CP04 live-map work; no live maps here |
| H18 settlement | admission/ledger halves | OPEN: BP06/BP07/CP09/SDK06 producers plus live quiescence |
| H21 attach isolation | lease exclusivity half | OPEN: BP04/BP05/BP10 producers plus live attach |
| H22 capability evidence | excluded-target refusal half | OPEN: BP03/BP10 admitted positives plus live negatives |
| H29 atomic RMW | orchestration only | OPEN: TC04 producer plus live old/new-value check |
| H30 profile containment | isa_profile binding in admission | OPEN: TC07 whole-guest mixed builds plus live cells |
| H31 AtomicLoad selection | orchestration only | OPEN: TC04/TC07 producers; refusal-vs-kernel-failure split needs live cells |
| H32 BTF preservation | orchestration only | OPEN: TC05/TC07/NX06 producers plus debug-record fixtures |
| UC12 actual attach/retire | excluded-target plus foreign-sentinel rules | OPEN: needs privileged cells with real A firing/B exclusion |
| OV10 kernel diagnosis | capability-probe evidence half | OPEN: BP03 native/live diagnosis producers |
| OV12 admission/quiescence/sample | admission plus ledger halves | OPEN: BP07/CP09 quiescence producers |
| OV13 cross-program isolation | orchestration only | OPEN: BP07 planned |
| OV25 toolchain/build isolation | per-run owned stage, no guest rebuild | OPEN: TC02/TC07 pairing producers |
| OV26 object/verifier regressions | exact bytes end-to-end (admit, transfer, loaded) | OPEN: TC03-TC07/BP10 semantic producers |
| H33 license boundary | offline declared-vs-observed binding; 3 declared cells | OPEN: live positive/refusal cells need privileged host plus GPL/non-GPL/helper-free fixtures (TC07/TC08) |

## Deliberate bounds

- Exclusive single-holder leases only (capacity 1); multi-holder
  cells are future work with their own exhaustion semantics.
- No kernel-config (`/proc/config.gz`) requirement kind yet; config
  gating stays future work.
- Semantic workload binding (BP live runners, guest reproducers) is
  TT05-full/TC07 work; gated cells report `INCOMPLETE` on capable
  hosts until then.
- Big-endian BPF objects parse (EI_DATA-selected) but no BE fixture
  ships; a BE exercised cell needs a BE-capable host.
