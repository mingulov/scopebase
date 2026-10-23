# TT04 real filesystem fixtures and mapping-policy audit

Plan authority: `docs/superpowers/plans/2026-10-17-scopebase-testing.md`
TT04 section; recipes FS01–FS10 from
`docs/superpowers/specs/2026-10-17-scopebase-testing-design.md`.
This file freezes the deterministic recipes: what each cell proves,
how to provision it, what this environment ran, and what stays open.

Every cell drives the real production APIs
(`scopebase_linux::mapping`/`process`) against live fixtures.
Independent oracles use only std reads of `/proc`, never the library
under test. A fixture that does not produce its trigger FAILS as
unexercised; cells that cannot run here SKIP with the exact cell name
plus the missing capability, never a vacuous pass.

## Cell inventory

| Cell | Rust test | Provision | Result here |
|---|---|---|---|
| FS01 ext4 control | `ext4_control` | privileged: 64M loop ext4 | PASS (alias/rename/delete) |
| FS02 btrfs split | `split_and_collision_are_required` | unprivileged subvols | PASS (stat dev 1048674, maps 0:35) |
| FS03 btrfs collision | `split_and_collision_are_required` | unprivileged snapshot pair | PASS (ino 257 triple) |
| FS04 overlay xino=off | `overlay_xino_off_aligned` | privileged mount | PASS (aligned ino) |
| FS05 overlay xino=on | `overlay_xino_on_split` | privileged mount, tmpfs lower | PASS (composed ino) |
| FS06 copy-up | `copy_up_trigger_must_happen` | FS04 mount + live write | PASS (ChangedSource/WrongContext) |
| FS07 metacopy | `metacopy_transition` | privileged metacopy=on mount | PASS (0-block stub) |
| FS08 views + churn | `wrong_mount_view_rejected`, `overmount_reads_target_view`, `mount_churn_keeps_retained_views`, `nspid_sequence_across_pidns`, `replaced_root_target` | privileged sleepers + churn driver | PASS |
| FS09 denial | `restricted_denial_is_real` | none (live) | PASS (ReopenHeld/Denied/Denied) |
| FS10 audit | `transient_target_mmap_detected` | none (ptrace preflight) | PASS (planted flagged, clean phase quiet) |
| lifecycle | `fork_exec_exit_verdicts` | none | PASS (TargetExited/exec Mismatch) |
| concurrency | `concurrent_same_owner_reads` | none | PASS (8x25 KeyCompatible) |
| escape | `symlink_escape_pinned` | none | PASS |
| policy matrix | `calibration_policy_matrix`, `sub_page_cap_inconclusive` | none | PASS |
| exact range | `exact_range_positive_privileged` | none (sudo cell only) | PASS under sudo, SKIP otherwise |

## This environment (surveyed 2026-10-23)

- Kernel 7.0+ (Debian), root filesystem Btrfs (`/dev/sda3`,
  subvol `/@`), overlay in `/proc/filesystems`, `/dev/loop-control`
  present, `mkfs.ext4` + `btrfs` + `unshare` installed.
- Observer uid 1000, passwordless `sudo -n` available, Yama scope 1
  (ptrace of owned children allowed).
- Unprivileged user namespaces are unusable: `unshare(CLONE_NEWUSER)`
  succeeds but writing `uid_map`/`gid_map` fails EPERM, so there is no
  unprivileged overlay/mount-namespace route here. All mounts and
  namespace sleepers come from the privileged provisioner.
- `map_files` stat is EPERM even for owned children (hardened
  kernel); root can stat it. Hence key-path cells run unprivileged
  and the ExactRange positive runs only under sudo.

## Operator route

Unprivileged survey and fixtures (never touches privileges):

```sh
python3 tools/qualification/provision_fs.py plan \
  --manifest /tmp/tt04plan.json --run-root /tmp/tt04run
python3 tools/qualification/provision_fs.py create \
  --manifest /tmp/tt04run-manifest.json --run-root /tmp/tt04run
python3 tools/qualification/provision_fs.py inspect \
  --manifest /tmp/tt04run-manifest.json --run-root /tmp/tt04run
```

Privileged provisioning (explicit grant; mounts/sleepers/churn driver):

```sh
python3 tools/qualification/provision_fs.py create --privileged \
  --manifest /tmp/tt04priv-manifest.json --run-root /tmp/tt04priv
```

Test suite (offline, locked):

```sh
# Unprivileged cells always run; provisioned cells skip exactly.
cargo test --offline --locked -p scopebase-testkit \
  --features linux-fixtures --test filesystem_cells
# Full matrix against a provisioned manifest:
TT04_MANIFEST=/tmp/tt04priv-manifest.json cargo test --offline --locked \
  -p scopebase-testkit --features linux-fixtures --test filesystem_cells
# ExactRange positive ONLY (compiled test binary, this cell alone):
sudo -n ./target/debug/deps/filesystem_cells-<hash> --nocapture \
  exact_range_positive_privileged
```

Retire (identity-checked kills, reverse unmounts, subvolume deletes):

```sh
python3 tools/qualification/provision_fs.py cleanup \
  --manifest /tmp/tt04priv-manifest.json --run-root /tmp/tt04priv
```

Both production mapping policies also run qualified through the
installed operator route (`scopebase-conformance run`, profile
`operator-delivery-v1`): `no-new-target-mappings` run `389c6d22…`
and `allow-private-calibration` run `c64282ff…`, each exit 0 with
the policy recorded in its receipt.

## LX06/LX08 TT04-cell deferral closures

| Deferred item | Disposition |
|---|---|
| LX06 Btrfs collision positive | CLOSED by `split_and_collision_are_required` |
| LX06 overlay copy-up + foreign-mount-table/churn | CLOSED by `copy_up_trigger_must_happen`, `wrong_mount_view_rejected`, `mount_churn_keeps_retained_views` |
| LX06 fork/exec/exit fixtures | CLOSED by `fork_exec_exit_verdicts` |
| LX06 privileged restriction (ExactRange positive) | CLOSED by `exact_range_positive_privileged` (sudo) |
| LX06 same-owner concurrent reads + wrong-proc-view ns | CLOSED by `concurrent_same_owner_reads`, `wrong_mount_view_rejected`, `nspid_sequence_across_pidns` |
| LX08 foreign/nested pidns + NSpid | CLOSED by `nspid_sequence_across_pidns` (depths 2 and 3) |
| LX08 child-overmount | CLOSED by `overmount_reads_target_view` + `wrong_mount_view_rejected` |
| LX08 symlink-escape | CLOSED by `symlink_escape_pinned` |
| LX08 replaced-root | CLOSED by `replaced_root_target` (static busybox chroot) |
| LX08 live mount-ns change + Btrfs/overlay mapping | CLOSED by `mount_churn_keeps_retained_views` + mapping legs |
| LX06 10k history/libFuzzer mapping-history | STAYS DEFERRED: TT06-owned fuzz target, not a TT04 cell |
| LX06 TT08 catalog gate | Not TT04-owned (TT08 route) |
| LX08 closed actual-EOF + no-control tracer | STAYS DEFERRED: needs TT03 accepted execution (TT03 still PLANNED) |
| LX08 installed profiles + second client | LX11/TT07-owned, not TT04 cells |

## Observed kernel behaviors (ground truth, not textbook)

- `xino=on` is IGNORED with all layers on one filesystem (dmesg:
  `"xino=on" is useless with all layers on same fs, ignore`). FS05
  therefore puts its lower on tmpfs; the provisioner verifies composed
  inodes and degrades FS05 to unsupported with evidence if ignored.
- Same-fs copy-up preserves the merged `(dev, ino, size)` key while
  replacing the object: FS06 asserts the identical key and refuses
  old-proof reuse via mtime/ctime + descriptor identity.
- Overlay read FDs opened pre-copy-up serve NEW bytes afterwards
  (verified with raw pread as well as HeldFile reads); private
  mappings faulted pre-copy-up keep OLD bytes, while mappings first
  touched post-copy-up fault new bytes. FS06 pre-faults deliberately.
- Rename follows to the new name in `/proc/PID/maps` (no stale
  path); delete appends ` (deleted)` as a separate field. The TT04
  maps oracle keeps the full remainder so the marker survives.
- `unshare --mount-proc` implies a fresh mount namespace
  (renumbered IDs); cross-view mount resolution therefore refuses
  with MountUnresolved. The pure-pidns sleeper (no `--mount-proc`)
  isolates the pidns boundary, which stays key-transparent.
- A chrooted target with no mounts inside shows an EMPTY
  `/proc/PID/mountinfo`; production refuses by mount domain.
- Metacopy metadata-only copy-up yields a zero-block upper stub
  (unprivileged-readable signature); data writes materialize blocks.
- Root-spawned sleepers drop to the observer uid and re-enable
  dumpability (`PR_SET_DUMPABLE`), without which same-uid maps/exe
  reads fail EPERM.
- The maps oracle fix during bring-up (keeping ` (deleted)`) is
  itself covered: the FS01 delete leg fails without it.

## SKIP catalog (exact reasons emitted)

- `missing TT04_MANIFEST (run provision_fs.py create --privileged)`:
  FS01/FS04/FS05/FS06/FS07/FS08-family without a manifest.
- `cell skipped/unsupported: <provisioner reason>`: per-cell
  provision outcome (missing grant, tool, or kernel support).
- `missing root map_files authority (run ONLY this cell under sudo)`:
  FS-exact as non-root.
- `euid 0 bypasses DAC: denial untestable as root`: FS09 as root.
- `ptrace preflight refused: <errno + yama note>`: FS10 without
  trace authority.
- `btrfs subvolume create refused: <stderr>` / `missing btrfs(8)
  tool`: FS02/FS03 without btrfs scratch.

## Limits and follow-ups

- PID reuse is never forced: the exit leg uses reap-then-observe
  (TargetExited), not a recycled PID. Forcing deterministic reuse
  stays open (racy by nature).
- TT06 owns the 10k-model/libFuzzer mapping-history exploration;
  TT03 owns closed-EOF orchestration; guest bindings and the second
  reference client ride TT05-full/LX11 respectively.
- The `host-v1`/`filesystem-v1` environment profiles declare TT04
  cells with statically-probed requirements for the TT05/CI layer;
  their workloads stay unbound (`needs_reproducer`), mirroring the
  gated kernel cells, because the runners are the cargo suite and
  the provisioner rather than staged BPF objects.
